//! `--doctor`：把"装没装好"这件事检查成一张表。
//!
//! 设计约束：**只做本地可判定的事**，不猜。
//! 根证书是否已装进用户根存储，用 Win32 API 可读（`certinfo`），此处只给人工核对命令，
//! 这里不调用系统工具（也不引入 `windows` crate），只给出确切的验证命令。

use std::time::Duration;

use crate::ca::CertAuthority;
use crate::certinfo;
use crate::config::App;
use crate::pac;
use crate::proxy::probe;
use crate::rewrite::Accel;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
}

impl Verdict {
    fn tag(self) -> &'static str {
        match self {
            Verdict::Pass => "OK  ",
            Verdict::Warn => "WARN",
            Verdict::Fail => "FAIL",
        }
    }
}

pub struct Check {
    pub name: &'static str,
    pub verdict: Verdict,
    pub detail: String,
}

impl Check {
    fn new(name: &'static str, verdict: Verdict, detail: impl Into<String>) -> Self {
        Self {
            name,
            verdict,
            detail: detail.into(),
        }
    }
}

/// 返回 (检查项, 是否全部通过)。WARN 不影响退出码。
/// `quick` 为真时只探到"够用"为止（见 [`QUICK_PROBE_TARGET`]）。
pub fn run(app: &App, quick: bool) -> (Vec<Check>, bool) {
    // 前四项是"本机状态"，顺序固定；后面的候选探测要等网络，放在后面。
    let mut checks = vec![
        check_listen(app),
        check_ca(app),
        check_pac(app),
        check_global_proxy(),
        check_winget(app),
    ];
    if let Some(check) = check_ca_residue() {
        checks.push(check);
    }

    // 探测要等网络。实测 43 个候选全部可达时约 20 秒（每批 6 个 → 8 批），
    // 全超时最坏约 57 秒。这段时间里此前**一个字都不输出**，用户会以为卡死了。
    let stop_after = if quick {
        Some(QUICK_PROBE_TARGET)
    } else {
        None
    };
    let batches = app.accels.len().div_ceil(DOCTOR_PROBE_CONCURRENCY);
    let worst_secs = batches as u64 * app.health_timeout.as_secs();
    if quick {
        println!(
            "正在探测候选加速器（--quick：找到 {} 个可达就停，最多 {worst_secs} 秒）…",
            QUICK_PROBE_TARGET
        );
    } else {
        println!(
            "正在探测 {} 个候选加速器（每批 {} 个并发，最坏约 {worst_secs} 秒）…",
            app.accels.len(),
            DOCTOR_PROBE_CONCURRENCY
        );
    }

    let accel_checks = check_accels(&app.accels, app.health_timeout, stop_after);
    let reachable_flags: Vec<bool> = accel_checks
        .iter()
        .map(|c| c.verdict == Verdict::Pass)
        .collect();
    let reachable = reachable_flags.iter().filter(|ok| **ok).count();
    let probed = accel_checks.len();
    // 是否只探测了部分候选（`--quick` 提前收工）。影响结论措辞——见 probe_asset_verdict。
    let partial = probed < app.accels.len();
    checks.extend(accel_checks);
    checks.push(check_chain(app, reachable, probed));
    // 顺序刻意放在 chain 之后：只有"有可达候选"时才有意义，
    // 且它回答的正是 chain 回答不了的那个问题——候选活着，但资产还在吗？
    if let Some(check) = check_probe_asset(app, &app.accels, &reachable_flags, partial) {
        checks.push(check);
    }
    if let Some(check) = check_caps(app) {
        checks.push(check);
    }

    let ok = checks.iter().all(|c| c.verdict != Verdict::Fail);
    (checks, ok)
}

/// 能力矩阵（design.md §7）：哪些候选只对部分 host 生效。
///
/// 只在配置里真的写了 `hosts` 时才输出——绝大多数用户不设限制，
/// 多一行"未启用"的检查只会稀释表格。
fn check_caps(app: &App) -> Option<Check> {
    if !app.has_capability_limits() {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    for (idx, accel) in app.accels.iter().enumerate() {
        if let Some(hosts) = app.caps.get(idx).filter(|hosts| !hosts.is_empty()) {
            parts.push(format!("{}: {}", accel.host, hosts.join("/")));
        }
    }
    Some(Check::new(
        "caps",
        Verdict::Pass,
        format!(
            "能力矩阵已启用（未列出的 host 不会改写给该候选）：{}",
            parts.join("；")
        ),
    ))
}

/// 本工具 CA 的残留检测：受信任的根里同时存在多张。
///
/// 与 `check_ca` 不同，这一项**不依赖 `certs/` 目录**：它只读证书存储。
/// 场景：CA 到期自动轮换时用 `certutil -delstore` 删旧证书，
/// 而部分环境会返回 `ERROR_NOT_SUPPORTED`，于是旧 CA 留在库里。
/// 后果不是"立刻坏"，而是用户以为只有一张——旧私钥若仍在磁盘上，
/// 就多了一条本可避免的冒用路径（范围仍限于那 4 个域名）。
fn check_ca_residue() -> Option<Check> {
    residue_check(crate::certinfo::our_ca_thumbprints().len())
}

/// 纯逻辑部分，便于单测：0/1 张不报，>1 张给出可执行建议。
fn residue_check(count: usize) -> Option<Check> {
    if count <= 1 {
        return None;
    }
    Some(Check::new(
        "ca-extra",
        Verdict::Warn,
        format!(
            "受信任根里有 {count} 张「winget-accel local CA」：多为轮换/卸载失败留下的。\
             建议执行 `winget-accel --remove-ca`，再重新启动一次并信任新 CA（旧私钥可能仍在磁盘上）"
        ),
    ))
}

fn check_listen(app: &App) -> Check {
    if !app.listen.ip().is_loopback() {
        return Check::new(
            "listen",
            Verdict::Fail,
            format!("{} 不是回环地址", app.listen),
        );
    }
    if std::net::TcpStream::connect_timeout(&app.listen, Duration::from_millis(300)).is_ok() {
        return Check::new(
            "listen",
            Verdict::Pass,
            format!("{} 已有进程在监听", app.listen),
        );
    }
    match std::net::TcpListener::bind(app.listen) {
        Ok(listener) => {
            drop(listener);
            Check::new(
                "listen",
                Verdict::Warn,
                format!(
                    "{} 可绑定，但当前没有代理监听；先启动 winget-accel",
                    app.listen
                ),
            )
        }
        Err(err) => Check::new(
            "listen",
            Verdict::Fail,
            format!("{} 被占用且代理 health 不可达: {err}", app.listen),
        ),
    }
}

/// 证书里实际的 `NameConstraints` 与当前配置是否一致。
pub enum ConstraintsVerdict {
    Matches,
    /// 能读出来但与配置不一致（列出的域名不同）。
    Mismatch(String),
    /// 读不出来（文件坏了、没有该扩展、被换成了别的 CA）。
    Unreadable(String),
}

pub struct ConstraintsCheck;

impl ConstraintsCheck {
    fn run(cert_pem: &std::path::Path, configured: &[String]) -> ConstraintsVerdict {
        match crate::ca::CertAuthority::permitted_dns_names(cert_pem) {
            Some(mut permitted) => {
                let mut expected: Vec<String> =
                    configured.iter().map(|h| h.to_ascii_lowercase()).collect();
                expected.sort();
                expected.dedup();
                permitted = permitted
                    .into_iter()
                    .map(|host| host.trim().to_ascii_lowercase())
                    .collect();
                permitted.sort();
                permitted.dedup();
                if permitted == expected {
                    ConstraintsVerdict::Matches
                } else {
                    ConstraintsVerdict::Mismatch(format!(
                        "证书的授权域名与当前 rewriteHosts 不一致：证书 {permitted:?} / 配置 {expected:?}。\
                         这张 CA 签不出其余 host 的有效证书（客户端会以 Name Constraints 拒绝），\
                         请删除证书目录重新生成（需重新信任一次）"
                    ))
                }
            }
            None => ConstraintsVerdict::Unreadable(format!(
                "{} 里没有可解析的 dNSName 约束",
                cert_pem.display()
            )),
        }
    }
}

fn check_ca(app: &App) -> Check {
    let path = CertAuthority::ca_pem_path(&app.cert_dir);
    if !path.exists() {
        return Check::new(
            "ca",
            Verdict::Fail,
            format!(
                "{} 不存在：先启动一次代理生成，再按文档信任它",
                path.display()
            ),
        );
    }
    let Ok(pem) = std::fs::read_to_string(&path) else {
        return Check::new("ca", Verdict::Fail, format!("{} 读不出来", path.display()));
    };
    if !pem.contains("BEGIN CERTIFICATE") {
        return Check::new(
            "ca",
            Verdict::Fail,
            format!("{} 不是 PEM 证书", path.display()),
        );
    }

    let meta_path = app.cert_dir.join("ca-meta.json");
    let meta_note = match std::fs::read_to_string(&meta_path) {
        Ok(meta) => match serde_json::from_str::<Vec<String>>(&meta) {
            Ok(recorded) if recorded == app.rewrite_hosts => None,
            Ok(recorded) => {
                return Check::new(
                    "ca",
                    Verdict::Fail,
                    format!(
                        "授权域名与配置不一致：旧 {recorded:?} / 新 {:?}；需删除证书目录重新生成",
                        app.rewrite_hosts
                    ),
                )
            }
            Err(err) => {
                return Check::new("ca", Verdict::Fail, format!("ca-meta.json 解析失败: {err}"))
            }
        },
        Err(_) => Some(format!("缺少 ca-meta.json（{}）", app.cert_dir.display())),
    };

    let Some(der) = certinfo::read_ca_der(&path) else {
        return Check::new(
            "ca",
            Verdict::Fail,
            format!("{} 无法解析为证书", path.display()),
        );
    };

    // 私钥与证书必须是一对。rcgen 不校验这一点：不配对时程序能启动、也签得出叶证书，
    // 但每个 MITM 握手都会被客户端拒绝，而 `ca` 这一项（信任/有效期/约束）全都正常——
    // 正是最难查的状态。这里单独判一次，代价只是一次公钥字节比较。
    if crate::ca::CertAuthority::key_matches_cert(&app.cert_dir) == Some(false) {
        return Check::new(
            "ca",
            Verdict::Fail,
            format!(
                "{} 里的私钥与证书**不配对**（文件被改动过？）：这样签出的叶证书会被所有客户端拒绝，\
                 表现为每一处都 `MITM-HANDSHAKE-FAIL`。请删除 {} 后重新启动（需重新信任一次）",
                app.cert_dir.display(),
                app.cert_dir.display()
            ),
        );
    }

    // 以**证书里实际的** NameConstraints 为准再核对一次。
    // `ca-meta.json` 只是我们写的旁注：旧版本升级上来可能没有（此时上面只留了一句
    // "缺少 ca-meta.json" 的提示），它与证书也可能不同步。而 Windows 校验的是证书本身，
    // 所以这里直接读证书——这才是"这张 CA 到底能签哪些域"的唯一真实答案。
    match ConstraintsCheck::run(&path, &app.rewrite_hosts) {
        ConstraintsVerdict::Matches => {}
        ConstraintsVerdict::Mismatch(detail) => {
            return Check::new("ca", Verdict::Fail, detail);
        }
        ConstraintsVerdict::Unreadable(detail) => {
            return Check::new(
                "ca",
                Verdict::Fail,
                format!("读不出证书里的 NameConstraints：{detail}"),
            );
        }
    }

    if !certinfo::is_trusted(&der) {
        return Check::new(
            "ca",
            Verdict::Fail,
            format!(
                "{} 已生成，但不在 CurrentUser\\Root；启动一次代理完成导入，或手动信任",
                path.display()
            ),
        );
    }

    match certinfo::info(&path) {
        Some(info) if info.days_left < 0 => Check::new(
            "ca",
            Verdict::Fail,
            format!(
                "CA 已过期 {} 天；删除证书目录后重新启动代理",
                -info.days_left
            ),
        ),
        Some(info) => {
            let mut detail = format!(
                "{} 已受信任，剩余 {} 天（{:?}）",
                path.display(),
                info.days_left,
                info.thumbprint
            );
            if let Some(note) = meta_note {
                detail.push('；');
                detail.push_str(&note);
            }
            Check::new("ca", Verdict::Pass, detail)
        }
        None => Check::new(
            "ca",
            Verdict::Pass,
            format!("{} 已受信任（无法读取有效期）", path.display()),
        ),
    }
}

fn pac_text_issue(app: &App) -> Option<String> {
    let text = pac::build(app.listen.port(), &app.rewrite_hosts);
    let missing: Vec<&str> = app
        .rewrite_hosts
        .iter()
        .filter(|host| !text.contains(&format!("host == \"{host}\"")))
        .map(|s| s.as_str())
        .collect();
    if missing.is_empty() {
        None
    } else {
        Some(format!("PAC 文本缺少 host: {missing:?}"))
    }
}

fn pac_registry_detail(expected: &str, actual: Option<&str>) -> (Verdict, String) {
    match actual {
        Some(value) if value.trim() == expected => {
            (Verdict::Pass, format!("AutoConfigURL 已指向 {expected}"))
        }
        Some(value) => (
            Verdict::Fail,
            format!(
                "AutoConfigURL = {value:?}，期望 {expected:?}；请重新启动代理或检查系统代理设置"
            ),
        ),
        None => (
            Verdict::Fail,
            format!("AutoConfigURL 未设置，期望 {expected:?}；请去掉 --no-env 后启动代理"),
        ),
    }
}

/// winget 下载器设置（ADR-017）。
///
/// 为什么值得单列一行：winget 默认先走 Delivery Optimization，而 DO 不读 PAC，
/// 对 GitHub 直连必失败（实测每次白等 60 秒）之后才回退到本代理。本工具启动时
/// 会把 `network.downloader` 钉成 WinINet，退出时还原。这行回答"现在到底生效没生效"：
/// 设置可能被 winget 自己改回去，也可能因为文件是手写的坏 JSON 而根本没被接管。
fn check_winget(app: &App) -> Check {
    if !app.winget_downloader {
        return Check::new(
            "winget",
            Verdict::Pass,
            "未接管（wingetDownloader=false）：winget 仍会先走 Delivery Optimization".to_string(),
        );
    }
    let Some(path) = crate::winget::settings_path() else {
        return Check::new(
            "winget",
            Verdict::Warn,
            "读不到 LOCALAPPDATA，无法定位 winget 的设置文件".to_string(),
        );
    };
    if !path.exists() {
        return Check::new(
            "winget",
            Verdict::Warn,
            format!(
                "未找到 {}（winget 还没有自己的设置文件；启动本工具时会创建）",
                path.display()
            ),
        );
    }
    match crate::winget::current_at(&path) {
        Some(value) if value == crate::winget::DOWNLOADER => Check::new(
            "winget",
            Verdict::Pass,
            format!("network.downloader={value}（启动时自动设置，退出还原）"),
        ),
        Some(value) => Check::new(
            "winget",
            Verdict::Warn,
            format!(
                "network.downloader={value}，启动本工具会自动改为 {}",
                crate::winget::DOWNLOADER
            ),
        ),
        None => Check::new(
            "winget",
            Verdict::Warn,
            format!(
                "{} 里读不出 network.downloader（没有该键，或文件不是合法 JSON）",
                path.display()
            ),
        ),
    }
}

fn check_pac(app: &App) -> Check {
    if let Some(issue) = pac_text_issue(app) {
        return Check::new("pac", Verdict::Fail, issue);
    }
    let expected = format!("http://127.0.0.1:{}/winget-accel.pac", app.listen.port());
    let actual = crate::autoenv::current_pac();
    let (verdict, detail) = pac_registry_detail(&expected, actual.as_deref());
    if verdict == Verdict::Fail {
        return Check::new("pac", verdict, detail);
    }

    // 注册表指向本机代理只说明"应该用它"，还得看**正在跑的那个实例**吐出来的是什么。
    // 改了 rewriteHosts 却忘了重启时，注册表看起来完全正常，而实际生效的还是旧 PAC。
    let expected_text = pac::build(app.listen.port(), &app.rewrite_hosts);
    let served = fetch_pac_text(app.listen.port());
    let (live_verdict, note) = pac_live_verdict(&expected_text, served.as_deref());
    Check::new("pac", live_verdict, format!("{detail}；{note}"))
}

/// 从本机代理取它正在提供的 PAC 文本；没有实例在监听时返回 `None`。
///
/// 复用 Hyper 客户端，按消息边界读取，并限制总期限和正文大小。
fn fetch_pac_text(port: u16) -> Option<String> {
    crate::http::get_text(
        &format!("http://127.0.0.1:{port}/winget-accel.pac"),
        Duration::from_secs(2),
        1024 * 1024,
    )
    .ok()
}
/// 纯逻辑部分（便于单测）：运行中实例提供的 PAC 是否与当前配置一致。
fn pac_live_verdict(expected: &str, served: Option<&str>) -> (Verdict, String) {
    match served {
        None => (
            Verdict::Pass,
            "当前没有实例在监听，未能核对运行中的 PAC".to_string(),
        ),
        Some(text) if text.trim() == expected.trim() => {
            (Verdict::Pass, "运行中的 PAC 与当前配置一致".to_string())
        }
        Some(_) => (
            Verdict::Warn,
            "运行中的实例提供的 PAC 与当前配置**不一致**：改了配置但没重启代理（重启后生效）"
                .to_string(),
        ),
    }
}

/// 系统里是否还开着一层全局代理（`ProxyEnable=1`）。
///
/// 本工具**从不改** `ProxyEnable`，而"全局代理 + PAC 并存时 WinINet 优先用哪个"
/// 本仓库没验证过（以前只是文档里的一句"未验证"）。既然能从注册表读出来，
/// 就不该让用户自己去猜——"装了没效果"时这是第一个要排除的变量。
fn check_global_proxy() -> Check {
    global_proxy_verdict(crate::autoenv::global_proxy_enabled())
}

/// 纯逻辑部分（便于单测）：`None` 表示读不出来，与"明确关闭"分开报。
fn global_proxy_verdict(enabled: Option<bool>) -> Check {
    match enabled {
        Some(false) => Check::new("proxyenv", Verdict::Pass, "未启用全局代理（ProxyEnable=0）"),
        Some(true) => Check::new(
            "proxyenv",
            Verdict::Warn,
            "系统全局代理已启用（ProxyEnable=1）。本工具只写 AutoConfigURL、不改它；\
             两者并存时 WinINet 优先哪一个，本工具未验证——下载异常时先手工关掉全局代理再试"
                .to_string(),
        ),
        None => Check::new(
            "proxyenv",
            Verdict::Warn,
            "读不到 ProxyEnable（reg query 失败）。若下载异常，请手工检查\
             「设置 → 网络和 Internet → 代理」里是否启用了全局代理",
        ),
    }
}

/// `--doctor` 的探测并发（与运行时一致）。
///
/// 试过把它提到 12：43 个候选的实测总耗时只从 **19.9 s** 变成 **18.1 s**，
/// 属于噪声。原因是**每批的耗时由该批最慢的那个候选决定**——把并发调高只是
/// 让更多慢候选挤进同一批，总时间并不会按比例下降。
/// 所以保持 6，不为一个测不出来的收益去提高对第三方服务的瞬时压力。
const DOCTOR_PROBE_CONCURRENCY: usize = 6;

/// `--quick` 模式下找到这么多个可达就停。
///
/// 用户跑体检真正要回答的是"我现在能不能下载"，而不是"44 个里通几个"。
/// 找到 3 个可用候选就已经能回答前者了，剩下的探测对结论没有增量价值，
/// 却可能让等待从十几秒涨到一分钟（实测候选池 44 个）。
const QUICK_PROBE_TARGET: usize = 3;

fn check_accels(accels: &[Accel], timeout: Duration, stop_after: Option<usize>) -> Vec<Check> {
    let mut checks: Vec<Check> = Vec::with_capacity(accels.len());
    for chunk in accels.chunks(DOCTOR_PROBE_CONCURRENCY) {
        if let Some(target) = stop_after {
            let reachable = checks.iter().filter(|c| c.verdict == Verdict::Pass).count();
            if reachable >= target {
                break;
            }
        }
        let mut batch = std::thread::scope(|scope| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|accel| {
                    let accel = accel.clone();
                    scope.spawn(move || check_one_accel(&accel, timeout))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("doctor probe thread panicked"))
                .collect::<Vec<_>>()
        });
        checks.append(&mut batch);
    }
    checks
}

fn check_one_accel(accel: &Accel, timeout: Duration) -> Check {
    let started = std::time::Instant::now();
    let ok = probe(accel, timeout);
    let ms = started.elapsed().as_millis();
    let detail = format!(
        "{}://{}:{} 探测 {}（{ms} ms）",
        accel.scheme.as_str(),
        accel.host,
        accel.port,
        if ok { "可达" } else { "不可达" }
    );
    Check::new(
        "accel",
        if ok { Verdict::Pass } else { Verdict::Warn },
        detail,
    )
}

/// 测速资产最多通过几个候选验证（每个最多 5 s）。
const DOCTOR_ASSET_CANDIDATES: usize = 3;
/// 单次取资产的超时。与运行时的 `PROBE_SPEED_TIMEOUT` 对齐。
const DOCTOR_ASSET_TIMEOUT: Duration = Duration::from_secs(5);

/// `health.probeUrl` 指的那个资产还取得到吗？
///
/// 为什么值得单开一行：这是"`chain` 显示 N/M 可达、却每个下载都 502"的唯一来源。
/// 运行时测速要求 `206` + ≥32 KiB，拿不到就把该候选判成"未通过实测"；
/// 所有候选都拿不到时**没有候选可用**（ADR-016 不回退直连）。
/// 默认资产绑着一个具体 release 文件——上游删掉它就会发生，而用户从日志里
/// 只看到一句 `SPEED ... 实测失败`，无从判断是"网络问题"还是"资产没了"。
fn check_probe_asset(
    app: &App,
    accels: &[Accel],
    reachable: &[bool],
    partial: bool,
) -> Option<Check> {
    // 一个可达候选都没有时 chain 已经 FAIL；再花 15 秒重复同一个结论只是噪音
    if !reachable.iter().any(|ok| *ok) {
        return None;
    }
    let mut outcomes: Vec<(String, Option<f64>)> = Vec::new();
    for (accel, ok) in accels.iter().zip(reachable) {
        if !ok {
            continue;
        }
        if outcomes.len() >= DOCTOR_ASSET_CANDIDATES {
            break;
        }
        let kbps = crate::proxy::probe_speed(accel, DOCTOR_ASSET_TIMEOUT, &app.health_probe);
        outcomes.push((accel.host.clone(), kbps));
    }
    Some(probe_asset_verdict(&app.health_probe, &outcomes, partial))
}

/// 纯逻辑部分（便于单测）：一个候选取到就算通过，全部取不到才判 FAIL。
fn probe_asset_verdict(asset: &str, outcomes: &[(String, Option<f64>)], partial: bool) -> Check {
    if let Some((host, kbps)) = outcomes
        .iter()
        .find_map(|(host, kbps)| kbps.map(|value| (host, value)))
    {
        return Check::new(
            "probe",
            Verdict::Pass,
            format!("测速资产可用：{host} {kbps:.0} KB/s（{asset}）"),
        );
    }
    // `--quick` 只探测了部分候选，此时"这些候选都取不到"不足以断定资产失效——
    // 断言成"下载全部 502"会变成假警报（实测过：quick 模式只探 6 个候选）。
    // 文案里必须把这一点说清，并给出"去掉 --quick 复核"的指引。
    let qualifier = if partial {
        "（注意：这是 --quick 的抽样结果，只在已探测的候选上验证过；\
         去掉 --quick 再跑一次可确认全部候选）"
    } else {
        ""
    };
    Check::new(
        "probe",
        Verdict::Fail,
        format!(
            "{} 个可达候选都取不到测速资产（{asset}）：它们会被判为「未通过实测」，\
             导致下载全部 502{qualifier}。确认该资产仍存在（它绑着具体 release，上游删掉即失效），\
             或用配置项 health.probeUrl 换成你自己的稳定资产",
            outcomes.len()
        ),
    )
}

/// 候选整体可用性。
///
/// 全挂时**不回退直连**（ADR-016），所以"一个都不可达"必须判 FAIL：
/// 此时下载一定会失败，用户不该等到装上才发现。
/// `probed` 是**实际探测过**的候选数：`--quick` 会提前收工，
/// 此时"可达/总数"会误导（44 个里探了 6 个、6 个都通，写成 "6/44 可达" 像是在说
/// 其余 38 个不通）。所以这种情况下改写成"X/Y 已探可达（共 N 个候选，其余未探）"。
fn check_chain(app: &App, reachable: usize, probed: usize) -> Check {
    let partial = probed < app.accels.len();
    if reachable == 0 {
        return Check::new(
            "chain",
            Verdict::Fail,
            format!(
                "{} 个候选全部不可达：下载会立即失败（不会回退直连，ADR-016）",
                app.accels.len()
            ),
        );
    }
    // 单点状态要警告——**两种来源都算**：配置里只有 1 个候选，或者候选很多但只有 1 个可达。
    //
    // 后者此前漏了：43 个候选里只有 1 个可达时报 `Pass`（详情 "1/43 个候选可达"），
    // 看起来"能下载"，但那一个一挂就全部 502，风险与单候选完全相同。
    // 而且"只剩 1 个可达"通常意味着网络只放行了个别服务、或上游清单大面积失效，
    // 恰恰是该让人注意的时候。
    if reachable < 2 {
        let reason = if app.accels.len() < 2 {
            "只有 1 个加速器候选".to_string()
        } else {
            format!("{reachable}/{} 个候选可达（单点）", app.accels.len())
        };
        return Check::new(
            "chain",
            Verdict::Warn,
            format!("{reason}：它一旦不可用，请求会快速返回 502（不会回退直连，ADR-016）"),
        );
    }
    let detail = if partial {
        format!(
            "{reachable}/{probed} 个已探测候选可达（共 {} 个候选，其余未探测；\
             完整结果请去掉 --quick 再跑一次）",
            app.accels.len()
        )
    } else {
        format!("{reachable}/{} 个候选可达", app.accels.len())
    };
    Check::new("chain", Verdict::Pass, detail)
}

/// 按**显示宽度**补空格。
///
/// 控制台里 CJK 占两列，而 `{:<10}` 只按字符数补——直接用会让表头比数据行短一截
/// （实测 `检查项` 后面差 3 列，表格看起来是歪的）。这里把非 ASCII 记 2 列。
fn pad_display(text: &str, width: usize) -> String {
    let used: usize = text
        .chars()
        .map(|ch| if ch.is_ascii() { 1 } else { 2 })
        .sum();
    let mut out = text.to_string();
    out.push_str(&" ".repeat(width.saturating_sub(used)));
    out
}

/// `--doctor` 的抬头：先给出"这是哪台机器上的哪个版本、日志在哪"。
///
/// 为什么需要：QUICKSTART 让用户"把 `--doctor` 的输出发出来"排障，而此前的输出里
/// **没有版本号、也没有日志路径**——恰恰是接手排查时最先要问的两件事。
/// 抬头做成纯函数便于单测（打印本身没有逻辑）。
fn header_lines(app: &App) -> Vec<String> {
    vec![
        format!("winget-accel {}", env!("CARGO_PKG_VERSION")),
        format!("  listen   {}", app.listen),
        format!("  certs    {}", app.cert_dir.display()),
        format!("  log      {}", app.log_path.display()),
        format!(
            "  rewrite  {} 个 host：{}",
            app.rewrite_hosts.len(),
            app.rewrite_hosts.join(", ")
        ),
        format!("  accel    {} 个候选", app.accels.len()),
    ]
}

/// 打印抬头 + 表格。返回是否存在 FAIL。
pub fn print(app: &App, checks: &[Check]) -> bool {
    for line in header_lines(app) {
        println!("{line}");
    }
    println!();
    // 列宽与下面数据行的 `{:<10} {:<5} ` 对齐：名称 10 列、结论从第 11 列起。
    println!(
        "{}{}详情",
        pad_display("检查项", 11),
        pad_display("结论", 6)
    );
    println!("{}", "-".repeat(78));
    for check in checks {
        println!(
            "{:<10} {:<5} {}",
            check.name,
            check.verdict.tag(),
            check.detail
        );
    }
    println!();
    let mut failed = false;
    for check in checks {
        if check.verdict == Verdict::Fail {
            failed = true;
            println!("失败项: {}", check.name);
        }
    }
    if !failed {
        println!("全部通过。");
        println!();
        println!("提示：若 PAC/CA 检查失败，先启动一次代理完成初始化。");
    }
    failed
}

/// 供测试用：不依赖真实网络。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AcceleratorCfg, App, FileConfig};

    fn app() -> App {
        let file = FileConfig {
            accelerators: vec![AcceleratorCfg {
                name: "test".into(),
                template: "https://test.example".into(),
                priority: 1,
                hosts: Vec::new(),
            }],
            cert_dir: Some(std::path::PathBuf::from("doctor-test-certs")),
            log_path: Some(std::path::PathBuf::from("doctor-test.log")),
            ..Default::default()
        };
        App::new(file).unwrap()
    }

    #[test]
    fn pac_text_contains_configured_hosts() {
        assert!(pac_text_issue(&app()).is_none());
    }

    #[test]
    fn pac_registry_match_is_pass() {
        let expected = "http://127.0.0.1:8443/winget-accel.pac";
        let (verdict, _) = pac_registry_detail(expected, Some(expected));
        assert_eq!(verdict, Verdict::Pass);
    }

    #[test]
    fn pac_registry_missing_or_different_is_fail() {
        let expected = "http://127.0.0.1:8443/winget-accel.pac";
        assert_eq!(pac_registry_detail(expected, None).0, Verdict::Fail);
        assert_eq!(
            pac_registry_detail(expected, Some("http://127.0.0.1:9999/x.pac")).0,
            Verdict::Fail
        );
    }

    #[test]
    fn missing_ca_is_a_failure() {
        let app = app();
        let check = check_ca(&app);
        assert_eq!(check.verdict, Verdict::Fail);
        assert!(check.detail.contains("不存在"));
    }

    #[test]
    fn single_candidate_warns_about_single_point() {
        // 默认配置现在内置 5 个候选，这里显式造一个单候选的配置
        let file = FileConfig {
            accelerators: vec![AcceleratorCfg {
                name: "only".into(),
                template: "https://only.example".into(),
                priority: 1,
                hosts: Vec::new(),
            }],
            ..Default::default()
        };
        let app = App::new(file).unwrap();
        assert_eq!(app.accels.len(), 1);
        let check = check_chain(&app, 1, app.accels.len());
        assert_eq!(check.verdict, Verdict::Warn);
        assert!(check.detail.contains("1 个加速器候选"));
    }

    #[test]
    fn multiple_candidates_have_a_fallback_chain() {
        let file = FileConfig {
            accelerators: vec![
                AcceleratorCfg {
                    name: "a".into(),
                    template: "https://a.example".into(),
                    priority: 1,
                    hosts: Vec::new(),
                },
                AcceleratorCfg {
                    name: "b".into(),
                    template: "https://b.example".into(),
                    priority: 2,
                    hosts: Vec::new(),
                },
            ],
            ..Default::default()
        };
        let app = App::new(file).unwrap();
        assert_eq!(app.accels.len(), 2);
        assert_eq!(
            check_chain(&app, app.accels.len(), app.accels.len()).verdict,
            Verdict::Pass
        );
    }

    #[test]
    fn all_candidates_down_is_a_failure() {
        let app = app();
        let check = check_chain(&app, 0, app.accels.len());
        assert_eq!(check.verdict, Verdict::Fail);
        assert!(check.detail.contains("全部不可达"));
    }

    #[test]
    fn multi_candidate_all_reachable_passes() {
        let file = FileConfig {
            accelerators: vec![
                AcceleratorCfg {
                    name: "a".into(),
                    template: "https://a.example".into(),
                    priority: 1,
                    hosts: Vec::new(),
                },
                AcceleratorCfg {
                    name: "b".into(),
                    template: "https://b.example".into(),
                    priority: 2,
                    hosts: Vec::new(),
                },
            ],
            ..Default::default()
        };
        let app = App::new(file).unwrap();
        let check = check_chain(&app, 2, app.accels.len());
        assert_eq!(check.verdict, Verdict::Pass);
        assert!(check.detail.contains("2/2"));
    }
    /// 配了很多候选、却只有 1 个可达时，必须**警告**——那是单点状态。
    ///
    /// 此前这种情形报 `Pass`（详情写 "1/43 个候选可达"）：可达数是 1，看起来"能下载"，
    /// 但那一个一挂就全部 502，风险与"配置里只有 1 个候选"完全相同，却没有提示。
    /// 43 个候选里只剩 1 个通常是"网络只放行了个别服务"或"上游清单大面积失效"，
    /// 正是该让人注意的时候。
    /// `--quick` 提前收工时，chain 的文案不能写成 "6/44 个候选可达"。
    ///
    /// 实测踩过：44 个候选只探了 6 个（都通），结论写成 "6/44 个候选可达"，
    /// 读起来像"其余 38 个不通"。必须区分"已探测"与"总数"。
    #[test]
    fn partial_probe_says_probed_not_total() {
        let file = FileConfig {
            accelerators: (0..10)
                .map(|i| AcceleratorCfg {
                    name: format!("a{i}"),
                    template: format!("https://a{i}.example"),
                    priority: i + 1,
                    hosts: Vec::new(),
                })
                .collect(),
            ..Default::default()
        };
        let app = App::new(file).unwrap();
        let check = check_chain(&app, 3, 3);
        assert_eq!(check.verdict, Verdict::Pass);
        assert!(
            check.detail.contains("3/3 个已探测"),
            "应写清只探了 3 个: {}",
            check.detail
        );
        assert!(
            check.detail.contains("共 10 个候选"),
            "应给出总候选数: {}",
            check.detail
        );
        assert!(
            !check.detail.starts_with("3/10"),
            "不能把未探的算成不可达: {}",
            check.detail
        );

        // 全量探测时仍用原来的 "N/M 个候选可达"
        let full = check_chain(&app, 10, 10);
        assert!(full.detail.contains("10/10 个候选可达"), "{}", full.detail);
    }

    #[test]
    fn only_one_reachable_out_of_many_warns_about_single_point() {
        let file = FileConfig {
            accelerators: vec![
                AcceleratorCfg {
                    name: "a".into(),
                    template: "https://a.example".into(),
                    priority: 1,
                    hosts: Vec::new(),
                },
                AcceleratorCfg {
                    name: "b".into(),
                    template: "https://b.example".into(),
                    priority: 2,
                    hosts: Vec::new(),
                },
                AcceleratorCfg {
                    name: "c".into(),
                    template: "https://c.example".into(),
                    priority: 3,
                    hosts: Vec::new(),
                },
            ],
            ..Default::default()
        };
        let app = App::new(file).unwrap();
        let check = check_chain(&app, 1, app.accels.len());
        assert_eq!(
            check.verdict,
            Verdict::Warn,
            "多候选中只剩 1 个可达是单点状态，不该报 Pass: {}",
            check.detail
        );
        assert!(check.detail.contains("1/3"), "应写清 1/3: {}", check.detail);
        assert!(
            check.detail.contains("单点") || check.detail.contains("一旦"),
            "应说明风险: {}",
            check.detail
        );
    }

    #[test]
    fn ca_residue_only_warns_when_more_than_one_is_trusted() {
        assert!(residue_check(0).is_none(), "一张都没有：不该多报一行");
        assert!(residue_check(1).is_none(), "正常情况只有一张");
        let check = residue_check(2).expect("两张应告警");
        assert_eq!(check.name, "ca-extra");
        assert_eq!(check.verdict, Verdict::Warn, "残留不阻塞退出码");
        assert!(check.detail.contains("2 张"), "{}", check.detail);
        assert!(check.detail.contains("--remove-ca"), "必须给出可执行命令");
    }

    #[test]
    fn verdict_tags_are_fixed_width() {
        assert_eq!(Verdict::Pass.tag().len(), 4);
        assert_eq!(Verdict::Fail.tag().len(), 4);
    }

    #[test]
    fn caps_check_only_appears_when_matrix_is_configured() {
        // 未声明 hosts：不输出 caps 行（保持表格简洁）
        let file = FileConfig {
            accelerators: vec![AcceleratorCfg {
                name: "a".into(),
                template: "https://a.example".into(),
                priority: 1,
                hosts: Vec::new(),
            }],
            ..Default::default()
        };
        let app = App::new(file).unwrap();
        assert!(check_caps(&app).is_none());

        // 声明了 hosts：输出一行，列出候选与其支持的 host
        let file = FileConfig {
            accelerators: vec![AcceleratorCfg {
                name: "a".into(),
                template: "https://a.example".into(),
                priority: 1,
                hosts: vec!["github.com".into()],
            }],
            ..Default::default()
        };
        let app = App::new(file).unwrap();
        let check = check_caps(&app).expect("应输出能力矩阵检查项");
        assert_eq!(check.name, "caps");
        assert!(
            check.detail.contains("a.example: github.com"),
            "{}",
            check.detail
        );
    }

    /// 测速资产失效是"chain 全 OK 但下载全 502"的唯一来源，必须能被单独查出。
    #[test]
    fn probe_asset_passes_if_any_candidate_can_fetch_it() {
        let outcomes = vec![
            ("a.example".to_string(), None),
            ("b.example".to_string(), Some(123.4)),
        ];
        let check = probe_asset_verdict("https://x/y.bin", &outcomes, false);
        assert_eq!(check.name, "probe");
        assert_eq!(check.verdict, Verdict::Pass);
        assert!(check.detail.contains("b.example"), "{}", check.detail);
        assert!(check.detail.contains("123 KB/s"), "{}", check.detail);
    }

    /// `--quick` 抽样时，probe 判 FAIL 的措辞必须说明"只验证了部分候选"。
    ///
    /// 否则会变成假警报：quick 只探 6 个候选，若这 6 个恰好都取不到资产，
    /// 文案断言"下载全部 502"就过头了——真实情况可能是其余 38 个里有能取到的。
    #[test]
    fn probe_fail_says_it_was_a_sample() {
        let outcomes = vec![
            ("a.example".to_string(), None),
            ("b.example".to_string(), None),
        ];

        let full = probe_asset_verdict("https://x/y.bin", &outcomes, false);
        assert_eq!(full.verdict, Verdict::Fail);
        assert!(
            !full.detail.contains("--quick"),
            "全量探测时不该提 --quick: {}",
            full.detail
        );

        let sampled = probe_asset_verdict("https://x/y.bin", &outcomes, true);
        assert_eq!(sampled.verdict, Verdict::Fail);
        assert!(
            sampled.detail.contains("--quick") && sampled.detail.contains("抽样"),
            "抽样时必须说明这是抽样结果: {}",
            sampled.detail
        );
        assert!(
            sampled.detail.contains("去掉 --quick"),
            "应给出复核方式: {}",
            sampled.detail
        );
    }
    #[test]
    fn probe_asset_fail_names_the_asset_and_the_override() {
        let outcomes = vec![
            ("a.example".to_string(), None),
            ("b.example".to_string(), None),
        ];
        let check = probe_asset_verdict("https://x/y.bin", &outcomes, false);
        assert_eq!(check.verdict, Verdict::Fail);
        // 用户需要三件事：后果、当前资产、可执行的改法
        assert!(check.detail.contains("502"), "{}", check.detail);
        assert!(check.detail.contains("https://x/y.bin"), "{}", check.detail);
        assert!(
            check.detail.contains("health.probeUrl"),
            "必须给出可执行的改法: {}",
            check.detail
        );
    }

    #[test]
    fn probe_asset_check_is_skipped_without_reachable_candidate() {
        // 没有可达候选时 chain 已经 FAIL，再花 3×5 秒重复结论只是噪音
        let app = app();
        assert_eq!(app.accels.len(), 1);
        assert!(check_probe_asset(&app, &app.accels, &[false], false).is_none());
    }

    /// 表头必须与数据行同宽：CJK 在控制台占两列，按字符数补空格会错位。
    ///
    /// 实测过一次：`{:<10}` 补 "检查项"（3 个汉字 = 6 列）会补出 13 列的宽度，
    /// 表格看起来整体歪掉。这里把"按显示宽度补"钉住。
    #[test]
    fn header_padding_uses_display_width_not_char_count() {
        let width = |text: &str| -> usize {
            text.chars()
                .map(|ch| if ch.is_ascii() { 1 } else { 2 })
                .sum()
        };
        // 数据行是 `{:<10} {:<5} `：名称 10 列 + 1 空格，结论从第 11 列起
        assert_eq!(width(&pad_display("检查项", 11)), 11);
        // 结论列 5 列宽 + 1 空格，详情从第 17 列起
        assert_eq!(width(&pad_display("结论", 6)), 6);
        // ASCII 不受影响，与 `{:<10}` 等价
        assert_eq!(pad_display("chain", 10), "chain     ");
        // 超宽时不截断（宁可错位，也不要吃掉列名）
        assert_eq!(pad_display("accel-extra", 10), "accel-extra");
    }

    /// 抬头必须包含接手排查最先要问的两件事：版本、日志路径。
    ///
    /// QUICKSTART 让用户把 `--doctor` 输出发出来，而此前那份输出里两者都没有。
    #[test]
    fn header_lists_version_paths_and_scope() {
        let app = app();
        let lines = header_lines(&app).join("\n");
        assert!(
            lines.contains(&format!("winget-accel {}", env!("CARGO_PKG_VERSION"))),
            "{lines}"
        );
        assert!(lines.contains("log      "), "必须给出日志路径: {lines}");
        assert!(
            lines.contains(&app.log_path.display().to_string()),
            "{lines}"
        );
        assert!(lines.contains("certs    "), "必须给出证书目录: {lines}");
        assert!(lines.contains("rewrite  "), "必须给出改写范围: {lines}");
        assert!(lines.contains("accel    "), "必须给出候选数: {lines}");
        assert!(lines.contains("github.com"), "应列出 host: {lines}");
    }

    /// 全局代理是"装了没效果"时第一个要排除的变量：必须能在 doctor 里看到。
    #[test]
    fn global_proxy_state_is_reported() {
        let clean = global_proxy_verdict(Some(false));
        assert_eq!(clean.name, "proxyenv");
        assert_eq!(clean.verdict, Verdict::Pass);
        assert!(clean.detail.contains("ProxyEnable=0"), "{}", clean.detail);

        let on = global_proxy_verdict(Some(true));
        assert_eq!(on.verdict, Verdict::Warn, "开着全局代理不该阻断退出码");
        assert!(on.detail.contains("未验证"), "{}", on.detail);
        assert!(
            on.detail.contains("关掉全局代理"),
            "必须给出可执行的建议: {}",
            on.detail
        );

        // 读不出来要说清是"读不出来"，不能假装成"没开"
        let unknown = global_proxy_verdict(None);
        assert_eq!(unknown.verdict, Verdict::Warn);
        assert!(unknown.detail.contains("读不到"), "{}", unknown.detail);
    }

    /// 以**证书本身**为准核对授权域名：meta 缺失时也能判断 CA 还能不能签。
    #[test]
    fn constraints_are_checked_against_the_certificate_not_the_meta_file() {
        use crate::ca::CertAuthority;

        let dir = std::env::temp_dir().join(format!("wg-doc-nc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hosts = vec!["github.com".to_string()];
        CertAuthority::load_or_create(&dir, &hosts).unwrap();
        let pem = CertAuthority::ca_pem_path(&dir);

        // 一致 → 通过
        assert!(matches!(
            ConstraintsCheck::run(&pem, &["github.com".to_string()]),
            ConstraintsVerdict::Matches
        ));
        // 大小写不同也算一致（不因大小写把人引去重建 CA）
        assert!(matches!(
            ConstraintsCheck::run(&pem, &["GitHub.COM".to_string()]),
            ConstraintsVerdict::Matches
        ));

        // 配置多了一个 host → 必须报不一致，并说清后果与改法
        let changed = vec!["github.com".to_string(), "codeload.github.com".to_string()];
        match ConstraintsCheck::run(&pem, &changed) {
            ConstraintsVerdict::Mismatch(detail) => {
                assert!(detail.contains("Name Constraints"), "{detail}");
                assert!(detail.contains("删除证书目录"), "{detail}");
            }
            _ => panic!("配置变了却没报不一致"),
        }

        // 文件不存在 → 读不出（不能静默算通过）
        assert!(matches!(
            ConstraintsCheck::run(&dir.join("nope.pem"), &hosts),
            ConstraintsVerdict::Unreadable(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 改了配置没重启代理时，注册表看起来正常、实际生效的还是旧 PAC。
    #[test]
    fn live_pac_mismatch_is_reported_as_warning() {
        let expected = "function FindProxyForURL(url, host) { ... github.com ... }";

        // 没有实例：不算错，但要说明"没核对成"
        let (verdict, note) = pac_live_verdict(expected, None);
        assert_eq!(verdict, Verdict::Pass);
        assert!(note.contains("没有实例"), "{note}");

        // 一致
        let (verdict, note) = pac_live_verdict(expected, Some(expected));
        assert_eq!(verdict, Verdict::Pass);
        assert!(note.contains("一致"), "{note}");

        // 不一致：WARN（不阻断退出码），且必须说清"重启后生效"
        let stale = "function FindProxyForURL(url, host) { ... 旧配置 ... }";
        let (verdict, note) = pac_live_verdict(expected, Some(stale));
        assert_eq!(verdict, Verdict::Warn);
        assert!(note.contains("重启"), "必须给出可执行的建议: {note}");
    }

    /// 真的连一个本机"代理"把 PAC 取回来：证明 `fetch_pac_text` 的分帧解析可用。
    ///
    /// 不依赖系统状态、不依赖外网——起一个只说一次话的 TCP 服务即可。
    #[test]
    fn fetch_pac_text_reads_body_of_a_local_server() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        const PAC: &str = "function FindProxyForURL(url, host) { return \"DIRECT\"; }\n";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{PAC}",
                PAC.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });

        let got = fetch_pac_text(port).expect("应能取到 PAC 正文");
        assert_eq!(got, PAC, "应只返回正文，不含响应头");

        // 没人在监听 → None（doctor 据此说明"未能核对"）
        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        assert!(fetch_pac_text(closed).is_none());
        server.join().unwrap();
    }
}
