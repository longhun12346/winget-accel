//! 配置与启动参数。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::rewrite::{parse_accel, Accel};

/// 默认改写范围（ADR-014 约束 2 的落地：只有这 4 个 host 会被终止 TLS）。
pub const DEFAULT_REWRITE_HOSTS: [&str; 4] = [
    "github.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "release-assets.githubusercontent.com",
];

const DEFAULT_LISTEN: &str = "127.0.0.1:8443";
const DEFAULT_ACCEL: &str = "https://gh-proxy.com";

/// 内置候选链（按多次实测中位数排序，2026-11-01）。
///
/// 刻意内置多个：即使不写配置文件，也不能只有一个候选——
/// 那个单点一挂，功能就整体不可用（不回退直连，ADR-016）。
#[derive(Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct FileConfig {
    pub listen: String,
    pub rewrite_hosts: Vec<String>,
    pub accelerators: Vec<AcceleratorCfg>,
    pub health: HealthCfg,
    pub routing: RoutingCfg,
    pub log_level: String,
    /// 可选：自定义证书目录。默认是 exe 同目录下的 `certs`。
    pub cert_dir: Option<PathBuf>,
    /// 可选：自定义日志文件。默认是 exe 同目录下的 `proxy.log`。
    pub log_path: Option<PathBuf>,
    /// 额外终止 TLS 但不改写的 host，仅用于 Name Constraints 等排障。
    pub mitm_extra: Vec<String>,
    /// 是否把 winget 的下载器钉成 WinINet（见 src/winget.rs 与 ADR-017）。
    ///
    /// 默认开启：Delivery Optimization 不读 PAC，受限网络可能先等待一次
    /// 直连失败；WinINet 能遵循自动路由的 DIRECT / PROXY 决策。
    pub winget_downloader: bool,
}
impl Default for FileConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN.to_string(),
            rewrite_hosts: DEFAULT_REWRITE_HOSTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            accelerators: Vec::new(),
            health: HealthCfg::default(),
            routing: RoutingCfg::default(),
            log_level: "info".into(),
            cert_dir: None,
            log_path: None,
            mitm_extra: Vec::new(),
            winget_downloader: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceleratorCfg {
    /// 便于人读配置；日志与 doctor 后续会用它代替裸 URL。
    #[allow(dead_code)]
    pub name: String,
    /// 完整基地址，如 `https://gh-proxy.com`。路径前缀由改写逻辑拼接。
    pub template: String,
    #[serde(default)]
    pub priority: u32,
    /// 该候选**支持**的 host（能力矩阵，design.md §7）。
    ///
    /// 空 = 未声明，按"全部 `rewriteHosts` 都支持"处理（保持既有行为）；
    /// 非空时，只有列在这里的 host 才会被改写给它，其余 host 会换下一个候选。
    /// 不同加速器对 host 的支持并不一致，而实测数据必须逐个验，不能猜。
    #[serde(default)]
    pub hosts: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HealthCfg {
    pub enabled: bool,
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub failures_before_unhealthy: u32,
    /// 测速用的基准资产（完整 https URL）。`None` 用编译期内置默认值。
    ///
    /// 为什么可配：默认值绑着一个具体 release 资产，上游删了它就会导致
    /// 所有候选"测速失败"，最终全站 502。留一个可覆盖的入口比写死更可控。
    pub probe_url: Option<String>,
}

impl Default for HealthCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: 300,
            timeout_seconds: 8,
            failures_before_unhealthy: 2,
            probe_url: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    Auto,
    Accelerator,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RoutingCfg {
    pub mode: RoutingMode,
    pub min_direct_kbps: u32,
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub cooldown_seconds: u64,
    /// Empty uses a release installer and a codeload archive. Redirect targets
    /// qualify only when observed in both successful samples.
    pub probe_urls: Vec<String>,
}

impl Default for RoutingCfg {
    fn default() -> Self {
        Self {
            mode: RoutingMode::Auto,
            min_direct_kbps: 512,
            interval_seconds: 300,
            timeout_seconds: 5,
            cooldown_seconds: 300,
            probe_urls: Vec::new(),
        }
    }
}

/// 运行期配置：文件配置 + 命令行覆盖。
#[derive(Debug)]
pub struct App {
    pub listen: SocketAddr,
    pub rewrite_hosts: Vec<String>,
    /// 按 priority 升序排列的加速器候选（回退链）。
    pub accels: Vec<Accel>,
    /// 与 `accels` 同下标的能力矩阵：每个候选声明支持的 host（空 = 全部）。
    pub caps: Vec<Vec<String>>,

    pub cert_dir: PathBuf,
    pub log_path: PathBuf,
    /// 额外拦截但不改写的 host（只用于验证 Name Constraints 与排障）。
    pub mitm_extra: Vec<String>,
    /// 启动时是否接管 winget 的下载器设置（退出时还原）。
    pub winget_downloader: bool,
    pub health_enabled: bool,
    pub health_interval: Duration,
    pub health_timeout: Duration,
    /// 连续失败多少次判定为不健康。
    pub health_failures: u32,
    /// 测速基准资产（完整 URL，已校验为 https）。
    pub health_probe: String,
    /// 是否用了自定义测速资产（在"全部候选失败"时据此给出针对性提示）。
    pub health_probe_custom: bool,
    pub routing: RoutingCfg,
}

impl App {
    pub fn new(file: FileConfig) -> Result<Self> {
        let listen_spec = file.listen;
        let listen: SocketAddr = listen_spec
            .parse()
            .with_context(|| format!("listen 不是合法的 host:port: {listen_spec:?}"))?;

        // 代理会终止 TLS，绝不能监听非回环地址。
        if !listen.ip().is_loopback() {
            bail!("listen 必须是回环地址（如 127.0.0.1:8443），当前为 {listen}");
        }
        // 端口 0 会让系统分配一个临时端口，但 PAC 与 `AutoConfigURL` 里拼的是**配置里的
        // 端口**，于是会写出 `http://127.0.0.1:0/winget-accel.pac`——谁连都连不上，
        // 而启动日志照样打印「已就绪」（实测复现）。这种配置不可能有意义，直接拒绝。
        if listen.port() == 0 {
            bail!(
                "listen 的端口不能是 0（{listen}）：端口 0 会让系统随机分配，\
                 但 PAC 里写的仍是 0，最终没有任何请求能连上。请写一个固定端口（如 127.0.0.1:8443）"
            );
        }
        // PAC 里的 `PROXY` 指令与 AutoConfigURL 都用 IPv4 字面量拼出
        // （`PROXY 127.0.0.1:<port>`）。允许 `[::1]` 或 127.0.0.2 会生成不可用的 PAC，
        // 且失败表现为"完全没有加速"，极难排查——所以直接拒绝，而不是静默降级。
        if listen.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) {
            bail!(
                "listen 只支持 127.0.0.1（如 127.0.0.1:8443）：\
                 PAC 的 PROXY 指令与 AutoConfigURL 都使用该地址，当前为 {listen}"
            );
        }

        let rewrite_hosts = if file.rewrite_hosts.is_empty() {
            DEFAULT_REWRITE_HOSTS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            file.rewrite_hosts
        };
        // 逐个校验改写白名单。
        //
        // 这些条目会被**原样**写进 PAC 的 `host == "…"` 精确比较里，
        // 所以任何"看起来像通配/像 URL"的写法都不会命中——而且不会有任何报错，
        // 用户只会看到"某个域名没被加速"。实测过 `*.github.com` 会被接受并生成
        // `host == "*.github.com"`（永远匹配不到），启动日志却照样把它列出来。
        for host in &rewrite_hosts {
            let trimmed = host.trim();
            if trimmed.is_empty() {
                bail!("rewriteHosts 里不能有空条目（请删掉空字符串）");
            }
            if trimmed.contains('*') || trimmed.contains('?') {
                bail!(
                    "rewriteHosts 不支持通配符：{trimmed:?}。请写精确的主机名（如 github.com）；\
                     github.com 的子域（api.github.com 等）已自动转入隧道，不需要另外声明"
                );
            }
            if trimmed.contains("://") || trimmed.contains('/') {
                bail!("rewriteHosts 只接受主机名，不要带协议或路径：{trimmed:?}（如 github.com）");
            }
            if trimmed.contains(':') {
                bail!("rewriteHosts 只接受主机名，不要带端口：{trimmed:?}（如 github.com）");
            }
        }
        let mut rewrite_hosts: Vec<String> = rewrite_hosts
            .into_iter()
            .map(|host| host.trim().to_ascii_lowercase())
            .collect();
        let mut seen_hosts = std::collections::HashSet::new();
        rewrite_hosts.retain(|host| seen_hosts.insert(host.clone()));

        let mut items = if file.accelerators.is_empty() {
            default_accelerators()
        } else {
            file.accelerators
        };
        items.sort_by_key(|a| a.priority);
        let mut accels = Vec::with_capacity(items.len());
        let mut caps = Vec::with_capacity(items.len());
        for item in &items {
            accels.push(parse_accel(&item.template)?);
            caps.push(item.hosts.clone());
        }
        if accels.is_empty() {
            accels.push(parse_accel(DEFAULT_ACCEL)?);
            caps.push(Vec::new());
        }

        let mut health_probe_custom = false;
        let health_probe = match file.health.probe_url.as_deref() {
            Some(url) if !url.trim().is_empty() => {
                let url = url.trim().to_string();
                if crate::proxy::split_asset(&url).is_none() {
                    bail!("health.probeUrl 必须是完整 https URL（如 https://host/path），当前为 {url:?}");
                }
                health_probe_custom = true;
                url
            }
            _ => crate::proxy::DEFAULT_PROBE_ASSET.to_string(),
        };

        if file.routing.min_direct_kbps == 0
            || !(1..=30).contains(&file.routing.timeout_seconds)
            || !(60..=86_400).contains(&file.routing.interval_seconds)
            || !(60..=86_400).contains(&file.routing.cooldown_seconds)
            || file.routing.probe_urls.len() > 8
        {
            bail!("routing 要求 minDirectKbps > 0、timeoutSeconds 为 1–30、intervalSeconds/cooldownSeconds 为 60–86400，probeUrls 最多 8 条");
        }
        for url in &file.routing.probe_urls {
            let uri: hyper::Uri = url.parse().context("routing.probeUrls URL 非法")?;
            if uri.scheme_str() != Some("https")
                || uri
                    .authority()
                    .is_some_and(|a| a.as_str() != a.host() && uri.port_u16() != Some(443))
                || !uri
                    .host()
                    .is_some_and(|host| rewrite_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)))
                || uri.authority().is_some_and(|a| a.as_str().contains('@'))
                || uri.path() == "/"
            {
                bail!("routing.probeUrls 必须是 rewriteHosts 内域名的 HTTPS 下载 URL（443 端口）: {url}");
            }
        }

        Ok(Self {
            listen,
            rewrite_hosts,
            accels,
            caps,
            cert_dir: file.cert_dir.unwrap_or_else(|| exe_dir().join("certs")),
            log_path: file.log_path.unwrap_or_else(|| exe_dir().join("proxy.log")),
            mitm_extra: file
                .mitm_extra
                .into_iter()
                .map(|host| host.trim().to_ascii_lowercase())
                .collect(),
            winget_downloader: file.winget_downloader,
            health_enabled: file.health.enabled,
            health_interval: Duration::from_secs(file.health.interval_seconds.max(60)),
            health_timeout: Duration::from_secs(file.health.timeout_seconds.max(1)),
            health_failures: file.health.failures_before_unhealthy.max(1),
            health_probe,
            health_probe_custom,
            routing: file.routing,
        })
    }

    /// 该 host 是否要被终止 TLS 并改写。
    ///
    /// 用**大小写不敏感**的比较：DNS 名字本身大小写不敏感（RFC 4343），
    /// 而 PAC 里也是 `host.toLowerCase()` 之后匹配。曾经这里用 `==`，
    /// 于是客户端发 `CONNECT GitHub.COM:443` 时 PAC 照样把流量导过来、
    /// 分流却判成 TUNNEL——那条下载完全没有被加速，而且日志里看着"一切正常"。
    pub fn should_rewrite(&self, host: &str) -> bool {
        self.rewrite_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
    }

    /// 该 host 是否要终止 TLS（改写 + 额外的排障 host）。
    pub fn should_mitm(&self, host: &str) -> bool {
        self.should_rewrite(host) || self.mitm_extra.iter().any(|h| h.eq_ignore_ascii_case(host))
    }

    /// 第 `idx` 个候选是否声明支持该 host（能力矩阵，见 design.md §7）。
    ///
    /// 未声明（空列表）= 不限制，保持历史行为；声明了就是硬约束——
    /// 不支持的组合不得改写，由调用方换下一个候选。
    pub fn accel_supports(&self, idx: usize, host: &str) -> bool {
        match self.caps.get(idx) {
            // 同上：host 比较大小写不敏感，否则配置里写 `GitHub.com` 会让矩阵静默失效
            Some(hosts) if !hosts.is_empty() => hosts.iter().any(|h| h.eq_ignore_ascii_case(host)),
            _ => true,
        }
    }

    /// 有没有任何候选声明了能力限制（doctor 用来判断要不要提示）。
    pub fn has_capability_limits(&self) -> bool {
        self.caps.iter().any(|hosts| !hosts.is_empty())
    }
}

/// exe 所在目录。默认证书/日志按绿色版约定放在 exe 旁边。
fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}
/// 读配置文件；路径不存在时用默认值。
///
/// 同时返回"不认识的键"——注意**不要在这里打日志**：调用时 `Logger` 还没建
/// （日志路径本身来自配置），此时 `log::warn` 只会落到控制台、进不了 `proxy.log`。
/// 由 main 在建好 logger 之后统一告警，才查得到。
pub fn load(path: Option<&PathBuf>) -> Result<(FileConfig, Vec<String>)> {
    let Some(path) = path else {
        return Ok((FileConfig::default(), Vec::new()));
    };
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("读不到配置文件: {}", path.display()))?;
    // 示例配置里带 $comment 键，serde 默认忽略未知键——
    // 但"忽略未知键"也意味着**拼错一个键名就静默失效**（写 `rewriteHost` 会悄悄用默认值）。
    let unknown = serde_json::from_str::<serde_json::Value>(&text)
        .map(|doc| unknown_config_keys(&doc))
        .unwrap_or_default();
    let config = serde_json::from_str(&text)
        .with_context(|| format!("配置文件不是合法 JSON: {}", path.display()))?;
    Ok((config, unknown))
}

/// 顶层配置项（与 `FileConfig` 的字段一一对应）。
const TOP_KEYS: [&str; 10] = [
    "listen",
    "rewriteHosts",
    "accelerators",
    "health",
    "routing",
    "logLevel",
    "certDir",
    "logPath",
    "mitmExtra",
    "wingetDownloader",
];
const HEALTH_KEYS: [&str; 5] = [
    "enabled",
    "intervalSeconds",
    "timeoutSeconds",
    "failuresBeforeUnhealthy",
    "probeUrl",
];
const ACCEL_KEYS: [&str; 4] = ["name", "template", "priority", "hosts"];
const ROUTING_KEYS: [&str; 6] = [
    "mode",
    "minDirectKbps",
    "intervalSeconds",
    "timeoutSeconds",
    "cooldownSeconds",
    "probeUrls",
];

/// 找出配置里不认识的键（以 `$` 开头的是注释性键，允许存在）。
///
/// 只看三层：顶层、`health`、`accelerators[]`——这三处是用户真正会手改的地方。
pub fn unknown_config_keys(doc: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(top) = doc.as_object() else {
        return out;
    };
    collect_unknown(top, "", &TOP_KEYS, &mut out);
    if let Some(routing) = top.get("routing").and_then(|value| value.as_object()) {
        collect_unknown(routing, "routing.", &ROUTING_KEYS, &mut out);
    }
    if let Some(health) = top.get("health").and_then(|value| value.as_object()) {
        collect_unknown(health, "health.", &HEALTH_KEYS, &mut out);
    }
    if let Some(list) = top.get("accelerators").and_then(|value| value.as_array()) {
        for (index, item) in list.iter().enumerate() {
            if let Some(item) = item.as_object() {
                collect_unknown(
                    item,
                    &format!("accelerators[{index}]."),
                    &ACCEL_KEYS,
                    &mut out,
                );
            }
        }
    }
    out
}

fn collect_unknown(
    object: &serde_json::Map<String, serde_json::Value>,
    prefix: &str,
    known: &[&str],
    out: &mut Vec<String>,
) {
    for key in object.keys() {
        if key.starts_with('$') || known.contains(&key.as_str()) {
            continue;
        }
        out.push(format!("{prefix}{key}"));
    }
}

/// 默认候选：仓库清单（`candidates.json`）+ 编译期内置，按 host 去重。
///
/// 为什么两者都要：清单是"可维护、可被 CI 更新"的那份，内置是"清单被写坏/删掉
/// 也还能启动"的兜底。合并顺序保持清单在前，这样优先级沿用清单顺序。
fn default_accelerators() -> Vec<AcceleratorCfg> {
    let mut out: Vec<AcceleratorCfg> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    let push = |name: &str,
                template: &str,
                priority: u32,
                out: &mut Vec<AcceleratorCfg>,
                seen: &mut Vec<String>| {
        // 按 host 去重：同一站点用不同路径前缀没必要占两个名额
        let probe = crate::candidates::Candidate {
            name: name.to_string(),
            template: template.to_string(),
            builtin: false,
        };
        let host = probe.host().unwrap_or(template).to_string();
        if seen.iter().any(|h| h == &host) {
            return;
        }
        seen.push(host);
        out.push(AcceleratorCfg {
            name: name.to_string(),
            template: template.to_string(),
            priority,
            hosts: Vec::new(),
        });
    };

    let (from_file, source) = crate::candidates::load(&exe_dir(), true);
    for (i, c) in from_file.iter().enumerate() {
        push(&c.name, &c.template, i as u32 + 1, &mut out, &mut seen);
    }

    if from_file.is_empty() {
        // 清单损坏/为空：至少保证有一个候选能启动。
        // 此时不再有"内置 5 个"可退——候选清单就是唯一来源。
        crate::log::warn(&format!(
            "候选清单为空，回退到单一默认候选: {DEFAULT_ACCEL}"
        ));
        out.push(AcceleratorCfg {
            name: "fallback".to_string(),
            template: DEFAULT_ACCEL.to_string(),
            priority: 1,
            hosts: Vec::new(),
        });
    } else {
        crate::log::info(&format!(
            "候选清单来源: {source}（{} 条，合并内置后共 {} 个候选）",
            from_file.len(),
            out.len()
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_file(listen: &str) -> FileConfig {
        FileConfig {
            listen: listen.to_string(),
            rewrite_hosts: DEFAULT_REWRITE_HOSTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            accelerators: vec![AcceleratorCfg {
                name: "a".into(),
                template: "https://a.example/{url}".into(),
                priority: 1,
                hosts: Vec::new(),
            }],
            health: HealthCfg::default(),
            routing: RoutingCfg::default(),
            log_level: "info".into(),
            cert_dir: Some(PathBuf::from("certs-test")),
            log_path: Some(PathBuf::from("proxy-test.log")),
            mitm_extra: Vec::new(),
            winget_downloader: true,
        }
    }

    fn app(listen: &str) -> Result<App> {
        App::new(test_file(listen))
    }

    #[test]
    fn defaults_are_loopback_and_whitelisted() {
        let app = app("127.0.0.1:8443").unwrap();
        assert_eq!(app.listen.port(), 8443);
        assert_eq!(app.rewrite_hosts.len(), 4);
        assert!(app.should_rewrite("github.com"));
        assert!(!app.should_rewrite("api.github.com"));
    }

    #[test]
    fn rejects_non_loopback_listen() {
        assert!(app("0.0.0.0:8443").is_err());
        assert!(app("192.168.1.10:8443").is_err());
    }

    #[test]
    fn host_normalization_reaches_the_rewrite_plan() {
        let mut file = test_file("127.0.0.1:8443");
        file.rewrite_hosts = vec![" GITHUB.COM ".into(), "github.com".into()];
        file.mitm_extra = vec![" Example.COM ".into()];
        let app = App::new(file).unwrap();
        assert_eq!(app.rewrite_hosts, vec!["github.com"]);
        assert!(app.should_mitm("example.com"));
        let plan = crate::rewrite::plan_with(
            "GET",
            "github.com",
            443,
            "/a.zip",
            &hyper::HeaderMap::new(),
            &app.rewrite_hosts,
            &app.accels[0],
            true,
        );
        assert!(plan.rewritten);
        assert_eq!(plan.path, "/https://github.com/a.zip");
    }

    #[test]
    fn rejects_other_loopback_addresses_because_pac_uses_localhost() {
        // PAC 与 AutoConfigURL 都按 IPv4 字面量生成；放行 [::1] 会得到指向空气的 PAC，
        // 表现为"完全没有加速"且极难排查。所以这里必须显式拒绝，而不是静默降级。
        for listen in ["[::1]:8443", "127.0.0.2:8443"] {
            let err = app(listen).expect_err("应拒绝 PAC 未使用的回环地址");
            assert!(err.to_string().contains("127.0.0.1"), "实际错误: {err}");
        }
    }

    /// 端口 0 必须被拒：PAC 里拼的是配置端口，写 0 就永远连不上。
    ///
    /// 实测过：`listen: "127.0.0.1:0"` 会被接受、系统随机分配端口、日志打印
    /// `PAC http://127.0.0.1:0/winget-accel.pac` 并显示「已就绪」——
    /// 完全不可用却毫无报错。
    #[test]
    fn rejects_port_zero() {
        let err = app("127.0.0.1:0").expect_err("端口 0 应被拒绝");
        let text = err.to_string();
        assert!(text.contains("端口"), "报错应说明端口问题: {text}");
        assert!(text.contains('0'), "报错应提到 0: {text}");
    }

    /// rewriteHosts 里"看起来像通配/像 URL"的写法必须被**拒绝**，而不是静默失效。
    ///
    /// 这些条目会原样进入 PAC 的 `host == "…"` 精确比较，匹配不到也不报错。
    /// 实测过 `*.github.com` 会被接受、生成永远不命中的规则，启动日志却照样列出它。
    #[test]
    fn rejects_unusable_rewrite_host_entries() {
        let cases = [
            ("*.github.com", "通配符"),
            ("api.?.com", "通配符"),
            ("https://github.com", "协议"),
            ("github.com/releases", "路径"),
            ("github.com:443", "端口"),
            ("   ", "空条目"),
        ];
        for (host, why) in cases {
            let mut file = test_file("127.0.0.1:8443");
            file.rewrite_hosts = vec![host.to_string()];
            let err = App::new(file)
                .err()
                .unwrap_or_else(|| panic!("应拒绝 {host:?}（{why}）"));
            let text = err.to_string();
            assert!(
                text.contains("rewriteHosts"),
                "报错应指明是哪个字段（{host:?}）: {text}"
            );
        }

        // 正常的主机名仍然可以用（含子域与大小写）
        let mut file = test_file("127.0.0.1:8443");
        file.rewrite_hosts = vec!["github.com".into(), "API.GitHub.com".into()];
        assert!(App::new(file).is_ok(), "精确主机名应被接受");
    }

    #[test]
    fn capability_matrix_limits_candidates_per_host() {
        let mut file = test_file("127.0.0.1:8443");
        file.accelerators = vec![
            AcceleratorCfg {
                name: "only-github".into(),
                template: "https://a.example/{url}".into(),
                priority: 1,
                hosts: vec!["github.com".into()],
            },
            AcceleratorCfg {
                name: "everything".into(),
                template: "https://b.example/{url}".into(),
                priority: 2,
                hosts: Vec::new(),
            },
        ];
        let app = App::new(file).unwrap();
        assert!(app.has_capability_limits());
        assert!(app.accel_supports(0, "github.com"));
        assert!(
            !app.accel_supports(0, "codeload.github.com"),
            "未声明的 host 不得使用"
        );
        // 未声明 hosts 的候选不设限（空 = 全部），保持历史行为
        assert!(app.accel_supports(1, "codeload.github.com"));
    }

    #[test]
    fn probe_url_must_be_https_and_defaults_to_builtin() {
        let mut file = test_file("127.0.0.1:8443");
        file.health.probe_url = None;
        assert_eq!(
            App::new(file).unwrap().health_probe,
            crate::proxy::DEFAULT_PROBE_ASSET
        );

        let mut file = test_file("127.0.0.1:8443");
        file.health.probe_url = Some("http://example.com/x".into());
        assert!(App::new(file).is_err(), "非 https 的探测资产必须拒绝");

        let mut file = test_file("127.0.0.1:8443");
        file.health.probe_url = Some("https://example.com/asset.bin".into());
        assert_eq!(
            App::new(file).unwrap().health_probe,
            "https://example.com/asset.bin"
        );
    }

    /// `health_probe_custom` 决定"全部候选失败"时要不要提测速资产。
    ///
    /// 实测：把 probeUrl 指到非 GitHub 域（加速器只代理 GitHub）会让**每个**候选都
    /// 「实测失败」，而日志里只有 `SPEED … 实测失败（非 206 或数据不足）`，
    /// 完全看不出是配置的锅。默认资产不该触发这条提示（否则就是噪音）。
    #[test]
    fn custom_probe_asset_is_flagged_for_hints() {
        let mut file = test_file("127.0.0.1:8443");
        file.health.probe_url = None;
        assert!(
            !App::new(file).unwrap().health_probe_custom,
            "默认资产不算自定义"
        );

        let mut file = test_file("127.0.0.1:8443");
        file.health.probe_url = Some("https://example.com/asset.bin".into());
        assert!(
            App::new(file).unwrap().health_probe_custom,
            "自定义资产必须被标记，否则失败时给不出提示"
        );

        // 纯空白等同于没配
        let mut file = test_file("127.0.0.1:8443");
        file.health.probe_url = Some("   ".into());
        assert!(!App::new(file).unwrap().health_probe_custom);
    }

    #[test]
    fn rejects_malformed_listen() {
        assert!(app("127.0.0.1").is_err());
        assert!(app("not-an-address").is_err());
    }

    /// host 比较必须大小写不敏感（RFC 4343）。
    ///
    /// 回归：曾经用 `==`，客户端发 `CONNECT GitHub.COM:443` 时 PAC（内部已 toLowerCase）
    /// 照样把流量导过来，分流却判成 TUNNEL——那条下载**完全没有被加速**，
    /// 而日志里只写 mode=TUNNEL，看着一切正常。实测复现过（design.md §3）。
    #[test]
    fn host_matching_is_case_insensitive() {
        let app = app("127.0.0.1:8443").unwrap();
        for host in ["github.com", "GitHub.COM", "GITHUB.com"] {
            assert!(app.should_rewrite(host), "应识别为白名单: {host}");
            assert!(app.should_mitm(host), "应走 MITM: {host}");
        }
        assert!(!app.should_rewrite("api.github.com"), "子域不在白名单内");

        // 配置里写成大写，也应匹配客户端的小写 host
        let mut file = test_file("127.0.0.1:8443");
        file.rewrite_hosts = vec!["GITHUB.COM".into()];
        file.mitm_extra = vec!["Example.COM".into()];
        let app = App::new(file).unwrap();
        assert!(app.should_rewrite("github.com"), "配置大写也要能匹配");
        assert!(app.should_mitm("example.com"));
    }

    /// 能力矩阵里的 host 也必须大小写不敏感，否则声明会静默失效。
    #[test]
    fn capability_matrix_is_case_insensitive() {
        let mut file = test_file("127.0.0.1:8443");
        file.accelerators = vec![AcceleratorCfg {
            name: "only-github".into(),
            template: "https://a.example/{url}".into(),
            priority: 1,
            hosts: vec!["GitHub.com".into()],
        }];
        let app = App::new(file).unwrap();
        assert!(app.accel_supports(0, "github.com"), "声明大写也应生效");
        assert!(!app.accel_supports(0, "codeload.github.com"));
    }

    #[test]
    fn mitm_extra_widens_mitm_but_not_rewrite() {
        let mut file = test_file("127.0.0.1:8443");
        file.mitm_extra = vec!["example.com".into()];
        let app = App::new(file).unwrap();
        assert!(app.should_mitm("example.com"));
        assert!(!app.should_rewrite("example.com"));
    }

    #[test]
    fn picks_lowest_priority_accelerator() {
        let mut file = test_file("127.0.0.1:8443");
        file.accelerators = vec![
            AcceleratorCfg {
                name: "b".into(),
                template: "https://second.example".into(),
                priority: 2,
                hosts: Vec::new(),
            },
            AcceleratorCfg {
                name: "a".into(),
                template: "https://first.example".into(),
                priority: 1,
                hosts: Vec::new(),
            },
        ];
        let app = App::new(file).unwrap();
        assert_eq!(app.accels[0].host, "first.example");
    }

    #[test]
    fn optional_paths_and_mitm_extra_are_honored() {
        let mut file = test_file("127.0.0.1:8443");
        file.cert_dir = Some(PathBuf::from("custom-certs"));
        file.log_path = Some(PathBuf::from("custom.log"));
        file.mitm_extra = vec!["example.com".into()];
        let app = App::new(file).unwrap();
        assert_eq!(app.cert_dir, PathBuf::from("custom-certs"));
        assert_eq!(app.log_path, PathBuf::from("custom.log"));
        assert!(app.should_mitm("example.com"));
    }

    #[test]
    fn default_config_has_no_eager_candidate_fetch() {
        let file = FileConfig::default();
        assert!(file.accelerators.is_empty());
        assert!(file.cert_dir.is_none());
        assert!(file.log_path.is_none());
        assert_eq!(file.routing.mode, RoutingMode::Auto);
        assert_eq!(file.routing.min_direct_kbps, 512);
    }

    #[test]
    fn routing_rejects_invalid_budgets_and_out_of_scope_assets() {
        for routing in [
            serde_json::json!({"minDirectKbps": 0}),
            serde_json::json!({"timeoutSeconds": 0}),
            serde_json::json!({"intervalSeconds": 59}),
            serde_json::json!({"cooldownSeconds": u64::MAX}),
        ] {
            let mut file = test_file("127.0.0.1:8443");
            file.routing = serde_json::from_value(routing).unwrap();
            assert!(App::new(file).is_err());
        }
        for url in [
            "http://github.com/file",
            "https://other.example/file",
            "https://github.com:8443/file",
            "https://github.com:bad/file",
            "https://user@github.com/file",
            "https://github.com/",
        ] {
            let mut file = test_file("127.0.0.1:8443");
            file.routing.probe_urls = vec![url.into()];
            assert!(App::new(file).is_err(), "{url}");
        }
    }
    /// 示例配置里不该有任何"不认识的键"——它是字段形状的唯一权威。
    ///
    /// 这条同时护住文档：改了 `config.example.json` 却忘了同步 `TOP_KEYS` /
    /// `HEALTH_KEYS` / `ACCEL_KEYS` 时，这里会立刻失败。
    #[test]
    fn example_config_has_no_unknown_keys() {
        let text = std::fs::read_to_string("config.example.json").unwrap();
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(unknown_config_keys(&doc), Vec::<String>::new());
    }

    /// 拼错的键必须被指出来（含嵌套路径），否则用户改了配置却静默用了默认值。
    #[test]
    fn unknown_keys_are_reported_with_their_path() {
        let doc: serde_json::Value = serde_json::from_str(
            r#"{
                "listen": "127.0.0.1:8443",
                "rewriteHost": ["github.com"],
                "$comment_ok": "注释性键允许存在",
                "health": { "enabled": true, "probeURL": "https://x/y" },
                "accelerators": [ { "name": "a", "template": "https://a/{url}", "host": [] } ]
            }"#,
        )
        .unwrap();
        let mut got = unknown_config_keys(&doc);
        got.sort();
        assert_eq!(
            got,
            vec![
                "accelerators[0].host".to_string(),
                "health.probeURL".to_string(),
                "rewriteHost".to_string(),
            ],
            "应报出拼错的键及其路径，且忽略 $ 开头的注释键"
        );
    }

    /// 非对象 / 空对象不该 panic。
    #[test]
    fn unknown_key_scan_tolerates_odd_shapes() {
        for text in ["[]", "{}", "null", "\"x\""] {
            let doc: serde_json::Value = serde_json::from_str(text).unwrap();
            assert!(unknown_config_keys(&doc).is_empty(), "{text}");
        }
    }

    #[test]
    fn example_config_parses() {
        let text = std::fs::read_to_string("config.example.json").unwrap();
        let file: FileConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(file.rewrite_hosts.len(), 4);
        assert!(!file.accelerators.is_empty());
    }
}
