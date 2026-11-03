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
pub fn run(app: &App) -> (Vec<Check>, bool) {
    let mut checks = Vec::new();

    checks.push(check_listen(app));
    checks.push(check_ca(app));
    checks.push(check_pac(app));

    let accel_checks = check_accels(&app.accels, app.health_timeout);
    let reachable = accel_checks
        .iter()
        .filter(|c| c.verdict == Verdict::Pass)
        .count();
    checks.extend(accel_checks);
    checks.push(check_chain(app, reachable));

    let ok = checks.iter().all(|c| c.verdict != Verdict::Fail);
    (checks, ok)
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

fn check_pac(app: &App) -> Check {
    if let Some(issue) = pac_text_issue(app) {
        return Check::new("pac", Verdict::Fail, issue);
    }
    let expected = format!("http://127.0.0.1:{}/winget-accel.pac", app.listen.port());
    let actual = crate::autoenv::current_pac();
    let (verdict, detail) = pac_registry_detail(&expected, actual.as_deref());
    Check::new("pac", verdict, detail)
}

const DOCTOR_PROBE_CONCURRENCY: usize = 6;

fn check_accels(accels: &[Accel], timeout: Duration) -> Vec<Check> {
    let mut checks = Vec::with_capacity(accels.len());
    for chunk in accels.chunks(DOCTOR_PROBE_CONCURRENCY) {
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

/// 候选整体可用性。
///
/// 全挂时**不回退直连**（ADR-016），所以"一个都不可达"必须判 FAIL：
/// 此时下载一定会失败，用户不该等到装上才发现。
fn check_chain(app: &App, reachable: usize) -> Check {
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
    if app.accels.len() < 2 {
        return Check::new(
            "chain",
            Verdict::Warn,
            "只有 1 个加速器候选：它一旦不可用，请求会快速返回 502（不会回退直连，ADR-016）",
        );
    }
    Check::new(
        "chain",
        Verdict::Pass,
        format!("{reachable}/{} 个候选可达", app.accels.len()),
    )
}

/// 打印表格。返回是否存在 FAIL。
pub fn print(checks: &[Check]) -> bool {
    println!("{:<10} {:<5} 详情", "检查项", "结论");
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
            }],
            ..Default::default()
        };
        let app = App::new(file).unwrap();
        assert_eq!(app.accels.len(), 1);
        let check = check_chain(&app, 1);
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
                },
                AcceleratorCfg {
                    name: "b".into(),
                    template: "https://b.example".into(),
                    priority: 2,
                },
            ],
            ..Default::default()
        };
        let app = App::new(file).unwrap();
        assert_eq!(app.accels.len(), 2);
        assert_eq!(check_chain(&app, app.accels.len()).verdict, Verdict::Pass);
    }

    #[test]
    fn all_candidates_down_is_a_failure() {
        let app = app();
        let check = check_chain(&app, 0);
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
                },
                AcceleratorCfg {
                    name: "b".into(),
                    template: "https://b.example".into(),
                    priority: 2,
                },
            ],
            ..Default::default()
        };
        let app = App::new(file).unwrap();
        let check = check_chain(&app, 2);
        assert_eq!(check.verdict, Verdict::Pass);
        assert!(check.detail.contains("2/2"));
    }

    #[test]
    fn verdict_tags_are_fixed_width() {
        assert_eq!(Verdict::Pass.tag().len(), 4);
        assert_eq!(Verdict::Fail.tag().len(), 4);
    }
}
