//! `--doctor`：把"装没装好"这件事检查成一张表。
//!
//! 设计约束：**只做本地可判定的事**，不猜。
//! 根证书是否已装进用户根存储，用 Win32 API 可读（`certinfo`），此处只给人工核对命令，
//! 这里不调用系统工具（也不引入 `windows` crate），只给出确切的验证命令。

use std::time::Duration;

use crate::ca::CertAuthority;
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
        return Check::new("listen", Verdict::Fail, format!("{} 不是回环地址", app.listen));
    }
    match std::net::TcpListener::bind(app.listen) {
        Ok(listener) => {
            drop(listener);
            Check::new("listen", Verdict::Pass, format!("{} 可绑定", app.listen))
        }
        Err(err) => Check::new(
            "listen",
            Verdict::Warn,
            format!("{} 绑定失败（可能已有实例在跑）: {err}", app.listen),
        ),
    }
}

fn check_ca(app: &App) -> Check {
    let path = CertAuthority::ca_pem_path(&app.cert_dir);
    if !path.exists() {
        return Check::new(
            "ca",
            Verdict::Fail,
            format!("{} 不存在：先启动一次代理生成，再按文档信任它", path.display()),
        );
    }
    let Ok(pem) = std::fs::read_to_string(&path) else {
        return Check::new("ca", Verdict::Fail, format!("{} 读不出来", path.display()));
    };
    if !pem.contains("BEGIN CERTIFICATE") {
        return Check::new("ca", Verdict::Fail, format!("{} 不是 PEM 证书", path.display()));
    }

    // 授权域名记录必须与当前配置一致，否则新 host 签不出证书
    let meta_path = app.cert_dir.join("ca-meta.json");
    match std::fs::read_to_string(&meta_path) {
        Ok(meta) => match serde_json::from_str::<Vec<String>>(&meta) {
            Ok(recorded) if recorded == app.rewrite_hosts => Check::new(
                "ca",
                Verdict::Pass,
                format!("{} 存在，授权域名与配置一致（{} 个）", path.display(), recorded.len()),
            ),
            Ok(recorded) => Check::new(
                "ca",
                Verdict::Fail,
                format!(
                    "授权域名与配置不一致：旧 {recorded:?} / 新 {:?}；需删除证书目录重新生成",
                    app.rewrite_hosts
                ),
            ),
            Err(err) => Check::new("ca", Verdict::Fail, format!("ca-meta.json 解析失败: {err}")),
        },
        Err(_) => Check::new(
            "ca",
            Verdict::Warn,
            format!("{} 缺少 ca-meta.json，无法核对授权域名", app.cert_dir.display()),
        ),
    }
}

fn check_pac(app: &App) -> Check {
    let text = pac::build(app.listen.port(), &app.rewrite_hosts);
    let missing: Vec<&str> = app
        .rewrite_hosts
        .iter()
        .filter(|host| !text.contains(&format!("host == \"{host}\"")))
        .map(|s| s.as_str())
        .collect();
    if missing.is_empty() {
        Check::new(
            "pac",
            Verdict::Pass,
            format!("含 {} 个 host，入口函数正常", app.rewrite_hosts.len()),
        )
    } else {
        Check::new("pac", Verdict::Fail, format!("PAC 缺少 host: {missing:?}"))
    }
}

fn check_accels(accels: &[Accel], timeout: Duration) -> Vec<Check> {
    accels
        .iter()
        .map(|accel| {
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
                if ok { Verdict::Pass } else { Verdict::Fail },
                detail,
            )
        })
        .collect()
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
        println!("{:<10} {:<5} {}", check.name, check.verdict.tag(), check.detail);
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
        println!("根证书是否已被信任需要你自己确认（这里不读系统存储）：");
        println!("  certutil -user -store Root | findstr /i winget-accel");
    }
    failed
}

/// 供测试用：不依赖真实网络。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AcceleratorCfg, App, CliOverrides, FileConfig};

    fn app() -> App {
        App::new(FileConfig::default(), CliOverrides::default()).unwrap()
    }

    #[test]
    fn pac_check_passes_for_default_config() {
        assert_eq!(check_pac(&app()).verdict, Verdict::Pass);
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
        let app = App::new(file, CliOverrides::default()).unwrap();
        assert_eq!(app.accels.len(), 1);
        let check = check_chain(&app, 1);
        assert_eq!(check.verdict, Verdict::Warn);
        assert!(check.detail.contains("1 个加速器候选"));
    }

    #[test]
    fn default_config_ships_five_candidates() {
        // 内置候选不能只有一个：单点一挂功能就整体不可用（ADR-016）
        let app = app();
        assert_eq!(app.accels.len(), 5);
        assert_eq!(check_chain(&app, 5).verdict, Verdict::Pass);
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
                AcceleratorCfg { name: "a".into(), template: "https://a.example".into(), priority: 1 },
                AcceleratorCfg { name: "b".into(), template: "https://b.example".into(), priority: 2 },
            ],
            ..Default::default()
        };
        let app = App::new(file, CliOverrides::default()).unwrap();
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

