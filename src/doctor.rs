//! `--doctor`：把"装没装好"这件事检查成一张表。
//!
//! 设计约束：**只做本地可判定的事**，不猜。
//! 根证书是否已装进用户根存储，需要通过 `certutil` 或 PowerShell 看证书存储，
//! 这里不调用系统工具（也不引入 `windows` crate），只给出确切的验证命令。

use std::time::Duration;

use crate::ca::CertAuthority;
use crate::config::App;
use crate::pac;
use crate::proxy::probe;
use crate::rewrite::Accel;

#[derive(Clone, Copy, PartialEq, Eq)]
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
    checks.extend(check_accels(&app.accels, app.health_timeout));
    checks.push(check_fallback(app));

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

fn check_fallback(app: &App) -> Check {
    if app.fallback_to_original && app.accels.len() < 2 {
        Check::new(
            "fallback",
            Verdict::Warn,
            "fallbackToOriginal=true 且只有 1 个候选：全挂时会失败，且直连 GitHub 在受限网络下等于卡死；\
             实际行为是快速返回 502",
        )
    } else {
        Check::new(
            "fallback",
            Verdict::Pass,
            format!("{} 个候选，fallbackToOriginal={}", app.accels.len(), app.fallback_to_original),
        )
    }
}

/// 打印表格。返回是否存在 FAIL。
pub fn print(checks: &[Check]) -> bool {
    println!("{:<10} {:<5} {}", "检查项", "结论", "详情");
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
        println!("  certutil -user -store Root | Select-String winget-accel");
    }
    failed
}

/// 供测试用：不依赖真实网络。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{App, CliOverrides, FileConfig};

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
    fn single_candidate_with_fallback_warns() {
        let app = app();
        assert_eq!(app.accels.len(), 1);
        assert_eq!(check_fallback(&app).verdict, Verdict::Warn);
    }

    #[test]
    fn verdict_tags_are_fixed_width() {
        assert_eq!(Verdict::Pass.tag().len(), 4);
        assert_eq!(Verdict::Fail.tag().len(), 4);
    }
}
