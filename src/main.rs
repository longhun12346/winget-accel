//! winget-accel：用 PAC 把 4 个 GitHub 下载域名指到本机，
//! 由本机终止 TLS 并把请求改写到加速器。
//!
//! Rust CLI 只保留必要入口；测试通过临时配置文件驱动。
//!

mod autoenv;
mod ca;
mod candidates;
mod certinfo;
mod config;
mod console;
mod doctor;
mod health;
mod http;
mod log;
mod pac;
mod proxy;
mod rewrite;
mod stats;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Result};

use crate::ca::CertAuthority;
use crate::config::App;
use crate::health::Tracker;
use crate::log::{Level, Logger};
use crate::proxy::Proxy;
use crate::stats::Stats;

struct Args {
    config: Option<PathBuf>,
    doctor: bool,
    no_env: bool,
    remove_ca: bool,
}

fn main() -> Result<()> {
    // rustls 0.23 要求先安装加密后端；用 ring 以避开 aws-lc-rs 的 cmake/NASM 依赖
    // 内部参数：看门狗子进程（由程序自己拉起，不需要用户传）
    if std::env::args().nth(1).as_deref() == Some("--watchdog") {
        let pid = std::env::args()
            .nth(2)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let state = std::env::args().nth(3).unwrap_or_default();
        autoenv::run_watchdog(pid, std::path::Path::new(&state));
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    // 中文 Windows 控制台默认 936(GBK)，而本程序输出 UTF-8。
    // 只在必要时切到 65001，并在退出时还原，避免影响同一终端里的其它程序。
    let _console = console::ensure_utf8();

    let args = parse_args()?;
    let auto_env = !args.no_env;

    if args.remove_ca {
        let (removed, failed) = crate::certinfo::remove_our_ca();
        if removed == 0 {
            println!("未找到属于本工具的根证书（可能本来就没装）。");
        } else {
            println!("已从「当前用户受信任的根」移除 {removed} 张本工具证书。");
            if failed > 0 {
                println!("有 {failed} 张未能移除（certutil 返回失败）。");
                println!("可手工执行：certutil -user -delstore Root <指纹>，或用 certmgr.msc 图形界面删除。");
            }
        }
        println!("提示：若系统 PAC 仍指向本机代理，请一并清除：");
        println!("  reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v AutoConfigURL /f");
        return Ok(());
    }

    let file = config::load(args.config.as_ref())?;
    let log_level = file.log_level.clone();
    let log_path = file
        .log_path
        .clone()
        .unwrap_or_else(|| exe_dir().join("proxy.log"));
    // 候选获取发生在 App::new() 内，日志必须先初始化，否则这些诊断只到控制台。
    let logger = Arc::new(Logger::new(Level::parse(&log_level), log_path));
    let app = Arc::new(App::new(file)?);

    if args.doctor {
        let (checks, _) = doctor::run(app.as_ref());
        let failed = doctor::print(&checks);
        if failed {
            std::process::exit(1);
        }
        return Ok(());
    }

    let base = exe_dir();
    let stats = Arc::new(Stats::default());

    let ca = Arc::new(CertAuthority::load_or_create(
        &app.cert_dir,
        &app.rewrite_hosts,
    )?);

    let tracker = Arc::new(Tracker::new(app.accels.clone(), app.health_failures));
    let proxy = Arc::new(Proxy::new(
        Arc::clone(&app),
        ca,
        Arc::clone(&stats),
        Arc::clone(&logger),
        tracker,
    ));

    // 先验证候选，再写 PAC、显示就绪、开始监听。
    if auto_env {
        let _ = autoenv::EnvGuard::recover_stale(&base);
    }
    proxy.bootstrap_health();
    let _env_guard = if auto_env {
        Some(autoenv::EnvGuard::enable(
            &app.cert_dir,
            &base,
            app.listen.port(),
        )?)
    } else {
        None
    };

    // 启动信息排成对齐的一列，比一堵 "key = value" 好扫。
    let chain: Vec<String> = app.accels.iter().map(|a| a.host.clone()).collect();
    logger.info(&format!(
        "winget-accel {} 已就绪",
        env!("CARGO_PKG_VERSION")
    ));
    logger.info(&format!(
        "  CA       {}",
        CertAuthority::ca_pem_path(&app.cert_dir).display()
    ));
    logger.info(&format!("  log      {}", app.log_path.display()));
    logger.info(&format!(
        "  PAC      http://{}/winget-accel.pac",
        app.listen
    ));
    logger.info(&format!("  listen   {}", app.listen));
    logger.info(&format!(
        "  accel    {}（{} 个候选）",
        chain.join(" > "),
        chain.len()
    ));
    if app.accels.len() == 1 {
        logger.warn("  只有 1 个加速器候选：事实上没有回退链");
    }
    logger.info(&format!("  rewrite  {}", app.rewrite_hosts.join(", ")));
    if !auto_env {
        logger.info("  env      未接管系统设置（--no-env），如需 winget 走代理请去掉该参数");
    }

    proxy.serve()
}

fn parse_args() -> Result<Args> {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from<I>(mut args: I) -> Result<Args>
where
    I: Iterator<Item = String>,
{
    let mut config = None;
    let mut doctor = false;
    let mut no_env = false;
    let mut remove_ca = false;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--config" => config = Some(PathBuf::from(next_value(&mut args, "--config")?)),
            "--doctor" => doctor = true,
            "--no-env" => no_env = true,
            "--remove-ca" => remove_ca = true,
            "--version" => {
                println!("winget-accel {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => bail!("未知参数: {other}（用 --help 看用法）"),
        }
    }

    Ok(Args {
        config,
        doctor,
        no_env,
        remove_ca,
    })
}
fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| anyhow::anyhow!("{flag} 缺少取值"))
}

/// exe 所在目录；取不到时退回当前目录（测试环境可能没有真实 exe 路径）。
fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn print_help() {
    println!(
        "winget-accel {}\n\n\
         用法: winget-accel [选项]\n\n\
         选项:\n\
         \x20 --config <路径>    配置文件（默认无，用内置默认值）\n\
         \x20 --doctor           检查配置、证书、PAC 与加速器可达性后退出\n\
         \x20 --no-env           不接管系统 CA/PAC（测试/高级用法）\n\
         \x20 --remove-ca        移除本工具装进根存储的证书后退出\n\
         \x20 --version          版本\n\
         \x20 --help             帮助\n\n\
         日常使用直接双击运行，不需要参数。",
        env!("CARGO_PKG_VERSION")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(items: &[&str]) -> Result<Args> {
        parse_args_from(items.iter().map(|s| s.to_string()))
    }

    #[test]
    fn parses_minimal_cli() {
        let args = parse(&["--config", "x.json", "--doctor", "--no-env", "--remove-ca"]).unwrap();
        assert_eq!(args.config, Some(PathBuf::from("x.json")));
        assert!(args.doctor);
        assert!(args.no_env);
        assert!(args.remove_ca);
    }

    #[test]
    fn rejects_removed_flags() {
        for flag in [
            "--listen",
            "--port",
            "--accel",
            "--cert-dir",
            "--log",
            "--log-level",
            "--mitm-extra",
            "--print-pac",
        ] {
            assert!(parse(&[flag]).is_err(), "已删除参数仍被接受: {flag}");
        }
    }

    #[test]
    fn config_requires_value() {
        assert!(parse(&["--config"]).is_err());
    }
}
