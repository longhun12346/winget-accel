//! winget-accel：验证下载直连能力，PAC 优先放行够快的域名，
//! 其余下载由本机终止 TLS 并改写到公共加速器。
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
mod learned;
mod log;
mod pac;
mod pacstate;
mod proxy;
mod rewrite;
mod routing;
mod stats;
mod winget;

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
    /// `--doctor --quick`：探到够用的可达候选就停，不扫完全部（见 doctor 的 QUICK_PROBE_TARGET）。
    quick: bool,
    no_env: bool,
    remove_ca: bool,
}

fn main() -> Result<()> {
    // rustls 0.23 要求先安装加密后端；用 ring 以避开 aws-lc-rs 的 cmake/NASM 依赖
    // 内部参数：看门狗子进程（由程序自己拉起，不需要用户传）
    // 形如：--watchdog <父PID> <state.json> <log 路径> <注册表键>
    // 最后一项是注册表键：生产永远是 Internet Settings，测试用自建一次性键。
    if std::env::args().nth(1).as_deref() == Some("--watchdog") {
        let pid = std::env::args()
            .nth(2)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let state = std::env::args().nth(3).unwrap_or_default();
        let log = std::env::args().nth(4).map(PathBuf::from);
        let key = std::env::args().nth(5);
        let session = std::env::args().nth(6);
        autoenv::run_watchdog(
            pid,
            std::path::Path::new(&state),
            log.as_deref(),
            key.as_deref(),
            session.as_deref(),
        );
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    // 中文 Windows 控制台默认 936(GBK)，而本程序输出 UTF-8。
    // 只在必要时切到 65001，并在退出时还原，避免影响同一终端里的其它程序。
    let _console = console::ensure_utf8();
    // 控制台事件处理器**无条件注册**：它不只为还原 PAC，也要还原上面切过的代码页。
    // （PAC 只在确实写过时才动，见 autoenv::restore_now 的 PAC_WRITTEN 判断。）
    autoenv::install_exit_handler();

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

    let (file, unknown_keys) = config::load(args.config.as_ref())?;
    let log_level = file.log_level.clone();
    let log_path = file
        .log_path
        .clone()
        .unwrap_or_else(|| exe_dir().join("proxy.log"));
    // 候选获取发生在 App::new() 内，日志必须先初始化，否则这些诊断只到控制台。
    let logger = Arc::new(Logger::new(Level::parse(&log_level), log_path));
    // 配置里不认识的键：拼错一个键名就会静默用默认值，所以必须告警。
    // 放在 logger 之后——否则这行只会出现在控制台，事后翻 proxy.log 查不到。
    for key in &unknown_keys {
        logger.warn(&format!(
            "配置文件里的 `{key}` 不被识别（多半是拼写错误），已忽略；字段以 config.example.json 为准"
        ));
    }
    // 启动时若临时改过控制台代码页，明确记一行：用户可能注意到终端编码变了，
    // 也可能在排障时怀疑"是不是这个程序动了我控制台"。正常退出会还原（见 console.rs）。
    if let Some(code_page) = console::pending_restore() {
        logger.log(
            Level::Debug,
            &format!("控制台代码页 {code_page} → 65001（退出时还原）"),
        );
    }
    let app = Arc::new(App::new(file)?);

    if args.doctor {
        let (checks, _) = doctor::run(app.as_ref(), args.quick);
        let failed = doctor::print(app.as_ref(), &checks);
        if failed {
            std::process::exit(1);
        }
        return Ok(());
    }

    let base = exe_dir();
    // 在证书轮换、恢复日志和任何系统设置改动前占住端口。
    let listener = Proxy::bind(&app)?;
    let pac_lock = if auto_env {
        Some(pacstate::PacLock::acquire()?)
    } else {
        None
    };
    if let Some(lock) = &pac_lock {
        autoenv::EnvGuard::recover_stale(lock.dir())?;
        // 升级兼容：旧版日志放在 exe 旁边。新日志统一放到用户级目录。
        if lock.dir() != base {
            autoenv::EnvGuard::recover_stale(&base)?;
        }
    }
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
    // 全局代理与本工具写的 PAC 并存时谁优先，本仓库未验证（design.md §8）。
    // 既然能从注册表读出来，就不要让用户自己猜：这是"装了没效果"时第一个该排除的变量。
    if autoenv::global_proxy_enabled() == Some(true) {
        logger.warn(
            "检测到系统已启用全局代理（ProxyEnable=1）：本工具只写 AutoConfigURL、不改它。\
             两者并存时 WinINet 优先哪一个未验证——若下载没走加速链，先关掉全局代理再试",
        );
    }
    // 探测期间还没写 PAC，等两条链路准备好之后才接管系统并报告就绪。
    logger.info(
        "正在检查直连路由和加速器候选。此间系统代理尚未接管，请等下面的「已就绪」再开始下载。",
    );
    proxy.routing.refresh(&logger);
    proxy.bootstrap_health();
    let _env_guard = if let Some(lock) = &pac_lock {
        Some(autoenv::EnvGuard::enable(
            &app.cert_dir,
            lock.dir(),
            app.listen.port(),
            app.winget_downloader,
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

    proxy.routing.spawn(logger);
    proxy.serve(listener)
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
    let mut quick = false;
    let mut no_env = false;
    let mut remove_ca = false;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--config" => config = Some(PathBuf::from(next_value(&mut args, "--config")?)),
            "--doctor" => doctor = true,
            "--quick" => quick = true,
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
        quick,
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
         \x20 --doctor           检查配置、证书、PAC 与加速器可达性后退出\n\x20 --quick            配合 --doctor：探到够用的可达候选就停（不扫完全部，快很多）\n\
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

    /// 中文被编码转换吞掉的护栏。
    ///
    /// 历史事故：一次 UTF-8 ↔ 本地代码页往返把三处中文日志替换成了 `?`（0x3F），
    /// 并随 v0.1.6 一起发布——最关键的"没有可用候选"告警在用户机器上不可读。
    /// 这里在 `cargo test` 阶段就拦住同类事故（本地与 CI 都会跑）。
    #[test]
    fn sources_have_no_replacement_question_marks() {
        let needle: String = "?".repeat(3);
        let sources = [
            ("autoenv.rs", include_str!("autoenv.rs")),
            ("ca.rs", include_str!("ca.rs")),
            ("candidates.rs", include_str!("candidates.rs")),
            ("certinfo.rs", include_str!("certinfo.rs")),
            ("config.rs", include_str!("config.rs")),
            ("console.rs", include_str!("console.rs")),
            ("doctor.rs", include_str!("doctor.rs")),
            ("health.rs", include_str!("health.rs")),
            ("http.rs", include_str!("http.rs")),
            ("log.rs", include_str!("log.rs")),
            ("main.rs", include_str!("main.rs")),
            ("pac.rs", include_str!("pac.rs")),
            ("proxy.rs", include_str!("proxy.rs")),
            ("proxy/network.rs", include_str!("proxy/network.rs")),
            ("proxy/local.rs", include_str!("proxy/local.rs")),
            ("proxy/probe.rs", include_str!("proxy/probe.rs")),
            ("rewrite.rs", include_str!("rewrite.rs")),
            ("routing.rs", include_str!("routing.rs")),
            ("stats.rs", include_str!("stats.rs")),
            ("winget.rs", include_str!("winget.rs")),
        ];
        for (name, text) in sources {
            assert!(
                !text.contains(&needle),
                "{name} 里出现了连续的问号：中文字符很可能被编码转换替换掉了"
            );
        }
    }
}
