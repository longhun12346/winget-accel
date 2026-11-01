//! winget-accel：用 PAC 把 4 个 GitHub 下载域名指到本机，
//! 由本机终止 TLS 并把请求改写到加速器。
//!
//! 命令行参数刻意与 `prototype/wgaccel.py` 保持一致，
//! 这样 docs/test-plan.md 里的协议用例可以直接驱动 Rust 二进制（见 §7）。

mod autoenv;
mod ca;
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
use crate::config::{App, CliOverrides};
use crate::health::Tracker;
use crate::log::{Level, Logger};
use crate::proxy::Proxy;
use crate::stats::Stats;

struct Args {
    config: Option<PathBuf>,
    overrides: CliOverrides,
    log_level: Option<String>,
    print_pac: bool,
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

    let mut args = parse_args()?;

    // 系统环境接管（装 CA / 设 PAC / 退出还原）**默认开启**，用 --no-env 显式关闭。
    //
    // 早期规则是"只有 argc == 1 才接管"，那是个坏设计：
    // 用户多加一个 --port 就静默失去核心功能，行为不可预期。
    let auto_env = !args.no_env;

    // 绿色版：默认把证书与日志放在 **exe 所在目录**，而不是当前工作目录。
    // 这样整个文件夹可以整包拷到任意位置，从哪启动都不影响行为。
    let base = exe_dir();
    if args.overrides.cert_dir.is_none() {
        args.overrides.cert_dir = Some(base.join("certs"));
    }
    if args.overrides.log.is_none() {
        args.overrides.log = Some(base.join("proxy.log"));
    }

    let file = config::load(args.config.as_ref())?;
    let log_level = args.log_level.unwrap_or_else(|| file.log_level.clone());
    let app = App::new(file, args.overrides)?;

    if args.print_pac {
        print!("{}", pac::build(app.listen.port(), &app.rewrite_hosts));
        return Ok(());
    }

    if args.remove_ca {
        let removed = crate::certinfo::remove_our_ca();
        if removed == 0 {
            println!("未找到属于本工具的根证书（可能本来就没装）。");
        } else {
            println!("已从「当前用户受信任的根」移除 {removed} 张本工具证书。");
        }
        println!("提示：若系统 PAC 仍指向本机代理，请一并清除：");
        println!("  reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v AutoConfigURL /f");
        return Ok(());
    }
    if args.doctor {
        let (checks, _) = doctor::run(&app);
        let failed = doctor::print(&checks);
        if failed {
            std::process::exit(1);
        }
        return Ok(());
    }

    let logger = Arc::new(Logger::new(Level::parse(&log_level), app.log_path.clone()));
    let stats = Arc::new(Stats::default());

    let ca = Arc::new(CertAuthority::load_or_create(&app.cert_dir, &app.rewrite_hosts)?);

    // 零参数启动 = 绿色版模式：自动信任 CA、设置 PAC，退出时还原。
    // 带任何参数时保持纯代理（测试与高级用法不能被改系统状态）。
    let _env_guard = if auto_env {
        let _ = autoenv::EnvGuard::recover_stale(&base);
        Some(autoenv::EnvGuard::enable(&base, app.listen.port())?)
    } else {
        None
    };

    logger.info(&format!(
        "CA   = {}",
        CertAuthority::ca_pem_path(&app.cert_dir).display()
    ));
    logger.info(&format!(
        "PAC  = http://{}/winget-accel.pac",
        app.listen
    ));
    let chain: Vec<String> = app
        .accels
        .iter()
        .map(|a| format!("{}://{}:{}", a.scheme.as_str(), a.host, a.port))
        .collect();
    logger.info(&format!("加速器链 = {}", chain.join(" > ")));
    if app.accels.len() == 1 {
        logger.warn("只有 1 个加速器候选：事实上没有回退链");
    }
    logger.info(&format!("改写范围 = {}", app.rewrite_hosts.join(", ")));

    let tracker = Arc::new(Tracker::new(app.accels.clone(), app.health_failures));

    let proxy = Arc::new(Proxy::new(
        Arc::new(app),
        ca,
        Arc::clone(&stats),
        Arc::clone(&logger),
        tracker,
    ));
    proxy.serve()
}

fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1);
    let mut config = None;
    let mut overrides = CliOverrides::default();
    let mut listen: Option<String> = None;
    let mut log_level = None;
    let mut print_pac = false;
    let mut doctor = false;
    let mut no_env = false;
    let mut remove_ca = false;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--config" => config = Some(PathBuf::from(next_value(&mut args, "--config")?)),
            "--listen" => listen = Some(next_value(&mut args, "--listen")?),
            "--port" => {
                let port: u16 = next_value(&mut args, "--port")?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("--port 需要数字"))?;
                listen = Some(format!("127.0.0.1:{port}"));
            }
            "--accel" => overrides.accel = Some(next_value(&mut args, "--accel")?),
            "--cert-dir" => {
                overrides.cert_dir = Some(PathBuf::from(next_value(&mut args, "--cert-dir")?))
            }
            "--log" => overrides.log = Some(PathBuf::from(next_value(&mut args, "--log")?)),
            "--log-level" => log_level = Some(next_value(&mut args, "--log-level")?),
            "--mitm-extra" => overrides
                .mitm_extra
                .push(next_value(&mut args, "--mitm-extra")?),
            "--print-pac" => print_pac = true,
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

    overrides.listen = listen;
    Ok(Args {
        config,
        overrides,
        log_level,
        print_pac,
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
         \x20 --config <路径>        配置文件（默认无，用内置默认值）\n\
         \x20 --listen <host:port>  监听地址，只允许回环（默认 127.0.0.1:8443）\n\
         \x20 --port <端口>         等价于 --listen 127.0.0.1:<端口>\n\
         \x20 --accel <基地址>      加速器，如 https://gh-proxy.com\n\
         \x20 --cert-dir <目录>     CA 存放目录（默认 certs）\n\
         \x20 --log <路径>          日志文件（默认 proxy.log）\n\
         \x20 --log-level <级别>    error|warn|info|debug\n\
         \x20 --mitm-extra <host>   额外拦截但不改写的 host（排障用，可重复）\n\
         \x20 --doctor              检查配置、证书、PAC 与加速器可达性后退出\n\
         \x20 --no-env              不接管系统环境（不改 CA/PAC，测试用）\n\
         \x20 --remove-ca           移除本工具装进根存储的证书后退出\n\
         \x20 --print-pac           打印 PAC 后退出\n\
         \x20 --version             版本\n",
        env!("CARGO_PKG_VERSION")
    );
}



