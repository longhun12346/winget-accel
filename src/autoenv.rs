//! 零参数模式下的系统环境接管：装 CA、设 PAC、退出还原。
//!
//! 设计约束（用户要求，2026-11-01）：
//! **不加命令行参数**。所以"绿色版"的入口就是双击 exe —— 无参数即全自动。
//! 带任何参数时退回纯代理模式，供测试与高级用法使用（测试不能改系统状态）。
//!
//! 不用 Win32 FFI：注册表走 `reg.exe`、证书走 `certutil.exe`/PowerShell，
//! 因此零新增依赖。代价是已运行的长驻程序（浏览器）可能不立即感知 PAC 变化；
//! 但 winget 每次是新进程，直接从注册表读配置，不受影响。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

const INET_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const STATE_FILE: &str = "state.json";

/// 退出时还原 PAC 的守卫。`Drop` 在正常返回/`?` 提前返回时都会执行。
pub struct EnvGuard {
    state_path: PathBuf,
    prior_pac: Option<String>,
    restored: bool,
}

impl EnvGuard {
    /// 上一次异常退出（点 X 关窗口、任务管理器结束）会留下 PAC。
    /// 启动时先无条件还原一次，避免"代理没跑、PAC 还指着它"的假死。
    pub fn recover_stale(dir: &Path) -> Result<()> {
        let state_path = dir.join(STATE_FILE);
        if !state_path.exists() {
            return Ok(());
        }
        let prior = std::fs::read_to_string(&state_path).unwrap_or_default();
        let prior = prior.trim();
        if prior.is_empty() {
            delete_pac()?;
        } else {
            write_pac(prior)?;
        }
        let _ = std::fs::remove_file(&state_path);
        Ok(())
    }

    /// 装好 CA、设好 PAC，返回守卫。
    pub fn enable(dir: &Path, port: u16) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("建不了目录: {}", dir.display()))?;

        let ca_pem = dir.join("certs").join("ca-cert.pem");
        if !ca_pem.exists() {
            bail!(
                "还没生成 CA（{}）。请先运行一次本程序让代理生成证书，再回来。",
                ca_pem.display()
            );
        }

        ensure_ca_trusted(&ca_pem)?;

        let prior = read_pac();
        let state_path = dir.join(STATE_FILE);
        std::fs::write(&state_path, prior.clone().unwrap_or_default())
            .with_context(|| format!("写不了 {}", state_path.display()))?;

        // 先登记原值再改 PAC：即使下一刻就被 Ctrl+C 打断，也能还原
        store_prior(prior.as_deref());
        install_exit_handler();

        write_pac(&format!("http://127.0.0.1:{port}/winget-accel.pac"))?;

        // 拉起看门狗：进程无论怎么死，PAC 都会被还原
        spawn_watchdog(&state_path);

        Ok(Self {
            state_path,
            prior_pac: prior,
            restored: false,
        })
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        let result = match &self.prior_pac {
            Some(value) if !value.trim().is_empty() => write_pac(value.trim()),
            _ => delete_pac(),
        };
        if result.is_ok() {
            let _ = std::fs::remove_file(&self.state_path);
            println!("\n已还原系统 PAC 设置。");
        } else {
            println!("\n⚠ 还原 PAC 失败，请手动检查 Internet Settings 的 AutoConfigURL。");
        }
    }
}

/// 读当前 AutoConfigURL；没有则返回 None。
fn read_pac() -> Option<String> {
    let out = Command::new("reg")
        .args(["query", INET_KEY, "/v", "AutoConfigURL"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // 形如：    AutoConfigURL    REG_SZ    http://...
    text.lines()
        .find(|line| line.contains("AutoConfigURL"))
        .and_then(|line| line.split("REG_SZ").nth(1))
        .map(|value| value.trim().to_string())
}

fn write_pac(value: &str) -> Result<()> {
    let status = Command::new("reg")
        .args([
            "add", INET_KEY, "/v", "AutoConfigURL", "/t", "REG_SZ", "/d", value, "/f",
        ])
        .stderr(Stdio::null())
        .status()
        .context("调用 reg.exe 失败")?;
    if !status.success() {
        bail!("写注册表失败（reg add 退出码 {status}）");
    }
    Ok(())
}

fn delete_pac() -> Result<()> {
    // 不存在时 reg 会返回非零，这不是错误
    let _ = Command::new("reg")
        .args(["delete", INET_KEY, "/v", "AutoConfigURL", "/f"])
        .stderr(Stdio::null())
        .status();
    Ok(())
}

/// CA 是否已在用户根存储里。
///
/// 按证书**编码字节**精确比对（`CertEnumCertificatesInStore`），
/// 不按 Subject，也不依赖 PowerShell。
/// 踩过的坑：同名不同证书是合法且常见的，按名字比会误判"已信任"，
/// 跳过导入后客户端报 TRUST_E_CERT_SIGNATURE / 0x80096004。
fn ca_is_trusted(ca_pem: &Path) -> bool {
    match crate::certinfo::read_ca_der(ca_pem) {
        Some(der) => crate::certinfo::is_trusted(&der),
        None => false,
    }
}
/// 不在就导入。certutil 会弹一次确认框；无桌面会话下它**不报错而是永久阻塞**，
/// 所以必须轮询 + 超时，超时后给出可手工执行的命令。
fn ensure_ca_trusted(ca_pem: &Path) -> Result<()> {
    if ca_is_trusted(ca_pem) {
        println!("本机 CA 已被信任，跳过导入。");
        return Ok(());
    }

    println!("需要把本机 CA 加入「受信任的根证书」。稍后会弹一次确认框，请点「是」。");
    let mut child = Command::new("certutil")
        .args(["-user", "-addstore", "Root"])
        .arg(ca_pem)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("启动 certutil 失败")?;

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    println!("CA 已加入受信任的根证书。");
                    return Ok(());
                }
                bail!("导入 CA 失败（certutil 退出码 {status}）");
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    bail!(
                        "等待确认超时。请手动执行下面这条命令，点「是」，然后重新运行：\n  \
                         certutil -user -addstore Root \"{}\"",
                        ca_pem.display()
                    );
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(err) => bail!("等待 certutil 失败: {err}"),
        }
    }
}

// ---------------------------------------------------------------- 退出时还原
//
// 关键事实：Rust 里 Ctrl+C 的默认行为是**直接终止进程、不展开栈**，
// 所以 Drop 不会执行。点窗口 X（CTRL_CLOSE_EVENT）同理。
// 因此必须注册控制台事件处理，在进程消失前同步把 PAC 还原。

use std::sync::atomic::Ordering as AtomicOrdering;

/// 没有"原 PAC"时的哨兵长度值。
const NO_PRIOR: usize = usize::MAX;

static PRIOR_PTR: std::sync::atomic::AtomicPtr<u8> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
static PRIOR_LEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(NO_PRIOR);

/// 把原 PAC 值泄漏成静态数据，供控制台事件线程读取（不能在里面加锁）。
fn store_prior(prior: Option<&str>) {
    match prior {
        Some(value) if !value.trim().is_empty() => {
            let boxed = value.as_bytes().to_vec().into_boxed_slice();
            let len = boxed.len();
            let ptr = Box::into_raw(boxed) as *mut u8;
            PRIOR_PTR.store(ptr, AtomicOrdering::SeqCst);
            PRIOR_LEN.store(len, AtomicOrdering::SeqCst);
        }
        _ => PRIOR_LEN.store(NO_PRIOR, AtomicOrdering::SeqCst),
    }
}

fn pending_prior() -> Option<String> {
    let len = PRIOR_LEN.load(AtomicOrdering::SeqCst);
    if len == NO_PRIOR {
        return None;
    }
    let ptr = PRIOR_PTR.load(AtomicOrdering::SeqCst);
    if ptr.is_null() {
        return None;
    }
    // SAFETY: ptr/len 来自上面泄漏的 Box<[u8]>，进程存活期间一直有效
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf8(bytes.to_vec()).ok()
}

fn restore_now() {
    match pending_prior() {
        Some(value) => {
            let _ = write_pac(&value);
        }
        None => {
            let _ = delete_pac();
        }
    }
}

unsafe extern "system" fn on_console_event(_event: u32) -> i32 {
    // 先同步还原（reg.exe 是阻塞调用，能保证在进程被杀前完成）
    restore_now();
    // 返回 FALSE(0) = "未处理"，交回默认处理器终止进程。
    // 注意：若返回 TRUE(1) 会阻止默认终止行为，导致按 Ctrl+C 后进程赖着不走。
    0
}

/// 注册控制台事件处理：Ctrl+C、关窗口、注销、关机都会触发还原。
pub fn install_exit_handler() {
    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }
    // SAFETY: 只注册一个函数指针，handler 签名与 Win32 要求一致
    unsafe {
        SetConsoleCtrlHandler(Some(on_console_event), 1);
    }
}

// ---------------------------------------------------------------- 看门狗
//
// 进程内部无法保证「一定」还原：被任务管理器结束、崩溃、强杀时
// Drop 和控制台事件处理都不会执行。所以额外起一个常驻子进程盯着父进程，
// 父进程一消失就还原 PAC —— 这是唯一能覆盖「任何死法」的方案。
//
// 子进程通过内部参数 --watchdog <父PID> <state.json 路径> 启动，
// 是程序自己拉起自己的，不需要用户传参。

const SYNCHRONIZE: u32 = 0x0010_0000;
const INFINITE: u32 = 0xFFFF_FFFF;

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
    fn WaitForSingleObject(handle: *mut std::ffi::c_void, millis: u32) -> u32;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
}

/// 启动看门狗（父进程调用）。
pub fn spawn_watchdog(state_path: &Path) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let pid = std::process::id();
    let _ = Command::new(exe)
        .arg("--watchdog")
        .arg(pid.to_string())
        .arg(state_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

/// 看门狗主循环（子进程调用）：等父进程退出，然后兜底还原。
pub fn run_watchdog(parent_pid: u32, state_path: &Path) -> ! {
    if parent_pid != 0 {
        // SAFETY: OpenProcess 只读取 pid；句柄用完即关
        unsafe {
            let handle = OpenProcess(SYNCHRONIZE, 0, parent_pid);
            if !handle.is_null() {
                WaitForSingleObject(handle, INFINITE);
                CloseHandle(handle);
            }
        }
    }
    // 父进程已结束。state.json 若还在，说明它没走正常还原流程。
    if state_path.exists() {
        let prior = std::fs::read_to_string(state_path).unwrap_or_default();
        let prior = prior.trim();
        let result = if prior.is_empty() {
            delete_pac()
        } else {
            write_pac(prior)
        };
        if result.is_ok() {
            let _ = std::fs::remove_file(state_path);
        }
    }
    std::process::exit(0);
}
