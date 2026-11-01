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
const CA_SUBJECT: &str = "winget-accel local CA";

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

        write_pac(&format!("http://127.0.0.1:{port}/proxy.pac"))?;

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

/// CA 是否已在用户根存储里（按主题模糊匹配，不依赖指纹计算）。
fn ca_is_trusted() -> bool {
    let script = format!(
        "if (Get-ChildItem Cert:\\CurrentUser\\Root | Where-Object {{ $_.Subject -like '*{CA_SUBJECT}*' }}) {{ 'TRUSTED' }} else {{ 'MISSING' }}"
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stderr(Stdio::null())
        .output();
    match out {
        Ok(out) => String::from_utf8_lossy(&out.stdout).contains("TRUSTED"),
        Err(_) => false,
    }
}

/// 不在就导入。certutil 会弹一次确认框；无桌面会话下它**不报错而是永久阻塞**，
/// 所以必须轮询 + 超时，超时后给出可手工执行的命令。
fn ensure_ca_trusted(ca_pem: &Path) -> Result<()> {
    if ca_is_trusted() {
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
