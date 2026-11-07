//! 零参数模式下的系统环境接管：装 CA、设 PAC、退出还原。
//!
//! 设计约束（用户要求，2026-11-01）：
//! **不加命令行参数**。所以"绿色版"的入口就是双击 exe —— 无参数即全自动。
//! `--no-env` 退回纯代理模式，供测试与高级用法使用。
//!
//! 注册表与 WinINet 有效连接配置分别保存、接管和恢复，证书导入走 `certutil.exe`。
//! 仅写 AutoConfigURL 不会保证自动脚本已启用；接管须通过 WinINet 设置 PAC 标志。
//!
//! 证书的**读取**（是否已信任、有效期）走 Win32 API（见 `certinfo.rs`），
//! 不依赖 PowerShell。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use windows_sys::Win32::System::Registry as R;

use crate::pacstate::{self, SavedState, WingetState, STATE_FILE};

const INET_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[cfg(test)]
/// `state.json` 里记的"开工前 AutoConfigURL 是什么"。
#[derive(Debug, PartialEq, Eq)]
enum PriorState {
    /// 开工前用户本来就没有 AutoConfigURL → 退出时删掉我们写的那个。
    Absent,
    /// 开工前用户有自己的 PAC → 退出时写回这个值。
    Value(String),
    /// 读不懂（写到一半、被改坏、未知格式）→ **不要动注册表**。
    Corrupt,
}

/// 序列化成结构化 JSON：`{"version":1,"prior":null|"<url>"}`。
///
/// 用显式结构而不是"空文件代表没有"：后者无法与"写了一半"区分开（见 `PriorState`）。
#[cfg(test)]
fn serialize_prior_state(prior: Option<&str>) -> String {
    let value = match prior {
        Some(url) if !url.trim().is_empty() => serde_json::Value::String(url.trim().to_string()),
        _ => serde_json::Value::Null,
    };
    serde_json::json!({ "version": 1, "prior": value }).to_string()
}

/// 解析 `state.json`。兼容**旧格式**（整个文件就是原始 URL，或空文件代表"原本没有"）。
#[cfg(test)]
fn parse_prior_state(text: &str) -> PriorState {
    match SavedState::parse(text) {
        Ok(state) => state.prior.map_or(PriorState::Absent, PriorState::Value),
        Err(_) => PriorState::Corrupt,
    }
}

/// 原子写 `state.json`：先写临时文件再改名，避免"崩在写一半"留下空文件。
#[cfg(test)]
fn write_prior_state(path: &Path, prior: Option<&str>) -> Result<()> {
    pacstate::write(path, &SavedState::parse(&serialize_prior_state(prior))?)
}

/// 退出时还原 PAC 的守卫。`Drop` 在正常返回/`?` 提前返回时都会执行。
pub struct EnvGuard {
    state_path: PathBuf,
    state: SavedState,
    restored: bool,
    /// 写哪个注册表键。生产永远是 `INET_KEY`；测试用自建的一次性键。
    inet_key: String,
    console_restore: bool,
}

impl EnvGuard {
    /// 上一次异常退出（点 X 关窗口、任务管理器结束）会留下 PAC。
    /// 调用者须持有用户级 PacLock；只恢复本工具仍拥有的 PAC。
    ///
    /// **读不懂的 state 文件不要乱动注册表**：早先的写法是"内容为空就当原本没有 PAC，
    /// 于是删掉 AutoConfigURL"。可 `state.json` 是普通写覆盖的，崩在写一半时文件会是空的——
    /// 于是一次崩溃会把用户**自己**的 PAC 设置删掉。现在改为按结构化格式解析，
    /// 解析失败就保留现状并告警（宁可留一个指向本机的 PAC 让人看见，也不悄悄删掉别人的设置）。
    pub fn recover_stale(dir: &Path) -> Result<()> {
        Self::recover_stale_at(dir, INET_KEY)
    }

    /// 同上，但注册表键可指定。
    ///
    /// 键做成参数只为一件事：让**真实 Win32 注册表 API + state 文件 + 还原**这条链能被测试。
    /// 生产路径固定用 `INET_KEY`；测试用自建的一次性键，不碰用户的代理设置。
    pub fn recover_stale_at(dir: &Path, inet_key: &str) -> Result<()> {
        let state_path = dir.join(STATE_FILE);
        restore_saved_state(&state_path, inet_key, None)?;
        Ok(())
    }

    /// 装好 CA、设好 PAC，返回守卫。
    ///
    /// `winget` 为真时顺带把 winget 的下载器钉成 WinINet（见 `crate::winget`），
    /// 退出/崩溃时按记录的原值还原；为假时完全不碰 winget 的设置文件。
    pub fn enable(cert_dir: &Path, state_dir: &Path, port: u16, winget: bool) -> Result<Self> {
        let opts = EnableOptions {
            versioned_pac: true,
            winget_path: if winget {
                crate::winget::settings_path()
            } else {
                None
            },
            ..EnableOptions::default()
        };
        Self::enable_with(cert_dir, state_dir, port, opts)
    }

    /// 同上，但把"会改系统状态的两步"（装 CA、拉起看门狗）与注册表键做成可替换的。
    ///
    /// 这样测试就能在**不装 CA、不起子进程**的前提下走完
    /// "设 PAC → 模拟崩溃 → 重启还原"整条链路（见 `pac_lifecycle_survives_a_crash`）。
    fn enable_with(
        cert_dir: &Path,
        state_dir: &Path,
        port: u16,
        opts: EnableOptions,
    ) -> Result<Self> {
        // 生产使用用户级状态目录，所有解压副本共用一个日志和互斥锁。
        std::fs::create_dir_all(state_dir).with_context(|| {
            format!(
                "建不了目录: {}。本程序要在这个位置记录原始代理设置（state.json），\
                 所以必须放在**可写**目录里——建议放到用户目录（例如桌面或 \
                 %LOCALAPPDATA%\\winget-accel）后重新运行",
                state_dir.display()
            )
        })?;

        let ca_pem = crate::ca::CertAuthority::root_pem_path(cert_dir);
        if !ca_pem.exists() {
            bail!(
                "还没生成 CA（{}）。请先运行一次本程序让代理生成证书，再回来。",
                ca_pem.display()
            );
        }

        if opts.ensure_ca {
            ensure_ca_trusted(&ca_pem)?;
        }

        let prior = read_pac_checked(&opts.inet_key)?;
        let winget_prior = match opts.winget_path.as_deref().map(crate::winget::inspect_at) {
            Some(Ok(prior)) => Some(prior),
            Some(Err(err)) => {
                // 读不出来（手写坏了 / 权限）→ 不改它，也不让启动失败
                crate::log::warn(&format!(
                    "WINGET-SKIP 读不了 winget 设置，本次不改下载器：{err:#}"
                ));
                None
            }
            None => None,
        };
        let state_path = state_dir.join(STATE_FILE);
        let mut state = SavedState::new(prior, port);
        state.wininet = SystemPac(&opts.inet_key).connection()?;
        if opts.versioned_pac {
            state.set_revision(0, state.owned_pac.clone().unwrap())?;
            state.previous_pac = None;
        }
        if let Some(prior) = &winget_prior {
            state = state.with_winget(WingetState {
                path: prior.path.to_string_lossy().to_string(),
                value: prior.value.clone(),
                created_file: prior.created_file,
            });
        }
        // 原子写：先落临时文件再改名。否则崩在写一半会留下空文件，
        // 而"空"在旧格式里等价于"用户原本没有 PAC"（见 recover_stale 的说明）。
        pacstate::write(&state_path, &state).with_context(|| {
            format!(
                "写不了 {}。该文件用来记录原始代理设置，退出时据此还原；\
                 写不了就不接管系统代理。请把程序放到可写目录后重试",
                state_path.display()
            )
        })?;

        // 先构造守卫：写 PAC 或启动看门狗失败时也会清理本次日志。
        let guard = Self {
            state_path,
            state,
            restored: false,
            inet_key: opts.inet_key,
            console_restore: opts.watchdog,
        };
        if opts.watchdog {
            // 必须在修改注册表前成功拉起看门狗。子进程不附着父控制台。
            spawn_watchdog(
                &guard.state_path,
                &guard.inet_key,
                guard
                    .state
                    .session
                    .as_deref()
                    .context("缺少 PAC 会话标识")?,
            )?;
            RESTORE_CONTEXT
                .set(RestoreContext {
                    state_path: guard.state_path.clone(),
                    inet_key: guard.inet_key.clone(),
                    session: guard.state.session.clone(),
                })
                .map_err(|_| anyhow::anyhow!("本进程已接管过系统 PAC，请重新启动"))?;
            install_exit_handler();
            // 写入前登记：控制台事件不再存在“已写成功但尚未登记”的空窗。
            PAC_WRITTEN.store(true, AtomicOrdering::SeqCst);
        }
        let pac_url = guard.state.owned_pac.as_deref().context("缺少接管 PAC")?;
        if let Some(prior) = &guard.state.wininet {
            crate::wininet::apply(&prior.with_pac(pac_url.to_string()))?;
        }
        write_pac_at(&guard.inet_key, pac_url)?;
        crate::log::info(&format!("PAC-SET {pac_url}"));

        // winget 的设置放在 PAC 之后：它是"锦上添花"，失败也不该影响代理本身。
        if let Some(prior) = &winget_prior {
            match crate::winget::apply_at(prior) {
                Ok(()) => crate::log::info(&format!(
                    "WINGET-SET network.downloader={} 原值={} 文件={}",
                    crate::winget::DOWNLOADER,
                    prior.value.as_deref().unwrap_or("<不存在>"),
                    prior.path.display()
                )),
                Err(err) => crate::log::warn(&format!("WINGET-SET-FAIL 未改 winget 设置：{err:#}")),
            }
        }
        Ok(guard)
    }
}

/// `EnvGuard::enable` 的环境依赖。
///
/// 默认值就是生产行为；测试用它把"装 CA / 起看门狗 / 用哪个注册表键"换掉。
struct EnableOptions {
    inet_key: String,
    ensure_ca: bool,
    watchdog: bool,
    /// winget 设置文件路径；`None` = 不接管 winget（测试默认、或配置关掉）。
    winget_path: Option<PathBuf>,
    versioned_pac: bool,
}

impl Default for EnableOptions {
    fn default() -> Self {
        Self {
            inet_key: INET_KEY.to_string(),
            ensure_ca: true,
            watchdog: true,
            winget_path: None,
            versioned_pac: false,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        if self.console_restore {
            PAC_WRITTEN.store(false, AtomicOrdering::SeqCst);
        }
        let outcome = restore_saved_state(
            &self.state_path,
            &self.inet_key,
            self.state.session.as_deref(),
        );
        match outcome {
            Ok(outcome) => crate::log::info(&format!("PAC-RESTORED {}", outcome.description())),
            Err(err) => crate::log::warn(&format!(
                "还原环境失败，已保留状态文件供重试，请检查 PAC 与 winget 设置：{err:#}"
            )),
        }
    }
}

/// 读当前 AutoConfigURL；没有则返回 None。
pub fn current_pac() -> Option<String> {
    read_pac()
}

/// 系统是否启用了"全局代理"（`ProxyEnable`）。
///
/// 接管保留 WinINet 手动代理标志，所以在启动与 `--doctor` 里指出已有全局代理，
/// 帮助排查用户环境中多层代理的影响。
///
/// 返回 `None` 表示读不出来（注册表项不存在、或无权限），与"明确关闭"区分开。
pub fn global_proxy_enabled() -> Option<bool> {
    let out = Command::new("reg")
        .args(["query", INET_KEY, "/v", "ProxyEnable"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_proxy_enable(&String::from_utf8_lossy(&out.stdout))
}

/// 从 `reg query` 输出里解析 `ProxyEnable`；与本地化无关（只看值与 `REG_DWORD`）。
///
/// 形如：`    ProxyEnable    REG_DWORD    0x0`
fn parse_proxy_enable(text: &str) -> Option<bool> {
    let line = text.lines().find(|line| line.contains("ProxyEnable"))?;
    let value = line.split("REG_DWORD").nth(1)?.trim();
    let numeric = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => value.parse::<u32>().ok()?,
    };
    Some(numeric != 0)
}

fn read_pac() -> Option<String> {
    read_pac_at(INET_KEY)
}

/// 读指定注册表键下的 `AutoConfigURL`。
///
/// 把键做成参数只为一件事：让**真实 Win32 注册表调用路径**能被测试。
/// 生产路径永远用 `INET_KEY`；测试用一个自建的一次性键，
/// 既验证了 Unicode 值的往返保全，又不会碰到用户真正的代理设置。
fn read_pac_at(key: &str) -> Option<String> {
    read_pac_checked(key).ok().flatten()
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn registry_path(key: &str) -> Result<Vec<u16>> {
    Ok(wide(
        key.strip_prefix("HKCU\\")
            .context("只允许读写当前用户的注册表键")?,
    ))
}

/// 只有真正不存在才返回 None；权限/类型/读取错误不得被误认为“用户没有 PAC”。
fn read_pac_checked(key: &str) -> Result<Option<String>> {
    let subkey = registry_path(key)?;
    let name = wide("AutoConfigURL");
    let mut bytes = 0u32;
    // SAFETY: UTF-16 字符串以 NUL 结尾；第一次调用只查询缓冲区长度。
    let status = unsafe {
        R::RegGetValueW(
            R::HKEY_CURRENT_USER,
            subkey.as_ptr(),
            name.as_ptr(),
            R::RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut bytes,
        )
    };
    if matches!(status, 2 | 3) {
        return Ok(None);
    }
    registry_result(status).context("读取原 PAC 失败，未接管系统设置")?;
    let mut value = vec![0u16; (bytes as usize).div_ceil(2)];
    // SAFETY: value 容量足够容纳 bytes；若查询之间值变大，API 返回错误而不会越界。
    let status = unsafe {
        R::RegGetValueW(
            R::HKEY_CURRENT_USER,
            subkey.as_ptr(),
            name.as_ptr(),
            R::RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            value.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    registry_result(status).context("读取原 PAC 失败，未接管系统设置")?;
    value.truncate(bytes as usize / 2);
    while value.last() == Some(&0) {
        value.pop();
    }
    Ok(Some(
        String::from_utf16(&value).context("PAC 不是合法 UTF-16")?,
    ))
}

fn registry_result(status: u32) -> Result<()> {
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32).into());
    }
    Ok(())
}

fn write_pac_at(key: &str, value: &str) -> Result<()> {
    let subkey = registry_path(key)?;
    let name = wide("AutoConfigURL");
    let value = wide(value);
    let mut opened = std::ptr::null_mut();
    // SAFETY: 输出句柄由 RegCloseKey 释放，所有字符串和缓冲区均存活至调用结束。
    unsafe {
        registry_result(R::RegCreateKeyExW(
            R::HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            std::ptr::null(),
            0,
            R::KEY_SET_VALUE,
            std::ptr::null(),
            &mut opened,
            std::ptr::null_mut(),
        ))?;
        let status = R::RegSetValueExW(
            opened,
            name.as_ptr(),
            0,
            R::REG_SZ,
            value.as_ptr().cast(),
            (value.len() * 2) as u32,
        );
        R::RegCloseKey(opened);
        registry_result(status).context("写 PAC 注册表失败")?;
    }
    notify_proxy_change(key);
    Ok(())
}

fn delete_pac_at(key: &str) -> Result<()> {
    let subkey = registry_path(key)?;
    let name = wide("AutoConfigURL");
    // SAFETY: 两个以 NUL 结尾的字符串在整个调用期间有效。
    let status =
        unsafe { R::RegDeleteKeyValueW(R::HKEY_CURRENT_USER, subkey.as_ptr(), name.as_ptr()) };
    if matches!(status, 2 | 3) {
        return Ok(());
    }
    registry_result(status).context("删除 PAC 注册表失败")?;
    notify_proxy_change(key);
    Ok(())
}

fn notify_proxy_change(key: &str) {
    // Scratch-key tests must never notify or modify the real system proxy.
    if key != INET_KEY {
        return;
    }
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    for option in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
        // SAFETY: these process-wide notifications take a null handle/buffer.
        if unsafe { InternetSetOptionW(std::ptr::null(), option, std::ptr::null(), 0) } == 0 {
            crate::log::warn(&format!(
                "PAC-NOTIFY-FAIL Windows 刷新通知失败: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
}

/// No-env has no restore context and never writes the registry or journal.
pub fn refresh_owned_pac(revision: u64) -> Result<bool> {
    let Some(context) = RESTORE_CONTEXT.get() else {
        return Ok(false);
    };
    if !PAC_WRITTEN.load(AtomicOrdering::SeqCst) {
        return Ok(false);
    }
    refresh_pac_at(
        &context.state_path,
        &context.inet_key,
        context.session.as_deref(),
        revision,
    )
}

fn refresh_pac_at(
    state_path: &Path,
    key: &str,
    session: Option<&str>,
    revision: u64,
) -> Result<bool> {
    refresh_pac_settings(state_path, session, revision, &mut SystemPac(key))
}

fn refresh_pac_settings(
    state_path: &Path,
    session: Option<&str>,
    revision: u64,
    settings: &mut impl PacSettings,
) -> Result<bool> {
    let _update = PAC_UPDATE.lock().expect("PAC update lock");
    let Some(mut state) = pacstate::read(state_path)? else {
        return Ok(false);
    };
    if session.is_none() || state.session.as_deref() != session {
        return Ok(false);
    }
    let Some(current) = settings.registry()?.filter(|value| state.owns(Some(value))) else {
        return Ok(false);
    };
    if state.wininet_restore.is_some() {
        return Ok(false);
    }
    let native = if state.wininet.is_some() {
        let connection = settings.connection()?;
        if !connection.as_ref().is_some_and(|value| {
            value.pac_enabled() && value.url.as_deref() == Some(current.as_str())
        }) {
            // An earlier update may have stopped between the native and
            // registry writes. Keep both journal URLs until recovery; replacing
            // previousPac here could lose the still-effective native URL.
            return Ok(false);
        }
        connection
    } else {
        None
    };
    state.set_revision(revision, current.clone())?;
    // Record both sides before touching the registry: either survives a crash.
    pacstate::write(state_path, &state)?;
    if settings.registry()?.as_deref() != Some(&current) {
        return Ok(false);
    }
    if let Some(native) = native {
        if settings.connection()?.as_ref() != Some(&native) {
            return Ok(false);
        }
        settings.apply(&native.with_pac(state.owned_pac.clone().unwrap()))?;
    }
    settings.write_registry(state.owned_pac.as_deref())?;
    state.previous_pac = None;
    pacstate::write(state_path, &state)?;
    crate::log::info(&format!("PAC-REFRESH revision={revision}"));
    Ok(true)
}

/// CA 是否已在用户根存储里。
///
/// 按证书**编码字节**精确比对（`CertEnumCertificatesInStore`），
/// 不按 Subject，也不依赖 PowerShell。
/// 踩过的坑：同名不同证书是合法且常见的，按名字比会误判"已信任"，
/// 跳过导入后客户端报 TRUST_E_CERT_SIGNATURE / 0x80096004。
fn ca_is_trusted(ca_pem: &Path) -> Result<bool> {
    let der = crate::certinfo::read_ca_der(ca_pem)
        .with_context(|| format!("无法读取或解析 CA：{}", ca_pem.display()))?;
    crate::certinfo::is_trusted(&der).context("无法读取当前用户根证书存储，信任状态未知")
}
/// 不在就导入。certutil 会弹一次确认框；无桌面会话下它**不报错而是永久阻塞**，
/// 所以必须轮询 + 超时，超时后给出可手工执行的命令。
fn ensure_ca_trusted(ca_pem: &Path) -> Result<()> {
    if ca_is_trusted(ca_pem)? {
        crate::log::info("本机 CA 已被信任，跳过导入。");
        return Ok(());
    }

    if let Some(info) = crate::certinfo::info(ca_pem) {
        crate::log::info(&format!("待导入根 CA SHA-1 指纹：{}", info.thumbprint));
    }
    crate::log::info("需要把本机 CA 加入「受信任的根证书」。稍后会弹一次确认框，请点「是」。");
    let mut child = Command::new("certutil")
        .args(["-user", "-addstore", "Root"])
        .arg(ca_pem)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("启动 certutil 失败")?;

    // 用户要去点那个安全警告框，给足时间；超时说明大概率是"没有可见桌面"。
    const CONFIRM_TIMEOUT_SECS: u64 = 60;
    let deadline = Instant::now() + Duration::from_secs(CONFIRM_TIMEOUT_SECS);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if let Err(error) = verify_ca_import(status, || ca_is_trusted(ca_pem)) {
                    crate::log::error(&format!("CA-IMPORT-FAIL {error:#}"));
                    return Err(error);
                }
                crate::log::info("CA 已加入受信任的根证书。");
                return Ok(());
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let error = format!(
                        "等待证书确认超时（{} 秒）。\n\
                         这条确认框是 Windows 的「是否信任此根证书」，必须在**当前可见桌面**上点「是」——\n\
                         无桌面的会话（服务、远程无交互、CI、被隐藏的窗口）里它会一直等下去。\n\
                         二选一：\n\
                         1) 在可见桌面上手动执行下面这条命令，点「是」，然后重新运行：\n   \
                         certutil -user -addstore Root \"{}\"\n\
                         2) 只想先试试代理本身（不改任何系统设置）：加 --no-env 启动",
                        CONFIRM_TIMEOUT_SECS,
                        ca_pem.display()
                    );
                    crate::log::error(&format!("CA-IMPORT-TIMEOUT {error}"));
                    bail!("{error}");
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                let error = format!("等待 certutil 失败: {err}");
                crate::log::error(&format!("CA-IMPORT-FAIL {error}"));
                bail!("{error}");
            }
        }
    }
}

/// A successful child process alone is not proof that trust was installed.
fn verify_ca_import(
    status: std::process::ExitStatus,
    trusted: impl FnOnce() -> Result<bool>,
) -> Result<()> {
    if !status.success() {
        bail!(
            "导入 CA 失败（certutil 退出码 {}）",
            describe_status(status.code().unwrap_or(-1))
        );
    }
    if !trusted()? {
        bail!(
            "certutil 返回成功，但 CurrentUser\\Root 中未找到本次 CA；\
             尚未接管 PAC 或 winget 设置。请在可见桌面手动确认信任后重试"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------- 退出时还原
//
// 关键事实：Rust 里 Ctrl+C 的默认行为是**直接终止进程、不展开栈**，
// 所以 Drop 不会执行。点窗口 X（CTRL_CLOSE_EVENT）同理。
// 因此必须注册控制台事件处理，在进程消失前同步把 PAC 还原。

use std::sync::atomic::Ordering as AtomicOrdering;

struct RestoreContext {
    state_path: PathBuf,
    inet_key: String,
    session: Option<String>,
}

static RESTORE_CONTEXT: std::sync::OnceLock<RestoreContext> = std::sync::OnceLock::new();
static PAC_UPDATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// 是否已进入本次 PAC 写入阶段。
///
/// 控制台事件处理器现在无条件注册（见 `install_exit_handler`），所以必须先问一句
/// "我们动过注册表吗"——否则 `--no-env` 或 CA 导入失败时按 Ctrl+C，
/// 会走 `delete_pac()` 把**用户自己的** `AutoConfigURL` 删掉。
static PAC_WRITTEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn restore_now() -> Option<Result<RestoreOutcome>> {
    if !PAC_WRITTEN.swap(false, AtomicOrdering::SeqCst) {
        return None;
    }
    RESTORE_CONTEXT.get().map(|context| {
        restore_saved_state_impl(
            &context.state_path,
            &context.inet_key,
            context.session.as_deref(),
            false,
        )
    })
}

/// 把控制台事件编号翻成可读名字（日志要能回答"是哪种退出方式"）。
fn event_name(event: u32) -> &'static str {
    match event {
        0 => "Ctrl+C",
        1 => "Ctrl+Break",
        2 => "关闭窗口",
        5 => "注销",
        6 => "关机",
        _ => "其它事件",
    }
}

unsafe extern "system" fn on_console_event(event: u32) -> i32 {
    let outcome = restore_now();
    // 代码页也要还原：Ctrl+C 下 Rust **不展开栈**，`Drop` 不会跑，
    // 只在 `Drop` 里还原的话退出后终端会停在 65001（中文控制台里后续命令可能显示异常）。
    crate::console::restore_pending();
    // 再记一行日志。用 `emergency`：它**不取日志锁**，
    // 避免主线程正持有锁时把事件线程卡住（那样按 Ctrl+C 会退不掉）。
    // 这一行是事后判断"加速何时失效、以什么方式失效"的唯一线索：
    // 此前这条路径静默还原，proxy.log 里完全看不出进程何时退出。
    if let Some(outcome) = outcome {
        let detail = match outcome {
            Ok(outcome) => outcome.description().to_string(),
            Err(err) => format!("失败，保留状态文件: {err:#}"),
        };
        crate::log::emergency(&format!(
            "PAC-RESTORED (console-event: {}) {detail}",
            event_name(event)
        ));
    }
    // 返回 FALSE(0) = "未处理"，交回默认处理器终止进程。
    // 注意：若返回 TRUE(1) 会阻止默认终止行为，导致按 Ctrl+C 后进程赖着不走。
    0
}

/// 注册控制台事件处理：Ctrl+C、关窗口、注销、关机都会触发还原。
///
/// **无条件注册**（main 一启动就调，不等接管环境）：除了 PAC，它还要还原控制台代码页，
/// 而代码页是启动时立刻切过去的。早先只在 `EnvGuard::enable` 里注册，
/// 于是 `--no-env`、或 CA 导入失败提前返回时，Ctrl+C 会把终端留在 65001
/// （实测：切换成功但不还原，退出码 0xC000013A）。
/// 安全性由 `restore_now()` 里的 `PAC_WRITTEN` 判断保证：没写过就不动注册表。
pub fn install_exit_handler() {
    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }
    // 幂等：重复注册同一个处理函数会让它被调用多次（无害但不干净）
    static REGISTERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if REGISTERED.swap(true, AtomicOrdering::SeqCst) {
        return;
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
// 父进程退出后核对会话与当前 PAC，再尝试恢复；系统关机或子进程也被结束仍需下次启动兜底。
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
///
/// 把日志路径一并传过去：父进程被硬杀时，是看门狗做的还原，
/// 只有它能写下"什么时候、因为什么还原了 PAC"这一行。
/// 注册表键也一并传：生产永远是 `INET_KEY`，测试用自建的一次性键
/// （否则看门狗会去动用户真正的代理设置，那样就没法自动验证了）。
pub fn spawn_watchdog(state_path: &Path, inet_key: &str, session: &str) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    let exe = std::env::current_exe()?;
    let pid = std::process::id();
    let mut cmd = Command::new(exe);
    cmd.arg("--watchdog")
        .arg(pid.to_string())
        .arg(state_path)
        .arg(crate::log::current_path().unwrap_or_default())
        .arg(inet_key)
        .arg(session);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .context("启动 PAC 看门狗失败，未接管系统设置")?;
    Ok(())
}

/// 等某个进程结束（`pid` 为 0 或打不开句柄时立即返回）。
///
/// 单独抽出来是为了能用**真实进程**验证这条 Win32 调用（见
/// `watchdog_waits_for_a_real_process`），而不是只信"平台限制没法测"。
fn wait_for_process(pid: u32) {
    if pid == 0 {
        return;
    }
    // SAFETY: OpenProcess 只读取 pid；句柄用完即关
    unsafe {
        let handle = OpenProcess(SYNCHRONIZE, 0, pid);
        if !handle.is_null() {
            WaitForSingleObject(handle, INFINITE);
            CloseHandle(handle);
        }
    }
}

/// 看门狗主循环（子进程调用）：等父进程退出，然后兜底还原。
///
/// `inet_key` 来自命令行（自己拉起的子进程才会传）。做一次前缀校验：
/// 只接受 `HKCU\` 开头的键，避免一个被篡改的命令行让我们往别处写注册表。
pub fn run_watchdog(
    parent_pid: u32,
    state_path: &Path,
    log_path: Option<&Path>,
    inet_key: Option<&str>,
    session: Option<&str>,
) -> ! {
    let key = match inet_key.map(str::trim) {
        Some(key) if key.starts_with("HKCU\\") => key.to_string(),
        Some(other) if !other.is_empty() => {
            crate::log::emergency(&format!(
                "看门狗收到的注册表键不合法（{other}），改回默认键"
            ));
            INET_KEY.to_string()
        }
        _ => INET_KEY.to_string(),
    };
    wait_for_process(parent_pid);
    // 父进程终止会释放锁。新实例可能抢先取得锁；此时旧看门狗只能处理自己的会话。
    if let Some(dir) = state_path.parent() {
        loop {
            match crate::pacstate::PacLock::acquire_at(dir) {
                Ok(_lock) => {
                    restore_from_state_for_session(state_path, log_path, &key, session);
                    break;
                }
                Err(err)
                    if err
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|err| err.raw_os_error() == Some(32)) =>
                {
                    if !matches!(pacstate::read(state_path), Ok(Some(state)) if state.session.as_deref() == session)
                    {
                        if let Some(path) = log_path {
                            crate::log::append_line(
                                path,
                                &crate::log::format_line(
                                    crate::log::Level::Info,
                                    "PAC-RESTORED (watchdog: 父进程已退出) 状态属于其他会话，跳过",
                                ),
                            );
                        }
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
    }
    std::process::exit(0);
}

/// 从 `state.json` 还原（看门狗的核心动作），返回是否已处理。
///
/// 与 `recover_stale_at` 的差别：这里是**子进程**在父进程死后运行，
/// 没有共享 logger，只能往日志文件追加一行。
#[cfg(test)]
fn restore_from_state(state_path: &Path, log_path: Option<&Path>, inet_key: &str) -> bool {
    restore_from_state_for_session(state_path, log_path, inet_key, None)
}

fn restore_from_state_for_session(
    state_path: &Path,
    log_path: Option<&Path>,
    inet_key: &str,
    session: Option<&str>,
) -> bool {
    let result = restore_saved_state(state_path, inet_key, session);
    if let Some(path) = log_path {
        // 用 append_line 而不是全局 logger：看门狗是独立进程，没有共享的 logger
        let outcome = match &result {
            Ok(outcome) => outcome.description().to_string(),
            Err(err) => format!("失败，保留状态文件: {err:#}"),
        };
        crate::log::append_line(
            path,
            &crate::log::format_line(
                crate::log::Level::Info,
                &format!("PAC-RESTORED (watchdog: 父进程已退出) {outcome}"),
            ),
        );
    }
    !matches!(result, Ok(RestoreOutcome::Absent))
}

#[derive(Debug, PartialEq, Eq)]
enum RestoreOutcome {
    Restored,
    Changed,
    NewSession,
    Absent,
}

impl RestoreOutcome {
    fn description(&self) -> &'static str {
        match self {
            Self::Restored => "已还原原始 PAC，并完成 winget 设置恢复检查",
            Self::Changed => "当前 PAC 已更改，保留现值；已完成 winget 设置恢复检查",
            Self::NewSession => "状态属于其他会话，跳过",
            Self::Absent => "无待恢复状态",
        }
    }
}

/// 与 PAC 共用恢复事务；错误向上传递，保留原值供看门狗或下次启动重试。
fn restore_winget_from(state: &SavedState) -> Result<()> {
    if let Some(winget) = &state.winget {
        crate::winget::restore_at(&crate::winget::Prior {
            path: PathBuf::from(&winget.path),
            value: winget.value.clone(),
            created_file: winget.created_file,
        })
        .context("还原 winget 下载器失败")?;
    }
    Ok(())
}

/// 四条退出/恢复路径共用。调用者持有用户级锁，控制台事件则仍由父进程持锁。
fn restore_saved_state(
    state_path: &Path,
    inet_key: &str,
    session: Option<&str>,
) -> Result<RestoreOutcome> {
    restore_saved_state_impl(state_path, inet_key, session, true)
}

fn restore_saved_state_impl(
    state_path: &Path,
    inet_key: &str,
    session: Option<&str>,
    consume: bool,
) -> Result<RestoreOutcome> {
    let _update = PAC_UPDATE.lock().expect("PAC update lock");
    let Some(mut state) = pacstate::read(state_path)? else {
        return Ok(RestoreOutcome::Absent);
    };
    if session.is_some() && state.session.as_deref() != session {
        return Ok(RestoreOutcome::NewSession);
    }
    let outcome = restore_pac_settings(state_path, &mut state, &mut SystemPac(inet_key))?;
    // PAC 已还原时也可重试 winget；全部成功后才消费恢复日志。
    restore_winget_from(&state)?;
    // 控制台事件发生时主线程可能还在写 PAC，保留日志供父进程真正退出后的看门狗再核对。
    if consume {
        std::fs::remove_file(state_path)
            .with_context(|| format!("无法清理 PAC 状态 {}", state_path.display()))?;
    }
    Ok(outcome)
}

/// The injected backend keeps regression tests away from real Internet Settings.
trait PacSettings {
    fn connection(&self) -> Result<Option<crate::wininet::Connection>>;
    fn apply(&mut self, value: &crate::wininet::Connection) -> Result<()>;
    fn registry(&self) -> Result<Option<String>>;
    fn write_registry(&mut self, value: Option<&str>) -> Result<()>;
}

struct SystemPac<'a>(&'a str);

impl PacSettings for SystemPac<'_> {
    fn connection(&self) -> Result<Option<crate::wininet::Connection>> {
        if self.0 == INET_KEY {
            crate::wininet::query().map(Some)
        } else {
            Ok(None)
        }
    }

    fn apply(&mut self, value: &crate::wininet::Connection) -> Result<()> {
        anyhow::ensure!(self.0 == INET_KEY, "测试键不得修改真实 WinINet 设置");
        crate::wininet::apply(value)?;
        notify_proxy_change(self.0);
        Ok(())
    }

    fn registry(&self) -> Result<Option<String>> {
        read_pac_checked(self.0)
    }

    fn write_registry(&mut self, value: Option<&str>) -> Result<()> {
        match value {
            Some(value) => write_pac_at(self.0, value),
            None => delete_pac_at(self.0),
        }
    }
}

fn restore_pac_settings(
    path: &Path,
    state: &mut SavedState,
    settings: &mut impl PacSettings,
) -> Result<RestoreOutcome> {
    let mut restored = false;
    if let Some(prior) = &state.wininet {
        let current = settings.connection()?.context("缺少 WinINet 配置")?;
        if state.wininet_restore.as_ref().is_some_and(|plan| {
            current != plan.before
                && current != plan.after
                && current.pac_enabled()
                && state.owns(current.url.as_deref())
        }) {
            // A retry must retain manual proxy/WPAD changes made meanwhile.
            state.wininet_restore = None;
        }
        if state.wininet_restore.is_none()
            && current.pac_enabled()
            && state.owns(current.url.as_deref())
        {
            let registry = settings.registry()?;
            state.wininet_restore = Some(crate::wininet::Restore {
                before: current.clone(),
                after: current.restore_pac(prior),
                registry_after: if state.owns(registry.as_deref()) {
                    state.prior.clone()
                } else {
                    registry.clone()
                },
                registry_before: registry,
            });
            // Persist intent before the native API overwrites the registry URL.
            pacstate::write(path, state)?;
        }
        if let Some(mut plan) = state.wininet_restore.clone() {
            let mut current = settings.connection()?.context("缺少 WinINet 配置")?;
            if current == plan.before {
                let registry = settings.registry()?;
                if registry != plan.registry_before {
                    // Recovery may be retried long after its first attempt.
                    // Capture newer registry edits before the native setter
                    // overwrites that value as a side effect.
                    plan.registry_after = if state.owns(registry.as_deref()) {
                        state.prior.clone()
                    } else {
                        registry.clone()
                    };
                    plan.registry_before = registry;
                    state.wininet_restore = Some(plan.clone());
                    pacstate::write(path, state)?;
                }
                settings.apply(&plan.after)?;
                current = settings.connection()?.context("缺少 WinINet 配置")?;
                anyhow::ensure!(current == plan.after, "WinINet PAC 还原尚未生效");
            }
            if current.url == plan.after.url {
                let registry = settings.registry()?;
                // On either side of the native write, restore the independent
                // registry original. Unrelated flag edits after the native
                // write must not strand its intermediate registry value.
                // A different user registry value always wins.
                if registry == plan.registry_before || registry == plan.after.url {
                    settings.write_registry(plan.registry_after.as_deref())?;
                }
                restored = true;
            }
        }
    }
    // Covers legacy journals, pre-native-write crashes and user native edits.
    if state.owns(settings.registry()?.as_deref()) {
        settings.write_registry(state.prior.as_deref())?;
        restored = true;
    }
    Ok(if restored {
        RestoreOutcome::Restored
    } else {
        RestoreOutcome::Changed
    })
}

/// 把退出码格式化成「十进制（十六进制）+ 常见原因」。
///
/// certutil 的失败信息是本地化文字，过去我们直接丢弃，
/// 导致拿到 `ERROR_NOT_SUPPORTED` 时无从判断。数字码是可搜索、可对照的。
fn describe_status(code: i32) -> String {
    let raw = code as u32;
    let hint = match raw {
        0x8007_0005 => "，拒绝访问（常见于安全软件拦截）",
        0x8007_0032 => "，系统不支持该操作（该环境禁止写证书存储）",
        _ => "",
    };
    format!("{code}（0x{raw:08X}）{hint}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_command_success_requires_certificate_in_store() {
        use std::os::windows::process::ExitStatusExt as _;
        let success = || std::process::ExitStatus::from_raw(0);
        assert!(verify_ca_import(success(), || Ok(true)).is_ok());
        let error = verify_ca_import(success(), || Ok(false)).unwrap_err();
        assert!(error.to_string().contains("未找到本次 CA"));
        let error = verify_ca_import(success(), || {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
        })
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(verify_ca_import(std::process::ExitStatus::from_raw(5), || {
            panic!("a failing importer must not be accepted because of a later store lookup")
        })
        .is_err());
    }

    #[test]
    fn native_pac_recovery_survives_partial_writes_and_preserves_user_edits() {
        use crate::wininet::Connection;
        struct Fake {
            connection: Connection,
            registry: Option<String>,
            fail_native: u8,
            fail_registry: bool,
        }
        impl PacSettings for Fake {
            fn connection(&self) -> Result<Option<Connection>> {
                Ok(Some(self.connection.clone()))
            }
            fn apply(&mut self, value: &Connection) -> Result<()> {
                anyhow::ensure!(self.fail_native != 1, "interrupted before native write");
                self.connection = value.clone();
                // Model the native setter's registry side effect.
                self.registry = value.url.clone();
                anyhow::ensure!(self.fail_native != 2, "interrupted after native write");
                Ok(())
            }
            fn registry(&self) -> Result<Option<String>> {
                Ok(self.registry.clone())
            }
            fn write_registry(&mut self, value: Option<&str>) -> Result<()> {
                anyhow::ensure!(!self.fail_registry, "registry unavailable");
                self.registry = value.map(str::to_owned);
                Ok(())
            }
        }
        let dir = std::env::temp_dir().join(format!("wg-native-{:016x}", fastrand::u64(..)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(STATE_FILE);
        for prior_registry in [None, Some(""), Some("http://corp/registry.pac")] {
            for prior_flags in [9, 13] {
                let prior_native = Connection {
                    flags: prior_flags,
                    url: Some("http://corp/effective.pac".into()),
                };
                let mut original = SavedState::new(prior_registry.map(str::to_owned), 18443);
                original
                    .set_revision(1, original.owned_pac.clone().unwrap())
                    .unwrap();
                original.previous_pac = None;
                original.wininet = Some(prior_native.clone());
                let active = prior_native.with_pac(original.owned_pac.clone().unwrap());
                for crash_stage in 0..6 {
                    let mut state = original.clone();
                    let mut fake = Fake {
                        // A manual proxy bit changed during our session.
                        connection: Connection {
                            flags: active.flags | 2,
                            ..active.clone()
                        },
                        registry: state.owned_pac.clone(),
                        fail_native: match crash_stage {
                            1 => 1,
                            2 => 2,
                            _ => 0,
                        },
                        fail_registry: crash_stage == 3,
                    };
                    pacstate::write(&path, &state).unwrap();
                    if crash_stage == 4 {
                        // Crash after journal but before initial PAC mutation.
                        fake.connection = prior_native.clone();
                        fake.registry = state.prior.clone();
                    }
                    if crash_stage == 5 {
                        // Initial native update completed, registry URL not
                        // written yet (or user independently deleted the value).
                        fake.registry = state.prior.clone();
                    }
                    let first = restore_pac_settings(&path, &mut state, &mut fake);
                    assert_eq!(first.is_err(), matches!(crash_stage, 1..=3));
                    // Reload exactly what a watchdog/new process would read.
                    state = pacstate::read(&path).unwrap().unwrap();
                    if crash_stage == 1 {
                        fake.connection.flags ^= 8; // user changed WPAD before retry
                    }
                    fake.fail_native = 0;
                    fake.fail_registry = false;
                    restore_pac_settings(&path, &mut state, &mut fake).unwrap();
                    assert_eq!(fake.registry, original.prior);
                    assert_eq!(fake.connection.url, prior_native.url);
                    assert_eq!(
                        fake.connection.flags,
                        if crash_stage == 4 {
                            prior_flags
                        } else {
                            (prior_flags | 2) ^ if crash_stage == 1 { 8 } else { 0 }
                        }
                    );
                    // Console restoration followed by watchdog is idempotent.
                    restore_pac_settings(&path, &mut state, &mut fake).unwrap();
                    assert_eq!(fake.registry, original.prior);
                }
                // Edits made after a failed recovery are newer than the saved
                // recovery intent and must survive its next attempt.
                for edit in 0..3 {
                    let mut state = original.clone();
                    let mut fake = Fake {
                        connection: active.clone(),
                        registry: active.url.clone(),
                        fail_native: if edit < 2 { 1 } else { 2 },
                        fail_registry: false,
                    };
                    pacstate::write(&path, &state).unwrap();
                    assert!(restore_pac_settings(&path, &mut state, &mut fake).is_err());
                    state = pacstate::read(&path).unwrap().unwrap();
                    let expected_registry = match edit {
                        0 => Some("http://user/after-failed-restore.pac".to_owned()),
                        1 => None,
                        _ => original.prior.clone(),
                    };
                    if edit < 2 {
                        fake.registry = expected_registry.clone();
                    } else {
                        fake.connection.flags ^= 2;
                    }
                    fake.fail_native = 0;
                    restore_pac_settings(&path, &mut state, &mut fake).unwrap();
                    assert_eq!(fake.registry, expected_registry, "edit={edit}");
                    assert_eq!(fake.connection.url, prior_native.url);
                    assert_eq!(
                        fake.connection.flags,
                        prior_flags ^ if edit == 2 { 2 } else { 0 },
                    );
                    restore_pac_settings(&path, &mut state, &mut fake).unwrap();
                    assert_eq!(fake.registry, expected_registry);
                }
                // Registry and native options can be edited independently.
                for edit_native in [false, true] {
                    let mut state = original.clone();
                    let manual = Some("http://user/new.pac".to_string());
                    let mut fake = Fake {
                        connection: if edit_native {
                            Connection {
                                flags: 3,
                                url: manual.clone(),
                            }
                        } else {
                            active.clone()
                        },
                        registry: manual.clone(),
                        fail_native: 0,
                        fail_registry: false,
                    };
                    pacstate::write(&path, &state).unwrap();
                    restore_pac_settings(&path, &mut state, &mut fake).unwrap();
                    assert_eq!(fake.registry, manual);
                    assert_eq!(
                        fake.connection.url,
                        if edit_native {
                            manual
                        } else {
                            prior_native.url.clone()
                        }
                    );
                }
                // User disabled PAC through native settings: leave it disabled.
                let mut state = original.clone();
                let mut fake = Fake {
                    connection: Connection {
                        flags: 9,
                        ..active.clone()
                    },
                    registry: active.url.clone(),
                    fail_native: 0,
                    fail_registry: false,
                };
                pacstate::write(&path, &state).unwrap();
                restore_pac_settings(&path, &mut state, &mut fake).unwrap();
                assert_eq!(fake.connection.flags, 9);
                assert_eq!(fake.registry, original.prior);
                // A refresh interrupted between its two writes must not lose
                // either owned URL when the next background revision arrives.
                for native_ahead in [false, true] {
                    let mut state = original.clone();
                    state.set_revision(2, active.url.clone().unwrap()).unwrap();
                    let newer = active.with_pac(state.owned_pac.clone().unwrap());
                    let mut fake = Fake {
                        connection: if native_ahead {
                            newer.clone()
                        } else {
                            active.clone()
                        },
                        registry: if native_ahead {
                            active.url.clone()
                        } else {
                            newer.url.clone()
                        },
                        fail_native: 0,
                        fail_registry: false,
                    };
                    pacstate::write(&path, &state).unwrap();
                    let journal = std::fs::read(&path).unwrap();
                    assert!(
                        !refresh_pac_settings(&path, state.session.as_deref(), 3, &mut fake,)
                            .unwrap()
                    );
                    assert_eq!(std::fs::read(&path).unwrap(), journal);
                    restore_pac_settings(&path, &mut state, &mut fake).unwrap();
                    assert_eq!(fake.connection, prior_native);
                    assert_eq!(fake.registry, original.prior);
                }
                let mut fake = Fake {
                    connection: active.clone(),
                    registry: active.url.clone(),
                    fail_native: 0,
                    fail_registry: false,
                };
                pacstate::write(&path, &original).unwrap();
                assert!(
                    refresh_pac_settings(&path, original.session.as_deref(), 3, &mut fake,)
                        .unwrap()
                );
                assert_eq!(fake.registry, fake.connection.url);
                assert!(fake.registry.as_deref().unwrap().ends_with("&route=3"));
                let mut state = pacstate::read(&path).unwrap().unwrap();
                assert!(state.previous_pac.is_none());
                restore_pac_settings(&path, &mut state, &mut fake).unwrap();
                assert_eq!(fake.connection, prior_native);
                assert_eq!(fake.registry, original.prior);
            }
        }
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn pac_refresh_is_recoverable_on_either_side_of_registry_update() {
        struct Sandbox {
            root: PathBuf,
            key: String,
        }
        impl Drop for Sandbox {
            fn drop(&mut self) {
                if let Ok(subkey) = registry_path(&self.key) {
                    // SAFETY: only this test's randomly named scratch key.
                    unsafe {
                        R::RegDeleteTreeW(R::HKEY_CURRENT_USER, subkey.as_ptr());
                    }
                }
                if let (Ok(root), Ok(temp)) = (
                    self.root.canonicalize(),
                    std::env::temp_dir().canonicalize(),
                ) {
                    if root.parent() == Some(temp.as_path())
                        && root
                            .file_name()
                            .is_some_and(|n| n.to_string_lossy().starts_with("wg-route-refresh-"))
                    {
                        let _ = std::fs::remove_dir_all(root);
                    }
                }
            }
        }
        let id = format!("{:016x}", fastrand::u64(..));
        let sandbox = Sandbox {
            root: std::env::temp_dir().join(format!("wg-route-refresh-{id}")),
            key: format!(r"HKCU\Software\winget-accel-route-{id}"),
        };
        let certs = sandbox.root.join("certs");
        std::fs::create_dir_all(&certs).unwrap();
        std::fs::write(certs.join("ca-cert.pem"), "placeholder").unwrap();
        std::fs::write(certs.join("root-cert.pem"), "placeholder").unwrap();
        let options = || EnableOptions {
            inet_key: sandbox.key.clone(),
            ensure_ca: false,
            watchdog: false,
            winget_path: None,
            versioned_pac: true,
        };
        let state_path = sandbox.root.join(STATE_FILE);
        let original = "http://corp.example/代理.pac";
        write_pac_at(&sandbox.key, original).unwrap();
        for registry_updated in [false, true] {
            let guard = EnvGuard::enable_with(&certs, &sandbox.root, 18443, options()).unwrap();
            let state = pacstate::read(&state_path).unwrap().unwrap();
            assert!(read_pac_checked(&sandbox.key)
                .unwrap()
                .unwrap()
                .contains("?session="));
            assert!(
                !refresh_pac_at(&state_path, &sandbox.key, Some("another-session"), 7).unwrap()
            );
            assert!(
                refresh_pac_at(&state_path, &sandbox.key, state.session.as_deref(), 7).unwrap()
            );
            let mut state = pacstate::read(&state_path).unwrap().unwrap();
            assert!(state.previous_pac.is_none());
            let current = read_pac_checked(&sandbox.key).unwrap().unwrap();
            assert!(current.ends_with("&route=7"));
            state.set_revision(8, current).unwrap();
            pacstate::write(&state_path, &state).unwrap();
            if registry_updated {
                write_pac_at(&sandbox.key, state.owned_pac.as_deref().unwrap()).unwrap();
            }
            std::mem::forget(guard);
            EnvGuard::recover_stale_at(&sandbox.root, &sandbox.key).unwrap();
            assert_eq!(
                read_pac_checked(&sandbox.key).unwrap().as_deref(),
                Some(original)
            );
        }
        let guard = EnvGuard::enable_with(&certs, &sandbox.root, 18443, options()).unwrap();
        let state = pacstate::read(&state_path).unwrap().unwrap();
        let manual = "http://corp.example/user-changed.pac";
        write_pac_at(&sandbox.key, manual).unwrap();
        let before = std::fs::read(&state_path).unwrap();
        assert!(!refresh_pac_at(&state_path, &sandbox.key, state.session.as_deref(), 9).unwrap());
        assert_eq!(std::fs::read(&state_path).unwrap(), before);
        drop(guard);
        assert_eq!(
            read_pac_checked(&sandbox.key).unwrap().as_deref(),
            Some(manual)
        );
        // PAC 已恢复但 winget 被独占时，日志必须保留，解锁后下次启动可完整重试。
        use std::os::windows::fs::OpenOptionsExt;
        let settings = sandbox.root.join("settings.json");
        std::fs::write(&settings, r#"{"network":{"downloader":"default"}}"#).unwrap();
        let guard = EnvGuard::enable_with(
            &certs,
            &sandbox.root,
            18443,
            EnableOptions {
                winget_path: Some(settings.clone()),
                ..options()
            },
        )
        .unwrap();
        let journal = std::fs::read(&state_path).unwrap();
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&settings)
            .unwrap();
        // 迟到的旧看门狗连 winget 都不能碰。
        assert!(restore_from_state_for_session(
            &state_path,
            None,
            &sandbox.key,
            Some("old-session")
        ));
        assert_eq!(std::fs::read(&state_path).unwrap(), journal);
        drop(guard);
        assert_eq!(std::fs::read(&state_path).unwrap(), journal);
        assert_eq!(
            read_pac_checked(&sandbox.key).unwrap().as_deref(),
            Some(manual)
        );
        drop(lock);
        assert_eq!(
            crate::winget::current_at(&settings).as_deref(),
            Some("wininet")
        );
        EnvGuard::recover_stale_at(&sandbox.root, &sandbox.key).unwrap();
        assert_eq!(
            crate::winget::current_at(&settings).as_deref(),
            Some("default")
        );
        assert!(!state_path.exists());
    }

    #[test]
    fn describes_known_error_codes() {
        // 0x80070032 = ERROR_NOT_SUPPORTED，这是实测踩到的那个
        let text = describe_status(0x8007_0032u32 as i32);
        assert!(text.contains("0x80070032"), "应含十六进制: {text}");
        assert!(text.contains("不支持"), "应给出原因提示: {text}");
    }

    #[test]
    fn describes_access_denied() {
        let text = describe_status(0x8007_0005u32 as i32);
        assert!(text.contains("0x80070005"));
        assert!(text.contains("拒绝访问"));
    }

    #[test]
    fn console_event_names_are_readable() {
        // 日志要能回答"是怎么退出的"，所以这几个编号必须有可读名字
        assert_eq!(event_name(0), "Ctrl+C");
        assert_eq!(event_name(2), "关闭窗口");
        assert_eq!(event_name(5), "注销");
        assert_eq!(event_name(6), "关机");
        assert_eq!(event_name(99), "其它事件");
    }

    #[test]
    fn unknown_code_still_shows_number() {
        let text = describe_status(1);
        assert!(text.contains('1'));
        assert!(text.contains("0x00000001"));
    }

    /// `ProxyEnable` 的解析必须与本地化无关：只看 `REG_DWORD` 右边的值。
    ///
    /// 真实输出（中文系统）：`    ProxyEnable    REG_DWORD    0x0`
    #[test]
    fn parses_proxy_enable_reg_output() {
        let off = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\n    ProxyEnable    REG_DWORD    0x0\n";
        assert_eq!(parse_proxy_enable(off), Some(false));

        let on = "    ProxyEnable    REG_DWORD    0x1\n";
        assert_eq!(parse_proxy_enable(on), Some(true));

        // 大写十六进制前缀、十进制写法都要认
        assert_eq!(parse_proxy_enable("ProxyEnable REG_DWORD 0X1"), Some(true));
        assert_eq!(parse_proxy_enable("ProxyEnable REG_DWORD 1"), Some(true));
        assert_eq!(parse_proxy_enable("ProxyEnable REG_DWORD 0"), Some(false));

        // 读不到 / 解析不了 → None（与"明确关闭"区分）
        assert_eq!(parse_proxy_enable(""), None);
        assert_eq!(parse_proxy_enable("ERROR: 找不到指定的注册表项"), None);
        assert_eq!(parse_proxy_enable("ProxyEnable REG_SZ nope"), None);
        assert_eq!(parse_proxy_enable("ProxyEnable REG_DWORD 0xZZ"), None);
    }

    /// 结构化 state 文件：显式区分"原本没有 PAC"与"写坏了"。
    ///
    /// 背景：旧格式是"整个文件就是原始 URL，空文件代表原本没有"。可普通写覆盖会
    /// 在崩在写一半时留下空文件，于是"崩溃"被误读成"用户原本没有 PAC"，
    /// 下一次启动就把用户**自己的** PAC 删了。
    #[test]
    fn prior_state_round_trips_through_json() {
        // 原本没有 PAC
        let text = serialize_prior_state(None);
        assert_eq!(parse_prior_state(&text), PriorState::Absent);
        // 原本是空串也按"没有"处理
        assert_eq!(
            parse_prior_state(&serialize_prior_state(Some("   "))),
            PriorState::Absent
        );

        // 原本有自己的 PAC
        let url = "http://corp.example/proxy.pac";
        let text = serialize_prior_state(Some(url));
        assert_eq!(parse_prior_state(&text), PriorState::Value(url.to_string()));
        // 前后空白会被裁掉
        assert_eq!(
            parse_prior_state(&serialize_prior_state(Some(" http://a/b.pac "))),
            PriorState::Value("http://a/b.pac".to_string())
        );
    }

    /// 写到一半的 JSON 必须被识别为"读不懂"，而不是"原本没有 PAC"。
    #[test]
    fn truncated_state_is_corrupt_not_absent() {
        assert_eq!(parse_prior_state("{\"version\":1,"), PriorState::Corrupt);
        assert_eq!(parse_prior_state("{\"prior\":123}"), PriorState::Corrupt);
    }

    /// 旧格式（裸 URL / 空文件）仍要能读——升级上来的机器不该被卡住。
    #[test]
    fn legacy_state_format_still_parses() {
        assert_eq!(
            parse_prior_state("http://old.example/p.pac\n"),
            PriorState::Value("http://old.example/p.pac".to_string())
        );
        // 旧格式里的空文件代表"原本没有 PAC"（新格式不会产生空文件）
        assert_eq!(parse_prior_state(""), PriorState::Absent);
        assert_eq!(parse_prior_state("  \r\n"), PriorState::Absent);
    }

    /// 原子写：落盘后内容可解析，且不留下 .tmp。
    #[test]
    fn state_file_is_written_atomically() {
        let dir = std::env::temp_dir().join(format!("wg-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(STATE_FILE);

        write_prior_state(&path, Some("http://x/y.pac")).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            parse_prior_state(&text),
            PriorState::Value("http://x/y.pac".to_string())
        );
        assert!(!dir.join("state.json.tmp").exists(), "不该留下临时文件");

        // 覆盖写同样原子
        write_prior_state(&path, None).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(parse_prior_state(&text), PriorState::Absent);
        assert!(!dir.join("state.json.tmp").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 用**真实 Win32 注册表 API** 走一遍读/写/删，验证本地化环境下的解析。
    ///
    /// 默认跳过（`cargo test` 不该有副作用）：设 `WINGET_ACCEL_SELFTEST=1` 才跑。
    /// 用的是自建的一次性键 `HKCU\Software\winget-accel-selftest`，
    /// **不碰** `Internet Settings` 下用户真正的代理设置；结束时把整个键删掉。
    #[test]
    fn pac_registry_roundtrip_against_scratch_key() {
        if std::env::var("WINGET_ACCEL_SELFTEST").as_deref() != Ok("1") {
            eprintln!("跳过：需要 WINGET_ACCEL_SELFTEST=1（会写自建的一次性注册表键）");
            return;
        }
        const KEY: &str = r"HKCU\Software\winget-accel-selftest";
        let cleanup = || {
            let _ = Command::new("reg")
                .args(["delete", KEY, "/f"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        };
        cleanup();

        // 一开始不存在 → None（与"读到空串"区分）
        assert_eq!(read_pac_at(KEY), None);
        // 删除一个不存在的值不算错误
        assert!(delete_pac_at(KEY).is_ok());

        // 写入并原样读回（真实 Win32 API + Unicode 值往返）
        let url = "http://127.0.0.1:8443/winget-accel.pac";
        write_pac_at(KEY, url).expect("写注册表失败");
        assert_eq!(read_pac_at(KEY).as_deref(), Some(url));

        // 覆盖写
        let other = "http://127.0.0.1:9000/other.pac";
        write_pac_at(KEY, other).expect("覆盖写失败");
        assert_eq!(read_pac_at(KEY).as_deref(), Some(other));

        // 删除后回到 None
        delete_pac_at(KEY).expect("删除失败");
        assert_eq!(read_pac_at(KEY), None);

        cleanup();
    }

    /// 看门狗的等待：用**真实子进程**验证（不是只信"平台限制没法测"）。
    ///
    /// 起一个 1 秒后自己退出的进程，`wait_for_process` 应当在它退出后才返回。
    #[test]
    fn watchdog_waits_for_a_real_process() {
        let mut child = Command::new("cmd")
            .args(["/c", "ping", "-n", "2", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("起测试子进程失败");

        let started = Instant::now();
        wait_for_process(child.id());
        let waited = started.elapsed();
        let status = child.wait().expect("等待子进程失败");

        assert!(status.success(), "测试子进程应正常退出");
        assert!(
            waited >= Duration::from_millis(150),
            "应当真的等到子进程退出，实际只等了 {waited:?}"
        );

        // pid 0 / 不存在的 pid 不该卡住
        let t0 = Instant::now();
        wait_for_process(0);
        wait_for_process(0xFFFF_FFF0);
        assert!(t0.elapsed() < Duration::from_secs(1), "无效 pid 不该阻塞");
    }

    /// 看门狗的核心动作：按 state.json 还原（用自建一次性键调用真实 Win32 API）。
    ///
    /// 这是最后一条没验过的退出路径（父进程被硬杀）。默认跳过；
    /// `WINGET_ACCEL_SELFTEST=1` 时运行。
    #[test]
    fn watchdog_restores_from_state_file() {
        if std::env::var("WINGET_ACCEL_SELFTEST").as_deref() != Ok("1") {
            eprintln!("跳过：需要 WINGET_ACCEL_SELFTEST=1（会写自建的一次性注册表键）");
            return;
        }
        const KEY: &str = r"HKCU\Software\winget-accel-watchdog";
        let cleanup_key = || {
            let _ = Command::new("reg")
                .args(["delete", KEY, "/f"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        };
        cleanup_key();

        let root = std::env::temp_dir().join(format!("wg-watchdog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let state = root.join(STATE_FILE);
        let log = root.join("wd.log");

        // 情形 A：原本有自己的 PAC → 应写回原值，并删掉 state.json
        let original = "http://corp.example/proxy.pac";
        write_pac_at(KEY, "http://127.0.0.1:18443/winget-accel.pac").unwrap();
        write_prior_state(&state, Some(original)).unwrap();
        assert!(restore_from_state(&state, Some(&log), KEY));
        assert_eq!(read_pac_at(KEY).as_deref(), Some(original));
        assert!(!state.exists(), "还原后应清掉 state.json");
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("PAC-RESTORED (watchdog"), "{text}");
        assert!(text.contains("已还原原始 PAC"), "{text}");

        // 情形 B：原本没有 PAC → 应删除
        write_pac_at(KEY, "http://127.0.0.1:18443/winget-accel.pac").unwrap();
        write_prior_state(&state, None).unwrap();
        assert!(restore_from_state(&state, Some(&log), KEY));
        assert_eq!(read_pac_at(KEY), None, "原本没有 PAC 时看门狗应删除");

        // 情形 C：state.json 被写坏 → 不动注册表
        let keep = "http://keep.example/p.pac";
        write_pac_at(KEY, keep).unwrap();
        std::fs::write(&state, "{\"version\":1,").unwrap();
        assert!(restore_from_state(&state, Some(&log), KEY));
        assert_eq!(
            read_pac_at(KEY).as_deref(),
            Some(keep),
            "读不懂时不该动注册表"
        );

        // 情形 D：没有 state.json → 什么都不做（返回 false）
        let _ = std::fs::remove_file(&state);
        assert!(!restore_from_state(&state, Some(&log), KEY));

        cleanup_key();
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 目录不可写时，报错必须**可执行**，而不是只丢一句"建不了目录"。
    ///
    /// 典型场景：把便携版解压进 `C:\Program Files\`（非管理员不可写），
    /// 而 `state.json` 必须写在可写的用户状态目录。这里用一个"父路径是普通文件"的
    /// 不可能目录来触发失败，避免依赖 ACL（那需要改系统状态）。
    #[test]
    fn unwritable_state_dir_gives_actionable_error() {
        let root = std::env::temp_dir().join(format!("wg-ro-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        // 先造一个**文件**，再把它的子路径当目录用 → create_dir_all 必定失败
        let blocker = root.join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let state_dir = blocker.join("sub");

        let certs = root.join("certs");
        std::fs::create_dir_all(&certs).unwrap();
        std::fs::write(certs.join("ca-cert.pem"), "placeholder").unwrap();
        std::fs::write(certs.join("root-cert.pem"), "placeholder").unwrap();

        let err = EnvGuard::enable_with(
            &certs,
            &state_dir,
            18443,
            EnableOptions {
                inet_key: r"HKCU\Software\winget-accel-unused".to_string(),
                ensure_ca: false,
                watchdog: false,
                winget_path: None,
                versioned_pac: false,
            },
        )
        .err()
        .expect("不可写目录必须失败");

        let text = format!("{err:#}");
        assert!(text.contains("建不了目录"), "应指出是建目录失败: {text}");
        assert!(text.contains("可写"), "必须给出可执行的做法: {text}");
        assert!(
            text.contains(&state_dir.display().to_string()),
            "必须包含具体路径: {text}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 端到端：设 PAC → **模拟崩溃**（不跑 Drop）→ 重启还原。
    ///
    /// 这是此前一直验不了的那条链：它需要"装 CA"与"起看门狗"两件会改系统状态的事，
    /// 所以把这两步做成可注入的（`EnableOptions`），并让注册表键可指定，
    /// 从而能在**自建一次性键**上跑通，不碰用户真正的代理设置。
    ///
    /// 默认跳过；`WINGET_ACCEL_SELFTEST=1` 时运行。
    #[test]
    fn pac_lifecycle_survives_a_crash() {
        if std::env::var("WINGET_ACCEL_SELFTEST").as_deref() != Ok("1") {
            eprintln!("跳过：需要 WINGET_ACCEL_SELFTEST=1（会写自建的一次性注册表键）");
            return;
        }
        const KEY: &str = r"HKCU\Software\winget-accel-lifecycle";
        let cleanup_key = || {
            let _ = Command::new("reg")
                .args(["delete", KEY, "/f"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        };
        cleanup_key();

        let root = std::env::temp_dir().join(format!("wg-lifecycle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let certs = root.join("certs");
        std::fs::create_dir_all(&certs).unwrap();
        // enable_with 只检查这个文件存在（ensure_ca=false，不会去解析它）
        std::fs::write(certs.join("ca-cert.pem"), "placeholder").unwrap();
        std::fs::write(certs.join("root-cert.pem"), "placeholder").unwrap();
        let opts = |key: &str| EnableOptions {
            inet_key: key.to_string(),
            ensure_ca: false,
            watchdog: false,
            winget_path: None,
            versioned_pac: false,
        };
        let pac_url = "http://127.0.0.1:18443/winget-accel.pac";

        // ---- 情形 A：原本没有 PAC → 崩溃 → 重启应删掉我们写的值
        let guard = EnvGuard::enable_with(&certs, &root, 18443, opts(KEY)).expect("设 PAC 失败");
        assert_eq!(
            read_pac_at(KEY).as_deref(),
            Some(pac_url),
            "应已写入我们的 PAC"
        );
        let state = root.join(STATE_FILE);
        assert!(state.exists(), "state.json 应已落盘");
        // 模拟崩溃：不运行 Drop（也就不会还原）
        std::mem::forget(guard);
        assert_eq!(
            read_pac_at(KEY).as_deref(),
            Some(pac_url),
            "崩溃后 PAC 应仍指向本机"
        );
        EnvGuard::recover_stale_at(&root, KEY).expect("重启还原失败");
        assert_eq!(read_pac_at(KEY), None, "原本没有 PAC → 应删除");
        assert!(!state.exists(), "还原后 state.json 应被清掉");

        // ---- 情形 B：原本有自己的 PAC → 崩溃 → 重启应写回原值
        let original = "http://corp.example/proxy.pac";
        write_pac_at(KEY, original).unwrap();
        let guard = EnvGuard::enable_with(&certs, &root, 18443, opts(KEY)).expect("设 PAC 失败");
        assert_eq!(read_pac_at(KEY).as_deref(), Some(pac_url));
        std::mem::forget(guard);
        EnvGuard::recover_stale_at(&root, KEY).expect("重启还原失败");
        assert_eq!(
            read_pac_at(KEY).as_deref(),
            Some(original),
            "必须写回用户原来的 PAC，而不是删掉"
        );

        // ---- 情形 C：state.json 被写坏 → 重启时不该动注册表
        write_pac_at(KEY, original).unwrap();
        std::fs::write(root.join(STATE_FILE), "{\"version\":1,").unwrap();
        assert!(
            EnvGuard::recover_stale_at(&root, KEY).is_err(),
            "坏 state 必须阻止继续接管，避免丢失原 PAC"
        );
        assert_eq!(
            read_pac_at(KEY).as_deref(),
            Some(original),
            "读不懂 state 时应保持现状，不能删别人的设置"
        );
        assert!(root.join(STATE_FILE).exists(), "保留坏文件便于恢复原设置");
        std::fs::remove_file(root.join(STATE_FILE)).unwrap();

        // ---- 情形 D：正常退出（Drop 生效）也要还原
        let guard = EnvGuard::enable_with(&certs, &root, 18443, opts(KEY)).expect("设 PAC 失败");
        assert_eq!(read_pac_at(KEY).as_deref(), Some(pac_url));
        drop(guard);
        assert_eq!(
            read_pac_at(KEY).as_deref(),
            Some(original),
            "正常退出也应写回原值"
        );

        cleanup_key();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pac_ownership_preserves_manual_changes_and_newer_sessions() {
        if std::env::var("WINGET_ACCEL_SELFTEST").as_deref() != Ok("1") {
            return;
        }
        let key = format!(
            r"HKCU\Software\winget-accel-ownership-{}",
            std::process::id()
        );
        let root = std::env::temp_dir().join(format!("wg-ownership-{}", std::process::id()));
        let certs = root.join("certs");
        std::fs::create_dir_all(&certs).unwrap();
        std::fs::write(certs.join("ca-cert.pem"), "placeholder").unwrap();
        std::fs::write(certs.join("root-cert.pem"), "placeholder").unwrap();
        let opts = || EnableOptions {
            inet_key: key.clone(),
            ensure_ca: false,
            watchdog: false,
            winget_path: None,
            versioned_pac: false,
        };
        let state_path = root.join(STATE_FILE);
        let original = "http://corp.example/代理.pac";
        let changed = "http://corp.example/new.pac";
        write_pac_at(&key, original).unwrap();

        // 正常退出必须保留中文原值，注册表读写不能经 OEM 编码往返。
        let guard = EnvGuard::enable_with(&certs, &root, 18443, opts()).unwrap();
        drop(guard);
        assert_eq!(read_pac_checked(&key).unwrap().as_deref(), Some(original));

        // 运行中被用户/其他代理替换、删除时，Drop 均不得覆盖。
        let guard = EnvGuard::enable_with(&certs, &root, 18443, opts()).unwrap();
        write_pac_at(&key, changed).unwrap();
        drop(guard);
        assert_eq!(read_pac_checked(&key).unwrap().as_deref(), Some(changed));
        assert!(!state_path.exists());
        let guard = EnvGuard::enable_with(&certs, &root, 18443, opts()).unwrap();
        delete_pac_at(&key).unwrap();
        drop(guard);
        assert_eq!(read_pac_checked(&key).unwrap(), None);

        // 模拟崩溃后用户改了 PAC，启动恢复和看门狗也必须保留。
        let old = SavedState::new(Some(original.into()), 18443);
        pacstate::write(&state_path, &old).unwrap();
        write_pac_at(&key, changed).unwrap();
        EnvGuard::recover_stale_at(&root, &key).unwrap();
        assert_eq!(read_pac_checked(&key).unwrap().as_deref(), Some(changed));
        pacstate::write(&state_path, &old).unwrap();
        assert_eq!(
            restore_saved_state(&state_path, &key, old.session.as_deref()).unwrap(),
            RestoreOutcome::Changed
        );
        assert_eq!(read_pac_checked(&key).unwrap().as_deref(), Some(changed));

        // 相同端口的新实例也有不同会话，迟到的旧看门狗不得恢复或删它的日志。
        let new = SavedState::new(Some(changed.into()), 18443);
        assert_ne!(new.session, old.session);
        pacstate::write(&state_path, &new).unwrap();
        write_pac_at(&key, new.owned_pac.as_deref().unwrap()).unwrap();
        assert_eq!(
            restore_saved_state(&state_path, &key, old.session.as_deref()).unwrap(),
            RestoreOutcome::NewSession
        );
        assert_eq!(pacstate::read(&state_path).unwrap(), Some(new.clone()));
        assert_eq!(read_pac_checked(&key).unwrap(), new.owned_pac);

        // 控制台事件先恢复但不消费日志，看门狗在进程真正退出后仍能兜底。
        assert_eq!(
            restore_saved_state_impl(&state_path, &key, new.session.as_deref(), false).unwrap(),
            RestoreOutcome::Restored
        );
        assert!(state_path.exists());
        write_pac_at(&key, new.owned_pac.as_deref().unwrap()).unwrap();
        assert_eq!(
            restore_saved_state(&state_path, &key, new.session.as_deref()).unwrap(),
            RestoreOutcome::Restored
        );
        assert_eq!(read_pac_checked(&key).unwrap().as_deref(), Some(changed));
        let _ = Command::new("reg")
            .args(["delete", &key, "/f"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        std::fs::remove_dir_all(root).unwrap();
    }
}
