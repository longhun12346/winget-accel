//! PAC 接管日志与用户级互斥。状态放在用户目录，避免不同解压目录各自接管同一个 HKCU。

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

pub const STATE_FILE: &str = "state.json";

pub struct PacLock {
    dir: PathBuf,
    _file: File,
}

impl PacLock {
    pub fn acquire() -> Result<Self> {
        let dir = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .context("读不到 LOCALAPPDATA，无法安全地互斥接管系统 PAC")?
            .join("winget-accel");
        Self::acquire_at(&dir)
    }

    pub fn acquire_at(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("建不了 PAC 状态目录 {}", dir.display()))?;
        // 不删除锁文件：删除/重建会产生两个独立的锁。句柄关闭或进程终止即释放互斥。
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .share_mode(0)
            .open(dir.join("pac.lock"))
            .with_context(|| {
                format!(
                    "无法取得系统 PAC 接管锁（{}）：可能已有 winget-accel 正在运行，请先关闭它",
                    dir.display()
                )
            })?;
        Ok(Self {
            dir: dir.to_path_buf(),
            _file: file,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// 接管 winget 设置时记录的原值（见 ADR-017）。
///
/// 与 PAC 原值放在同一个状态文件里：退出、崩溃、下次启动兜底都走同一条恢复路径，
/// 不会出现"PAC 还原了、winget 设置还钉在 wininet"的半吊子状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WingetState {
    pub path: String,
    pub value: Option<String>,
    pub created_file: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedState {
    pub prior: Option<String>,
    pub owned_pac: Option<String>,
    /// During a URL refresh either registry value is recoverable after a crash.
    pub previous_pac: Option<String>,
    pub session: Option<String>,
    /// 本次是否接管过 winget 的设置文件；`None` = 没接管。
    pub winget: Option<WingetState>,
}

impl SavedState {
    pub fn new(prior: Option<String>, port: u16) -> Self {
        Self {
            prior,
            owned_pac: Some(format!("http://127.0.0.1:{port}/winget-accel.pac")),
            previous_pac: None,
            // 这是会话标识，不用作认证凭据。
            session: Some(format!(
                "{:016x}{:016x}",
                fastrand::u64(..),
                fastrand::u64(..)
            )),
            winget: None,
        }
    }

    /// 记下 winget 设置的原值（由 `EnvGuard::enable` 在写入后调用）。
    pub fn with_winget(mut self, winget: WingetState) -> Self {
        self.winget = Some(winget);
        self
    }

    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        if !text.starts_with('{') {
            // 升级兼容：旧版用空文件表示原本没有 PAC，或直接记录原 URL。
            if text.is_empty()
                || text.starts_with("http://")
                || text.starts_with("https://")
                || text.starts_with("file://")
            {
                return Ok(Self {
                    prior: (!text.is_empty()).then(|| text.to_string()),
                    owned_pac: None,
                    previous_pac: None,
                    session: None,
                    winget: None,
                });
            }
            bail!("PAC 状态不是可识别的旧格式或 JSON");
        }
        let doc: serde_json::Value = serde_json::from_str(text)?;
        let version = doc.get("version").and_then(|v| v.as_u64());
        if !matches!(version, Some(1 | 2)) {
            bail!("PAC 状态版本不支持");
        }
        let prior = match doc.get("prior") {
            Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(value)) if version == Some(1) => {
                (!value.trim().is_empty()).then(|| value.clone())
            }
            Some(serde_json::Value::String(value)) => Some(value.clone()),
            _ => bail!("PAC 状态缺少合法的 prior"),
        };
        let (owned_pac, session) = if version == Some(2) {
            let owned = doc
                .get("ownedPac")
                .and_then(|v| v.as_str())
                .filter(|value| is_owned_endpoint(value))
                .context("PAC 状态缺少合法的 ownedPac")?;
            let session = doc
                .get("session")
                .and_then(|v| v.as_str())
                .filter(|value| !value.is_empty())
                .context("PAC 状态缺少 session")?;
            if !matches_session(owned, session) {
                bail!("PAC 状态 ownedPac 会话不匹配");
            }
            (Some(owned.to_string()), Some(session.to_string()))
        } else {
            (None, None)
        };
        let previous_pac = match doc.get("previousPac") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(value))
                if is_owned_endpoint(value)
                    && session
                        .as_deref()
                        .is_some_and(|session| matches_session(value, session))
                    && value.split('?').next()
                        == owned_pac.as_deref().and_then(|url| url.split('?').next()) =>
            {
                Some(value.clone())
            }
            _ => bail!("PAC 状态 previousPac 非法"),
        };
        Ok(Self {
            prior,
            owned_pac,
            previous_pac,
            session,
            winget: parse_winget(&doc),
        })
    }

    pub fn owns(&self, current: Option<&str>) -> bool {
        match (&self.owned_pac, current) {
            (Some(owned), Some(current)) => {
                current == owned || self.previous_pac.as_deref() == Some(current)
            }
            // 旧版没有记录自己写入的值，只在当前仍明确指向本工具时恢复。
            (None, Some(current)) => is_our_pac(current),
            _ => false,
        }
    }

    pub fn set_revision(&mut self, revision: u64, current: String) -> Result<()> {
        let base = self
            .owned_pac
            .as_deref()
            .context("missing owned PAC")?
            .split('?')
            .next()
            .unwrap();
        let session = self.session.as_deref().context("missing session")?;
        self.owned_pac = Some(format!("{base}?session={session}&route={revision}"));
        self.previous_pac = Some(current);
        Ok(())
    }
}

/// 解析 winget 原值。字段缺失或类型不对就当作"没接管过"——
/// 宁可少恢复一次，也不要在信息不全时去改用户的设置文件。
fn parse_winget(doc: &serde_json::Value) -> Option<WingetState> {
    let winget = doc.get("winget")?;
    if winget.is_null() {
        return None;
    }
    let path = winget.get("path")?.as_str()?.to_string();
    if path.trim().is_empty() {
        return None;
    }
    let value = match winget.get("value") {
        Some(serde_json::Value::String(text)) => Some(text.clone()),
        Some(serde_json::Value::Null) | None => None,
        Some(_) => return None,
    };
    let created_file = winget
        .get("createdFile")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Some(WingetState {
        path,
        value,
        created_file,
    })
}

fn is_our_pac(value: &str) -> bool {
    value
        .strip_prefix("http://127.0.0.1:")
        .and_then(|rest| rest.strip_suffix("/winget-accel.pac"))
        .and_then(|port| port.parse::<u16>().ok())
        .is_some_and(|port| port != 0)
}

fn is_owned_endpoint(value: &str) -> bool {
    if is_our_pac(value) {
        return true;
    }
    let Some((base, query)) = value.split_once('?') else {
        return false;
    };
    let Some((session, revision)) = query
        .strip_prefix("session=")
        .and_then(|q| q.split_once("&route="))
    else {
        return false;
    };
    is_our_pac(base)
        && !session.is_empty()
        && session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && revision.parse::<u64>().is_ok()
}

fn matches_session(value: &str, session: &str) -> bool {
    value.split_once('?').is_none_or(|(_, query)| {
        query
            .strip_prefix("session=")
            .and_then(|q| q.split_once("&route="))
            .is_some_and(|(value, _)| value == session)
    })
}

pub fn read(path: &Path) -> Result<Option<SavedState>> {
    match std::fs::read_to_string(path) {
        Ok(text) => SavedState::parse(&text).map(Some).with_context(|| {
            format!(
                "PAC 状态 {} 无法解析；保留文件，请检查后再启动",
                path.display()
            )
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("读不了 PAC 状态 {}", path.display())),
    }
}

pub fn write(path: &Path, state: &SavedState) -> Result<()> {
    let mut doc = if state.session.is_some() {
        serde_json::json!({
            "version": 2,
            "prior": state.prior,
            "ownedPac": state.owned_pac,
            "previousPac": state.previous_pac,
            "session": state.session,
        })
    } else {
        serde_json::json!({ "version": 1, "prior": state.prior })
    };
    if let Some(winget) = &state.winget {
        doc["winget"] = serde_json::json!({
            "path": winget.path,
            "value": winget.value,
            "createdFile": winget.created_file,
        });
    }
    let tmp = path.with_extension("json.tmp");
    let mut file = File::create(&tmp)
        .with_context(|| format!("写不了 {}，请检查状态目录是否可写", tmp.display()))?;
    file.write_all(doc.to_string().as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path).with_context(|| format!("无法原子替换 PAC 状态 {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_requires_owner_and_version_and_preserves_prior() {
        let state = SavedState::new(Some("http://corp.example/代理.pac".into()), 18443);
        assert!(state.owns(Some("http://127.0.0.1:18443/winget-accel.pac")));
        assert!(!state.owns(Some("http://corp.example/new.pac")));
        assert!(!state.owns(None));
        for text in [
            "{}",
            r#"{"version":999,"prior":null}"#,
            r#"{"version":2,"prior":null}"#,
            r#"{"version":1}"#,
            r#"{"version":1,"prior":false}"#,
        ] {
            assert!(SavedState::parse(text).is_err(), "{text}");
        }
        // 空 REG_SZ 与值不存在不同，新日志须原样保留。
        let mut empty = state.clone();
        empty.prior = Some(String::new());
        let text = serde_json::json!({
            "version": 2, "prior": "", "ownedPac": empty.owned_pac, "session": empty.session
        })
        .to_string();
        assert_eq!(SavedState::parse(&text).unwrap(), empty);
        let mut versioned = state.clone();
        versioned
            .set_revision(1, state.owned_pac.clone().unwrap())
            .unwrap();
        let mut doc = serde_json::json!({
            "version": 2, "prior": state.prior, "ownedPac": versioned.owned_pac,
            "previousPac": versioned.previous_pac, "session": versioned.session
        });
        assert_eq!(SavedState::parse(&doc.to_string()).unwrap(), versioned);
        doc["session"] = "different-session".into();
        assert!(SavedState::parse(&doc.to_string()).is_err());
        doc["session"] = versioned.session.unwrap().into();
        doc["previousPac"] =
            "http://127.0.0.1:18443/winget-accel.pac?session=different&route=0".into();
        assert!(SavedState::parse(&doc.to_string()).is_err());
    }

    #[test]
    fn legacy_recovery_only_owns_an_exact_local_pac_url() {
        let state = SavedState::parse("").unwrap();
        assert!(state.owns(Some("http://127.0.0.1:8443/winget-accel.pac")));
        for current in [
            "http://corp.example/new.pac",
            "http://127.0.0.1:8443/other.pac",
            "http://127.0.0.1:0/winget-accel.pac",
            "http://127.0.0.1:8443/winget-accel.pac?x=1",
        ] {
            assert!(!state.owns(Some(current)), "{current}");
        }
    }

    #[test]
    fn journal_roundtrip_and_unreadable_state_are_distinct_from_absent() {
        let dir = std::env::temp_dir().join(format!("wg-journal-{:016x}", fastrand::u64(..)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(STATE_FILE);
        assert!(read(&path).unwrap().is_none());
        // 目录不能被误读为空 state，否则会把原 PAC 当成不存在。
        assert!(read(&dir).is_err());
        let state = SavedState::new(Some("http://corp.example/代理.pac".into()), 18443);
        write(&path, &state).unwrap();
        assert_eq!(read(&path).unwrap(), Some(state));
        let next = SavedState::new(None, 18444);
        write(&path, &next).unwrap();
        assert_eq!(read(&path).unwrap(), Some(next));
        assert!(!path.with_extension("json.tmp").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pac_lock_is_exclusive_and_released_on_drop() {
        let dir = std::env::temp_dir().join(format!("wg-lock-{:016x}", fastrand::u64(..)));
        let first = PacLock::acquire_at(&dir).unwrap();
        assert!(PacLock::acquire_at(&dir).is_err());
        drop(first);
        let second = PacLock::acquire_at(&dir).unwrap();
        drop(second);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
