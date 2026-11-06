//! 接管 winget 的下载器选择：把 `network.downloader` 设为 `wininet`，退出时还原。
//!
//! 为什么需要（2026-11-04 实测）：winget 下载的顺序是
//! 「Delivery Optimization → 失败 → WinINet」。DO 不读 PAC，直连 github.com 必失败，
//! 每次白等 60 秒（日志 `DeliveryOptimization error 0x80072EE2`），之后才回退到
//! WinINet 走本代理。3 轮 `winget download --id Git.Git` 的实测：
//! 第 1 轮 165 秒后 `0x80072EFD` 失败且**全程没碰到代理**（DO 两次 + WinINet 两次直连），
//! 第 2 轮 600 秒超时，第 3 轮 334 秒成功。把下载器钉成 WinINet 能直接消掉那条必败路径。
//!
//! 边界（刻意不越界）：
//! - 只改 `network.downloader` 一个键，其余键（含未知键）原样保留，写回时按 JSON 原结构；
//! - 文件不存在就创建一个**只含该键**的文件，退出时若仍是空对象就删掉它；
//! - 绝不碰 DO 的系统级设置（WinHTTP 代理、机器根证书）：那会把代理扩到「全机所有
//!   WinHTTP 客户端」，直接违反 ADR-014 的第 2 条约束（见 docs/decisions.md）。
//! - 配置写坏（不是合法 JSON）时**不覆盖**，只报错让调用方告警——宁可不管，也不毁别人的配置。

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// 要写入的下载器取值。winget 的 `network.downloader` 只接受 `default`/`wininet`/`do`。
pub const DOWNLOADER: &str = "wininet";

/// winget 的用户级设置文件。
///
/// 路径由 App Installer 的包族名决定（`Microsoft.DesktopAppInstaller_8wekyb3d8bbwe`），
/// 这是 winget 自身的约定，不随语言/版本变化。
pub fn settings_path() -> Option<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")?;
    Some(
        PathBuf::from(local)
            .join("Packages")
            .join("Microsoft.DesktopAppInstaller_8wekyb3d8bbwe")
            .join("LocalState")
            .join("settings.json"),
    )
}

/// 改动前的状态，够用来精确还原。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prior {
    pub path: PathBuf,
    /// 改动前的 `network.downloader`；`None` = 原本没有这个键。
    pub value: Option<String>,
    /// 文件是否由我们创建（原本不存在）。还原时据此决定删文件还是只删键。
    pub created_file: bool,
}

/// 读出"改动前"的状态，**不写任何东西**。
///
/// 与 [`apply_at`] 分开是必要的：状态必须先落到 `state.json`，再去改别人的配置——
/// 否则"改完就崩"会丢掉原值，再也还原不回去。
pub fn inspect_at(path: &Path) -> Result<Prior> {
    if !path.exists() {
        return Ok(Prior {
            path: path.to_path_buf(),
            value: None,
            created_file: true,
        });
    }
    let doc = read_doc(path)?;
    let value = downloader_of(&doc);
    Ok(Prior {
        path: path.to_path_buf(),
        value,
        created_file: false,
    })
}

/// 写入 `network.downloader = wininet`，其余内容保持不变。
pub fn apply_at(prior: &Prior) -> Result<()> {
    let mut doc = if prior.created_file && !prior.path.exists() {
        // 文件本来不存在：从一个空对象开始，父目录按需创建
        serde_json::json!({})
    } else {
        read_doc(&prior.path)?
    };
    let obj = doc
        .as_object_mut()
        .with_context(|| format!("{} 的顶层不是 JSON 对象，不敢改", prior.path.display()))?;
    let network = obj
        .entry("network")
        .or_insert_with(|| serde_json::json!({}));
    let kind = kind_of(network);
    let net = network.as_object_mut().with_context(|| {
        format!(
            "{} 里的 `network` 不是对象（实际是 {kind}），不敢改",
            prior.path.display()
        )
    })?;
    net.insert(
        "downloader".to_string(),
        serde_json::Value::String(DOWNLOADER.to_string()),
    );
    write_doc(&prior.path, &doc)
}

/// 还原到 [`apply_at`] 之前的样子。
///
/// 三种情形：原本有值 → 写回；原本没这个键 → 删掉；文件本来不存在且现在只剩空壳 → 删文件。
pub fn restore_at(prior: &Prior) -> Result<()> {
    if !prior.path.exists() {
        // 文件被别的东西删了：没有可还原的东西，也不算失败
        return Ok(());
    }
    let mut doc = read_doc(&prior.path)?;
    // 只撤销仍属于本程序的值，保留用户在运行期间修改或删除的设置。
    if downloader_of(&doc).as_deref() != Some(DOWNLOADER) {
        return Ok(());
    }
    let Some(obj) = doc.as_object_mut() else {
        bail!("{} 的顶层不是 JSON 对象，无法还原", prior.path.display());
    };

    let mut drop_network = false;
    if let Some(net) = obj.get_mut("network").and_then(|v| v.as_object_mut()) {
        match &prior.value {
            Some(value) => {
                net.insert(
                    "downloader".to_string(),
                    serde_json::Value::String(value.clone()),
                );
            }
            None => {
                net.remove("downloader");
                drop_network = net.is_empty();
            }
        }
    }
    if drop_network {
        obj.remove("network");
    }

    if obj.is_empty() && prior.created_file {
        // 这个文件是我们为了一个键而创建的，现在没有内容了，删掉才叫"还原"
        return std::fs::remove_file(&prior.path)
            .with_context(|| format!("删不了 {}", prior.path.display()));
    }
    write_doc(&prior.path, &doc)
}

/// 当前 `network.downloader` 的值（`--doctor` 用）。读不出来一律 `None`。
pub fn current_at(path: &Path) -> Option<String> {
    let doc = read_doc(path).ok()?;
    downloader_of(&doc)
}

fn downloader_of(doc: &serde_json::Value) -> Option<String> {
    doc.get("network")
        .and_then(|n| n.get("downloader"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn read_doc(path: &Path) -> Result<serde_json::Value> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("读不了 {}", path.display()))?;
    // 空文件（被截断）按空对象处理：winget 自己也读不出内容，覆盖写掉反而是修复。
    // 但**非空且非法**的 JSON 一定要报错——那可能是用户手写的配置，不能吞掉。
    if text.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_str(&text).with_context(|| {
        format!(
            "{} 不是合法 JSON（可能是手写配置或写了一半），为免覆盖你的设置，本次不改",
            path.display()
        )
    })
}

fn write_doc(path: &Path, doc: &serde_json::Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("建不了目录 {}", parent.display()))?;
    }
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".wg.tmp");
    let tmp = PathBuf::from(tmp);
    let text = serde_json::to_string_pretty(doc).context("序列化 settings.json 失败")?;
    std::fs::write(&tmp, text + "\n").with_context(|| format!("写不了 {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("改不了名 {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

fn kind_of(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "布尔值",
        serde_json::Value::Number(_) => "数字",
        serde_json::Value::String(_) => "字符串",
        serde_json::Value::Array(_) => "数组",
        serde_json::Value::Object(_) => "对象",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn restore_preserves_manual_changes_and_deletions() {
        let dir = temp_dir("winget-manual");
        let path = dir.join("settings.json");
        for manual in [
            serde_json::json!({"network":{"downloader":"do"}, "custom":true}),
            serde_json::json!({"network":{}, "custom":true}),
            serde_json::json!({"custom":true}),
        ] {
            write_doc(
                &path,
                &serde_json::json!({"network":{"downloader":"default"}}),
            )
            .unwrap();
            let prior = inspect_at(&path).unwrap();
            apply_at(&prior).unwrap();
            write_doc(&path, &manual).unwrap();
            let before = std::fs::read(&path).unwrap();
            restore_at(&prior).unwrap();
            restore_at(&prior).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
        let prior = inspect_at(&path).unwrap();
        apply_at(&prior).unwrap();
        std::fs::remove_file(&path).unwrap();
        restore_at(&prior).unwrap();
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// 文件不存在时：创建它、写入键、并标记 created_file。
    #[test]
    fn creates_settings_file_when_missing() {
        let dir = temp_dir("winget-create");
        let path = dir.join("settings.json");

        let prior = inspect_at(&path).unwrap();
        assert!(prior.created_file);
        assert_eq!(prior.value, None);

        apply_at(&prior).unwrap();
        assert_eq!(current_at(&path).as_deref(), Some(DOWNLOADER));

        // 还原后文件应被删掉：原本不存在，就不该留下一个空壳
        restore_at(&prior).unwrap();
        assert!(!path.exists(), "原本没有文件，还原后不该留文件");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 已有文件：只改一个键，其它键（含未知键、其它顶层对象）必须原样保留。
    #[test]
    fn preserves_other_keys() {
        let dir = temp_dir("winget-preserve");
        let path = dir.join("settings.json");
        std::fs::write(
            &path,
            r#"{
  "$schema": "https://aka.ms/winget-settings.schema.json",
  "installBehavior": { "preferences": { "scope": "user" } },
  "network": { "doProgressTimeoutInSeconds": 15, "downloader": "default" }
}"#,
        )
        .unwrap();

        let prior = inspect_at(&path).unwrap();
        assert_eq!(prior.value.as_deref(), Some("default"));
        assert!(!prior.created_file);

        apply_at(&prior).unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["network"]["downloader"], "wininet");
        assert_eq!(doc["network"]["doProgressTimeoutInSeconds"], 15);
        assert_eq!(doc["installBehavior"]["preferences"]["scope"], "user");

        restore_at(&prior).unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["network"]["downloader"], "default", "必须写回原值");
        assert_eq!(doc["network"]["doProgressTimeoutInSeconds"], 15);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 原本没有 `network` 键：还原后要把整个 `network` 对象删掉，而不是留一个空对象。
    #[test]
    fn restore_removes_network_object_when_absent_before() {
        let dir = temp_dir("winget-remove");
        let path = dir.join("settings.json");
        std::fs::write(&path, r#"{ "visual": { "progressBar": "disabled" } }"#).unwrap();

        let prior = inspect_at(&path).unwrap();
        assert_eq!(prior.value, None);
        apply_at(&prior).unwrap();
        restore_at(&prior).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(
            doc.get("network").is_none(),
            "原本没有 network，还原后不该留: {text}"
        );
        assert_eq!(doc["visual"]["progressBar"], "disabled");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 非法 JSON：必须报错且**不覆盖**文件（那是用户手写的配置）。
    #[test]
    fn invalid_json_is_reported_and_untouched() {
        let dir = temp_dir("winget-invalid");
        let path = dir.join("settings.json");
        let broken = "{ \"network\": { \"downloader\": ";
        std::fs::write(&path, broken).unwrap();

        let err = inspect_at(&path).unwrap_err();
        assert!(
            format!("{err:#}").contains("不是合法 JSON"),
            "应说明原因: {err:#}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            broken,
            "原文件不能被改"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 空文件（崩溃留下）按空对象处理：这是可恢复的，不该挡住启动。
    #[test]
    fn empty_settings_file_is_treated_as_empty_object() {
        let dir = temp_dir("winget-empty");
        let path = dir.join("settings.json");
        std::fs::write(&path, "").unwrap();

        let prior = inspect_at(&path).unwrap();
        assert_eq!(prior.value, None);
        apply_at(&prior).unwrap();
        assert_eq!(current_at(&path).as_deref(), Some(DOWNLOADER));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `network` 存在但不是对象 → 报错，不要去"修"它。
    #[test]
    fn non_object_network_is_rejected() {
        let dir = temp_dir("winget-network-type");
        let path = dir.join("settings.json");
        std::fs::write(&path, r#"{ "network": 3 }"#).unwrap();

        let prior = inspect_at(&path).unwrap();
        let err = apply_at(&prior).unwrap_err();
        assert!(format!("{err:#}").contains("不是对象"), "{err:#}");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            r#"{ "network": 3 }"#,
            "不该改坏原文件"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 写回时用的是原子改名的临时文件，不该留下 `.wg.tmp`。
    #[test]
    fn write_leaves_no_temp_file() {
        let dir = temp_dir("winget-atomic");
        let path = dir.join("settings.json");
        let prior = inspect_at(&path).unwrap();
        apply_at(&prior).unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|name| name.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "不该留下临时文件: {leftovers:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
