//! 候选加速器清单：从仓库内的 `candidates.json` 读取，与内置默认合并。
//!
//! 设计取舍（2026-11-02 与用户对齐）：
//!
//! - **不抓第三方清单页**。实测过 roadmap 里记的两个源：
//!   `hubporg/CF-GitHub-Proxy` 的 README 尚可用但内容会变，
//!   `lightjunction/magicnet` 的 `docs/github-downloads.md` 已经 404（文件被删）。
//!   把"别人的 README"当数据源，等于把可用性绑在别人不删文件上。
//! - 清单**维护在本仓库**，由 `candidates.yml` 定期实测后自动更新（见该 workflow）。
//! - 运行时**不联网**取清单：优先读 exe 同目录的 `candidates.json`（用户可自行编辑），
//!   没有则用编译期嵌入的那份。这样"绿色版"不依赖网络，也不会因为源站挂了而失效。
//! - 清单里的条目属于**外来候选**，必须实测通过才启用（见 `proxy::spawn_health_prober`）；
//!   内置的 5 个即使探测失败也保留可用（探测失败可能只是探测资产不可达）。

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// 编译期嵌入的清单（来自仓库根的 candidates.json）。
const EMBEDDED: &str = include_str!("../candidates.json");

/// 随包的清单文件名（放在 exe 同目录，用户可改）。
pub const FILE_NAME: &str = "candidates.json";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDoc {
    #[serde(default)]
    candidates: Vec<RawEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEntry {
    name: String,
    template: String,
    /// 内置候选：探测失败也保留可用。
    #[serde(default)]
    builtin: bool,
}

/// 一条候选。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub name: String,
    pub template: String,
    /// 是否内置。内置的探测失败不排除；外来的探测失败即排除。
    pub builtin: bool,
}

impl Candidate {
    /// 从 template 里取 host，用于去重。
    pub fn host(&self) -> Option<&str> {
        let rest = self.template.split_once("://")?.1;
        let authority = rest.split('/').next()?;
        Some(authority.split(':').next().unwrap_or(authority))
    }
}

/// 读取清单：优先 exe 同目录的 `candidates.json`，否则用嵌入版。
///
/// 返回 (候选列表, 来源说明)。来源说明用于日志——用户需要知道
/// "这次用的是随包清单还是编译进去的那份"。
pub fn load(dir: &Path) -> (Vec<Candidate>, String) {
    let external = dir.join(FILE_NAME);
    if external.is_file() {
        match std::fs::read_to_string(&external) {
            Ok(text) => match parse(&text) {
                Ok(list) if !list.is_empty() => {
                    return (list, format!("{}（外部）", external.display()));
                }
                Ok(_) => {}
                Err(err) => {
                    // 外部文件写坏了不该导致启动失败，退回嵌入版并说明原因
                    crate::log::warn(&format!(
                        "候选清单解析失败（{err:#}），改用内置清单: {}",
                        external.display()
                    ));
                }
            },
            Err(err) => crate::log::warn(&format!(
                "候选清单读取失败（{err}），改用内置清单: {}",
                external.display()
            )),
        }
    }
    match parse(EMBEDDED) {
        Ok(list) => (list, "编译期内置".to_string()),
        Err(err) => {
            // 嵌入的内容是编译期常量，坏了属于程序 bug；退化为空表，
            // 由调用方回退到 DEFAULT_ACCELERATORS。
            crate::log::error(&format!("内置候选清单损坏（不应发生）: {err:#}"));
            (Vec::new(), "内置清单损坏".to_string())
        }
    }
}

fn parse(text: &str) -> Result<Vec<Candidate>> {
    let doc: RawDoc = serde_json::from_str(text).context("候选清单不是合法 JSON")?;
    let mut out = Vec::with_capacity(doc.candidates.len());
    for entry in doc.candidates {
        if entry.name.trim().is_empty() || entry.template.trim().is_empty() {
            continue;
        }
        // 清单比配置文件更严格：必须显式带 http(s)://，且必须含 {url} 占位符。
        //
        // 为什么不只靠 parse_accel：它对配置是宽容的（`host`、`host:port` 都算合法，
        // 缺 scheme 时按 https 处理），所以在清单里 `"not-a-url"` 会被解析成一个
        // 主机名叫 `not-a-url` 的候选——不报错，但永远连不上，属于静默失效。
        if entry.template.trim() != entry.template {
            crate::log::warn(&format!("候选模板含多余空白，已跳过: {}", entry.name));
            continue;
        }
        let has_scheme =
            entry.template.starts_with("http://") || entry.template.starts_with("https://");
        if !has_scheme {
            crate::log::warn(&format!(
                "候选模板缺少 http(s)://，已跳过: {} => {}",
                entry.name, entry.template
            ));
            continue;
        }
        if !entry.template.contains("{url}") {
            crate::log::warn(&format!(
                "候选模板缺少 {{url}} 占位符，已跳过: {} => {}",
                entry.name, entry.template
            ));
            continue;
        }
        if crate::rewrite::parse_accel(&entry.template).is_err() {
            crate::log::warn(&format!(
                "候选模板非法，已跳过: {} => {}",
                entry.name, entry.template
            ));
            continue;
        }
        out.push(Candidate {
            name: entry.name,
            template: entry.template,
            builtin: entry.builtin,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_list_parses_and_has_entries() {
        let list = parse(EMBEDDED).expect("嵌入清单必须可解析");
        // 不断言具体数量：清单会随实测调整（2026-11-02 按"必须权威可靠"降到 4 个）。
        // 断言的是不变量：必须有内置条目，否则离线/上游消失时没有兜底。
        assert!(!list.is_empty(), "嵌入清单不能为空");
        assert!(
            list.iter().any(|c| c.builtin),
            "必须至少有一个 builtin 候选作为离线兜底"
        );
        assert!(
            list.iter().all(|c| c.template.contains("{url}")),
            "每条模板都必须含 {{url}}"
        );
    }

    #[test]
    fn host_is_extracted_from_template() {
        let c = Candidate {
            name: "x".into(),
            template: "https://gh-proxy.com/{url}".into(),
            builtin: true,
        };
        assert_eq!(c.host(), Some("gh-proxy.com"));
    }

    #[test]
    fn host_handles_explicit_port() {
        let c = Candidate {
            name: "x".into(),
            template: "http://127.0.0.1:8080/{url}".into(),
            builtin: false,
        };
        assert_eq!(c.host(), Some("127.0.0.1"));
    }

    #[test]
    fn invalid_template_is_dropped() {
        let json = r#"{"candidates":[
            {"name":"good","template":"https://a.example/{url}"},
            {"name":"bad","template":"not-a-url"}
        ]}"#;
        let list = parse(json).unwrap();
        assert_eq!(list.len(), 1, "非法模板应被丢弃");
        assert_eq!(list[0].name, "good");
    }

    #[test]
    fn empty_names_are_dropped() {
        let json = r#"{"candidates":[
            {"name":"","template":"https://a.example/{url}"},
            {"name":"ok","template":"https://b.example/{url}"}
        ]}"#;
        assert_eq!(parse(json).unwrap().len(), 1);
    }

    #[test]
    fn broken_json_is_an_error_not_a_panic() {
        assert!(parse("{not json").is_err());
    }

    #[test]
    fn load_falls_back_to_embedded_when_file_absent() {
        let dir = std::env::temp_dir().join("wg-cand-absent-test");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(dir.join(FILE_NAME));
        let (list, source) = load(&dir);
        assert!(!list.is_empty(), "应回退到嵌入清单");
        assert_eq!(source, "编译期内置");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_prefers_external_file() {
        let dir = std::env::temp_dir().join("wg-cand-ext-test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join(FILE_NAME),
            r#"{"candidates":[{"name":"ext","template":"https://ext.example/{url}"}]}"#,
        )
        .unwrap();
        let (list, source) = load(&dir);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "ext");
        assert!(source.contains("外部"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broken_external_file_falls_back_to_embedded() {
        let dir = std::env::temp_dir().join("wg-cand-broken-test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join(FILE_NAME), "{ broken").unwrap();
        let (list, source) = load(&dir);
        assert!(!list.is_empty(), "外部清单损坏时应回退");
        assert_eq!(source, "编译期内置");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
