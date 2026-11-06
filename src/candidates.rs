//! 候选清单：启动时刷新，网络失败时回退缓存与编译期内置清单。
//!
//! 用户手放的 candidates.json 优先。自动获取并发请求权威源与公共加速器，
//! 在六秒预算内选择候选数最多的有效结果，再缓存供离线使用。
//! 获取到的候选仍须通过运行期资产验证，不能直接进入下载调度。

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// 编译期嵌入的清单（来自仓库根的 candidates.json）。
const EMBEDDED: &str = include_str!("../candidates.json");

/// 随包的清单文件名（放在 exe 同目录）。
pub const FILE_NAME: &str = "candidates.json";
/// 获取结果的缓存文件名。机器写入，用户不必编辑。
pub const CACHE_FILE_NAME: &str = "candidates.cache.json";

/// 并发获取的上游：权威源与公共加速器。环境变量 WINGET_ACCEL_CANDIDATES_URL
/// 可覆盖为自建镜像或本地验证地址。
const UPSTREAM_URLS: [&str; 2] = [
    // 权威源。直连不通时靠下面的加速器。
    "https://raw.githubusercontent.com/longhun12346/winget-accel/main/candidates.json",
    // 加速器路径：内容与权威源一致（实测两者都是 43 条），只是多一跳。
    "https://gh-proxy.com/https://raw.githubusercontent.com/longhun12346/winget-accel/main/candidates.json",
];

/// **不要**把 jsDelivr 的 `@main` 端点当成数据源。
///
/// 实测踩过：jsDelivr 对 `@branch` 有约 12 小时缓存。我们刚把清单从 4 条
/// 更新到 43 条，`cdn.jsdelivr.net` 与 `fastly.jsdelivr.net` 仍返回旧的 4 条，
/// 而 `raw.githubusercontent.com` 与加速器已是 43 条。
/// 当时 `fetch_best` 取"最快成功"的那个，而 jsDelivr 响应更快，
/// 结果就是**拿到了过期数据**。
///
/// 教训："最快"不等于"最新"。宁可多等 300 ms 拿权威源，也不要秒回旧数据。
/// 若将来要用 jsDelivr，必须用 tag 或 commit hash 的 URL（不可变），不能用分支。

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
    /// 内置候选。仅内嵌清单会用它。
    #[serde(default)]
    builtin: bool,
}

/// 一条候选。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub name: String,
    pub template: String,
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

/// 读取清单。
///
/// 优先级：用户手放的 `candidates.json` > 网络刷新 > 网络缓存 > 内嵌清单。
///
/// `allow_fetch` 为 false 时不联网（测试或用户显式关闭）。
pub fn load(dir: &Path, allow_fetch: bool) -> (Vec<Candidate>, String) {
    // 1) 用户手放的文件优先：那是明确的人工选择
    let manual = dir.join(FILE_NAME);
    if manual.is_file() {
        match std::fs::read_to_string(&manual) {
            Ok(text) => match parse(&text) {
                Ok(list) if !list.is_empty() => {
                    return (list, format!("{}（手动放置）", manual.display()));
                }
                Ok(_) => {}
                Err(err) => crate::log::warn(&format!(
                    "候选清单解析失败（{err:#}），忽略: {}",
                    manual.display()
                )),
            },
            Err(err) => crate::log::warn(&format!(
                "候选清单读取失败（{err}），忽略: {}",
                manual.display()
            )),
        }
    }

    let cache = dir.join(CACHE_FILE_NAME);

    // 2) **每次运行都从上游获取**（用户明确要求）。
    //    并发请求所有端点，在六秒预算内取候选数最多的有效结果。
    if allow_fetch {
        let started = std::time::Instant::now();
        match fetch_best() {
            Ok((body, list, url)) => {
                // 缓存是给"下次离线"用的兜底，写失败不影响本次
                if let Err(err) = std::fs::write(&cache, &body) {
                    crate::log::warn(&format!("候选清单缓存写入失败（{err}）"));
                }
                crate::log::info(&format!(
                    "已从上游获取候选清单：{} 条，来源={}，耗时 {} ms",
                    list.len(),
                    url,
                    started.elapsed().as_millis()
                ));
                return (list, format!("上游获取: {url}"));
            }
            Err(err) => {
                crate::log::warn(&format!(
                    "获取候选清单失败（{err:#}），改用本地缓存/内置清单；不影响使用"
                ));
            }
        }
    }

    // 3) 获取失败才看缓存（离线 / 上游全挂）
    if cache.is_file() {
        if let Ok(text) = std::fs::read_to_string(&cache) {
            if let Ok(list) = parse(&text) {
                if !list.is_empty() {
                    return (list, format!("{}（缓存）", cache.display()));
                }
            }
            crate::log::warn("候选清单缓存损坏，改用内置清单");
        }
    }

    // 4) 内嵌兜底
    match parse(EMBEDDED) {
        Ok(list) => (list, "编译期内置".to_string()),
        Err(err) => {
            crate::log::error(&format!("内置候选清单损坏（不应发生）: {err:#}"));
            (Vec::new(), "内置清单损坏".to_string())
        }
    }
}

/// 并发获取上游，六秒内选择候选数最多的有效结果；全部失败则回退本地清单。
fn fetch_best() -> Result<(String, Vec<Candidate>, String)> {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    // 环境变量覆盖：自建镜像用，也方便本地验证整条链路
    let override_url = std::env::var("WINGET_ACCEL_CANDIDATES_URL").ok();
    let urls: Vec<String> = match &override_url {
        Some(u) if !u.trim().is_empty() => vec![u.trim().to_string()],
        _ => UPSTREAM_URLS.iter().map(|u| (*u).to_string()).collect(),
    };

    let known_urls = urls.clone();
    let mut seen: Vec<String> = Vec::new();

    let (tx, rx) = mpsc::channel();
    for url in urls {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let result = http_get(&url, 5).and_then(|body| {
                let list = parse(&body)?;
                Ok((body, list))
            });
            let _ = tx.send((url, result));
        });
    }
    drop(tx);

    // 取**内容最完整**的那份，而不是"最先返回"的那份。
    //
    // 原因：实测中 jsDelivr 的旧缓存比权威源快，按"最快"取会拿到过期数据。
    // 现在的做法是：等所有端点（最多 6 秒），选候选数最多的有效结果。
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut errors: Vec<String> = Vec::new();
    let mut best: Option<(String, Vec<Candidate>, String)> = None;
    loop {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => d,
            _ => break,
        };
        match rx.recv_timeout(remaining) {
            Ok((url, Ok((body, list)))) if !list.is_empty() => {
                seen.push(url.clone());
                crate::log::info(&format!("候选源成功: {url} -> {} 条", list.len()));
                let better = match &best {
                    Some((_, cur, _)) => list.len() > cur.len(),
                    None => true,
                };
                if better {
                    best = Some((body, list, url));
                }
            }
            Ok((url, Ok(_))) => {
                seen.push(url.clone());
                crate::log::warn(&format!("候选源返回空内容: {url}"));
                errors.push(format!("{url}: 内容为空"));
            }
            Ok((url, Err(err))) => {
                seen.push(url.clone());
                crate::log::warn(&format!("候选源失败: {url}: {err:#}"));
                errors.push(format!("{url}: {err:#}"));
            }
            Err(_) => break,
        }
    }
    for url in known_urls {
        if !seen.contains(&url) {
            crate::log::warn(&format!("候选源超时: {url}: 6 秒内未返回"));
            errors.push(format!("{url}: 6 秒内未返回"));
        }
    }
    if let Some(found) = best {
        return Ok(found);
    }
    if errors.is_empty() {
        anyhow::bail!("所有上游都在 6 秒内没有响应");
    }
    anyhow::bail!("所有上游都失败: {}", errors.join(" | "))
}
/// Same Hyper transport and total deadline as probes; decoded payload is bounded.
fn http_get(url: &str, timeout_secs: u64) -> Result<String> {
    crate::http::get_text(
        url,
        std::time::Duration::from_secs(timeout_secs),
        1024 * 1024,
    )
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
    fn read_http_body<R: std::io::Read>(reader: &mut R) -> Result<String> {
        use std::io::{Read, Write};
        let mut raw = Vec::new();
        reader.read_to_end(&mut raw)?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(&raw);
        });
        let result = http_get(&format!("http://{address}/"), 2);
        server.join().unwrap();
        result
    }

    #[test]
    fn embedded_list_parses_and_has_entries() {
        let list = parse(EMBEDDED).expect("嵌入清单必须可解析");
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
    fn load_falls_back_to_embedded_when_nothing_available() {
        let dir = std::env::temp_dir().join("wg-cand-absent-test");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(dir.join(FILE_NAME));
        let _ = std::fs::remove_file(dir.join(CACHE_FILE_NAME));
        // allow_fetch = false：不联网，直接走内嵌兜底
        let (list, source) = load(&dir, false);
        assert!(!list.is_empty(), "应回退到嵌入清单");
        assert_eq!(source, "编译期内置");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_prefers_manual_file_over_cache() {
        let dir = std::env::temp_dir().join("wg-cand-manual-test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join(FILE_NAME),
            r#"{"candidates":[{"name":"manual","template":"https://manual.example/{url}"}]}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join(CACHE_FILE_NAME),
            r#"{"candidates":[{"name":"cached","template":"https://cached.example/{url}"}]}"#,
        )
        .unwrap();
        let (list, source) = load(&dir, false);
        assert_eq!(list[0].name, "manual", "手放的文件优先于缓存");
        assert!(source.contains("手动放置"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_uses_cache_when_no_manual_file() {
        let dir = std::env::temp_dir().join("wg-cand-cache-test");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(dir.join(FILE_NAME));
        std::fs::write(
            dir.join(CACHE_FILE_NAME),
            r#"{"candidates":[{"name":"cached","template":"https://cached.example/{url}"}]}"#,
        )
        .unwrap();
        let (list, source) = load(&dir, false);
        assert_eq!(list[0].name, "cached");
        assert!(source.contains("缓存"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broken_external_file_falls_back_to_embedded() {
        let dir = std::env::temp_dir().join("wg-cand-broken-test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join(FILE_NAME), "{ broken").unwrap();
        let _ = std::fs::remove_file(dir.join(CACHE_FILE_NAME));
        let (list, source) = load(&dir, false);
        assert!(!list.is_empty(), "外部清单损坏时应回退");
        assert_eq!(source, "编译期内置");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn response_handles_plain_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let body = read_http_body(&mut std::io::Cursor::new(raw)).unwrap();
        assert_eq!(body, "hello");
    }

    #[test]
    fn response_handles_chunked() {
        use std::io::{Read, Write};
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: \tChUnKeD\r\n\r\n5\r\nhello\r\n3\r\nabc\r\n0\r\nX-Tag: test\r\n\r\n";
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (finished, wait) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0; 4096];
            let _ = stream.read(&mut buf);
            stream.write_all(raw).unwrap();
            // Keep the connection open until the client has consumed the message.
            let _ = wait.recv_timeout(std::time::Duration::from_secs(3));
        });
        let result = http_get(&format!("http://{address}/"), 1);
        let _ = finished.send(());
        server.join().unwrap();
        assert_eq!(result.unwrap(), "helloabc");
    }

    #[test]
    fn response_without_blank_line_is_error() {
        assert!(read_http_body(&mut std::io::Cursor::new(b"HTTP/1.1 200 OK")).is_err());
    }
    #[test]
    fn response_handles_chunk_extensions() {
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;foo=bar\r\nhello\r\n0\r\n\r\n";
        let body = read_http_body(&mut std::io::Cursor::new(raw)).unwrap();
        assert_eq!(body, "hello");
    }

    #[test]
    fn response_rejects_invalid_chunk_size() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n";
        assert!(read_http_body(&mut std::io::Cursor::new(raw)).is_err());
    }

    #[test]
    fn response_rejects_truncated_chunk() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
        assert!(read_http_body(&mut std::io::Cursor::new(raw)).is_err());
    }

    #[test]
    fn response_rejects_missing_terminal_chunk() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert!(read_http_body(&mut std::io::Cursor::new(raw)).is_err());
    }

    #[test]
    fn response_rejects_overflowing_chunk_length_without_panicking() {
        let size = usize::MAX - (usize::BITS as usize / 4 + 2);
        let raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size:x}\r\n");
        assert!(read_http_body(&mut std::io::Cursor::new(raw)).is_err());
    }

    #[test]
    fn response_rejects_incomplete_length_or_trailers() {
        for raw in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n{}"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n{}"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n"[..],
        ] {
            assert!(read_http_body(&mut std::io::Cursor::new(raw)).is_err());
        }
    }
}
