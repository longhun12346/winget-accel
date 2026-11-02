//! 候选加速器清单：首次运行时从上游获取一次，缓存到本地，与内置清单合并。
//!
//! 设计取舍（2026-11-02 与用户对齐，含一次纠正）：
//!
//! - **首次运行时获取一次**。用户明确要求动态获取；此前我实现成"编译期嵌入 +
//!   本地文件覆盖"，没有任何网络获取，等于把需求换掉了。这条注释就是为了
//!   避免以后再次误读。
//! - 之后走缓存，不再每次启动都联网（公共站点不该被每次启动打扰）。
//! - 多个上游端点按顺序回退：`raw.githubusercontent.com` 在国内可能不通，
//!   所以再挂 jsDelivr 与加速器两条备路。全失败就用内置清单，程序照常启动。
//! - **获取到的候选不直接信任**：它们只是"待测"，启动探测（206 + 64 KiB + 速度）
//!   没通过的一律不进调度池。清单来源不可信，实测结果才可信。
//! - 内嵌清单永远保留，作为离线兜底（上游全挂、断网、缓存损坏都能启动）。

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// 编译期嵌入的清单（来自仓库根的 candidates.json）。
const EMBEDDED: &str = include_str!("../candidates.json");

/// 随包的清单文件名（放在 exe 同目录）。
pub const FILE_NAME: &str = "candidates.json";
/// 获取结果的缓存文件名。机器写入，用户不必编辑。
pub const CACHE_FILE_NAME: &str = "candidates.cache.json";

/// 上游端点，按顺序尝试。任一成功即止。
///
/// 为什么多个：
/// - `raw.githubusercontent.com` 最直接，但国内经常不通；
/// - jsDelivr 服务 GitHub 公开仓库文件（实测 cdn/fastly/gcore/testingcf 四个域都 200，
///   其中 testingcf 最快 893 ms）；
/// - 最后一条走公共加速器，是"用被加速的对象去取加速器清单"的自举，
///   聊胜于无。
///
/// **注意**：本仓库当前是私有的，jsDelivr 与 githack 都取不到私有仓库的文件，
/// 所以第 2、3 条现在必然失败——只有在仓库转公开、或清单另存到公开位置后才有效。
/// 保留它们是因为那是最可能的后续形态，失败时只是回退下一条。
const UPSTREAM_URLS: [&str; 4] = [
    "https://raw.githubusercontent.com/longhun12346/winget-accel/main/candidates.json",
    "https://cdn.jsdelivr.net/gh/longhun12346/winget-accel@main/candidates.json",
    "https://fastly.jsdelivr.net/gh/longhun12346/winget-accel@main/candidates.json",
    "https://gh-proxy.com/https://raw.githubusercontent.com/longhun12346/winget-accel/main/candidates.json",
];

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
/// 优先级：用户手放的 `candidates.json` > 网络缓存 > 首次获取 > 内嵌清单。
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

    // 2) 网络缓存
    let cache = dir.join(CACHE_FILE_NAME);
    if cache.is_file() {
        if let Ok(text) = std::fs::read_to_string(&cache) {
            if let Ok(list) = parse(&text) {
                if !list.is_empty() {
                    return (list, format!("{}（缓存）", cache.display()));
                }
            }
            crate::log::warn("候选清单缓存损坏，将重新获取");
        }
    }

    // 3) 首次运行：从上游获取一次并落缓存
    if allow_fetch {
        match fetch_and_cache(&cache) {
            Ok(list) => {
                crate::log::info(&format!(
                    "首次运行：已从上游获取候选清单（{} 条），已缓存",
                    list.len()
                ));
                return (list, "上游获取".to_string());
            }
            Err(err) => {
                crate::log::warn(&format!(
                    "获取候选清单失败（{err:#}），改用内置清单；不影响使用"
                ));
            }
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

/// 依次尝试各上游端点，成功后写缓存并返回。
fn fetch_and_cache(cache: &Path) -> Result<Vec<Candidate>> {
    let mut errors: Vec<String> = Vec::new();
    for url in UPSTREAM_URLS {
        match http_get(url, 8) {
            Ok(body) => match parse(&body) {
                Ok(list) if !list.is_empty() => {
                    // 缓存写失败不该导致失败：清单已经拿到了
                    if let Err(err) = std::fs::write(cache, &body) {
                        crate::log::warn(&format!("候选清单缓存写入失败（{err}）"));
                    }
                    return Ok(list);
                }
                Ok(_) => errors.push(format!("{url}: 内容为空")),
                Err(err) => errors.push(format!("{url}: 解析失败 {err:#}")),
            },
            Err(err) => errors.push(format!("{url}: {err:#}")),
        }
    }
    anyhow::bail!("所有上游都失败: {}", errors.join(" | "))
}

/// 极简 HTTPS GET（只要 200 的纯文本）。
///
/// 不复用 proxy 的转发逻辑：那套是"改写 + 转发"，这里是"直连取一个小文件"，
/// 混在一起会让两边都变复杂。这里只要 rustls + webpki-roots。
fn http_get(url: &str, timeout_secs: u64) -> Result<String> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let rest = url.split_once("://").context("URL 缺少 scheme")?.1;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let host = authority.split(':').next().unwrap_or(authority);
    let port = 443u16;

    let timeout = Duration::from_secs(timeout_secs);
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("解析不了 {host}"))?
        .collect();
    let mut stream = None;
    for addr in addrs {
        if let Ok(s) = TcpStream::connect_timeout(&addr, timeout) {
            stream = Some(s);
            break;
        }
    }
    let tcp = stream.with_context(|| format!("连不上 {host}:{port}"))?;
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name: rustls::pki_types::ServerName<'static> = host
        .to_string()
        .try_into()
        .map_err(|_| anyhow::anyhow!("非法主机名: {host}"))?;
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(cfg), name)
        .context("建立 TLS 连接失败")?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: winget-accel/{}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    tls.write_all(req.as_bytes()).context("发送请求失败")?;
    tls.flush().ok();

    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                // 防御：清单不该超过 1 MB，超过说明取到的不是我们要的东西
                if raw.len() > 1024 * 1024 {
                    anyhow::bail!("响应过大（>1 MB），可能不是候选清单");
                }
            }
            Err(err) => {
                // Connection: close 下服务端关闭可能表现为错误；已收到内容就不算失败
                if raw.is_empty() {
                    return Err(err).context("读取响应失败");
                }
                break;
            }
        }
    }

    let (head, body) = split_http_response(&raw)?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status != 200 {
        anyhow::bail!("HTTP {status}");
    }
    String::from_utf8(body).context("响应不是 UTF-8")
}

/// 拆出响应头与正文；处理 `Transfer-Encoding: chunked`。
fn split_http_response(raw: &[u8]) -> Result<(String, Vec<u8>)> {
    let pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("响应里没有头部结束标记")?;
    let head = String::from_utf8_lossy(&raw[..pos]).to_string();
    let body = &raw[pos + 4..];

    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        let mut out = Vec::new();
        let mut rest = body;
        while let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") {
            let size_str = String::from_utf8_lossy(&rest[..line_end]);
            let size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);
            if size == 0 {
                break;
            }
            let start = line_end + 2;
            let end = start + size;
            if end > rest.len() {
                out.extend_from_slice(&rest[start..]);
                break;
            }
            out.extend_from_slice(&rest[start..end]);
            rest = &rest[(end + 2).min(rest.len())..];
        }
        return Ok((head, out));
    }

    Ok((head, body.to_vec()))
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
    fn split_response_handles_plain_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (head, body) = split_http_response(raw).unwrap();
        assert!(head.starts_with("HTTP/1.1 200"));
        assert_eq!(body, b"hello");
    }

    #[test]
    fn split_response_handles_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n";
        let (_head, body) = split_http_response(raw).unwrap();
        assert_eq!(body, b"helloabc");
    }

    #[test]
    fn split_response_without_blank_line_is_error() {
        assert!(split_http_response(b"HTTP/1.1 200 OK").is_err());
    }
}
