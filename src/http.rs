//! 最小 HTTP/1.1 读写工具。
//!
//! 刻意不用 hyper：本地单用户、并发个位数，手写这几百行反而更好审计（ADR-012）。

use std::io::{self, Read, Write};

/// 请求/响应头的大小上限。超过即认为对端有问题，直接断开。
pub const MAX_HEAD: usize = 32 * 1024;

/// httparse 需要预先分配的头部槽位数。
const MAX_HEADERS: usize = 64;

const COPY_BUF: usize = 32 * 1024;

/// 逐字节读到 `\r\n\r\n` 为止。
///
/// **必须逐字节**：CONNECT 的响应发出后，客户端会立刻开始 TLS 握手，
/// 一次性多读一个缓冲区就会把 ClientHello 吞掉，握手永远等不到数据。
/// Python 原型踩过这个坑，这里用类型和用例把它钉住。
pub fn read_head<R: Read>(stream: &mut R) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "连接在请求头结束前关闭（已读取 {} 字节: {}）",
                        buf.len(),
                        bytes_preview(&buf)
                    ),
                ))
            }
            Ok(_) => {
                buf.push(byte[0]);
                if buf.len() >= 4 && buf.ends_with(b"\r\n\r\n") {
                    return Ok(buf);
                }
                if buf.len() > MAX_HEAD {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "请求头过大（已读取 {} 字节: {}）",
                            buf.len(),
                            bytes_preview(&buf)
                        ),
                    ));
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!(
                        "读取请求头失败（已读取 {} 字节: {}）: {e}",
                        buf.len(),
                        bytes_preview(&buf)
                    ),
                ))
            }
        }
    }
}

/// 给连接失败日志提供极短的前缀预览，不记录完整请求/正文。
pub fn bytes_preview(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "空".to_string();
    }
    let hex = bytes
        .iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let hint = if bytes[0] == 0x16 {
        "，疑似 TLS ClientHello（不是 HTTP/CONNECT）"
    } else {
        ""
    };
    format!("{hex}{hint}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub method: String,
    pub target: String,
    pub version: String,
    /// 原始头行（不含请求行，不含结尾空行）。
    pub headers: Vec<String>,
}

impl Head {
    /// 按名取头的值（大小写不敏感）。目前只有单测用到，
    /// 保留是因为按头决策（如 Accept-Encoding、If-Range）会落在这一层。
    #[allow(dead_code)]
    pub fn header(&self, name: &str) -> Option<&str> {
        let want = name.to_ascii_lowercase();
        self.headers.iter().find_map(|line| {
            let (k, v) = line.split_once(':')?;
            if k.trim().to_ascii_lowercase() == want {
                Some(v.trim())
            } else {
                None
            }
        })
    }
}

/// 解析请求头。畸形输入返回 `None`，由调用方决定怎么记录。
///
/// 解析交给 `httparse`（hyper 内部用的同一套，零传递依赖），
/// 不再自己切请求行、扫冒号。`headers` 仍保留原始行文本，
/// 因为转发时要逐行透传、且要按名字剥离逐跳头。
pub fn parse_head(raw: &[u8]) -> Option<Head> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(raw) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return None,
    }

    let method = req.method?.to_string();
    let target = req.path?.to_string();
    let version = match req.version {
        Some(0) => "HTTP/1.0".to_string(),
        _ => "HTTP/1.1".to_string(),
    };
    if method.is_empty() || target.is_empty() {
        return None;
    }

    let headers = req
        .headers
        .iter()
        .map(|h| {
            let value = String::from_utf8_lossy(h.value);
            format!("{}: {}", h.name, value.trim())
        })
        .collect();

    Some(Head {
        method,
        target,
        version,
        headers,
    })
}

/// 从响应头里取状态码。
pub fn status_code(head: &[u8]) -> Option<u16> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut res = httparse::Response::new(&mut headers);
    match res.parse(head) {
        Ok(httparse::Status::Complete(_)) => res.code,
        _ => None,
    }
}

/// 从响应头里取 `Content-Length`。
pub fn content_length(head: &[u8]) -> Option<u64> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut res = httparse::Response::new(&mut headers);
    match res.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return None,
    }
    res.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|v| v.trim().parse().ok())
}

/// 按响应头决定如何转发正文，返回正文字节数。
///
/// 单独拆出来是为了让调用方**先看状态码再决定要不要转发**——
/// 遇到 429/503 时要换候选重试，不能已经把响应头写给客户端。
pub fn forward_body<R: Read, W: Write>(
    up: &mut R,
    dst: &mut W,
    head: &[u8],
    no_body: bool,
) -> io::Result<u64> {
    let status = status_code(head).unwrap_or(0);
    if no_body || status == 204 || status == 304 {
        return Ok(0);
    }
    let copied = match content_length(head) {
        Some(len) => copy_exact(up, dst, len)?,
        None => copy_to_eof(up, dst)?,
    };
    dst.flush()?;
    Ok(copied)
}

/// 429 / 503：被限流或暂时不可用，值得换一个候选重试。
pub fn is_rate_limited(status: u16) -> bool {
    matches!(status, 429 | 503)
}

fn copy_exact<R: Read, W: Write>(src: &mut R, dst: &mut W, len: u64) -> io::Result<u64> {
    let mut buf = vec![0u8; COPY_BUF];
    let mut left = len;
    while left > 0 {
        let want = std::cmp::min(left, buf.len() as u64) as usize;
        let n = match src.read(&mut buf[..want]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "上游提前关闭，正文不完整",
                ))
            }
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        dst.write_all(&buf[..n])?;
        left -= n as u64;
    }
    Ok(len)
}

fn copy_to_eof<R: Read, W: Write>(src: &mut R, dst: &mut W) -> io::Result<u64> {
    let mut buf = vec![0u8; COPY_BUF];
    let mut total = 0u64;
    loop {
        match src.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                dst.write_all(&buf[..n])?;
                total += n as u64;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// 等价于"读头 → 写头 → 转发正文"，供分帧测试使用。
    /// 生产路径走 proxy::relay_checked（它在写头前会先判 429/503）。
    fn relay_via_forward_body<R: Read, W: Write>(
        up: &mut R,
        dst: &mut W,
        no_body: bool,
    ) -> io::Result<(u16, u64)> {
        let head = read_head(up)?;
        let status = status_code(&head).unwrap_or(0);
        dst.write_all(&head)?;
        let n = forward_body(up, dst, &head, no_body)?;
        Ok((status, n))
    }

    #[test]
    fn read_head_stops_exactly_at_delimiter() {
        // 模拟 CONNECT 之后的真实情形：头后面紧跟 TLS ClientHello
        let mut data = b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n".to_vec();
        data.extend_from_slice(&[0x16, 0x03, 0x01, 0x02, 0x00]); // ClientHello 起始
        let mut cursor = Cursor::new(data.clone());

        let head = read_head(&mut cursor).unwrap();

        assert_eq!(head, b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(
            cursor.position() as usize,
            head.len(),
            "多读了 {} 字节，会把 ClientHello 吞掉",
            cursor.position() as usize - head.len()
        );
    }

    #[test]
    fn read_head_rejects_eof_before_delimiter() {
        let mut cursor = Cursor::new(b"GET /x HTTP/1.1\r\nHost: a\r\n".to_vec());
        assert!(read_head(&mut cursor).is_err());
    }

    #[test]
    fn read_head_rejects_oversized_head() {
        let mut data = b"GET / HTTP/1.1\r\n".to_vec();
        data.extend(std::iter::repeat(b'X').take(MAX_HEAD + 16));
        let mut cursor = Cursor::new(data);
        assert!(read_head(&mut cursor).is_err());
    }

    #[test]
    fn parses_request_line_and_headers() {
        let head =
            parse_head(b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n").unwrap();
        assert_eq!(head.method, "CONNECT");
        assert_eq!(head.target, "github.com:443");
        assert_eq!(head.version, "HTTP/1.1");
        assert_eq!(head.header("host"), Some("github.com:443"));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let head = parse_head(b"GET / HTTP/1.1\r\nRaNgE: bytes=0-9\r\n\r\n").unwrap();
        assert_eq!(head.header("range"), Some("bytes=0-9"));
        assert_eq!(head.header("RANGE"), Some("bytes=0-9"));
    }

    #[test]
    fn rejects_malformed_request_line() {
        assert!(parse_head(b"GARBAGE\r\n\r\n").is_none());
        assert!(parse_head(b"\r\n\r\n").is_none());
        assert!(parse_head(&[0xff, 0xfe, 0x00]).is_none(), "非 UTF-8 应拒绝");
    }

    #[test]
    fn extracts_status_and_length() {
        let head = b"HTTP/1.1 206 Partial Content\r\nContent-Length: 100\r\n\r\n";
        assert_eq!(status_code(head), Some(206));
        assert_eq!(content_length(head), Some(100));
        assert_eq!(content_length(b"HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    #[test]
    fn relay_copies_content_length_exactly() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec();
        let mut up = Cursor::new(response);
        let mut out = Vec::new();

        let (status, bytes) = relay_via_forward_body(&mut up, &mut out, false).unwrap();

        assert_eq!(status, 200);
        assert_eq!(bytes, 5);
        assert!(out.ends_with(b"hello"));
    }

    #[test]
    fn relay_copies_until_eof_without_content_length() {
        let response = b"HTTP/1.1 200 OK\r\n\r\nno-length-body".to_vec();
        let mut up = Cursor::new(response);
        let mut out = Vec::new();

        let (status, bytes) = relay_via_forward_body(&mut up, &mut out, false).unwrap();

        assert_eq!(status, 200);
        assert_eq!(bytes, b"no-length-body".len() as u64);
        assert!(out.ends_with(b"no-length-body"));
    }

    #[test]
    fn relay_preserves_chunked_framing_verbatim() {
        let response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n".to_vec();
        let mut up = Cursor::new(response.clone());
        let mut out = Vec::new();

        relay_via_forward_body(&mut up, &mut out, false).unwrap();

        assert_eq!(out, response, "chunked 必须原样转发，不能重新分帧");
    }

    #[test]
    fn relay_reports_truncation_as_error() {
        // 声明 100 字节却只给 5 字节：必须报错，不能静静当成功
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello".to_vec();
        let mut up = Cursor::new(response);
        let mut out = Vec::new();
        assert!(relay_via_forward_body(&mut up, &mut out, false).is_err());
    }

    #[test]
    fn relay_skips_body_for_204() {
        let response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec();
        let mut up = Cursor::new(response);
        let mut out = Vec::new();
        let (status, bytes) = relay_via_forward_body(&mut up, &mut out, false).unwrap();
        assert_eq!((status, bytes), (204, 0));
    }

    #[test]
    fn rate_limit_statuses_are_recognized() {
        assert!(is_rate_limited(429), "429 应识别为限流");
        assert!(is_rate_limited(503), "503 应识别为暂时不可用");
        assert!(!is_rate_limited(200));
        assert!(!is_rate_limited(404));
        assert!(!is_rate_limited(500), "500 是服务端错误，不算限流");
    }

    #[test]
    fn forward_body_does_not_write_head() {
        // forward_body 只转发正文；响应头由调用方在判定状态码之后再写。
        // 这是"先判后转"的前提：若它把 header 也写了，就没法换候选。
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody".to_vec();
        let mut up = Cursor::new(response);
        let head = read_head(&mut up).unwrap();
        let mut out = Vec::new();
        let n = forward_body(&mut up, &mut out, &head, false).unwrap();
        assert_eq!(n, 4);
        assert_eq!(out, b"body", "只应包含正文");
    }
    #[test]
    fn status_code_rejects_malformed_response() {
        assert_eq!(status_code(b"NOT HTTP\r\n\r\n"), None);
    }

    #[test]
    fn content_length_rejects_invalid_value() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n";
        assert_eq!(content_length(head), None);
    }

    #[test]
    fn read_head_rejects_lf_only_termination() {
        let mut cursor = Cursor::new(b"GET / HTTP/1.1\n\n".to_vec());
        assert!(read_head(&mut cursor).is_err());
    }
    #[test]
    fn read_head_eof_error_reports_prefix_and_protocol_hint() {
        let mut cursor = Cursor::new(vec![0x16, 0x03, 0x01, 0x00, 0x00]);
        let err = read_head(&mut cursor).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("已读取 5 字节"), "{msg}");
        assert!(msg.contains("TLS ClientHello"), "{msg}");
    }
}
