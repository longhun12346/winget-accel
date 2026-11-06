//! 最小 HTTP/1.1 读写工具。
//!
//! 刻意不用 hyper：本地单用户、并发个位数，手写这几百行反而更好审计（ADR-012）。

use std::io::{self, Read, Write};

/// 请求/响应头的大小上限。超过即认为对端有问题，直接断开。
pub const MAX_HEAD: usize = 32 * 1024;

/// httparse 需要预先分配的头部槽位数。
const MAX_HEADERS: usize = 64;

/// 逐字节读到 `\r\n\r\n` 为止。
///
/// **必须逐字节**：CONNECT 的响应发出后，客户端会立刻开始 TLS 握手，
/// 一次性多读一个缓冲区就会把 ClientHello 吞掉，握手永远等不到数据。
/// 这里用类型和用例把这个边界钉住。
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

/// 最后一个传输编码决定消息边界；多个 TE 头按出现顺序合并。
fn final_transfer_encoding(head: &[u8]) -> Option<&str> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut res = httparse::Response::new(&mut headers);
    if !matches!(res.parse(head), Ok(httparse::Status::Complete(_))) {
        return None;
    }
    res.headers
        .iter()
        .rev()
        .find(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
        .map(|h| {
            std::str::from_utf8(h.value)
                .unwrap_or("")
                .rsplit(',')
                .next()
                .unwrap_or("")
                .trim()
        })
}

/// 按响应头决定如何转发正文，返回正文字节数。
///
/// 单独拆出来是为了让调用方**先看状态码再决定要不要转发**——
/// 遇到 429/503 时要换候选重试，不能已经把响应头写给客户端。
///
/// **`Transfer-Encoding` 优先于 `Content-Length`**（RFC 7230 §3.3.3）：
/// 两者同时出现时客户端会按分块解析，我们却按 `Content-Length` 读固定长度，
/// 就会切在 chunk 中间——客户端解析分块直接失败。分块响应在终止块和 trailer
/// 结束后收尾，不能继续等 EOF；其它传输编码仍以连接关闭为边界。
/// 分块帧始终原样转发，不解码或重新分帧。
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
    let (wire, _) = copy_body(up, dst, head, u64::MAX)?;
    dst.flush()?;
    Ok(wire)
}

/// 测速只累计有效载荷，分块扩展与 trailer 不算下载样本，并限制正文总量。
/// 另给分帧留出八倍正文加两组头部上限的读取预算，避免用极长扩展拖住探测。
pub fn measure_body<R: Read>(up: &mut R, head: &[u8], limit: u64) -> io::Result<u64> {
    let wire_limit = limit
        .saturating_mul(8)
        .saturating_add((MAX_HEAD * 2) as u64);
    let mut bounded = up.take(wire_limit);
    let (_, payload) = copy_body(&mut bounded, &mut io::sink(), head, limit)?;
    Ok(payload)
}

/// 返回 (原样写出的字节数, 不含分块帧的正文大小)。
fn copy_body<R: Read, W: Write>(
    up: &mut R,
    dst: &mut W,
    head: &[u8],
    limit: u64,
) -> io::Result<(u64, u64)> {
    let copied = if let Some(encoding) = final_transfer_encoding(head) {
        if encoding.eq_ignore_ascii_case("chunked") {
            return copy_chunked(up, dst, limit);
        } else {
            io::copy(&mut up.take(limit.saturating_add(1)), dst)?
        }
    } else {
        match content_length(head) {
            Some(len) if len > limit => return Err(body_too_large()),
            Some(len) => copy_exact(up, dst, len)?,
            None => io::copy(&mut up.take(limit.saturating_add(1)), dst)?,
        }
    };
    if copied > limit {
        return Err(body_too_large());
    }
    Ok((copied, copied))
}

fn body_too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "上游正文超过采样上限")
}

/// 429 / 503：被限流或暂时不可用，值得换一个候选重试。
pub fn is_rate_limited(status: u16) -> bool {
    matches!(status, 429 | 503)
}

fn copy_exact<R: Read, W: Write>(src: &mut R, dst: &mut W, len: u64) -> io::Result<u64> {
    let copied = io::copy(&mut src.take(len), dst)?;
    if copied != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "上游提前关闭，正文不完整",
        ));
    }
    Ok(copied)
}

/// 只读取分帧行，正文仍由 copy_exact 搬运。限制扩展行及整个 trailer 的大小。
fn read_crlf_line<R: Read>(src: &mut R, limit: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while line.len() < limit {
        src.read_exact(&mut byte)?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "分块扩展或 trailer 过大",
    ))
}

fn copy_chunked<R: Read, W: Write>(src: &mut R, dst: &mut W, limit: u64) -> io::Result<(u64, u64)> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "上游分块帧格式错误");
    let mut copied = 0;
    let mut payload = 0u64;
    loop {
        let line = read_crlf_line(src, MAX_HEAD)?;
        // httparse 接受空的大小行；这里额外要求至少一个十六进制数字。
        if !line[0].is_ascii_hexdigit() {
            return Err(invalid());
        }
        let size = match httparse::parse_chunk_size(&line) {
            Ok(httparse::Status::Complete((used, size))) if used == line.len() => size,
            _ => return Err(invalid()),
        };
        payload = payload
            .checked_add(size)
            .filter(|total| *total <= limit)
            .ok_or_else(body_too_large)?;
        dst.write_all(&line)?;
        copied += line.len() as u64;
        if size == 0 {
            let mut trailers = Vec::new();
            loop {
                let line = read_crlf_line(src, MAX_HEAD - trailers.len())?;
                let done = line == b"\r\n";
                trailers.extend_from_slice(&line);
                if done {
                    break;
                }
            }
            let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            if !matches!(
                httparse::parse_headers(&trailers, &mut headers),
                Ok(httparse::Status::Complete((used, _))) if used == trailers.len()
            ) {
                return Err(invalid());
            }
            dst.write_all(&trailers)?;
            return Ok((copied + trailers.len() as u64, payload));
        }
        copied += copy_exact(src, dst, size)?;
        let mut crlf = [0u8; 2];
        src.read_exact(&mut crlf)?;
        if crlf != *b"\r\n" {
            return Err(invalid());
        }
        dst.write_all(&crlf)?;
        copied += 2;
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
    fn chunked_body_stops_after_trailers_without_waiting_for_eof() {
        let body = b"8;name=value\r\n\r\n0\r\n\r\nx\r\n00;done=yes\r\nX-Checksum: test\r\n\r\n";
        let head =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: ChUnKeD\r\n\r\n";
        let mut wire = body.to_vec();
        wire.extend_from_slice(b"next-response");
        let mut up = Cursor::new(wire);
        let mut out = Vec::new();

        let count = forward_body(&mut up, &mut out, head, false).unwrap();

        assert_eq!(out, body, "块扩展、正文与 trailer 必须原样保留");
        assert_eq!(count, body.len() as u64);
        assert_eq!(up.position(), body.len() as u64, "终止块后不能再读取上游");
    }

    #[test]
    fn chunked_body_rejects_incomplete_or_malformed_framing() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let oversized_extension = format!("1;{}\r\nx\r\n0\r\n\r\n", "x".repeat(MAX_HEAD));
        let oversized_trailers = format!("0\r\n{}\r\n", "X: v\r\n".repeat(MAX_HEAD / 6 + 1));
        for body in [
            &b"3\r\nabc\r\n"[..],
            &b"3\r\nab"[..],
            &b"3\r\nabcXX0\r\n\r\n"[..],
            &b"not-hex\r\nabc\r\n0\r\n\r\n"[..],
            &b"\r\n\r\n"[..],
            &b"10000000000000000\r\n"[..],
            &b"0\r\nnot-a-header\r\n\r\n"[..],
            &b"0\r\nX-Checksum: unfinished\r\n"[..],
            oversized_extension.as_bytes(),
            oversized_trailers.as_bytes(),
        ] {
            let result = forward_body(&mut Cursor::new(body), &mut Vec::new(), head, false);
            assert!(result.is_err(), "不能把畸形分块流当成功：{body:?}");
        }
    }

    #[test]
    fn non_chunked_final_transfer_encoding_uses_eof() {
        let head =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\nContent-Length: 1\r\n\r\n";
        let body = b"encoded-body";
        let mut out = Vec::new();
        let count = forward_body(&mut Cursor::new(body), &mut out, head, false).unwrap();
        assert_eq!(out, body);
        assert_eq!(count, body.len() as u64);
    }

    /// `Transfer-Encoding` 与 `Content-Length` 同时出现时，以 TE 为准（RFC 7230 §3.3.3）。
    ///
    /// 回归：此前 `forward_body` 先看 `Content-Length`，于是按 CL 读固定字节数：
    /// 这里 CL=999，分块流只有十几字节 → 读到 EOF 报 `UnexpectedEof`，
    /// 客户端拿到的是被截断的分块流（解析必然失败）。这种响应本身可疑，
    /// 但转发方必须按接收方会采用的口径读。
    #[test]
    fn transfer_encoding_overrides_content_length() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\n\r\n3\r\nabc\r\n0\r\n\r\n".to_vec();
        let body_len = {
            let pos = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            (response.len() - pos - 4) as u64
        };
        let mut up = Cursor::new(response.clone());
        let mut out = Vec::new();

        let (status, bytes) = relay_via_forward_body(&mut up, &mut out, false).unwrap();

        assert_eq!(status, 200);
        assert_eq!(out, response, "必须把完整的分块帧原样转发出去");
        assert_eq!(bytes, body_len, "应完整读取分块流，而不是按 CL 截断");
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
