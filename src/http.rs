//! 最小 HTTP/1.1 读写工具。
//!
//! 刻意不用 hyper：本地单用户、并发个位数，手写这几百行反而更好审计（ADR-012）。

use std::io::{self, Read, Write};

/// 请求/响应头的大小上限。超过即认为对端有问题，直接断开。
pub const MAX_HEAD: usize = 32 * 1024;

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
                    "连接在请求头结束前关闭",
                ))
            }
            Ok(_) => {
                buf.push(byte[0]);
                if buf.len() >= 4 && buf.ends_with(b"\r\n\r\n") {
                    return Ok(buf);
                }
                if buf.len() > MAX_HEAD {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "请求头过大"));
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
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
pub fn parse_head(raw: &[u8]) -> Option<Head> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut lines = text.split("\r\n");
    let start = lines.next()?;
    let mut parts = start.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    if method.is_empty() || target.is_empty() {
        return None;
    }

    let headers = lines
        .take_while(|line| !line.is_empty())
        .map(|line| line.to_string())
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
    let text = std::str::from_utf8(head).ok()?;
    text.split(' ').nth(1)?.parse().ok()
}

/// 从响应头里取 `Content-Length`。
pub fn content_length(head: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(head).ok()?;
    text.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("content-length") {
            v.trim().parse().ok()
        } else {
            None
        }
    })
}

/// 转发响应，返回 (状态码, 正文字节数)。
///
/// 分帧只有三种可能，这里不重写任何字节：
/// - 有 `Content-Length`：精确拷贝这么多字节
/// - 否则（chunked 或"连接关闭定界"）：拷到 EOF
///
/// 因为我们向上游发了 `Connection: close`，响应必然会以关闭结束，
/// 所以 chunked 也能靠 EOF 定界，不需要自己解析 chunk 长度。
pub fn relay_response<R: Read, W: Write>(
    up: &mut R,
    dst: &mut W,
    no_body: bool,
) -> io::Result<(u16, u64)> {
    let head = read_head(up)?;
    let status = status_code(&head).unwrap_or(0);
    dst.write_all(&head)?;
    dst.flush()?;

    if no_body || status == 204 || status == 304 {
        return Ok((status, 0));
    }

    let copied = match content_length(&head) {
        Some(len) => copy_exact(up, dst, len)?,
        None => copy_to_eof(up, dst)?,
    };
    dst.flush()?;
    Ok((status, copied))
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
        let head = parse_head(b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n").unwrap();
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

        let (status, bytes) = relay_response(&mut up, &mut out, false).unwrap();

        assert_eq!(status, 200);
        assert_eq!(bytes, 5);
        assert!(out.ends_with(b"hello"));
    }

    #[test]
    fn relay_copies_until_eof_without_content_length() {
        let response = b"HTTP/1.1 200 OK\r\n\r\nno-length-body".to_vec();
        let mut up = Cursor::new(response);
        let mut out = Vec::new();

        let (status, bytes) = relay_response(&mut up, &mut out, false).unwrap();

        assert_eq!(status, 200);
        assert_eq!(bytes, b"no-length-body".len() as u64);
        assert!(out.ends_with(b"no-length-body"));
    }

    #[test]
    fn relay_preserves_chunked_framing_verbatim() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n".to_vec();
        let mut up = Cursor::new(response.clone());
        let mut out = Vec::new();

        relay_response(&mut up, &mut out, false).unwrap();

        assert_eq!(out, response, "chunked 必须原样转发，不能重新分帧");
    }

    #[test]
    fn relay_reports_truncation_as_error() {
        // 声明 100 字节却只给 5 字节：必须报错，不能静静当成功
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello".to_vec();
        let mut up = Cursor::new(response);
        let mut out = Vec::new();
        assert!(relay_response(&mut up, &mut out, false).is_err());
    }

    #[test]
    fn relay_skips_body_for_204() {
        let response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec();
        let mut up = Cursor::new(response);
        let mut out = Vec::new();
        let (status, bytes) = relay_response(&mut up, &mut out, false).unwrap();
        assert_eq!((status, bytes), (204, 0));
    }
}
