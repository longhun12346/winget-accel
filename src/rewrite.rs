//! 改写决策：把"客户端请求"变成"发往上游的请求"。
//!
//! 全程不碰 socket，因此可以用纯单元测试钉住行为。对应
//! docs/test-plan.md 的 REW-01..REW-08，与 Python 原型 `plan_upstream` 逐条对齐。

use anyhow::{bail, Result};

/// 逐跳头（RFC 7230 §6.1）：只对单跳连接有意义，不得转发。
///
/// `host` 单独处理：改写时替换为加速器，透传时保留客户端原值。
pub const HOP_BY_HOP: [&str; 6] = [
    "proxy-connection",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accel {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// `{url}` 之前的路径前缀（通常为空）。
    ///
    /// 配置里写 `https://gh-proxy.com/{url}` 时前缀是空串；
    /// 写 `https://accel/p/{url}` 时前缀是 `/p`，改写后路径为 `/p/https://host/path`。
    pub prefix: String,
}

impl Accel {
    /// 是否走默认端口。日志与 doctor 里用来判断 Host 头要不要带端口时用。
    #[allow(dead_code)]
    pub fn uses_default_port(&self) -> bool {
        self.port == self.scheme.default_port()
    }
}

/// 解析加速器地址：`host` / `host:port` / `scheme://host:port[/prefix]`。
///
/// 允许在末尾带 `{url}` 占位符（与 config.example.json 的写法一致）；
/// 也允许 http，用于测试与自建场景。
pub fn parse_accel(spec: &str) -> Result<Accel> {
    let (scheme, rest) = match spec.split_once("://") {
        Some((scheme, rest)) => {
            let scheme = match scheme.to_ascii_lowercase().as_str() {
                "http" => Scheme::Http,
                "https" => Scheme::Https,
                other => bail!("不支持的加速器协议: {other}"),
            };
            (scheme, rest)
        }
        None => (Scheme::Https, spec),
    };

    // 去掉 {url} 占位符，剩下的路径部分作为前缀
    let rest = rest.replace("{url}", "");
    let (authority, prefix) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{}", path.trim_end_matches('/'))),
        None => (rest.as_str(), String::new()),
    };
    let prefix = if prefix == "/" { String::new() } else { prefix };

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() => {
            let port: u16 = port
                .parse()
                .map_err(|_| anyhow::anyhow!("加速器端口非法: {port}"))?;
            (host, port)
        }
        _ => (authority, scheme.default_port()),
    };

    if host.is_empty() {
        bail!("加速器地址缺少主机名: {spec:?}");
    }

    Ok(Accel {
        scheme,
        host: host.to_string(),
        port,
        prefix,
    })
}

/// 把 origin-form 的 target 改写为加速器的路径形式。
pub fn rewrite_path(accel: &Accel, host: &str, target: &str) -> String {
    format!("{}/https://{host}{target}", accel.prefix)
}

/// Host 头：非默认端口必须带端口，否则上游会按 80/443 解释。
pub fn host_header(scheme: Scheme, host: &str, port: u16) -> String {
    if port == scheme.default_port() {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// 一次改写/透传的全部决策结果。
#[derive(Clone, Debug)]
pub struct Plan {
    pub rewritten: bool,
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub path: String,
    /// 完整的请求头文本（含请求行与结尾空行）。
    pub head: Vec<u8>,
}

/// 决定上游地址、请求行与要转发的头。
pub fn plan(
    method: &str,
    host: &str,
    port: u16,
    target: &str,
    header_lines: &[String],
    rewrite_hosts: &[String],
    accel: &Accel,
) -> Plan {
    let rewritten = rewrite_hosts.iter().any(|h| h == host);

    let (scheme, up_host, up_port, up_path) = if rewritten {
        (
            accel.scheme,
            accel.host.clone(),
            accel.port,
            rewrite_path(accel, host, target),
        )
    } else {
        // 透传：客户端已按原站 TLS 建连，上游必须仍是 https
        (Scheme::Https, host.to_string(), port, target.to_string())
    };

    let mut head = String::with_capacity(256);
    head.push_str(&format!("{method} {up_path} HTTP/1.1\r\n"));
    if rewritten {
        head.push_str(&format!("Host: {}\r\n", host_header(scheme, &up_host, up_port)));
    }

    for line in header_lines {
        if line.is_empty() {
            break;
        }
        let name = line
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        if rewritten && name == "host" {
            continue;
        }
        head.push_str(line);
        head.push_str("\r\n");
    }
    // 统一以 close 结束，简化响应定界
    head.push_str("Connection: close\r\n\r\n");

    Plan {
        rewritten,
        scheme,
        host: up_host,
        port: up_port,
        path: up_path,
        head: head.into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn whitelist() -> Vec<String> {
        [
            "github.com",
            "objects.githubusercontent.com",
            "codeload.github.com",
            "release-assets.githubusercontent.com",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn accel() -> Accel {
        Accel {
            scheme: Scheme::Https,
            host: "gh-proxy.com".into(),
            port: 443,
            prefix: String::new(),
        }
    }

    fn head_of(plan: &Plan) -> String {
        String::from_utf8(plan.head.clone()).unwrap()
    }

    fn headers(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // CFG-01
    #[test]
    fn parse_accel_accepts_supported_forms() {
        let cases = [
            ("gh-proxy.com", ("gh-proxy.com", 443, Scheme::Https)),
            ("127.0.0.1:9999", ("127.0.0.1", 9999, Scheme::Https)),
            ("http://127.0.0.1:9999", ("127.0.0.1", 9999, Scheme::Http)),
            ("https://gh-proxy.com", ("gh-proxy.com", 443, Scheme::Https)),
            ("http://example.com", ("example.com", 80, Scheme::Http)),
        ];
        for (spec, (host, port, scheme)) in cases {
            let got = parse_accel(spec).unwrap();
            assert_eq!(got.host, host, "{spec}");
            assert_eq!(got.port, port, "{spec}");
            assert_eq!(got.scheme, scheme, "{spec}");
        }
    }

    // CFG-02
    #[test]
    fn parse_accel_rejects_bad_input() {
        for spec in ["ftp://x", "http://", ":8080", "host:notaport"] {
            assert!(parse_accel(spec).is_err(), "应拒绝 {spec}");
        }
    }

    // REW-01
    #[test]
    fn rewrites_path_with_prefix() {
        assert_eq!(
            rewrite_path(&accel(), "github.com", "/a/b.zip?x=1&y=2"),
            "/https://github.com/a/b.zip?x=1&y=2"
        );
    }

    // 配置里写的是 `https://gh-proxy.com/{url}`，占位符必须被正确吃掉
    #[test]
    fn template_placeholder_yields_empty_prefix() {
        let parsed = parse_accel("https://gh-proxy.com/{url}").unwrap();
        assert_eq!(parsed.prefix, "");
        assert_eq!((parsed.host.as_str(), parsed.port), ("gh-proxy.com", 443));
    }

    // 带路径前缀的加速器：https://accel/p/{url}
    #[test]
    fn template_with_path_prefix_is_preserved() {
        let parsed = parse_accel("https://accel.example/p/{url}").unwrap();
        assert_eq!(parsed.prefix, "/p");
        let plan = plan(
            "GET",
            "github.com",
            443,
            "/a.zip",
            &headers(&["Host: github.com"]),
            &whitelist(),
            &parsed,
        );
        assert_eq!(plan.path, "/p/https://github.com/a.zip");
    }

    // REW-02
    #[test]
    fn keeps_query_string_and_encoded_bytes() {
        let target = "/releases/download/v1/x.zip?download=1&foo=%E4%B8%AD";
        let plan = plan(
            "GET",
            "github.com",
            443,
            target,
            &headers(&["Host: github.com"]),
            &whitelist(),
            &accel(),
        );
        assert!(plan.path.ends_with(target));
        assert!(plan.path.contains("%E4%B8%AD"), "不得二次编码");
    }

    // REW-03
    #[test]
    fn rewrite_targets_accel_and_replaces_host() {
        let plan = plan(
            "GET",
            "github.com",
            443,
            "/a.zip",
            &headers(&["Host: github.com", "User-Agent: winget"]),
            &whitelist(),
            &accel(),
        );
        assert!(plan.rewritten);
        assert_eq!((plan.scheme, plan.host.as_str(), plan.port), (Scheme::Https, "gh-proxy.com", 443));
        assert_eq!(plan.path, "/https://github.com/a.zip");
        let head = head_of(&plan);
        assert!(head.starts_with("GET /https://github.com/a.zip HTTP/1.1\r\n"));
        assert!(head.contains("Host: gh-proxy.com\r\n"));
        assert!(!head.contains("Host: github.com\r\n"));
    }

    #[test]
    fn host_header_includes_non_default_port() {
        let accel = Accel {
            scheme: Scheme::Http,
            host: "127.0.0.1".into(),
            port: 9000,
            prefix: String::new(),
        };
        let plan = plan("GET", "github.com", 443, "/x", &headers(&["Host: github.com"]), &whitelist(), &accel);
        assert!(head_of(&plan).contains("Host: 127.0.0.1:9000\r\n"));
    }

    // REW-04
    #[test]
    fn drops_hop_by_hop_and_forces_close() {
        let plan = plan(
            "GET",
            "github.com",
            443,
            "/a.zip",
            &headers(&[
                "Host: github.com",
                "Range: bytes=0-1023",
                "Connection: keep-alive",
                "Proxy-Connection: keep-alive",
                "Keep-Alive: timeout=5",
                "TE: trailers",
                "Trailer: X",
                "Upgrade: h2c",
                "Accept: */*",
            ]),
            &whitelist(),
            &accel(),
        );
        let head = head_of(&plan).to_ascii_lowercase();
        assert!(head.contains("range: bytes=0-1023"));
        assert!(head.contains("accept: */*"));
        for gone in ["proxy-connection", "keep-alive:", "te:", "trailer:", "upgrade:"] {
            assert!(!head.contains(gone), "未剥离 {gone}");
        }
        assert!(head.contains("connection: close"));
    }

    // REW-05
    #[test]
    fn passthrough_keeps_host_and_path() {
        let plan = plan(
            "GET",
            "example.com",
            443,
            "/index.html",
            &headers(&["Host: example.com"]),
            &whitelist(),
            &accel(),
        );
        assert!(!plan.rewritten);
        assert_eq!((plan.scheme, plan.host.as_str(), plan.port), (Scheme::Https, "example.com", 443));
        assert_eq!(plan.path, "/index.html");
        let head = head_of(&plan);
        assert!(head.contains("Host: example.com\r\n"));
        assert!(!head.contains("gh-proxy.com"));
    }

    // REW-06
    #[test]
    fn passthrough_keeps_nonstandard_port() {
        let plan = plan(
            "GET",
            "127.0.0.1",
            9443,
            "/",
            &headers(&["Host: 127.0.0.1:9443"]),
            &whitelist(),
            &accel(),
        );
        assert_eq!((plan.host.as_str(), plan.port), ("127.0.0.1", 9443));
    }

    // REW-07
    #[test]
    fn every_whitelisted_host_is_rewritten() {
        for host in whitelist() {
            let plan = plan(
                "GET",
                &host,
                443,
                "/x",
                &headers(&[&format!("Host: {host}")]),
                &whitelist(),
                &accel(),
            );
            assert!(plan.rewritten, "{host}");
            assert_eq!(plan.path, format!("/https://{host}/x"));
        }
    }

    // REW-08
    #[test]
    fn non_whitelisted_hosts_are_not_rewritten() {
        for host in ["api.github.com", "example.com", "cdn.winget.microsoft.com"] {
            let plan = plan(
                "GET",
                host,
                443,
                "/x",
                &headers(&[&format!("Host: {host}")]),
                &whitelist(),
                &accel(),
            );
            assert!(!plan.rewritten, "{host}");
            assert_eq!(plan.path, "/x");
        }
    }
}
