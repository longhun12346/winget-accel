//! 改写决策：把"客户端请求"变成"发往上游的请求"。
//!
//! 全程不碰 socket，因此可以用纯单元测试钉住行为。改写规则的 ID（REW-01..REW-08）
//! 与协议集成测试逐条对应。

use anyhow::{bail, Context, Result};
use hyper::HeaderMap;

/// 逐跳头（RFC 7230 §6.1）：只对单跳连接有意义，不得转发。
///
/// `host` 单独处理：改写时替换为加速器，透传时保留客户端原值。
pub const HOP_BY_HOP: [&str; 8] = [
    "proxy-connection",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
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
///
/// `{url}` 只能出现在**末尾**（或干脆不写，两者等价）。放在中间会静默产生
/// 带 `//` 的畸形前缀——实测 `https://a.example/{url}/tail` 得到前缀 `//tail`，
/// 于是每个请求都变成 `//tail/https://github.com/…`，加速器只会回 404，
/// 而配置层不会有任何抱怨。所以这里直接拒绝。
pub fn parse_accel(spec: &str) -> Result<Accel> {
    // 占位符只允许在末尾；中间的写法无法产生有意义的前缀。
    if let Some(pos) = spec.find("{url}") {
        let tail = &spec[pos + "{url}".len()..];
        if !tail.is_empty() && tail != "/" {
            bail!(
                "加速器模板里的 {{url}} 只能放在**末尾**：{spec:?}。\
                 占位符的含义是「把原始完整 URL 填在这里」，放在中间会拼出畸形路径"
            );
        }
        if spec.matches("{url}").count() > 1 {
            bail!("加速器模板里出现了多个 {{url}}：{spec:?}（只需要末尾一个）");
        }
    }

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

    let authority: hyper::http::uri::Authority =
        authority.parse().context("加速器 authority 非法")?;
    if authority.as_str().contains('@')
        || authority.host().is_empty()
        || (authority.as_str() != authority.host() && authority.port_u16().is_none())
    {
        bail!("加速器地址或端口非法: {spec:?}");
    }
    let host = authority
        .host()
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    let port = authority.port_u16().unwrap_or(scheme.default_port());

    Ok(Accel {
        scheme,
        host,
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
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == scheme.default_port() {
        host
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
    pub method: String,
    pub headers: HeaderMap,
}

/// PAC 只能整域代理 `github.com`（WinINet 对 HTTPS 不把路径交给 PAC，见 ADR-018），
/// 所以"只改写下载路径"必须由代理按真实请求路径判断：命中这里才改写，
/// 其余路径原样转发回真实 github.com——否则普通页面会被改写成加速器的响应。
pub const GITHUB_HOST: &str = "github.com";

/// `github.com` 上需要改写的路径标记（与旧 PAC 的路径规则保持一致）。
/// 用"包含"而不是"前缀"：下载路径带仓库名，如 `/sharkdp/fd/releases/download/…`。
const DOWNLOAD_PATH_PREFIXES: [&str; 5] = [
    "/releases/download/",
    "/releases/latest/download/",
    "/archive/",
    "/raw/",
    "/blob/",
];

/// 这条请求是否应该改写到加速器。
///
/// 只有 `github.com` 需要按路径区分；其余白名单 host（资产域名）本来就是纯下载站。
pub fn needs_rewrite(host: &str, target: &str) -> bool {
    if !host.eq_ignore_ascii_case(GITHUB_HOST) {
        return true;
    }
    // 只比较路径部分：查询串里出现 "/releases/download/" 不算。
    let path = target.split('?').next().unwrap_or(target);
    DOWNLOAD_PATH_PREFIXES
        .iter()
        .any(|marker| path.contains(marker))
}

/// 同 [`plan`]，但由调用方决定"这条请求是否允许改写"。
///
/// `github.com` 的普通页面必须走 `allow_rewrite = false`（原样转发），
/// 只有下载类路径才允许改写（见 [`needs_rewrite`] 与 ADR-018）。
#[allow(clippy::too_many_arguments)]
pub fn plan_with(
    method: &str,
    host: &str,
    port: u16,
    target: &str,
    headers: &HeaderMap,
    rewrite_hosts: &[String],
    accel: &Accel,
    allow_rewrite: bool,
) -> Plan {
    let rewritten = allow_rewrite && rewrite_hosts.iter().any(|h| h.eq_ignore_ascii_case(host));

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

    let mut headers = headers.clone();
    crate::http::strip_hop_headers(&mut headers);
    if rewritten {
        headers.insert(
            "host",
            host_header(scheme, &up_host, up_port)
                .parse()
                .expect("validated accelerator authority"),
        );
    }
    Plan {
        rewritten,
        scheme,
        host: up_host,
        port: up_port,
        path: up_path,
        method: method.to_string(),
        headers,
    }
}

#[cfg(test)]
mod tests {
    /// `github.com` 只有下载类路径才改写；其余路径必须原样转发（ADR-018）。
    ///
    /// 为什么这条这么重要：PAC 现在整域代理 github.com（WinINet 不给路径），
    /// 如果这里判错，普通页面会被改写成加速器返回的垃圾——实测 `/ip7z/7zip`
    /// 曾拿到 2 字节响应。
    #[test]
    fn only_download_paths_are_rewritten_on_github() {
        for path in [
            "/sharkdp/fd/releases/download/v10.5.0/fd.zip",
            "/owner/repo/releases/latest/download/x.zip",
            "/git/git/archive/refs/tags/v2.43.0.tar.gz",
            "/owner/repo/raw/main/file.txt",
            "/owner/repo/blob/main/file.txt",
        ] {
            assert!(needs_rewrite("github.com", path), "应改写: {path}");
        }
        for path in [
            "/octocat/Hello-World.git/info/refs?service=git-upload-pack",
            "/octocat/Hello-World.git/git-upload-pack",
            "/owner/repo",
            "/owner/repo/pulls",
            // 查询串里出现下载字样不算：只比较路径部分
            "/owner/repo?next=/releases/download/x.zip",
        ] {
            assert!(!needs_rewrite("github.com", path), "应透传: {path}");
        }
        // 其它白名单 host 本来就是下载站，一律改写
        for host in [
            "codeload.github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
        ] {
            assert!(needs_rewrite(host, "/anything"), "{host} 应改写");
        }
        // 大小写不敏感
        assert!(needs_rewrite("GitHub.com", "/releases/download/x"));
    }
    /// 测试里默认允许改写；需要验证透传时直接调 `plan_with(…, false)`。
    #[allow(clippy::too_many_arguments)]
    fn plan(
        method: &str,
        host: &str,
        port: u16,
        target: &str,
        headers: &HeaderMap,
        rewrite_hosts: &[String],
        accel: &Accel,
    ) -> Plan {
        plan_with(
            method,
            host,
            port,
            target,
            headers,
            rewrite_hosts,
            accel,
            true,
        )
    }
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

    fn headers(items: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in items {
            let (name, value) = line.split_once(':').unwrap();
            headers.append(
                name.parse::<hyper::header::HeaderName>().unwrap(),
                value.trim().parse().unwrap(),
            );
        }
        headers
    }

    #[test]
    fn mixed_case_whitelist_rewrites_and_connection_tokens_are_not_forwarded() {
        let plan = plan(
            "GET",
            "github.com",
            443,
            "/owner/repo/releases/download/v1/app.exe",
            &headers(&[
                "Host: github.com",
                "Connection: X-Internal-Token, keep-alive",
                "connection: X-Second",
                "X-Internal-Token: secret",
                "X-Second: secret",
                "Proxy-Authorization: Basic secret",
                "Proxy-Authenticate: Basic",
                "Range: bytes=0-1",
                "If-Range: \"etag\"",
                "X-End-To-End: keep",
            ]),
            &["GITHUB.COM".to_string()],
            &accel(),
        );
        assert!(plan.rewritten);
        assert_eq!(plan.host, "gh-proxy.com");

        for name in [
            "x-internal-token",
            "x-second",
            "proxy-authorization",
            "proxy-authenticate",
            "connection",
        ] {
            assert!(!plan.headers.contains_key(name));
        }
        assert_eq!(plan.headers["range"], "bytes=0-1");
        assert_eq!(plan.headers["if-range"], "\"etag\"");
        assert_eq!(plan.headers["x-end-to-end"], "keep");
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

    /// `{url}` 只能放在末尾（或省略，两者等价）；放中间会静默拼出畸形前缀。
    ///
    /// 实测：`https://a.example/{url}/tail` 得到前缀 `//tail`，改写结果
    /// `//tail/https://github.com/…` —— 加速器只会回 404，而配置层毫无反应。
    #[test]
    fn rejects_placeholder_that_is_not_at_the_end() {
        for spec in [
            "https://accel.example/{url}/tail",
            "https://accel.example/a/{url}/b",
            "https://accel.example/{url}{url}",
        ] {
            let err = parse_accel(spec).expect_err(&format!("应拒绝 {spec:?}"));
            assert!(
                err.to_string().contains("{url}"),
                "报错应提到 {{url}}（{spec:?}）: {err}"
            );
        }

        // 末尾带占位符、斜杠结尾、以及干脆不写 —— 三种都应正常工作
        for spec in [
            "https://gh-proxy.com/{url}",
            "https://gh-proxy.com/{url}/",
            "https://gh-proxy.com",
        ] {
            let parsed = parse_accel(spec).unwrap_or_else(|e| panic!("{spec:?} 应可用: {e}"));
            assert_eq!(parsed.prefix, "", "{spec:?}");
            assert_eq!(parsed.host, "gh-proxy.com", "{spec:?}");
        }
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
        assert_eq!(
            (plan.scheme, plan.host.as_str(), plan.port),
            (Scheme::Https, "gh-proxy.com", 443)
        );
        assert_eq!(plan.path, "/https://github.com/a.zip");
        assert_eq!(plan.method, "GET");
        assert_eq!(plan.headers["host"], "gh-proxy.com");
    }

    #[test]
    fn host_header_includes_non_default_port() {
        let accel = Accel {
            scheme: Scheme::Http,
            host: "127.0.0.1".into(),
            port: 9000,
            prefix: String::new(),
        };
        let plan = plan(
            "GET",
            "github.com",
            443,
            "/x",
            &headers(&["Host: github.com"]),
            &whitelist(),
            &accel,
        );
        assert_eq!(plan.headers["host"], "127.0.0.1:9000");
    }

    /// 条件请求头必须原样透传（design.md §5 的承诺）。
    ///
    /// winget 用 `Range` + `If-Range` 做续传、用 `If-None-Match` 做条件请求；
    /// 这些头丢了不会报错，只会让上游回整包或 200，进而退化成重传/哈希不符。
    /// 此前协议用例只覆盖了 `Range` 与自定义头，`If-Range`/`If-None-Match` 没有用例。
    #[test]
    fn conditional_headers_are_forwarded_verbatim() {
        let plan = plan(
            "GET",
            "github.com",
            443,
            "/a.zip",
            &headers(&[
                "Host: github.com",
                "Range: bytes=1024-2047",
                "If-Range: \"abc123etag\"",
                "If-None-Match: \"abc123etag\"",
                "User-Agent: winget-cli/1.29",
            ]),
            &whitelist(),
            &accel(),
        );
        assert_eq!(plan.headers["range"], "bytes=1024-2047");
        assert_eq!(plan.headers["if-range"], "\"abc123etag\"");
        assert_eq!(plan.headers["if-none-match"], "\"abc123etag\"");
        assert_eq!(plan.headers["user-agent"], "winget-cli/1.29");
        assert_eq!(plan.headers["host"], "gh-proxy.com");
    }

    // REW-04
    #[test]
    fn drops_hop_by_hop_before_hyper_frames_request() {
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
        assert_eq!(plan.headers["range"], "bytes=0-1023");
        assert_eq!(plan.headers["accept"], "*/*");
        for gone in HOP_BY_HOP {
            assert!(!plan.headers.contains_key(gone));
        }
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
        assert_eq!(
            (plan.scheme, plan.host.as_str(), plan.port),
            (Scheme::Https, "example.com", 443)
        );
        assert_eq!(plan.path, "/index.html");
        assert_eq!(plan.headers["host"], "example.com");
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

    #[test]
    fn parse_accel_handles_ipv6() {
        // 带方括号与端口
        let a = parse_accel("http://[::1]:8080/{url}").unwrap();
        assert_eq!(a.host, "::1", "方括号应被剥掉");
        assert_eq!(a.port, 8080);
        // 带方括号、默认端口
        let b = parse_accel("http://[::1]/{url}").unwrap();
        assert_eq!(b.host, "::1");
        assert_eq!(b.port, 80);
    }

    #[test]
    fn parse_accel_rejects_non_numeric_port() {
        // 有冒号但端口不是数字 → 报错，不退化成"无端口"
        let err = parse_accel("http://host:notaport").unwrap_err();
        assert!(err.to_string().contains("端口"), "实际: {err}");
    }
}
