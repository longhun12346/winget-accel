//! PAC 文本生成。
//!
//! PAC 的作用范围**比 MITM 范围宽**：只有 `rewrite_hosts` 会被终止 TLS 并改写，
//! 但这些 host 的子域（如 `api.github.com`）也会被圈进代理，只做隧道。
//! 这样做的目的是避免子域流量落到"系统直连"上被卡死（见 docs/design.md §2）。
//!
//! `github.com` 必须整域交给代理，因为 WinINet 的 HTTPS PAC 调用不包含路径；
//! 代理收到请求后再按路径决定是否改写。这样普通页面和 git clone 仍保持原目标，
//! 不会被发送到公共加速器（`git clone` 依赖 POST 请求体，本代理不转发）。

/// 主站域名。PAC 对它整站代理，代理层按路径细分；其它 host 整站代理。
const GITHUB: &str = "github.com";
/// 生成 PAC 脚本。
///
/// `github.com` 整个 host 走代理；代理层再按真实请求路径判断是否改写。
///
/// 原因（实测，不是推测）：`git clone` 的 smart HTTP 需要
/// `POST /owner/repo.git/git-upload-pack` 并发送请求体，而本代理只转发响应体、
/// 不转发请求体——假上游收到 `Content-Length: 15` 的头，但那 15 字节没到。
/// 所以把 `github.com` 整个圈进代理，`git clone` 会在协议层直接失败。
///
/// `rewrite::needs_rewrite` 再识别 release、archive、raw、blob 等下载路径；
/// 认不出来的路径会通过代理隧道回到原始 GitHub。
///
/// `github.com` 上的 release 下载会 302 到 `release-assets.githubusercontent.com`，
/// 那个 host 仍在完整代理列表里，所以跳转后照样被改写。
pub fn build(port: u16, rewrite_hosts: &[String]) -> String {
    let mut conditions: Vec<String> = Vec::new();

    // 配置里的 host 一律**小写化**后再写进 PAC。
    //
    // 这个 PAC 的第一行就是 `host = host.toLowerCase()`，而条件里是精确比较
    // （`host == "github.com"`）。所以配置里写成 `GitHub.com` 时，生成的规则
    // 永远不会命中——表面上"配置了"，实际那些域名走的是 DIRECT，没有任何加速，
    // 而且 `doctor`/日志都显示得好好的（实测复现过）。
    // 顺带：小写化也让 `h == GITHUB` 的判断与自己是否大小写无关。
    let hosts: Vec<String> = rewrite_hosts
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();

    let has_github = hosts.iter().any(|h| h == GITHUB);
    if has_github {
        // WinINet 对 HTTPS 只把 `https://host:port/` 交给 PAC（无路径），
        // 因此 github.com 必须整域代理；“只改写下载路径”由代理按真实请求判断
        //（rewrite::needs_rewrite）。
        conditions.push(format!("host == \"{GITHUB}\""));
        // 子域整站代理：api/raw/gist 等子域没有 git 上传场景
        conditions.push(format!("shExpMatch(host, \"*.{GITHUB}\")"));
    }

    // 其它 host（release-assets / codeload / objects）本来只服务下载，整 host 匹配
    for host in hosts.iter().filter(|h| h.as_str() != GITHUB) {
        conditions.push(format!("host == \"{}\"", escape_js(host)));
    }

    let condition = if conditions.is_empty() {
        "false".to_string()
    } else {
        conditions.join(" || ")
    };

    // 只接管 **https**：本代理对白名单 host 做的是"终止 TLS 再改写"，
    // 明文 http 请求进来只会被 `serve_local` 回 405（实测）。
    // 所以把 http 的下载 URL 也圈进来是**错**的——那会让本来能直连的请求失败。
    // 客户端（winget）对这些 host 一律用 https，这条限定不损失功能。
    let condition = format!("(url.substring(0, 6) == \"https:\") && ({condition})");

    format!(
        "function FindProxyForURL(url, host) {{\n\
         \x20 host = host.toLowerCase();\n\
         \x20 if ({condition}) {{\n\
         \x20   return \"PROXY 127.0.0.1:{port}\";\n\
         \x20 }}\n\
         \x20 return \"DIRECT\";\n\
         }}\n"
    )
}

/// 把 host 转义成可以安全放进 JS 双引号字符串的形式。
///
/// 配置是自己写的，但 `"` 或反斜杠会把生成的 PAC 变成语法错误——
/// 而 PAC 解析失败时 Windows 的行为是"退回直连"，用户只会看到"没加速"。
fn escape_js(host: &str) -> String {
    host.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts() -> Vec<String> {
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

    // PAC-01
    #[test]
    fn declares_entry_function() {
        assert!(build(8443, &hosts()).contains("function FindProxyForURL(url, host)"));
    }

    // PAC-02
    #[test]
    fn covers_all_rewrite_hosts() {
        let text = build(8443, &hosts());
        for host in hosts() {
            assert!(text.contains(&format!("host == \"{host}\"")), "缺少 {host}");
        }
    }

    // PAC-03
    #[test]
    fn only_github_subdomain_wildcard() {
        let text = build(8443, &hosts());
        assert!(text.contains("shExpMatch(host, \"*.github.com\")"));
        assert!(!text.contains("*.com\""), "不允许过宽的通配");
        // 只有 1 次：子域通配。路径规则已删除（ADR-018）。
        assert_eq!(
            text.matches("shExpMatch").count(),
            1,
            "只应保留子域通配: {text}"
        );
    }

    // PAC-04
    #[test]
    fn embeds_port_and_defaults_to_direct() {
        let text = build(9123, &hosts());
        assert!(text.contains("PROXY 127.0.0.1:9123"));
        assert!(text.contains("return \"DIRECT\";"));
    }

    // PAC-05
    #[test]
    fn lowercases_host() {
        assert!(build(8443, &hosts()).contains("host.toLowerCase()"));
    }

    #[test]
    fn subdomain_wildcard_requires_github_in_list() {
        let other = vec!["example.com".to_string()];
        assert!(!build(8443, &other).contains("shExpMatch"));
    }

    /// 配置里写成大写时，PAC 也必须能命中。
    ///
    /// 实测复现过：`rewriteHosts: ["GitHub.com"]` 生成的规则是 `host == "GitHub.com"`，
    /// 而 PAC 第一行就把 `host` 小写化了——**这条规则永远不会命中**，
    /// 于是那些域名走 DIRECT、没有任何加速，而配置和 doctor 看上去都正常。
    /// 同时 `h == GITHUB` 的大小写敏感判断还会让路径细分与 `*.github.com` 通配一起消失。
    #[test]
    fn mixed_case_hosts_are_normalized_in_pac() {
        let hosts = vec![
            "GitHub.com".to_string(),
            "  CodeLoad.GitHub.COM  ".to_string(),
        ];
        let text = build(8443, &hosts);

        assert!(
            text.contains("host == \"github.com\""),
            "github.com 应被小写化: {text}"
        );
        assert!(
            text.contains("host == \"codeload.github.com\""),
            "其它 host 也应小写化（且去掉首尾空白）: {text}"
        );
        assert!(
            !text.contains("GitHub.com") && !text.contains("GitHub.COM"),
            "不该出现任何原始大小写: {text}"
        );
        // 大小写不敏感地识别出 github.com 之后，子域通配必须在；
        // 路径规则**不该**存在（ADR-018）。
        assert!(
            !text.contains("shExpMatch(url"),
            "不该再生成路径规则: {text}"
        );
        assert!(
            text.contains("shExpMatch(host, \"*.github.com\")"),
            "应保留子域通配: {text}"
        );
    }

    /// host 里的 `"` / `\` 必须转义，否则生成的 PAC 语法错误。
    ///
    /// PAC 解析失败时 Windows 的行为是"退回直连"——用户只会看到"没加速"，
    /// 完全联想不到是配置里多了个引号。
    #[test]
    fn host_with_quotes_cannot_break_the_pac() {
        let hosts = vec![
            "evil\"host.example".to_string(),
            "back\\slash.example".to_string(),
        ];
        let text = build(8443, &hosts);
        assert!(text.contains(r#"host == "evil\"host.example""#), "{text}");
        assert!(text.contains(r#"host == "back\\slash.example""#), "{text}");
    }

    #[test]
    fn empty_scope_yields_direct_only() {
        let text = build(8443, &[]);
        // 空白名单时条件恒假。注意外层还有 https 限定，所以断言"条件里含 false"
        // 而不是整行的 `if (false)`（前者不依赖外层怎么包）。
        assert!(text.contains("(false)"), "条件应为假: {text}");
        assert!(text.contains("return \"DIRECT\";"));
        assert!(!text.contains("host =="), "不该出现任何 host 匹配: {text}");
    }

    /// 只接管 https：明文 http 进代理只会被 405，圈进来反而把能直连的请求弄坏。
    #[test]
    fn only_https_is_proxied() {
        let text = build(8443, &hosts());
        assert!(
            text.contains("url.substring(0, 6) == \"https:\""),
            "PAC 应显式限定 https: {text}"
        );
    }

    /// 模拟生成的 PAC：**只看 host**。
    ///
    /// 这不是执行 JS，而是把生成的 host 条件抄成 Rust 里的等价形式。
    /// 路径分流不再属于 PAC（WinINet 对 HTTPS 不给路径，见 ADR-018），
    /// 那部分由 `rewrite::needs_rewrite` 在代理侧完成。
    fn routes_to_proxy(url: &str) -> bool {
        let host = {
            let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
            rest.split('/').next().unwrap_or("").to_lowercase()
        };
        if host.ends_with(".github.com") {
            return true;
        }
        if host == "objects.githubusercontent.com"
            || host == "codeload.github.com"
            || host == "release-assets.githubusercontent.com"
        {
            return true;
        }
        host == "github.com"
    }

    #[test]
    fn clone_paths_are_routed_to_proxy_but_not_rewritten() {
        // PAC 只能整域（ADR-018）；"clone 路径不改写"由代理按真实路径判断，
        // 见 rewrite::tests 里对 needs_rewrite 的断言。
        for url in [
            "https://github.com/octocat/Hello-World.git/info/refs?service=git-upload-pack",
            "https://github.com/octocat/Hello-World.git/git-upload-pack",
            "https://github.com/octocat/Hello-World.git",
            "https://github.com/owner/repo",
            "https://github.com/owner/repo/pulls",
        ] {
            assert!(routes_to_proxy(url), "PAC 应整域走代理: {url}");
        }
    }

    #[test]
    fn winget_download_paths_go_proxy() {
        for url in [
            "https://github.com/sharkdp/fd/releases/download/v10.5.0/fd.zip",
            "https://github.com/owner/repo/releases/latest/download/x.zip",
            "https://github.com/git/git/archive/refs/tags/v2.43.0.tar.gz",
            "https://github.com/owner/repo/raw/main/file.txt",
            "https://github.com/owner/repo/blob/main/file.txt",
        ] {
            assert!(routes_to_proxy(url), "应走代理: {url}");
        }
    }

    #[test]
    fn other_download_hosts_go_proxy() {
        for url in [
            "https://codeload.github.com/git/git/tar.gz/refs/tags/v2.43.0",
            "https://release-assets.githubusercontent.com/github-production-release-asset/x",
            "https://objects.githubusercontent.com/some/blob",
            "https://api.github.com/repos/sharkdp/fd",
        ] {
            assert!(routes_to_proxy(url), "应走代理: {url}");
        }
    }

    #[test]
    fn pac_text_has_no_path_rules() {
        // WinINet 对 HTTPS 只把 `https://host:port/` 交给 PAC，
        // 路径规则写了也永远不命中（ADR-018 实测），所以生成器不能再输出它们。
        let pac = build(8443, &hosts());
        assert!(
            !pac.contains("shExpMatch(url"),
            "PAC 不该有基于 url 的规则: {pac}"
        );
        assert!(
            !pac.contains("releases/download"),
            "路径判断已移到代理侧: {pac}"
        );
        assert!(!pac.contains("git-upload"), "PAC 不应出现 clone 相关路径");
        // clone 路径不在放行列表里。
        // 注意不能断言 !pac.contains("*.git")：PAC 里有 "*.github.com"，
        // 它是 "*.git" 的超串，contains 会误判（这里踩过一次）。
        assert!(!pac.contains("*.git\""), "不应有 *.git 通配规则");
        assert!(!pac.contains("/info/refs"), "不应放行 clone 的 info/refs");
    }
}
