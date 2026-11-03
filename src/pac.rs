//! PAC 文本生成。
//!
//! PAC 的作用范围**比 MITM 范围宽**：只有 `rewrite_hosts` 会被终止 TLS 并改写，
//! 但这些 host 的子域（如 `api.github.com`）也会被圈进代理，只做隧道。
//! 这样做的目的是避免子域流量落到"系统直连"上被卡死（见 docs/design.md §4）。
//!
//! 例外：`github.com` 本身按**路径**细分，只把下载类路径交给代理——
//! 详见 [`build`] 的说明（`git clone` 依赖 POST 请求体，本代理不转发）。

/// 主站域名。它的 PAC 规则按路径细分，其它 host 整站代理。
const GITHUB: &str = "github.com";
/// 生成 PAC 脚本。
///
/// `github.com` **按路径**判断，不是整个 host 走代理。
///
/// 原因（实测，不是推测）：`git clone` 的 smart HTTP 需要
/// `POST /owner/repo.git/git-upload-pack` 并发送请求体，而本代理只转发响应体、
/// 不转发请求体——假上游收到 `Content-Length: 15` 的头，但那 15 字节没到。
/// 所以把 `github.com` 整个圈进代理，`git clone` 会在协议层直接失败。
///
/// 现在只把这些路径交给代理，其余 `github.com` 流量 DIRECT：
///   `*/releases/download/*`         release 资产（winget 下载主路径）
///   `*/releases/latest/download/*`  最新版直链
///   `*/archive/*`                   源码归档
///   `*/raw/*`、`*/blob/*`           原始文件
///
/// 认不出来的一律 DIRECT。本工具的职责是让 winget 下得动，不该连累别的用法。
///
/// `github.com` 上的 release 下载会 302 到 `release-assets.githubusercontent.com`，
/// 那个 host 仍在完整代理列表里，所以跳转后照样被改写。
pub fn build(port: u16, rewrite_hosts: &[String]) -> String {
    let mut conditions: Vec<String> = Vec::new();

    let has_github = rewrite_hosts.iter().any(|h| h == GITHUB);
    if has_github {
        conditions.push(format!("(host == \"{GITHUB}\" && ({PATH_CHECKS}))"));
        // 子域整站代理：api/raw/gist 等子域没有 git 上传场景
        conditions.push(format!("shExpMatch(host, \"*.{GITHUB}\")"));
    }

    // 其它 host（release-assets / codeload / objects）本来只服务下载，整 host 匹配
    for host in rewrite_hosts.iter().filter(|h| h.as_str() != GITHUB) {
        conditions.push(format!("host == \"{host}\""));
    }

    let condition = if conditions.is_empty() {
        "false".to_string()
    } else {
        conditions.join(" || ")
    };

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

/// `github.com` 上需要走代理的路径。
const PATH_CHECKS: &str = concat!(
    "shExpMatch(url, \"*/releases/download/*\")",
    " || shExpMatch(url, \"*/releases/latest/download/*\")",
    " || shExpMatch(url, \"*/archive/*\")",
    " || shExpMatch(url, \"*/raw/*\")",
    " || shExpMatch(url, \"*/blob/*\")"
);

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
        // shExpMatch 现在会多次出现：1 次子域通配 + 若干次 github.com 的路径规则。
        // 断言"恰好 1 次"是旧设计的残留（那时 github.com 整站走代理）。
        assert!(
            text.matches("shExpMatch").count() >= 2,
            "应同时含子域通配与 github.com 路径规则"
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

    #[test]
    fn empty_scope_yields_direct_only() {
        let text = build(8443, &[]);
        assert!(text.contains("if (false)"));
        assert!(text.contains("return \"DIRECT\";"));
    }

    /// 用正则粗略模拟 PAC 里的条件，验证"哪些 URL 会走代理"。
    /// 这不是执行 JS，而是把 PATH_CHECKS 的三段字符串与 host 判断抄成 Rust 里等价的形式。
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
        if host == "github.com" {
            return url.contains("/releases/download/")
                || url.contains("/releases/latest/download/")
                || url.contains("/archive/")
                || url.contains("/raw/")
                || url.contains("/blob/");
        }
        false
    }

    #[test]
    fn git_clone_paths_go_direct() {
        // 这是本次改动的核心动机：clone 依赖 POST + 请求体，本代理不转发请求体，
        // 所以这些路径必须直连，否则 clone 在协议层失败。
        for url in [
            "https://github.com/octocat/Hello-World.git/info/refs?service=git-upload-pack",
            "https://github.com/octocat/Hello-World.git/git-upload-pack",
            "https://github.com/octocat/Hello-World.git",
            "https://github.com/owner/repo",
            "https://github.com/owner/repo/pulls",
        ] {
            assert!(!routes_to_proxy(url), "应直连: {url}");
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
    fn pac_text_contains_path_rules() {
        let pac = build(8443, &hosts());
        assert!(
            pac.contains("releases/download"),
            "PAC 必须含 release 路径规则"
        );
        assert!(!pac.contains("git-upload"), "PAC 不应出现 clone 相关路径");
        // clone 路径不在放行列表里。
        // 注意不能断言 !pac.contains("*.git")：PAC 里有 "*.github.com"，
        // 它是 "*.git" 的超串，contains 会误判（这里踩过一次）。
        assert!(!pac.contains("*.git\""), "不应有 *.git 通配规则");
        assert!(!pac.contains("/info/refs"), "不应放行 clone 的 info/refs");
    }
}
