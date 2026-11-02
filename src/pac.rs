//! PAC 文本生成。
//!
//! PAC 的作用范围**比 MITM 范围宽**：只有 `rewrite_hosts` 会被终止 TLS 并改写，
//! 但这些 host 的子域（如 `api.github.com`）也会被圈进代理，只做隧道。
//! 这样做的目的是避免子域流量落到"系统直连"上被卡死（见 docs/design.md §4）。

use crate::config::DEFAULT_REWRITE_HOSTS;

/// 需要额外用通配符圈进来的子域根。
///
/// 目前只有 `github.com`：`api.github.com`、`raw.githubusercontent.com` 之类的
/// 子域虽然不改写，但让它们走隧道比让 winget 直连更稳。
const SUBDOMAIN_ROOTS: [&str; 1] = ["github.com"];

/// 生成 PAC 脚本。
pub fn build(port: u16, rewrite_hosts: &[String]) -> String {
    let exact: Vec<String> = rewrite_hosts
        .iter()
        .map(|host| format!("host == \"{host}\""))
        .collect();

    let mut conditions = exact;
    for root in SUBDOMAIN_ROOTS {
        if rewrite_hosts.iter().any(|h| h == root) {
            conditions.push(format!("shExpMatch(host, \"*.{root}\")"));
        }
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

/// 默认端口下生成 PAC（给 `--print-pac` 之类的便捷场景用）。
#[allow(dead_code)]
pub fn build_default(port: u16) -> String {
    let hosts: Vec<String> = DEFAULT_REWRITE_HOSTS
        .iter()
        .map(|s| s.to_string())
        .collect();
    build(port, &hosts)
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
        assert_eq!(text.matches("shExpMatch").count(), 1);
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
}
