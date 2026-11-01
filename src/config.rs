//! 配置与启动参数。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::rewrite::{parse_accel, Accel};

/// 默认改写范围（ADR-014 约束 2 的落地：只有这 4 个 host 会被终止 TLS）。
pub const DEFAULT_REWRITE_HOSTS: [&str; 4] = [
    "github.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "release-assets.githubusercontent.com",
];

const DEFAULT_LISTEN: &str = "127.0.0.1:8443";
const DEFAULT_ACCEL: &str = "https://gh-proxy.com";

#[derive(Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct FileConfig {
    pub listen: String,
    pub rewrite_hosts: Vec<String>,
    pub accelerators: Vec<AcceleratorCfg>,
    pub health: HealthCfg,
    pub fallback_to_original: bool,
    pub log_level: String,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN.to_string(),
            rewrite_hosts: DEFAULT_REWRITE_HOSTS.iter().map(|s| s.to_string()).collect(),
            accelerators: vec![AcceleratorCfg {
                name: "gh-proxy".into(),
                template: DEFAULT_ACCEL.into(),
                priority: 1,
            }],
            health: HealthCfg::default(),
            fallback_to_original: true,
            log_level: "info".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceleratorCfg {
    pub name: String,
    /// 完整基地址，如 `https://gh-proxy.com`。路径前缀由改写逻辑拼接。
    pub template: String,
    #[serde(default)]
    pub priority: u32,
}

#[derive(Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HealthCfg {
    pub enabled: bool,
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub failures_before_unhealthy: u32,
}

impl Default for HealthCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: 300,
            timeout_seconds: 8,
            failures_before_unhealthy: 2,
        }
    }
}

/// 运行期配置：文件配置 + 命令行覆盖。
#[derive(Debug)]
pub struct App {
    pub listen: SocketAddr,
    pub rewrite_hosts: Vec<String>,
    /// 按 priority 升序排列的加速器候选（回退链）。
    pub accels: Vec<Accel>,
    pub fallback_to_original: bool,
    pub cert_dir: PathBuf,
    pub log_path: PathBuf,
    /// 额外拦截但不改写的 host（只用于验证 Name Constraints 与排障）。
    pub mitm_extra: Vec<String>,
    pub health_enabled: bool,
    pub health_interval: Duration,
    pub health_timeout: Duration,
    /// 连续失败多少次判定为不健康。
    pub health_failures: u32,
}

impl App {
    pub fn new(file: FileConfig, cli: CliOverrides) -> Result<Self> {
        let listen_spec = cli.listen.unwrap_or(file.listen);
        let listen: SocketAddr = listen_spec
            .parse()
            .with_context(|| format!("listen 不是合法的 host:port: {listen_spec:?}"))?;

        // 代理会终止 TLS，绝不能监听非回环地址——那等于对外提供 MITM 服务。
        if !listen.ip().is_loopback() {
            bail!("listen 必须是回环地址（如 127.0.0.1:8443），当前为 {listen}");
        }

        let rewrite_hosts = if file.rewrite_hosts.is_empty() {
            DEFAULT_REWRITE_HOSTS.iter().map(|s| s.to_string()).collect()
        } else {
            file.rewrite_hosts
        };

        // 按 priority 升序构成回退链；--accel 覆盖成单元素
        let specs: Vec<String> = match cli.accel {
            Some(spec) => vec![spec],
            None => {
                let mut items: Vec<&AcceleratorCfg> = file.accelerators.iter().collect();
                items.sort_by_key(|a| a.priority);
                items.iter().map(|a| a.template.clone()).collect()
            }
        };
        let specs = if specs.is_empty() {
            vec![DEFAULT_ACCEL.to_string()]
        } else {
            specs
        };
        let mut accels = Vec::with_capacity(specs.len());
        for spec in &specs {
            accels.push(parse_accel(spec)?);
        }

        Ok(Self {
            listen,
            rewrite_hosts,
            accels,
            fallback_to_original: file.fallback_to_original,
            cert_dir: cli.cert_dir.unwrap_or_else(|| PathBuf::from("certs")),
            log_path: cli.log.unwrap_or_else(|| PathBuf::from("proxy.log")),
            mitm_extra: cli.mitm_extra,
            health_enabled: file.health.enabled,
            health_interval: Duration::from_secs(file.health.interval_seconds.max(60)),
            health_timeout: Duration::from_secs(file.health.timeout_seconds.max(1)),
            health_failures: file.health.failures_before_unhealthy.max(1),
        })
    }

    /// 该 host 是否要被终止 TLS 并改写。
    pub fn should_rewrite(&self, host: &str) -> bool {
        self.rewrite_hosts.iter().any(|h| h == host)
    }

    /// 该 host 是否要终止 TLS（改写 + 额外的排障 host）。
    pub fn should_mitm(&self, host: &str) -> bool {
        self.should_rewrite(host) || self.mitm_extra.iter().any(|h| h == host)
    }
}

#[derive(Debug, Default)]
pub struct CliOverrides {
    pub listen: Option<String>,
    pub accel: Option<String>,
    pub cert_dir: Option<PathBuf>,
    pub log: Option<PathBuf>,
    pub mitm_extra: Vec<String>,
}

/// 读配置文件；路径不存在时用默认值。
pub fn load(path: Option<&PathBuf>) -> Result<FileConfig> {
    let Some(path) = path else {
        return Ok(FileConfig::default());
    };
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("读不到配置文件: {}", path.display()))?;
    // 示例配置里带 $comment 键，serde 默认忽略未知键，无需额外处理
    serde_json::from_str(&text).with_context(|| format!("配置文件不是合法 JSON: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(listen: &str) -> Result<App> {
        let file = FileConfig {
            listen: listen.to_string(),
            ..Default::default()
        };
        App::new(file, CliOverrides::default())
    }

    #[test]
    fn defaults_are_loopback_and_whitelisted() {
        let app = app("127.0.0.1:8443").unwrap();
        assert_eq!(app.listen.port(), 8443);
        assert_eq!(app.rewrite_hosts.len(), 4);
        assert!(app.should_rewrite("github.com"));
        assert!(!app.should_rewrite("api.github.com"));
    }

    #[test]
    fn rejects_non_loopback_listen() {
        // 对外提供终止 TLS 的服务是不可接受的
        assert!(app("0.0.0.0:8443").is_err());
        assert!(app("192.168.1.10:8443").is_err());
    }

    #[test]
    fn accepts_ipv6_loopback() {
        assert!(app("[::1]:8443").is_ok());
    }

    #[test]
    fn rejects_malformed_listen() {
        assert!(app("127.0.0.1").is_err());
        assert!(app("not-an-address").is_err());
    }

    #[test]
    fn mitm_extra_widens_mitm_but_not_rewrite() {
        let file = FileConfig::default();
        let cli = CliOverrides {
            mitm_extra: vec!["example.com".into()],
            ..Default::default()
        };
        let app = App::new(file, cli).unwrap();
        assert!(app.should_mitm("example.com"));
        assert!(!app.should_rewrite("example.com"));
    }

    #[test]
    fn picks_lowest_priority_accelerator() {
        let file = FileConfig {
            accelerators: vec![
                AcceleratorCfg { name: "b".into(), template: "https://second.example".into(), priority: 2 },
                AcceleratorCfg { name: "a".into(), template: "https://first.example".into(), priority: 1 },
            ],
            ..Default::default()
        };
        let app = App::new(file, CliOverrides::default()).unwrap();
        assert_eq!(app.accels[0].host, "first.example");
    }

    #[test]
    fn cli_accel_overrides_file() {
        let file = FileConfig::default();
        let cli = CliOverrides {
            accel: Some("http://127.0.0.1:9000".into()),
            ..Default::default()
        };
        let app = App::new(file, cli).unwrap();
        assert_eq!(app.accels.len(), 1, "--accel 应覆盖成单候选");
        assert_eq!((app.accels[0].host.as_str(), app.accels[0].port), ("127.0.0.1", 9000));
    }

    #[test]
    fn example_config_parses() {
        let text = std::fs::read_to_string("config.example.json").unwrap();
        let file: FileConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(file.rewrite_hosts.len(), 4);
        assert!(!file.accelerators.is_empty());
    }
}
