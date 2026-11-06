//! Bounded real-asset checks decide which exact PAC hosts can bypass the proxy.
//! Evidence stays in memory; a new process always verifies its own network.
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Body;
use hyper::{HeaderMap, Response, Uri};
use serde::{Deserialize, Serialize};

use crate::config::{App, RoutingCfg, RoutingMode};
use crate::http;
use crate::log::{Level, Logger};
use crate::rewrite::Scheme;

const SAMPLE_BYTES: usize = 256 * 1024;
const MAX_REDIRECTS: usize = 5;
const CODELOAD_ASSET: &str = "https://codeload.github.com/git/git/tar.gz/refs/tags/v2.43.0";

pub struct Router {
    cfg: RoutingCfg,
    hosts: Vec<String>,
    urls: Vec<String>,
    state: Mutex<State>,
}

struct State {
    revision: u64,
    hosts: Vec<Host>,
}

struct Host {
    direct: bool,
    kbps: Option<f64>,
    checked: Option<Instant>,
    changed: Option<Instant>,
    expires_at: u64,
    reason: &'static str,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub mode: RoutingMode,
    pub revision: u64,
    pub hosts: Vec<HostSnapshot>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostSnapshot {
    pub host: String,
    pub direct: bool,
    pub kbps: Option<u64>,
    pub checked_seconds_ago: Option<u64>,
    pub expires_at: u64,
    pub reason: String,
}

impl Snapshot {
    pub fn pac_routes(&self) -> Vec<(String, u64)> {
        self.hosts
            .iter()
            .filter(|host| host.direct)
            .map(|host| (host.host.clone(), host.expires_at))
            .collect()
    }
}

impl Router {
    pub fn new(app: &App) -> Self {
        let urls = if app.routing.probe_urls.is_empty() {
            [crate::proxy::DEFAULT_PROBE_ASSET, CODELOAD_ASSET]
                .into_iter()
                .filter(|url| {
                    url.parse::<Uri>()
                        .ok()
                        .and_then(|uri| uri.host().map(str::to_owned))
                        .is_some_and(|host| app.rewrite_hosts.contains(&host))
                })
                .map(str::to_owned)
                .collect()
        } else {
            app.routing.probe_urls.clone()
        };
        Self {
            cfg: app.routing.clone(),
            hosts: app.rewrite_hosts.clone(),
            urls,
            state: Mutex::new(State {
                revision: 0,
                hosts: app
                    .rewrite_hosts
                    .iter()
                    .map(|_| Host {
                        direct: false,
                        kbps: None,
                        checked: None,
                        changed: None,
                        expires_at: 0,
                        reason: if app.routing.mode == RoutingMode::Auto {
                            "unverified"
                        } else {
                            "forced"
                        },
                    })
                    .collect(),
            }),
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().expect("routing lock");
        let wall_ms = epoch_millis();
        Snapshot {
            mode: self.cfg.mode,
            revision: state.revision,
            hosts: self
                .hosts
                .iter()
                .zip(&state.hosts)
                .map(|(name, host)| HostSnapshot {
                    host: name.clone(),
                    direct: host.direct && wall_ms < host.expires_at,
                    kbps: host.kbps.map(|speed| speed as u64),
                    checked_seconds_ago: host.checked.map(|at| at.elapsed().as_secs()),
                    expires_at: host.expires_at,
                    reason: if host.direct && wall_ms >= host.expires_at {
                        "expired".into()
                    } else {
                        host.reason.into()
                    },
                })
                .collect(),
        }
    }

    /// Refresh in parallel with a single total deadline per URL (both samples,
    /// DNS, TLS, redirects and payload). No locks are held across network I/O.
    pub fn refresh(&self, log: &Logger) -> bool {
        if self.cfg.mode == RoutingMode::Accelerator {
            return false;
        }
        let evidence = http::block_on(async {
            let mut tasks = tokio::task::JoinSet::new();
            for url in &self.urls {
                let url = url.clone();
                let hosts = self.hosts.clone();
                let duration = Duration::from_secs(self.cfg.timeout_seconds);
                tasks.spawn(async move {
                    let result = measure(&url, &hosts, duration, |uri| async move {
                        let authority = uri.authority().context("missing authority")?;
                        let mut headers = HeaderMap::new();
                        headers.insert("host", authority.as_str().parse()?);
                        headers.insert("range", format!("bytes=0-{}", SAMPLE_BYTES - 1).parse()?);
                        headers.insert("accept-encoding", "identity".parse()?);
                        headers.insert("user-agent", "winget-accel-direct-probe".parse()?);
                        let request = http::request(
                            "GET",
                            uri.path_and_query().context("missing path")?.as_str(),
                            headers,
                        )?;
                        http::send(Scheme::Https, authority.host(), 443, request, duration).await
                    })
                    .await;
                    (
                        url.parse::<Uri>()
                            .ok()
                            .and_then(|uri| uri.host().map(str::to_owned))
                            .unwrap_or_default(),
                        result,
                    )
                });
            }
            let mut evidence: HashMap<String, f64> = HashMap::new();
            let mut failed_hosts = HashSet::new();
            while let Some(result) = tasks.join_next().await {
                match result {
                    Ok((_, Ok(sample))) => {
                        for host in sample.hosts {
                            // Conflicting assets on the same host use the conservative sample.
                            evidence
                                .entry(host)
                                .and_modify(|speed| *speed = speed.min(sample.kbps))
                                .or_insert(sample.kbps);
                        }
                    }
                    Ok((host, Err(error))) => {
                        log.log(Level::Debug, &format!("DIRECT-PROBE host={host} {error:#}"));
                        failed_hosts.insert(host.to_ascii_lowercase());
                    }
                    Err(error) => log.warn(&format!("DIRECT-PROBE task failed: {error}")),
                }
            }
            evidence.retain(|host, _| !failed_hosts.contains(host));
            evidence
        });
        let publish = self.apply(&evidence, Instant::now(), epoch_millis(), log);
        log.info(&format!(
            "ROUTE-CHECK direct={}/{} threshold={}KiB/s",
            self.snapshot()
                .hosts
                .iter()
                .filter(|host| host.direct)
                .count(),
            self.hosts.len(),
            self.cfg.min_direct_kbps
        ));
        publish
    }

    fn apply(
        &self,
        evidence: &HashMap<String, f64>,
        now: Instant,
        wall_ms: u64,
        log: &Logger,
    ) -> bool {
        let mut state = self.state.lock().expect("routing lock");
        let mut publish = false;
        let lifetime_ms = (self.cfg.interval_seconds + self.cfg.timeout_seconds + 10) * 1000;
        for (name, host) in self.hosts.iter().zip(&mut state.hosts) {
            let was_direct = host.direct;
            host.kbps = evidence.get(name).copied();
            host.checked = Some(now);
            let qualified = host
                .kbps
                .is_some_and(|speed| speed >= self.cfg.min_direct_kbps as f64);
            let cooling = !was_direct
                && host.changed.is_some_and(|changed| {
                    now.duration_since(changed) < Duration::from_secs(self.cfg.cooldown_seconds)
                });
            host.direct = qualified && !cooling;
            host.reason = if host.direct {
                "verified"
            } else if qualified && cooling {
                "cooldown"
            } else if host.kbps.is_some() {
                "slow"
            } else {
                "unverified"
            };
            host.expires_at = if host.direct {
                wall_ms.saturating_add(lifetime_ms)
            } else {
                0
            };
            if host.direct != was_direct {
                host.changed = Some(now);
                log.info(&format!(
                    "ROUTE-CHANGE host={name} route={} kbps={:.0} reason={}",
                    if host.direct { "DIRECT" } else { "ACCELERATOR" },
                    host.kbps.unwrap_or(0.0),
                    host.reason
                ));
            }
            // Renew expiring DIRECT evidence even when the selected route is unchanged.
            publish |= host.direct || was_direct;
        }
        if publish {
            state.revision += 1;
        }
        publish
    }

    pub fn spawn(self: &Arc<Self>, log: Arc<Logger>) {
        if self.cfg.mode == RoutingMode::Accelerator {
            return;
        }
        let router = self.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(router.cfg.interval_seconds));
            if router.refresh(&log) {
                if let Err(error) = crate::autoenv::refresh_owned_pac(router.snapshot().revision) {
                    log.warn(&format!("PAC-REFRESH-FAIL {error:#}"));
                }
            }
        });
    }
}

fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct Sample {
    hosts: HashSet<String>,
    kbps: f64,
}

async fn measure<F, Fut, B>(
    url: &str,
    allowed: &[String],
    duration: Duration,
    mut fetch: F,
) -> Result<Sample>
where
    F: FnMut(Uri) -> Fut,
    Fut: Future<Output = Result<Response<B>>>,
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<anyhow::Error>,
{
    tokio::time::timeout(duration, async {
        let mut first = sample(url, allowed, &mut fetch).await?;
        let second = sample(url, allowed, &mut fetch).await?;
        first.hosts.retain(|host| second.hosts.contains(host));
        first.kbps = first.kbps.min(second.kbps);
        Ok(first)
    })
    .await
    .context("direct probe total timeout")?
}

async fn sample<F, Fut, B>(url: &str, allowed: &[String], fetch: &mut F) -> Result<Sample>
where
    F: FnMut(Uri) -> Fut,
    Fut: Future<Output = Result<Response<B>>>,
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<anyhow::Error>,
{
    let started = Instant::now();
    let mut uri: Uri = url.parse()?;
    let mut hosts = HashSet::new();
    for hop in 0..=MAX_REDIRECTS {
        let host = uri.host().context("missing host")?.to_ascii_lowercase();
        let authority = uri.authority().context("missing authority")?;
        if uri.scheme_str() != Some("https")
            || authority.as_str().contains('@')
            || (authority.as_str() != authority.host() && uri.port_u16() != Some(443))
            || !allowed.contains(&host)
        {
            bail!("redirect is outside HTTPS download scope");
        }
        hosts.insert(host);
        let response = fetch(uri).await?;
        if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            if hop == MAX_REDIRECTS {
                bail!("too many redirects");
            }
            // GitHub asset redirects are absolute. Unsupported forms fail closed.
            uri = response
                .headers()
                .get("location")
                .context("redirect has no location")?
                .to_str()?
                .parse()?;
            continue;
        }
        let partial = response.status() == 206;
        if !partial && response.status() != 200 {
            bail!("download did not succeed");
        }
        if partial {
            let range = response
                .headers()
                .get("content-range")
                .context("missing Content-Range")?
                .to_str()?;
            let (last, total) = range
                .strip_prefix("bytes 0-")
                .and_then(|r| r.split_once('/'))
                .context("invalid Content-Range")?;
            if last.parse::<usize>()? != SAMPLE_BYTES - 1
                || total.parse::<u64>()? < SAMPLE_BYTES as u64
            {
                bail!("wrong sample range");
            }
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if content_type.starts_with("text/")
            || content_type.contains("html")
            || content_type.contains("json")
            || response
                .headers()
                .get("content-encoding")
                .is_some_and(|v| v != "identity")
        {
            bail!("not an unencoded download asset");
        }
        let mut body = response.into_body();
        let mut count = 0;
        let mut prefix = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame.map_err(Into::into)?.into_data() {
                prefix.extend_from_slice(&data[..data.len().min(32 - prefix.len())]);
                if partial && data.len() > SAMPLE_BYTES - count {
                    bail!("oversized range sample");
                }
                count = (count + data.len()).min(SAMPLE_BYTES);
                if !partial && count == SAMPLE_BYTES {
                    break;
                }
            }
        }
        if count != SAMPLE_BYTES
            || prefix
                .iter()
                .copied()
                .find(|byte| !byte.is_ascii_whitespace())
                == Some(b'<')
        {
            bail!("incomplete or non-download sample");
        }
        return Ok(Sample {
            hosts,
            kbps: count as f64 / 1024.0 / started.elapsed().as_secs_f64().max(f64::EPSILON),
        });
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn asset(status: u16, body: Bytes) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header(
                "content-range",
                format!("bytes 0-{}/1048576", SAMPLE_BYTES - 1),
            )
            .body(Full::new(body))
            .unwrap()
    }

    fn scope() -> Vec<String> {
        vec![
            "github.com".into(),
            "release-assets.githubusercontent.com".into(),
        ]
    }

    #[test]
    fn verifies_both_samples_and_redirect_hosts() {
        let calls = AtomicUsize::new(0);
        let result = http::block_on(measure(
            "https://github.com/asset",
            &scope(),
            Duration::from_secs(1),
            |uri| {
                calls.fetch_add(1, Ordering::Relaxed);
                std::future::ready(Ok(if uri.host() == Some("github.com") {
                    Response::builder()
                        .status(302)
                        .header(
                            "location",
                            "https://release-assets.githubusercontent.com/asset?sig=test",
                        )
                        .body(Full::new(Bytes::new()))
                        .unwrap()
                } else {
                    asset(206, Bytes::from(vec![b'P'; SAMPLE_BYTES]))
                }))
            },
        ))
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 4);
        assert_eq!(result.hosts, scope().into_iter().collect());
        assert!(result.kbps > 0.0);
    }

    #[test]
    fn accepts_bounded_prefix_when_archive_server_ignores_range() {
        let result = http::block_on(measure(
            "https://github.com/archive",
            &scope(),
            Duration::from_secs(1),
            |_| std::future::ready(Ok(asset(200, Bytes::from(vec![b'P'; SAMPLE_BYTES * 2])))),
        ));
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_html_short_encoded_and_invalid_partial_samples() {
        for case in 0..6 {
            let result = http::block_on(measure(
                "https://github.com/asset",
                &scope(),
                Duration::from_secs(1),
                |_| {
                    let mut response = asset(206, Bytes::from(vec![b'P'; SAMPLE_BYTES]));
                    match case {
                        0 => {
                            response
                                .headers_mut()
                                .insert("content-type", "text/html".parse().unwrap());
                        }
                        1 => {
                            *response.body_mut() =
                                Full::new(Bytes::from(vec![b'P'; SAMPLE_BYTES - 1]));
                        }
                        2 => {
                            response
                                .headers_mut()
                                .insert("content-encoding", "gzip".parse().unwrap());
                        }
                        3 => {
                            response.headers_mut().remove("content-range");
                        }
                        4 => {
                            *response.body_mut() =
                                Full::new(Bytes::from(vec![b'P'; SAMPLE_BYTES + 1]));
                        }
                        _ => {
                            *response.body_mut() = Full::new(Bytes::from(vec![b'<'; SAMPLE_BYTES]));
                        }
                    }
                    std::future::ready(Ok(response))
                },
            ));
            assert!(result.is_err(), "case={case}");
        }
    }

    #[test]
    fn redirect_scope_and_hop_limit_are_enforced_before_connecting() {
        for target in [
            "http://github.com/asset",
            "https://other.example/asset",
            "https://github.com:8443/asset",
            "https://user@github.com/asset",
            "https://github.com/loop",
        ] {
            let calls = AtomicUsize::new(0);
            let result = http::block_on(measure(
                "https://github.com/asset",
                &scope(),
                Duration::from_secs(1),
                |_| {
                    calls.fetch_add(1, Ordering::Relaxed);
                    std::future::ready(Ok(Response::builder()
                        .status(302)
                        .header("location", target)
                        .body(Full::new(Bytes::new()))
                        .unwrap()))
                },
            ));
            assert!(result.is_err(), "{target}");
            assert_eq!(
                calls.load(Ordering::Relaxed),
                if target.ends_with("loop") {
                    MAX_REDIRECTS + 1
                } else {
                    1
                }
            );
        }
    }

    #[test]
    fn deadline_is_shared_by_both_samples() {
        let started = Instant::now();
        let result = http::block_on(measure(
            "https://github.com/asset",
            &scope(),
            Duration::from_millis(70),
            |_| async {
                tokio::time::sleep(Duration::from_millis(45)).await;
                Ok(asset(206, Bytes::from(vec![b'P'; SAMPLE_BYTES])))
            },
        ));
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn routes_require_fresh_evidence_and_failed_routes_cool_down() {
        let mut file: crate::config::FileConfig = serde_json::from_str(
            r#"{"accelerators":[{"name":"test","template":"https://accel.example"}]}"#,
        )
        .unwrap();
        file.routing.interval_seconds = 60;
        file.routing.cooldown_seconds = 60;
        let app = App::new(file).unwrap();
        let router = Router::new(&app);
        let log = Logger::new(
            crate::log::Level::Error,
            std::env::temp_dir().join("wg-routing-test.log"),
        );
        let now = Instant::now();
        assert!(router.snapshot().pac_routes().is_empty());
        let fast = HashMap::from([("github.com".into(), 1024.0)]);
        assert!(router.apply(&fast, now, 1000, &log));
        let snapshot = router.snapshot();
        assert!(!snapshot.hosts[0].direct);
        assert_eq!(snapshot.hosts[0].reason, "expired");
        assert_eq!(snapshot.hosts[0].expires_at, 76_000);
        assert!(router.apply(&HashMap::new(), now + Duration::from_secs(1), 2000, &log));
        assert!(router.snapshot().pac_routes().is_empty());
        assert!(!router.apply(&fast, now + Duration::from_secs(2), 3000, &log));
        assert_eq!(router.snapshot().hosts[0].reason, "cooldown");
        assert!(router.apply(&fast, now + Duration::from_secs(62), 63_000, &log));
        assert_eq!(router.snapshot().hosts[0].expires_at, 138_000);
        assert!(router.apply(&fast, now + Duration::from_secs(63), epoch_millis(), &log));
        assert_eq!(router.snapshot().pac_routes().len(), 1);
    }
}
