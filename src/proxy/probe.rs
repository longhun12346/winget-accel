//! 本机候选验证：有界异步竞争、小运行池、轮换探索和失败退避。

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::Proxy;
use crate::health::POOL_CANDIDATES;
use crate::http;
use crate::log::Level;
use crate::rewrite;

const BOOTSTRAP_BUDGET: Duration = Duration::from_secs(8);
const PROBE_CONCURRENCY: usize = 4;
const BACKGROUND_CONCURRENCY: usize = 2;
const BOOTSTRAP_TARGET: usize = 2;
const PROBE_SPEED_TIMEOUT: Duration = Duration::from_secs(5);
const RECOVERY_INTERVAL: Duration = Duration::from_secs(30);
const SCHEDULER_TICK: Duration = Duration::from_secs(5);

struct Retry {
    next: Instant,
    failures: u32,
}
struct Schedule {
    entries: Vec<Retry>,
    cursor: usize,
    next_explore: Instant,
}

/// 取消任务不记录失败；只有完整结束的探测才推进退避。
pub(super) struct Scheduler {
    state: Mutex<Schedule>,
    demand: Mutex<Vec<String>>,
    wake: tokio::sync::Notify,
}
impl Scheduler {
    pub(super) fn new(count: usize) -> Self {
        let now = Instant::now();
        Self {
            state: Mutex::new(Schedule {
                entries: (0..count)
                    .map(|_| Retry {
                        next: now,
                        failures: 0,
                    })
                    .collect(),
                cursor: 0,
                next_explore: now,
            }),
            demand: Mutex::new(Vec::new()),
            wake: tokio::sync::Notify::new(),
        }
    }
    pub(super) fn request(&self, host: &str) {
        let mut demand = self.demand.lock().expect("probe demand lock");
        if !demand.iter().any(|h| h == host) {
            demand.push(host.to_owned());
            self.wake.notify_one();
        }
    }
    pub(super) fn wake(&self) {
        self.wake.notify_one();
    }
    fn completed(&self, idx: usize, success: bool, interval: Duration) {
        let mut state = self.state.lock().expect("probe schedule lock");
        let entry = &mut state.entries[idx];
        let delay = if success {
            entry.failures = 0;
            interval
        } else {
            entry.failures = entry.failures.saturating_add(1);
            RECOVERY_INTERVAL
                .saturating_mul(1 << entry.failures.saturating_sub(1).min(6))
                .min(Duration::from_secs(30 * 60))
        };
        entry.next = Instant::now() + delay;
    }
}

impl Proxy {
    pub(super) fn spawn_health_prober(self: &Arc<Self>) {
        let proxy = self.clone();
        // 复用已有 Tokio 运行时；异步任务在 block_on 返回后仍由共享运行时驱动。
        http::block_on(async move {
            tokio::spawn(async move {
                loop {
                    let notified = proxy.probes.wake.notified();
                    let (candidates, target) = proxy.maintenance_candidates();
                    if !candidates.is_empty() {
                        proxy
                            .verify_candidates(
                                candidates,
                                target,
                                BACKGROUND_CONCURRENCY,
                                BOOTSTRAP_BUDGET,
                            )
                            .await;
                        proxy.report_health_state();
                    }
                    let _ = tokio::time::timeout(SCHEDULER_TICK, notified).await;
                }
            });
        });
    }

    /// 找到两个可用候选即可就绪；达到总期限时取消剩余 I/O，不把取消记成失败。
    pub fn bootstrap_health(self: &Arc<Self>) {
        let candidates = (0..self.app.accels.len()).collect();
        let started = Instant::now();
        let probed = http::block_on(self.verify_candidates(
            candidates,
            Some(BOOTSTRAP_TARGET),
            PROBE_CONCURRENCY,
            BOOTSTRAP_BUDGET,
        ));
        let healthy = self.health.healthy_count();
        if healthy > 0 {
            self.log.info(&format!("HEALTH-READY 已有 {healthy} 个候选通过验证（完成 {probed} 个，{:.2}s），后台按需补充", started.elapsed().as_secs_f64()));
        } else {
            self.log.error(
                "NO-VERIFIED-ACCEL 启动验证未找到可用候选，后台继续轮换恢复；加速请求暂时返回 502",
            );
            if self.app.health_probe_custom {
                self.log.warn(&format!(
                    "提示：请检查自定义 health.probeUrl {}；候选必须能代理这个 HTTPS GitHub 资产",
                    self.app.health_probe
                ));
            }
        }
    }

    async fn verify_candidates(
        self: &Arc<Self>,
        candidates: Vec<usize>,
        target: Option<usize>,
        concurrency: usize,
        budget: Duration,
    ) -> usize {
        let deadline = tokio::time::Instant::now() + budget;
        let mut queue = candidates.into_iter();
        let mut tasks = tokio::task::JoinSet::new();
        let mut completed = 0;
        loop {
            if target.is_some_and(|target| self.health.healthy_count() >= target)
                || tokio::time::Instant::now() >= deadline
            {
                break;
            }
            while tasks.len() < concurrency {
                let Some(idx) = queue.next() else {
                    break;
                };
                let accel = self.app.accels[idx].clone();
                let asset = self.app.health_probe.clone();
                let duration = PROBE_SPEED_TIMEOUT
                    .min(self.app.health_timeout)
                    .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
                // 游标在派发时推进，取消的慢节点不会永远挡在后续候选之前。
                self.probes
                    .state
                    .lock()
                    .expect("probe schedule lock")
                    .cursor = (idx + 1) % self.app.accels.len();
                tasks
                    .spawn(async move { (idx, probe_speed_async(&accel, duration, &asset).await) });
            }
            if tasks.is_empty() {
                break;
            }
            match tokio::time::timeout_at(deadline, tasks.join_next()).await {
                Ok(Some(Ok((idx, result)))) => {
                    if tokio::time::Instant::now() >= deadline {
                        break;
                    }
                    completed += 1;
                    match result {
                        Some(kbps) => self.health.seed_speed(idx, kbps),
                        None => self.health.mark(idx, false),
                    }
                    let success = self.health.is_healthy(idx);
                    self.probes
                        .completed(idx, success, self.app.health_interval);
                    self.log.log(
                        if success { Level::Debug } else { Level::Warn },
                        &format!(
                            "SPEED {} -> {}",
                            self.app.accels[idx].host,
                            result.map_or_else(
                                || "实测失败（非 206、范围错误、超时或数据不足），已排除".into(),
                                |kbps| format!("{kbps:.0} KB/s 本机短测 healthy={success}")
                            ),
                        ),
                    );
                }
                Ok(Some(Err(error))) => self.log.warn(&format!("HEALTH 探测任务异常: {error}")),
                _ => break,
            }
        }
        tasks.shutdown().await;
        completed
    }

    fn maintenance_candidates(&self) -> (Vec<usize>, Option<usize>) {
        let eligible = |idx| !self.cooldowns.is_service_blocked(idx);
        let pool: Vec<_> = self
            .health
            .ranked_verified_where(eligible)
            .into_iter()
            .take(POOL_CANDIDATES)
            .collect();
        let mut demand = self.probes.demand.lock().expect("probe demand lock");
        demand.retain(|host| {
            self.health
                .ranked_verified_where(|idx| self.usable_for(idx, host))
                .is_empty()
        });
        if !self.app.health_enabled && !pool.is_empty() && demand.is_empty() {
            return (Vec::new(), None);
        }
        let now = Instant::now();
        let mut schedule = self.probes.state.lock().expect("probe schedule lock");
        let count = schedule.entries.len();
        if count == 0 {
            return (Vec::new(), None);
        }
        let due = |idx: usize| schedule.entries[idx].next <= now && eligible(idx);
        let mut candidates: Vec<_> = pool
            .iter()
            .copied()
            .filter(|idx| {
                due(*idx)
                    && (demand.is_empty() || demand.iter().any(|host| self.usable_for(*idx, host)))
                    && !self
                        .health
                        .recently_succeeded(*idx, self.app.health_interval)
            })
            .collect();
        let fill = pool.len() < POOL_CANDIDATES;
        // 满池后每个配置周期仅探索两个节点；有下载时让出带宽。
        let explore = fill
            || !demand.is_empty()
            || (now >= schedule.next_explore
                && self.active.load(std::sync::atomic::Ordering::Relaxed) == 0);
        let mut explored = 0;
        if explore {
            for offset in 0..count {
                let idx = (schedule.cursor + offset) % count;
                if candidates.contains(&idx) || pool.contains(&idx) || !due(idx) {
                    continue;
                }
                if !demand.is_empty() && !demand.iter().any(|host| self.usable_for(idx, host)) {
                    continue;
                }
                candidates.push(idx);
                explored += 1;
                if !fill && demand.is_empty() && explored >= 2 {
                    break;
                }
            }
        }
        if explored > 0 {
            schedule.next_explore = now + self.app.health_interval;
        }
        let target = if fill && demand.is_empty() {
            Some(POOL_CANDIDATES)
        } else {
            None
        };
        (candidates, target)
    }
}

/// 探测基准资产（默认值）：用 release 资产（CDN 静态文件），不用 codeload 的 tag 归档。
///
/// 实测依据：`codeload` 的 tarball 在 5 个加速器里有 4 个返回 403/404/超时，
/// 用它当基准会把正常候选误判成不可用；而 release 资产 5/5 都返回 206。
///
/// **它绑着一个具体版本号，这是已知弱点**：上游一旦删掉该资产，所有候选都会
/// "测速失败"→ 全部判死 → 全站 502。所以该值可通过配置 `health.probeUrl` 覆盖
/// （见 docs/design.md）；启动验证没有可用结果时会提示检查自定义资产。
pub const DEFAULT_PROBE_ASSET: &str =
    "https://github.com/git-for-windows/git/releases/download/v2.43.0.windows.1/Git-2.43.0-64-bit.exe";
/// 本机粗测采样量。要求完整 64 KiB，DNS/TLS/响应头和正文共用单次期限。
const PROBE_BYTES: u64 = 64 * 1024;

/// 把基准资产拆成 (host, path+query)。只接受 https，避免把 http 资产
/// 拼成 `https://host/...` 这种自相矛盾的改写路径。
///
/// `pub(crate)`：`config` 加载 `health.probeUrl` 时用它做校验，避免两处各写一套。
pub(crate) fn split_asset(asset: &str) -> Option<(String, String)> {
    let uri: hyper::Uri = asset.parse().ok()?;
    if uri.scheme_str()? != "https" {
        return None;
    }
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    if uri.port_u16() == Some(0) {
        return None;
    }
    let path = uri.path_and_query()?;
    if path.path() == "/" {
        return None;
    }
    Some((authority.as_str().to_string(), path.to_string()))
}

pub(crate) fn probe_speed(accel: &rewrite::Accel, duration: Duration, asset: &str) -> Option<f64> {
    http::block_on(probe_speed_async(accel, duration, asset))
}

async fn probe_speed_async(accel: &rewrite::Accel, duration: Duration, asset: &str) -> Option<f64> {
    let (host, path) = split_asset(asset)?;
    tokio::time::timeout(duration, async {
        let started = Instant::now();
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "host",
            rewrite::host_header(accel.scheme, &accel.host, accel.port)
                .parse()
                .ok()?,
        );
        headers.insert("user-agent", "winget-accel-probe".parse().ok()?);
        headers.insert(
            "range",
            format!("bytes=0-{}", PROBE_BYTES - 1).parse().ok()?,
        );
        let request =
            http::request("GET", &rewrite::rewrite_path(accel, &host, &path), headers).ok()?;
        let response = http::send(accel.scheme, &accel.host, accel.port, request, duration)
            .await
            .ok()?;
        if response.status() != 206 {
            return None;
        }
        let mut requested = hyper::HeaderMap::new();
        requested.insert(
            "range",
            format!("bytes=0-{}", PROBE_BYTES - 1).parse().ok()?,
        );
        if !super::range_response_matches(&requested, response.headers()) {
            return None;
        }
        let body = http::read_body(response, PROBE_BYTES as usize).await.ok()?;
        if body.len() != PROBE_BYTES as usize {
            return None;
        }
        Some((body.len() as f64 / 1024.0) / started.elapsed().as_secs_f64().max(f64::EPSILON))
    })
    .await
    .ok()
    .flatten()
}

/// Root reachability alone never qualifies a candidate for download scheduling.
pub fn probe(accel: &rewrite::Accel, duration: Duration) -> bool {
    http::block_on(async {
        let result = async {
            let mut headers = hyper::HeaderMap::new();
            headers.insert(
                "host",
                rewrite::host_header(accel.scheme, &accel.host, accel.port).parse()?,
            );
            headers.insert("user-agent", "winget-accel-health".parse()?);
            let request = http::request("GET", "/", headers)?;
            http::send(accel.scheme, &accel.host, accel.port, request, duration).await
        }
        .await;
        result.is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    struct Fixture {
        url: String,
        requests: Arc<Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl Fixture {
        async fn start(delay: Duration, status: u16) -> Self {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = requests.clone();
            let task = tokio::spawn(async move {
                let mut clients = tokio::task::JoinSet::new();
                while let Ok((mut socket, _)) = listener.accept().await {
                    while clients.try_join_next().is_some() {}
                    let recorded = recorded.clone();
                    clients.spawn(async move {
                        let mut head = Vec::new();
                        while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
                            let mut byte = [0];
                            if socket.read_exact(&mut byte).await.is_err() { return; }
                            head.push(byte[0]);
                        }
                        recorded.lock().unwrap().push(String::from_utf8(head).unwrap());
                        tokio::time::sleep(delay).await;
                        let head = format!("HTTP/1.1 {status} Result\r\nContent-Length: 65536\r\nContent-Range: bytes 0-65535/1048576\r\nConnection: close\r\n\r\n");
                        if socket.write_all(head.as_bytes()).await.is_ok() {
                            let _ = socket.write_all(&vec![b'P'; PROBE_BYTES as usize]).await;
                        }
                    });
                }
            });
            Self {
                url,
                requests,
                task,
            }
        }
    }
    struct Sandbox {
        proxy: Arc<Proxy>,
        root: std::path::PathBuf,
    }
    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    fn sandbox(urls: &[&str]) -> Sandbox {
        let root = std::env::temp_dir().join(format!("wg-scheduler-{:016x}", fastrand::u64(..)));
        let app = Arc::new(
            crate::config::App::new(crate::config::FileConfig {
                accelerators: urls
                    .iter()
                    .enumerate()
                    .map(|(i, url)| crate::config::AcceleratorCfg {
                        name: format!("fixture-{i}"),
                        template: url.to_string(),
                        priority: i as u32,
                        hosts: Vec::new(),
                    })
                    .collect(),
                ..crate::config::FileConfig::default()
            })
            .unwrap(),
        );
        let ca = Arc::new(
            crate::ca::CertAuthority::load_or_create(&root, &app.rewrite_hosts, false).unwrap(),
        );
        let tracker = Arc::new(crate::health::Tracker::new(app.accels.clone(), 2));
        let proxy = Arc::new(Proxy::new(
            app,
            ca,
            Arc::new(crate::stats::Stats::default()),
            Arc::new(crate::log::Logger::new(Level::Error, root.join("test.log"))),
            tracker,
        ));
        Sandbox { proxy, root }
    }

    #[test]
    fn completed_results_bypass_stalled_peers_and_cancellation_is_not_failure() {
        http::block_on(async {
            let slow = Fixture::start(Duration::from_secs(3), 206).await;
            let fast = Fixture::start(Duration::ZERO, 206).await;
            let bad = Fixture::start(Duration::ZERO, 503).await;
            let next = Fixture::start(Duration::from_millis(20), 206).await;
            let later = Fixture::start(Duration::ZERO, 206).await;
            let sandbox = sandbox(&[&slow.url, &fast.url, &bad.url, &next.url, &later.url]);
            let proxy = &sandbox.proxy;
            let started = Instant::now();
            let completed = proxy
                .verify_candidates((0..5).collect(), Some(2), 2, Duration::from_secs(2))
                .await;
            assert_eq!(completed, 3);
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "不能等待同批的慢候选"
            );
            assert_eq!(proxy.health.snapshot()[0].1, crate::health::Health::Unknown);
            assert_eq!(proxy.probes.state.lock().unwrap().entries[0].failures, 0);
            assert_eq!(proxy.health.healthy_count(), 2);
            assert!(later.requests.lock().unwrap().is_empty());
            let request = &fast.requests.lock().unwrap()[0];
            assert!(
                request.starts_with("GET /https://"),
                "直接请求资产，不访问首页: {request}"
            );
        });
    }

    #[test]
    fn total_deadline_cancels_io_and_does_not_launch_the_entire_catalog() {
        http::block_on(async {
            let slow = Fixture::start(Duration::from_secs(3), 206).await;
            let sandbox = sandbox(&[slow.url.as_str(); 10]);
            let proxy = &sandbox.proxy;
            let started = Instant::now();
            proxy
                .verify_candidates((0..10).collect(), Some(2), 4, Duration::from_millis(150))
                .await;
            assert!(started.elapsed() < Duration::from_millis(800));
            assert_eq!(slow.requests.lock().unwrap().len(), 4);
            assert_eq!(proxy.health.healthy_count(), 0);
            assert!(
                proxy
                    .probes
                    .state
                    .lock()
                    .unwrap()
                    .entries
                    .iter()
                    .all(|entry| entry.failures == 0),
                "总期限取消不能累计失败"
            );
            // 未派发的项始终保留为 Unknown；没有按清单长度放大等待期限。
            for (_, health) in proxy.health.snapshot().into_iter().skip(4) {
                assert_eq!(health, crate::health::Health::Unknown);
            }
        });
    }

    #[test]
    fn full_pool_reuses_downloads_rotates_discovery_and_backs_off_failures() {
        http::block_on(async {
            let bad = Fixture::start(Duration::ZERO, 503).await;
            let sandbox = sandbox(&[bad.url.as_str(); 12]);
            let proxy = &sandbox.proxy;
            for i in 0..8 {
                proxy.health.seed_speed(i, 100.0);
            }
            let (candidates, target) = proxy.maintenance_candidates();
            assert_eq!(
                candidates,
                vec![8, 9],
                "只探索两项，已有近期成功的八项不重复测速"
            );
            proxy
                .verify_candidates(candidates, target, 2, Duration::from_secs(1))
                .await;
            assert!(
                proxy.maintenance_candidates().0.is_empty(),
                "不能每五秒都探索或重试失败项"
            );
            proxy.probes.state.lock().unwrap().next_explore = Instant::now();
            assert_eq!(
                proxy.maintenance_candidates().0,
                vec![10, 11],
                "下一轮继续向后探索"
            );
            proxy.probes.completed(8, false, Duration::from_secs(300));
            let state = proxy.probes.state.lock().unwrap();
            assert_eq!(state.entries[8].failures, 2);
            assert!(state.entries[8].next.duration_since(Instant::now()) > Duration::from_secs(55));
        });
    }

    #[test]
    fn missing_host_support_expands_beyond_pool_even_with_routine_checks_disabled() {
        let mut sandbox = sandbox(&["http://127.0.0.1:9"; 10]);
        let proxy = Arc::get_mut(&mut sandbox.proxy).unwrap();
        let app = Arc::get_mut(&mut proxy.app).unwrap();
        app.health_enabled = false;
        // caps 由配置私有持有，使用已学到的不支持证据模拟特定目标的缺口。
        for i in 0..8 {
            proxy.health.seed_speed(i, 100.0);
            proxy.learned.note_unsupported(i, "codeload.github.com");
            proxy.learned.note_unsupported(i, "codeload.github.com");
        }
        assert!(proxy.maintenance_candidates().0.is_empty());
        proxy.probes.request("codeload.github.com");
        assert_eq!(proxy.maintenance_candidates().0, vec![8, 9]);
        proxy.health.seed_speed(8, 100.0);
        assert!(
            proxy.maintenance_candidates().0.is_empty(),
            "应急恢复成功后不能重新开启已关闭的例行巡检"
        );
    }

    fn sample(response: Vec<u8>) -> Option<f64> {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(&response);
        });
        let result = probe_speed(
            &http_accel(port),
            Duration::from_secs(2),
            "https://example.com/x.bin",
        );
        server.join().unwrap();
        result
    }

    fn http_accel(port: u16) -> rewrite::Accel {
        rewrite::Accel {
            scheme: rewrite::Scheme::Http,
            host: "127.0.0.1".into(),
            port,
            prefix: String::new(),
        }
    }

    #[test]
    fn probe_accepts_any_http_response_including_404() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        });

        assert!(probe(&http_accel(port), Duration::from_secs(2)));
        server.join().unwrap();
    }

    /// 端口"没人监听"时探测必须返回 false。
    ///
    /// **不能用 `bind(0)` 取端口再释放**：`0` 由系统从临时端口范围（Windows 上是
    /// 49152–65535）分配，而同一个测试进程里其它并行用例也会 `bind(0)`，
    /// 于是刚释放的端口可能立刻被另一个用例的监听占上，探测就变成"连得上"。
    /// 实测撞到过这一条（本仓库自己新增的测速用例把窗口放大了）。
    /// 所以改用临时端口范围以下的固定端口：先确认它此刻空闲，再探测。
    #[test]
    fn probe_returns_false_for_closed_port() {
        use std::net::TcpListener;
        let port = (12_345u16..12_355)
            .find(|candidate| TcpListener::bind(("127.0.0.1", *candidate)).is_ok())
            .expect("12345–12354 应当至少有一个空闲端口");
        assert!(!probe(&http_accel(port), Duration::from_millis(200)));
    }

    #[test]
    fn probe_respects_timeout() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(1000));
        });

        let started = std::time::Instant::now();
        assert!(!probe(&http_accel(port), Duration::from_millis(50)));
        assert!(started.elapsed() < Duration::from_millis(900));
        server.join().unwrap();
    }
    #[test]
    fn splits_https_asset_into_host_and_path() {
        let (host, path) = split_asset("https://github.com/a/b.zip?x=1").unwrap();
        assert_eq!(host, "github.com");
        assert_eq!(path, "/a/b.zip?x=1");
        // 只接受 https：否则会把 http 资产拼成 https://host/... 的错误路径
        assert!(split_asset("http://github.com/a").is_none());
        assert!(split_asset("https://github.com").is_none());
        assert!(split_asset("https://github.com:0/a").is_none());
        assert!(split_asset("https://user@github.com/a").is_none());
        assert!(split_asset("not-a-url").is_none());
    }

    #[test]
    fn probe_rejects_oversized_payload() {
        for head in ["Content-Length: 65537", "Transfer-Encoding: chunked", ""] {
            let body = "x".repeat(PROBE_BYTES as usize + 1);
            let response = if head.starts_with("Transfer") {
                format!(
                    "HTTP/1.1 206 Partial Content\r\n{head}\r\n\r\n10001\r\n{body}\r\n0\r\n\r\n"
                )
            } else if head.is_empty() {
                format!("HTTP/1.1 206 Partial Content\r\n\r\n{body}")
            } else {
                format!("HTTP/1.1 206 Partial Content\r\n{head}\r\n\r\n{body}")
            };
            assert!(sample(response.into_bytes()).is_none());
        }
    }

    #[test]
    fn probe_accepts_full_samples_with_each_body_framing() {
        for framing in ["Content-Length: 65536", "Transfer-Encoding: chunked", ""] {
            let body = "x".repeat(PROBE_BYTES as usize);
            let response = if framing.starts_with("Transfer") {
                format!("HTTP/1.1 206 Partial Content\r\n{framing}\r\n\r\n10000;ext=sample\r\n{body}\r\n0\r\nX-Tag: sample\r\n\r\n")
            } else if framing.is_empty() {
                format!("HTTP/1.1 206 Partial Content\r\n\r\n{body}")
            } else {
                format!("HTTP/1.1 206 Partial Content\r\n{framing}\r\n\r\n{body}")
            };
            assert!(sample(response.into_bytes()).is_some(), "{framing}");
        }
    }

    #[test]
    fn probe_does_not_count_chunk_metadata_as_downloaded_data() {
        let response = format!("HTTP/1.1 206 Partial Content\r\nTransfer-Encoding: chunked\r\n\r\n1;{}\r\nx\r\n0\r\nX-Tag: sample\r\n\r\n", "p".repeat(PROBE_BYTES as usize / 2 - 16));
        assert!(sample(response.into_bytes()).is_none());
    }

    #[test]
    fn probe_speed_budget_is_not_reset_by_incoming_data() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let _ =
                stream.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 65536\r\n\r\n");
            for _ in 0..8 {
                if stream.write_all(&[b'x'; 8192]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(80));
            }
        });
        let got = probe_speed(
            &http_accel(port),
            Duration::from_millis(300),
            "https://example.com/x.bin",
        );
        server.join().unwrap();
        assert!(got.is_none(), "持续有数据也不能重置整次探测的时间预算");
    }

    /// 读超时必须由 `timeout` 决定，不能被 `IO_TIMEOUT`（60 s）放大。
    ///
    /// 历史事故：`probe_speed` 只把 timeout 用于连接，读沿用 60 s，
    /// 结果"能连上但不响应"的候选把启动拖到 60.4 秒（手工实测）。
    #[test]
    fn probe_speed_uses_given_timeout_for_reads() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf);
            // 收下请求但永不响应
            std::thread::sleep(Duration::from_secs(3));
            let _ = stream.write_all(b"");
        });

        let started = std::time::Instant::now();
        let got = probe_speed(
            &http_accel(port),
            Duration::from_millis(200),
            "https://example.com/x.bin",
        );
        assert!(got.is_none(), "卡住的上游不该给出速度");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "读超时未生效，实际耗时 {:?}",
            started.elapsed()
        );
        server.join().unwrap();
    }
}
