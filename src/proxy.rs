//! 监听、CONNECT 分流、隧道与 MITM 改写。
//!
//! 分流规则（ADR-014 约束 2）：只有 `rewrite_hosts`（含配置中的 `mitmExtra`）会被终止 TLS，
//! 其余 host 一律原样隧道——我们不解析、不记录、不改写那些流量。

use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use hyper::body::Incoming;
use hyper::{Request, Response};

use crate::ca::CertAuthority;
use crate::config::App;
use crate::health::Tracker;
use crate::http;
use crate::log::{Level, Logger};
use crate::rewrite;
use crate::stats::Stats;

mod local;
mod network;
mod probe;

pub use probe::{probe, DEFAULT_PROBE_ASSET};
pub(crate) use probe::{probe_speed, split_asset};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
use crate::http::IO_TIMEOUT;
/// 建连后等**首个请求头**的期限。
///
/// 比 `IO_TIMEOUT` 短得多：连接在发出任何请求之前就占着一个并发名额（总共 64 个）。
/// 浏览器开一批 `*.github.com` 标签页时容易攒出几十条空闲连接，
/// 让它们各自占 60 秒，winget 的下载就可能被 503 挡掉。
/// 正文使用独立的 `IO_TIMEOUT`，持续有数据的大文件不会受首包期限影响。
const FIRST_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// 同时处理的连接上限，限制下载和 TLS 会话占用。
const MAX_CONNECTIONS: usize = 64;
/// 隧道最多占多少个名额（留一部分给下载）。
///
/// 隧道来自 `*.github.com` 这类子域：浏览器开着若干 GitHub 标签页时，每条连接
/// 都可能长期占着名额。实测过：64 条隧道把名额占满后，winget 的下载 CONNECT
/// 直接拿到 503（`CONNECT tunnel failed, response 503`）——用户会看到"装了反而下载不了"。
/// 下载是本工具存在的唯一理由，隧道只是"顺手不挡路"，所以给它设上限：
/// 超出的隧道被拒绝（回 503 并在日志里说明），名额优先留给 MITM。
///
/// **由 [`MAX_CONNECTIONS`] 推导**，不是独立硬编码：早先它是单独写的 48，
/// 若有人把 `MAX_CONNECTIONS` 改成 32，隧道上限反而大于总数——编译器不会报，
/// 运行时也没有意义。下面两条断言把这个关系钉死在编译期。
const MAX_TUNNELS: usize = MAX_CONNECTIONS / 4 * 3;
const _: () = assert!(
    MAX_TUNNELS < MAX_CONNECTIONS,
    "隧道上限必须小于总名额，否则「把名额留给下载」就不成立"
);
const _: () = assert!(
    MAX_CONNECTIONS - MAX_TUNNELS >= 8,
    "至少要给下载留 8 个名额，否则并发分片会被饿死"
);
/// 同一文件的候选绑定有效期。winget 下载一个包通常几十秒到几分钟。
const PIN_TTL: Duration = Duration::from_secs(600);
/// 绑定表最多记多少个文件。
///
/// 键是 `host + 请求路径`，每个文件一条；过期项在每次写入前清理。
/// 达到上限后**不再新增绑定**（功能仍正确，只是同文件的分片可能散到不同候选），
/// 并在首次饱和时打一条 `PIN-FULL`。
const MAX_PINS: usize = 512;

/// Max candidates attempted per request; also bounded by MAX_FAILOVER_TIME.
///
/// Five attempts plus a 20s budget balances success rate and worst-case latency.
const MAX_ACCEL_RETRIES: usize = 5;
/// Total failover budget for one client request.
const MAX_FAILOVER_TIME: Duration = Duration::from_secs(20);
/// Keep a failed candidate out of rotation for this long.
const FAILURE_COOLDOWN: Duration = Duration::from_secs(30);
/// Initial winget Range probe is fatal if the proxy returns 502 to the client.
const INITIAL_PROBE_TIME: Duration = Duration::from_secs(15);
/// A single initial-probe candidate attempt must not consume the whole budget.
const INITIAL_PROBE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
/// 失败冷却，分两个作用域。
///
/// 为什么要分：`429`/`503`/连接失败是**服务级**问题（整个候选都不用试），
/// 而 `403`/`404` 往往是**host 级**的（某加速器不服务 codeload，但服务 github.com 没问题）。
/// 早先只有"按候选"一种冷却，于是一个 host 上的 403 会让该候选在 30 秒内
/// 连别的 host 也不可用——同时进行的另一个 host 的下载被无辜牵连。
#[derive(Default)]
struct Cooldowns {
    inner: std::sync::Mutex<CooldownState>,
}

#[derive(Default)]
struct CooldownState {
    /// 服务级：`idx -> 到期时刻`。
    service: std::collections::HashMap<usize, std::time::Instant>,
    /// host 级：`(idx, host) -> 到期时刻`。
    host: std::collections::HashMap<(usize, String), std::time::Instant>,
}

impl Cooldowns {
    /// 服务级冷却：整个候选都先别用（限流、5xx、连不上）。
    fn block_service(&self, idx: usize, duration: Duration) {
        let mut state = self.inner.lock().expect("cooldown lock poisoned");
        state
            .service
            .insert(idx, std::time::Instant::now() + duration);
    }

    /// host 级冷却：只有这个 host 先别用（403/404，通常意味着该候选不支持它）。
    fn block_host(&self, idx: usize, host: &str, duration: Duration) {
        let mut state = self.inner.lock().expect("cooldown lock poisoned");
        state.host.insert(
            (idx, host.to_ascii_lowercase()),
            std::time::Instant::now() + duration,
        );
    }

    fn is_service_blocked(&self, idx: usize) -> bool {
        let now = std::time::Instant::now();
        let state = self.inner.lock().expect("cooldown lock poisoned");
        state
            .service
            .get(&idx)
            .is_some_and(|expires| *expires > now)
    }

    fn is_host_blocked(&self, idx: usize, host: &str) -> bool {
        let now = std::time::Instant::now();
        let key = (idx, host.to_ascii_lowercase());
        let state = self.inner.lock().expect("cooldown lock poisoned");
        state.host.get(&key).is_some_and(|expires| *expires > now)
    }

    /// 该候选能不能用于这个 host（两个作用域都要看）。
    fn is_blocked_for(&self, idx: usize, host: &str) -> bool {
        self.is_service_blocked(idx) || self.is_host_blocked(idx, host)
    }

    /// 仍在服务级冷却中的候选（用于把候选从随机候选池里整体排除）。
    fn service_blocked(&self) -> Vec<usize> {
        let now = std::time::Instant::now();
        let mut state = self.inner.lock().expect("cooldown lock poisoned");
        state.service.retain(|_, exp| *exp > now);
        state.host.retain(|_, exp| *exp > now);
        state.service.keys().copied().collect()
    }

    /// 某候选在某 host 上成功了：只解除这一对（成功过别的 host 不代表这个 host 也行），
    /// 同时解除它的服务级冷却——能正常服务就说明服务本身没坏。
    fn clear_for(&self, idx: usize, host: &str) {
        let mut state = self.inner.lock().expect("cooldown lock poisoned");
        state.service.remove(&idx);
        state.host.remove(&(idx, host.to_ascii_lowercase()));
    }
}

/// 冷却作用域：失败影响的是整个候选，还是只影响某个 host。
#[derive(Clone, Copy)]
enum CooldownScope<'a> {
    /// 限流、5xx、连不上——问题在服务本身。
    Service,
    /// 403/404——往往只是该候选不服务这个 host。
    Host(&'a str),
}

impl CooldownScope<'_> {
    fn label(&self) -> &'static str {
        match self {
            CooldownScope::Service => "service",
            CooldownScope::Host(_) => "host",
        }
    }

    /// 这次失败要不要计入候选的**全局**健康计数？
    ///
    /// 只有服务级失败算：`429/5xx/连不上`说明"这个候选现在不行"，
    /// 而某个 host 上的 403/404 说明的是"它不服务这个 host"，别的 host 上它可能好好的。
    /// 让 host 级失败把候选判成整体不健康，等于在健康状态上又犯一次"按候选一刀切"。
    fn affects_health(&self) -> bool {
        matches!(self, CooldownScope::Service)
    }
}

/// 槽位跨 CONNECT 升级共享，直到 TLS/隧道任务结束才归还。
struct ActiveSlot(Arc<Proxy>);

/// 隧道连接的计数守卫（`Proxy::tunnels` 的 RAII 包装）。
///
/// 建连失败、升级失败和搬运结束都会通过 Drop 归还名额。
struct TunnelSlot(Arc<Proxy>);

impl Drop for TunnelSlot {
    fn drop(&mut self) {
        self.0.tunnels.fetch_sub(1, Ordering::Relaxed);
    }
}
impl Drop for ActiveSlot {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct Proxy {
    pub app: Arc<App>,
    pub ca: Arc<CertAuthority>,
    pub stats: Arc<Stats>,
    pub log: Arc<Logger>,
    pub health: Arc<Tracker>,
    pub routing: Arc<crate::routing::Router>,
    /// 同一文件的候选绑定：键 = host + path，值 = (候选索引, 过期时刻)。
    pins: std::sync::Mutex<std::collections::HashMap<String, (usize, std::time::Instant)>>,
    /// 绑定表是否已饱和到 [`MAX_PINS`]；只用来让 `PIN-FULL` 告警**只打一次**。
    pins_saturated: AtomicBool,
    /// 上一次观测到的"全挂"状态，用来只在**状态翻转**时报警，避免每请求刷日志。
    down: AtomicBool,
    /// 当前在处理中的连接数（含隧道与 MITM），从 accept 开始计数。
    active: std::sync::atomic::AtomicUsize,
    /// 当前**隧道**连接数（是 `active` 的子集），用于把名额优先留给下载。
    tunnels: std::sync::atomic::AtomicUsize,
    /// Candidate failure cooldowns: index -> unblock instant.
    cooldowns: Cooldowns,
    /// 进程启动时刻，`/health` 用它算 `uptimeSeconds`。
    started: std::time::Instant,
    /// 运行期学到的"某候选对某 host 不可用"（见 `learned` 模块的文件头说明）。
    learned: crate::learned::LearnedCaps,
    probes: probe::Scheduler,
}

impl Proxy {
    pub fn new(
        app: Arc<App>,
        ca: Arc<CertAuthority>,
        stats: Arc<Stats>,
        log: Arc<Logger>,
        health: Arc<Tracker>,
    ) -> Self {
        Self {
            routing: Arc::new(crate::routing::Router::new(&app)),
            probes: probe::Scheduler::new(app.accels.len()),
            app,
            ca,
            stats,
            log,
            health,
            down: AtomicBool::new(false),
            active: std::sync::atomic::AtomicUsize::new(0),
            tunnels: std::sync::atomic::AtomicUsize::new(0),
            cooldowns: Cooldowns::default(),
            pins: std::sync::Mutex::new(std::collections::HashMap::new()),
            pins_saturated: AtomicBool::new(false),
            started: std::time::Instant::now(),
            learned: crate::learned::LearnedCaps::new(),
        }
    }

    pub fn bind(app: &App) -> Result<TcpListener> {
        TcpListener::bind(app.listen).map_err(|err| {
            let port = app.listen.port();
            let owner = match port_owner(app.listen) {
                Some(who) => format!("，占用者 {who}"),
                None => format!("，未能确定占用进程（可用 `netstat -ano | findstr :{port}` 查看）"),
            };
            anyhow!("端口被占用或不可用: {}{owner}（{err}）", app.listen)
        })
    }

    /// Select candidates before exposing response headers; never retry a streamed body.
    async fn download(
        self: Arc<Self>,
        mut req: Request<Incoming>,
        host: &str,
        port: u16,
    ) -> Response<http::BoxBody> {
        use http_body_util::BodyExt;
        let target = req
            .uri()
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_string();
        if req.headers().contains_key("transfer-encoding")
            || req
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|n| n > 0)
        {
            Stats::bump(&self.stats.errors);
            self.log.warn(&format!(
                "REQ-BODY-UNSUPPORTED host={host} method={} 返回 501",
                req.method()
            ));
            // Do not poll an Expect: 100-continue body just to reject it.
            if !req.headers().contains_key("expect") {
                let _ = tokio::time::timeout(
                    Duration::from_millis(300),
                    http_body_util::Limited::new(req.body_mut(), 64 * 1024).collect(),
                )
                .await;
            }
            return http::response(501, "text/plain", "");
        }
        if !rewrite::needs_rewrite(host, &target)
            || !self
                .app
                .rewrite_hosts
                .iter()
                .any(|h| h.eq_ignore_ascii_case(host))
        {
            let plan =
                rewrite::origin_plan(req.method().as_str(), host, port, &target, req.headers());
            return self.forward_original(plan).await;
        }
        let expect_partial = req.headers().contains_key("range");
        let initial_probe = is_initial_probe(&req);
        let retryable = matches!(req.method().as_str(), "GET" | "HEAD");
        let failover_limit = if initial_probe {
            usize::MAX
        } else {
            self.max_retries()
        };
        let failover_time = if initial_probe {
            INITIAL_PROBE_TIME
        } else {
            MAX_FAILOVER_TIME
        };
        let started = std::time::Instant::now();
        let attempt_timeout = if initial_probe {
            INITIAL_PROBE_ATTEMPT_TIMEOUT
        } else {
            failover_time
        };
        let mut tried = Vec::new();
        let mut last_status: Option<u16> = None;
        if initial_probe {
            self.log
                .info(&format!("INITIAL-PROBE host={host} range=bytes=0-1"));
        }
        loop {
            if !tried.is_empty() && started.elapsed() >= failover_time {
                self.log.warn(&format!(
                    "FAILOVER-TIMEOUT host={host} tried={}",
                    tried.len()
                ));
                return http::response(502, "text/plain", "");
            }
            let Some((idx, accel, from_pin)) = self.pick_for(host, &target, &tried) else {
                Stats::bump(&self.stats.errors);
                self.log
                    .warn(&format!("NO-VERIFIED-ACCEL {host} tried={}", tried.len()));
                return http::response(
                    last_status.filter(|s| *s >= 400).unwrap_or(502),
                    "text/plain",
                    "",
                );
            };
            let plan = rewrite::plan_with(
                req.method().as_str(),
                host,
                port,
                &target,
                req.headers(),
                &self.app.rewrite_hosts,
                &accel,
                rewrite::needs_rewrite(host, &target),
            );
            let allow_retry = retryable && plan.rewritten && tried.len() + 1 < failover_limit;
            let attempt_started = std::time::Instant::now();
            let outcome = match http::request(&plan.method, &plan.path, plan.headers.clone()) {
                Ok(request) => {
                    match remaining_attempt_budget(
                        started.elapsed(),
                        failover_time,
                        attempt_timeout,
                    ) {
                        Some(budget) => {
                            http::send(plan.scheme, &plan.host, plan.port, request, budget).await
                        }
                        None => Err(anyhow!("failover total deadline exceeded")),
                    }
                }
                Err(error) => Err(error),
            };
            match outcome {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let bad_range =
                        status == 206 && !range_response_matches(req.headers(), response.headers());
                    // Even an empty gzip needs an 18-byte header/trailer; GitHub
                    // source archives cannot be a two-byte service "ok" page.
                    // Restrict this to full archive responses: tiny ranges and
                    // text release assets are legitimate.
                    let bad_archive = status == 200
                        && archive_response_is_invalid(host, req.uri().path(), response.headers());
                    if bad_range {
                        self.log.warn(&format!(
                            "ACCEL-BAD-RANGE {} 响应范围与请求不一致",
                            accel.host
                        ));
                    }
                    if bad_archive {
                        self.log.warn(&format!(
                            "ACCEL-BAD-ARCHIVE {} 归档响应长度不足",
                            accel.host
                        ));
                    }
                    if bad_range
                        || bad_archive
                        || (expect_partial && status == 200)
                        || http::is_rate_limited(status)
                        || is_retryable_status(status)
                    {
                        Stats::bump(&self.stats.errors);
                        if http::is_rate_limited(status) {
                            self.health.mark(idx, false);
                            self.cooldowns.block_service(idx, FAILURE_COOLDOWN);
                            Stats::bump(&self.stats.ratelimited);
                            self.log.warn(&format!(
                                "ACCEL-COOLDOWN {} rate limited {status}",
                                accel.host
                            ));
                        } else {
                            self.note_accel_failure(
                                idx,
                                &accel,
                                &format!("upstream status {status}"),
                                if bad_archive {
                                    CooldownScope::Host(host)
                                } else {
                                    failure_scope(status, host)
                                },
                            );
                            if matches!(status, 403 | 404)
                                && plan.rewritten
                                && self.learned.note_unsupported(idx, host)
                            {
                                self.log.warn(&format!(
                                    "CAPS-LEARNED host={host} via={} status={status}",
                                    accel.host
                                ));
                            }
                        }
                        self.log.warn(&format!(
                            "ACCEL-BAD-STATUS {} 返回 {status}，换下一个候选重试",
                            accel.host
                        ));
                        last_status = Some(status);
                        tried.push(idx);
                        if initial_probe {
                            self.log.warn(&format!(
                                "INITIAL-PROBE-RETRY via={} status={status} tried={}",
                                accel.host,
                                tried.len()
                            ));
                        }
                        if !allow_retry {
                            return http::response(
                                if status >= 400 { status } else { 502 },
                                "text/plain",
                                "",
                            );
                        }
                        continue;
                    }
                    let host = host.to_owned();
                    let proxy = self.clone();
                    return http::observe(response, move |result| {
                        let size = match result {
                            Ok(size) => size,
                            Err(err) => {
                                Stats::bump(&proxy.stats.errors);
                                if plan.rewritten {
                                    proxy.unpin(&host, &target);
                                    // A cancelled response is usually the client
                                    // going away and must not punish the candidate.
                                    // Timeout and early EOF mean the upstream body
                                    // failed after headers were sent. We cannot
                                    // fail over after that point, but we can keep
                                    // the same candidate out of the next request.
                                    if matches!(io_error_kind(&err), "timeout" | "early-eof") {
                                        proxy.note_accel_failure(
                                            idx,
                                            &accel,
                                            &format!("relay {}: {err:#}", io_error_kind(&err)),
                                            CooldownScope::Service,
                                        );
                                    }
                                }
                                proxy.log.warn(&format!(
                                    "RELAY-ERR host={host} via={} kind={} retry={} elapsed={:.2}s pin_cleared={} path={} err={err:#}",
                                    accel.host, io_error_kind(&err), tried.len(), started.elapsed().as_secs_f64(),
                                    plan.rewritten, crate::log::loggable(&plan.path, 100)));
                                return;
                            }
                        };
                        if initial_probe {
                            proxy.log.info(&format!(
                                "INITIAL-PROBE-OK via={} status={status} size={size} tried={}",
                                accel.host,
                                tried.len()
                            ));
                        }
                        if plan.rewritten {
                            Stats::bump(&proxy.stats.rewrites);
                            if (200..300).contains(&status) {
                                proxy.cooldowns.clear_for(idx, &host);
                                proxy.health.record_success(idx);
                                proxy.health.record_sample(
                                    idx,
                                    size,
                                    attempt_started.elapsed().as_secs_f64(),
                                );
                                proxy.pin(&host, &target, idx);
                                proxy.learned.note_success(idx, &host);
                                proxy.report_health_state();
                            }
                        }
                        Stats::add(&proxy.stats.bytes, size);
                        let tag = if plan.rewritten { "REWRITE" } else { "PASS" };
                        let via = if plan.rewritten {
                            accel.host.as_str()
                        } else {
                            "-"
                        };
                        let pin = if from_pin { "bind" } else { "pick" };
                        proxy.log.info(&format!(
                            "{tag} via={via} {pin} retry={} {} -> {status} {size}B {:.2}s",
                            tried.len(),
                            crate::log::loggable(&plan.path, 76),
                            started.elapsed().as_secs_f64()
                        ));
                        if plan.rewritten && !(200..300).contains(&status) {
                            proxy.log.warn(&format!("REWRITE-FAILED via={via} status={status} size={size}B tried={tried:?} {}", crate::log::loggable(&plan.path, 100)));
                        }
                    });
                }
                Err(err) => {
                    Stats::bump(&self.stats.errors);
                    self.log.warn(&format!(
                        "UPSTREAM-FAIL {host} -> {}:{} {err:#}",
                        plan.host, plan.port
                    ));
                    if plan.rewritten {
                        self.note_accel_failure(
                            idx,
                            &accel,
                            &format!("{err:#}"),
                            CooldownScope::Service,
                        );
                    }
                    tried.push(idx);
                    if !allow_retry {
                        return http::response(502, "text/plain", "");
                    }
                    self.log.warn(&format!("RETRY {host} 换下一个候选"));
                }
            }
        }
    }

    /// 复用同一 HTTP/TLS 传输，原站状态与正文原样返回，不触发加速器冷却或学习。
    async fn forward_original(self: Arc<Self>, plan: rewrite::Plan) -> Response<http::BoxBody> {
        let started = std::time::Instant::now();
        let outcome = match http::request(&plan.method, &plan.path, plan.headers.clone()) {
            Ok(request) => {
                http::send(
                    plan.scheme,
                    &plan.host,
                    plan.port,
                    request,
                    MAX_FAILOVER_TIME,
                )
                .await
            }
            Err(error) => Err(error),
        };
        match outcome {
            Ok(response) => {
                let status = response.status();
                http::observe(response, move |result| match result {
                    Ok(size) => {
                        Stats::add(&self.stats.bytes, size);
                        self.log.info(&format!(
                            "PASS via=- {} -> {status} {size}B {:.2}s",
                            crate::log::loggable(&plan.path, 76),
                            started.elapsed().as_secs_f64()
                        ));
                    }
                    Err(error) => {
                        Stats::bump(&self.stats.errors);
                        self.log
                            .warn(&format!("RELAY-ERR host={} via=- err={error:#}", plan.host));
                    }
                })
            }
            Err(error) => {
                Stats::bump(&self.stats.errors);
                self.log.warn(&format!(
                    "UPSTREAM-FAIL {}:{} {error:#}",
                    plan.host, plan.port
                ));
                http::response(502, "text/plain", "")
            }
        }
    }

    /// 同一个文件（同 host + 同 path）固定用同一个候选。
    ///
    /// 代理看不到"文件"，只能看到请求；winget 对一个包发的多个 Range 分片
    /// 除了 Range 头以外完全相同，所以用 host + target 作键。
    /// 这样做有两个好处：同一批并发分片不会散到多个服务（避免同时施压），
    /// 且分片速度一致不会拖慢整体。
    ///
    /// **键里丢掉 query**：带签名的 URL（GitHub 资产会 302 到
    /// `release-assets.githubusercontent.com/…?sp=r&…&se=…&sig=…`）的 query 里有时间戳，
    /// 签名一换 key 就变，同一个文件会被当成两个文件、pin 白丢；而且几百字节的 query
    /// 直接进 key 也会把绑定表撑大。query 只影响"上游认不认这次请求"，不影响"这是哪个文件"。
    fn pin_key(host: &str, target: &str) -> String {
        let path = target.split_once('?').map_or(target, |(p, _)| p);
        format!("{host}{path}")
    }

    fn pin(&self, host: &str, target: &str, idx: usize) {
        let key = Self::pin_key(host, target);
        let mut pins = self.pins.lock().expect("pin 锁中毒");
        // 顺手清理过期项，避免长期占内存
        let now = std::time::Instant::now();
        pins.retain(|_, (_, exp)| *exp > now);
        if pins.len() >= MAX_PINS {
            // 表满时**不再 pin**：分片可能散到不同候选上（速度参差），
            // 但功能仍正确（内容由 winget 的哈希兜底）。这里必须出声一次——
            // 早先是静默丢弃，"pin 为什么没生效"没有任何线索。
            // 只在首次饱和时告警，避免每个请求刷一行。
            if !self.pins_saturated.swap(true, Ordering::Relaxed) {
                self.log.warn(&format!(
                    "PIN-FULL 绑定表已达上限 {MAX_PINS} 个文件，后续文件不再固定候选；\
                     同文件的多个分片可能落到不同加速器（不影响正确性，只影响速度一致性）"
                ));
            }
            return;
        }
        self.pins_saturated.store(false, Ordering::Relaxed);
        pins.insert(key, (idx, now + PIN_TTL));
    }

    /// 上游中途失败后解除该文件的 pin，避免之后的 Range 分片继续钉在坏候选。
    fn unpin(&self, host: &str, target: &str) {
        let key = Self::pin_key(host, target);
        let mut pins = self.pins.lock().expect("pin 锁中毒");
        pins.remove(&key);
    }
    fn usable_for(&self, idx: usize, host: &str) -> bool {
        self.app.accel_supports(idx, host)
            && !self.learned.is_blocked(idx, host)
            && !self.cooldowns.is_blocked_for(idx, host)
    }

    /// 选候选：优先复用同一文件的 pin，否则加权随机。
    fn pick_for(
        &self,
        host: &str,
        target: &str,
        tried: &[usize],
    ) -> Option<(usize, crate::rewrite::Accel, bool)> {
        let key = Self::pin_key(host, target);
        let mut excluded = tried.to_vec();
        excluded.extend(self.cooldowns.service_blocked());
        // 命中即续期：pin 的语义是"正在用的那个候选"，不是"上次成功收尾后的 10 分钟"。
        // 只在成功收尾时续期的话，一个跑超过 PIN_TTL 的大分片中途就会失去绑定。
        // 先读取 pin，再在锁外检查健康/冷却，最后用候选下标校验并续期。
        // 这样不会形成 pins -> cooldowns -> health，而选择器走的是
        // health -> cooldowns 的锁顺序。
        let pinned = {
            let now = std::time::Instant::now();
            let idx = {
                let pins = self.pins.lock().expect("pin 锁中毒");
                peek_pin(&pins, &key, now)
            };
            idx.filter(|idx| {
                !excluded.contains(idx)
                    && self.health.is_healthy(*idx)
                    && self.app.accel_supports(*idx, host)
                    && !self.learned.is_blocked(*idx, host)
                    && !self.cooldowns.is_blocked_for(*idx, host)
            })
            .filter(|idx| {
                let mut pins = self.pins.lock().expect("pin 锁中毒");
                refresh_pin(&mut pins, &key, *idx, now, PIN_TTL)
            })
        };
        if let Some(idx) = pinned {
            if let Some(accel) = self.health.accel_at(idx) {
                return Some((idx, accel, true));
            }
        }
        // 能力矩阵：只从"声明支持该 host"的健康候选里选（design.md §7）；
        // 再叠一层：host 级冷却（该候选在这个 host 上刚失败过）与运行期学到的限制
        let picked = self.health.pick_verified_excluding_where(&excluded, |idx| {
            self.app.accel_supports(idx, host)
                && !self.learned.is_blocked(idx, host)
                // `service_blocked()` above is only a snapshot. A concurrent
                // request can add a service cooldown before this predicate runs.
                && !self.cooldowns.is_service_blocked(idx)
                && !self.cooldowns.is_host_blocked(idx, host)
        });
        // 这段是 debug 诊断：43 个候选时每次选候选都要拼 43 段字符串。
        // 默认日志级别是 info，不先判级别就是纯浪费（每个请求一次）。
        if let Some((idx, a)) = &picked {
            if self.log.enabled(Level::Debug) {
                let weights: Vec<String> = self
                    .health
                    .speed_snapshot()
                    .iter()
                    .map(|(h, kbps, n)| format!("{h}={:.0}KB/s/{}", kbps, n))
                    .collect();
                self.log.log(
                    Level::Debug,
                    &format!("PICK idx={idx} host={} | {}", a.host, weights.join(" ")),
                );
            }
        }
        if picked.is_none() {
            self.probes.request(host);
        }
        picked.map(|(i, a)| (i, a, false))
    }
    /// 记一次加速器失败；跨过阈值时打一条告警（便于用户从日志判断是否被切换）。
    ///
    /// `scope` 决定冷却范围：服务级（限流/5xx/连不上）冷却整个候选；
    /// host 级（403/404）只冷却这一对，别牵连同一候选服务其它 host 的能力。
    fn note_accel_failure(
        &self,
        idx: usize,
        accel: &rewrite::Accel,
        why: &str,
        scope: CooldownScope<'_>,
    ) {
        match scope {
            CooldownScope::Service => self.cooldowns.block_service(idx, FAILURE_COOLDOWN),
            CooldownScope::Host(host) => self.cooldowns.block_host(idx, host, FAILURE_COOLDOWN),
        }
        self.log.warn(&format!(
            "ACCEL-COOLDOWN {} for {}s ({}): {why}",
            accel.host,
            FAILURE_COOLDOWN.as_secs(),
            scope.label()
        ));
        // host 级失败不计入全局健康：它只说明"这个 host 不行"（见 affects_health）
        if scope.affects_health() && self.health.record_failure(idx) {
            self.log.warn(&format!(
                "ACCEL-UNHEALTHY {} 连续失败达阈值（{why}），改用下一个候选",
                accel.host
            ));
        }
        self.probes.wake();
        self.report_health_state();
    }

    /// 全挂时**报错**，恢复时再报一次。
    ///
    /// 只在状态翻转时报：否则每个失败请求都会刷一条，日志里真正那条反而被埋掉。
    fn report_health_state(&self) {
        let down = self
            .health
            .ranked_verified_where(|idx| !self.cooldowns.is_service_blocked(idx))
            .is_empty();
        let was_down = self.down.swap(down, Ordering::Relaxed);

        if down && !was_down {
            let detail = self
                .health
                .snapshot()
                .iter()
                .map(|(host, health)| format!("{host}={}", health.as_str()))
                .collect::<Vec<_>>()
                .join(", ");
            self.log.error(&format!(
                "ALL-ACCEL-DOWN 所有加速器均不可用（{detail}）：请求会立即返回 502，后台继续重试。\
                 若候选网络本身正常，检查测速资产是否仍存在（当前 {}，可用 health.probeUrl 覆盖）",
                self.app.health_probe
            ));
        } else if !down && was_down {
            self.log.info(&format!(
                "ALL-ACCEL-RECOVERED 已有 {} 个加速器恢复可用",
                self.health.healthy_count()
            ));
        }
    }

    /// 实际重试上限：取常量与候选数中较小者（候选只有 2 个时不该允许试 3 次）。
    fn max_retries(&self) -> usize {
        MAX_ACCEL_RETRIES.min(self.health.accels().len().max(1))
    }
}

/// 取 pin 并在命中时**续期**；不满足条件时既不续期也不生效。
///
/// - 过期 → `None`
/// - 存在但该候选已不可用（被排除 / 冷却中 / 不健康 / 不支持该 host） → `None`，
///   且**不刷新**它的过期时间：一个用不了的 pin 不该靠"被反复查到"续命
/// - 命中 → 把过期时间推到 `now + ttl` 并返回候选下标
///
/// 抽成独立函数是为了能直接单测这三种情形（`Proxy` 本身依赖网络与证书，不好造）。
#[cfg(test)]
fn take_pin<F>(
    pins: &mut std::collections::HashMap<String, (usize, std::time::Instant)>,
    key: &str,
    now: std::time::Instant,
    ttl: Duration,
    accept: F,
) -> Option<usize>
where
    F: Fn(usize) -> bool,
{
    let (idx, expires) = *pins.get(key)?;
    if expires <= now || !accept(idx) {
        return None;
    }
    if let Some(entry) = pins.get_mut(key) {
        entry.1 = now + ttl;
    }
    Some(idx)
}

/// 读取未过期 pin，不在锁外保留引用。
fn peek_pin(
    pins: &std::collections::HashMap<String, (usize, std::time::Instant)>,
    key: &str,
    now: std::time::Instant,
) -> Option<usize> {
    let (idx, expires) = *pins.get(key)?;
    (expires > now).then_some(idx)
}

/// 只有 pin 仍绑定同一个候选且没有过期时才续期。
fn refresh_pin(
    pins: &mut std::collections::HashMap<String, (usize, std::time::Instant)>,
    key: &str,
    idx: usize,
    now: std::time::Instant,
    ttl: Duration,
) -> bool {
    let Some((current, expires)) = pins.get_mut(key) else {
        return false;
    };
    if *current != idx || *expires <= now {
        return false;
    }
    *expires = now + ttl;
    true
}

/// 这个状态码是否意味着"**该候选**不行，换一个可能就成"。
///
/// - `403`/`404`：加速器不代理这个 host / 路径（最常见的"没有这个能力"）
/// - `5xx`：加速器自己出错
/// - `401`：该加速器要求认证（有的服务需要 token）。这是**它**的限制，不是内容的属性
/// - `451`：被该服务因法律原因屏蔽，同样是**它**的立场
///
/// 401/451 早先不在列表里，实测表现为"试 1 次就透传"（`retry=0`）：
/// 明明换一个候选大概率能成功，却把失败直接丢给用户。
/// 重试本身是有界的（`MAX_ACCEL_RETRIES` / 20 s 预算），所以放宽不会失控。
/// 某个上游状态码失败时，冷却应该只影响这一对（候选, host），还是整个候选？
///
/// 判据是"这个失败说明了什么"：
/// - `403`/`404`：该候选**不愿/不能服务这个 host 或路径**。同一候选服务别的 host 可能完全正常，
///   所以只冷却这一对（还记进能力学习）。这是唯一一类"host 特有"的证据。
/// - 其它（`401`/`429`/`451`/`5xx`/杂项 `4xx`）：都是**服务对我的态度**——要认证、在限流、
///   被法律屏蔽、自己出故障。这些不随 host 变化，冷却整个候选更安全；
///   只冷却 host 的话，用户会继续拿一个正在出问题的候选去打别的 host。
///
/// 抽成独立函数是为了能直接单测这条映射（内联在 `if` 里就只能靠集成测试碰运气）。
fn failure_scope(status: u16, host: &str) -> CooldownScope<'_> {
    if matches!(status, 403 | 404) {
        CooldownScope::Host(host)
    } else {
        CooldownScope::Service
    }
}
fn is_retryable_status(status: u16) -> bool {
    matches!(status, 401 | 403 | 404 | 451) || status >= 500
}

/// 把中继失败的 IO 类型归成三类，写进 `RELAY-ERR` 的 `kind=` 字段。
///
/// 为什么值得区分（实测，design.md §6）：
/// - `timeout`：上游在完整消息结束前不再发数据；
/// - `early-eof`：上游提前断开，声明了 `Content-Length` 却没给够，是真的正文不完整；
/// - `other`：其它 IO 错误（连接被重置等）。
///
/// 混在一起时两种情况的日志一模一样，排障的人会把"其实成功的下载"当成失败。
fn io_error_kind(err: &anyhow::Error) -> &'static str {
    http::error_kind(err)
}

/// 查谁占用了监听端口：`netstat -ano` 找 PID，`tasklist` 找进程名。
///
/// 设计文档要求"端口被占用时立即失败并打印占用进程"——只报"端口不可用"
/// 会让用户无从下手（尤其 PAC 里端口是写死的，换端口不可行）。
/// 两个工具都是 Windows 自带组件，与项目既有的 certutil.exe 取舍一致。
fn port_owner(addr: SocketAddr) -> Option<String> {
    let out = std::process::Command::new("netstat")
        .args(["-ano", "-p", "tcp"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let pid = pid_from_netstat(&text, addr.port())?;
    let name = process_name(pid).unwrap_or_else(|| "未知进程".to_string());
    Some(format!("PID {pid}（{name}）"))
}

/// 从 `netstat -ano` 输出里找监听指定端口的 PID。
///
/// 输出形如（本地化系统上表头不同，只依赖列位置与 `LISTENING` 状态）：
/// `  TCP    127.0.0.1:8443    0.0.0.0:0    LISTENING    12345`
fn pid_from_netstat(text: &str, port: u16) -> Option<u32> {
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 5 || !cols[3].eq_ignore_ascii_case("LISTENING") {
            continue;
        }
        let local_port = cols[1]
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok());
        if local_port == Some(port) {
            if let Ok(pid) = cols[4].parse::<u32>() {
                return Some(pid);
            }
        }
    }
    None
}

/// 用 `tasklist` 把 PID 翻译成进程名；失败返回 None（调用方只打印 PID）。
fn process_name(pid: u32) -> Option<String> {
    let out = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next()?.trim();
    // 无匹配时 tasklist 返回的是本地化提示文字（不是 CSV），据此判失败
    if !first.starts_with('"') {
        return None;
    }
    // "winget-accel.exe","12345","Console","1","12,345 K"
    let name = first.trim_start_matches('"').split('"').next()?.to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn split_host_port(target: &str) -> Result<(String, u16)> {
    let authority: hyper::http::uri::Authority =
        target.parse().context("invalid CONNECT authority")?;
    let port = authority
        .port_u16()
        .context("CONNECT requires an explicit port")?;
    if port == 0 {
        bail!("CONNECT requires a non-zero port");
    }
    let host = authority.host().trim_matches(['[', ']']);
    if host.is_empty() {
        bail!("CONNECT requires a host");
    }
    Ok((host.to_ascii_lowercase(), port))
}
fn is_initial_probe(req: &Request<Incoming>) -> bool {
    req.headers()
        .get("range")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("bytes=0-1"))
}

fn remaining_attempt_budget(
    elapsed: Duration,
    total: Duration,
    per_attempt: Duration,
) -> Option<Duration> {
    total
        .checked_sub(elapsed)
        .map(|remaining| remaining.min(per_attempt))
        .filter(|d| !d.is_zero())
}

/// RFC 9110 §14：只校验显式范围与请求的一致性，消息分帧仍由 Hyper 负责。
/// 兼容部分公共服务省略 Content-Range；multipart 正文不在此解析。
fn range_response_matches(request: &hyper::HeaderMap, response: &hyper::HeaderMap) -> bool {
    let Some(content_range) = response.get("content-range") else {
        return true;
    };
    let parse = || -> Option<bool> {
        if response.get_all("content-range").iter().count() != 1 {
            return None;
        }
        let (unit, value) = content_range.to_str().ok()?.trim().split_once(' ')?;
        if !unit.eq_ignore_ascii_case("bytes") {
            return None;
        }
        let (interval, total) = value.split_once('/')?;
        let (first, last) = interval.split_once('-')?;
        let number = |s: &str| -> Option<u64> {
            if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            s.parse().ok()
        };
        let first = number(first)?;
        let last = number(last)?;
        let length = last.checked_sub(first)?.checked_add(1)?;
        let total = if total == "*" {
            None
        } else {
            Some(number(total)?)
        };
        if total.is_some_and(|total| last >= total) {
            return None;
        }
        if let Some(length_header) = response.get("content-length") {
            if number(length_header.to_str().ok()?)? != length {
                return None;
            }
        }
        let range = request.get("range")?.to_str().ok()?.trim();
        let (unit, ranges) = range.split_once('=')?;
        if !unit.eq_ignore_ascii_case("bytes") {
            return None;
        }
        Some(ranges.split(',').any(|range| {
            let Some((start, end)) = range.trim().split_once('-') else {
                return false;
            };
            if start.is_empty() {
                let Some(suffix) = number(end).filter(|n| *n > 0) else {
                    return false;
                };
                return match total {
                    Some(total) => first == total.saturating_sub(suffix) && last == total - 1,
                    None => length <= suffix,
                };
            }
            let Some(start) = number(start) else {
                return false;
            };
            if first != start {
                return false;
            }
            if end.is_empty() {
                return total.is_none_or(|total| last == total - 1);
            }
            let Some(end) = number(end).filter(|end| *end >= start) else {
                return false;
            };
            last == total.map_or(end, |total| end.min(total - 1))
        }))
    };
    parse() == Some(true)
}

/// A successful source-archive response must at least look like an archive.
///
/// Some public mirrors return a small text error page with status 200. A
/// `Content-Length` check catches the common fixed-length form, but chunked
/// error pages have no length header and would otherwise be forwarded to the
/// client as a successful archive. Header-only checks are deliberate here:
/// the response body has not been sent yet, so a bad candidate can still be
/// retried without buffering or partially forwarding the archive.
fn archive_response_is_invalid(host: &str, path: &str, headers: &hyper::HeaderMap) -> bool {
    let archive = host.eq_ignore_ascii_case("codeload.github.com")
        || (host.eq_ignore_ascii_case("github.com") && path.contains("/archive/"));
    if !archive {
        return false;
    }
    let too_short = headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length < 18);
    let text_error = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::to_ascii_lowercase)
        .is_some_and(|value| {
            value.starts_with("text/") || value.contains("html") || value.contains("json")
        });
    too_short || text_error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failover_attempts_share_one_total_budget() {
        let total = Duration::from_secs(20);
        assert_eq!(
            remaining_attempt_budget(Duration::from_secs(11), total, total),
            Some(Duration::from_secs(9))
        );
        assert_eq!(
            remaining_attempt_budget(
                Duration::from_secs(14),
                Duration::from_secs(15),
                Duration::from_secs(5)
            ),
            Some(Duration::from_secs(1))
        );
        assert_eq!(remaining_attempt_budget(total, total, total), None);
        assert_eq!(
            remaining_attempt_budget(total + Duration::from_secs(1), total, total),
            None
        );
    }

    #[test]
    fn explicit_response_ranges_must_match_requested_bytes() {
        for (requested, returned, length, valid) in [
            ("bytes=0-1", "bytes 0-1/1024", "2", true),
            ("bytes=0-1", "bytes 100-101/1024", "2", false),
            ("bytes=0-1000", "bytes 0-99/100", "100", true),
            ("bytes=50-", "bytes 50-99/100", "50", true),
            ("bytes=-10", "bytes 90-99/100", "10", true),
            ("bytes=-1000", "bytes 0-99/100", "100", true),
            ("bytes=0-1", "bytes 0-1/*", "2", true),
            ("bytes=0-1", "bytes 0-1/1", "2", false),
            ("bytes=0-1", "bytes 1-0/100", "2", false),
            ("bytes=0-1", "bytes 0-1/100", "1", false),
            ("bytes=0-1", "bytes 0-18446744073709551615/*", "0", false),
            ("bytes=0-1", "invalid", "2", false),
        ] {
            let mut request = hyper::HeaderMap::new();
            request.insert("range", requested.parse().unwrap());
            let mut response = hyper::HeaderMap::new();
            response.insert("content-range", returned.parse().unwrap());
            response.insert("content-length", length.parse().unwrap());
            assert_eq!(
                range_response_matches(&request, &response),
                valid,
                "{requested} -> {returned}"
            );
        }
        assert!(range_response_matches(
            &hyper::HeaderMap::new(),
            &hyper::HeaderMap::new()
        ));
    }

    #[test]
    fn archive_error_pages_are_rejected_even_without_content_length() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());
        assert!(archive_response_is_invalid(
            "codeload.github.com",
            "/owner/repo/tar.gz/refs/tags/v1",
            &headers
        ));

        let mut headers = hyper::HeaderMap::new();
        headers.insert("content-type", "application/gzip".parse().unwrap());
        headers.insert("content-length", "1024".parse().unwrap());
        assert!(!archive_response_is_invalid(
            "codeload.github.com",
            "/owner/repo/tar.gz/refs/tags/v1",
            &headers
        ));
        assert!(!archive_response_is_invalid(
            "github.com",
            "/owner/repo/releases/download/v1/app.zip",
            &headers
        ));
    }

    #[test]
    fn origin_refusals_preserve_body_without_penalizing_candidates() {
        use http_body_util::BodyExt;
        use std::io::{Read, Write};
        for verified in [false, true] {
            for status in [403, 429, 503] {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let port = listener.local_addr().unwrap().port();
                let server = std::thread::spawn(move || {
                    let (mut socket, _) = listener.accept().unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    while !bytes.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        socket.read_exact(&mut byte).unwrap();
                        bytes.push(byte[0]);
                    }
                    write!(socket, "HTTP/1.1 {status} Refused\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin").unwrap();
                });
                let app = Arc::new(
                    App::new(crate::config::FileConfig {
                        accelerators: vec![crate::config::AcceleratorCfg {
                            name: "test".into(),
                            template: "http://127.0.0.1:9/{url}".into(),
                            priority: 1,
                            hosts: Vec::new(),
                        }],
                        ..crate::config::FileConfig::default()
                    })
                    .unwrap(),
                );
                let health = Arc::new(Tracker::new(app.accels.clone(), app.health_failures));
                if verified {
                    health.mark(0, true);
                }
                let before = health.snapshot();
                let ca_dir = std::env::temp_dir().join(format!(
                    "wg-pass-{}-{verified}-{status}",
                    std::process::id()
                ));
                let ca = Arc::new(
                    CertAuthority::load_or_create(&ca_dir, &app.rewrite_hosts, false).unwrap(),
                );
                let log = Arc::new(Logger::new(Level::Error, ca_dir.join("test.log")));
                let proxy = Arc::new(Proxy::new(
                    app,
                    ca,
                    Arc::new(Stats::default()),
                    log,
                    health.clone(),
                ));
                // Only this local fixture uses HTTP; production origin_plan always selects HTTPS.
                let mut plan = rewrite::origin_plan(
                    "GET",
                    "127.0.0.1",
                    port,
                    "/ordinary",
                    &hyper::HeaderMap::new(),
                );
                plan.scheme = rewrite::Scheme::Http;
                let response = http::block_on(proxy.clone().forward_original(plan));
                assert_eq!(response.status().as_u16(), status);
                let body = http::block_on(response.into_body().collect())
                    .unwrap()
                    .to_bytes();
                assert_eq!(body.as_ref(), b"origin");
                assert_eq!(health.snapshot(), before);
                assert!(proxy.cooldowns.service_blocked().is_empty());
                assert!(proxy.learned.blocked_pairs().is_empty());
                assert_eq!(proxy.stats.ratelimited.load(Ordering::Relaxed), 0);
                server.join().unwrap();
                std::fs::remove_dir_all(ca_dir).unwrap();
            }
        }
    }

    #[test]
    fn splits_host_port() {
        assert_eq!(
            split_host_port("github.com:443").unwrap(),
            ("github.com".into(), 443)
        );
        assert_eq!(split_host_port("[::1]:8443").unwrap(), ("::1".into(), 8443));
    }

    #[test]
    fn rejects_targets_without_port() {
        assert!(split_host_port("github.com").is_err());
        assert!(split_host_port(":443").is_err());
        assert!(split_host_port("github.com:0").is_err());
    }
    /// 401/451 表示"**这个**候选不行"，必须换候选重试；而 `HttpStatus` 之外的
    /// 非 2xx（如 418）仍透传。
    ///
    /// 实测背景：401/451 早先不在可重试集合里，表现为"试 1 次就透传"（`retry=0`）——
    /// 明明换一个候选大概率能成功，却把失败直接丢给用户。
    #[test]
    fn auth_and_legal_blocks_are_retryable() {
        for status in [401u16, 403, 404, 451, 500, 502, 503] {
            assert!(is_retryable_status(status), "{status} 应可重试");
        }
        // 这些不该触发换候选（透传给客户端才有意义）
        for status in [200u16, 204, 206, 302, 304, 418] {
            assert!(!is_retryable_status(status), "{status} 不该当作候选故障");
        }
    }

    /// `RELAY-ERR` 的 `kind=` 必须能分开"上游不发数据了"与"正文真的不完整"。
    ///
    /// 超时和截断意味着不同的上游故障，日志必须保留这个区别。
    #[test]
    fn relay_error_kind_separates_timeout_from_truncation() {
        let blocking: anyhow::Error =
            std::io::Error::new(std::io::ErrorKind::WouldBlock, "x").into();
        assert_eq!(io_error_kind(&blocking), "timeout");
        let timed: anyhow::Error = std::io::Error::new(std::io::ErrorKind::TimedOut, "x").into();
        assert_eq!(io_error_kind(&timed), "timeout");

        let eof: anyhow::Error = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "x").into();
        assert_eq!(io_error_kind(&eof), "early-eof");

        let reset: anyhow::Error =
            std::io::Error::new(std::io::ErrorKind::ConnectionReset, "x").into();
        assert_eq!(io_error_kind(&reset), "other");
        assert_eq!(io_error_kind(&anyhow!("纯文本错误")), "other");

        // 被 anyhow 的上下文包住时，仍应认出底层的 io 错误类型
        let wrapped =
            anyhow::Error::new(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "x"))
                .context("读正文失败");
        assert_eq!(io_error_kind(&wrapped), "early-eof");
    }

    /// 服务级冷却：整个候选都被排除。
    #[test]
    fn service_cooldown_blocks_every_host() {
        let cooldowns = Cooldowns::default();
        cooldowns.block_service(3, Duration::from_secs(30));
        assert!(cooldowns.is_service_blocked(3));
        assert!(
            cooldowns.is_blocked_for(3, "github.com"),
            "服务级冷却对所有 host 生效"
        );
        assert!(cooldowns.is_blocked_for(3, "codeload.github.com"));
        assert!(cooldowns.service_blocked().contains(&3));

        cooldowns.clear_for(3, "github.com");
        assert!(
            !cooldowns.is_blocked_for(3, "codeload.github.com"),
            "成功一次即解除服务级冷却"
        );
    }

    /// host 级冷却：只影响这一对，别牵连同一候选服务其它 host。
    ///
    /// 这是本轮修的问题：早先只有按候选的冷却，于是一个 codeload 上的 403
    /// 会让该候选 30 秒内连 github.com 也不可用。
    #[test]
    fn host_cooldown_is_scoped_to_one_host() {
        let cooldowns = Cooldowns::default();
        cooldowns.block_host(5, "codeload.github.com", Duration::from_secs(30));

        assert!(cooldowns.is_host_blocked(5, "codeload.github.com"));
        assert!(
            cooldowns.is_host_blocked(5, "CodeLoad.GitHub.COM"),
            "大小写不敏感"
        );
        assert!(
            !cooldowns.is_blocked_for(5, "github.com"),
            "同一候选在别的 host 上必须仍然可用"
        );
        assert!(
            !cooldowns.service_blocked().contains(&5),
            "host 级冷却不该把候选从随机池里整体剔除"
        );

        // 只有"在那个 host 上成功"才解除；在别的 host 上成功不该解除它
        cooldowns.clear_for(5, "github.com");
        assert!(
            cooldowns.is_host_blocked(5, "codeload.github.com"),
            "别的 host 成功不能替它开脱"
        );
        cooldowns.clear_for(5, "codeload.github.com");
        assert!(!cooldowns.is_host_blocked(5, "codeload.github.com"));
    }

    /// host 级失败不计入候选的全局健康计数。
    ///
    /// 否则一个 host 上的 403 会把候选整体判成 `Unhealthy`——等于在健康状态上
    /// 又犯一次"按候选一刀切"，和冷却按 host 拆分是同一个道理。
    /// 状态码 → 冷却作用域的映射。**只有 403/404 是 host 级**。
    ///
    /// 这条映射原先内联在一个 `if` 里，只能靠集成测试间接碰；抽成函数后可以直接钉住。
    /// 判据是"这个失败说明了什么"：403/404 是"该候选不愿服务这个 host"（同一候选服务别的
    /// host 可能正常）；401/429/451/5xx 则是"服务对我的态度"，不随 host 变化，
    /// 冷却整个候选才安全——否则用户会继续拿一个正在出问题的候选去打别的 host。
    #[test]
    fn failure_scope_is_host_only_for_403_and_404() {
        // CooldownScope 没实现 PartialEq，用 label() 比较（它同时是日志里显示的名字）
        for status in [403u16, 404] {
            let scope = failure_scope(status, "github.com");
            assert_eq!(scope.label(), "host", "{status} 应只冷却该 host");
            assert!(!scope.affects_health(), "{status} 不该影响整体健康度");
        }
        for status in [400u16, 401, 405, 418, 429, 451, 500, 502, 503] {
            let scope = failure_scope(status, "github.com");
            assert_eq!(scope.label(), "service", "{status} 应冷却整个候选");
            assert!(scope.affects_health(), "{status} 应计入健康度");
        }
    }

    #[test]
    fn only_service_failures_affect_health() {
        assert!(CooldownScope::Service.affects_health());
        assert!(!CooldownScope::Host("github.com").affects_health());
        assert_eq!(CooldownScope::Service.label(), "service");
        assert_eq!(CooldownScope::Host("github.com").label(), "host");
    }

    /// 绑定表饱和时**不再新增**，但**已过期项先被清掉**——所以"满"只在真的有
    /// 512 个**未过期**文件时才出现。
    ///
    /// 这条规则写成独立用例，是因为它直接对应 `pin()` 的结构：
    /// `retain(未过期)` → 判断长度 → 决定插入。生产代码里 `PIN-FULL` 只该打一次。
    #[test]
    fn pin_table_purges_expired_before_deciding_it_is_full() {
        let now = std::time::Instant::now();
        let mut pins: std::collections::HashMap<String, (usize, std::time::Instant)> =
            std::collections::HashMap::new();

        // 填满到上限，全部未过期
        for i in 0..MAX_PINS {
            pins.insert(format!("host/file-{i}"), (0, now + PIN_TTL));
        }
        assert_eq!(pins.len(), MAX_PINS);

        // 按生产顺序：先清理过期项 —— 此时没有过期的，于是"满"
        pins.retain(|_, (_, exp)| *exp > now);
        assert!(pins.len() >= MAX_PINS, "全都未过期时应判定为满");

        // 让一半过期后再清理，就腾出了空间（说明"满"不是永久状态）
        let expired = now - Duration::from_secs(1);
        let stale_keys: Vec<String> = pins.keys().take(MAX_PINS / 2).cloned().collect();
        for key in stale_keys {
            pins.insert(key, (0, expired));
        }
        pins.retain(|_, (_, exp)| *exp > now);
        assert!(pins.len() < MAX_PINS, "清理过期项后应腾出空间");
    }

    /// 同一文件的不同**签名**必须映射到同一个 pin 键。
    ///
    /// GitHub 资产会 302 到 `release-assets.githubusercontent.com/…?sp=r&…&se=…&sig=…`，
    /// query 里带过期时间戳，签名一换（跨小时、或客户端重新解析 URL）整串就变。
    /// 若把 query 也算进键，同一个文件会被当成两个文件：pin 白丢、绑定表还被几百字节的
    /// query 撑大。query 只决定"上游认不认这次请求"，不决定"这是哪个文件"。
    #[test]
    fn pin_key_ignores_query_string() {
        let a = Proxy::pin_key(
            "release-assets.githubusercontent.com",
            "/github-production-release-asset/1/2/file.zip?sp=r&se=2026-11-04T12%3A48%3A08Z&sig=AAA",
        );
        let b = Proxy::pin_key(
            "release-assets.githubusercontent.com",
            "/github-production-release-asset/1/2/file.zip?sp=r&se=2026-11-04T14%3A00%3A00Z&sig=BBB",
        );
        assert_eq!(a, b, "不同签名应视为同一个文件");
        assert!(
            !a.contains('?') && !a.contains("sig="),
            "键里不该残留 query: {a}"
        );

        // 不同路径仍是不同文件
        let c = Proxy::pin_key("github.com", "/o/r/other.zip");
        assert_ne!(a, c);

        // 无 query 时行为不变（不能把路径本身截掉）
        let d = Proxy::pin_key("github.com", "/o/r/x.zip");
        assert_eq!(d, "github.com/o/r/x.zip");
    }

    /// pin 在每次命中时续期，而不是只在分片成功收尾时。
    ///
    /// 否则一个跑得比 `PIN_TTL`（600 s）还久的大分片会在中途失去绑定，
    /// 后续分片可能落到别的加速器上（速度参差，且违背 pin 的初衷）。
    #[test]
    fn pin_is_refreshed_on_hit_but_not_when_unusable() {
        let mut pins = std::collections::HashMap::new();
        let ttl = Duration::from_secs(600);
        let now = std::time::Instant::now();

        // 命中并续期
        pins.insert("k".to_string(), (7, now + Duration::from_secs(1)));
        assert_eq!(take_pin(&mut pins, "k", now, ttl, |_| true), Some(7));
        assert_eq!(pins["k"].1, now + ttl, "命中后过期时间应推到 now + ttl");

        // 过期的 pin 不生效
        pins.insert("old".to_string(), (8, now - Duration::from_secs(1)));
        assert_eq!(take_pin(&mut pins, "old", now, ttl, |_| true), None);

        // 候选不可用时既不返回也不续期：靠"被反复查到"续命会让坏 pin 永不过期
        let stale_expiry = now - Duration::from_secs(5);
        pins.insert("bad".to_string(), (9, stale_expiry));
        assert_eq!(take_pin(&mut pins, "bad", now, ttl, |_| false), None);
        assert_eq!(pins["bad"].1, stale_expiry, "未通过的 pin 不该被续期");

        // 不存在 → None
        assert_eq!(take_pin(&mut pins, "missing", now, ttl, |_| true), None);
    }

    #[test]
    fn pin_peek_and_refresh_do_not_refresh_after_candidate_changes() {
        let mut pins = std::collections::HashMap::new();
        let now = std::time::Instant::now();
        pins.insert("k".to_string(), (7, now + Duration::from_secs(1)));

        assert_eq!(peek_pin(&pins, "k", now), Some(7));
        assert!(!refresh_pin(
            &mut pins,
            "k",
            8,
            now,
            Duration::from_secs(600)
        ));
        assert_eq!(pins["k"].1, now + Duration::from_secs(1));
        assert!(refresh_pin(
            &mut pins,
            "k",
            7,
            now,
            Duration::from_secs(600)
        ));
        assert_eq!(pins["k"].1, now + Duration::from_secs(600));
    }

    #[test]
    fn netstat_pid_lookup_finds_listening_port() {
        let text = concat!(
            "\n\n\n",
            "协议  本地地址          外部地址        状态           PID\n",
            "TCP    127.0.0.1:8443    0.0.0.0:0       LISTENING       12345\n",
            "TCP    127.0.0.1:8444    0.0.0.0:0       LISTENING       999\n",
            "TCP    127.0.0.1:8443    127.0.0.1:5000  ESTABLISHED     12345\n",
            "TCP    [::1]:18080        [::]:0          LISTENING       777\n",
        );
        assert_eq!(pid_from_netstat(text, 8443), Some(12345));
        assert_eq!(pid_from_netstat(text, 8444), Some(999));
        assert_eq!(pid_from_netstat(text, 18080), Some(777));
        assert_eq!(pid_from_netstat(text, 8080), None);
    }
}
