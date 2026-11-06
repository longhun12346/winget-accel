//! 监听、CONNECT 分流、隧道与 MITM 改写。
//!
//! 分流规则（ADR-014 约束 2）：只有 `rewrite_hosts`（含配置中的 `mitmExtra`）会被终止 TLS，
//! 其余 host 一律原样隧道——我们不解析、不记录、不改写那些流量。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::ca::{upstream_client_config, CertAuthority};
use crate::config::App;
use crate::health::Tracker;
use crate::http;
use crate::log::{Level, Logger};
use crate::rewrite;
use crate::stats::Stats;

mod local;
mod probe;

pub use probe::{probe, DEFAULT_PROBE_ASSET};
pub(crate) use probe::{probe_speed, split_asset};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(60);
/// 建连后等**首个请求头**的期限。
///
/// 比 `IO_TIMEOUT` 短得多：连接在发出任何请求之前就占着一个并发名额（总共 64 个）。
/// 浏览器开一批 `*.github.com` 标签页时容易攒出几十条空闲连接，
/// 让它们各自占 60 秒，winget 的下载就可能被 503 挡掉。
/// 读完请求头之后会恢复成 `IO_TIMEOUT`（见 `handle_client`）。
const FIRST_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// 单次上游尝试的最短 idle 超时。
///
/// 换候选的预算（`MAX_FAILOVER_TIME`）不是硬上限——它只在每次尝试**开始前**检查，
/// 一次卡住的尝试仍可超出它一个 idle 超时。
/// 这里的下限保证收窄后也不会变成"刚发出就超时"：读超时衡量的是"多久没有新数据"，
/// 设得比 `MIN_ATTEMPT_TIMEOUT` 更小会误杀正常但偏慢的链路。
const MIN_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
/// 同时处理的连接上限。超出直接拒绝，避免 PAC 把大量子域流量导进来时无限建线程。
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
const BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
/// 带请求体的请求：本代理只转发响应体，明确不支持而不是让它卡到超时。
const BODY_UNSUPPORTED: &[u8] =
    b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// 回 501 前最多读掉多少请求体。
///
/// 不是"支持请求体"，只是为了让客户端能读到那个 501：连接里留着未读数据就关闭，
/// Windows 会发 RST，客户端只会看到"连接被重置"。上限很小，因为它只是礼貌性的收尾。
const MAX_DRAIN: u64 = 64 * 1024;
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
/// 一次上游尝试的结果。
///
/// 拆成三态是为了支持"换候选重试"：
/// 429/503 时上游还没把任何字节转发给客户端，可以安全地换一个候选；
/// 而一旦开始转发正文，就不能再改主意了。
enum Fwd {
    /// 响应已经完整（或按协议定界）转发给客户端。
    Done(u16, u64),
    /// 尚未向客户端写任何字节，可以换候选重试。
    RetryableStatus(u16),
    /// 上游连接/读取失败，尚未向客户端写任何字节。
    RetryableFailure(anyhow::Error),
}

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

/// 连接槽位：线程结束时把 `Proxy::active` 减回去。
///
/// 用 Drop 而不是在每处 return 手动减——`handle_client` 有多条提前返回路径，
/// 漏掉一条就会永久占用一个名额，最终把自己锁死。
struct ActiveSlot(Arc<Proxy>);

/// 隧道连接的计数守卫（`Proxy::tunnels` 的 RAII 包装）。
///
/// 用 Drop 释放而不是在每个返回点手写 `fetch_sub`：`do_tunnel` 有多条提前返回路径，
/// 漏一条就会永久吃掉一个名额（和 `ActiveSlot` 当初同样的理由）。
/// 这里借用计数器的引用而非 `Arc<Proxy>`——`dispatch_connect` 拿到的是 `&Proxy`。
struct TunnelSlot<'a>(&'a std::sync::atomic::AtomicUsize);

impl Drop for TunnelSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
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
    /// 同一文件的候选绑定：键 = host + path，值 = (候选索引, 过期时刻)。
    pins: std::sync::Mutex<std::collections::HashMap<String, (usize, std::time::Instant)>>,
    /// 绑定表是否已饱和到 [`MAX_PINS`]；只用来让 `PIN-FULL` 告警**只打一次**。
    pins_saturated: AtomicBool,
    /// 上一次观测到的"全挂"状态，用来只在**状态翻转**时报警，避免每请求刷日志。
    down: AtomicBool,
    /// 当前在处理中的连接数（含隧道与 MITM），用于限制线程数。
    active: std::sync::atomic::AtomicUsize,
    /// 当前**隧道**连接数（是 `active` 的子集），用于把名额优先留给下载。
    tunnels: std::sync::atomic::AtomicUsize,
    /// Candidate failure cooldowns: index -> unblock instant.
    cooldowns: Cooldowns,
    /// 进程启动时刻，`/health` 用它算 `uptimeSeconds`。
    started: std::time::Instant,
    /// 运行期学到的"某候选对某 host 不可用"（见 `learned` 模块的文件头说明）。
    learned: crate::learned::LearnedCaps,
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

    /// 阻塞式接受连接，每连接一个线程；监听端口由 main 在接管系统前预留。
    pub fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        self.spawn_health_prober();

        for incoming in listener.incoming() {
            match incoming {
                Ok(mut stream) => {
                    let peer = stream
                        .peer_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|_| "unknown".to_string());
                    // 先原子占一个名额再判断：`load()` 后 `fetch_add()` 之间有两个线程
                    // 同时看到 63 的窗口，一起进来就会变成 65，上限形同虚设。
                    // 占用失败立刻还回去，避免泄漏名额。
                    let slot = self.active.fetch_add(1, Ordering::Relaxed);
                    if slot >= MAX_CONNECTIONS {
                        self.active.fetch_sub(1, Ordering::Relaxed);
                        // 名额满时，**本地端点仍要能服务**：Windows 会定期重新取 PAC，
                        // 而占满名额的正是下载本身——取不到 PAC 就可能退回直连，
                        // 于是"下载越多、加速越容易失效"。实测：64 个连接占满后
                        // `GET /winget-accel.pac` 会拿到 503。
                        if self.serve_local_if_saturated(&mut stream, &peer) {
                            continue;
                        }
                        Stats::bump(&self.stats.conn_limited);
                        self.log.warn(&format!(
                            "CONN-LIMIT peer={peer} 并发连接已达上限 {MAX_CONNECTIONS}，拒绝本次连接"
                        ));
                        let _ = stream.write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                    let proxy = Arc::clone(&self);
                    std::thread::spawn(move || {
                        let _slot = ActiveSlot(Arc::clone(&proxy));
                        // 建连后先给一个**短的**"首个请求"期限：连接在发请求之前就占着一个
                        // 并发名额，而名额只有 64 个。浏览器打开一批 `*.github.com` 标签页
                        // 时很容易攒出几十条空闲连接；若都按 60 s 的 IO 超时等着，
                        // winget 的下载可能被 503 挡掉。
                        let _ = stream.set_read_timeout(Some(FIRST_REQUEST_TIMEOUT));
                        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                        let started = std::time::Instant::now();
                        proxy
                            .log
                            .log(Level::Debug, &format!("CONN-ACCEPT peer={peer}"));
                        if let Err(err) = proxy.handle_client(stream) {
                            proxy.log.warn(&format!(
                                "CONN-FAIL peer={peer} elapsed={:.2}s {err:#}",
                                started.elapsed().as_secs_f64()
                            ));
                        }
                    });
                }
                Err(err) => self.log.warn(&format!("ACCEPT-FAIL {err}")),
            }
        }
        Ok(())
    }

    fn handle_client(&self, mut stream: TcpStream) -> Result<()> {
        Stats::bump(&self.stats.connects);

        let head = match http::read_head(&mut stream) {
            Ok(head) => head,
            Err(err) => {
                Stats::bump(&self.stats.errors);
                // 头过大时回一个明确的 431，而不是默默断线。
                //
                // 但只在"已经能看出这是个 HTTP 请求"时才回：随机二进制/TLS 握手打进来的
                // 连接得到一个 HTTP 响应没有意义，对端也读不懂。
                // 本地代理不是对外服务，这一条纯粹是为了"客户端报错能指对方向"——
                // 实测超大请求头此前表现为客户端侧的连接重置，看不出原因。
                if err.kind() == std::io::ErrorKind::InvalidData {
                    let _ = stream.write_all(
                        b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    let _ = stream.flush();
                    // 写完要先**排空对端还在发的数据**再关，否则内核会发 RST，
                    // 某些客户端连 431 都读不到（实测：直接 ConnectionResetError，
                    // 而用 curl 手工写同样的字节却能看到 431——差别就在收尾方式）。
                    drain_briefly(&mut stream, MAX_DRAIN, Duration::from_millis(300));
                }
                return Err(anyhow!("读请求头失败: {err}"));
            }
        };

        // 请求头已经到了：把读超时恢复成常规值。此前的 10 秒只针对"连上但不说话"
        // 的连接（保护 64 个并发名额），不该限制后续的正常收发。
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));

        let Some(req) = http::parse_head(&head) else {
            Stats::bump(&self.stats.errors);
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            return Err(anyhow!(
                "请求头无法解析（{} 字节: {}）",
                head.len(),
                http::bytes_preview(&head)
            ));
        };

        if req.method.eq_ignore_ascii_case("CONNECT") {
            return self.dispatch_connect(stream, &req);
        }
        self.serve_local(stream, &req)
    }

    /// CONNECT 分流：白名单走 MITM，其余走隧道。
    fn dispatch_connect(&self, stream: TcpStream, req: &http::Head) -> Result<()> {
        let (host, port) = split_host_port(&req.target)
            .with_context(|| format!("CONNECT 目标非法: {}", req.target))?;
        // 统一转小写再往下走：DNS 名字大小写不敏感（RFC 4343），而下游的
        // pin 键、能力矩阵、日志都以它为准。也让"PAC 匹配上了却分流到隧道"
        // 这种自相矛盾的情形不可能再出现。
        let host = host.to_ascii_lowercase();

        let mode = if self.app.should_mitm(&host) {
            "MITM"
        } else {
            "TUNNEL"
        };
        self.log.info(&format!("CONNECT {host}:{port} mode={mode}"));

        if self.app.should_mitm(&host) {
            Stats::bump(&self.stats.mitm);
            self.do_mitm(stream, &host, port)
        } else {
            // 隧道名额有独立上限：超了就把这个名额让给下载（见 MAX_TUNNELS 的说明）。
            // 检查与占用是同一步 `fetch_add`，不会两个线程同时看到 47 一起进来。
            let n = self.tunnels.fetch_add(1, Ordering::Relaxed);
            if n >= MAX_TUNNELS {
                self.tunnels.fetch_sub(1, Ordering::Relaxed);
                Stats::bump(&self.stats.conn_limited);
                self.log.warn(&format!(
                    "TUNNEL-LIMIT {host}:{port} 隧道已达上限 {MAX_TUNNELS}（总名额 {MAX_CONNECTIONS}）：\
                     名额优先留给下载，本次隧道被拒"
                ));
                let mut stream = stream;
                let _ = stream.write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return Ok(());
            }
            let _guard = TunnelSlot(&self.tunnels);
            Stats::bump(&self.stats.tunnel);
            self.do_tunnel(stream, &host, port)
        }
    }

    /// 原样隧道：不终止 TLS，不解析内容。
    fn do_tunnel(&self, mut client: TcpStream, host: &str, port: u16) -> Result<()> {
        let upstream = match connect_tcp(host, port) {
            Ok(stream) => stream,
            Err(err) => {
                Stats::bump(&self.stats.errors);
                self.log.warn(&format!("TUNNEL-FAIL {host}:{port} {err:#}"));
                let _ = client.write_all(BAD_GATEWAY);
                return Ok(());
            }
        };
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;

        let mut up_read = upstream.try_clone()?;
        let mut cli_read = client.try_clone()?;
        let mut cli_write = client;
        let mut up_write = upstream;

        let up_to_cli = std::thread::spawn(move || {
            let _ = std::io::copy(&mut up_read, &mut cli_write);
            let _ = cli_write.shutdown(std::net::Shutdown::Write);
        });
        let _ = std::io::copy(&mut cli_read, &mut up_write);
        let _ = up_write.shutdown(std::net::Shutdown::Write);
        let _ = up_to_cli.join();

        self.log.info(&format!("TUNNEL {host}:{port}"));
        Ok(())
    }

    /// 终止 TLS 并改写请求。
    fn do_mitm(&self, mut client: TcpStream, host: &str, port: u16) -> Result<()> {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;

        let server_cfg = self.ca.server_config(host)?;
        let conn = ServerConnection::new(server_cfg).context("构造 TLS 服务端会话失败")?;
        let mut tls = StreamOwned::new(conn, client);

        let head = match http::read_head(&mut tls) {
            Ok(head) => head,
            Err(err) => {
                Stats::bump(&self.stats.errors);
                self.log.warn(&format!("MITM-READ-FAIL {host} {err}"));
                return Ok(());
            }
        };
        let Some(req) = http::parse_head(&head) else {
            Stats::bump(&self.stats.errors);
            return Ok(());
        };

        // 带请求体的请求直接 501：本代理不转发请求体，硬发出去只会让上游等 body、
        // 让客户端卡到读超时。失败要快，而且要能一眼看出原因（见 `has_request_body`）。
        if has_request_body(&req) {
            Stats::bump(&self.stats.errors);
            self.log.warn(&format!(
                "REQ-BODY-UNSUPPORTED host={host} method={} contentLength={} \
                 本代理不转发请求体（git clone 等走 PAC 的 DIRECT），返回 501",
                req.method,
                req.header("content-length").unwrap_or("-")
            ));
            // 先把**小的**请求体读掉再回 501：连接里还有未读数据就关闭，
            // Windows 会发 RST，客户端读不到这个 501、只看到"连接被重置"。
            // 上限 64 KiB——本代理本来就不支持请求体，为它无限读没有意义。
            if let Some(len) = request_body_len(&req).filter(|len| *len <= MAX_DRAIN) {
                // 对方可能正在等 100 Continue，不能为了拒绝请求先等它发 body。
                let _ = tls.sock.set_read_timeout(Some(Duration::from_millis(300)));
                let _ = std::io::copy(&mut (&mut tls).take(len), &mut std::io::sink());
            }
            self.send_status(&mut tls, BODY_UNSUPPORTED);
            return Ok(());
        }

        let no_body = req.method.eq_ignore_ascii_case("HEAD");
        let expect_partial = req.header("range").is_some();
        let initial_probe = is_initial_probe(&req);
        // 只有幂等方法才允许换候选重试（GET/HEAD）。
        let retryable = req.method.eq_ignore_ascii_case("GET") || no_body;
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
        // 读写超时在进入重试循环时算**一次**，所有尝试共用：它是"多久没有新数据"的
        // idle 超时，不是总时长。刻意不按每次尝试收窄——把重试的超时越收越短，
        // 会把"慢但能成"的候选误杀（本项目的目标是"下载可用"，不是"总耗时最短"）。
        // 代价：卡住的单次尝试可以超出 MAX_FAILOVER_TIME 一个 idle 超时，
        // 所以那个预算只是"近似有界"，真正的硬边界是"不再发起新尝试"。
        let attempt_timeout = if initial_probe {
            Some(INITIAL_PROBE_ATTEMPT_TIMEOUT)
        } else {
            let remaining = failover_time.saturating_sub(started.elapsed());
            Some(remaining.max(MIN_ATTEMPT_TIMEOUT))
        };

        // 每轮尝试各自的起点（在 `break` 里带出）：速度样本要用"这一次尝试"的耗时，
        // 而不是整个请求的耗时（含之前失败候选的切换开销，那会把速度算低）。
        let mut tried: Vec<usize> = Vec::new();
        // 最近一次"候选给出了明确状态码"的响应。
        //
        // 为什么需要：401/451 这类状态码说明**这个候选**不行（要认证 / 被它屏蔽），
        // 换候选重试是对的；但如果候选用尽了，把 401 变成 502 就丢了上游语义——
        // 用户看到 451 会想到"被屏蔽"，看到 502 只会以为是我们这层挂了。
        // 实测过：单候选返回 401 时，改动后客户端拿到 502，排查方向完全被带偏。
        let mut last_status: Option<u16> = None;
        if initial_probe {
            self.log
                .info(&format!("INITIAL-PROBE host={host} range=bytes=0-1"));
        }

        let (plan, accel_idx, accel, status, size, pin_hit, attempt_started) = loop {
            if !tried.is_empty() && started.elapsed() >= failover_time {
                self.log.warn(&format!(
                    "FAILOVER-TIMEOUT host={host} initial_probe={initial_probe} tried={} elapsed={:.2}s",
                    tried.len(),
                    started.elapsed().as_secs_f64()
                ));
                self.send_bad_gateway(&mut tls);
                return Ok(());
            }
            let Some((accel_idx, accel, from_pin)) = self.pick_for(host, &req.target, &tried)
            else {
                Stats::bump(&self.stats.errors);
                // 候选用尽，但最后一次曾拿到**表示拒绝**的状态码 → 透传它，别一律 502。
                // 401（要认证）/451（被屏蔽）与 502（我们这层挂了）对用户意味着完全不同的处理方向。
                // 但 2xx 绝不能透传：Range 请求拿到 200 说明上游回了整包，
                // 交给客户端会被当成某个分片，内容就错了。
                if let Some(status) = last_status.filter(|s| *s >= 400) {
                    self.log.warn(&format!(
                        "NO-VERIFIED-ACCEL {host} 候选已试 {} 个均失败，透传最后一次状态 {status}",
                        tried.len()
                    ));
                    self.send_passthrough_status(&mut tls, status);
                } else {
                    self.log.warn(&format!(
                        "NO-VERIFIED-ACCEL {host} 无已验证候选（未探测候选不会使用；已试 {} 个），返回 502",
                        tried.len()
                    ));
                    self.send_bad_gateway(&mut tls);
                }
                return Ok(());
            };

            let plan = rewrite::plan_with(
                &req.method,
                host,
                port,
                &req.target,
                &req.headers,
                &self.app.rewrite_hosts,
                &accel,
                rewrite::needs_rewrite(host, &req.target),
            );

            // 关键：在写任何客户端字节前确定本次是否还可能重试。
            let allow_retry = retryable
                && plan.rewritten
                && tried.len() + 1 < failover_limit
                && started.elapsed() < failover_time;
            let attempt_started = std::time::Instant::now();
            let outcome = match plan.scheme {
                rewrite::Scheme::Https => {
                    self.forward_tls(&plan, no_body, expect_partial, attempt_timeout, &mut tls)
                }
                rewrite::Scheme::Http => {
                    self.forward_plain(&plan, no_body, expect_partial, attempt_timeout, &mut tls)
                }
            };

            match outcome {
                Ok(Fwd::Done(status, size)) => {
                    break (
                        plan,
                        accel_idx,
                        accel,
                        status,
                        size,
                        from_pin,
                        attempt_started,
                    );
                }
                Ok(Fwd::RetryableStatus(status)) => {
                    Stats::bump(&self.stats.errors);
                    if http::is_rate_limited(status) {
                        self.health.mark(accel_idx, false);
                        self.cooldowns.block_service(accel_idx, FAILURE_COOLDOWN);
                        self.log.warn(&format!(
                            "ACCEL-COOLDOWN {} for {}s: rate limited {status}",
                            accel.host,
                            FAILURE_COOLDOWN.as_secs()
                        ));
                        Stats::bump(&self.stats.ratelimited);
                    } else {
                        let scope = failure_scope(status, host);
                        self.note_accel_failure(
                            accel_idx,
                            &accel,
                            &format!("upstream status {status}"),
                            scope,
                        );
                        // 403/404 是"该候选不愿服务这个 URL"的证据（限流/故障不是），
                        // 记进能力学习：同一 (候选, host) 反复如此就临时跳过它，
                        // 免得后续请求继续把换候选预算浪费在它身上。
                        if matches!(status, 403 | 404)
                            && plan.rewritten
                            && self.learned.note_unsupported(accel_idx, host)
                        {
                            self.log.warn(&format!(
                                "CAPS-LEARNED host={host} 候选 {} 连续返回 {status}，\
                                 该组合暂时跳过（这是运行期学到的，不是配置里的能力矩阵）",
                                accel.host
                            ));
                        }
                    }
                    self.log.warn(&format!(
                        "ACCEL-BAD-STATUS {} 返回 {status}，换下一个候选重试",
                        accel.host
                    ));
                    // 记下它，候选用尽时透传（别把 401/451 变成 502）
                    last_status = Some(status);
                    if initial_probe {
                        self.log.warn(&format!(
                            "INITIAL-PROBE-RETRY via={} status={status} tried={}",
                            accel.host,
                            tried.len()
                        ));
                    }
                    tried.push(accel_idx);
                    if !allow_retry {
                        // 不能重试（非幂等方法，或只剩这一条）：这是最后一次尝试。
                        // 只透传**表示拒绝**的状态码（4xx/5xx）——401/451 变成 502 会把
                        // 排查方向带偏。2xx 不能透传：Range 请求拿到 200 意味着上游回了整包，
                        // 交给客户端会被当成某个分片，内容就错了（协议用例钉住这条）。
                        if status >= 400 {
                            self.send_passthrough_status(&mut tls, status);
                        } else {
                            self.send_bad_gateway(&mut tls);
                        }
                        return Ok(());
                    }
                }
                Ok(Fwd::RetryableFailure(err)) => {
                    Stats::bump(&self.stats.errors);
                    self.log.warn(&format!(
                        "UPSTREAM-FAIL {host} -> {}:{} {err:#}",
                        plan.host, plan.port
                    ));
                    if plan.rewritten {
                        self.note_accel_failure(
                            accel_idx,
                            &accel,
                            &format!("{err:#}"),
                            CooldownScope::Service,
                        );
                    }
                    tried.push(accel_idx);
                    if allow_retry {
                        self.log.warn(&format!("RETRY {host} 换下一个候选"));
                    } else {
                        self.send_bad_gateway(&mut tls);
                        return Ok(());
                    }
                }
                Err(err) => {
                    Stats::bump(&self.stats.errors);
                    // `kind=` 让两种完全不同的情况不再长得一样：
                    // - timeout：上游不再发数据（chunked 收尾后没关连接时很常见，
                    //   此时客户端多半已经拿全了内容）
                    // - early-eof：上游提前断开，正文真的不完整
                    // 以前它们都只是"RELAY-ERR + 一句 err"，排障时容易误判成下载失败。
                    self.log.warn(&format!(
                        "RELAY-ERR host={host} via={} kind={} retry={} elapsed={:.2}s pin_cleared={} path={} err={err:#}",
                        accel.host,
                        io_error_kind(&err),
                        tried.len(),
                        started.elapsed().as_secs_f64(),
                        plan.rewritten,
                        crate::log::loggable(&plan.path, 100)
                    ));
                    if plan.rewritten {
                        self.unpin(host, &req.target);
                    }
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                    let _ = tls.sock.shutdown(std::net::Shutdown::Both);
                    return Ok(());
                }
            }
        };

        if initial_probe {
            self.log.info(&format!(
                "INITIAL-PROBE-OK via={} status={status} size={size} tried={}",
                accel.host,
                tried.len()
            ));
        }

        if plan.rewritten {
            Stats::bump(&self.stats.rewrites);
            if (200..300).contains(&status) {
                self.cooldowns.clear_for(accel_idx, host);
                self.health.record_success(accel_idx);
                // 用**这一次尝试**的耗时，不含之前失败候选的切换开销：
                // 用总耗时会把速度算低，进而把这个候选的权重压低（选择越选越偏）。
                self.health
                    .record_sample(accel_idx, size, attempt_started.elapsed().as_secs_f64());
                self.pin(host, &req.target, accel_idx);
                // 它确实服务过这个 host：把"不支持"的记录清掉，避免误杀
                self.learned.note_success(accel_idx, host);
            } else {
                // 3xx 是**合法**响应：客户端（winget）会自己跟随重定向，我们只负责透传。
                // 实测：加速器返回 302 指向 release-assets.githubusercontent.com 时，
                // 原来的日志写成 `ACCEL-BAD-STATUS … 返回 302`，看起来像候选坏了——
                // 而它其实工作正常，只是把重定向交回客户端。分开写，别误导排查。
                if (300..400).contains(&status) {
                    self.log.log(
                        Level::Debug,
                        &format!(
                            "ACCEL-REDIRECT {} 返回 {status}（{host}），原样透传给客户端跟随",
                            accel.host
                        ),
                    );
                } else {
                    self.log.warn(&format!(
                        "ACCEL-BAD-STATUS {} 返回 {status}（{host}），不计样本、不绑定",
                        accel.host
                    ));
                }
            }
        }

        Stats::add(&self.stats.bytes, size);
        if plan.rewritten {
            if status >= 500 {
                self.note_accel_failure(
                    accel_idx,
                    &accel,
                    &format!("上游返回 {status}"),
                    CooldownScope::Service,
                );
            } else if (200..300).contains(&status) {
                self.report_health_state();
            }
        }

        let tag = if plan.rewritten { "REWRITE" } else { "PASS" };
        let via = if plan.rewritten {
            accel.host.as_str()
        } else {
            "-"
        };
        let pin = if pin_hit { "bind" } else { "pick" };
        self.log.info(&format!(
            "{tag} via={via} {pin} retry={} {} -> {status} {size}B {:.2}s",
            tried.len(),
            crate::log::loggable(&plan.path, 76),
            started.elapsed().as_secs_f64()
        ));
        if plan.rewritten && !(200..300).contains(&status) {
            let elapsed = started.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 {
                (size as f64 / 1024.0) / elapsed
            } else {
                0.0
            };
            self.log.warn(&format!(
                "REWRITE-FAILED via={via} status={status} size={size}B {speed:.0}KB/s tried={tried:?} {}",
                crate::log::loggable(&plan.path, 100)
            ));
        }

        tls.conn.send_close_notify();
        let _ = tls.flush();
        let _ = tls.sock.shutdown(std::net::Shutdown::Both);
        Ok(())
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
        let pinned = {
            let mut pins = self.pins.lock().expect("pin 锁中毒");
            take_pin(&mut pins, &key, std::time::Instant::now(), PIN_TTL, |idx| {
                !excluded.contains(&idx)
                    && !self.cooldowns.is_blocked_for(idx, host)
                    && self.health.is_healthy(idx)
                    && self.app.accel_supports(idx, host)
                    && !self.learned.is_blocked(idx, host)
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
        self.report_health_state();
    }

    /// 全挂时**报错**，恢复时再报一次。
    ///
    /// 只在状态翻转时报：否则每个失败请求都会刷一条，日志里真正那条反而被埋掉。
    fn report_health_state(&self) {
        let down = self.health.all_unhealthy();
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

    fn forward_tls(
        &self,
        plan: &rewrite::Plan,
        no_body: bool,
        expect_partial: bool,
        attempt_timeout: Option<Duration>,
        tls: &mut StreamOwned<ServerConnection, TcpStream>,
    ) -> Result<Fwd> {
        let timeout = attempt_timeout.unwrap_or(CONNECT_TIMEOUT);
        let mut upstream = match self.open_tls_upstream(plan, timeout) {
            Ok(stream) => stream,
            Err(err) => return Ok(Fwd::RetryableFailure(err)),
        };

        if let Some(timeout) = attempt_timeout {
            let _ = upstream.sock.set_read_timeout(Some(timeout));
            let _ = upstream.sock.set_write_timeout(Some(timeout));
        }

        if let Err(err) = upstream
            .write_all(&plan.head)
            .and_then(|()| upstream.flush())
        {
            return Ok(Fwd::RetryableFailure(err.into()));
        }

        let result = self.relay_checked(&mut upstream, tls, no_body, expect_partial);
        upstream.conn.send_close_notify();
        result
    }

    fn forward_plain(
        &self,
        plan: &rewrite::Plan,
        no_body: bool,
        expect_partial: bool,
        attempt_timeout: Option<Duration>,
        tls: &mut StreamOwned<ServerConnection, TcpStream>,
    ) -> Result<Fwd> {
        let timeout = attempt_timeout.unwrap_or(CONNECT_TIMEOUT);
        let mut upstream = match connect_tcp_timeout(&plan.host, plan.port, timeout) {
            Ok(stream) => stream,
            Err(err) => return Ok(Fwd::RetryableFailure(err)),
        };
        if let Some(timeout) = attempt_timeout {
            let _ = upstream.set_read_timeout(Some(timeout));
            let _ = upstream.set_write_timeout(Some(timeout));
        }

        if let Err(err) = upstream
            .write_all(&plan.head)
            .and_then(|()| upstream.flush())
        {
            return Ok(Fwd::RetryableFailure(err.into()));
        }

        self.relay_checked(&mut upstream, tls, no_body, expect_partial)
    }

    /// 先读上游响应头并转发；具体判定见 `relay_checked_impl`。
    ///
    /// 这里**不判断能否重试**：`Fwd` 的三态本身就是"写到客户端了没有"，
    /// 由调用方（`do_mitm`）根据自己的 `allow_retry` 决定换候选还是回 502。
    /// 曾经把这个布尔一路传进来但没人用，读代码的人会以为"重试是在这里决定的"。
    fn relay_checked<R: std::io::Read>(
        &self,
        up: &mut R,
        tls: &mut StreamOwned<ServerConnection, TcpStream>,
        no_body: bool,
        expect_partial: bool,
    ) -> Result<Fwd> {
        relay_checked_impl(up, tls, no_body, expect_partial)
    }
    /// 只在最终失败时调用；保证客户端只收到一个 502。
    fn send_bad_gateway(&self, tls: &mut StreamOwned<ServerConnection, TcpStream>) {
        self.send_status(tls, BAD_GATEWAY);
    }

    /// 把上游给过的某个状态码原样回给客户端（无正文）。
    ///
    /// 用于"候选都试过了，最后一个是 401/451 这类明确语义"的情形：
    /// 与其一律换成 502，不如让客户端看到上游的真实回答——
    /// 401 指向"需要认证"、451 指向"被该服务屏蔽"，而 502 只会让人以为是我们这层坏了。
    fn send_passthrough_status(
        &self,
        tls: &mut StreamOwned<ServerConnection, TcpStream>,
        status: u16,
    ) {
        let reason = match status {
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            451 => "Unavailable For Legal Reasons",
            500..=599 => "Server Error",
            _ => "Error",
        };
        let response =
            format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        self.send_status(tls, response.as_bytes());
    }

    /// 向客户端写一个**预先固定**的响应并收尾（不再读上游）。
    ///
    /// 传 `&[u8]` 而不是 code + body：调用点只有两种固定响应，
    /// 拼字符串只会多一处可以写错的地方。
    fn send_status(&self, tls: &mut StreamOwned<ServerConnection, TcpStream>, response: &[u8]) {
        let _ = tls.write_all(response);
        tls.conn.send_close_notify();
        let _ = tls.flush();
        let _ = tls.sock.shutdown(std::net::Shutdown::Both);
    }
    fn open_tls_upstream(
        &self,
        plan: &rewrite::Plan,
        timeout: Duration,
    ) -> Result<StreamOwned<ClientConnection, TcpStream>> {
        let cfg = upstream_client_config();
        let server_name: rustls::pki_types::ServerName<'static> = plan
            .host
            .clone()
            .try_into()
            .map_err(|_| anyhow!("上游主机名非法: {}", plan.host))?;
        let conn = ClientConnection::new(cfg, server_name).context("构造 TLS 客户端会话失败")?;
        let stream = connect_tcp_timeout(&plan.host, plan.port, timeout)?;
        Ok(StreamOwned::new(conn, stream))
    }
}

/// 读上游响应头并判断"这个响应能不能改写客户端"。
///
/// 返回值的三态就是答案：`Done` 已经写出去（不能再改主意）；
/// `RetryableStatus` / `RetryableFailure` 保证**一个字节都没写给客户端**，
/// 所以调用方可以安全地换候选。能不能换由调用方按自己的预算决定。
fn relay_checked_impl<R: std::io::Read, W: std::io::Write>(
    up: &mut R,
    client: &mut W,
    no_body: bool,
    expect_partial: bool,
) -> Result<Fwd> {
    let head = match http::read_head(up) {
        Ok(head) => head,
        Err(err) => return Ok(Fwd::RetryableFailure(anyhow!("读取上游响应头失败: {err}"))),
    };
    let status = http::status_code(&head).unwrap_or(0);

    // Range 请求如果被上游忽略并返回 200，不能把这个响应透给 winget：
    // winget 会把小探测响应误认为完整安装包，随后报哈希不匹配。
    if expect_partial && status == 200 {
        return Ok(Fwd::RetryableStatus(200));
    }

    // 429/503 即使在最后一次尝试也要由调用方合成 502；
    // 其它坏状态只有还有候选时才在写客户端前拦截。
    if http::is_rate_limited(status) || is_retryable_status(status) {
        return Ok(Fwd::RetryableStatus(status));
    }

    client.write_all(&head)?;
    client.flush()?;
    let size = http::forward_body(up, client, &head, no_body)?;
    Ok(Fwd::Done(status, size))
}
/// 哪些上游状态值得换候选重试。
fn is_initial_probe(req: &http::Head) -> bool {
    req.header("range")
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("bytes=0-1"))
}

/// 取 pin 并在命中时**续期**；不满足条件时既不续期也不生效。
///
/// - 过期 → `None`
/// - 存在但该候选已不可用（被排除 / 冷却中 / 不健康 / 不支持该 host） → `None`，
///   且**不刷新**它的过期时间：一个用不了的 pin 不该靠"被反复查到"续命
/// - 命中 → 把过期时间推到 `now + ttl` 并返回候选下标
///
/// 抽成独立函数是为了能直接单测这三种情形（`Proxy` 本身依赖网络与证书，不好造）。
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
/// - `timeout`：上游不再发数据。chunked 响应里**上游没按 `Connection: close` 关闭**时
///   就会这样——客户端其实已经拿到终端块、内容完整，只是我们还在等 EOF；
/// - `early-eof`：上游提前断开，声明了 `Content-Length` 却没给够，是真的正文不完整；
/// - `other`：其它 IO 错误（连接被重置等）。
///
/// 混在一起时两种情况的日志一模一样，排障的人会把"其实成功的下载"当成失败。
fn io_error_kind(err: &anyhow::Error) -> &'static str {
    match err.downcast_ref::<std::io::Error>().map(|io| io.kind()) {
        Some(std::io::ErrorKind::WouldBlock) | Some(std::io::ErrorKind::TimedOut) => "timeout",
        Some(std::io::ErrorKind::UnexpectedEof) => "early-eof",
        _ => "other",
    }
}

/// 请求体长度（仅当有合法的 `Content-Length`）。
fn request_body_len(req: &http::Head) -> Option<u64> {
    req.header("content-length")
        .and_then(|value| value.trim().parse::<u64>().ok())
}

/// 请求是否带正文。
///
/// 本代理**只转发响应体，不转发请求体**（这也是 PAC 把 `git clone` 路径设为 DIRECT
/// 的原因：clone 的 `git-upload-pack` 依赖 POST body）。
/// 真有人在 MITM 路径上发带体的请求时，必须立刻拒绝：
/// 否则上游收到 `Content-Length: 15` 却永远等不到那 15 字节，
/// 客户端要卡满 60 秒读超时才失败，期间还占着一个连接名额。
///
/// `Content-Length: 0` 不算带体；`Transfer-Encoding` 一律算（分块体长度未知）。
fn has_request_body(req: &http::Head) -> bool {
    req.header("transfer-encoding").is_some() || request_body_len(req).is_some_and(|len| len > 0)
}

/// 在关闭连接前，把对端**还在发**的数据读掉一小段。
///
/// 为什么必须做：连接里还有未读数据就直接关闭，Windows 会发 RST 而不是 FIN，
/// 客户端那边**连我们刚写好的响应都读不到**，只看到"连接被重置"。
/// 这个坑出现过两次：501（请求体不支持）与 431（请求头过大）。
/// 上限与超时都很保守——本代理从不为对端的多余数据无限等待。
fn drain_briefly(stream: &mut TcpStream, max: u64, timeout: Duration) {
    // 排空阶段用**短**超时：对端若不再发数据，最多等这么久。
    // 不调的话会沿用常规 IO_TIMEOUT（60 s），反而把连接名额占住。
    let _ = stream.set_read_timeout(Some(timeout));
    let mut sink = std::io::sink();
    let _ = std::io::copy(&mut stream.take(max), &mut sink);
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

fn connect_tcp(host: &str, port: u16) -> Result<TcpStream> {
    connect_tcp_timeout(host, port, CONNECT_TIMEOUT)
}

fn connect_tcp_timeout(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("解析不了 {host}:{port}"))?
        .collect();

    let mut last: Option<anyhow::Error> = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(err) => last = Some(err.into()),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("没有可用地址: {host}:{port}")))
}

/// 解析 `host:port`，支持 IPv6 方括号写法。
fn split_host_port(target: &str) -> Result<(String, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("IPv6 目标缺少 ]: {target}"))?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("IPv6 目标缺少端口: {target}"))?;
        return Ok((host.to_string(), port.parse()?));
    }
    match target.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Ok((host.to_string(), port.parse()?)),
        _ => bail!("缺少端口: {target}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
    /// 3xx 是**合法**响应，必须原样透传、不能当作候选故障。
    ///
    /// 实测背景：加速器可能返回 302 指向 `release-assets.githubusercontent.com`
    /// （GitHub 资产最终就落在那里），客户端会自己跟随。而 `release-assets` 也在
    /// `rewriteHosts` 里，所以下一跳仍会经过我们。
    /// 这条用例钉住两件事：重定向**不被改写/吞掉**，也不进入"可重试"分支
    /// （否则会白白换候选并给健康度扣分）。
    #[test]
    fn redirect_is_forwarded_and_not_treated_as_failure() {
        use std::io::Cursor;
        let mut up = Cursor::new(
            b"HTTP/1.1 302 Found\r\nLocation: https://release-assets.githubusercontent.com/x\r\n\
              Content-Length: 0\r\n\r\n"
                .to_vec(),
        );
        let mut client = Vec::new();
        let result = relay_checked_impl(&mut up, &mut client, false, false).unwrap();
        // 不是 RetryableStatus —— 客户端要拿到这个 302
        assert!(
            matches!(result, Fwd::Done(302, _)),
            "302 应原样透传，实际不是 Done(302)"
        );
        let text = String::from_utf8_lossy(&client);
        assert!(text.starts_with("HTTP/1.1 302"), "{text}");
        assert!(
            text.contains("Location: https://release-assets.githubusercontent.com/x"),
            "Location 头必须保留: {text}"
        );
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

    #[test]
    fn retryable_status_is_not_written_to_client() {
        use std::io::Cursor;
        let mut up = Cursor::new(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".to_vec());
        let mut client = Vec::new();
        let result = relay_checked_impl(&mut up, &mut client, false, false).unwrap();
        assert!(matches!(result, Fwd::RetryableStatus(502)));
        assert!(client.is_empty(), "重试前不得向客户端写任何字节");
    }

    #[test]
    fn final_response_is_written_exactly_once() {
        use std::io::Cursor;
        let mut up = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec());
        let mut client = Vec::new();
        let result = relay_checked_impl(&mut up, &mut client, false, false).unwrap();
        assert!(matches!(result, Fwd::Done(200, 5)));
        assert!(client.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(client.ends_with(b"hello"));
    }

    #[test]
    fn rate_limit_is_retryable_even_on_last_attempt() {
        use std::io::Cursor;
        let mut up =
            Cursor::new(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n".to_vec());
        let mut client = Vec::new();
        let result = relay_checked_impl(&mut up, &mut client, false, false).unwrap();
        assert!(matches!(result, Fwd::RetryableStatus(429)));
        assert!(client.is_empty());
    }
    #[test]
    fn retry_then_success_writes_only_second_response() {
        use std::io::Cursor;
        let mut bad =
            Cursor::new(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".to_vec());
        let mut good = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec());
        let mut client = Vec::new();

        let first = relay_checked_impl(&mut bad, &mut client, false, false).unwrap();
        assert!(matches!(first, Fwd::RetryableStatus(502)));
        assert!(client.is_empty(), "第一次失败不能写客户端");

        let second = relay_checked_impl(&mut good, &mut client, false, false).unwrap();
        assert!(matches!(second, Fwd::Done(200, 5)));
        let text = String::from_utf8(client).unwrap();
        assert_eq!(text.matches("HTTP/1.1").count(), 1, "只能有一个最终响应");
        assert!(text.ends_with("hello"));
    }

    #[test]
    fn all_candidates_fail_write_single_502() {
        use std::io::Cursor;
        let mut bad =
            Cursor::new(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".to_vec());
        let mut client = Vec::new();

        let first = relay_checked_impl(&mut bad, &mut client, false, false).unwrap();
        assert!(matches!(first, Fwd::RetryableStatus(502)));
        assert!(client.is_empty());

        let mut bad2 =
            Cursor::new(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".to_vec());
        let last = relay_checked_impl(&mut bad2, &mut client, false, false).unwrap();
        assert!(matches!(last, Fwd::RetryableStatus(502)));
        assert!(client.is_empty(), "最终坏状态由调用方统一合成 502");
    }

    #[test]
    fn malformed_upstream_head_is_retryable_without_client_write() {
        use std::io::Cursor;
        let mut up = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n".to_vec());
        let mut client = Vec::new();
        let result = relay_checked_impl(&mut up, &mut client, false, false).unwrap();
        assert!(matches!(result, Fwd::RetryableFailure(_)));
        assert!(client.is_empty());
    }
    #[test]
    fn range_request_rejects_upstream_200() {
        use std::io::Cursor;
        let mut up = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab".to_vec());
        let mut client = Vec::new();
        let result = relay_checked_impl(&mut up, &mut client, false, true).unwrap();
        assert!(matches!(result, Fwd::RetryableStatus(200)));
        assert!(client.is_empty(), "200 不能作为 Range 响应透给客户端");
    }

    /// `RELAY-ERR` 的 `kind=` 必须能分开"上游不发数据了"与"正文真的不完整"。
    ///
    /// 实测依据（design.md §6）：chunked 响应且上游不按 `Connection: close` 关闭时，
    /// 代理会等到读超时（20.01 s）才收尾，而客户端 0.1 s 就拿到了完整内容。
    /// 这两种情况以前在日志里一模一样，很容易把"其实成功了"读成失败。
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
    fn final_403_is_returned_as_retryable_status_not_written() {
        use std::io::Cursor;
        let mut up = Cursor::new(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno".to_vec());
        let mut client = Vec::new();
        let result = relay_checked_impl(&mut up, &mut client, false, true).unwrap();
        assert!(matches!(result, Fwd::RetryableStatus(403)));
        assert!(client.is_empty(), "最终 403 也不能透传给客户端");
    }

    #[test]
    fn initial_probe_is_detected() {
        let head = http::parse_head(b"GET / HTTP/1.1\r\nRange: bytes=0-1\r\n\r\n").unwrap();
        assert!(is_initial_probe(&head));
        let full = http::parse_head(b"GET / HTTP/1.1\r\nRange: bytes=0-9\r\n\r\n").unwrap();
        assert!(!is_initial_probe(&full));
    }

    /// 带请求体的请求必须被判出来（然后回 501），否则会卡到 60 秒读超时。
    #[test]
    fn request_body_detection() {
        let with_len =
            http::parse_head(b"POST /x HTTP/1.1\r\nHost: github.com\r\nContent-Length: 15\r\n\r\n")
                .unwrap();
        assert!(has_request_body(&with_len), "Content-Length > 0 应判为带体");

        let zero = http::parse_head(b"POST /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n").unwrap();
        assert!(!has_request_body(&zero), "Content-Length: 0 不带体");

        let chunked =
            http::parse_head(b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        assert!(has_request_body(&chunked), "分块体长度未知，一律算带体");

        let get = http::parse_head(b"GET /x HTTP/1.1\r\nHost: github.com\r\n\r\n").unwrap();
        assert!(!has_request_body(&get), "普通 GET 不带体");

        // 畸形的 Content-Length 不该 panic，也不该被当成带体
        let bad = http::parse_head(b"POST /x HTTP/1.1\r\nContent-Length: nope\r\n\r\n").unwrap();
        assert!(!has_request_body(&bad));
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
