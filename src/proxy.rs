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
use crate::pac;
use crate::rewrite;
use crate::stats::Stats;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
/// 同一文件的候选绑定有效期。winget 下载一个包通常几十秒到几分钟。
const PIN_TTL: Duration = Duration::from_secs(600);

/// 一轮探测的并发数。6 是折中：43 个候选串行要 120 秒，全开对第三方不礼貌。
const PROBE_CONCURRENCY: usize = 6;

/// 单个候选的测速超时。
///
/// 从 15 秒降到 5 秒：候选池有 43 个后，15 秒意味着个别挂住的域名
/// 能拖垮整轮探测。5 秒足够拿到 64 KiB（实测最快 30 ms、最慢约 3 秒）。
const PROBE_SPEED_TIMEOUT: Duration = Duration::from_secs(5);

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

#[derive(Default)]
struct Cooldowns {
    inner: std::sync::Mutex<std::collections::HashMap<usize, std::time::Instant>>,
}

impl Cooldowns {
    fn block(&self, idx: usize, duration: Duration) {
        let mut inner = self.inner.lock().expect("cooldown lock poisoned");
        inner.insert(idx, std::time::Instant::now() + duration);
    }

    fn is_blocked(&self, idx: usize) -> bool {
        let inner = self.inner.lock().expect("cooldown lock poisoned");
        inner
            .get(&idx)
            .is_some_and(|exp| *exp > std::time::Instant::now())
    }

    fn active(&self) -> Vec<usize> {
        let now = std::time::Instant::now();
        let mut inner = self.inner.lock().expect("cooldown lock poisoned");
        inner.retain(|_, exp| *exp > now);
        inner.keys().copied().collect()
    }

    fn clear(&self, idx: usize) {
        let mut inner = self.inner.lock().expect("cooldown lock poisoned");
        inner.remove(&idx);
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
    /// 上一次观测到的"全挂"状态，用来只在**状态翻转**时报警，避免每请求刷日志。
    down: AtomicBool,
    /// Candidate failure cooldowns: index -> unblock instant.
    cooldowns: Cooldowns,
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
            cooldowns: Cooldowns::default(),
            pins: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// 阻塞式接受连接，每连接一个线程。
    pub fn serve(self: Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind(self.app.listen)
            .with_context(|| format!("端口被占用或不可用: {}", self.app.listen))?;

        self.spawn_health_prober();

        for incoming in listener.incoming() {
            match incoming {
                Ok(stream) => {
                    let peer = stream
                        .peer_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|_| "unknown".to_string());
                    let proxy = Arc::clone(&self);
                    std::thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
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
                return Err(anyhow!("读请求头失败: {err}"));
            }
        };

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
        let attempt_timeout = if initial_probe {
            Some(INITIAL_PROBE_ATTEMPT_TIMEOUT)
        } else {
            None
        };

        let started = std::time::Instant::now();
        let mut tried: Vec<usize> = Vec::new();
        if initial_probe {
            self.log
                .info(&format!("INITIAL-PROBE host={host} range=bytes=0-1"));
        }

        let (plan, accel_idx, accel, status, size, pin_hit) = loop {
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
                self.log.warn(&format!(
                    "NO-VERIFIED-ACCEL {host} 无已验证候选（未探测候选不会使用；已试 {} 个），返回 502",
                    tried.len()
                ));
                self.send_bad_gateway(&mut tls);
                return Ok(());
            };

            let plan = rewrite::plan(
                &req.method,
                host,
                port,
                &req.target,
                &req.headers,
                &self.app.rewrite_hosts,
                &accel,
            );

            // 关键：在写任何客户端字节前确定本次是否还可能重试。
            let allow_retry = retryable
                && plan.rewritten
                && tried.len() + 1 < failover_limit
                && started.elapsed() < failover_time;
            let outcome = match plan.scheme {
                rewrite::Scheme::Https => self.forward_tls(
                    &plan,
                    no_body,
                    expect_partial,
                    attempt_timeout,
                    &mut tls,
                    allow_retry,
                ),
                rewrite::Scheme::Http => self.forward_plain(
                    &plan,
                    no_body,
                    expect_partial,
                    attempt_timeout,
                    &mut tls,
                    allow_retry,
                ),
            };

            match outcome {
                Ok(Fwd::Done(status, size)) => {
                    break (plan, accel_idx, accel, status, size, from_pin);
                }
                Ok(Fwd::RetryableStatus(status)) => {
                    Stats::bump(&self.stats.errors);
                    if http::is_rate_limited(status) {
                        self.health.mark(accel_idx, false);
                        self.cooldowns.block(accel_idx, FAILURE_COOLDOWN);
                        self.log.warn(&format!(
                            "ACCEL-COOLDOWN {} for {}s: rate limited {status}",
                            accel.host,
                            FAILURE_COOLDOWN.as_secs()
                        ));
                        Stats::bump(&self.stats.ratelimited);
                    } else {
                        self.note_accel_failure(
                            accel_idx,
                            &accel,
                            &format!("upstream status {status}"),
                        );
                    }
                    self.log.warn(&format!(
                        "ACCEL-BAD-STATUS {} 返回 {status}，换下一个候选重试",
                        accel.host
                    ));
                    if initial_probe {
                        self.log.warn(&format!(
                            "INITIAL-PROBE-RETRY via={} status={status} tried={}",
                            accel.host,
                            tried.len()
                        ));
                    }
                    tried.push(accel_idx);
                    if !allow_retry {
                        self.send_bad_gateway(&mut tls);
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
                        self.note_accel_failure(accel_idx, &accel, &format!("{err:#}"));
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
                    self.log.warn(&format!(
                        "RELAY-ERR host={host} via={} retry={} elapsed={:.2}s pin_cleared={} path={} err={err:#}",
                        accel.host,
                        tried.len(),
                        started.elapsed().as_secs_f64(),
                        plan.rewritten,
                        crate::log::shorten(&plan.path, 100)
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
                self.cooldowns.clear(accel_idx);
                self.health
                    .record_sample(accel_idx, size, started.elapsed().as_secs_f64());
                self.pin(host, &req.target, accel_idx);
            } else {
                self.log.warn(&format!(
                    "ACCEL-BAD-STATUS {} 返回 {status}（{host}），不计样本、不绑定",
                    accel.host
                ));
            }
        }

        Stats::add(&self.stats.bytes, size);
        if plan.rewritten {
            if status >= 500 {
                self.note_accel_failure(accel_idx, &accel, &format!("上游返回 {status}"));
            } else if (200..300).contains(&status) {
                self.health.record_success(accel_idx);
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
            crate::log::shorten(&plan.path, 76),
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
                crate::log::shorten(&plan.path, 100)
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
    fn pin_key(host: &str, target: &str) -> String {
        format!("{host}{target}")
    }

    fn pin(&self, host: &str, target: &str, idx: usize) {
        let key = Self::pin_key(host, target);
        let mut pins = self.pins.lock().expect("pin 锁中毒");
        // 顺手清理过期项，避免长期占内存
        let now = std::time::Instant::now();
        pins.retain(|_, (_, exp)| *exp > now);
        if pins.len() < 512 {
            pins.insert(key, (idx, now + PIN_TTL));
        }
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
        excluded.extend(self.cooldowns.active());
        {
            let pins = self.pins.lock().expect("pin 锁中毒");
            if let Some((idx, exp)) = pins.get(&key) {
                if *exp > std::time::Instant::now()
                    && !excluded.contains(idx)
                    && !self.cooldowns.is_blocked(*idx)
                    && self.health.is_healthy(*idx)
                {
                    if let Some(accel) = self.health.accel_at(*idx) {
                        return Some((*idx, accel, true));
                    }
                }
            }
        }
        let picked = self.health.pick_verified_excluding(&excluded);
        if let Some((idx, a)) = &picked {
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
        picked.map(|(i, a)| (i, a, false))
    }
    /// 记一次加速器失败；跨过阈值时打一条告警（便于用户从日志判断是否被切换）。
    fn note_accel_failure(&self, idx: usize, accel: &rewrite::Accel, why: &str) {
        self.cooldowns.block(idx, FAILURE_COOLDOWN);
        self.log.warn(&format!(
            "ACCEL-COOLDOWN {} for {}s: {why}",
            accel.host,
            FAILURE_COOLDOWN.as_secs()
        ));
        if self.health.record_failure(idx) {
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
                "ALL-ACCEL-DOWN 所有加速器均不可用（{detail}）：请求会立即返回 502，后台继续重试"
            ));
        } else if !down && was_down {
            self.log.info(&format!(
                "ALL-ACCEL-RECOVERED 已有 {} 个加速器恢复可用",
                self.health.healthy_count()
            ));
        }
    }

    /// 周期探测所有候选。**单候选也探**——否则一旦被判死就永久 502，没有任何恢复路径。
    ///
    /// 只探各自 origin 的根路径，收到任意 HTTP 响应（含 404）即视为可达；
    /// 不能拿 GitHub 资产路径去探，受限网络下那里本身就不通，会把候选全部误判。
    fn spawn_health_prober(self: &Arc<Self>) {
        if !self.app.health_enabled {
            return;
        }
        let proxy = Arc::clone(self);

        std::thread::spawn(move || loop {
            proxy.probe_round();
            proxy.report_health_state();

            // 全挂时缩短重试间隔，让恢复更快被发现
            let wait = if proxy.down.load(Ordering::Relaxed) {
                Duration::from_secs(30)
            } else {
                proxy.app.health_interval
            };
            std::thread::sleep(wait);
        });
    }

    /// 一轮完整探测：**分批并发**，每批 [`PROBE_CONCURRENCY`] 个。
    ///
    /// 为什么要并发：候选池从 4 个涨到 43 个后，串行一轮要 120 秒
    /// （实测 5 个 14 秒）。这段时间内大部分候选是 `Unknown`，
    /// 权重只能按乐观值给，前几分钟的下载可能反复打到死候选。
    ///
    /// 为什么限 6 路而不是全开：
    /// - 这些是第三方免费服务，43 个一起打过去不礼貌，也容易触发 429；
    /// - 6 路 × 64 KiB 的瞬时流量对用户网络负担可忽略。
    ///
    /// 用分块 + `thread::scope` 而不是线程池：块内线程在 scope 结束时自动 join，
    /// 不需要额外的池实现，也不会泄漏线程。
    /// 实际重试上限：取常量与候选数中较小者（候选只有 2 个时不该允许试 3 次）。
    fn max_retries(&self) -> usize {
        MAX_ACCEL_RETRIES.min(self.health.accels().len().max(1))
    }

    /// Verify a small seed set before any download can use a candidate.
    /// Unknown candidates are intentionally not eligible for downloads.
    pub fn bootstrap_health(&self) {
        let list: Vec<(usize, rewrite::Accel)> =
            self.health.accels().iter().cloned().enumerate().collect();
        if list.is_empty() {
            self.log.error("NO-VERIFIED-ACCEL ???????????");
            return;
        }
        for chunk in list.chunks(PROBE_CONCURRENCY).take(1) {
            std::thread::scope(|scope| {
                for (idx, accel) in chunk {
                    scope.spawn(move || self.probe_one(*idx, accel));
                }
            });
        }
        let healthy = self.health.healthy_count();
        if healthy > 0 {
            self.log.info(&format!("HEALTH-READY ???????{healthy} ???"));
        } else {
            self.log
                .error("NO-VERIFIED-ACCEL ???????????????????????????? 502");
        }
    }

    fn probe_round(&self) {
        // 快照一份候选，避免持有锁跨线程
        let list: Vec<(usize, rewrite::Accel)> =
            self.health.accels().iter().cloned().enumerate().collect();

        for chunk in list.chunks(PROBE_CONCURRENCY) {
            std::thread::scope(|scope| {
                for (idx, accel) in chunk {
                    scope.spawn(move || self.probe_one(*idx, accel));
                }
            });
        }
    }

    /// 探测单个候选：先判可达，再量吞吐。
    fn probe_one(&self, idx: usize, accel: &rewrite::Accel) {
        let ok = probe(accel, self.app.health_timeout);
        self.health.mark(idx, ok);
        if !ok {
            self.log
                .log(Level::Debug, &format!("HEALTH {} -> fail", accel.host));
            return;
        }

        // 只判"明显不可用/太慢"，不做排序（排序靠真实下载样本）
        match probe_speed(accel, PROBE_SPEED_TIMEOUT) {
            Some(kbps) => {
                self.health.seed_speed(idx, kbps);
                self.log.log(
                    Level::Debug,
                    &format!("SPEED {} -> {:.0} KB/s", accel.host, kbps),
                );
            }
            None => {
                // 拿不到探测资产就是"没通过实测"，一律排除，内置的也一样。
                //
                // 这里曾经写成"内置候选保留可用"，理由是"探测资产不可达
                // 不代表服务不可用"。那个理由是错的，而且动机更错：
                // 当时是为了让协议用例通过才把生产逻辑改弱（夹具对探测请求
                // 返回 200 而不是 206，导致探测必然失败）。
                // 正确做法是让夹具正确响应，而不是放宽生产判据——
                // 没通过实测的候选不该进下载路径，内置的也一样。
                self.health.mark(idx, false);
                self.log.warn(&format!(
                    "SPEED {} -> 实测失败（非 206 或数据不足），已排除",
                    accel.host
                ));
            }
        }
    }

    fn forward_tls(
        &self,
        plan: &rewrite::Plan,
        no_body: bool,
        expect_partial: bool,
        attempt_timeout: Option<Duration>,
        tls: &mut StreamOwned<ServerConnection, TcpStream>,
        allow_retry: bool,
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

        let result = self.relay_checked(&mut upstream, tls, no_body, expect_partial, allow_retry);
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
        allow_retry: bool,
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

        self.relay_checked(&mut upstream, tls, no_body, expect_partial, allow_retry)
    }

    /// 先读上游响应头并转发；具体判定见 `relay_checked_impl`。
    fn relay_checked<R: std::io::Read>(
        &self,
        up: &mut R,
        tls: &mut StreamOwned<ServerConnection, TcpStream>,
        no_body: bool,
        expect_partial: bool,
        allow_retry: bool,
    ) -> Result<Fwd> {
        relay_checked_impl(up, tls, no_body, expect_partial, allow_retry)
    }
    /// 只在最终失败时调用；保证客户端只收到一个 502。
    fn send_bad_gateway(&self, tls: &mut StreamOwned<ServerConnection, TcpStream>) {
        let _ = tls.write_all(BAD_GATEWAY);
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

    /// 明文请求：只提供 PAC 与 health，其余 405。
    fn serve_local(&self, mut stream: TcpStream, req: &http::Head) -> Result<()> {
        let path = req.target.split('?').next().unwrap_or("");

        match (req.method.as_str(), path) {
            ("GET", "/winget-accel.pac") => {
                let peer = stream
                    .peer_addr()
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|_| "unknown".to_string());
                self.log.info(&format!("PAC-SERVED peer={peer}"));
                let body = pac::build(self.app.listen.port(), &self.app.rewrite_hosts);
                write_response(&mut stream, 200, "application/x-ns-proxy-autoconfig", &body)
            }
            ("GET", "/health") => {
                // 计数器 + 每个候选的健康状态 + 总体状态，交给 serde_json 序列化
                let speeds = self.health.speed_snapshot();
                let accelerators: Vec<crate::stats::AccelHealth> = self
                    .health
                    .snapshot()
                    .iter()
                    .enumerate()
                    .map(|(i, (host, health))| {
                        let (_, kbps, samples) =
                            speeds.get(i).cloned().unwrap_or((host.clone(), 0.0, 0));
                        crate::stats::AccelHealth {
                            host: host.clone(),
                            health: health.as_str(),
                            kbps: kbps.max(0.0) as u32,
                            samples,
                        }
                    })
                    .collect();
                let status = if self.health.all_unhealthy() {
                    "down"
                } else {
                    "ok"
                };
                let body = self.stats.health_json(status, accelerators);
                write_response(&mut stream, 200, "application/json", &body)
            }
            _ => write_response(
                &mut stream,
                405,
                "text/plain; charset=utf-8",
                "只支持 GET /winget-accel.pac 与 /health",
            ),
        }
    }
}

/// 读上游响应头并决定是否可以在写客户端前重试。
fn relay_checked_impl<R: std::io::Read, W: std::io::Write>(
    up: &mut R,
    client: &mut W,
    no_body: bool,
    expect_partial: bool,
    _allow_retry: bool,
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

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 403 | 404) || status >= 500
}
fn write_response(stream: &mut TcpStream, status: u16, ctype: &str, body: &str) -> Result<()> {
    let reason = match status {
        200 => "OK",
        405 => "Method Not Allowed",
        _ => "OK",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
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

/// 探测基准资产：用 release 资产（CDN 静态文件），不用 codeload 的 tag 归档。
///
/// 实测依据：`codeload` 的 tarball 在 5 个加速器里有 4 个返回 403/404/超时，
/// 用它当基准会把正常候选误判成不可用；而 release 资产 5/5 都返回 206。
/// 选 git-for-windows（组织级长期项目、固定 tag）比个人仓库更稳。
const PROBE_ASSET: &str = "https://github.com/git-for-windows/git/releases/download/v2.43.0.windows.1/Git-2.43.0-64-bit.exe";
/// 探测采样量。64 KB 实测约 1.6–1.9 秒（256 KB 要 5–7 秒），
/// 5 个候选串行才不会把启动拖到半分钟以上，且仍能分辨速度量级。
const PROBE_BYTES: u64 = 64 * 1024;

/// 通过加速器取一段固定资产，量出吞吐（KB/s）。
///
/// 返回 None 表示拿不到（非 206、或读到的字节数明显不足）。
fn probe_speed(accel: &rewrite::Accel, timeout: Duration) -> Option<f64> {
    let started = std::time::Instant::now();
    let mut upstream = match accel.scheme {
        rewrite::Scheme::Http => connect_tcp_timeout(&accel.host, accel.port, timeout).ok()?,
        rewrite::Scheme::Https => {
            let cfg = upstream_client_config();
            let name: Result<rustls::pki_types::ServerName<'static>, _> =
                accel.host.clone().try_into();
            let Ok(name) = name else { return None };
            let Ok(conn) = ClientConnection::new(cfg, name) else {
                return None;
            };
            let stream = connect_tcp_timeout(&accel.host, accel.port, timeout).ok()?;
            let s = StreamOwned::new(conn, stream);
            // 用 Box 统一类型太绕，这里直接分支处理
            return probe_speed_tls(s, accel, started);
        }
    };

    let head = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nRange: bytes=0-{}\r\nUser-Agent: winget-accel-probe\r\nConnection: close\r\n\r\n",
        rewrite::rewrite_path(accel, "github.com", &PROBE_ASSET["https://github.com".len()..]),
        rewrite::host_header(accel.scheme, &accel.host, accel.port),
        PROBE_BYTES - 1
    );
    upstream.write_all(head.as_bytes()).ok()?;
    upstream.flush().ok()?;
    read_probe_response(&mut upstream, started)
}

fn probe_speed_tls(
    mut s: StreamOwned<ClientConnection, TcpStream>,
    accel: &rewrite::Accel,
    started: std::time::Instant,
) -> Option<f64> {
    let head = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nRange: bytes=0-{}\r\nUser-Agent: winget-accel-probe\r\nConnection: close\r\n\r\n",
        rewrite::rewrite_path(accel, "github.com", &PROBE_ASSET["https://github.com".len()..]),
        rewrite::host_header(accel.scheme, &accel.host, accel.port),
        PROBE_BYTES - 1
    );
    s.write_all(head.as_bytes()).ok()?;
    s.flush().ok()?;
    read_probe_response(&mut s, started)
}

fn read_probe_response<R: Read>(up: &mut R, started: std::time::Instant) -> Option<f64> {
    let head = http::read_head(up).ok()?;
    if http::status_code(&head) != Some(206) {
        return None;
    }
    let mut sink = std::io::sink();
    let copied = http::forward_body(up, &mut sink, &head, false).ok()?;
    let secs = started.elapsed().as_secs_f64();
    if copied < PROBE_BYTES / 2 || secs <= 0.0 {
        return None;
    }
    Some((copied as f64 / 1024.0) / secs)
}
/// 探测加速器是否可达：打它自己的根路径，收到任意 HTTP 响应就算通。
pub fn probe(accel: &rewrite::Accel, timeout: Duration) -> bool {
    let Ok(stream) = connect_tcp_timeout(&accel.host, accel.port, timeout) else {
        return false;
    };
    // 健康探测必须受 health.timeoutSeconds 约束，不能被普通转发 IO_TIMEOUT 放大。
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: winget-accel-health\r\nConnection: close\r\n\r\n",
        rewrite::host_header(accel.scheme, &accel.host, accel.port)
    );

    match accel.scheme {
        rewrite::Scheme::Http => {
            let mut stream = stream;
            if stream.write_all(request.as_bytes()).is_err() {
                return false;
            }
            read_any(&mut stream)
        }
        rewrite::Scheme::Https => {
            let cfg = upstream_client_config();
            let name: Result<rustls::pki_types::ServerName<'static>, _> =
                accel.host.clone().try_into();
            let Ok(name) = name else {
                return false;
            };
            let Ok(conn) = ClientConnection::new(cfg, name) else {
                return false;
            };
            let mut tls = StreamOwned::new(conn, stream);
            if tls.write_all(request.as_bytes()).is_err() || tls.flush().is_err() {
                return false;
            }
            read_any(&mut tls)
        }
    }
}

fn read_any<R: Read>(src: &mut R) -> bool {
    let mut buf = [0u8; 64];
    matches!(src.read(&mut buf), Ok(n) if n > 0)
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
    #[test]
    fn retryable_status_is_not_written_to_client() {
        use std::io::Cursor;
        let mut up = Cursor::new(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".to_vec());
        let mut client = Vec::new();
        let result = relay_checked_impl(&mut up, &mut client, false, false, true).unwrap();
        assert!(matches!(result, Fwd::RetryableStatus(502)));
        assert!(client.is_empty(), "重试前不得向客户端写任何字节");
    }

    #[test]
    fn final_response_is_written_exactly_once() {
        use std::io::Cursor;
        let mut up = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec());
        let mut client = Vec::new();
        let result = relay_checked_impl(&mut up, &mut client, false, false, false).unwrap();
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
        let result = relay_checked_impl(&mut up, &mut client, false, false, false).unwrap();
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

        let first = relay_checked_impl(&mut bad, &mut client, false, false, true).unwrap();
        assert!(matches!(first, Fwd::RetryableStatus(502)));
        assert!(client.is_empty(), "第一次失败不能写客户端");

        let second = relay_checked_impl(&mut good, &mut client, false, false, false).unwrap();
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

        let first = relay_checked_impl(&mut bad, &mut client, false, false, true).unwrap();
        assert!(matches!(first, Fwd::RetryableStatus(502)));
        assert!(client.is_empty());

        let mut bad2 =
            Cursor::new(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".to_vec());
        let last = relay_checked_impl(&mut bad2, &mut client, false, false, false).unwrap();
        assert!(matches!(last, Fwd::RetryableStatus(502)));
        assert!(client.is_empty(), "最终坏状态由调用方统一合成 502");
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

    #[test]
    fn probe_returns_false_for_closed_port() {
        use std::net::TcpListener;
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
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
    fn malformed_upstream_head_is_retryable_without_client_write() {
        use std::io::Cursor;
        let mut up = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n".to_vec());
        let mut client = Vec::new();
        let result = relay_checked_impl(&mut up, &mut client, false, false, true).unwrap();
        assert!(matches!(result, Fwd::RetryableFailure(_)));
        assert!(client.is_empty());
    }
    #[test]
    fn range_request_rejects_upstream_200() {
        use std::io::Cursor;
        let mut up = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab".to_vec());
        let mut client = Vec::new();
        let result = relay_checked_impl(&mut up, &mut client, false, true, true).unwrap();
        assert!(matches!(result, Fwd::RetryableStatus(200)));
        assert!(client.is_empty(), "200 不能作为 Range 响应透给客户端");
    }
    #[test]
    fn cooldown_blocks_then_clears() {
        let cooldowns = Cooldowns::default();
        cooldowns.block(3, std::time::Duration::from_secs(30));
        assert!(cooldowns.is_blocked(3));
        assert!(cooldowns.active().contains(&3));
        cooldowns.clear(3);
        assert!(!cooldowns.is_blocked(3));
    }
    #[test]
    fn final_403_is_returned_as_retryable_status_not_written() {
        use std::io::Cursor;
        let mut up = Cursor::new(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno".to_vec());
        let mut client = Vec::new();
        let result = relay_checked_impl(&mut up, &mut client, false, true, false).unwrap();
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
}
