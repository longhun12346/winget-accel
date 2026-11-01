//! 监听、CONNECT 分流、隧道与 MITM 改写。
//!
//! 分流规则（ADR-014 约束 2）：只有 `rewrite_hosts`（含 `--mitm-extra`）会被终止 TLS，
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
/// 一次上游尝试的结果。
///
/// 拆成三态是为了支持"换候选重试"：
/// 429/503 时上游还没把任何字节转发给客户端，可以安全地换一个候选；
/// 而一旦开始转发正文，就不能再改主意了。
enum Fwd {
    Done(u16, u64),
    RateLimited(u16),
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
            pins: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// 阻塞式接受连接，每连接一个线程。
    pub fn serve(self: Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind(self.app.listen)
            .with_context(|| format!("端口被占用或不可用: {}", self.app.listen))?;
        self.log.info(&format!("LISTEN {}", self.app.listen));

        self.spawn_health_prober();

        for incoming in listener.incoming() {
            match incoming {
                Ok(stream) => {
                    let proxy = Arc::clone(&self);
                    std::thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                        if let Err(err) = proxy.handle_client(stream) {
                            proxy.log.warn(&format!("CONN-FAIL {err:#}"));
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
            return Err(anyhow!("请求头无法解析"));
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
        let upstream = connect_tcp(host, port)?;
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
        // 只有幂等方法才允许换候选重试（GET/HEAD）。
        // 这里的请求都是下载，正常情况下都是 GET。
        let retryable = req.method.eq_ignore_ascii_case("GET") || no_body;

        let started = std::time::Instant::now();
        let mut tried: Vec<usize> = Vec::new();

        // 换候选重试循环：遇到 429/503（限流/暂时不可用）就把该候选标记为不可用，
        // 换下一个再试。不把 429 直接透给客户端——winget 收到就失败了，
        // 而我们还有别的候选可用。
        let (plan, accel_idx, accel, status, size, pin_hit) = loop {
            let Some((accel_idx, accel, from_pin)) = self.pick_for(host, &req.target, &tried) else {
                // 没有可用候选（或都已试过）
                Stats::bump(&self.stats.errors);
                self.log.warn(&format!(
                    "NO-HEALTHY-ACCEL {host} 无可用加速器（已试 {} 个），返回 502",
                    tried.len()
                ));
                let _ = tls.write_all(BAD_GATEWAY);
                tls.conn.send_close_notify();
                let _ = tls.flush();
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

            let outcome = match plan.scheme {
                rewrite::Scheme::Https => self.forward_tls(&plan, no_body, &mut tls),
                rewrite::Scheme::Http => self.forward_plain(&plan, no_body, &mut tls),
            };

            match outcome {
                Ok(Fwd::Done(status, size)) => {
                    // 加速器对某个资产返回 403/404，往往意味着"它不支持这个路径"，
                    // 而不是资产真的不存在——换一个候选重试更可能成功。
                    // 实测：fzf 和 ripgrep 各失败过一次，就是因为第一个候选返回 404
                    // 而响应被直接透给了 winget。
                    // 403/404：该加速器可能不支持这个路径
                    // 5xx：加速器自身出错（实测 imciel 会返回 502）
                    // 两类都换候选，都不该直接透给 winget —— 透过去就是下载失败。
                    let bad_status = matches!(status, 403 | 404) || status >= 500;
                    if plan.rewritten && bad_status && retryable && tried.len() + 1 < self.health.accels().len() {
                        self.log.warn(&format!(
                            "ACCEL-BAD-STATUS {} 返回 {status}，换下一个候选重试",
                            accel.host
                        ));
                        tried.push(accel_idx);
                        continue;
                    }
                    break (plan, accel_idx, accel, status, size, from_pin);
                }
                Ok(Fwd::RateLimited(status)) => {
                    // 上游明确让我们退避：立即标记该候选不可用并换下一个。
                    // 用 mark(false) 而不是计入失败次数——这是服务端的确定信号。
                    self.health.mark(accel_idx, false);
                    Stats::bump(&self.stats.ratelimited);
                    self.log.warn(&format!(
                        "ACCEL-RATELIMITED {} 返回 {status}，换下一个候选",
                        accel.host
                    ));
                    tried.push(accel_idx);
                    if !retryable || tried.len() >= self.health.accels().len() {
                        Stats::bump(&self.stats.errors);
                        let _ = tls.write_all(BAD_GATEWAY);
                        tls.conn.send_close_notify();
                        let _ = tls.flush();
                        return Ok(());
                    }
                }
                Err(err) => {
                    Stats::bump(&self.stats.errors);
                    self.log.warn(&format!(
                        "UPSTREAM-FAIL {host} -> {}:{} {err:#}",
                        plan.host, plan.port
                    ));
                    if plan.rewritten {
                        self.note_accel_failure(accel_idx, &accel, &format!("{err:#}"));
                    }
                    tried.push(accel_idx);
                    if !retryable || tried.len() >= self.health.accels().len() {
                        let _ = tls.write_all(BAD_GATEWAY);
                        tls.conn.send_close_notify();
                        let _ = tls.flush();
                        return Ok(());
                    }
                    self.log.warn(&format!("RETRY {host} 换下一个候选"));
                }
            }
        };

        if plan.rewritten {
            Stats::bump(&self.stats.rewrites);
            // 只有 2xx 才算"这次候选真的服务成功"。
            // 实测教训：把 404 也当成功去 pin 和记样本，会让同一文件的后续分片
            // 全部钉在这个坏候选上，整个下载直接失败（fzf/ripgrep 各失败一次）。
            if (200..300).contains(&status) {
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

        {
            {
                Stats::add(&self.stats.bytes, size);
                // 只有"被改写的请求"才把成败记到加速器账上；
                // 隧道路径的失败属于目标站，与加速器无关。
                if plan.rewritten {
                    if status >= 500 {
                        self.note_accel_failure(accel_idx, &accel, &format!("上游返回 {status}"));
                    } else {
                        self.health.record_success(accel_idx);
                        self.report_health_state();
                    }
                }
                let tag = if plan.rewritten { "REWRITE" } else { "PASS" };
                // 带上实际使用的加速器：否则日志无法回答"这次是哪个候选在服务"
                let via = if plan.rewritten { accel.host.as_str() } else { "-" };
                let pin = if pin_hit { "pin" } else { "pick" };
                self.log.info(&format!(
                    "{tag} via={via} {pin} retries={} {host}{} -> {status} {size}B {:.2}s",
                    tried.len(),
                    truncate(&plan.path, 90),
                    started.elapsed().as_secs_f64()
                ));
                // 非 2xx 单独告警：这是"用户看到下载失败"的直接原因，
                // 必须在日志里一眼能找到，否则只能靠猜（前几轮就是这么浪费掉的）。
                if plan.rewritten && !(200..300).contains(&status) {
                    let elapsed = started.elapsed().as_secs_f64();
                    let speed = if elapsed > 0.0 {
                        (size as f64 / 1024.0) / elapsed
                    } else {
                        0.0
                    };
                    self.log.warn(&format!(
                        "REWRITE-FAILED via={via} status={status} size={size}B {speed:.0}KB/s tried={tried:?} path={}",
                        truncate(&plan.path, 120)
                    ));
                }
            }
        }

        // 必须发 close_notify，否则客户端会把"连接被重置"当成下载失败
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

    /// 选候选：优先复用同一文件的 pin，否则加权随机。
    fn pick_for(
        &self,
        host: &str,
        target: &str,
        tried: &[usize],
    ) -> Option<(usize, crate::rewrite::Accel, bool)> {
        let key = Self::pin_key(host, target);
        {
            let pins = self.pins.lock().expect("pin 锁中毒");
            if let Some((idx, exp)) = pins.get(&key) {
                if *exp > std::time::Instant::now() && !tried.contains(idx) {
                    if let Some(accel) = self.health.accel_at(*idx) {
                        return Some((*idx, accel, true));
                    }
                }
            }
        }
        let picked = self.health.pick_excluding(tried);
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
            for (idx, accel) in proxy.health.accels().iter().enumerate() {
                let ok = probe(accel, proxy.app.health_timeout);
                proxy.health.mark(idx, ok);
                if !ok {
                    proxy.log.log(Level::Debug, &format!("HEALTH {} -> fail", accel.host));
                    continue;
                }
                // 只判"明显不可用/太慢"，不做排序（排序靠真实下载样本）
                match probe_speed(accel, Duration::from_secs(15)) {
                    Some(kbps) => {
                        proxy.health.seed_speed(idx, kbps);
                        proxy
                            .log
                            .log(Level::Debug, &format!("SPEED {} -> {:.0} KB/s", accel.host, kbps));
                    }
                    None => {
                        // 拿不到探测资产**不等于服务不可用**：可能它不支持这个资产、
                        // 或资产本身有问题。所以不判死，只表示"没有速度数据"，
                        // 该候选按乐观权重参与选择（见 pick_excluding）。
                        //
                        // 之前的写法在这里 mark(false)，导致唯一候选被误判为全挂、
                        // 所有请求 502 —— 协议用例直接抓到（3 个失败）。
                        proxy.log.log(
                            Level::Debug,
                            &format!("SPEED {} -> 无数据（保留可用）", accel.host),
                        );
                    }
                }
            }
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

    fn forward_tls(
        &self,
        plan: &rewrite::Plan,
        no_body: bool,
        tls: &mut StreamOwned<ServerConnection, TcpStream>,
    ) -> Result<Fwd> {
        let mut upstream = match self.open_tls_upstream(plan) {
            Ok(stream) => stream,
            // 这里还没往客户端写任何字节，可以安全地回 502
            Err(err) => return Ok(self.bad_gateway(plan, tls, err)),
        };

        if let Err(err) = upstream.write_all(&plan.head).and_then(|()| upstream.flush()) {
            return Ok(self.bad_gateway(plan, tls, err.into()));
        }

        let result = self.relay_checked(&mut upstream, tls, no_body);
        upstream.conn.send_close_notify();
        result
    }

    fn forward_plain(
        &self,
        plan: &rewrite::Plan,
        no_body: bool,
        tls: &mut StreamOwned<ServerConnection, TcpStream>,
    ) -> Result<Fwd> {
        let mut upstream = match connect_tcp(&plan.host, plan.port) {
            Ok(stream) => stream,
            Err(err) => return Ok(self.bad_gateway(plan, tls, err)),
        };

        if let Err(err) = upstream.write_all(&plan.head).and_then(|()| upstream.flush()) {
            return Ok(self.bad_gateway(plan, tls, err.into()));
        }

        self.relay_checked(&mut upstream, tls, no_body)
    }

    /// 先读上游响应头，遇到 429/503 就**不转发**、直接报告限流，让调用方换候选。
    ///
    /// 这一点必须是"先判后转"：一旦把响应头发给客户端，就没法再换候选了。
    fn relay_checked<R: std::io::Read>(
        &self,
        up: &mut R,
        tls: &mut StreamOwned<ServerConnection, TcpStream>,
        no_body: bool,
    ) -> Result<Fwd> {
        let head = http::read_head(up)?;
        let status = http::status_code(&head).unwrap_or(0);

        if http::is_rate_limited(status) {
            return Ok(Fwd::RateLimited(status));
        }

        tls.write_all(&head)?;
        tls.flush()?;
        let size = http::forward_body(up, tls, &head, no_body)?;
        Ok(Fwd::Done(status, size))
    }
    fn open_tls_upstream(
        &self,
        plan: &rewrite::Plan,
    ) -> Result<StreamOwned<ClientConnection, TcpStream>> {
        let cfg = upstream_client_config();
        let server_name: rustls::pki_types::ServerName<'static> = plan
            .host
            .clone()
            .try_into()
            .map_err(|_| anyhow!("上游主机名非法: {}", plan.host))?;
        let conn = ClientConnection::new(cfg, server_name).context("构造 TLS 客户端会话失败")?;
        let stream = connect_tcp(&plan.host, plan.port)?;
        Ok(StreamOwned::new(conn, stream))
    }

    fn bad_gateway(
        &self,
        plan: &rewrite::Plan,
        tls: &mut StreamOwned<ServerConnection, TcpStream>,
        err: anyhow::Error,
    ) -> Fwd {
        // 契约要求：加速器不可达时 errors 计数 +1（docs/test-plan.md ERR-02）
        Stats::bump(&self.stats.errors);
        self.log.warn(&format!(
            "UPSTREAM-FAIL {}:{} {err:#}",
            plan.host, plan.port
        ));
        let _ = tls.write_all(BAD_GATEWAY);
        Fwd::Done(502, 0)
    }

    /// 明文请求：只提供 PAC 与 health，其余 405。
    fn serve_local(&self, mut stream: TcpStream, req: &http::Head) -> Result<()> {
        let path = req.target.split('?').next().unwrap_or("");

        match (req.method.as_str(), path) {
            ("GET", "/winget-accel.pac") => {
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
                        let (_, kbps, samples) = speeds
                            .get(i)
                            .cloned()
                            .unwrap_or((host.clone(), 0.0, 0));
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
            _ => write_response(&mut stream, 405, "text/plain; charset=utf-8", "只支持 GET /winget-accel.pac 与 /health"),
        }
    }
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
            let name: Result<rustls::pki_types::ServerName<'static>, _> = accel.host.clone().try_into();
            let Ok(name) = name else { return None };
            let Ok(conn) = ClientConnection::new(cfg, name) else { return None };
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

fn truncate(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        text
    } else {
        &text[..limit]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_host_port() {
        assert_eq!(split_host_port("github.com:443").unwrap(), ("github.com".into(), 443));
        assert_eq!(split_host_port("[::1]:8443").unwrap(), ("::1".into(), 8443));
    }

    #[test]
    fn rejects_targets_without_port() {
        assert!(split_host_port("github.com").is_err());
        assert!(split_host_port(":443").is_err());
    }

    #[test]
    fn truncate_keeps_short_text() {
        assert_eq!(truncate("abc", 10), "abc");
    }
}
















