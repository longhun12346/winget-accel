//! 监听、CONNECT 分流、隧道与 MITM 改写。
//!
//! 分流规则（ADR-014 约束 2）：只有 `rewrite_hosts`（含 `--mitm-extra`）会被终止 TLS，
//! 其余 host 一律原样隧道——我们不解析、不记录、不改写那些流量。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
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

pub struct Proxy {
    pub app: Arc<App>,
    pub ca: Arc<CertAuthority>,
    pub stats: Arc<Stats>,
    pub log: Arc<Logger>,
    pub health: Arc<Tracker>,
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

        let Some((accel_idx, accel)) = self.health.current() else {
            // 全挂时快速失败。刻意不"回退到原始 URL"：受限网络下直连 GitHub
            // 本身就是卡死，那会让 winget 长时间无响应（roadmap 风险表）。
            Stats::bump(&self.stats.errors);
            self.log.warn(&format!(
                "NO-HEALTHY-ACCEL {host} 所有加速器都不健康，返回 502"
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

        if plan.rewritten {
            Stats::bump(&self.stats.rewrites);
        }

        let no_body = req.method.eq_ignore_ascii_case("HEAD");
        let started = std::time::Instant::now();

        let outcome = match plan.scheme {
            rewrite::Scheme::Https => self.forward_tls(&plan, no_body, &mut tls),
            rewrite::Scheme::Http => self.forward_plain(&plan, no_body, &mut tls),
        };

        match outcome {
            Ok((status, size)) => {
                Stats::add(&self.stats.bytes, size);
                // 只有"被改写的请求"才把成败记到加速器账上；
                // 隧道路径的失败属于目标站，与加速器无关。
                if plan.rewritten {
                    if status >= 500 {
                        self.note_accel_failure(accel_idx, &accel, &format!("上游返回 {status}"));
                    } else {
                        self.health.record_success(accel_idx);
                    }
                }
                let tag = if plan.rewritten { "REWRITE" } else { "PASS" };
                self.log.info(&format!(
                    "{tag} {host}{} -> {status} {size}B {:.2}s",
                    truncate(&plan.path, 90),
                    started.elapsed().as_secs_f64()
                ));
            }
            Err(err) => {
                Stats::bump(&self.stats.errors);
                // 不在这里写 502：失败可能发生在响应已经发出一半之后，
                // 再追加一段状态行只会把响应彻底搞坏。连接会直接关闭。
                self.log.warn(&format!(
                    "UPSTREAM-FAIL {host} -> {}:{} {err:#}",
                    plan.host, plan.port
                ));
                if plan.rewritten {
                    self.note_accel_failure(accel_idx, &accel, &format!("{err:#}"));
                }
            }
        }

        // 必须发 close_notify，否则客户端会把"连接被重置"当成下载失败
        tls.conn.send_close_notify();
        let _ = tls.flush();
        let _ = tls.sock.shutdown(std::net::Shutdown::Both);
        Ok(())
    }

    /// 记一次加速器失败；跨过阈值时打一条告警（便于用户从日志判断是否被切换）。
    fn note_accel_failure(&self, idx: usize, accel: &rewrite::Accel, why: &str) {
        if self.health.record_failure(idx) {
            self.log.warn(&format!(
                "ACCEL-UNHEALTHY {} 连续失败达阈值（{why}），改用下一个候选",
                accel.host
            ));
        }
    }

    /// 周期探测所有候选。只探各自 origin 的根路径，
    /// 收到任意 HTTP 响应（含 404）即视为可达——不能拿 GitHub 资产路径去探，
    /// 受限网络下那里本身就不通，会把所有候选一起误判为不健康。
    fn spawn_health_prober(&self) {
        if !self.app.health_enabled || self.health.accels().len() < 2 {
            return;
        }
        let health = Arc::clone(&self.health);
        let log = Arc::clone(&self.log);
        let timeout = self.app.health_timeout;
        let interval = self.app.health_interval;

        std::thread::spawn(move || loop {
            for (idx, accel) in health.accels().iter().enumerate() {
                let ok = probe(accel, timeout);
                health.mark(idx, ok);
                log.log(
                    Level::Debug,
                    &format!(
                        "HEALTH {} -> {}",
                        accel.host,
                        if ok { "ok" } else { "fail" }
                    ),
                );
            }
            std::thread::sleep(interval);
        });
    }

    fn forward_tls(
        &self,
        plan: &rewrite::Plan,
        no_body: bool,
        tls: &mut StreamOwned<ServerConnection, TcpStream>,
    ) -> Result<(u16, u64)> {
        let mut upstream = match self.open_tls_upstream(plan) {
            Ok(stream) => stream,
            // 这里还没往客户端写任何字节，可以安全地回 502
            Err(err) => return Ok(self.bad_gateway(plan, tls, err)),
        };

        if let Err(err) = upstream.write_all(&plan.head).and_then(|()| upstream.flush()) {
            return Ok(self.bad_gateway(plan, tls, err.into()));
        }

        let result = http::relay_response(&mut upstream, tls, no_body);
        upstream.conn.send_close_notify();
        result.map_err(Into::into)
    }

    fn forward_plain(
        &self,
        plan: &rewrite::Plan,
        no_body: bool,
        tls: &mut StreamOwned<ServerConnection, TcpStream>,
    ) -> Result<(u16, u64)> {
        let mut upstream = match connect_tcp(&plan.host, plan.port) {
            Ok(stream) => stream,
            Err(err) => return Ok(self.bad_gateway(plan, tls, err)),
        };

        if let Err(err) = upstream.write_all(&plan.head).and_then(|()| upstream.flush()) {
            return Ok(self.bad_gateway(plan, tls, err.into()));
        }

        http::relay_response(&mut upstream, tls, no_body).map_err(Into::into)
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
    ) -> (u16, u64) {
        // 契约要求：加速器不可达时 errors 计数 +1（docs/test-plan.md ERR-02）
        Stats::bump(&self.stats.errors);
        self.log.warn(&format!(
            "UPSTREAM-FAIL {}:{} {err:#}",
            plan.host, plan.port
        ));
        let _ = tls.write_all(BAD_GATEWAY);
        (502, 0)
    }

    /// 明文请求：只提供 PAC 与 health，其余 405。
    fn serve_local(&self, mut stream: TcpStream, req: &http::Head) -> Result<()> {
        let path = req.target.split('?').next().unwrap_or("");

        match (req.method.as_str(), path) {
            ("GET", "/proxy.pac") => {
                let body = pac::build(self.app.listen.port(), &self.app.rewrite_hosts);
                write_response(&mut stream, 200, "application/x-ns-proxy-autoconfig", &body)
            }
            ("GET", "/health") => {
                // 在计数器之外附上每个候选的健康状态，便于排障时一眼看出切换到了谁
                let mut body = self.stats.to_json();
                let accels: Vec<String> = self
                    .health
                    .snapshot()
                    .iter()
                    .map(|(host, health)| {
                        format!("{{\"host\":\"{host}\",\"health\":\"{}\"}}", health.as_str())
                    })
                    .collect();
                body.insert_str(
                    body.len() - 1,
                    &format!(",\"accelerators\":[{}]", accels.join(",")),
                );
                write_response(&mut stream, 200, "application/json", &body)
            }
            _ => write_response(&mut stream, 405, "text/plain; charset=utf-8", "只支持 GET /proxy.pac 与 /health"),
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
