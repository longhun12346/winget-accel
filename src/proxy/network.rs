//! Async accept, Hyper CONNECT upgrades and TLS termination.
use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use super::{
    ActiveSlot, Proxy, TunnelSlot, CONNECT_TIMEOUT, FIRST_REQUEST_TIMEOUT, IO_TIMEOUT,
    MAX_CONNECTIONS, MAX_TUNNELS,
};
use crate::{http, log::Level, stats::Stats};

type Reply = Response<http::BoxBody>;

impl Proxy {
    /// Reserve slots at accept, including clients that have sent no bytes yet.
    pub fn serve(self: Arc<Self>, listener: std::net::TcpListener) -> Result<()> {
        self.spawn_health_prober();
        listener.set_nonblocking(true)?;
        http::block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener)?;
            // Bounded spare connections let PAC/health work during download saturation.
            let spare = Arc::new(tokio::sync::Semaphore::new(16));
            loop {
                let (mut stream, peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(err) => {
                        self.log.warn(&format!("ACCEPT-FAIL {err}"));
                        continue;
                    }
                };
                let n = self.active.fetch_add(1, Ordering::Relaxed);
                let saturated = n >= MAX_CONNECTIONS;
                let slot = if saturated {
                    self.active.fetch_sub(1, Ordering::Relaxed);
                    None
                } else {
                    Some(Arc::new(ActiveSlot(self.clone())))
                };
                let extra = if saturated {
                    match spare.clone().try_acquire_owned() {
                        Ok(permit) => Some(permit),
                        Err(_) => {
                            Stats::bump(&self.stats.conn_limited);
                            continue;
                        }
                    }
                } else {
                    None
                };
                let proxy = self.clone();
                tokio::spawn(async move {
                    let _extra = extra;
                    if saturated {
                        let mut byte = [0];
                        if !matches!(
                            timeout(Duration::from_millis(200), stream.peek(&mut byte)).await,
                            Ok(Ok(1..))
                        ) {
                            Stats::bump(&proxy.stats.conn_limited);
                            // No HTTP request exists for Hyper to answer on an idle excess socket.
                            let _ = timeout(Duration::from_secs(1), async {
                                stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                                stream.shutdown().await
                            }).await;
                            return;
                        }
                    }
                    Stats::bump(&proxy.stats.connects);
                    proxy
                        .log
                        .log(Level::Debug, &format!("CONN-ACCEPT peer={peer}"));
                    let service_proxy = proxy.clone();
                    let service = service_fn(move |request| {
                        let proxy = service_proxy.clone();
                        let slot = slot.clone();
                        async move {
                            let reply = if http::oversized_request(&request) {
                                Stats::bump(&proxy.stats.errors);
                                http::response(431, "text/plain", "")
                            } else if saturated {
                                if request.method() == "GET"
                                    && matches!(
                                        request.uri().path(),
                                        "/health" | "/winget-accel.pac"
                                    )
                                {
                                    proxy.local_response(&request, &peer.to_string())
                                } else {
                                    Stats::bump(&proxy.stats.conn_limited);
                                    http::response(503, "text/plain", "")
                                }
                            } else if request.method() == "CONNECT" {
                                proxy
                                    .connect(request, slot.expect("reserved connection slot"))
                                    .await
                            } else {
                                proxy.local_response(&request, &peer.to_string())
                            };
                            Ok::<_, Infallible>(reply)
                        }
                    });
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder
                        .keep_alive(false)
                        .max_buf_size(http::MAX_SERVER_HEAD_BUFFER)
                        .timer(TokioTimer::new())
                        .header_read_timeout(if saturated {
                            Duration::from_millis(200)
                        } else {
                            FIRST_REQUEST_TIMEOUT
                        });
                    if let Err(err) = builder
                        .serve_connection(TokioIo::new(http::timed(stream, IO_TIMEOUT)), service)
                        .with_upgrades()
                        .await
                    {
                        Stats::bump(&proxy.stats.errors);
                        proxy.log.warn(&format!("CONN-FAIL peer={peer} {err:#}"));
                    }
                });
            }
            #[allow(unreachable_code)]
            Ok(())
        })
    }

    async fn connect(self: Arc<Self>, mut req: Request<Incoming>, slot: Arc<ActiveSlot>) -> Reply {
        let (host, port) = match super::split_host_port(&req.uri().to_string()) {
            Ok(target) => target,
            Err(err) => {
                self.log.warn(&format!("CONNECT-INVALID {err:#}"));
                return http::response(400, "text/plain", "");
            }
        };
        let mitm = self.app.should_mitm(&host);
        self.log.info(&format!(
            "CONNECT {host}:{port} mode={}",
            if mitm { "MITM" } else { "TUNNEL" }
        ));
        if mitm {
            Stats::bump(&self.stats.mitm);
            let ca = self.ca.clone();
            let cert_host = host.clone();
            let cfg = match tokio::task::spawn_blocking(move || ca.server_config(&cert_host)).await
            {
                Ok(Ok(cfg)) => cfg,
                _ => {
                    Stats::bump(&self.stats.errors);
                    return http::response(502, "text/plain", "");
                }
            };
            let upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                let _slot = slot;
                let result = async {
                    let upgraded = upgrade.await?;
                    let tls = timeout(
                        CONNECT_TIMEOUT,
                        tokio_rustls::TlsAcceptor::from(cfg).accept(TokioIo::new(upgraded)),
                    )
                    .await
                    .context("client TLS handshake timeout")??;
                    self.clone().serve_mitm(tls, host.clone(), port).await
                }
                .await;
                if let Err(err) = result {
                    Stats::bump(&self.stats.errors);
                    self.log.warn(&format!("MITM-READ-FAIL {host} {err:#}"));
                }
            });
        } else {
            if self.tunnels.fetch_add(1, Ordering::Relaxed) >= MAX_TUNNELS {
                self.tunnels.fetch_sub(1, Ordering::Relaxed);
                Stats::bump(&self.stats.conn_limited);
                self.log.warn(&format!("TUNNEL-LIMIT {host}:{port}"));
                return http::response(503, "text/plain", "");
            }
            let tunnel_slot = TunnelSlot(self.clone());
            let upstream = match crate::http::connect_tcp(&host, port, CONNECT_TIMEOUT).await {
                Ok(stream) => stream,
                Err(error) => {
                    Stats::bump(&self.stats.errors);
                    self.log
                        .warn(&format!("TUNNEL-CONNECT-FAIL {host}:{port} {error:#}"));
                    return http::response(502, "text/plain", "");
                }
            };
            Stats::bump(&self.stats.tunnel);
            let upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                let _slot = slot;
                let _tunnel_slot = tunnel_slot;
                let result = async {
                    let mut client = http::timed(TokioIo::new(upgrade.await?), IO_TIMEOUT);
                    let mut upstream = http::timed(upstream, IO_TIMEOUT);
                    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if let Err(err) = result {
                    self.log.warn(&format!("TUNNEL-FAIL {host}:{port} {err:#}"));
                }
            });
        }
        let mut response = http::response(200, "text/plain", "");
        response.headers_mut().remove("connection");
        response
    }

    async fn serve_mitm<I>(self: Arc<Self>, io: I, host: String, port: u16) -> Result<()>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let service = service_fn(move |req| {
            let proxy = self.clone();
            let host = host.clone();
            async move {
                let response = if http::oversized_request(&req) {
                    Stats::bump(&proxy.stats.errors);
                    http::response(431, "text/plain", "")
                } else {
                    proxy.download(req, &host, port).await
                };
                Ok::<_, Infallible>(response)
            }
        });
        hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .max_buf_size(http::MAX_SERVER_HEAD_BUFFER)
            .timer(TokioTimer::new())
            .header_read_timeout(FIRST_REQUEST_TIMEOUT)
            .serve_connection(TokioIo::new(http::timed(io, IO_TIMEOUT)), service)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn upstream_connect_resolves_and_connects_to_a_local_listener() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
        let port = listener.local_addr().expect("listener address").port();
        let thread = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let result = crate::http::block_on(crate::http::connect_tcp(
            "127.0.0.1",
            port,
            Duration::from_secs(2),
        ));
        assert!(result.is_ok(), "{result:?}");
        thread.join().expect("listener thread");
    }

    #[test]
    fn upstream_connect_reports_empty_or_unresolvable_targets() {
        let result = crate::http::block_on(crate::http::connect_tcp(
            "does-not-exist.invalid",
            443,
            Duration::from_millis(250),
        ));
        assert!(result.is_err());
        let text = format!("{:#}", result.unwrap_err());
        assert!(
            text.contains("DNS") || text.contains("addresses") || text.contains("connect"),
            "{text}"
        );
    }
}
