//! Hyper HTTP/1.1 transport shared by downloads, probes and local diagnostics.
//! Hyper owns parsing, message boundaries and CONNECT read-ahead; this module
//! supplies explicit routing, bounded reads and application completion callbacks.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use bytes::Bytes;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Empty, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::{HeaderMap, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::time::timeout;
use tokio_io_timeout::TimeoutStream;

use crate::rewrite::Scheme;

pub const MAX_HEAD: usize = 32 * 1024;
/// Leave parser headroom to turn moderately oversized requests into a
/// deterministic 431 response instead of letting Hyper reset the socket
/// before the service can inspect the request. The service still enforces
/// [`MAX_HEAD`] as the actual request-header budget.
pub const MAX_SERVER_HEAD_BUFFER: usize = MAX_HEAD * 2;
pub const IO_TIMEOUT: Duration = Duration::from_secs(60);
pub type BoxBody = UnsyncBoxBody<Bytes, anyhow::Error>;

/// Synchronous Windows lifecycle and diagnostic workers share one async runtime.
/// Never call this bridge from a runtime task; proxy services use async APIs directly.
pub fn block_on<F: Future>(future: F) -> F::Output {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .expect("create network runtime")
        })
        .block_on(future)
}

/// Either direction making progress keeps the connection alive. Hyper may poll
/// reads while streaming a response, so independent read deadlines are incorrect.
pub struct IdleStream<S> {
    inner: Pin<Box<TimeoutStream<S>>>,
    duration: Duration,
}

pub fn timed<S: AsyncRead + AsyncWrite>(stream: S, duration: Duration) -> IdleStream<S> {
    let mut stream = TimeoutStream::new(stream);
    stream.set_read_timeout(Some(duration));
    stream.set_write_timeout(Some(duration));
    IdleStream {
        inner: Box::pin(stream),
        duration,
    }
}

/// Resolve all addresses before connecting and prefer IPv4.
///
/// A hostname can resolve to an unreachable IPv6 address and a usable IPv4
/// address. Keep DNS and every connection attempt inside one shared deadline
/// so both ordinary upstream requests and CONNECT tunnels behave consistently.
pub async fn connect_tcp(host: &str, port: u16, budget: Duration) -> Result<TcpStream> {
    let deadline = tokio::time::Instant::now() + budget;
    let addresses = timeout(
        deadline.saturating_duration_since(tokio::time::Instant::now()),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .context("upstream DNS timeout")?
    .context("upstream DNS lookup failed")?;
    let mut addresses: Vec<_> = addresses.collect();
    addresses.sort_by_key(|address| if address.is_ipv4() { 0 } else { 1 });
    connect_addresses(
        addresses,
        deadline.saturating_duration_since(tokio::time::Instant::now()),
    )
    .await
}

/// Race resolved addresses with a small stagger, while sharing one deadline.
///
/// Sequential fallback is insufficient when the first IPv4 route silently
/// drops SYN packets: one address can consume the entire budget before a
/// healthy address is tried. A short stagger avoids a burst while allowing a
/// later address to win without waiting for the first one to time out.
async fn connect_addresses(addresses: Vec<SocketAddr>, budget: Duration) -> Result<TcpStream> {
    if addresses.is_empty() {
        return Err(anyhow!("upstream DNS returned no addresses"));
    }

    const ADDRESS_STAGGER: Duration = Duration::from_millis(200);
    let deadline = tokio::time::Instant::now() + budget;
    let mut tasks = tokio::task::JoinSet::new();
    for (index, address) in addresses.into_iter().enumerate() {
        let start_after = ADDRESS_STAGGER.saturating_mul(index as u32);
        tasks.spawn(async move {
            if !start_after.is_zero() {
                tokio::time::sleep(start_after).await;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(format!("{address}: deadline exceeded"));
            }
            match timeout(remaining, TcpStream::connect(address)).await {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(error)) => Err(format!("{address}: {error}")),
                Err(_) => Err(format!("{address}: connect timeout")),
            }
        });
    }

    let mut errors = Vec::new();
    loop {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(result)) => match result {
                Ok(Ok(stream)) => {
                    tasks.abort_all();
                    return Ok(stream);
                }
                Ok(Err(error)) => errors.push(error),
                Err(error) => errors.push(format!("address task failed: {error}")),
            },
            Ok(None) | Err(_) => {
                tasks.abort_all();
                break;
            }
        }
    }
    Err(anyhow!(
        "all upstream addresses failed: {}",
        if errors.is_empty() {
            "deadline exceeded".to_owned()
        } else {
            errors.join("; ")
        }
    ))
}

impl<S: AsyncRead + AsyncWrite> AsyncRead for IdleStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = self.inner.as_mut().poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            let duration = self.duration;
            self.inner.as_mut().set_write_timeout_pinned(Some(duration));
        }
        result
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncWrite for IdleStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = self.inner.as_mut().poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(1..))) {
            let duration = self.duration;
            self.inner.as_mut().set_read_timeout_pinned(Some(duration));
        }
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let result = self.inner.as_mut().poll_write_vectored(cx, bufs);
        if matches!(result, Poll::Ready(Ok(1..))) {
            let duration = self.duration;
            self.inner.as_mut().set_read_timeout_pinned(Some(duration));
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_shutdown(cx)
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// One explicitly routed request. No environment proxies, redirects or decoding.
/// Dropping the sender closes the driver after its response body is consumed/dropped.
pub async fn send(
    scheme: Scheme,
    host: &str,
    port: u16,
    mut request: Request<Empty<Bytes>>,
    deadline: Duration,
) -> Result<Response<Incoming>> {
    timeout(deadline, async {
        let stream = connect_tcp(host, port, deadline)
            .await
            .with_context(|| format!("connect {host}:{port}"))?;
        stream.set_nodelay(true)?;
        let stream = timed(stream, IO_TIMEOUT);
        let io: Box<dyn Io> = match scheme {
            Scheme::Http => Box::new(stream),
            Scheme::Https => {
                let name = rustls::pki_types::ServerName::try_from(host.to_owned())?;
                let tls = tokio_rustls::TlsConnector::from(crate::ca::upstream_client_config())
                    .connect(name, stream)
                    .await
                    .context("upstream TLS handshake")?;
                Box::new(tls)
            }
        };
        // Hyper recomputes framing. The caller only supplies end-to-end headers.
        request.headers_mut().insert("connection", "close".parse()?);
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(MAX_HEAD)
            .handshake(TokioIo::new(io))
            .await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok::<_, anyhow::Error>(sender.send_request(request).await?)
    })
    .await
    .context("upstream headers timeout")?
}

pub fn request(method: &str, path: &str, headers: HeaderMap) -> Result<Request<Empty<Bytes>>> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .body(Empty::new())?;
    *request.headers_mut() = headers;
    Ok(request)
}

pub async fn read_body(mut response: Response<Incoming>, limit: usize) -> Result<Vec<u8>> {
    if response
        .body()
        .size_hint()
        .upper()
        .is_some_and(|n| n > limit as u64)
    {
        bail!("response exceeds {limit} bytes");
    }
    let mut bytes = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        if let Ok(data) = frame?.into_data() {
            if data.len() > limit - bytes.len() {
                bail!("response exceeds {limit} bytes");
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes)
}

pub async fn get_text_async(url: &str, duration: Duration, limit: usize) -> Result<String> {
    timeout(duration, async {
        let uri: Uri = url.parse()?;
        let scheme = match uri.scheme_str() {
            Some("http") => Scheme::Http,
            Some("https") => Scheme::Https,
            _ => bail!("unsupported URL scheme"),
        };
        let authority = uri.authority().context("URL has no host")?;
        let host = authority.host().trim_matches(['[', ']']);
        let mut headers = HeaderMap::new();
        headers.insert("host", authority.as_str().parse()?);
        headers.insert(
            "user-agent",
            concat!("winget-accel/", env!("CARGO_PKG_VERSION")).parse()?,
        );
        let req = request(
            "GET",
            uri.path_and_query().map_or("/", |p| p.as_str()),
            headers,
        )?;
        let response = send(
            scheme,
            host,
            authority.port_u16().unwrap_or(scheme.default_port()),
            req,
            duration,
        )
        .await?;
        if response.status() != 200 {
            bail!("HTTP {}", response.status());
        }
        String::from_utf8(read_body(response, limit).await?).context("response is not UTF-8")
    })
    .await
    .context("HTTP GET total timeout")?
}

pub fn get_text(url: &str, duration: Duration, limit: usize) -> Result<String> {
    block_on(get_text_async(url, duration, limit))
}

pub fn response(status: u16, content_type: &str, body: impl Into<Bytes>) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("connection", "close")
        .body(
            Full::new(body.into())
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .expect("valid local response")
}

/// Connection-scoped fields must never cross a proxy hop. Hyper supplies new framing.
pub fn strip_hop_headers(headers: &mut HeaderMap) {
    let transfer_encoded = headers.contains_key("transfer-encoding");
    let nominated: Vec<_> = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| name.trim().parse::<hyper::header::HeaderName>().ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in crate::rewrite::HOP_BY_HOP {
        headers.remove(name);
    }
    // Hyper has already decoded transfer framing; CL must not survive TE+CL.
    headers.remove("transfer-encoding");
    if transfer_encoded {
        headers.remove("content-length");
    }
}

pub fn is_rate_limited(status: u16) -> bool {
    matches!(status, 429 | 503)
}

pub fn oversized_request(request: &Request<Incoming>) -> bool {
    let head_size = request.method().as_str().len()
        + request.uri().to_string().len()
        + 16
        + request
            .headers()
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len() + 4)
            .sum::<usize>();
    head_size > MAX_HEAD
}

pub fn error_kind(err: &anyhow::Error) -> &'static str {
    for cause in err.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            match io.kind() {
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => return "timeout",
                std::io::ErrorKind::UnexpectedEof => return "early-eof",
                _ => {}
            }
        }
        if let Some(hyper) = cause.downcast_ref::<hyper::Error>() {
            if hyper.is_incomplete_message() {
                return "early-eof";
            }
        }
    }
    "other"
}

type OnComplete = Box<dyn FnOnce(Result<u64>) + Send>;
/// Observe payload completion, not HTTP frame syntax. Dropped/failed bodies never pin.
struct ObservedBody {
    inner: Incoming,
    bytes: u64,
    on_complete: Option<OnComplete>,
}
impl ObservedBody {
    fn finish(&mut self, result: Result<u64>) {
        if let Some(done) = self.on_complete.take() {
            done(result);
        }
    }
}
impl Body for ObservedBody {
    type Data = Bytes;
    type Error = anyhow::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.bytes += data.len() as u64;
                }
                if frame.is_trailers() || self.inner.is_end_stream() {
                    let size = self.bytes;
                    self.finish(Ok(size));
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                let size = self.bytes;
                self.finish(Ok(size));
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                let error = anyhow::Error::from(error);
                // The callback and downstream both need the original error chain.
                let kind = error_kind(&error);
                self.finish(Err(std::io::Error::new(
                    match kind {
                        "timeout" => std::io::ErrorKind::TimedOut,
                        "early-eof" => std::io::ErrorKind::UnexpectedEof,
                        _ => std::io::ErrorKind::Other,
                    },
                    format!("{error:#}"),
                )
                .into()));
                Poll::Ready(Some(Err(error)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
impl Drop for ObservedBody {
    fn drop(&mut self) {
        if self.inner.is_end_stream() {
            self.finish(Ok(self.bytes));
        } else {
            self.finish(Err(anyhow::anyhow!("response body cancelled")));
        }
    }
}
pub fn observe(
    response: Response<Incoming>,
    on_complete: impl FnOnce(Result<u64>) + Send + 'static,
) -> Response<BoxBody> {
    let (mut parts, inner) = response.into_parts();
    strip_hop_headers(&mut parts.headers);
    parts.headers.insert("connection", "close".parse().unwrap());
    let mut body = ObservedBody {
        inner,
        bytes: 0,
        on_complete: Some(Box::new(on_complete)),
    };
    if body.inner.is_end_stream() {
        body.finish(Ok(0));
    }
    Response::from_parts(parts, body.boxed_unsync())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn connect_addresses_falls_back_when_first_address_fails() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
        let port = listener.local_addr().expect("listener address").port();
        let closed = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind closed address");
        let closed_port = closed.local_addr().expect("closed address").port();
        drop(closed);
        let thread = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let result = block_on(connect_addresses(
            vec![
                SocketAddr::from(([127, 0, 0, 1], closed_port)),
                SocketAddr::from(([127, 0, 0, 1], port)),
            ],
            Duration::from_secs(2),
        ));
        assert!(result.is_ok(), "{result:?}");
        thread.join().expect("listener thread");
    }

    #[test]
    fn connect_addresses_does_not_wait_for_delayed_tasks_after_deadline() {
        let listeners: Vec<_> = (0..20)
            .map(|_| std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind listener"))
            .collect();
        let addresses: Vec<_> = listeners
            .iter()
            .map(|listener| listener.local_addr().expect("listener address"))
            .collect();
        drop(listeners);

        let started = std::time::Instant::now();
        let result = block_on(connect_addresses(addresses, Duration::from_millis(50)));
        assert!(result.is_err());
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "deadline should include delayed address tasks: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn activity_in_either_direction_extends_idle_deadline() {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::pause();
                for writing in [true, false] {
                    let (local, mut peer) = tokio::io::duplex(8);
                    let mut local = timed(local, Duration::from_secs(4));
                    let mut cx = Context::from_waker(std::task::Waker::noop());
                    let mut bytes = [0; 1];
                    if !writing {
                        local.write_all(&[0; 8]).await.unwrap();
                    }
                    // One direction remains pending for much longer than four
                    // seconds while the opposite direction makes progress.
                    for _ in 0..5 {
                        if writing {
                            assert!(Pin::new(&mut local)
                                .poll_read(&mut cx, &mut ReadBuf::new(&mut bytes))
                                .is_pending());
                        } else {
                            assert!(Pin::new(&mut local).poll_write(&mut cx, &[1]).is_pending());
                        }
                        tokio::time::advance(Duration::from_secs(3)).await;
                        if writing {
                            local.write_all(&[1]).await.unwrap();
                            peer.read_exact(&mut bytes).await.unwrap();
                        } else {
                            peer.write_all(&[1]).await.unwrap();
                            local.read_exact(&mut bytes).await.unwrap();
                        }
                    }
                    // Start the final idle period, then verify real silence
                    // still expires in both directions.
                    if writing {
                        assert!(Pin::new(&mut local)
                            .poll_read(&mut cx, &mut ReadBuf::new(&mut bytes))
                            .is_pending());
                    } else {
                        assert!(Pin::new(&mut local).poll_write(&mut cx, &[1]).is_pending());
                    }
                    tokio::time::advance(Duration::from_secs(5)).await;
                    let error = if writing {
                        local.read(&mut bytes).await.unwrap_err()
                    } else {
                        local.write(&[1]).await.unwrap_err()
                    };
                    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
                }
            });
    }
}
