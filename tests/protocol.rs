#![cfg(windows)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

const STATUS_MARK: &[u8] = b"\nHTTP_STATUS:";
const ASSET_PREFIX: &str = "https://github.com/test/repo/releases/download/v1/";
const PROBE_BYTES: usize = 64 * 1024;
const DEFAULT_REWRITE_HOSTS: [&str; 4] = [
    "github.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "release-assets.githubusercontent.com",
];

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
struct RequestRecord {
    path: String,
    headers: HashMap<String, String>,
}

#[derive(Clone, Copy, Debug)]
enum UpstreamMode {
    Normal,
    IgnoreRange,
}

struct HttpUpstream {
    addr: SocketAddr,
    records: Arc<Mutex<Vec<RequestRecord>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl HttpUpstream {
    fn start(mode: UpstreamMode) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fake upstream");
        let addr = listener.local_addr().expect("fake upstream addr");
        listener
            .set_nonblocking(true)
            .expect("set fake upstream nonblocking");
        let records = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_records = Arc::clone(&records);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let records = Arc::clone(&thread_records);
                        thread::spawn(move || handle_http_connection(stream, mode, records));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            records,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn records(&self) -> Vec<RequestRecord> {
        self.records.lock().expect("records lock").clone()
    }
}

impl Drop for HttpUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn handle_http_connection(
    mut stream: TcpStream,
    mode: UpstreamMode,
    records: Arc<Mutex<Vec<RequestRecord>>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let Some((path, headers)) = read_request(&mut stream) else {
        return;
    };
    let user_agent = headers.get("user-agent").map(String::as_str).unwrap_or("");
    if user_agent == "winget-accel-health" {
        write_response(&mut stream, 200, &[], b"ok");
        return;
    }
    if user_agent == "winget-accel-probe" {
        let body = vec![b'P'; PROBE_BYTES];
        write_response(
            &mut stream,
            206,
            &[("Content-Range", "bytes 0-65535/1048576")],
            &body,
        );
        return;
    }

    records.lock().expect("records lock").push(RequestRecord {
        path: path.clone(),
        headers: headers.clone(),
    });

    if matches!(mode, UpstreamMode::IgnoreRange) && headers.contains_key("range") {
        write_response(&mut stream, 200, &[], &[b'Q'; 65_536]);
        return;
    }
    if path.contains("boom") {
        write_response(&mut stream, 502, &[], &[]);
        return;
    }
    if path.contains("range-ignored") {
        write_response(&mut stream, 200, &[], b"ab");
        return;
    }
    if path.contains("chunkedboth") {
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\
             Connection: close\r\n\r\n3\r\nabc\r\n4\r\ndefg\r\n1\r\nh\r\n0\r\n\r\n"
        );
        let _ = stream.flush();
        return;
    }
    if path.contains("chunked") {
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
             3\r\nabc\r\n4\r\ndefg\r\n1\r\nh\r\n0\r\n\r\n"
        );
        let _ = stream.flush();
        return;
    }
    if path.contains("nolength") {
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nno-length-body"
        );
        let _ = stream.flush();
        return;
    }
    if path.contains("big") {
        let body = vec![b'x'; 1024 * 1024];
        write_response(&mut stream, 200, &[], &body);
        return;
    }
    if path.contains("range") {
        let body: Vec<u8> = (0..=255).cycle().take(1024).collect();
        if let Some((start, end)) = parse_range(headers.get("range"), body.len()) {
            let part = &body[start..=end];
            let content_range = format!("bytes {start}-{end}/{}", body.len());
            write_response(&mut stream, 206, &[("Content-Range", &content_range)], part);
        } else {
            write_response(&mut stream, 200, &[], &body);
        }
        return;
    }
    write_response(&mut stream, 200, &[], b"hello-through-proxy");
}

fn parse_range(value: Option<&String>, len: usize) -> Option<(usize, usize)> {
    let value = value?.strip_prefix("bytes=")?;
    let (start, end) = value.split_once('-')?;
    let start = start.parse::<usize>().ok()?;
    let end = if end.is_empty() {
        len.checked_sub(1)?
    } else {
        end.parse::<usize>().ok()?.min(len.checked_sub(1)?)
    };
    (start <= end && start < len).then_some((start, end))
}

fn write_response(stream: &mut TcpStream, status: u16, extra: &[(&str, &str)], body: &[u8]) {
    let reason = match status {
        200 => "OK",
        206 => "Partial Content",
        502 => "Bad Gateway",
        _ => "Response",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in extra {
        let _ = write!(stream, "{name}: {value}\r\n");
    }
    let _ = write!(stream, "\r\n");
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn read_request(stream: &mut TcpStream) -> Option<(String, HashMap<String, String>)> {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    while !data.windows(4).any(|window| window == b"\r\n\r\n") {
        let count = stream.read(&mut buf).ok()?;
        if count == 0 || data.len() > 128 * 1024 {
            return None;
        }
        data.extend_from_slice(&buf[..count]);
    }
    let text = String::from_utf8_lossy(&data);
    let mut lines = text.split("\r\n");
    let path = lines.next()?.split_whitespace().nth(1)?.to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    Some((path, headers))
}

struct Proxy {
    child: Child,
    port: u16,
    dir: TestDir,
    cert_dir: PathBuf,
    log: PathBuf,
    _stdout: std::fs::File,
    _stderr: std::fs::File,
}

impl Proxy {
    fn start(upstreams: &[(&str, UpstreamMode)], mitm_extra: &[&str]) -> Self {
        let dir = TestDir::new();
        let cert_dir = dir.path().join("certs");
        let log = dir.path().join("proxy.log");
        let port = free_port();
        let accelerators: Vec<Value> = upstreams
            .iter()
            .enumerate()
            .map(|(index, (url, _))| {
                json!({
                    "name": format!("test-{index}"),
                    "template": url,
                    "priority": index + 1
                })
            })
            .collect();
        let config = json!({
            "listen": format!("127.0.0.1:{port}"),
            "rewriteHosts": DEFAULT_REWRITE_HOSTS,
            "accelerators": accelerators,
            "certDir": cert_dir,
            "logPath": log,
            "mitmExtra": mitm_extra,
            "wingetDownloader": false,
            "health": {
                "intervalSeconds": 60,
                "timeoutSeconds": 2,
                "probeUrl": "https://github.com/probe.bin"
            }
        });
        let config_path = dir.path().join("config.json");
        std::fs::write(
            &config_path,
            serde_json::to_vec_pretty(&config).expect("serialize config"),
        )
        .expect("write config");
        let stdout_path = dir.path().join("stdout.log");
        let stderr_path = dir.path().join("stderr.log");
        let stdout = std::fs::File::create(&stdout_path).expect("create stdout log");
        let stderr = std::fs::File::create(&stderr_path).expect("create stderr log");
        let mut child = Command::new(env!("CARGO_BIN_EXE_winget-accel"))
            .args([
                "--config",
                config_path.to_str().expect("config path"),
                "--no-env",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout.try_clone().expect("clone stdout")))
            .stderr(Stdio::from(stderr.try_clone().expect("clone stderr")))
            .spawn()
            .expect("start proxy");

        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(response) = raw_http(port, "GET", "/health", &[]) {
                if response.starts_with(b"HTTP/1.1") {
                    break;
                }
            }
            if let Some(status) = child.try_wait().expect("poll proxy") {
                let error = std::fs::read_to_string(&stderr_path).unwrap_or_default();
                panic!("proxy exited during startup ({status}): {error}");
            }
            if Instant::now() >= deadline {
                let error = std::fs::read_to_string(&stderr_path).unwrap_or_default();
                panic!("proxy did not become ready: {error}");
            }
            thread::sleep(Duration::from_millis(50));
        }
        Self {
            child,
            port,
            dir,
            cert_dir,
            log,
            _stdout: stdout,
            _stderr: stderr,
        }
    }

    fn ca_path(&self) -> PathBuf {
        self.cert_dir.join("ca-cert.pem")
    }

    fn health(&self) -> Value {
        let response = raw_http(self.port, "GET", "/health", &[]).expect("health request");
        let body = http_body(&response);
        serde_json::from_slice(&body).expect("health json")
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn pac(&self) -> Vec<u8> {
        let response = raw_http(self.port, "GET", "/winget-accel.pac", &[]).expect("pac");
        http_body(&response)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = &self.dir;
    }
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "winget-accel-protocol-{}-{stamp}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create test dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("free port")
        .local_addr()
        .expect("free port addr")
        .port()
}

fn raw_http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n")?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    stream.write_all(b"Connection: close\r\n\r\n")?;
    stream.flush()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn http_body(response: &[u8]) -> Vec<u8> {
    response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| response[index + 4..].to_vec())
        .unwrap_or_default()
}

struct CurlResult {
    output: Output,
    body: Vec<u8>,
    status: u16,
}

fn curl(proxy: &Proxy, url: &str, args: &[&str]) -> CurlResult {
    let mut command = Command::new("curl.exe");
    command.args([
        "-sS",
        "--max-time",
        "30",
        "--noproxy",
        "",
        "-x",
        &format!("http://127.0.0.1:{}", proxy.port),
        "--ssl-no-revoke",
        "--cacert",
        proxy.ca_path().to_str().expect("ca path"),
    ]);
    command.args(args);
    command.args(["-w", "\nHTTP_STATUS:%{http_code}", url]);
    let output = command.output().expect("run curl.exe");
    let (body, status) = split_curl_output(&output.stdout);
    CurlResult {
        output,
        body,
        status,
    }
}

fn split_curl_output(output: &[u8]) -> (Vec<u8>, u16) {
    let Some(index) = output
        .windows(STATUS_MARK.len())
        .rposition(|window| window == STATUS_MARK)
    else {
        return (output.to_vec(), 0);
    };
    let body = output[..index].to_vec();
    let status = output[index + STATUS_MARK.len()..]
        .split(|byte| *byte == b'\r' || *byte == b'\n')
        .next()
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    (body, status)
}

fn asset(name: &str) -> String {
    format!("{ASSET_PREFIX}{name}")
}

fn assert_curl_ok(result: &CurlResult) {
    assert!(
        result.output.status.success(),
        "curl failed: {}",
        String::from_utf8_lossy(&result.output.stderr)
    );
}

#[test]
fn rewrites_downloads_and_filters_proxy_headers() {
    let upstream = HttpUpstream::start(UpstreamMode::Normal);
    let proxy = Proxy::start(&[(&upstream.url(), UpstreamMode::Normal)], &[]);
    let result = curl(
        &proxy,
        &asset("ok"),
        &[
            "-H",
            "X-Custom: 1",
            "--proxy-header",
            "Proxy-Authorization: Basic should-not-reach-upstream",
        ],
    );
    assert_curl_ok(&result);
    assert_eq!(result.status, 200);
    assert_eq!(result.body, b"hello-through-proxy");

    let records = upstream.records();
    assert_eq!(records.len(), 1);
    assert!(records[0].path.starts_with("/https://github.com/"));
    assert_eq!(
        records[0].headers.get("host"),
        Some(&upstream.addr.to_string())
    );
    assert_eq!(
        records[0].headers.get("connection"),
        Some(&"close".to_string())
    );
    assert_eq!(records[0].headers.get("x-custom"), Some(&"1".to_string()));
    assert!(!records[0].headers.contains_key("proxy-authorization"));
    assert!(!records[0].headers.contains_key("proxy-connection"));
}

#[test]
fn preserves_ranges_and_response_boundaries() {
    let upstream = HttpUpstream::start(UpstreamMode::Normal);
    let proxy = Proxy::start(&[(&upstream.url(), UpstreamMode::Normal)], &[]);

    let range = curl(&proxy, &asset("range"), &["-r", "0-9"]);
    assert_curl_ok(&range);
    assert_eq!(range.status, 206);
    assert_eq!(range.body, (0u8..=9).collect::<Vec<_>>());

    let chunked = curl(&proxy, &asset("chunked"), &[]);
    assert_curl_ok(&chunked);
    assert_eq!(chunked.body, b"abcdefgh");

    let chunked_with_length = curl(&proxy, &asset("chunkedboth"), &[]);
    assert_curl_ok(&chunked_with_length);
    assert_eq!(chunked_with_length.body, b"abcdefgh");

    let no_length = curl(&proxy, &asset("nolength"), &[]);
    assert_curl_ok(&no_length);
    assert_eq!(no_length.body, b"no-length-body");
}

#[test]
fn reassembles_adjacent_ranges_exactly() {
    let upstream = HttpUpstream::start(UpstreamMode::Normal);
    let proxy = Proxy::start(&[(&upstream.url(), UpstreamMode::Normal)], &[]);
    let first = curl(&proxy, &asset("range"), &["-r", "0-511"]);
    let second = curl(&proxy, &asset("range"), &["-r", "512-1023"]);
    assert_curl_ok(&first);
    assert_curl_ok(&second);
    assert_eq!(first.status, 206);
    assert_eq!(second.status, 206);
    let mut joined = first.body;
    joined.extend(second.body);
    let expected: Vec<u8> = (0..=255).cycle().take(1024).collect();
    assert_eq!(joined, expected);
    assert_eq!(upstream.records().len(), 2);
}

#[test]
fn rejects_invalid_range_responses_and_reports_upstream_errors() {
    let upstream = HttpUpstream::start(UpstreamMode::Normal);
    let proxy = Proxy::start(&[(&upstream.url(), UpstreamMode::Normal)], &[]);

    let ignored = curl(&proxy, &asset("range-ignored"), &["-r", "0-1"]);
    assert_curl_ok(&ignored);
    assert_eq!(ignored.status, 502);
    assert!(ignored.body.is_empty());

    let boom = curl(&proxy, &asset("boom"), &[]);
    assert_curl_ok(&boom);
    assert_eq!(boom.status, 502);
}

#[test]
fn fails_over_when_all_candidates_ignore_range() {
    let first = HttpUpstream::start(UpstreamMode::IgnoreRange);
    let second = HttpUpstream::start(UpstreamMode::IgnoreRange);
    let first_url = first.url();
    let second_url = second.url();
    let proxy = Proxy::start(
        &[
            (&first_url, UpstreamMode::IgnoreRange),
            (&second_url, UpstreamMode::IgnoreRange),
        ],
        &[],
    );
    let result = curl(&proxy, &asset("all-bad-range"), &["-r", "0-65535"]);
    assert_curl_ok(&result);
    assert_eq!(result.status, 502);
    assert!(result.body.is_empty());
}

#[test]
fn rejects_request_bodies_without_touching_upstream() {
    let upstream = HttpUpstream::start(UpstreamMode::Normal);
    let proxy = Proxy::start(&[(&upstream.url(), UpstreamMode::Normal)], &[]);
    let result = curl(
        &proxy,
        "https://github.com/upload",
        &["-X", "POST", "-d", "0123456789abcdef"],
    );
    assert_curl_ok(&result);
    assert_eq!(result.status, 501);
    assert!(upstream.records().is_empty());
    assert!(proxy.log_text().contains("REQ-BODY-UNSUPPORTED"));
}

#[test]
fn serves_pac_and_health_and_tracks_rewrites() {
    let upstream = HttpUpstream::start(UpstreamMode::Normal);
    let proxy = Proxy::start(&[(&upstream.url(), UpstreamMode::Normal)], &[]);
    let pac = proxy.pac();
    let pac_text = String::from_utf8_lossy(&pac);
    assert!(pac_text.contains("function FindProxyForURL"));
    assert!(pac_text.contains(&format!("PROXY 127.0.0.1:{}", proxy.port)));
    assert!(pac_text.contains("github.com"));

    let before = proxy.health();
    let result = curl(&proxy, &asset("health-counter"), &[]);
    assert_curl_ok(&result);
    let after = proxy.health();
    assert_eq!(result.status, 200);
    assert_eq!(
        after["rewrites"].as_u64(),
        Some(before["rewrites"].as_u64().unwrap() + 1)
    );
    assert!(after["bytes"].as_u64().unwrap() > before["bytes"].as_u64().unwrap());
    assert!(after["mitm"].as_u64().unwrap() >= 1);
}

#[test]
fn non_whitelisted_host_is_tunneled() {
    let upstream = RawTunnelUpstream::start();
    let proxy = Proxy::start(&[("http://127.0.0.1:9", UpstreamMode::Normal)], &[]);
    let mut client = TcpStream::connect(("127.0.0.1", proxy.port)).expect("connect proxy");
    write!(
        client,
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        upstream.addr.port(),
        upstream.addr.port()
    )
    .expect("write connect");
    let head = read_until(&mut client, b"\r\n\r\n");
    assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
    client
        .write_all(b"GET /plain HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .expect("write tunneled request");
    let response = read_to_end(&mut client);
    assert!(response.ends_with(b"hello-through-tunnel"), "{response:?}");
    assert_eq!(
        upstream.requests.lock().expect("tunnel records").as_slice(),
        &["/plain".to_string()]
    );
}

#[test]
fn oversized_headers_get_431_and_connection_limit_is_bounded() {
    let proxy = Proxy::start(&[("http://127.0.0.1:9", UpstreamMode::Normal)], &[]);
    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).expect("connect proxy");
    stream
        .write_all(b"GET / HTTP/1.1\r\nX: ")
        .expect("write oversized head");
    stream
        .write_all(&vec![b'a'; 33_000])
        .expect("write oversized value");
    stream
        .write_all(b"\r\n\r\n")
        .expect("finish oversized head");
    let response = read_some(&mut stream);
    assert!(response.starts_with(b"HTTP/1.1 431"), "{response:?}");
    drop(stream);

    let mut held = Vec::new();
    for _ in 0..64 {
        let socket = TcpStream::connect(("127.0.0.1", proxy.port)).expect("hold slot");
        held.push(socket);
    }
    thread::sleep(Duration::from_millis(300));
    let mut extra = TcpStream::connect(("127.0.0.1", proxy.port)).expect("extra slot");
    let response = read_some(&mut extra);
    assert!(
        response.windows(3).any(|window| window == b"503"),
        "{response:?}"
    );
}

#[test]
fn concurrent_first_connections_all_complete() {
    let upstream = HttpUpstream::start(UpstreamMode::Normal);
    let proxy = Arc::new(Proxy::start(
        &[(&upstream.url(), UpstreamMode::Normal)],
        &[],
    ));
    let mut threads = Vec::new();
    for _ in 0..5 {
        let proxy = Arc::clone(&proxy);
        threads.push(thread::spawn(move || {
            curl(&proxy, &asset("concurrent"), &[])
        }));
    }
    for thread in threads {
        let result = thread.join().expect("curl thread");
        assert_curl_ok(&result);
        assert_eq!(result.body, b"hello-through-proxy");
    }
    assert!(proxy.health()["rewrites"].as_u64().unwrap() >= 5);
}

#[test]
fn same_port_second_instance_fails_fast() {
    let upstream = HttpUpstream::start(UpstreamMode::Normal);
    let proxy = Proxy::start(&[(&upstream.url(), UpstreamMode::Normal)], &[]);
    let dir = TestDir::new();
    let config = dir.path().join("config.json");
    let cert_dir = dir.path().join("certs");
    let log = dir.path().join("proxy.log");
    let value = json!({
        "listen": format!("127.0.0.1:{}", proxy.port),
        "accelerators": [{"name": "test", "template": upstream.url(), "priority": 1}],
        "certDir": cert_dir,
        "logPath": log,
        "wingetDownloader": false,
        "health": {"probeUrl": "https://github.com/probe.bin"}
    });
    std::fs::write(&config, serde_json::to_vec(&value).expect("config json")).expect("config");
    let output = Command::new(env!("CARGO_BIN_EXE_winget-accel"))
        .args([
            "--config",
            config.to_str().expect("config path"),
            "--no-env",
        ])
        .output()
        .expect("second proxy");
    assert!(!output.status.success());
    assert!(!cert_dir.exists());
}

#[test]
fn name_constraints_reject_an_extra_host() {
    let proxy = Proxy::start(
        &[("http://127.0.0.1:9", UpstreamMode::Normal)],
        &["example.com"],
    );
    let result = curl(&proxy, "https://example.com/", &["--max-time", "10"]);
    assert!(!result.output.status.success());
    let stderr = String::from_utf8_lossy(&result.output.stderr).to_ascii_lowercase();
    assert!(
        stderr.contains("certificate") || stderr.contains("ssl"),
        "{stderr}"
    );
}

fn read_some(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut buf = vec![0u8; 512];
    let count = stream.read(&mut buf).expect("read response");
    buf.truncate(count);
    buf
}

struct RawTunnelUpstream {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl RawTunnelUpstream {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind tunnel upstream");
        let addr = listener.local_addr().expect("tunnel upstream addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("tls listener nonblocking");
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let requests = Arc::clone(&thread_requests);
                        thread::spawn(move || {
                            let mut stream = stream;
                            let _ = stream.set_nonblocking(false);
                            if let Some((path, _)) = read_request(&mut stream) {
                                requests.lock().expect("tunnel records").push(path);
                                write_response(&mut stream, 200, &[], b"hello-through-tunnel");
                            }
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            requests,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for RawTunnelUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_until(stream: &mut TcpStream, marker: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    while !data.windows(marker.len()).any(|window| window == marker) {
        let count = stream.read(&mut buf).expect("read until");
        assert!(count > 0, "connection ended before marker");
        data.extend_from_slice(&buf[..count]);
    }
    data
}

fn read_to_end(stream: &mut TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    stream.read_to_end(&mut data).expect("read to end");
    data
}
