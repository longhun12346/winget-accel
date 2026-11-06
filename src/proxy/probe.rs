//! 候选可达性、资产测速与后台健康探测。

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use rustls::{ClientConnection, StreamOwned};

use crate::ca::upstream_client_config;
use crate::http;
use crate::log::Level;
use crate::rewrite;

use super::{connect_tcp_timeout, Proxy};

/// 启动阶段验证候选的总预算。超过就先去监听，剩余候选交给后台探测。
const BOOTSTRAP_BUDGET: Duration = Duration::from_secs(30);
/// 一轮探测的并发数。6 是折中：43 个候选串行要 120 秒，全开对第三方不礼貌。
const PROBE_CONCURRENCY: usize = 6;

/// 全挂状态下的重探间隔。
///
/// 比 `health.intervalSeconds`（默认 300 s）短得多：全挂时每个请求都立刻 502，
/// 用户唯一能做的是等，所以恢复必须在一分钟内被尝试，不能等满一个周期。
const RECOVERY_INTERVAL: Duration = Duration::from_secs(30);

/// 未启用例行探测时的空闲巡检间隔：只用来发现"是不是变成全挂了"。
const DISABLED_IDLE_CHECK: Duration = Duration::from_secs(60);

/// 这一轮要不要探测？
///
/// 例行探测由 `health.enabled` 控制；**恢复探测不受它控制**——
/// 全挂状态下必须继续探，否则没有任何路径能让候选恢复
/// （所有请求都 502，成功样本永远不会产生）。
fn should_probe(enabled: bool, all_unhealthy: bool) -> bool {
    enabled || all_unhealthy
}

/// 恢复探测是否该提前结束？
///
/// 只有"这轮是恢复探测"且"已经有候选恢复"时提前收工。
/// 例行探测不提前结束：它的作用是把**所有**候选的状态刷新一遍，
/// 中途停会让后面那些候选永远停在旧状态。
fn should_stop_probing(stop_when_healthy: bool, healthy: usize) -> bool {
    stop_when_healthy && healthy > 0
}

/// 单个候选的测速超时。
///
/// 从 15 秒降到 5 秒：候选池有 43 个后，15 秒意味着个别挂住的域名
/// 能拖垮整轮探测。5 秒足够拿到 64 KiB（实测最快 30 ms、最慢约 3 秒）。
const PROBE_SPEED_TIMEOUT: Duration = Duration::from_secs(5);

/// 把剩余预算应用到每次底层 socket I/O；TLS 握手也通过这层读写。
struct ProbeSocket {
    stream: TcpStream,
    deadline: Instant,
}

impl ProbeSocket {
    fn connect(accel: &rewrite::Accel, timeout: Duration) -> Option<Self> {
        let deadline = Instant::now().checked_add(timeout)?;
        let stream = connect_tcp_timeout(&accel.host, accel.port, timeout).ok()?;
        Some(Self { stream, deadline })
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "探测 I/O 总时间预算耗尽"))
    }
}

impl Read for ProbeSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        let count = self.stream.read(buf)?;
        self.remaining()?;
        Ok(count)
    }
}

impl Write for ProbeSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        let count = self.stream.write(buf)?;
        self.remaining()?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}

impl Proxy {
    /// 周期探测所有候选。**单候选也探**——否则一旦被判死就永久 502，没有任何恢复路径。
    ///
    /// 只探各自 origin 的根路径，收到任意 HTTP 响应（含 404）即视为可达；
    /// 不能拿 GitHub 资产路径去探，受限网络下那里本身就不通，会把候选全部误判。
    ///
    /// `health.enabled = false` 只关掉**例行**探测，恢复探测照跑（见 [`should_probe`]）：
    /// 否则启动那轮把候选全判死之后就没有任何恢复路径了——所有请求都 502，
    /// `record_success` 永远等不到一次成功，等于永久失效。
    pub(super) fn spawn_health_prober(self: &Arc<Self>) {
        let proxy = Arc::clone(self);

        std::thread::spawn(move || loop {
            let enabled = proxy.app.health_enabled;
            let down = proxy.health.all_unhealthy();

            if should_probe(enabled, down) {
                // 全挂恢复时提前收工：有一个候选能用就够，不必扫完 43 个。
                // 周期性巡检仅对已验证且仍健康的候选省略测速。
                proxy.probe_round(down, false);
                proxy.report_health_state();
            }

            // 全挂时缩短重试间隔，让恢复更快被发现
            let wait = if proxy.health.all_unhealthy() {
                RECOVERY_INTERVAL
            } else if enabled {
                proxy.app.health_interval
            } else {
                // 没开例行探测、也没全挂：只定期看一眼"是不是变成全挂了"
                DISABLED_IDLE_CHECK
            };
            std::thread::sleep(wait);
        });
    }

    /// Verify a small seed set before any download can use a candidate.
    /// Unknown candidates are intentionally not eligible for downloads.
    pub fn bootstrap_health(&self) {
        let list: Vec<(usize, rewrite::Accel)> =
            self.health.accels().iter().cloned().enumerate().collect();
        if list.is_empty() {
            self.log
                .error("NO-VERIFIED-ACCEL 没有配置任何加速器候选，下载会立即返回 502");
            return;
        }
        // 启动验证：逐批（每批 PROBE_CONCURRENCY 个）探测，**一旦有一批通过就停**。
        //
        // 早期只探第一批（`.take(1)`）：前 6 个候选恰好都挂、第 7 个可用时，
        // 要等后台整轮探测跑完才可能恢复，期间所有下载都被 502 挡掉。
        // 现在向后继续探，同时用 BOOTSTRAP_BUDGET 兜住启动时长。
        let deadline = std::time::Instant::now() + BOOTSTRAP_BUDGET;
        let mut probed = 0usize;
        for chunk in list.chunks(PROBE_CONCURRENCY) {
            if self.health.healthy_count() > 0 || std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::scope(|scope| {
                for (idx, accel) in chunk {
                    // 启动时**要**测速：初始权重需要一份速度基准
                    scope.spawn(move || self.probe_one(*idx, accel, true));
                }
            });
            probed += chunk.len();
        }
        let healthy = self.health.healthy_count();
        if healthy > 0 {
            self.log.info(&format!(
                "HEALTH-READY 已有 {healthy} 个候选通过验证（本轮探测 {probed} 个）"
            ));
        } else {
            self.log.error(&format!(
                "NO-VERIFIED-ACCEL 启动批次（{probed} 个候选）均未通过验证，后台继续探测；期间请求返回 502"
            ));
            // 自定义测速资产是"全部失败"的常见原因之一，而且从
            // `SPEED … 实测失败（非 206 或数据不足）` 看不出这一点：
            // 加速器大多只代理 GitHub 域，把 probeUrl 指到别处会让**每个**候选都失败。
            // 实测过：probeUrl 设为 https://example.com/64k.bin 时，gh-proxy.com 直接判死。
            if self.app.health_probe_custom {
                self.log.warn(&format!(
                    "提示：当前用的是自定义测速资产 {}。加速器一般只代理 GitHub 域的地址，\
                     指向其它域名会让所有候选都「实测失败」。可以去掉 health.probeUrl 用默认值，\
                     或先跑 --doctor 看 probe 这一项",
                    self.app.health_probe
                ));
            }
        }
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
    ///
    /// `stop_when_healthy` 为真时（全挂恢复场景），一旦有候选恢复就结束这一轮：
    /// 43 个候选全探完约 90 秒，而恢复只需要"有一个能用"——
    /// 剩下的候选留给下一轮，用户不必为别人的失败继续等待。
    ///
    /// `with_speed` 为真则所有候选测速。周期性巡检用 `false`：
    /// 只对已验证且仍健康的候选省略 64 KiB 资产下载，其速度由真实下载样本更新；
    /// 未验证或被排除的候选仍须测速，根路径可达不足以恢复下载资格。
    fn probe_round(&self, stop_when_healthy: bool, with_speed: bool) {
        // 快照一份候选，避免持有锁跨线程
        let list: Vec<(usize, rewrite::Accel)> =
            self.health.accels().iter().cloned().enumerate().collect();

        for chunk in list.chunks(PROBE_CONCURRENCY) {
            // 检查点放在每批之间：批内是并发探测，无法中断单个候选
            if should_stop_probing(stop_when_healthy, self.health.healthy_count()) {
                break;
            }
            std::thread::scope(|scope| {
                for (idx, accel) in chunk {
                    scope.spawn(move || self.probe_one(*idx, accel, with_speed));
                }
            });
        }
    }

    /// 探测单个候选：先判可达；`with_speed` 为真时再量吞吐。
    ///
    /// 周期性巡检用 `with_speed = false`，已验证且仍健康的候选只打根路径；
    /// 其余候选必须重新通过资产验证，首页可达不能直接恢复下载资格。
    fn probe_one(&self, idx: usize, accel: &rewrite::Accel, with_speed: bool) {
        let needs_speed = with_speed || self.health.needs_verification(idx);
        let ok = probe(accel, self.app.health_timeout);
        if !ok {
            self.health.mark(idx, false);
            self.log
                .log(Level::Debug, &format!("HEALTH {} -> fail", accel.host));
            return;
        }
        if !needs_speed {
            self.health.mark(idx, true);
            self.log.log(
                Level::Debug,
                &format!("HEALTH {} -> ok（本轮不测速）", accel.host),
            );
            return;
        }

        // 只判"明显不可用/太慢"，不做排序（排序靠真实下载样本）
        match probe_speed(accel, PROBE_SPEED_TIMEOUT, &self.app.health_probe) {
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
}

/// 探测基准资产（默认值）：用 release 资产（CDN 静态文件），不用 codeload 的 tag 归档。
///
/// 实测依据：`codeload` 的 tarball 在 5 个加速器里有 4 个返回 403/404/超时，
/// 用它当基准会把正常候选误判成不可用；而 release 资产 5/5 都返回 206。
///
/// **它绑着一个具体版本号，这是已知弱点**：上游一旦删掉该资产，所有候选都会
/// "测速失败"→ 全部判死 → 全站 502。所以该值可通过配置 `health.probeUrl` 覆盖
/// （见 `docs/design.md` §7），并且 `probe_one` 会在整轮测速全失败时给出提示。
pub const DEFAULT_PROBE_ASSET: &str =
    "https://github.com/git-for-windows/git/releases/download/v2.43.0.windows.1/Git-2.43.0-64-bit.exe";
/// 探测采样量。64 KB 实测约 1.6–1.9 秒（256 KB 要 5–7 秒），
/// 分批并发才不会把启动拖到半分钟以上，且仍能分辨速度量级。
const PROBE_BYTES: u64 = 64 * 1024;

/// 把基准资产拆成 (host, path+query)。只接受 https，避免把 http 资产
/// 拼成 `https://host/...` 这种自相矛盾的改写路径。
///
/// `pub(crate)`：`config` 加载 `health.probeUrl` 时用它做校验，避免两处各写一套。
pub(crate) fn split_asset(asset: &str) -> Option<(String, String)> {
    let rest = asset.strip_prefix("https://")?;
    let (host, path) = rest.split_once('/')?;
    if host.is_empty() || path.is_empty() {
        return None;
    }
    Some((host.to_string(), format!("/{path}")))
}

/// 测速请求的请求行/头（明文与 TLS 两条路径共用）。
fn probe_request(accel: &rewrite::Accel, asset: &str) -> Option<String> {
    let (host, path) = split_asset(asset)?;
    Some(format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nRange: bytes=0-{}\r\nUser-Agent: winget-accel-probe\r\nConnection: close\r\n\r\n",
        rewrite::rewrite_path(accel, &host, &path),
        rewrite::host_header(accel.scheme, &accel.host, accel.port),
        PROBE_BYTES - 1
    ))
}

/// 通过加速器取一段固定资产，量出吞吐（KB/s）。
///
/// 返回 None 表示拿不到（非 206、正文不足或超过采样上限）。
///
/// `ProbeSocket` 按剩余预算控制每次 I/O，持续有少量数据也不会续长测速。
///
/// `pub(crate)`：`--doctor` 用它单独验证"测速资产还取得到吗"——
/// 那个资产是整条链路唯一的版本绑定依赖，失效时表现是"chain 全 OK 但所有下载 502"。
pub(crate) fn probe_speed(accel: &rewrite::Accel, timeout: Duration, asset: &str) -> Option<f64> {
    let started = std::time::Instant::now();
    let request = probe_request(accel, asset)?;

    match accel.scheme {
        rewrite::Scheme::Http => {
            let mut upstream = ProbeSocket::connect(accel, timeout)?;
            upstream.write_all(request.as_bytes()).ok()?;
            upstream.flush().ok()?;
            read_probe_response(&mut upstream, started)
        }
        rewrite::Scheme::Https => {
            let cfg = upstream_client_config();
            let name: Result<rustls::pki_types::ServerName<'static>, _> =
                accel.host.clone().try_into();
            let Ok(name) = name else { return None };
            let Ok(conn) = ClientConnection::new(cfg, name) else {
                return None;
            };
            let stream = ProbeSocket::connect(accel, timeout)?;
            let mut tls = StreamOwned::new(conn, stream);
            tls.write_all(request.as_bytes()).ok()?;
            tls.flush().ok()?;
            read_probe_response(&mut tls, started)
        }
    }
}

fn read_probe_response<R: Read>(up: &mut R, started: std::time::Instant) -> Option<f64> {
    let head = http::read_head(up).ok()?;
    if http::status_code(&head) != Some(206) {
        return None;
    }
    let copied = http::measure_body(up, &head, PROBE_BYTES).ok()?;
    let secs = started.elapsed().as_secs_f64();
    if copied < PROBE_BYTES / 2 || secs <= 0.0 {
        return None;
    }
    Some((copied as f64 / 1024.0) / secs)
}
/// 探测加速器是否可达：打它自己的根路径，收到任意 HTTP 响应就算通。
pub fn probe(accel: &rewrite::Accel, timeout: Duration) -> bool {
    let Some(stream) = ProbeSocket::connect(accel, timeout) else {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    /// `health.enabled = false` 不能连"恢复探测"一起关掉。
    ///
    /// 否则存在一个真实的死锁：启动那轮 bootstrap 把候选全判死后，后台线程根本不转，
    /// 所有下载立刻 502，`record_success` 永远等不到成功样本——永久失效且无法自愈。
    #[test]
    fn recovery_probe_survives_health_disabled() {
        // 开了例行探测：总是探
        assert!(should_probe(true, false));
        assert!(should_probe(true, true));
        // 关了例行探测：平时不探，但全挂时必须探
        assert!(!should_probe(false, false), "关掉后不该做例行探测");
        assert!(
            should_probe(false, true),
            "全挂时必须恢复探测，否则永久 502"
        );
    }

    /// 恢复探测一旦有候选可用就提前结束；例行探测必须扫完。
    ///
    /// 动机是等待时间：一整轮 43 个候选约 90 秒（6 路并发 × 每次 8 s 可达 + 5 s 测速），
    /// 而恢复只需要"有一个能用"。但例行探测不能提前停，否则后面的候选永远停在旧状态。
    #[test]
    fn recovery_probe_stops_at_first_healthy_but_routine_does_not() {
        assert!(!should_stop_probing(true, 0), "还没有可用候选时继续探");
        assert!(should_stop_probing(true, 1), "恢复场景：有一个就收工");
        assert!(should_stop_probing(true, 7));
        // 例行探测：无论多少候选健康都要扫完
        assert!(!should_stop_probing(false, 0));
        assert!(!should_stop_probing(false, 7), "例行探测不该半途而废");
    }
    #[test]
    fn splits_https_asset_into_host_and_path() {
        let (host, path) = split_asset("https://github.com/a/b.zip?x=1").unwrap();
        assert_eq!(host, "github.com");
        assert_eq!(path, "/a/b.zip?x=1");
        // 只接受 https：否则会把 http 资产拼成 https://host/... 的错误路径
        assert!(split_asset("http://github.com/a").is_none());
        assert!(split_asset("https://github.com").is_none());
        assert!(split_asset("not-a-url").is_none());
    }

    #[test]
    fn probe_rejects_oversized_body_before_reading_it() {
        use std::io::Cursor;
        for framing in [
            format!("Content-Length: {}", PROBE_BYTES + 1),
            "Transfer-Encoding: chunked".to_string(),
        ] {
            let mut response = format!("HTTP/1.1 206 Partial Content\r\n{framing}\r\n\r\n");
            if framing.starts_with("Transfer-Encoding") {
                response.push_str("10001\r\n");
            }
            let body_start = response.len() as u64;
            response.push_str(&"x".repeat(PROBE_BYTES as usize + 1));
            let mut up = Cursor::new(response);
            assert!(read_probe_response(&mut up, std::time::Instant::now()).is_none());
            assert_eq!(up.position(), body_start, "不能读取超出采样上限的正文");
        }
    }

    #[test]
    fn probe_accepts_full_samples_with_each_body_framing() {
        use std::io::Cursor;
        for framing in ["Content-Length: 65536", "Transfer-Encoding: chunked", ""] {
            let mut response = "HTTP/1.1 206 Partial Content\r\n".to_string();
            if !framing.is_empty() {
                response.push_str(framing);
                response.push_str("\r\n");
            }
            response.push_str("\r\n");
            if framing.starts_with("Transfer-Encoding") {
                response.push_str("10000;ext=sample\r\n");
            }
            response.push_str(&"x".repeat(PROBE_BYTES as usize));
            if framing.starts_with("Transfer-Encoding") {
                response.push_str("\r\n0\r\nX-Tag: sample\r\n\r\n");
            }
            let mut up = Cursor::new(response);
            assert!(
                read_probe_response(&mut up, std::time::Instant::now()).is_some(),
                "应支持完整样本的 {framing}"
            );
        }
        let mut too_long = Cursor::new(format!(
            "HTTP/1.1 206 Partial Content\r\n\r\n{}",
            "x".repeat(PROBE_BYTES as usize + 1)
        ));
        assert!(read_probe_response(&mut too_long, std::time::Instant::now()).is_none());
    }

    #[test]
    fn probe_does_not_count_chunk_metadata_as_downloaded_data() {
        use std::io::Cursor;
        let response = format!(
            "HTTP/1.1 206 Partial Content\r\nTransfer-Encoding: chunked\r\n\r\n\
             1;{}\r\nx\r\n0\r\nX-Tag: sample\r\n\r\n",
            "p".repeat(PROBE_BYTES as usize / 2 - 16)
        );
        let mut up = Cursor::new(response);
        assert!(read_probe_response(&mut up, std::time::Instant::now()).is_none());
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
