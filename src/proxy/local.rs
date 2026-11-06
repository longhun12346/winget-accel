//! 本地 PAC 与健康状态端点，包括连接名额耗尽时的兜底。

use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;

use crate::http;
use crate::log::Level;
use crate::pac;

use super::{Proxy, IO_TIMEOUT};

impl Proxy {
    /// 名额已满时的兜底：如果这是发往**本地端点**（PAC / health）的请求，
    /// 就地服务并返回 true（不占名额、不开线程）。
    ///
    /// 为什么值得单独处理：Windows 会定期重新取 PAC，而把 64 个名额占满的正是下载本身。
    /// 若 PAC 请求也被 503，浏览器就可能退回直连——"下载越多、加速越容易失效"。
    /// 实测过：64 个连接占满后 `GET /winget-accel.pac` 返回 503。
    ///
    /// 只接受本地端点，其余返回 false 让调用方照常 503；请求头读取受
    /// 200 ms 的读超时约束，不会成为新的挂起点。
    pub(super) fn serve_local_if_saturated(&self, stream: &mut TcpStream, peer: &str) -> bool {
        // 用**很短**的读超时：这是"名额已满"的兜底路径，不能为了等一个不发数据的连接
        // 而拖住 accept 循环——实测过，用 10 秒读超时会让原来"第 65 个连接立刻拿到 503"
        // 的契约退化成"卡到超时"。真正的 PAC/health 客户端会立刻把请求头发过来。
        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let Ok(head) = http::read_head(stream) else {
            return false;
        };
        let Some(req) = http::parse_head(&head) else {
            return false;
        };
        let path = req.target.split('?').next().unwrap_or("");
        // 只认这两个本地端点；CONNECT 与其它路径一律按"满"处理。
        if req.method != "GET" || !matches!(path, "/winget-accel.pac" | "/health") {
            return false;
        }
        self.log.log(
            Level::Debug,
            &format!("CONN-LIMIT-BYPASS peer={peer} path={path}（本地端点不占名额）"),
        );
        let stream_owned = match stream.try_clone() {
            Ok(clone) => clone,
            Err(_) => return false,
        };
        let _ = self.serve_local(stream_owned, &req);
        true
    }
    /// 明文请求：只提供 PAC 与 health，其余 405。
    pub(super) fn serve_local(&self, mut stream: TcpStream, req: &http::Head) -> Result<()> {
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
                let learned: Vec<crate::stats::LearnedBlock> = self
                    .learned
                    .blocked_pairs()
                    .into_iter()
                    .map(|(candidate, host)| crate::stats::LearnedBlock { candidate, host })
                    .collect();
                let body = self.stats.health_json(
                    status,
                    accelerators,
                    self.started.elapsed().as_secs(),
                    learned,
                    self.pins_saturated.load(Ordering::Relaxed),
                );
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
