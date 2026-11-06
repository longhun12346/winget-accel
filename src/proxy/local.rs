//! Local PAC and health endpoints; available even when download slots are full.
use super::Proxy;
use crate::{http, pac};
use hyper::{body::Incoming, Request, Response};
use std::sync::atomic::Ordering;

impl Proxy {
    /// 明文请求：只提供 PAC 与 health，其余 405。
    pub(super) fn local_response(
        &self,
        req: &Request<Incoming>,
        peer: &str,
    ) -> Response<http::BoxBody> {
        let path = req.uri().path();

        match (req.method().as_str(), path) {
            ("GET", "/winget-accel.pac") => {
                self.log.info(&format!("PAC-SERVED peer={peer}"));
                let snapshot = self.routing.snapshot();
                let body = pac::build_with_routes(
                    self.app.listen.port(),
                    &self.app.rewrite_hosts,
                    &snapshot.pac_routes(),
                );
                let mut response = http::response(200, "application/x-ns-proxy-autoconfig", body);
                response
                    .headers_mut()
                    .insert("cache-control", "no-store, max-age=0".parse().unwrap());
                response
            }
            ("GET", "/health") => {
                // 计数器 + 每个候选的健康状态 + 总体状态，交给 serde_json 序列化
                let speeds = self.health.speed_snapshot();
                let ranked = self
                    .health
                    .ranked_verified_where(|idx| !self.cooldowns.is_service_blocked(idx));
                let scores = self.health.selection_scores();
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
                            pool: match ranked.iter().position(|idx| *idx == i) {
                                Some(rank) if rank < crate::health::ACTIVE_CANDIDATES => "active",
                                Some(rank) if rank < crate::health::POOL_CANDIDATES => "standby",
                                _ => "discovery",
                            },
                            selection_score: scores[i],
                        }
                    })
                    .collect();
                let routing = self.routing.snapshot();
                let status = if ranked.is_empty() && !routing.hosts.iter().all(|host| host.direct) {
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
                    Some(routing),
                );
                http::response(200, "application/json", body)
            }
            _ => http::response(
                405,
                "text/plain; charset=utf-8",
                "只支持 GET /winget-accel.pac 与 /health",
            ),
        }
    }
}
