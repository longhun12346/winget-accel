//! 加速器健康状态机。
//!
//! 只做状态与选择，不碰网络（探测逻辑在 `proxy.rs`，那里已有 TLS 管线）。
//! 这样选择策略可以纯单测，而探测失败不会污染状态机的语义。

use std::sync::Mutex;

use crate::rewrite::Accel;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    /// 还没探测过
    Unknown,
    Healthy,
    Unhealthy,
}

impl Health {
    pub fn as_str(self) -> &'static str {
        match self {
            Health::Unknown => "unknown",
            Health::Healthy => "healthy",
            Health::Unhealthy => "unhealthy",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct State {
    health: Health,
    failures: u32,
    /// 实测吞吐的衰减滑动平均（KB/s）。样本不足时不可信，见 MIN_SAMPLES。
    ema_kbps: f64,
    /// 累计样本数（启动粗筛也算，记满 MIN_SAMPLES）。
    samples: u32,
    /// 连续"低于绝对下限"的次数，用于决定是否排除。
    consecutive_slow: u32,
}

/// 真实样本的衰减系数：半衰期约 20 个样本。
const EMA_DECAY: f64 = 0.966;
/// 少于这个样本数时速度不可信，权重按乐观值处理。
const MIN_SAMPLES: u32 = 3;
/// 权重地板：最慢的候选也保留 20% 份额，避免流量全压一个。
const WEIGHT_FLOOR_RATIO: f64 = 0.2;
/// 绝对下限（KB/s）：低于它说明这条链路基本没用（比直连还差）。
///
/// 刻意设得很低。实测同一时刻五个候选可能全都只有 34–40 KB/s，
/// 如果门槛设成 64 KB/s 会把所有候选一起判死，反而没有可用候选。
/// "相对太慢"由 `SLOW_RELATIVE_RATIO` 处理。
pub const SLOW_FLOOR_KBPS: f64 = 24.0;
/// 相对门槛：低于当前最快候选的这个比例，才算"太慢"。
const SLOW_RELATIVE_RATIO: f64 = 0.25;
/// 连续多少个样本都低于下限才排除（单次慢可能是抖动）。
const SLOW_STRIKES: u32 = 3;

pub struct Tracker {
    accels: Vec<Accel>,
    states: Mutex<Vec<State>>,
    threshold: u32,
}

impl Tracker {
    pub fn new(accels: Vec<Accel>, failures_before_unhealthy: u32) -> Self {
        let states = accels
            .iter()
            .map(|_| State {
                health: Health::Unknown,
                failures: 0,
                ema_kbps: 0.0,
                samples: 0,
                consecutive_slow: 0,
            })
            .collect();
        Self {
            accels,
            states: Mutex::new(states),
            threshold: failures_before_unhealthy.max(1),
        }
    }

    pub fn accels(&self) -> &[Accel] {
        &self.accels
    }

    /// 记一次失败；连续失败达到阈值才标记为不健康（避免偶发抖动就切换）。
    /// 返回是否发生了"健康 → 不健康"的转变。
    pub fn record_failure(&self, idx: usize) -> bool {
        let mut states = self.states.lock().expect("健康状态锁中毒");
        let Some(state) = states.get_mut(idx) else {
            return false;
        };
        state.failures = state.failures.saturating_add(1);
        if state.health != Health::Unhealthy && state.failures >= self.threshold {
            state.health = Health::Unhealthy;
            return true;
        }
        false
    }

    /// 记一次成功：立即恢复健康并清零计数。
    pub fn record_success(&self, idx: usize) {
        let mut states = self.states.lock().expect("健康状态锁中毒");
        if let Some(state) = states.get_mut(idx) {
            state.health = Health::Healthy;
            state.failures = 0;
        }
    }

    /// 主动探测的结论，直接覆盖状态。
    pub fn mark(&self, idx: usize, healthy: bool) {
        let mut states = self.states.lock().expect("健康状态锁中毒");
        if let Some(state) = states.get_mut(idx) {
            state.health = if healthy {
                Health::Healthy
            } else {
                Health::Unhealthy
            };
            if healthy {
                state.failures = 0;
            }
        }
    }

    /// 选一个当前该用的加速器，按配置顺序（priority 升序）。
    ///
    /// 优先 `Healthy`；若没有，退回第一个 `Unknown`——启动时还没来得及探测，
    /// 此时乐观放行比直接拒绝好，真实失败会立刻把状态推成 `Unhealthy`。
    /// 全部 `Unhealthy` 时返回 `None`。
    #[allow(dead_code)] // 单测在用；生产路径改走 current_excluding
    pub fn current(&self) -> Option<(usize, Accel)> {
        let states = self.states.lock().expect("健康状态锁中毒");
        if let Some(idx) = states.iter().position(|s| s.health == Health::Healthy) {
            return Some((idx, self.accels[idx].clone()));
        }
        if let Some(idx) = states.iter().position(|s| s.health == Health::Unknown) {
            return Some((idx, self.accels[idx].clone()));
        }
        None
    }

    pub fn is_healthy(&self, idx: usize) -> bool {
        let states = self.states.lock().expect("健康状态锁中毒");
        matches!(states.get(idx), Some(state) if state.health == Health::Healthy)
    }
    pub fn snapshot(&self) -> Vec<(String, Health)> {
        let states = self.states.lock().expect("健康状态锁中毒");
        self.accels
            .iter()
            .zip(states.iter())
            .map(|(accel, state)| (accel.host.clone(), state.health))
            .collect()
    }

    /// 所有候选都被判定为不健康。
    ///
    /// 单候选时这就是"唯一那条路断了"，必须显式报告，而不是等用户从 502 里猜。
    pub fn all_unhealthy(&self) -> bool {
        let states = self.states.lock().expect("健康状态锁中毒");
        !states.is_empty() && states.iter().all(|s| s.health == Health::Unhealthy)
    }

    pub fn healthy_count(&self) -> usize {
        let states = self.states.lock().expect("健康状态锁中毒");
        states
            .iter()
            .filter(|s| s.health == Health::Healthy)
            .count()
    }

    /// 记录一次**真实下载**的速度样本（不是探测）。
    ///
    /// 小于 64 KiB 的样本会被忽略：winget 每次先发 `Range: bytes=0-1` 探大小，
    /// 那种请求的耗时反映往返延迟而非吞吐，记进去会把速度算成接近 0。
    pub fn record_sample(&self, idx: usize, bytes: u64, secs: f64) {
        if bytes < 64 * 1024 || secs <= 0.0 {
            return;
        }
        let kbps = (bytes as f64 / 1024.0) / secs;
        let mut states = self.states.lock().expect("健康状态锁中毒");
        // 先算同期最快值（不可变借用），再取可变借用
        let best = states.iter().map(|s| s.ema_kbps).fold(0.0f64, f64::max);
        let Some(state) = states.get_mut(idx) else {
            return;
        };
        state.ema_kbps = if state.samples == 0 {
            kbps
        } else {
            state.ema_kbps * EMA_DECAY + kbps * (1.0 - EMA_DECAY)
        };
        state.samples = state.samples.saturating_add(1);

        // "太慢"要同时看绝对与相对：绝对下限挡掉基本没用的链路，
        // 相对门槛挡掉"比同期最快的差一个数量级"的链路。
        // 只用绝对门槛会在整体网络变差时把所有候选一起判死。
        let too_slow = kbps < SLOW_FLOOR_KBPS || (best > 0.0 && kbps < best * SLOW_RELATIVE_RATIO);

        if too_slow {
            state.consecutive_slow = state.consecutive_slow.saturating_add(1);
            if state.consecutive_slow >= SLOW_STRIKES {
                state.health = Health::Unhealthy;
            }
        } else {
            state.consecutive_slow = 0;
            if state.health == Health::Unhealthy {
                state.health = Health::Healthy;
            }
        }
    }

    /// 启动粗筛结果：只用来排除"明显不可用/太慢"，不用于排序。
    pub fn seed_speed(&self, idx: usize, kbps: f64) {
        let mut states = self.states.lock().expect("健康状态锁中毒");
        let Some(state) = states.get_mut(idx) else {
            return;
        };
        state.ema_kbps = kbps;
        state.samples = MIN_SAMPLES;
        state.health = if kbps < SLOW_FLOOR_KBPS {
            Health::Unhealthy
        } else {
            Health::Healthy
        };
    }

    /// 按速度加权、随机选一个候选（排除 `exclude` 与不健康的）。
    ///
    /// 用加权随机而非"永远选最快"：流量全压一个更容易把它打到限流。
    /// 样本不足的候选按当前最大值（乐观）参与，避免"还没数据"被永久压掉。
    pub fn pick_verified_excluding(&self, exclude: &[usize]) -> Option<(usize, Accel)> {
        let states = self.states.lock().expect("健康状态锁中毒");
        let cands: Vec<usize> = (0..states.len())
            .filter(|&i| !exclude.contains(&i) && states[i].health == Health::Healthy)
            .collect();
        if cands.is_empty() {
            return None;
        }

        let max_ema = cands
            .iter()
            .map(|&i| {
                if states[i].samples >= MIN_SAMPLES {
                    states[i].ema_kbps
                } else {
                    0.0
                }
            })
            .fold(0.0f64, f64::max);

        let weights: Vec<f64> = cands
            .iter()
            .map(|&i| {
                let s = &states[i];
                let base = if s.samples >= MIN_SAMPLES && s.ema_kbps > 0.0 {
                    // 有数据：用自己的速度
                    s.ema_kbps
                } else if s.samples == 0 {
                    // 探测就失败/没测到：**不能给最高权重**。
                    // 实测教训：给乐观值会让"探测失败但仍有 unknown 状态"的候选
                    // 和最快的候选同权，结果流量全落到它身上、下载直接失败。
                    max_ema * WEIGHT_FLOOR_RATIO
                } else {
                    // 有样本但不足 MIN_SAMPLES：轻微乐观
                    max_ema * 0.5
                };
                base.max(max_ema * WEIGHT_FLOOR_RATIO).max(1.0)
            })
            .collect();

        let total: f64 = weights.iter().sum();
        let mut remaining = fastrand::f64() * total;
        let mut chosen = *cands.last().expect("cands 非空");
        for (idx, w) in cands.iter().zip(weights.iter()) {
            if remaining < *w {
                chosen = *idx;
                break;
            }
            remaining -= *w;
        }
        drop(states);
        Some((chosen, self.accels[chosen].clone()))
    }

    /// 按索引取候选（pin 命中时用）。
    pub fn accel_at(&self, idx: usize) -> Option<Accel> {
        self.accels.get(idx).cloned()
    }

    /// 供 /health 与 doctor：每候选的（host, KB/s, 样本数）。
    pub fn speed_snapshot(&self) -> Vec<(String, f64, u32)> {
        let states = self.states.lock().expect("健康状态锁中毒");
        self.accels
            .iter()
            .zip(states.iter())
            .map(|(a, s)| (a.host.clone(), s.ema_kbps, s.samples))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::Scheme;

    fn accel(host: &str, priority_port: u16) -> Accel {
        Accel {
            scheme: Scheme::Https,
            host: host.to_string(),
            port: priority_port,
            prefix: String::new(),
        }
    }

    fn tracker(threshold: u32) -> Tracker {
        Tracker::new(
            vec![accel("a.example", 443), accel("b.example", 443)],
            threshold,
        )
    }

    #[test]
    fn unknown_is_usable_so_startup_is_not_blocked() {
        let t = tracker(2);
        let (idx, accel) = t.current().unwrap();
        assert_eq!(idx, 0);
        assert_eq!(accel.host, "a.example");
    }

    #[test]
    fn prefers_healthy_over_unknown() {
        let t = tracker(2);
        t.mark(1, true);
        assert_eq!(t.current().unwrap().0, 1);
    }

    #[test]
    fn falls_back_when_first_becomes_unhealthy() {
        let t = tracker(2);
        t.mark(0, false);
        assert_eq!(t.current().unwrap().0, 1);
    }

    #[test]
    fn all_unhealthy_yields_none() {
        let t = tracker(1);
        t.mark(0, false);
        t.mark(1, false);
        assert!(t.current().is_none());
    }

    #[test]
    fn failure_threshold_is_respected() {
        let t = tracker(2);
        assert!(!t.record_failure(0), "第 1 次失败还不该切换");
        assert_eq!(t.current().unwrap().0, 0);
        assert!(t.record_failure(0), "第 2 次失败应触发切换");
        assert_eq!(t.current().unwrap().0, 1);
    }

    #[test]
    fn success_restores_health_and_resets_counter() {
        let t = tracker(2);
        t.record_failure(0);
        t.record_failure(0);
        assert_eq!(t.current().unwrap().0, 1);
        t.record_success(0);
        assert_eq!(t.current().unwrap().0, 0);
        // 计数已清零，需要再次连续失败才会切换
        assert!(!t.record_failure(0));
    }

    #[test]
    fn snapshot_reports_each_accelerator() {
        let t = tracker(2);
        t.mark(1, false);
        let snap = t.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0], ("a.example".to_string(), Health::Unknown));
        assert_eq!(snap[1], ("b.example".to_string(), Health::Unhealthy));
    }

    #[test]
    fn out_of_range_index_is_ignored() {
        let t = tracker(2);
        assert!(!t.record_failure(9));
        t.record_success(9);
        t.mark(9, true);
        assert_eq!(t.snapshot().len(), 2);
    }

    #[test]
    fn all_unhealthy_only_when_every_candidate_is_down() {
        let t = tracker(1);
        assert!(!t.all_unhealthy(), "启动时是 Unknown，不该报全挂");
        t.mark(0, false);
        assert!(!t.all_unhealthy(), "还有一个 Unknown，不算全挂");
        t.mark(1, false);
        assert!(t.all_unhealthy());
    }

    #[test]
    fn recovers_from_total_outage() {
        // 单候选被判死之后，必须还能靠探测恢复——否则永久 502
        let single = Tracker::new(vec![accel("only.example", 443)], 1);
        single.mark(0, false);
        assert!(single.all_unhealthy());
        assert!(single.current().is_none());

        single.mark(0, true);
        assert!(!single.all_unhealthy());
        assert_eq!(single.current().unwrap().0, 0);
        assert_eq!(single.healthy_count(), 1);
    }

    #[test]
    fn pick_excluding_respects_exclusions() {
        let t = tracker(2);
        t.mark(0, true);
        t.mark(1, true);
        // 加权随机下不假定选中谁，只验证"落在允许集合里"
        let first = t.pick_verified_excluding(&[]).unwrap();
        assert!(first.0 < 2, "索引必须有效");
        // 排除 0 之后只能给 1
        let second = t.pick_verified_excluding(&[0]).unwrap();
        assert_eq!(second.0, 1, "排除 0 后只能是 1");
        // 都排除则没有可用
        assert!(t.pick_verified_excluding(&[0, 1]).is_none());
    }

    #[test]
    fn pick_excluding_skips_unhealthy() {
        let t = tracker(1);
        t.mark(0, true);
        t.mark(1, false);
        let got = t.pick_verified_excluding(&[]).unwrap();
        assert_eq!(got.0, 0, "应跳过不健康的候选");
    }

    #[test]
    fn candidate_that_failed_probe_is_never_selected() {
        // 这条规则曾经被放宽过（"内置候选探测失败仍可用"），
        // 当时是为了让协议用例通过而改弱生产逻辑——方向错了。
        // 现在用单测钉住：没通过实测就不能进下载路径。
        let t = tracker(2);
        t.mark(0, true);
        t.mark(1, false);
        for _ in 0..50 {
            let picked = t.pick_verified_excluding(&[]).expect("至少有 0 号可用");
            assert_eq!(picked.0, 0, "1 号未通过实测，不应被选中");
        }
    }

    #[test]
    fn all_failed_probe_yields_no_candidate() {
        let t = tracker(2);
        t.mark(0, false);
        t.mark(1, false);
        assert!(
            t.pick_verified_excluding(&[]).is_none(),
            "全部未通过实测时应返回 None（由调用方回 502），不能拿坏候选凑数"
        );
        assert!(t.all_unhealthy());
    }
    #[test]
    fn verified_picker_never_returns_unknown() {
        let t = tracker(2);
        assert!(t.pick_verified_excluding(&[]).is_none());
        t.mark(0, true);
        assert_eq!(t.pick_verified_excluding(&[]).unwrap().0, 0);
    }

    #[test]
    fn unhealthy_is_not_healthy() {
        let t = tracker(1);
        assert!(!t.is_healthy(0));
        t.mark(0, false);
        assert!(!t.is_healthy(0));
        t.mark(0, true);
        assert!(t.is_healthy(0));
    }
}
