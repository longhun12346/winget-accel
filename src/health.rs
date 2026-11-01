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
}

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

    pub fn snapshot(&self) -> Vec<(String, Health)> {
        let states = self.states.lock().expect("健康状态锁中毒");
        self.accels
            .iter()
            .zip(states.iter())
            .map(|(accel, state)| (accel.host.clone(), state.health))
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
        Tracker::new(vec![accel("a.example", 443), accel("b.example", 443)], threshold)
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
}
