//! 运行期计数器与 `/health` 输出。
//!
//! 键名与 Python 原型保持一致，这样 docs/test-plan.md 的 LCL-02 用例
//! 可以直接复用（同一套断言，换二进制）。

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Stats {
    pub connects: AtomicU64,
    pub mitm: AtomicU64,
    pub tunnel: AtomicU64,
    pub rewrites: AtomicU64,
    pub bytes: AtomicU64,
    pub errors: AtomicU64,
}

impl Stats {
    pub fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"connects\":{},\"mitm\":{},\"tunnel\":{},\"rewrites\":{},\"bytes\":{},\"errors\":{}}}",
            self.connects.load(Ordering::Relaxed),
            self.mitm.load(Ordering::Relaxed),
            self.tunnel.load(Ordering::Relaxed),
            self.rewrites.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_has_all_counters_and_starts_at_zero() {
        let stats = Stats::default();
        let json = stats.to_json();
        for key in ["connects", "mitm", "tunnel", "rewrites", "bytes", "errors"] {
            assert!(json.contains(&format!("\"{key}\":0")), "缺少 {key}");
        }
        assert_eq!(json.matches(':').count(), 6);
    }

    #[test]
    fn counters_are_monotonic() {
        let stats = Stats::default();
        Stats::bump(&stats.rewrites);
        Stats::add(&stats.bytes, 1024);
        assert!(stats.to_json().contains("\"rewrites\":1"));
        assert!(stats.to_json().contains("\"bytes\":1024"));
    }
}
