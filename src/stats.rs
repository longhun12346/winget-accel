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

/// 单个加速器候选的健康状态（`/health` 里的一项）。
#[derive(serde::Serialize)]
pub struct AccelHealth {
    pub host: String,
    pub health: &'static str,
}

impl Stats {
    pub fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    /// 生成 `/health` 的 JSON。
    ///
    /// 早先用 `format!` 手拼 JSON，并在 `proxy.rs` 里靠
    /// `body.insert_str(body.len() - 1, ...)` 往末尾 `}` 前插字段——
    /// 只要某个 host 含 `"` 或 `\`，整个 JSON 就坏。这里改成序列化结构体，
    /// 转义交给 serde_json。
    pub fn health_json(&self, status: &str, accelerators: Vec<AccelHealth>) -> String {
        #[derive(serde::Serialize)]
        struct Doc<'a> {
            connects: u64,
            mitm: u64,
            tunnel: u64,
            rewrites: u64,
            bytes: u64,
            errors: u64,
            status: &'a str,
            accelerators: Vec<AccelHealth>,
        }

        let doc = Doc {
            connects: self.connects.load(Ordering::Relaxed),
            mitm: self.mitm.load(Ordering::Relaxed),
            tunnel: self.tunnel.load(Ordering::Relaxed),
            rewrites: self.rewrites.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            status,
            accelerators,
        };
        serde_json::to_string(&doc).unwrap_or_else(|_| "{}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_json_has_all_counters_at_zero() {
        let stats = Stats::default();
        let json = stats.health_json("ok", Vec::new());
        for key in ["connects", "mitm", "tunnel", "rewrites", "bytes", "errors"] {
            assert!(json.contains(&format!("\"{key}\":0")), "缺少 {key}: {json}");
        }
        assert!(json.contains("\"status\":\"ok\""), "{json}");
        assert!(json.contains("\"accelerators\":[]"), "{json}");
    }

    #[test]
    fn counters_are_reflected_in_json() {
        let stats = Stats::default();
        Stats::bump(&stats.rewrites);
        Stats::add(&stats.bytes, 1024);
        let json = stats.health_json("down", Vec::new());
        assert!(json.contains("\"rewrites\":1"), "{json}");
        assert!(json.contains("\"bytes\":1024"), "{json}");
        assert!(json.contains("\"status\":\"down\""), "{json}");
    }

    #[test]
    fn host_with_quotes_still_produces_valid_json() {
        // 手拼 JSON 时这种输入会破坏结构；serde 会正确转义
        let stats = Stats::default();
        let accels = vec![AccelHealth {
            host: "evil\"host\\x".to_string(),
            health: "unknown",
        }];
        let json = stats.health_json("ok", accels);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("必须是合法 JSON");
        assert_eq!(
            parsed["accelerators"][0]["host"].as_str().unwrap(),
            "evil\"host\\x"
        );
    }

    #[test]
    fn accelerators_are_listed_with_health() {
        let stats = Stats::default();
        let accels = vec![
            AccelHealth {
                host: "a.example".into(),
                health: "healthy",
            },
            AccelHealth {
                host: "b.example".into(),
                health: "unhealthy",
            },
        ];
        let json = stats.health_json("ok", accels);
        assert!(json.contains("\"host\":\"a.example\""), "{json}");
        assert!(json.contains("\"health\":\"unhealthy\""), "{json}");
    }
}
