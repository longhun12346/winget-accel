//! 运行期计数器与 `/health` 输出。
//!
//! 键名是协议的一部分，Rust 协议集成测试直接比较 `/health` 返回的 JSON。

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Stats {
    /// 接入的连接数（含隧道与 MITM）。
    pub connects: AtomicU64,
    /// 走 MITM 的连接数（含改写与"终止 TLS 但透传"）。
    pub mitm: AtomicU64,
    /// 走隧道的连接数（不解析内容）。
    pub tunnel: AtomicU64,
    /// 改写过 URL 的请求数。
    pub rewrites: AtomicU64,
    /// **只统计 MITM 路径**的正文字节，不含隧道。
    ///
    /// 隧道是"我们不解析的字节"：双向 `io::copy` 拿到的计数只算单方向、还要和
    /// 客户端写超时纠缠，拿它当"总流量"会给出一个看起来精确、实际没意义的数。
    /// 所以宁可少统计一个方向，也不要把两种口径混进同一个字段。
    pub bytes: AtomicU64,
    pub errors: AtomicU64,
    /// 上游返回 429/503 的次数（被限流）。
    pub ratelimited: AtomicU64,
    /// 因**并发上限**被 503 拒绝的连接数。
    ///
    /// 这是个"降级信号"：非 0 说明本机同时有太多连接（常见于浏览器开着多个
    /// `*.github.com` 标签页），而名额只有 64 个。只在日志里出现过，
    /// 用户贴 `/health` 时看不到——所以单列一个计数。
    pub conn_limited: AtomicU64,
}

/// 运行期学到的一条"候选 × host 不可用"（`/health` 里 `learned` 的一项）。
#[derive(serde::Serialize)]
pub struct LearnedBlock {
    /// 候选下标（与 `accelerators` 数组同序）。
    pub candidate: usize,
    pub host: String,
}

/// 单个加速器候选的健康状态（`/health` 里的一项）。
#[derive(serde::Serialize)]
pub struct AccelHealth {
    pub host: String,
    pub health: &'static str,
    /// 实测吞吐（KB/s，衰减滑动平均）；样本不足时不可信。
    pub kbps: u32,
    /// 真实下载样本数。
    pub samples: u32,
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
    ///
    /// `uptime_seconds` 由调用方传入（进程启动到现在的秒数）：
    /// 排查"这个响应到底来自哪个实例、跑了多久"时，没有它就只能靠猜。
    pub fn health_json(
        &self,
        status: &str,
        accelerators: Vec<AccelHealth>,
        uptime_seconds: u64,
        learned: Vec<LearnedBlock>,
        pin_saturated: bool,
    ) -> String {
        #[derive(serde::Serialize)]
        struct Doc<'a> {
            version: &'a str,
            /// JSON 里是 `uptimeSeconds`（与配置文件的 camelCase 风格一致），
            /// Rust 侧仍用 snake_case 命名。
            #[serde(rename = "uptimeSeconds")]
            uptime_seconds: u64,
            /// 运行期学到的"某候选对某 host 不可用"组合数（会过期，不是配置）。
            #[serde(rename = "learnedBlocks")]
            learned_blocks: usize,
            /// 具体是哪几对——只给数字回答不了"为什么这个候选没被用"。
            learned: Vec<LearnedBlock>,
            connects: u64,
            mitm: u64,
            tunnel: u64,
            rewrites: u64,
            bytes: u64,
            errors: u64,
            ratelimited: u64,
            /// 因并发上限被拒的连接数（降级信号，见 `Stats::conn_limited`）。
            #[serde(rename = "connLimitRejects")]
            conn_limit_rejects: u64,
            /// 绑定表是否已饱和（饱和后同文件的多个分片可能散到不同候选）。
            #[serde(rename = "pinSaturated")]
            pin_saturated: bool,
            status: &'a str,
            accelerators: Vec<AccelHealth>,
        }

        let doc = Doc {
            version: env!("CARGO_PKG_VERSION"),
            uptime_seconds,
            learned_blocks: learned.len(),
            learned,
            connects: self.connects.load(Ordering::Relaxed),
            mitm: self.mitm.load(Ordering::Relaxed),
            tunnel: self.tunnel.load(Ordering::Relaxed),
            rewrites: self.rewrites.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            ratelimited: self.ratelimited.load(Ordering::Relaxed),
            conn_limit_rejects: self.conn_limited.load(Ordering::Relaxed),
            pin_saturated,
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
        let json = stats.health_json("ok", Vec::new(), 0, Vec::new(), false);
        for key in ["connects", "mitm", "tunnel", "rewrites", "bytes", "errors"] {
            assert!(json.contains(&format!("\"{key}\":0")), "缺少 {key}: {json}");
        }
        assert!(json.contains("\"status\":\"ok\""), "{json}");
        assert!(json.contains("\"accelerators\":[]"), "{json}");
    }

    /// `/health` 要能回答"这是哪个实例、跑了多久"。
    ///
    /// 排障时拿到一份 JSON 却不知道它来自哪个版本、是不是刚才那个进程，很常见。
    #[test]
    fn health_json_reports_version_and_uptime() {
        let stats = Stats::default();
        let json = stats.health_json(
            "ok",
            Vec::new(),
            123,
            vec![LearnedBlock {
                candidate: 1,
                host: "codeload.github.com".into(),
            }],
            true,
        );
        assert!(
            json.contains(&format!("\"version\":\"{}\"", env!("CARGO_PKG_VERSION"))),
            "{json}"
        );
        assert!(json.contains("\"uptimeSeconds\":123"), "{json}");
        // 必须是合法 JSON（字段加错位置时这里会立刻炸）
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("必须是合法 JSON");
        assert_eq!(parsed["uptimeSeconds"].as_u64(), Some(123));
        // 运行期学到的能力限制要能看到具体组合，否则"为什么这个候选没被用"无从判断
        assert_eq!(parsed["learnedBlocks"].as_u64(), Some(1), "{json}");
        // 两个"降级信号"也要能在 /health 里看到，而不是只能在日志里翻
        assert_eq!(parsed["pinSaturated"].as_bool(), Some(true), "{json}");
        assert_eq!(parsed["connLimitRejects"].as_u64(), Some(0), "{json}");
        assert_eq!(
            parsed["learned"][0]["candidate"].as_u64(),
            Some(1),
            "{json}"
        );
        assert_eq!(
            parsed["learned"][0]["host"].as_str(),
            Some("codeload.github.com"),
            "{json}"
        );
        // 计数必须与列表长度一致（不能各算各的）
        assert_eq!(
            parsed["learnedBlocks"].as_u64().unwrap() as usize,
            parsed["learned"].as_array().unwrap().len()
        );
    }

    #[test]
    fn counters_are_reflected_in_json() {
        let stats = Stats::default();
        Stats::bump(&stats.rewrites);
        Stats::add(&stats.bytes, 1024);
        let json = stats.health_json("down", Vec::new(), 42, Vec::new(), false);
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
            kbps: 0,
            samples: 0,
        }];
        let json = stats.health_json("ok", accels, 7, Vec::new(), false);
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
                kbps: 500,
                samples: 5,
            },
            AccelHealth {
                host: "b.example".into(),
                health: "unhealthy",
                kbps: 0,
                samples: 0,
            },
        ];
        let json = stats.health_json("ok", accels, 7, Vec::new(), false);
        assert!(json.contains("\"host\":\"a.example\""), "{json}");
        assert!(json.contains("\"health\":\"unhealthy\""), "{json}");
    }
}
