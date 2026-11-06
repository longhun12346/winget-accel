//! 运行期学到的"某候选对某 host 不可用"。
//!
//! 为什么需要：不同加速器对 host 的支持并不一致（能力矩阵，design.md §7）。
//! 配置里的 `accelerators[].hosts` 是**人工声明**的，默认不声明；而实测数据要逐个验，
//! 不能猜。于是运行期只能一个个试——试错是有代价的：
//! winget 的首个 `Range: bytes=0-1` 只有 15 s 总预算、单候选最多 5 s，
//! 几个"对 github.com 返回 403"的候选就能把预算吃光，最终回 502。
//!
//! 这里记的是**证据**，不是猜测：
//! - 只有 `403`/`404` 算"这个候选不愿服务这个 URL"；
//!   `429`/`5xx`/超时都不算（那是限流或故障，说明不了 host 支持情况）；
//! - 同一个 `(候选, host)` 累计 **2 次**不支持且**最近 30 分钟内没有成功证据**，才临时排除；
//! - 一次成功保留 30 分钟正面证据（宁可多试，不要误杀）；
//! - 排除有 TTL，到期后重新给机会——候选可能后来支持了。
//!
//! 为什么门槛设成"2 次且零成功"而不是"1 次"：单个文件 404（上游删包）会让所有候选
//! 同时返回 404，若一次就排除，会把该 host 上本来能用的候选全部拉黑半小时。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 累计多少次"明确不支持"才排除该组合。
const STRIKES_BEFORE_BLOCK: u32 = 2;
/// 排除的有效期：到期后重新尝试。
const BLOCK_TTL: Duration = Duration::from_secs(30 * 60);
/// 表规模上限。超出时先清理过期项，仍然超就移除最早到期项——宁可忘记，也不要无界增长。
const MAX_ENTRIES: usize = 512;

#[derive(Clone, Copy, Default)]
struct Entry {
    unsupported: u32,
    successful: bool,
    /// 证据或排除的到期时刻。
    until: Option<Instant>,
}

impl Entry {
    fn blocked(&self, now: Instant) -> bool {
        !self.successful
            && self.unsupported >= STRIKES_BEFORE_BLOCK
            && self.until.is_some_and(|until| until > now)
    }
}

/// 运行期学到的能力限制。线程安全；查询是 O(1)。
pub struct LearnedCaps {
    entries: Mutex<HashMap<(usize, String), Entry>>,
}

impl Default for LearnedCaps {
    fn default() -> Self {
        Self::new()
    }
}

impl LearnedCaps {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// 记一次"该候选对该 host 返回 403/404"。
    ///
    /// 返回 `true` 表示**这一次**让它变成了被排除状态（调用方据此打日志）。
    pub fn note_unsupported(&self, idx: usize, host: &str) -> bool {
        let key = (idx, host.to_ascii_lowercase());
        let mut entries = self.entries.lock().expect("能力学习锁中毒");
        let now = Instant::now();
        let entry = entry_at(&mut entries, key, now);
        if entry.successful {
            return false;
        }
        let was_blocked = entry.blocked(now);
        entry.unsupported = entry.unsupported.saturating_add(1);
        if entry.unsupported >= STRIKES_BEFORE_BLOCK {
            entry.until = Some(now + BLOCK_TTL);
        }
        !was_blocked && entry.blocked(now)
    }

    /// 记一次成功：保留有期限的正面证据，避免单个文件的 404 误伤整个 host。
    pub fn note_success(&self, idx: usize, host: &str) {
        let key = (idx, host.to_ascii_lowercase());
        let mut entries = self.entries.lock().expect("能力学习锁中毒");
        *entry_at(&mut entries, key, Instant::now()) = Entry {
            successful: true,
            until: Some(Instant::now() + BLOCK_TTL),
            ..Entry::default()
        };
    }

    /// 该组合当前是否应被跳过。
    pub fn is_blocked(&self, idx: usize, host: &str) -> bool {
        let key = (idx, host.to_ascii_lowercase());
        let now = Instant::now();
        let entries = self.entries.lock().expect("能力学习锁中毒");
        entries.get(&key).is_some_and(|entry| entry.blocked(now))
    }

    /// 当前被排除的 `(候选下标, host)` 列表，按 host、下标排序（诊断用）。
    ///
    /// 只给个数字不足以回答"为什么这个候选没被用"——那正是要排查的问题，
    /// 所以 `/health` 里给出具体组合。
    pub fn blocked_pairs(&self) -> Vec<(usize, String)> {
        let now = Instant::now();
        let entries = self.entries.lock().expect("能力学习锁中毒");
        let mut out: Vec<(usize, String)> = entries
            .iter()
            .filter(|(_, entry)| entry.blocked(now))
            .map(|((idx, host), _)| (*idx, host.clone()))
            .collect();
        out.sort();
        out
    }
}

fn entry_at(
    entries: &mut HashMap<(usize, String), Entry>,
    key: (usize, String),
    now: Instant,
) -> &mut Entry {
    if !entries.contains_key(&key) && entries.len() >= MAX_ENTRIES {
        entries.retain(|_, entry| entry.until.is_some_and(|until| until > now));
        if entries.len() >= MAX_ENTRIES {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.until)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&oldest);
            }
        }
    }
    let entry = entries.entry(key).or_default();
    if entry.until.is_none_or(|until| until <= now) {
        *entry = Entry {
            until: Some(now + BLOCK_TTL),
            ..Entry::default()
        };
    }
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_strike_is_not_enough() {
        let caps = LearnedCaps::new();
        assert!(!caps.note_unsupported(0, "github.com"), "第一次不该排除");
        assert!(!caps.is_blocked(0, "github.com"));
        assert_eq!(caps.blocked_pairs().len(), 0);
    }

    #[test]
    fn two_strikes_block_and_only_then_report_transition() {
        let caps = LearnedCaps::new();
        assert!(!caps.note_unsupported(3, "github.com"));
        assert!(caps.note_unsupported(3, "github.com"), "第二次才形成排除");
        assert!(caps.is_blocked(3, "github.com"));
        // 已经排除之后再记一次，不算"新的转变"（避免刷日志）
        assert!(!caps.note_unsupported(3, "github.com"));
        assert_eq!(caps.blocked_pairs().len(), 1);
    }

    #[test]
    fn recent_success_prevents_later_refusals_from_blocking_pair() {
        let caps = LearnedCaps::new();
        caps.note_unsupported(1, "codeload.github.com");
        caps.note_success(1, "codeload.github.com");
        caps.note_unsupported(1, "codeload.github.com");
        caps.note_unsupported(1, "codeload.github.com");
        assert!(
            !caps.is_blocked(1, "codeload.github.com"),
            "成功过就说明它支持该 host，不能因为后来的 404 被拉黑"
        );
    }

    #[test]
    fn pairs_are_independent_per_host_and_candidate() {
        let caps = LearnedCaps::new();
        caps.note_unsupported(0, "github.com");
        caps.note_unsupported(0, "github.com");
        assert!(caps.is_blocked(0, "github.com"));
        assert!(
            !caps.is_blocked(0, "codeload.github.com"),
            "别的 host 不受牵连"
        );
        assert!(!caps.is_blocked(1, "github.com"), "别的候选不受牵连");
    }

    #[test]
    fn host_matching_is_case_insensitive() {
        let caps = LearnedCaps::new();
        caps.note_unsupported(0, "GitHub.COM");
        caps.note_unsupported(0, "github.com");
        assert!(caps.is_blocked(0, "GITHUB.com"));
    }

    #[test]
    fn block_expires_after_ttl() {
        // 直接构造一个已到期的记录：正常路径要等 30 分钟，不适合放进单测
        let caps = LearnedCaps::new();
        {
            let mut entries = caps.entries.lock().unwrap();
            entries.insert(
                (0, "github.com".to_string()),
                Entry {
                    unsupported: 5,
                    successful: false,
                    until: Some(Instant::now() - Duration::from_secs(1)),
                },
            );
        }
        assert!(!caps.is_blocked(0, "github.com"), "TTL 到期后应重新给机会");
        assert_eq!(caps.blocked_pairs().len(), 0);
    }

    #[test]
    fn expired_success_requires_two_fresh_strikes() {
        let caps = LearnedCaps::new();
        caps.note_success(0, "github.com");
        caps.entries
            .lock()
            .unwrap()
            .get_mut(&(0, "github.com".to_string()))
            .unwrap()
            .until = Some(Instant::now() - Duration::from_secs(1));
        assert!(!caps.note_unsupported(0, "github.com"));
        assert!(caps.note_unsupported(0, "github.com"));
    }

    #[test]
    fn table_never_exceeds_its_cap() {
        let caps = LearnedCaps::new();
        for i in 0..(MAX_ENTRIES * 2) {
            caps.note_success(i, "github.com");
            caps.note_unsupported(i, "github.com");
        }
        let len = caps.entries.lock().unwrap().len();
        assert!(len <= MAX_ENTRIES, "表规模必须受限，实际 {len}");
    }
}
