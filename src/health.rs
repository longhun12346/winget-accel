//! 加速器健康状态机。
//!
//! 只做状态与选择，不碰网络（探测逻辑在 `proxy.rs`，那里已有 TLS 管线）。
//! 这样选择策略可以纯单测，而探测失败不会污染状态机的语义。

use std::sync::Mutex;
use std::time::Duration;

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
    /// 最近一次速度样本（或启动粗筛）的时刻；`None` 表示从没测过。
    ///
    /// 相对门槛只该拿"最近的"数据当基准：EMA 不会随时间自己衰减，
    /// 拿一小时前的数字比现在，会把正在正常工作的候选判成"太慢"。
    last_sample: Option<std::time::Instant>,
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
///
/// 注释里一直写的是"差一个数量级"，所以取 0.1。早先是 0.25（4 倍），
/// 而"排除"是硬判据（`Unhealthy` 之后完全不再被选中），实测会把一个稳定的
/// 100 KB/s 候选判死——可它比绝对下限（24 KB/s）高 4 倍，明明能用。
/// 4 倍这种差距本来就该由**权重**（EMA 已经算了）体现，而不是直接踢出候选池。
const SLOW_RELATIVE_RATIO: f64 = 0.1;
/// 相对门槛只用**这段时间内**的样本做基准。
///
/// EMA 只在有新样本时才变化，所以一个"一小时前很快、之后再没测过"的候选会**永远**
/// 抬高基准；拿它去比当前候选，就会把正在正常工作的候选判成"太慢"。
/// 超过这个窗口的样本不参与基准计算（宁可只按绝对下限判）。
const BASELINE_WINDOW: Duration = Duration::from_secs(600);
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
                last_sample: None,
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

    /// 主动探测的结论，**直接覆盖**状态：一轮即定，不累计失败次数。
    ///
    /// 与 [`Self::record_failure`] 的差别是刻意的，不是漏了阈值：
    /// - 探测是**主动测量**——这一轮没测到就是没测到；继续保留 `Healthy`
    ///   只会让请求打到明明连不上的候选上，把失败推迟到用户那边；
    /// - `failuresBeforeUnhealthy` 只约束**真实下载**失败（单次抖动不该引发切换）。
    ///
    /// 代价（见 design.md §7）：单轮网络抖动可能让全部候选同时判死
    /// （`ALL-ACCEL-DOWN`，请求立即 502），恢复靠"全挂时 30 秒重探"兜住。
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
    /// 首页可达不能证明能下载；新候选和被排除的候选都须重新取样验证。
    pub fn needs_verification(&self, idx: usize) -> bool {
        let states = self.states.lock().expect("健康状态锁中毒");
        states
            .get(idx)
            .is_none_or(|state| state.health != Health::Healthy || state.samples == 0)
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
        let now = std::time::Instant::now();
        let mut states = self.states.lock().expect("健康状态锁中毒");
        // 基准只取**最近**的样本：过期样本不参与，否则会永久抬高基准（见 BASELINE_WINDOW）
        let best = states
            .iter()
            .filter(|s| {
                s.last_sample
                    .is_some_and(|at| now.duration_since(at) <= BASELINE_WINDOW)
            })
            .map(|s| s.ema_kbps)
            .fold(0.0f64, f64::max);
        let Some(state) = states.get_mut(idx) else {
            return;
        };
        state.ema_kbps = if state.samples == 0 {
            kbps
        } else {
            state.ema_kbps * EMA_DECAY + kbps * (1.0 - EMA_DECAY)
        };
        state.samples = state.samples.saturating_add(1);
        state.last_sample = Some(now);

        // "太慢"要同时看绝对与相对：绝对下限挡掉基本没用的链路，
        // 相对门槛挡掉"比同期最快的差一个数量级"的链路。
        // 只用绝对门槛会在整体网络变差时把所有候选一起判死；
        // 没有近期基准（best == 0）时只按绝对下限判，不猜。
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
        state.consecutive_slow = 0;
        state.failures = 0;
        // 启动粗筛也是"证据"，打上时间戳，让它能参与相对基准
        state.last_sample = Some(std::time::Instant::now());
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
    #[allow(dead_code)] // 生产路径统一走 `_where` 版本；保留本方法供单测直接调用
    pub fn pick_verified_excluding(&self, exclude: &[usize]) -> Option<(usize, Accel)> {
        self.pick_verified_excluding_where(exclude, |_| true)
    }

    /// 同上，但额外用一个外部判据过滤候选（用于 host × 加速器 能力矩阵）。
    ///
    /// 矩阵的判断属于配置语义（`App::accel_supports`），放在这里会污染状态机，
    /// 所以用闭包注入：状态机只管"健康与权重"，"能不能用于这个 host"由调用方决定。
    pub fn pick_verified_excluding_where<F>(
        &self,
        exclude: &[usize],
        allow: F,
    ) -> Option<(usize, Accel)>
    where
        F: Fn(usize) -> bool,
    {
        let states = self.states.lock().expect("健康状态锁中毒");
        let cands: Vec<usize> = (0..states.len())
            .filter(|&i| !exclude.contains(&i) && states[i].health == Health::Healthy && allow(i))
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

    /// 把 EMA 的时间常数**量化**下来——它是唯一没有被数字说明的调参。
    ///
    /// 半衰期 = ln(0.5)/ln(EMA_DECAY) ≈ 20 个样本：也就是"20 个真实样本之后，
    /// 旧速度的权重降到一半"。这条测试把它钉住，改了常量就会红，强迫重新想一遍。
    #[test]
    fn ema_half_life_is_about_twenty_samples() {
        let half_life = 0.5f64.ln() / EMA_DECAY.ln();
        assert!(
            (half_life - 20.0).abs() < 1.0,
            "半衰期应约 20 个样本，实际 {half_life:.1}（EMA_DECAY={EMA_DECAY}）"
        );
    }

    /// 阶跃响应：速度从 100 跳到 400 KB/s 后，需要多少个样本才追到新值的 90%？
    ///
    /// 实测（按 `EMA_DECAY` 逐样本迭代）：**59 个样本**。理论值是
    /// ln(0.1)/ln(0.5) ≈ 3.32 个半衰期 ≈ 66 个样本，差异来自离散化
    /// （第一步只走 3.4%，而连续指数衰减的头一小段更快）。
    ///
    /// 这个数字说明"候选变快后权重多久跟上"——大约 60 个真实样本。
    /// 变慢也是同样的时间常数，所以**急性故障不靠 EMA**：由 `SLOW_STRIKES = 3`
    /// （连续 3 个慢样本即判 Unhealthy）兜底。两者分工明确，不必把 EMA 调快。
    #[test]
    fn ema_reaches_ninety_percent_after_one_half_life() {
        // 用纯公式模拟，不依赖 Tracker：EMA 的更新就是一行线性插值。
        let mut ema = 100.0f64;
        let target = 400.0f64;
        let mut samples = 0;
        while ema < target * 0.9 && samples < 200 {
            ema = ema * EMA_DECAY + target * (1.0 - EMA_DECAY);
            samples += 1;
        }
        // 90% 需要约 3.3 个半衰期（ln(0.1)/ln(0.5)≈3.32 → 约 66 个样本）。
        // 这里只断言"量级对"，避免把精确数字写死成脆弱的测试。
        assert!(
            (40..=80).contains(&samples),
            "追到 90% 应在 40~80 个样本之间，实际 {samples}"
        );
    }
    /// 加权随机必须**真的按权重分配**，不能退化成"总选第一个"或"均匀随机"。
    ///
    /// 此前完全没有分布测试：权重算错（遍历提前 break、remaining 初始化写错）
    /// 会让流量全压一个候选，而功能上"能下载"，很难被发现。
    /// 用 1:4 两个候选跑 4000 次，检验频率比例（容差 ±5 个百分点，避免随机性偶发失败）。
    #[test]
    fn weighted_pick_follows_the_weights() {
        let t = tracker(1);
        t.mark(0, true);
        t.mark(1, true);
        t.seed_speed(0, 100.0); // 1 份
        t.seed_speed(1, 400.0); // 4 份

        let mut counts = [0usize; 2];
        let rounds = 4000;
        for _ in 0..rounds {
            let (idx, _) = t.pick_verified_excluding(&[]).expect("两个都健康");
            counts[idx] += 1;
        }

        let fast = counts[1] as f64 / rounds as f64;
        assert!(
            (fast - 0.80).abs() < 0.05,
            "快候选应约占 80%，实际 {:.1}%（counts={counts:?}）",
            fast * 100.0
        );
        assert!(counts[0] > 0, "慢候选也必须有机会被选中");
    }

    /// 全部候选都没有速度样本时退化成**均匀随机**，而不是全压在第一个。
    ///
    /// `max_ema` 为 0 时每个权重都被 `.max(1.0)` 兜到 1.0，这是刻意的：
    /// 没数据就别假装知道谁快。
    #[test]
    fn no_samples_falls_back_to_uniform() {
        let t = tracker(1);
        t.mark(0, true);
        t.mark(1, true);

        let mut counts = [0usize; 2];
        let rounds = 2000;
        for _ in 0..rounds {
            let (idx, _) = t.pick_verified_excluding(&[]).expect("两个都健康");
            counts[idx] += 1;
        }
        let ratio = counts[0] as f64 / rounds as f64;
        assert!(
            (ratio - 0.5).abs() < 0.06,
            "无样本时应接近 50/50，实际 {:.1}%（counts={counts:?}）",
            ratio * 100.0
        );
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
    fn picker_honors_capability_predicate() {
        // 能力矩阵（design.md §7）：两个候选都健康，但只有 1 号声明支持该 host
        let t = tracker(1);
        t.mark(0, true);
        t.mark(1, true);
        let got = t
            .pick_verified_excluding_where(&[], |idx| idx == 1)
            .expect("1 号可用");
        assert_eq!(got.0, 1, "只能选声明支持该 host 的候选");

        // 唯一支持者被排除时，必须返回 None（换了不支持的候选只会拿到 403/404）
        assert!(t
            .pick_verified_excluding_where(&[1], |idx| idx == 1)
            .is_none());
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
    fn homepage_success_does_not_replace_download_verification() {
        let t = tracker(2);
        assert!(t.needs_verification(0));
        t.mark(0, true);
        assert!(t.needs_verification(0), "首页可达但没有下载样本");
        t.seed_speed(0, 200.0);
        assert!(!t.needs_verification(0));
        t.mark(0, false);
        assert!(t.needs_verification(0), "被排除后必须重新验证下载");
        t.seed_speed(0, 1.0);
        assert!(t.needs_verification(0), "太慢的候选不能靠首页可达复活");
    }

    #[test]
    fn completed_slow_downloads_remain_excluded() {
        let t = tracker(2);
        t.seed_speed(0, 800.0);
        for _ in 0..SLOW_STRIKES {
            // 与生产调用顺序一致：先记录 HTTP 成功，再记录吞吐判据。
            t.record_success(0);
            t.record_sample(0, 64 * 1024, 8.0);
        }
        assert!(!t.is_healthy(0));
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

    /// 钉住"探测"与"下载失败"两套判定语义的差别（design.md §7）。
    ///
    /// 曾经只有代码里有这个区别、文档里写成"连续 2 次失败才判不健康"，
    /// 读文档的人会以为探测也有容错次数。现在两边一致，并由此用例护住：
    /// 探测一轮即定，`failuresBeforeUnhealthy` 只数真实下载失败。
    #[test]
    fn probe_verdict_is_immediate_while_download_failures_use_threshold() {
        // 探测：阈值设成 3，一次探测失败也必须立刻判死
        let t = tracker(3);
        t.mark(0, true);
        assert_eq!(t.current().unwrap().0, 0, "起点是健康的 0 号");
        t.mark(0, false);
        assert_eq!(t.current().unwrap().0, 1, "探测失败一轮即定，不等阈值");
        assert!(!t.is_healthy(0));

        // 对照：下载失败要连续 3 次才判死
        let t2 = tracker(3);
        t2.mark(0, true);
        assert!(!t2.record_failure(0), "第 1 次不到阈值");
        assert!(!t2.record_failure(0), "第 2 次不到阈值");
        assert!(t2.record_failure(0), "第 3 次达阈值才切换");
        assert!(!t2.is_healthy(0));
    }

    /// 相对门槛不能用**过期**样本当基准。
    ///
    /// 实测过：A 启动时测出 500 KB/s、之后再也没有新样本（EMA 不会随时间衰减），
    /// B 稳定跑 100 KB/s（比绝对下限 24 高 4 倍，完全可用）——
    /// 旧逻辑拿 A 的旧值当基准，3 个样本后把 B 判成 `Unhealthy`，直接从候选池里踢掉。
    #[test]
    fn stale_speed_samples_do_not_poison_the_relative_baseline() {
        let t = tracker(3);
        t.seed_speed(0, 500.0);
        t.seed_speed(1, 100.0);

        // 把 A 的样本时间戳改成"很久以前"（超过 BASELINE_WINDOW）
        {
            let mut states = t.states.lock().unwrap();
            states[0].last_sample =
                Some(std::time::Instant::now() - BASELINE_WINDOW - Duration::from_secs(1));
        }

        // B 连续 3 次 100 KB/s：没有近期基准可依，只按绝对下限判 → 应当保持健康
        for _ in 0..3 {
            t.record_sample(1, 200 * 1024, 2.0);
        }
        assert!(
            t.is_healthy(1),
            "100 KB/s 远高于绝对下限，不该因为别的候选的过期样本被判死"
        );
    }

    /// 相对门槛应按"差一个数量级"（0.1）判，而不是 4 倍（旧值 0.25）。
    ///
    /// 4 倍的差距本来就该由权重体现（EMA 已经算进去了），不该直接踢出候选池。
    #[test]
    fn moderately_slower_candidate_keeps_its_health() {
        let t = tracker(3);
        t.seed_speed(0, 400.0);
        t.seed_speed(1, 100.0); // 4 倍慢，但完全可用

        for _ in 0..SLOW_STRIKES {
            t.record_sample(1, 200 * 1024, 2.0); // 100 KB/s
        }
        assert!(
            t.is_healthy(1),
            "4 倍慢只该降低权重，不该判成不健康（相对门槛是 0.1，即 10 倍）"
        );
    }

    /// 但真正"差一个数量级"仍然要被判死；绝对下限也要照常生效。
    #[test]
    fn order_of_magnitude_slower_is_still_excluded() {
        let t = tracker(3);
        t.seed_speed(0, 800.0);
        t.seed_speed(1, 800.0);
        // B 掉到 40 KB/s：是 800 的 5%…… 但仍高于绝对下限 24
        for _ in 0..SLOW_STRIKES {
            t.record_sample(1, 80 * 1024, 2.0); // 40 KB/s
        }
        assert!(
            !t.is_healthy(1),
            "40 KB/s 相对 800 KB/s 不足 10%，应判为太慢"
        );

        // 绝对下限：不管别人多慢，低于 24 KB/s 一律排除
        let t2 = tracker(3);
        for _ in 0..SLOW_STRIKES {
            t2.record_sample(0, 16 * 1024, 2.0); // 8 KB/s
        }
        assert!(!t2.is_healthy(0), "低于绝对下限必须排除");
    }
}
