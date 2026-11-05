//! 极简日志：控制台（带颜色）+ 追加文件（纯文本）。
//!
//! 两条输出流**内容相同但着色不同**：
//! - 控制台：按级别着色、3 字符级别标签，便于扫读
//! - 文件：不含 ANSI 转义码，便于 grep 与贴到 issue 里
//!
//! 时间戳用本地时间（Win32 `GetLocalTime`）。早先用 UTC 只是为省一个依赖，
//! 结果日志时间与其它工具差 8 小时，排障时对不上。

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
}

impl Level {
    pub fn parse(text: &str) -> Level {
        match text.to_ascii_lowercase().as_str() {
            "error" => Level::Error,
            "warn" => Level::Warn,
            "debug" => Level::Debug,
            _ => Level::Info,
        }
    }

    /// 固定 3 字符，保证日志列对齐。
    fn tag(self) -> &'static str {
        match self {
            Level::Error => "ERR",
            Level::Warn => "WRN",
            Level::Info => "INF",
            Level::Debug => "DBG",
        }
    }

    /// 控制台着色（仅在检测到真控制台时使用）。
    fn color(self) -> &'static str {
        match self {
            Level::Error => "\x1b[31m", // 红
            Level::Warn => "\x1b[33m",  // 黄
            Level::Info => "\x1b[0m",   // 默认
            Level::Debug => "\x1b[90m", // 灰
        }
    }
}

const RESET: &str = "\x1b[0m";

pub struct Logger {
    level: Level,
    path: PathBuf,
    /// 是否给控制台输出着色。输出被重定向时为 false。
    color: bool,
    lock: Mutex<()>,
}

/// 全局 logger。
///
/// 为什么需要：`autoenv`（装 CA / 设 PAC / 退出还原）与 `ca`（到期轮换）
/// 里的都是**运行时事件**，必须进日志；但这两个模块拿不到 `Arc<Logger>`。
/// 它们原先用裸 `println!`，导致这些最关键的行既没有级别/颜色，
/// 也**不写进日志文件**——用户回头排查时恰恰看不到它们。
static GLOBAL: std::sync::OnceLock<Mutex<GlobalState>> = std::sync::OnceLock::new();

/// 日志文件路径的独立登记（**在锁外可读**）。
///
/// 供退出路径使用：控制台事件线程与看门狗子进程必须能写日志，
/// 但它们不能去抢 `GLOBAL` 里的那把锁——主线程可能正持有它，
/// 在事件线程里等锁会让进程退不掉（Ctrl+C 之后卡死）。
static LOG_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

struct GlobalState {
    level: Level,
    path: PathBuf,
    color: bool,
}

/// 日志文件大小上限。超过就把当前文件改名成 `<name>.1`，重新开一个新文件。
///
/// 为什么需要：本工具设计上要长时间挂着（窗口不关即生效），而每建一条隧道都会写一行
/// `CONNECT … mode=TUNNEL`。不轮转的话 `proxy.log` 会无限增长——用户几个月后发现
/// 一个几百 MB 的日志，而且（旧格式只有 `HH:MM:SS`）根本分不清哪行是哪天的。
const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;
/// 每写这么多行检查一次大小：每行都 `stat` 一次没必要。
const ROTATE_CHECK_EVERY: u64 = 128;
/// 已写行数，用于节流大小检查。
static WRITE_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 拼一行日志（时间戳 + 3 字符级别 + 正文）。所有输出路径共用，保证格式一致。
pub fn format_line(level: Level, msg: &str) -> String {
    format!("{} {} {msg}", timestamp(), level.tag())
}

/// 追加一行到指定文件，并按需轮转。
///
/// **不加任何锁**：用于看门狗子进程（它拿不到全局 logger）。极端情况下可能与主进程的
/// 行交错，但这只发生在一行诊断信息上，比"退出时什么都不记"好得多。
pub fn append_line(path: &std::path::Path, line: &str) {
    append_line_to(path, line);
}

fn append_line_to(path: &std::path::Path, line: &str) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
    }
    maybe_rotate(path);
}

fn maybe_rotate(path: &std::path::Path) {
    let count = WRITE_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if count % ROTATE_CHECK_EVERY == 0 {
        rotate_if_too_big(path, MAX_LOG_BYTES);
    }
}

/// 超过 `max` 就把 `path` 改名为 `path.1`（旧备份被覆盖）。
///
/// 只保留一份备份：目的是"别无限长"，不是"留审计归档"。失败静默——
/// 日志轮转不该影响主流程。
fn rotate_if_too_big(path: &std::path::Path, max: u64) {
    let too_big = std::fs::metadata(path)
        .map(|meta| meta.len() > max)
        .unwrap_or(false);
    if !too_big {
        return;
    }
    let mut backup = path.as_os_str().to_os_string();
    backup.push(".1");
    let _ = std::fs::rename(path, std::path::PathBuf::from(backup));
}

/// 当前日志文件路径；未初始化时为 None。
pub fn current_path() -> Option<PathBuf> {
    LOG_PATH.get().cloned()
}

/// 退出路径专用：写一行日志，**不取锁**。
///
/// 只在 `GLOBAL` 已初始化时写文件；否则退化为 stderr（绝不 panic、绝不阻塞）。
pub fn emergency(msg: &str) {
    let line = format_line(Level::Info, msg);
    match LOG_PATH.get() {
        Some(path) => append_line(path, &line),
        None => eprintln!("{line}"),
    }
}

/// 用全局 logger 输出；未初始化时退化为纯文本 println（保持可用）。
pub fn info(msg: &str) {
    emit(Level::Info, msg);
}

pub fn warn(msg: &str) {
    emit(Level::Warn, msg);
}

pub fn error(msg: &str) {
    emit(Level::Error, msg);
}

fn emit(level: Level, msg: &str) {
    let Some(state) = GLOBAL.get() else {
        println!("{msg}");
        return;
    };
    let guard = state.lock().expect("日志锁中毒");
    if level > guard.level {
        return;
    }
    let plain = format_line(level, msg);
    if guard.color {
        println!("{}{plain}{RESET}", level.color());
    } else {
        println!("{plain}");
    }
    write_file(&guard.path, &plain);
}

/// 追加一行到日志文件（含轮转）。失败静默 —— 日志不该影响主流程。
fn write_file(path: &std::path::Path, line: &str) {
    append_line_to(path, line);
}

impl Logger {
    pub fn new(level: Level, path: PathBuf) -> Self {
        let color = crate::console::enable_ansi();
        // 首次创建时登记为全局，供 autoenv / ca 使用
        let _ = GLOBAL.set(Mutex::new(GlobalState {
            level,
            path: path.clone(),
            color,
        }));
        // 路径单独登记一份，供退出路径在**不取锁**的前提下写日志
        let _ = LOG_PATH.set(path.clone());
        // 启动时先检查一次大小。
        //
        // 常规检查挂在 `maybe_rotate` 上，每 128 次写入才做一次——实测过：
        // 若日志已经是 9 MB（比如上次用过 debug），而这次以 info 级别跑了很短时间
        // （远不到 128 行就退出），轮转根本不会触发，那个大文件就一直留在磁盘上。
        // 最坏情况是"每次运行都不足 128 行"，于是它永远不轮转。
        // 启动时补一次检查，成本是一次 metadata 调用。
        rotate_if_too_big(&path, MAX_LOG_BYTES);
        Self {
            level,
            path,
            color,
            lock: Mutex::new(()),
        }
    }

    pub fn log(&self, level: Level, msg: &str) {
        if level > self.level {
            return;
        }
        let plain = format_line(level, msg);

        // 先拿锁再输出：多线程（每连接一线程 + 探测线程）下，
        // 先 println 再取锁会让控制台出现半行交错。
        let _guard = self.lock.lock();
        if self.color {
            println!("{}{plain}{RESET}", level.color());
        } else {
            println!("{plain}");
        }

        append_line_to(&self.path, &plain);
    }

    pub fn info(&self, msg: &str) {
        self.log(Level::Info, msg);
    }

    /// 该级别是否会被输出。
    ///
    /// 给"先判级别、再决定要不要拼字符串"的调用方用：诊断日志常常要遍历、
    /// 格式化一堆运行时状态（例如每次选候选都列出全部候选的速度），
    /// 级别不够时那些拼装纯属浪费。
    pub fn enabled(&self, level: Level) -> bool {
        level <= self.level
    }

    pub fn warn(&self, msg: &str) {
        self.log(Level::Warn, msg);
    }

    pub fn error(&self, msg: &str) {
        self.log(Level::Error, msg);
    }
}

/// `YYYY-MM-DD HH:MM:SS`（**本地时间**）。
///
/// 带日期是必要的：本工具要长时间挂着，日志跨天很常见，只有 `HH:MM:SS` 时
/// "这个 502 是今天的还是三天前的"根本判断不了。本地时间而非 UTC：
/// 早先用 UTC 只是为省一个依赖，结果日志与其它工具差 8 小时，排障时对不上。
fn timestamp() -> String {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    // SAFETY: 传一个本地 SYSTEMTIME 的可写指针，SDK 约定该调用只写这块内存
    unsafe {
        let mut st = std::mem::zeroed();
        GetLocalTime(&mut st);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
        )
    }
}

/// 从**左侧**截断长路径，保留尾部。
///
/// 下载路径的关键信息在文件名，硬切右侧会切掉最有用的一段
/// （之前日志里出现过 `...pc-w` 这种半截单词）。
pub fn shorten(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count <= max || max == 0 {
        return text.to_string();
    }
    let keep: String = text.chars().skip(count - (max - 1)).collect();
    format!("…{keep}")
}

/// 把请求路径变成**可以写进日志**的形式：丢掉查询串，只保留它的长度。
///
/// 为什么必须丢：`shorten` 保留的是**尾部**，而带签名的 URL 尾部正是查询串。
/// 实测 GitHub release 资产会 302 到
/// `release-assets.githubusercontent.com/...?sp=r&sv=…&se=…&sig=…`（Azure SAS 签名）；
/// 原样记下来就是把凭据写进 `proxy.log`——而用户会把它贴进 issue。
/// design.md 承诺"不记录敏感内容"，这一条得在代码里兑现，不能只写在文档上。
///
/// 输出形如 `…/file.zip?<64B 查询串已省略>`：既保留"有没有查询串"这个诊断信息，
/// 又不泄露内容。
pub fn loggable(target: &str, max: usize) -> String {
    match target.split_once('?') {
        Some((path, query)) if !query.is_empty() => {
            let note = format!("?<{len}B 查询串已省略>", len = query.len());
            let budget = max.saturating_sub(note.chars().count()).max(1);
            format!("{}{note}", shorten(path, budget))
        }
        _ => shorten(target, max),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shorten_keeps_the_tail() {
        let path = "/https://github.com/sharkdp/fd/releases/download/v10.5.0/fd-v10.5.0-x86_64-pc-windows-msvc.zip";
        let out = shorten(path, 40);
        assert!(out.starts_with('…'), "应以省略号开头: {out}");
        assert_eq!(out.chars().count(), 40);
        assert!(out.ends_with(".zip"), "必须保留文件名结尾: {out}");
    }

    #[test]
    fn shorten_leaves_short_text_alone() {
        assert_eq!(shorten("abc", 10), "abc");
        assert_eq!(shorten("abc", 3), "abc");
    }

    /// 日志里**不能**出现查询串：带签名的 URL 尾部就是凭据。
    ///
    /// 实测来源：GitHub release 资产 302 到
    /// `release-assets.githubusercontent.com/…?sp=r&sv=2018-11-09&se=…&sig=…`（Azure SAS）。
    /// `shorten` 保留尾部，于是签名会被原样写进 `proxy.log`——而用户会把它贴进 issue。
    #[test]
    fn loggable_drops_query_string() {
        let signed = "/https://release-assets.githubusercontent.com/github-production-release-asset/1/2/Git-2.43.0-64-bit.exe?sp=r&sv=2018-11-09&sig=SECRETTOKEN";
        let out = loggable(signed, 60);

        assert!(!out.contains("SECRETTOKEN"), "签名绝不能进日志: {out}");
        assert!(!out.contains("sig="), "查询串整体都不该出现: {out}");
        assert!(!out.contains('?') || out.contains("查询串已省略"), "{out}");
        assert!(out.contains("Git-2.43.0-64-bit.exe"), "文件名要保留: {out}");
        assert!(out.chars().count() <= 60, "仍要受长度上限约束: {out}");
    }

    /// 没有查询串时行为与 `shorten` 完全一致（不改变既有日志）。
    #[test]
    fn loggable_without_query_matches_shorten() {
        let path = "/https://github.com/sharkdp/fd/releases/download/v10.5.0/fd.zip";
        assert_eq!(loggable(path, 40), shorten(path, 40));
        assert_eq!(loggable("abc", 10), "abc");
        // 空查询串（末尾只有一个 `?`）也按无查询处理
        assert_eq!(loggable("/x?", 40), "/x?");
    }

    #[test]
    fn appended_line_lands_in_file_with_timestamp_and_tag() {
        // 退出路径（控制台事件 / 看门狗）就是靠 append_line 落盘的，
        // 这里把"能写进去、格式对"钉住——否则那条 PAC-RESTORED 会静默丢失。
        let dir = std::env::temp_dir().join(format!("wg-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.log");
        let _ = std::fs::remove_file(&path);
        append_line(
            &path,
            &format_line(Level::Info, "PAC-RESTORED (console-event: Ctrl+C)"),
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains(" INF PAC-RESTORED (console-event: Ctrl+C)"),
            "{text}"
        );
        assert!(text.trim_end().len() > 30, "应含时间戳前缀: {text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn level_tags_are_fixed_width() {
        for level in [Level::Error, Level::Warn, Level::Info, Level::Debug] {
            assert_eq!(level.tag().len(), 3, "级别标签必须等宽以便对齐");
        }
    }

    #[test]
    fn level_ordering_filters_correctly() {
        // Error < Warn < Info < Debug：配成 Info 时应过滤掉 Debug
        assert!(Level::Debug > Level::Info);
        assert!(Level::Warn < Level::Info);
    }

    /// 时间戳必须带日期：本工具会挂很多天，只有 `HH:MM:SS` 时分不清哪天的日志。
    #[test]
    fn timestamp_carries_date_and_time() {
        let line = format_line(Level::Info, "x");
        let head: Vec<char> = line.chars().take(19).collect();
        assert_eq!(head.len(), 19, "{line}");
        assert_eq!(
            (head[4], head[7]),
            ('-', '-'),
            "日期应为 YYYY-MM-DD: {line}"
        );
        assert_eq!(head[10], ' ', "日期与时间之间应有空格: {line}");
        assert_eq!(
            (head[13], head[16]),
            (':', ':'),
            "时间应为 HH:MM:SS: {line}"
        );
        assert!(
            head[..4].iter().all(|ch| ch.is_ascii_digit()),
            "年份应是四位数字: {line}"
        );
        assert!(head[11..13].iter().all(|ch| ch.is_ascii_digit()), "{line}");
    }

    /// 启动时必须检查一次大小，不能只靠"每 128 次写入"。
    ///
    /// 实测过的坑：日志已是 9 MB（上次用过 debug），这次以 info 级别只跑几秒就退出
    /// （远不到 128 行），`maybe_rotate` 从不触发，那个大文件就永远留在磁盘上。
    /// 极端情况下"每次运行都不足 128 行"→ 永不轮转。
    /// 这里用 `Logger::new` 验证启动即轮转（它是公开入口，内部同样调用 rotate_if_too_big）。
    #[test]
    fn oversized_log_is_rotated_at_startup() {
        let dir = std::env::temp_dir().join(format!("wg-log-startup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.log");
        let backup = dir.join("big.log.1");

        // 造一个明显超过 8 MiB 的文件（内容无所谓，只看大小与改名）
        std::fs::write(&path, vec![b'x'; MAX_LOG_BYTES as usize + 1024]).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() > MAX_LOG_BYTES);

        let _logger = Logger::new(Level::Info, path.clone());

        assert!(backup.exists(), "启动时应把超标日志改名为 .1");
        let new_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        assert!(
            new_len < MAX_LOG_BYTES,
            "启动后当前日志不该仍然是超标的（实际 {new_len} 字节）"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 日志超过阈值要轮转成 `.log.1`，且只保留一份备份。
    #[test]
    fn oversized_log_is_rotated_to_single_backup() {
        let dir = std::env::temp_dir().join(format!("wg-log-rotate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("r.log");
        let backup = dir.join("r.log.1");

        std::fs::write(&path, b"0123456789").unwrap();
        rotate_if_too_big(&path, 5);
        assert_eq!(
            std::fs::read(&backup).unwrap(),
            b"0123456789",
            "超过阈值应整体改名成 .1"
        );
        assert!(!path.exists(), "轮转后原文件不该还在");

        // 未超阈值：不动
        std::fs::write(&path, b"abc").unwrap();
        rotate_if_too_big(&path, 5);
        assert!(path.exists(), "小文件不该被轮转");
        assert_eq!(std::fs::read(&backup).unwrap(), b"0123456789");

        // 再超一次：旧备份被覆盖，只留一份
        std::fs::write(&path, b"second").unwrap();
        rotate_if_too_big(&path, 3);
        assert_eq!(
            std::fs::read(&backup).unwrap(),
            b"second",
            "只保留一份备份，旧的覆盖掉"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 大小检查是按行数节流的（每 `ROTATE_CHECK_EVERY` 行一次）。
    /// 这里证明节流确实会走到轮转，而不是"写了个从未被调用的函数"。
    #[test]
    fn write_counter_reaches_rotation_within_one_window() {
        let dir = std::env::temp_dir().join(format!("wg-log-throttle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.log");
        std::fs::write(&path, vec![b'x'; (MAX_LOG_BYTES + 1) as usize]).unwrap();

        // 无论全局计数从哪里开始，连续 128 次调用必然命中一次 `count % 128 == 0`
        for _ in 0..ROTATE_CHECK_EVERY {
            maybe_rotate(&path);
        }

        let mut backup = path.as_os_str().to_os_string();
        backup.push(".1");
        assert!(
            std::path::Path::new(&backup).exists(),
            "128 次写入内应至少触发一次轮转"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `enabled()` 决定"要不要为一条 debug 日志先拼字符串"。
    ///
    /// 用它的地方是选候选：43 个候选时每次都要遍历并格式化一遍，
    /// 默认 info 级别下那些拼装全是白做。
    #[test]
    fn enabled_reports_whether_level_would_be_written() {
        let dir = std::env::temp_dir().join(format!("wg-log-enabled-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let logger = Logger::new(Level::Info, dir.join("e.log"));

        assert!(logger.enabled(Level::Error));
        assert!(logger.enabled(Level::Warn));
        assert!(logger.enabled(Level::Info));
        assert!(
            !logger.enabled(Level::Debug),
            "info 级别不该为 debug 拼字符串"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
