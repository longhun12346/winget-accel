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

impl Logger {
    pub fn new(level: Level, path: PathBuf) -> Self {
        Self {
            level,
            path,
            color: crate::console::enable_ansi(),
            lock: Mutex::new(()),
        }
    }

    pub fn log(&self, level: Level, msg: &str) {
        if level > self.level {
            return;
        }
        let plain = format!("{} {} {msg}", timestamp(), level.tag());

        if self.color {
            println!("{}{plain}{RESET}", level.color());
        } else {
            println!("{plain}");
        }

        let _guard = self.lock.lock();
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = writeln!(file, "{plain}");
        }
    }

    pub fn info(&self, msg: &str) {
        self.log(Level::Info, msg);
    }

    pub fn warn(&self, msg: &str) {
        self.log(Level::Warn, msg);
    }

    pub fn error(&self, msg: &str) {
        self.log(Level::Error, msg);
    }
}

/// HH:MM:SS（**本地时间**）。
fn timestamp() -> String {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    // SAFETY: 传一个本地 SYSTEMTIME 的可写指针，SDK 约定该调用只写这块内存
    unsafe {
        let mut st = std::mem::zeroed();
        GetLocalTime(&mut st);
        format!("{:02}:{:02}:{:02}", st.wHour, st.wMinute, st.wSecond)
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
}
