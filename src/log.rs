//! 极简日志：控制台 + 追加文件。
//!
//! 时间戳用 UTC（不引入 chrono/time 依赖）。日志只用于排障，
//! 不参与任何判定逻辑。

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

    fn tag(self) -> &'static str {
        match self {
            Level::Error => "E",
            Level::Warn => "W",
            Level::Info => "I",
            Level::Debug => "D",
        }
    }
}

pub struct Logger {
    level: Level,
    path: PathBuf,
    lock: Mutex<()>,
}

impl Logger {
    pub fn new(level: Level, path: PathBuf) -> Self {
        Self {
            level,
            path,
            lock: Mutex::new(()),
        }
    }

    pub fn log(&self, level: Level, msg: &str) {
        if level > self.level {
            return;
        }
        let line = format!("{} {} {msg}", timestamp(), level.tag());
        println!("{line}");
        let _guard = self.lock.lock();
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(file, "{line}");
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
///
/// 早先用 UTC，理由只是"不想引入时间依赖"——但国内用户看到的时间与本地差 8 小时，
/// 排障时对不上任何其它日志。为一个依赖牺牲可用性不值得，改用 Win32 的 GetLocalTime。
fn timestamp() -> String {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    // SAFETY: 传一个本地 SYSTEMTIME 的可写指针，SDK 约定该调用只写这块内存
    unsafe {
        let mut st = std::mem::zeroed();
        GetLocalTime(&mut st);
        format!("{:02}:{:02}:{:02}", st.wHour, st.wMinute, st.wSecond)
    }
}

