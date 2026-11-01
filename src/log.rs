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

    /// 目前致命错误都经 `Result` 往上抛、由 Rust 打出来，
    /// 保留这一级是为了将来"降级继续跑"的场景。
    #[allow(dead_code)]
    pub fn error(&self, msg: &str) {
        self.log(Level::Error, msg);
    }
}

/// HH:MM:SS（UTC）
fn timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        % 86_400;
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}
