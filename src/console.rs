//! 控制台代码页适配。
//!
//! 程序输出固定是 UTF-8。中文 Windows 的控制台默认是 936（GBK），
//! 于是 UTF-8 的中文会显示成乱码——**问题在控制台，不在输出**。
//!
//! 所以做法是：启动时检测当前输出代码页，
//! - 已经是 65001（UTF-8）→ 什么都不做
//! - 不是 → 临时切到 65001，退出时还原（不让副作用留在用户终端上）
//! - 没有控制台（服务/重定向）→ 跳过
//!
//! **还原有两条路径**，缺一条就会留下副作用：
//! - `Drop`：正常返回 / `?` 提前返回
//! - 控制台事件（Ctrl+C、关窗口）：Rust 在 Ctrl+C 下**不展开栈**，`Drop` 不会执行，
//!   所以 `autoenv::on_console_event` 里也要调 [`restore_pending`]
//!
//! 仍未覆盖的是被强杀（任务管理器 / `taskkill /f`）——那种死法既没有 `Drop`
//! 也没有控制台事件，代码页会停在 65001。代价有限（同一控制台里后续命令可能显示异常，
//! 重新 `chcp` 即可），但**不要**声称"任何退出方式都会还原"。

use std::sync::atomic::{AtomicU32, Ordering};

/// 进入时看到的原始代码页；0 表示"不需要还原"。
static ORIGINAL_CP: AtomicU32 = AtomicU32::new(0);

/// 切到 UTF-8 之后的还原守卫；`None` 表示不需要或无法切换。
pub struct Utf8Console(u32);

impl Drop for Utf8Console {
    fn drop(&mut self) {
        set_console_cp(self.0);
        // 已经由 Drop 还原过，控制台事件那条路径不必再来一次
        ORIGINAL_CP.store(0, Ordering::SeqCst);
    }
}

/// 需要时把控制台输出代码页切到 UTF-8，返回还原守卫。
pub fn ensure_utf8() -> Option<Utf8Console> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleOutputCP() -> u32;
        fn SetConsoleOutputCP(code_page: u32) -> i32;
    }

    // SAFETY: 两个调用都只涉及一个 u32 参数/返回值，无内存安全问题
    unsafe {
        let current = GetConsoleOutputCP();
        // 0 = 没有 attached console（服务、重定向到管道时也可能非 0）
        if current == 0 || current == UTF8_CODE_PAGE {
            return None;
        }
        if SetConsoleOutputCP(UTF8_CODE_PAGE) == 0 {
            return None;
        }
        ORIGINAL_CP.store(current, Ordering::SeqCst);
        Some(Utf8Console(current))
    }
}

const UTF8_CODE_PAGE: u32 = 65001;

/// 还挂着待还原的代码页（`None` 表示没有需要还原的）。
pub fn pending_restore() -> Option<u32> {
    match ORIGINAL_CP.load(Ordering::SeqCst) {
        0 => None,
        code_page => Some(code_page),
    }
}

/// 退出路径专用：把代码页改回进入时的值，并把"待还原"清掉。
///
/// 幂等、不 panic、不阻塞——它会被控制台事件线程调用（见模块头说明）。
/// 没有待还原项时什么都不做。
pub fn restore_pending() {
    let code_page = ORIGINAL_CP.swap(0, Ordering::SeqCst);
    if code_page != 0 {
        set_console_cp(code_page);
    }
}

fn set_console_cp(code_page: u32) {
    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleOutputCP(code_page: u32) -> i32;
    }
    // SAFETY: 只是设置控制台输出代码页，无指针/生命周期问题
    unsafe {
        SetConsoleOutputCP(code_page);
    }
}

/// 尝试为当前控制台启用 ANSI 转义序列（VT processing）。
///
/// 返回 true 表示**可以安全地输出颜色**：既启用了 VT，stdout 也确实连着控制台。
/// 输出被重定向到文件时为 false —— 否则 ANSI 转义码会写进日志文件，
/// 用任何编辑器打开都是乱码。
pub fn enable_ansi() -> bool {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(which: u32) -> *mut core::ffi::c_void;
        fn GetConsoleMode(handle: *mut core::ffi::c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: *mut core::ffi::c_void, mode: u32) -> i32;
    }
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle.is_null() {
            return false;
        }
        let mut mode: u32 = 0;
        // GetConsoleMode 失败说明 stdout 不是控制台（被重定向）
        if GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return true; // 已经开了
        }
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 控制台代码页是**进程级共享状态**：这两个用例都会改它，必须串行执行，
    /// 否则并行跑时会互相踩（曾经把 `ensure_utf8_is_idempotent_when_called_twice`
    /// 弄成偶发失败）。
    static CP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn utf8_code_page_constant_is_correct() {
        assert_eq!(UTF8_CODE_PAGE, 65001);
    }

    #[test]
    fn ensure_utf8_is_idempotent_when_called_twice() {
        let _guard = CP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 第一次可能切换（返回守卫），第二次应当看到已是 65001 而返回 None
        let first = ensure_utf8();
        let second = ensure_utf8();
        assert!(second.is_none(), "已是 UTF-8 时不应重复切换");
        drop(second);
        drop(first);
    }

    /// 控制台事件那条路径靠 `pending_restore` / `restore_pending` 的配对来还原。
    ///
    /// 这里直接摆弄登记值（本环境 stdout 是管道、没有 attached console，
    /// 所以 `ensure_utf8` 会走"不切换"的分支，测不到真实切换）。
    /// 覆盖的是**登记与清除的语义**：设过就报出来、还原一次后不再报。
    #[test]
    fn pending_restore_is_recorded_and_cleared_once() {
        let _guard = CP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 先确保干净
        restore_pending();
        assert_eq!(pending_restore(), None, "初始应当没有待还原项");

        ORIGINAL_CP.store(936, Ordering::SeqCst);
        assert_eq!(pending_restore(), Some(936));

        restore_pending();
        assert_eq!(pending_restore(), None, "还原一次后应清除，避免重复设置");

        // 幂等：没有待还原项时再调一次也不该 panic
        restore_pending();
        assert_eq!(pending_restore(), None);
    }
}
