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
//! 只在"需要时才切"，且切了会还原，避免影响同一控制台里的其它程序。

/// 切到 UTF-8 之后的还原守卫；`None` 表示不需要或无法切换。
pub struct Utf8Console(u32);

impl Drop for Utf8Console {
    fn drop(&mut self) {
        #[link(name = "kernel32")]
        extern "system" {
            fn SetConsoleOutputCP(code_page: u32) -> i32;
        }
        // SAFETY: 只是把代码页改回进入时的值，无指针/生命周期问题
        unsafe {
            SetConsoleOutputCP(self.0);
        }
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
        Some(Utf8Console(current))
    }
}

const UTF8_CODE_PAGE: u32 = 65001;

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

    #[test]
    fn utf8_code_page_constant_is_correct() {
        assert_eq!(UTF8_CODE_PAGE, 65001);
    }

    #[test]
    fn ensure_utf8_is_idempotent_when_called_twice() {
        // 第一次可能切换（返回守卫），第二次应当看到已是 65001 而返回 None
        let first = ensure_utf8();
        let second = ensure_utf8();
        assert!(second.is_none(), "已是 UTF-8 时不应重复切换");
        drop(second);
        drop(first);
    }
}

