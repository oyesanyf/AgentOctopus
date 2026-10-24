//! Interactive Console & `conhost.exe` Hardening (`EDR-VEC-23`)
//!
//! Adapted from `D:\harfile\OshoosiClaw\crates\osoosi-core\src\console_defense.rs`:
//! Prevents interactive console selection hangs (Windows QuickEdit Mode pause where clicking
//! a terminal window blocks stdout writes indefinitely) and ensures background child commands
//! execute with `CREATE_NO_WINDOW (0x08000000)`.

/// Standard Windows console input flags (`wincon.h`).
pub const ENABLE_INSERT_MODE: u32 = 0x0020;
pub const ENABLE_QUICK_EDIT_MODE: u32 = 0x0040;
pub const ENABLE_EXTENDED_FLAGS: u32 = 0x0080;
pub const ENABLE_MOUSE_INPUT: u32 = 0x0010;

/// Standard Windows process creation flag (`winbase.h`) to prevent allocating a console window.
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Computes the hardened console input mode bitmask (`EDR-VEC-23`):
/// - Strips `ENABLE_QUICK_EDIT_MODE` (`0x0040`), `ENABLE_INSERT_MODE` (`0x0020`), and `ENABLE_MOUSE_INPUT` (`0x0010`).
/// - Sets `ENABLE_EXTENDED_FLAGS` (`0x0080`) so the Windows console subsystem honors clearing QuickEdit.
#[inline]
pub const fn compute_hardened_console_mode(current_mode: u32) -> u32 {
    (current_mode & !(ENABLE_QUICK_EDIT_MODE | ENABLE_INSERT_MODE | ENABLE_MOUSE_INPUT))
        | ENABLE_EXTENDED_FLAGS
}

/// Verifies whether a Windows console input mode bitmask is hardened against QuickEdit/Insert hangs.
#[inline]
pub const fn is_console_mode_hardened(mode: u32) -> bool {
    let quick_edit_disabled = (mode & ENABLE_QUICK_EDIT_MODE) == 0;
    let insert_mode_disabled = (mode & ENABLE_INSERT_MODE) == 0;
    let mouse_input_disabled = (mode & ENABLE_MOUSE_INPUT) == 0;
    let extended_flags_set = (mode & ENABLE_EXTENDED_FLAGS) != 0;
    quick_edit_disabled && insert_mode_disabled && mouse_input_disabled && extended_flags_set
}

/// Applies `EDR-VEC-23` console hardening to the current process's `STD_INPUT_HANDLE` on Windows.
/// Safe no-op when running headless without an attached console or on non-Windows targets.
pub fn harden_windows_console() -> Result<u32, String> {
    #[cfg(windows)]
    {
        extern "system" {
            fn GetStdHandle(nStdHandle: u32) -> *mut std::ffi::c_void;
            fn GetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, lpMode: *mut u32) -> i32;
            fn SetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, dwMode: u32) -> i32;
        }
        const STD_INPUT_HANDLE: u32 = (-10i32) as u32;
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() || handle == (-1isize as *mut std::ffi::c_void) {
            return Ok(ENABLE_EXTENDED_FLAGS);
        }

        let mut current_mode: u32 = 0;
        let got = unsafe { GetConsoleMode(handle, &mut current_mode) };
        if got == 0 {
            // Headless / redirected stdin pipe (not an interactive console)
            return Ok(ENABLE_EXTENDED_FLAGS);
        }

        let new_mode = compute_hardened_console_mode(current_mode);
        let set_ok = unsafe { SetConsoleMode(handle, new_mode) };
        if set_ok == 0 {
            return Err("Failed to apply hardened SetConsoleMode".to_string());
        }
        Ok(new_mode)
    }

    #[cfg(not(windows))]
    {
        Ok(ENABLE_EXTENDED_FLAGS)
    }
}

/// Extension trait for `std::process::Command` to enforce `CREATE_NO_WINDOW (0x08000000)` on Windows.
pub trait CommandConsoleExt {
    fn enforce_no_window(&mut self) -> &mut Self;
}

impl CommandConsoleExt for std::process::Command {
    fn enforce_no_window(&mut self) -> &mut Self {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            self.creation_flags(CREATE_NO_WINDOW);
        }
        self
    }
}
