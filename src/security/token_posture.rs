//! Process Token Posture Inspection & Mandatory De-Elevation (Finding 7).
//!
//! When `start.exe` is launched from an elevated (Administrator / High integrity) context, every
//! in-process arm inherits that token: `SeBackupPrivilege`, `SeDebugPrivilege`, `reg save HKLM\SAM`,
//! Volume Shadow Copy access and raw disk reads all become reachable — a full breakout that no
//! user-mode sandbox check can stop.
//!
//! This module provides:
//! - [`current_token_posture`] / [`TokenPosture::of_process`]: real `GetTokenInformation` inspection
//!   (`TokenElevation`, `TokenIntegrityLevel`, `TokenGroups`, `TokenPrivileges`).
//! - [`create_deelevated_token`]: `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE | LUA_TOKEN)` with
//!   `BUILTIN\Administrators` set to deny-only and the integrity label lowered to Medium.
//! - [`spawn_deelevated`]: `CreateProcessAsUserW` in `CREATE_SUSPENDED` state; the *child's* token is
//!   re-inspected **before** `ResumeThread` and the process is terminated (never resumed) if it is
//!   elevated, above Medium integrity, has Administrators enabled, or holds any dangerous privilege.
//! - [`relaunch_deelevated_or_fail`]: used at the top of `start.exe` / `agent_octopus` `main`.
//!   There is no "continue elevated" fallback.

use crate::core::types::OctopusSecurityError;
use serde::{Deserialize, Serialize};

/// Environment marker set (process-scoped only) on a de-elevated relaunch to prevent relaunch loops.
pub const DEELEVATED_ENV_MARKER: &str = "OCTOPUS_DEELEVATED";

/// Mandatory integrity RIDs (`S-1-16-<rid>`).
pub const INTEGRITY_UNTRUSTED: u32 = 0x0000;
pub const INTEGRITY_LOW: u32 = 0x1000;
pub const INTEGRITY_MEDIUM: u32 = 0x2000;
pub const INTEGRITY_HIGH: u32 = 0x3000;
pub const INTEGRITY_SYSTEM: u32 = 0x4000;

/// Privileges that, if merely *present* (even disabled) in an agent token, permit a breakout
/// (the holder can call `AdjustTokenPrivileges` to enable them).
pub const DANGEROUS_PRIVILEGES: &[&str] = &[
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeDebugPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeImpersonatePrivilege",
    "SeTcbPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeSecurityPrivilege",
    "SeManageVolumePrivilege",
    "SeCreateTokenPrivilege",
    "SeRelabelPrivilege",
    "SeSystemEnvironmentPrivilege",
];

/// Real, kernel-reported posture of a process token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenPosture {
    /// `TOKEN_ELEVATION.TokenIsElevated != 0`.
    pub elevated: bool,
    /// Mandatory integrity RID (e.g. `0x2000` = Medium, `0x3000` = High).
    pub integrity_rid: u32,
    /// `BUILTIN\Administrators` present with `SE_GROUP_ENABLED`.
    pub admins_enabled: bool,
    /// `BUILTIN\Administrators` present with `SE_GROUP_USE_FOR_DENY_ONLY`.
    pub admins_deny_only: bool,
    /// Every privilege present in the token (enabled or not).
    pub present_privileges: Vec<String>,
    /// Privileges currently enabled.
    pub enabled_privileges: Vec<String>,
}

impl TokenPosture {
    /// Dangerous privileges present in this token.
    pub fn dangerous_privileges_present(&self) -> Vec<String> {
        self.present_privileges
            .iter()
            .filter(|p| DANGEROUS_PRIVILEGES.iter().any(|d| d.eq_ignore_ascii_case(p)))
            .cloned()
            .collect()
    }

    /// Human-readable integrity level label.
    pub fn integrity_label(&self) -> &'static str {
        match self.integrity_rid {
            r if r >= INTEGRITY_SYSTEM => "System",
            r if r >= INTEGRITY_HIGH => "High",
            r if r >= INTEGRITY_MEDIUM => "Medium",
            r if r >= INTEGRITY_LOW => "Low",
            _ => "Untrusted",
        }
    }

    /// Fail-closed predicate used before resuming any agent process.
    /// Returns `Err(reasons)` listing every violated invariant.
    pub fn verify_agent_safe(&self) -> Result<(), Vec<String>> {
        let mut reasons = Vec::new();
        if self.elevated {
            reasons.push("TokenIsElevated != 0".to_string());
        }
        if self.integrity_rid > INTEGRITY_MEDIUM {
            reasons.push(format!(
                "integrity {} (0x{:x}) exceeds Medium",
                self.integrity_label(),
                self.integrity_rid
            ));
        }
        if self.admins_enabled {
            reasons.push("BUILTIN\\Administrators group is enabled".to_string());
        }
        let dangerous = self.dangerous_privileges_present();
        if !dangerous.is_empty() {
            reasons.push(format!("dangerous privileges present: {}", dangerous.join(", ")));
        }
        if reasons.is_empty() {
            Ok(())
        } else {
            Err(reasons)
        }
    }
}

// ============================================================================
// Windows implementation
// ============================================================================

#[cfg(windows)]
mod sys {
    use std::ffi::c_void;
    pub use windows_sys::Win32::Foundation::HANDLE;
    pub use windows_sys::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOW};

    pub type BOOL = i32;
    pub type PSID = *mut c_void;

    pub const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
    pub const TOKEN_DUPLICATE: u32 = 0x0002;
    pub const TOKEN_QUERY: u32 = 0x0008;
    pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;

    pub const TOKEN_GROUPS_CLASS: u32 = 2;
    pub const TOKEN_PRIVILEGES_CLASS: u32 = 3;
    pub const TOKEN_ELEVATION_CLASS: u32 = 20;
    pub const TOKEN_INTEGRITY_LEVEL_CLASS: u32 = 25;

    pub const SE_GROUP_ENABLED: u32 = 0x0000_0004;
    pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
    pub const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;
    pub const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;

    pub const DISABLE_MAX_PRIVILEGE: u32 = 0x1;
    pub const LUA_TOKEN: u32 = 0x4;

    pub const CREATE_SUSPENDED: u32 = 0x0000_0004;
    pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    pub const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    pub const INFINITE: u32 = 0xFFFF_FFFF;

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    pub struct SID_AND_ATTRIBUTES {
        pub Sid: PSID,
        pub Attributes: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct TOKEN_MANDATORY_LABEL {
        pub Label: SID_AND_ATTRIBUTES,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    pub struct LUID {
        pub LowPart: u32,
        pub HighPart: i32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    pub struct LUID_AND_ATTRIBUTES {
        pub Luid: LUID,
        pub Attributes: u32,
    }

    #[allow(clashing_extern_declarations)]
    #[link(name = "advapi32")]
    extern "system" {
        pub fn OpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: u32, TokenHandle: *mut HANDLE) -> BOOL;
        pub fn GetTokenInformation(
            TokenHandle: HANDLE,
            TokenInformationClass: u32,
            TokenInformation: *mut c_void,
            TokenInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> BOOL;
        pub fn SetTokenInformation(
            TokenHandle: HANDLE,
            TokenInformationClass: u32,
            TokenInformation: *const c_void,
            TokenInformationLength: u32,
        ) -> BOOL;
        pub fn CreateRestrictedToken(
            ExistingTokenHandle: HANDLE,
            Flags: u32,
            DisableSidCount: u32,
            SidsToDisable: *const SID_AND_ATTRIBUTES,
            DeletePrivilegeCount: u32,
            PrivilegesToDelete: *const c_void,
            RestrictedSidCount: u32,
            SidsToRestrict: *const SID_AND_ATTRIBUTES,
            NewTokenHandle: *mut HANDLE,
        ) -> BOOL;
        pub fn ConvertStringSidToSidW(StringSid: *const u16, Sid: *mut PSID) -> BOOL;
        pub fn EqualSid(pSid1: PSID, pSid2: PSID) -> BOOL;
        pub fn GetLengthSid(pSid: PSID) -> u32;
        pub fn GetSidSubAuthorityCount(pSid: PSID) -> *mut u8;
        pub fn GetSidSubAuthority(pSid: PSID, nSubAuthority: u32) -> *mut u32;
        pub fn LookupPrivilegeNameW(
            lpSystemName: *const u16,
            lpLuid: *const LUID,
            lpName: *mut u16,
            cchName: *mut u32,
        ) -> BOOL;
        pub fn CreateProcessAsUserW(
            hToken: HANDLE,
            lpApplicationName: *const u16,
            lpCommandLine: *mut u16,
            lpProcessAttributes: *const c_void,
            lpThreadAttributes: *const c_void,
            bInheritHandles: BOOL,
            dwCreationFlags: u32,
            lpEnvironment: *const c_void,
            lpCurrentDirectory: *const u16,
            lpStartupInfo: *const STARTUPINFOW,
            lpProcessInformation: *mut PROCESS_INFORMATION,
        ) -> BOOL;
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetCurrentProcess() -> HANDLE;
        pub fn CloseHandle(hObject: HANDLE) -> BOOL;
        pub fn LocalFree(hMem: *mut c_void) -> *mut c_void;
        pub fn GetLastError() -> u32;
        pub fn ResumeThread(hThread: HANDLE) -> u32;
        pub fn TerminateProcess(hProcess: HANDLE, uExitCode: u32) -> BOOL;
        pub fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: u32) -> u32;
        pub fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut u32) -> BOOL;
        pub fn GetCommandLineW() -> *const u16;
    }
}

/// Owned Win32 handle closed on drop.
#[cfg(windows)]
#[derive(Debug)]
pub struct OwnedToken(sys::HANDLE);

#[cfg(windows)]
unsafe impl Send for OwnedToken {}
#[cfg(windows)]
unsafe impl Sync for OwnedToken {}

#[cfg(windows)]
impl OwnedToken {
    pub fn raw(&self) -> sys::HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { sys::CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
fn last_err(ctx: &str) -> OctopusSecurityError {
    let code = unsafe { sys::GetLastError() };
    OctopusSecurityError::IsolationViolation(format!("FAIL-CLOSED: {} failed (OS Error {})", ctx, code))
}

/// SID allocated by `ConvertStringSidToSidW`, freed with `LocalFree`.
#[cfg(windows)]
struct LocalSid(sys::PSID);

#[cfg(windows)]
impl LocalSid {
    fn from_str(s: &str) -> Result<Self, OctopusSecurityError> {
        let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid: sys::PSID = std::ptr::null_mut();
        let ok = unsafe { sys::ConvertStringSidToSidW(wide.as_ptr(), &mut sid) };
        if ok == 0 || sid.is_null() {
            return Err(last_err(&format!("ConvertStringSidToSidW({})", s)));
        }
        Ok(Self(sid))
    }
}

#[cfg(windows)]
impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { sys::LocalFree(self.0) };
        }
    }
}

#[cfg(windows)]
fn query_token_buffer(token: sys::HANDLE, class: u32) -> Result<Vec<u64>, OctopusSecurityError> {
    let mut needed: u32 = 0;
    unsafe { sys::GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(last_err(&format!("GetTokenInformation(class={}) size probe", class)));
    }
    // u64-backed buffer guarantees 8-byte alignment for SID_AND_ATTRIBUTES arrays.
    let mut buf: Vec<u64> = vec![0u64; (needed as usize + 7) / 8];
    let ok = unsafe {
        sys::GetTokenInformation(
            token,
            class,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            (buf.len() * 8) as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(last_err(&format!("GetTokenInformation(class={})", class)));
    }
    Ok(buf)
}

#[cfg(windows)]
fn sid_integrity_rid(sid: sys::PSID) -> u32 {
    unsafe {
        let count_ptr = sys::GetSidSubAuthorityCount(sid);
        if count_ptr.is_null() || *count_ptr == 0 {
            return INTEGRITY_UNTRUSTED;
        }
        let rid_ptr = sys::GetSidSubAuthority(sid, (*count_ptr - 1) as u32);
        if rid_ptr.is_null() {
            INTEGRITY_UNTRUSTED
        } else {
            *rid_ptr
        }
    }
}

#[cfg(windows)]
fn privilege_name(luid: &sys::LUID) -> String {
    let mut buf = [0u16; 128];
    let mut len: u32 = buf.len() as u32;
    let ok = unsafe { sys::LookupPrivilegeNameW(std::ptr::null(), luid, buf.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return format!("LUID({},{})", luid.HighPart, luid.LowPart);
    }
    String::from_utf16_lossy(&buf[..len as usize])
}

#[cfg(windows)]
impl TokenPosture {
    /// Inspects an open token handle (requires `TOKEN_QUERY`).
    pub fn of_token(token: sys::HANDLE) -> Result<Self, OctopusSecurityError> {
        // 1. TokenElevation
        let elev = query_token_buffer(token, sys::TOKEN_ELEVATION_CLASS)?;
        let elevated = (elev[0] as u32) != 0;

        // 2. TokenIntegrityLevel
        let il = query_token_buffer(token, sys::TOKEN_INTEGRITY_LEVEL_CLASS)?;
        let label = unsafe { &*(il.as_ptr() as *const sys::TOKEN_MANDATORY_LABEL) };
        let integrity_rid = sid_integrity_rid(label.Label.Sid);

        // 3. TokenGroups -> BUILTIN\Administrators state
        let admins = LocalSid::from_str("S-1-5-32-544")?;
        let groups = query_token_buffer(token, sys::TOKEN_GROUPS_CLASS)?;
        let group_count = unsafe { *(groups.as_ptr() as *const u32) } as usize;
        let groups_ptr = unsafe {
            (groups.as_ptr() as *const u8).add(std::mem::size_of::<usize>()) as *const sys::SID_AND_ATTRIBUTES
        };
        let mut admins_enabled = false;
        let mut admins_deny_only = false;
        for i in 0..group_count {
            let g = unsafe { *groups_ptr.add(i) };
            if unsafe { sys::EqualSid(g.Sid, admins.0) } != 0 {
                if g.Attributes & sys::SE_GROUP_USE_FOR_DENY_ONLY != 0 {
                    admins_deny_only = true;
                } else if g.Attributes & sys::SE_GROUP_ENABLED != 0 {
                    admins_enabled = true;
                }
            }
        }

        // 4. TokenPrivileges
        let privs = query_token_buffer(token, sys::TOKEN_PRIVILEGES_CLASS)?;
        let priv_count = unsafe { *(privs.as_ptr() as *const u32) } as usize;
        let priv_ptr = unsafe { (privs.as_ptr() as *const u8).add(4) as *const sys::LUID_AND_ATTRIBUTES };
        let mut present_privileges = Vec::with_capacity(priv_count);
        let mut enabled_privileges = Vec::new();
        for i in 0..priv_count {
            let p = unsafe { std::ptr::read_unaligned(priv_ptr.add(i)) };
            let name = privilege_name(&p.Luid);
            if p.Attributes & sys::SE_PRIVILEGE_ENABLED != 0 {
                enabled_privileges.push(name.clone());
            }
            present_privileges.push(name);
        }

        Ok(Self {
            elevated,
            integrity_rid,
            admins_enabled,
            admins_deny_only,
            present_privileges,
            enabled_privileges,
        })
    }

    /// Inspects the primary token of a process handle (requires `PROCESS_QUERY_LIMITED_INFORMATION`).
    pub fn of_process(process: sys::HANDLE) -> Result<Self, OctopusSecurityError> {
        let mut token: sys::HANDLE = std::ptr::null_mut();
        let ok = unsafe { sys::OpenProcessToken(process, sys::TOKEN_QUERY, &mut token) };
        if ok == 0 || token.is_null() {
            return Err(last_err("OpenProcessToken(TOKEN_QUERY)"));
        }
        let owned = OwnedToken(token);
        Self::of_token(owned.raw())
    }
}

/// Real posture of the current process token.
#[cfg(windows)]
pub fn current_token_posture() -> Result<TokenPosture, OctopusSecurityError> {
    TokenPosture::of_process(unsafe { sys::GetCurrentProcess() })
}

/// Real posture of the current process (non-Windows: elevated == effective UID 0).
#[cfg(not(windows))]
pub fn current_token_posture() -> Result<TokenPosture, OctopusSecurityError> {
    let euid = unsafe { libc::geteuid() };
    Ok(TokenPosture {
        elevated: euid == 0,
        integrity_rid: if euid == 0 { INTEGRITY_SYSTEM } else { INTEGRITY_MEDIUM },
        admins_enabled: euid == 0,
        admins_deny_only: false,
        present_privileges: Vec::new(),
        enabled_privileges: Vec::new(),
    })
}

/// Creates a de-elevated primary token derived from the current process token:
/// - `DISABLE_MAX_PRIVILEGE`: deletes every privilege except `SeChangeNotifyPrivilege`.
/// - `LUA_TOKEN`: marks the token as a limited-user (UAC-filtered) token.
/// - `BUILTIN\Administrators` (`S-1-5-32-544`) set to `SE_GROUP_USE_FOR_DENY_ONLY`.
/// - Mandatory integrity label lowered to Medium (`S-1-16-8192`) if currently higher.
///
/// The resulting token is re-inspected and rejected if it still violates [`TokenPosture::verify_agent_safe`].
#[cfg(windows)]
pub fn create_deelevated_token() -> Result<OwnedToken, OctopusSecurityError> {
    let mut current: sys::HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        sys::OpenProcessToken(
            sys::GetCurrentProcess(),
            sys::TOKEN_DUPLICATE | sys::TOKEN_QUERY | sys::TOKEN_ASSIGN_PRIMARY | sys::TOKEN_ADJUST_DEFAULT,
            &mut current,
        )
    };
    if ok == 0 || current.is_null() {
        return Err(last_err("OpenProcessToken(current)"));
    }
    let current = OwnedToken(current);

    let admins = LocalSid::from_str("S-1-5-32-544")?;
    let disable = [sys::SID_AND_ATTRIBUTES { Sid: admins.0, Attributes: 0 }];

    let mut restricted: sys::HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        sys::CreateRestrictedToken(
            current.raw(),
            sys::DISABLE_MAX_PRIVILEGE | sys::LUA_TOKEN,
            disable.len() as u32,
            disable.as_ptr(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut restricted,
        )
    };
    if ok == 0 || restricted.is_null() {
        return Err(last_err("CreateRestrictedToken(DISABLE_MAX_PRIVILEGE|LUA_TOKEN)"));
    }
    let restricted = OwnedToken(restricted);

    let posture_before = TokenPosture::of_token(restricted.raw())?;
    if posture_before.integrity_rid > INTEGRITY_MEDIUM {
        let medium = LocalSid::from_str("S-1-16-8192")?;
        let label = sys::TOKEN_MANDATORY_LABEL {
            Label: sys::SID_AND_ATTRIBUTES { Sid: medium.0, Attributes: sys::SE_GROUP_INTEGRITY },
        };
        let size = std::mem::size_of::<sys::TOKEN_MANDATORY_LABEL>() as u32 + unsafe { sys::GetLengthSid(medium.0) };
        let ok = unsafe {
            sys::SetTokenInformation(
                restricted.raw(),
                sys::TOKEN_INTEGRITY_LEVEL_CLASS,
                &label as *const _ as *const std::ffi::c_void,
                size,
            )
        };
        if ok == 0 {
            return Err(last_err("SetTokenInformation(TokenIntegrityLevel=Medium)"));
        }
    }

    let posture = TokenPosture::of_token(restricted.raw())?;
    if let Err(reasons) = posture.verify_agent_safe() {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: De-elevated token still unsafe: {}",
            reasons.join("; ")
        )));
    }
    Ok(restricted)
}

/// A child process launched under a verified de-elevated token.
#[cfg(windows)]
#[derive(Debug)]
pub struct DeelevatedChild {
    pub pid: u32,
    pub posture: TokenPosture,
    process: sys::HANDLE,
}

#[cfg(windows)]
unsafe impl Send for DeelevatedChild {}

#[cfg(windows)]
impl DeelevatedChild {
    /// Blocks until the child exits and returns its exit code.
    pub fn wait(&self) -> Result<u32, OctopusSecurityError> {
        unsafe { sys::WaitForSingleObject(self.process, sys::INFINITE) };
        let mut code: u32 = 0;
        if unsafe { sys::GetExitCodeProcess(self.process, &mut code) } == 0 {
            return Err(last_err("GetExitCodeProcess"));
        }
        Ok(code)
    }
}

#[cfg(windows)]
impl Drop for DeelevatedChild {
    fn drop(&mut self) {
        if !self.process.is_null() {
            unsafe { sys::CloseHandle(self.process) };
        }
    }
}

/// Spawns `command_line` under [`create_deelevated_token`].
///
/// FAIL-CLOSED: the process is created `CREATE_SUSPENDED`; its *own* primary token is inspected via
/// `OpenProcessToken`, and if [`TokenPosture::verify_agent_safe`] fails it is terminated without
/// `ResumeThread` ever being called.
#[cfg(windows)]
pub fn spawn_deelevated(command_line: &str, hide_window: bool) -> Result<DeelevatedChild, OctopusSecurityError> {
    let token = create_deelevated_token()?;

    let mut si: sys::STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<sys::STARTUPINFOW>() as u32;
    let mut pi: sys::PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let mut wide_cmd: Vec<u16> = command_line.encode_utf16().chain(std::iter::once(0)).collect();

    let mut flags = sys::CREATE_SUSPENDED | sys::CREATE_UNICODE_ENVIRONMENT;
    if hide_window {
        flags |= sys::CREATE_NO_WINDOW;
    }

    let ok = unsafe {
        sys::CreateProcessAsUserW(
            token.raw(),
            std::ptr::null(),
            wide_cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            flags,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(last_err("CreateProcessAsUserW(de-elevated, CREATE_SUSPENDED)"));
    }

    let terminate = |reason: String| -> OctopusSecurityError {
        unsafe {
            sys::TerminateProcess(pi.hProcess, 1);
            sys::CloseHandle(pi.hThread);
            sys::CloseHandle(pi.hProcess);
        }
        OctopusSecurityError::IsolationViolation(reason)
    };

    let posture = match TokenPosture::of_process(pi.hProcess) {
        Ok(p) => p,
        Err(e) => return Err(terminate(format!("FAIL-CLOSED: child token inspection failed: {}", e))),
    };
    if let Err(reasons) = posture.verify_agent_safe() {
        return Err(terminate(format!(
            "FAIL-CLOSED: suspended child token unsafe, terminated before ResumeThread: {}",
            reasons.join("; ")
        )));
    }

    if unsafe { sys::ResumeThread(pi.hThread) } == u32::MAX {
        return Err(terminate("FAIL-CLOSED: ResumeThread failed on verified child".to_string()));
    }
    unsafe { sys::CloseHandle(pi.hThread) };

    Ok(DeelevatedChild { pid: pi.dwProcessId, posture, process: pi.hProcess })
}

/// Called first thing in `main` of every long-running Agent Octopus binary.
///
/// - Not elevated → returns `Ok(posture)` and the caller continues.
/// - Elevated and not yet relaunched → relaunches the exact same command line under a verified
///   de-elevated token and **exits the elevated process** (`std::process::exit`).
/// - Elevated even after relaunch (marker present) → `Err`, the caller must refuse to start.
pub fn relaunch_deelevated_or_fail(hide_window: bool) -> Result<TokenPosture, OctopusSecurityError> {
    let posture = current_token_posture()?;
    if posture.verify_agent_safe().is_ok() {
        return Ok(posture);
    }

    if std::env::var(DEELEVATED_ENV_MARKER).ok().as_deref() == Some("1") {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: Process is still privileged after de-elevated relaunch ({}). Refusing to start.",
            posture.verify_agent_safe().err().unwrap_or_default().join("; ")
        )));
    }

    #[cfg(windows)]
    {
        // Process-scoped only: inherited by the child through its default environment block.
        std::env::set_var(DEELEVATED_ENV_MARKER, "1");
        let cmdline = unsafe {
            let ptr = sys::GetCommandLineW();
            let mut len = 0usize;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
        };
        let child = spawn_deelevated(&cmdline, hide_window)?;
        eprintln!(
            "[TOKEN-POSTURE] Elevated launch detected; relaunched de-elevated as PID {} (integrity {}, elevated={})",
            child.pid,
            child.posture.integrity_label(),
            child.posture.elevated
        );
        if !hide_window {
            // Console mode: keep the (idle) parent attached so the shared console stays open,
            // and propagate the de-elevated child's exit code. The Medium-IL child cannot open
            // a handle to this High-IL parent (mandatory integrity policy: no-write-up).
            let code = child.wait().unwrap_or(1);
            std::process::exit(code as i32);
        }
        std::process::exit(0);
    }

    #[cfg(not(windows))]
    {
        let _ = hide_window;
        Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: Refusing to run Agent Octopus as root (effective UID 0). Start it as an unprivileged user."
                .to_string(),
        ))
    }
}
