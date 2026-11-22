use crate::core::types::OctopusSecurityError;
use sha2::Digest;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Win32 `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` (`0x0002_0007`) for `UpdateProcThreadAttribute`.
pub const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: usize = 0x0002_0007;
/// `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON` (bit 28).
pub const PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON: u64 = 1u64 << 28;
/// `PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON` (bit 32).
pub const PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON: u64 = 1u64 << 32;
/// `PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON` (bit 52).
pub const PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON: u64 = 1u64 << 52;
/// `PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON` (bit 56).
pub const PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON: u64 = 1u64 << 56;
/// `PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON` (bit 60).
pub const PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON: u64 = 1u64 << 60;

/// Computes the deterministic Windows `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` bitmask
/// for confined child processes (pure cross-OS helper).
#[must_use]
pub fn compute_windows_mitigation_policy_mask(disallow_win32k: bool, shield_active: bool) -> u64 {
    let mut mask = PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
        | PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
        | PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON
        | PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON;
    if disallow_win32k && shield_active {
        mask |= PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON;
    }
    mask
}

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::GetCurrentProcess;

#[cfg(windows)]
pub mod win32 {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::HANDLE;
    pub type BOOL = i32;
    pub type DWORD = u32;
    pub type HRESULT = i32;
    pub type PWSTR = *mut u16;
    pub type PSID = *mut c_void;

    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct SID_AND_ATTRIBUTES {
        pub Sid: PSID,
        pub Attributes: DWORD,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct SECURITY_CAPABILITIES {
        pub AppContainerSid: PSID,
        pub Capabilities: *mut SID_AND_ATTRIBUTES,
        pub CapabilityCount: DWORD,
        pub Reserved: DWORD,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct STARTUPINFOEXW {
        pub StartupInfo: windows_sys::Win32::System::Threading::STARTUPINFOW,
        pub lpAttributeList: *mut c_void,
    }

    #[link(name = "userenv")]
    extern "system" {
        pub fn CreateAppContainerProfile(
            pszAppContainerName: *const u16,
            pszDisplayName: *const u16,
            pszDescription: *const u16,
            pCapabilities: *const SID_AND_ATTRIBUTES,
            dwCapabilityCount: DWORD,
            ppSidAppContainer: *mut PSID,
        ) -> HRESULT;

        pub fn DeriveAppContainerSidFromAppContainerName(
            pszAppContainerName: *const u16,
            ppsidAppContainerSid: *mut PSID,
        ) -> HRESULT;

        pub fn DeleteAppContainerProfile(pszAppContainerName: *const u16) -> HRESULT;
    }

    #[link(name = "advapi32")]
    extern "system" {
        pub fn ConvertSidToStringSidW(pSid: PSID, ptrSid: *mut PWSTR) -> BOOL;
        pub fn ConvertStringSidToSidW(StringSid: *const u16, Sid: *mut PSID) -> BOOL;
        pub fn OpenProcessToken(
            ProcessHandle: HANDLE,
            DesiredAccess: DWORD,
            TokenHandle: *mut HANDLE,
        ) -> BOOL;
        pub fn CreateRestrictedToken(
            ExistingTokenHandle: HANDLE,
            Flags: DWORD,
            DisableSidCount: DWORD,
            SidsToDisable: *const c_void,
            DeletePrivilegeCount: DWORD,
            PrivilegesToDelete: *const c_void,
            RestrictedSidCount: DWORD,
            SidsToRestrict: *const c_void,
            NewTokenHandle: *mut HANDLE,
        ) -> BOOL;
        pub fn IsTokenRestricted(TokenHandle: HANDLE) -> BOOL;
        pub fn EqualSid(pSid1: PSID, pSid2: PSID) -> BOOL;
        pub fn FreeSid(pSid: PSID) -> *mut c_void;
        pub fn GetTokenInformation(
            TokenHandle: HANDLE,
            TokenInformationClass: DWORD,
            TokenInformation: *mut c_void,
            TokenInformationLength: DWORD,
            ReturnLength: *mut DWORD,
        ) -> BOOL;
        pub fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            StringSecurityDescriptor: *const u16,
            StringSecurityRevision: DWORD,
            SecurityDescriptor: *mut *mut c_void,
            SecurityDescriptorSize: *mut u32,
        ) -> BOOL;
        pub fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            SecurityDescriptor: *const c_void,
            RequestedStringSDRevision: DWORD,
            SecurityInformation: DWORD,
            StringSecurityDescriptor: *mut PWSTR,
            StringSecurityDescriptorLen: *mut DWORD,
        ) -> BOOL;
        pub fn GetNamedSecurityInfoW(
            pObjectName: *const u16,
            ObjectType: DWORD,
            SecurityInfo: DWORD,
            ppsidOwner: *mut PSID,
            ppsidGroup: *mut PSID,
            ppDacl: *mut *mut c_void,
            ppSacl: *mut *mut c_void,
            ppSecurityDescriptor: *mut *mut c_void,
        ) -> DWORD;
        pub fn SetNamedSecurityInfoW(
            pObjectName: *mut u16,
            ObjectType: DWORD,
            SecurityInfo: DWORD,
            psidOwner: PSID,
            psidGroup: PSID,
            pDacl: *mut c_void,
            pSacl: *mut c_void,
        ) -> DWORD;
        pub fn GetSecurityDescriptorDacl(
            pSecurityDescriptor: *const c_void,
            lpbDaclPresent: *mut BOOL,
            pDacl: *mut *mut c_void,
            lpbDaclDefaulted: *mut BOOL,
        ) -> BOOL;
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn LocalFree(hMem: *mut c_void) -> *mut c_void;
        pub fn GetProcessHeap() -> HANDLE;
        pub fn HeapFree(hHeap: HANDLE, dwFlags: DWORD, lpMem: *mut c_void) -> BOOL;
        pub fn LoadLibraryW(lpLibFileName: *const u16) -> HANDLE;
        pub fn GetProcAddress(hModule: HANDLE, lpProcName: *const u8) -> *const c_void;
        pub fn FreeLibrary(hLibModule: HANDLE) -> BOOL;
        pub fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD;
        pub fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut DWORD) -> BOOL;
        pub fn InitializeProcThreadAttributeList(
            lpAttributeList: *mut c_void,
            dwAttributeCount: DWORD,
            dwFlags: DWORD,
            lpSize: *mut usize,
        ) -> BOOL;
        pub fn UpdateProcThreadAttribute(
            lpAttributeList: *mut c_void,
            dwFlags: DWORD,
            Attribute: usize,
            lpValue: *const c_void,
            cbSize: usize,
            lpPreviousValue: *mut c_void,
            lpReturnSize: *mut usize,
        ) -> BOOL;
        pub fn DeleteProcThreadAttributeList(lpAttributeList: *mut c_void);
        pub fn ResumeThread(hThread: HANDLE) -> DWORD;
        pub fn TerminateProcess(hProcess: HANDLE, uExitCode: u32) -> BOOL;
        pub fn GetLastError() -> DWORD;
        pub fn QueryInformationJobObject(
            hJob: HANDLE,
            JobObjectInformationClass: u32,
            lpJobObjectInformation: *mut c_void,
            cbJobObjectInformationLength: u32,
            lpReturnLength: *mut u32,
        ) -> BOOL;
        pub fn CreateProcessW(
            lpApplicationName: *const u16,
            lpCommandLine: *mut u16,
            lpProcessAttributes: *mut c_void,
            lpThreadAttributes: *mut c_void,
            bInheritHandles: BOOL,
            dwCreationFlags: DWORD,
            lpEnvironment: *mut c_void,
            lpCurrentDirectory: *const u16,
            lpStartupInfo: *const c_void,
            lpProcessInformation: *mut windows_sys::Win32::System::Threading::PROCESS_INFORMATION,
        ) -> BOOL;
        pub fn CreateMutexW(
            lpMutexAttributes: *const c_void,
            bInitialOwner: BOOL,
            lpName: *const u16,
        ) -> HANDLE;
        pub fn ReleaseMutex(hMutex: HANDLE) -> BOOL;
    }
}

/// Genuine Windows Job Object wrapper providing kernel-enforced process and resource boundaries.
/// Guarantees that all child processes are killed on close, active process count is bounded,
/// and memory ceilings are strictly enforced by the Windows NT kernel.
///
/// FAIL-CLOSED INVARIANT: Never returns an unprivileged or null fallback handle.
/// If Job Object creation or process assignment fails, sandbox initialization halts immediately.
#[derive(Debug)]
pub struct WindowsJobObject {
    #[cfg(windows)]
    pub(crate) handle: HANDLE,
    pub name: String,
    pub max_processes: u32,
    pub max_memory_bytes: usize,
    pub is_terminated: Arc<AtomicBool>,
}

unsafe impl Send for WindowsJobObject {}
unsafe impl Sync for WindowsJobObject {}

impl WindowsJobObject {
    /// Creates a new Windows Job Object configured with kernel-enforced limits.
    pub fn create(
        name: impl Into<String>,
        max_processes: u32,
        max_memory_bytes: usize,
    ) -> Result<Self, OctopusSecurityError> {
        let name_str = name.into();
        let is_terminated = Arc::new(AtomicBool::new(false));

        #[cfg(windows)]
        {
            let wide_name: Vec<u16> = name_str.encode_utf16().chain(std::iter::once(0)).collect();

            let handle = unsafe { CreateJobObjectW(std::ptr::null(), wide_name.as_ptr()) };

            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: Failed to create Windows Job Object '{}'",
                    name_str
                )));
            }

            // Configure Job Object limits at the Windows kernel level
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_JOB_MEMORY
                | JOB_OBJECT_LIMIT_PROCESS_MEMORY;

            info.BasicLimitInformation.ActiveProcessLimit = max_processes;
            info.JobMemoryLimit = max_memory_bytes;
            info.ProcessMemoryLimit = max_memory_bytes;

            let success = unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };

            if success == 0 {
                unsafe { CloseHandle(handle) };
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: Failed to set kernel limits on Windows Job Object '{}'",
                    name_str
                )));
            }

            // Enforce JOB_OBJECT_UILIMIT_ALL (0x000000FF) to block shatter, clipboard, global atom,
            // and desktop handle access across the Job Object boundary (AO-FIND-02).
            #[repr(C)]
            struct JOBOBJECT_BASIC_UI_RESTRICTIONS {
                ui_restrictions_class: u32,
            }
            const JOB_OBJECT_BASIC_UI_RESTRICTIONS_CLASS: i32 = 4;
            const JOB_OBJECT_UILIMIT_ALL: u32 = 0x0000_00FF;
            let ui_limits = JOBOBJECT_BASIC_UI_RESTRICTIONS {
                ui_restrictions_class: JOB_OBJECT_UILIMIT_ALL,
            };
            let ui_ok = unsafe {
                SetInformationJobObject(
                    handle,
                    JOB_OBJECT_BASIC_UI_RESTRICTIONS_CLASS,
                    &ui_limits as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
                )
            };
            if ui_ok == 0 {
                unsafe { CloseHandle(handle) };
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: Failed to set JOB_OBJECT_UILIMIT_ALL on Windows Job Object '{}'",
                    name_str
                )));
            }

            Ok(Self {
                handle,
                name: name_str,
                max_processes,
                max_memory_bytes,
                is_terminated,
            })
        }

        #[cfg(not(windows))]
        {
            Ok(Self {
                name: name_str,
                max_processes,
                max_memory_bytes,
                is_terminated,
            })
        }
    }

    /// Assigns an operating system process handle to this Job Object.
    /// This binds the process and all its future child tasks to the kernel limits.
    #[cfg(windows)]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn assign_process(&self, process_handle: HANDLE) -> Result<(), OctopusSecurityError> {
        if self.handle.is_null() || self.handle == INVALID_HANDLE_VALUE {
            return Err(OctopusSecurityError::IsolationViolation(
                "FAIL-CLOSED: Cannot assign process to null or invalid Job Object handle"
                    .to_string(),
            ));
        }

        let success = unsafe { AssignProcessToJobObject(self.handle, process_handle) };

        if success == 0 {
            // Note: If running inside another job that disallows breakaway without nested jobs,
            // we capture the specific OS diagnostic code.
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: Failed to assign process handle to Windows Job Object '{}'",
                self.name
            )));
        }

        Ok(())
    }

    /// Binds the current process into this Job Object boundary.
    /// FAIL-CLOSED: Errors out if OS assignment fails or process is not verified inside the Job Object.
    pub fn assign_current_process(&self) -> Result<(), OctopusSecurityError> {
        #[cfg(windows)]
        {
            let current_proc = unsafe { GetCurrentProcess() };
            // Fail-closed enforcement: assign and verify membership
            self.assign_process(current_proc)?;

            let mut in_job: i32 = 0;
            let check_success = unsafe { IsProcessInJob(current_proc, self.handle, &mut in_job) };
            if check_success == 0 || in_job == 0 {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: Current process verified NOT in Windows Job Object '{}'",
                    self.name
                )));
            }
        }
        Ok(())
    }

    /// Checks kernel containment: verifies whether a specific process is strictly bound inside this Job Object.
    #[cfg(windows)]
    pub fn verify_process_in_job(
        &self,
        process_handle: HANDLE,
    ) -> Result<bool, OctopusSecurityError> {
        if self.handle.is_null() || self.handle == INVALID_HANDLE_VALUE {
            return Err(OctopusSecurityError::IsolationViolation(
                "Cannot check process in null or invalid Job Object".to_string(),
            ));
        }
        let mut in_job: i32 = 0;
        let res = unsafe { IsProcessInJob(process_handle, self.handle, &mut in_job) };
        if res == 0 {
            let err = unsafe { win32::GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "IsProcessInJob query failed with OS error {}",
                err
            )));
        }
        Ok(in_job != 0)
    }

    #[cfg(not(windows))]
    pub fn verify_process_in_job(&self, _process_handle: ()) -> Result<bool, OctopusSecurityError> {
        Ok(false)
    }

    /// Verifies that break-away escape is blocked by kernel limits (JOB_OBJECT_LIMIT_BREAKAWAY_OK is not set).
    pub fn verify_breakaway_contained(&self) -> Result<bool, OctopusSecurityError> {
        #[cfg(windows)]
        {
            if self.handle.is_null() || self.handle == INVALID_HANDLE_VALUE {
                return Err(OctopusSecurityError::IsolationViolation(
                    "Cannot query limits on null or invalid Job Object".to_string(),
                ));
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            let mut ret_len: u32 = 0;
            const JOB_OBJECT_EXTENDED_LIMIT_INFO_CLASS: u32 = 9;
            let ok = unsafe {
                win32::QueryInformationJobObject(
                    self.handle,
                    JOB_OBJECT_EXTENDED_LIMIT_INFO_CLASS,
                    &mut info as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    &mut ret_len,
                )
            };
            if ok == 0 {
                let err = unsafe { win32::GetLastError() };
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "QueryInformationJobObject failed with OS error {}",
                    err
                )));
            }
            const JOB_OBJECT_LIMIT_BREAKAWAY_OK_FLAG: u32 = 0x00000800;
            const JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK_FLAG: u32 = 0x00001000;
            let flags = info.BasicLimitInformation.LimitFlags;
            let breakaway_allowed = (flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK_FLAG) != 0
                || (flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK_FLAG) != 0;
            let kill_on_close = (flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0;
            Ok(!breakaway_allowed && kill_on_close)
        }
        #[cfg(not(windows))]
        {
            Ok(true)
        }
    }

    /// Terminates all processes assigned to this Windows Job Object immediately at the kernel level.
    pub fn terminate(&self, _exit_code: u32) -> Result<(), OctopusSecurityError> {
        self.is_terminated.store(true, Ordering::SeqCst);

        #[cfg(windows)]
        {
            if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
                let success = unsafe { TerminateJobObject(self.handle, _exit_code) };
                if success == 0 {
                    return Err(OctopusSecurityError::IsolationViolation(format!(
                        "Failed to terminate Windows Job Object '{}'",
                        self.name
                    )));
                }
            }
        }

        Ok(())
    }
}

impl Drop for WindowsJobObject {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(self.handle);
                }
            }
        }
    }
}

/// AppContainer / LPAC (Less Privileged AppContainer) security profile.
/// Uses Windows userenv.dll APIs to derive genuine AppContainer SIDs and enforce kernel ACLs.
#[derive(Debug, Clone)]
pub struct WindowsAppContainerProfile {
    pub container_name: String,
    pub package_sid: String,
    pub is_lpac: bool,
    pub allow_internet_client: bool,
    pub allowed_capabilities: Vec<String>,
}

#[cfg(windows)]
unsafe fn pwstr_to_string(ptr: win32::PWSTR) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

#[cfg(windows)]
pub fn create_or_open_appcontainer_profile(
    name: &str,
    display_name: &str,
    description: &str,
) -> Result<(String, win32::PSID), OctopusSecurityError> {
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_display: Vec<u16> = display_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let wide_desc: Vec<u16> = description
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut psid: win32::PSID = std::ptr::null_mut();
    let hr = unsafe {
        win32::CreateAppContainerProfile(
            wide_name.as_ptr(),
            wide_display.as_ptr(),
            wide_desc.as_ptr(),
            std::ptr::null(),
            0,
            &mut psid,
        )
    };

    if hr != 0 || psid.is_null() {
        let hr_derive = unsafe {
            win32::DeriveAppContainerSidFromAppContainerName(wide_name.as_ptr(), &mut psid)
        };
        if hr_derive != 0 || psid.is_null() {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: DeriveAppContainerSidFromAppContainerName failed with HRESULT 0x{:08X}",
                hr_derive
            )));
        }
    }

    let mut str_sid_ptr: win32::PWSTR = std::ptr::null_mut();
    let conv_res = unsafe { win32::ConvertSidToStringSidW(psid, &mut str_sid_ptr) };
    if conv_res == 0 || str_sid_ptr.is_null() {
        unsafe {
            win32::FreeSid(psid);
            win32::DeleteAppContainerProfile(wide_name.as_ptr());
        };
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: ConvertSidToStringSidW failed to format AppContainer SID".to_string(),
        ));
    }

    let sid_str = unsafe {
        let s = pwstr_to_string(str_sid_ptr);
        win32::LocalFree(str_sid_ptr as *mut std::ffi::c_void);
        s
    };

    Ok((sid_str, psid))
}

#[cfg(windows)]
fn rollback_appcontainer_profile(name: &str) {
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let _ = win32::DeleteAppContainerProfile(wide_name.as_ptr());
    }
}

#[cfg(windows)]
type FnNetworkIsolationGetAppContainerConfig = unsafe extern "system" fn(
    pdw_num_public_app_cs: *mut win32::DWORD,
    app_container_sids: *mut *mut win32::SID_AND_ATTRIBUTES,
) -> win32::DWORD;

#[cfg(windows)]
type FnNetworkIsolationSetAppContainerConfig = unsafe extern "system" fn(
    dw_num_public_app_cs: win32::DWORD,
    app_container_sids: *const win32::SID_AND_ATTRIBUTES,
) -> win32::DWORD;

#[cfg(windows)]
unsafe fn load_network_isolation_fns() -> Option<(
    HANDLE,
    FnNetworkIsolationGetAppContainerConfig,
    FnNetworkIsolationSetAppContainerConfig,
)> {
    let dll_name: Vec<u16> = "firewallapi.dll"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let hmod = win32::LoadLibraryW(dll_name.as_ptr());
    if hmod.is_null() {
        return None;
    }
    let p_get = win32::GetProcAddress(hmod, b"NetworkIsolationGetAppContainerConfig\0".as_ptr());
    let p_set = win32::GetProcAddress(hmod, b"NetworkIsolationSetAppContainerConfig\0".as_ptr());
    if p_get.is_null() || p_set.is_null() {
        win32::FreeLibrary(hmod);
        return None;
    }
    let get_fn: FnNetworkIsolationGetAppContainerConfig = std::mem::transmute(p_get);
    let set_fn: FnNetworkIsolationSetAppContainerConfig = std::mem::transmute(p_set);
    Some((hmod, get_fn, set_fn))
}

#[cfg(windows)]
unsafe fn free_network_isolation_config(count: win32::DWORD, arr: *mut win32::SID_AND_ATTRIBUTES) {
    if arr.is_null() {
        return;
    }
    let heap = win32::GetProcessHeap();
    for i in 0..(count as usize) {
        let sid_ptr = (*arr.add(i)).Sid;
        if !sid_ptr.is_null() {
            win32::HeapFree(heap, 0, sid_ptr);
        }
    }
    win32::HeapFree(heap, 0, arr as *mut std::ffi::c_void);
}

#[cfg(windows)]
const APPCONTAINER_ACL_MUTEX_NAME: &str = "Local\\AgentOctopus_AppContainer_ACL_Lock";
#[cfg(windows)]
const APPCONTAINER_LOOPBACK_MUTEX_NAME: &str = "Local\\AgentOctopus_AppContainer_Loopback_Lock";
#[cfg(windows)]
const APPCONTAINER_MUTEX_TIMEOUT_MS: u32 = 30_000;

#[cfg(windows)]
struct Win32NamedMutexGuard {
    handle: HANDLE,
}

#[cfg(windows)]
impl Win32NamedMutexGuard {
    fn acquire(name: &str, timeout_ms: u32) -> Result<Self, OctopusSecurityError> {
        const WAIT_OBJECT_0: u32 = 0x0000_0000;
        const WAIT_ABANDONED: u32 = 0x0000_0080;
        const WAIT_TIMEOUT: u32 = 0x0000_0102;

        let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe { win32::CreateMutexW(std::ptr::null(), 0, wide_name.as_ptr()) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            let err = unsafe { win32::GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: CreateMutexW('{}') failed (OS Error {})",
                name, err
            )));
        }

        let rc = unsafe { win32::WaitForSingleObject(handle, timeout_ms) };
        match rc {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self { handle }),
            WAIT_TIMEOUT => {
                unsafe { CloseHandle(handle) };
                Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: Timed out after {}ms waiting for Windows named mutex '{}'",
                    timeout_ms, name
                )))
            }
            _ => {
                let err = unsafe { win32::GetLastError() };
                unsafe { CloseHandle(handle) };
                Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: WaitForSingleObject('{}') failed (rc=0x{:08X}, OS Error {})",
                    name, rc, err
                )))
            }
        }
    }
}

#[cfg(windows)]
impl Drop for Win32NamedMutexGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                let _ = win32::ReleaseMutex(self.handle);
                CloseHandle(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
    }
}

#[cfg(windows)]
fn run_icacls_output_locked(
    _acl_lock: &Win32NamedMutexGuard,
    path: &std::path::Path,
    extra_args: &[&str],
) -> Result<std::process::Output, OctopusSecurityError> {
    std::process::Command::new("icacls")
        .arg(path)
        .args(extra_args)
        .output()
        .map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: failed to invoke icacls on '{}': {}",
                path.display(),
                e
            ))
        })
}

#[cfg(windows)]
fn has_only_inherited_aces_locked(acl_lock: &Win32NamedMutexGuard, path: &std::path::Path) -> bool {
    let Ok(out) = run_icacls_output_locked(acl_lock, path, &[]) else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut saw_ace = false;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Successfully processed") {
            continue;
        }
        // Lines with ACEs contain `:(...)` (e.g., `NT AUTHORITY\SYSTEM:(I)(F)`).
        if let Some(colon_idx) = trimmed.rfind(':') {
            let perms = &trimmed[colon_idx + 1..];
            if perms.starts_with('(') {
                saw_ace = true;
                if !perms.contains("(I)") {
                    return false;
                }
            }
        }
    }
    saw_ace
}

#[cfg(windows)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default, PartialEq, Eq)]
struct PreIsolationAclSnapshot {
    original_inherited_only: bool,
    #[serde(default)]
    original_protected: bool,
    #[serde(default)]
    original_explicit_sddl_aces: Vec<String>,
}

#[cfg(windows)]
fn is_transient_appcontainer_sddl_sid(sid: &str) -> bool {
    let lower = sid.trim().to_ascii_lowercase();
    if let Some(tail) = lower.strip_prefix("s-1-15-2-") {
        let sub_count = tail.split('-').filter(|seg| !seg.is_empty()).count();
        return sub_count >= 2;
    }
    false
}

#[cfg(windows)]
fn parse_pre_isolation_dacl_sddl(dacl_sddl: &str) -> Option<(bool, Vec<String>)> {
    let rest = dacl_sddl.trim().strip_prefix("D:")?;
    if rest.eq_ignore_ascii_case("NO_ACCESS_CONTROL") || rest.is_empty() {
        return Some((false, Vec::new()));
    }
    let first_paren = rest.find('(').unwrap_or(rest.len());
    let flags_str = &rest[..first_paren];
    let original_protected = flags_str.contains('P');

    let mut explicit_aces = Vec::new();
    let bytes = rest.as_bytes();
    let mut i = first_paren;
    while i < bytes.len() {
        if bytes[i] == b'(' {
            let start = i;
            let mut depth = 0usize;
            while i < bytes.len() {
                if bytes[i] == b'(' {
                    depth += 1;
                } else if bytes[i] == b')' {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                i += 1;
            }
            let ace = &rest[start..i];
            if ace.len() >= 2 && ace.starts_with('(') && ace.ends_with(')') {
                let inner = &ace[1..ace.len() - 1];
                let parts: Vec<&str> = inner.split(';').collect();
                if parts.len() >= 6 {
                    let ace_flags = parts[1].trim();
                    let is_inherited = ace_flags
                        .as_bytes()
                        .chunks(2)
                        .any(|chunk| chunk.eq_ignore_ascii_case(b"ID"));
                    let trustee_sid = parts[5].trim();
                    if !is_inherited && !is_transient_appcontainer_sddl_sid(trustee_sid) {
                        explicit_aces.push(ace.to_string());
                    }
                }
            }
        } else {
            i += 1;
        }
    }

    Some((original_protected, explicit_aces))
}

#[cfg(windows)]
fn capture_pre_isolation_acl_locked(
    acl_lock: &Win32NamedMutexGuard,
    path: &std::path::Path,
) -> PreIsolationAclSnapshot {
    const SE_FILE_OBJECT: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const SDDL_REVISION_1: u32 = 1;

    use std::os::windows::ffi::OsStrExt;
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut p_dacl: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut p_sd: *mut std::ffi::c_void = std::ptr::null_mut();
    let rc = unsafe {
        win32::GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut p_dacl,
            std::ptr::null_mut(),
            &mut p_sd,
        )
    };
    if rc == 0 && !p_sd.is_null() {
        let mut p_str_sd: win32::PWSTR = std::ptr::null_mut();
        let mut str_len: u32 = 0;
        let ok = unsafe {
            win32::ConvertSecurityDescriptorToStringSecurityDescriptorW(
                p_sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut p_str_sd,
                &mut str_len,
            )
        };
        let mut parsed_opt = None;
        if ok != 0 && !p_str_sd.is_null() {
            let mut len = 0usize;
            unsafe {
                while *p_str_sd.add(len) != 0 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts(p_str_sd, len);
                let sddl = String::from_utf16_lossy(slice);
                parsed_opt = parse_pre_isolation_dacl_sddl(&sddl);
                win32::LocalFree(p_str_sd as *mut std::ffi::c_void);
            }
        }
        unsafe { win32::LocalFree(p_sd) };
        if let Some((original_protected, original_explicit_sddl_aces)) = parsed_opt {
            let original_inherited_only =
                !original_protected && original_explicit_sddl_aces.is_empty();
            return PreIsolationAclSnapshot {
                original_inherited_only,
                original_protected,
                original_explicit_sddl_aces,
            };
        }
    }

    PreIsolationAclSnapshot {
        original_inherited_only: has_only_inherited_aces_locked(acl_lock, path),
        original_protected: false,
        original_explicit_sddl_aces: Vec::new(),
    }
}

#[cfg(windows)]
fn apply_sddl_dacl_locked(
    _acl_lock: &Win32NamedMutexGuard,
    target: &std::path::Path,
    original_protected: bool,
    explicit_aces: &[String],
) -> bool {
    const SE_FILE_OBJECT: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
    const UNPROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x2000_0000;
    const SDDL_REVISION_1: u32 = 1;

    use std::os::windows::ffi::OsStrExt;
    let mut sddl = String::from(if original_protected { "D:P" } else { "D:" });
    for ace in explicit_aces {
        sddl.push_str(ace);
    }
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut p_sd: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut sd_size: u32 = 0;
    if unsafe {
        win32::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut p_sd,
            &mut sd_size,
        )
    } == 0
        || p_sd.is_null()
    {
        return false;
    }

    let mut dacl_present: win32::BOOL = 0;
    let mut p_dacl: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut dacl_defaulted: win32::BOOL = 0;
    let got_dacl = unsafe {
        win32::GetSecurityDescriptorDacl(p_sd, &mut dacl_present, &mut p_dacl, &mut dacl_defaulted)
    };
    if got_dacl == 0 || dacl_present == 0 {
        unsafe { win32::LocalFree(p_sd) };
        return false;
    }

    let mut wide_path: Vec<u16> = target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let sec_info = DACL_SECURITY_INFORMATION
        | if original_protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
    let rc = unsafe {
        win32::SetNamedSecurityInfoW(
            wide_path.as_mut_ptr(),
            SE_FILE_OBJECT,
            sec_info,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            p_dacl,
            std::ptr::null_mut(),
        )
    };
    unsafe { win32::LocalFree(p_sd) };
    rc == 0
}

#[cfg(windows)]
fn restore_target_pre_acl_locked(
    acl_lock: &Win32NamedMutexGuard,
    target: &std::path::Path,
    snap: &PreIsolationAclSnapshot,
) {
    if !snap.original_protected && snap.original_explicit_sddl_aces.is_empty() {
        let _ = run_icacls_output_locked(acl_lock, target, &["/reset", "/Q"]);
        return;
    }
    if apply_sddl_dacl_locked(
        acl_lock,
        target,
        snap.original_protected,
        &snap.original_explicit_sddl_aces,
    ) {
        return;
    }
    if !snap.original_protected {
        let _ = run_icacls_output_locked(acl_lock, target, &["/inheritance:e", "/Q"]);
    }
}

#[cfg(windows)]
fn icacls_line_has_other_appcontainer_sid(
    line: &str,
    own_sid: &str,
    own_container_name: Option<&str>,
) -> bool {
    const PREFIX: &str = "s-1-15-2-";
    const MONIKER_PREFIX: &str = "application package authority\\";
    let own_lower = own_sid.to_ascii_lowercase();
    let lower = line.to_ascii_lowercase();
    if let Some(mpos) = lower.find(MONIKER_PREFIX) {
        let after = &lower[mpos + MONIKER_PREFIX.len()..];
        let moniker = after.split(':').next().unwrap_or(after).trim();
        let is_own = own_container_name
            .map(|name| moniker.eq_ignore_ascii_case(name))
            .unwrap_or(false);
        if moniker.starts_with("agentoctopus.") && !is_own {
            return true;
        }
    }
    let mut rest = lower.as_str();
    while let Some(pos) = rest.find(PREFIX) {
        let cand = &rest[pos..];
        let tail = &cand[PREFIX.len()..];
        let tail_end = tail
            .find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(tail.len());
        let sid_end = PREFIX.len() + tail_end;
        let sid = &cand[..sid_end];
        let sub_count = if tail_end == 0 {
            0
        } else {
            tail[..tail_end]
                .split('-')
                .filter(|seg| !seg.is_empty())
                .count()
        };
        // Ignore well-known S-1-15-2-1 (ALL APPLICATION PACKAGES) and S-1-15-2-2 (ALL RESTRICTED),
        // plus our own package SID.
        if sub_count >= 2 && sid != own_lower {
            return true;
        }
        rest = &cand[sid_end..];
    }
    false
}

#[cfg(windows)]
fn norm_acl_cmp_path(p: &std::path::Path) -> String {
    let resolved = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let s = resolved.to_string_lossy().replace('\\', "/");
    let s = s.strip_prefix("//?/").unwrap_or(&s);
    s.trim_end_matches('/').to_ascii_lowercase()
}

#[cfg(windows)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct AppContainerLedgerActor {
    sid: String,
    container_name: String,
}

#[cfg(windows)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct AppContainerAclLedgerEntry {
    original_inherited_only: bool,
    #[serde(default)]
    original_protected: bool,
    #[serde(default)]
    original_explicit_sddl_aces: Vec<String>,
    target_path: String,
    active_containers: Vec<AppContainerLedgerActor>,
    pending_restore: bool,
    ancestor_paths: Vec<String>,
}

#[cfg(windows)]
impl AppContainerAclLedgerEntry {
    fn snapshot(&self) -> PreIsolationAclSnapshot {
        PreIsolationAclSnapshot {
            original_inherited_only: self.original_inherited_only,
            original_protected: self.original_protected,
            original_explicit_sddl_aces: self.original_explicit_sddl_aces.clone(),
        }
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct AppContainerAclLedger {
    entries: std::collections::BTreeMap<String, AppContainerAclLedgerEntry>,
}

#[cfg(windows)]
fn acl_ledger_path() -> std::path::PathBuf {
    std::env::temp_dir().join("agentoctopus_ac_acl_ledger.json")
}

#[cfg(windows)]
fn load_acl_ledger_locked(_acl_lock: &Win32NamedMutexGuard) -> AppContainerAclLedger {
    let path = acl_ledger_path();
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return AppContainerAclLedger::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

#[cfg(windows)]
fn save_acl_ledger_locked(_acl_lock: &Win32NamedMutexGuard, ledger: &AppContainerAclLedger) {
    let path = acl_ledger_path();
    if ledger.entries.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    if let Ok(json) = serde_json::to_string(ledger) {
        let _ = std::fs::write(&path, json);
    }
}

#[cfg(windows)]
fn collect_relevant_ancestors(
    target: &std::path::Path,
    candidate_ancestors: &[std::path::PathBuf],
) -> Vec<std::path::PathBuf> {
    let target_norm = norm_acl_cmp_path(target);
    let mut dirs_to_check: Vec<std::path::PathBuf> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    if let Some(parent) = target.parent() {
        if parent.exists() {
            let pn = norm_acl_cmp_path(parent);
            if seen.insert(pn) {
                dirs_to_check.push(parent.to_path_buf());
            }
        }
    }
    for gp in candidate_ancestors {
        if !gp.exists() {
            continue;
        }
        let gpn = norm_acl_cmp_path(gp);
        if !gpn.is_empty() && target_norm.starts_with(&format!("{}/", gpn)) && seen.insert(gpn) {
            dirs_to_check.push(gp.clone());
        }
    }
    dirs_to_check
}

#[cfg(windows)]
fn validate_ledger_entry_live_locked(
    acl_lock: &Win32NamedMutexGuard,
    entry: &mut AppContainerAclLedgerEntry,
    candidate_ancestors: &[std::path::PathBuf],
) -> bool {
    let target = std::path::Path::new(&entry.target_path);
    if !target.exists() && std::fs::symlink_metadata(target).is_err() {
        return false;
    }
    let mut check_paths = collect_relevant_ancestors(target, candidate_ancestors);
    let mut seen: std::collections::HashSet<String> =
        check_paths.iter().map(|p| norm_acl_cmp_path(p)).collect();
    for ap in &entry.ancestor_paths {
        let p = std::path::PathBuf::from(ap);
        if p.exists() {
            let pn = norm_acl_cmp_path(&p);
            if seen.insert(pn) {
                check_paths.push(p);
            }
        }
    }

    let mut live_sids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut any_ac_sid_on_ancestors = false;

    for dir in &check_paths {
        let Ok(out) = run_icacls_output_locked(acl_lock, dir, &[]) else {
            // Fail-safe: keep entry if icacls inspection fails.
            return true;
        };
        if !out.status.success() {
            return true;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("Successfully processed") {
                continue;
            }
            let lower = trimmed.to_ascii_lowercase();
            if icacls_line_has_other_appcontainer_sid(trimmed, "", None) {
                any_ac_sid_on_ancestors = true;
            }
            for actor in &entry.active_containers {
                let sid_l = actor.sid.to_ascii_lowercase();
                let moniker_l = format!(
                    "application package authority\\{}",
                    actor.container_name.to_ascii_lowercase()
                );
                if lower.contains(&sid_l) || lower.contains(&moniker_l) {
                    live_sids.insert(sid_l);
                }
            }
        }
    }

    entry
        .active_containers
        .retain(|a| live_sids.contains(&a.sid.to_ascii_lowercase()));

    if !entry.active_containers.is_empty() {
        return true;
    }

    if entry.pending_restore {
        if any_ac_sid_on_ancestors {
            return true;
        }
        // Orphaned pending_restore with zero active AppContainer SIDs left on ancestors: restore now.
        let snap = entry.snapshot();
        restore_target_pre_acl_locked(acl_lock, target, &snap);
    }
    false
}

#[cfg(windows)]
fn ancestors_have_other_appcontainer_sid_locked(
    acl_lock: &Win32NamedMutexGuard,
    target: &std::path::Path,
    granted_paths: &[std::path::PathBuf],
    own_sid: &str,
    own_container_name: Option<&str>,
) -> bool {
    let dirs_to_check = collect_relevant_ancestors(target, granted_paths);

    for dir in dirs_to_check {
        let Ok(out) = run_icacls_output_locked(acl_lock, &dir, &[]) else {
            // Fail-safe: if inspection fails while another container may be active, defer /reset
            return true;
        };
        if !out.status.success() {
            return true;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("Successfully processed") {
                continue;
            }
            if icacls_line_has_other_appcontainer_sid(trimmed, own_sid, own_container_name) {
                return true;
            }
        }
    }
    false
}

#[cfg(windows)]
fn run_icacls_locked(
    _acl_lock: &Win32NamedMutexGuard,
    path: &std::path::Path,
    op_flag: &str,
    arg_val: &str,
) -> Result<bool, OctopusSecurityError> {
    let status = std::process::Command::new("icacls")
        .arg(path)
        .arg(op_flag)
        .arg(arg_val)
        .arg("/Q")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: failed to invoke icacls on '{}': {}",
                path.display(),
                e
            ))
        })?;
    Ok(status.success())
}

#[cfg(windows)]
fn revoke_appcontainer_loopback_exemption(sid_str: &str) {
    let wide_sid: Vec<u16> = sid_str.encode_utf16().chain(std::iter::once(0)).collect();
    let mut target_psid: win32::PSID = std::ptr::null_mut();
    if unsafe { win32::ConvertStringSidToSidW(wide_sid.as_ptr(), &mut target_psid) } == 0
        || target_psid.is_null()
    {
        return;
    }
    let Ok(_lb_lock) = Win32NamedMutexGuard::acquire(
        APPCONTAINER_LOOPBACK_MUTEX_NAME,
        APPCONTAINER_MUTEX_TIMEOUT_MS,
    ) else {
        unsafe { win32::LocalFree(target_psid) };
        return;
    };
    unsafe {
        if let Some((hmod, get_fn, set_fn)) = load_network_isolation_fns() {
            let mut count: win32::DWORD = 0;
            let mut arr: *mut win32::SID_AND_ATTRIBUTES = std::ptr::null_mut();
            if get_fn(&mut count, &mut arr) == 0 && !arr.is_null() && count > 0 {
                let mut filtered: Vec<win32::SID_AND_ATTRIBUTES> =
                    Vec::with_capacity(count as usize);
                let mut removed_any = false;
                for i in 0..(count as usize) {
                    let entry = &*arr.add(i);
                    if !entry.Sid.is_null() && win32::EqualSid(entry.Sid, target_psid) != 0 {
                        removed_any = true;
                    } else {
                        filtered.push(win32::SID_AND_ATTRIBUTES {
                            Sid: entry.Sid,
                            Attributes: entry.Attributes,
                        });
                    }
                }
                if removed_any {
                    let ptr = if filtered.is_empty() {
                        std::ptr::null()
                    } else {
                        filtered.as_ptr()
                    };
                    let _ = set_fn(filtered.len() as win32::DWORD, ptr);
                }
            }
            free_network_isolation_config(count, arr);
            win32::FreeLibrary(hmod);
        }
        win32::LocalFree(target_psid);
    }
}

/// Pre-created Windows AppContainer profile whose SID is known before spawning the child process
/// (allowing Named Pipe DACLs and optional NetworkIsolation loopback exemptions to bind strictly to this SID).
#[cfg(windows)]
#[derive(Debug)]
pub struct PreparedAppContainerProfile {
    pub container_name: String,
    pub sid_str: String,
    psid: win32::PSID,
    loopback_exempt_added: bool,
    already_loopback_exempt: bool,
}

#[cfg(windows)]
unsafe impl Send for PreparedAppContainerProfile {}

#[cfg(windows)]
impl PreparedAppContainerProfile {
    pub fn prepare_appcontainer_profile() -> Result<Self, OctopusSecurityError> {
        let container_name = format!(
            "AgentOctopus.OctopusRun.{}_{:08x}",
            std::process::id(),
            rand::random::<u32>()
        );
        let (sid_str, psid) = create_or_open_appcontainer_profile(
            &container_name,
            "AgentOctopus Strict CLI Sandbox",
            "AppContainer boundary for octopus run --sandbox strict",
        )?;
        Ok(Self {
            container_name,
            sid_str,
            psid,
            loopback_exempt_added: false,
            already_loopback_exempt: false,
        })
    }

    pub fn try_enable_loopback_exemption(&mut self) -> bool {
        if self.psid.is_null() {
            return false;
        }
        if self.already_loopback_exempt || self.loopback_exempt_added {
            return true;
        }
        let Ok(_lb_lock) = Win32NamedMutexGuard::acquire(
            APPCONTAINER_LOOPBACK_MUTEX_NAME,
            APPCONTAINER_MUTEX_TIMEOUT_MS,
        ) else {
            return false;
        };
        unsafe {
            let Some((hmod, get_fn, set_fn)) = load_network_isolation_fns() else {
                return false;
            };
            let mut count: win32::DWORD = 0;
            let mut arr: *mut win32::SID_AND_ATTRIBUTES = std::ptr::null_mut();
            let rc_get = get_fn(&mut count, &mut arr);
            if rc_get != 0 {
                free_network_isolation_config(count, arr);
                win32::FreeLibrary(hmod);
                return false;
            }
            let mut new_list: Vec<win32::SID_AND_ATTRIBUTES> =
                Vec::with_capacity((count as usize) + 1);
            if !arr.is_null() {
                for i in 0..(count as usize) {
                    let entry = &*arr.add(i);
                    if !entry.Sid.is_null() && win32::EqualSid(entry.Sid, self.psid) != 0 {
                        self.already_loopback_exempt = true;
                        free_network_isolation_config(count, arr);
                        win32::FreeLibrary(hmod);
                        return true;
                    }
                    new_list.push(win32::SID_AND_ATTRIBUTES {
                        Sid: entry.Sid,
                        Attributes: entry.Attributes,
                    });
                }
            }
            new_list.push(win32::SID_AND_ATTRIBUTES {
                Sid: self.psid,
                Attributes: 0,
            });
            let rc_set = set_fn(new_list.len() as win32::DWORD, new_list.as_ptr());
            free_network_isolation_config(count, arr);
            win32::FreeLibrary(hmod);
            if rc_set == 0 {
                self.loopback_exempt_added = true;
                true
            } else {
                false
            }
        }
    }

    pub fn loopback_exempt_active(&self) -> bool {
        self.already_loopback_exempt || self.loopback_exempt_added
    }

    fn take_raw(&mut self) -> Option<(String, String, win32::PSID, bool, bool)> {
        if self.psid.is_null() {
            return None;
        }
        let psid = self.psid;
        self.psid = std::ptr::null_mut();
        let added = self.loopback_exempt_added;
        self.loopback_exempt_added = false;
        let already = self.already_loopback_exempt;
        self.already_loopback_exempt = false;
        Some((
            std::mem::take(&mut self.container_name),
            std::mem::take(&mut self.sid_str),
            psid,
            added,
            already,
        ))
    }
}

#[cfg(windows)]
impl Drop for PreparedAppContainerProfile {
    fn drop(&mut self) {
        if !self.psid.is_null() {
            if self.loopback_exempt_added {
                revoke_appcontainer_loopback_exemption(&self.sid_str);
            }
            unsafe {
                win32::FreeSid(self.psid);
            }
            self.psid = std::ptr::null_mut();
            rollback_appcontainer_profile(&self.container_name);
        }
    }
}

/// Quotes a single Windows command-line argument according to the Microsoft C/C++ runtime
/// (`CommandLineToArgvW` / MSVCRT) parsing rules, preventing quote-escape and trailing-backslash
/// argument injection.
pub fn quote_windows_argv_arg(arg: &str) -> String {
    if !arg.is_empty()
        && !arg
            .chars()
            .any(|c| c == ' ' || c == '\t' || c == '\n' || c == '\x0b' || c == '"')
    {
        return arg.to_string();
    }
    let mut quoted = String::with_capacity(arg.len() + 4);
    quoted.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                quoted.push('\\');
            }
            quoted.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                quoted.push('\\');
            }
            backslashes = 0;
            quoted.push(ch);
        }
    }
    for _ in 0..(backslashes * 2) {
        quoted.push('\\');
    }
    quoted.push('"');
    quoted
}

/// Builds a complete MSVCRT-quoted command line from an executable path and argument vector.
pub fn build_windows_command_line(program: &str, args: &[String]) -> String {
    let mut cmdline = format!("\"{}\"", program.replace('"', ""));
    for arg in args {
        cmdline.push(' ');
        cmdline.push_str(&quote_windows_argv_arg(arg));
    }
    cmdline
}

impl WindowsAppContainerProfile {
    /// Creates a new AppContainer profile derived via Windows userenv API when available.
    pub fn new(agent_id: &str, is_lpac: bool, allow_google_only: bool) -> Self {
        let container_name = format!("AgentOctopus.AppContainer.{}", agent_id);

        #[cfg(windows)]
        {
            if let Ok((sid, psid)) = create_or_open_appcontainer_profile(
                &container_name,
                &format!("Agent Octopus {}", agent_id),
                "AppContainer profile for Agent Octopus agent",
            ) {
                unsafe {
                    win32::FreeSid(psid);
                }
                let mut allowed_capabilities = Vec::new();
                if allow_google_only {
                    allowed_capabilities.push("internetClient".to_string());
                }
                return Self {
                    container_name,
                    package_sid: sid,
                    is_lpac,
                    allow_internet_client: allow_google_only,
                    allowed_capabilities,
                };
            }
        }

        // Deterministic derivation for non-Windows or fallback
        let hash = sha2::Sha256::digest(container_name.as_bytes());
        let mut sub_authorities = Vec::with_capacity(7);
        for chunk in hash[..28].chunks_exact(4) {
            let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            sub_authorities.push(val.to_string());
        }
        let derived_sid = format!("S-1-15-2-{}", sub_authorities.join("-"));

        let mut allowed_capabilities = Vec::new();
        if allow_google_only {
            allowed_capabilities.push("internetClient".to_string());
        }

        Self {
            container_name,
            package_sid: derived_sid,
            is_lpac,
            allow_internet_client: allow_google_only,
            allowed_capabilities,
        }
    }

    /// Creates a mandatory AppContainer profile in production with genuine Windows kernel isolation.
    /// FAIL-CLOSED: Fails with OctopusSecurityError if userenv profile creation cannot be completed.
    pub fn create_mandatory(
        _agent_id: &str,
        _is_lpac: bool,
        _allow_google_only: bool,
    ) -> Result<Self, OctopusSecurityError> {
        #[cfg(windows)]
        {
            let container_name = format!("AgentOctopus.AppContainer.{}", _agent_id);
            let (sid, psid) = create_or_open_appcontainer_profile(
                &container_name,
                &format!("Agent Octopus {}", _agent_id),
                "AppContainer profile for Agent Octopus agent",
            )?;
            unsafe {
                win32::FreeSid(psid);
            }

            let mut allowed_capabilities = Vec::new();
            if _allow_google_only {
                allowed_capabilities.push("internetClient".to_string());
            }

            Ok(Self {
                container_name,
                package_sid: sid,
                is_lpac: _is_lpac,
                allow_internet_client: _allow_google_only,
                allowed_capabilities,
            })
        }

        #[cfg(not(windows))]
        {
            Err(OctopusSecurityError::IsolationViolation(
                "FAIL-CLOSED: AppContainer kernel profile is only supported on Windows".to_string(),
            ))
        }
    }

    /// Validates whether a given system operation is permitted under this AppContainer profile.
    /// Strictly parses and validates destination hostnames to prevent bypasses like
    /// `https://google.com.attacker.example/collect`.
    pub fn verify_access(
        &self,
        target_resource: &str,
        is_network: bool,
    ) -> Result<(), OctopusSecurityError> {
        if is_network {
            if !self.allow_internet_client {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "AppContainer [{}] denied network egress to '{}': zero network capability granted",
                    self.container_name, target_resource
                )));
            }

            // Strict URL and Hostname Verification (Zero Bypass for google.com)
            let trimmed = target_resource.trim();
            let parsed_url = url::Url::parse(trimmed).map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!(
                    "AppContainer [{}] rejected malformed network URI '{}': {}",
                    self.container_name, target_resource, e
                ))
            })?;

            if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "AppContainer [{}] rejected network URI '{}': missing http(s) scheme",
                    self.container_name, target_resource
                )));
            }

            // Reject any credentials in URI (user:pass@host)
            if !parsed_url.username().is_empty() || parsed_url.password().is_some() {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "AppContainer [{}] rejected network URI with embedded credentials: '{}'",
                    self.container_name, target_resource
                )));
            }

            // Extract host handling Domain, IPv4, and IPv6 safely
            let host = match parsed_url.host() {
                Some(url::Host::Domain(d)) => d.to_lowercase(),
                Some(url::Host::Ipv4(ip)) => ip.to_string(),
                Some(url::Host::Ipv6(ip)) => format!("[{}]", ip),
                None => {
                    return Err(OctopusSecurityError::IsolationViolation(format!(
                        "AppContainer [{}] rejected network URI missing valid host: '{}'",
                        self.container_name, target_resource
                    )));
                }
            };

            // Strict Allowlist: ONLY google.com or www.google.com
            let is_authorized_google = host == "google.com" || host == "www.google.com";

            if !is_authorized_google {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "AppContainer [{}] network policy violation: host '{}' from URI '{}' is NOT authorized Google egress (subdomains, IPv6/IPv4, and suffixes blocked)",
                    self.container_name, host, target_resource
                )));
            }
        } else {
            // Kernel-level AppContainer blocks all access outside authorized sandboxed prefixes
            let lower = target_resource.to_lowercase();
            if lower.contains("c:\\windows")
                || lower.contains("c:\\users")
                || lower.contains("/etc/")
                || lower.contains("..")
                || lower.contains("%2e")
                || lower.starts_with("\\\\")
                || lower.contains("docker.sock")
            {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "AppContainer [{}] kernel ACL blocked unauthorized filesystem access to '{}'",
                    self.container_name, target_resource
                )));
            }
            crate::security::isolation::SandboxConfinementPolicy::default()
                .validate_filesystem_confinement(target_resource)?;
        }
        Ok(())
    }
}

/// Windows Restricted Token configuration.
/// Strips dangerous privileges (SeDebug, SeTcb, SeShutdown, SeTakeOwnership)
/// and removes high-integrity SIDs to prevent privilege escalation.
#[derive(Debug, Clone)]
pub struct WindowsRestrictedTokenPolicy {
    pub stripped_privileges: Vec<String>,
    pub restricted_sids: Vec<String>,
    pub token_integrity_level: String,
}

impl Default for WindowsRestrictedTokenPolicy {
    fn default() -> Self {
        Self {
            stripped_privileges: vec![
                "SeDebugPrivilege".to_string(),
                "SeTcbPrivilege".to_string(),
                "SeTakeOwnershipPrivilege".to_string(),
                "SeShutdownPrivilege".to_string(),
                "SeAssignPrimaryTokenPrivilege".to_string(),
                "SeIncreaseQuotaPrivilege".to_string(),
                "SeSecurityPrivilege".to_string(),
                "SeBackupPrivilege".to_string(),
                "SeRestorePrivilege".to_string(),
            ],
            restricted_sids: vec![
                "S-1-5-32-544".to_string(), // Built-in Administrators (Stripped)
                "S-1-5-18".to_string(),     // Local System (Denied)
            ],
            token_integrity_level: "Low".to_string(), // Untrusted / Low integrity
        }
    }
}

impl WindowsRestrictedTokenPolicy {
    /// Creates a genuine Windows Restricted Token stripping dangerous privileges and administrative SIDs.
    #[cfg(windows)]
    pub fn create_restricted_token(
        &self,
    ) -> Result<windows_sys::Win32::Foundation::HANDLE, OctopusSecurityError> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        const TOKEN_DUPLICATE: u32 = 0x0002;
        const TOKEN_QUERY: u32 = 0x0008;
        const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
        const DISABLE_MAX_PRIVILEGE: u32 = 0x1;

        let mut current_token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        let open_res = unsafe {
            win32::OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
                &mut current_token,
            )
        };
        if open_res == 0 || current_token.is_null() {
            let err = unsafe { win32::GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: OpenProcessToken failed (OS Error {})",
                err
            )));
        }

        let mut restricted_sid: win32::PSID = std::ptr::null_mut();
        let sid_w: Vec<u16> = "S-1-5-12\0".encode_utf16().collect();
        let _ = unsafe { win32::ConvertStringSidToSidW(sid_w.as_ptr(), &mut restricted_sid) };

        let mut sid_and_attr = win32::SID_AND_ATTRIBUTES {
            Sid: restricted_sid,
            Attributes: 0,
        };

        let (sid_count, sid_ptr) = if !restricted_sid.is_null() {
            (1, &mut sid_and_attr as *mut _ as *const std::ffi::c_void)
        } else {
            (0, std::ptr::null())
        };

        let mut restricted_token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();

        // BUILTIN\Administrators (S-1-5-32-544) must be deny-only in any agent token; otherwise an
        // elevated supervisor hands full admin group membership to the "restricted" child.
        let mut admins_sid: win32::PSID = std::ptr::null_mut();
        let admins_w: Vec<u16> = "S-1-5-32-544\0".encode_utf16().collect();
        let admins_ok =
            unsafe { win32::ConvertStringSidToSidW(admins_w.as_ptr(), &mut admins_sid) };
        if admins_ok == 0 || admins_sid.is_null() {
            unsafe {
                CloseHandle(current_token);
            }
            if !restricted_sid.is_null() {
                unsafe {
                    win32::LocalFree(restricted_sid);
                }
            }
            return Err(OctopusSecurityError::IsolationViolation(
                "FAIL-CLOSED: Unable to resolve BUILTIN\\Administrators SID for deny-only"
                    .to_string(),
            ));
        }
        let disable_admins = win32::SID_AND_ATTRIBUTES {
            Sid: admins_sid,
            Attributes: 0,
        };

        // LUA_TOKEN (0x4): UAC-filtered limited-user token.
        const LUA_TOKEN: u32 = 0x4;
        let rest_res = unsafe {
            win32::CreateRestrictedToken(
                current_token,
                DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
                1,
                &disable_admins as *const _ as *const std::ffi::c_void,
                0,
                std::ptr::null(),
                sid_count,
                sid_ptr,
                &mut restricted_token,
            )
        };
        unsafe {
            CloseHandle(current_token);
        }
        unsafe {
            win32::LocalFree(admins_sid);
        }
        if !restricted_sid.is_null() {
            unsafe {
                win32::LocalFree(restricted_sid);
            }
        }

        if rest_res == 0 || restricted_token.is_null() {
            let err = unsafe { win32::GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: CreateRestrictedToken failed (OS Error {})",
                err
            )));
        }

        let is_restricted = unsafe { win32::IsTokenRestricted(restricted_token) };
        if is_restricted == 0 {
            unsafe {
                CloseHandle(restricted_token);
            }
            return Err(OctopusSecurityError::IsolationViolation(
                "FAIL-CLOSED: Created token failed IsTokenRestricted verification".to_string(),
            ));
        }

        Ok(restricted_token)
    }

    #[cfg(not(windows))]
    pub fn create_restricted_token(&self) -> Result<(), OctopusSecurityError> {
        Err(OctopusSecurityError::IsolationViolation(
            "Windows Restricted Tokens are only supported on Windows".to_string(),
        ))
    }
}

/// Named pipe security descriptor configuration.
/// Defines SDDL granting access exclusively to the supervisor process and designated agent.
/// Excludes anonymous or world users (`AU`) to prevent local IPC eavesdropping or forgery.
#[derive(Debug, Clone)]
pub struct WindowsNamedPipeSecurity {
    pub pipe_name: String,
    pub sddl_descriptor: String,
}

impl WindowsNamedPipeSecurity {
    pub fn new(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
            // SDDL: Grants Generic All (GA) to SYSTEM (SY) and Builtin Administrators (BA),
            // Generic Read/Write (GRGW) to Owner Rights (OW).
            // Prevents any other unprivileged user or process from connecting.
            sddl_descriptor: "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;OW)".to_string(),
        }
    }
}

/// Owned handle to a quarantined OS worker process running inside a Windows Job Object
/// and AppContainer isolation boundary. Eliminates resource leaks and provides active supervisor lifecycle management.
#[derive(Debug)]
pub struct QuarantinedProcessInstance {
    pub job: Arc<WindowsJobObject>,
    #[cfg(windows)]
    pub process_handle: windows_sys::Win32::Foundation::HANDLE,
    pub pid: u32,
    pub container_name: String,
    pub package_sid: String,
    pub spawned_at: std::time::Instant,
}

unsafe impl Send for QuarantinedProcessInstance {}
unsafe impl Sync for QuarantinedProcessInstance {}

impl QuarantinedProcessInstance {
    /// Actively terminates the quarantined process and all its tree within the Job Object.
    pub fn terminate(&self, exit_code: u32) -> Result<(), OctopusSecurityError> {
        let _ = self.job.terminate(exit_code);
        #[cfg(windows)]
        {
            if !self.process_handle.is_null()
                && self.process_handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
            {
                unsafe {
                    win32::TerminateProcess(self.process_handle, exit_code);
                }
            }
        }
        Ok(())
    }
}

impl Drop for QuarantinedProcessInstance {
    fn drop(&mut self) {
        let _ = self.terminate(1);
        #[cfg(windows)]
        {
            if !self.process_handle.is_null()
                && self.process_handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
            {
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(self.process_handle);
                }
            }
            let wide_name: Vec<u16> = self
                .container_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            unsafe {
                win32::DeleteAppContainerProfile(wide_name.as_ptr());
            }
        }
    }
}

/// Launches a quarantined worker process inside genuine Windows Job Object and AppContainer isolation boundaries.
///
/// FAIL-CLOSED SECURITY INVARIANTS:
/// 1. Process is created in CREATE_SUSPENDED state before executing any user code.
/// 2. Binds process into Windows Job Object and validates kernel membership (IsProcessInJob).
/// 3. Resumes primary thread ONLY after OS isolation is confirmed.
/// 4. Rejects execution without fallback if the worker executable is missing or cannot be contained.
#[cfg(windows)]
pub fn spawn_quarantined_worker_in_job_and_appcontainer(
    worker_exe: &std::path::Path,
    arm_id: u64,
    report_id: &str,
    operation: &str,
    job: &Arc<WindowsJobObject>,
) -> Result<QuarantinedProcessInstance, OctopusSecurityError> {
    if !worker_exe.exists() {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: Quarantined worker binary does not exist at '{}'. Zero fallback execution allowed.",
            worker_exe.display()
        )));
    }

    let container_name = format!(
        "AgentOctopus.Arm{}_{}_{:08x}",
        arm_id,
        report_id.replace('-', "_"),
        rand::random::<u32>()
    );
    let (sid_str, psid) = create_or_open_appcontainer_profile(
        &container_name,
        &format!("Arm {} Quarantine Sandbox", arm_id),
        "Isolated execution sandbox for suspicious/quarantined workload",
    )?;

    // Configure SECURITY_CAPABILITIES for AppContainer isolation
    let mut sec_cap = win32::SECURITY_CAPABILITIES {
        AppContainerSid: psid,
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };

    let mut mitigation_policy: u64 = compute_windows_mitigation_policy_mask(
        false,
        crate::security::virtual_patch_shield::current_shield_posture().is_shield_active(),
    );

    // Calculate required buffer size for attribute list (SECURITY_CAPABILITIES + MITIGATION_POLICY)
    let mut attr_size: usize = 0;
    unsafe {
        win32::InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut attr_size);
    }
    if attr_size == 0 {
        unsafe { win32::FreeSid(psid) };
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: InitializeProcThreadAttributeList failed to calculate attribute size"
                .to_string(),
        ));
    }

    let mut attr_buf: Vec<u8> = vec![0u8; attr_size];
    let attr_list = attr_buf.as_mut_ptr() as *mut std::ffi::c_void;
    let init_ok =
        unsafe { win32::InitializeProcThreadAttributeList(attr_list, 2, 0, &mut attr_size) };
    if init_ok == 0 {
        unsafe { win32::FreeSid(psid) };
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: InitializeProcThreadAttributeList failed to initialize attribute buffer"
                .to_string(),
        ));
    }

    // PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
    let update_ok = unsafe {
        win32::UpdateProcThreadAttribute(
            attr_list,
            0,
            0x00020009,
            &mut sec_cap as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<win32::SECURITY_CAPABILITIES>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if update_ok == 0 {
        unsafe {
            win32::DeleteProcThreadAttributeList(attr_list);
            win32::FreeSid(psid);
        };
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: UpdateProcThreadAttribute failed with error {}",
            unsafe { win32::GetLastError() }
        )));
    }
    if unsafe {
        win32::UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            (&mut mitigation_policy as *mut u64).cast::<std::ffi::c_void>(),
            std::mem::size_of::<u64>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        unsafe {
            win32::DeleteProcThreadAttributeList(attr_list);
            win32::FreeSid(psid);
        };
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: UpdateProcThreadAttribute(MITIGATION_POLICY) failed with error {}",
            unsafe { win32::GetLastError() }
        )));
    }

    // Prepare STARTUPINFOEXW
    let mut si_ex: win32::STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si_ex.StartupInfo.cb = std::mem::size_of::<win32::STARTUPINFOEXW>() as u32;
    si_ex.lpAttributeList = attr_list;

    let mut pi: windows_sys::Win32::System::Threading::PROCESS_INFORMATION =
        unsafe { std::mem::zeroed() };

    let cmdline = format!("\"{}\" {} {}", worker_exe.display(), arm_id, operation);
    let mut wide_cmdline: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();

    // Spawn process suspended with extended startup info (AppContainer isolation)
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x00080000;
    const CREATE_SUSPENDED: u32 = 0x00000004;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let create_res = unsafe {
        win32::CreateProcessW(
            std::ptr::null(),
            wide_cmdline.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
            std::ptr::null_mut(),
            std::ptr::null(),
            &si_ex as *const _ as *const std::ffi::c_void,
            &mut pi,
        )
    };

    unsafe {
        win32::DeleteProcThreadAttributeList(attr_list);
    };

    if create_res == 0 {
        let err = unsafe { win32::GetLastError() };
        unsafe { win32::FreeSid(psid) };
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: Failed to spawn worker in AppContainer profile '{}' (OS Error {})",
            container_name, err
        )));
    }

    // Assign suspended process to Job Object BEFORE ANY CODE RUNS
    let assign_res = unsafe {
        windows_sys::Win32::System::JobObjects::AssignProcessToJobObject(job.handle, pi.hProcess)
    };
    if assign_res == 0 {
        let err = unsafe { win32::GetLastError() };
        unsafe {
            win32::TerminateProcess(pi.hProcess, 1);
            windows_sys::Win32::Foundation::CloseHandle(pi.hProcess);
            windows_sys::Win32::Foundation::CloseHandle(pi.hThread);
            win32::FreeSid(psid);
        };
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: AssignProcessToJobObject failed on suspended worker process (OS Error {}). Execution halted.",
            err
        )));
    }

    // Verify membership with IsProcessInJob AND actual child process token AppContainer identity (AO-FIND-02)
    let ac_check = verify_process_appcontainer_token(pi.hProcess, psid, &sid_str, job);
    unsafe { win32::FreeSid(psid) };
    if let Err(e) = ac_check {
        unsafe {
            win32::TerminateProcess(pi.hProcess, 1);
            windows_sys::Win32::Foundation::CloseHandle(pi.hProcess);
            windows_sys::Win32::Foundation::CloseHandle(pi.hThread);
        };
        rollback_appcontainer_profile(&container_name);
        return Err(e);
    }

    // Now that kernel containment is fully verified, resume the primary thread!
    let resume_res = unsafe { win32::ResumeThread(pi.hThread) };
    if resume_res == u32::MAX {
        let err = unsafe { win32::GetLastError() };
        unsafe {
            win32::TerminateProcess(pi.hProcess, 1);
            windows_sys::Win32::Foundation::CloseHandle(pi.hProcess);
            windows_sys::Win32::Foundation::CloseHandle(pi.hThread);
        };
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: ResumeThread failed on sandboxed worker process (OS Error {})",
            err
        )));
    }

    // Primary thread is running; close thread handle as it is no longer needed
    unsafe {
        windows_sys::Win32::Foundation::CloseHandle(pi.hThread);
    }

    Ok(QuarantinedProcessInstance {
        job: Arc::clone(job),
        process_handle: pi.hProcess,
        pid: pi.dwProcessId,
        container_name,
        package_sid: sid_str,
        spawned_at: std::time::Instant::now(),
    })
}

#[cfg(not(windows))]
pub fn spawn_quarantined_worker_in_job_and_appcontainer(
    _worker_exe: &std::path::Path,
    _arm_id: u64,
    _report_id: &str,
    _operation: &str,
    _job: &Arc<WindowsJobObject>,
) -> Result<QuarantinedProcessInstance, OctopusSecurityError> {
    Err(OctopusSecurityError::IsolationViolation(
        "FAIL-CLOSED: Windows Job Object and AppContainer process isolation is strictly unsupported on non-Windows platforms. Production containment refused.".to_string(),
    ))
}

// ============================================================================
// OshoosiClaw Adapted Windows Confinement Policy & Pre-Resume Confinement Gate
// ============================================================================

/// Windows Job Object + AppContainer + UI Limit Confinement Policy (`RULE[windows_containment_invariants.md]`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WindowsConfinementPolicy {
    pub container_name: String,
    pub require_appcontainer: bool,
    pub kill_on_job_close: bool,
    pub active_process_limit: u32,
    pub max_memory_bytes: usize,
    pub enforce_ui_limits: bool,
    pub create_suspended_before_job_assign: bool,
}

impl Default for WindowsConfinementPolicy {
    fn default() -> Self {
        Self {
            container_name: "AgentOctopus.DefaultConfinement".to_string(),
            require_appcontainer: true,
            kill_on_job_close: true,
            active_process_limit: 1,
            max_memory_bytes: 64 * 1024 * 1024,
            enforce_ui_limits: true,
            create_suspended_before_job_assign: true,
        }
    }
}

/// Validates that a `WindowsConfinementPolicy` satisfies all mandatory kernel isolation invariants.
pub fn verify_windows_confinement_invariants(
    policy: &WindowsConfinementPolicy,
) -> Result<(), OctopusSecurityError> {
    if !policy.create_suspended_before_job_assign {
        return Err(OctopusSecurityError::IsolationViolation(
            "WIN_CONFINEMENT_INVARIANT: Worker process MUST be spawned with CREATE_SUSPENDED (0x00000004) before Job Object assignment".to_string(),
        ));
    }
    if !policy.kill_on_job_close {
        return Err(OctopusSecurityError::IsolationViolation(
            "WIN_CONFINEMENT_INVARIANT: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE must be enabled"
                .to_string(),
        ));
    }
    if policy.active_process_limit == 0 {
        return Err(OctopusSecurityError::IsolationViolation(
            "WIN_CONFINEMENT_INVARIANT: active_process_limit must be >= 1".to_string(),
        ));
    }
    if policy.max_memory_bytes == 0 || policy.max_memory_bytes > 512 * 1024 * 1024 {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "WIN_CONFINEMENT_INVARIANT: max_memory_bytes ({}) outside valid confinement range",
            policy.max_memory_bytes
        )));
    }
    if !policy.enforce_ui_limits {
        return Err(OctopusSecurityError::IsolationViolation(
            "WIN_CONFINEMENT_INVARIANT: JOB_OBJECT_UILIMIT_ALL must be enforced to prevent Shatter/clipboard attacks".to_string(),
        ));
    }
    Ok(())
}

/// Evaluates the pre-resume confinement gate (`RULE[windows_containment_invariants.md]`):
/// Asserts that `created_suspended`, `appcontainer_bound` (when required), `assigned_to_job`,
/// and `verified_in_job` (`IsProcessInJob == TRUE`) all hold BEFORE `ResumeThread` is ever called.
/// If any check fails, the suspended process MUST be terminated immediately with zero fallback.
pub fn evaluate_pre_resume_confinement_gate(
    policy: &WindowsConfinementPolicy,
    created_suspended: bool,
    appcontainer_bound: bool,
    assigned_to_job: bool,
    verified_in_job: bool,
) -> Result<(), OctopusSecurityError> {
    verify_windows_confinement_invariants(policy)?;

    if !created_suspended {
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL_CLOSED_PRE_RESUME: Process was not created with CREATE_SUSPENDED (0x00000004)"
                .to_string(),
        ));
    }
    if policy.require_appcontainer && !appcontainer_bound {
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL_CLOSED_PRE_RESUME: AppContainer profile/SID binding failed; unisolated fallback forbidden".to_string(),
        ));
    }
    if !assigned_to_job {
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL_CLOSED_PRE_RESUME: AssignProcessToJobObject failed; terminating suspended process before ResumeThread".to_string(),
        ));
    }
    if !verified_in_job {
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL_CLOSED_PRE_RESUME: IsProcessInJob returned FALSE; terminating suspended process before ResumeThread".to_string(),
        ));
    }
    Ok(())
}

/// Kernel-verified AppContainer + Job Object token posture for a suspended Tier 2 child process (`AO-FIND-02`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppContainerTokenVerification {
    pub is_appcontainer: bool,
    pub package_sid: String,
    pub sid_matches_expected: bool,
    pub job_membership_verified: bool,
}

/// Result of launching and waiting on a Tier 2 native binary inside a kernel-verified
/// Windows AppContainer + Windows Job Object (`AO-FIND-02`, `AO-FIND-04`, `AO-FIND-07`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Tier2ConfinedChildResult {
    pub pid: u32,
    pub exit_code: i32,
    pub token_posture: crate::security::token_posture::TokenPosture,
    pub appcontainer_verification: AppContainerTokenVerification,
}

/// Inspects the actual kernel process token of a suspended child process BEFORE `ResumeThread`
/// (`AO-FIND-02`) to prove:
/// 1. `IsProcessInJob(process_handle, job.handle) == TRUE`,
/// 2. `GetTokenInformation(TokenIsAppContainer = 29) != 0`,
/// 3. `GetTokenInformation(TokenAppContainerSid = 31)` equals `expected_sid` via `EqualSid`.
#[cfg(windows)]
pub fn verify_process_appcontainer_token(
    process_handle: HANDLE,
    expected_sid: win32::PSID,
    expected_sid_str: &str,
    job: &WindowsJobObject,
) -> Result<AppContainerTokenVerification, OctopusSecurityError> {
    let in_job = job.verify_process_in_job(process_handle)?;
    if !in_job {
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED [AO-FIND-02]: Suspended child verified NOT in Windows Job Object"
                .to_string(),
        ));
    }

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_IS_APP_CONTAINER_CLASS: u32 = 29;
    const TOKEN_APP_CONTAINER_SID_CLASS: u32 = 31;

    let mut token_handle: HANDLE = std::ptr::null_mut();
    if unsafe { win32::OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle) } == 0
        || token_handle.is_null()
    {
        let err = unsafe { win32::GetLastError() };
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED [AO-FIND-02]: OpenProcessToken failed on suspended child (OS Error {})",
            err
        )));
    }

    // 1. Query TokenIsAppContainer (29)
    let mut is_ac: u32 = 0;
    let mut ret_len: u32 = 0;
    let ac_ok = unsafe {
        win32::GetTokenInformation(
            token_handle,
            TOKEN_IS_APP_CONTAINER_CLASS,
            &mut is_ac as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            &mut ret_len,
        )
    };
    if ac_ok == 0 || is_ac == 0 {
        unsafe { CloseHandle(token_handle) };
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED [AO-FIND-02]: Child process token has TokenIsAppContainer == 0; refusing to resume uncontained child".to_string(),
        ));
    }

    // 2. Query TokenAppContainerSid (31) and compare with expected_sid via EqualSid
    #[repr(C)]
    #[allow(non_snake_case)]
    struct TOKEN_APPCONTAINER_INFORMATION {
        TokenAppContainer: win32::PSID,
    }
    let mut sid_buf = vec![0u8; 128];
    let mut sid_ret_len: u32 = 0;
    let sid_ok = unsafe {
        win32::GetTokenInformation(
            token_handle,
            TOKEN_APP_CONTAINER_SID_CLASS,
            sid_buf.as_mut_ptr() as *mut std::ffi::c_void,
            sid_buf.len() as u32,
            &mut sid_ret_len,
        )
    };
    if sid_ok == 0 {
        let err = unsafe { win32::GetLastError() };
        unsafe { CloseHandle(token_handle) };
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED [AO-FIND-02]: GetTokenInformation(TokenAppContainerSid) failed (OS Error {})",
            err
        )));
    }

    let info_ptr = sid_buf.as_ptr() as *const TOKEN_APPCONTAINER_INFORMATION;
    let token_ac_sid = unsafe { (*info_ptr).TokenAppContainer };
    let sid_matches = !token_ac_sid.is_null()
        && !expected_sid.is_null()
        && unsafe { win32::EqualSid(token_ac_sid, expected_sid) } != 0;

    unsafe { CloseHandle(token_handle) };

    if !sid_matches {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED [AO-FIND-02]: Child TokenAppContainerSid does not match expected package SID '{}'",
            expected_sid_str
        )));
    }

    Ok(AppContainerTokenVerification {
        is_appcontainer: true,
        package_sid: expected_sid_str.to_string(),
        sid_matches_expected: true,
        job_membership_verified: true,
    })
}

/// Launches a handle-locked, identity-verified native executable (`VerifiedExecutableHandle`)
/// inside a genuine Windows AppContainer (`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`, zero network/loopback capabilities)
/// AND bound to `job` (`WindowsJobObject` with `JOB_OBJECT_UILIMIT_ALL`), verifying both
/// `IsProcessInJob` and `TokenIsAppContainer` / `TokenAppContainerSid` while `CREATE_SUSPENDED`
/// before calling `ResumeThread` (`AO-FIND-02`, `AO-FIND-04`, `AO-FIND-07`).
#[cfg(windows)]
pub fn spawn_tier2_appcontainer_command(
    verified_exe: &crate::security::executable_identity::VerifiedExecutableHandle,
    args: &[String],
    agent_id: &str,
    scratchpad_root: &std::path::Path,
    job: &WindowsJobObject,
) -> Result<Tier2ConfinedChildResult, OctopusSecurityError> {
    let _ = std::fs::create_dir_all(scratchpad_root);
    let sanitized_agent: String = agent_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(32)
        .collect();
    let container_name = format!("AgentOctopus.Tier2.{}", sanitized_agent);
    let (sid_str, psid) = create_or_open_appcontainer_profile(
        &container_name,
        &format!("AgentOctopus Tier 2 Sandbox ({})", sanitized_agent),
        "Zero-ambient-authority Tier 2 AppContainer for native CLI tools",
    )?;

    let mut sec_cap = win32::SECURITY_CAPABILITIES {
        AppContainerSid: psid,
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0, // Zero capabilities -> no internetClient, no privateNetworkClientServer, no loopback
        Reserved: 0,
    };

    // Note: `spawn_tier2_appcontainer_command` launches `CREATE_NO_WINDOW` without piped stdio,
    // which triggers `conhost.exe` initialization inside the AppContainer; `NO_LOW_LABEL` causes
    // `STATUS_DLL_INIT_FAILED` (`0xC0000142`) on `conhost`/console attaches, so retain
    // `EXTENSION_POINT_DISABLE | IMAGE_LOAD_NO_REMOTE | IMAGE_LOAD_PREFER_SYSTEM32`.
    let mut mitigation_policy: u64 = compute_windows_mitigation_policy_mask(
        false,
        crate::security::virtual_patch_shield::current_shield_posture().is_shield_active(),
    )
        & !PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON;

    let mut attr_size: usize = 0;
    unsafe {
        win32::InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut attr_size);
    }
    if attr_size == 0 {
        unsafe { win32::FreeSid(psid) };
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: InitializeProcThreadAttributeList size query failed".to_string(),
        ));
    }

    let mut attr_buf = vec![0u8; attr_size];
    let attr_list = attr_buf.as_mut_ptr() as *mut std::ffi::c_void;
    if unsafe { win32::InitializeProcThreadAttributeList(attr_list, 2, 0, &mut attr_size) } == 0 {
        unsafe { win32::FreeSid(psid) };
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: InitializeProcThreadAttributeList buffer init failed".to_string(),
        ));
    }

    // PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
    if unsafe {
        win32::UpdateProcThreadAttribute(
            attr_list,
            0,
            0x00020009,
            &mut sec_cap as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<win32::SECURITY_CAPABILITIES>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        unsafe {
            win32::DeleteProcThreadAttributeList(attr_list);
            win32::FreeSid(psid);
        }
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES) failed".to_string(),
        ));
    }
    if unsafe {
        win32::UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            (&mut mitigation_policy as *mut u64).cast::<std::ffi::c_void>(),
            std::mem::size_of::<u64>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        unsafe {
            win32::DeleteProcThreadAttributeList(attr_list);
            win32::FreeSid(psid);
        }
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY) failed".to_string(),
        ));
    }

    let mut si_ex: win32::STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si_ex.StartupInfo.cb = std::mem::size_of::<win32::STARTUPINFOEXW>() as u32;
    si_ex.lpAttributeList = attr_list;

    // Construct lpApplicationName from the handle-locked canonical path and escaped command line
    let canonical_exe = &verified_exe.metadata.canonical_path;
    let wide_app: Vec<u16> = canonical_exe
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let cmdline = build_windows_command_line(canonical_exe, args);
    let mut wide_cmd: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();

    // Sanitized minimal Unicode environment block (prevents leaking host API keys/tokens into Tier 2).
    // NOTE: Windows `RtlQueryEnvironmentVariable_U` (`BasepCreateLowBox`) binary-searches the environment
    // block by uppercase variable name; if entries are not sorted case-insensitively or omit USERPROFILE /
    // LOCALAPPDATA / SystemRoot, CreateProcessW in AppContainer fails with ERROR_ENVVAR_NOT_FOUND (203).
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let sys_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let user_profile = std::env::var("USERPROFILE")
        .unwrap_or_else(|_| scratchpad_root.to_string_lossy().to_string());
    let local_app_data = std::env::var("LOCALAPPDATA")
        .unwrap_or_else(|_| scratchpad_root.to_string_lossy().to_string());
    let app_data =
        std::env::var("APPDATA").unwrap_or_else(|_| scratchpad_root.to_string_lossy().to_string());
    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| format!("{}\\ProgramData", sys_drive));
    let scratch_str = scratchpad_root.to_string_lossy();
    let mut env_pairs: Vec<(String, String)> = vec![
        ("AGENT_OCTOPUS_TIER2_CONFINED".to_string(), "1".to_string()),
        ("ALLUSERSPROFILE".to_string(), program_data.clone()),
        ("APPDATA".to_string(), app_data),
        (
            "ComSpec".to_string(),
            format!("{}\\System32\\cmd.exe", sys_root),
        ),
        ("LOCALAPPDATA".to_string(), local_app_data),
        ("PATH".to_string(), format!("{}\\System32", sys_root)),
        ("PATHEXT".to_string(), ".COM;.EXE".to_string()),
        ("ProgramData".to_string(), program_data),
        ("SystemDrive".to_string(), sys_drive),
        ("SystemRoot".to_string(), sys_root.clone()),
        ("TEMP".to_string(), scratch_str.to_string()),
        ("TMP".to_string(), scratch_str.to_string()),
        ("USERPROFILE".to_string(), user_profile),
        ("WINDIR".to_string(), sys_root),
    ];
    env_pairs.sort_by(|a, b| a.0.to_ascii_uppercase().cmp(&b.0.to_ascii_uppercase()));
    let mut env_block: Vec<u16> = Vec::new();
    for (k, v) in &env_pairs {
        let entry = format!("{}={}", k, v);
        env_block.extend(entry.encode_utf16());
        env_block.push(0);
    }
    env_block.push(0);

    let mut pi: windows_sys::Win32::System::Threading::PROCESS_INFORMATION =
        unsafe { std::mem::zeroed() };

    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    const CREATE_SUSPENDED: u32 = 0x0000_0004;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;

    // Launch with bInheritHandles = 0 (FALSE) while `verified_exe` holds FILE_SHARE_READ on the image
    let created = unsafe {
        win32::CreateProcessW(
            wide_app.as_ptr(),
            wide_cmd.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0, // bInheritHandles = FALSE (zero supervisor handle inheritance)
            EXTENDED_STARTUPINFO_PRESENT
                | CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT,
            env_block.as_mut_ptr() as *mut std::ffi::c_void,
            std::ptr::null(),
            &si_ex as *const _ as *const std::ffi::c_void,
            &mut pi,
        )
    };

    unsafe {
        win32::DeleteProcThreadAttributeList(attr_list);
    }

    if created == 0 {
        let err = unsafe { win32::GetLastError() };
        unsafe { win32::FreeSid(psid) };
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: CreateProcessW in AppContainer '{}' for '{}' failed (OS Error {})",
            container_name, canonical_exe, err
        )));
    }

    // 1. Bind suspended process to WindowsJobObject BEFORE ResumeThread (AO-FIND-07)
    if let Err(e) = job.assign_process(pi.hProcess) {
        unsafe {
            win32::TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            win32::FreeSid(psid);
        }
        rollback_appcontainer_profile(&container_name);
        return Err(e);
    }

    // 2. Verify actual child token AppContainer identity & Job Object membership BEFORE ResumeThread (AO-FIND-02)
    let ac_verification = match verify_process_appcontainer_token(pi.hProcess, psid, &sid_str, job)
    {
        Ok(v) => v,
        Err(e) => {
            unsafe {
                win32::TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                win32::FreeSid(psid);
            }
            rollback_appcontainer_profile(&container_name);
            return Err(e);
        }
    };
    unsafe { win32::FreeSid(psid) };

    // 3. Query child TokenPosture while still suspended
    let token_posture = match crate::security::token_posture::TokenPosture::of_process(pi.hProcess)
    {
        Ok(p) => p,
        Err(e) => {
            unsafe {
                win32::TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            rollback_appcontainer_profile(&container_name);
            return Err(e);
        }
    };

    if let Err(reasons) = token_posture.verify_agent_safe() {
        unsafe {
            win32::TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: Child TokenPosture failed verify_agent_safe: {}",
            reasons.join("; ")
        )));
    }

    // 4. Resume primary thread now that Job Object + AppContainer + TokenPosture + Binary Identity are verified
    if unsafe { win32::ResumeThread(pi.hThread) } == u32::MAX {
        let err = unsafe { win32::GetLastError() };
        unsafe {
            win32::TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: ResumeThread failed on AppContainer Tier 2 child (OS Error {})",
            err
        )));
    }
    unsafe { CloseHandle(pi.hThread) };

    // 5. Wait for completion with hard 10s wall-clock ceiling; terminate job on timeout
    const WAIT_OBJECT_0: u32 = 0x0000_0000;
    let wait_rc = unsafe { win32::WaitForSingleObject(pi.hProcess, 10_000) };
    if wait_rc != WAIT_OBJECT_0 {
        let _ = job.terminate(1);
        unsafe { CloseHandle(pi.hProcess) };
        rollback_appcontainer_profile(&container_name);
        return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
            "TIER2_WALL_CLOCK_TIMEOUT: Process {} in AppContainer '{}' exceeded 10s deadline; job terminated",
            pi.dwProcessId, container_name
        )));
    }

    let mut exit_code: u32 = 1;
    let _ = unsafe { win32::GetExitCodeProcess(pi.hProcess, &mut exit_code) };
    unsafe { CloseHandle(pi.hProcess) };
    rollback_appcontainer_profile(&container_name);

    Ok(Tier2ConfinedChildResult {
        pid: pi.dwProcessId,
        exit_code: exit_code as i32,
        token_posture,
        appcontainer_verification: ac_verification,
    })
}

#[cfg(target_os = "linux")]
pub fn spawn_tier2_appcontainer_command(
    verified_exe: &crate::security::executable_identity::VerifiedExecutableHandle,
    args: &[String],
    agent_id: &str,
    scratchpad_root: &std::path::Path,
    job: &WindowsJobObject,
) -> Result<Tier2ConfinedChildResult, OctopusSecurityError> {
    crate::security::linux_sandbox::spawn_tier2_linux_command(
        verified_exe,
        args,
        agent_id,
        scratchpad_root,
        job,
    )
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub fn spawn_tier2_appcontainer_command(
    _verified_exe: &crate::security::executable_identity::VerifiedExecutableHandle,
    _args: &[String],
    _agent_id: &str,
    _scratchpad_root: &std::path::Path,
    _job: &WindowsJobObject,
) -> Result<Tier2ConfinedChildResult, OctopusSecurityError> {
    Err(OctopusSecurityError::IsolationViolation(
        "FAIL-CLOSED: Tier 2 native child confinement is unsupported on this operating system (requires Windows AppContainer or Linux Landlock/seccomp-BPF)".to_string(),
    ))
}

/// Owned handle to a Windows AppContainer + Job Object confined child process for `octopus run --sandbox strict`.
#[cfg(windows)]
#[derive(Debug)]
pub struct AppContainerChildHandle {
    pub pid: u32,
    pub container_name: String,
    pub package_sid: String,
    pub posture: crate::security::token_posture::TokenPosture,
    pub appcontainer_verification: AppContainerTokenVerification,
    granted_acl_paths: Vec<std::path::PathBuf>,
    reset_inheritance_paths: Vec<(std::path::PathBuf, PreIsolationAclSnapshot)>,
    loopback_exempt_added: bool,
    process: HANDLE,
}

#[cfg(windows)]
unsafe impl Send for AppContainerChildHandle {}

#[cfg(windows)]
impl AppContainerChildHandle {
    /// Waits up to `timeout` (or indefinitely if `None`). Returns `Ok(None)` on timeout.
    pub fn wait_with_timeout(
        &self,
        timeout: Option<std::time::Duration>,
    ) -> Result<Option<u32>, OctopusSecurityError> {
        const WAIT_OBJECT_0: u32 = 0x0000_0000;
        const WAIT_TIMEOUT: u32 = 0x0000_0102;
        const INFINITE: u32 = 0xFFFF_FFFF;
        let ms = match timeout {
            Some(d) => d.as_millis().min((INFINITE - 1) as u128) as u32,
            None => INFINITE,
        };
        let rc = unsafe { win32::WaitForSingleObject(self.process, ms) };
        if rc == WAIT_TIMEOUT {
            return Ok(None);
        }
        if rc != WAIT_OBJECT_0 {
            let err = unsafe { win32::GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: WaitForSingleObject(AppContainer) failed (OS Error {})",
                err
            )));
        }
        let mut code: u32 = 1;
        if unsafe { win32::GetExitCodeProcess(self.process, &mut code) } == 0 {
            let err = unsafe { win32::GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: GetExitCodeProcess(AppContainer) failed (OS Error {})",
                err
            )));
        }
        Ok(Some(code))
    }
}

#[cfg(windows)]
fn revoke_appcontainer_acls(
    package_sid: &str,
    container_name: &str,
    paths: &[std::path::PathBuf],
    reset_paths: &[(std::path::PathBuf, PreIsolationAclSnapshot)],
) {
    // Never run icacls /remove or /reset unlocked (nor panic in Drop) if mutex acquisition fails.
    let Ok(acl_lock) =
        Win32NamedMutexGuard::acquire(APPCONTAINER_ACL_MUTEX_NAME, APPCONTAINER_MUTEX_TIMEOUT_MS)
    else {
        return;
    };
    let sid_arg = format!("*{}", package_sid);
    for (p, _) in reset_paths.iter().rev() {
        if p.exists() || std::fs::symlink_metadata(p).is_ok() {
            let _ = run_icacls_locked(&acl_lock, p, "/remove", &sid_arg);
        }
    }
    for p in paths.iter().rev() {
        if p.exists() || std::fs::symlink_metadata(p).is_ok() {
            let _ = run_icacls_locked(&acl_lock, p, "/remove", &sid_arg);
        }
    }

    let mut ledger = load_acl_ledger_locked(&acl_lock);
    let own_sid_lower = package_sid.to_ascii_lowercase();

    let mut restore_order: Vec<&(std::path::PathBuf, PreIsolationAclSnapshot)> =
        reset_paths.iter().collect();
    restore_order.sort_by(|(pa, _), (pb, _)| {
        let na = norm_acl_cmp_path(pa);
        let nb = norm_acl_cmp_path(pb);
        na.len().cmp(&nb.len()).then_with(|| na.cmp(&nb))
    });
    for (p, fallback_snap) in restore_order {
        let tn = norm_acl_cmp_path(p);
        let entry_opt = ledger.entries.get_mut(&tn);
        let effective_snap = entry_opt
            .as_ref()
            .map(|e| e.snapshot())
            .unwrap_or_else(|| fallback_snap.clone());

        let mut combined_ancestors: Vec<std::path::PathBuf> = paths.to_vec();
        if let Some(entry) = entry_opt.as_ref() {
            for ap in &entry.ancestor_paths {
                combined_ancestors.push(std::path::PathBuf::from(ap));
            }
        }

        if p.exists() || std::fs::symlink_metadata(p).is_ok() {
            // Defer /reset or explicit-ACL restoration if another active AppContainer SID remains on a parent
            // or workspace ancestor so the surviving peer container cannot inherit access to denied targets.
            if ancestors_have_other_appcontainer_sid_locked(
                &acl_lock,
                p,
                &combined_ancestors,
                package_sid,
                Some(container_name),
            ) {
                if let Some(entry) = ledger.entries.get_mut(&tn) {
                    entry
                        .active_containers
                        .retain(|a| !a.sid.eq_ignore_ascii_case(&own_sid_lower));
                    entry.pending_restore = true;
                    let mut seen: std::collections::HashSet<String> = entry
                        .ancestor_paths
                        .iter()
                        .map(|s| norm_acl_cmp_path(std::path::Path::new(s)))
                        .collect();
                    for anc in collect_relevant_ancestors(p, paths) {
                        let an = norm_acl_cmp_path(&anc);
                        if seen.insert(an) {
                            entry.ancestor_paths.push(anc.to_string_lossy().to_string());
                        }
                    }
                } else {
                    let anc_strs = collect_relevant_ancestors(p, paths)
                        .into_iter()
                        .map(|ap| ap.to_string_lossy().to_string())
                        .collect();
                    ledger.entries.insert(
                        tn,
                        AppContainerAclLedgerEntry {
                            original_inherited_only: effective_snap.original_inherited_only,
                            original_protected: effective_snap.original_protected,
                            original_explicit_sddl_aces: effective_snap
                                .original_explicit_sddl_aces
                                .clone(),
                            target_path: p.to_string_lossy().to_string(),
                            active_containers: Vec::new(),
                            pending_restore: true,
                            ancestor_paths: anc_strs,
                        },
                    );
                }
                continue;
            }
            restore_target_pre_acl_locked(&acl_lock, p, &effective_snap);
        }
        ledger.entries.remove(&tn);
    }

    // Check all pending-restore ledger entries (including nested targets like
    // `.git` -> `.git/hooks` and `.git/modules/sub/hooks`) shallowest path first
    // in a fixed-point loop so restoring a parent unblocks its children.
    let mut pending_keys: Vec<String> = ledger
        .entries
        .iter()
        .filter(|(_, e)| e.pending_restore)
        .map(|(k, _)| k.clone())
        .collect();
    pending_keys.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));

    loop {
        let mut progressed = false;
        let mut remaining = Vec::with_capacity(pending_keys.len());
        for key in pending_keys {
            let Some(entry) = ledger.entries.get(&key).cloned() else {
                continue;
            };
            let target = std::path::Path::new(&entry.target_path);
            if !target.exists() && std::fs::symlink_metadata(target).is_err() {
                ledger.entries.remove(&key);
                progressed = true;
                continue;
            }
            let mut combined_ancestors: Vec<std::path::PathBuf> = paths.to_vec();
            for ap in &entry.ancestor_paths {
                combined_ancestors.push(std::path::PathBuf::from(ap));
            }
            if !ancestors_have_other_appcontainer_sid_locked(
                &acl_lock,
                target,
                &combined_ancestors,
                "",
                None,
            ) {
                restore_target_pre_acl_locked(&acl_lock, target, &entry.snapshot());
                ledger.entries.remove(&key);
                progressed = true;
            } else {
                remaining.push(key);
            }
        }
        pending_keys = remaining;
        if !progressed || pending_keys.is_empty() {
            break;
        }
    }

    // Prune stale ledger entries (including `pending_restore == false` from hard-killed processes)
    // whose `target_path` no longer exists on disk so deleted temp dirs never accumulate.
    ledger.entries.retain(|_, entry| {
        let p = std::path::Path::new(&entry.target_path);
        p.exists() || std::fs::symlink_metadata(p).is_ok()
    });

    save_acl_ledger_locked(&acl_lock, &ledger);
}

#[cfg(windows)]
impl Drop for AppContainerChildHandle {
    fn drop(&mut self) {
        if !self.process.is_null() && self.process != INVALID_HANDLE_VALUE {
            unsafe {
                const WAIT_TIMEOUT: u32 = 0x0000_0102;
                if win32::WaitForSingleObject(self.process, 0) == WAIT_TIMEOUT {
                    let _ = win32::TerminateProcess(self.process, 1);
                    let _ = win32::WaitForSingleObject(self.process, 2000);
                }
                CloseHandle(self.process);
            }
        }
        if self.loopback_exempt_added {
            revoke_appcontainer_loopback_exemption(&self.package_sid);
        }
        revoke_appcontainer_acls(
            &self.package_sid,
            &self.container_name,
            &self.granted_acl_paths,
            &self.reset_inheritance_paths,
        );
        rollback_appcontainer_profile(&self.container_name);
    }
}

/// Spawns a CLI workload inside a verified Windows AppContainer + `WindowsJobObject` (`--sandbox strict`)
/// with explicit `cwd`, sanitized `env_pairs`, and inherited or piped stdio. Fails closed if
/// AppContainer creation, job binding, or AppContainer token verification fails.
#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
pub fn spawn_appcontainer_in_job_with_io(
    application_name: &str,
    args: &[String],
    cwd: &std::path::Path,
    env_pairs: &[(String, String)],
    allow_loopback_cap: bool,
    allow_read_dirs: &[std::path::PathBuf],
    allow_write_dirs: &[std::path::PathBuf],
    mandatory_ro_dirs: &[std::path::PathBuf],
    pipe_stdio: bool,
    job: &WindowsJobObject,
) -> Result<
    (
        AppContainerChildHandle,
        Option<std::fs::File>,
        Option<std::fs::File>,
    ),
    OctopusSecurityError,
> {
    spawn_appcontainer_in_job_with_io_prepared(
        application_name,
        args,
        cwd,
        env_pairs,
        allow_loopback_cap,
        allow_read_dirs,
        allow_write_dirs,
        mandatory_ro_dirs,
        &[],
        pipe_stdio,
        job,
        None,
        false,
    )
}

/// Spawns a CLI workload inside a verified Windows AppContainer + `WindowsJobObject` (`--sandbox strict`)
/// optionally consuming a pre-created `PreparedAppContainerProfile`. Grants network capability SIDs
/// (`S-1-15-3-1`, `S-1-15-3-3`) ONLY when `allow_loopback_cap && loopback_exempt_active`; otherwise
/// enforces `CapabilityCount = 0` so kernel network blocks fail fast.
#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
pub fn spawn_appcontainer_in_job_with_io_prepared(
    application_name: &str,
    args: &[String],
    cwd: &std::path::Path,
    env_pairs: &[(String, String)],
    allow_loopback_cap: bool,
    allow_read_dirs: &[std::path::PathBuf],
    allow_write_dirs: &[std::path::PathBuf],
    mandatory_ro_dirs: &[std::path::PathBuf],
    deny_paths: &[std::path::PathBuf],
    pipe_stdio: bool,
    job: &WindowsJobObject,
    prepared: Option<PreparedAppContainerProfile>,
    disallow_win32k: bool,
) -> Result<
    (
        AppContainerChildHandle,
        Option<std::fs::File>,
        Option<std::fs::File>,
    ),
    OctopusSecurityError,
> {
    use std::os::windows::io::{FromRawHandle, RawHandle};

    #[repr(C)]
    #[allow(non_snake_case)]
    struct AC_SECURITY_ATTRIBUTES {
        nLength: u32,
        lpSecurityDescriptor: *mut std::ffi::c_void,
        bInheritHandle: i32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreatePipe(
            hReadPipe: *mut HANDLE,
            hWritePipe: *mut HANDLE,
            lpPipeAttributes: *const AC_SECURITY_ATTRIBUTES,
            nSize: u32,
        ) -> i32;
        fn SetHandleInformation(hObject: HANDLE, dwMask: u32, dwFlags: u32) -> i32;
        fn GetStdHandle(nStdHandle: u32) -> HANDLE;
    }

    const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
    const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
    const STD_INPUT_HANDLE: u32 = (-10i32) as u32;
    const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
    const STD_ERROR_HANDLE: u32 = (-12i32) as u32;
    const SE_GROUP_ENABLED: u32 = 0x0000_0004;
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    const CREATE_SUSPENDED: u32 = 0x0000_0004;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;

    let (container_name, sid_str, psid, loopback_exempt_added, loopback_exempt_active) =
        if let Some(mut prep) = prepared {
            let (cn, ss, p, added, already) = prep.take_raw().ok_or_else(|| {
                OctopusSecurityError::IsolationViolation(
                    "FAIL-CLOSED: PreparedAppContainerProfile missing SID".to_string(),
                )
            })?;
            (cn, ss, p, added, added || already)
        } else {
            let cn = format!(
                "AgentOctopus.OctopusRun.{}_{:08x}",
                std::process::id(),
                rand::random::<u32>()
            );
            let (ss, p) = create_or_open_appcontainer_profile(
                &cn,
                "AgentOctopus Strict CLI Sandbox",
                "AppContainer boundary for octopus run --sandbox strict",
            )?;
            (cn, ss, p, false, false)
        };

    let mut reset_inheritance_paths: Vec<(std::path::PathBuf, PreIsolationAclSnapshot)> =
        Vec::new();
    let mut granted_acl_paths = Vec::new();
    let cleanup_profile =
        |acl_paths: &[std::path::PathBuf],
         reset_paths: &[(std::path::PathBuf, PreIsolationAclSnapshot)]| {
            if loopback_exempt_added {
                revoke_appcontainer_loopback_exemption(&sid_str);
            }
            revoke_appcontainer_acls(&sid_str, &container_name, acl_paths, reset_paths);
            rollback_appcontainer_profile(&container_name);
        };

    let acl_setup_res: Result<(), OctopusSecurityError> = (|| {
        let acl_lock = Win32NamedMutexGuard::acquire(
            APPCONTAINER_ACL_MUTEX_NAME,
            APPCONTAINER_MUTEX_TIMEOUT_MS,
        )?;

        let candidate_granted_dirs: Vec<std::path::PathBuf> = allow_read_dirs
            .iter()
            .chain(std::iter::once(&cwd.to_path_buf()))
            .chain(allow_write_dirs.iter())
            .chain(mandatory_ro_dirs.iter())
            .filter(|p| p.exists())
            .cloned()
            .collect();
        let granted_norms: Vec<String> = candidate_granted_dirs
            .iter()
            .map(|p| norm_acl_cmp_path(p))
            .collect();
        let is_under_granted = |target: &std::path::Path| -> bool {
            let tn = norm_acl_cmp_path(target);
            granted_norms
                .iter()
                .any(|gn| !gn.is_empty() && (tn == *gn || tn.starts_with(&format!("{}/", gn))))
        };

        // Inspect inheritance posture on existing deny / mandatory write-deny targets BEFORE granting
        // parent ACLs so cleanup_profile can restore their exact pre-sandbox inheritance state.
        // Consult the shared ACL ledger so staggered concurrent AppContainers inherit the true
        // pre-sandbox inheritance state rather than sampling a peer's mid-run `/inheritance:d`.
        let mut ledger = load_acl_ledger_locked(&acl_lock);
        let mut recorded_pre_norms: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let own_actor = AppContainerLedgerActor {
            sid: sid_str.clone(),
            container_name: container_name.clone(),
        };
        let mut record_pre_acl = |target: &std::path::Path| {
            if (target.exists() || std::fs::symlink_metadata(target).is_ok())
                && is_under_granted(target)
            {
                let tn = norm_acl_cmp_path(target);
                if recorded_pre_norms.insert(tn.clone()) {
                    let relevant_ancestors =
                        collect_relevant_ancestors(target, &candidate_granted_dirs);
                    let ancestor_strs: Vec<String> = relevant_ancestors
                        .iter()
                        .map(|p| p.to_string_lossy().to_string())
                        .collect();

                    let mut existing_snap = None;
                    if let Some(entry) = ledger.entries.get_mut(&tn) {
                        if validate_ledger_entry_live_locked(
                            &acl_lock,
                            entry,
                            &candidate_granted_dirs,
                        ) {
                            existing_snap = Some(entry.snapshot());
                            if !entry
                                .active_containers
                                .iter()
                                .any(|a| a.sid.eq_ignore_ascii_case(&own_actor.sid))
                            {
                                entry.active_containers.push(own_actor.clone());
                            }
                            entry.pending_restore = false;
                            let mut seen_anc: std::collections::HashSet<String> = entry
                                .ancestor_paths
                                .iter()
                                .map(|s| norm_acl_cmp_path(std::path::Path::new(s)))
                                .collect();
                            for anc in &relevant_ancestors {
                                let an = norm_acl_cmp_path(anc);
                                if seen_anc.insert(an) {
                                    entry.ancestor_paths.push(anc.to_string_lossy().to_string());
                                }
                            }
                        } else {
                            ledger.entries.remove(&tn);
                        }
                    }

                    let snap = match existing_snap {
                        Some(orig) => orig,
                        None => {
                            let orig = capture_pre_isolation_acl_locked(&acl_lock, target);
                            ledger.entries.insert(
                                tn,
                                AppContainerAclLedgerEntry {
                                    original_inherited_only: orig.original_inherited_only,
                                    original_protected: orig.original_protected,
                                    original_explicit_sddl_aces: orig
                                        .original_explicit_sddl_aces
                                        .clone(),
                                    target_path: target.to_string_lossy().to_string(),
                                    active_containers: vec![own_actor.clone()],
                                    pending_restore: false,
                                    ancestor_paths: ancestor_strs,
                                },
                            );
                            orig
                        }
                    };
                    reset_inheritance_paths.push((target.to_path_buf(), snap));
                }
            }
        };
        for dp in deny_paths {
            record_pre_acl(dp);
        }
        for wdir in allow_write_dirs {
            if !wdir.is_dir() {
                continue;
            }
            for rel in [
                ".git",
                ".git/hooks",
                ".git/modules",
                ".git/config",
                ".gitmodules",
                ".gitconfig",
                ".githooks",
                ".vscode",
                ".idea",
                ".claude/commands",
                ".claude/agents",
                ".mcp.json",
                ".ripgreprc",
                ".bashrc",
                ".bash_profile",
                ".zshrc",
                ".zprofile",
                ".profile",
                ".env",
            ] {
                record_pre_acl(&wdir.join(rel));
            }
            if let Ok(entries) = std::fs::read_dir(wdir) {
                for entry in entries.flatten() {
                    let name_lower = entry.file_name().to_string_lossy().to_ascii_lowercase();
                    if name_lower.starts_with(".env.") && entry.path().is_file() {
                        record_pre_acl(&entry.path());
                    }
                }
            }
        }
        save_acl_ledger_locked(&acl_lock, &ledger);

        // Best-effort grant AppContainer SID ACLs on declared user directories so scripts/cwd are readable/writable.
        let sid_grant_rx = format!("*{}:(OI)(CI)RX", sid_str);
        let sid_grant_m = format!("*{}:(OI)(CI)M", sid_str);
        let mut try_grant =
            |path: &std::path::Path, perm: &str| -> Result<(), OctopusSecurityError> {
                if path.exists()
                    && run_icacls_locked(&acl_lock, path, "/grant", perm)?
                    && !granted_acl_paths.contains(&path.to_path_buf())
                {
                    granted_acl_paths.push(path.to_path_buf());
                }
                Ok(())
            };
        for p in allow_read_dirs {
            try_grant(p, &sid_grant_rx)?;
        }
        try_grant(cwd, &sid_grant_rx)?;
        for p in allow_write_dirs {
            try_grant(p, &sid_grant_m)?;
        }
        if let Some(exe_parent) = std::path::Path::new(application_name).parent() {
            try_grant(exe_parent, &sid_grant_rx)?;
        }
        for p in mandatory_ro_dirs {
            let granted = if p.exists() {
                run_icacls_locked(&acl_lock, p, "/grant", &sid_grant_rx)?
            } else {
                false
            };
            if !granted {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: failed to grant AppContainer (RX) ACL on mandatory guard directory '{}'",
                    p.display()
                )));
            }
            if !granted_acl_paths.contains(&p.to_path_buf()) {
                granted_acl_paths.push(p.to_path_buf());
            }
        }

        // Break inheritance on mandatory write-deny and `filesystem.deny` targets inside granted
        // directories, strip the inherited package SID, and (for mandatory write-deny not covered by
        // `filesystem.deny`) grant ONLY read-only (RX) so Windows AppContainer AccessCheck fails closed
        // at the kernel boundary. Mandatory write-deny RX runs BEFORE `deny_paths` (None) isolation
        // and skips any target under `deny_paths` so `filesystem.deny` is never overwritten with RX.
        let deny_norms: Vec<String> = deny_paths
            .iter()
            .filter(|dp| dp.exists() || std::fs::symlink_metadata(dp).is_ok())
            .map(|dp| norm_acl_cmp_path(dp))
            .collect();
        let is_denied_target = |target: &std::path::Path| -> bool {
            let tn = norm_acl_cmp_path(target);
            deny_norms
                .iter()
                .any(|dn| !dn.is_empty() && (tn == *dn || tn.starts_with(&format!("{}/", dn))))
        };
        let sid_remove_arg = format!("*{}", sid_str);
        let isolate_target_acl = |target: &std::path::Path,
                                  ro_grant_perm: Option<&str>,
                                  fail_closed: bool|
         -> Result<(), OctopusSecurityError> {
            if !target.exists() && std::fs::symlink_metadata(target).is_err() {
                return Ok(());
            }
            let inh_out = run_icacls_output_locked(&acl_lock, target, &["/inheritance:d", "/Q"]);
            let inh_ok = matches!(&inh_out, Ok(o) if o.status.success());
            let rem_ok = matches!(
                run_icacls_locked(&acl_lock, target, "/remove", &sid_remove_arg),
                Ok(true)
            );
            let grant_ok = match ro_grant_perm {
                Some(perm) => matches!(
                    run_icacls_locked(&acl_lock, target, "/grant", perm),
                    Ok(true)
                ),
                None => true,
            };
            if !(inh_ok && rem_ok && grant_ok) && fail_closed {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: failed to isolate AppContainer ACL on '{}'",
                    target.display()
                )));
            }
            Ok(())
        };

        let sid_ro_dir = format!("*{}:(OI)(CI)RX", sid_str);
        let sid_ro_file = format!("*{}:RX", sid_str);

        for wdir in allow_write_dirs {
            if !wdir.is_dir() {
                continue;
            }
            for sub_dir in [
                ".git",
                ".git/hooks",
                ".git/modules",
                ".githooks",
                ".vscode",
                ".idea",
                ".claude/commands",
                ".claude/agents",
            ] {
                let target = wdir.join(sub_dir);
                if target.is_dir() && !is_denied_target(&target) {
                    isolate_target_acl(&target, Some(&sid_ro_dir), true)?;
                }
            }
            for sub_file in [
                ".git/config",
                ".gitmodules",
                ".gitconfig",
                ".mcp.json",
                ".ripgreprc",
                ".bashrc",
                ".bash_profile",
                ".zshrc",
                ".zprofile",
                ".profile",
                ".env",
            ] {
                let target = wdir.join(sub_file);
                if target.is_file() && !is_denied_target(&target) {
                    isolate_target_acl(&target, Some(&sid_ro_file), true)?;
                }
            }
            if let Ok(entries) = std::fs::read_dir(wdir) {
                for entry in entries.flatten() {
                    let name_lower = entry.file_name().to_string_lossy().to_ascii_lowercase();
                    let entry_path = entry.path();
                    if name_lower.starts_with(".env.")
                        && entry_path.is_file()
                        && !is_denied_target(&entry_path)
                    {
                        isolate_target_acl(&entry_path, Some(&sid_ro_file), true)?;
                    }
                }
            }
        }

        for dp in deny_paths {
            if !dp.exists() && std::fs::symlink_metadata(dp).is_err() {
                continue;
            }
            if is_under_granted(dp) {
                isolate_target_acl(dp, None, true)?;
            }
        }

        Ok(())
    })();

    if let Err(e) = acl_setup_res {
        unsafe { win32::FreeSid(psid) };
        cleanup_profile(&granted_acl_paths, &reset_inheritance_paths);
        return Err(e);
    }

    let mut cap_sids: Vec<win32::PSID> = Vec::new();
    let mut caps: Vec<win32::SID_AND_ATTRIBUTES> = Vec::new();
    if allow_loopback_cap && loopback_exempt_active {
        for sid_lit in ["S-1-15-3-1", "S-1-15-3-3"] {
            let wide: Vec<u16> = sid_lit.encode_utf16().chain(std::iter::once(0)).collect();
            let mut csid: win32::PSID = std::ptr::null_mut();
            if unsafe { win32::ConvertStringSidToSidW(wide.as_ptr(), &mut csid) } != 0
                && !csid.is_null()
            {
                cap_sids.push(csid);
                caps.push(win32::SID_AND_ATTRIBUTES {
                    Sid: csid,
                    Attributes: SE_GROUP_ENABLED,
                });
            }
        }
    }

    let free_cap_sids = |sids: &[win32::PSID]| {
        for &cs in sids {
            if !cs.is_null() {
                unsafe { win32::LocalFree(cs) };
            }
        }
    };

    let mut sec_cap = win32::SECURITY_CAPABILITIES {
        AppContainerSid: psid,
        Capabilities: if caps.is_empty() {
            std::ptr::null_mut()
        } else {
            caps.as_mut_ptr()
        },
        CapabilityCount: caps.len() as u32,
        Reserved: 0,
    };

    let mut mitigation_policy: u64 = compute_windows_mitigation_policy_mask(
        disallow_win32k,
        disallow_win32k
            || crate::security::virtual_patch_shield::current_shield_posture().is_shield_active(),
    );

    let mut attr_size: usize = 0;
    unsafe {
        win32::InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut attr_size);
    }
    if attr_size == 0 {
        free_cap_sids(&cap_sids);
        unsafe { win32::FreeSid(psid) };
        cleanup_profile(&granted_acl_paths, &reset_inheritance_paths);
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: InitializeProcThreadAttributeList size query failed".to_string(),
        ));
    }

    let mut attr_buf = vec![0u8; attr_size];
    let attr_list = attr_buf.as_mut_ptr() as *mut std::ffi::c_void;
    if unsafe { win32::InitializeProcThreadAttributeList(attr_list, 2, 0, &mut attr_size) } == 0 {
        free_cap_sids(&cap_sids);
        unsafe { win32::FreeSid(psid) };
        cleanup_profile(&granted_acl_paths, &reset_inheritance_paths);
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: InitializeProcThreadAttributeList init failed".to_string(),
        ));
    }

    if unsafe {
        win32::UpdateProcThreadAttribute(
            attr_list,
            0,
            0x00020009,
            &mut sec_cap as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<win32::SECURITY_CAPABILITIES>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        unsafe {
            win32::DeleteProcThreadAttributeList(attr_list);
            win32::FreeSid(psid);
        }
        free_cap_sids(&cap_sids);
        cleanup_profile(&granted_acl_paths, &reset_inheritance_paths);
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed".to_string(),
        ));
    }
    if unsafe {
        win32::UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            (&mut mitigation_policy as *mut u64).cast::<std::ffi::c_void>(),
            std::mem::size_of::<u64>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        unsafe {
            win32::DeleteProcThreadAttributeList(attr_list);
            win32::FreeSid(psid);
        }
        free_cap_sids(&cap_sids);
        cleanup_profile(&granted_acl_paths, &reset_inheritance_paths);
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: UpdateProcThreadAttribute(MITIGATION_POLICY) failed".to_string(),
        ));
    }

    let mut out_read: HANDLE = std::ptr::null_mut();
    let mut out_write: HANDLE = std::ptr::null_mut();
    let mut err_read: HANDLE = std::ptr::null_mut();
    let mut err_write: HANDLE = std::ptr::null_mut();
    let close_pipes = |handles: &[HANDLE]| {
        for &h in handles {
            if !h.is_null() && h != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(h) };
            }
        }
    };

    let mut si_ex: win32::STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si_ex.StartupInfo.cb = std::mem::size_of::<win32::STARTUPINFOEXW>() as u32;
    si_ex.lpAttributeList = attr_list;

    if pipe_stdio {
        let sa = AC_SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<AC_SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };
        if unsafe { CreatePipe(&mut out_read, &mut out_write, &sa, 0) } == 0 {
            unsafe {
                win32::DeleteProcThreadAttributeList(attr_list);
                win32::FreeSid(psid);
            }
            free_cap_sids(&cap_sids);
            cleanup_profile(&granted_acl_paths, &reset_inheritance_paths);
            return Err(OctopusSecurityError::IsolationViolation(
                "FAIL-CLOSED: CreatePipe(stdout) failed".to_string(),
            ));
        }
        unsafe { SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0) };
        if unsafe { CreatePipe(&mut err_read, &mut err_write, &sa, 0) } == 0 {
            close_pipes(&[out_read, out_write]);
            unsafe {
                win32::DeleteProcThreadAttributeList(attr_list);
                win32::FreeSid(psid);
            }
            free_cap_sids(&cap_sids);
            cleanup_profile(&granted_acl_paths, &reset_inheritance_paths);
            return Err(OctopusSecurityError::IsolationViolation(
                "FAIL-CLOSED: CreatePipe(stderr) failed".to_string(),
            ));
        }
        unsafe { SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0) };
        let stdin_h = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if !stdin_h.is_null() && stdin_h != INVALID_HANDLE_VALUE {
            unsafe { SetHandleInformation(stdin_h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) };
        }
        si_ex.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        si_ex.StartupInfo.hStdInput = stdin_h;
        si_ex.StartupInfo.hStdOutput = out_write;
        si_ex.StartupInfo.hStdError = err_write;
    } else {
        let stdin_h = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let stdout_h = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        let stderr_h = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        for h in [stdin_h, stdout_h, stderr_h] {
            if !h.is_null() && h != INVALID_HANDLE_VALUE {
                unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) };
            }
        }
        si_ex.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        si_ex.StartupInfo.hStdInput = stdin_h;
        si_ex.StartupInfo.hStdOutput = stdout_h;
        si_ex.StartupInfo.hStdError = stderr_h;
    }

    // Ensure AppContainer-required Windows env vars exist and are sorted case-insensitively.
    let mut env_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (k, v) in env_pairs {
        env_map.insert(k.clone(), v.clone());
    }
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let sys_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let cwd_str = cwd.to_string_lossy().to_string();
    let defaults = [
        ("SystemRoot", sys_root.clone()),
        ("WINDIR", sys_root.clone()),
        ("SystemDrive", sys_drive.clone()),
        (
            "ProgramData",
            std::env::var("ProgramData").unwrap_or_else(|_| format!("{}\\ProgramData", sys_drive)),
        ),
        ("ComSpec", format!("{}\\System32\\cmd.exe", sys_root)),
        ("PATHEXT", ".COM;.EXE;.BAT;.CMD".to_string()),
        (
            "USERPROFILE",
            std::env::var("USERPROFILE").unwrap_or_else(|_| cwd_str.clone()),
        ),
        (
            "LOCALAPPDATA",
            std::env::var("LOCALAPPDATA").unwrap_or_else(|_| cwd_str.clone()),
        ),
        (
            "APPDATA",
            std::env::var("APPDATA").unwrap_or_else(|_| cwd_str.clone()),
        ),
    ];
    for (k, v) in defaults {
        if !env_map.keys().any(|ek| ek.eq_ignore_ascii_case(k)) {
            env_map.insert(k.to_string(), v);
        }
    }
    let mut sorted_env: Vec<(String, String)> = env_map.into_iter().collect();
    sorted_env.sort_by(|a, b| a.0.to_ascii_uppercase().cmp(&b.0.to_ascii_uppercase()));
    let mut env_block: Vec<u16> = Vec::new();
    for (k, v) in &sorted_env {
        let entry = format!("{}={}", k, v);
        env_block.extend(entry.encode_utf16());
        env_block.push(0);
    }
    env_block.push(0);

    let wide_app: Vec<u16> = application_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let cmdline = build_windows_command_line(application_name, args);
    let mut wide_cmd: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_cwd: Vec<u16> = cwd_str.encode_utf16().chain(std::iter::once(0)).collect();

    let mut pi: windows_sys::Win32::System::Threading::PROCESS_INFORMATION =
        unsafe { std::mem::zeroed() };

    let created = unsafe {
        win32::CreateProcessW(
            wide_app.as_ptr(),
            wide_cmd.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            1, // bInheritHandles = TRUE for stdio streaming
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            env_block.as_mut_ptr() as *mut std::ffi::c_void,
            wide_cwd.as_ptr(),
            &si_ex as *const _ as *const std::ffi::c_void,
            &mut pi,
        )
    };

    unsafe {
        win32::DeleteProcThreadAttributeList(attr_list);
    }
    free_cap_sids(&cap_sids);
    close_pipes(&[out_write, err_write]);

    if created == 0 {
        let err = unsafe { win32::GetLastError() };
        close_pipes(&[out_read, err_read]);
        unsafe { win32::FreeSid(psid) };
        cleanup_profile(&granted_acl_paths, &reset_inheritance_paths);
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: CreateProcessW in AppContainer '{}' for '{}' failed (OS Error {})",
            container_name, application_name, err
        )));
    }

    let cleanup_fail = |reason: OctopusSecurityError| -> OctopusSecurityError {
        unsafe {
            win32::TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        close_pipes(&[out_read, err_read]);
        cleanup_profile(&granted_acl_paths, &reset_inheritance_paths);
        reason
    };

    if let Err(e) = job.assign_process(pi.hProcess) {
        unsafe { win32::FreeSid(psid) };
        return Err(cleanup_fail(e));
    }

    let ac_verification = match verify_process_appcontainer_token(pi.hProcess, psid, &sid_str, job)
    {
        Ok(v) => {
            unsafe { win32::FreeSid(psid) };
            v
        }
        Err(e) => {
            unsafe { win32::FreeSid(psid) };
            return Err(cleanup_fail(e));
        }
    };

    let posture = match crate::security::token_posture::TokenPosture::of_process(pi.hProcess) {
        Ok(p) => p,
        Err(e) => return Err(cleanup_fail(e)),
    };
    if let Err(reasons) = posture.verify_agent_safe() {
        return Err(cleanup_fail(OctopusSecurityError::IsolationViolation(
            format!(
                "FAIL-CLOSED: AppContainer child TokenPosture unsafe: {}",
                reasons.join("; ")
            ),
        )));
    }

    if unsafe { win32::ResumeThread(pi.hThread) } == u32::MAX {
        let err = unsafe { win32::GetLastError() };
        return Err(cleanup_fail(OctopusSecurityError::IsolationViolation(
            format!(
                "FAIL-CLOSED: ResumeThread failed on AppContainer child (OS Error {})",
                err
            ),
        )));
    }
    unsafe { CloseHandle(pi.hThread) };

    let stdout_file = if pipe_stdio && !out_read.is_null() {
        Some(unsafe { std::fs::File::from_raw_handle(out_read as RawHandle) })
    } else {
        None
    };
    let stderr_file = if pipe_stdio && !err_read.is_null() {
        Some(unsafe { std::fs::File::from_raw_handle(err_read as RawHandle) })
    } else {
        None
    };

    Ok((
        AppContainerChildHandle {
            pid: pi.dwProcessId,
            container_name,
            package_sid: sid_str,
            posture,
            appcontainer_verification: ac_verification,
            granted_acl_paths,
            reset_inheritance_paths,
            loopback_exempt_added,
            process: pi.hProcess,
        },
        stdout_file,
        stderr_file,
    ))
}
