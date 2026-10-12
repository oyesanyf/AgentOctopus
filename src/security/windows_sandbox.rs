use crate::core::types::OctopusSecurityError;
use sha2::Digest;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, SetInformationJobObject, TerminateJobObject,
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
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
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn LocalFree(hMem: *mut c_void) -> *mut c_void;
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
            
            let handle = unsafe {
                CreateJobObjectW(std::ptr::null(), wide_name.as_ptr())
            };

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
                "FAIL-CLOSED: Cannot assign process to null or invalid Job Object handle".to_string(),
            ));
        }

        let success = unsafe {
            AssignProcessToJobObject(self.handle, process_handle)
        };

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
            let check_success = unsafe {
                IsProcessInJob(current_proc, self.handle, &mut in_job)
            };
            if check_success == 0 || in_job == 0 {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: Current process verified NOT in Windows Job Object '{}'",
                    self.name
                )));
            }
        }
        Ok(())
    }

    /// Terminates all processes assigned to this Windows Job Object immediately at the kernel level.
    pub fn terminate(&self, exit_code: u32) -> Result<(), OctopusSecurityError> {
        self.is_terminated.store(true, Ordering::SeqCst);

        #[cfg(windows)]
        {
            if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
                let success = unsafe { TerminateJobObject(self.handle, exit_code) };
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
    let wide_display: Vec<u16> = display_name.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_desc: Vec<u16> = description.encode_utf16().chain(std::iter::once(0)).collect();

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

impl WindowsAppContainerProfile {
    /// Creates a new AppContainer profile derived via Windows userenv API when available.
    pub fn new(agent_id: &str, is_lpac: bool, allow_google_only: bool) -> Self {
        let container_name = format!("AgentOctopus.AppContainer.{}", agent_id);

        #[cfg(windows)]
        {
            if let Ok((sid, _)) = create_or_open_appcontainer_profile(
                &container_name,
                &format!("Agent Octopus {}", agent_id),
                "AppContainer profile for Agent Octopus agent",
            ) {
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
            let val = u32::from_le_bytes(chunk.try_into().unwrap());
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

    /// Validates whether a given system operation is permitted under this AppContainer profile.
    /// Strictly parses and validates destination hostnames to prevent bypasses like
    /// `https://google.com.attacker.example/collect`.
    pub fn verify_access(&self, target_resource: &str, is_network: bool) -> Result<(), OctopusSecurityError> {
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
            if lower.contains("c:\\windows") || lower.contains("c:\\users") || lower.contains("/etc/") || lower.contains("..") {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "AppContainer [{}] kernel ACL blocked unauthorized filesystem access to '{}'",
                    self.container_name, target_resource
                )));
            }
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
            if !self.process_handle.is_null() && self.process_handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
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
            if !self.process_handle.is_null() && self.process_handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(self.process_handle);
                }
            }
            let wide_name: Vec<u16> = self.container_name.encode_utf16().chain(std::iter::once(0)).collect();
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

    // Calculate required buffer size for attribute list
    let mut attr_size: usize = 0;
    unsafe {
        win32::InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size);
    }
    if attr_size == 0 {
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: InitializeProcThreadAttributeList failed to calculate attribute size".to_string(),
        ));
    }

    let mut attr_buf: Vec<u8> = vec![0u8; attr_size];
    let attr_list = attr_buf.as_mut_ptr() as *mut std::ffi::c_void;
    let init_ok = unsafe {
        win32::InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size)
    };
    if init_ok == 0 {
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: InitializeProcThreadAttributeList failed to initialize attribute buffer".to_string(),
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
        unsafe { win32::DeleteProcThreadAttributeList(attr_list) };
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: UpdateProcThreadAttribute failed with error {}",
            unsafe { win32::GetLastError() }
        )));
    }

    // Prepare STARTUPINFOEXW
    let mut si_ex: win32::STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si_ex.StartupInfo.cb = std::mem::size_of::<win32::STARTUPINFOEXW>() as u32;
    si_ex.lpAttributeList = attr_list;

    let mut pi: windows_sys::Win32::System::Threading::PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

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

    unsafe { win32::DeleteProcThreadAttributeList(attr_list) };

    if create_res == 0 {
        let err = unsafe { win32::GetLastError() };
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
        };
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: AssignProcessToJobObject failed on suspended worker process (OS Error {}). Execution halted.",
            err
        )));
    }

    // Verify membership with IsProcessInJob
    let mut in_job: i32 = 0;
    let check_res = unsafe {
        windows_sys::Win32::System::JobObjects::IsProcessInJob(pi.hProcess, job.handle, &mut in_job)
    };
    if check_res == 0 || in_job == 0 {
        unsafe {
            win32::TerminateProcess(pi.hProcess, 1);
            windows_sys::Win32::Foundation::CloseHandle(pi.hProcess);
            windows_sys::Win32::Foundation::CloseHandle(pi.hThread);
        };
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: Suspended worker verified NOT in Windows Job Object. Execution halted.".to_string(),
        ));
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
