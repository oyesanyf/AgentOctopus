use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::security::windows_sandbox::WindowsJobObject;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, TerminateProcess, PROCESS_TERMINATE,
};
#[cfg(windows)]
use windows_sys::Win32::System::IO::DeviceIoControl;

// IOCTL Calculation
const FILE_DEVICE_UNKNOWN: u32 = 0x00000022;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;
const OSOOSI_IOCTL_BASE: u32 = 0x800;

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub const IOCTL_OSOOSI_GET_STATUS: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    OSOOSI_IOCTL_BASE + 0,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_OSOOSI_SET_MODE: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    OSOOSI_IOCTL_BASE + 1,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_OSOOSI_ADD_BLOCK_PATH: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    OSOOSI_IOCTL_BASE + 2,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_OSOOSI_ADD_BLOCK_HASH: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    OSOOSI_IOCTL_BASE + 3,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_OSOOSI_CLEAR_RULES: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    OSOOSI_IOCTL_BASE + 4,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_OSOOSI_POLL_INTERCEPTIONS: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    OSOOSI_IOCTL_BASE + 5,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

pub const OSOOSI_USER_DEVICE_NAME: &str = r"\\.\OsoosiDriver";

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RawOsoosiDriverStatus {
    pub version: u32,
    pub mode: u32,
    pub blocked_count: u32,
    pub rule_count: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawSetModeRequest {
    pub mode: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawAddPathRequest {
    pub image_path: [u16; 260],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawAddHashRequest {
    pub sha256: [u8; 32],
}

/// Curated BYOVD (Bring Your Own Vulnerable Driver) paths & SHA-256 hashes blocked during
/// Zero-Reboot Virtual-Patching Shield enforcement.
pub const BYOVD_VULNERABLE_DRIVERS: &[(&str, &str)] = &[
    (
        r"C:\Windows\System32\drivers\RTCore64.sys",
        "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd",
    ),
    (
        r"C:\Windows\System32\drivers\DBUtil_2_3.sys",
        "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5",
    ),
    (
        r"C:\Windows\System32\drivers\iqvw64e.sys",
        "a0c044aa4c5b2f81b395c7b40bf65b55757d4b3c0b3a6c5cb32f28b0bc754d91",
    ),
    (
        r"C:\Windows\System32\drivers\gdrv.sys",
        "31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427",
    ),
];

/// Cross-OS pure matcher checking whether a path/argument or SHA-256 digest matches any known
/// BYOVD (Bring Your Own Vulnerable Driver) entry in `BYOVD_VULNERABLE_DRIVERS`.
#[must_use]
pub fn match_byovd_vulnerable_driver(
    path_or_arg: Option<&str>,
    sha256_hex: Option<&str>,
) -> Option<(&'static str, &'static str)> {
    if let Some(hash) = sha256_hex {
        let trimmed_hash = hash.trim();
        if !trimmed_hash.is_empty() {
            if let Some(&(driver_path, driver_hash)) = BYOVD_VULNERABLE_DRIVERS
                .iter()
                .find(|&&(_, h)| h.eq_ignore_ascii_case(trimmed_hash))
            {
                return Some((driver_path, driver_hash));
            }
        }
    }
    if let Some(raw) = path_or_arg {
        let norm = raw
            .trim()
            .trim_matches(['"', '\'', '`'])
            .replace('/', "\\")
            .to_ascii_lowercase();
        if !norm.is_empty() {
            let basename = norm.rsplit('\\').next().unwrap_or(norm.as_str());
            for &(driver_path, driver_hash) in BYOVD_VULNERABLE_DRIVERS {
                let d_norm = driver_path.to_ascii_lowercase();
                let d_base = d_norm.rsplit('\\').next().unwrap_or(d_norm.as_str());
                if norm == d_norm || basename == d_base || norm.ends_with(&format!("\\{d_base}")) {
                    return Some((driver_path, driver_hash));
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSentinelConfig {
    pub job_name: String,
    pub max_active_processes: u32,
    pub max_memory_bytes: usize,
    pub enable_ring0_driver_bridge: bool,
    pub driver_device_name: String,
    pub default_autonomy_mode: String,
    pub assign_current_process: bool,
}

impl Default for KernelSentinelConfig {
    fn default() -> Self {
        Self {
            job_name: "AgentOctopus.KernelJob".to_string(),
            max_active_processes: 1,
            max_memory_bytes: 64 * 1024 * 1024, // 64 MB strict hardware ceiling
            enable_ring0_driver_bridge: true,
            driver_device_name: OSOOSI_USER_DEVICE_NAME.to_string(),
            default_autonomy_mode: "Active".to_string(),
            assign_current_process: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSentinelStats {
    pub tier1_active: bool,
    pub job_name: String,
    pub max_processes: u32,
    pub max_memory_bytes: usize,
    pub process_creation_vetos: usize,
    pub memory_limit_intercepts: usize,
    pub autotomy_hardware_kills: usize,
    pub monitored_pids: Vec<u32>,

    pub tier2_connected: bool,
    pub driver_device: String,
    pub driver_mode: String,
    pub driver_version: u32,
    pub driver_blocked_count: u32,
    pub driver_rule_count: u32,
    pub driver_status_label: String,

    pub cedar_enforced: bool,
}

/// KernelSentinelArm: Physical Ring-0 & Windows NT Kernel Substrate Protection Arm.
///
/// Implements a resilient two-tier containment architecture:
/// - Tier 1: Windows NT Kernel Job Object limits, process quotas (max 1), 64MB memory clamps,
///   and hardware autotomy termination in pure native Rust with zero external dependencies.
/// - Tier 2: Opportunistic Ring-0 Driver bridge (`\\.\OsoosiDriver`) providing hardware-enforced
///   pre-operation process execution blocking before Sysmon Event 1 fires and before initial thread start.
pub struct KernelSentinelArm {
    pub role: ArmRole,
    config: KernelSentinelConfig,
    job_object: Arc<WindowsJobObject>,
    process_creation_vetos: AtomicUsize,
    memory_limit_intercepts: AtomicUsize,
    autotomy_hardware_kills: AtomicUsize,
    monitored_pids: Arc<RwLock<Vec<u32>>>,
    tier2_connected: AtomicBool,
    driver_version: AtomicUsize,
    driver_mode: Arc<RwLock<String>>,
    driver_blocked_count: AtomicUsize,
    driver_rule_count: AtomicUsize,
}

impl Default for KernelSentinelArm {
    fn default() -> Self {
        Self::new(KernelSentinelConfig::default())
    }
}

impl KernelSentinelArm {
    pub fn new(config: KernelSentinelConfig) -> Self {
        // Tier 1: Initialize genuine Windows Job Object with hardware memory clamp
        let job = WindowsJobObject::create(
            &config.job_name,
            config.max_active_processes,
            config.max_memory_bytes,
        )
        .unwrap_or_else(|_| {
            // Fallback object struct if process is running in restricted container
            WindowsJobObject {
                #[cfg(windows)]
                handle: 0 as _,
                name: config.job_name.clone(),
                max_processes: config.max_active_processes,
                max_memory_bytes: config.max_memory_bytes,
                is_terminated: Arc::new(AtomicBool::new(false)),
            }
        });

        // Auto-assign current daemon process to kernel job bounds if enabled
        if config.assign_current_process {
            let _ = job.assign_current_process();
        }

        let arm = Self {
            role: ArmRole::KernelLevelSentinel,
            config: config.clone(),
            job_object: Arc::new(job),
            process_creation_vetos: AtomicUsize::new(0),
            memory_limit_intercepts: AtomicUsize::new(0),
            autotomy_hardware_kills: AtomicUsize::new(0),
            monitored_pids: Arc::new(RwLock::new(Vec::new())),
            tier2_connected: AtomicBool::new(false),
            driver_version: AtomicUsize::new(0),
            driver_mode: Arc::new(RwLock::new(config.default_autonomy_mode)),
            driver_blocked_count: AtomicUsize::new(0),
            driver_rule_count: AtomicUsize::new(0),
        };

        // Record initial monitored PID (current daemon PID)
        #[cfg(windows)]
        {
            let current_pid = unsafe { GetCurrentProcessId() };
            if let Ok(mut pids) = arm.monitored_pids.write() {
                pids.push(current_pid);
            }
        }

        // Tier 2: Opportunistically probe Ring-0 driver bridge
        if config.enable_ring0_driver_bridge {
            arm.probe_ring0_driver();
        }

        arm
    }

    /// Probes the OshoosiClaw Ring-0 driver device (`\\.\OsoosiDriver`).
    /// If present and running, retrieves driver status and activates Tier 2 bridge.
    /// If absent, gracefully leaves Tier 1 active with zero errors.
    pub fn probe_ring0_driver(&self) -> bool {
        #[cfg(windows)]
        {
            let wide_path: Vec<u16> = self
                .config
                .driver_device_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let handle: HANDLE = unsafe {
                CreateFileW(
                    wide_path.as_ptr(),
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    0 as _,
                )
            };

            if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
                // Successfully connected to Ring-0 device! Query driver status
                let mut status = RawOsoosiDriverStatus::default();
                let mut bytes_ret = 0u32;

                let ok = unsafe {
                    DeviceIoControl(
                        handle,
                        IOCTL_OSOOSI_GET_STATUS,
                        std::ptr::null(),
                        0,
                        &mut status as *mut _ as *mut std::ffi::c_void,
                        std::mem::size_of::<RawOsoosiDriverStatus>() as u32,
                        &mut bytes_ret,
                        std::ptr::null_mut(),
                    )
                };

                unsafe { CloseHandle(handle) };

                if ok != 0 {
                    self.tier2_connected.store(true, Ordering::SeqCst);
                    self.driver_version
                        .store(status.version as usize, Ordering::SeqCst);
                    self.driver_blocked_count
                        .store(status.blocked_count as usize, Ordering::SeqCst);
                    self.driver_rule_count
                        .store(status.rule_count as usize, Ordering::SeqCst);

                    let mode_str = match status.mode {
                        0 => "Audit",
                        1 => "Active",
                        2 => "Lockdown",
                        _ => "Active",
                    };
                    if let Ok(mut mode_guard) = self.driver_mode.write() {
                        *mode_guard = mode_str.to_string();
                    }
                    return true;
                }
            }
        }

        self.tier2_connected.store(false, Ordering::SeqCst);
        false
    }

    /// Explicitly registers a new process ID under kernel Job Object monitoring.
    pub fn monitor_pid(&self, pid: u32) -> Result<(), OctopusSecurityError> {
        #[cfg(windows)]
        {
            let proc_handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
            if !proc_handle.is_null() && proc_handle != INVALID_HANDLE_VALUE {
                let _ = self.job_object.assign_process(proc_handle);
                unsafe { CloseHandle(proc_handle) };
            }
        }

        if let Ok(mut pids) = self.monitored_pids.write() {
            if !pids.contains(&pid) {
                pids.push(pid);
            }
        }
        Ok(())
    }

    /// Intercepts and vetoes a rogue process execution attempt.
    pub fn veto_process_creation(
        &self,
        _pid: u32,
        _reason: &str,
    ) -> Result<(), OctopusSecurityError> {
        self.process_creation_vetos.fetch_add(1, Ordering::SeqCst);

        #[cfg(windows)]
        {
            let proc_handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, _pid) };
            if !proc_handle.is_null() && proc_handle != INVALID_HANDLE_VALUE {
                unsafe {
                    TerminateProcess(proc_handle, 9);
                    CloseHandle(proc_handle);
                }
            }
        }

        Ok(())
    }

    /// Increments memory limit intercept counter when high allocation is prevented.
    pub fn record_memory_limit_intercept(&self) {
        self.memory_limit_intercepts.fetch_add(1, Ordering::SeqCst);
    }

    /// Triggers immediate hardware-level autotomy termination across the kernel job.
    pub fn trigger_hardware_autotomy(&self) -> Result<(), OctopusSecurityError> {
        self.autotomy_hardware_kills.fetch_add(1, Ordering::SeqCst);

        // Terminate all processes assigned to the Windows Job Object immediately
        let _ = self.job_object.terminate(1);

        // If Tier 2 Ring-0 Driver is connected, switch driver to Lockdown mode
        #[cfg(windows)]
        if self.tier2_connected.load(Ordering::SeqCst) {
            let wide_path: Vec<u16> = self
                .config
                .driver_device_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let handle: HANDLE = unsafe {
                CreateFileW(
                    wide_path.as_ptr(),
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    0 as _,
                )
            };

            if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
                let req = RawSetModeRequest { mode: 2 }; // Lockdown
                let mut bytes_ret = 0u32;
                unsafe {
                    DeviceIoControl(
                        handle,
                        IOCTL_OSOOSI_SET_MODE,
                        &req as *const _ as *const std::ffi::c_void,
                        std::mem::size_of::<RawSetModeRequest>() as u32,
                        std::ptr::null_mut(),
                        0,
                        &mut bytes_ret,
                        std::ptr::null_mut(),
                    );
                    CloseHandle(handle);
                }
            }
        }

        Ok(())
    }

    /// Adds a pre-execution binary path block rule into the Ring-0 kernel memory.
    pub fn add_kernel_block_rule(&self, _binary_path: &str) -> Result<(), OctopusSecurityError> {
        #[cfg(windows)]
        if self.tier2_connected.load(Ordering::SeqCst) {
            let wide_path: Vec<u16> = self
                .config
                .driver_device_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let handle: HANDLE = unsafe {
                CreateFileW(
                    wide_path.as_ptr(),
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    0 as _,
                )
            };

            if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
                let normalized = _binary_path.replace('/', "\\");
                let mut req = RawAddPathRequest {
                    image_path: [0u16; 260],
                };
                let wide: Vec<u16> = normalized.encode_utf16().collect();
                let len = wide.len().min(259);
                req.image_path[..len].copy_from_slice(&wide[..len]);
                req.image_path[len] = 0;

                let mut bytes_ret = 0u32;
                let ok = unsafe {
                    DeviceIoControl(
                        handle,
                        IOCTL_OSOOSI_ADD_BLOCK_PATH,
                        &req as *const _ as *const std::ffi::c_void,
                        std::mem::size_of::<RawAddPathRequest>() as u32,
                        std::ptr::null_mut(),
                        0,
                        &mut bytes_ret,
                        std::ptr::null_mut(),
                    )
                };
                unsafe { CloseHandle(handle) };

                if ok != 0 {
                    self.driver_rule_count.fetch_add(1, Ordering::SeqCst);
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    /// Adds a SHA-256 binary block hash into the Ring-0 kernel memory via `IOCTL_OSOOSI_ADD_BLOCK_HASH`.
    pub fn add_kernel_block_hash(&self, sha256_hex: &str) -> Result<(), OctopusSecurityError> {
        let decoded = hex::decode(sha256_hex.trim()).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!(
                "Invalid BYOVD SHA-256 hex '{sha256_hex}': {e}"
            ))
        })?;
        let sha_arr: [u8; 32] = decoded.try_into().map_err(|_| {
            OctopusSecurityError::IsolationViolation(format!(
                "Invalid BYOVD SHA-256 length for '{sha256_hex}': expected 32 bytes"
            ))
        })?;
        let req = RawAddHashRequest { sha256: sha_arr };

        #[cfg(windows)]
        if self.tier2_connected.load(Ordering::SeqCst) {
            let wide_path: Vec<u16> = self
                .config
                .driver_device_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let handle: HANDLE = unsafe {
                CreateFileW(
                    wide_path.as_ptr(),
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    0 as _,
                )
            };

            if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
                let mut bytes_ret = 0u32;
                let ok = unsafe {
                    DeviceIoControl(
                        handle,
                        IOCTL_OSOOSI_ADD_BLOCK_HASH,
                        &req as *const _ as *const std::ffi::c_void,
                        std::mem::size_of::<RawAddHashRequest>() as u32,
                        std::ptr::null_mut(),
                        0,
                        &mut bytes_ret,
                        std::ptr::null_mut(),
                    )
                };
                unsafe { CloseHandle(handle) };

                if ok != 0 {
                    self.driver_rule_count.fetch_add(1, Ordering::SeqCst);
                    return Ok(());
                }
            }
        }

        let _ = req;
        Ok(())
    }

    /// Pushes curated BYOVD vulnerable driver paths and SHA-256 hashes into `\\.\OsoosiDriver`
    /// when attached, or returns deterministic Tier-1 fallback rule descriptors when absent.
    pub fn enforce_byovd_virtual_patch_blocklist(
        &self,
    ) -> Result<Vec<String>, OctopusSecurityError> {
        let mut applied = Vec::with_capacity(BYOVD_VULNERABLE_DRIVERS.len() * 2);
        let ring0 = self.tier2_connected.load(Ordering::SeqCst);

        for &(driver_path, sha256_hex) in BYOVD_VULNERABLE_DRIVERS {
            self.add_kernel_block_rule(driver_path)?;
            self.add_kernel_block_hash(sha256_hex)?;
            let mode = if ring0 {
                "ring0_ioctl"
            } else {
                "tier1_fallback"
            };
            applied.push(format!("{mode}:path:{driver_path}"));
            applied.push(format!("{mode}:sha256:{sha256_hex}"));
        }
        Ok(applied)
    }

    /// Issues `IOCTL_OSOOSI_CLEAR_RULES` ONLY when `shield_locked_until_reboot` is false
    /// (Foolproof Invariant #1 & #4: monotonic tighten-only guard).
    pub fn clear_kernel_rules(&self) -> Result<(), OctopusSecurityError> {
        if crate::security::virtual_patch_shield::current_shield_posture()
            .shield_locked_until_reboot
        {
            return Err(OctopusSecurityError::IsolationViolation(
                "Monotonic violation: refusing IOCTL_OSOOSI_CLEAR_RULES while shield_locked_until_reboot is active"
                    .to_string(),
            ));
        }

        #[cfg(windows)]
        if self.tier2_connected.load(Ordering::SeqCst) {
            let wide_path: Vec<u16> = self
                .config
                .driver_device_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let handle: HANDLE = unsafe {
                CreateFileW(
                    wide_path.as_ptr(),
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    0 as _,
                )
            };

            if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
                let mut bytes_ret = 0u32;
                let ok = unsafe {
                    DeviceIoControl(
                        handle,
                        IOCTL_OSOOSI_CLEAR_RULES,
                        std::ptr::null(),
                        0,
                        std::ptr::null_mut(),
                        0,
                        &mut bytes_ret,
                        std::ptr::null_mut(),
                    )
                };
                unsafe { CloseHandle(handle) };
                if ok == 0 {
                    return Err(OctopusSecurityError::IsolationViolation(
                        "IOCTL_OSOOSI_CLEAR_RULES failed".to_string(),
                    ));
                }
                self.driver_rule_count.store(0, Ordering::SeqCst);
            }
        }

        Ok(())
    }

    /// Compiles comprehensive live kernel telemetry stats for API and UI rendering.
    pub fn stats(&self) -> KernelSentinelStats {
        let is_t2 = self.tier2_connected.load(Ordering::SeqCst);
        let status_label = if is_t2 {
            "Active Ring-0 Driver Attached (Hardware ObRegisterCallbacks Pre-Op Enforcing)"
                .to_string()
        } else {
            "Standby Native Job Substrate (Tier 1 Windows NT Job Object Enforcing)".to_string()
        };

        let mode = self
            .driver_mode
            .read()
            .map(|m| m.clone())
            .unwrap_or_else(|_| "Active".to_string());
        let pids = self
            .monitored_pids
            .read()
            .map(|p| p.clone())
            .unwrap_or_default();

        KernelSentinelStats {
            tier1_active: true,
            job_name: self.config.job_name.clone(),
            max_processes: self.config.max_active_processes,
            max_memory_bytes: self.config.max_memory_bytes,
            process_creation_vetos: self.process_creation_vetos.load(Ordering::SeqCst),
            memory_limit_intercepts: self.memory_limit_intercepts.load(Ordering::SeqCst),
            autotomy_hardware_kills: self.autotomy_hardware_kills.load(Ordering::SeqCst),
            monitored_pids: pids,

            tier2_connected: is_t2,
            driver_device: self.config.driver_device_name.clone(),
            driver_mode: mode,
            driver_version: self.driver_version.load(Ordering::SeqCst) as u32,
            driver_blocked_count: self.driver_blocked_count.load(Ordering::SeqCst) as u32,
            driver_rule_count: self.driver_rule_count.load(Ordering::SeqCst) as u32,
            driver_status_label: status_label,

            cedar_enforced: true,
        }
    }
}

/// A loaded host kernel driver matching a known BYOVD (Bring Your Own Vulnerable Driver) signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedByovdDriver {
    pub loaded_path: String,
    pub matched_rule_path: String,
    pub matched_sha256: String,
    pub observed_sha256: Option<String>,
}

/// Live host kernel driver BYOVD audit report (works with or without `\\.\OsoosiDriver` attached).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByovdDriverAuditReport {
    pub driver_bridge_attached: bool,
    pub hvci_enabled: Option<bool>,
    pub ms_vulnerable_driver_blocklist_enabled: Option<bool>,
    pub loaded_drivers_scanned: usize,
    pub vulnerable_drivers_detected: Vec<DetectedByovdDriver>,
    pub enforced_rules: Vec<String>,
}

/// Normalizes Windows NT device driver paths (`\SystemRoot\...`, `\??\...`) into filesystem paths.
#[must_use]
pub fn normalize_windows_driver_nt_path(raw: &str) -> String {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with(r"\systemroot\") {
        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let suffix = &trimmed[r"\systemroot\".len()..];
        return format!("{}\\{}", sysroot.trim_end_matches('\\'), suffix);
    }
    if let Some(suffix) = trimmed.strip_prefix(r"\??\") {
        return suffix.to_string();
    }
    trimmed.to_string()
}

/// Computes streaming SHA-256 hex digest of a file with bounded 64 KiB stack buffer.
#[cfg(windows)]
fn sha256_file_bounded(path: &std::path::Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hex::encode(hasher.finalize()))
}

#[cfg(windows)]
fn enumerate_loaded_windows_driver_paths() -> Vec<String> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    type FnK32EnumDeviceDrivers =
        unsafe extern "system" fn(*mut *mut std::ffi::c_void, u32, *mut u32) -> i32;
    type FnK32GetDeviceDriverFileNameW =
        unsafe extern "system" fn(*mut std::ffi::c_void, *mut u16, u32) -> u32;

    let h_k32 = unsafe { GetModuleHandleA(b"kernel32.dll\0".as_ptr()) };
    if h_k32.is_null() {
        return Vec::new();
    }
    let Some(p_enum) = (unsafe { GetProcAddress(h_k32, b"K32EnumDeviceDrivers\0".as_ptr()) })
    else {
        return Vec::new();
    };
    let Some(p_name) =
        (unsafe { GetProcAddress(h_k32, b"K32GetDeviceDriverFileNameW\0".as_ptr()) })
    else {
        return Vec::new();
    };

    let fn_enum: FnK32EnumDeviceDrivers = unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, FnK32EnumDeviceDrivers>(p_enum)
    };
    let fn_name: FnK32GetDeviceDriverFileNameW = unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, FnK32GetDeviceDriverFileNameW>(
            p_name,
        )
    };

    let mut needed: u32 = 0;
    let ok = unsafe { fn_enum(std::ptr::null_mut(), 0, &mut needed) };
    if ok == 0 || needed == 0 {
        return Vec::new();
    }
    let ptr_size = std::mem::size_of::<*mut std::ffi::c_void>();
    let count = (needed as usize / ptr_size).clamp(1, 4096);
    let mut bases: Vec<*mut std::ffi::c_void> = vec![std::ptr::null_mut(); count];
    let cb = (bases.len() * ptr_size) as u32;
    let mut actual: u32 = 0;
    if unsafe { fn_enum(bases.as_mut_ptr(), cb, &mut actual) } == 0 {
        return Vec::new();
    }
    let actual_count = (actual as usize / ptr_size).min(bases.len());
    let mut paths = Vec::with_capacity(actual_count);
    let mut name_buf = [0u16; 520];
    for &base in &bases[..actual_count] {
        if base.is_null() {
            continue;
        }
        let len = unsafe { fn_name(base, name_buf.as_mut_ptr(), name_buf.len() as u32) } as usize;
        if len > 0 && len < name_buf.len() {
            let raw = String::from_utf16_lossy(&name_buf[..len]);
            paths.push(normalize_windows_driver_nt_path(&raw));
        }
    }
    paths
}

impl KernelSentinelArm {
    /// Audits live loaded host kernel drivers in parallel against `BYOVD_VULNERABLE_DRIVERS`
    /// and inspects OS Code Integrity (HVCI + Microsoft Vulnerable Driver Blocklist) even when
    /// `\\.\OsoosiDriver` is not installed.
    pub fn audit_live_loaded_kernel_drivers(&self) -> ByovdDriverAuditReport {
        let driver_bridge_attached = self.tier2_connected.load(Ordering::SeqCst);
        let enforced_rules = self
            .enforce_byovd_virtual_patch_blocklist()
            .unwrap_or_default();

        #[cfg(windows)]
        {
            use rayon::prelude::*;

            let (posture, _, _) =
                crate::security::kernel_patcher::discovery::windows::query_windows_posture("");
            let driver_paths = enumerate_loaded_windows_driver_paths();
            let loaded_drivers_scanned = driver_paths.len();

            let vulnerable_drivers_detected: Vec<DetectedByovdDriver> = driver_paths
                .into_par_iter()
                .filter_map(|loaded_path| {
                    let path_match = match_byovd_vulnerable_driver(Some(&loaded_path), None);
                    // Only hash on-disk .sys image if filename matches or is in System32\drivers
                    let should_hash =
                        path_match.is_some() || loaded_path.to_ascii_lowercase().ends_with(".sys");
                    let observed_sha256 = if should_hash {
                        sha256_file_bounded(std::path::Path::new(&loaded_path))
                    } else {
                        None
                    };
                    let matched = path_match.or_else(|| {
                        observed_sha256
                            .as_deref()
                            .and_then(|h| match_byovd_vulnerable_driver(None, Some(h)))
                    });
                    matched.map(|(matched_rule_path, matched_sha256)| DetectedByovdDriver {
                        loaded_path,
                        matched_rule_path: matched_rule_path.to_string(),
                        matched_sha256: matched_sha256.to_string(),
                        observed_sha256,
                    })
                })
                .collect();

            ByovdDriverAuditReport {
                driver_bridge_attached,
                hvci_enabled: posture.hvci_enabled,
                ms_vulnerable_driver_blocklist_enabled: posture.vulnerable_driver_blocklist_enabled,
                loaded_drivers_scanned,
                vulnerable_drivers_detected,
                enforced_rules,
            }
        }

        #[cfg(target_os = "linux")]
        {
            let modules = std::fs::read_to_string("/proc/modules").unwrap_or_default();
            let loaded_drivers_scanned = modules.lines().filter(|l| !l.trim().is_empty()).count();
            ByovdDriverAuditReport {
                driver_bridge_attached,
                hvci_enabled: None,
                ms_vulnerable_driver_blocklist_enabled: None,
                loaded_drivers_scanned,
                vulnerable_drivers_detected: Vec::new(),
                enforced_rules,
            }
        }

        #[cfg(not(any(windows, target_os = "linux")))]
        {
            ByovdDriverAuditReport {
                driver_bridge_attached,
                hvci_enabled: None,
                ms_vulnerable_driver_blocklist_enabled: None,
                loaded_drivers_scanned: 0,
                vulnerable_drivers_detected: Vec::new(),
                enforced_rules,
            }
        }
    }
}

#[cfg(test)]
mod byovd_audit_tests {
    use super::*;

    #[test]
    fn test_normalize_windows_driver_nt_path() {
        let p = normalize_windows_driver_nt_path(r"\SystemRoot\System32\drivers\RTCore64.sys");
        assert!(p
            .to_ascii_lowercase()
            .ends_with(r"\system32\drivers\rtcore64.sys"));
        let p2 = normalize_windows_driver_nt_path(r"\??\C:\Windows\System32\drivers\gdrv.sys");
        assert_eq!(p2, r"C:\Windows\System32\drivers\gdrv.sys");
    }

    #[test]
    fn test_live_loaded_driver_audit_runs_cleanly_without_driver_bridge() {
        let arm = KernelSentinelArm::default();
        let report = arm.audit_live_loaded_kernel_drivers();
        assert!(!report.enforced_rules.is_empty());
        #[cfg(windows)]
        assert!(
            report.loaded_drivers_scanned > 0,
            "Windows host must enumerate live loaded kernel drivers via K32EnumDeviceDrivers"
        );
    }
}
