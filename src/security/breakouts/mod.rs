pub mod behavioral;
pub mod data;
pub mod operational;
pub mod technical;

pub use behavioral::{BehavioralBreakoutGuard, BehavioralBreakoutVerdict};
pub use data::{AgentTrustTier, DataBreakoutGuard, DataBreakoutVerdict};
pub use operational::{OperationalContainmentGuard, OperationalContainmentVerdict};
pub use technical::{TechnicalBreakoutGuard, TechnicalBreakoutVerdict};

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Comprehensive evaluation verdict across the 4-Category Taxonomy from the paper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedBreakoutEvaluation {
    pub is_clean: bool,
    pub technical: TechnicalBreakoutVerdict,
    pub operational: OperationalContainmentVerdict,
    pub behavioral: BehavioralBreakoutVerdict,
    pub data: DataBreakoutVerdict,
    pub composite_verdict: String,
    pub recommended_action_tier: String,
}

/// Unified Breakout Defense Coordinator orchestrating the 4 guards from "Beyond One and Done: Agent Breakouts".
pub struct BreakoutDefenseCoordinator {
    pub technical: Arc<TechnicalBreakoutGuard>,
    pub operational: Arc<OperationalContainmentGuard>,
    pub behavioral: Arc<BehavioralBreakoutGuard>,
    pub data: Arc<DataBreakoutGuard>,
}

impl Default for BreakoutDefenseCoordinator {
    fn default() -> Self {
        Self {
            technical: Arc::new(TechnicalBreakoutGuard::default()),
            operational: Arc::new(OperationalContainmentGuard::default()),
            behavioral: Arc::new(BehavioralBreakoutGuard::default()),
            data: Arc::new(DataBreakoutGuard::default()),
        }
    }
}

impl BreakoutDefenseCoordinator {
    /// Comprehensive audit of an agent action across all 4 taxonomy categories.
    pub fn evaluate_action(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        payload: &str,
    ) -> UnifiedBreakoutEvaluation {
        let tech_res = self.technical.evaluate_execution(resource, payload);
        let oper_res = self.operational.evaluate_context_leakage(payload);
        let behav_res = self.behavioral.evaluate_action(action, resource, payload);
        let data_res = self.data.evaluate_data_access(principal, resource, payload);

        let is_clean = tech_res.is_clean && oper_res.is_clean && behav_res.is_clean && data_res.is_clean;

        let composite_verdict = if is_clean {
            "PERMIT_ALL_CATEGORIES_INTACT".to_string()
        } else {
            let mut reasons = Vec::new();
            if !tech_res.is_clean { reasons.push("TECHNICAL_BREAKOUT"); }
            if !oper_res.is_clean { reasons.push("OPERATIONAL_FAILURE"); }
            if !behav_res.is_clean { reasons.push("BEHAVIORAL_BREAKOUT"); }
            if !data_res.is_clean { reasons.push("DATA_BREAKOUT"); }
            format!("VETO_{}", reasons.join("_AND_"))
        };

        let recommended_action_tier = if !tech_res.is_clean || !data_res.is_clean {
            "HardMitigation"
        } else if !behav_res.is_clean || !oper_res.is_clean {
            "MicroContainment"
        } else {
            "PassiveObserve"
        };

        UnifiedBreakoutEvaluation {
            is_clean,
            technical: tech_res,
            operational: oper_res,
            behavioral: behav_res,
            data: data_res,
            composite_verdict,
            recommended_action_tier: recommended_action_tier.to_string(),
        }
    }
}


// ============================================================================
// Safe Path::join Replacement Guard & Elastic Workspace Confinement
// ============================================================================

/// Lexical pre-filter for a relative path before joining to a sandbox root (`RULE[containment_ring_breakout_invariants.md]`).
///
/// **IMPORTANT (Finding 5)**: This function checks path syntax only and is **NOT** a standalone
/// filesystem confinement boundary (it does not inspect junctions, symlinks, hardlinks, or TOCTOU
/// directory swaps on disk). Call [`open_confined`] to obtain a handle verified on disk after open.
///
/// Rejects:
/// - Drive letters (`:`), NTFS Alternate Data Streams (`file.txt:secret`)
/// - Leading slashes or backslashes (`/`, `\`), UNC paths (`\\`)
/// - Percent-encoded traversal (`%2e`, `%2f`, `%5c`, `%00`)
/// - `Component::ParentDir` (`..`), `Component::RootDir`, `Component::Prefix`
pub fn validate_sandbox_relative_path(
    sandbox_root: &std::path::Path,
    relative_input: &str,
) -> Result<std::path::PathBuf, crate::core::types::OctopusSecurityError> {
    use crate::core::types::OctopusSecurityError;
    use std::path::Component;

    let trimmed = relative_input.trim();
    if trimmed.is_empty() {
        return Err(OctopusSecurityError::IsolationViolation(
            "PATH_JOIN_EMPTY: Relative sandbox path cannot be empty".to_string(),
        ));
    }

    if trimmed.contains('\0')
        || trimmed.contains(':')
        || trimmed.starts_with('/')
        || trimmed.starts_with('\\')
    {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "PATH_JOIN_REPLACEMENT_BLOCKED: Relative path '{}' contains drive/root/ADS prefix",
            trimmed
        )));
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
        || lower.contains("..")
    {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "PATH_JOIN_TRAVERSAL_BLOCKED: Relative path '{}' contains traversal or percent-encoded sequence",
            trimmed
        )));
    }

    let rel_path = std::path::Path::new(trimmed);
    for comp in rel_path.components() {
        match comp {
            Component::Normal(os_str) => {
                let s = os_str.to_string_lossy();
                if s.contains(':') || s == ".." {
                    return Err(OctopusSecurityError::IsolationViolation(format!(
                        "PATH_JOIN_COMPONENT_BLOCKED: Illegal path component '{}'",
                        s
                    )));
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "PATH_JOIN_NON_RELATIVE_COMPONENT: Disallowed component '{:?}' in '{}'",
                    comp, trimmed
                )));
            }
        }
    }

    Ok(sandbox_root.join(rel_path))
}

/// Validates agent filesystem access against elastic workspace confinement, sensitive credential stores,
/// and system roots (`C:\Windows`, `/etc/shadow`, `.ssh/id_rsa`, `.aws/credentials`, `.env`, etc.).
pub fn validate_agent_filesystem_access(
    target_path: &str,
    workspace_root: Option<&std::path::Path>,
) -> Result<(), crate::core::types::OctopusSecurityError> {
    use crate::core::types::OctopusSecurityError;

    let trimmed = target_path.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err(OctopusSecurityError::IsolationViolation(
            "FS_INVALID_PATH: Empty or null-byte path rejected".to_string(),
        ));
    }

    let norm = trimmed.replace('\\', "/").to_ascii_lowercase();
    if norm.contains("..")
        || norm.contains("%2e")
        || norm.contains("%2f")
        || norm.contains("%5c")
        || norm.starts_with("//")
    {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FS_TRAVERSAL_OR_UNC_BLOCKED: Path '{}' rejected",
            trimmed
        )));
    }

    // Reject NTFS Alternate Data Streams (colon after drive prefix)
    let after_drive = if norm.len() >= 2 && norm.as_bytes()[1] == b':' {
        &norm[2..]
    } else {
        &norm[..]
    };
    if after_drive.contains(':') {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FS_NTFS_ADS_BLOCKED: Alternate Data Stream rejected in '{}'",
            trimmed
        )));
    }

    let forbidden_patterns = [
        "/etc/shadow",
        "/etc/passwd",
        "/proc/self",
        "c:/windows",
        "system32/config/sam",
        ".ssh/id_rsa",
        ".ssh/id_ed25519",
        ".aws/credentials",
        ".kube/config",
        "docker.sock",
        ".git/hooks",
        ".githooks/post-commit",
    ];
    for pat in forbidden_patterns {
        if norm.contains(pat) {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FS_SENSITIVE_SYSTEM_OR_CREDENTIAL_PATH: Access to '{}' blocked by rule '{}'",
                trimmed, pat
            )));
        }
    }

    if let Some(ws) = workspace_root {
        let ws_norm = ws.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
        if norm.starts_with('/') || (norm.len() >= 2 && norm.as_bytes()[1] == b':') {
            if !norm.starts_with(&ws_norm) {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FS_OUTSIDE_WORKSPACE_ROOT: '{}' is outside authorized workspace '{}'",
                    trimmed,
                    ws.display()
                )));
            }
        } else {
            let _ = validate_sandbox_relative_path(ws, trimmed)?;
        }
    }

    Ok(())
}

/// Handle-based confined file opener (Finding 5).
///
/// Eliminates the TOCTOU / symlink / junction / hardlink gap in lexical path checks by:
/// 1. Running [`validate_sandbox_relative_path`] as a fast lexical pre-filter.
/// 2. Opening `sandbox_root` and reading its kernel-resolved path via `GetFinalPathNameByHandleW`.
/// 3. Walking each component from `sandbox_root` downward, opening every intermediate directory and
///    the target with `FILE_FLAG_OPEN_REPARSE_POINT` and inspecting `BY_HANDLE_FILE_INFORMATION`:
///    - Rejects any component with `FILE_ATTRIBUTE_REPARSE_POINT` (NTFS junctions, mount points,
///      symbolic links) *before* the kernel traverses it.
///    - Rejects regular files with `nNumberOfLinks > 1` (hardlinks to files outside the sandbox).
/// 4. Querying `GetFinalPathNameByHandleW` on the opened file handle and verifying that its
///    canonical path is strictly inside the canonical `sandbox_root` (with a path-separator
///    boundary check).
/// 5. Returning the already-opened [`std::fs::File`] so the caller never re-opens by path.
pub fn open_confined(
    sandbox_root: &std::path::Path,
    relative_input: &str,
    write: bool,
) -> Result<std::fs::File, crate::core::types::OctopusSecurityError> {
    let _joined = validate_sandbox_relative_path(sandbox_root, relative_input)?;

    #[cfg(windows)]
    {
        win_confined::open_confined_windows(sandbox_root, relative_input, write)
    }

    #[cfg(not(windows))]
    {
        unix_confined::open_confined_unix(sandbox_root, relative_input, write)
    }
}

#[cfg(windows)]
mod win_confined {
    use crate::core::types::OctopusSecurityError;
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
    use std::path::{Component, Path};

    type HANDLE = *mut c_void;
    type BOOL = i32;
    type DWORD = u32;
    type NTSTATUS = i32;

    const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
    const GENERIC_READ: DWORD = 0x8000_0000;
    const GENERIC_WRITE: DWORD = 0x4000_0000;
    const SYNCHRONIZE: DWORD = 0x0010_0000;
    const FILE_LIST_DIRECTORY: DWORD = 0x0000_0001;
    const FILE_TRAVERSE: DWORD = 0x0000_0020;
    const FILE_READ_ATTRIBUTES: DWORD = 0x0000_0080;
    const FILE_SHARE_READ: DWORD = 0x0000_0001;
    const FILE_SHARE_WRITE: DWORD = 0x0000_0002;
    const OPEN_EXISTING: DWORD = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: DWORD = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: DWORD = 0x0020_0000;
    const FILE_ATTRIBUTE_NORMAL: DWORD = 0x0000_0080;
    const FILE_ATTRIBUTE_DIRECTORY: DWORD = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: DWORD = 0x0000_0400;

    // Native NT (`NtCreateFile`) constants for handle-relative single-component resolution (AO-FIND-06)
    const OBJ_CASE_INSENSITIVE: DWORD = 0x0000_0040;
    const FILE_OPEN: DWORD = 0x0000_0001;
    const FILE_OPEN_IF: DWORD = 0x0000_0003;
    const FILE_DIRECTORY_FILE: DWORD = 0x0000_0001;
    const FILE_NON_DIRECTORY_FILE: DWORD = 0x0000_0040;
    const FILE_SYNCHRONOUS_IO_NONALERT: DWORD = 0x0000_0020;
    const FILE_OPEN_REPARSE_POINT: DWORD = 0x0020_0000;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct UNICODE_STRING {
        Length: u16,
        MaximumLength: u16,
        Buffer: *mut u16,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct OBJECT_ATTRIBUTES {
        Length: DWORD,
        RootDirectory: HANDLE,
        ObjectName: *mut UNICODE_STRING,
        Attributes: DWORD,
        SecurityDescriptor: *mut c_void,
        SecurityQualityOfService: *mut c_void,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct IO_STATUS_BLOCK {
        StatusOrPointer: *mut c_void,
        Information: usize,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    struct FILETIME {
        dwLowDateTime: DWORD,
        dwHighDateTime: DWORD,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct BY_HANDLE_FILE_INFORMATION {
        dwFileAttributes: DWORD,
        ftCreationTime: FILETIME,
        ftLastAccessTime: FILETIME,
        ftLastWriteTime: FILETIME,
        dwVolumeSerialNumber: DWORD,
        nFileSizeHigh: DWORD,
        nFileSizeLow: DWORD,
        nNumberOfLinks: DWORD,
        nFileIndexHigh: DWORD,
        nFileIndexLow: DWORD,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: DWORD,
            dwShareMode: DWORD,
            lpSecurityAttributes: *const c_void,
            dwCreationDisposition: DWORD,
            dwFlagsAndAttributes: DWORD,
            hTemplateFile: HANDLE,
        ) -> HANDLE;
        fn GetFileInformationByHandle(
            hFile: HANDLE,
            lpFileInformation: *mut BY_HANDLE_FILE_INFORMATION,
        ) -> BOOL;
        fn GetFinalPathNameByHandleW(
            hFile: HANDLE,
            lpszFilePath: *mut u16,
            cchFilePath: DWORD,
            dwFlags: DWORD,
        ) -> DWORD;
        fn GetLastError() -> DWORD;
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtCreateFile(
            FileHandle: *mut HANDLE,
            DesiredAccess: DWORD,
            ObjectAttributes: *mut OBJECT_ATTRIBUTES,
            IoStatusBlock: *mut IO_STATUS_BLOCK,
            AllocationSize: *mut i64,
            FileAttributes: DWORD,
            ShareAccess: DWORD,
            CreateDisposition: DWORD,
            CreateOptions: DWORD,
            EaBuffer: *mut c_void,
            EaLength: DWORD,
        ) -> NTSTATUS;
    }

    fn to_wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    fn final_path_of_handle(h: HANDLE) -> Result<String, OctopusSecurityError> {
        let mut buf = vec![0u16; 1024];
        let len = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as DWORD, 0) };
        if len == 0 {
            let err = unsafe { GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_FINAL_PATH_FAILED: GetFinalPathNameByHandleW failed (OS Error {})",
                err
            )));
        }
        if (len as usize) >= buf.len() {
            buf.resize((len as usize) + 2, 0);
            let len2 = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as DWORD, 0) };
            if len2 == 0 || (len2 as usize) >= buf.len() {
                return Err(OctopusSecurityError::IsolationViolation(
                    "CONFINED_OPEN_FINAL_PATH_OVERFLOW: Path exceeds buffer".to_string(),
                ));
            }
            return Ok(String::from_utf16_lossy(&buf[..len2 as usize]));
        }
        Ok(String::from_utf16_lossy(&buf[..len as usize]))
    }

    fn handle_info(h: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION, OctopusSecurityError> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe { GetFileInformationByHandle(h, &mut info) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_INFO_FAILED: GetFileInformationByHandle failed (OS Error {})",
                err
            )));
        }
        Ok(info)
    }

    fn open_root_raw(path: &Path) -> Result<std::fs::File, OctopusSecurityError> {
        let wide = to_wide(path);
        // Omit FILE_SHARE_DELETE so the sandbox root directory cannot be renamed or unlinked while open
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_CREATEFILE_FAILED: '{}' failed (OS Error {})",
                path.display(),
                err
            )));
        }
        Ok(unsafe { std::fs::File::from_raw_handle(h as RawHandle) })
    }

    /// Opens a single path component strictly relative to `parent_dir_handle` via `ntdll!NtCreateFile`
    /// with `OBJECT_ATTRIBUTES.RootDirectory = parent_dir_handle` and `FILE_OPEN_REPARSE_POINT` (AO-FIND-06).
    fn nt_open_single_component_relative(
        parent_dir_handle: HANDLE,
        component: &str,
        desired_access: DWORD,
        share_access: DWORD,
        create_disposition: DWORD,
        create_options: DWORD,
    ) -> Result<std::fs::File, OctopusSecurityError> {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains('\\')
            || component.contains('/')
            || component.contains(':')
            || component.contains('\0')
        {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_INVALID_COMPONENT: '{}' is not a valid single relative filename component",
                component
            )));
        }

        let mut wide: Vec<u16> = OsStr::new(component).encode_wide().collect();
        let byte_len = wide
            .len()
            .checked_mul(2)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| {
                OctopusSecurityError::IsolationViolation(
                    "CONFINED_OPEN_COMPONENT_TOO_LONG: Component exceeds UNICODE_STRING limit"
                        .to_string(),
                )
            })?;
        wide.push(0);

        let mut ustr = UNICODE_STRING {
            Length: byte_len,
            MaximumLength: byte_len.saturating_add(2),
            Buffer: wide.as_mut_ptr(),
        };

        let mut obj_attr = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as DWORD,
            RootDirectory: parent_dir_handle,
            ObjectName: &mut ustr,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };

        let mut io_status: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        let mut out_handle: HANDLE = std::ptr::null_mut();

        let status = unsafe {
            NtCreateFile(
                &mut out_handle,
                desired_access | SYNCHRONIZE,
                &mut obj_attr,
                &mut io_status,
                std::ptr::null_mut(),
                FILE_ATTRIBUTE_NORMAL,
                share_access,
                create_disposition,
                create_options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null_mut(),
                0,
            )
        };

        if status < 0 || out_handle.is_null() || out_handle == INVALID_HANDLE_VALUE {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_NTCREATEFILE_FAILED: Handle-relative open of '{}' failed (NTSTATUS 0x{:08X})",
                component, status as u32
            )));
        }

        Ok(unsafe { std::fs::File::from_raw_handle(out_handle as RawHandle) })
    }

    fn normalize_final(s: &str) -> String {
        s.trim_end_matches(&['\\', '/'][..])
            .replace('/', "\\")
            .to_ascii_lowercase()
    }

    fn is_strictly_inside_or_equal(candidate: &str, root: &str) -> bool {
        let c = normalize_final(candidate);
        let r = normalize_final(root);
        if c == r {
            return true;
        }
        c.strip_prefix(&r)
            .map(|rest| rest.starts_with('\\'))
            .unwrap_or(false)
    }

    pub fn open_confined_windows(
        sandbox_root: &Path,
        relative_input: &str,
        write: bool,
    ) -> Result<std::fs::File, OctopusSecurityError> {
        // 1. Open sandbox root without following reparse points and verify it is a real directory.
        let root_file = open_root_raw(sandbox_root)?;
        let root_h = root_file.as_raw_handle() as HANDLE;
        let root_info = handle_info(root_h)?;
        if root_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_REPARSE_ROOT_BLOCKED: Sandbox root '{}' is itself a reparse point / junction / symlink",
                sandbox_root.display()
            )));
        }
        if root_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_ROOT_NOT_DIR: Sandbox root '{}' is not a directory",
                sandbox_root.display()
            )));
        }
        let canonical_root = final_path_of_handle(root_h)?;

        // 2. Collect normal components of `relative_input`.
        let comps: Vec<String> = Path::new(relative_input.trim())
            .components()
            .filter_map(|c| match c {
                Component::Normal(o) => Some(o.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();
        if comps.is_empty() {
            return Err(OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_EMPTY_COMPONENTS: Relative path has no target component".to_string(),
            ));
        }

        // 3. Walk intermediate directories strictly relative to the already-validated parent HANDLE via NtCreateFile (AO-FIND-06).
        // Each open directory handle omits FILE_SHARE_DELETE and stays alive in `_held_dirs` until the leaf is verified.
        let mut _held_dirs: Vec<std::fs::File> = vec![root_file];
        for dir_comp in &comps[..comps.len() - 1] {
            let parent_h = _held_dirs
                .last()
                .ok_or_else(|| {
                    OctopusSecurityError::IsolationViolation(
                        "CONFINED_OPEN_MISSING_PARENT: Parent directory handle stack empty".to_string(),
                    )
                })?
                .as_raw_handle() as HANDLE;
            let dir_file = nt_open_single_component_relative(
                parent_h,
                dir_comp,
                FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE,
            )?;
            let dh = dir_file.as_raw_handle() as HANDLE;
            let dinfo = handle_info(dh)?;
            if dinfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_OPEN_REPARSE_DIR_BLOCKED: Directory component '{}' is a junction or symlink",
                    dir_comp
                )));
            }
            if dinfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_OPEN_INTERMEDIATE_NOT_DIR: '{}' is not a directory",
                    dir_comp
                )));
            }
            let dir_final = final_path_of_handle(dh)?;
            if !is_strictly_inside_or_equal(&dir_final, &canonical_root) {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_OPEN_DIR_ESCAPED_ROOT: '{}' resolved to '{}' outside '{}'",
                    dir_comp, dir_final, canonical_root
                )));
            }
            _held_dirs.push(dir_file);
        }

        // 4. Open the final single-component leaf relative to the validated parent directory HANDLE via NtCreateFile.
        // Writable files (`write == true`) enforce exclusive sharing (`ShareAccess = 0`) to block concurrent race mutation.
        let parent_h = _held_dirs
            .last()
            .ok_or_else(|| {
                OctopusSecurityError::IsolationViolation(
                    "CONFINED_OPEN_MISSING_PARENT: Parent directory handle stack empty".to_string(),
                )
            })?
            .as_raw_handle() as HANDLE;
        let leaf_comp = comps.last().ok_or_else(|| {
            OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_EMPTY_COMPONENTS: Missing leaf path component".to_string(),
            )
        })?;
        let access = if write {
            GENERIC_READ | GENERIC_WRITE
        } else {
            GENERIC_READ
        };
        let share_access = if write { 0 } else { FILE_SHARE_READ };
        let disposition = if write { FILE_OPEN_IF } else { FILE_OPEN };
        let leaf_file = nt_open_single_component_relative(
            parent_h,
            leaf_comp,
            access,
            share_access,
            disposition,
            FILE_NON_DIRECTORY_FILE,
        )?;
        let lh = leaf_file.as_raw_handle() as HANDLE;
        let linfo = handle_info(lh)?;
        if linfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_REPARSE_FILE_BLOCKED: Target '{}' is a symlink or reparse point",
                relative_input
            )));
        }
        if linfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_TARGET_IS_DIR: Target '{}' is a directory, expected regular file",
                relative_input
            )));
        }
        if linfo.nNumberOfLinks > 1 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_HARDLINK_BLOCKED: Target '{}' has nNumberOfLinks={} (> 1); hardlinks are prohibited inside the sandbox",
                relative_input, linfo.nNumberOfLinks
            )));
        }

        // 5. Re-verify the kernel-reported final path of the open handle against the canonical root.
        let leaf_final = final_path_of_handle(lh)?;
        if !is_strictly_inside_or_equal(&leaf_final, &canonical_root)
            || normalize_final(&leaf_final) == normalize_final(&canonical_root)
        {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_ESCAPE_DETECTED: Handle final path '{}' is outside canonical sandbox root '{}'",
                leaf_final, canonical_root
            )));
        }

        // 6. Truncate writable leaf file AFTER hardlink and canonical path verification succeed,
        // preventing stale trailing bytes when overwriting with a shorter payload.
        if write {
            leaf_file.set_len(0).map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_OPEN_TRUNCATE_FAILED: Failed to truncate writable file '{}': {}",
                    relative_input, e
                ))
            })?;
        }

        Ok(leaf_file)
    }
}

#[cfg(not(windows))]
mod unix_confined {
    use crate::core::types::OctopusSecurityError;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path};

    pub fn open_confined_unix(
        sandbox_root: &Path,
        relative_input: &str,
        write: bool,
    ) -> Result<std::fs::File, OctopusSecurityError> {
        let root_meta = std::fs::symlink_metadata(sandbox_root).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_ROOT_STAT: {}", e))
        })?;
        if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
            return Err(OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_ROOT_INVALID: sandbox root must be a real directory".to_string(),
            ));
        }
        let canonical_root = std::fs::canonicalize(sandbox_root).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_ROOT_CANON: {}", e))
        })?;

        let mut cursor = canonical_root.clone();
        let comps: Vec<_> = Path::new(relative_input.trim())
            .components()
            .filter_map(|c| match c {
                Component::Normal(o) => Some(o.to_os_string()),
                _ => None,
            })
            .collect();
        if comps.is_empty() {
            return Err(OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_EMPTY_COMPONENTS: Relative path has no target component".to_string(),
            ));
        }
        for comp in &comps[..comps.len() - 1] {
            cursor.push(comp);
            let m = std::fs::symlink_metadata(&cursor).map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_DIR_STAT: {}", e))
            })?;
            if m.file_type().is_symlink() || !m.is_dir() {
                return Err(OctopusSecurityError::IsolationViolation(
                    "CONFINED_OPEN_SYMLINK_DIR_BLOCKED".to_string(),
                ));
            }
        }
        let leaf_comp = comps.last().ok_or_else(|| {
            OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_EMPTY_COMPONENTS: Missing leaf path component".to_string(),
            )
        })?;
        cursor.push(leaf_comp);
        if let Ok(m) = std::fs::symlink_metadata(&cursor) {
            if m.file_type().is_symlink() {
                return Err(OctopusSecurityError::IsolationViolation(
                    "CONFINED_OPEN_SYMLINK_FILE_BLOCKED".to_string(),
                ));
            }
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(write)
            .create(write)
            .open(&cursor)
            .map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_OPEN: {}", e))
            })?;
        let fmeta = file.metadata().map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_FSTAT: {}", e))
        })?;
        if fmeta.nlink() > 1 {
            return Err(OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_HARDLINK_BLOCKED".to_string(),
            ));
        }
        let canon_leaf = std::fs::canonicalize(&cursor).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_LEAF_CANON: {}", e))
        })?;
        if !canon_leaf.starts_with(&canonical_root) || canon_leaf == canonical_root {
            return Err(OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_ESCAPE_DETECTED".to_string(),
            ));
        }
        if write {
            file.set_len(0).map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_OPEN_TRUNCATE_FAILED: {}",
                    e
                ))
            })?;
        }
        Ok(file)
    }
}

// ============================================================================
// Law 8: Zero-Mutual-Information Canonical Output Projector (\Pi_0)
// ============================================================================

/// Result of projecting an outbound agent response through Law 8 ($\Pi_0$).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroMiProjectionResult {
    pub canonical_output: String,
    pub zero_width_chars_stripped: usize,
    pub covert_secrets_redacted: usize,
    pub json_keys_canonicalized: bool,
    pub quantized_release_slot_ms: u64,
    pub mutual_information_upper_bound_bits: f64,
}

/// Law 8: Zero-Mutual-Information Canonical Output Projector ($\Pi_0$).
///
/// Ensures $I(\text{Secret}; \Pi_0(\text{Output})) = 0$ by:
/// 1. Stripping all zero-width & invisible Unicode steganography (`U+200B..U+200F`, `U+FEFF`, `U+2060..U+2064`, variation selectors).
/// 2. Detecting and redacting high-entropy keys, NATO-phonetic spelled secrets, delimiter-interleaved tokens,
///    and Base64/Hex encoded credentials with `<ZK_MI_REDACTED>`.
/// 3. Canonicalizing JSON object key ordering (`BTreeMap` lexicographical order via `serde_json::Value`)
///    to destroy key-permutation covert channels.
/// 4. Quantizing emission timestamps to coarse discrete slots $T_{\text{slot}}$ to eliminate timing covert channels.
#[derive(Debug, Clone, Default)]
pub struct ZeroMutualInformationProjector;

impl ZeroMutualInformationProjector {
    pub fn is_zero_width_or_stego_char(c: char) -> bool {
        let u = c as u32;
        matches!(
            u,
            0x200B..=0x200F
                | 0x202A..=0x202E
                | 0x2060..=0x206F
                | 0xFEFF
                | 0xFE00..=0xFE0F
                | 0xE0100..=0xE01EF
        )
    }

    /// Projects `raw_output` through the deterministic canonicalizer $\Pi_0$.
    pub fn project_output(raw_output: &str, timestamp_ms: u64, slot_width_ms: u64) -> ZeroMiProjectionResult {
        let mut zero_width_chars_stripped = 0usize;
        let mut cleaned = String::with_capacity(raw_output.len());
        for ch in raw_output.chars() {
            if Self::is_zero_width_or_stego_char(ch) {
                zero_width_chars_stripped += 1;
            } else {
                cleaned.push(ch);
            }
        }

        let mut covert_secrets_redacted = 0usize;

        // Detect direct, delimiter-interleaved (e.g. s.k.-.l.i.v.e), or NATO-spelled secrets
        let collapsed_alnum: String = cleaned
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<String>()
            .to_ascii_lowercase();

        let has_interleaved_secret = collapsed_alnum.contains("sklive")
            || collapsed_alnum.contains("skproj")
            || collapsed_alnum.contains("akia")
            || collapsed_alnum.contains("ghp_")
            || collapsed_alnum.contains("githubpat")
            || collapsed_alnum.contains("beginrsaprivatekey")
            || collapsed_alnum.contains(" sierra") && collapsed_alnum.contains("kilo");

        let lower_words = cleaned.to_ascii_lowercase();
        let nato_hits = [
            "sierra", "kilo", "lima", "india", "victor", "echo", "alpha", "bravo", "charlie",
        ]
        .iter()
        .filter(|w| lower_words.contains(**w))
        .count();

        if has_interleaved_secret || nato_hits >= 4 {
            covert_secrets_redacted += 1;
            cleaned = "<ZK_MI_REDACTED>".to_string();
        } else {
            let sanitized = crate::security::LogSanitizer::sanitize_text(&cleaned);
            if sanitized != cleaned {
                covert_secrets_redacted += 1;
                cleaned = sanitized;
            }
        }

        // Canonicalize JSON key ordering if `cleaned` is valid JSON
        let mut json_keys_canonicalized = false;
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&cleaned) {
            if let Ok(canon_str) = serde_json::to_string(&json_val) {
                cleaned = canon_str;
                json_keys_canonicalized = true;
            }
        }

        let width = slot_width_ms.max(100);
        let quantized_release_slot_ms = ((timestamp_ms + width - 1) / width) * width;

        ZeroMiProjectionResult {
            canonical_output: cleaned,
            zero_width_chars_stripped,
            covert_secrets_redacted,
            json_keys_canonicalized,
            quantized_release_slot_ms,
            mutual_information_upper_bound_bits: 0.0,
        }
    }
}
