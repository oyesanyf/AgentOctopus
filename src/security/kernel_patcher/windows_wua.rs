//! Native Windows Update Agent (WUA) COM Orchestrator (`wuapi.h`).
//!
//! Replaces fire-and-forget `UsoClient.exe` calls with synchronous, observable COM execution
//! via dynamic `ole32.dll` / `oleaut32.dll` (`IUpdateSession` -> `IUpdateSearcher` ->
//! `IUpdateDownloader` -> `IUpdateInstaller` and `ISystemInformation::RebootRequired`).
//!
//! Cross-OS pure DTO types and result classifiers compile cleanly on all platforms so unit
//! tests run identically on Linux, macOS, BSD, and Windows with zero extra crate dependencies.

use serde::{Deserialize, Serialize};

/// Canonicalized Windows Update Agent `OperationResultCode` values (`wuapi.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WuaOperationResult {
    NotStarted,
    InProgress,
    Succeeded,
    SucceededWithErrors,
    Failed,
    Aborted,
    Unknown(i32),
}

impl WuaOperationResult {
    /// Converts raw WUA `OperationResultCode` integer (`0..=5`) into a typed enum.
    #[must_use]
    pub fn from_raw(code: i32) -> Self {
        match code {
            0 => Self::NotStarted,
            1 => Self::InProgress,
            2 => Self::Succeeded,
            3 => Self::SucceededWithErrors,
            4 => Self::Failed,
            5 => Self::Aborted,
            other => Self::Unknown(other),
        }
    }

    /// Returns `true` when the WUA operation succeeded cleanly (or partially with non-fatal warnings).
    #[must_use]
    pub fn is_ok(self) -> bool {
        matches!(self, Self::Succeeded | Self::SucceededWithErrors)
    }
}

/// Structured metadata for a single pending Windows Update candidate discovered via `IUpdateSearcher`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WuaUpdateCandidate {
    pub title: String,
    #[serde(default)]
    pub kb_article_ids: Vec<String>,
    #[serde(default)]
    pub security_bulletin_ids: Vec<String>,
    pub is_downloaded: bool,
    pub is_mandatory: bool,
    pub eula_accepted: bool,
    pub is_hotpatch_eligible: bool,
}

/// Complete telemetry summary returned by a native WUA COM search or download+install cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WuaExecutionSummary {
    pub engine: String,
    pub dry_run: bool,
    pub search_result: WuaOperationResult,
    pub download_result: Option<WuaOperationResult>,
    pub install_result: Option<WuaOperationResult>,
    pub pending_count: usize,
    pub downloaded_count: usize,
    pub installed_count: usize,
    pub skipped_eula_count: usize,
    pub reboot_required: bool,
    pub hotpatch_updates_detected: usize,
    #[serde(default)]
    pub candidates: Vec<WuaUpdateCandidate>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Returns `true` if a Windows Update title indicates Windows Hotpatch / rebootless servicing.
#[must_use]
pub fn is_hotpatch_update_title(title: &str) -> bool {
    let lower = title.to_ascii_lowercase();
    lower.contains("hotpatch") || lower.contains("rebootless")
}

/// Formats a human-readable multi-line summary of a `WuaExecutionSummary`.
#[must_use]
pub fn format_wua_summary_lines(summary: &WuaExecutionSummary) -> Vec<String> {
    let prefix = if summary.dry_run {
        "[DRY-RUN] [WUA-COM]"
    } else {
        "[WUA-COM]"
    };
    let mut lines = Vec::with_capacity(summary.candidates.len() + summary.warnings.len() + 4);
    lines.push(format!(
        "{prefix} search={:?} pending={} hotpatch_eligible={} reboot_required={}",
        summary.search_result,
        summary.pending_count,
        summary.hotpatch_updates_detected,
        summary.reboot_required
    ));
    if let Some(dl) = summary.download_result {
        lines.push(format!(
            "{prefix} download={dl:?} downloaded={}",
            summary.downloaded_count
        ));
    }
    if let Some(inst) = summary.install_result {
        lines.push(format!(
            "{prefix} install={inst:?} installed={} skipped_eula={}",
            summary.installed_count, summary.skipped_eula_count
        ));
    }
    for cand in summary.candidates.iter().take(20) {
        let kbs = if cand.kb_article_ids.is_empty() {
            "no-KB".to_string()
        } else {
            cand.kb_article_ids
                .iter()
                .map(|k| {
                    if k.starts_with("KB") {
                        k.clone()
                    } else {
                        format!("KB{k}")
                    }
                })
                .collect::<Vec<_>>()
                .join(",")
        };
        lines.push(format!(
            "{prefix} candidate [{kbs}] downloaded={} hotpatch={} :: {}",
            cand.is_downloaded, cand.is_hotpatch_eligible, cand.title
        ));
    }
    for warn in &summary.warnings {
        lines.push(format!("{prefix} warning: {warn}"));
    }
    lines
}

#[cfg(windows)]
mod native {
    use super::*;
    use crate::security::kernel_patcher::error::PatcherError;
    use std::ffi::c_void;
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    const WUA_SEARCH_CRITERIA: &str = "IsInstalled=0 and IsHidden=0 and Type='Software'";
    const COINIT_MULTITHREADED: u32 = 0x0;
    const CLSCTX_INPROC_SERVER: u32 = 0x1;
    const S_OK: i32 = 0;
    const S_FALSE: i32 = 1;
    const RPC_E_CHANGED_MODE: i32 = -2147417850; // 0x80010106
    const VARIANT_TRUE: i16 = -1;
    const VARIANT_FALSE: i16 = 0;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ComGuid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    // Verified against Windows SDK 10.0.26100.0 `um\wuapi.h`
    const CLSID_SYSTEM_INFORMATION: ComGuid = ComGuid {
        data1: 0xC01B_9BA0,
        data2: 0xBEA7,
        data3: 0x41BA,
        data4: [0xB6, 0x04, 0xD0, 0xA3, 0x6F, 0x46, 0x91, 0x33],
    };
    const IID_ISYSTEM_INFORMATION: ComGuid = ComGuid {
        data1: 0xADE8_7BF7,
        data2: 0x7B56,
        data3: 0x4275,
        data4: [0x8F, 0xAB, 0xB9, 0xB0, 0xE5, 0x91, 0x84, 0x4B],
    };
    const CLSID_UPDATE_COLLECTION: ComGuid = ComGuid {
        data1: 0x1363_9463,
        data2: 0x00DB,
        data3: 0x4646,
        data4: [0x80, 0x3D, 0x52, 0x80, 0x26, 0x14, 0x0D, 0x88],
    };
    const IID_IUPDATE_COLLECTION: ComGuid = ComGuid {
        data1: 0x07F7_438C,
        data2: 0x7709,
        data3: 0x4CA5,
        data4: [0xB5, 0x18, 0x91, 0x27, 0x92, 0x88, 0x13, 0x4E],
    };
    const CLSID_UPDATE_SESSION: ComGuid = ComGuid {
        data1: 0x4CB4_3D7F,
        data2: 0x7EEE,
        data3: 0x4906,
        data4: [0x86, 0x98, 0x60, 0xDA, 0x1C, 0x38, 0xF2, 0xFE],
    };
    const IID_IUPDATE_SESSION: ComGuid = ComGuid {
        data1: 0x8168_58A4,
        data2: 0x260D,
        data3: 0x4260,
        data4: [0x93, 0x3A, 0x25, 0x85, 0xF1, 0xAB, 0xC7, 0x6B],
    };

    type FnCoInitializeEx = unsafe extern "system" fn(*mut c_void, u32) -> i32;
    type FnCoUninitialize = unsafe extern "system" fn();
    type FnCoCreateInstance = unsafe extern "system" fn(
        *const ComGuid,
        *mut c_void,
        u32,
        *const ComGuid,
        *mut *mut c_void,
    ) -> i32;
    type FnSysAllocString = unsafe extern "system" fn(*const u16) -> *mut u16;
    type FnSysFreeString = unsafe extern "system" fn(*mut u16);
    type FnSysStringLen = unsafe extern "system" fn(*const u16) -> u32;

    struct OleFns {
        co_init: FnCoInitializeEx,
        co_uninit: FnCoUninitialize,
        co_create: FnCoCreateInstance,
        sys_alloc: FnSysAllocString,
        sys_free: FnSysFreeString,
        sys_len: FnSysStringLen,
    }

    impl OleFns {
        fn load() -> Result<Self, PatcherError> {
            let ole32_w: Vec<u16> = "ole32.dll\0".encode_utf16().collect();
            let oleaut_w: Vec<u16> = "oleaut32.dll\0".encode_utf16().collect();
            let h_ole32 = unsafe { LoadLibraryW(ole32_w.as_ptr()) };
            let h_oleaut = unsafe { LoadLibraryW(oleaut_w.as_ptr()) };
            if h_ole32.is_null() || h_oleaut.is_null() {
                return Err(PatcherError::ExecutionFailed(
                    "Failed loading ole32.dll / oleaut32.dll for WUA COM".to_string(),
                ));
            }
            unsafe {
                let p_init =
                    GetProcAddress(h_ole32, b"CoInitializeEx\0".as_ptr()).ok_or_else(|| {
                        PatcherError::ExecutionFailed("Missing CoInitializeEx".to_string())
                    })?;
                let p_uninit =
                    GetProcAddress(h_ole32, b"CoUninitialize\0".as_ptr()).ok_or_else(|| {
                        PatcherError::ExecutionFailed("Missing CoUninitialize".to_string())
                    })?;
                let p_create =
                    GetProcAddress(h_ole32, b"CoCreateInstance\0".as_ptr()).ok_or_else(|| {
                        PatcherError::ExecutionFailed("Missing CoCreateInstance".to_string())
                    })?;
                let p_alloc =
                    GetProcAddress(h_oleaut, b"SysAllocString\0".as_ptr()).ok_or_else(|| {
                        PatcherError::ExecutionFailed("Missing SysAllocString".to_string())
                    })?;
                let p_free =
                    GetProcAddress(h_oleaut, b"SysFreeString\0".as_ptr()).ok_or_else(|| {
                        PatcherError::ExecutionFailed("Missing SysFreeString".to_string())
                    })?;
                let p_len =
                    GetProcAddress(h_oleaut, b"SysStringLen\0".as_ptr()).ok_or_else(|| {
                        PatcherError::ExecutionFailed("Missing SysStringLen".to_string())
                    })?;
                Ok(Self {
                    co_init: std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        FnCoInitializeEx,
                    >(p_init),
                    co_uninit: std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        FnCoUninitialize,
                    >(p_uninit),
                    co_create: std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        FnCoCreateInstance,
                    >(p_create),
                    sys_alloc: std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        FnSysAllocString,
                    >(p_alloc),
                    sys_free: std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        FnSysFreeString,
                    >(p_free),
                    sys_len: std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        FnSysStringLen,
                    >(p_len),
                })
            }
        }

        fn alloc_bstr(&self, s: &str) -> *mut u16 {
            let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe { (self.sys_alloc)(wide.as_ptr()) }
        }

        fn take_bstr_string(&self, bstr: *mut u16) -> String {
            if bstr.is_null() {
                return String::new();
            }
            let len = unsafe { (self.sys_len)(bstr) } as usize;
            let slice = unsafe { std::slice::from_raw_parts(bstr, len) };
            let out = String::from_utf16_lossy(slice);
            unsafe { (self.sys_free)(bstr) };
            out
        }
    }

    struct ComApartmentGuard {
        should_uninit: bool,
        co_uninit: FnCoUninitialize,
    }

    impl ComApartmentGuard {
        fn init_mta(ole: &OleFns) -> Result<Self, PatcherError> {
            let hr = unsafe { (ole.co_init)(std::ptr::null_mut(), COINIT_MULTITHREADED) };
            if hr == S_OK || hr == S_FALSE {
                Ok(Self {
                    should_uninit: true,
                    co_uninit: ole.co_uninit,
                })
            } else if hr == RPC_E_CHANGED_MODE {
                Ok(Self {
                    should_uninit: false,
                    co_uninit: ole.co_uninit,
                })
            } else {
                Err(PatcherError::ExecutionFailed(format!(
                    "CoInitializeEx failed with HRESULT 0x{:08X}",
                    hr as u32
                )))
            }
        }
    }

    impl Drop for ComApartmentGuard {
        fn drop(&mut self) {
            if self.should_uninit {
                unsafe { (self.co_uninit)() };
            }
        }
    }

    /// RAII COM interface pointer guard releasing on drop (slot 2 = `IUnknown::Release`).
    struct ComPtr(*mut c_void);

    impl ComPtr {
        #[inline]
        unsafe fn vtbl_slot(&self, slot: usize) -> *const c_void {
            let vtbl = *(self.0 as *const *const *const c_void);
            *vtbl.add(slot)
        }

        fn as_ptr(&self) -> *mut c_void {
            self.0
        }
    }

    impl Drop for ComPtr {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    type FnRelease = unsafe extern "system" fn(*mut c_void) -> u32;
                    let rel: FnRelease = std::mem::transmute(self.vtbl_slot(2));
                    let _ = rel(self.0);
                }
                self.0 = std::ptr::null_mut();
            }
        }
    }

    #[inline]
    fn hr_ok(hr: i32) -> bool {
        hr >= 0
    }

    fn co_create(
        ole: &OleFns,
        clsid: &ComGuid,
        iid: &ComGuid,
        label: &str,
    ) -> Result<ComPtr, PatcherError> {
        let mut raw: *mut c_void = std::ptr::null_mut();
        let hr = unsafe {
            (ole.co_create)(
                clsid,
                std::ptr::null_mut(),
                CLSCTX_INPROC_SERVER,
                iid,
                &mut raw,
            )
        };
        if !hr_ok(hr) || raw.is_null() {
            return Err(PatcherError::ExecutionFailed(format!(
                "CoCreateInstance({label}) failed: HRESULT 0x{:08X}",
                hr as u32
            )));
        }
        Ok(ComPtr(raw))
    }

    fn query_com_reboot_required(ole: &OleFns) -> Option<bool> {
        let sys_info = co_create(
            ole,
            &CLSID_SYSTEM_INFORMATION,
            &IID_ISYSTEM_INFORMATION,
            "SystemInformation",
        )
        .ok()?;
        let mut flag: i16 = 0;
        let hr = unsafe {
            type FnGetReboot = unsafe extern "system" fn(*mut c_void, *mut i16) -> i32;
            let f: FnGetReboot = std::mem::transmute(sys_info.vtbl_slot(8));
            f(sys_info.as_ptr(), &mut flag)
        };
        if hr_ok(hr) {
            Some(flag != VARIANT_FALSE)
        } else {
            None
        }
    }

    fn read_string_collection(ole: &OleFns, coll: &ComPtr) -> Vec<String> {
        let mut count: i32 = 0;
        let hr = unsafe {
            type FnCount = unsafe extern "system" fn(*mut c_void, *mut i32) -> i32;
            let f: FnCount = std::mem::transmute(coll.vtbl_slot(10));
            f(coll.as_ptr(), &mut count)
        };
        if !hr_ok(hr) || count <= 0 {
            return Vec::new();
        }
        let mut items = Vec::with_capacity(count as usize);
        for idx in 0..count {
            let mut bstr: *mut u16 = std::ptr::null_mut();
            let ihr = unsafe {
                type FnItem = unsafe extern "system" fn(*mut c_void, i32, *mut *mut u16) -> i32;
                let f: FnItem = std::mem::transmute(coll.vtbl_slot(7));
                f(coll.as_ptr(), idx, &mut bstr)
            };
            if hr_ok(ihr) && !bstr.is_null() {
                let s = ole.take_bstr_string(bstr);
                if !s.is_empty() {
                    items.push(s);
                }
            }
        }
        items
    }

    fn extract_candidate(ole: &OleFns, update: &ComPtr) -> WuaUpdateCandidate {
        let title = {
            let mut bstr: *mut u16 = std::ptr::null_mut();
            let hr = unsafe {
                type FnTitle = unsafe extern "system" fn(*mut c_void, *mut *mut u16) -> i32;
                let f: FnTitle = std::mem::transmute(update.vtbl_slot(7));
                f(update.as_ptr(), &mut bstr)
            };
            if hr_ok(hr) && !bstr.is_null() {
                ole.take_bstr_string(bstr)
            } else {
                "(untitled update)".to_string()
            }
        };

        let get_bool = |slot: usize, default_val: bool| -> bool {
            let mut v: i16 = 0;
            let hr = unsafe {
                type FnBool = unsafe extern "system" fn(*mut c_void, *mut i16) -> i32;
                let f: FnBool = std::mem::transmute(update.vtbl_slot(slot));
                f(update.as_ptr(), &mut v)
            };
            if hr_ok(hr) {
                v != VARIANT_FALSE
            } else {
                default_val
            }
        };

        let get_str_coll = |slot: usize| -> Vec<String> {
            let mut raw: *mut c_void = std::ptr::null_mut();
            let hr = unsafe {
                type FnColl = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
                let f: FnColl = std::mem::transmute(update.vtbl_slot(slot));
                f(update.as_ptr(), &mut raw)
            };
            if hr_ok(hr) && !raw.is_null() {
                let coll = ComPtr(raw);
                read_string_collection(ole, &coll)
            } else {
                Vec::new()
            }
        };

        let eula_accepted = get_bool(16, true);
        let is_downloaded = get_bool(23, false);
        let is_mandatory = get_bool(27, false);
        let security_bulletin_ids = get_str_coll(39);
        let kb_article_ids = get_str_coll(46);
        let is_hotpatch_eligible = is_hotpatch_update_title(&title);

        WuaUpdateCandidate {
            title,
            kb_article_ids,
            security_bulletin_ids,
            is_downloaded,
            is_mandatory,
            eula_accepted,
            is_hotpatch_eligible,
        }
    }

    fn search_updates(
        ole: &OleFns,
        session: &ComPtr,
    ) -> Result<(WuaOperationResult, ComPtr), PatcherError> {
        let mut raw_searcher: *mut c_void = std::ptr::null_mut();
        let hr = unsafe {
            type FnCreate = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
            let f: FnCreate = std::mem::transmute(session.vtbl_slot(12));
            f(session.as_ptr(), &mut raw_searcher)
        };
        if !hr_ok(hr) || raw_searcher.is_null() {
            return Err(PatcherError::ExecutionFailed(format!(
                "IUpdateSession::CreateUpdateSearcher failed: HRESULT 0x{:08X}",
                hr as u32
            )));
        }
        let searcher = ComPtr(raw_searcher);

        // SetOnline(VARIANT_TRUE) -> slot 21
        unsafe {
            type FnPutOnline = unsafe extern "system" fn(*mut c_void, i16) -> i32;
            let f: FnPutOnline = std::mem::transmute(searcher.vtbl_slot(21));
            let _ = f(searcher.as_ptr(), VARIANT_TRUE);
        }

        let bstr_criteria = ole.alloc_bstr(WUA_SEARCH_CRITERIA);
        let mut raw_result: *mut c_void = std::ptr::null_mut();
        let shr = unsafe {
            type FnSearch =
                unsafe extern "system" fn(*mut c_void, *mut u16, *mut *mut c_void) -> i32;
            let f: FnSearch = std::mem::transmute(searcher.vtbl_slot(19));
            f(searcher.as_ptr(), bstr_criteria, &mut raw_result)
        };
        if !bstr_criteria.is_null() {
            unsafe { (ole.sys_free)(bstr_criteria) };
        }
        if !hr_ok(shr) || raw_result.is_null() {
            return Err(PatcherError::ExecutionFailed(format!(
                "IUpdateSearcher::Search failed: HRESULT 0x{:08X}",
                shr as u32
            )));
        }
        let search_res = ComPtr(raw_result);

        let mut raw_code: i32 = -1;
        unsafe {
            type FnCode = unsafe extern "system" fn(*mut c_void, *mut i32) -> i32;
            let f: FnCode = std::mem::transmute(search_res.vtbl_slot(7));
            let _ = f(search_res.as_ptr(), &mut raw_code);
        }
        let search_code = WuaOperationResult::from_raw(raw_code);

        let mut raw_updates: *mut c_void = std::ptr::null_mut();
        let uhr = unsafe {
            type FnUpdates = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
            let f: FnUpdates = std::mem::transmute(search_res.vtbl_slot(9));
            f(search_res.as_ptr(), &mut raw_updates)
        };
        if !hr_ok(uhr) || raw_updates.is_null() {
            return Err(PatcherError::ExecutionFailed(format!(
                "ISearchResult::Updates failed: HRESULT 0x{:08X}",
                uhr as u32
            )));
        }
        Ok((search_code, ComPtr(raw_updates)))
    }

    fn update_collection_count(coll: &ComPtr) -> i32 {
        let mut count: i32 = 0;
        let hr = unsafe {
            type FnCount = unsafe extern "system" fn(*mut c_void, *mut i32) -> i32;
            let f: FnCount = std::mem::transmute(coll.vtbl_slot(10));
            f(coll.as_ptr(), &mut count)
        };
        if hr_ok(hr) {
            count.max(0)
        } else {
            0
        }
    }

    fn update_collection_item(coll: &ComPtr, idx: i32) -> Option<ComPtr> {
        let mut raw: *mut c_void = std::ptr::null_mut();
        let hr = unsafe {
            type FnItem = unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32;
            let f: FnItem = std::mem::transmute(coll.vtbl_slot(7));
            f(coll.as_ptr(), idx, &mut raw)
        };
        if hr_ok(hr) && !raw.is_null() {
            Some(ComPtr(raw))
        } else {
            None
        }
    }

    fn update_collection_add(coll: &ComPtr, update: &ComPtr) -> bool {
        let mut out_idx: i32 = -1;
        let hr = unsafe {
            type FnAdd = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut i32) -> i32;
            let f: FnAdd = std::mem::transmute(coll.vtbl_slot(12));
            f(coll.as_ptr(), update.as_ptr(), &mut out_idx)
        };
        hr_ok(hr)
    }

    /// Queries Windows Update Agent COM for pending software/security updates (read-only).
    pub fn query_pending_updates_blocking() -> Result<WuaExecutionSummary, PatcherError> {
        let ole = OleFns::load()?;
        let _com = ComApartmentGuard::init_mta(&ole)?;
        let session = co_create(
            &ole,
            &CLSID_UPDATE_SESSION,
            &IID_IUPDATE_SESSION,
            "UpdateSession",
        )?;
        let (search_code, updates) = search_updates(&ole, &session)?;
        let count = update_collection_count(&updates);

        let mut candidates = Vec::with_capacity(count as usize);
        let mut hotpatch_count = 0usize;
        for idx in 0..count {
            if let Some(upd) = update_collection_item(&updates, idx) {
                let cand = extract_candidate(&ole, &upd);
                if cand.is_hotpatch_eligible {
                    hotpatch_count += 1;
                }
                candidates.push(cand);
            }
        }
        let reboot_required = query_com_reboot_required(&ole).unwrap_or(false);

        Ok(WuaExecutionSummary {
            engine: "WindowsUpdateAgentCOM".to_string(),
            dry_run: true,
            search_result: search_code,
            download_result: None,
            install_result: None,
            pending_count: candidates.len(),
            downloaded_count: candidates.iter().filter(|c| c.is_downloaded).count(),
            installed_count: 0,
            skipped_eula_count: 0,
            reboot_required,
            hotpatch_updates_detected: hotpatch_count,
            candidates,
            warnings: Vec::new(),
        })
    }

    /// Synchronously searches, downloads, and installs pending Windows updates via WUA COM.
    /// Must only be called when the process is elevated (Administrator).
    pub fn download_and_install_updates_blocking(
        auto_accept_eula: bool,
    ) -> Result<WuaExecutionSummary, PatcherError> {
        let ole = OleFns::load()?;
        let _com = ComApartmentGuard::init_mta(&ole)?;
        let session = co_create(
            &ole,
            &CLSID_UPDATE_SESSION,
            &IID_IUPDATE_SESSION,
            "UpdateSession",
        )?;
        let (search_code, found_updates) = search_updates(&ole, &session)?;
        let count = update_collection_count(&found_updates);

        let to_download = co_create(
            &ole,
            &CLSID_UPDATE_COLLECTION,
            &IID_IUPDATE_COLLECTION,
            "UpdateCollection(download)",
        )?;
        let to_install = co_create(
            &ole,
            &CLSID_UPDATE_COLLECTION,
            &IID_IUPDATE_COLLECTION,
            "UpdateCollection(install)",
        )?;

        let mut candidates = Vec::with_capacity(count as usize);
        let mut warnings = Vec::new();
        let mut skipped_eula_count = 0usize;
        let mut hotpatch_count = 0usize;

        for idx in 0..count {
            if let Some(upd) = update_collection_item(&found_updates, idx) {
                let mut cand = extract_candidate(&ole, &upd);
                if cand.is_hotpatch_eligible {
                    hotpatch_count += 1;
                }
                if !cand.eula_accepted {
                    if auto_accept_eula {
                        let ehr = unsafe {
                            type FnAccept = unsafe extern "system" fn(*mut c_void) -> i32;
                            let f: FnAccept = std::mem::transmute(upd.vtbl_slot(47));
                            f(upd.as_ptr())
                        };
                        if !hr_ok(ehr) {
                            warnings.push(format!(
                                "Failed to accept EULA for '{}' (HRESULT 0x{:08X})",
                                cand.title, ehr as u32
                            ));
                            skipped_eula_count += 1;
                            candidates.push(cand);
                            continue;
                        }
                        cand.eula_accepted = true;
                    } else {
                        warnings.push(format!(
                            "Skipped '{}' because EULA was not accepted",
                            cand.title
                        ));
                        skipped_eula_count += 1;
                        candidates.push(cand);
                        continue;
                    }
                }
                if !cand.is_downloaded {
                    let _ = update_collection_add(&to_download, &upd);
                }
                let _ = update_collection_add(&to_install, &upd);
                candidates.push(cand);
            }
        }

        let pending_count = candidates.len();
        let dl_queued = update_collection_count(&to_download) as usize;
        let inst_queued = update_collection_count(&to_install) as usize;

        if inst_queued == 0 {
            let reboot_required = query_com_reboot_required(&ole).unwrap_or(false);
            return Ok(WuaExecutionSummary {
                engine: "WindowsUpdateAgentCOM".to_string(),
                dry_run: false,
                search_result: search_code,
                download_result: Some(WuaOperationResult::Succeeded),
                install_result: Some(WuaOperationResult::Succeeded),
                pending_count,
                downloaded_count: 0,
                installed_count: 0,
                skipped_eula_count,
                reboot_required,
                hotpatch_updates_detected: hotpatch_count,
                candidates,
                warnings,
            });
        }

        let (download_result, downloaded_count) = if dl_queued > 0 {
            let mut raw_dl: *mut c_void = std::ptr::null_mut();
            let hr = unsafe {
                type FnCreateDl = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
                let f: FnCreateDl = std::mem::transmute(session.vtbl_slot(13));
                f(session.as_ptr(), &mut raw_dl)
            };
            if !hr_ok(hr) || raw_dl.is_null() {
                return Err(PatcherError::ExecutionFailed(format!(
                    "IUpdateSession::CreateUpdateDownloader failed: HRESULT 0x{:08X}",
                    hr as u32
                )));
            }
            let downloader = ComPtr(raw_dl);
            let phr = unsafe {
                type FnPutUpd = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
                let f: FnPutUpd = std::mem::transmute(downloader.vtbl_slot(14));
                f(downloader.as_ptr(), to_download.as_ptr())
            };
            if !hr_ok(phr) {
                return Err(PatcherError::ExecutionFailed(format!(
                    "IUpdateDownloader::put_Updates failed: HRESULT 0x{:08X}",
                    phr as u32
                )));
            }
            let mut raw_dl_res: *mut c_void = std::ptr::null_mut();
            let dhr = unsafe {
                type FnDl = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
                let f: FnDl = std::mem::transmute(downloader.vtbl_slot(16));
                f(downloader.as_ptr(), &mut raw_dl_res)
            };
            if !hr_ok(dhr) || raw_dl_res.is_null() {
                return Err(PatcherError::ExecutionFailed(format!(
                    "IUpdateDownloader::Download failed: HRESULT 0x{:08X}",
                    dhr as u32
                )));
            }
            let dl_res = ComPtr(raw_dl_res);
            let mut raw_code: i32 = -1;
            unsafe {
                type FnCode = unsafe extern "system" fn(*mut c_void, *mut i32) -> i32;
                let f: FnCode = std::mem::transmute(dl_res.vtbl_slot(8));
                let _ = f(dl_res.as_ptr(), &mut raw_code);
            }
            let code = WuaOperationResult::from_raw(raw_code);
            let ok_count = if code.is_ok() { dl_queued } else { 0 };
            (Some(code), ok_count)
        } else {
            (Some(WuaOperationResult::Succeeded), 0)
        };

        if let Some(dl_code) = download_result {
            if !dl_code.is_ok() {
                let reboot_required = query_com_reboot_required(&ole).unwrap_or(false);
                warnings.push(format!("WUA download did not succeed: {dl_code:?}"));
                return Ok(WuaExecutionSummary {
                    engine: "WindowsUpdateAgentCOM".to_string(),
                    dry_run: false,
                    search_result: search_code,
                    download_result,
                    install_result: None,
                    pending_count,
                    downloaded_count,
                    installed_count: 0,
                    skipped_eula_count,
                    reboot_required,
                    hotpatch_updates_detected: hotpatch_count,
                    candidates,
                    warnings,
                });
            }
        }

        let mut raw_inst: *mut c_void = std::ptr::null_mut();
        let hr = unsafe {
            type FnCreateInst = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
            let f: FnCreateInst = std::mem::transmute(session.vtbl_slot(14));
            f(session.as_ptr(), &mut raw_inst)
        };
        if !hr_ok(hr) || raw_inst.is_null() {
            return Err(PatcherError::ExecutionFailed(format!(
                "IUpdateSession::CreateUpdateInstaller failed: HRESULT 0x{:08X}",
                hr as u32
            )));
        }
        let installer = ComPtr(raw_inst);
        unsafe {
            type FnPutPrompts = unsafe extern "system" fn(*mut c_void, i16) -> i32;
            let f: FnPutPrompts = std::mem::transmute(installer.vtbl_slot(26));
            let _ = f(installer.as_ptr(), VARIANT_FALSE);
        }
        let phr = unsafe {
            type FnPutUpd = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
            let f: FnPutUpd = std::mem::transmute(installer.vtbl_slot(16));
            f(installer.as_ptr(), to_install.as_ptr())
        };
        if !hr_ok(phr) {
            return Err(PatcherError::ExecutionFailed(format!(
                "IUpdateInstaller::put_Updates failed: HRESULT 0x{:08X}",
                phr as u32
            )));
        }
        let mut raw_inst_res: *mut c_void = std::ptr::null_mut();
        let ihr = unsafe {
            type FnInstall = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
            let f: FnInstall = std::mem::transmute(installer.vtbl_slot(21));
            f(installer.as_ptr(), &mut raw_inst_res)
        };
        if !hr_ok(ihr) || raw_inst_res.is_null() {
            return Err(PatcherError::ExecutionFailed(format!(
                "IUpdateInstaller::Install failed: HRESULT 0x{:08X}",
                ihr as u32
            )));
        }
        let inst_res = ComPtr(raw_inst_res);

        let mut raw_reboot: i16 = 0;
        let mut raw_code: i32 = -1;
        unsafe {
            type FnReboot = unsafe extern "system" fn(*mut c_void, *mut i16) -> i32;
            type FnCode = unsafe extern "system" fn(*mut c_void, *mut i32) -> i32;
            let fr: FnReboot = std::mem::transmute(inst_res.vtbl_slot(8));
            let fc: FnCode = std::mem::transmute(inst_res.vtbl_slot(9));
            let _ = fr(inst_res.as_ptr(), &mut raw_reboot);
            let _ = fc(inst_res.as_ptr(), &mut raw_code);
        }
        let inst_code = WuaOperationResult::from_raw(raw_code);
        let inst_reboot = raw_reboot != VARIANT_FALSE;
        let sys_reboot = query_com_reboot_required(&ole).unwrap_or(false);
        let installed_count = if inst_code.is_ok() { inst_queued } else { 0 };

        Ok(WuaExecutionSummary {
            engine: "WindowsUpdateAgentCOM".to_string(),
            dry_run: false,
            search_result: search_code,
            download_result,
            install_result: Some(inst_code),
            pending_count,
            downloaded_count,
            installed_count,
            skipped_eula_count,
            reboot_required: inst_reboot || sys_reboot,
            hotpatch_updates_detected: hotpatch_count,
            candidates,
            warnings,
        })
    }

    /// Queries `ISystemInformation::RebootRequired()` without mutating state.
    pub fn query_wua_reboot_required() -> Option<bool> {
        let ole = OleFns::load().ok()?;
        let _com = ComApartmentGuard::init_mta(&ole).ok()?;
        query_com_reboot_required(&ole)
    }
}

#[cfg(windows)]
pub use native::{
    download_and_install_updates_blocking, query_pending_updates_blocking,
    query_wua_reboot_required,
};

#[cfg(not(windows))]
pub fn query_wua_reboot_required() -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wua_operation_result_mapping_and_hotpatch_detection() {
        assert_eq!(
            WuaOperationResult::from_raw(0),
            WuaOperationResult::NotStarted
        );
        assert_eq!(
            WuaOperationResult::from_raw(1),
            WuaOperationResult::InProgress
        );
        assert_eq!(
            WuaOperationResult::from_raw(2),
            WuaOperationResult::Succeeded
        );
        assert!(WuaOperationResult::Succeeded.is_ok());
        assert!(WuaOperationResult::SucceededWithErrors.is_ok());
        assert!(!WuaOperationResult::Failed.is_ok());
        assert!(!WuaOperationResult::Aborted.is_ok());
        assert_eq!(
            WuaOperationResult::from_raw(99),
            WuaOperationResult::Unknown(99)
        );

        assert!(is_hotpatch_update_title(
            "2026-11 Hotpatch Security Update for Windows 11 24H2 (KB5061234)"
        ));
        assert!(is_hotpatch_update_title(
            "Rebootless Kernel Security Servicing Patch"
        ));
        assert!(!is_hotpatch_update_title(
            "2026-11 Cumulative Update for Windows 11 (KB5060001)"
        ));
    }

    #[test]
    fn test_format_wua_summary_lines_preserves_dry_run_prefix_and_kb_ids() {
        let summary = WuaExecutionSummary {
            engine: "WindowsUpdateAgentCOM".to_string(),
            dry_run: true,
            search_result: WuaOperationResult::Succeeded,
            download_result: None,
            install_result: None,
            pending_count: 1,
            downloaded_count: 0,
            installed_count: 0,
            skipped_eula_count: 0,
            reboot_required: false,
            hotpatch_updates_detected: 1,
            candidates: vec![WuaUpdateCandidate {
                title: "2026-11 Hotpatch Update".to_string(),
                kb_article_ids: vec!["5061234".to_string()],
                security_bulletin_ids: vec![],
                is_downloaded: false,
                is_mandatory: true,
                eula_accepted: true,
                is_hotpatch_eligible: true,
            }],
            warnings: vec![],
        };
        let lines = format_wua_summary_lines(&summary);
        assert!(lines[0].contains("[DRY-RUN] [WUA-COM]"));
        assert!(lines[0].contains("hotpatch_eligible=1"));
        assert!(lines[1].contains("KB5061234"));
    }
}
