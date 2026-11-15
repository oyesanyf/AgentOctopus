//! Windows host kernel discovery using dynamic `ntdll!RtlGetVersion` and Win32 Registry APIs.

#[cfg(windows)]
use super::super::cpe::{canonicalize_windows_cpe, Cpe23};
use super::super::error::PatcherError;
use super::super::types::HostKernelInfo;
#[cfg(windows)]
use super::super::types::OsFamily;

#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
pub struct OSVERSIONINFOEXW {
    pub dwOSVersionInfoSize: u32,
    pub dwMajorVersion: u32,
    pub dwMinorVersion: u32,
    pub dwBuildNumber: u32,
    pub dwPlatformId: u32,
    pub szCSDVersion: [u16; 128],
    pub wServicePackMajor: u16,
    pub wServicePackMinor: u16,
    pub wSuiteMask: u16,
    pub wProductType: u8,
    pub wReserved: u8,
}

#[cfg(windows)]
type RtlGetVersionFn = unsafe extern "system" fn(*mut OSVERSIONINFOEXW) -> i32;

/// Raw NT kernel version fields extracted via `RtlGetVersion`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawNtVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub is_workstation: bool,
}

/// Queries `ntdll!RtlGetVersion` directly to avoid Windows version manifest shims.
#[cfg(windows)]
pub fn query_ntdll_rtl_get_version() -> Result<RawNtVersion, PatcherError> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return Err(PatcherError::DetectionFailed(
                "ntdll.dll module handle not found".into(),
            ));
        }
        let proc = GetProcAddress(ntdll, b"RtlGetVersion\0".as_ptr());
        let Some(proc) = proc else {
            return Err(PatcherError::DetectionFailed(
                "RtlGetVersion symbol not found in ntdll.dll".into(),
            ));
        };
        let rtl_get_version: RtlGetVersionFn =
            std::mem::transmute::<unsafe extern "system" fn() -> isize, RtlGetVersionFn>(proc);

        let mut os_info: OSVERSIONINFOEXW = std::mem::zeroed();
        os_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;

        let status = rtl_get_version(&mut os_info);
        if status != 0 {
            return Err(PatcherError::DetectionFailed(format!(
                "RtlGetVersion failed with NTSTATUS 0x{status:08X}"
            )));
        }

        Ok(RawNtVersion {
            major: os_info.dwMajorVersion,
            minor: os_info.dwMinorVersion,
            build: os_info.dwBuildNumber,
            is_workstation: os_info.wProductType == 1,
        })
    }
}

/// Registry metadata read from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowsRegistryInfo {
    pub ubr: Option<u32>,
    pub display_version: Option<String>,
    pub product_name: Option<String>,
    pub edition_id: Option<String>,
    pub installation_type: Option<String>,
}

#[cfg(windows)]
struct RegKeyGuard(windows_sys::Win32::System::Registry::HKEY);

#[cfg(windows)]
impl Drop for RegKeyGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::System::Registry::RegCloseKey(self.0);
            }
        }
    }
}

#[cfg(windows)]
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn read_reg_dword(hkey: windows_sys::Win32::System::Registry::HKEY, name: &str) -> Option<u32> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{RegQueryValueExW, REG_DWORD, REG_VALUE_TYPE};

    let wide_name = to_wide_null(name);
    let mut val_type: REG_VALUE_TYPE = 0;
    let mut buf = [0u8; 4];
    let mut cb_data: u32 = 4;

    let status = unsafe {
        RegQueryValueExW(
            hkey,
            wide_name.as_ptr(),
            std::ptr::null(),
            &mut val_type,
            buf.as_mut_ptr(),
            &mut cb_data,
        )
    };
    if status == ERROR_SUCCESS && val_type == REG_DWORD && cb_data == 4 {
        Some(u32::from_le_bytes(buf))
    } else {
        None
    }
}

#[cfg(windows)]
fn read_reg_string(hkey: windows_sys::Win32::System::Registry::HKEY, name: &str) -> Option<String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegQueryValueExW, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
    };

    const MAX_REG_STRING_BYTES: u32 = 64 * 1024;

    let wide_name = to_wide_null(name);
    let mut val_type: REG_VALUE_TYPE = 0;
    let mut cb_data: u32 = 0;

    let status = unsafe {
        RegQueryValueExW(
            hkey,
            wide_name.as_ptr(),
            std::ptr::null(),
            &mut val_type,
            std::ptr::null_mut(),
            &mut cb_data,
        )
    };
    if status != ERROR_SUCCESS
        || cb_data == 0
        || cb_data > MAX_REG_STRING_BYTES
        || (val_type != REG_SZ && val_type != REG_EXPAND_SZ)
    {
        return None;
    }

    let word_len = (cb_data as usize).div_ceil(2);
    let mut wide_buf = vec![0u16; word_len];
    let mut read_bytes: u32 = (wide_buf.len() * 2) as u32;

    let status = unsafe {
        RegQueryValueExW(
            hkey,
            wide_name.as_ptr(),
            std::ptr::null(),
            &mut val_type,
            wide_buf.as_mut_ptr().cast::<u8>(),
            &mut read_bytes,
        )
    };
    if status != ERROR_SUCCESS || (val_type != REG_SZ && val_type != REG_EXPAND_SZ) {
        return None;
    }

    let actual_words = ((read_bytes as usize) / 2).min(wide_buf.len());
    let slice = &wide_buf[..actual_words];
    let end = slice.iter().position(|&w| w == 0).unwrap_or(slice.len());
    let decoded = String::from_utf16_lossy(&slice[..end]).trim().to_string();
    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

/// Reads Windows release and UBR metadata using `windows-sys` registry APIs.
#[cfg(windows)]
pub fn query_windows_registry() -> WindowsRegistryInfo {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ};

    let subkey = to_wide_null("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    let mut hkey: HKEY = std::ptr::null_mut();

    let status =
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut hkey) };
    if status != ERROR_SUCCESS || hkey.is_null() {
        return WindowsRegistryInfo::default();
    }

    let guard = RegKeyGuard(hkey);
    let ubr = read_reg_dword(guard.0, "UBR");
    let display_version = read_reg_string(guard.0, "DisplayVersion")
        .or_else(|| read_reg_string(guard.0, "ReleaseId"));
    let product_name = read_reg_string(guard.0, "ProductName");
    let edition_id = read_reg_string(guard.0, "EditionID");
    let installation_type = read_reg_string(guard.0, "InstallationType");

    WindowsRegistryInfo {
        ubr,
        display_version,
        product_name,
        edition_id,
        installation_type,
    }
}

#[cfg(windows)]
pub fn detect_windows_kernel() -> Result<HostKernelInfo, PatcherError> {
    let raw = query_ntdll_rtl_get_version()?;
    let reg = query_windows_registry();

    let is_server = !raw.is_workstation
        || reg
            .installation_type
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("Server"))
            .unwrap_or(false);

    let (cpe_product, cpe_version) =
        canonicalize_windows_cpe(raw.build, is_server, reg.display_version.as_deref());
    let cpe = Cpe23::new_os("microsoft", cpe_product, cpe_version);
    let cpe23 = cpe.to_formatted_string();

    let kernel_release = match reg.ubr {
        Some(ubr) => format!("{}.{}.{}.{}", raw.major, raw.minor, raw.build, ubr),
        None => format!("{}.{}.{}", raw.major, raw.minor, raw.build),
    };

    let product_label = if is_server {
        if raw.build >= 26100 {
            "Windows Server 2025"
        } else if raw.build >= 20348 {
            "Windows Server 2022"
        } else if raw.build >= 17763 {
            "Windows Server 2019"
        } else if raw.build >= 14393 {
            "Windows Server 2016"
        } else {
            "Windows Server"
        }
    } else if raw.build >= 22000 {
        "Windows 11"
    } else if raw.build >= 10240 {
        "Windows 10"
    } else {
        "Windows"
    };

    let os_version = match (reg.product_name.as_deref(), reg.display_version.as_deref()) {
        (Some(p), Some(dv)) => format!("{p} {dv} (Build {kernel_release})"),
        (Some(p), None) => format!("{p} (Build {kernel_release})"),
        (None, Some(dv)) => format!("{product_label} {dv} (Build {kernel_release})"),
        (None, None) => format!("{product_label} (Build {kernel_release})"),
    };

    Ok(HostKernelInfo {
        os_family: OsFamily::Windows,
        kernel_release,
        os_version,
        cpe23,
        architecture: std::env::consts::ARCH.to_string(),
    })
}

#[cfg(not(windows))]
pub fn detect_windows_kernel() -> Result<HostKernelInfo, PatcherError> {
    Err(PatcherError::UnsupportedPlatform(
        "Windows detection invoked on non-Windows host".to_string(),
    ))
}
