//! macOS host kernel discovery using `libc::sysctlbyname`.

#[cfg(target_os = "macos")]
use super::super::cpe::{canonicalize_macos_version, Cpe23};
use super::super::error::PatcherError;
#[cfg(target_os = "macos")]
use super::super::types::OsFamily;
use super::super::types::{HostKernelInfo, OsSecurityPosture, RebootPendingStatus};

#[cfg(target_os = "macos")]
pub fn sysctl_string(name: &str) -> Result<String, PatcherError> {
    use std::ffi::CString;
    use std::ptr;

    let c_name = CString::new(name)
        .map_err(|e| PatcherError::DetectionFailed(format!("Invalid sysctl name '{name}': {e}")))?;

    let mut size: libc::size_t = 0;
    let ret = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            ptr::null_mut(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size == 0 {
        return Err(PatcherError::DetectionFailed(format!(
            "sysctlbyname('{name}') failed to query size: errno={}",
            std::io::Error::last_os_error()
        )));
    }

    let mut buf = vec![0u8; size];
    let ret = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return Err(PatcherError::DetectionFailed(format!(
            "sysctlbyname('{name}') failed to retrieve value: errno={}",
            std::io::Error::last_os_error()
        )));
    }

    while buf.last() == Some(&0) {
        buf.pop();
    }
    String::from_utf8(buf).map_err(|e| {
        PatcherError::DetectionFailed(format!("sysctlbyname('{name}') returned non-UTF8: {e}"))
    })
}

#[cfg(target_os = "macos")]
pub fn detect_macos_host_kernel() -> Result<HostKernelInfo, PatcherError> {
    let kernel_release = sysctl_string("kern.osrelease")?;
    let os_version = sysctl_string("kern.osproductversion")
        .map(|v| canonicalize_macos_version(&v))
        .unwrap_or_else(|_| {
            // Darwin math fallback: Darwin 20+ -> macOS (Darwin - 9)
            if let Some(major) = kernel_release
                .split('.')
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|&m| m >= 20)
            {
                return format!("{}.0", major - 9);
            }
            "14.0".to_string()
        });

    let cpe = Cpe23::new_os("apple", "macos", &os_version);
    let cpe23 = cpe.to_formatted_string();

    Ok(HostKernelInfo {
        os_family: OsFamily::MacOS,
        kernel_release,
        os_version,
        cpe23,
        architecture: std::env::consts::ARCH.to_string(),
    })
}

/// Pure analyzer for macOS SIP (`csrutil status`), Rapid Security Response (RSR),
/// and `softwareupdate --list` reboot-pending posture (cross-OS testable).
#[must_use]
pub fn parse_macos_posture(
    kernel_release: &str,
    os_product_version: Option<&str>,
    csrutil_output: Option<&str>,
    pending_updates_output: Option<&str>,
) -> (OsSecurityPosture, RebootPendingStatus) {
    let sip_enabled = csrutil_output.and_then(|out| {
        let lower = out.to_ascii_lowercase();
        if lower.contains("enabled") {
            Some(true)
        } else if lower.contains("disabled") {
            Some(false)
        } else {
            None
        }
    });

    let rsr_version = os_product_version.and_then(|ver| {
        let trimmed = ver.trim();
        if trimmed.contains('(') && trimmed.contains(')') {
            Some(trimmed.to_string())
        } else {
            None
        }
    });

    let mut reasons = Vec::new();
    if let Some(updates) = pending_updates_output {
        let lower = updates.to_ascii_lowercase();
        if lower.contains("[restart]") || lower.contains("restart required") {
            reasons.push("softwareupdate indicates [restart] required".to_string());
        }
    }

    let reboot_required = !reasons.is_empty();
    let posture = OsSecurityPosture {
        sip_enabled,
        rsr_version,
        ..Default::default()
    };
    let reboot = RebootPendingStatus {
        reboot_required,
        running_kernel: kernel_release.to_string(),
        newest_installed_kernel: None,
        reasons,
        livepatch_mitigated: false,
        shield_locked_until_reboot: reboot_required,
    };
    (posture, reboot)
}

#[cfg(target_os = "macos")]
fn run_pinned_macos_probe(path: &str, args: &[&str], timeout_secs: u64) -> Option<String> {
    use std::io::Read;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    if super::super::validation::verify_pinned_binary_path(path).is_err() {
        return None;
    }
    let mut child = std::process::Command::new(path)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let out_handle = child.stdout.take().map(|mut p| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = p.read_to_end(&mut buf);
            buf
        })
    });
    let err_handle = child.stderr.take().map(|mut p| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = p.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(h) = out_handle {
                    let _ = h.join();
                }
                if let Some(h) = err_handle {
                    let _ = h.join();
                }
                return None;
            }
        }
    }

    let out_buf = out_handle.and_then(|h| h.join().ok()).unwrap_or_default();
    let err_buf = err_handle.and_then(|h| h.join().ok()).unwrap_or_default();
    let mut combined = String::from_utf8_lossy(&out_buf).into_owned();
    if !err_buf.is_empty() {
        if !combined.is_empty() {
            combined.push('\n');
        }
        combined.push_str(&String::from_utf8_lossy(&err_buf));
    }
    Some(combined)
}

#[cfg(target_os = "macos")]
pub fn query_macos_posture(
    kernel_release: &str,
    os_product_version: Option<&str>,
) -> (OsSecurityPosture, RebootPendingStatus) {
    let csr_out = run_pinned_macos_probe("/usr/bin/csrutil", &["status"], 3);
    let updates_out = run_pinned_macos_probe("/usr/sbin/softwareupdate", &["--list"], 5);

    parse_macos_posture(
        kernel_release,
        os_product_version,
        csr_out.as_deref(),
        updates_out.as_deref(),
    )
}

#[cfg(not(target_os = "macos"))]
pub fn detect_macos_host_kernel() -> Result<HostKernelInfo, PatcherError> {
    Err(PatcherError::UnsupportedPlatform(
        "macOS detection invoked on non-macOS host".to_string(),
    ))
}
