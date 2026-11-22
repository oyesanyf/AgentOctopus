//! FreeBSD, OpenBSD, and NetBSD host kernel discovery and posture analysis.

use super::super::cpe::bsd_cpe23;
use super::super::error::PatcherError;
use super::super::types::{HostKernelInfo, OsFamily, OsSecurityPosture, RebootPendingStatus};

/// Pure parser for FreeBSD host kernel metadata (cross-OS unit testable).
#[must_use]
pub fn parse_freebsd_kernel_info(kernel_release: &str, arch: &str) -> HostKernelInfo {
    let clean_rel = kernel_release.trim().to_string();
    let cpe23 = bsd_cpe23(&OsFamily::FreeBSD, &clean_rel)
        .unwrap_or_else(|| "cpe:2.3:o:freebsd:freebsd:*:*:*:*:*:*:*:*".to_string());
    HostKernelInfo {
        os_family: OsFamily::FreeBSD,
        os_version: clean_rel.clone(),
        kernel_release: clean_rel,
        cpe23,
        architecture: arch.to_string(),
    }
}

/// Pure parser for OpenBSD host kernel metadata (cross-OS unit testable).
#[must_use]
pub fn parse_openbsd_kernel_info(kernel_release: &str, arch: &str) -> HostKernelInfo {
    let clean_rel = kernel_release.trim().to_string();
    let cpe23 = bsd_cpe23(&OsFamily::OpenBSD, &clean_rel)
        .unwrap_or_else(|| "cpe:2.3:o:openbsd:openbsd:*:*:*:*:*:*:*:*".to_string());
    HostKernelInfo {
        os_family: OsFamily::OpenBSD,
        os_version: clean_rel.clone(),
        kernel_release: clean_rel,
        cpe23,
        architecture: arch.to_string(),
    }
}

/// Pure parser for NetBSD host kernel metadata (cross-OS unit testable).
#[must_use]
pub fn parse_netbsd_kernel_info(kernel_release: &str, arch: &str) -> HostKernelInfo {
    let clean_rel = kernel_release.trim().to_string();
    let cpe23 = bsd_cpe23(&OsFamily::NetBSD, &clean_rel)
        .unwrap_or_else(|| "cpe:2.3:o:netbsd:netbsd:*:*:*:*:*:*:*:*".to_string());
    HostKernelInfo {
        os_family: OsFamily::NetBSD,
        os_version: clean_rel.clone(),
        kernel_release: clean_rel,
        cpe23,
        architecture: arch.to_string(),
    }
}

/// Pure analyzer for BSD staged kernel update / reboot-pending posture.
#[must_use]
pub fn parse_bsd_reboot_pending(
    running_kernel: &str,
    staged_update_marker: bool,
    syspatch_pending_output: Option<&str>,
    kern_securelevel: Option<i32>,
) -> (OsSecurityPosture, RebootPendingStatus) {
    let mut reasons = Vec::new();
    if staged_update_marker {
        reasons.push("staged BSD kernel update pending reboot".to_string());
    }
    if let Some(out) = syspatch_pending_output {
        let lower = out.to_ascii_lowercase();
        if lower.contains("reboot") || lower.contains("new kernel") {
            reasons.push("syspatch/freebsd-update requires reboot for new kernel".to_string());
        }
    }
    let reboot_required = !reasons.is_empty();
    let posture = OsSecurityPosture {
        kern_securelevel,
        ..Default::default()
    };
    let reboot = RebootPendingStatus {
        reboot_required,
        running_kernel: running_kernel.to_string(),
        newest_installed_kernel: None,
        reasons,
        livepatch_mitigated: false,
        shield_locked_until_reboot: reboot_required,
    };
    (posture, reboot)
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
fn run_pinned_bsd_probe(candidates: &[&str], args: &[&str]) -> Option<String> {
    use std::process::Stdio;
    for path in candidates {
        if super::super::validation::verify_pinned_binary_path(path).is_err() {
            continue;
        }
        if let Ok(out) = std::process::Command::new(path)
            .args(args)
            .env_clear()
            .env("PATH", "/sbin:/usr/sbin:/bin:/usr/bin")
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .output()
        {
            if out.status.success() {
                return Some(String::from_utf8_lossy(&out.stdout).to_string());
            }
        }
    }
    None
}

/// Probes live BSD `kern.securelevel` and pending kernel-update/reboot markers.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub fn query_bsd_posture(running_kernel: &str) -> (OsSecurityPosture, RebootPendingStatus) {
    let kern_securelevel = run_pinned_bsd_probe(
        &["/sbin/sysctl", "/usr/sbin/sysctl"],
        &["-n", "kern.securelevel"],
    )
    .and_then(|s| s.trim().parse::<i32>().ok());

    let mut staged_marker = std::path::Path::new("/var/run/reboot-required").exists();
    #[allow(unused_mut)]
    let mut pending_output: Option<String> = None;

    #[cfg(target_os = "freebsd")]
    {
        if let Ok(entries) = std::fs::read_dir("/var/db/freebsd-update") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                if name.contains("install.") || name.contains("staged") || name.contains("reboot") {
                    staged_marker = true;
                    break;
                }
            }
        }
        if let Some(kver) = run_pinned_bsd_probe(&["/bin/freebsd-version"], &["-k"]) {
            let trimmed = kver.trim();
            if !trimmed.is_empty()
                && !running_kernel.trim().is_empty()
                && trimmed != running_kernel.trim()
            {
                staged_marker = true;
            }
        }
    }

    #[cfg(target_os = "openbsd")]
    {
        if std::path::Path::new("/var/run/syspatch.reboot").exists()
            || std::path::Path::new("/var/syspatch/.needs_reboot").exists()
        {
            staged_marker = true;
        }
        pending_output = run_pinned_bsd_probe(&["/usr/sbin/syspatch"], &["-c"]);
    }

    #[cfg(target_os = "netbsd")]
    {
        if std::path::Path::new("/var/db/pkgin/reboot-required").exists() {
            staged_marker = true;
        }
        if let Ok(entries) = std::fs::read_dir("/var/cache/sysupgrade") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                if (name.starts_with("kern-") || name.starts_with("netbsd-"))
                    && (name.ends_with(".tgz") || name.ends_with(".tar.xz"))
                {
                    staged_marker = true;
                    break;
                }
            }
        }
    }

    parse_bsd_reboot_pending(
        running_kernel,
        staged_marker,
        pending_output.as_deref(),
        kern_securelevel,
    )
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub fn detect_bsd_host_kernel() -> Result<HostKernelInfo, PatcherError> {
    let release = unsafe {
        let mut uts = std::mem::zeroed::<libc::utsname>();
        if libc::uname(&mut uts) != 0 {
            return Err(PatcherError::DetectionFailed(
                "BSD uname syscall failed".to_string(),
            ));
        }
        std::ffi::CStr::from_ptr(uts.release.as_ptr())
            .to_string_lossy()
            .trim()
            .to_string()
    };
    let arch = std::env::consts::ARCH;
    #[cfg(target_os = "freebsd")]
    {
        Ok(parse_freebsd_kernel_info(&release, arch))
    }
    #[cfg(target_os = "openbsd")]
    {
        Ok(parse_openbsd_kernel_info(&release, arch))
    }
    #[cfg(target_os = "netbsd")]
    {
        Ok(parse_netbsd_kernel_info(&release, arch))
    }
}

#[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
pub fn detect_bsd_host_kernel() -> Result<HostKernelInfo, PatcherError> {
    Err(PatcherError::UnsupportedPlatform(
        "BSD detection invoked on non-BSD host".to_string(),
    ))
}
