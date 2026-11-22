//! Host operating system and kernel discovery across Linux, Windows, macOS, and BSD.

pub mod bsd;
pub mod linux;
pub mod macos;
pub mod windows;

use super::cpe::{
    canonicalize_linux_kernel_version, canonicalize_macos_version, canonicalize_windows_cpe, Cpe23,
};
use super::error::PatcherError;
use super::types::{HostKernelInfo, HostKernelPostureSnapshot, OsFamily};

/// Returns the compile-time host CPU architecture.
#[inline]
#[must_use]
pub fn detect_architecture() -> String {
    std::env::consts::ARCH.to_string()
}

/// Dispatches kernel detection to the current operating system platform.
pub fn detect_host_kernel() -> Result<HostKernelInfo, PatcherError> {
    #[cfg(target_os = "windows")]
    {
        windows::detect_windows_kernel()
    }
    #[cfg(target_os = "linux")]
    {
        linux::detect_linux_host_kernel()
    }
    #[cfg(target_os = "macos")]
    {
        macos::detect_macos_host_kernel()
    }
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        bsd::detect_bsd_host_kernel()
    }
    #[cfg(not(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        Err(PatcherError::UnsupportedPlatform(
            std::env::consts::OS.to_string(),
        ))
    }
}

/// Probes host kernel, Linux distro CPE, livepatch state, reboot-pending state, and OS hardening posture.
pub fn detect_host_posture_snapshot() -> Result<HostKernelPostureSnapshot, PatcherError> {
    let host_kernel = detect_host_kernel()?;

    #[cfg(target_os = "linux")]
    {
        let os_release = linux::detect_linux_os_release();
        let distro = linux::classify_linux_distro(&os_release);
        let distro_cpe23 = super::cpe::linux_distro_cpe23(&distro, &os_release.version_id);
        let livepatch = linux::detect_linux_livepatch_sysfs();
        let reboot_pending =
            linux::detect_linux_reboot_pending(&host_kernel.kernel_release, &livepatch);
        let security_posture = linux::detect_linux_security_posture(&livepatch);
        Ok(HostKernelPostureSnapshot {
            host_kernel,
            distro: Some(distro),
            distro_cpe23,
            livepatch,
            reboot_pending,
            security_posture,
        })
    }

    #[cfg(target_os = "windows")]
    {
        let (security_posture, reboot_pending, livepatch) =
            windows::query_windows_posture(&host_kernel.kernel_release);
        Ok(HostKernelPostureSnapshot {
            host_kernel,
            distro: None,
            distro_cpe23: None,
            livepatch,
            reboot_pending,
            security_posture,
        })
    }

    #[cfg(target_os = "macos")]
    {
        let prod_ver = macos::sysctl_string("kern.osproductversion").ok();
        let (security_posture, reboot_pending) =
            macos::query_macos_posture(&host_kernel.kernel_release, prod_ver.as_deref());
        Ok(HostKernelPostureSnapshot {
            host_kernel,
            distro: None,
            distro_cpe23: None,
            livepatch: super::types::LivepatchStatus::default(),
            reboot_pending,
            security_posture,
        })
    }

    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        let (security_posture, reboot_pending) =
            bsd::query_bsd_posture(&host_kernel.kernel_release);
        Ok(HostKernelPostureSnapshot {
            host_kernel,
            distro: None,
            distro_cpe23: None,
            livepatch: super::types::LivepatchStatus::default(),
            reboot_pending,
            security_posture,
        })
    }

    #[cfg(not(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        Ok(HostKernelPostureSnapshot {
            reboot_pending: super::types::RebootPendingStatus {
                running_kernel: host_kernel.kernel_release.clone(),
                ..Default::default()
            },
            host_kernel,
            distro: None,
            distro_cpe23: None,
            livepatch: super::types::LivepatchStatus::default(),
            security_posture: super::types::OsSecurityPosture::default(),
        })
    }
}

/// Pure parser for Linux kernel discovery metadata (decoupled for cross-OS testing).
#[must_use]
pub fn parse_linux_kernel_info(
    kernel_release: &str,
    os_release_content: Option<&str>,
    arch: &str,
) -> HostKernelInfo {
    let os_release = os_release_content
        .map(linux::parse_os_release_content)
        .unwrap_or_default();

    let base_version = canonicalize_linux_kernel_version(kernel_release);
    let cpe = Cpe23::new_os("linux", "linux_kernel", base_version);
    let cpe23 = cpe.to_formatted_string();

    let os_version = if !os_release.version_id.is_empty() {
        os_release.version_id
    } else if !os_release.pretty_name.is_empty() {
        os_release.pretty_name
    } else {
        "unknown".to_string()
    };

    HostKernelInfo {
        os_family: OsFamily::Linux,
        kernel_release: kernel_release.trim().to_string(),
        os_version,
        cpe23,
        architecture: arch.to_string(),
    }
}

/// Pure parser for Windows kernel discovery metadata (decoupled for cross-OS testing).
#[must_use]
pub fn parse_windows_kernel_info(
    major: u32,
    minor: u32,
    build: u32,
    ubr: Option<u32>,
    product_name: Option<&str>,
    display_version: Option<&str>,
    arch: &str,
) -> HostKernelInfo {
    let is_server = product_name
        .map(|p| p.to_ascii_lowercase().contains("server"))
        .unwrap_or(false);

    let (cpe_product, cpe_version) = canonicalize_windows_cpe(build, is_server, display_version);
    let cpe = Cpe23::new_os("microsoft", cpe_product, cpe_version);
    let cpe23 = cpe.to_formatted_string();

    let kernel_release = match ubr {
        Some(u) => format!("{major}.{minor}.{build}.{u}"),
        None => format!("{major}.{minor}.{build}"),
    };

    let os_version = match (product_name, display_version) {
        (Some(p), Some(dv)) => format!("{p} {dv} (Build {kernel_release})"),
        (Some(p), None) => format!("{p} (Build {kernel_release})"),
        (None, Some(dv)) => {
            let label = windows_product_label(build, is_server);
            format!("{label} {dv} (Build {kernel_release})")
        }
        (None, None) => {
            let label = windows_product_label(build, is_server);
            format!("{label} (Build {kernel_release})")
        }
    };

    HostKernelInfo {
        os_family: OsFamily::Windows,
        kernel_release,
        os_version,
        cpe23,
        architecture: arch.to_string(),
    }
}

fn windows_product_label(build: u32, is_server: bool) -> &'static str {
    if is_server {
        "Windows Server"
    } else if build >= 22000 {
        "Windows 11"
    } else {
        "Windows 10"
    }
}

/// Pure parser for macOS kernel discovery metadata (decoupled for cross-OS testing).
#[must_use]
pub fn parse_macos_kernel_info(
    os_product_version: Option<&str>,
    kernel_release: &str,
    arch: &str,
) -> HostKernelInfo {
    let os_version = os_product_version
        .map(canonicalize_macos_version)
        .unwrap_or_else(|| {
            if let Some(major_str) = kernel_release.split('.').next() {
                if let Ok(major) = major_str.parse::<u32>() {
                    if major >= 20 {
                        return format!("{}.0", major - 9);
                    }
                }
            }
            "14.0".to_string()
        });

    let cpe = Cpe23::new_os("apple", "macos", &os_version);
    let cpe23 = cpe.to_formatted_string();

    HostKernelInfo {
        os_family: OsFamily::MacOS,
        kernel_release: kernel_release.trim().to_string(),
        os_version,
        cpe23,
        architecture: arch.to_string(),
    }
}
