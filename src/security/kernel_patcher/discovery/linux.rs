//! Linux host kernel discovery via `/proc/sys/kernel/osrelease`, `/etc/os-release`, and `libc::uname`.

#[cfg(target_os = "linux")]
use super::super::cpe::{canonicalize_linux_kernel_version, Cpe23};
use super::super::error::PatcherError;
use super::super::types::{
    HostKernelInfo, LinuxDistro, LivepatchEngine, LivepatchStatus, RebootPendingStatus,
};
#[cfg(target_os = "linux")]
use super::super::types::{OsFamily, OsSecurityPosture};
use super::super::validation::validate_os_release_token;

/// Metadata parsed from `/etc/os-release` or `/usr/lib/os-release`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsRelease {
    pub id: String,
    pub version_id: String,
    pub pretty_name: String,
    pub id_like: Vec<String>,
}

/// Validates `/etc/os-release` `VERSION_ID` against `[A-Za-z0-9._+-]` (max 64 bytes, no `..`).
pub fn validate_os_release_version_id(raw: &str) -> Result<String, PatcherError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.len() > 64 || trimmed.contains("..") {
        return Err(PatcherError::InvalidInput(
            "Invalid VERSION_ID in os-release: out of bounds or contains '..'".to_string(),
        ));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
    {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid VERSION_ID '{trimmed}' in os-release: disallowed characters"
        )));
    }
    Ok(trimmed.to_string())
}

/// Strictly parses `/etc/os-release`, returning `PatcherError::InvalidInput` if `ID` or `ID_LIKE`
/// or `VERSION_ID` contains shell metacharacters or invalid characters (Foolproof Invariant #2).
pub fn parse_os_release_strict(content: &str) -> Result<OsRelease, PatcherError> {
    let mut info = OsRelease::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let mut val = v.trim();
            if ((val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\'')))
                && val.len() >= 2
            {
                val = &val[1..val.len() - 1];
            }
            match key {
                "ID" => {
                    info.id = validate_os_release_token(val, "ID")?;
                }
                "VERSION_ID" => {
                    info.version_id = validate_os_release_version_id(val)?;
                }
                "PRETTY_NAME" => {
                    info.pretty_name = val.chars().filter(|c| !c.is_control()).take(128).collect();
                }
                "ID_LIKE" => {
                    let mut tokens = Vec::new();
                    for tok in val.split_whitespace() {
                        tokens.push(validate_os_release_token(tok, "ID_LIKE")?);
                    }
                    info.id_like = tokens;
                }
                _ => {}
            }
        }
    }
    Ok(info)
}

/// Parses standard freedesktop.org `/etc/os-release` file content, discarding any non-allowlisted
/// `ID`, `VERSION_ID`, or `ID_LIKE` tokens so shell metacharacters never propagate.
#[must_use]
pub fn parse_os_release_content(content: &str) -> OsRelease {
    let mut info = OsRelease::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let mut val = v.trim();
            if ((val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\'')))
                && val.len() >= 2
            {
                val = &val[1..val.len() - 1];
            }
            match key {
                "ID" => {
                    if let Ok(clean) = validate_os_release_token(val, "ID") {
                        info.id = clean;
                    }
                }
                "VERSION_ID" => {
                    if let Ok(clean) = validate_os_release_version_id(val) {
                        info.version_id = clean;
                    }
                }
                "PRETTY_NAME" => {
                    info.pretty_name = val.chars().filter(|c| !c.is_control()).take(128).collect();
                }
                "ID_LIKE" => {
                    info.id_like = val
                        .split_whitespace()
                        .filter_map(|s| validate_os_release_token(s, "ID_LIKE").ok())
                        .collect();
                }
                _ => {}
            }
        }
    }
    info
}

/// Classifies `/etc/os-release` metadata into one of the 17 supported Linux distributions.
#[must_use]
pub fn classify_linux_distro(os_release: &OsRelease) -> LinuxDistro {
    match os_release.id.as_str() {
        "ubuntu" => return LinuxDistro::Ubuntu,
        "debian" => return LinuxDistro::Debian,
        "kali" => return LinuxDistro::Kali,
        "rhel" | "redhat" => return LinuxDistro::Rhel,
        "fedora" => return LinuxDistro::Fedora,
        "rocky" => return LinuxDistro::Rocky,
        "almalinux" | "alma" => return LinuxDistro::Alma,
        "centos" => return LinuxDistro::CentOS,
        "amzn" | "amazon" => return LinuxDistro::AmazonLinux,
        "ol" | "oracle" => return LinuxDistro::OracleLinux,
        "sles" | "sled" | "sle_hpc" => return LinuxDistro::Sles,
        "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "opensuse-microos" => {
            return LinuxDistro::OpenSuse
        }
        "arch" | "archarm" => return LinuxDistro::Arch,
        "alpine" => return LinuxDistro::Alpine,
        "nixos" => return LinuxDistro::NixOS,
        "gentoo" => return LinuxDistro::Gentoo,
        "flatcar" => return LinuxDistro::Flatcar,
        _ => {}
    }

    for like in &os_release.id_like {
        match like.as_str() {
            "ubuntu" => return LinuxDistro::Ubuntu,
            "debian" => return LinuxDistro::Debian,
            "rhel" => return LinuxDistro::Rhel,
            "fedora" => return LinuxDistro::Fedora,
            "suse" | "sles" | "opensuse" => return LinuxDistro::Sles,
            "arch" => return LinuxDistro::Arch,
            "alpine" => return LinuxDistro::Alpine,
            "gentoo" => return LinuxDistro::Gentoo,
            _ => {}
        }
    }

    if os_release.id.is_empty() {
        LinuxDistro::Unknown("linux".to_string())
    } else {
        LinuxDistro::Unknown(os_release.id.clone())
    }
}

/// Pure parser for `/sys/kernel/livepatch/*` `(patch_name, enabled_content)` pairs.
#[must_use]
pub fn parse_sysfs_livepatch_entries(entries: &[(&str, &str)]) -> LivepatchStatus {
    let mut active_patches = Vec::new();
    for &(name, enabled_raw) in entries {
        let val = enabled_raw.trim();
        if val == "1" || val.eq_ignore_ascii_case("true") {
            active_patches.push(name.to_string());
        }
    }
    if active_patches.is_empty() {
        return LivepatchStatus::default();
    }

    let joined_lower = active_patches.join(" ").to_ascii_lowercase();
    let engine = if joined_lower.contains("livepatch") || joined_lower.contains("lkp_") {
        LivepatchEngine::CanonicalLivepatch
    } else if joined_lower.contains("kpatch") {
        LivepatchEngine::Kpatch
    } else if joined_lower.contains("ksplice") || joined_lower.contains("uptrack") {
        LivepatchEngine::KspliceUptrack
    } else if joined_lower.contains("klp") || joined_lower.contains("kgraft") {
        LivepatchEngine::KlpKgraft
    } else {
        LivepatchEngine::SysfsGeneric
    };

    LivepatchStatus {
        engine,
        active_in_ram: true,
        details: format!(
            "Active in-RAM livepatch modules via /sys/kernel/livepatch: {}",
            active_patches.join(", ")
        ),
        sysfs_patches: active_patches,
    }
}

/// Pure analyzer for Linux "Patched on Disk, Still Vulnerable in RAM" pre-reboot gap.
#[must_use]
pub fn parse_linux_reboot_pending(
    running_kernel: &str,
    reboot_required_exists: bool,
    reboot_required_pkgs: &[&str],
    installed_kernels: &[&str],
    livepatch: &LivepatchStatus,
) -> RebootPendingStatus {
    let mut reasons = Vec::new();
    if reboot_required_exists {
        reasons.push("/var/run/reboot-required present".to_string());
    }
    for pkg in reboot_required_pkgs {
        let trimmed = pkg.trim();
        if !trimmed.is_empty() {
            reasons.push(format!("reboot-required.pkgs: {trimmed}"));
        }
    }

    let running_trimmed = running_kernel.trim();
    let mut newest_installed: Option<String> = None;
    for k in installed_kernels {
        let k_trimmed = k.trim();
        if k_trimmed.is_empty() {
            continue;
        }
        let replace = match &newest_installed {
            None => true,
            Some(cur) => compare_kernel_versions(k_trimmed, cur) == std::cmp::Ordering::Greater,
        };
        if replace {
            newest_installed = Some(k_trimmed.to_string());
        }
    }

    if let Some(ref newest) = newest_installed {
        if !running_trimmed.is_empty() && newest != running_trimmed {
            reasons.push(format!(
                "running kernel '{running_trimmed}' differs from newest installed '{newest}'"
            ));
        }
    }

    let reboot_required = !reasons.is_empty();
    let livepatch_mitigated = livepatch.active_in_ram;
    let shield_locked_until_reboot = reboot_required && !livepatch_mitigated;

    RebootPendingStatus {
        reboot_required,
        running_kernel: running_trimmed.to_string(),
        newest_installed_kernel: newest_installed,
        reasons,
        livepatch_mitigated,
        shield_locked_until_reboot,
    }
}

fn compare_kernel_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parse_nums = |s: &str| -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|part| !part.is_empty())
            .filter_map(|part| part.parse::<u64>().ok())
            .collect()
    };
    parse_nums(a).cmp(&parse_nums(b))
}

#[cfg(target_os = "linux")]
pub fn detect_linux_os_release() -> OsRelease {
    use std::fs;
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        return parse_os_release_content(&content);
    }
    if let Ok(content) = fs::read_to_string("/usr/lib/os-release") {
        return parse_os_release_content(&content);
    }
    OsRelease::default()
}

#[cfg(target_os = "linux")]
pub fn detect_linux_kernel_release() -> Result<String, PatcherError> {
    use std::fs;
    if let Ok(content) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        let release = content.trim().to_string();
        if !release.is_empty() {
            return Ok(release);
        }
    }

    // Fallback to libc::uname
    unsafe {
        let mut uts = std::mem::zeroed::<libc::utsname>();
        if libc::uname(&mut uts) != 0 {
            return Err(PatcherError::DetectionFailed(
                "uname syscall failed".to_string(),
            ));
        }
        let c_str = std::ffi::CStr::from_ptr(uts.release.as_ptr());
        let release = c_str.to_string_lossy().trim().to_string();
        if release.is_empty() {
            Err(PatcherError::DetectionFailed(
                "Empty kernel release returned by uname".to_string(),
            ))
        } else {
            Ok(release)
        }
    }
}

#[cfg(target_os = "linux")]
pub fn detect_linux_host_kernel() -> Result<HostKernelInfo, PatcherError> {
    let kernel_release = detect_linux_kernel_release()?;
    let os_release = detect_linux_os_release();
    let base_version = canonicalize_linux_kernel_version(&kernel_release);
    let cpe = Cpe23::new_os("linux", "linux_kernel", base_version);
    let cpe23 = cpe.to_formatted_string();

    let os_version = if !os_release.version_id.is_empty() {
        os_release.version_id
    } else if !os_release.pretty_name.is_empty() {
        os_release.pretty_name
    } else {
        "unknown".to_string()
    };

    Ok(HostKernelInfo {
        os_family: OsFamily::Linux,
        kernel_release,
        os_version,
        cpe23,
        architecture: std::env::consts::ARCH.to_string(),
    })
}

#[cfg(target_os = "linux")]
pub fn detect_linux_livepatch_sysfs() -> LivepatchStatus {
    use std::fs;
    let base = std::path::Path::new("/sys/kernel/livepatch");
    let Ok(read_dir) = fs::read_dir(base) else {
        return LivepatchStatus::default();
    };
    let mut pairs: Vec<(String, String)> = Vec::new();
    for entry in read_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let enabled_path = entry.path().join("enabled");
        if let Ok(val) = fs::read_to_string(enabled_path) {
            pairs.push((name, val));
        }
    }
    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    parse_sysfs_livepatch_entries(&refs)
}

#[cfg(target_os = "linux")]
pub fn detect_linux_reboot_pending(
    running_kernel: &str,
    livepatch: &LivepatchStatus,
) -> RebootPendingStatus {
    use std::fs;
    let reboot_required_exists = std::path::Path::new("/var/run/reboot-required").exists();
    let pkgs_raw = fs::read_to_string("/var/run/reboot-required.pkgs").unwrap_or_default();
    let pkgs: Vec<&str> = pkgs_raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    let mut installed = Vec::new();
    if let Ok(entries) = fs::read_dir("/lib/modules") {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                installed.push(entry.file_name().to_string_lossy().to_string());
            }
        }
    }
    if let Ok(entries) = fs::read_dir("/boot") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(ver) = name.strip_prefix("vmlinuz-") {
                if !installed.iter().any(|k| k == ver) {
                    installed.push(ver.to_string());
                }
            }
        }
    }
    let installed_refs: Vec<&str> = installed.iter().map(String::as_str).collect();
    parse_linux_reboot_pending(
        running_kernel,
        reboot_required_exists,
        &pkgs,
        &installed_refs,
        livepatch,
    )
}

#[cfg(target_os = "linux")]
pub fn detect_linux_security_posture(livepatch: &LivepatchStatus) -> OsSecurityPosture {
    let lockdown_mode = std::fs::read_to_string("/sys/kernel/security/lockdown")
        .ok()
        .and_then(|raw| {
            raw.split_whitespace()
                .find(|tok| tok.starts_with('[') && tok.ends_with(']'))
                .map(|tok| tok.trim_matches(&['[', ']'][..]).to_string())
        });
    OsSecurityPosture {
        lockdown_mode,
        livepatch_sysfs_count: livepatch.sysfs_patches.len(),
        ..Default::default()
    }
}

#[cfg(not(target_os = "linux"))]
pub fn detect_linux_host_kernel() -> Result<HostKernelInfo, PatcherError> {
    Err(PatcherError::UnsupportedPlatform(
        "Linux detection invoked on non-Linux host".to_string(),
    ))
}
