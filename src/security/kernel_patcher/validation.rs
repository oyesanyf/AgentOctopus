//! Strict input allowlists, environment scrubbing, and pinned system binary verification
//! (Foolproof Invariant #2: Zero Shell Injection, Zero PATH Hijack, Zero Env Poisoning).

use super::cpe::split_unescaped_colons;
use super::error::PatcherError;
use super::types::OsFamily;
use std::path::Path;

/// Environment variables stripped before invoking any elevated OS patch binary.
pub const UNTRUSTED_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "BASH_ENV",
    "ENV",
    "CDPATH",
    "IFS",
    "PROMPT_COMMAND",
    "PYTHONPATH",
    "PERL5OPT",
    "RUBYOPT",
];

const FORBIDDEN_SHELL_BASENAMES: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "csh",
    "tcsh",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
];

const WINDOWS_TRUSTED_PREFIXES: &[&str] = &[r"C:\Windows\System32\"];

const UNIX_TRUSTED_PREFIXES: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/snap/bin/",
    "/run/current-system/sw/bin/",
    "/usr/pkg/sbin/",
];

/// Validates `/etc/os-release` `ID` / `ID_LIKE` tokens against `[a-zA-Z0-9._-]`, length `1..=64`.
pub fn validate_os_release_token(raw: &str, field: &str) -> Result<String, PatcherError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid os-release field '{field}': length {} out of bounds (1..=64)",
            trimmed.len()
        )));
    }
    if trimmed.contains("..") {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid os-release field '{field}': path traversal sequence '..' forbidden"
        )));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid os-release field '{field}': disallowed characters in '{trimmed}'"
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Validates a kernel release string (`uname -r`) against `[A-Za-z0-9._+-]`, length `1..=128`.
pub fn validate_kernel_release(raw: &str) -> Result<String, PatcherError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid kernel release: length {} out of bounds (1..=128)",
            trimmed.len()
        )));
    }
    if trimmed.starts_with('-') || trimmed.contains("..") {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid kernel release '{trimmed}': leading '-' or '..' forbidden"
        )));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid kernel release '{trimmed}': disallowed characters"
        )));
    }
    Ok(trimmed.to_string())
}

/// Validates an OS package name (`[A-Za-z0-9._+-]`, at most one `/` for Gentoo category/pkg).
pub fn validate_package_name(raw: &str) -> Result<String, PatcherError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid package name: length {} out of bounds (1..=128)",
            trimmed.len()
        )));
    }
    if trimmed.starts_with('-') || trimmed.starts_with('/') || trimmed.ends_with('/') {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid package name '{trimmed}': invalid boundary character"
        )));
    }
    if trimmed.contains("..") {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid package name '{trimmed}': '..' forbidden"
        )));
    }
    let slash_count = trimmed.bytes().filter(|&b| b == b'/').count();
    if slash_count > 1 {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid package name '{trimmed}': at most one '/' allowed"
        )));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-' | b'/'))
    {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid package name '{trimmed}': disallowed characters"
        )));
    }
    Ok(trimmed.to_string())
}

/// Validates exact `CVE-YYYY-NNNN+` format (`CVE-` + 4 digits + `-` + 4..=8 digits).
pub fn validate_cve_id(raw: &str) -> Result<String, PatcherError> {
    let trimmed = raw.trim();
    let Some(rest) = trimmed.strip_prefix("CVE-") else {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid CVE ID '{trimmed}': must start with 'CVE-'"
        )));
    };
    let Some((year, seq)) = rest.split_once('-') else {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid CVE ID '{trimmed}': missing sequence separator"
        )));
    };
    if year.len() != 4 || !year.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid CVE ID '{trimmed}': invalid 4-digit year"
        )));
    }
    if !(4..=8).contains(&seq.len()) || !seq.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid CVE ID '{trimmed}': invalid sequence digits"
        )));
    }
    Ok(trimmed.to_string())
}

/// Validates a NIST IR 7695 CPE 2.3 formatted string (`cpe:2.3:[aho]:...` with 13 components).
pub fn validate_cpe23(raw: &str) -> Result<String, PatcherError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return Err(PatcherError::InvalidInput(
            "Invalid CPE 2.3: empty or exceeds 256 chars".to_string(),
        ));
    }
    if !(trimmed.starts_with("cpe:2.3:o:")
        || trimmed.starts_with("cpe:2.3:a:")
        || trimmed.starts_with("cpe:2.3:h:"))
    {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid CPE 2.3 '{trimmed}': must start with cpe:2.3:o:/a:/h:"
        )));
    }
    if !trimmed.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b':' | b'.' | b'_' | b'-' | b'*' | b'+' | b'~')
    }) || trimmed.contains("..")
    {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid CPE 2.3 '{trimmed}': forbidden characters or '..'"
        )));
    }
    let parts = split_unescaped_colons(trimmed);
    if parts.len() != 13 || parts.iter().any(|p| p.is_empty()) {
        return Err(PatcherError::InvalidInput(format!(
            "Invalid CPE 2.3 '{trimmed}': expected 13 non-empty components, found {}",
            parts.len()
        )));
    }
    Ok(trimmed.to_string())
}

/// Clears process environment and applies pinned, minimal PATH + OS locale + allowlisted extras.
pub fn apply_scrubbed_env(
    cmd: &mut tokio::process::Command,
    os_family: &OsFamily,
    extra_env: &[(&str, &str)],
) -> Result<(), PatcherError> {
    cmd.env_clear();
    match os_family {
        OsFamily::Windows => {
            let system_root = std::env::var("SystemRoot")
                .ok()
                .filter(|v| v.eq_ignore_ascii_case(r"C:\Windows"))
                .unwrap_or_else(|| r"C:\Windows".to_string());
            cmd.env("PATH", r"C:\Windows\System32;C:\Windows")
                .env("SYSTEMROOT", &system_root)
                .env("WINDIR", &system_root)
                .env("PATHEXT", ".EXE;.COM");
        }
        _ => {
            cmd.env(
                "PATH",
                "/usr/sbin:/usr/bin:/sbin:/bin:/run/current-system/sw/bin:/usr/pkg/sbin",
            )
            .env("LC_ALL", "C")
            .env("LANG", "C");
        }
    }

    for &(k, v) in extra_env {
        let key_upper = k.trim().to_ascii_uppercase();
        if key_upper == "PATH"
            || UNTRUSTED_ENV_VARS
                .iter()
                .any(|u| u.eq_ignore_ascii_case(&key_upper))
        {
            return Err(PatcherError::InvalidInput(format!(
                "Refusing to inject untrusted environment variable '{k}'"
            )));
        }
        if v.chars().any(|c| c == '\0' || c == '\n' || c == '\r') {
            return Err(PatcherError::InvalidInput(format!(
                "Environment variable '{k}' contains control characters"
            )));
        }
        cmd.env(k, v);
    }
    Ok(())
}

/// Validates that `path` is a pinned absolute trusted system binary (never a shell, never `/tmp`,
/// never symlinked outside trusted prefixes, and not world-writable on Unix).
pub fn verify_pinned_binary_path(path: &str) -> Result<(), PatcherError> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed.contains("..") {
        return Err(PatcherError::UntrustedOrMissingBinary(format!(
            "Invalid binary path '{path}'"
        )));
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("/tmp/")
        || lower.starts_with("/var/tmp/")
        || lower.contains("\\temp\\")
        || lower.contains("\\appdata\\")
    {
        return Err(PatcherError::UntrustedOrMissingBinary(format!(
            "Binary path '{path}' resides in untrusted temporary location"
        )));
    }

    let has_trusted_prefix = if is_windows_pinned_path(trimmed) {
        WINDOWS_TRUSTED_PREFIXES
            .iter()
            .any(|p| lower.starts_with(&p.to_ascii_lowercase()))
    } else {
        UNIX_TRUSTED_PREFIXES.iter().any(|p| trimmed.starts_with(p))
    };

    if !has_trusted_prefix {
        return Err(PatcherError::UntrustedOrMissingBinary(format!(
            "Binary path '{path}' is not under a pinned system prefix"
        )));
    }

    let file_name = Path::new(trimmed)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if FORBIDDEN_SHELL_BASENAMES.contains(&file_name.as_str()) {
        return Err(PatcherError::UntrustedOrMissingBinary(format!(
            "Refusing shell interpreter '{path}' in kernel patcher"
        )));
    }

    let p = Path::new(trimmed);
    let sym_meta = std::fs::symlink_metadata(p).map_err(|_| {
        PatcherError::UntrustedOrMissingBinary(format!("Pinned binary missing on host: '{path}'"))
    })?;

    let canon = std::fs::canonicalize(p).map_err(|_| {
        PatcherError::UntrustedOrMissingBinary(format!(
            "Failed to resolve canonical path for pinned binary '{path}'"
        ))
    })?;
    let canon_raw = canon.to_string_lossy();
    let canon_normalized = canon_raw.strip_prefix(r"\\?\").unwrap_or(&canon_raw);
    let canon_lower = canon_normalized.to_ascii_lowercase();

    if canon_normalized.contains("..")
        || canon_lower.starts_with("/tmp/")
        || canon_lower.starts_with("/var/tmp/")
        || canon_lower.contains("\\temp\\")
        || canon_lower.contains("\\appdata\\")
    {
        return Err(PatcherError::UntrustedOrMissingBinary(format!(
            "Canonical binary target '{canon_normalized}' resides in untrusted location"
        )));
    }

    let canon_file_name = Path::new(canon_normalized)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if FORBIDDEN_SHELL_BASENAMES.contains(&canon_file_name.as_str()) {
        return Err(PatcherError::UntrustedOrMissingBinary(format!(
            "Refusing canonical shell interpreter target '{canon_normalized}' for '{path}'"
        )));
    }

    if sym_meta.file_type().is_symlink() {
        let is_nixos_store_target = trimmed.starts_with("/run/current-system/sw/bin/")
            && canon_normalized.starts_with("/nix/store/")
            && !canon_normalized.contains("..");
        let target_trusted = if is_windows_pinned_path(canon_normalized) {
            WINDOWS_TRUSTED_PREFIXES
                .iter()
                .any(|pref| canon_lower.starts_with(&pref.to_ascii_lowercase()))
        } else {
            is_nixos_store_target
                || UNIX_TRUSTED_PREFIXES
                    .iter()
                    .any(|pref| canon_normalized.starts_with(pref))
        };
        if !target_trusted {
            return Err(PatcherError::UntrustedOrMissingBinary(format!(
                "Symlink target '{canon_normalized}' escapes trusted system prefixes"
            )));
        }
    }

    let meta = std::fs::metadata(p).map_err(|_| {
        PatcherError::UntrustedOrMissingBinary(format!("Cannot stat pinned binary '{path}'"))
    })?;
    if !meta.is_file() {
        return Err(PatcherError::UntrustedOrMissingBinary(format!(
            "Pinned binary path '{path}' is not a regular file"
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if (mode & 0o002) != 0 {
            return Err(PatcherError::UntrustedOrMissingBinary(format!(
                "Pinned binary '{path}' is world-writable (mode {mode:o})"
            )));
        }
    }

    Ok(())
}

fn is_windows_pinned_path(path: &str) -> bool {
    path.len() >= 3 && path.as_bytes()[1] == b':' && (path.contains('\\') || path.contains('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_cpe23_strict_allowlist() {
        assert!(validate_cpe23("cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*").is_ok());
        assert!(validate_cpe23("cpe:2.3:o:canonical:ubuntu_linux:24.04:*:*:*:*:*:*:*").is_ok());
        for bad in [
            "cpe:2.3:o:linux:linux_kernel:$(whoami):*:*:*:*:*:*:*",
            "cpe:2.3:o:linux:linux_kernel:6.8.0;id:*:*:*:*:*:*:*",
            "cpe:2.3:o:linux:linux_kernel:6.8.0|sh:*:*:*:*:*:*:*",
            "cpe:2.3:o:linux:linux_kernel:6.8.0'foo:*:*:*:*:*:*:*",
            "cpe:2.3:o:linux:linux_kernel:6.8.0\"foo:*:*:*:*:*:*:*",
            "cpe:2.3:o:linux:linux_kernel:..:*:*:*:*:*:*:*",
            "cpe:2.3:o:linux:linux_kernel::*:*:*:*:*:*:*",
        ] {
            assert!(validate_cpe23(bad).is_err(), "must reject bad CPE: {bad}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_verify_pinned_binary_path_windows_system32() {
        let cmd_path = r"C:\Windows\System32\cmd.exe";
        let err = verify_pinned_binary_path(cmd_path).expect_err("shell must be refused");
        assert!(matches!(err, PatcherError::UntrustedOrMissingBinary(_)));

        let where_exe = r"C:\Windows\System32\where.exe";
        if std::path::Path::new(where_exe).is_file() {
            assert!(verify_pinned_binary_path(where_exe).is_ok());
        }
    }
}
