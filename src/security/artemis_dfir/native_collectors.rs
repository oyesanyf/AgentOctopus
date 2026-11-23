//! Native Zero-Dependency Cross-OS DFIR Collectors for ABIBO Break-In & Break-Out Detection.
//!
//! Runs in parallel (`rayon`) with bounded reads across:
//! - Agent instruction & persistent memory files (`.cursorrules`, `CLAUDE.md`, `AGENTS.md`, `SKILL.md`, `MEMORY.md`)
//! - Windows Mark-of-the-Web (`Zone.Identifier` ADS), Run/RunOnce registry keys, Startup folder, Scheduled Tasks XML, Prefetch (`*.pf`)
//! - Linux systemd user timers/services, cron directories, shell startup files
//! - macOS LaunchAgents / LaunchDaemons plist XML and `com.apple.quarantine` attributes
//! - Local MCP connector configuration inventory (flagging write-capable scopes & redacting inline secrets)

use super::liveness::unix_now_secs;
use super::types::{
    AbiboDirection, ArtemisForensicEvent, ForensicArtifactKind, ForensicSeverity,
    McpConnectorAuditEntry, PersistenceArtifactFinding, WindowsPrefetchHeader,
};
use crate::security::log_sanitizer::LogSanitizer;
use chrono::Utc;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const MAX_READ_BYTES: u64 = 512 * 1024; // 512 KiB strict cap per inspected forensic artifact

const SUSPICIOUS_EXEC_MARKERS: &[&str] = &[
    "powershell",
    "pwsh",
    "cmd.exe",
    "mshta",
    "wscript",
    "cscript",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "curl ",
    "wget ",
    "nc -e",
    "/tmp/",
    "\\temp\\",
    "appdata\\local\\temp",
    "base64",
    "-enc ",
    "-encodedcommand",
];

const WRITE_CAPABLE_MCP_TOKENS: &[&str] = &[
    "gmail",
    "calendar",
    "slack",
    "github",
    "notion",
    "filesystem",
    "shell",
    "terminal",
    "exec",
    "bash",
    "powershell",
    "write",
    "postgres",
    "sqlite",
    "email",
    "jira",
    "linear",
    "drive",
    "sheets",
];

const SECRET_ENV_KEY_TOKENS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "API_KEY",
    "APIKEY",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "PRIVATE_KEY",
    "OAUTH",
    "AUTH",
];

const INSTRUCTION_INJECTION_PATTERNS: &[&str] = &[
    "ignore previous instructions",
    "ignore all prior instructions",
    "disregard all prior",
    "exfiltrate",
    "send to webhook",
    "discord.com/api/webhooks",
    "curl -x post",
    "curl --data",
    "invoke-webrequest",
    "<|im_start|>",
    "<|system|>",
    "read ~/.ssh",
    "id_rsa",
    ".aws/credentials",
    "override system policy",
];

/// Parses a Windows Prefetch (`*.pf`) binary header (both uncompressed SCCA v17/23/26/30
/// and Windows 10/11 `MAM\x04` compressed Prefetch headers) in pure Rust.
#[must_use]
pub fn parse_windows_prefetch_header(bytes: &[u8]) -> Option<WindowsPrefetchHeader> {
    if bytes.len() < 8 {
        return None;
    }
    // Windows 10/11 compressed Prefetch magic: "MAM\x04"
    if &bytes[0..4] == b"MAM\x04" {
        return Some(WindowsPrefetchHeader {
            format_version: 30,
            compressed_mam: true,
            executable_name: "(MAM-compressed)".to_string(),
            run_count: None,
        });
    }
    // Uncompressed SCCA header: bytes[0..4] = version (17, 23, 26, 30), bytes[4..8] = "SCCA"
    if &bytes[4..8] != b"SCCA" || bytes.len() < 84 {
        return None;
    }
    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    // Executable name is UTF-16LE at offset 16..76 (60 bytes = 30 u16 chars)
    let mut utf16_chars = Vec::with_capacity(30);
    for chunk in bytes[16..76].chunks_exact(2) {
        let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
        if ch == 0 {
            break;
        }
        utf16_chars.push(ch);
    }
    let executable_name = String::from_utf16_lossy(&utf16_chars).trim().to_string();
    // Run count offset varies by Prefetch format version (v17: 144, v23: 152, v26/v30: 208)
    let run_count_offset = match version {
        17 => Some(144usize),
        23 => Some(152usize),
        26 | 30 => Some(208usize),
        _ => None,
    };
    let run_count = run_count_offset.and_then(|off| {
        if bytes.len() >= off + 4 {
            Some(u32::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
            ]))
        } else {
            None
        }
    });
    Some(WindowsPrefetchHeader {
        format_version: version,
        compressed_mam: false,
        executable_name,
        run_count,
    })
}

/// Checks whether a Windows file has an NTFS `Zone.Identifier` Alternate Data Stream
/// indicating internet origin (`ZoneId=3` or `ZoneId=4`, Mark-of-the-Web).
#[must_use]
pub fn inspect_mark_of_the_web(path: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        let ads_path = format!("{}:Zone.Identifier", path.to_string_lossy());
        if let Ok(raw) = std::fs::read_to_string(&ads_path) {
            if raw.contains("ZoneId=3") || raw.contains("ZoneId=4") {
                let cleaned = LogSanitizer::sanitize_text(&raw);
                return Some(cleaned.lines().take(4).collect::<Vec<_>>().join(" | "));
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

fn sha256_bounded_file(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 8 * 1024 * 1024 {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    Some(hex::encode(Sha256::digest(&bytes)))
}

fn read_text_bounded(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_READ_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

fn is_suspicious_command_string(raw: &str) -> Option<&'static str> {
    let lower = raw.to_ascii_lowercase();
    SUSPICIOUS_EXEC_MARKERS
        .iter()
        .copied()
        .find(|m| lower.contains(m))
}

/// Audits agent instruction & persistent memory files in `workspace_root` for Break-In
/// poisoning (prompt injection, invisible GhostJacking Unicode, and Mark-of-the-Web origin).
#[must_use]
pub fn audit_agent_instruction_and_memory_files(
    workspace_root: &Path,
) -> Vec<ArtemisForensicEvent> {
    let candidate_names = [
        ".cursorrules",
        "CLAUDE.md",
        "AGENTS.md",
        "MEMORY.md",
        "SKILL.md",
        ".github/copilot-instructions.md",
        ".cursor/rules",
        ".windsurfrules",
    ];

    let paths: Vec<PathBuf> = candidate_names
        .iter()
        .map(|rel| workspace_root.join(rel))
        .filter(|p| p.is_file())
        .collect();

    paths
        .into_par_iter()
        .filter_map(|path| {
            let raw = read_text_bounded(&path)?;
            let digest = hex::encode(Sha256::digest(raw.as_bytes()));
            let stripped = LogSanitizer::strip_dangerous_unicode(&raw);
            let had_invisible_unicode = stripped.len() != raw.len();
            let lower = stripped.to_ascii_lowercase();
            let mut indicators = Vec::new();
            if had_invisible_unicode {
                indicators.push("invisible_unicode_smuggling".to_string());
            }
            for pat in INSTRUCTION_INJECTION_PATTERNS {
                if lower.contains(pat) {
                    indicators.push(format!("injection_pattern:{pat}"));
                }
            }
            if let Some(motw) = inspect_mark_of_the_web(&path) {
                indicators.push(format!("windows_motw:{motw}"));
            }
            if indicators.is_empty() {
                return None;
            }
            let severity = if indicators.len() >= 2
                || indicators
                    .iter()
                    .any(|i| i.starts_with("injection_pattern:"))
            {
                ForensicSeverity::High
            } else {
                ForensicSeverity::Medium
            };
            Some(ArtemisForensicEvent {
                timestamp_utc: Utc::now().to_rfc3339(),
                timestamp_unix: unix_now_secs(),
                artifact: ForensicArtifactKind::AgentMemoryFile,
                direction: AbiboDirection::BreakIn,
                severity,
                principal: "workspace_instruction_file".to_string(),
                path_or_uri: path.to_string_lossy().to_string(),
                summary: format!(
                    "Suspicious Break-In indicators in agent instruction/memory file: {}",
                    indicators.join(", ")
                ),
                sha256: Some(digest),
                indicators,
                raw_source: "native_agent_memory_auditor".to_string(),
            })
        })
        .collect()
}

/// Parses an MCP JSON configuration document (e.g., `claude_desktop_config.json`, `mcp_config.json`,
/// `.cursor/mcp.json`) into audited connector entries without leaking any secret values.
#[must_use]
pub fn parse_mcp_config_json(source_path: &str, json_text: &str) -> Vec<McpConnectorAuditEntry> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(json_text) else {
        return Vec::new();
    };
    let servers = val
        .get("mcpServers")
        .or_else(|| val.get("servers"))
        .and_then(|v| v.as_object());
    let Some(map) = servers else {
        return Vec::new();
    };

    let mut entries = Vec::with_capacity(map.len());
    for (server_name, cfg) in map {
        let cmd = cfg
            .get("command")
            .and_then(|v| v.as_str())
            .or_else(|| cfg.get("url").and_then(|v| v.as_str()))
            .or_else(|| cfg.get("serverUrl").and_then(|v| v.as_str()))
            .unwrap_or("(unspecified)");
        let args_joined = cfg
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let combined_lower = format!("{server_name} {cmd} {args_joined}").to_ascii_lowercase();
        let write_capable = WRITE_CAPABLE_MCP_TOKENS
            .iter()
            .any(|tok| combined_lower.contains(tok));

        let mut has_inline_secret = false;
        let mut risk_notes = Vec::new();
        if let Some(env_obj) = cfg.get("env").and_then(|v| v.as_object()) {
            for (k, v) in env_obj {
                let ku = k.to_ascii_uppercase();
                let val_str = v.as_str().unwrap_or("");
                if SECRET_ENV_KEY_TOKENS.iter().any(|t| ku.contains(t))
                    && !val_str.trim().is_empty()
                    && !val_str.starts_with('$')
                {
                    has_inline_secret = true;
                    risk_notes.push(format!("standing_inline_secret_key:{k}"));
                }
            }
        }
        if cmd.starts_with("http://") || cmd.starts_with("https://") {
            let is_loopback = cmd.contains("127.0.0.1") || cmd.contains("localhost");
            if !is_loopback {
                risk_notes.push("remote_unmediated_mcp_endpoint".to_string());
            }
        }
        if write_capable {
            risk_notes.push("write_capable_connector_requires_abibo_mediation".to_string());
        }

        let safe_cmd_preview = LogSanitizer::scrub_credentials(&format!(
            "{cmd}{}",
            if args_joined.is_empty() {
                String::new()
            } else {
                format!(" {args_joined}")
            }
        ));

        entries.push(McpConnectorAuditEntry {
            config_source: source_path.to_string(),
            server_name: server_name.clone(),
            command_or_url: safe_cmd_preview,
            write_capable,
            has_inline_secret,
            risk_notes: if risk_notes.is_empty() {
                "read_only_or_local".to_string()
            } else {
                risk_notes.join("; ")
            },
        });
    }
    entries
}

/// Discovers local MCP connector configuration files across standard developer/agent locations.
#[must_use]
pub fn collect_local_mcp_connectors(workspace_root: &Path) -> Vec<McpConnectorAuditEntry> {
    let mut candidate_paths = vec![
        workspace_root.join(".cursor").join("mcp.json"),
        workspace_root.join(".vscode").join("mcp.json"),
        workspace_root.join("mcp.json"),
    ];

    if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
        let h = PathBuf::from(home);
        candidate_paths.push(h.join(".cursor").join("mcp.json"));
        candidate_paths.push(
            h.join(".gemini")
                .join("antigravity")
                .join("mcp_config.json"),
        );
        candidate_paths.push(h.join(".gemini").join("config").join("mcp_config.json"));
        candidate_paths.push(h.join(".claude.json"));
    }
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let a = PathBuf::from(appdata);
        candidate_paths.push(a.join("Claude").join("claude_desktop_config.json"));
    }

    candidate_paths
        .into_par_iter()
        .filter(|p| p.is_file())
        .flat_map(|p| {
            let src = p.to_string_lossy().to_string();
            read_text_bounded(&p)
                .map(|txt| parse_mcp_config_json(&src, &txt))
                .unwrap_or_default()
        })
        .collect()
}

/// Collects native OS persistence artifacts (Windows RunKeys/Startup/Prefetch, Linux systemd/cron,
/// macOS LaunchAgents) for ABIBO delayed Break-In & persistence detection.
#[must_use]
pub fn collect_native_persistence_artifacts() -> Vec<PersistenceArtifactFinding> {
    #[cfg(windows)]
    {
        collect_windows_persistence()
    }
    #[cfg(target_os = "linux")]
    {
        collect_linux_persistence()
    }
    #[cfg(target_os = "macos")]
    {
        collect_macos_persistence()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
fn collect_windows_persistence() -> Vec<PersistenceArtifactFinding> {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, KEY_READ,
        REG_EXPAND_SZ, REG_SZ,
    };

    let mut findings = Vec::new();
    let subkeys = [
        ("HKCU_Run", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (
            "HKCU_RunOnce",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
    ];

    for (cat, subkey) in subkeys {
        let sub_w: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey: HKEY = std::ptr::null_mut();
        let rc =
            unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, sub_w.as_ptr(), 0, KEY_READ, &mut hkey) };
        if rc != 0 || hkey.is_null() {
            continue;
        }
        for idx in 0..64u32 {
            let mut name_buf = [0u16; 256];
            let mut name_len = name_buf.len() as u32;
            let mut val_type: u32 = 0;
            let mut data_buf = [0u8; 2048];
            let mut data_len = data_buf.len() as u32;
            let er = unsafe {
                RegEnumValueW(
                    hkey,
                    idx,
                    name_buf.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null(),
                    &mut val_type,
                    data_buf.as_mut_ptr(),
                    &mut data_len,
                )
            };
            if er != 0 {
                break;
            }
            if val_type == REG_SZ || val_type == REG_EXPAND_SZ {
                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let u16_slice: Vec<u16> = data_buf[..(data_len as usize).min(data_buf.len())]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&c| c != 0)
                    .collect();
                let cmd = String::from_utf16_lossy(&u16_slice);
                let susp = is_suspicious_command_string(&cmd);
                findings.push(PersistenceArtifactFinding {
                    os_family: "Windows".to_string(),
                    category: cat.to_string(),
                    name,
                    command_or_path: LogSanitizer::scrub_credentials(&cmd),
                    suspicious: susp.is_some(),
                    reason: susp
                        .map(|m| format!("Suspicious persistence execution token '{m}'"))
                        .unwrap_or_else(|| "Standard user startup entry".to_string()),
                    sha256: None,
                });
            }
        }
        unsafe {
            let _ = RegCloseKey(hkey);
        }
    }

    // Inspect user Startup folder items
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let startup = PathBuf::from(appdata)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup");
        if let Ok(entries) = std::fs::read_dir(&startup) {
            for ent in entries.flatten().take(32) {
                let p = ent.path();
                if p.is_file() {
                    let fname = ent.file_name().to_string_lossy().to_string();
                    let lower = fname.to_ascii_lowercase();
                    let susp = lower.ends_with(".ps1")
                        || lower.ends_with(".vbs")
                        || lower.ends_with(".bat")
                        || lower.ends_with(".cmd")
                        || lower.ends_with(".js")
                        || lower.ends_with(".hta");
                    findings.push(PersistenceArtifactFinding {
                        os_family: "Windows".to_string(),
                        category: "StartupFolder".to_string(),
                        name: fname,
                        command_or_path: p.to_string_lossy().to_string(),
                        suspicious: susp,
                        reason: if susp {
                            "Script-based persistence item in user Startup folder".to_string()
                        } else {
                            "Startup folder item".to_string()
                        },
                        sha256: sha256_bounded_file(&p),
                    });
                }
            }
        }
    }

    // Bounded inspection of Windows Prefetch headers if readable (requires admin on some hosts)
    let prefetch_dir = Path::new(r"C:\Windows\Prefetch");
    if let Ok(entries) = std::fs::read_dir(prefetch_dir) {
        let pf_paths: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("pf"))
            })
            .take(64)
            .collect();
        for pf in pf_paths {
            if let Ok(bytes) = std::fs::read(&pf) {
                if let Some(hdr) = parse_windows_prefetch_header(&bytes) {
                    let fname = pf
                        .file_name()
                        .map(|f| f.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let susp = is_suspicious_command_string(&fname)
                        .or_else(|| is_suspicious_command_string(&hdr.executable_name));
                    if let Some(tok) = susp {
                        findings.push(PersistenceArtifactFinding {
                            os_family: "Windows".to_string(),
                            category: "Prefetch".to_string(),
                            name: fname,
                            command_or_path: format!(
                                "{} (v{}, mam={}, runs={:?})",
                                hdr.executable_name,
                                hdr.format_version,
                                hdr.compressed_mam,
                                hdr.run_count
                            ),
                            suspicious: true,
                            reason: format!("LOLBin/script execution artifact '{tok}' in Prefetch"),
                            sha256: None,
                        });
                    }
                }
            }
        }
    }

    findings
}

#[cfg(target_os = "linux")]
fn collect_linux_persistence() -> Vec<PersistenceArtifactFinding> {
    let mut findings = Vec::new();
    let mut scan_dirs: Vec<(&str, PathBuf)> = vec![("CronDir", PathBuf::from("/etc/cron.d"))];
    if let Some(home) = std::env::var_os("HOME") {
        let h = PathBuf::from(home);
        scan_dirs.push((
            "SystemdUser",
            h.join(".config").join("systemd").join("user"),
        ));
    }
    for (cat, dir) in scan_dirs {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for ent in entries.flatten().take(48) {
                let p = ent.path();
                if p.is_file() {
                    let name = ent.file_name().to_string_lossy().to_string();
                    let body = read_text_bounded(&p).unwrap_or_default();
                    let susp = is_suspicious_command_string(&body);
                    findings.push(PersistenceArtifactFinding {
                        os_family: "Linux".to_string(),
                        category: cat.to_string(),
                        name,
                        command_or_path: p.to_string_lossy().to_string(),
                        suspicious: susp.is_some(),
                        reason: susp
                            .map(|m| format!("Suspicious persistence marker '{m}'"))
                            .unwrap_or_else(|| "Systemd/cron unit".to_string()),
                        sha256: sha256_bounded_file(&p),
                    });
                }
            }
        }
    }
    findings
}

#[cfg(target_os = "macos")]
fn collect_macos_persistence() -> Vec<PersistenceArtifactFinding> {
    let mut findings = Vec::new();
    let mut dirs = vec![
        ("LaunchAgents", PathBuf::from("/Library/LaunchAgents")),
        ("LaunchDaemons", PathBuf::from("/Library/LaunchDaemons")),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push((
            "UserLaunchAgents",
            PathBuf::from(home).join("Library").join("LaunchAgents"),
        ));
    }
    for (cat, dir) in dirs {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for ent in entries.flatten().take(48) {
                let p = ent.path();
                if p.extension().and_then(|e| e.to_str()) == Some("plist") {
                    let name = ent.file_name().to_string_lossy().to_string();
                    let body = read_text_bounded(&p).unwrap_or_default();
                    let susp = is_suspicious_command_string(&body);
                    findings.push(PersistenceArtifactFinding {
                        os_family: "macOS".to_string(),
                        category: cat.to_string(),
                        name,
                        command_or_path: p.to_string_lossy().to_string(),
                        suspicious: susp.is_some(),
                        reason: susp
                            .map(|m| format!("Suspicious Launchd plist marker '{m}'"))
                            .unwrap_or_else(|| "Launchd plist".to_string()),
                        sha256: sha256_bounded_file(&p),
                    });
                }
            }
        }
    }
    findings
}
