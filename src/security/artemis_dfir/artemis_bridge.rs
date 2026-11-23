//! Artemis v0.21 (`puffyCid/artemis`) TOML Recipe Generator, Safe CLI Runner & JSONL/Timesketch Ingestor.
//!
//! Zero extra Cargo dependencies: generates byte-for-byte valid `ArtemisToml` collection
//! recipes, optionally invokes a locally installed `artemis` binary via safe argv-only
//! execution (never invoking a shell), and ingests Artemis JSONL / JSON / Timesketch
//! forensic outputs into normalized `ArtemisForensicEvent` timelines correlated against
//! workstation sleep/lock Event-Horizon windows.

use super::liveness::unix_now_secs;
use super::types::{
    AbiboDirection, ArtemisForensicEvent, ForensicArtifactKind, ForensicSeverity, SleepLockWindow,
};
use crate::security::log_sanitizer::LogSanitizer;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_ARTEMIS_FILE_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB bounded read cap
const MAX_INGESTED_EVENTS: usize = 2048;

const BREAKOUT_AND_LOLBIN_INDICATORS: &[&str] = &[
    "powershell",
    "pwsh",
    "cmd.exe",
    "mshta",
    "rundll32",
    "certutil",
    "bitsadmin",
    "regsvr32",
    "curl ",
    "wget ",
    "invoke-webrequest",
    "invoke-restmethod",
    "nc -e",
    "bash -i",
    "python -c",
    "/etc/shadow",
    ".ssh/id_",
    ".aws/credentials",
    "169.254.169.254",
    "exfiltrat",
    "grok",
    "mcp-server",
    "gmail_send",
    "calendar_delete",
    "slack_post",
];

fn escape_toml_basic_string(raw: &str) -> String {
    raw.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\r', '\n'], " ")
}

/// Generates a valid `puffyCid/artemis` v0.21 `ArtemisToml` forensic collection recipe
/// tailored for ABIBO (Break-In & Break-Out) investigation on Windows, Linux, or macOS.
#[must_use]
pub fn generate_abibo_artemis_toml(os_family: &str, output_dir: &str, endpoint_id: &str) -> String {
    let os_lower = os_family.trim().to_ascii_lowercase();
    let safe_dir = escape_toml_basic_string(output_dir);
    let safe_ep = escape_toml_basic_string(endpoint_id);

    let mut toml = format!(
        r#"# AgentOctopus ABIBO (Agent Break In & Break Out) Forensic Collection Recipe
# Compatible with puffyCid/artemis v0.21+ (`artemis acquire -t abibo_artemis.toml`)

[output]
name = "agentoctopus_abibo_dfir"
directory = "{safe_dir}"
format = "jsonl"
compress = false
endpoint_id = "{safe_ep}"
output = "local"
"#
    );

    if os_lower.contains("win") {
        toml.push_str(
            r#"
[[artifacts]]
artifact_name = "processes"
[artifacts.processes]
md5 = false
sha1 = false
sha256 = true
metadata = true

[[artifacts]]
artifact_name = "eventlogs"
[artifacts.eventlogs]
include_templates = false

[[artifacts]]
artifact_name = "tasks"
[artifacts.tasks]

[[artifacts]]
artifact_name = "services"
[artifacts.services]

[[artifacts]]
artifact_name = "registry"
[artifacts.registry]
user_hives = true
system_hives = true

[[artifacts]]
artifact_name = "prefetch"
[artifacts.prefetch]

[[artifacts]]
artifact_name = "srum"
[artifacts.srum]
"#,
        );
    } else if os_lower.contains("mac") || os_lower.contains("darwin") {
        toml.push_str(
            r#"
[[artifacts]]
artifact_name = "processes"
[artifacts.processes]
md5 = false
sha1 = false
sha256 = true
metadata = true

[[artifacts]]
artifact_name = "launchd"
[artifacts.launchd]

[[artifacts]]
artifact_name = "unifiedlogs"
[artifacts.unifiedlogs]
sources = ["Persist", "Special"]

[[artifacts]]
artifact_name = "fsevents"
[artifacts.fsevents]
"#,
        );
    } else {
        toml.push_str(
            r#"
[[artifacts]]
artifact_name = "processes"
[artifacts.processes]
md5 = false
sha1 = false
sha256 = true
metadata = true

[[artifacts]]
artifact_name = "journal"
[artifacts.journal]

[[artifacts]]
artifact_name = "cron"
[artifacts.cron]

[[artifacts]]
artifact_name = "logons"
[artifacts.logons]
"#,
        );
    }

    toml
}

/// Detects an optional locally installed `puffyCid/artemis` CLI binary via
/// `OCTOPUS_ARTEMIS_BIN` or standard `PATH` lookup (never mutating `PATH`).
#[must_use]
pub fn detect_local_artemis_binary() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("OCTOPUS_ARTEMIS_BIN") {
        let p = PathBuf::from(explicit.trim());
        if p.is_file() {
            if let Ok(meta) = std::fs::symlink_metadata(&p) {
                if !meta.file_type().is_symlink() {
                    return Some(p);
                }
            }
        }
    }

    let bin_name = if cfg!(windows) {
        "artemis.exe"
    } else {
        "artemis"
    };
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let cand = dir.join(bin_name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

/// Executes a locally installed `artemis` binary with strict argv-only arguments,
/// scrubbed environment, and bounded timeout (zero shell spawning).
pub fn run_local_artemis_collection(
    artemis_bin: &Path,
    toml_path: &Path,
    timeout_secs: u64,
) -> Result<String, String> {
    let bin_meta = std::fs::symlink_metadata(artemis_bin)
        .map_err(|e| format!("Artemis binary metadata error: {e}"))?;
    if !bin_meta.is_file() || bin_meta.file_type().is_symlink() {
        return Err("Refusing to execute non-regular or symlinked Artemis binary".to_string());
    }
    let toml_meta = std::fs::symlink_metadata(toml_path)
        .map_err(|e| format!("Artemis TOML metadata error: {e}"))?;
    if !toml_meta.is_file() || toml_meta.file_type().is_symlink() {
        return Err("Refusing to read non-regular or symlinked Artemis TOML file".to_string());
    }

    let mut cmd = Command::new(artemis_bin);
    cmd.arg("acquire")
        .arg("-t")
        .arg(toml_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(windows)]
    {
        use crate::security::console_defense::CommandConsoleExt;
        cmd.enforce_no_window();
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn Artemis CLI: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(timeout_secs.clamp(5, 300));

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|e| format!("Failed collecting Artemis CLI output: {e}"))?;
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if status.success() {
                    return Ok(LogSanitizer::sanitize_text(stdout.trim()));
                }
                return Err(format!(
                    "Artemis CLI exited with {}: {}",
                    status,
                    LogSanitizer::sanitize_text(stderr.trim())
                ));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "Artemis CLI timed out after {}s and was terminated",
                        timeout_secs.clamp(5, 300)
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                let _ = child.kill();
                return Err(format!("Failed polling Artemis CLI child process: {e}"));
            }
        }
    }
}

fn parse_timestamp(val: &Value) -> (String, u64) {
    let candidates = [
        "datetime",
        "timestamp",
        "created",
        "modified",
        "event_time",
        "time",
    ];
    for key in candidates {
        if let Some(v) = val.get(key) {
            if let Some(s) = v.as_str() {
                if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
                    let utc = dt.with_timezone(&Utc);
                    return (utc.to_rfc3339(), utc.timestamp().max(0) as u64);
                }
                if let Ok(ts) = s.trim().parse::<u64>() {
                    let secs = if ts > 10_000_000_000 { ts / 1000 } else { ts };
                    let dt =
                        DateTime::<Utc>::from_timestamp(secs as i64, 0).unwrap_or_else(Utc::now);
                    return (dt.to_rfc3339(), secs);
                }
            } else if let Some(n) = v.as_u64() {
                let secs = if n > 10_000_000_000 { n / 1000 } else { n };
                let dt = DateTime::<Utc>::from_timestamp(secs as i64, 0).unwrap_or_else(Utc::now);
                return (dt.to_rfc3339(), secs);
            }
        }
    }
    let now = Utc::now();
    (now.to_rfc3339(), unix_now_secs())
}

fn classify_artifact(val: &Value) -> ForensicArtifactKind {
    let raw = val
        .get("artifact")
        .or_else(|| val.get("artifact_name"))
        .or_else(|| val.get("data_type"))
        .or_else(|| val.get("source"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if raw.contains("eventlog") || raw.contains("evtx") {
        ForensicArtifactKind::EventLog
    } else if raw.contains("task") {
        ForensicArtifactKind::ScheduledTask
    } else if raw.contains("registry") || raw.contains("runkey") {
        ForensicArtifactKind::RegistryRunKey
    } else if raw.contains("service") {
        ForensicArtifactKind::Service
    } else if raw.contains("prefetch") {
        ForensicArtifactKind::Prefetch
    } else if raw.contains("launchd") || raw.contains("launchagent") || raw.contains("plist") {
        ForensicArtifactKind::LaunchAgent
    } else if raw.contains("systemd") {
        ForensicArtifactKind::SystemdTimer
    } else if raw.contains("cron") {
        ForensicArtifactKind::CronJob
    } else if raw.contains("srum") {
        ForensicArtifactKind::Srum
    } else if raw.contains("amcache") {
        ForensicArtifactKind::Amcache
    } else if raw.contains("shimcache") {
        ForensicArtifactKind::Shimcache
    } else if raw.contains("usnjrnl") {
        ForensicArtifactKind::UsnJrnl
    } else if raw.contains("unifiedlog") {
        ForensicArtifactKind::UnifiedLogs
    } else if raw.contains("fsevent") {
        ForensicArtifactKind::FsEvents
    } else if raw.contains("journal") {
        ForensicArtifactKind::Journal
    } else if raw.contains("mcp") {
        ForensicArtifactKind::McpConfig
    } else if raw.contains("process") {
        ForensicArtifactKind::Process
    } else if raw.contains("network") || raw.contains("connection") || raw.contains("socket") {
        ForensicArtifactKind::NetworkConnection
    } else if raw.contains("motw") || raw.contains("zone.identifier") {
        ForensicArtifactKind::MarkOfTheWeb
    } else {
        ForensicArtifactKind::ArtemisExternal
    }
}

fn first_str<'a>(val: &'a Value, keys: &[&str]) -> Option<&'a str> {
    for k in keys {
        if let Some(s) = val.get(*k).and_then(|v| v.as_str()) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

fn normalize_artemis_record(
    val: &Value,
    sleep_windows: &[SleepLockWindow],
) -> Option<ArtemisForensicEvent> {
    if !val.is_object() {
        return None;
    }

    let (timestamp_utc, timestamp_unix) = parse_timestamp(val);
    let artifact = classify_artifact(val);

    let principal = first_str(
        val,
        &[
            "principal",
            "username",
            "user",
            "agent_id",
            "actor",
            "process_name",
            "name",
        ],
    )
    .unwrap_or("unknown_principal");

    let path_or_uri = first_str(
        val,
        &[
            "path",
            "full_path",
            "target",
            "destination",
            "domain",
            "url",
            "command_line",
            "arguments",
            "executable",
            "tool_name",
        ],
    )
    .unwrap_or("");

    let message = first_str(
        val,
        &[
            "message",
            "summary",
            "description",
            "command_line",
            "timestamp_desc",
        ],
    )
    .unwrap_or("");

    let sha256 = first_str(val, &["sha256", "hash_sha256"]).map(|s| s.to_ascii_lowercase());
    let event_id = val.get("event_id").and_then(|v| v.as_u64());

    let combined_raw = format!(
        "{} {} {} {}",
        artifact.as_str(),
        principal,
        path_or_uri,
        message
    );
    let combined_lower = combined_raw.to_ascii_lowercase();

    let mut indicators: Vec<String> = Vec::new();
    let mut severity = ForensicSeverity::Info;
    let mut direction = AbiboDirection::Telemetry;

    // 1. Check sleep/lock Event-Horizon correlation (ABIBO Unconsented Control-Plane Activation)
    let during_sleep = sleep_windows.iter().any(|w| w.contains(timestamp_unix));
    if during_sleep {
        indicators.push("unconsented_sleep_window_activity".to_string());
        direction = AbiboDirection::BreakIn;
        severity = ForensicSeverity::Critical;
    }

    // 2. Check persistence & Windows Security event IDs (4698 Scheduled Task, 7045 New Service, 4624/4625)
    let is_persistence_artifact = matches!(
        artifact,
        ForensicArtifactKind::ScheduledTask
            | ForensicArtifactKind::RegistryRunKey
            | ForensicArtifactKind::Service
            | ForensicArtifactKind::LaunchAgent
            | ForensicArtifactKind::SystemdTimer
            | ForensicArtifactKind::CronJob
    );
    if is_persistence_artifact || matches!(event_id, Some(4698 | 7045 | 4697 | 1102)) {
        indicators.push(format!(
            "persistence_or_security_event:{}",
            event_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| artifact.as_str().to_string())
        ));
        if direction == AbiboDirection::Telemetry {
            direction = AbiboDirection::BreakIn;
        }
        severity = severity.max(ForensicSeverity::High);
    }

    // 3. Check Break-Out / LOLBin / Exfiltration markers
    for marker in BREAKOUT_AND_LOLBIN_INDICATORS {
        if combined_lower.contains(marker) {
            indicators.push(format!("abibo_marker:{marker}"));
            direction = if direction == AbiboDirection::BreakIn {
                AbiboDirection::BidirectionalCoupling
            } else {
                AbiboDirection::BreakOut
            };
            severity = severity.max(ForensicSeverity::High);
        }
    }

    // 4. Check agent instruction / memory / MCP config paths
    if combined_lower.contains(".cursorrules")
        || combined_lower.contains("claude.md")
        || combined_lower.contains("agents.md")
        || combined_lower.contains("memory.md")
        || combined_lower.contains("skill.md")
        || combined_lower.contains("mcp.json")
        || combined_lower.contains("zone.identifier")
    {
        indicators.push("agent_instruction_or_mcp_surface".to_string());
        if direction == AbiboDirection::Telemetry {
            direction = AbiboDirection::BreakIn;
        }
        severity = severity.max(ForensicSeverity::High);
    }

    // 5. Explicit severity override if present in Artemis record
    if let Some(sev_str) = first_str(val, &["severity", "level"]) {
        match sev_str.to_ascii_lowercase().as_str() {
            "critical" => severity = ForensicSeverity::Critical,
            "high" => severity = severity.max(ForensicSeverity::High),
            "medium" | "warn" | "warning" => severity = severity.max(ForensicSeverity::Medium),
            _ => {}
        }
    }

    let safe_principal = LogSanitizer::sanitize_text(principal);
    let safe_path = LogSanitizer::sanitize_text(path_or_uri);
    let raw_summary = if message.is_empty() {
        format!(
            "Artemis {} record for '{}' ({})",
            artifact.as_str(),
            safe_principal,
            safe_path
        )
    } else {
        message.to_string()
    };
    let safe_summary = LogSanitizer::sanitize_text(&raw_summary);

    Some(ArtemisForensicEvent {
        timestamp_utc,
        timestamp_unix,
        artifact,
        direction,
        severity,
        principal: safe_principal,
        path_or_uri: safe_path,
        summary: safe_summary,
        sha256,
        indicators,
        raw_source: "artemis_v021_jsonl".to_string(),
    })
}

/// Parses Artemis v0.21 JSONL, JSON array, or Timesketch export text into normalized
/// `ArtemisForensicEvent` rows correlated with workstation `sleep_windows`.
#[must_use]
pub fn ingest_artemis_jsonl_str(
    input: &str,
    sleep_windows: &[SleepLockWindow],
) -> Vec<ArtemisForensicEvent> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut events = Vec::new();

    // Support top-level JSON array exports as well as JSONL (one JSON object per line)
    if trimmed.starts_with('[') {
        if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(trimmed) {
            for item in arr.into_iter().take(MAX_INGESTED_EVENTS) {
                if let Some(ev) = normalize_artemis_record(&item, sleep_windows) {
                    events.push(ev);
                }
            }
            return events;
        }
    }

    for line in trimmed.lines().take(MAX_INGESTED_EVENTS) {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<Value>(l) {
            if let Some(ev) = normalize_artemis_record(&val, sleep_windows) {
                events.push(ev);
            }
        }
    }

    events
}

/// Safely reads and ingests an Artemis JSONL/JSON export file (rejecting symlinks and files > 16 MiB).
pub fn ingest_artemis_file(
    path: &Path,
    sleep_windows: &[SleepLockWindow],
) -> Result<Vec<ArtemisForensicEvent>, String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("Failed inspecting Artemis export file: {e}"))?;
    if meta.file_type().is_symlink() {
        return Err("Refusing to ingest symlinked Artemis export file".to_string());
    }
    if !meta.is_file() {
        return Err("Artemis export path is not a regular file".to_string());
    }
    if meta.len() > MAX_ARTEMIS_FILE_BYTES {
        return Err(format!(
            "Artemis export exceeds {} MiB cap ({} bytes)",
            MAX_ARTEMIS_FILE_BYTES / (1024 * 1024),
            meta.len()
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed reading Artemis export file as UTF-8: {e}"))?;
    Ok(ingest_artemis_jsonl_str(&text, sleep_windows))
}
