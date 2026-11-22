//! Inline Agent Hooks, MCP Stdio Proxy & Wire Synonym Normalization.
//!
//! Enforces Requirement R1:
//! - 0ms synchronous pre/post execution hooks for Claude Code, Cursor, GitHub Copilot, OpenCode, and MCP.
//! - Normalizes all 9 canonical wire-format field synonym groups.
//! - Preserves JSON-RPC 2.0 §5.1 request `id` on MCP tool calls.
//! - Evaluates multi-layer security pipeline (sensitive paths, AST privilege class, DLP, circumvention memory).
//! - Records live interception events for Siquery discovery (`agent_interceptions`).

use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tracing::debug;

use crate::containment_ring::egress_proxy::is_non_standard_ip_host_encoding;
use crate::security::atif_scan::AtifScanner;
use crate::security::circumvention::{
    is_cross_boundary_invocation, DynamicDenialSignal, TemporalCircumventionCorrelator,
};
use crate::security::semantic_command::{
    parse_semantic_command, DynamicBinaryMetadataProbe, PrivilegeEquivalenceClass,
};
use crate::security::semantic_dlp::SemanticDlpEngine;

pub static GLOBAL_CORRELATOR: LazyLock<TemporalCircumventionCorrelator> =
    LazyLock::new(|| TemporalCircumventionCorrelator::new(Duration::from_secs(60)));

static HOOK_ATIF_SCANNER: LazyLock<AtifScanner> = LazyLock::new(AtifScanner::default);

static EVENT_COUNTER: AtomicU64 = AtomicU64::new(1);

pub type AgentInterceptionRecord = AgentInterceptionEvent;
pub use snapshot_interception_events as snapshot_interceptions;

/// Supported AI coding agent runtime kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SupportedAgentKind {
    Claude,
    Cursor,
    Copilot,
    OpenCode,
    Mcp,
}

impl SupportedAgentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Cursor => "cursor",
            Self::Copilot => "copilot",
            Self::OpenCode => "opencode",
            Self::Mcp => "mcp",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "claude" | "claudecode" | "claude-code" => Some(Self::Claude),
            "cursor" => Some(Self::Cursor),
            "copilot" | "github-copilot" => Some(Self::Copilot),
            "opencode" => Some(Self::OpenCode),
            "mcp" | "mcp-proxy" => Some(Self::Mcp),
            _ => None,
        }
    }
}

impl fmt::Display for SupportedAgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Agent lifecycle event type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookEventType {
    PreToolUse,
    PostToolUse,
    BeforeShellExecution,
    AfterShellExecution,
    BeforeMCPExecution,
    BeforeReadFile,
    Custom(String),
}

impl HookEventType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::PreToolUse => "PreToolUse",
            Self::PostToolUse => "PostToolUse",
            Self::BeforeShellExecution => "beforeShellExecution",
            Self::AfterShellExecution => "afterShellExecution",
            Self::BeforeMCPExecution => "beforeMCPExecution",
            Self::BeforeReadFile => "beforeReadFile",
            Self::Custom(s) => s.as_str(),
        }
    }

    pub fn is_post(&self) -> bool {
        matches!(self, Self::PostToolUse | Self::AfterShellExecution)
    }

    pub fn from_name(name: &str) -> Self {
        match name.trim() {
            "PreToolUse" | "preToolUse" | "pre" | "before" => Self::PreToolUse,
            "PostToolUse" | "postToolUse" | "post" => Self::PostToolUse,
            "beforeShellExecution" => Self::BeforeShellExecution,
            "afterShellExecution" => Self::AfterShellExecution,
            "beforeMCPExecution" => Self::BeforeMCPExecution,
            "beforeReadFile" => Self::BeforeReadFile,
            other => Self::Custom(other.to_string()),
        }
    }
}

/// Canonical normalized hook request across all agent wire formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedHookRequest {
    pub agent: SupportedAgentKind,
    pub event_type: HookEventType,
    pub tool_name: Option<String>,
    pub command: Option<String>,
    pub file_path: Option<String>,
    pub arguments: Option<serde_json::Value>,
    pub exit_code: Option<i32>,
    pub stderr: Option<String>,
    pub cwd: Option<String>,
    pub session_id: Option<String>,
    #[serde(default)]
    pub rpc_id: Option<serde_json::Value>,
}

impl Default for NormalizedHookRequest {
    fn default() -> Self {
        Self {
            agent: SupportedAgentKind::Claude,
            event_type: HookEventType::PreToolUse,
            tool_name: None,
            command: None,
            file_path: None,
            arguments: None,
            exit_code: None,
            stderr: None,
            cwd: None,
            session_id: None,
            rpc_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookEvaluationDecision {
    pub allowed: bool,
    pub rationale: String,
    pub denied_by_layer: Option<String>,
    pub remediation: Option<String>,
    pub duration_us: u64,
}

impl HookEvaluationDecision {
    pub fn allow(rationale: impl Into<String>, duration_us: u64) -> Self {
        Self {
            allowed: true,
            rationale: rationale.into(),
            denied_by_layer: None,
            remediation: None,
            duration_us,
        }
    }

    pub fn deny(
        rationale: impl Into<String>,
        denied_by_layer: Option<&str>,
        remediation: Option<&str>,
        duration_us: u64,
    ) -> Self {
        Self {
            allowed: false,
            rationale: rationale.into(),
            denied_by_layer: denied_by_layer.map(ToString::to_string),
            remediation: remediation.map(ToString::to_string),
            duration_us,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentInterceptionEvent {
    pub event_id: String,
    pub timestamp_utc: String,
    pub agent: String,
    pub event_type: String,
    pub tool_name: Option<String>,
    pub command: Option<String>,
    pub file_path: Option<String>,
    pub session_id: Option<String>,
    pub allowed: bool,
    pub rationale: String,
    pub denied_by_layer: Option<String>,
    pub duration_us: u64,
}

pub static AGENT_INTERCEPTION_EVENTS: LazyLock<RwLock<VecDeque<AgentInterceptionEvent>>> =
    LazyLock::new(|| RwLock::new(VecDeque::with_capacity(1024)));

pub fn record_interception_event(evt: AgentInterceptionEvent) {
    let mut buf = AGENT_INTERCEPTION_EVENTS.write();
    if buf.len() >= 1024 {
        buf.pop_front();
    }
    buf.push_back(evt);
}

pub fn snapshot_interception_events() -> Vec<AgentInterceptionEvent> {
    AGENT_INTERCEPTION_EVENTS.read().iter().cloned().collect()
}

pub fn clear_interception_events() {
    AGENT_INTERCEPTION_EVENTS.write().clear();
}

fn record_decision(req: &NormalizedHookRequest, decision: &HookEvaluationDecision) {
    let evt = AgentInterceptionEvent {
        event_id: format!("hook-{}", EVENT_COUNTER.fetch_add(1, Ordering::SeqCst)),
        timestamp_utc: Utc::now().to_rfc3339(),
        agent: req.agent.as_str().to_string(),
        event_type: req.event_type.as_str().to_string(),
        tool_name: req.tool_name.clone(),
        command: req.command.clone(),
        file_path: req.file_path.clone(),
        session_id: req.session_id.clone(),
        allowed: decision.allowed,
        rationale: decision.rationale.clone(),
        denied_by_layer: decision.denied_by_layer.clone(),
        duration_us: decision.duration_us,
    };
    record_interception_event(evt);
}

// =============================================================================
// Wire-Format Synonyms & Normalization Handlers
// =============================================================================

pub fn extract_wire_tool_name(val: &serde_json::Value) -> Option<String> {
    const CANDIDATES: &[&str] = &["tool_name", "toolName", "name", "tool"];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if let Some(s) = v.as_str() {
                return Some(s.to_string());
            }
        }
    }
    None
}

pub fn extract_wire_arguments(val: &serde_json::Value) -> Option<serde_json::Value> {
    const CANDIDATES: &[&str] = &[
        "arguments",
        "tool_input",
        "toolArgs",
        "tool_args",
        "args",
        "parameters",
        "input",
    ];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if !v.is_null() {
                if let Some(s) = v.as_str() {
                    let trimmed = s.trim();
                    if (trimmed.starts_with('{') && trimmed.ends_with('}'))
                        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
                    {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) {
                            return Some(parsed);
                        }
                    }
                }
                return Some(v.clone());
            }
        }
    }
    None
}

pub fn extract_wire_tool_response(val: &serde_json::Value) -> Option<&serde_json::Value> {
    const CANDIDATES: &[&str] = &[
        "tool_response",
        "tool_result",
        "result",
        "output",
        "content",
    ];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if !v.is_null() {
                return Some(v);
            }
        }
    }
    None
}

pub fn extract_wire_command(val: &serde_json::Value) -> Option<String> {
    const CANDIDATES: &[&str] = &[
        "command",
        "cmd",
        "script",
        "cursor_command",
        "copilot_action",
        "subcommand",
        "action",
    ];
    for &key in CANDIDATES {
        if let Some(f) = val.get(key) {
            if let Some(s) = f.as_str() {
                return Some(s.to_string());
            }
            if let Some(arr) = f.as_array() {
                let parts: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                if !parts.is_empty() {
                    return Some(parts.join(" "));
                }
            }
        }
    }
    None
}

pub fn extract_wire_file_path(val: &serde_json::Value) -> Option<String> {
    const CANDIDATES: &[&str] = &[
        "file_path",
        "path",
        "filePath",
        "uri",
        "working_file",
        "editor_context",
        "file",
        "context_paths",
    ];
    for &key in CANDIDATES {
        if let Some(f) = val.get(key) {
            if let Some(s) = f.as_str() {
                return Some(s.to_string());
            }
            if let Some(arr) = f.as_array() {
                if let Some(first) = arr.first().and_then(|v| v.as_str()) {
                    return Some(first.to_string());
                }
            }
        }
    }
    None
}

pub fn extract_wire_session_id(val: &serde_json::Value) -> Option<String> {
    const CANDIDATES: &[&str] = &[
        "session_id",
        "sessionId",
        "conversation_id",
        "cursor_trace_id",
        "tool_use_id",
    ];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if let Some(s) = v.as_str() {
                return Some(s.to_string());
            }
        }
    }
    None
}

pub fn extract_wire_exit_code(val: &serde_json::Value) -> Option<i32> {
    const CANDIDATES: &[&str] = &["exit_code", "exitCode"];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if let Some(i) = v.as_i64() {
                return Some(i as i32);
            }
        }
    }
    None
}

pub fn extract_wire_stderr(val: &serde_json::Value) -> Option<String> {
    const CANDIDATES: &[&str] = &["stderr", "error"];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if let Some(s) = v.as_str() {
                return Some(s.to_string());
            }
        }
    }
    None
}

pub fn extract_wire_cwd(val: &serde_json::Value) -> Option<String> {
    const CANDIDATES: &[&str] = &["cwd", "working_dir", "workingDirectory"];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if let Some(s) = v.as_str() {
                return Some(s.to_string());
            }
        }
    }
    None
}

// =============================================================================
// Wire Protocol Parsers
// =============================================================================

pub fn parse_claude_request(
    json_str: &str,
    is_post: bool,
) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid JSON for Claude: {e}"))?;

    if !val.is_object() {
        return Err("Invalid JSON for Claude: Payload must be a JSON object".to_string());
    }

    let event_type = if is_post {
        HookEventType::PostToolUse
    } else {
        HookEventType::PreToolUse
    };

    let tool_name = extract_wire_tool_name(&val);
    let arguments = extract_wire_arguments(&val);
    let command =
        extract_wire_command(&val).or_else(|| arguments.as_ref().and_then(extract_wire_command));
    let file_path = extract_wire_file_path(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_file_path));
    let session_id = extract_wire_session_id(&val);
    let exit_code = extract_wire_exit_code(&val);
    let stderr = extract_wire_stderr(&val);
    let cwd = extract_wire_cwd(&val);

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::Claude,
        event_type,
        tool_name,
        command,
        file_path,
        arguments,
        exit_code,
        stderr,
        cwd,
        session_id,
        rpc_id: None,
    })
}

pub fn parse_cursor_request(
    json_str: &str,
    event_name: &str,
) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid JSON for Cursor: {e}"))?;

    if !val.is_object() {
        return Err("Invalid JSON for Cursor: Payload must be a JSON object".to_string());
    }

    let event_type = HookEventType::from_name(event_name);
    let tool_name_raw = extract_wire_tool_name(&val);
    let arguments = extract_wire_arguments(&val);
    let command =
        extract_wire_command(&val).or_else(|| arguments.as_ref().and_then(extract_wire_command));
    let file_path = extract_wire_file_path(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_file_path));
    let tool_name = tool_name_raw.or_else(|| {
        if command.is_some() {
            Some("shell".to_string())
        } else {
            None
        }
    });
    let session_id = extract_wire_session_id(&val);
    let exit_code = extract_wire_exit_code(&val);
    let stderr = extract_wire_stderr(&val);
    let cwd = extract_wire_cwd(&val);

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::Cursor,
        event_type,
        tool_name,
        command,
        file_path,
        arguments,
        exit_code,
        stderr,
        cwd,
        session_id,
        rpc_id: None,
    })
}

pub fn parse_copilot_request(
    json_str: &str,
    event_name: &str,
) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid JSON for Copilot: {e}"))?;

    if !val.is_object() {
        return Err("Invalid JSON for Copilot: Payload must be a JSON object".to_string());
    }

    let event_type = HookEventType::from_name(event_name);
    let tool_name = extract_wire_tool_name(&val);
    let arguments = extract_wire_arguments(&val);
    let command =
        extract_wire_command(&val).or_else(|| arguments.as_ref().and_then(extract_wire_command));
    let file_path = extract_wire_file_path(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_file_path));
    let session_id = extract_wire_session_id(&val);
    let exit_code = extract_wire_exit_code(&val);
    let stderr = extract_wire_stderr(&val);
    let cwd = extract_wire_cwd(&val);

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::Copilot,
        event_type,
        tool_name,
        command,
        file_path,
        arguments,
        exit_code,
        stderr,
        cwd,
        session_id,
        rpc_id: None,
    })
}

pub fn parse_opencode_request(json_str: &str) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid JSON for OpenCode: {e}"))?;

    if !val.is_object() {
        return Err("Invalid JSON for OpenCode: Payload must be a JSON object".to_string());
    }

    let event_type = HookEventType::PreToolUse;
    let tool_name = extract_wire_tool_name(&val);
    let arguments = extract_wire_arguments(&val);
    let command =
        extract_wire_command(&val).or_else(|| arguments.as_ref().and_then(extract_wire_command));
    let file_path = extract_wire_file_path(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_file_path));
    let session_id = extract_wire_session_id(&val);
    let exit_code = extract_wire_exit_code(&val);
    let stderr = extract_wire_stderr(&val);
    let cwd = extract_wire_cwd(&val);

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::OpenCode,
        event_type,
        tool_name,
        command,
        file_path,
        arguments,
        exit_code,
        stderr,
        cwd,
        session_id,
        rpc_id: None,
    })
}

pub fn parse_mcp_call_request(json_str: &str) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid JSON-RPC 2.0: {e}"))?;

    if !val.is_object() {
        return Err("Invalid JSON-RPC 2.0: Payload must be a JSON object".to_string());
    }

    let rpc_id = val.get("id").cloned();
    let params = val
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let tool_name = extract_wire_tool_name(&params).or_else(|| extract_wire_tool_name(&val));
    let arguments = extract_wire_arguments(&params).or_else(|| extract_wire_arguments(&val));
    let command =
        extract_wire_command(&params).or_else(|| arguments.as_ref().and_then(extract_wire_command));
    let file_path = extract_wire_file_path(&params)
        .or_else(|| arguments.as_ref().and_then(extract_wire_file_path));

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::Mcp,
        event_type: HookEventType::BeforeMCPExecution,
        tool_name,
        command,
        file_path,
        arguments,
        exit_code: None,
        stderr: None,
        cwd: None,
        session_id: extract_wire_session_id(&val),
        rpc_id,
    })
}

pub use parse_mcp_call_request as parse_mcp_request;

// =============================================================================
// Output Formatters
// =============================================================================

pub fn format_claude_response(decision: &HookEvaluationDecision) -> (i32, String) {
    if decision.allowed {
        (0, String::new())
    } else {
        (
            2,
            format!("AgentOctopus Hook Policy Denied: {}\n", decision.rationale),
        )
    }
}

pub fn format_cursor_response(decision: &HookEvaluationDecision) -> (i32, String) {
    let obj = if decision.allowed {
        serde_json::json!({
            "permission": "allow",
            "user_message": "Authorized by AgentOctopus PEP",
            "agent_message": ""
        })
    } else {
        serde_json::json!({
            "permission": "deny",
            "user_message": format!("AgentOctopus Containment: {}", decision.rationale),
            "agent_message": decision.rationale
        })
    };
    (0, obj.to_string())
}

pub fn format_copilot_response(decision: &HookEvaluationDecision) -> (i32, String) {
    let obj = if decision.allowed {
        serde_json::json!({
            "permissionDecision": "allow",
            "permissionDecisionReason": "AgentOctopus cleared execution"
        })
    } else {
        serde_json::json!({
            "permissionDecision": "deny",
            "permissionDecisionReason": format!("AgentOctopus Policy Violation: {}", decision.rationale)
        })
    };
    (0, obj.to_string())
}

pub fn format_opencode_response(decision: &HookEvaluationDecision) -> (i32, String) {
    let obj = if decision.allowed {
        serde_json::json!({
            "allow": true,
            "reason": "AgentOctopus cleared execution"
        })
    } else {
        serde_json::json!({
            "allow": false,
            "reason": format!("AgentOctopus Policy Violation: {}", decision.rationale)
        })
    };
    (0, obj.to_string())
}

pub fn format_mcp_error_response(
    id: &serde_json::Value,
    decision: &HookEvaluationDecision,
) -> String {
    let mut error_obj = serde_json::json!({
        "code": -32000,
        "message": format!("AgentOctopus Policy Violation: {}", decision.rationale)
    });

    if decision.denied_by_layer.is_some() || decision.remediation.is_some() {
        error_obj["data"] = serde_json::json!({
            "denied_by_layer": decision.denied_by_layer.as_deref().unwrap_or("Unknown"),
            "suggested_remediation": decision.remediation.as_deref().unwrap_or("None"),
        });
    }

    let resp = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": error_obj,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": format!("AgentOctopus Policy Violation: {}", decision.rationale)
                }
            ],
            "isError": true
        }
    });
    resp.to_string()
}

fn is_dotenv_write_target(raw: &str) -> bool {
    let norm = crate::security::sensitive_paths::normalize_path_for_inspection(raw);
    if norm.is_empty() {
        return false;
    }
    let stripped = norm.strip_prefix('/').unwrap_or(&norm);
    let basename = stripped.rsplit('/').next().unwrap_or(stripped);
    basename == ".env" || basename.starts_with(".env.")
}

fn collect_hook_commands_from_json(val: &serde_json::Value, out: &mut Vec<String>) {
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let kl = k.to_ascii_lowercase();
                if matches!(
                    kl.as_str(),
                    "command"
                        | "cmd"
                        | "script"
                        | "cursor_command"
                        | "copilot_action"
                        | "subcommand"
                        | "action"
                ) {
                    if let Some(s) = v.as_str() {
                        if !s.trim().is_empty() && !out.iter().any(|existing| existing == s) {
                            out.push(s.to_string());
                        }
                    } else if let Some(arr) = v.as_array() {
                        let parts: Vec<&str> = arr.iter().filter_map(|x| x.as_str()).collect();
                        if !parts.is_empty() {
                            let joined = parts.join(" ");
                            if !joined.trim().is_empty()
                                && !out.iter().any(|existing| existing == &joined)
                            {
                                out.push(joined);
                            }
                        }
                    }
                }
                collect_hook_commands_from_json(v, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_hook_commands_from_json(item, out);
            }
        }
        _ => {}
    }
}

fn collect_hook_commands(req: &NormalizedHookRequest) -> Vec<String> {
    let mut cmds = Vec::new();
    if let Some(c) = &req.command {
        if !c.trim().is_empty() {
            cmds.push(c.clone());
        }
    }
    if let Some(args) = &req.arguments {
        collect_hook_commands_from_json(args, &mut cmds);
        if req.command.is_none() {
            if let serde_json::Value::String(s) = args {
                if !s.trim().is_empty() {
                    let is_shell_tool = req
                        .tool_name
                        .as_deref()
                        .map(|t| {
                            matches!(
                                t.trim().to_ascii_lowercase().as_str(),
                                "bash"
                                    | "sh"
                                    | "shell"
                                    | "terminal"
                                    | "execute"
                                    | "run_command"
                                    | "powershell"
                                    | "pwsh"
                                    | "cmd"
                            )
                        })
                        .unwrap_or(false);
                    if is_shell_tool && !cmds.iter().any(|existing| existing == s) {
                        cmds.push(s.clone());
                    }
                }
            }
        }
    }
    cmds
}

fn posix_unescape_word(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next_c) = chars.next() {
                out.push(next_c);
            } else {
                out.push('\\');
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn check_shell_write_deny_path_candidate(cand: &str, allow_pinned_parent: bool) -> Option<String> {
    if let Some(reason) = check_write_deny_path_candidate(cand, allow_pinned_parent) {
        return Some(reason);
    }
    if cand.contains('\\') {
        let unescaped = posix_unescape_word(cand);
        if unescaped != cand {
            if let Some(reason) = check_write_deny_path_candidate(&unescaped, allow_pinned_parent) {
                return Some(reason);
            }
        }
    }
    None
}

fn extract_redirection_targets(cmd: &str) -> Vec<String> {
    let bytes = cmd.as_bytes();
    let mut targets = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'>' {
            let prev = if i > 0 { Some(bytes[i - 1]) } else { None };
            let next = bytes.get(i + 1).copied();
            // Skip comparison / arrow operators (->, =>, >=)
            if matches!(prev, Some(b'-') | Some(b'=')) || next == Some(b'=') {
                i += 1;
                continue;
            }
            let mut j = i + 1;
            if next == Some(b'&') {
                // Only skip fd duplication/close (`>&2`, `1>&2`, `2>&1`, `>&-`, `>& 2`).
                // In bash/zsh, `>& <file>` / `>&<file>` redirects stdout+stderr to `<file>`.
                j += 1;
                let mut k = j;
                while k < bytes.len() && matches!(bytes[k], b' ' | b'\t') {
                    k += 1;
                }
                if k >= bytes.len() {
                    i = k;
                    continue;
                }
                if !matches!(bytes[k], b'"' | b'\'' | b'`') {
                    let mut tok_end = k;
                    while tok_end < bytes.len() {
                        let b = bytes[tok_end];
                        if b.is_ascii_whitespace()
                            || matches!(
                                b,
                                b';' | b'&'
                                    | b'|'
                                    | b'<'
                                    | b'>'
                                    | b'('
                                    | b')'
                                    | b'`'
                                    | b'"'
                                    | b'\''
                            )
                        {
                            break;
                        }
                        tok_end += 1;
                    }
                    let fd_tok = &bytes[k..tok_end];
                    if fd_tok.is_empty()
                        || fd_tok == b"-"
                        || fd_tok.iter().all(|b| b.is_ascii_digit())
                    {
                        i = tok_end;
                        continue;
                    }
                }
            } else if matches!(bytes.get(j).copied(), Some(b'>') | Some(b'|')) {
                j += 1;
            }
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                j += 1;
            }
            if j < bytes.len() {
                let mut raw_word = String::new();
                let mut unescaped_word = String::new();
                let mut has_unquoted_backslash = false;
                let mut quote_char: Option<char> = None;
                let mut in_ansi_single = false;
                let mut consumed_bytes = 0usize;
                let mut iter = cmd[j..].chars().peekable();

                while let Some(c) = iter.next() {
                    if in_ansi_single {
                        consumed_bytes += c.len_utf8();
                        if c == '\'' {
                            in_ansi_single = false;
                        } else if c == '\\' {
                            let mut decoded = String::new();
                            consumed_bytes += decode_ansi_c_escape(&mut iter, &mut decoded);
                            raw_word.push_str(&decoded);
                            unescaped_word.push_str(&decoded);
                        } else {
                            raw_word.push(c);
                            unescaped_word.push(c);
                        }
                        continue;
                    }
                    if let Some(q) = quote_char {
                        consumed_bytes += c.len_utf8();
                        if q != '\'' && c == '\\' {
                            if let Some(&next_c) = iter.peek() {
                                if next_c == q || next_c == '\\' {
                                    let nc = iter.next().unwrap();
                                    consumed_bytes += nc.len_utf8();
                                    raw_word.push(nc);
                                    unescaped_word.push(nc);
                                    continue;
                                }
                            }
                            raw_word.push('\\');
                            unescaped_word.push('\\');
                            continue;
                        }
                        if c == q {
                            quote_char = None;
                        } else {
                            raw_word.push(c);
                            unescaped_word.push(c);
                        }
                        continue;
                    }

                    // Unquoted: stop at unquoted whitespace or shell operator delimiter
                    if c.is_whitespace()
                        || matches!(c, ';' | '&' | '|' | '<' | '>' | '(' | ')' | '\n' | '\r')
                    {
                        break;
                    }

                    consumed_bytes += c.len_utf8();
                    match c {
                        '$' if iter.peek().is_some_and(|&nc| nc == '\'') => {
                            let q = iter.next().unwrap();
                            consumed_bytes += q.len_utf8();
                            in_ansi_single = true;
                        }
                        '$' if iter.peek().is_some_and(|&nc| nc == '"') => {
                            let q = iter.next().unwrap();
                            consumed_bytes += q.len_utf8();
                            quote_char = Some('"');
                        }
                        '\'' | '"' | '`' => {
                            quote_char = Some(c);
                        }
                        '\\' => {
                            has_unquoted_backslash = true;
                            if let Some(&next_c) = iter.peek() {
                                if !next_c.is_whitespace()
                                    && !matches!(
                                        next_c,
                                        ';' | '&' | '|' | '<' | '>' | '(' | ')' | '\n' | '\r'
                                    )
                                {
                                    let nc = iter.next().unwrap();
                                    consumed_bytes += nc.len_utf8();
                                    raw_word.push('\\');
                                    raw_word.push(nc);
                                    unescaped_word.push(nc);
                                    continue;
                                }
                            }
                            raw_word.push('\\');
                        }
                        _ => {
                            raw_word.push(c);
                            unescaped_word.push(c);
                        }
                    }
                }

                if !raw_word.is_empty() {
                    targets.push(raw_word.clone());
                }
                if has_unquoted_backslash
                    && !unescaped_word.is_empty()
                    && unescaped_word != raw_word
                {
                    targets.push(unescaped_word);
                }
                i = j + consumed_bytes;
                continue;
            }
        }
        i += 1;
    }
    targets
}

fn strip_key_prefix_for_path(tok: &str) -> &str {
    if let Some(eq_pos) = tok.find('=') {
        let key = &tok[..eq_pos];
        let val = &tok[eq_pos + 1..];
        if !key.is_empty()
            && !key.contains('/')
            && !key.contains('\\')
            && !val.is_empty()
            && (key.starts_with('-')
                || matches!(
                    key.to_ascii_lowercase().as_str(),
                    "of" | "path" | "file" | "target" | "out" | "dest" | "destination"
                ))
        {
            return val.trim_matches(['"', '\'', '`']);
        }
    }
    if tok.starts_with('-') {
        if let Some(colon_pos) = tok.find(':') {
            let key = &tok[..colon_pos];
            let val = &tok[colon_pos + 1..];
            if !key.contains('/') && !key.contains('\\') && !val.is_empty() {
                return val.trim_matches(['"', '\'', '`']);
            }
        }
    }
    tok
}

fn check_write_deny_path_candidate(cand: &str, allow_pinned_parent: bool) -> Option<String> {
    if let Some(kind) = crate::security::sensitive_paths::classify_mandatory_write_deny_path(cand) {
        return Some(format!("{} ('{}')", kind.description(), cand));
    }
    if allow_pinned_parent {
        if let Some(kind) =
            crate::security::sensitive_paths::classify_pinned_parent_for_write_deny(cand)
        {
            return Some(format!("{} ('{}')", kind.description(), cand));
        }
    }
    if is_dotenv_write_target(cand) {
        return Some(format!(
            "Mandatory write-deny: protected environment file ('{}')",
            cand
        ));
    }
    None
}

fn canonical_bin_stem(token: &str) -> String {
    let trimmed = token.trim().trim_matches(['"', '\'', '`']);
    let file_part = trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed);
    let lower = file_part.to_ascii_lowercase();
    lower
        .strip_suffix(".exe")
        .or_else(|| lower.strip_suffix(".cmd"))
        .or_else(|| lower.strip_suffix(".bat"))
        .unwrap_or(&lower)
        .to_string()
}

fn is_env_assignment(tok: &str) -> bool {
    let Some((key, _val)) = tok.split_once('=') else {
        return false;
    };
    !key.is_empty()
        && !key.starts_with('-')
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

struct StrippedCommandSegment {
    tokens: Vec<String>,
    chdir_dirs: Vec<String>,
    wrapper_write_targets: Vec<String>,
    wrapper_inner_scripts: Vec<String>,
}

fn strip_transparent_wrappers_and_env(mut seg: Vec<String>) -> StrippedCommandSegment {
    let mut idx = 0usize;
    let mut split_expansions = 0usize;
    let mut inhibit_outer_env_assignment = false;
    let mut chdir_dirs: Vec<String> = Vec::new();
    let mut wrapper_write_targets: Vec<String> = Vec::new();
    let mut wrapper_inner_scripts: Vec<String> = Vec::new();

    while idx < seg.len() {
        let tok = seg[idx].as_str();
        if !inhibit_outer_env_assignment && is_env_assignment(tok) {
            idx += 1;
            continue;
        }
        let stem = canonical_bin_stem(tok);
        match stem.as_str() {
            "env" => {
                idx += 1;
                while idx < seg.len() {
                    let arg = seg[idx].as_str();
                    if arg == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    if is_env_assignment(arg) {
                        idx += 1;
                        continue;
                    }
                    let split_opt: Option<(String, usize)> =
                        if arg == "-S" || arg == "--split-string" {
                            if idx + 1 < seg.len() {
                                Some((seg[idx + 1].clone(), idx + 2))
                            } else {
                                None
                            }
                        } else if let Some(stripped) = arg.strip_prefix("--split-string=") {
                            Some((stripped.to_string(), idx + 1))
                        } else if arg.starts_with('-') && !arg.starts_with("--") {
                            let rest = &arg[1..];
                            if let Some(s_pos) = rest.find('S') {
                                if rest[..s_pos].chars().all(|c| matches!(c, 'i' | '0' | 'v')) {
                                    let tail = &rest[s_pos + 1..];
                                    if tail.is_empty() {
                                        if idx + 1 < seg.len() {
                                            Some((seg[idx + 1].clone(), idx + 2))
                                        } else {
                                            None
                                        }
                                    } else {
                                        let payload = tail.strip_prefix('=').unwrap_or(tail);
                                        Some((payload.to_string(), idx + 1))
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                    if let Some((payload, next_idx)) = split_opt {
                        if split_expansions < 8 {
                            split_expansions += 1;
                            let mut combined =
                                crate::security::semantic_command::tokenize_command(&payload);
                            combined.extend_from_slice(&seg[next_idx..]);
                            seg.splice(idx.., combined);
                            continue;
                        }
                    }
                    if let Some(dir) = arg.strip_prefix("--chdir=") {
                        if !dir.is_empty() {
                            chdir_dirs.push(dir.to_string());
                        }
                        idx += 1;
                        continue;
                    }
                    if matches!(arg, "-C" | "--chdir") {
                        if idx + 1 < seg.len() {
                            chdir_dirs.push(seg[idx + 1].clone());
                            idx += 2;
                        } else {
                            idx += 1;
                        }
                        continue;
                    }
                    if matches!(
                        arg,
                        "-u" | "--unset" | "-a" | "--argv0" | "-P" | "--default-path"
                    ) {
                        idx += 2;
                        continue;
                    }
                    if arg.starts_with('-') && !arg.starts_with("--") {
                        let rest = &arg[1..];
                        if let Some(pos) = rest.find(['u', 'C', 'a', 'P']) {
                            if rest[..pos].chars().all(|c| matches!(c, 'i' | '0' | 'v')) {
                                let ch = rest.as_bytes()[pos];
                                let tail = &rest[pos + 1..];
                                if tail.is_empty() {
                                    if ch == b'C' && idx + 1 < seg.len() {
                                        chdir_dirs.push(seg[idx + 1].clone());
                                    }
                                    idx += 2;
                                } else {
                                    if ch == b'C' {
                                        let dir = tail.strip_prefix('=').unwrap_or(tail);
                                        if !dir.is_empty() {
                                            chdir_dirs.push(dir.to_string());
                                        }
                                    }
                                    idx += 1;
                                }
                                continue;
                            }
                        }
                    }
                    if arg.starts_with('-') {
                        idx += 1;
                        continue;
                    }
                    break;
                }
            }
            "command" => {
                idx += 1;
                let mut is_query_only = false;
                while idx < seg.len() && seg[idx].starts_with('-') {
                    let arg = seg[idx].as_str();
                    if arg == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    if !arg.starts_with("--") && (arg[1..].contains('v') || arg[1..].contains('V'))
                    {
                        is_query_only = true;
                    }
                    idx += 1;
                }
                if is_query_only {
                    idx = seg.len();
                    break;
                }
            }
            "nohup" | "setsid" => {
                idx += 1;
                while idx < seg.len() && seg[idx].starts_with('-') {
                    if seg[idx] == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    idx += 1;
                }
            }
            "time" => {
                idx += 1;
                while idx < seg.len() && seg[idx].starts_with('-') {
                    let arg = seg[idx].as_str();
                    if arg == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    if matches!(arg, "-f" | "--format") {
                        idx += 2;
                        continue;
                    }
                    if arg.starts_with("--format=") {
                        idx += 1;
                        continue;
                    }
                    if matches!(arg, "-o" | "--output") {
                        if idx + 1 < seg.len() {
                            let target = seg[idx + 1].clone();
                            if target != "-" && target != "/dev/null" {
                                wrapper_write_targets.push(target);
                            }
                            idx += 2;
                        } else {
                            idx += 1;
                        }
                        continue;
                    }
                    if let Some(val) = arg.strip_prefix("--output=") {
                        if val != "-" && val != "/dev/null" {
                            wrapper_write_targets.push(val.to_string());
                        }
                        idx += 1;
                        continue;
                    }
                    if !arg.starts_with("--") {
                        let rest = &arg[1..];
                        let mut consumed = false;
                        for (pos, ch) in rest.char_indices() {
                            if matches!(ch, 'f' | 'o') {
                                let after_flag = &rest[pos + ch.len_utf8()..];
                                let val = if !after_flag.is_empty() {
                                    idx += 1;
                                    Some(after_flag.to_string())
                                } else if idx + 1 < seg.len() {
                                    let v = seg[idx + 1].clone();
                                    idx += 2;
                                    Some(v)
                                } else {
                                    idx += 1;
                                    None
                                };
                                if ch == 'o' {
                                    if let Some(target) = val {
                                        if target != "-" && target != "/dev/null" {
                                            wrapper_write_targets.push(target);
                                        }
                                    }
                                }
                                consumed = true;
                                break;
                            }
                        }
                        if consumed {
                            continue;
                        }
                    }
                    idx += 1;
                }
            }
            "exec" => {
                idx += 1;
                while idx < seg.len() && seg[idx].starts_with('-') {
                    let arg = seg[idx].as_str();
                    if arg == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    if arg == "-a" {
                        idx += 2;
                        continue;
                    }
                    if !arg.starts_with("--") {
                        let rest = &arg[1..];
                        if let Some(pos) = rest.find('a') {
                            if rest[..pos].chars().all(|c| matches!(c, 'c' | 'l')) {
                                if rest[pos + 1..].is_empty() {
                                    idx += 2;
                                } else {
                                    idx += 1;
                                }
                                continue;
                            }
                        }
                    }
                    idx += 1;
                }
            }
            "ionice" => {
                idx += 1;
                while idx < seg.len() && seg[idx].starts_with('-') {
                    let arg = seg[idx].as_str();
                    if arg == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    if matches!(
                        arg,
                        "-c" | "--class"
                            | "-n"
                            | "--classdata"
                            | "-p"
                            | "--pid"
                            | "-P"
                            | "--pgid"
                            | "-u"
                            | "--uid"
                    ) {
                        idx += 2;
                        continue;
                    }
                    if !arg.starts_with("--") {
                        let rest = &arg[1..];
                        if let Some(pos) = rest.find(['c', 'n', 'p', 'P', 'u']) {
                            if rest[..pos].chars().all(|c| c == 't') {
                                if rest[pos + 1..].is_empty() {
                                    idx += 2;
                                } else {
                                    idx += 1;
                                }
                                continue;
                            }
                        }
                    }
                    idx += 1;
                }
            }
            "taskset" => {
                idx += 1;
                let mut is_pid_mode = false;
                let mut has_cpu_list = false;
                while idx < seg.len() && seg[idx].starts_with('-') {
                    let arg = seg[idx].as_str();
                    if arg == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    if arg == "-p" || arg == "--pid" {
                        is_pid_mode = true;
                        idx += 1;
                        continue;
                    }
                    if arg == "--cpu-list" {
                        has_cpu_list = true;
                        idx += 2;
                        continue;
                    }
                    if arg.starts_with("--cpu-list=") {
                        has_cpu_list = true;
                        idx += 1;
                        continue;
                    }
                    if !arg.starts_with("--") {
                        let rest = &arg[1..];
                        if let Some(pos) = rest.find('c') {
                            if rest[..pos].chars().all(|c| matches!(c, 'a' | 'p')) {
                                if rest[..pos].contains('p') {
                                    is_pid_mode = true;
                                }
                                has_cpu_list = true;
                                if rest[pos + 1..].is_empty() {
                                    idx += 2;
                                } else {
                                    idx += 1;
                                }
                                continue;
                            }
                        }
                        if rest.contains('p') {
                            is_pid_mode = true;
                        }
                    }
                    idx += 1;
                }
                if is_pid_mode {
                    idx = seg.len();
                    break;
                }
                // Consume mandatory mask operand only when -c/--cpu-list was not already consumed.
                if !has_cpu_list && idx < seg.len() {
                    idx += 1;
                }
            }
            "chrt" => {
                idx += 1;
                let mut is_pid_or_query = false;
                while idx < seg.len() && seg[idx].starts_with('-') {
                    let arg = seg[idx].as_str();
                    if arg == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    if matches!(
                        arg,
                        "-p" | "--pid" | "-m" | "--max" | "-h" | "--help" | "-V" | "--version"
                    ) {
                        is_pid_or_query = true;
                        idx += 1;
                        continue;
                    }
                    if matches!(
                        arg,
                        "-T" | "--sched-runtime"
                            | "-P"
                            | "--sched-period"
                            | "-D"
                            | "--sched-deadline"
                    ) {
                        idx += 2;
                        continue;
                    }
                    if arg.starts_with("--sched-runtime=")
                        || arg.starts_with("--sched-period=")
                        || arg.starts_with("--sched-deadline=")
                    {
                        idx += 1;
                        continue;
                    }
                    if !arg.starts_with("--") {
                        let rest = &arg[1..];
                        if rest.contains('p') || rest.contains('m') || rest.contains('V') {
                            is_pid_or_query = true;
                        }
                        if let Some(pos) = rest.find(['T', 'P', 'D']) {
                            if rest[pos + 1..].is_empty() {
                                idx += 2;
                            } else {
                                idx += 1;
                            }
                            continue;
                        }
                    }
                    idx += 1;
                }
                if is_pid_or_query {
                    idx = seg.len();
                    break;
                }
                // Consume mandatory priority positional operand.
                if idx < seg.len() {
                    idx += 1;
                }
            }
            "flock" => {
                idx += 1;
                let mut is_query_only = false;
                let mut extracted_cmd = false;
                while idx < seg.len() && seg[idx].starts_with('-') {
                    let arg = seg[idx].as_str();
                    if arg == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    if matches!(arg, "-h" | "--help" | "-V" | "--version") {
                        is_query_only = true;
                        idx += 1;
                        continue;
                    }
                    if matches!(arg, "-c" | "--command") {
                        if idx + 1 < seg.len() {
                            wrapper_inner_scripts.push(seg[idx + 1].clone());
                        }
                        extracted_cmd = true;
                        break;
                    }
                    if let Some(cmd_str) = arg.strip_prefix("--command=") {
                        wrapper_inner_scripts.push(cmd_str.to_string());
                        extracted_cmd = true;
                        break;
                    }
                    if matches!(
                        arg,
                        "-E" | "--conflict-exit-code" | "-w" | "--wait" | "--timeout"
                    ) {
                        idx += 2;
                        continue;
                    }
                    if arg.starts_with("--conflict-exit-code=")
                        || arg.starts_with("--wait=")
                        || arg.starts_with("--timeout=")
                    {
                        idx += 1;
                        continue;
                    }
                    if !arg.starts_with("--") {
                        let rest = &arg[1..];
                        if let Some(pos) = rest.find(['c', 'E', 'w', 'W']) {
                            let ch = rest.as_bytes()[pos];
                            let after_flag = &rest[pos + 1..];
                            if ch == b'c' {
                                if !after_flag.is_empty() {
                                    wrapper_inner_scripts.push(after_flag.to_string());
                                } else if idx + 1 < seg.len() {
                                    wrapper_inner_scripts.push(seg[idx + 1].clone());
                                }
                                extracted_cmd = true;
                                break;
                            }
                            if after_flag.is_empty() {
                                idx += 2;
                            } else {
                                idx += 1;
                            }
                            continue;
                        }
                    }
                    idx += 1;
                }
                if is_query_only || extracted_cmd {
                    idx = seg.len();
                    break;
                }
                // Consume positional lockfile or fd number.
                if idx < seg.len() {
                    idx += 1;
                }
                // Also handle `flock /tmp/lock -c "<cmd>"` where -c follows lockfile.
                if idx < seg.len() {
                    let next_tok = seg[idx].as_str();
                    if matches!(next_tok, "-c" | "--command") {
                        if idx + 1 < seg.len() {
                            wrapper_inner_scripts.push(seg[idx + 1].clone());
                        }
                        idx = seg.len();
                        break;
                    }
                    if let Some(cmd_str) = next_tok.strip_prefix("--command=") {
                        wrapper_inner_scripts.push(cmd_str.to_string());
                        idx = seg.len();
                        break;
                    }
                }
            }
            "script" => {
                idx += 1;
                let mut is_query_only = false;
                while idx < seg.len() && seg[idx].starts_with('-') {
                    let arg = seg[idx].as_str();
                    if arg == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    if matches!(arg, "-h" | "--help" | "-V" | "--version") {
                        is_query_only = true;
                        idx += 1;
                        continue;
                    }
                    if matches!(arg, "-c" | "--command") {
                        if idx + 1 < seg.len() {
                            wrapper_inner_scripts.push(seg[idx + 1].clone());
                            idx += 2;
                        } else {
                            idx += 1;
                        }
                        continue;
                    }
                    if let Some(cmd_str) = arg.strip_prefix("--command=") {
                        wrapper_inner_scripts.push(cmd_str.to_string());
                        idx += 1;
                        continue;
                    }
                    if matches!(arg, "-O" | "--log-out" | "-B" | "--log-io") {
                        if idx + 1 < seg.len() {
                            let target = seg[idx + 1].clone();
                            if target != "-" && target != "/dev/null" {
                                wrapper_write_targets.push(target);
                            }
                            idx += 2;
                        } else {
                            idx += 1;
                        }
                        continue;
                    }
                    if let Some(val) = arg
                        .strip_prefix("--log-out=")
                        .or_else(|| arg.strip_prefix("--log-io="))
                    {
                        if val != "-" && val != "/dev/null" {
                            wrapper_write_targets.push(val.to_string());
                        }
                        idx += 1;
                        continue;
                    }
                    if matches!(arg, "-I" | "--log-in" | "-E" | "--echo") {
                        idx += 2;
                        continue;
                    }
                    if !arg.starts_with("--") {
                        let rest = &arg[1..];
                        if let Some(pos) = rest.find(['c', 'O', 'B', 'I', 'E']) {
                            let ch = rest.as_bytes()[pos];
                            let after_flag = &rest[pos + 1..];
                            let val = if !after_flag.is_empty() {
                                idx += 1;
                                Some(after_flag.to_string())
                            } else if idx + 1 < seg.len() {
                                let v = seg[idx + 1].clone();
                                idx += 2;
                                Some(v)
                            } else {
                                idx += 1;
                                None
                            };
                            if let Some(v) = val {
                                if ch == b'c' {
                                    wrapper_inner_scripts.push(v);
                                } else if matches!(ch, b'O' | b'B') && v != "-" && v != "/dev/null"
                                {
                                    wrapper_write_targets.push(v);
                                }
                            }
                            continue;
                        }
                    }
                    idx += 1;
                }
                if is_query_only {
                    idx = seg.len();
                    break;
                }
                // Consume optional typescript output file and check against write-deny.
                if idx < seg.len() && !seg[idx].starts_with('-') {
                    let ts_file = seg[idx].as_str();
                    if ts_file != "/dev/null" && ts_file != "-" {
                        wrapper_write_targets.push(ts_file.to_string());
                    }
                    idx += 1;
                }
            }
            "strace" => {
                idx += 1;
                while idx < seg.len() && seg[idx].starts_with('-') {
                    let arg = seg[idx].as_str();
                    if arg == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    if matches!(arg, "-o" | "--output") {
                        if idx + 1 < seg.len() {
                            let target = seg[idx + 1].clone();
                            if target != "-" && target != "/dev/null" {
                                wrapper_write_targets.push(target);
                            }
                            idx += 2;
                        } else {
                            idx += 1;
                        }
                        continue;
                    }
                    if let Some(val) = arg.strip_prefix("--output=") {
                        if val != "-" && val != "/dev/null" {
                            wrapper_write_targets.push(val.to_string());
                        }
                        idx += 1;
                        continue;
                    }
                    if matches!(
                        arg,
                        "-e" | "-p"
                            | "-u"
                            | "-s"
                            | "-S"
                            | "-P"
                            | "-E"
                            | "-I"
                            | "-b"
                            | "-X"
                            | "-U"
                            | "-O"
                            | "--trace"
                            | "--attach"
                            | "--user"
                            | "--string-limit"
                            | "--sort-by"
                            | "--decode-fds"
                            | "--env"
                    ) {
                        idx += 2;
                        continue;
                    }
                    if !arg.starts_with("--") {
                        let rest = &arg[1..];
                        let mut consumed = false;
                        for (pos, ch) in rest.char_indices() {
                            if matches!(
                                ch,
                                'e' | 'o'
                                    | 'p'
                                    | 'u'
                                    | 's'
                                    | 'S'
                                    | 'P'
                                    | 'E'
                                    | 'I'
                                    | 'b'
                                    | 'X'
                                    | 'U'
                                    | 'O'
                            ) {
                                let after_flag = &rest[pos + ch.len_utf8()..];
                                let val = if !after_flag.is_empty() {
                                    idx += 1;
                                    Some(after_flag.to_string())
                                } else if idx + 1 < seg.len() {
                                    let v = seg[idx + 1].clone();
                                    idx += 2;
                                    Some(v)
                                } else {
                                    idx += 1;
                                    None
                                };
                                if ch == 'o' {
                                    if let Some(target) = val {
                                        if target != "-" && target != "/dev/null" {
                                            wrapper_write_targets.push(target);
                                        }
                                    }
                                }
                                consumed = true;
                                break;
                            }
                        }
                        if consumed {
                            continue;
                        }
                    }
                    idx += 1;
                }
            }
            "caffeinate" => {
                idx += 1;
                while idx < seg.len() && seg[idx].starts_with('-') {
                    let arg = seg[idx].as_str();
                    if arg == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    if matches!(arg, "-w" | "-t") {
                        idx += 2;
                        continue;
                    }
                    if !arg.starts_with("--") {
                        let rest = &arg[1..];
                        if let Some(pos) = rest.find(['w', 't']) {
                            if rest[pos + 1..].is_empty() {
                                idx += 2;
                            } else {
                                idx += 1;
                            }
                            continue;
                        }
                    }
                    idx += 1;
                }
            }
            "busybox" => {
                idx += 1;
                if idx < seg.len()
                    && matches!(
                        seg[idx].as_str(),
                        "--list" | "--list-full" | "--help" | "--install"
                    )
                {
                    idx = seg.len();
                    break;
                }
            }
            "nice" => {
                idx += 1;
                while idx < seg.len() && seg[idx].starts_with('-') {
                    if seg[idx] == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    if seg[idx] == "-n" || seg[idx] == "--adjustment" {
                        idx += 2;
                    } else {
                        idx += 1;
                    }
                }
            }
            "timeout" => {
                idx += 1;
                while idx < seg.len() {
                    let arg = seg[idx].as_str();
                    if arg == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    if matches!(arg, "-k" | "--kill-after" | "-s" | "--signal") {
                        idx += 2;
                        continue;
                    }
                    if arg.starts_with('-') {
                        if !arg.starts_with("--")
                            && arg.len() >= 2
                            && matches!(arg.as_bytes().last(), Some(b'k' | b's'))
                            && !arg[1..arg.len() - 1].contains(['k', 's'])
                        {
                            idx += 2;
                        } else {
                            idx += 1;
                        }
                        continue;
                    }
                    break;
                }
                // Consume mandatory DURATION operand.
                if idx < seg.len() {
                    idx += 1;
                }
            }
            "stdbuf" => {
                idx += 1;
                while idx < seg.len() && seg[idx].starts_with('-') {
                    let arg = seg[idx].as_str();
                    if arg == "--" {
                        idx += 1;
                        inhibit_outer_env_assignment = true;
                        break;
                    }
                    if matches!(arg, "-i" | "--input" | "-o" | "--output" | "-e" | "--error") {
                        idx += 2;
                        continue;
                    }
                    if !arg.starts_with("--")
                        && arg.len() == 2
                        && matches!(arg.as_bytes()[1], b'i' | b'o' | b'e')
                    {
                        idx += 2;
                        continue;
                    }
                    idx += 1;
                }
            }
            _ => break,
        }
    }
    seg.drain(0..idx.min(seg.len()));
    StrippedCommandSegment {
        tokens: seg,
        chdir_dirs,
        wrapper_write_targets,
        wrapper_inner_scripts,
    }
}

fn decode_ansi_c_escape(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    out: &mut String,
) -> usize {
    let Some(first) = chars.next() else {
        out.push('\\');
        return 0;
    };
    let mut consumed = first.len_utf8();
    match first {
        '\'' => out.push('\''),
        '"' => out.push('"'),
        '\\' => out.push('\\'),
        'a' => out.push('\x07'),
        'b' => out.push('\x08'),
        'e' | 'E' => out.push('\x1b'),
        'f' => out.push('\x0c'),
        'n' => out.push('\n'),
        'r' => out.push('\r'),
        't' => out.push('\t'),
        'v' => out.push('\x0b'),
        'x' => {
            let mut hex = String::new();
            for _ in 0..2 {
                if let Some(&d) = chars.peek() {
                    if d.is_ascii_hexdigit() {
                        hex.push(d);
                        chars.next();
                        consumed += d.len_utf8();
                    } else {
                        break;
                    }
                }
            }
            if let Ok(v) = u8::from_str_radix(&hex, 16) {
                out.push(v as char);
            } else {
                out.push_str("\\x");
            }
        }
        'u' => {
            let mut hex = String::new();
            for _ in 0..4 {
                if let Some(&d) = chars.peek() {
                    if d.is_ascii_hexdigit() {
                        hex.push(d);
                        chars.next();
                        consumed += d.len_utf8();
                    } else {
                        break;
                    }
                }
            }
            if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                out.push(ch);
            } else {
                out.push_str("\\u");
                out.push_str(&hex);
            }
        }
        'U' => {
            let mut hex = String::new();
            for _ in 0..8 {
                if let Some(&d) = chars.peek() {
                    if d.is_ascii_hexdigit() {
                        hex.push(d);
                        chars.next();
                        consumed += d.len_utf8();
                    } else {
                        break;
                    }
                }
            }
            if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                out.push(ch);
            } else {
                out.push_str("\\U");
                out.push_str(&hex);
            }
        }
        d @ '0'..='7' => {
            let mut oct = String::new();
            oct.push(d);
            for _ in 0..2 {
                if let Some(&nd) = chars.peek() {
                    if ('0'..='7').contains(&nd) {
                        oct.push(nd);
                        chars.next();
                        consumed += nd.len_utf8();
                    } else {
                        break;
                    }
                }
            }
            if let Ok(v) = u8::from_str_radix(&oct, 8) {
                out.push(v as char);
            }
        }
        other => {
            out.push('\\');
            out.push(other);
        }
    }
    consumed
}

fn strip_ps_backticks_outside_single_quotes(script: &str) -> String {
    let mut out = String::with_capacity(script.len());
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = script.chars().peekable();
    while let Some(c) = chars.next() {
        if in_single {
            if c == '\'' {
                in_single = false;
            }
            out.push(c);
        } else if in_double {
            if c == '`' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    out.push('"');
                } else if chars.peek() == Some(&'`') {
                    chars.next();
                    out.push('`');
                }
            } else {
                if c == '"' {
                    in_double = false;
                }
                out.push(c);
            }
        } else if c == '\'' {
            in_single = true;
            out.push(c);
        } else if c == '"' {
            in_double = true;
            out.push(c);
        } else if c != '`' {
            out.push(c);
        }
    }
    out
}

fn tokenize_shell_segments_raw(cmd: &str) -> Vec<Vec<String>> {
    let mut segments: Vec<Vec<String>> = Vec::new();
    let mut current_seg: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut token_started = false;
    let mut in_single = false;
    let mut in_ansi_single = false;
    let mut in_double = false;
    let mut prev_char: Option<char> = None;

    let mut chars = cmd.chars().peekable();
    while let Some(c) = chars.next() {
        if in_ansi_single {
            if c == '\'' {
                in_ansi_single = false;
                prev_char = Some(c);
            } else if c == '\\' {
                let _ = decode_ansi_c_escape(&mut chars, &mut current);
                prev_char = None;
            } else {
                current.push(c);
                prev_char = Some(c);
            }
            continue;
        }
        if in_single {
            if c == '\'' {
                in_single = false;
            } else {
                current.push(c);
            }
            prev_char = Some(c);
            continue;
        }
        if in_double {
            if c == '\\' {
                // Inside double quotes: only escape \" or \\ (Windows path safe)
                if let Some(&next_c) = chars.peek() {
                    if next_c == '"' || next_c == '\\' {
                        chars.next();
                        current.push(next_c);
                        prev_char = Some(next_c);
                    } else {
                        current.push('\\');
                        prev_char = Some('\\');
                    }
                } else {
                    current.push('\\');
                    prev_char = Some('\\');
                }
                continue;
            }
            if c == '"' {
                in_double = false;
            } else {
                current.push(c);
            }
            prev_char = Some(c);
            continue;
        }

        // Unquoted
        match c {
            '\\' => {
                // Outside quotes: only escape shell metacharacters/whitespace/quotes (Windows path safe)
                token_started = true;
                if let Some(&next_c) = chars.peek() {
                    if matches!(
                        next_c,
                        ' ' | '\t' | '"' | '\'' | '\\' | ';' | '&' | '|' | '<' | '>'
                    ) {
                        chars.next();
                        current.push(next_c);
                        prev_char = Some(next_c);
                    } else {
                        current.push('\\');
                        prev_char = Some('\\');
                    }
                } else {
                    current.push('\\');
                    prev_char = Some('\\');
                }
                continue;
            }
            '$' if chars.peek() == Some(&'\'') => {
                chars.next();
                in_ansi_single = true;
                token_started = true;
                prev_char = Some('\'');
                continue;
            }
            '$' if chars.peek() == Some(&'"') => {
                chars.next();
                in_double = true;
                token_started = true;
                prev_char = Some('"');
                continue;
            }
            '\'' => {
                in_single = true;
                token_started = true;
            }
            '"' => {
                in_double = true;
                token_started = true;
            }
            ';' | '|' | '\n' | '\r' | '(' | ')' | '`' => {
                if token_started {
                    current_seg.push(std::mem::take(&mut current));
                    token_started = false;
                }
                if c == '|' && chars.peek() == Some(&'|') {
                    chars.next();
                }
                if !current_seg.is_empty() {
                    segments.push(std::mem::take(&mut current_seg));
                }
            }
            '&' => {
                let next_c = chars.peek().copied();
                if prev_char == Some('>') {
                    // Part of `>&` or `2>&1` redirection — do not split segment
                    if token_started {
                        current_seg.push(std::mem::take(&mut current));
                        token_started = false;
                    }
                } else if next_c == Some('>') {
                    // Part of `&>` or `&>>` redirection — consume `&` and `>`(s), do not split
                    if token_started {
                        current_seg.push(std::mem::take(&mut current));
                        token_started = false;
                    }
                    chars.next();
                    if chars.peek() == Some(&'>') {
                        chars.next();
                    }
                } else {
                    if token_started {
                        current_seg.push(std::mem::take(&mut current));
                        token_started = false;
                    }
                    if next_c == Some('&') {
                        chars.next();
                    }
                    if !current_seg.is_empty() {
                        segments.push(std::mem::take(&mut current_seg));
                    }
                }
            }
            '>' | '<' => {
                if token_started {
                    current_seg.push(std::mem::take(&mut current));
                    token_started = false;
                }
            }
            _ if c.is_whitespace() => {
                if token_started {
                    current_seg.push(std::mem::take(&mut current));
                    token_started = false;
                }
            }
            _ => {
                current.push(c);
                token_started = true;
            }
        }
        prev_char = Some(c);
    }
    if token_started {
        current_seg.push(current);
    }
    if !current_seg.is_empty() {
        segments.push(current_seg);
    }
    segments
}

struct ShellSegmentWithContext {
    tokens: Vec<String>,
    chdir_dirs: Vec<String>,
}

struct ShellScriptWithContext {
    script: String,
    is_ps: bool,
    chdir_dirs: Vec<String>,
}

struct ShellCommandAnalysis {
    segments: Vec<ShellSegmentWithContext>,
    scripts: Vec<ShellScriptWithContext>,
    wrapper_write_targets: Vec<(String, Vec<String>)>,
}

fn is_relative_path_candidate(p: &str) -> bool {
    let trimmed = p.trim();
    !trimmed.is_empty()
        && !trimmed.starts_with('/')
        && !trimmed.starts_with('\\')
        && !(trimmed.len() >= 2
            && trimmed.as_bytes()[0].is_ascii_alphabetic()
            && trimmed.as_bytes()[1] == b':')
}

fn combine_chdir_target(dir: &str, target: &str) -> Option<String> {
    if !is_relative_path_candidate(target) {
        return None;
    }
    let dir_clean = dir.trim_end_matches(['/', '\\']);
    if dir_clean.is_empty() {
        return None;
    }
    Some(format!(
        "{}/{}",
        dir_clean,
        target.trim_start_matches(['/', '\\'])
    ))
}

fn resolve_effective_chdirs(inherited: &[String], local: &[String]) -> Vec<String> {
    if local.is_empty() {
        return inherited.to_vec();
    }
    if inherited.is_empty() {
        return local.to_vec();
    }
    let mut combined = Vec::new();
    for d in local {
        if is_relative_path_candidate(d) {
            for parent in inherited {
                if let Some(joined) = combine_chdir_target(parent, d) {
                    combined.push(joined);
                }
            }
        } else {
            combined.push(d.clone());
        }
    }
    combined
}

fn extract_double_quoted_cmd_subs(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_single = false;
    let mut in_ansi_single = false;
    let mut in_double = false;
    let mut chars = cmd.chars().peekable();

    while let Some(c) = chars.next() {
        if in_ansi_single {
            if c == '\\' {
                let _ = chars.next();
            } else if c == '\'' {
                in_ansi_single = false;
            }
            continue;
        }
        if in_single {
            if c == '\'' {
                in_single = false;
            }
            continue;
        }
        if in_double {
            if c == '\\' {
                let _ = chars.next();
                continue;
            }
            if c == '"' {
                in_double = false;
                continue;
            }
            if c == '$' && chars.peek() == Some(&'(') {
                chars.next();
                let mut sub = String::new();
                let mut paren_depth = 1usize;
                let mut sub_in_single = false;
                let mut sub_in_ansi_single = false;
                let mut sub_in_double = false;
                while let Some(sc) = chars.next() {
                    if sub_in_ansi_single {
                        sub.push(sc);
                        if sc == '\\' {
                            if let Some(esc) = chars.next() {
                                sub.push(esc);
                            }
                        } else if sc == '\'' {
                            sub_in_ansi_single = false;
                        }
                    } else if sub_in_single {
                        sub.push(sc);
                        if sc == '\'' {
                            sub_in_single = false;
                        }
                    } else if sub_in_double {
                        sub.push(sc);
                        if sc == '\\' {
                            if let Some(esc) = chars.next() {
                                sub.push(esc);
                            }
                        } else if sc == '"' {
                            sub_in_double = false;
                        }
                    } else if sc == '\\' {
                        sub.push(sc);
                        if let Some(esc) = chars.next() {
                            sub.push(esc);
                        }
                    } else if sc == '$' && chars.peek() == Some(&'\'') {
                        sub.push(sc);
                        sub.push(chars.next().unwrap());
                        sub_in_ansi_single = true;
                    } else if sc == '$' && chars.peek() == Some(&'"') {
                        sub.push(sc);
                        sub.push(chars.next().unwrap());
                        sub_in_double = true;
                    } else if sc == '\'' {
                        sub.push(sc);
                        sub_in_single = true;
                    } else if sc == '"' {
                        sub.push(sc);
                        sub_in_double = true;
                    } else if sc == '(' {
                        paren_depth += 1;
                        sub.push(sc);
                    } else if sc == ')' {
                        paren_depth -= 1;
                        if paren_depth == 0 {
                            break;
                        }
                        sub.push(sc);
                    } else {
                        sub.push(sc);
                    }
                }
                if !sub.trim().is_empty() {
                    out.push(sub);
                }
                continue;
            }
            if c == '`' {
                let mut sub = String::new();
                while let Some(sc) = chars.next() {
                    if sc == '\\' {
                        if let Some(&nc) = chars.peek() {
                            if matches!(nc, '\\' | '`' | '$' | '"') {
                                sub.push(chars.next().unwrap());
                                continue;
                            }
                        }
                        sub.push('\\');
                    } else if sc == '`' {
                        break;
                    } else {
                        sub.push(sc);
                    }
                }
                if !sub.trim().is_empty() {
                    out.push(sub);
                }
                continue;
            }
            continue;
        }

        // Unquoted
        if c == '\\' {
            let _ = chars.next();
        } else if c == '$' && chars.peek() == Some(&'\'') {
            chars.next();
            in_ansi_single = true;
        } else if c == '$' && chars.peek() == Some(&'"') {
            chars.next();
            in_double = true;
        } else if c == '\'' {
            in_single = true;
        } else if c == '"' {
            in_double = true;
        }
    }

    out
}

fn split_shell_command_segments_depth(
    cmd: &str,
    depth: u8,
    inherited_chdirs: &[String],
    out: &mut ShellCommandAnalysis,
) {
    if depth > 4 {
        return;
    }
    for sub_cmd in extract_double_quoted_cmd_subs(cmd) {
        if !sub_cmd.trim().is_empty() {
            out.scripts.push(ShellScriptWithContext {
                script: sub_cmd.clone(),
                is_ps: false,
                chdir_dirs: inherited_chdirs.to_vec(),
            });
            split_shell_command_segments_depth(&sub_cmd, depth + 1, inherited_chdirs, out);
        }
    }

    for raw_seg in tokenize_shell_segments_raw(cmd) {
        let stripped = strip_transparent_wrappers_and_env(raw_seg);
        let effective_chdirs = resolve_effective_chdirs(inherited_chdirs, &stripped.chdir_dirs);
        for target in stripped.wrapper_write_targets {
            out.wrapper_write_targets
                .push((target, effective_chdirs.clone()));
        }
        let mut inner_scripts: Vec<(String, bool)> = stripped
            .wrapper_inner_scripts
            .into_iter()
            .map(|s| (s, false))
            .collect();
        let seg = stripped.tokens;
        if seg.is_empty() {
            for (script, is_ps) in inner_scripts {
                out.scripts.push(ShellScriptWithContext {
                    script: script.clone(),
                    is_ps,
                    chdir_dirs: effective_chdirs.clone(),
                });
                split_shell_command_segments_depth(&script, depth + 1, &effective_chdirs, out);
            }
            continue;
        }
        let stem = canonical_bin_stem(&seg[0]);
        if matches!(
            stem.as_str(),
            "sh" | "bash"
                | "zsh"
                | "dash"
                | "ksh"
                | "ksh93"
                | "mksh"
                | "pdksh"
                | "ash"
                | "rbash"
                | "fish"
        ) {
            let mut i = 1usize;
            let mut saw_c = false;
            while i < seg.len() {
                let flag = seg[i].as_str();
                if flag == "--" {
                    if saw_c && i + 1 < seg.len() {
                        inner_scripts.push((seg[i + 1].clone(), false));
                    }
                    break;
                }
                if let Some(script) = flag.strip_prefix("--command=") {
                    inner_scripts.push((script.to_string(), false));
                    break;
                }
                if stem == "fish" {
                    if let Some(script) = flag.strip_prefix("--init-command=") {
                        inner_scripts.push((script.to_string(), false));
                        i += 1;
                        continue;
                    }
                    if flag == "--init-command" {
                        if i + 1 < seg.len() {
                            inner_scripts.push((seg[i + 1].clone(), false));
                            i += 2;
                        } else {
                            i += 1;
                        }
                        continue;
                    }
                    if flag.starts_with('-') && !flag.starts_with("--") {
                        let rest = &flag[1..];
                        if let Some(pos) = rest.find('C') {
                            let after_c = &rest[pos + 1..];
                            if !after_c.is_empty() {
                                inner_scripts.push((after_c.to_string(), false));
                                i += 1;
                            } else if i + 1 < seg.len() {
                                inner_scripts.push((seg[i + 1].clone(), false));
                                i += 2;
                            } else {
                                i += 1;
                            }
                            continue;
                        }
                    }
                }
                let is_short_cluster = (flag.starts_with('-') || flag.starts_with('+'))
                    && !flag.starts_with("--")
                    && flag.len() >= 2;
                if flag.starts_with('-') && !flag.starts_with("--") && flag.contains('c') {
                    saw_c = true;
                }
                if matches!(flag, "-o" | "+o" | "-O" | "+O" | "--rcfile" | "--init-file") {
                    i += 2;
                    continue;
                }
                if is_short_cluster {
                    let operand_count = flag[1..]
                        .bytes()
                        .filter(|&b| matches!(b, b'o' | b'O'))
                        .count();
                    if operand_count > 0 {
                        i += 1 + operand_count;
                        continue;
                    }
                }
                if flag == "-c"
                    || flag == "--command"
                    || (flag.starts_with('-') && !flag.starts_with("--") && flag.contains('c'))
                {
                    saw_c = true;
                    i += 1;
                    continue;
                }
                if flag.starts_with('-') || flag.starts_with('+') {
                    i += 1;
                    continue;
                }
                if saw_c {
                    inner_scripts.push((seg[i].clone(), false));
                }
                break;
            }
        } else if stem == "eval" {
            let start = if seg.get(1).map(|s| s.as_str()) == Some("--") {
                2
            } else {
                1
            };
            if start < seg.len() {
                let eval_script = seg[start..].join(" ");
                if !eval_script.trim().is_empty() {
                    inner_scripts.push((eval_script, false));
                }
            }
        } else if stem == "cmd" {
            let mut i = 1usize;
            while i < seg.len() {
                if seg[i].eq_ignore_ascii_case("/c") || seg[i].eq_ignore_ascii_case("/k") {
                    if i + 1 < seg.len() {
                        inner_scripts.push((seg[i + 1..].join(" "), false));
                    }
                    break;
                }
                i += 1;
            }
        } else if matches!(stem.as_str(), "powershell" | "pwsh") {
            let ps_params = crate::security::command_line::parse_powershell_args(&seg[1..]);
            let mut saw_file = false;
            let mut saw_command_or_enc = false;
            let mut positional_cmds: Vec<String> = Vec::new();
            for param in ps_params {
                match param {
                    crate::security::command_line::PsParameter::EncodedCommand(b64) => {
                        saw_command_or_enc = true;
                        if let crate::security::command_line::EncodedCommandState::Decoded {
                            decoded_utf16le,
                            ..
                        } = crate::security::command_line::decode_encoded_command(&b64)
                        {
                            let norm = strip_ps_backticks_outside_single_quotes(&decoded_utf16le);
                            if !norm.trim().is_empty() {
                                inner_scripts.push((norm, true));
                            }
                        }
                    }
                    crate::security::command_line::PsParameter::Command(ps_cmd) => {
                        saw_command_or_enc = true;
                        let norm = strip_ps_backticks_outside_single_quotes(&ps_cmd);
                        if !norm.trim().is_empty() {
                            inner_scripts.push((norm, true));
                        }
                    }
                    crate::security::command_line::PsParameter::File(_) => {
                        saw_file = true;
                    }
                    crate::security::command_line::PsParameter::Positional(pos) => {
                        let trimmed = pos.trim();
                        if !saw_file && !saw_command_or_enc && !trimmed.is_empty() {
                            let lower = trimmed.to_ascii_lowercase();
                            let is_script_path_only = positional_cmds.is_empty()
                                && !trimmed.chars().any(|c| {
                                    c.is_whitespace()
                                        || matches!(
                                            c,
                                            ';' | '&'
                                                | '|'
                                                | '<'
                                                | '>'
                                                | '('
                                                | ')'
                                                | '`'
                                                | '"'
                                                | '\''
                                        )
                                })
                                && (lower.ends_with(".ps1")
                                    || lower.ends_with(".psm1")
                                    || lower.ends_with(".psd1"));
                            if is_script_path_only {
                                saw_file = true;
                            } else {
                                positional_cmds.push(pos);
                            }
                        }
                    }
                    _ => {}
                }
            }
            if !saw_file && !positional_cmds.is_empty() {
                let joined = strip_ps_backticks_outside_single_quotes(&positional_cmds.join(" "));
                if !joined.trim().is_empty() {
                    inner_scripts.push((joined, true));
                }
                if positional_cmds.len() > 1 {
                    for pos in positional_cmds {
                        if pos.chars().any(|c| {
                            c.is_whitespace()
                                || matches!(c, ';' | '&' | '|' | '<' | '>' | '(' | ')')
                        }) {
                            let norm = strip_ps_backticks_outside_single_quotes(&pos);
                            if !norm.trim().is_empty() {
                                inner_scripts.push((norm, true));
                            }
                        }
                    }
                }
            }
        }
        out.segments.push(ShellSegmentWithContext {
            tokens: seg,
            chdir_dirs: effective_chdirs.clone(),
        });
        for (script, is_ps) in inner_scripts {
            out.scripts.push(ShellScriptWithContext {
                script: script.clone(),
                is_ps,
                chdir_dirs: effective_chdirs.clone(),
            });
            split_shell_command_segments_depth(&script, depth + 1, &effective_chdirs, out);
        }
    }
}

fn analyze_shell_command(cmd: &str) -> ShellCommandAnalysis {
    let mut out = ShellCommandAnalysis {
        segments: Vec::new(),
        scripts: vec![ShellScriptWithContext {
            script: cmd.to_string(),
            is_ps: false,
            chdir_dirs: Vec::new(),
        }],
        wrapper_write_targets: Vec::new(),
    };
    split_shell_command_segments_depth(cmd, 0, &[], &mut out);
    out
}

fn split_shell_command_segments_and_scripts(cmd: &str) -> (Vec<Vec<String>>, Vec<(String, bool)>) {
    let analysis = analyze_shell_command(cmd);
    let segs = analysis.segments.into_iter().map(|s| s.tokens).collect();
    let scripts = analysis
        .scripts
        .into_iter()
        .map(|s| (s.script, s.is_ps))
        .collect();
    (segs, scripts)
}

fn detect_git_config_write_deny(seg: &[String]) -> Option<String> {
    let mut idx = 1usize;
    let mut subcmd_idx: Option<usize> = None;
    while idx < seg.len() {
        let tok = seg[idx].as_str();
        if tok == "--" {
            break;
        }
        if matches!(
            tok,
            "-C" | "-c"
                | "--git-dir"
                | "--work-tree"
                | "--namespace"
                | "--exec-path"
                | "--super-prefix"
                | "--config-env"
                | "--list-cmds"
        ) {
            idx += 2;
            continue;
        }
        if tok.starts_with('-') {
            idx += 1;
            continue;
        }
        subcmd_idx = Some(idx);
        break;
    }

    let s_idx = subcmd_idx?;
    if seg[s_idx] != "config" {
        return None;
    }

    let mut has_mutating_flag = false;
    let mut has_readonly_flag = false;
    let mut positional: Vec<&str> = Vec::new();
    let mut after_double_dash = false;
    let mut i = s_idx + 1;
    while i < seg.len() {
        let tok = seg[i].as_str();
        if !after_double_dash && tok == "--" {
            after_double_dash = true;
            i += 1;
            continue;
        }
        if !after_double_dash && tok.starts_with('-') {
            if matches!(
                tok,
                "-f" | "--file" | "--blob" | "-t" | "--type" | "--default"
            ) {
                i += 2;
                continue;
            }
            if tok.starts_with("--file=")
                || tok.starts_with("--blob=")
                || tok.starts_with("--type=")
                || tok.starts_with("--default=")
            {
                i += 1;
                continue;
            }
            if matches!(
                tok,
                "--add"
                    | "--replace-all"
                    | "--unset"
                    | "--unset-all"
                    | "--rename-section"
                    | "--remove-section"
                    | "--edit"
                    | "-e"
            ) || (!tok.starts_with("--") && tok[1..].contains('e'))
            {
                has_mutating_flag = true;
            } else if matches!(
                tok,
                "--list"
                    | "-l"
                    | "--get"
                    | "--get-all"
                    | "--get-regexp"
                    | "--get-urlmatch"
                    | "--get-color"
                    | "--get-colorbool"
                    | "--help"
                    | "-h"
            ) || (!tok.starts_with("--") && tok[1..].contains('l'))
            {
                has_readonly_flag = true;
            }
            i += 1;
            continue;
        }
        positional.push(tok);
        i += 1;
    }

    let first_pos = positional.first().copied();
    let is_mutating_subcmd = matches!(
        first_pos,
        Some("set" | "unset" | "rename-section" | "remove-section" | "edit")
    );
    let is_readonly_subcmd = matches!(first_pos, Some("list" | "get"));

    if has_mutating_flag
        || is_mutating_subcmd
        || (!has_readonly_flag && !is_readonly_subcmd && positional.len() >= 2)
    {
        return Some(format!(
            "{} ('git config')",
            crate::security::sensitive_paths::MandatoryWriteDenyKind::GitHooksOrConfig
                .description()
        ));
    }
    None
}

fn url_basename_candidate(url: &str) -> &str {
    let without_qf = url.split(['?', '#']).next().unwrap_or(url);
    without_qf.rsplit('/').next().unwrap_or(without_qf)
}

fn url_path_candidate(url: &str) -> &str {
    let without_qf = url.split(['?', '#']).next().unwrap_or(url);
    if let Some(scheme_pos) = without_qf.find("://") {
        let after_scheme = &without_qf[scheme_pos + 3..];
        if let Some(slash_pos) = after_scheme.find('/') {
            return after_scheme[slash_pos + 1..].trim_start_matches('/');
        }
        return "";
    }
    without_qf.trim_start_matches('/')
}

fn check_target_with_chdirs(
    target: &str,
    allow_pinned_parent: bool,
    chdir_dirs: &[String],
) -> Option<String> {
    if let Some(reason) = check_shell_write_deny_path_candidate(target, allow_pinned_parent) {
        return Some(reason);
    }
    for dir in chdir_dirs {
        if let Some(combined) = combine_chdir_target(dir, target) {
            if let Some(reason) =
                check_shell_write_deny_path_candidate(&combined, allow_pinned_parent)
            {
                return Some(reason);
            }
        }
    }
    None
}

fn detect_curl_write_deny(seg: &[String], chdir_dirs: &[String]) -> Option<String> {
    let mut write_targets: Vec<String> = Vec::new();
    let mut output_file_targets: Vec<String> = Vec::new();
    let mut output_dir: Option<String> = None;
    let mut urls: Vec<&str> = Vec::new();
    let mut remote_name = false;
    let mut after_double_dash = false;
    let mut i = 1usize;

    while i < seg.len() {
        let tok = seg[i].as_str();
        if !after_double_dash && tok == "--" {
            after_double_dash = true;
            i += 1;
            continue;
        }
        if !after_double_dash && tok.starts_with('-') && tok.len() > 1 {
            if tok == "--output-dir" {
                if i + 1 < seg.len() {
                    output_dir = Some(seg[i + 1].clone());
                    i += 2;
                    continue;
                }
            }
            if let Some(val) = tok.strip_prefix("--output-dir=") {
                output_dir = Some(val.to_string());
                i += 1;
                continue;
            }
            if let Some(val) = tok.strip_prefix("--url=") {
                urls.push(val);
                i += 1;
                continue;
            }
            if matches!(
                tok,
                "-o" | "--output"
                    | "-D"
                    | "--dump-header"
                    | "-c"
                    | "--cookie-jar"
                    | "--trace"
                    | "--trace-ascii"
            ) {
                if i + 1 < seg.len() {
                    let target = seg[i + 1].clone();
                    if matches!(tok, "-o" | "--output") {
                        output_file_targets.push(target.clone());
                    }
                    write_targets.push(target);
                    i += 2;
                    continue;
                }
            }
            if let Some(val) = tok.strip_prefix("--output=") {
                output_file_targets.push(val.to_string());
                write_targets.push(val.to_string());
                i += 1;
                continue;
            }
            if let Some(val) = tok
                .strip_prefix("--dump-header=")
                .or_else(|| tok.strip_prefix("--cookie-jar="))
                .or_else(|| tok.strip_prefix("--trace="))
                .or_else(|| tok.strip_prefix("--trace-ascii="))
            {
                write_targets.push(val.to_string());
                i += 1;
                continue;
            }
            if matches!(tok, "-O" | "--remote-name" | "--remote-name-all") {
                remote_name = true;
                i += 1;
                continue;
            }
            if !tok.starts_with("--") {
                let rest = &tok[1..];
                let mut consumed = false;
                for (pos, ch) in rest.char_indices() {
                    if matches!(ch, 'o' | 'D' | 'c') {
                        let after_flag = &rest[pos + ch.len_utf8()..];
                        if !after_flag.is_empty() {
                            if ch == 'o' {
                                output_file_targets.push(after_flag.to_string());
                            }
                            write_targets.push(after_flag.to_string());
                            i += 1;
                        } else if i + 1 < seg.len() {
                            let target = seg[i + 1].clone();
                            if ch == 'o' {
                                output_file_targets.push(target.clone());
                            }
                            write_targets.push(target);
                            i += 2;
                        } else {
                            i += 1;
                        }
                        consumed = true;
                        break;
                    }
                    if matches!(
                        ch,
                        'd' | 'u'
                            | 'A'
                            | 'H'
                            | 'X'
                            | 'b'
                            | 'e'
                            | 'F'
                            | 'T'
                            | 'm'
                            | 'w'
                            | 'r'
                            | 'E'
                            | 'K'
                            | 'x'
                            | 'U'
                            | 'Y'
                            | 'y'
                            | 'z'
                            | 'Q'
                            | 'C'
                            | 't'
                            | 'P'
                    ) {
                        let after_flag = &rest[pos + ch.len_utf8()..];
                        if !after_flag.is_empty() {
                            i += 1;
                        } else if i + 1 < seg.len() {
                            i += 2;
                        } else {
                            i += 1;
                        }
                        consumed = true;
                        break;
                    }
                    if ch == 'O' {
                        remote_name = true;
                    }
                }
                if consumed {
                    continue;
                }
                i += 1;
                continue;
            }
            if matches!(
                tok,
                "--request"
                    | "--header"
                    | "--data"
                    | "--data-raw"
                    | "--data-binary"
                    | "--data-urlencode"
                    | "--user"
                    | "--user-agent"
                    | "--referer"
                    | "--cookie"
                    | "--form"
                    | "--upload-file"
                    | "--max-time"
                    | "--connect-timeout"
                    | "--write-out"
                    | "--range"
                    | "--cert"
                    | "--config"
                    | "--proxy"
                    | "--proxy-user"
                    | "--resolve"
                    | "--interface"
            ) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        urls.push(tok);
        i += 1;
    }

    if let Some(ref dir) = output_dir {
        if let Some(reason) = check_target_with_chdirs(dir, true, chdir_dirs) {
            return Some(reason);
        }
    }
    for t in &write_targets {
        if t != "-" {
            if let Some(reason) = check_target_with_chdirs(t, false, chdir_dirs) {
                return Some(reason);
            }
        }
    }
    if let Some(ref dir) = output_dir {
        let dir_clean = dir.trim_end_matches(['/', '\\']);
        for t in &output_file_targets {
            if t != "-" {
                let combined = format!("{}/{}", dir_clean, t.trim_start_matches(['/', '\\']));
                if let Some(reason) = check_target_with_chdirs(&combined, false, chdir_dirs) {
                    return Some(reason);
                }
            }
        }
    }
    if remote_name {
        for url in urls {
            let base = url_basename_candidate(url);
            if !base.is_empty() {
                if let Some(reason) = check_target_with_chdirs(base, false, chdir_dirs) {
                    return Some(reason);
                }
                if let Some(ref dir) = output_dir {
                    let combined = format!("{}/{}", dir.trim_end_matches(['/', '\\']), base);
                    if let Some(reason) = check_target_with_chdirs(&combined, false, chdir_dirs) {
                        return Some(reason);
                    }
                }
            }
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn apply_wget_execute_directive(
    expr: &str,
    write_targets: &mut Vec<String>,
    has_explicit_doc: &mut bool,
    dir_prefix: &mut Option<String>,
    default_page: &mut Option<String>,
    force_directories: &mut bool,
) {
    let Some((raw_k, raw_v)) = expr.split_once('=') else {
        return;
    };
    let key: String = raw_k
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| !matches!(c, '_' | '-'))
        .collect();
    let val = raw_v.trim().trim_matches(['"', '\'']).to_string();
    match key.as_str() {
        "outputdocument" => {
            *has_explicit_doc = true;
            write_targets.push(val);
        }
        "logfile" | "appendoutput" => {
            write_targets.push(val);
        }
        "dirprefix" => {
            *dir_prefix = Some(val);
        }
        "defaultpage" => {
            *default_page = Some(val);
        }
        "forcedirectories" | "recursive" | "mirror" => {
            if matches!(
                val.to_ascii_lowercase().as_str(),
                "on" | "1" | "yes" | "true"
            ) {
                *force_directories = true;
            }
        }
        _ => {}
    }
}

fn detect_wget_write_deny(seg: &[String], chdir_dirs: &[String]) -> Option<String> {
    let mut write_targets: Vec<String> = Vec::new();
    let mut has_explicit_doc = false;
    let mut is_spider = false;
    let mut force_directories = false;
    let mut dir_prefix: Option<String> = None;
    let mut default_page: Option<String> = None;
    let mut urls: Vec<&str> = Vec::new();
    let mut after_double_dash = false;
    let mut i = 1usize;

    while i < seg.len() {
        let tok = seg[i].as_str();
        if !after_double_dash && tok == "--" {
            after_double_dash = true;
            i += 1;
            continue;
        }
        if !after_double_dash && tok.starts_with('-') && tok.len() > 1 {
            if tok == "--spider" {
                is_spider = true;
                i += 1;
                continue;
            }
            if matches!(
                tok,
                "--force-directories" | "--recursive" | "--mirror" | "--page-requisites"
            ) {
                force_directories = true;
                i += 1;
                continue;
            }
            if matches!(
                tok,
                "-O" | "--output-document" | "-o" | "--output-file" | "-a" | "--append-output"
            ) {
                if matches!(tok, "-O" | "--output-document") {
                    has_explicit_doc = true;
                }
                if i + 1 < seg.len() {
                    write_targets.push(seg[i + 1].clone());
                    i += 2;
                    continue;
                }
            }
            if let Some(val) = tok
                .strip_prefix("--output-document=")
                .or_else(|| tok.strip_prefix("--output-file="))
                .or_else(|| tok.strip_prefix("--append-output="))
            {
                if tok.starts_with("--output-document=") {
                    has_explicit_doc = true;
                }
                write_targets.push(val.to_string());
                i += 1;
                continue;
            }
            if matches!(tok, "-P" | "--directory-prefix") {
                if i + 1 < seg.len() {
                    dir_prefix = Some(seg[i + 1].clone());
                    i += 2;
                    continue;
                }
            }
            if let Some(val) = tok.strip_prefix("--directory-prefix=") {
                dir_prefix = Some(val.to_string());
                i += 1;
                continue;
            }
            if tok == "--default-page" {
                if i + 1 < seg.len() {
                    default_page = Some(seg[i + 1].clone());
                    i += 2;
                    continue;
                }
            }
            if let Some(val) = tok.strip_prefix("--default-page=") {
                default_page = Some(val.to_string());
                i += 1;
                continue;
            }
            if tok == "--execute" {
                if i + 1 < seg.len() {
                    apply_wget_execute_directive(
                        &seg[i + 1],
                        &mut write_targets,
                        &mut has_explicit_doc,
                        &mut dir_prefix,
                        &mut default_page,
                        &mut force_directories,
                    );
                    i += 2;
                    continue;
                }
            }
            if let Some(val) = tok.strip_prefix("--execute=") {
                apply_wget_execute_directive(
                    val,
                    &mut write_targets,
                    &mut has_explicit_doc,
                    &mut dir_prefix,
                    &mut default_page,
                    &mut force_directories,
                );
                i += 1;
                continue;
            }
            if !tok.starts_with("--") {
                let rest = &tok[1..];
                let mut consumed = false;
                for (pos, ch) in rest.char_indices() {
                    if matches!(ch, 'x' | 'r' | 'm' | 'p') {
                        force_directories = true;
                    }
                    if matches!(ch, 'O' | 'o' | 'a' | 'P' | 'e') {
                        let after_flag = &rest[pos + ch.len_utf8()..];
                        let val = if !after_flag.is_empty() {
                            i += 1;
                            Some(after_flag.to_string())
                        } else if i + 1 < seg.len() {
                            let v = seg[i + 1].clone();
                            i += 2;
                            Some(v)
                        } else {
                            i += 1;
                            None
                        };
                        if let Some(val) = val {
                            if ch == 'O' {
                                has_explicit_doc = true;
                                write_targets.push(val);
                            } else if ch == 'P' {
                                dir_prefix = Some(val);
                            } else if ch == 'e' {
                                apply_wget_execute_directive(
                                    &val,
                                    &mut write_targets,
                                    &mut has_explicit_doc,
                                    &mut dir_prefix,
                                    &mut default_page,
                                    &mut force_directories,
                                );
                            } else {
                                write_targets.push(val);
                            }
                        }
                        consumed = true;
                        break;
                    }
                    if matches!(
                        ch,
                        'U' | 't' | 'T' | 'w' | 'Q' | 'i' | 'B' | 'l' | 'A' | 'R' | 'D' | 'I' | 'X'
                    ) {
                        let after_flag = &rest[pos + ch.len_utf8()..];
                        if !after_flag.is_empty() {
                            i += 1;
                        } else if i + 1 < seg.len() {
                            i += 2;
                        } else {
                            i += 1;
                        }
                        consumed = true;
                        break;
                    }
                }
                if consumed {
                    continue;
                }
                i += 1;
                continue;
            }
            if matches!(
                tok,
                "--tries"
                    | "--timeout"
                    | "--wait"
                    | "--quota"
                    | "--user-agent"
                    | "--header"
                    | "--user"
                    | "--password"
                    | "--input-file"
                    | "--base"
                    | "--level"
                    | "--accept"
                    | "--reject"
                    | "--domains"
                    | "--include-directories"
                    | "--exclude-directories"
            ) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        urls.push(tok);
        i += 1;
    }

    if let Some(ref dir) = dir_prefix {
        if let Some(reason) = check_target_with_chdirs(dir, true, chdir_dirs) {
            return Some(reason);
        }
    }
    for t in &write_targets {
        if t != "-" {
            if let Some(reason) = check_target_with_chdirs(t, false, chdir_dirs) {
                return Some(reason);
            }
            if let Some(ref dir) = dir_prefix {
                if is_relative_path_candidate(t) {
                    let combined = format!("{}/{}", dir.trim_end_matches(['/', '\\']), t);
                    if let Some(reason) = check_target_with_chdirs(&combined, false, chdir_dirs) {
                        return Some(reason);
                    }
                }
            }
        }
    }
    if !is_spider {
        if let Some(ref dp) = default_page {
            if let Some(reason) = check_target_with_chdirs(dp, false, chdir_dirs) {
                return Some(reason);
            }
            if let Some(ref dir) = dir_prefix {
                if is_relative_path_candidate(dp) {
                    let combined = format!("{}/{}", dir.trim_end_matches(['/', '\\']), dp);
                    if let Some(reason) = check_target_with_chdirs(&combined, false, chdir_dirs) {
                        return Some(reason);
                    }
                }
            }
        }
    }
    if !has_explicit_doc && !is_spider {
        for url in urls {
            let base = url_basename_candidate(url);
            if !base.is_empty() {
                if let Some(reason) = check_target_with_chdirs(base, false, chdir_dirs) {
                    return Some(reason);
                }
                if let Some(ref dir) = dir_prefix {
                    let combined = format!("{}/{}", dir.trim_end_matches(['/', '\\']), base);
                    if let Some(reason) = check_target_with_chdirs(&combined, false, chdir_dirs) {
                        return Some(reason);
                    }
                }
            }
            if force_directories {
                let url_path = url_path_candidate(url);
                if !url_path.is_empty() {
                    if let Some(reason) = check_target_with_chdirs(url_path, false, chdir_dirs) {
                        return Some(reason);
                    }
                    if let Some(ref dir) = dir_prefix {
                        let combined =
                            format!("{}/{}", dir.trim_end_matches(['/', '\\']), url_path);
                        if let Some(reason) = check_target_with_chdirs(&combined, false, chdir_dirs)
                        {
                            return Some(reason);
                        }
                    }
                }
            }
        }
    }
    None
}

fn detect_patch_write_deny(seg: &[String], chdir_dirs: &[String]) -> Option<String> {
    let mut is_dry_run = false;
    let mut write_files: Vec<String> = Vec::new();
    let mut write_dirs: Vec<String> = Vec::new();
    let mut positional: Vec<&str> = Vec::new();
    let mut after_double_dash = false;
    let mut i = 1usize;

    while i < seg.len() {
        let tok = seg[i].as_str();
        if !after_double_dash && tok == "--" {
            after_double_dash = true;
            i += 1;
            continue;
        }
        if !after_double_dash && tok.starts_with('-') && tok.len() > 1 {
            if matches!(tok, "--dry-run" | "--help" | "--version" | "-v") {
                is_dry_run = true;
                i += 1;
                continue;
            }
            if matches!(tok, "-o" | "--output") && i + 1 < seg.len() {
                write_files.push(seg[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(val) = tok.strip_prefix("--output=") {
                write_files.push(val.to_string());
                i += 1;
                continue;
            }
            if matches!(tok, "-d" | "--directory") && i + 1 < seg.len() {
                write_dirs.push(seg[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(val) = tok.strip_prefix("--directory=") {
                write_dirs.push(val.to_string());
                i += 1;
                continue;
            }
            if matches!(
                tok,
                "-p" | "--strip"
                    | "-i"
                    | "--input"
                    | "-r"
                    | "--reject-file"
                    | "-b"
                    | "--backup"
                    | "-B"
                    | "--prefix"
                    | "-z"
                    | "--suffix"
                    | "-V"
                    | "--version-control"
                    | "-F"
                    | "--fuzz"
                    | "-g"
                    | "--get"
                    | "-D"
                    | "--ifdef"
                    | "--read-only"
            ) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        positional.push(tok);
        i += 1;
    }

    if is_dry_run {
        return None;
    }
    for d in &write_dirs {
        if let Some(reason) = check_target_with_chdirs(d, true, chdir_dirs) {
            return Some(reason);
        }
    }
    for f in &write_files {
        if f != "-" {
            if let Some(reason) = check_target_with_chdirs(f, false, chdir_dirs) {
                return Some(reason);
            }
        }
    }
    for pos in &positional {
        if let Some(reason) = check_target_with_chdirs(pos, false, chdir_dirs) {
            return Some(reason);
        }
    }
    if positional.is_empty() && write_dirs.is_empty() {
        for dir in chdir_dirs {
            if let Some(reason) = check_shell_write_deny_path_candidate(dir, true) {
                return Some(reason);
            }
        }
    }
    None
}

fn tar_one_top_level_stem(archive: &str) -> &str {
    let base = archive.rsplit(['/', '\\']).next().unwrap_or(archive);
    for suffix in [
        ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tgz", ".tbz2", ".txz", ".tzst", ".tar",
    ] {
        if let Some(stripped) = base.strip_suffix(suffix) {
            if !stripped.is_empty() {
                return stripped;
            }
        }
    }
    base
}

fn apply_tar_sed_clause(input: &str, pat: &str, repl: &str, global: bool) -> String {
    let expand_repl = |matched: &str| -> String { repl.replace('&', matched) };
    if pat == "^" {
        return format!("{}{}", expand_repl(""), input);
    }
    if pat == "$" {
        return format!("{}{}", input, expand_repl(""));
    }
    if pat == ".*" || pat == "^.*$" {
        return expand_repl(input);
    }
    if let Some(prefix) = pat.strip_prefix('^') {
        if !prefix.contains(['*', '+', '?', '[', ']', '(', ')', '|', '$']) {
            if let Some(rest) = input.strip_prefix(prefix) {
                return format!("{}{}", expand_repl(prefix), rest);
            }
            return input.to_string();
        }
    }
    if let Some(suffix) = pat.strip_suffix('$') {
        if !suffix.contains(['*', '+', '?', '[', ']', '(', ')', '|', '^']) {
            if let Some(head) = input.strip_suffix(suffix) {
                return format!("{}{}", head, expand_repl(suffix));
            }
            return input.to_string();
        }
    }
    if !pat.is_empty() && !pat.contains(['^', '$', '*', '+', '?', '[', ']', '(', ')', '|', '.']) {
        if global {
            return input.replace(pat, &expand_repl(pat));
        }
        if let Some((before, after)) = input.split_once(pat) {
            return format!("{}{}{}", before, expand_repl(pat), after);
        }
    }
    input.to_string()
}

fn extract_tar_transform_candidates(expr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut clauses: Vec<(String, String, bool)> = Vec::new();
    for sub in expr.split(';') {
        let trimmed = sub.trim();
        let Some(after_s) = trimmed.strip_prefix('s') else {
            continue;
        };
        let mut chars = after_s.chars();
        let Some(delim) = chars.next() else {
            continue;
        };
        let mut escaped = false;
        let mut found_pattern_end = false;
        let mut found_repl_end = false;
        let mut pat = String::new();
        let mut repl_raw = String::new();
        let mut repl_clean = String::new();
        let mut flags = String::new();
        for c in chars {
            if !found_pattern_end {
                if escaped {
                    if c != delim {
                        pat.push('\\');
                    }
                    pat.push(c);
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == delim {
                    found_pattern_end = true;
                } else {
                    pat.push(c);
                }
            } else if !found_repl_end {
                if escaped {
                    if c == delim {
                        repl_raw.push(delim);
                        repl_clean.push(delim);
                    } else if !c.is_ascii_digit() {
                        repl_raw.push(c);
                        repl_clean.push(c);
                    }
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == delim {
                    found_repl_end = true;
                } else {
                    repl_raw.push(c);
                    if c != '&' {
                        repl_clean.push(c);
                    }
                }
            } else {
                flags.push(c);
            }
        }
        let cleaned = repl_clean.trim();
        if !cleaned.is_empty() {
            out.push(cleaned.to_string());
        }
        clauses.push((pat, repl_raw, flags.contains('g')));
    }
    if clauses.len() >= 2 {
        let joined: String = clauses
            .iter()
            .map(|(_, r, _)| r.replace('&', ""))
            .collect::<String>();
        let joined_trimmed = joined.trim();
        if !joined_trimmed.is_empty() && !out.iter().any(|x| x == joined_trimmed) {
            out.push(joined_trimmed.to_string());
        }
        for sample in ["", "foo", "file.txt", "sub/file"] {
            let mut val = sample.to_string();
            for (pat, repl, global) in &clauses {
                val = apply_tar_sed_clause(&val, pat, repl, *global);
            }
            let val_trimmed = val.trim();
            if !val_trimmed.is_empty() && !out.iter().any(|x| x == val_trimmed) {
                out.push(val_trimmed.to_string());
            }
        }
    }
    if out.is_empty() && !expr.trim().is_empty() {
        out.push(expr.trim().to_string());
    }
    out
}

fn detect_tar_write_deny(seg: &[String], chdir_dirs: &[String]) -> Option<String> {
    let mut is_extract = false;
    let mut is_create_or_update = false;
    let mut is_list = false;
    let mut has_one_top_level_default = false;
    let mut dirs: Vec<String> = Vec::new();
    let mut archives: Vec<String> = Vec::new();
    let mut members: Vec<String> = Vec::new();
    let mut hook_commands: Vec<String> = Vec::new();
    let mut transforms: Vec<String> = Vec::new();
    let mut after_double_dash = false;
    let mut i = 1usize;

    while i < seg.len() {
        let tok = seg[i].as_str();
        if !after_double_dash && tok == "--" {
            after_double_dash = true;
            i += 1;
            continue;
        }
        let is_dashless_cluster = i == 1
            && !after_double_dash
            && !tok.starts_with('-')
            && !tok.contains('/')
            && !tok.contains('\\')
            && !tok.contains('.')
            && !tok.is_empty()
            && tok.chars().all(|c| c.is_ascii_alphabetic());

        if !after_double_dash && ((tok.starts_with('-') && tok.len() > 1) || is_dashless_cluster) {
            if matches!(tok, "--extract" | "--get") {
                is_extract = true;
                i += 1;
                continue;
            }
            if matches!(tok, "--create" | "--append" | "--update") {
                is_create_or_update = true;
                i += 1;
                continue;
            }
            if tok == "--list" {
                is_list = true;
                i += 1;
                continue;
            }
            if matches!(tok, "-C" | "--directory") && i + 1 < seg.len() {
                dirs.push(seg[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(val) = tok.strip_prefix("--directory=") {
                dirs.push(val.to_string());
                i += 1;
                continue;
            }
            if tok == "--one-top-level" {
                has_one_top_level_default = true;
                i += 1;
                continue;
            }
            if let Some(val) = tok.strip_prefix("--one-top-level=") {
                dirs.push(val.to_string());
                i += 1;
                continue;
            }
            if matches!(tok, "-f" | "--file") && i + 1 < seg.len() {
                archives.push(seg[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(val) = tok.strip_prefix("--file=") {
                archives.push(val.to_string());
                i += 1;
                continue;
            }
            if matches!(tok, "--to-command" | "--use-compress-program") && i + 1 < seg.len() {
                hook_commands.push(seg[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(val) = tok
                .strip_prefix("--to-command=")
                .or_else(|| tok.strip_prefix("--use-compress-program="))
            {
                hook_commands.push(val.to_string());
                i += 1;
                continue;
            }
            if tok == "--checkpoint-action" && i + 1 < seg.len() {
                if let Some(cmd) = seg[i + 1].strip_prefix("exec=") {
                    hook_commands.push(cmd.to_string());
                }
                i += 2;
                continue;
            }
            if let Some(val) = tok.strip_prefix("--checkpoint-action=") {
                if let Some(cmd) = val.strip_prefix("exec=") {
                    hook_commands.push(cmd.to_string());
                }
                i += 1;
                continue;
            }
            if matches!(tok, "--transform" | "--xform") && i + 1 < seg.len() {
                transforms.push(seg[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(val) = tok
                .strip_prefix("--transform=")
                .or_else(|| tok.strip_prefix("--xform="))
            {
                transforms.push(val.to_string());
                i += 1;
                continue;
            }
            if matches!(
                tok,
                "-b" | "-T"
                    | "--files-from"
                    | "-X"
                    | "--exclude-from"
                    | "-s"
                    | "--exclude"
                    | "--strip-components"
            ) {
                i += 2;
                continue;
            }
            if !tok.starts_with("--") {
                let cluster = tok.strip_prefix('-').unwrap_or(tok);
                if cluster.contains('x') {
                    is_extract = true;
                }
                if cluster.contains('c') || cluster.contains('r') || cluster.contains('u') {
                    is_create_or_update = true;
                }
                if cluster.contains('t') {
                    is_list = true;
                }
                if let Some(pos) = cluster.find(['f', 'C', 'I']) {
                    let ch = cluster.as_bytes()[pos];
                    let after_flag = &cluster[pos + 1..];
                    let val = if !after_flag.is_empty() {
                        i += 1;
                        Some(after_flag.to_string())
                    } else if i + 1 < seg.len() {
                        let v = seg[i + 1].clone();
                        i += 2;
                        Some(v)
                    } else {
                        i += 1;
                        None
                    };
                    if let Some(v) = val {
                        if ch == b'f' {
                            archives.push(v);
                        } else if ch == b'C' {
                            dirs.push(v);
                        } else {
                            hook_commands.push(v);
                        }
                    }
                    continue;
                }
            }
            i += 1;
            continue;
        }
        members.push(tok.to_string());
        i += 1;
    }

    for cmd in &hook_commands {
        if let Some(reason) = detect_shell_mandatory_write_deny(cmd) {
            return Some(reason);
        }
    }
    if is_list && !is_extract && !is_create_or_update {
        return None;
    }
    if is_extract {
        for d in chdir_dirs {
            if let Some(reason) = check_shell_write_deny_path_candidate(d, true) {
                return Some(reason);
            }
        }
        for d in &dirs {
            if let Some(reason) = check_target_with_chdirs(d, true, chdir_dirs) {
                return Some(reason);
            }
        }
        for expr in &transforms {
            for cand in extract_tar_transform_candidates(expr) {
                if let Some(reason) = check_target_with_chdirs(&cand, true, chdir_dirs) {
                    return Some(reason);
                }
                for d in &dirs {
                    let combined = format!("{}/{}", d.trim_end_matches(['/', '\\']), cand);
                    if let Some(reason) = check_target_with_chdirs(&combined, true, chdir_dirs) {
                        return Some(reason);
                    }
                }
            }
        }
        if has_one_top_level_default {
            for arch in &archives {
                if arch != "-" {
                    let stem = tar_one_top_level_stem(arch);
                    if let Some(reason) = check_target_with_chdirs(stem, true, chdir_dirs) {
                        return Some(reason);
                    }
                }
            }
        }
        for m in &members {
            if let Some(reason) = check_target_with_chdirs(m, true, chdir_dirs) {
                return Some(reason);
            }
            for d in &dirs {
                let combined = format!("{}/{}", d.trim_end_matches(['/', '\\']), m);
                if let Some(reason) = check_target_with_chdirs(&combined, true, chdir_dirs) {
                    return Some(reason);
                }
            }
        }
    }
    if is_create_or_update {
        for arch in &archives {
            if arch != "-" {
                if let Some(reason) = check_target_with_chdirs(arch, false, chdir_dirs) {
                    return Some(reason);
                }
            }
        }
    }
    None
}

fn detect_unzip_write_deny(seg: &[String], chdir_dirs: &[String]) -> Option<String> {
    let mut is_list_or_test = false;
    let mut dirs: Vec<String> = Vec::new();
    let mut archive: Option<String> = None;
    let mut members: Vec<String> = Vec::new();
    let mut in_exclude = false;
    let mut after_double_dash = false;
    let mut i = 1usize;

    while i < seg.len() {
        let tok = seg[i].as_str();
        if !after_double_dash && tok == "--" {
            after_double_dash = true;
            in_exclude = false;
            i += 1;
            continue;
        }
        if !after_double_dash && tok.starts_with('-') && tok.len() > 1 {
            in_exclude = false;
            if matches!(tok, "--help" | "--version") {
                is_list_or_test = true;
                i += 1;
                continue;
            }
            if tok == "-d" {
                if i + 1 < seg.len() {
                    dirs.push(seg[i + 1].clone());
                    i += 2;
                    continue;
                }
            }
            if let Some(val) = tok.strip_prefix("-d") {
                if !val.is_empty() {
                    dirs.push(val.to_string());
                    i += 1;
                    continue;
                }
            }
            if tok == "-x" {
                in_exclude = true;
                i += 1;
                continue;
            }
            if matches!(tok, "-P" | "-O" | "-I") {
                i += 2;
                continue;
            }
            if !tok.starts_with("--") {
                let rest = &tok[1..];
                if rest.contains('l')
                    || rest.contains('t')
                    || rest.contains('Z')
                    || rest.contains('v')
                {
                    is_list_or_test = true;
                }
            }
            i += 1;
            continue;
        }
        if !in_exclude {
            if archive.is_none() {
                archive = Some(tok.to_string());
            } else {
                members.push(tok.to_string());
            }
        }
        i += 1;
    }

    if is_list_or_test {
        return None;
    }
    if archive.is_some() && dirs.is_empty() {
        for d in chdir_dirs {
            if let Some(reason) = check_shell_write_deny_path_candidate(d, true) {
                return Some(reason);
            }
        }
    }
    for d in &dirs {
        if let Some(reason) = check_target_with_chdirs(d, true, chdir_dirs) {
            return Some(reason);
        }
    }
    for m in &members {
        if let Some(reason) = check_target_with_chdirs(m, true, chdir_dirs) {
            return Some(reason);
        }
        for d in &dirs {
            let combined = format!("{}/{}", d.trim_end_matches(['/', '\\']), m);
            if let Some(reason) = check_target_with_chdirs(&combined, true, chdir_dirs) {
                return Some(reason);
            }
        }
    }
    None
}

fn detect_rsync_write_deny(seg: &[String], chdir_dirs: &[String]) -> Option<String> {
    let mut is_dry_run = false;
    let mut is_readonly = false;
    let mut extra_write_dirs: Vec<String> = Vec::new();
    let mut extra_write_files: Vec<String> = Vec::new();
    let mut rsh_cmds: Vec<String> = Vec::new();
    let mut positional: Vec<&str> = Vec::new();
    let mut after_double_dash = false;
    let mut i = 1usize;

    while i < seg.len() {
        let tok = seg[i].as_str();
        if !after_double_dash && tok == "--" {
            after_double_dash = true;
            i += 1;
            continue;
        }
        if !after_double_dash && tok.starts_with('-') && tok.len() > 1 {
            if matches!(tok, "--dry-run" | "-n") {
                is_dry_run = true;
                i += 1;
                continue;
            }
            if tok == "--no-dry-run" {
                is_dry_run = false;
                i += 1;
                continue;
            }
            if matches!(tok, "--list-only" | "--help" | "--version") {
                is_readonly = true;
                i += 1;
                continue;
            }
            if matches!(tok, "--backup-dir" | "--partial-dir" | "--temp-dir" | "-T") {
                if i + 1 < seg.len() {
                    extra_write_dirs.push(seg[i + 1].clone());
                    i += 2;
                    continue;
                }
            }
            if let Some(val) = tok
                .strip_prefix("--backup-dir=")
                .or_else(|| tok.strip_prefix("--partial-dir="))
                .or_else(|| tok.strip_prefix("--temp-dir="))
            {
                extra_write_dirs.push(val.to_string());
                i += 1;
                continue;
            }
            if matches!(tok, "--log-file" | "--write-batch" | "--only-write-batch") {
                if i + 1 < seg.len() {
                    extra_write_files.push(seg[i + 1].clone());
                    i += 2;
                    continue;
                }
            }
            if let Some(val) = tok
                .strip_prefix("--log-file=")
                .or_else(|| tok.strip_prefix("--write-batch="))
                .or_else(|| tok.strip_prefix("--only-write-batch="))
            {
                extra_write_files.push(val.to_string());
                i += 1;
                continue;
            }
            if matches!(tok, "-e" | "--rsh" | "--rsync-path") {
                if i + 1 < seg.len() {
                    rsh_cmds.push(seg[i + 1].clone());
                    i += 2;
                    continue;
                }
            }
            if let Some(val) = tok
                .strip_prefix("--rsh=")
                .or_else(|| tok.strip_prefix("--rsync-path="))
            {
                rsh_cmds.push(val.to_string());
                i += 1;
                continue;
            }
            if !tok.starts_with("--") {
                let rest = &tok[1..];
                let mut cluster_dry_run = false;
                let mut consumed_with_operand = false;
                for (pos, ch) in rest.char_indices() {
                    if matches!(ch, 'e' | 'T' | 'f' | 'B' | 'M') {
                        let after_flag = &rest[pos + ch.len_utf8()..];
                        let val = if !after_flag.is_empty() {
                            i += 1;
                            Some(after_flag.to_string())
                        } else if i + 1 < seg.len() {
                            let v = seg[i + 1].clone();
                            i += 2;
                            Some(v)
                        } else {
                            i += 1;
                            None
                        };
                        if let Some(v) = val {
                            if ch == 'T' {
                                extra_write_dirs.push(v);
                            } else if ch == 'e' {
                                rsh_cmds.push(v);
                            }
                        }
                        consumed_with_operand = true;
                        break;
                    }
                    if !ch.is_ascii_alphabetic() {
                        break;
                    }
                    if ch == 'n' {
                        cluster_dry_run = true;
                    }
                }
                if cluster_dry_run {
                    is_dry_run = true;
                }
                if consumed_with_operand {
                    continue;
                }
            }
            if matches!(
                tok,
                "--exclude"
                    | "--exclude-from"
                    | "--include"
                    | "--include-from"
                    | "-f"
                    | "--filter"
                    | "--files-from"
                    | "--compare-dest"
                    | "--copy-dest"
                    | "--link-dest"
                    | "--suffix"
                    | "--out-format"
                    | "--chmod"
                    | "--chown"
                    | "--bwlimit"
                    | "--max-size"
                    | "--min-size"
                    | "--port"
                    | "--address"
                    | "--password-file"
                    | "--sockopts"
                    | "--iconv"
                    | "--usermap"
                    | "--groupmap"
                    | "-B"
                    | "--block-size"
                    | "--timeout"
                    | "--contimeout"
            ) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        positional.push(tok);
        i += 1;
    }

    for rsh_cmd in &rsh_cmds {
        if let Some(reason) = detect_shell_mandatory_write_deny(rsh_cmd) {
            return Some(reason);
        }
    }
    if is_dry_run || is_readonly {
        return None;
    }
    for d in &extra_write_dirs {
        if let Some(reason) = check_target_with_chdirs(d, true, chdir_dirs) {
            return Some(reason);
        }
    }
    for f in &extra_write_files {
        if let Some(reason) = check_target_with_chdirs(f, false, chdir_dirs) {
            return Some(reason);
        }
    }
    if positional.len() >= 2 {
        if let Some(dest) = positional.last() {
            if let Some(reason) = check_target_with_chdirs(dest, true, chdir_dirs) {
                return Some(reason);
            }
        }
    }
    None
}

fn detect_segment_mandatory_write_deny(seg: &[String], chdir_dirs: &[String]) -> Option<String> {
    if seg.is_empty() {
        return None;
    }
    match canonical_bin_stem(&seg[0]).as_str() {
        "git" => detect_git_config_write_deny(seg),
        "curl" => detect_curl_write_deny(seg, chdir_dirs),
        "wget" => detect_wget_write_deny(seg, chdir_dirs),
        "patch" => detect_patch_write_deny(seg, chdir_dirs),
        "tar" => detect_tar_write_deny(seg, chdir_dirs),
        "unzip" => detect_unzip_write_deny(seg, chdir_dirs),
        "rsync" => detect_rsync_write_deny(seg, chdir_dirs),
        _ => None,
    }
}

fn is_versioned_interpreter_stem(clean: &str, prefix: &str) -> bool {
    if let Some(rest) = clean.strip_prefix(prefix) {
        if rest.is_empty() {
            return true;
        }
        let rest = rest.strip_prefix('-').unwrap_or(rest);
        let version_part = if matches!(prefix, "python" | "pythonw")
            && rest.len() >= 2
            && matches!(rest.as_bytes().last(), Some(b't' | b'd' | b'u' | b'm'))
        {
            &rest[..rest.len() - 1]
        } else {
            rest
        };
        !version_part.is_empty()
            && !version_part.ends_with('.')
            && !version_part.contains("..")
            && version_part
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_digit())
            && version_part
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'.')
    } else {
        false
    }
}

fn is_interpreter_binary(clean: &str) -> bool {
    clean == "powershell"
        || is_versioned_interpreter_stem(clean, "pwsh")
        || is_versioned_interpreter_stem(clean, "python")
        || is_versioned_interpreter_stem(clean, "pythonw")
        || is_versioned_interpreter_stem(clean, "py")
        || is_versioned_interpreter_stem(clean, "node")
        || is_versioned_interpreter_stem(clean, "nodejs")
        || is_versioned_interpreter_stem(clean, "ruby")
        || is_versioned_interpreter_stem(clean, "perl")
        || is_versioned_interpreter_stem(clean, "php")
}

fn contains_non_member_call_or_import(lower_cmd: &str, ident: &str) -> bool {
    let bytes = lower_cmd.as_bytes();
    let ident_bytes = ident.as_bytes();
    if ident_bytes.is_empty() || bytes.len() < ident_bytes.len() {
        return false;
    }
    let mut start = 0usize;
    while let Some(rel) = lower_cmd[start..].find(ident) {
        let pos = start + rel;
        let prev_byte = if pos > 0 { Some(bytes[pos - 1]) } else { None };
        let prev_ok = prev_byte
            .map(|b| {
                !b.is_ascii_alphanumeric() && b != b'_' && b != b'.' && b != b'\'' && b != b'"'
            })
            .unwrap_or(true);
        let after_pos = pos + ident_bytes.len();
        let after = &lower_cmd[after_pos..];
        let next_non_ws = after.chars().find(|c| !c.is_whitespace());
        if prev_ok && next_non_ws == Some('(') {
            return true;
        }
        if prev_byte.is_some_and(|b| b.is_ascii_whitespace() || b == b',') {
            let prefix = lower_cmd[..pos].trim_end();
            let before = prefix
                .rsplit([';', '\n', '\r'])
                .next()
                .unwrap_or(prefix)
                .trim();
            if before.contains("import")
                && !before.contains('\'')
                && !before.contains('"')
                && after
                    .chars()
                    .next()
                    .is_none_or(|c| c.is_whitespace() || matches!(c, ',' | ';'))
            {
                return true;
            }
        }
        start = pos + 1;
    }
    false
}

fn detect_script_text_mandatory_write_deny(
    script: &str,
    is_ps_context: bool,
    chdir_dirs: &[String],
) -> Option<String> {
    let raw_words: Vec<&str> = script
        .split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    ';' | '&' | '|' | '<' | '>' | '(' | ')' | '`' | ',' | '{' | '}' | '"' | '\''
                )
        })
        .map(|w| w.trim())
        .filter(|w| !w.is_empty())
        .collect();

    let mut is_dir_mutation = false;
    let mut is_file_mutation = false;
    let mut has_sed = false;
    let mut has_sed_inplace = false;
    let mut has_perl = false;
    let mut has_perl_inplace = false;
    let mut has_interpreter = false;
    let mut has_php = false;
    let mut has_ps_web_cmd = false;
    let mut has_ps_dash_o = false;
    let mut has_ps_short_outfile = false;
    let mut has_ps_new_object = false;

    for word in &raw_words {
        let base_word = word
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(word)
            .to_ascii_lowercase();
        let clean = base_word
            .strip_suffix(".exe")
            .or_else(|| base_word.strip_suffix(".cmd"))
            .or_else(|| base_word.strip_suffix(".bat"))
            .unwrap_or(&base_word);

        if matches!(
            clean,
            "rm" | "rmdir"
                | "mv"
                | "del"
                | "erase"
                | "rd"
                | "ren"
                | "rename"
                | "remove-item"
                | "move-item"
                | "rename-item"
                | "unlink"
        ) || (is_ps_context && matches!(clean, "ri" | "mi" | "rni"))
        {
            is_dir_mutation = true;
            is_file_mutation = true;
        } else if matches!(
            clean,
            "tee"
                | "cp"
                | "chmod"
                | "chown"
                | "chgrp"
                | "touch"
                | "truncate"
                | "dd"
                | "install"
                | "ln"
                | "mkdir"
                | "shred"
                | "copy"
                | "xcopy"
                | "robocopy"
                | "move"
                | "mklink"
                | "set-content"
                | "add-content"
                | "out-file"
                | "new-item"
                | "clear-content"
                | "copy-item"
                | "tee-object"
                | "export-csv"
                | "export-clixml"
                | "export-alias"
                | "start-transcript"
        ) || (is_ps_context
            && matches!(clean, "sc" | "ac" | "ni" | "cpi" | "clc" | "epcsv" | "epal"))
        {
            is_file_mutation = true;
        }

        if is_ps_context && clean == "new-object" {
            has_ps_new_object = true;
        }

        if matches!(
            clean,
            "invoke-webrequest" | "iwr" | "invoke-restmethod" | "irm"
        ) || (is_ps_context && matches!(clean, "curl" | "wget"))
        {
            has_ps_web_cmd = true;
        }

        if clean == "sed" {
            has_sed = true;
        }
        if is_versioned_interpreter_stem(clean, "perl") {
            has_perl = true;
        }
        if is_versioned_interpreter_stem(clean, "php") {
            has_php = true;
        }
        if is_interpreter_binary(clean) {
            has_interpreter = true;
        }

        let word_lower = word.to_ascii_lowercase();
        let flag_name = word_lower
            .split(&[':', '='][..])
            .next()
            .unwrap_or(&word_lower);
        if let Some(name) = flag_name
            .strip_prefix('-')
            .or_else(|| flag_name.strip_prefix('/'))
        {
            if name.len() >= 4 && "outfile".starts_with(name) {
                is_file_mutation = true;
            } else if name.len() >= 2 && "outfile".starts_with(name) {
                has_ps_short_outfile = true;
            } else if name == "o" {
                has_ps_dash_o = true;
            }
        }

        if word.starts_with("--in-place") {
            has_sed_inplace = true;
            has_perl_inplace = true;
        } else if word.starts_with('-') && !word.starts_with("--") && word[1..].contains('i') {
            has_sed_inplace = true;
            has_perl_inplace = true;
        }
    }

    if (has_sed && has_sed_inplace)
        || (has_perl && has_perl_inplace)
        || (has_ps_web_cmd && (has_ps_dash_o || has_ps_short_outfile))
    {
        is_file_mutation = true;
    }

    let lower_cmd = script.to_ascii_lowercase();
    let has_fileinfo_mutation = (lower_cmd.contains("io.fileinfo")
        || (is_ps_context && lower_cmd.contains("fileinfo")))
        && [
            ".create",
            ".openwrite",
            ".appendtext",
            ".createtext",
            ".delete",
            ".replace",
            ".moveto",
            ".copyto",
            ".open(",
        ]
        .iter()
        .any(|m| lower_cmd.contains(m));

    let has_ps_unqualified_io_writer = has_ps_new_object
        && raw_words.iter().any(|w| {
            matches!(
                w.to_ascii_lowercase().as_str(),
                "streamwriter" | "filestream"
            )
        });

    let has_ps_unqualified_file_or_dir = is_ps_context
        && [
            "[file]::writealltext",
            "[file]::writeallbytes",
            "[file]::writealllines",
            "[file]::appendalltext",
            "[file]::appendalllines",
            "[file]::appendtext",
            "[file]::createtext",
            "[file]::create",
            "[file]::openwrite",
            "[file]::open(",
            "[file]::replace",
            "[file]::copy",
            "[file]::move",
            "[file]::delete",
            "[directory]::delete",
            "[directory]::move",
        ]
        .iter()
        .any(|p| lower_cmd.contains(p));

    let has_ps_type_reflection_io = is_ps_context
        && (lower_cmd.contains("type]::gettype")
            && (lower_cmd.contains("system.io.file") || lower_cmd.contains("system.io.directory")))
        && [
            "::writealltext",
            "::writeallbytes",
            "::writealllines",
            "::appendalltext",
            "::appendalllines",
            "::appendtext",
            "::createtext",
            "::create",
            "::openwrite",
            "::open(",
            "::replace",
            "::copy",
            "::move",
            "::delete",
        ]
        .iter()
        .any(|m| lower_cmd.contains(m));

    if has_fileinfo_mutation
        || has_ps_unqualified_io_writer
        || has_ps_unqualified_file_or_dir
        || has_ps_type_reflection_io
        || [
            "os.remove",
            "os.unlink",
            "os.rename",
            "os.replace",
            "os.symlink",
            "os.link",
            "shutil.rmtree",
            "shutil.move",
            "fs.unlink",
            "fs.rm",
            "fs.rmdir",
            "fs.rename",
            "fs.symlink",
            "fs.link",
            "symlinksync",
            "linksync",
            "file.symlink",
            "remove-item",
            "move-item",
            "rename-item",
            "io.file]::writealltext",
            "io.file]::writeallbytes",
            "io.file]::writealllines",
            "io.file]::appendalltext",
            "io.file]::appendalllines",
            "io.file]::appendtext",
            "io.file]::createtext",
            "io.file]::create",
            "io.file]::openwrite",
            "io.file]::open(",
            "io.file]::replace",
            "io.file]::copy",
            "io.file]::move",
            "io.file]::delete",
            "io.directory]::delete",
            "system.io.directory]::delete",
            "io.directory]::move",
            "system.io.directory]::move",
            "io.streamwriter",
            "streamwriter(",
            "streamwriter]::new",
            "io.filestream",
            "filestream(",
            "filestream]::new",
        ]
        .iter()
        .any(|p| lower_cmd.contains(p))
        || (has_interpreter
            && ([
                ".rm(",
                "rmsync(",
                "rmdirsync(",
                "renamesync(",
                "unlinksync(",
                ".unlink(",
                ".rmdir(",
                ".rename(",
                "file.delete",
                "file.unlink",
                "dir.rmdir",
                "dir.delete",
                "dir.unlink",
                "fileutils.",
            ]
            .iter()
            .any(|p| lower_cmd.contains(p))
                || contains_non_member_call_or_import(&lower_cmd, "remove")
                || contains_non_member_call_or_import(&lower_cmd, "rmtree")))
    {
        is_dir_mutation = true;
        is_file_mutation = true;
    }

    if (has_php || (has_interpreter && lower_cmd.contains("fopen(")))
        && [
            "'c'", "\"c\"", "'c+'", "\"c+\"", "'cb'", "\"cb\"", "'ct'", "\"ct\"", "'c+b'",
            "\"c+b\"", "'c+t'", "\"c+t\"", "'cb+'", "\"cb+\"", "'ct+'", "\"ct+\"",
        ]
        .iter()
        .any(|p| lower_cmd.contains(p))
    {
        is_file_mutation = true;
    }

    if has_interpreter
        && [
            ".write(",
            "writesync(",
            "writevsync(",
            ".writelines(",
            ".write_text(",
            ".write_bytes(",
            ".writefilesync(",
            ".appendfilesync(",
            ".touch(",
            ".replace(",
            ".symlink_to(",
            ".hardlink_to(",
            "os.truncate",
            ".truncate(",
            "os.symlink",
            "os.link",
            "os.chmod",
            "os.open",
            "fs.truncate",
            "truncatesync",
            "fs.symlink",
            "fs.link",
            "fs.chmod",
            "chmodsync",
            "fs.cp",
            "cpsync",
            "fs.copyfile",
            "copyfilesync",
            "createwritestream",
            "file.binwrite",
            "io.binwrite",
            "file.truncate",
            "file.chmod",
            "file.symlink",
            "file_put_contents",
            "fwrite(",
            "fputs(",
            "writefile",
            "appendfile",
            "sysopen",
            "syswrite",
            "o_wronly",
            "o_creat",
            "o_rdwr",
            "file::wronly",
            "file::creat",
            "file::rdwr",
            "io::wronly",
            "io::creat",
            "io::rdwr",
            "sqlite3.connect",
            "shutil.",
            "fs.write",
            "fs.append",
            "file.write",
            "io.write",
            "set-content",
            "out-file",
            "add-content",
            "'w'",
            "\"w\"",
            "'a'",
            "\"a\"",
            "'r+'",
            "\"r+\"",
            "'r+b'",
            "\"r+b\"",
            "'rb+'",
            "\"rb+\"",
            "'br+'",
            "\"br+\"",
            "'b+r'",
            "\"b+r\"",
            "'+br'",
            "\"+br\"",
            "'+rb'",
            "\"+rb\"",
            "'r+t'",
            "\"r+t\"",
            "'rt+'",
            "\"rt+\"",
            "'tr+'",
            "\"tr+\"",
            "'t+r'",
            "\"t+r\"",
            "'+tr'",
            "\"+tr\"",
            "'+rt'",
            "\"+rt\"",
            "'+r'",
            "\"+r\"",
            "'w+'",
            "\"w+\"",
            "'w+b'",
            "\"w+b\"",
            "'wb+'",
            "\"wb+\"",
            "'bw+'",
            "\"bw+\"",
            "'b+w'",
            "\"b+w\"",
            "'+bw'",
            "\"+bw\"",
            "'+wb'",
            "\"+wb\"",
            "'w+t'",
            "\"w+t\"",
            "'wt+'",
            "\"wt+\"",
            "'tw+'",
            "\"tw+\"",
            "'t+w'",
            "\"t+w\"",
            "'+tw'",
            "\"+tw\"",
            "'+wt'",
            "\"+wt\"",
            "'+w'",
            "\"+w\"",
            "'a+'",
            "\"a+\"",
            "'a+b'",
            "\"a+b\"",
            "'ab+'",
            "\"ab+\"",
            "'ba+'",
            "\"ba+\"",
            "'b+a'",
            "\"b+a\"",
            "'+ba'",
            "\"+ba\"",
            "'+ab'",
            "\"+ab\"",
            "'a+t'",
            "\"a+t\"",
            "'at+'",
            "\"at+\"",
            "'ta+'",
            "\"ta+\"",
            "'t+a'",
            "\"t+a\"",
            "'+ta'",
            "\"+ta\"",
            "'+at'",
            "\"+at\"",
            "'+a'",
            "\"+a\"",
            "'wb'",
            "\"wb\"",
            "'bw'",
            "\"bw\"",
            "'ab'",
            "\"ab\"",
            "'ba'",
            "\"ba\"",
            "'wt'",
            "\"wt\"",
            "'tw'",
            "\"tw\"",
            "'at'",
            "\"at\"",
            "'ta'",
            "\"ta\"",
            "'x'",
            "\"x\"",
            "'x+'",
            "\"x+\"",
            "'+x'",
            "\"+x\"",
            "'xb'",
            "\"xb\"",
            "'bx'",
            "\"bx\"",
            "'x+b'",
            "\"x+b\"",
            "'xb+'",
            "\"xb+\"",
            "'bx+'",
            "\"bx+\"",
            "'b+x'",
            "\"b+x\"",
            "'+bx'",
            "\"+bx\"",
            "'+xb'",
            "\"+xb\"",
            "'xt'",
            "\"xt\"",
            "'tx'",
            "\"tx\"",
            "'x+t'",
            "\"x+t\"",
            "'xt+'",
            "\"xt+\"",
            "'tx+'",
            "\"tx+\"",
            "'t+x'",
            "\"t+x\"",
            "'+tx'",
            "\"+tx\"",
            "'+xt'",
            "\"+xt\"",
        ]
        .iter()
        .any(|p| lower_cmd.contains(p))
    {
        is_file_mutation = true;
    }

    if !is_file_mutation {
        return None;
    }

    let mut candidates: Vec<String> = Vec::new();
    for w in &raw_words {
        let stripped = strip_key_prefix_for_path(w);
        if !stripped.is_empty() {
            candidates.push(stripped.to_string());
        }
    }
    for tok in crate::security::semantic_command::tokenize_command(script) {
        let trimmed = tok.trim_matches(['"', '\'', '`', ';', ',']);
        let stripped = strip_key_prefix_for_path(trimmed);
        if !stripped.is_empty() && !candidates.iter().any(|c| c == stripped) {
            candidates.push(stripped.to_string());
        }
    }

    for cand in candidates {
        if let Some(reason) = check_target_with_chdirs(&cand, is_dir_mutation, chdir_dirs) {
            return Some(reason);
        }
    }
    None
}

fn detect_shell_mandatory_write_deny(cmd: &str) -> Option<String> {
    let analysis = analyze_shell_command(cmd);
    for script_ctx in &analysis.scripts {
        for target in extract_redirection_targets(&script_ctx.script) {
            if let Some(reason) = check_target_with_chdirs(&target, false, &script_ctx.chdir_dirs) {
                return Some(reason);
            }
        }
    }

    for (target, chdir_dirs) in &analysis.wrapper_write_targets {
        if let Some(reason) = check_target_with_chdirs(target, false, chdir_dirs) {
            return Some(reason);
        }
    }

    for seg in &analysis.segments {
        if let Some(reason) = detect_segment_mandatory_write_deny(&seg.tokens, &seg.chdir_dirs) {
            return Some(reason);
        }
        if !seg.chdir_dirs.is_empty() && !seg.tokens.is_empty() {
            let wrapped = seg.tokens.join(" ");
            if let Some(reason) =
                detect_script_text_mandatory_write_deny(&wrapped, false, &seg.chdir_dirs)
            {
                return Some(reason);
            }
        }
    }

    for script_ctx in &analysis.scripts {
        if let Some(reason) = detect_script_text_mandatory_write_deny(
            &script_ctx.script,
            script_ctx.is_ps,
            &script_ctx.chdir_dirs,
        ) {
            return Some(reason);
        }
    }
    None
}

fn is_imds_or_link_local_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            (o[0] == 169 && o[1] == 254)
                || o == [168, 63, 129, 16]
                || o == [192, 0, 0, 192]
                || o == [100, 100, 100, 200]
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] == 0xfd00 && s[1] == 0x0ec2)
                || s == [0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254]
                || s == [0xfd00, 0x00c1, 0, 0, 0, 0, 0xa9fe, 0xa9fe]
                || s == [0xfd00, 0x0042, 0, 0, 0, 0, 0, 0x0042]
                || (s[0] & 0xffc0) == 0xfe80
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_imds_or_link_local_ip(std::net::IpAddr::V4(v4)))
                || v6
                    .to_ipv4()
                    .is_some_and(|v4| is_imds_or_link_local_ip(std::net::IpAddr::V4(v4)))
        }
    }
}

fn check_host_token_for_imds_ssrf(raw_host: &str) -> Option<String> {
    let mut h = raw_host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return None;
    }
    if h.starts_with('[') && h.ends_with(']') && h.len() >= 2 {
        h = h[1..h.len() - 1].to_string();
    }
    if let Some((addr_part, _zone)) = h.split_once('%') {
        h = addr_part.to_string();
    }
    if matches!(
        h.as_str(),
        "metadata.google.internal" | "metadata.goog" | "instance-data.ec2.internal"
    ) {
        return Some(format!(
            "Cloud IMDS metadata hostname blocked ('{}')",
            raw_host
        ));
    }
    if is_non_standard_ip_host_encoding(&h) {
        return Some(format!(
            "Non-standard IP encoding in network target blocked ('{}')",
            raw_host
        ));
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        if is_imds_or_link_local_ip(ip) {
            return Some(format!("Cloud/link-local IMDS endpoint blocked ('{}')", ip));
        }
    }
    None
}

fn extract_authority_host_from_url_str(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches(['"', '\'', '`', '<', '>']);
    let after_scheme = if let Some(idx) = trimmed.find("://") {
        &trimmed[idx + 3..]
    } else {
        trimmed.strip_prefix("//")?
    };
    let auth_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let auth = &after_scheme[..auth_end];
    let host_port = auth.rsplit('@').next().unwrap_or(auth).trim();
    if host_port.is_empty() {
        return None;
    }
    if let Some(after_open) = host_port.strip_prefix('[') {
        if let Some((inside, _)) = after_open.split_once(']') {
            return Some(inside.to_string());
        }
    }
    if host_port.matches(':').count() == 1 {
        return Some(host_port.split(':').next().unwrap_or(host_port).to_string());
    }
    Some(host_port.to_string())
}

fn inspect_url_or_host_candidate_for_imds_ssrf(
    cand: &str,
    is_explicit_network_field: bool,
) -> Option<String> {
    let trimmed = cand
        .trim()
        .trim_matches(['"', '\'', '`', '<', '>', ';', ',']);
    if trimmed.is_empty() {
        return None;
    }
    if let Some(raw_host) = extract_authority_host_from_url_str(trimmed) {
        if let Some(reason) = check_host_token_for_imds_ssrf(&raw_host) {
            return Some(reason);
        }
    }
    if let Ok(parsed) = url::Url::parse(trimmed) {
        if let Some(host) = parsed.host_str() {
            if let Some(reason) = check_host_token_for_imds_ssrf(host) {
                return Some(reason);
            }
        }
    }
    if is_explicit_network_field {
        let host_only = if let Some(after_open) = trimmed.strip_prefix('[') {
            after_open.split(']').next().unwrap_or(trimmed)
        } else if trimmed.matches(':').count() == 1 && !trimmed.contains('/') {
            trimmed.split(':').next().unwrap_or(trimmed)
        } else {
            trimmed
        };
        if let Some(reason) = check_host_token_for_imds_ssrf(host_only) {
            return Some(reason);
        }
    }
    None
}

fn collect_hook_strings_from_json(
    val: &serde_json::Value,
    key_hint: Option<&str>,
    out: &mut Vec<(bool, String)>,
) {
    match val {
        serde_json::Value::String(s) => {
            let is_net_key = key_hint
                .map(|k| {
                    matches!(
                        k.to_ascii_lowercase().as_str(),
                        "url"
                            | "uri"
                            | "endpoint"
                            | "target_url"
                            | "href"
                            | "host"
                            | "base_url"
                            | "webhook_url"
                            | "callback_url"
                    )
                })
                .unwrap_or(false);
            if !s.trim().is_empty() {
                out.push((is_net_key, s.clone()));
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_hook_strings_from_json(item, key_hint, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                collect_hook_strings_from_json(v, Some(k), out);
            }
        }
        _ => {}
    }
}

fn parse_inet_aton_part(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        return u64::from_str_radix(hex, 16).ok();
    }
    if part.len() > 1 && part.starts_with('0') {
        if !part.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return None;
        }
        return u64::from_str_radix(&part[1..], 8).ok();
    }
    if !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse::<u64>().ok()
}

fn parse_inet_aton_ipv4(host: &str) -> Option<std::net::Ipv4Addr> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut vals = [0u64; 4];
    for (idx, p) in parts.iter().enumerate() {
        vals[idx] = parse_inet_aton_part(p)?;
    }
    for &v in &vals[..parts.len() - 1] {
        if v > 0xff {
            return None;
        }
    }
    let last = vals[parts.len() - 1];
    let addr_u32 = match parts.len() {
        1 => {
            if last > u32::MAX as u64 {
                return None;
            }
            last as u32
        }
        2 => {
            if last > 0x00ff_ffff {
                return None;
            }
            ((vals[0] as u32) << 24) | (last as u32)
        }
        3 => {
            if last > 0xffff {
                return None;
            }
            ((vals[0] as u32) << 24) | ((vals[1] as u32) << 16) | (last as u32)
        }
        4 => {
            if last > 0xff {
                return None;
            }
            ((vals[0] as u32) << 24)
                | ((vals[1] as u32) << 16)
                | ((vals[2] as u32) << 8)
                | (last as u32)
        }
        _ => return None,
    };
    Some(std::net::Ipv4Addr::from(addr_u32))
}

fn check_schemeless_host_candidate_for_imds_ssrf(tok: &str) -> Option<String> {
    let trimmed = tok
        .trim()
        .trim_matches(['"', '\'', '`', '<', '>', ';', ',']);
    if trimmed.is_empty() {
        return None;
    }
    if let Some(eq_idx) = trimmed.find('=') {
        let slash_idx = trimmed.find('/').unwrap_or(usize::MAX);
        if eq_idx < slash_idx {
            let rhs = &trimmed[eq_idx + 1..];
            if let Some(reason) = check_schemeless_host_candidate_for_imds_ssrf(rhs) {
                return Some(reason);
            }
        }
    }
    if trimmed.starts_with('/') && !trimmed.starts_with("//") {
        return None;
    }
    let without_slashes = trimmed.strip_prefix("//").unwrap_or(trimmed);
    let auth_end = without_slashes
        .find(['/', '?', '#'])
        .unwrap_or(without_slashes.len());
    let auth = &without_slashes[..auth_end];
    let host_port = auth.rsplit('@').next().unwrap_or(auth).trim();
    if host_port.is_empty() {
        return None;
    }

    let mut host = if let Some(after_open) = host_port.strip_prefix('[') {
        let (inside, _) = after_open.split_once(']')?;
        inside.to_string()
    } else if host_port.matches(':').count() == 1 {
        let (h, port) = host_port.split_once(':').unwrap_or((host_port, ""));
        if !port.is_empty() && !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        h.to_string()
    } else {
        host_port.to_string()
    };

    host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some((addr_part, _zone)) = host.split_once('%') {
        host = addr_part.to_string();
    }
    if host.is_empty() {
        return None;
    }

    if matches!(
        host.as_str(),
        "metadata.google.internal" | "metadata.goog" | "instance-data.ec2.internal"
    ) {
        return Some(format!("Cloud IMDS metadata hostname blocked ('{}')", tok));
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_imds_or_link_local_ip(ip) {
            return Some(format!("Cloud/link-local IMDS endpoint blocked ('{}')", ip));
        }
        return None;
    }
    if let Some(v4) = parse_inet_aton_ipv4(&host) {
        if is_imds_or_link_local_ip(std::net::IpAddr::V4(v4)) {
            return Some(format!(
                "Non-standard IP encoding targeting IMDS blocked ('{}' -> {})",
                tok, v4
            ));
        }
    }
    None
}

fn detect_imds_or_ssrf(req: &NormalizedHookRequest) -> Option<String> {
    let mut texts: Vec<(bool, String)> = Vec::new();
    if let Some(cmd) = &req.command {
        if !cmd.trim().is_empty() {
            texts.push((false, cmd.clone()));
        }
    }
    if let Some(fp) = &req.file_path {
        if !fp.trim().is_empty() {
            texts.push((false, fp.clone()));
        }
    }
    if let Some(args) = &req.arguments {
        collect_hook_strings_from_json(args, None, &mut texts);
    }

    for (is_net_key, text) in texts {
        if is_net_key {
            if let Some(reason) = inspect_url_or_host_candidate_for_imds_ssrf(&text, true) {
                return Some(reason);
            }
        }
        let (segs, scripts) = if is_net_key {
            (Vec::new(), vec![(text, false)])
        } else {
            split_shell_command_segments_and_scripts(&text)
        };
        for (script, _is_ps) in &scripts {
            for sig in HOOK_ATIF_SCANNER.scan_text(script) {
                if sig.id == "network.imds_metadata_probe" {
                    return Some(format!(
                        "Cloud/link-local IMDS SSRF probe blocked ({})",
                        sig.pattern_matched
                    ));
                }
            }
            for tok in script.split(|c: char| {
                c.is_whitespace()
                    || matches!(
                        c,
                        '"' | '\'' | '`' | ';' | ',' | '(' | ')' | '<' | '>' | '&' | '|'
                    )
            }) {
                let tl = tok.to_ascii_lowercase();
                if tl.contains("://") {
                    if let Some(reason) = inspect_url_or_host_candidate_for_imds_ssrf(tok, false) {
                        return Some(reason);
                    }
                } else if let Some(reason) = check_schemeless_host_candidate_for_imds_ssrf(tok) {
                    return Some(reason);
                }
            }
        }
        for seg in &segs {
            for tok in seg {
                let tl = tok.to_ascii_lowercase();
                if tl.contains("://") {
                    if let Some(reason) = inspect_url_or_host_candidate_for_imds_ssrf(tok, false) {
                        return Some(reason);
                    }
                } else if let Some(reason) = check_schemeless_host_candidate_for_imds_ssrf(tok) {
                    return Some(reason);
                }
            }
        }
    }
    None
}

// =============================================================================
// Synchronous 6-Layer Hook Evaluation Pipeline
// =============================================================================

pub fn evaluate_hook_synchronously(req: &NormalizedHookRequest) -> HookEvaluationDecision {
    let start_instant = Instant::now();
    let session_id = req.session_id.as_deref().unwrap_or("agent-session-default");

    // 1. Post-Execution Handling (Capture dynamic denials for Incident A circumvention memory)
    if req.event_type.is_post() {
        let is_denial = req.exit_code.map(|c| c != 0).unwrap_or(false)
            || req
                .stderr
                .as_ref()
                .map(|e| {
                    let l = e.to_ascii_lowercase();
                    l.contains("password is required")
                        || l.contains("permission denied")
                        || l.contains("eacces")
                        || l.contains("eperm")
                        || l.contains("access denied")
                })
                .unwrap_or(false);

        if is_denial {
            let cmd_str = req.command.as_deref().unwrap_or("unknown_command");
            let sem = parse_semantic_command(cmd_str);
            let signal = DynamicDenialSignal::new(
                format!("denial-{}", EVENT_COUNTER.fetch_add(1, Ordering::SeqCst)),
                session_id,
                None,
                std::process::id(),
                cmd_str,
                sem.privilege_class,
                req.exit_code,
                true,
                req.stderr.clone(),
                Instant::now(),
            );
            GLOBAL_CORRELATOR.record_denial(signal);
            debug!("PostToolUse recorded dynamic denial for Incident A memory");
        }

        let duration_us = start_instant.elapsed().as_micros() as u64;
        let decision =
            HookEvaluationDecision::allow("PostToolUse completed and recorded", duration_us);
        record_decision(req, &decision);
        return decision;
    }

    // 2. Sensitive System Path Guard
    let mut detected_sensitive_store = None;

    if let Some(path) = &req.file_path {
        if let Some(kind) = crate::security::sensitive_paths::classify_sensitive_system_path(path) {
            detected_sensitive_store = Some((kind, path.clone()));
        } else if let Some(found) =
            crate::security::sensitive_paths::scan_for_sensitive_system_path(path)
        {
            detected_sensitive_store = Some(found);
        }
    }

    if detected_sensitive_store.is_none() {
        if let Some(args) = &req.arguments {
            if let Some(found) =
                crate::security::sensitive_paths::scan_json_for_sensitive_path(args)
            {
                detected_sensitive_store = Some(found);
            }
        }
    }

    if detected_sensitive_store.is_none() {
        if let Some(cmd) = &req.command {
            if let Some(found) =
                crate::security::sensitive_paths::scan_for_sensitive_system_path(cmd)
            {
                detected_sensitive_store = Some(found);
            }
        }
    }

    if let Some((store_kind, matched_path)) = detected_sensitive_store {
        let duration_us = start_instant.elapsed().as_micros() as u64;
        let decision = HookEvaluationDecision::deny(
            format!(
                "Access to sensitive system credential store blocked: {} ('{}')",
                store_kind.description(),
                matched_path
            ),
            Some("SensitiveSystemPathGuard"),
            Some("Access to protected credential stores is strictly forbidden"),
            duration_us,
        );
        record_decision(req, &decision);
        return decision;
    }

    // 2b. Mandatory Auto-Protected Workspace Write-Deny Guard
    if let Some(tool) = &req.tool_name {
        let t_lower = tool.to_ascii_lowercase();
        let is_mutating_file_tool = [
            "write", "edit", "replace", "create", "delete", "remove", "rename", "move", "append",
            "patch",
        ]
        .iter()
        .any(|kw| t_lower.contains(kw))
            && !t_lower.contains("read")
            && !t_lower.contains("view");
        if is_mutating_file_tool {
            let mut candidate_paths = Vec::new();
            if let Some(fp) = &req.file_path {
                candidate_paths.push(fp.clone());
            }
            if let Some(args) = &req.arguments {
                for key in ["file_path", "path", "target_file", "destination", "target"] {
                    if let Some(s) = args.get(key).and_then(|v| v.as_str()) {
                        candidate_paths.push(s.to_string());
                    }
                }
            }
            let is_dir_mutation = ["delete", "remove", "rename", "move"]
                .iter()
                .any(|kw| t_lower.contains(kw));
            for cand in candidate_paths {
                let deny_reason = check_write_deny_path_candidate(&cand, is_dir_mutation);
                if let Some(reason) = deny_reason {
                    let duration_us = start_instant.elapsed().as_micros() as u64;
                    let decision = HookEvaluationDecision::deny(
                        reason,
                        Some("MandatoryWriteDenyGuard"),
                        Some("Auto-protected workspace hook, shell, env, and IDE configs cannot be modified"),
                        duration_us,
                    );
                    record_decision(req, &decision);
                    return decision;
                }
            }
        }
    }

    for cmd_str in collect_hook_commands(req) {
        if let Some(reason) = detect_shell_mandatory_write_deny(&cmd_str) {
            let duration_us = start_instant.elapsed().as_micros() as u64;
            let decision = HookEvaluationDecision::deny(
                reason,
                Some("MandatoryWriteDenyGuard"),
                Some("Shell command write or mutation against protected workspace configs or .env is forbidden"),
                duration_us,
            );
            record_decision(req, &decision);
            return decision;
        }
    }

    // 2c. Cloud / Link-Local IMDS & SSRF URL Guard
    if let Some(imds_reason) = detect_imds_or_ssrf(req) {
        let duration_us = start_instant.elapsed().as_micros() as u64;
        let decision = HookEvaluationDecision::deny(
            imds_reason,
            Some("ImdsSsrfGuard"),
            Some("Requests targeting Cloud IMDS, link-local IPv6, or non-standard IP encodings are forbidden"),
            duration_us,
        );
        record_decision(req, &decision);
        return decision;
    }

    // 3. Layer 1: SemanticCommandAst (Structural privilege escalation AST parsing)
    if let Some(cmd) = &req.command {
        let sem = parse_semantic_command(cmd);
        if sem.privilege_class == PrivilegeEquivalenceClass::RootOrAdminElevation
            || sem.privilege_class == PrivilegeEquivalenceClass::TargetUserDelegation
        {
            let duration_us = start_instant.elapsed().as_micros() as u64;
            let decision = HookEvaluationDecision::deny(
                format!("Privileged command elevation rejected: '{cmd}'"),
                Some("Layer 1: SemanticCommandAst"),
                Some("Execute unprivileged commands or obtain signed authorization"),
                duration_us,
            );
            record_decision(req, &decision);
            return decision;
        }
    }

    // 4. Layer 2: DynamicBinaryMetadataProbe
    if let Some(cmd) = &req.command {
        let tokens = crate::security::semantic_command::tokenize_command(cmd);
        if let Some(first) = tokens.first() {
            let target_path = Path::new(first);
            if target_path.exists() {
                if let Ok(probe) = DynamicBinaryMetadataProbe::probe_path(target_path) {
                    if probe.is_privileged_target() {
                        let duration_us = start_instant.elapsed().as_micros() as u64;
                        let decision = HookEvaluationDecision::deny(
                            format!(
                                "Target binary on disk requires administrator privileges: '{}'",
                                target_path.display()
                            ),
                            Some("Layer 2: DynamicBinaryMetadataProbe"),
                            Some("Target unprivileged binaries"),
                            duration_us,
                        );
                        record_decision(req, &decision);
                        return decision;
                    }
                }
            }
        }
    }

    // 5. Layer 3: SemanticDlpEngine (Structured entity and PHI/PII classification)
    let mut payload_to_inspect = String::new();
    if let Some(cmd) = &req.command {
        payload_to_inspect.push_str(cmd);
        payload_to_inspect.push(' ');
    }
    if let Some(path) = &req.file_path {
        payload_to_inspect.push_str(path);
        payload_to_inspect.push(' ');
    }
    if let Some(args) = &req.arguments {
        let s = args.to_string();
        for ch in s.chars() {
            if ch == '{'
                || ch == '}'
                || ch == '['
                || ch == ']'
                || ch == ':'
                || ch == ','
                || ch == '"'
            {
                payload_to_inspect.push(' ');
                payload_to_inspect.push(ch);
                payload_to_inspect.push(' ');
            } else {
                payload_to_inspect.push(ch);
            }
        }
    }

    if !payload_to_inspect.trim().is_empty() {
        let dlp = SemanticDlpEngine::default();
        let verdict = dlp.evaluate_verdict_fail_closed(&payload_to_inspect);
        if !verdict.is_allow() {
            let duration_us = start_instant.elapsed().as_micros() as u64;
            let decision = HookEvaluationDecision::deny(
                format!(
                    "Sensitive data or PHI/PII entity detected: {:?}",
                    verdict.entities()
                ),
                Some("Layer 3: SemanticDlpEngine"),
                Some("Scrub sensitive records before tool execution"),
                duration_us,
            );
            record_decision(req, &decision);
            return decision;
        }
    }

    // 6. Layer 4: TemporalCircumventionCorrelator (Incident A circumvention memory)
    if let Some(cmd) = &req.command {
        let now = Instant::now();
        if let Some(alert) = GLOBAL_CORRELATOR.check_candidate(session_id, None, cmd, now) {
            let duration_us = start_instant.elapsed().as_micros() as u64;
            let decision = HookEvaluationDecision::deny(
                alert.summary,
                Some("Layer 4: TemporalCircumventionCorrelator"),
                Some("Incident A cross-boundary circumvention attempt blocked"),
                duration_us,
            );
            record_decision(req, &decision);
            return decision;
        }

        let sem = parse_semantic_command(cmd);
        if is_cross_boundary_invocation(cmd, &sem) && GLOBAL_CORRELATOR.active_denial_count() > 0 {
            let duration_us = start_instant.elapsed().as_micros() as u64;
            let decision = HookEvaluationDecision::deny(
                format!("Incident A cross-boundary execution denied: '{cmd}'"),
                Some("Layer 4: TemporalCircumventionCorrelator"),
                Some("Do not attempt cross-boundary retry"),
                duration_us,
            );
            record_decision(req, &decision);
            return decision;
        }
    }

    // All layers cleared
    let duration_us = start_instant.elapsed().as_micros() as u64;
    let decision = HookEvaluationDecision::allow(
        "Execution cleared all AgentOctopus security layers",
        duration_us,
    );
    record_decision(req, &decision);
    decision
}

/// Installs hook configurations across specified agent configuration files in a workspace.
pub fn install_agent_hooks(
    workspace: &Path,
    agents: &[SupportedAgentKind],
    bin_path: &Path,
) -> Result<Vec<PathBuf>, String> {
    let mut installed = Vec::new();
    let bin_str = bin_path.to_string_lossy().to_string();

    for &agent in agents {
        match agent {
            SupportedAgentKind::Claude => {
                let claude_cfg_dir = workspace.join(".claude");
                let _ = std::fs::create_dir_all(&claude_cfg_dir);
                let cfg_file = claude_cfg_dir.join("config.json");
                let hook_content = serde_json::json!({
                    "hooks": {
                        "PreToolUse": format!("\"{}\" hook evaluate --agent claude", bin_str),
                        "PostToolUse": format!("\"{}\" hook evaluate --agent claude --post", bin_str)
                    }
                });
                if std::fs::write(
                    &cfg_file,
                    serde_json::to_string_pretty(&hook_content).unwrap(),
                )
                .is_ok()
                {
                    installed.push(cfg_file);
                }
            }
            SupportedAgentKind::Cursor => {
                let cursor_dir = workspace.join(".cursor");
                let _ = std::fs::create_dir_all(&cursor_dir);
                let cfg_file = cursor_dir.join("hooks.json");
                let hook_content = serde_json::json!({
                    "version": 1,
                    "hooks": {
                        "beforeShellExecution": format!("\"{}\" hook evaluate --agent cursor --event beforeShellExecution", bin_str),
                        "afterShellExecution": format!("\"{}\" hook evaluate --agent cursor --event afterShellExecution --post", bin_str)
                    }
                });
                if std::fs::write(
                    &cfg_file,
                    serde_json::to_string_pretty(&hook_content).unwrap(),
                )
                .is_ok()
                {
                    installed.push(cfg_file);
                }
            }
            SupportedAgentKind::Copilot => {
                let github_dir = workspace.join(".github");
                let _ = std::fs::create_dir_all(&github_dir);
                let cfg_file = github_dir.join("copilot-instructions.md");
                let hook_text = format!(
                    "<!-- AgentOctopus Copilot Guard Hook -->\n[policy_enforcement]: \"{}\" hook evaluate --agent copilot\n",
                    bin_str
                );
                if std::fs::write(&cfg_file, hook_text).is_ok() {
                    installed.push(cfg_file);
                }
            }
            SupportedAgentKind::OpenCode => {
                let opencode_dir = workspace.join(".opencode");
                let _ = std::fs::create_dir_all(&opencode_dir);
                let cfg_file = opencode_dir.join("security_hook.json");
                let hook_content = serde_json::json!({
                    "pre_hook": format!("\"{}\" hook evaluate --agent opencode", bin_str)
                });
                if std::fs::write(
                    &cfg_file,
                    serde_json::to_string_pretty(&hook_content).unwrap(),
                )
                .is_ok()
                {
                    installed.push(cfg_file);
                }
            }
            SupportedAgentKind::Mcp => {}
        }
    }

    Ok(installed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_synonym_extraction() {
        let v = serde_json::json!({
            "cursor_command": "echo hello",
            "context_paths": ["/workspace/test.txt"],
            "sessionId": "sess-123",
            "tool_input": { "key": "val" },
            "tool_result": "done"
        });

        assert_eq!(extract_wire_command(&v), Some("echo hello".to_string()));
        assert_eq!(
            extract_wire_file_path(&v),
            Some("/workspace/test.txt".to_string())
        );
        assert_eq!(extract_wire_session_id(&v), Some("sess-123".to_string()));
        assert!(extract_wire_arguments(&v).is_some());
        assert!(extract_wire_tool_response(&v).is_some());
    }

    #[test]
    fn test_mcp_error_response_preserves_id() {
        let req_id = serde_json::json!(42);
        let decision =
            HookEvaluationDecision::deny("Root access forbidden", Some("AST"), None, 100);
        let resp_str = format_mcp_error_response(&req_id, &decision);
        let parsed: serde_json::Value = serde_json::from_str(&resp_str).unwrap();

        assert_eq!(parsed.get("id"), Some(&req_id));
        assert_eq!(parsed.get("jsonrpc").and_then(|v| v.as_str()), Some("2.0"));
        assert!(parsed.get("error").is_some());
    }

    #[test]
    fn test_sensitive_path_hook_denial() {
        let req = NormalizedHookRequest {
            agent: SupportedAgentKind::Claude,
            event_type: HookEventType::PreToolUse,
            tool_name: Some("read_file".into()),
            command: None,
            file_path: Some("/etc/shadow".into()),
            arguments: None,
            exit_code: None,
            stderr: None,
            cwd: None,
            session_id: None,
            rpc_id: None,
        };

        let decision = evaluate_hook_synchronously(&req);
        assert!(!decision.allowed);
        assert!(decision
            .rationale
            .contains("sensitive system credential store blocked"));
    }

    #[test]
    fn test_mandatory_write_deny_hook_blocks_git_hooks_and_mcp_json() {
        let write_req = NormalizedHookRequest {
            agent: SupportedAgentKind::Claude,
            event_type: HookEventType::PreToolUse,
            tool_name: Some("write_to_file".into()),
            command: None,
            file_path: Some(".git/hooks/pre-commit".into()),
            arguments: None,
            exit_code: None,
            stderr: None,
            cwd: None,
            session_id: None,
            rpc_id: None,
        };
        let decision = evaluate_hook_synchronously(&write_req);
        assert!(!decision.allowed);
        assert_eq!(
            decision.denied_by_layer.as_deref(),
            Some("MandatoryWriteDenyGuard")
        );

        let read_req = NormalizedHookRequest {
            tool_name: Some("read_file".into()),
            file_path: Some(".mcp.json".into()),
            ..write_req
        };
        assert!(evaluate_hook_synchronously(&read_req).allowed);
    }

    #[test]
    fn test_shell_bash_write_deny_guard_blocks_mutations_and_allows_benign() {
        let blocked_cmds = [
            "echo pwn > .git/hooks/pre-commit",
            "echo pwn>>.env",
            "echo pwn >| .env.local",
            "cat x 2> .bashrc",
            "echo {} &> .mcp.json",
            "echo pwn >& .git/hooks/pre-commit",
            "echo pwn >&.env",
            r#"echo pwn >& ".env""#,
            "echo ok >&2 > .env",
            "echo pwn | tee .git/hooks/pre-commit",
            "cp payload .git/config",
            "mv payload .env",
            "rm -rf .git",
            "chmod +x .git/hooks/pre-commit",
            "touch .vscode/tasks.json",
            "truncate -s 0 .env",
            "dd if=/dev/zero of=.git/hooks/pre-commit count=1",
            "ln -s /tmp/x .mcp.json",
            "sed -i 's/a/b/' .bashrc",
            "perl -pi -e 's/a/b/' .mcp.json",
            r#"python3 -c "open('.env','w').write('X=1')""#,
            r#"python -c "import pathlib; pathlib.Path('.env').touch()""#,
            r#"powershell -Command "Set-Content .git/hooks/pre-commit 'pwn'""#,
            "git config core.hooksPath /tmp/evil",
            "git -C repo config core.hooksPath /tmp/evil",
            "git config --global core.hooksPath /tmp/evil",
            "git config --add core.hooksPath /tmp/evil",
            "git config --unset core.hooksPath",
            "git config set core.hooksPath /tmp/evil",
            "git config --list && git config core.hooksPath /tmp/evil",
            r#"sh -c "git config core.hooksPath /tmp/evil""#,
            "curl -s -o .env https://api.github.com/zen",
            "curl -sLo .git/hooks/pre-commit https://api.github.com/zen",
            "curl -O https://example.com/.env",
            "wget -O .env https://api.github.com/zen",
            "wget -P .git/hooks https://api.github.com/zen",
            "patch .env evil.patch",
            "tar -xf evil.tar -C .git/hooks",
            "tar xf evil.tar .git/hooks/pre-commit",
            "tar -cf .env safe.txt",
            r"curl -o .\.env https://api.github.com/zen",
            r"curl -o .git\hooks\pre-commit https://api.github.com/zen",
            r"tar -xf evil.tar -C .claude\commands",
            r#"powershell -Command "curl -o .\.env https://api.github.com/zen""#,
            r"echo pwn > .git\hooks\pre-commit",
            r#"echo pwn > "".env"#,
            r"echo pwn > ''.git/hooks/pre-commit",
            r#"echo pwn > .e"n"v"#,
            r#"echo pwn >& "".env"#,
            r"echo pwn > .en\v",
            r#"sh -c "echo pwn > \"\".env""#,
            "curl --output-dir .git/hooks -O https://example.com/pre-commit",
            "curl --output-dir=.git/hooks -O https://example.com/pre-commit",
            "curl --output-dir .git -o hooks/pre-commit https://example.com/pwn",
            "tar -xf evil.tar --one-top-level=.git/hooks",
            "tar -xf .env.tar --one-top-level",
            r#"python -c "f=open('.env','r+'); print('X=1',file=f)""#,
            r#"python -c "f=open('.env','r+b'); f.write(b'X=1')""#,
            r#"python -c "f=open('.env','rb+'); f.write(b'X=1')""#,
            r#"powershell -Com "curl -o .\.env https://api.github.com/zen""#,
            r#"pwsh -Com "curl -o .\.env https://api.github.com/zen""#,
            r#"powershell -Com "tar -xf evil.tar -C .git\hooks""#,
            r#"powershell /c "curl -o .env https://api.github.com/zen""#,
            r#"powershell /Command "curl -o .env https://api.github.com/zen""#,
            r#"env -S "curl -o .env https://api.github.com/zen""#,
            r#"env -S "git config core.hooksPath /tmp/evil""#,
            r#"env --split-string="curl -o .env https://api.github.com/zen""#,
            r#"env --split-string "curl -o .env https://api.github.com/zen""#,
            r#"env -S"curl -o .env https://api.github.com/zen""#,
            r#"env -S "FOO=bar curl -o .env https://api.github.com/zen""#,
            r#"env -i -S "FOO=1 -- git config core.hooksPath /tmp/evil""#,
            r#"sh -c -- "curl -o .env https://api.github.com/zen""#,
            r#"bash -c -e -- "curl -o .env https://api.github.com/zen""#,
            r#"bash -ec -- "curl -o .env https://api.github.com/zen""#,
            r#"zsh -c -o errexit -- "git config core.hooksPath /tmp/evil""#,
            "unzip evil.zip -d .git/hooks",
            "unzip evil.zip -d.claude",
            "unzip evil.zip .env",
            "rsync evil.txt .env",
            "rsync -a evil/ .git/hooks/",
            "rsync -a evil/ .git",
            r#"python -c "import os; os.truncate('.env', 0)""#,
            r#"python -c "import os; os.symlink('/tmp/x', '.git/hooks/pre-commit')""#,
            r#"python -c "import os; os.link('/tmp/x', '.env')""#,
            r#"python -c "import os; os.chmod('.git/hooks/pre-commit', 0o777)""#,
            r#"python -c "import os; os.open('.env', os.O_WRONLY)""#,
            r#"node -e "require('fs').truncateSync('.env')""#,
            r#"node -e "require('fs').symlinkSync('/tmp/x', '.git/hooks/pre-commit')""#,
            r#"node -e "require('fs').copyFileSync('/tmp/x', '.env')""#,
            r#"ruby -e "File.binwrite('.env', 'X=1')""#,
            r#"ruby -e "File.truncate('.env', 0)""#,
            "curl -O --url=https://example.com/.env",
            r#"powershell "curl -o .env https://api.github.com/zen""#,
            r#"powershell "tar -xf evil.tar -C .git/hooks""#,
            r#"pwsh -NoProfile "git config core.hooksPath /tmp/evil""#,
            r#"env -iS"curl -o .env https://api.github.com/zen""#,
            r#"env -0S"curl -o .env https://api.github.com/zen""#,
            r#"env -vS"unzip -d .git/hooks evil.zip""#,
            r#"env -iS"git config core.hooksPath /tmp/evil""#,
            r#"env -iS="curl -o .env https://api.github.com/zen""#,
            r#"bash -O extglob -c "curl -o .env https://api.github.com/zen""#,
            r#"bash +O extglob -c "curl -o .env https://api.github.com/zen""#,
            r#"bash -c -O extglob "curl -o .env https://api.github.com/zen""#,
            r#"bash -c +O extglob "curl -o .env https://api.github.com/zen""#,
            r#"python3.12 -c "open('.env','w').write('X=1')""#,
            r#"python3.11 -c "import os; os.truncate('.env', 0)""#,
            r#"python3.12 -c "import pathlib; pathlib.Path('.env').write_text('X=1')""#,
            r#"node20 -e "require('fs').truncateSync('.env')""#,
            r#"ruby3.3 -e "File.binwrite('.env', 'X=1')""#,
            r#"php8.2 -r "file_put_contents('.env', 'X=1');""#,
            r#"powershell -Command "Invoke-WebRequest https://example.com -OutFile .env""#,
            r#"powershell -Command "iwr https://example.com -OutFile .env""#,
            r#"powershell -Command "irm https://example.com -OutFile .env""#,
            r#"powershell -Command "[IO.File]::WriteAllText('.env','X=1')""#,
            r#"powershell -Command "[System.IO.File]::Create('.env')""#,
            r#"powershell -Command "[IO.File]::OpenWrite('.env')""#,
            r#"powershell -Command "New-Object System.IO.StreamWriter('.env')""#,
            "rsync --log-file=.env src/ dst/",
            "rsync --log-file .git/hooks/pre-commit src/ dst/",
            "rsync --write-batch=.env src/ dst/",
            "rsync --write-batch .git/hooks/pre-commit src/ dst/",
            // Group 1: PowerShell value-taking switches & unquoted positional commands
            "powershell curl -o .env https://example.com",
            "powershell tar -xf evil.tar -C .git/hooks",
            "powershell rsync --log-file .env src/ dst/",
            "pwsh -NoProfile curl -o .env https://example.com",
            r#"powershell -Version 5.1 "curl -o .env https://api.github.com/zen""#,
            r#"powershell -InputFormat Text "git config core.hooksPath /tmp/evil""#,
            r#"powershell -OutputFormat Text "tar -xf evil.tar -C .git/hooks""#,
            r#"pwsh -WorkingDirectory . "rsync --log-file=.env src/ dst/""#,
            r#"pwsh -wd . "unzip -d .git/hooks evil.zip""#,
            r#"powershell -ConfigurationName foo "curl -o .env https://example.com""#,
            r#"pwsh -CustomPipeName bar "curl -o .env https://example.com""#,
            r#"pwsh -SettingsFile s.json "curl -o .env https://example.com""#,
            // Group 2: PowerShell aliases, backtick escaping, .NET Open/FileStream/FileInfo/space-arg StreamWriter
            r#"powershell -Command "sc .env 'X=1'""#,
            r#"powershell -Command "ac .env 'X=1'""#,
            r#"powershell -Command "ni .env -Force -Value 'X=1'""#,
            r#"powershell -Command "cpi evil.txt .env""#,
            r#"powershell -Command "mi evil.txt .env""#,
            r#"powershell -Command "ri .env""#,
            r#"powershell -Command "rni .env .env.bak""#,
            r#"powershell -Command "clc .env""#,
            r#"powershell -Command "Se`t-Content .env 'X=1'""#,
            r#"powershell -Command "Set-Content .e`nv 'X=1'""#,
            r#"powershell -Command "[IO.File]::Open('.env', 'Create')""#,
            r#"powershell -Command "New-Object IO.FileStream('.env', 'Create')""#,
            r#"powershell -Command "[IO.FileStream]::new('.env','Create')""#,
            r#"powershell -Command "New-Object System.IO.StreamWriter '.env'""#,
            r#"powershell -Command "[System.IO.FileInfo]::new('.env').Create()""#,
            r#"powershell -Command "[System.IO.FileInfo]::new('.env').Delete()""#,
            // Group 3: env clustered -iu / -a <argv0> / --argv0 AND timeout / stdbuf wrappers
            "env -iu FOO curl -o .env https://example.com",
            "env -a fake0 curl -o .env https://example.com",
            "env --argv0 fake0 curl -o .env https://example.com",
            "env --argv0=fake0 curl -o .env https://example.com",
            "timeout 5 curl -o .env https://example.com",
            "timeout -k 2 -s TERM 5s rsync --log-file=.env src/ dst/",
            "stdbuf -oL curl -o .env https://example.com",
            "stdbuf -o 0 git config core.hooksPath /tmp/evil",
            // Group 4: ANSI-C $'...', bash -Oc <shopt>, fish -c
            "bash -c $'curl -o .env https://example.com'",
            "bash -c $'git config core.hooksPath /tmp/evil'",
            "bash -c $'tar -xf evil.tar -C .git/hooks'",
            r#"bash -c $'curl\x20-o\x20.env\x20https://example.com'"#,
            r#"bash -Oc extglob "curl -o .env https://example.com""#,
            r#"fish -c "curl -o .env https://example.com""#,
            // Group 5: python3.13t ABI suffix, reversed Python modes, Node createWriteStream
            r#"python3.13t -c "open('.env','w').write('X=1')""#,
            r#"python3.12 -c "open('.env','bw')""#,
            r#"python3.12 -c "open('.env','ba')""#,
            r#"python3.12 -c "open('.env','bx')""#,
            r#"python3.12 -c "open('.env','tw')""#,
            r#"python3.12 -c "open('.env','br+')""#,
            r#"node22 -e "require('fs').createWriteStream('.env').end('X=1')""#,
            // Group 6: rsync attached -T<dir>, -e/--rsh/--rsync-path, and dry-run cluster accuracy
            "rsync -a -T.git/hooks src/ dst/",
            "rsync -a -M--no-inc-recursive src/ .env",
            r#"rsync -e"ssh -n" evil.txt .env"#,
            "rsync -T/tmp/new evil.txt .env",
            r#"rsync -e "curl -o .env https://example.com" src/ dst/"#,
            r#"rsync --rsh="curl -o .env https://example.com" src/ dst/"#,
            r#"rsync --rsync-path="curl -o .env https://example.com" src/ dst/"#,
            // Group 7: tar attached -f<archive>
            "tar -xfevil.tar -C.git/hooks",
            "tar -xfevil.tar --one-top-level=.git/hooks",
            "tar -cf.env safe.txt",
            // Iter 11 fixes (9 consolidated findings)
            "env -P /usr/bin curl -o .env https://example.com",
            "env -iP /usr/bin curl -o .env https://example.com",
            "env --default-path /usr/bin curl -o .env https://example.com",
            "env -P /usr/bin -u FOO curl -o .env https://example.com",
            "env -PS curl -o .env https://example.com",
            r"echo pwn > $'\x2eenv'",
            r"echo pwn > $'\056env'",
            r"cat x > $'\x2egit/hooks/pre-commit'",
            r#"powershell -Command "using namespace System.IO; New-Object StreamWriter '.env'""#,
            r#"powershell -Command "using namespace System.IO; New-Object FileStream '.env', 'Create'""#,
            "exec curl -o .env https://example.com",
            "exec -a fake0 curl -o .env https://example.com",
            "exec -ca fake0 curl -o .env https://example.com",
            r#"bash -c "exec curl -o .env https://example.com""#,
            "setsid curl -o .env https://example.com",
            "setsid -w --ctty curl -o .env https://example.com",
            "ionice -c 3 curl -o .env https://example.com",
            "ionice -c3 -t curl -o .env https://example.com",
            "taskset -c 0 curl -o .env https://example.com",
            "taskset 0x1 curl -o .env https://example.com",
            r#"fish -C "curl -o .env https://example.com""#,
            r#"fish --init-command="curl -o .env https://example.com""#,
            r#"fish --init-command "curl -o .env https://example.com""#,
            r#"powershell -Command "[IO.File]::AppendText('.env')""#,
            r#"powershell -Command "[IO.File]::CreateText('.env')""#,
            r#"powershell -Command "Write-Output 'X=1' | Tee-Object .env""#,
            r#"powershell -Command "Export-Csv .env""#,
            r#"powershell -Command "Export-Clixml .env""#,
            r#"powershell -Command "Start-Transcript .env""#,
            "curl -dabc -o .env https://example.com",
            "curl -uuser:abc -o .env https://example.com",
            "wget -Umyua -O .git/hooks/pre-commit https://example.com",
            r#"tar -xf archive.tar --to-command="curl -o .env https://example.com""#,
            r#"tar -xf archive.tar --to-command "curl -o .env https://example.com""#,
            r#"tar -xf archive.tar --transform="s|^|.git/hooks/|""#,
            r#"tar -xf archive.tar --xform="s|^|.env|""#,
            r#"tar -xf archive.tar --transform "s|^|.bashrc|""#,
            r#"node -e "require('fs').rmSync('.env')""#,
            r#"node -e "require('fs').rmdirSync('.git/hooks')""#,
            r#"node -e "require('fs').renameSync('evil', '.env')""#,
            r#"node -e "require('fs/promises').rm('.env')""#,
            r#"node -e "require('fs').writeSync(require('fs').openSync('.env', 65), 'X=1')""#,
            r#"node -e "require('fs').writeFileSync('.env', 'X=1')""#,
            r#"node -e "require('fs').appendFileSync('.env', 'X=1')""#,
            r#"ruby -e "File.delete('.env')""#,
            r#"ruby -e "IO.binwrite('.env', 'X=1')""#,
            r#"ruby -e "IO.write('.env', 'X=1')""#,
            r#"php -r "$f=fopen('.env','c'); fwrite($f,'X=1');""#,
            r#"php -r "$f=fopen('.env','c+'); fputs($f,'X=1');""#,
            // Iter 12 fixes (10 consolidated Iteration 11 findings)
            "setsid -- exec curl -o .env https://example.com",
            "env -- exec curl -o .env https://example.com",
            "exec -- setsid curl -o .env https://example.com",
            "stdbuf -oL -- exec curl -o .env https://example.com",
            "taskset -c0 curl -o .env https://example.com",
            "taskset -ac0 curl -o .env https://example.com",
            "taskset --cpu-list=0 curl -o .env https://example.com",
            r#"time -f "%e" curl -o .env https://example.com"#,
            "time -o .env echo hi",
            "time --output=.env echo hi",
            "chrt -f 10 curl -o .env https://example.com",
            "flock /tmp/lock curl -o .env https://example.com",
            r#"flock /tmp/lock -c "curl -o .env https://example.com""#,
            r#"script -q -c "curl -o .env https://example.com" /dev/null"#,
            "script -q .env",
            "strace -o /dev/null curl -o .env https://example.com",
            "strace -o .env echo hi",
            "caffeinate -i curl -o .env https://example.com",
            "env -C .git/hooks curl -o pre-commit https://example.com",
            "env --chdir=.git/hooks curl -o pre-commit https://example.com",
            "env -C .git/hooks tar -xf archive.tar",
            r#"env -C .git/hooks sh -c "echo pwn > pre-commit""#,
            r#"curl -o $".env" https://example.com"#,
            r#"echo pwn > $".env""#,
            r#"echo "$(curl -o .env https://example.com)""#,
            r#"echo "`curl -o .env https://example.com`""#,
            r#"X="$(wget -O .env https://example.com)""#,
            r#"eval "curl -o .env https://example.com""#,
            r#"bash -c "eval 'curl -o .env https://example.com'""#,
            r#"ash -c "curl -o .env https://example.com""#,
            r#"mksh -c "curl -o .env https://example.com""#,
            r#"pdksh -c "curl -o .env https://example.com""#,
            r#"rbash -c "curl -o .env https://example.com""#,
            r#"ksh93 -c "curl -o .env https://example.com""#,
            r#"busybox sh -c "curl -o .env https://example.com""#,
            "busybox wget -O .env https://example.com",
            r#"powershell -Command "using namespace System.IO; [File]::WriteAllText('.env','X=1')""#,
            r#"powershell -Command "using namespace System.IO; [File]::AppendText('.env')""#,
            r#"powershell -Command "using namespace System.IO; [File]::Delete('.env')""#,
            r#"powershell -Command "using namespace System.IO; [File]::Create('.env')""#,
            r#"powershell -Command "using namespace System.IO; [File]::OpenWrite('.env')""#,
            r#"powershell -Command "iwr https://example.com -out .env""#,
            r#"powershell -Command "iwr https://example.com -ou .env""#,
            r#"powershell -Command "curl https://example.com -O .git/hooks/pre-commit""#,
            r#"powershell -Command "[IO.Directory]::Delete('.git/hooks', $true)""#,
            r#"powershell -Command "Export-Alias .env""#,
            r#"powershell -Command "epal .env""#,
            r#"powershell -Command "([System.Type]::GetType('System.IO.File'))::WriteAllText('.env','X=1')""#,
            "wget -e output_document=.env https://example.com",
            "wget --execute=output_document=.env https://example.com",
            "wget -x -nH https://example.com/.git/hooks/pre-commit",
            "wget --default-page=.env https://example.com/",
            r#"tar -xf archive.tar --transform="s|^|.|;s|$|env|""#,
            r#"tar -xf archive.tar --xform="s|^|.|;s|$|env|""#,
            r#"tar -xf archive.tar --transform="s|^|.|;s|foo$|env|""#,
            r#"tar -xf archive.tar --use-compress-program="curl -o .env https://example.com""#,
            r#"tar -xf archive.tar -I "curl -o .env https://example.com""#,
            r#"tar -xf archive.tar --checkpoint=1 --checkpoint-action=exec="curl -o .env https://example.com""#,
            r#"node -e "const {rmSync}=require('fs'); rmSync('.env')""#,
            r#"node -e "const {rmdirSync}=require('fs'); rmdirSync('.git/hooks')""#,
            r#"node -e "const {writeSync,openSync,constants}=require('fs'); writeSync(openSync('.env',constants.O_WRONLY|constants.O_CREAT),'X=1')""#,
            r#"ruby -e "File.open('.env', File::WRONLY|File::CREAT) { |f| f.puts 'X=1' }""#,
            r#"ruby -e "File.unlink '.env'""#,
            r#"ruby -e "Dir.rmdir '.git/hooks'""#,
            r#"ruby -e "Dir.delete('.git/hooks')""#,
            r#"ruby -e "Dir.unlink '.git/hooks'""#,
            r#"ruby -rfileutils -e "FileUtils.rm_rf('.git')""#,
            r#"ruby -e "IO.new(IO.sysopen('.env', IO::WRONLY|IO::CREAT)).syswrite('X=1')""#,
            r#"python -c "from os import remove; remove('.env')""#,
            r#"python -c "from shutil import rmtree; rmtree('.git/hooks')""#,
            r#"python -c "import sqlite3; sqlite3.connect('.env').execute('create table t(x)')""#,
        ];
        let enc_write_echo = format!(
            "powershell -EncodedCommand {}",
            crate::security::command_line::encode_utf16le_base64("echo pwn > .env")
        );
        let enc_write_curl = format!(
            "powershell -enc {}",
            crate::security::command_line::encode_utf16le_base64(
                "curl -o .env https://api.github.com/zen"
            )
        );
        let enc_write_setcontent = format!(
            "pwsh -ec {}",
            crate::security::command_line::encode_utf16le_base64(
                "Set-Content .git/hooks/pre-commit 'pwn'"
            )
        );
        let enc_write_truncate = format!(
            "powershell -e {}",
            crate::security::command_line::encode_utf16le_base64(
                r#"python -c "import os; os.truncate('.env', 0)""#
            )
        );
        let enc_write_slash = format!(
            "powershell /enc {}",
            crate::security::command_line::encode_utf16le_base64("echo pwn > .env")
        );
        let enc_write_eq = format!(
            "powershell -enc={}",
            crate::security::command_line::encode_utf16le_base64(
                "curl -o .env https://api.github.com/zen"
            )
        );
        let enc_write_iwr = format!(
            "powershell -EncodedCommand {}",
            crate::security::command_line::encode_utf16le_base64(
                "Invoke-WebRequest https://example.com -OutFile .env"
            )
        );
        let enc_write_iofile = format!(
            "powershell -EncodedCommand {}",
            crate::security::command_line::encode_utf16le_base64(
                "[IO.File]::WriteAllText('.env','X=1')"
            )
        );
        let enc_write_alias_ni = format!(
            "powershell -EncodedCommand {}",
            crate::security::command_line::encode_utf16le_base64("ni .env -Force -Value 'X=1'")
        );
        let enc_write_dotnet_open = format!(
            "powershell -EncodedCommand {}",
            crate::security::command_line::encode_utf16le_base64(
                "[IO.File]::Open('.env', 'Create')"
            )
        );
        let enc_write_streamwriter_noparen = format!(
            "powershell -EncodedCommand {}",
            crate::security::command_line::encode_utf16le_base64(
                "New-Object System.IO.StreamWriter '.env'"
            )
        );
        let enc_write_backtick = format!(
            "powershell -EncodedCommand {}",
            crate::security::command_line::encode_utf16le_base64("Se`t-Content .e`nv 'X=1'")
        );
        let enc_write_appendtext = format!(
            "powershell -EncodedCommand {}",
            crate::security::command_line::encode_utf16le_base64("[IO.File]::AppendText('.env')")
        );
        let enc_write_tee_object = format!(
            "powershell -EncodedCommand {}",
            crate::security::command_line::encode_utf16le_base64(
                "Write-Output 'X=1' | Tee-Object .env"
            )
        );
        let enc_write_iwr_out = format!(
            "powershell -EncodedCommand {}",
            crate::security::command_line::encode_utf16le_base64(
                "iwr https://example.com -out .env"
            )
        );
        let enc_write_file_writealltext = format!(
            "powershell -EncodedCommand {}",
            crate::security::command_line::encode_utf16le_base64(
                "using namespace System.IO; [File]::WriteAllText('.env','X=1')"
            )
        );
        let mut all_blocked_cmds: Vec<&str> = blocked_cmds.to_vec();
        all_blocked_cmds.extend([
            enc_write_echo.as_str(),
            enc_write_curl.as_str(),
            enc_write_setcontent.as_str(),
            enc_write_truncate.as_str(),
            enc_write_slash.as_str(),
            enc_write_eq.as_str(),
            enc_write_iwr.as_str(),
            enc_write_iofile.as_str(),
            enc_write_alias_ni.as_str(),
            enc_write_dotnet_open.as_str(),
            enc_write_streamwriter_noparen.as_str(),
            enc_write_backtick.as_str(),
            enc_write_appendtext.as_str(),
            enc_write_tee_object.as_str(),
            enc_write_iwr_out.as_str(),
            enc_write_file_writealltext.as_str(),
        ]);

        for cmd in all_blocked_cmds {
            let payload = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": { "command": cmd }
            })
            .to_string();
            for (agent_name, req) in [
                ("claude", parse_claude_request(&payload, false).unwrap()),
                (
                    "cursor",
                    parse_cursor_request(&payload, "PreToolUse").unwrap(),
                ),
                (
                    "copilot",
                    parse_copilot_request(&payload, "PreToolUse").unwrap(),
                ),
                ("opencode", parse_opencode_request(&payload).unwrap()),
            ] {
                let decision = evaluate_hook_synchronously(&req);
                assert!(
                    !decision.allowed,
                    "[{}] expected shell write command '{}' to be denied, got allowed",
                    agent_name, cmd
                );
                assert_eq!(
                    decision.denied_by_layer.as_deref(),
                    Some("MandatoryWriteDenyGuard"),
                    "[{}] unexpected layer for '{}'",
                    agent_name,
                    cmd
                );
            }
        }

        let allowed_cmds = [
            "echo hello",
            "echo ok >&2",
            "echo ok 1>&2",
            "echo ok >&-",
            "cat .mcp.json >&2",
            "git status",
            "git config --list",
            "git config -l",
            "git config --get user.name",
            "git config --get-all remote.origin.fetch",
            "git config --get-regexp core.*",
            "git config --show-origin --list",
            "git config user.name",
            "git config list",
            r#"git commit -m "update git config""#,
            "git grep config",
            "git status && echo config",
            "curl -s https://api.github.com/zen",
            "curl -s https://example.com/.env",
            "curl -s -o out.txt https://example.com/.env",
            "wget --spider https://example.com/.env",
            "tar -tf archive.tar",
            "tar -cf backup.tar .env",
            "patch --dry-run .env evil.patch",
            "ls -la",
            "echo safe > output.txt",
            r"echo safe > dir\output.txt",
            "echo a&&echo b",
            "echo ok|cat",
            "curl --output-dir build -O https://example.com/safe.txt",
            "curl -s https://api.github.com/zen?a=1&b=2",
            "tar -xf archive.tar --one-top-level=build",
            "tar -tf archive.tar --one-top-level=.git/hooks",
            r#"python -c "f=open('safe.txt','r+'); print('ok',file=f)""#,
            r#"python -c "print(open('.env','r').read())""#,
            "cat .mcp.json",
            r#"python3 -c "print(1 + 2)""#,
            "powershell -NoProfile -File safe.ps1",
            r#"powershell -Com "echo hello""#,
            r#"env -S "echo hello""#,
            r#"env -S "FOO=1 echo hello""#,
            r#"sh -c -- "echo hello""#,
            r#"bash -c -e -- "echo hello""#,
            "unzip -l archive.zip",
            "unzip -t archive.zip",
            "unzip evil.zip -x .env -d build",
            "rsync --dry-run src/ dst/",
            "rsync --dry-run src/ .env",
            "curl -s --url=https://example.com/.env",
            r#"python -c "import os; os.truncate('safe.txt', 0)""#,
            r#"powershell -Command "Write-Output .env""#,
            r#"powershell "Write-Output .env""#,
            r#"powershell -Command "Invoke-WebRequest https://example.com""#,
            "powershell -NoProfile safe.ps1",
            r#"env -iS"echo hello""#,
            r#"bash -O extglob -c "echo hello""#,
            r#"python3.12 -c "print(open('.env','r').read())""#,
            "rsync --log-file=sync.log src/ dst/",
            "rsync --dry-run --log-file=.env src/ dst/",
            r#"powershell -Version 5.1 "Write-Output .env""#,
            r#"rsync -e"ssh -n" src/ dst/"#,
            "rsync -T/tmp/new src/ dst/",
            r#"python3.13t -c "print(open('.env','r').read())""#,
            r#"python3.12 -c "print(open('.env','rb').read())""#,
            "timeout 5 echo hello",
            "stdbuf -oL echo hello",
            "tar -xfevil.tar -tf",
            "bash -c $'echo hello'",
            r#"fish -c "echo hello""#,
            r#"node22 -e "require('fs').readFileSync('.env')""#,
            r#"powershell -Command "[IO.File]::OpenRead('.env')""#,
            // Iter 11 benign controls
            r#"powershell -Command "Write-Output StreamWriter""#,
            "env -P /usr/bin echo hello",
            r"echo pwn > $'\x6f\x75\x74.txt'",
            "curl -dabc https://example.com",
            r#"powershell -Command "Import-Csv .env""#,
            r#"powershell -Command "Get-Content .env""#,
            r#"node -e "require('fs').readFileSync('.env')""#,
            r#"ruby -e "puts File.read('.env')""#,
            r#"php -r "echo file_get_contents('.env');""#,
            "exec echo hello",
            "taskset -c 0 echo hello",
            "setsid echo hello",
            "ionice -c 3 echo hello",
            r#"fish -C "echo hello""#,
            r#"tar -xf archive.tar --transform="s|^|build/|""#,
            r#"tar -xf archive.tar --to-command="wc -c""#,
            r#"python -c "print(open('.env','r').read().count('c'))""#,
            // Iter 12 benign controls
            "setsid -- exec echo hello",
            "env -- exec echo hello",
            "taskset -c0 echo hello",
            "taskset --cpu-list=0 echo hello",
            r#"time -f "%e" echo hello"#,
            "time -o timing.log echo hello",
            "chrt -f 10 echo hello",
            "flock /tmp/lock echo hello",
            r#"flock /tmp/lock -c "echo hello""#,
            r#"script -q -c "echo hello" /dev/null"#,
            "strace -o /dev/null echo hello",
            "caffeinate -i echo hello",
            "env -C .git/hooks ls -la",
            "env -C .git/hooks echo hello",
            "env -C .git/hooks tar -tf archive.tar",
            "env -C .git/hooks curl -s https://example.com",
            "env -C build curl -o output.txt https://example.com",
            "env -C .git/hooks ls > output.txt",
            "cat .env > output.txt",
            r#"echo "$(date)""#,
            r#"echo '$(curl -o .env https://example.com)'"#,
            r#"echo "\$(curl -o .env https://example.com)""#,
            r#"echo $"hello""#,
            r#"eval "echo hello""#,
            r#"ash -c "echo hello""#,
            r#"busybox sh -c "echo hello""#,
            "busybox ls -la",
            r#"powershell -Command "Write-Output '[File]::ReadAllText'""#,
            r#"powershell -Command "curl -s https://example.com""#,
            r#"powershell -Command "Get-Alias""#,
            "wget -e user_agent=test https://example.com/",
            "wget -x -nH https://example.com/docs/index.html",
            "wget --spider -x -nH https://example.com/.git/hooks/pre-commit",
            "wget --default-page=index.html https://example.com/",
            r#"tar -tf archive.tar --transform="s|^|.|;s|$|env|""#,
            "tar -xf archive.tar -I zstd",
            "tar -cf out.tar --use-compress-program=pigz src/",
            r#"python -c "print([l for l in open('.env') if 'remove' not in l])""#,
            r#"python -c "import sqlite3; sqlite3.connect('app.db').execute('select 1')""#,
            r#"node -e "const {readFileSync}=require('fs'); readFileSync('.env')""#,
        ];
        let enc_allow_write_output = format!(
            "powershell -EncodedCommand {}",
            crate::security::command_line::encode_utf16le_base64("Write-Output hello")
        );
        let mut all_allowed_cmds: Vec<&str> = allowed_cmds.to_vec();
        all_allowed_cmds.push(enc_allow_write_output.as_str());
        for cmd in all_allowed_cmds {
            let payload = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": { "command": cmd }
            })
            .to_string();
            for (agent_name, req) in [
                ("claude", parse_claude_request(&payload, false).unwrap()),
                (
                    "cursor",
                    parse_cursor_request(&payload, "PreToolUse").unwrap(),
                ),
                (
                    "copilot",
                    parse_copilot_request(&payload, "PreToolUse").unwrap(),
                ),
                ("opencode", parse_opencode_request(&payload).unwrap()),
            ] {
                let decision = evaluate_hook_synchronously(&req);
                assert!(
                    decision.allowed,
                    "[{}] expected benign command '{}' to be allowed, got denied: {:?}",
                    agent_name, cmd, decision
                );
            }
        }
    }

    #[test]
    fn test_hook_imds_ssrf_guard_blocks_all_variants_and_allows_github() {
        let imds_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://168.63.129.16/machine/?comp=goalstate",
            "http://192.0.0.192/latest/",
            "http://100.100.100.200/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://[fe80::1]/latest/meta-data/",
            "http://[fe81::1%25eth0]/latest/meta-data/",
            "http://[febf::1]/latest/meta-data/",
            "http://[::ffff:a9fe:a9fe]/latest/meta-data/",
            "http://2852039166/latest/meta-data/",
            "http://0xa9fea9fe/latest/meta-data/",
            "http://0251.0376.0251.0376/latest/meta-data/",
            "http://169.254.43518/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ];

        for url in imds_urls {
            let webfetch_payload = serde_json::json!({
                "tool_name": "WebFetch",
                "tool_input": { "url": url }
            })
            .to_string();
            let bash_payload = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": { "command": format!("curl -s {}", url) }
            })
            .to_string();

            for payload in [&webfetch_payload, &bash_payload] {
                for (agent_name, req) in [
                    ("claude", parse_claude_request(payload, false).unwrap()),
                    (
                        "cursor",
                        parse_cursor_request(payload, "PreToolUse").unwrap(),
                    ),
                    (
                        "copilot",
                        parse_copilot_request(payload, "PreToolUse").unwrap(),
                    ),
                    ("opencode", parse_opencode_request(payload).unwrap()),
                ] {
                    let decision = evaluate_hook_synchronously(&req);
                    assert!(
                        !decision.allowed,
                        "[{}] expected IMDS URL '{}' to be denied in {}",
                        agent_name, url, payload
                    );
                    assert_eq!(
                        decision.denied_by_layer.as_deref(),
                        Some("ImdsSsrfGuard"),
                        "[{}] unexpected layer for '{}'",
                        agent_name,
                        url
                    );
                }
            }
        }

        let schemeless_imds_cmds = [
            "curl 2852039166/latest/meta-data/",
            "curl 0xa9fea9fe/latest/meta-data/",
            "curl 0251.0376.0251.0376/latest/",
            "curl 169.254.43518/latest/",
            "curl 2852039166",
            "curl 0xa9fea9fe",
            "curl [fe80::1]/latest/",
            "curl --url=0xa9fea9fe/latest/meta-data/",
            "curl http://0xa9fea9fe&&echo ok",
            "curl http://2852039166|cat",
            "curl 2852039166&&echo ok",
            "curl 0xa9fea9fe|cat",
            "curl 0xa9fea9fe&",
            "curl http://169.254.169.254/?a=1&b=2",
            r#"curl 0xa9fe""a9fe"#,
            r#"curl 285203""9166"#,
            r#"curl 16""9.254.169.254"#,
            "curl '169'.'254'.'169'.'254'",
            r#"powershell -Com "curl 0xa9fea9fe/latest/meta-data/""#,
            r#"env -S "curl 0xa9fea9fe""#,
            r#"sh -c -- "curl 2852039166""#,
            r#"env -iS"curl 16\"\"9.254.169.254""#,
            r#"bash +O extglob -c "curl 0xa9fe\"\"a9fe""#,
            r#"powershell "curl 0xa9fea9fe/latest/meta-data/""#,
        ];
        let enc_imds_ps = format!(
            "powershell -EncodedCommand {}",
            crate::security::command_line::encode_utf16le_base64(
                "curl http://169.254.169.254/latest/meta-data/"
            )
        );
        let enc_imds_pwsh = format!(
            "pwsh -enc {}",
            crate::security::command_line::encode_utf16le_base64(
                "curl http://169.254.169.254/latest/meta-data/"
            )
        );
        let mut all_schemeless_imds_cmds: Vec<&str> = schemeless_imds_cmds.to_vec();
        all_schemeless_imds_cmds.push(enc_imds_ps.as_str());
        all_schemeless_imds_cmds.push(enc_imds_pwsh.as_str());
        for cmd in all_schemeless_imds_cmds {
            let payload = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": { "command": cmd }
            })
            .to_string();
            for (agent_name, req) in [
                ("claude", parse_claude_request(&payload, false).unwrap()),
                (
                    "cursor",
                    parse_cursor_request(&payload, "PreToolUse").unwrap(),
                ),
                (
                    "copilot",
                    parse_copilot_request(&payload, "PreToolUse").unwrap(),
                ),
                ("opencode", parse_opencode_request(&payload).unwrap()),
            ] {
                let decision = evaluate_hook_synchronously(&req);
                assert!(
                    !decision.allowed,
                    "[{}] expected schemeless IMDS command '{}' to be denied",
                    agent_name, cmd
                );
                assert_eq!(
                    decision.denied_by_layer.as_deref(),
                    Some("ImdsSsrfGuard"),
                    "[{}] unexpected layer for '{}'",
                    agent_name,
                    cmd
                );
            }
        }

        let benign_numeric_cmds = [
            "sleep 10",
            "chmod 755 script.sh",
            "cat 2024/01/02/report.txt",
            "tar -xf 2024.01/archive.tar",
            "ls v1.2/foo",
            "curl 127.0.0.1:8080/health",
        ];
        for cmd in benign_numeric_cmds {
            let payload = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": { "command": cmd }
            })
            .to_string();
            for (agent_name, req) in [
                ("claude", parse_claude_request(&payload, false).unwrap()),
                (
                    "cursor",
                    parse_cursor_request(&payload, "PreToolUse").unwrap(),
                ),
                (
                    "copilot",
                    parse_copilot_request(&payload, "PreToolUse").unwrap(),
                ),
                ("opencode", parse_opencode_request(&payload).unwrap()),
            ] {
                let decision = evaluate_hook_synchronously(&req);
                assert!(
                    decision.allowed,
                    "[{}] expected benign numeric command '{}' to be allowed, got {:?}",
                    agent_name, cmd, decision
                );
            }
        }

        let benign_webfetch = serde_json::json!({
            "tool_name": "WebFetch",
            "tool_input": { "url": "https://api.github.com/zen" }
        })
        .to_string();
        for (agent_name, req) in [
            (
                "claude",
                parse_claude_request(&benign_webfetch, false).unwrap(),
            ),
            (
                "cursor",
                parse_cursor_request(&benign_webfetch, "PreToolUse").unwrap(),
            ),
            (
                "copilot",
                parse_copilot_request(&benign_webfetch, "PreToolUse").unwrap(),
            ),
            (
                "opencode",
                parse_opencode_request(&benign_webfetch).unwrap(),
            ),
        ] {
            let decision = evaluate_hook_synchronously(&req);
            assert!(
                decision.allowed,
                "[{}] expected https://api.github.com/zen to be allowed, got {:?}",
                agent_name, decision
            );
        }
    }

    #[test]
    fn test_copilot_toolname_and_toolargs_schema_normalization() {
        let copilot_obj = r#"{"toolName":"Bash","toolArgs":{"command":"echo pwn > .env"}}"#;
        let d_obj =
            evaluate_hook_synchronously(&parse_copilot_request(copilot_obj, "PreToolUse").unwrap());
        assert!(!d_obj.allowed);
        assert_eq!(
            d_obj.denied_by_layer.as_deref(),
            Some("MandatoryWriteDenyGuard")
        );

        let copilot_json_str =
            r#"{"toolName":"bash","toolArgs":"{\"command\":\"echo pwn > .env\"}"}"#;
        let d_str = evaluate_hook_synchronously(
            &parse_copilot_request(copilot_json_str, "PreToolUse").unwrap(),
        );
        assert!(!d_str.allowed);
        assert_eq!(
            d_str.denied_by_layer.as_deref(),
            Some("MandatoryWriteDenyGuard")
        );

        let copilot_scalar_str = r#"{"toolName":"bash","toolArgs":"echo pwn > .env"}"#;
        let d_scalar = evaluate_hook_synchronously(
            &parse_copilot_request(copilot_scalar_str, "PreToolUse").unwrap(),
        );
        assert!(!d_scalar.allowed);
        assert_eq!(
            d_scalar.denied_by_layer.as_deref(),
            Some("MandatoryWriteDenyGuard")
        );

        let copilot_edit =
            r#"{"toolName":"edit","toolArgs":"{\"path\":\".git/hooks/pre-commit\"}"}"#;
        let d_edit = evaluate_hook_synchronously(
            &parse_copilot_request(copilot_edit, "PreToolUse").unwrap(),
        );
        assert!(!d_edit.allowed);
        assert_eq!(
            d_edit.denied_by_layer.as_deref(),
            Some("MandatoryWriteDenyGuard")
        );

        let copilot_imds =
            r#"{"toolName":"webFetch","toolArgs":"{\"url\":\"http://2852039166/latest/\"}"}"#;
        let d_imds = evaluate_hook_synchronously(
            &parse_copilot_request(copilot_imds, "PreToolUse").unwrap(),
        );
        assert!(!d_imds.allowed);
        assert_eq!(d_imds.denied_by_layer.as_deref(), Some("ImdsSsrfGuard"));

        let copilot_allow =
            r#"{"toolName":"bash","toolArgs":"{\"command\":\"git config --list\"}"}"#;
        let d_allow = evaluate_hook_synchronously(
            &parse_copilot_request(copilot_allow, "PreToolUse").unwrap(),
        );
        assert!(
            d_allow.allowed,
            "Expected benign copilot payload allowed: {:?}",
            d_allow
        );
    }
}
