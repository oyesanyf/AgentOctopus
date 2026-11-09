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

use crate::security::circumvention::{
    is_cross_boundary_invocation, DynamicDenialSignal, TemporalCircumventionCorrelator,
};
use crate::security::semantic_command::{
    parse_semantic_command, DynamicBinaryMetadataProbe, PrivilegeEquivalenceClass,
};
use crate::security::semantic_dlp::SemanticDlpEngine;

pub static GLOBAL_CORRELATOR: LazyLock<TemporalCircumventionCorrelator> =
    LazyLock::new(|| TemporalCircumventionCorrelator::new(Duration::from_secs(60)));

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
    const CANDIDATES: &[&str] = &["tool_name", "name", "tool"];
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
    const CANDIDATES: &[&str] = &["arguments", "tool_input", "args", "parameters", "input"];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if !v.is_null() {
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
    let command = extract_wire_command(&val);
    let file_path = extract_wire_file_path(&val);
    let tool_name = extract_wire_tool_name(&val).or_else(|| {
        if command.is_some() {
            Some("shell".to_string())
        } else {
            None
        }
    });
    let arguments = extract_wire_arguments(&val);
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
    let command = extract_wire_command(&val);
    let file_path = extract_wire_file_path(&val);
    let tool_name = extract_wire_tool_name(&val);
    let arguments = extract_wire_arguments(&val);
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
    let command = extract_wire_command(&val);
    let file_path = extract_wire_file_path(&val);
    let tool_name = extract_wire_tool_name(&val);
    let arguments = extract_wire_arguments(&val);
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
            Some("Access to root credential databases (/etc/shadow, SAM, SYSTEM) is strictly forbidden"),
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
}
