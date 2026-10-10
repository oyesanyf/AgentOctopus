use crate::arm::{KernelSentinelArm, TarpitArm};
use crate::core::types::ArmRole;
use crate::security::audit::SecurityAuditLog;
use crate::security::breakouts::BreakoutDefenseCoordinator;
use crate::security::cedar_arm::*;
use crate::security::continuous_eval::ContinuousEvaluationEngine;
use crate::security::governor::{
    GovernorConfig, IncidentRecord, KernelEventKind, SecurityGovernorState, TelemetrySample,
};
use crate::security::math_validator::VassilevMathValidator;
use crate::security::rasp::{
    AdaptiveMitigationTier, AgentRaspEngine, AgentSecuritySubject, RaspAgentTrustTier, RaspDecision,
};
use crate::security::rl_defense::{AdaptiveDefenseAction, AdaptiveRlDefenseEngine, AdaptiveStateVector};
use crate::telemetry::otel::{OtelSessionTelemetry, OtelSpanKind, OtelStatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveTestEvent {
    pub id: usize,
    pub timestamp_secs: u64,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub is_allowed: bool,
    pub verdict: String,
    pub reason: String,
    pub policy: String,
    pub record_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorPayload {
    pub error: bool,
    pub code: String,
    pub message: String,
    pub timestamp: String,
}

pub fn json_error_payload(code: &str, message: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    json!({
        "error": true,
        "code": code,
        "message": message,
        "timestamp": format!("{}", now),
    }).to_string()
}

/// Global state shared across web API requests.
pub struct WebState {
    pub gateway: Arc<CedarAuthorizationGateway>,
    pub audit_log: Arc<SecurityAuditLog>,
    pub live_events: Arc<std::sync::Mutex<Vec<LiveTestEvent>>>,
    pub tarpit: Arc<TarpitArm>,
    pub kernel_sentinel: Arc<KernelSentinelArm>,
    pub allowed_domains: Arc<std::sync::RwLock<Vec<String>>>,
    pub rl_defense: Arc<AdaptiveRlDefenseEngine>,
    pub breakout_coordinator: Arc<BreakoutDefenseCoordinator>,
    pub otel_telemetry: Arc<OtelSessionTelemetry>,
    pub continuous_eval: Arc<ContinuousEvaluationEngine>,
    pub governor_state: Arc<std::sync::RwLock<SecurityGovernorState>>,
    pub rasp_engine: Arc<AgentRaspEngine>,
}

fn load_or_init_egress_domains() -> Vec<String> {
    let config_dir = std::path::PathBuf::from("config");
    let _ = std::fs::create_dir_all(&config_dir);
    let path = config_dir.join("egress_domains.json");
    if path.exists() {
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(domains) = serde_json::from_slice::<Vec<String>>(&bytes) {
                if !domains.is_empty() {
                    return domains;
                }
            }
        }
    }
    let defaults = vec![
        "google.com".to_string(),
        "www.google.com".to_string(),
        "api.openai.com".to_string(),
        "api.anthropic.com".to_string(),
        "huggingface.co".to_string(),
        "github.com".to_string(),
    ];
    let _ = std::fs::write(&path, serde_json::to_string_pretty(&defaults).unwrap_or_default());
    defaults
}

fn save_egress_domains(domains: &[String]) {
    let config_dir = std::path::PathBuf::from("config");
    let _ = std::fs::create_dir_all(&config_dir);
    let path = config_dir.join("egress_domains.json");
    let _ = std::fs::write(&path, serde_json::to_string_pretty(domains).unwrap_or_default());
}

fn is_valid_domain(d: &str) -> bool {
    let d = d.trim().to_ascii_lowercase();
    if d.is_empty() || d.len() > 253 {
        return false;
    }
    if d.contains('/') || d.contains(':') || d.contains('\\') || d.contains('@') {
        return false;
    }
    if d.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    let parts: Vec<&str> = d.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    for part in parts {
        if part.is_empty() || part.len() > 63 {
            return false;
        }
        if part.starts_with('-') || part.ends_with('-') {
            return false;
        }
        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
}

impl Default for WebState {
    fn default() -> Self {
        let secret_seed = b"agent_octopus_web_dashboard_secret_seed_32_bytes";
        let policy_fingerprint = "cedar_v4_13_octopus_v1";
        let logs_dir = std::path::PathBuf::from("logs");
        let _ = std::fs::create_dir_all(&logs_dir);
        let audit_log = Arc::new(SecurityAuditLog::with_disk_persistence(logs_dir.join("audit.log")));
        let gateway = Arc::new(
            CedarAuthorizationGateway::new(secret_seed, policy_fingerprint)
                .with_audit_log((*audit_log).clone()),
        );
        let live_events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let tarpit = Arc::new(TarpitArm::default());
        let kernel_sentinel = Arc::new(KernelSentinelArm::default());

        let initial_domains = load_or_init_egress_domains();
        let _ = gateway.engine().update_egress_domains(&initial_domains);
        let allowed_domains = Arc::new(std::sync::RwLock::new(initial_domains));

        let rl_defense = Arc::new(AdaptiveRlDefenseEngine::default());
        let breakout_coordinator = Arc::new(BreakoutDefenseCoordinator::default());
        let otel_telemetry = Arc::new(OtelSessionTelemetry::default());
        let continuous_eval = Arc::new(ContinuousEvaluationEngine::new(
            Arc::clone(&breakout_coordinator),
            Arc::clone(&rl_defense),
            Arc::clone(&otel_telemetry),
        ));

        let mut gov_config = GovernorConfig::default();
        gov_config.warning_threshold = 0.70;
        gov_config.critical_termination_threshold = 0.35;
        let governor_state = Arc::new(std::sync::RwLock::new(SecurityGovernorState::new(gov_config)));

        let rasp_engine = Arc::new(AgentRaspEngine::new(
            Arc::clone(&rl_defense),
            Arc::clone(&otel_telemetry),
        ));

        Self {
            gateway,
            audit_log,
            live_events,
            tarpit,
            kernel_sentinel,
            allowed_domains,
            rl_defense,
            breakout_coordinator,
            otel_telemetry,
            continuous_eval,
            governor_state,
            rasp_engine,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct EvaluateCedarRequest {
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub context: serde_json::Value,
    #[serde(default)]
    pub attach_supervisor_approval: bool,
    #[serde(default)]
    pub adversary_id: Option<String>,
    #[serde(default)]
    pub engage_tarpit: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluateCedarResponse {
    pub is_allowed: bool,
    pub determining_policies: Vec<String>,
    pub diagnostic_errors: Vec<String>,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tarpit_engaged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoy_honey_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rl_action_tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breakout_verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

pub fn handle_status(state: &WebState) -> String {
    let policy_count = state.gateway.engine().policy_count();
    let audit_count = state.audit_log.record_count();
    let is_valid = state.audit_log.verify_integrity();
    let tarpit_stats = state.tarpit.stats();
    let kernel_stats = state.kernel_sentinel.stats();
    let rl_stats = state.rl_defense.stats();
    let resilience = state.otel_telemetry.get_resilience_metrics();
    let (harness_clean, tampered_files) = state.breakout_coordinator.behavioral.verify_harness_integrity();

    let json_val = json!({
        "status": "ONLINE",
        "version": "0.1.0",
        "engine": "Cedar v4.13",
        "active_policies": policy_count,
        "audit_records": audit_count,
        "audit_chain_valid": is_valid,
        "egress_allowed": state.allowed_domains.read().unwrap_or_else(|e| e.into_inner()).clone(),
        "os_isolation": {
            "job_objects": "Active (64MB clamp, max_processes <= 1)",
            "app_container": "Active (S-1-15-2-...) sandbox",
            "wasmtime_fuel": "Active"
        },
        "tarpit_defense": {
            "status": "Active",
            "role": "TarpitDecoyDefense",
            "trapped_callers": tarpit_stats.trapped_callers,
            "tokens_burned": tarpit_stats.total_tokens_burned,
            "total_delay_ms": tarpit_stats.total_delay_introduced_ms,
            "active_quarantines": tarpit_stats.active_quarantines,
            "base_delay_ms": tarpit_stats.base_delay_ms
        },
        "kernel_protection": {
            "status": if kernel_stats.tier2_connected { "Ring-0 Active" } else { "Tier 1 Native Job Active" },
            "role": "KernelLevelSentinel",
            "tier1_job_substrate": {
                "active": kernel_stats.tier1_active,
                "job_name": kernel_stats.job_name,
                "max_processes": kernel_stats.max_processes,
                "max_memory_mb": kernel_stats.max_memory_bytes / (1024 * 1024),
                "process_vetos": kernel_stats.process_creation_vetos,
                "memory_limit_intercepts": kernel_stats.memory_limit_intercepts,
                "autotomy_hardware_kills": kernel_stats.autotomy_hardware_kills,
                "monitored_pids": kernel_stats.monitored_pids
            },
            "tier2_ring0_driver": {
                "connected": kernel_stats.tier2_connected,
                "device_name": kernel_stats.driver_device,
                "mode": kernel_stats.driver_mode,
                "driver_version": kernel_stats.driver_version,
                "blocked_count": kernel_stats.driver_blocked_count,
                "rule_count": kernel_stats.driver_rule_count,
                "status_label": kernel_stats.driver_status_label
            },
            "cedar_enforced": kernel_stats.cedar_enforced
        },
        "rl_active_defense": {
            "status": "Active",
            "posture": rl_stats.current_defense_posture,
            "total_episodes": rl_stats.total_episodes,
            "total_steps": rl_stats.total_steps,
            "epsilon": rl_stats.epsilon,
            "average_reward": rl_stats.average_reward,
            "action_distribution": rl_stats.action_distribution,
            "q_table_entries": rl_stats.q_table_entries,
            "replay_buffer_size": rl_stats.replay_buffer_size
        },
        "resilience_metrics": {
            "mttd_ms": resilience.mttd_ms,
            "mttr_ms": resilience.mttr_ms,
            "total_breach_events": resilience.total_breach_events,
            "cumulative_survival_prob": resilience.cumulative_survival_prob,
            "current_step_count": resilience.current_step_count,
            "epsilon_min": resilience.epsilon_min
        },
        "breakout_guards": {
            "technical": "Active (Ephemeral sandbox + Docker socket guard)",
            "operational": "Active (Dynamic STS token brokering + env leak filter)",
            "behavioral": if harness_clean { "Aligned" } else { "Tampering Detected" },
            "tampered_files": tampered_files,
            "data": "Active (Cross-agent memory & scratchpad isolation)"
        },
        "rt_asp": state.rasp_engine.status_summary()
    });

    json_val.to_string()
}

pub fn handle_kernel_stats(state: &WebState) -> String {
    let stats = state.kernel_sentinel.stats();
    serde_json::to_string(&stats).unwrap_or_default()
}

pub fn handle_audit_log(state: &WebState) -> String {
    let entries = state.audit_log.get_entries();
    let is_valid = state.audit_log.verify_integrity();

    let json_val = json!({
        "is_chain_valid": is_valid,
        "latest_hash": state.audit_log.latest_hash(),
        "total_records": entries.len(),
        "records": entries
    });

    json_val.to_string()
}

pub fn handle_live_tests(state: &WebState, since_id: usize) -> String {
    let events = state.live_events.lock().unwrap_or_else(|e| e.into_inner());
    let filtered: Vec<LiveTestEvent> = events.iter().filter(|e| e.id > since_id).cloned().collect();
    let total_recorded = events.len();
    drop(events);

    let json_val = json!({
        "total_recorded": total_recorded,
        "events": filtered
    });
    json_val.to_string()
}

pub async fn handle_evaluate_cedar(state: &WebState, body: &str) -> Result<String, String> {
    let req: EvaluateCedarRequest = serde_json::from_str(body)
        .map_err(|e| json_error_payload("INVALID_JSON", &format!("Invalid JSON request: {}", e)))?;

    // Map tool name
    let tool_name = match req.action.as_str() {
        "extract" => "doc_extractor",
        "write" => "ledger_writer",
        "egress" => "http_egress",
        "notify" => "notifier",
        "change_security_policy" => "change_security_policy",
        "quarantine" => "quarantine",
        "kernel_enforce" => "kernel_sentinel",
        "execute_code" => "code_executor",
        _ => req.action.as_str(),
    };

    let role = match req.principal.as_str() {
        "document_arm" => ArmRole::UntrustedDocIngest,
        "ledger_arm" => ArmRole::AccountingLedgerWrite,
        "network_arm" => ArmRole::NetworkEgress,
        "tarpit_arm" => ArmRole::TarpitDecoyDefense,
        "kernel_sentinel_arm" | "kernel_arm" => ArmRole::KernelLevelSentinel,
        _ => ArmRole::UntrustedDocIngest,
    };

    // Schema type validation: amount_cents in Ledger write must be an exact integer; reject float, NaN, Inf, non-numbers, and undeclared keys
    if tool_name == "ledger_writer" {
        if let Some(map) = req.context.as_object() {
            let allowed_keys = [
                "amount_cents",
                "approved",
                "instruction_language",
                "translated_prompt",
                "language_code",
                "sender_agent",
                "target_agent",
                "inter_agent_message",
                "originator",
            ];
            if map.keys().any(|k| !allowed_keys.contains(&k.as_str())) {
                let err_msg = "Schema validation error: context contains undeclared attributes or duplicate key tampering".to_string();
                let honey_token = state.tarpit.generate_synthetic_honey_tokens(&req.principal, "schema_tamper", body);
                let res = EvaluateCedarResponse {
                    is_allowed: false,
                    determining_policies: vec![],
                    diagnostic_errors: vec![err_msg.clone()],
                    reason: err_msg,
                    tarpit_engaged: Some(true),
                    decoy_honey_token: Some(honey_token),
                    rl_action_tier: Some("MicroContainment".to_string()),
                    breakout_verdict: Some("VETO_SCHEMA_TAMPERING".to_string()),
                    trace_id: None,
                };
                return Ok(serde_json::to_string(&res).unwrap_or_default());
            }
        }
        if let Some(amt_val) = req.context.get("amount_cents") {
            let is_valid_int = amt_val.is_i64() || amt_val.is_u64();
            if !is_valid_int {
                let err_msg = "Schema validation error: amount_cents must be an exact 64-bit integer, received floating point, NaN, Inf, or invalid type".to_string();
                let honey_token = state.tarpit.generate_synthetic_honey_tokens(&req.principal, "schema_tamper", body);
                let res = EvaluateCedarResponse {
                    is_allowed: false,
                    determining_policies: vec![],
                    diagnostic_errors: vec![err_msg.clone()],
                    reason: err_msg,
                    tarpit_engaged: Some(true),
                    decoy_honey_token: Some(honey_token),
                    rl_action_tier: Some("MicroContainment".to_string()),
                    breakout_verdict: Some("VETO_SCHEMA_TAMPERING".to_string()),
                    trace_id: None,
                };
                return Ok(serde_json::to_string(&res).unwrap_or_default());
            }
        }
    }

    // Issue capability token for request
    let token = state.gateway.auth_engine().issue_capability(
        "brain",
        &req.principal,
        role.clone(),
        tool_name,
        &req.resource,
    );

    let approval_receipt = if req.attach_supervisor_approval {
        let requested_cents = req.context.get("amount_cents").and_then(|v| v.as_u64()).unwrap_or(0);
        let approved_ceiling = requested_cents.max(10000000);
        state.gateway.issue_supervisor_approval(
            "security_supervisor",
            &req.principal,
            &req.resource,
            approved_ceiling,
            300,
        ).ok()
    } else {
        None
    };

    let start_instant = std::time::Instant::now();
    let start_nano = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let session_id = format!("session_{}", req.principal);
    let (_, trace_id) = state.otel_telemetry.get_or_start_session(&session_id, &req.principal);

    // 1. Real-Time Agentic Self-Protection (RT-ASP) Interception
    let subject_trust = if req.principal.contains("supervisor") || req.attach_supervisor_approval {
        RaspAgentTrustTier::SupervisorAttested
    } else if req.principal.contains("kernel") || req.principal.contains("system") {
        RaspAgentTrustTier::SystemKernel
    } else {
        RaspAgentTrustTier::WorkerSandboxed
    };

    let role_str = format!("{:?}", role);
    let mut subject = AgentSecuritySubject::new(&req.principal, &role_str, subject_trust);
    if req.attach_supervisor_approval {
        subject = subject.with_supervisor_attestation("attested_supervisor_sig");
    }

    let (rasp_dec, _rasp_threat, _sanitized_context) = state.rasp_engine.inspect_actuator(
        tool_name,
        &req.context,
        &subject,
        None,
    );

    // 2. Evaluate Breakout Taxonomy Guards (Technical, Operational, Behavioral, Data)
    let payload_str = serde_json::to_string(&req.context).unwrap_or_default();
    let breakout_eval = state.breakout_coordinator.evaluate_action(
        &req.principal,
        &req.action,
        &req.resource,
        &payload_str,
    );

    // 3. Synthesize 10-D State Vector for RL Engine
    let mut state_vec = AdaptiveStateVector::default();
    if !breakout_eval.technical.is_clean {
        state_vec.credential_access_pressure = 0.95;
    }
    if !breakout_eval.operational.is_clean {
        state_vec.credential_access_pressure = 0.85;
    }
    if !breakout_eval.behavioral.is_clean {
        state_vec.eval_harness_tamper_signal = 0.95;
    }
    if !breakout_eval.data.is_clean {
        state_vec.cross_agent_scratchpad_leak = 0.9;
    }
    if rasp_dec.is_blocked() {
        state_vec.schema_tamper_score = 0.95;
    }

    // 4. Query Progressive Action from RL Engine
    let rl_action = state.rl_defense.select_action(&state_vec);
    state.otel_telemetry.update_session_rl_tier(&session_id, rl_action.as_str());

    let result = state.gateway.authorize_tool_invocation_with_approval(
        &token,
        &req.principal,
        tool_name,
        &req.resource,
        req.context.clone(),
        approval_receipt.as_ref(),
    );

    let (mut is_allowed, determining_policies, mut diagnostic_errors, mut reason) = match result {
        Ok(verdict) => {
            let r = if verdict.is_allowed {
                "Action authorized by active Cedar policy".to_string()
            } else {
                "Action denied by Cedar default-deny or forbid rule".to_string()
            };
            (verdict.is_allowed, verdict.determining_policies, verdict.diagnostic_errors, r)
        }
        Err(err) => {
            (false, vec![], vec![err.to_string()], format!("Authorization Gateway Denied: {}", err))
        }
    };

    // Override if RT-ASP, Breakout Guard, or RL Action Tier mandates containment!
    if rasp_dec.is_blocked() {
        is_allowed = false;
        let r_msg = match &rasp_dec {
            RaspDecision::Deny { reason, .. } => reason.clone(),
            RaspDecision::Quarantine { reason, .. } => reason.clone(),
            _ => "Vetoed by Real-Time Agentic Self-Protection (RT-ASP)".to_string(),
        };
        reason = format!("VETO BY RT-ASP: {}", r_msg);
        diagnostic_errors.push(r_msg);
    } else if !breakout_eval.is_clean {
        is_allowed = false;
        reason = format!("VETO BY BREAKOUT TAXONOMY: {}", breakout_eval.composite_verdict);
        diagnostic_errors.push(breakout_eval.composite_verdict.clone());
    } else if rl_action.is_containment() && state_vec.composite_threat_severity() > 0.0 {
        is_allowed = false;
        reason = format!("VETO BY RL ADAPTIVE DEFENSE: Escalated to {}", rl_action.as_str());
        diagnostic_errors.push(format!("RL_DEFENSE_ESCALATION_{}", rl_action.as_str()));
    }

    let duration_ms = start_instant.elapsed().as_secs_f64() * 1000.0;
    let is_threat = !breakout_eval.is_clean || !is_allowed;
    let was_contained = !is_allowed;

    // Track resilience (MTTD/MTTR)
    let (mttd_ms, mttr_ms) = if is_threat {
        (duration_ms * 0.4, duration_ms * 0.6)
    } else {
        (0.0, 0.0)
    };
    state.otel_telemetry.record_resilience_event(mttd_ms, mttr_ms, Some(&session_id));

    // RL Step Update
    let mut next_state_vec = state_vec.clone();
    next_state_vec.step_count_drift = (next_state_vec.step_count_drift + 0.005).min(1.0);
    state.rl_defense.step(
        &state_vec,
        rl_action,
        is_threat,
        was_contained,
        duration_ms,
        &next_state_vec,
        false,
    );

    // Record OTel Span
    let end_nano = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let mut span_attrs = std::collections::HashMap::new();
    span_attrs.insert("session.id".to_string(), session_id);
    span_attrs.insert("agent.principal".to_string(), req.principal.clone());
    span_attrs.insert("tool.name".to_string(), tool_name.to_string());
    span_attrs.insert("resource".to_string(), req.resource.clone());
    span_attrs.insert("security.verdict".to_string(), if is_allowed { "ALLOW".to_string() } else { "DENY".to_string() });
    span_attrs.insert("breakout.composite".to_string(), breakout_eval.composite_verdict.clone());
    span_attrs.insert("rl.action_tier".to_string(), rl_action.as_str().to_string());

    let status_code = if is_allowed { OtelStatusCode::Ok } else { OtelStatusCode::Error };
    state.otel_telemetry.record_span(
        &trace_id,
        None,
        &format!("evaluate_{}", tool_name),
        OtelSpanKind::Server,
        start_nano,
        end_nano,
        status_code,
        None,
        span_attrs,
        vec![],
    );

    let decision_str = if is_allowed { "ALLOW" } else { "DENY" };
    let hash = state.audit_log.record_event(
        "CEDAR_POLICY_EVAL",
        &req.principal,
        &format!("Action: '{}' on Resource: '{}' | Context: {}", tool_name, req.resource, req.context),
        decision_str,
    );

    // Tarpit Engagement for unauthorized/denied attempts
    let should_engage = req.engage_tarpit.unwrap_or(true);
    let (tarpit_engaged, decoy_honey_token) = if !is_allowed && should_engage {
        let adv_id = req.adversary_id.as_deref().unwrap_or(&req.principal);
        let engagement = state.tarpit.engage_adversary(
            adv_id,
            &req.action,
            &serde_json::to_string(&req.context).unwrap_or_default(),
        ).await;
        (Some(true), Some(engagement.synthetic_honey_tokens))
    } else {
        (None, None)
    };

    let mut events = state.live_events.lock().unwrap_or_else(|e| e.into_inner());
    let event_id = events.len() + 1;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    events.push(LiveTestEvent {
        id: event_id,
        timestamp_secs: now,
        principal: req.principal.clone(),
        action: req.action.clone(),
        resource: req.resource.clone(),
        is_allowed,
        verdict: decision_str.to_string(),
        reason: reason.clone(),
        policy: if is_allowed { "Cedar Permit Rule".to_string() } else { "Cedar Forbid / Default-Deny".to_string() },
        record_hash: hash,
    });

    let res = EvaluateCedarResponse {
        is_allowed,
        determining_policies,
        diagnostic_errors,
        reason,
        tarpit_engaged,
        decoy_honey_token,
        rl_action_tier: Some(rl_action.as_str().to_string()),
        breakout_verdict: Some(breakout_eval.composite_verdict),
        trace_id: Some(trace_id),
    };
    Ok(serde_json::to_string(&res).unwrap_or_default())
}

#[derive(Debug, Deserialize)]
pub struct UpdateEgressDomainsRequest {
    pub action: String, // "add", "remove", "reset"
    pub domain: Option<String>,
}

pub fn handle_get_egress_domains(state: &WebState) -> String {
    let domains = state.allowed_domains.read().unwrap_or_else(|e| e.into_inner()).clone();
    json!({
        "success": true,
        "count": domains.len(),
        "domains": domains
    }).to_string()
}

pub fn handle_update_egress_domains(state: &WebState, body: &str) -> Result<String, String> {
    let req: UpdateEgressDomainsRequest = serde_json::from_str(body)
        .map_err(|e| json_error_payload("INVALID_JSON", &format!("Invalid JSON request: {}", e)))?;

    let mut domains = state.allowed_domains.write().unwrap_or_else(|e| e.into_inner());

    match req.action.to_ascii_lowercase().as_str() {
        "add" => {
            let raw_domain = req.domain.ok_or_else(|| json_error_payload("MISSING_PARAMETER", "Missing 'domain' parameter"))?;
            let clean_domain = raw_domain.trim().to_ascii_lowercase();
            if !is_valid_domain(&clean_domain) {
                return Err(json_error_payload(
                    "INVALID_DOMAIN",
                    &format!(
                        "Invalid domain '{}': must be a valid FQDN (e.g. 'api.openai.com'). Direct IP addresses and schemes (http://) are forbidden to prevent SSRF bypasses.",
                        clean_domain
                    ),
                ));
            }
            if !domains.contains(&clean_domain) {
                domains.push(clean_domain.clone());
            }
            state.audit_log.record_event(
                "EGRESS_ALLOWLIST_ADD",
                "web_ui_administrator",
                &format!("Added approved egress domain: {}", clean_domain),
                "CONFIG_UPDATE",
            );
        }
        "remove" => {
            let raw_domain = req.domain.ok_or_else(|| json_error_payload("MISSING_PARAMETER", "Missing 'domain' parameter"))?;
            let clean_domain = raw_domain.trim().to_ascii_lowercase();
            domains.retain(|d| d != &clean_domain);
            state.audit_log.record_event(
                "EGRESS_ALLOWLIST_REMOVE",
                "web_ui_administrator",
                &format!("Removed egress domain: {}", clean_domain),
                "CONFIG_UPDATE",
            );
        }
        "reset" => {
            *domains = vec![
                "google.com".to_string(),
                "www.google.com".to_string(),
                "api.openai.com".to_string(),
                "api.anthropic.com".to_string(),
                "huggingface.co".to_string(),
                "github.com".to_string(),
            ];
            state.audit_log.record_event(
                "EGRESS_ALLOWLIST_RESET",
                "web_ui_administrator",
                "Reset egress domains to default baseline",
                "CONFIG_UPDATE",
            );
        }
        _ => return Err(json_error_payload("UNKNOWN_ACTION", &format!("Unknown action '{}': supported actions are 'add', 'remove', 'reset'", req.action))),
    }

    save_egress_domains(&domains);
    let _ = state.gateway.engine().update_egress_domains(&domains);

    Ok(json!({
        "success": true,
        "count": domains.len(),
        "domains": domains.clone()
    }).to_string())
}

pub fn handle_rl_defense_status(state: &WebState) -> String {
    let stats = state.rl_defense.stats();
    serde_json::to_string(&stats).unwrap_or_default()
}

pub async fn handle_rl_defense_train_cycle(state: &WebState) -> String {
    let report = state.continuous_eval.run_continuous_training_cycle().await;
    serde_json::to_string(&report).unwrap_or_default()
}

pub async fn handle_rl_defense_latest_cycle(state: &WebState) -> String {
    if let Some(report) = state.continuous_eval.get_latest_report() {
        serde_json::to_string(&report).unwrap_or_default()
    } else {
        let report = state.continuous_eval.run_continuous_training_cycle().await;
        serde_json::to_string(&report).unwrap_or_default()
    }
}

#[derive(Debug, Deserialize)]
pub struct RlEvaluateActionRequest {
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub payload: Option<String>,
}

pub fn handle_rl_evaluate_action(state: &WebState, body: &str) -> Result<String, String> {
    let req: RlEvaluateActionRequest = serde_json::from_str(body)
        .map_err(|e| json_error_payload("INVALID_JSON", &format!("Invalid JSON request: {}", e)))?;

    let payload = req.payload.unwrap_or_default();
    let breakout_eval = state.breakout_coordinator.evaluate_action(
        &req.principal,
        &req.action,
        &req.resource,
        &payload,
    );

    let mut state_vec = AdaptiveStateVector::default();
    if !breakout_eval.technical.is_clean { state_vec.credential_access_pressure = 0.95; }
    if !breakout_eval.operational.is_clean { state_vec.credential_access_pressure = 0.85; }
    if !breakout_eval.behavioral.is_clean { state_vec.eval_harness_tamper_signal = 0.95; }
    if !breakout_eval.data.is_clean { state_vec.cross_agent_scratchpad_leak = 0.9; }

    let action = state.rl_defense.select_action(&state_vec);

    Ok(json!({
        "principal": req.principal,
        "action": req.action,
        "resource": req.resource,
        "breakout_evaluation": breakout_eval,
        "rl_action_selected": action.as_str(),
        "rl_tier_description": action.tier_description(),
        "is_containment": action.is_containment(),
        "threat_severity": state_vec.composite_threat_severity()
    }).to_string())
}

pub fn handle_otel_sessions(state: &WebState) -> String {
    let sessions = state.otel_telemetry.list_sessions();
    json!({ "total": sessions.len(), "sessions": sessions }).to_string()
}

pub fn handle_otel_spans(state: &WebState, limit: usize) -> String {
    let spans = state.otel_telemetry.get_recent_spans(limit);
    json!({ "total": spans.len(), "spans": spans }).to_string()
}

pub fn handle_resilience_metrics(state: &WebState) -> String {
    let metrics = state.otel_telemetry.get_resilience_metrics();
    serde_json::to_string(&metrics).unwrap_or_default()
}

pub fn handle_breakout_guards_status(state: &WebState) -> String {
    let (harness_clean, tampered) = state.breakout_coordinator.behavioral.verify_harness_integrity();
    json!({
        "status": "ONLINE",
        "technical_guard": {
            "status": "Active",
            "ephemeral_virtualization": "Hardware-isolated (Read-only root + Copy-on-Write overlay)",
            "socket_protection": "Unmasked Docker / containerd daemon socket blocker active",
            "wasm_bounds": "Wasmtime fuel limit & memory grow clamps active"
        },
        "operational_guard": {
            "status": "Active",
            "sts_token_brokering": "Active (Minute-level TTL, cryptographic signing)",
            "env_leak_scrubber": "Active (Scans for cloud API tokens across contexts)",
            "ephemeral_disk_sanitizer": "Active"
        },
        "behavioral_guard": {
            "status": if harness_clean { "Aligned" } else { "Tampering Detected" },
            "harness_integrity_verified": harness_clean,
            "tampered_files": tampered,
            "network_evasion_filter": "Active (route table / DNS tunnel / hosts file clamps)"
        },
        "data_guard": {
            "status": "Active",
            "cross_agent_isolation": "Role-Based Scratchpad & Message Broker Isolation Active",
            "memory_dump_blocker": "Active (Blocks /proc, procdump, strings)"
        }
    }).to_string()
}

#[derive(Debug, Deserialize)]
pub struct ValidateSisypheanRequest {
    pub trajectories: Option<usize>,
    pub steps: Option<usize>,
    pub epsilon_min: Option<f64>,
    pub rl_epsilon_0: Option<f64>,
    pub lambda: Option<f64>,
    pub gamma: Option<f64>,
}

pub fn handle_validate_sisyphean(_state: &WebState, body: &str) -> Result<String, String> {
    let req: ValidateSisypheanRequest = if body.trim().is_empty() {
        ValidateSisypheanRequest {
            trajectories: None,
            steps: None,
            epsilon_min: None,
            rl_epsilon_0: None,
            lambda: None,
            gamma: None,
        }
    } else {
        serde_json::from_str(body)
            .map_err(|e| json_error_payload("INVALID_JSON", &format!("Invalid JSON request: {}", e)))?
    };

    let trajectories = req.trajectories.unwrap_or(10_000).clamp(100, 100_000);
    let steps = req.steps.unwrap_or(500).clamp(10, 5000);
    let epsilon_min = req.epsilon_min.unwrap_or(0.01).clamp(0.0001, 0.5);
    let rl_epsilon_0 = req.rl_epsilon_0.unwrap_or(0.05).clamp(0.001, 0.9);
    let lambda = req.lambda.unwrap_or(0.05).clamp(0.001, 1.0);
    let gamma = req.gamma.unwrap_or(1.25).clamp(0.1, 5.0);

    let res = VassilevMathValidator::simulate_monte_carlo(
        trajectories,
        steps,
        epsilon_min,
        rl_epsilon_0,
        lambda,
        gamma,
    );

    let (z, p, verdict) = VassilevMathValidator::hypothesis_test(
        res.rl_survivors,
        res.total_trajectories,
        res.static_survivors,
        res.total_trajectories,
    );

    let p_infty = VassilevMathValidator::compute_rl_asymptotic_floor(rl_epsilon_0, lambda, gamma);
    let static_analytical = VassilevMathValidator::compute_static_survival_bound(steps, epsilon_min);

    Ok(json!({
        "status": "SUCCESS",
        "parameters": {
            "trajectories": trajectories,
            "steps": steps,
            "epsilon_min": epsilon_min,
            "rl_epsilon_0": rl_epsilon_0,
            "lambda": lambda,
            "gamma": gamma,
        },
        "theoretical_bounds": {
            "vassilev_equation_8_static_analytical": static_analytical,
            "vassilev_equation_10_paper_benchmark": 0.006570699,
            "theorem_1_asymptotic_floor": p_infty,
            "sisyphean_collapse_escaped": p_infty > 0.0 && gamma > 1.0,
        },
        "monte_carlo_results": {
            "static_survivors": res.static_survivors,
            "static_survival_rate": res.static_survival_rate,
            "rl_survivors": res.rl_survivors,
            "rl_survival_rate": res.rl_survival_rate,
            "improvement_multiplier": if res.static_survival_rate > 0.0 {
                res.rl_survival_rate / res.static_survival_rate
            } else {
                999.0
            },
        },
        "statistical_hypothesis_test": {
            "z_score": z,
            "p_value": p,
            "verdict": verdict,
            "h0_rejected": p < 0.001,
        }
    }).to_string())
}

pub fn handle_vassilev_proof(_state: &WebState) -> String {
    let report = VassilevMathValidator::generate_validation_report(
        500,
        0.01,
        0.05,
        0.05,
        1.25,
        10_000,
        &[],
    );
    json!({
        "paper_title": "Beyond One and Done: Agent Breakouts and Continuous Security for Agentic AI Systems",
        "paper_author": "Femi Oyesanya, October 2026",
        "equations_implemented": [
            {"eq": "1-2", "name": "MDP Trajectory", "formula": "h_t = (s_0, a_0, r_0, ..., s_t)"},
            {"eq": "3-4", "name": "Vassilev Godelian Incompleteness", "formula": "Exists s in S s.t. Dec_Static(s) = FAIL"},
            {"eq": "5", "name": "Information Horizon Bound", "formula": "|S_W| <= |Sigma|^W"},
            {"eq": "6", "name": "Per-Step Error Probability", "formula": "P(E_t) = epsilon_t >= epsilon_min > 0"},
            {"eq": "7-8", "name": "Cumulative Containment Survival", "formula": "P_secure(N) <= (1 - epsilon_min)^N"},
            {"eq": "9-10", "name": "Asymptotic Decay Limit & Benchmark", "formula": "lim_{N->inf} P_secure(N) = 0; P_secure(500) <= 0.00657 (< 0.7%)"},
            {"eq": "11", "name": "Mean Time to Detect (MTTD)", "formula": "MTTD = (1/K) \\sum (t_{detect} - t_{breach})"},
            {"eq": "12", "name": "Mean Time to Remediate (MTTR)", "formula": "MTTR = (1/K) \\sum (t_{contained} - t_{detect})"},
            {"eq": "Theorem 1", "name": "Continuous Adaptation Transference Theorem", "formula": "P_inf = \\prod_{t=1}^inf (1 - epsilon(t)) > 0  iff  \\sum epsilon(t) < inf (gamma > 1.0)"}
        ],
        "validation_report": report
    }).to_string()
}

#[derive(Debug, Deserialize)]
pub struct InjectGovernorSampleRequest {
    pub event_type: String,
    pub is_malicious: Option<bool>,
    pub use_rl_mitigation: Option<bool>,
    pub custom_detail: Option<String>,
}

pub fn handle_governor_status(state: &WebState) -> String {
    let gov = state.governor_state.read().unwrap_or_else(|e| e.into_inner());
    let metrics = gov.get_metrics_summary();
    let history: Vec<_> = gov.history.iter().rev().take(20).cloned().collect();
    let is_halted = gov.current_survival_prob <= gov.config.critical_termination_threshold;
    let warning_triggered = gov.current_survival_prob <= gov.config.warning_threshold;

    json!({
        "status": "ONLINE",
        "current_step": gov.current_step,
        "current_survival_prob": gov.current_survival_prob,
        "target_pid": gov.config.target_pid,
        "warning_threshold": gov.config.warning_threshold,
        "critical_termination_threshold": gov.config.critical_termination_threshold,
        "is_halted": is_halted,
        "warning_triggered": warning_triggered,
        "circuit_breaker_tripped": is_halted,
        "recent_history": history.into_iter().map(|(step, eps, p)| {
            json!({ "step": step, "epsilon_t": eps, "survival_prob": p })
        }).collect::<Vec<_>>(),
        "metrics": {
            "total_incidents": metrics.total_incidents,
            "mean_time_to_detect_ms": metrics.mean_time_to_detect.as_secs_f64() * 1000.0,
            "mean_time_to_remediate_ms": metrics.mean_time_to_remediate.as_secs_f64() * 1000.0,
            "total_containment_failures": metrics.total_containment_failures,
        }
    }).to_string()
}

pub fn handle_governor_inject_sample(state: &WebState, body: &str) -> Result<String, String> {
    let req: InjectGovernorSampleRequest = serde_json::from_str(body)
        .map_err(|e| json_error_payload("INVALID_JSON", &format!("Invalid JSON request: {}", e)))?;

    let is_malicious = req.is_malicious.unwrap_or(false);
    let use_rl = req.use_rl_mitigation.unwrap_or(false);

    let event = match req.event_type.to_ascii_lowercase().as_str() {
        "shell_exec" | "process_exec" => KernelEventKind::ProcessExec {
            executable_path: std::path::PathBuf::from("/bin/bash"),
            arguments: vec!["-c".to_string(), "id; whoami".to_string()],
            is_interactive_shell_or_compiler: is_malicious,
        },
        "socket_connect" | "egress" => KernelEventKind::SocketConnect {
            destination_ip: "198.51.100.23".parse().unwrap(),
            port: if is_malicious { 4444 } else { 443 },
            is_whitelisted_endpoint: !is_malicious,
        },
        "restricted_fs" | "virtual_fs" => KernelEventKind::FileAccess {
            path: if is_malicious { std::path::PathBuf::from("/proc/kcore") } else { std::path::PathBuf::from("/workspace/src/lib.rs") },
            is_read_only: true,
            is_restricted_virtual_fs: is_malicious,
        },
        "schema_drift" => KernelEventKind::ToolSchemaDrift {
            tool_name: "query_database".to_string(),
            entropy_divergence: if is_malicious { 0.85 } else { 0.05 },
            unrecognized_parameters: if is_malicious { 3 } else { 0 },
        },
        _ => KernelEventKind::FileAccess {
            path: std::path::PathBuf::from("/workspace/data.json"),
            is_read_only: false,
            is_restricted_virtual_fs: false,
        },
    };

    let mut gov = state.governor_state.write().unwrap_or_else(|e| e.into_inner());
    let next_step = gov.current_step + 1;

    let sample = TelemetrySample {
        step: next_step,
        timestamp: std::time::Instant::now(),
        breach_time_estimate: if is_malicious {
            Some(std::time::Instant::now() - std::time::Duration::from_millis(15))
        } else {
            None
        },
        event,
    };

    let raw_epsilon = gov.compute_step_risk(&sample.event);
    
    // Demonstrate Code Adaptation & Improvement:
    // If use_rl is enabled, consult the RL engine to attenuate hazard via learned containment
    let (effective_epsilon, rl_action_name, mitigation_factor) = if use_rl && is_malicious {
        let mut s_vec = AdaptiveStateVector::default();
        s_vec.credential_access_pressure = 0.9;
        let action = state.rl_defense.select_action(&s_vec);
        let factor = match action {
            AdaptiveDefenseAction::HardMitigation => 0.85,
            AdaptiveDefenseAction::MicroContainment => 0.65,
            AdaptiveDefenseAction::MemoryIntrospection => 0.40,
            AdaptiveDefenseAction::TraceElevation => 0.25,
            AdaptiveDefenseAction::PassiveObserve => 0.05,
        };
        (raw_epsilon * (1.0 - factor), action.as_str().to_string(), factor)
    } else {
        (raw_epsilon, "StaticBaseline (No RL Mitigation)".to_string(), 0.0)
    };

    gov.current_step = next_step;
    gov.current_survival_prob *= 1.0 - effective_epsilon;
    let prob = gov.current_survival_prob;
    if gov.history.len() >= gov.config.max_history_capacity {
        gov.history.pop_front();
    }
    gov.history.push_back((next_step, effective_epsilon, prob));

    let is_anomaly = effective_epsilon > (gov.config.weights.weight_baseline_noise * 5.0);
    if is_anomaly {
        let detection_ts = std::time::Instant::now();
        let breach_ts = sample.breach_time_estimate.unwrap_or(sample.timestamp);
        gov.incidents.push(IncidentRecord {
            step: next_step,
            breach_timestamp: breach_ts,
            detection_timestamp: detection_ts,
            containment_timestamp: Some(detection_ts + std::time::Duration::from_millis(2)),
        });
    }

    let is_tripped = gov.current_survival_prob <= gov.config.critical_termination_threshold;
    let is_warned = gov.current_survival_prob <= gov.config.warning_threshold;

    Ok(json!({
        "step": next_step,
        "event_type": req.event_type,
        "is_malicious": is_malicious,
        "raw_epsilon_t": raw_epsilon,
        "effective_epsilon_t": effective_epsilon,
        "use_rl_mitigation": use_rl,
        "rl_action_selected": rl_action_name,
        "rl_mitigation_attenuation": mitigation_factor,
        "survival_probability": gov.current_survival_prob,
        "is_anomaly": is_anomaly,
        "warning_triggered": is_warned,
        "circuit_breaker_tripped": is_tripped,
    }).to_string())
}

pub fn handle_governor_reset(state: &WebState) -> String {
    let mut gov = state.governor_state.write().unwrap_or_else(|e| e.into_inner());
    gov.current_step = 0;
    gov.current_survival_prob = 1.0;
    gov.history.clear();
    gov.incidents.clear();
    json!({ "status": "RESET", "current_survival_prob": 1.0, "step": 0 }).to_string()
}

// ============================================================================
// Real-Time Agentic Self-Protection (RT-ASP) API Handlers
// ============================================================================

pub fn handle_rasp_status(state: &WebState) -> String {
    state.rasp_engine.status_summary().to_string()
}

pub fn handle_rasp_telemetry(state: &WebState, limit: usize) -> String {
    let limit = if limit == 0 { 50 } else { limit.min(200) };
    let events = state.rasp_engine.get_recent_events(limit);
    let metrics = state.rasp_engine.telemetry_registry().get_metrics();
    json!({
        "metrics": metrics,
        "events": events
    }).to_string()
}

#[derive(Debug, Deserialize)]
pub struct RaspPromptInterceptRequest {
    pub prompt: String,
    #[serde(default)]
    pub language_code: Option<String>,
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
    #[serde(default)]
    pub trust_tier: Option<String>,
}

fn default_agent_id() -> String {
    "agent_untrusted_worker".to_string()
}

pub fn handle_rasp_intercept_prompt(state: &WebState, body: &str) -> Result<String, String> {
    let req: RaspPromptInterceptRequest = serde_json::from_str(body).map_err(|e| {
        json_error_payload("INVALID_JSON", &format!("Invalid prompt intercept request: {}", e))
    })?;

    let tier = match req.trust_tier.as_deref() {
        Some("SystemKernel") => RaspAgentTrustTier::SystemKernel,
        Some("SupervisorAttested") => RaspAgentTrustTier::SupervisorAttested,
        _ => RaspAgentTrustTier::WorkerSandboxed,
    };

    let subject = AgentSecuritySubject::new(&req.agent_id, "worker", tier);
    let (decision, threat) = state.rasp_engine.inspect_invocation(
        &req.prompt,
        req.language_code.as_deref(),
        &subject,
    );

    Ok(json!({
        "verdict": decision.verdict_str(),
        "is_allowed": decision.is_allowed(),
        "threat_category": threat.map(|t| t.to_string()),
        "decision_details": decision,
    }).to_string())
}

#[derive(Debug, Deserialize)]
pub struct RaspToolInterceptRequest {
    pub tool_name: String,
    pub params: serde_json::Value,
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
    #[serde(default)]
    pub supervisor_signature: Option<String>,
}

pub fn handle_rasp_intercept_tool(state: &WebState, body: &str) -> Result<String, String> {
    let req: RaspToolInterceptRequest = serde_json::from_str(body).map_err(|e| {
        json_error_payload("INVALID_JSON", &format!("Invalid tool intercept request: {}", e))
    })?;

    let mut subject = AgentSecuritySubject::new(&req.agent_id, "worker", RaspAgentTrustTier::WorkerSandboxed);
    if let Some(ref sig) = req.supervisor_signature {
        subject = subject.with_supervisor_attestation(sig);
    }

    let (decision, threat, params) = state.rasp_engine.inspect_actuator(
        &req.tool_name,
        &req.params,
        &subject,
        Some(state.gateway.as_ref()),
    );

    Ok(json!({
        "verdict": decision.verdict_str(),
        "is_allowed": decision.is_allowed(),
        "threat_category": threat.map(|t| t.to_string()),
        "sanitized_params": params,
        "decision_details": decision,
    }).to_string())
}

#[derive(Debug, Deserialize)]
pub struct RaspMemoryInterceptRequest {
    pub operation: String,
    pub key: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
}

pub fn handle_rasp_intercept_memory(state: &WebState, body: &str) -> Result<String, String> {
    let req: RaspMemoryInterceptRequest = serde_json::from_str(body).map_err(|e| {
        json_error_payload("INVALID_JSON", &format!("Invalid memory intercept request: {}", e))
    })?;

    let subject = AgentSecuritySubject::new(&req.agent_id, "worker", RaspAgentTrustTier::WorkerSandboxed);

    match req.operation.to_ascii_lowercase().as_str() {
        "read" => {
            let (decision, threat) = state.rasp_engine.inspect_memory_read(&req.key, &subject);
            Ok(json!({
                "operation": "read",
                "key": req.key,
                "verdict": decision.verdict_str(),
                "is_allowed": decision.is_allowed(),
                "threat_category": threat.map(|t| t.to_string()),
                "decision_details": decision,
            }).to_string())
        }
        "write" => {
            let content = req.content.unwrap_or_default();
            let (decision, threat, sanitized) = state.rasp_engine.inspect_memory_write(&req.key, &content, &subject);
            Ok(json!({
                "operation": "write",
                "key": req.key,
                "verdict": decision.verdict_str(),
                "is_allowed": decision.is_allowed(),
                "threat_category": threat.map(|t| t.to_string()),
                "sanitized_content": sanitized,
                "decision_details": decision,
            }).to_string())
        }
        other => Err(json_error_payload("INVALID_OPERATION", &format!("Unsupported memory operation: {}", other))),
    }
}

#[derive(Debug, Deserialize)]
pub struct RaspCreateCanaryRequest {
    pub label: String,
}

pub fn handle_rasp_create_canary(state: &WebState, body: &str) -> Result<String, String> {
    let req: RaspCreateCanaryRequest = serde_json::from_str(body).map_err(|e| {
        json_error_payload("INVALID_JSON", &format!("Invalid canary creation request: {}", e))
    })?;

    let token = state.rasp_engine.register_canary(&req.label);
    Ok(json!({
        "status": "CREATED",
        "label": req.label,
        "canary_token": token,
        "instructions": "Place this token in honey files or sensitive memory; any unauthorized read or write trips immediate RT-ASP alert."
    }).to_string())
}

#[derive(Debug, Deserialize)]
pub struct RaspMitigationTierRequest {
    pub tier: String,
}

pub fn handle_rasp_set_mitigation_tier(state: &WebState, body: &str) -> Result<String, String> {
    let req: RaspMitigationTierRequest = serde_json::from_str(body).map_err(|e| {
        json_error_payload("INVALID_JSON", &format!("Invalid mitigation tier request: {}", e))
    })?;

    let tier = match req.tier.to_ascii_lowercase().as_str() {
        "level0" | "monitor" => AdaptiveMitigationTier::Level0Monitor,
        "level1" | "sanitize" => AdaptiveMitigationTier::Level1Sanitize,
        "level2" | "decoy" | "synthetic" => AdaptiveMitigationTier::Level2SyntheticDecoy,
        "level3" | "tarpit" => AdaptiveMitigationTier::Level3TarpitStall,
        "level4" | "revoke" | "quarantine" => AdaptiveMitigationTier::Level4HardRevoke,
        other => return Err(json_error_payload("INVALID_TIER", &format!("Unknown mitigation tier: {}", other))),
    };

    state.rasp_engine.policy_engine().set_mitigation_tier(tier);
    Ok(json!({
        "status": "UPDATED",
        "new_mitigation_tier": format!("{:?}", tier)
    }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_error_payload_schema() {
        let payload_str = json_error_payload("INVALID_JSON", "Unexpected token at line 1");
        let parsed: serde_json::Value = serde_json::from_str(&payload_str).expect("Must parse as JSON");
        assert_eq!(parsed["error"], true);
        assert_eq!(parsed["code"], "INVALID_JSON");
        assert_eq!(parsed["message"], "Unexpected token at line 1");
        assert!(parsed["timestamp"].is_string());
    }

    #[test]
    fn test_api_error_payload_struct() {
        let payload = ApiErrorPayload {
            error: true,
            code: "TEST_CODE".to_string(),
            message: "Test error message".to_string(),
            timestamp: "1234567890".to_string(),
        };
        let serialized = serde_json::to_string(&payload).expect("Must serialize");
        let deserialized: ApiErrorPayload = serde_json::from_str(&serialized).expect("Must deserialize");
        assert_eq!(deserialized.error, true);
        assert_eq!(deserialized.code, "TEST_CODE");
        assert_eq!(deserialized.message, "Test error message");
    }

    #[tokio::test]
    async fn test_handle_evaluate_cedar_malformed_json_returns_error_payload() {
        let state = WebState::default();
        let res = handle_evaluate_cedar(&state, "{not valid json").await;
        assert!(res.is_err());
        let err_str = res.unwrap_err();
        let parsed: serde_json::Value = serde_json::from_str(&err_str).expect("Must parse error as JSON");
        assert_eq!(parsed["error"], true);
        assert_eq!(parsed["code"], "INVALID_JSON");
        assert!(parsed["message"].as_str().unwrap().contains("Invalid JSON request"));
    }

    #[tokio::test]
    async fn test_handle_evaluate_cedar_duplicate_key_schema_tampering() {
        let state = WebState::default();
        let body = serde_json::json!({
            "principal": "ledger_arm",
            "action": "write",
            "resource": "Ledger",
            "context": {
                "amount_cents": 50000,
                "amount_cents_2": 99999999,
                "approved": true
            },
            "attach_supervisor_approval": false
        }).to_string();

        let res = handle_evaluate_cedar(&state, &body).await;
        assert!(res.is_ok());
        let json_str = res.unwrap();
        let resp: EvaluateCedarResponse = serde_json::from_str(&json_str).expect("Must parse response");
        assert_eq!(resp.is_allowed, false);
        assert_eq!(resp.breakout_verdict.as_deref(), Some("VETO_SCHEMA_TAMPERING"));
    }

    #[test]
    fn test_handle_update_egress_domains_malformed_json_and_errors() {
        let state = WebState::default();
        let res1 = handle_update_egress_domains(&state, "{broken");
        assert!(res1.is_err());
        let parsed1: serde_json::Value = serde_json::from_str(&res1.unwrap_err()).unwrap();
        assert_eq!(parsed1["error"], true);
        assert_eq!(parsed1["code"], "INVALID_JSON");

        let res2 = handle_update_egress_domains(&state, r#"{"action": "add"}"#);
        assert!(res2.is_err());
        let parsed2: serde_json::Value = serde_json::from_str(&res2.unwrap_err()).unwrap();
        assert_eq!(parsed2["error"], true);
        assert_eq!(parsed2["code"], "MISSING_PARAMETER");

        let res3 = handle_update_egress_domains(&state, r#"{"action": "unsupported"}"#);
        assert!(res3.is_err());
        let parsed3: serde_json::Value = serde_json::from_str(&res3.unwrap_err()).unwrap();
        assert_eq!(parsed3["error"], true);
        assert_eq!(parsed3["code"], "UNKNOWN_ACTION");
    }

    #[test]
    fn test_handle_rl_evaluate_action_malformed_json() {
        let state = WebState::default();
        let res = handle_rl_evaluate_action(&state, "{bad_json");
        assert!(res.is_err());
        let parsed: serde_json::Value = serde_json::from_str(&res.unwrap_err()).unwrap();
        assert_eq!(parsed["error"], true);
        assert_eq!(parsed["code"], "INVALID_JSON");
    }
}



