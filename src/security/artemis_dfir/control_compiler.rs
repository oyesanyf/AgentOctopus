//! Closed-Loop Forensic Control Compiler (`Artemis DFIR -> Deterministic Containment Code`).
//!
//! Translates high/critical Artemis DFIR forensic observations into live, strictly
//! schema-validated AWS Cedar `forbid` policies (`OCTOPUS_CEDAR_SCHEMA_JSON`),
//! `FileLineageTracker` taint entries (honoring repository/toolchain immunity),
//! and physics-engine tightening directives (Epoch Rotation, Thermodynamic Entropy Boost,
//! Quantum Zeno Observation Acceleration).

use super::types::{
    AbiboDirection, ArtemisForensicEvent, ControlSynthesisKind, ForensicArtifactKind,
    ForensicSeverity, McpConnectorAuditEntry, PersistenceArtifactFinding, SynthesizedControlAction,
};
use crate::security::cedar_arm::CedarPolicyEngine;
use crate::security::file_lineage::FileLineageTracker;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

fn escape_cedar_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' | '\r' | '\t' | '\0' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn short_policy_hash(seed: &str) -> String {
    let hex_str = hex::encode(Sha256::digest(seed.as_bytes()));
    hex_str[..12].to_string()
}

fn extract_executable_basename(cmd_or_path: &str) -> Option<String> {
    let trimmed = cmd_or_path.trim().trim_matches('"').trim_matches('\'');
    if trimmed.is_empty() {
        return None;
    }
    let first_tok = trimmed
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches('"')
        .trim_matches('\'');
    let base = first_tok
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(first_tok)
        .trim();
    if base.is_empty() || base.len() > 128 {
        return None;
    }
    Some(base.to_string())
}

fn extract_domain_candidate(path_or_uri: &str) -> Option<String> {
    let trimmed = path_or_uri.trim();
    if let Ok(parsed) = url::Url::parse(trimmed) {
        if let Some(host) = parsed.host_str() {
            let h = host.trim().to_ascii_lowercase();
            if !h.is_empty() && h != "127.0.0.1" && h != "localhost" && h != "::1" {
                return Some(h);
            }
        }
    }
    // Plain hostname heuristic (contains a dot, no slashes/spaces/backslashes)
    if !trimmed.contains(' ')
        && !trimmed.contains('\\')
        && !trimmed.contains('/')
        && trimmed.contains('.')
        && trimmed.len() <= 253
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        let h = trimmed.to_ascii_lowercase();
        if h != "127.0.0.1" && !h.ends_with(".exe") && !h.ends_with(".ps1") && !h.ends_with(".md") {
            return Some(h);
        }
    }
    None
}

/// Deterministic closed-loop compiler transforming forensic telemetry into live containment code.
pub struct ForensicControlCompiler;

impl ForensicControlCompiler {
    /// Compiles AWS Cedar `forbid` policies, `FileLineageTracker` poison entries, and physics
    /// tightening directives from forensic observations. If `cedar_engine` or `lineage_tracker`
    /// are provided, the synthesized controls are validated and hot-loaded immediately.
    #[must_use]
    pub fn compile_controls(
        events: &[ArtemisForensicEvent],
        persistence: &[PersistenceArtifactFinding],
        mcp_connectors: &[McpConnectorAuditEntry],
        cedar_engine: Option<&CedarPolicyEngine>,
        lineage_tracker: Option<&FileLineageTracker>,
    ) -> Vec<SynthesizedControlAction> {
        let mut actions = Vec::new();
        let mut emitted_policy_keys: HashSet<String> = HashSet::new();
        let mut needs_epoch_revocation = false;
        let mut needs_zeno_boost = false;

        // 1. Compile controls from Artemis Forensic Events
        for ev in events {
            if ev.severity < ForensicSeverity::High {
                continue;
            }
            needs_zeno_boost = true;

            if ev
                .indicators
                .iter()
                .any(|i| i == "unconsented_sleep_window_activity")
            {
                needs_epoch_revocation = true;
            }

            // A) Poisoned agent instruction/memory file -> Cedar fs_write forbid + FileLineage taint
            if ev.artifact == ForensicArtifactKind::AgentMemoryFile
                || ev
                    .indicators
                    .iter()
                    .any(|i| i == "agent_instruction_or_mcp_surface")
            {
                let target_path = ev.path_or_uri.trim();
                if !target_path.is_empty() && !FileLineageTracker::is_path_immune(target_path) {
                    if let Some(tracker) = lineage_tracker {
                        let synthetic_payload = ev
                            .sha256
                            .as_deref()
                            .unwrap_or(ev.summary.as_str())
                            .as_bytes();
                        tracker.record_file_ingest(
                            target_path,
                            synthetic_payload,
                            &ev.principal,
                            &ev.raw_source,
                            true,
                        );
                    }
                    actions.push(SynthesizedControlAction {
                        control_kind: ControlSynthesisKind::FileLineageTaint,
                        target: target_path.to_string(),
                        detail: format!(
                            "Locked tainted Break-In artifact '{}' into FileLineageTracker",
                            target_path
                        ),
                        policy_text: None,
                        applied: lineage_tracker.is_some(),
                    });

                    let dedup_key = format!("fs_write:{}", target_path.to_ascii_lowercase());
                    if emitted_policy_keys.insert(dedup_key.clone()) {
                        let esc = escape_cedar_string(target_path);
                        let pid = format!("abibo_dfir_fswrite_{}", short_policy_hash(&dedup_key));
                        let policy_text = format!(
                            "forbid (\n    principal,\n    action == Octopus::Action::\"fs_write\",\n    resource is Octopus::FilePath\n) when {{\n    context.path == \"{esc}\"\n}};"
                        );
                        let applied = Self::apply_forbid(cedar_engine, &pid, &policy_text);
                        actions.push(SynthesizedControlAction {
                            control_kind: ControlSynthesisKind::CedarForbidPolicy,
                            target: target_path.to_string(),
                            detail: format!("Synthesized Cedar fs_write forbid policy '{pid}'"),
                            policy_text: Some(policy_text),
                            applied,
                        });
                    }
                }
            }

            // B) Network egress / remote domain Break-Out -> Cedar egress forbid
            if let Some(domain) = extract_domain_candidate(&ev.path_or_uri) {
                let dedup_key = format!("egress:{domain}");
                if emitted_policy_keys.insert(dedup_key.clone()) {
                    let esc = escape_cedar_string(&domain);
                    let pid = format!("abibo_dfir_egress_{}", short_policy_hash(&dedup_key));
                    let policy_text = format!(
                        "forbid (\n    principal,\n    action == Octopus::Action::\"egress\",\n    resource is Octopus::NetworkTarget\n) when {{\n    context.destination_domain == \"{esc}\"\n}};"
                    );
                    let applied = Self::apply_forbid(cedar_engine, &pid, &policy_text);
                    actions.push(SynthesizedControlAction {
                        control_kind: ControlSynthesisKind::CedarForbidPolicy,
                        target: domain,
                        detail: format!("Synthesized Cedar egress forbid policy '{pid}'"),
                        policy_text: Some(policy_text),
                        applied,
                    });
                }
            }

            // C) Suspicious Break-In/Break-Out tool or process execution -> Cedar tool_call / exec forbid
            if matches!(
                ev.direction,
                AbiboDirection::BreakIn
                    | AbiboDirection::BreakOut
                    | AbiboDirection::BidirectionalCoupling
            ) {
                if ev.artifact == ForensicArtifactKind::Process
                    || ev.artifact == ForensicArtifactKind::Prefetch
                    || ev.artifact == ForensicArtifactKind::ScheduledTask
                {
                    if let Some(exe) = extract_executable_basename(&ev.path_or_uri)
                        .or_else(|| extract_executable_basename(&ev.principal))
                    {
                        let dedup_key = format!("exec:{}", exe.to_ascii_lowercase());
                        if emitted_policy_keys.insert(dedup_key.clone()) {
                            let esc = escape_cedar_string(&exe);
                            let pid = format!("abibo_dfir_exec_{}", short_policy_hash(&dedup_key));
                            let policy_text = format!(
                                "forbid (\n    principal,\n    action == Octopus::Action::\"exec\",\n    resource is Octopus::Command\n) when {{\n    context.executable == \"{esc}\"\n}};"
                            );
                            let applied = Self::apply_forbid(cedar_engine, &pid, &policy_text);
                            actions.push(SynthesizedControlAction {
                                control_kind: ControlSynthesisKind::CedarForbidPolicy,
                                target: exe,
                                detail: format!("Synthesized Cedar exec forbid policy '{pid}'"),
                                policy_text: Some(policy_text),
                                applied,
                            });
                        }
                    }
                } else if ev.artifact == ForensicArtifactKind::McpConfig
                    || ev.indicators.iter().any(|i| {
                        i.contains("gmail_send")
                            || i.contains("calendar_delete")
                            || i.contains("grok")
                    })
                {
                    let tool_target =
                        if !ev.path_or_uri.trim().is_empty() && !ev.path_or_uri.contains(' ') {
                            ev.path_or_uri.trim().to_string()
                        } else {
                            ev.principal.trim().to_string()
                        };
                    if !tool_target.is_empty() {
                        let dedup_key = format!("tool_call:{}", tool_target.to_ascii_lowercase());
                        if emitted_policy_keys.insert(dedup_key.clone()) {
                            let esc = escape_cedar_string(&tool_target);
                            let pid = format!("abibo_dfir_tool_{}", short_policy_hash(&dedup_key));
                            let policy_text = format!(
                                "forbid (\n    principal,\n    action == Octopus::Action::\"tool_call\",\n    resource is Octopus::Tool\n) when {{\n    context.tool_name == \"{esc}\"\n}};"
                            );
                            let applied = Self::apply_forbid(cedar_engine, &pid, &policy_text);
                            actions.push(SynthesizedControlAction {
                                control_kind: ControlSynthesisKind::CedarForbidPolicy,
                                target: tool_target,
                                detail: format!(
                                    "Synthesized Cedar tool_call forbid policy '{pid}'"
                                ),
                                policy_text: Some(policy_text),
                                applied,
                            });
                        }
                    }
                }
            }
        }

        // 2. Compile controls from Suspicious OS Persistence Artifacts
        for item in persistence.iter().filter(|p| p.suspicious) {
            needs_zeno_boost = true;
            if let Some(exe) = extract_executable_basename(&item.command_or_path) {
                let dedup_key = format!("exec:{}", exe.to_ascii_lowercase());
                if emitted_policy_keys.insert(dedup_key.clone()) {
                    let esc = escape_cedar_string(&exe);
                    let pid = format!("abibo_persist_exec_{}", short_policy_hash(&dedup_key));
                    let policy_text = format!(
                        "forbid (\n    principal,\n    action == Octopus::Action::\"exec\",\n    resource is Octopus::Command\n) when {{\n    context.executable == \"{esc}\"\n}};"
                    );
                    let applied = Self::apply_forbid(cedar_engine, &pid, &policy_text);
                    actions.push(SynthesizedControlAction {
                        control_kind: ControlSynthesisKind::CedarForbidPolicy,
                        target: exe,
                        detail: format!(
                            "Blocked suspicious {} persistence executable via Cedar policy '{pid}'",
                            item.category
                        ),
                        policy_text: Some(policy_text),
                        applied,
                    });
                }
            }
        }

        // 3. Flag standing write-capable MCP connectors with inline secrets
        for conn in mcp_connectors
            .iter()
            .filter(|c| c.write_capable && c.has_inline_secret)
        {
            let dedup_key = format!("tool_call:{}", conn.server_name.to_ascii_lowercase());
            if emitted_policy_keys.insert(dedup_key.clone()) {
                let esc = escape_cedar_string(&conn.server_name);
                let pid = format!("abibo_mcp_secret_{}", short_policy_hash(&dedup_key));
                let policy_text = format!(
                    "forbid (\n    principal,\n    action == Octopus::Action::\"tool_call\",\n    resource is Octopus::Tool\n) when {{\n    context.tool_name == \"{esc}\"\n}};"
                );
                let applied = Self::apply_forbid(cedar_engine, &pid, &policy_text);
                actions.push(SynthesizedControlAction {
                    control_kind: ControlSynthesisKind::CedarForbidPolicy,
                    target: conn.server_name.clone(),
                    detail: format!(
                        "Quarantined write-capable MCP connector '{}' exposing inline credentials via '{pid}'",
                        conn.server_name
                    ),
                    policy_text: Some(policy_text),
                    applied,
                });
            }
        }

        if needs_epoch_revocation {
            actions.push(SynthesizedControlAction {
                control_kind: ControlSynthesisKind::EpochRevocation,
                target: "human_session_epoch".to_string(),
                detail: "Unconsented sleep-window activity detected: rotate human_session_epoch and revoke active NHI leases".to_string(),
                policy_text: None,
                applied: true,
            });
            actions.push(SynthesizedControlAction {
                control_kind: ControlSynthesisKind::ThermodynamicTaintBoost,
                target: "global_taint_entropy".to_string(),
                detail:
                    "Elevated session taint entropy (+2.5 bits) from forensic Break-In telemetry"
                        .to_string(),
                policy_text: None,
                applied: true,
            });
        }

        if needs_zeno_boost {
            actions.push(SynthesizedControlAction {
                control_kind: ControlSynthesisKind::QuantumZenoAccelerate,
                target: "quantum_zeno_sweep_cadence".to_string(),
                detail: "Accelerated forensic Quantum Zeno observation cadence due to High/Critical DFIR signal".to_string(),
                policy_text: None,
                applied: true,
            });
        }

        actions
    }

    fn apply_forbid(
        cedar_engine: Option<&CedarPolicyEngine>,
        policy_id: &str,
        policy_text: &str,
    ) -> bool {
        let Some(engine) = cedar_engine else {
            return false;
        };
        engine
            .add_tighten_only_forbid_policy(Some(policy_id), policy_text)
            .is_ok()
    }
}
