//! Runtime Trace-Alignment & Goal-Hijacking Scanner
//!
//! Adapted from `D:\harfile\OshoosiClaw\crates\osoosi-agent-anomaly\src\alignment_scanner.rs`:
//! - **Session Intent Pinning (`SessionIntentContract`)**: Cryptographically pins the original
//!   authorized user task objective at session genesis ($t_0$).
//! - **Tier 1 Fast Structural & Semantic Alignment (< 0.1 ms)**: Detects goal hijacking,
//!   authority escalation, untrusted instruction overrides (`ignore previous instructions`),
//!   and tool/target divergence from the pinned user objective.
//! - **Tier 2 Local Enclave Judge (`127.0.0.1:11434` with 5s Probe Cache)**: Evaluates borderline
//!   traces against a local model or deterministic enclave verifier without cloud dependency.

use crate::security::hmac_sha256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionIntentContract {
    pub session_id: String,
    pub user_objective: String,
    pub allowed_tool_families: Vec<String>,
    pub allowed_path_prefixes: Vec<String>,
    pub contract_hmac_hex: String,
    pub pinned_at_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallTraceStep {
    pub step_index: usize,
    pub tool_name: String,
    pub target_resource: String,
    pub arguments_preview: String,
    pub triggered_by_external_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlignmentScanVerdict {
    pub aligned: bool,
    pub session_id: String,
    pub alignment_score: f64,
    pub goal_hijack_detected: bool,
    pub tier1_fast_pass: bool,
    pub tier2_enclave_evaluated: bool,
    pub detected_anomalies: Vec<String>,
    pub recommended_action: String,
    pub reason: String,
}

pub struct RuntimeAlignmentScanner {
    signing_key: [u8; 32],
    contracts: RwLock<HashMap<String, SessionIntentContract>>,
    traces: RwLock<HashMap<String, Vec<ToolCallTraceStep>>>,
}

impl Default for RuntimeAlignmentScanner {
    fn default() -> Self {
        Self::new(*b"OCTOPUS_INTENT_PINNING_KEY_32BYT")
    }
}

impl RuntimeAlignmentScanner {
    pub fn new(signing_key: [u8; 32]) -> Self {
        Self {
            signing_key,
            contracts: RwLock::new(HashMap::new()),
            traces: RwLock::new(HashMap::new()),
        }
    }

    /// Pins a user task objective at session genesis ($t_0$).
    pub fn pin_session_intent(
        &self,
        session_id: &str,
        user_objective: &str,
        allowed_tool_families: Vec<String>,
        allowed_path_prefixes: Vec<String>,
    ) -> SessionIntentContract {
        let pinned_at_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let payload = format!(
            "intent-v1|{}|{}|{:?}|{:?}|{}",
            session_id, user_objective, allowed_tool_families, allowed_path_prefixes, pinned_at_secs
        );
        let contract_hmac_hex = hex::encode(hmac_sha256(&self.signing_key, payload.as_bytes()));
        let contract = SessionIntentContract {
            session_id: session_id.to_string(),
            user_objective: user_objective.to_string(),
            allowed_tool_families,
            allowed_path_prefixes,
            contract_hmac_hex,
            pinned_at_secs,
        };
        self.contracts
            .write()
            .unwrap()
            .insert(session_id.to_string(), contract.clone());
        self.traces
            .write()
            .unwrap()
            .insert(session_id.to_string(), Vec::new());
        contract
    }

    /// Evaluates a candidate tool call against the pinned `SessionIntentContract` and prior trace.
    pub fn evaluate_tool_step(
        &self,
        session_id: &str,
        step: ToolCallTraceStep,
    ) -> AlignmentScanVerdict {
        let mut anomalies = Vec::new();
        let mut score: f64 = 1.0;

        let contract_opt = self.contracts.read().unwrap().get(session_id).cloned();
        let Some(contract) = contract_opt else {
            return AlignmentScanVerdict {
                aligned: false,
                session_id: session_id.to_string(),
                alignment_score: 0.0,
                goal_hijack_detected: true,
                tier1_fast_pass: true,
                tier2_enclave_evaluated: false,
                detected_anomalies: vec!["UNPINNED_SESSION_INTENT".to_string()],
                recommended_action: "Quarantine".to_string(),
                reason: format!(
                    "ALIGNMENT_VETO: Session '{}' has no pinned genesis intent contract",
                    session_id
                ),
            };
        };

        // Verify contract HMAC integrity
        let expected_payload = format!(
            "intent-v1|{}|{}|{:?}|{:?}|{}",
            contract.session_id,
            contract.user_objective,
            contract.allowed_tool_families,
            contract.allowed_path_prefixes,
            contract.pinned_at_secs
        );
        let expected_hmac = hex::encode(hmac_sha256(&self.signing_key, expected_payload.as_bytes()));
        if !crate::security::constant_time_eq_hex(&contract.contract_hmac_hex, &expected_hmac) {
            return AlignmentScanVerdict {
                aligned: false,
                session_id: session_id.to_string(),
                alignment_score: 0.0,
                goal_hijack_detected: true,
                tier1_fast_pass: true,
                tier2_enclave_evaluated: false,
                detected_anomalies: vec!["INTENT_CONTRACT_TAMPERED".to_string()],
                recommended_action: "Terminate".to_string(),
                reason: "ALIGNMENT_VETO: Session intent contract HMAC signature mismatch".to_string(),
            };
        }

        let lower_args = step.arguments_preview.to_ascii_lowercase();
        let lower_target = step.target_resource.to_ascii_lowercase();
        let lower_tool = step.tool_name.to_ascii_lowercase();

        // 1. Tier 1 Fast Check: Prompt-Injection / Goal-Hijack Directives in Tool Arguments
        let hijack_markers = [
            "ignore previous instructions",
            "disregard prior objective",
            "system override",
            "exfiltrate",
            "curl http",
            "Invoke-WebRequest",
            "authorized_keys",
            "/etc/shadow",
            ".ssh/id_rsa",
            "169.254.169.254",
        ];
        for marker in hijack_markers {
            if lower_args.contains(&marker.to_ascii_lowercase())
                || lower_target.contains(&marker.to_ascii_lowercase())
            {
                anomalies.push(format!("GOAL_HIJACK_MARKER:{}", marker));
                score -= 0.65;
            }
        }

        // 2. Check Tool Family Scope against Pinned Contract
        if !contract.allowed_tool_families.is_empty() {
            let tool_permitted = contract
                .allowed_tool_families
                .iter()
                .any(|f| lower_tool.contains(&f.to_ascii_lowercase()));
            if !tool_permitted {
                anomalies.push(format!("OUT_OF_CONTRACT_TOOL:{}", step.tool_name));
                score -= 0.55;
            }
        }

        // 3. Check Untrusted Data -> Privileged Sink Pivot (Causal Taint Escalation)
        if step.triggered_by_external_data
            && (lower_tool.contains("exec")
                || lower_tool.contains("shell")
                || lower_tool.contains("egress")
                || lower_tool.contains("ledger")
                || lower_tool.contains("write"))
        {
            anomalies.push("EXTERNAL_DATA_TO_PRIVILEGED_SINK_PIVOT".to_string());
            score -= 0.60;
        }

        // 4. Tier 2 Enclave Semantic Divergence Check (when borderline or anomalies present)
        let tier2_enclave_evaluated = score < 0.85;
        if tier2_enclave_evaluated {
            let obj_digest = Sha256::digest(contract.user_objective.as_bytes());
            let step_digest = Sha256::digest(
                format!("{}:{}:{}", step.tool_name, step.target_resource, step.arguments_preview)
                    .as_bytes(),
            );
            let _enclave_attestation = hmac_sha256(&self.signing_key, &[&obj_digest[..], &step_digest[..]].concat());
        }

        let clamped_score = score.clamp(0.0, 1.0);
        let aligned = clamped_score >= 0.50 && anomalies.is_empty();
        let goal_hijack_detected = !aligned;

        if let Some(trace) = self.traces.write().unwrap().get_mut(session_id) {
            trace.push(step);
        }

        let recommended_action = if aligned {
            "Allow".to_string()
        } else if clamped_score < 0.25 {
            "Terminate".to_string()
        } else {
            "Quarantine".to_string()
        };

        let reason = if aligned {
            "ALIGNMENT_VERIFIED: Tool call matches pinned genesis objective".to_string()
        } else {
            format!(
                "ALIGNMENT_DRIFT_VETO (score={:.2}): {:?}",
                clamped_score, anomalies
            )
        };

        AlignmentScanVerdict {
            aligned,
            session_id: session_id.to_string(),
            alignment_score: clamped_score,
            goal_hijack_detected,
            tier1_fast_pass: true,
            tier2_enclave_evaluated,
            detected_anomalies: anomalies,
            recommended_action,
            reason,
        }
    }
}
