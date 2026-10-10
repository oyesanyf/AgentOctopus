use super::policy_engine::CedarEvaluationVerdict;
use crate::security::audit::SecurityAuditLog;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarAuditEntry {
    pub timestamp_epoch_secs: u64,
    pub principal_id: String,
    pub action_name: String,
    pub resource_id: String,
    pub decision: String,
    pub determining_policies: Vec<String>,
    pub diagnostic_errors: Vec<String>,
}

/// Bridges Cedar evaluation diagnostics into the tamper-evident cryptographic audit log.
pub struct CedarAuditBridge;

impl CedarAuditBridge {
    /// Records a Cedar authorization decision into the SecurityAuditLog and returns the structured entry.
    pub fn record_decision(
        audit_log: &SecurityAuditLog,
        principal_id: &str,
        action_name: &str,
        resource_id: &str,
        verdict: &CedarEvaluationVerdict,
    ) -> CedarAuditEntry {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let decision_str = if verdict.is_allowed { "ALLOW" } else { "DENY" };
        let details = format!(
            "Action: {}, Resource: {}, Determining: {:?}",
            action_name, resource_id, verdict.determining_policies
        );

        audit_log.record_event(
            "CEDAR_POLICY_EVALUATION",
            principal_id,
            &details,
            decision_str,
        );

        CedarAuditEntry {
            timestamp_epoch_secs: now_secs,
            principal_id: principal_id.to_string(),
            action_name: action_name.to_string(),
            resource_id: resource_id.to_string(),
            decision: decision_str.to_string(),
            determining_policies: verdict.determining_policies.clone(),
            diagnostic_errors: verdict.diagnostic_errors.clone(),
        }
    }
}
