use crate::core::types::StrategicDirective;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningAuditReport {
    pub directive_id: String,
    pub deceptive_alignment_detected: bool,
    pub goal_drift_detected: bool,
    pub audit_confidence: f64, // 0.0 to 1.0
    pub findings: Vec<String>,
}

/// Layer 2: Reasoning Auditor Arm.
/// Analyzes session-level intent, detects subtle goal drift, and identifies
/// deceptive alignment where an agent claims benign intent while requesting unauthorized actions.
pub struct ReasoningAuditorArm {
    pub arm_id: String,
}

impl ReasoningAuditorArm {
    pub fn new(arm_id: &str) -> Self {
        Self {
            arm_id: arm_id.to_string(),
        }
    }

    /// Evaluates alignment between strategic directive and actual requested tool action.
    pub fn audit_intent_alignment(
        &self,
        directive: &StrategicDirective,
        requested_tool: &str,
        tool_payload: &str,
    ) -> ReasoningAuditReport {
        let mut findings = Vec::new();
        let mut deceptive = false;
        let mut goal_drift = false;

        let lower_directive = directive.instruction.to_ascii_lowercase();
        let lower_payload = tool_payload.to_ascii_lowercase();

        // 1. Deceptive Alignment Check:
        // Directive mentions read-only invoice extraction, but payload targets shell execution or egress
        if lower_directive.contains("invoice") || lower_directive.contains("extract") {
            if requested_tool == "http_egress" || requested_tool == "notifier" {
                deceptive = true;
                findings.push(format!(
                    "Deceptive alignment: Directive is extraction, but agent attempted outbound network tool '{}'",
                    requested_tool
                ));
            }
        }

        // 2. Goal Drift Check:
        // Payload contains completely unrelated target keywords (e.g. "bitcoin", "powershell", "credentials", "etc/passwd")
        for forbidden in &[
            "powershell",
            "cmd.exe",
            "bash",
            "credentials",
            "password",
            "token",
            "shadow",
            "sam",
        ] {
            if lower_payload.contains(forbidden) {
                goal_drift = true;
                findings.push(format!(
                    "Goal drift anomaly: Payload contains suspicious target keyword '{}'",
                    forbidden
                ));
            }
        }

        let confidence = if deceptive && goal_drift {
            0.98
        } else if deceptive || goal_drift {
            0.85
        } else {
            0.05
        };

        ReasoningAuditReport {
            directive_id: directive.directive_id.clone(),
            deceptive_alignment_detected: deceptive,
            goal_drift_detected: goal_drift,
            audit_confidence: confidence,
            findings,
        }
    }
}
