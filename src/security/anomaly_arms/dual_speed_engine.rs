use super::behavioral_sentinel::{BehavioralAnomalyReport, BehavioralSentinelArm};
use super::reasoning_auditor::{ReasoningAuditReport, ReasoningAuditorArm};
use super::tool_forensics::{ToolForensicsArm, ToolInvocationTrace};
use crate::core::types::{OctopusSecurityError, StrategicDirective};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct DualSpeedAuditVerdict {
    pub allow_fast_path: bool,
    pub fast_path_duration_micros: u128,
    pub async_alarm_triggered: bool,
    pub composite_anomaly_score: f64,
    pub forensic_trace: ToolInvocationTrace,
    pub behavioral_report: BehavioralAnomalyReport,
    pub reasoning_report: ReasoningAuditReport,
}

/// Dual-Speed Security Engine:
/// Merges real-time deterministic inline prevention (< 5ms) with
/// deep asynchronous investigative anomaly detection (Google 3-Layer Pattern).
pub struct DualSpeedSecurityEngine {
    pub behavioral_sentinel: BehavioralSentinelArm,
    pub reasoning_auditor: ReasoningAuditorArm,
    pub tool_forensics: ToolForensicsArm,
}

impl DualSpeedSecurityEngine {
    pub fn new() -> Self {
        Self {
            behavioral_sentinel: BehavioralSentinelArm::new("sentinel_layer1", 5.0),
            reasoning_auditor: ReasoningAuditorArm::new("auditor_layer2"),
            tool_forensics: ToolForensicsArm::new("forensics_layer3"),
        }
    }

    /// Evaluates tool invocation across both the Fast Path and Deep Forensic Path.
    pub fn evaluate_invocation(
        &mut self,
        directive: &StrategicDirective,
        caller_agent_id: &str,
        tool_name: &str,
        raw_arguments: &str,
        tokens_consumed: usize,
        payload_entropy: f64,
    ) -> Result<DualSpeedAuditVerdict, OctopusSecurityError> {
        let start = Instant::now();

        // --- Fast Path: Tool Parameter Sanitization (< 5ms) ---
        let invocation_id = format!("inv-{}", start.elapsed().as_nanos());
        let forensic_trace = self.tool_forensics.inspect_invocation(
            &invocation_id,
            caller_agent_id,
            tool_name,
            raw_arguments,
        );

        if !forensic_trace.sanitized {
            return Err(OctopusSecurityError::DeterministicLayerViolation(format!(
                "Fast-path tool sanitization failed: {:?}",
                forensic_trace.security_flags
            )));
        }

        let fast_path_micros = start.elapsed().as_micros();

        // --- Deep Path: Layer 1 Behavioral ML + Layer 2 Reasoning Audit ---
        let behavioral_report = self.behavioral_sentinel.record_event(
            caller_agent_id,
            tokens_consumed,
            payload_entropy,
        );

        let reasoning_report =
            self.reasoning_auditor
                .audit_intent_alignment(directive, tool_name, raw_arguments);

        let mut composite_score = behavioral_report.anomaly_score;
        if reasoning_report.deceptive_alignment_detected {
            composite_score += 5.0;
        }
        if reasoning_report.goal_drift_detected {
            composite_score += 3.0;
        }

        let alarm_triggered = behavioral_report.is_anomalous
            || reasoning_report.deceptive_alignment_detected
            || composite_score >= 7.0;

        Ok(DualSpeedAuditVerdict {
            allow_fast_path: true,
            fast_path_duration_micros: fast_path_micros,
            async_alarm_triggered: alarm_triggered,
            composite_anomaly_score: composite_score,
            forensic_trace,
            behavioral_report,
            reasoning_report,
        })
    }
}
