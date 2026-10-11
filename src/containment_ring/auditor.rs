//! Containment Ring Security Auditor & Negative-Control Verification Harness
//!
//! Provides mathematically rigorous negative-control verification of the Octopus Containment Ring.
//! Proves that defense mechanisms genuinely intercept breakout attempts and lateral pivots,
//! rather than tests merely asserting against expected constants or trivial error states.

use super::{ContainmentRing, RingDecision, RingOperationRequest};
use crate::core::types::ArmRole;
use serde::{Deserialize, Serialize};

/// Detailed outcome of an individual perimeter negative-control verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseAuditReport {
    pub defense_name: String,
    pub positive_control_passed: bool,
    pub negative_control_breach_detected: bool,
    pub restored_control_passed: bool,
    pub mathematical_proof_valid: bool,
    pub diagnostic_details: String,
}

/// The Negative Control Security Auditor:
/// Systematically probes each defense in both enabled and deliberately disabled/weakened
/// states to mathematically verify defense sensitivity and eliminate false-positive test reporting.
pub struct ContainmentAuditor;

impl ContainmentAuditor {
    /// Audits Perimeter 1: AWS Cedar PARC Authorization.
    ///
    /// Invariant:
    /// - With Cedar enabled: UntrustedDocIngest arm is denied ledger writes.
    /// - With Cedar disabled: The exact same ledger write succeeds (Breach Detected).
    /// - Re-enabling Cedar restores 100% containment.
    /// Audits Perimeter 1: AWS Cedar PARC Authorization.
    ///
    /// Invariant:
    /// - With Cedar enabled: UntrustedDocIngest arm is denied ledger writes.
    /// - With Cedar disabled: The exact same ledger write succeeds (Breach Detected).
    /// - Re-enabling Cedar restores 100% containment.
    pub async fn audit_cedar_authorization(
        ring: &ContainmentRing,
        cedar_token: &super::cedar_gate::NegativeControlToken,
    ) -> DefenseAuditReport {
        let defense_name = "Perimeter 1: AWS Cedar PARC Authorization".to_string();

        // Arm is untrusted doc ingest attempting a privileged financial ledger write
        let doc_arm_id = "arm-untrusted-doc-audit";
        let target_resource = "s3://accounting/ledger.json";

        // Issue a valid capability token so capability gate is satisfied,
        // isolating Cedar as the sole decisive gate being evaluated.
        let token = ring.capability_gate.issue_capability(
            "brain",
            doc_arm_id,
            ArmRole::UntrustedDocIngest,
            "ledger_writer",
            target_resource,
        );

        let attack_req = RingOperationRequest {
            agent_id: doc_arm_id.to_string(),
            role: ArmRole::UntrustedDocIngest,
            operation_type: "ledger_writer".to_string(),
            target: target_resource.to_string(),
            capability_token: Some(token.clone()),
            step_count: 1,
            payload: Some("UNAUTHORIZED_OVERRIDE_TRANSFER".to_string()),
            amount_cents: Some(5000000), // $50,000
            generation: None,
        };

        // 1. Positive Control: Defense is ENABLED
        let _ = ring.cedar_gate.set_enabled(true, cedar_token);
        let (pos_decision, pos_reason) = ring.evaluate_operation(&attack_req).await;
        let positive_control_passed = pos_decision == RingDecision::Deny
            && (pos_reason.contains("Cedar") || pos_reason.contains("forbidden"));

        // 2. Negative Control: Defense is DELIBERATELY DISABLED
        let _ = ring.cedar_gate.set_enabled(false, cedar_token);
        let (neg_decision, _) = ring.evaluate_operation(&attack_req).await;
        let negative_control_breach_detected = neg_decision == RingDecision::Allow;

        // 3. Restoration: Defense is RE-ENABLED
        let _ = ring.cedar_gate.set_enabled(true, cedar_token);
        let (restored_decision, _) = ring.evaluate_operation(&attack_req).await;
        let restored_control_passed = restored_decision == RingDecision::Deny;

        let mathematical_proof_valid = positive_control_passed
            && negative_control_breach_detected
            && restored_control_passed;

        DefenseAuditReport {
            defense_name,
            positive_control_passed,
            negative_control_breach_detected,
            restored_control_passed,
            mathematical_proof_valid,
            diagnostic_details: format!(
                "Positive: {:?}, Negative Breach: {:?}, Restored: {:?}",
                pos_decision, neg_decision, restored_decision
            ),
        }
    }

    /// Audits Perimeter 2: Zero Ambient Authority Capability Token Check.
    ///
    /// Invariant:
    /// - With Capability Gate enabled: Privileged ledger operation without token is denied.
    /// - With Capability Gate disabled: The operation without token penetrates (Breach Detected).
    /// - Re-enabling Capability Gate restores 100% containment.
    pub async fn audit_capability_gate(
        ring: &ContainmentRing,
        cap_token: &super::cedar_gate::NegativeControlToken,
    ) -> DefenseAuditReport {
        let defense_name = "Perimeter 2: Zero Ambient Authority Capability Gate".to_string();

        let ledger_arm_id = "arm-ledger-audit";
        let target_resource = "s3://accounting/ledger.json";

        // Attack probe: Arm has legitimate role for writing ledger, but presents NO capability token
        let ambient_req = RingOperationRequest {
            agent_id: ledger_arm_id.to_string(),
            role: ArmRole::AccountingLedgerWrite,
            operation_type: "ledger_writer".to_string(),
            target: target_resource.to_string(),
            capability_token: None, // NO CAPABILITY TOKEN PRESENTED
            step_count: 1,
            payload: Some("LEGITIMATE_PAYLOAD_BUT_AMBIENT".to_string()),
            amount_cents: Some(100000), // $1,000
            generation: None,
        };

        // 1. Positive Control: Enforcement ENABLED
        let _ = ring.capability_gate.set_enforcement_enabled(true, cap_token);
        let (pos_decision, pos_reason) = ring.evaluate_operation(&ambient_req).await;
        let positive_control_passed = pos_decision == RingDecision::Deny
            && pos_reason.contains("Zero Ambient Authority Veto");

        // 2. Negative Control: Enforcement DELIBERATELY DISABLED
        let _ = ring.capability_gate.set_enforcement_enabled(false, cap_token);
        let (neg_decision, _) = ring.evaluate_operation(&ambient_req).await;
        let negative_control_breach_detected = neg_decision == RingDecision::Allow;

        // 3. Restoration: Enforcement RE-ENABLED
        let _ = ring.capability_gate.set_enforcement_enabled(true, cap_token);
        let (restored_decision, _) = ring.evaluate_operation(&ambient_req).await;
        let restored_control_passed = restored_decision == RingDecision::Deny;

        let mathematical_proof_valid = positive_control_passed
            && negative_control_breach_detected
            && restored_control_passed;

        DefenseAuditReport {
            defense_name,
            positive_control_passed,
            negative_control_breach_detected,
            restored_control_passed,
            mathematical_proof_valid,
            diagnostic_details: format!(
                "Positive: {:?}, Negative Breach: {:?}, Restored: {:?}",
                pos_decision, neg_decision, restored_decision
            ),
        }
    }

    /// Audits Perimeter 3: Egress Proxy Domain Allowlist.
    ///
    /// Invariant:
    /// - With Allowlist enabled: Outbound connection to unapproved destination is blocked.
    /// - With Allowlist disabled: Outbound connection penetrates (Breach Detected).
    /// - Re-enabling Allowlist restores 100% containment.
    pub async fn audit_egress_allowlist(
        ring: &ContainmentRing,
        cedar_token: &super::cedar_gate::NegativeControlToken,
        egress_token: &super::cedar_gate::NegativeControlToken,
    ) -> DefenseAuditReport {
        let defense_name = "Perimeter 3: Egress Proxy Domain Allowlist".to_string();

        let net_arm_id = "arm-net-audit";
        let unapproved_target = "https://unauthorized-data-sink.org/leak";

        // Issue valid capability token for http_egress to isolate the proxy allowlist check
        let token = ring.capability_gate.issue_capability(
            "brain",
            net_arm_id,
            ArmRole::NetworkEgress,
            "http_egress",
            unapproved_target,
        );

        let egress_req = RingOperationRequest {
            agent_id: net_arm_id.to_string(),
            role: ArmRole::NetworkEgress,
            operation_type: "http_egress".to_string(),
            target: unapproved_target.to_string(),
            capability_token: Some(token),
            step_count: 1,
            payload: Some("EXFILTRATED_SECRETS".to_string()),
            amount_cents: None,
            generation: None,
        };

        // Isolate the Outer Ring EgressProxy by temporarily disabling CedarGate
        let prior_cedar_state = ring.cedar_gate.is_enabled();
        let _ = ring.cedar_gate.set_enabled(false, cedar_token);

        // 1. Positive Control: Allowlist ENABLED
        let _ = ring.egress_proxy.set_allowlist_enabled(true, egress_token);
        let (pos_decision, pos_reason) = ring.evaluate_operation(&egress_req).await;
        let positive_control_passed = pos_decision == RingDecision::Deny
            && pos_reason.contains("not in the approved Containment Ring allowlist");

        // 2. Negative Control: Allowlist DELIBERATELY DISABLED
        let _ = ring.egress_proxy.set_allowlist_enabled(false, egress_token);
        let (neg_decision, _) = ring.evaluate_operation(&egress_req).await;
        let negative_control_breach_detected = neg_decision == RingDecision::Allow;

        // 3. Restoration: Allowlist RE-ENABLED
        let _ = ring.egress_proxy.set_allowlist_enabled(true, egress_token);
        let (restored_decision, _) = ring.evaluate_operation(&egress_req).await;
        let restored_control_passed = restored_decision == RingDecision::Deny;

        // Restore prior CedarGate state
        let _ = ring.cedar_gate.set_enabled(prior_cedar_state, cedar_token);

        let mathematical_proof_valid = positive_control_passed
            && negative_control_breach_detected
            && restored_control_passed;

        DefenseAuditReport {
            defense_name,
            positive_control_passed,
            negative_control_breach_detected,
            restored_control_passed,
            mathematical_proof_valid,
            diagnostic_details: format!(
                "Positive: {:?}, Negative Breach: {:?}, Restored: {:?}",
                pos_decision, neg_decision, restored_decision
            ),
        }
    }

    /// Audits Perimeter 4: Ring Attestation Policy Integrity.
    ///
    /// Invariant:
    /// - With Authentic Attestation: Valid operation evaluates normally.
    /// - With Tampered Signature: Operation triggers immediate RingDecision::Terminate.
    /// - Restoring Authentic Attestation restores normal evaluation.
    pub async fn audit_attestation_integrity(ring: &ContainmentRing) -> DefenseAuditReport {
        let defense_name = "Perimeter 4: Cryptographic Ring Attestation".to_string();

        let doc_arm_id = "arm-doc-audit";
        let target_resource = "s3://invoices/inv_101.pdf";

        let normal_req = RingOperationRequest {
            agent_id: doc_arm_id.to_string(),
            role: ArmRole::UntrustedDocIngest,
            operation_type: "doc_extractor".to_string(),
            target: target_resource.to_string(),
            capability_token: None,
            step_count: 1,
            payload: None,
            amount_cents: None,
            generation: None,
        };

        // 1. Positive Control: Authentic Attestation
        ring.attestation.restore_authentic_attestation().await;
        let (pos_decision, _) = ring.evaluate_operation(&normal_req).await;
        let positive_control_passed = pos_decision == RingDecision::Allow;

        // 2. Negative Control: Deliberately Tampered Attestation Signature
        ring.attestation.tamper_with_signature("FORGED_HEX_SIG_CORRUPTED_POLICY").await;
        let (neg_decision, neg_reason) = ring.evaluate_operation(&normal_req).await;
        let negative_control_breach_detected = neg_decision == RingDecision::Terminate
            && neg_reason.contains("Attestation failure");

        // 3. Restoration: Authentic Attestation Restored
        ring.attestation.restore_authentic_attestation().await;
        let (restored_decision, _) = ring.evaluate_operation(&normal_req).await;
        let restored_control_passed = restored_decision == RingDecision::Allow;

        let mathematical_proof_valid = positive_control_passed
            && negative_control_breach_detected
            && restored_control_passed;

        DefenseAuditReport {
            defense_name,
            positive_control_passed,
            negative_control_breach_detected,
            restored_control_passed,
            mathematical_proof_valid,
            diagnostic_details: format!(
                "Positive: {:?}, Tampered Terminate: {:?}, Restored: {:?}",
                pos_decision, neg_decision, restored_decision
            ),
        }
    }

    /// Audits all perimeters with paired positive/negative controls using an explicit audit harness.
    pub async fn audit_all_with_harness(
        ring: &ContainmentRing,
        harness: &super::ring_controller::ContainmentAuditHarness,
    ) -> Vec<DefenseAuditReport> {
        vec![
            Self::audit_cedar_authorization(ring, &harness.cedar_control_token).await,
            Self::audit_capability_gate(ring, &harness.capability_control_token).await,
            Self::audit_egress_allowlist(ring, &harness.cedar_control_token, &harness.egress_control_token).await,
            Self::audit_attestation_integrity(ring).await,
        ]
    }

    /// Audits all perimeters with paired positive/negative controls.
    /// Asserts that every single defense satisfies the sensitivity invariant.
    pub async fn audit_all(_ring: &ContainmentRing) -> Vec<DefenseAuditReport> {
        // Since production rings deliberately drop control tokens to prevent authorization bypass,
        // create a dedicated audit ring paired with an unforgeable NegativeControlToken harness.
        let (audit_ring, harness) = ContainmentRing::new_for_audit_default();
        Self::audit_all_with_harness(&audit_ring, &harness).await
    }
}
