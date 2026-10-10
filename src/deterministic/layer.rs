use crate::core::types::{OctopusSecurityError, StrategicDirective, VerifiedInvoiceArtifact};
use crate::deterministic::fsm::{ArmState, FsmTransitionGuard};
use crate::deterministic::policy_guard::PolicyGuard;
use crate::deterministic::schema_guard::SchemaGuard;

/// The Unified Deterministic Layer.
/// Operates as an invariant boundary between stochastic autonomous models and external environments.
#[derive(Debug, Clone)]
pub struct DeterministicLayer {
    pub fsm: FsmTransitionGuard,
    pub policy: PolicyGuard,
    pub schema: SchemaGuard,
}

impl Default for DeterministicLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl DeterministicLayer {
    pub fn new() -> Self {
        Self {
            fsm: FsmTransitionGuard::new(),
            policy: PolicyGuard::default(),
            schema: SchemaGuard::default(),
        }
    }

    pub fn state(&self) -> ArmState {
        self.fsm.state()
    }

    /// Gate 1: Directive Ingestion & Pre-Execution Policy Check
    pub fn accept_directive(&mut self, directive: &StrategicDirective) -> Result<(), OctopusSecurityError> {
        self.policy.enforce_directive(directive)?;
        self.fsm.transition_to(ArmState::DirectiveAccepted)?;
        Ok(())
    }

    /// Gate 2: Enclave Intake & Digest Initialization
    pub fn enter_enclave_digest(&mut self) -> Result<(), OctopusSecurityError> {
        self.fsm.transition_to(ArmState::EnclaveDigesting)?;
        Ok(())
    }

    /// Gate 3: Cryptographic Merkle Root Sealing
    pub fn seal_merkle_trace(&mut self, root_hex: &str) -> Result<(), OctopusSecurityError> {
        if root_hex.len() != 64 {
            return Err(OctopusSecurityError::DeterministicLayerViolation(
                "Invalid Merkle root format: must be 64 hex characters (32 bytes)".to_string(),
            ));
        }
        self.fsm.transition_to(ArmState::MerkleSealed)?;
        Ok(())
    }

    /// Gate 4: Final Schema Assertion & Spending Cap Verification
    pub fn finalize_artifact(&mut self, artifact: &VerifiedInvoiceArtifact) -> Result<(), OctopusSecurityError> {
        // Enforce schema typing
        self.schema.validate_fields(
            &artifact.invoice_id,
            &artifact.vendor_name,
            artifact.amount_cents,
        )?;

        // Enforce policy invariants
        self.policy.enforce_artifact(artifact)?;

        // Enforce final state completion
        self.fsm.transition_to(ArmState::Completed)?;
        Ok(())
    }

    /// Immediate trip to Quarantined state upon autotomy or circuit break
    pub fn quarantine(&mut self) {
        let _ = self.fsm.transition_to(ArmState::Quarantined);
    }
}
