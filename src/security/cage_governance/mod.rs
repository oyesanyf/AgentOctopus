// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Reference: Google Cybernetic Agent Governance Engine (CAGE), arXiv:2606.12320
// Adapted from LalaSkye/no-direct-bind under Apache-2.0

//! Native Rust Google Cybernetic Agent Governance Engine (CAGE) Core Module
//!
//! Provides production-ready implementations of:
//! - Multi-format Substrate Policy Translator (ACS, AAIF, OSCAL 1.1.x, Lula, CAGE STPA)
//! - Forward-Looking Trajectory Reachability Analyzer (FTRA) & Tier 1 STPA Validator
//! - Discrete-Time Exponential Control Barrier Functions (CBF) & Fiscal Debit Ledger
//! - Evidence-Bound HMAC-SHA256 Cryptographic Routing Seals (30s TTL, single-use)
//! - 7-Tier Two-Phase Dynamic Governance Pipeline
//! - 34-State BFS Formal Model & 7-Rule Trace Conformance Verifier
//! - Unified `CageGovernanceEngine` public runtime facade

pub mod substrate_translator;
pub mod ftra_stpa;
pub mod cbf_fiscal;
pub mod routing_seal;
pub mod pipeline;
pub mod no_direct_bind_proof;

pub use substrate_translator::*;
pub use ftra_stpa::*;
pub use cbf_fiscal::*;
pub use routing_seal::*;
pub use pipeline::*;
pub use no_direct_bind_proof::*;

use crate::containment_ring::tiered_executor::TieredExecutionReceipt;
use crate::security::audit::SecurityAuditLog;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

/// Standardized API error enumeration for CAGE Substrate endpoints.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum CageApiError {
    #[error("Policy version mismatch: expected '{expected}', active is '{actual}'")]
    PolicyVersionMismatch { expected: String, actual: String },

    #[error("Invalid policy format or syntax error: {reason}")]
    InvalidPolicyFormat { reason: String },

    #[error("Routing seal has already been consumed: {seal_id}")]
    SealAlreadyConsumed { seal_id: String },

    #[error("Routing seal has expired: current={current_time}, expires_at={expires_at}")]
    SealExpired { current_time: u64, expires_at: u64 },

    #[error("Routing seal signature is invalid")]
    SealInvalidSignature,

    #[error("Action digest mismatch: expected '{expected}', got '{actual}'")]
    ActionDigestMismatch { expected: String, actual: String },

    #[error("Control Barrier Function boundary breach: {details}")]
    CbfBarrierBreach { details: String },

    #[error("Audit evidence unanchored: {reason}")]
    EvidenceUnanchored { reason: String },

    #[error("Invalid request payload: {message}")]
    InvalidRequestPayload { message: String },
}

impl CageApiError {
    /// Returns canonical HTTP status code string.
    pub fn http_status_code(&self) -> &'static str {
        match self {
            Self::PolicyVersionMismatch { .. } => "409 Conflict",
            Self::SealAlreadyConsumed { .. } => "409 Conflict",
            Self::InvalidPolicyFormat { .. } => "400 Bad Request",
            Self::InvalidRequestPayload { .. } => "400 Bad Request",
            Self::SealExpired { .. } => "403 Forbidden",
            Self::SealInvalidSignature => "403 Forbidden",
            Self::ActionDigestMismatch { .. } => "403 Forbidden",
            Self::CbfBarrierBreach { .. } => "403 Forbidden",
            Self::EvidenceUnanchored { .. } => "500 Internal Server Error",
        }
    }

    /// Returns uppercase machine-readable error code.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::PolicyVersionMismatch { .. } => "POLICY_VERSION_MISMATCH",
            Self::SealAlreadyConsumed { .. } => "SEAL_ALREADY_CONSUMED",
            Self::InvalidPolicyFormat { .. } => "INVALID_POLICY_FORMAT",
            Self::InvalidRequestPayload { .. } => "INVALID_REQUEST_PAYLOAD",
            Self::SealExpired { .. } => "SEAL_EXPIRED",
            Self::SealInvalidSignature => "SEAL_SIGNATURE_INVALID",
            Self::ActionDigestMismatch { .. } => "ACTION_DIGEST_MISMATCH",
            Self::CbfBarrierBreach { .. } => "CBF_BARRIER_BREACH",
            Self::EvidenceUnanchored { .. } => "EVIDENCE_CHAIN_UNANCHORED",
        }
    }
}

/// Response payload for policy ingestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestPolicyResponse {
    pub format: PolicyFormat,
    pub policy_version_id: String,
    pub cedar_rules_count: usize,
    pub stpa_ucas_count: usize,
    pub active_hash: String,
}

/// Response payload for seal consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumeSealResponse {
    pub status: String,
    pub seal_id: String,
    pub consumed_at: u64,
}

/// Response payload for BFS proof status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStatusResponse {
    pub model: String,
    pub reachable_states: usize,
    pub no_direct_bind_proven: bool,
    pub counterexample_detected: bool,
    pub ungated_states: usize,
    pub ungated_counterexample_proven: bool,
    pub proof_hash: String,
}

/// Unified CAGE Governance Engine managing policy, fiscal ledger, routing seals, and audit integration.
pub struct CageGovernanceEngine {
    policy: Arc<RwLock<CompiledCagePolicy>>,
    ledger: Arc<DebitLedger>,
    seal_signer: Arc<RoutingSealSigner>,
    pipeline: Arc<CagePipeline>,
    audit_log: Arc<SecurityAuditLog>,
}

impl CageGovernanceEngine {
    /// Constructs a new CAGE governance engine with explicit initial policy, ledger parameters, secret key, and audit log.
    pub fn new(
        initial_policy: CompiledCagePolicy,
        initial_budget: f64,
        gamma: f64,
        b_min: f64,
        secret_key: &[u8],
        audit_log: Arc<SecurityAuditLog>,
    ) -> Result<Self, CbfViolation> {
        let policy_ver = initial_policy.policy_version_id.clone();
        let policy = Arc::new(RwLock::new(initial_policy.clone()));
        let ledger = Arc::new(DebitLedger::new(initial_budget, gamma, b_min)?);
        let seal_signer = Arc::new(RoutingSealSigner::new(secret_key, &policy_ver));
        let pipeline = Arc::new(CagePipeline::new(
            initial_policy,
            Arc::clone(&ledger),
            secret_key,
            Arc::clone(&audit_log),
        ));

        Ok(Self {
            policy,
            ledger,
            seal_signer,
            pipeline,
            audit_log,
        })
    }

    /// Creates a default engine instance with root CAGE policy, 1000.0 budget, gamma=0.1, b_min=10.0.
    pub fn with_default_policy(audit_log: Arc<SecurityAuditLog>, secret_key: &[u8]) -> Self {
        let root_policy = SubstrateTranslator::compile_policy(
            r#"{"stpa_control_structure": {"unsafe_control_actions": []}}"#,
            None,
        )
        .expect("Root default policy compilation must succeed");

        Self::new(root_policy, 1000.0, 0.1, 10.0, secret_key, audit_log)
            .expect("Default engine initialization must succeed")
    }

    /// Ingests and compiles a new policy specification, validating against optional expected version.
    pub fn ingest_policy(
        &self,
        raw_policy: &str,
        expected_version: Option<&str>,
    ) -> Result<IngestPolicyResponse, CageApiError> {
        let compiled = SubstrateTranslator::compile_policy(raw_policy, None)
            .map_err(|e| CageApiError::InvalidPolicyFormat { reason: e.to_string() })?;

        // Version pinning check
        let active_ver = self.active_policy_version();
        if let Some(expected) = expected_version {
            if expected != active_ver {
                return Err(CageApiError::PolicyVersionMismatch {
                    expected: expected.to_string(),
                    actual: active_ver,
                });
            }
        }

        let resp = IngestPolicyResponse {
            format: compiled.format,
            policy_version_id: compiled.policy_version_id.clone(),
            cedar_rules_count: compiled.cedar_rules.len(),
            stpa_ucas_count: compiled.unsafe_control_actions.len(),
            active_hash: compiled.policy_version_id.clone(),
        };

        // Update active policy and pipeline
        self.pipeline.update_policy(compiled.clone());
        self.seal_signer.set_policy_version(&compiled.policy_version_id);
        *self.policy.write().unwrap() = compiled;

        Ok(resp)
    }

    /// Returns active pinned policy version ID.
    pub fn active_policy_version(&self) -> String {
        self.policy.read().unwrap().policy_version_id.clone()
    }

    /// Evaluates an action through the 7-tier two-phase dynamic pipeline.
    pub fn validate_action(
        &self,
        req: &GovernanceRequest,
    ) -> Result<GovernanceEvaluationResult, CageApiError> {
        // Enforce version pinning if specified
        if let Some(ref expected) = req.expected_policy_version {
            let active = self.active_policy_version();
            if expected != &active {
                return Err(CageApiError::PolicyVersionMismatch {
                    expected: expected.clone(),
                    actual: active,
                });
            }
        }

        let result = self.pipeline.run_pipeline(req);
        Ok(result)
    }

    /// Computes action digest for an action and parameter set.
    pub fn compute_action_digest(&self, action_name: &str, params: &serde_json::Value) -> String {
        compute_action_digest(action_name, params)
    }

    /// Verifies and atomically consumes a routing seal in the actuator gate.
    pub fn verify_and_consume_seal(
        &self,
        seal: &CageRoutingSeal,
        _expected_action: &str,
        expected_digest: &str,
    ) -> Result<(), SealRejection> {
        // Look up latest audit record hash from log or verify against seal's record_hash
        self.seal_signer
            .validate_and_consume_now(seal, expected_digest, &seal.record_hash)
    }

    /// Consumes a seal directly from serialized JSON (used by REST API).
    pub fn verify_and_consume_seal_direct(
        &self,
        seal_json: &str,
    ) -> Result<ConsumeSealResponse, CageApiError> {
        let seal: CageRoutingSeal = serde_json::from_str(seal_json)
            .map_err(|e| CageApiError::InvalidRequestPayload { message: e.to_string() })?;

        self.verify_and_consume_seal(&seal, "", &seal.action_digest)
            .map_err(|e| match e {
                SealRejection::AlreadyConsumed(id) => CageApiError::SealAlreadyConsumed { seal_id: id },
                SealRejection::Expired { current_time, expires_at } => {
                    CageApiError::SealExpired { current_time, expires_at }
                }
                SealRejection::InvalidSignature => CageApiError::SealInvalidSignature,
                SealRejection::ActionDigestMismatch { expected, actual } => {
                    CageApiError::ActionDigestMismatch { expected, actual }
                }
                SealRejection::PolicyVersionMismatch { expected, actual } => {
                    CageApiError::PolicyVersionMismatch { expected, actual }
                }
                other => CageApiError::InvalidRequestPayload { message: other.to_string() },
            })?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(ConsumeSealResponse {
            status: "CONSUMED".to_string(),
            seal_id: seal.seal_id,
            consumed_at: now,
        })
    }

    /// Confirms and settles a fiscal debit reservation once actuation finishes.
    pub fn confirm_fiscal_reservation(&self, debit_id: &str) -> Result<(), CbfViolation> {
        self.ledger.confirm(debit_id)
    }

    /// Records an execution trace receipt into the immutable audit ledger.
    pub fn record_actuation_trace(
        &self,
        seal_ref: &str,
        action: &str,
        receipt: &TieredExecutionReceipt,
    ) -> Result<String, String> {
        let details = serde_json::json!({
            "event_type": "ACTUATION_RECEIPT",
            "seal_id": seal_ref,
            "action": action,
            "agent_id": receipt.agent_id,
            "tool_name": receipt.tool_name,
            "selected_tier": format!("{:?}", receipt.selected_tier),
            "exit_code": receipt.exit_code,
            "total_elapsed_us": receipt.total_elapsed_us,
        })
        .to_string();

        let record_hash = self.audit_log.record_event(
            "ACTUATION_RECEIPT",
            &receipt.agent_id,
            &details,
            if receipt.exit_code == 0 { "SUCCESS" } else { "FAILURE" },
        );

        Ok(record_hash)
    }

    /// Evaluates BFS formal model and counterexample, returning proof status.
    pub fn proof_status(&self) -> ProofStatusResponse {
        let gated_proof = FormalBfsModel::prove_no_direct_bind();
        let ungated_result = FormalBfsModel::explore_ungated_counterexample();

        ProofStatusResponse {
            model: "CAGE 7-Tier Two-Phase BFS State Machine".to_string(),
            reachable_states: gated_proof.reachable_states,
            no_direct_bind_proven: gated_proof.proven,
            counterexample_detected: !ungated_result.violations.is_empty(),
            ungated_states: ungated_result.reachable_count,
            ungated_counterexample_proven: !ungated_result.violations.is_empty(),
            proof_hash: gated_proof.proof_receipt,
        }
    }

    /// Verifies trace conformance against all 7 rules.
    pub fn verify_trace_conformance(
        &self,
        traces: &[serde_json::Value],
    ) -> Result<StreamVerificationReport, CageApiError> {
        Ok(FormalBfsModel::check_trace_conformance(traces))
    }

    /// Returns a reference to the debit ledger.
    pub fn ledger(&self) -> &Arc<DebitLedger> {
        &self.ledger
    }

    /// Returns a reference to the routing seal signer.
    pub fn seal_signer(&self) -> &Arc<RoutingSealSigner> {
        &self.seal_signer
    }

    /// Returns a reference to the security audit log.
    pub fn audit_log(&self) -> &Arc<SecurityAuditLog> {
        &self.audit_log
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cage_governance_engine_end_to_end() {
        let audit_log = Arc::new(SecurityAuditLog::new());
        let secret = b"cage_governance_engine_test_key_32";
        let engine = CageGovernanceEngine::with_default_policy(audit_log, secret);

        assert_eq!(engine.active_policy_version().len(), 16);

        let req = GovernanceRequest {
            action_name: "list_files".to_string(),
            principal: "arm-worker-1".to_string(),
            resource: "workspace/tmp".to_string(),
            parameters: serde_json::json!({}),
            caller_authority: 3,
            confidence_score: 0.98,
            consensus_score: 0.85,
            fuel_cost: 2.0,
            expected_policy_version: None,
            execution_profile: Some(Profile::Full),
        };

        let result = engine.validate_action(&req).unwrap();
        assert_eq!(result.verdict, GovernanceVerdict::Allow);
        assert!(result.seal.is_some());

        let seal = result.seal.unwrap();
        let digest = engine.compute_action_digest(&req.action_name, &req.parameters);

        // Verify and consume seal
        assert!(engine.verify_and_consume_seal(&seal, &req.action_name, &digest).is_ok());

        // Replay rejection
        let replay_err = engine.verify_and_consume_seal(&seal, &req.action_name, &digest).unwrap_err();
        assert!(matches!(replay_err, SealRejection::AlreadyConsumed(_)));

        // Proof status
        let proof = engine.proof_status();
        assert_eq!(proof.reachable_states, 34);
        assert!(proof.no_direct_bind_proven);
        assert!(proof.counterexample_detected);
        assert_eq!(proof.ungated_states, 17);
    }
}
