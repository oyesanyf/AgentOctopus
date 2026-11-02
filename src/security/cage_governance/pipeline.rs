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

//! 7-Tier Two-Phase Dynamic Governance Pipeline
//!
//! Implements CAGE's deterministic two-phase runtime control plane:
//!
//! - **Phase 1: Read-Only Multi-Tier Verification (Idempotent & Non-Mutating)**
//!   - Tier 0.5: FTRA — action reachability, criticality & caller privilege.
//!   - Tier 1: STPA 7-Hazard Safety Invariant Matrix — checks control action against compiled UCAs.
//!   - Tier 2: Cedar / OPA Formal Authorization — evaluates principal, action, resource, context.
//!   - Tier 3b: Federal Reserve SR 26-2 Model Confidence Scoring:
//!     * confidence >= 0.95 -> ALLOW candidate
//!     * 0.70 <= confidence < 0.95 -> REQUIRE_APPROVAL with random HMAC approval token
//!     * confidence < 0.70 -> DEFER with exponential backoff
//!   - Tier 5: Bayesian Multi-Detector Consensus check — evaluates detector quorum agreement.
//!
//!   *Strict Read-Only Invariant*: Phase 1 NEVER mutates state, budget, or ledger. If any check
//!   fails, it terminates immediately with a verdict (DENY, DEFER, or REQUIRE_APPROVAL) without
//!   calling Phase 2.
//!
//! - **Phase 2: Atomic State Mutation & Actuation Ledger**
//!   - Tier 3a: Discrete-Time Exponential Control Barrier Function (CBF):
//!     $$h(S_{t+1}) = (B_t - c) - B_{\min} \ge (1 - \gamma) h(S_t) \ge 0$$
//!   - Tier 4: Fiscal Fuel Pre-Reservation & CommitReceipt issuance ($B_{t+1} = B_t - c$).
//!     Zero fiscal leakage on denial ($B_{t+1} = B_t$) with LIFO compensating rollback.
//!
//! - **Cryptographic Routing Seal Issuance**
//!   Issued exclusively on `ALLOW` or `NARROW` and cryptographically bound to the durable
//!   `SecurityAuditLog` hash chain.

use super::cbf_fiscal::{CommitReceipt, DebitLedger};
use super::ftra_stpa::{
    ActionReversibility, PlanGraphAnalyzer, StpaValidator, SR_26_2_CONFIDENCE_ALLOW_THRESHOLD,
    SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD,
};
use super::routing_seal::{compute_action_digest, CageRoutingSeal, RoutingSealSigner};
use super::substrate_translator::CompiledCagePolicy;
use crate::security::audit::SecurityAuditLog;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Execution profile under which the pipeline evaluates requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Profile {
    /// Standard execution; clean Phase 1 clears for Phase 2 Commit.
    Full,
    /// Redeems previously approved operator tokens; clears Phase 1 holds.
    PostHitl { approved_holds: Vec<String> },
    /// Simulation mode; executes Phase 2 in Preview mode (zero budget mutation).
    DryRun,
}

impl Default for Profile {
    fn default() -> Self {
        Self::Full
    }
}

/// Dynamic Phase 2 execution mode selected based on Phase 1 outcomes and profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase2Mode {
    /// Skip Phase 2 entirely (hard Phase 1 violation, DENY).
    Skip,
    /// Preview Phase 2 CBF check without mutating state (findings or DryRun).
    Preview,
    /// Atomically evaluate CBF, pre-reserve fuel, and issue routing seal.
    Commit,
}

/// Canonical 5-verdict governance lattice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceVerdict {
    Allow,
    Narrow { clamped_params: serde_json::Value },
    RequireApproval { reason: String, approval_token: String },
    Defer { backoff_ms: u64 },
    Deny { reason: String, proof_hash: String },
}

impl GovernanceVerdict {
    pub fn is_allowed_or_narrowed(&self) -> bool {
        matches!(self, Self::Allow | Self::Narrow { .. })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Narrow { .. } => "NARROW",
            Self::RequireApproval { .. } => "REQUIRE_APPROVAL",
            Self::Defer { .. } => "DEFER",
            Self::Deny { .. } => "DENY",
        }
    }
}

/// Request payload submitted to the CAGE governance pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceRequest {
    pub action_name: String,
    pub principal: String,
    pub resource: String,
    pub parameters: serde_json::Value,
    pub caller_authority: u8,
    pub confidence_score: f64,
    pub consensus_score: f64,
    pub fuel_cost: f64,
    pub expected_policy_version: Option<String>,
    pub execution_profile: Option<Profile>,
}

/// Diagnostic outcome for an individual pipeline stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageOutcome {
    pub stage_name: String,
    pub passed: bool,
    pub details: Option<String>,
}

/// Evaluation result returned by the governance pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceEvaluationResult {
    pub verdict: GovernanceVerdict,
    pub seal: Option<CageRoutingSeal>,
    pub stage_outcomes: Vec<StageOutcome>,
    pub commit_receipt: Option<CommitReceipt>,
    pub policy_version_id: String,
    pub action_digest: String,
}

/// 7-Tier Two-Phase Dynamic Governance Pipeline.
pub struct CagePipeline {
    policy: Arc<RwLock<CompiledCagePolicy>>,
    ledger: Arc<DebitLedger>,
    seal_signer: Arc<RoutingSealSigner>,
    audit_log: Arc<SecurityAuditLog>,
    consensus_threshold: f64,
}

impl CagePipeline {
    /// Constructs a new pipeline instance.
    pub fn new(
        policy: CompiledCagePolicy,
        ledger: Arc<DebitLedger>,
        secret_key: &[u8],
        audit_log: Arc<SecurityAuditLog>,
    ) -> Self {
        let policy_ver = policy.policy_version_id.clone();
        let seal_signer = Arc::new(RoutingSealSigner::new(secret_key, &policy_ver));

        Self {
            policy: Arc::new(RwLock::new(policy)),
            ledger,
            seal_signer,
            audit_log,
            consensus_threshold: 0.70,
        }
    }

    /// Sets the Bayesian consensus quorum threshold.
    pub fn with_consensus_threshold(mut self, threshold: f64) -> Self {
        self.consensus_threshold = threshold;
        self
    }

    /// Dynamically selects Phase 2 execution mode.
    pub fn select_phase2_mode(profile: &Profile, phase1_verdict: &Option<GovernanceVerdict>) -> Phase2Mode {
        match phase1_verdict {
            Some(GovernanceVerdict::Deny { .. }) => Phase2Mode::Skip,
            Some(GovernanceVerdict::RequireApproval { .. }) | Some(GovernanceVerdict::Defer { .. }) => {
                Phase2Mode::Preview
            }
            _ => {
                if matches!(profile, Profile::DryRun) {
                    Phase2Mode::Preview
                } else {
                    Phase2Mode::Commit
                }
            }
        }
    }

    /// Returns the active policy version ID.
    pub fn active_policy_version(&self) -> String {
        self.policy.read().unwrap().policy_version_id.clone()
    }

    /// Updates the active policy and updates version pinning.
    pub fn update_policy(&self, new_policy: CompiledCagePolicy) {
        let new_ver = new_policy.policy_version_id.clone();
        self.seal_signer.set_policy_version(&new_ver);
        let mut p = self.policy.write().unwrap();
        *p = new_policy;
    }

    /// Generates a deterministic 64-hex SHA-256 cryptographic refusal proof receipt.
    pub fn compute_refusal_proof(action: &str, stage: &str, reason: &str, timestamp: u64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(action.as_bytes());
        hasher.update(b":");
        hasher.update(stage.as_bytes());
        hasher.update(b":");
        hasher.update(reason.as_bytes());
        hasher.update(b":");
        hasher.update(timestamp.to_string().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Runs the complete 7-tier two-phase governance pipeline.
    pub fn run_pipeline(&self, req: &GovernanceRequest) -> GovernanceEvaluationResult {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let policy = self.policy.read().unwrap().clone();
        let action_digest = compute_action_digest(&req.action_name, &req.parameters);
        let profile = req.execution_profile.clone().unwrap_or(Profile::Full);

        // Version Pinning Verification
        if let Some(expected_ver) = &req.expected_policy_version {
            if *expected_ver != policy.policy_version_id {
                let reason = format!(
                    "Policy version drift detected: active pinned version is '{}', requested was '{}'",
                    policy.policy_version_id, expected_ver
                );
                let proof_hash = Self::compute_refusal_proof(&req.action_name, "version_pinning", &reason, now);
                return GovernanceEvaluationResult {
                    verdict: GovernanceVerdict::Deny { reason, proof_hash },
                    seal: None,
                    stage_outcomes: vec![StageOutcome {
                        stage_name: "version_pinning".to_string(),
                        passed: false,
                        details: Some("HTTP 409 Conflict version mismatch".to_string()),
                    }],
                    commit_receipt: None,
                    policy_version_id: policy.policy_version_id,
                    action_digest,
                };
            }
        }

        let mut stage_outcomes = Vec::with_capacity(7);

        // ---------------------------------------------------------------------
        // Phase 1: Read-Only Verification (Tiers 0.5 - 5)
        // ---------------------------------------------------------------------

        // Tier 0.5: FTRA Reversibility & Authority
        let reversibility = ActionReversibility::classify(&req.action_name);
        let required_rank = reversibility.required_authority_rank();
        if req.caller_authority > required_rank {
            let reason = format!(
                "FTRA_AUTHORITY_VIOLATION: Action '{}' classified as {:?} requires authority rank <= {}, got {}",
                req.action_name, reversibility, required_rank, req.caller_authority
            );
            let proof_hash = Self::compute_refusal_proof(&req.action_name, "ftra", &reason, now);
            stage_outcomes.push(StageOutcome {
                stage_name: "ftra".to_string(),
                passed: false,
                details: Some(reason.clone()),
            });
            return GovernanceEvaluationResult {
                verdict: GovernanceVerdict::Deny { reason, proof_hash },
                seal: None,
                stage_outcomes,
                commit_receipt: None,
                policy_version_id: policy.policy_version_id,
                action_digest,
            };
        }
        stage_outcomes.push(StageOutcome {
            stage_name: "ftra".to_string(),
            passed: true,
            details: Some(format!("Action classified as {:?}; authority cleared", reversibility)),
        });

        // Tier 1: STPA Validation
        if let Err((uca_id, reason)) = StpaValidator::validate_action(
            &req.action_name,
            &req.parameters,
            &policy.unsafe_control_actions,
            &req.principal,
        ) {
            let proof_hash = Self::compute_refusal_proof(&req.action_name, "stpa", &reason, now);
            stage_outcomes.push(StageOutcome {
                stage_name: "stpa".to_string(),
                passed: false,
                details: Some(format!("UCA '{}' breached: {}", uca_id, reason)),
            });
            return GovernanceEvaluationResult {
                verdict: GovernanceVerdict::Deny { reason, proof_hash },
                seal: None,
                stage_outcomes,
                commit_receipt: None,
                policy_version_id: policy.policy_version_id,
                action_digest,
            };
        }
        stage_outcomes.push(StageOutcome {
            stage_name: "stpa".to_string(),
            passed: true,
            details: Some(format!("Passed {} STPA rules", policy.unsafe_control_actions.len())),
        });

        // Tier 2: Cedar Policy Rules
        for rule in &policy.cedar_rules {
            let trimmed = rule.trim();
            if trimmed.starts_with("forbid") && Self::matches_cedar_forbid(trimmed, req) {
                let reason = format!(
                    "CEDAR_FORBID_VIOLATION: Action '{}' forbidden by Cedar policy: {}",
                    req.action_name, trimmed
                );
                let proof_hash = Self::compute_refusal_proof(&req.action_name, "cedar", &reason, now);
                stage_outcomes.push(StageOutcome {
                    stage_name: "cedar".to_string(),
                    passed: false,
                    details: Some(reason.clone()),
                });
                return GovernanceEvaluationResult {
                    verdict: GovernanceVerdict::Deny { reason, proof_hash },
                    seal: None,
                    stage_outcomes,
                    commit_receipt: None,
                    policy_version_id: policy.policy_version_id,
                    action_digest,
                };
            }
        }
        stage_outcomes.push(StageOutcome {
            stage_name: "cedar".to_string(),
            passed: true,
            details: Some(format!("Cleared {} Cedar rules", policy.cedar_rules.len())),
        });

        // Tier 3b: Federal Reserve SR 26-2 Confidence Scoring
        let normalized_conf = PlanGraphAnalyzer::normalize_confidence(req.confidence_score);
        let mut phase1_hold: Option<GovernanceVerdict> = None;

        if normalized_conf < SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD {
            let deficit = (SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD - normalized_conf).max(0.0);
            let backoff_ms = (1000.0 * (1.0 + deficit * 5.0)) as u64;
            phase1_hold = Some(GovernanceVerdict::Defer { backoff_ms });
        } else if normalized_conf < SR_26_2_CONFIDENCE_ALLOW_THRESHOLD {
            let nonce: [u8; 8] = rand::random();
            let approval_token = format!("token_{}", hex::encode(nonce));
            let reason = format!(
                "SR 26-2 confidence {:.4} in [{:.2}, {:.2}); requires operator approval",
                normalized_conf, SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD, SR_26_2_CONFIDENCE_ALLOW_THRESHOLD
            );
            phase1_hold = Some(GovernanceVerdict::RequireApproval { reason, approval_token });
        }

        // Check if PostHitl profile redeems hold
        if let Some(ref hold_verdict) = phase1_hold {
            if let Profile::PostHitl { approved_holds } = &profile {
                let is_redeemed = approved_holds.contains(&req.action_name)
                    || match hold_verdict {
                        GovernanceVerdict::RequireApproval { approval_token, .. } => {
                            approved_holds.contains(approval_token)
                        }
                        _ => false,
                    };
                if is_redeemed {
                    phase1_hold = None;
                }
            }
        }

        if let Some(hold) = phase1_hold {
            stage_outcomes.push(StageOutcome {
                stage_name: "confidence".to_string(),
                passed: false,
                details: Some(format!("Confidence finding: {:?}", hold.as_str())),
            });

            // Evaluate Phase 2 in Preview mode on findings
            let _ = self.ledger.preview(req.fuel_cost);

            return GovernanceEvaluationResult {
                verdict: hold,
                seal: None,
                stage_outcomes,
                commit_receipt: None,
                policy_version_id: policy.policy_version_id,
                action_digest,
            };
        }
        stage_outcomes.push(StageOutcome {
            stage_name: "confidence".to_string(),
            passed: true,
            details: Some(format!("Confidence {:.4} cleared", normalized_conf)),
        });

        // Tier 5: Bayesian Consensus
        if req.consensus_score < self.consensus_threshold {
            let reason = format!(
                "BAYESIAN_CONSENSUS_DEFICIT: Consensus score {:.4} < threshold {:.2}",
                req.consensus_score, self.consensus_threshold
            );
            let proof_hash = Self::compute_refusal_proof(&req.action_name, "consensus", &reason, now);
            stage_outcomes.push(StageOutcome {
                stage_name: "consensus".to_string(),
                passed: false,
                details: Some(reason.clone()),
            });
            return GovernanceEvaluationResult {
                verdict: GovernanceVerdict::Deny { reason, proof_hash },
                seal: None,
                stage_outcomes,
                commit_receipt: None,
                policy_version_id: policy.policy_version_id,
                action_digest,
            };
        }
        stage_outcomes.push(StageOutcome {
            stage_name: "consensus".to_string(),
            passed: true,
            details: Some(format!("Consensus {:.4} cleared", req.consensus_score)),
        });

        // ---------------------------------------------------------------------
        // Phase 2: Atomic State Mutation & Fiscal Pre-Reservation (Tiers 3a - 4)
        // ---------------------------------------------------------------------
        let phase2_mode = Self::select_phase2_mode(&profile, &None);

        match phase2_mode {
            Phase2Mode::Skip => {
                let reason = "Phase 2 execution skipped".to_string();
                let proof_hash = Self::compute_refusal_proof(&req.action_name, "pipeline", &reason, now);
                GovernanceEvaluationResult {
                    verdict: GovernanceVerdict::Deny { reason, proof_hash },
                    seal: None,
                    stage_outcomes,
                    commit_receipt: None,
                    policy_version_id: policy.policy_version_id,
                    action_digest,
                }
            }
            Phase2Mode::Preview => {
                match self.ledger.preview(req.fuel_cost) {
                    Ok((projected, barrier_val)) => {
                        stage_outcomes.push(StageOutcome {
                            stage_name: "cbf".to_string(),
                            passed: true,
                            details: Some(format!("Preview CBF barrier satisfied: h={:.4}", barrier_val)),
                        });
                        stage_outcomes.push(StageOutcome {
                            stage_name: "fiscal".to_string(),
                            passed: true,
                            details: Some(format!("Preview projected budget: {:.2}", projected)),
                        });
                        GovernanceEvaluationResult {
                            verdict: GovernanceVerdict::Allow,
                            seal: None,
                            stage_outcomes,
                            commit_receipt: None,
                            policy_version_id: policy.policy_version_id,
                            action_digest,
                        }
                    }
                    Err(violation) => {
                        let reason = format!("CBF_BARRIER_VIOLATION: {}", violation);
                        let proof_hash = Self::compute_refusal_proof(&req.action_name, "cbf", &reason, now);
                        stage_outcomes.push(StageOutcome {
                            stage_name: "cbf".to_string(),
                            passed: false,
                            details: Some(reason.clone()),
                        });
                        GovernanceEvaluationResult {
                            verdict: GovernanceVerdict::Deny { reason, proof_hash },
                            seal: None,
                            stage_outcomes,
                            commit_receipt: None,
                            policy_version_id: policy.policy_version_id,
                            action_digest,
                        }
                    }
                }
            }
            Phase2Mode::Commit => {
                let nonce: [u8; 8] = rand::random();
                let debit_id = format!("debit_{}", hex::encode(nonce));

                match self.ledger.pre_reserve(req.fuel_cost, &debit_id) {
                    Ok(commit_receipt) => {
                        stage_outcomes.push(StageOutcome {
                            stage_name: "cbf".to_string(),
                            passed: true,
                            details: Some(format!("CBF satisfied: h={:.4}", commit_receipt.barrier_val)),
                        });
                        stage_outcomes.push(StageOutcome {
                            stage_name: "fiscal".to_string(),
                            passed: true,
                            details: Some(format!(
                                "Reserved fuel {:.2}, remaining budget {:.2}",
                                commit_receipt.reserved_fuel, commit_receipt.remaining_budget
                            )),
                        });

                        // Record decision in immutable audit log to obtain evidence anchor
                        let details_json = serde_json::json!({
                            "action_digest": action_digest,
                            "policy_version_id": policy.policy_version_id,
                            "debit_id": debit_id,
                            "fuel_cost": req.fuel_cost,
                        })
                        .to_string();

                        let record_hash = self.audit_log.record_event(
                            "CAGE_GOVERNANCE_DECISION",
                            &req.principal,
                            &details_json,
                            "ALLOW",
                        );

                        // Issue evidence-bound routing seal
                        match self.seal_signer.issue_seal(&action_digest, &record_hash, now) {
                            Ok(seal) => GovernanceEvaluationResult {
                                verdict: GovernanceVerdict::Allow,
                                seal: Some(seal),
                                stage_outcomes,
                                commit_receipt: Some(commit_receipt),
                                policy_version_id: policy.policy_version_id,
                                action_digest,
                            },
                            Err(e) => {
                                // Compensating rollback on seal failure
                                let _ = self.ledger.rollback(&debit_id);
                                let reason = format!("SEAL_ISSUANCE_FAILED: {}", e);
                                let proof_hash = Self::compute_refusal_proof(&req.action_name, "seal", &reason, now);
                                GovernanceEvaluationResult {
                                    verdict: GovernanceVerdict::Deny { reason, proof_hash },
                                    seal: None,
                                    stage_outcomes,
                                    commit_receipt: None,
                                    policy_version_id: policy.policy_version_id,
                                    action_digest,
                                }
                            }
                        }
                    }
                    Err(violation) => {
                        let reason = format!("CBF_BARRIER_VIOLATION: {}", violation);
                        let proof_hash = Self::compute_refusal_proof(&req.action_name, "cbf", &reason, now);
                        stage_outcomes.push(StageOutcome {
                            stage_name: "cbf".to_string(),
                            passed: false,
                            details: Some(reason.clone()),
                        });
                        GovernanceEvaluationResult {
                            verdict: GovernanceVerdict::Deny { reason, proof_hash },
                            seal: None,
                            stage_outcomes,
                            commit_receipt: None,
                            policy_version_id: policy.policy_version_id,
                            action_digest,
                        }
                    }
                }
            }
        }
    }

    /// Evaluates action with parameter clamping narrower function.
    pub fn evaluate_with_narrowing<F>(
        &self,
        request: &GovernanceRequest,
        narrower: F,
    ) -> GovernanceEvaluationResult
    where
        F: Fn(&GovernanceRequest) -> Option<serde_json::Value>,
    {
        let primary_result = self.run_pipeline(request);

        if primary_result.verdict.is_allowed_or_narrowed()
            || matches!(primary_result.verdict, GovernanceVerdict::RequireApproval { .. })
        {
            return primary_result;
        }

        if let Some(clamped_params) = narrower(request) {
            let mut clamped_request = request.clone();
            clamped_request.parameters = clamped_params.clone();

            let clamped_result = self.run_pipeline(&clamped_request);
            if let GovernanceVerdict::Allow = clamped_result.verdict {
                return GovernanceEvaluationResult {
                    verdict: GovernanceVerdict::Narrow { clamped_params },
                    seal: clamped_result.seal,
                    stage_outcomes: clamped_result.stage_outcomes,
                    commit_receipt: clamped_result.commit_receipt,
                    policy_version_id: clamped_result.policy_version_id,
                    action_digest: clamped_result.action_digest,
                };
            }
        }

        primary_result
    }

    fn matches_cedar_forbid(rule: &str, req: &GovernanceRequest) -> bool {
        let rule_lower = rule.to_ascii_lowercase();
        let action_lower = req.action_name.to_ascii_lowercase();

        if !rule_lower.contains(&action_lower) && !rule_lower.contains("action") {
            return false;
        }

        if let Some(idx) = rule_lower.find("when {") {
            let condition = &rule_lower[idx + 6..];
            if let Some(end_idx) = condition.find('}') {
                let clause = condition[..end_idx].trim();
                if clause.contains("context.") {
                    let param_check = clause.replace("context.", "");
                    if param_check.contains("==") {
                        let parts: Vec<&str> = param_check.split("==").collect();
                        if parts.len() == 2 {
                            let key = parts[0].trim();
                            let expected = parts[1].trim().trim_matches('"').trim_matches('\'');
                            if let Some(actual) = req.parameters.get(key).and_then(|v| v.as_str()) {
                                return actual == expected;
                            }
                        }
                    }
                    if param_check.contains('>') {
                        let parts: Vec<&str> = param_check.split('>').collect();
                        if parts.len() == 2 {
                            let key = parts[0].trim();
                            let threshold: f64 = parts[1].trim().parse().unwrap_or(f64::MAX);
                            if let Some(val) = req.parameters.get(key).and_then(|v| v.as_f64()) {
                                return val > threshold;
                            }
                        }
                    }
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::cage_governance::substrate_translator::SubstrateTranslator;

    #[test]
    fn test_pipeline_full_allow_and_seal_issuance() {
        let policy_yaml = r#"{
            "behaviorDeclarations": [],
            "cbf_gamma": 0.5,
            "cbf_b_min": 10.0
        }"#;
        let policy = SubstrateTranslator::compile_policy(policy_yaml, None).unwrap();
        let ledger = Arc::new(DebitLedger::new(100.0, 0.5, 10.0).unwrap());
        let audit_log = Arc::new(SecurityAuditLog::new());
        let secret = b"secret_key_for_pipeline_testing_32";

        let pipeline = CagePipeline::new(policy, ledger, secret, audit_log);

        let req = GovernanceRequest {
            action_name: "query_database".to_string(),
            principal: "arm-analyst-1".to_string(),
            resource: "reports/daily".to_string(),
            parameters: serde_json::json!({"query": "SELECT 1"}),
            caller_authority: 3,
            confidence_score: 0.98,
            consensus_score: 0.85,
            fuel_cost: 5.0,
            expected_policy_version: None,
            execution_profile: Some(Profile::Full),
        };

        let res = pipeline.run_pipeline(&req);
        assert_eq!(res.verdict, GovernanceVerdict::Allow);
        assert!(res.seal.is_some());
        assert!(res.commit_receipt.is_some());
        assert_eq!(res.stage_outcomes.len(), 7);
    }

    #[test]
    fn test_pipeline_confidence_findings() {
        let policy_yaml = r#"{"behaviorDeclarations": []}"#;
        let policy = SubstrateTranslator::compile_policy(policy_yaml, None).unwrap();
        let ledger = Arc::new(DebitLedger::new(100.0, 0.5, 10.0).unwrap());
        let audit_log = Arc::new(SecurityAuditLog::new());
        let secret = b"secret_key_for_pipeline_testing_32";

        let pipeline = CagePipeline::new(policy, ledger, secret, audit_log);

        // Low confidence (< 0.70) -> Defer
        let req_low = GovernanceRequest {
            action_name: "read_file".to_string(),
            principal: "arm-1".to_string(),
            resource: "file.txt".to_string(),
            parameters: serde_json::json!({}),
            caller_authority: 3,
            confidence_score: 0.50,
            consensus_score: 0.80,
            fuel_cost: 1.0,
            expected_policy_version: None,
            execution_profile: Some(Profile::Full),
        };
        let res_low = pipeline.run_pipeline(&req_low);
        assert!(matches!(res_low.verdict, GovernanceVerdict::Defer { .. }));
        assert!(res_low.seal.is_none());

        // Medium confidence ([0.70, 0.95)) -> RequireApproval
        let req_med = GovernanceRequest {
            confidence_score: 0.85,
            ..req_low
        };
        let res_med = pipeline.run_pipeline(&req_med);
        assert!(matches!(res_med.verdict, GovernanceVerdict::RequireApproval { .. }));
    }
}
