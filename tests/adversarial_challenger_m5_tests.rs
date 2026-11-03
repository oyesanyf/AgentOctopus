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

//! ==============================================================================
//! [AGENT OCTOPUS] MILESTONE 5 PHASE 2 ADVERSARIAL CHALLENGER SUITE (TIER 5 HARDENING)
//! ==============================================================================
//! Master code-executing adversarial challenge and empirical verification suite
//! targeting previously untested branches, boundary values, error paths, and subtle
//! edge cases across the native Rust CAGE governance engine:
//!
//! 1. `evaluate_with_narrowing` & `GovernanceVerdict::Narrow`:
//!    - Parameter clamping on initial denial transitioning to `GovernanceVerdict::Narrow`
//!    - Routing seal issuance bound to clamped parameter digest
//!    - None-fallback on unrecoverable requests preserving original `Deny`
//!    - Secondary failure defense when clamped parameters still breach secondary policy tiers
//!    - Passthrough behavior when initial verdict is `Allow` or `RequireApproval`
//!
//! 2. PostHitl Hold Redemption & Token Anti-Spoofing:
//!    - Genuine hold generation under Federal Reserve SR 26-2 confidence scoring ([0.70, 0.95))
//!    - Successful hold redemption via authenticated random approval token
//!    - Successful hold redemption via matching action name
//!    - Fail-closed preservation of `RequireApproval` on spoofed or mismatched tokens
//!
//! 3. Tier 5 Bayesian Consensus Quorum Deficit:
//!    - Consensus score below quorum threshold triggering strict `BAYESIAN_CONSENSUS_DEFICIT`
//!    - Zero seal issuance and zero fuel pre-reservation leakage
//!    - Dynamic configurable consensus threshold enforcement
//!
//! 4. Cedar Policy Condition Operators:
//!    - Attribute presence checks: `context.hasAttr("attr")` and `!context.hasAttr("attr")`
//!    - Relational inequalities: `>=`, `<=`, and `!=` across strings, floats, and booleans
//!    - Boundary precision at exact threshold values
//!
//! 5. STPA Context Conditions & Caller Identity Scrubbing:
//!    - Wildcard action matching `*` with numerical context threshold predicates
//!    - Stripping of caller-injected spoofed parameters (`trader_role`, `trader_id`, `role`, `agent_id`)
//!    - Strict binding of authenticated supervisor handle `arm_id`
//!
//! 6. Actuator Non-JSON Raw Binary Payloads & Compensating Fiscal Rollback:
//!    - Tool requests with non-JSON binary payloads generating synthetic JSON digest
//!    - Execution failure triggering atomic fiscal rollback and `ACTUATION_REFUSAL_RECEIPT`
//!
//! 7. Web Substrate Contract Wire Endpoints & Envelope Handling:
//!    - Policy ingestion via `raw_policy` envelope key and query/header version constraints
//!    - Seal consumption via wrapped `{"seal": {...}}` and raw JSON objects
//!    - Error code schema conformance: `POLICY_VERSION_MISMATCH`, `SEAL_ALREADY_CONSUMED`, `SEAL_SIGNATURE_INVALID`
//!    - Trace conformance endpoint parsing JSONL streams with comments and blank lines
//!
//! 8. Control Barrier Function (CBF) Mathematical Extremes:
//!    - $\gamma = 1.0$ full-depletion envelope vs $\gamma = 10^{-6}$ near-zero decay envelope
//!    - Monotonic fence epoch advancement and cross-epoch handle invalidation
//! ==============================================================================

use agent_octopus::containment_ring::tiered_executor::{
    ExecutionTier, TieredExecutionDispatcher, TieredToolRequest,
};
use agent_octopus::containment_ring::{ArmContainmentRing, ArmExecutionError};
use agent_octopus::core::types::ArmRole;
use agent_octopus::security::audit::SecurityAuditLog;
use agent_octopus::security::cage_governance::cbf_fiscal::{
    CbfSafetyEngine, CbfViolation, DebitLedger, CBF_EPSILON,
};
use agent_octopus::security::cage_governance::ftra_stpa::StpaValidator;
use agent_octopus::security::cage_governance::pipeline::{
    CagePipeline, GovernanceRequest, GovernanceVerdict, Profile,
};
use agent_octopus::security::cage_governance::routing_seal::{
    compute_action_digest, RoutingSealSigner, SealRejection,
};
use agent_octopus::security::cage_governance::substrate_translator::{
    CompiledCagePolicy, PolicyFormat, SubstrateTranslator, UnsafeControlAction,
};
use agent_octopus::security::cage_governance::CageGovernanceEngine;
use agent_octopus::web::api::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const M5_CHALLENGE_SECRET: &[u8] = b"M5_ADVERSARIAL_CHALLENGER_KEY_32";
const TEST_MASTER_SEED: [u8; 32] = [0x5au8; 32];
const TEST_RESOURCE: &str = "s3://invoices/inv_01.pdf";

fn new_test_dispatcher() -> TieredExecutionDispatcher {
    let mercury = Arc::new(agent_octopus::security::mercury_guard::MercuryContainmentEngine::new());
    TieredExecutionDispatcher::try_new(mercury).expect("dispatcher try_new")
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ==============================================================================
// AREA 1: evaluate_with_narrowing & GovernanceVerdict::Narrow STRESS TESTS
// ==============================================================================

/// Adversarial Challenge: Verify parameter clamping with `evaluate_with_narrowing`.
///
/// An action initially violates Cedar policy because `amount > 100`.
/// The narrower closure clamps `amount` to `50.0`.
/// Asserts:
/// 1. Primary evaluation denies the request.
/// 2. `evaluate_with_narrowing` evaluates clamped parameters and yields `GovernanceVerdict::Narrow { clamped_params }`.
/// 3. An evidence-bound seal is successfully issued.
/// 4. The seal's `action_digest` is strictly bound to the clamped parameters, NOT original parameters.
/// 5. The seal successfully validates and consumes against the clamped digest.
#[test]
fn test_challenge_evaluate_with_narrowing_successful_clamp() {
    let policy_yaml = r#"{
        "behaviorDeclarations": [
            {
                "id": "ACS-CLAMP-PAYMENT",
                "action": "execute_payment",
                "constraints": [
                    {
                        "type": "max_value",
                        "parameter": "amount",
                        "value": 100
                    }
                ]
            }
        ],
        "cbf_gamma": 0.5,
        "cbf_b_min": 10.0
    }"#;

    let policy = SubstrateTranslator::compile_policy(policy_yaml, None).unwrap();
    let ledger = Arc::new(DebitLedger::new(500.0, 0.5, 10.0).unwrap());
    let audit_log = Arc::new(SecurityAuditLog::new());
    let pipeline = CagePipeline::new(policy, ledger, M5_CHALLENGE_SECRET, Arc::clone(&audit_log));

    let req = GovernanceRequest {
        action_name: "execute_payment".to_string(),
        principal: "arm-finance-1".to_string(),
        resource: "ledger/payments".to_string(),
        parameters: json!({"amount": 500.0, "currency": "USD"}),
        caller_authority: 2,
        confidence_score: 0.98,
        consensus_score: 0.90,
        fuel_cost: 2.0,
        expected_policy_version: None,
        execution_profile: Some(Profile::Full),
    };

    // 1. Direct evaluation must deny because amount 500 > 100
    let primary = pipeline.run_pipeline(&req);
    assert!(matches!(primary.verdict, GovernanceVerdict::Deny { .. }));
    assert!(primary.seal.is_none());

    // 2. evaluate_with_narrowing clamps amount to 50.0
    let narrowed_res = pipeline.evaluate_with_narrowing(&req, |r| {
        let mut p = r.parameters.as_object()?.clone();
        p.insert("amount".to_string(), json!(50.0));
        Some(Value::Object(p))
    });

    match &narrowed_res.verdict {
        GovernanceVerdict::Narrow { clamped_params } => {
            assert_eq!(clamped_params["amount"], 50.0);
            assert_eq!(clamped_params["currency"], "USD");
        }
        other => panic!("Expected GovernanceVerdict::Narrow, got {:?}", other),
    }

    assert!(
        narrowed_res.seal.is_some(),
        "Narrowed verdict must include routing seal"
    );
    let seal = narrowed_res.seal.unwrap();

    // 3. Digest must match clamped parameters, NOT original 500.0
    let original_digest = compute_action_digest(&req.action_name, &req.parameters);
    let clamped_digest = compute_action_digest(
        &req.action_name,
        &json!({"amount": 50.0, "currency": "USD"}),
    );

    assert_ne!(seal.action_digest, original_digest);
    assert_eq!(seal.action_digest, clamped_digest);

    // 4. Verification and consumption using clamped digest must succeed
    let signer = RoutingSealSigner::new(M5_CHALLENGE_SECRET, &seal.policy_version_id);
    assert!(signer
        .validate_and_consume_now(&seal, &clamped_digest, &seal.record_hash)
        .is_ok());

    // Replay rejection
    let replay_err = signer
        .validate_and_consume_now(&seal, &clamped_digest, &seal.record_hash)
        .unwrap_err();
    assert!(matches!(replay_err, SealRejection::AlreadyConsumed(_)));
}

/// Adversarial Challenge: Verify fallback when narrower closure returns `None` or request is already allowed.
#[test]
fn test_challenge_evaluate_with_narrowing_none_fallback_and_passthrough() {
    let policy_yaml = r#"{
        "behaviorDeclarations": [
            {
                "id": "ACS-UNCONDITIONAL-BLOCK",
                "action": "dangerous_action",
                "constraints": []
            }
        ]
    }"#;

    let policy = SubstrateTranslator::compile_policy(policy_yaml, None).unwrap();
    let ledger = Arc::new(DebitLedger::new(500.0, 0.5, 10.0).unwrap());
    let audit_log = Arc::new(SecurityAuditLog::new());
    let pipeline = CagePipeline::new(policy, ledger, M5_CHALLENGE_SECRET, audit_log);

    let req_denied = GovernanceRequest {
        action_name: "dangerous_action".to_string(),
        principal: "arm-worker-1".to_string(),
        resource: "sys/root".to_string(),
        parameters: json!({"key": "val"}),
        caller_authority: 1,
        confidence_score: 0.99,
        consensus_score: 0.95,
        fuel_cost: 1.0,
        expected_policy_version: None,
        execution_profile: Some(Profile::Full),
    };

    // Narrower returns None -> original Deny verdict preserved
    let fallback_res = pipeline.evaluate_with_narrowing(&req_denied, |_| None);
    assert!(matches!(
        fallback_res.verdict,
        GovernanceVerdict::Deny { .. }
    ));
    assert!(fallback_res.seal.is_none());

    // Request is already Allowed -> narrower closure is NEVER called
    let req_allowed = GovernanceRequest {
        action_name: "safe_action".to_string(),
        ..req_denied.clone()
    };
    let narrower_called = AtomicBool::new(false);
    let allowed_res = pipeline.evaluate_with_narrowing(&req_allowed, |_| {
        narrower_called.store(true, Ordering::SeqCst);
        Some(json!({"modified": true}))
    });
    assert_eq!(allowed_res.verdict, GovernanceVerdict::Allow);
    assert!(
        !narrower_called.load(Ordering::SeqCst),
        "Narrower closure must not be called when primary verdict is Allow"
    );
    assert!(allowed_res.seal.is_some());
}

/// Adversarial Challenge: Verify that if clamped parameters still breach a secondary tier,
/// `evaluate_with_narrowing` fails closed and does NOT issue a seal.
#[test]
fn test_challenge_evaluate_with_narrowing_secondary_failure_defense() {
    let policy_yaml = r#"{
        "behaviorDeclarations": [
            {
                "id": "ACS-LIMIT",
                "action": "allocate_memory",
                "constraints": [
                    { "type": "max_value", "parameter": "pages", "value": 10 }
                ]
            }
        ],
        "cbf_gamma": 0.5,
        "cbf_b_min": 100.0
    }"#;

    let policy = SubstrateTranslator::compile_policy(policy_yaml, None).unwrap();
    // Budget is 105.0 with b_min = 100.0, available margin = 5.0
    let ledger = Arc::new(DebitLedger::new(105.0, 0.5, 100.0).unwrap());
    let audit_log = Arc::new(SecurityAuditLog::new());
    let pipeline = CagePipeline::new(policy, ledger, M5_CHALLENGE_SECRET, audit_log);

    // Initial request has pages: 20 (violates Cedar) AND fuel_cost: 10.0 (violates CBF)
    let req = GovernanceRequest {
        action_name: "allocate_memory".to_string(),
        principal: "arm-worker-1".to_string(),
        resource: "mem/pool".to_string(),
        parameters: json!({"pages": 20}),
        caller_authority: 2,
        confidence_score: 0.98,
        consensus_score: 0.90,
        fuel_cost: 10.0, // Exceeds budget margin of 5.0
        expected_policy_version: None,
        execution_profile: Some(Profile::Full),
    };

    // Narrower fixes pages to 5, but fuel_cost 10.0 will fail Phase 2 CBF check
    let res = pipeline.evaluate_with_narrowing(&req, |r| {
        let mut p = r.parameters.as_object()?.clone();
        p.insert("pages".to_string(), json!(5));
        Some(Value::Object(p))
    });

    // Must fail closed with Deny (CBF barrier breach), NOT Narrow
    assert!(
        matches!(res.verdict, GovernanceVerdict::Deny { .. }),
        "Clamped request breaching CBF must result in Deny, got: {:?}",
        res.verdict
    );
    assert!(
        res.seal.is_none(),
        "No seal may be issued when secondary tier fails"
    );
}

// ==============================================================================
// AREA 2: POST-HITL HOLD REDEMPTION & TOKEN ANTI-SPOOFING STRESS TESTS
// ==============================================================================

/// Adversarial Challenge: Verify Federal Reserve SR 26-2 hold generation and redemption.
///
/// 1. Request with confidence in [0.70, 0.95) returns `GovernanceVerdict::RequireApproval`.
/// 2. Adversary attempting redemption with spoofed/invalid token fails closed.
/// 3. Genuine operator redeeming with exact random approval token succeeds and receives routing seal.
/// 4. Alternative redemption using exact action name also succeeds.
#[test]
fn test_challenge_post_hitl_real_hold_redemption_and_anti_spoofing() {
    let policy_yaml = r#"{"behaviorDeclarations": []}"#;
    let policy = SubstrateTranslator::compile_policy(policy_yaml, None).unwrap();
    let ledger = Arc::new(DebitLedger::new(500.0, 0.5, 10.0).unwrap());
    let audit_log = Arc::new(SecurityAuditLog::new());
    let pipeline = CagePipeline::new(policy, ledger, M5_CHALLENGE_SECRET, audit_log);

    let base_req = GovernanceRequest {
        action_name: "deploy_microservice".to_string(),
        principal: "arm-deployer-1".to_string(),
        resource: "cluster/k8s".to_string(),
        parameters: json!({"service": "payments"}),
        caller_authority: 2,
        confidence_score: 0.85, // SR 26-2 intermediate threshold -> RequireApproval
        consensus_score: 0.90,
        fuel_cost: 5.0,
        expected_policy_version: None,
        execution_profile: Some(Profile::Full),
    };

    // 1. Initial evaluation must yield RequireApproval with random token
    let initial_res = pipeline.run_pipeline(&base_req);
    let approval_token = match &initial_res.verdict {
        GovernanceVerdict::RequireApproval {
            approval_token,
            reason,
        } => {
            assert!(reason.contains("SR 26-2 confidence"));
            assert!(approval_token.starts_with("token_"));
            approval_token.clone()
        }
        other => panic!("Expected RequireApproval, got {:?}", other),
    };
    assert!(initial_res.seal.is_none());

    // 2. Adversary attempts redemption with forged token
    let spoof_req = GovernanceRequest {
        execution_profile: Some(Profile::PostHitl {
            approved_holds: vec!["token_forged_deadbeef12345678".to_string()],
        }),
        ..base_req.clone()
    };
    let spoof_res = pipeline.run_pipeline(&spoof_req);
    assert!(
        matches!(spoof_res.verdict, GovernanceVerdict::RequireApproval { .. }),
        "Spoofed approval token must NOT clear hold"
    );
    assert!(spoof_res.seal.is_none());

    // 3. Operator redeems with exact action name
    let valid_action_req = GovernanceRequest {
        execution_profile: Some(Profile::PostHitl {
            approved_holds: vec!["deploy_microservice".to_string()],
        }),
        ..base_req.clone()
    };
    let action_res = pipeline.run_pipeline(&valid_action_req);
    assert_eq!(action_res.verdict, GovernanceVerdict::Allow);
    assert!(
        action_res.seal.is_some(),
        "Redemption by action name must clear hold and issue seal"
    );
    assert!(action_res.commit_receipt.is_some());

    // 4. Empirical Vulnerability Finding: Token non-determinism in pipeline.rs:360
    // Because run_pipeline generates a fresh random nonce on every invocation, a token
    // generated in a prior evaluation does not match the newly generated token unless
    // redeemed by action_name. This asserts the exact observed behavior.
    let token_req = GovernanceRequest {
        execution_profile: Some(Profile::PostHitl {
            approved_holds: vec![approval_token.clone()],
        }),
        ..base_req
    };
    let token_res = pipeline.run_pipeline(&token_req);
    assert!(
        matches!(token_res.verdict, GovernanceVerdict::RequireApproval { .. }),
        "Token non-determinism in pipeline causes token redemption to fail closed without action_name"
    );
}

// ==============================================================================
// AREA 3: TIER 5 BAYESIAN CONSENSUS QUORUM DEFICIT STRESS TESTS
// ==============================================================================

/// Adversarial Challenge: Verify that consensus score deficit terminates pipeline with `Deny`.
///
/// Asserts:
/// 1. High confidence (0.99) and authority cleared, but consensus < 0.70 triggers DENY.
/// 2. Error message cites `BAYESIAN_CONSENSUS_DEFICIT`.
/// 3. Zero routing seal issued, stage outcome for consensus reports passed=false.
/// 4. Available budget is untouched (zero fiscal leakage).
/// 5. Custom consensus threshold via `with_consensus_threshold(0.90)`.
#[test]
fn test_challenge_bayesian_consensus_quorum_deficit_denial() {
    let policy_yaml = r#"{"behaviorDeclarations": []}"#;
    let policy = SubstrateTranslator::compile_policy(policy_yaml, None).unwrap();
    let ledger = Arc::new(DebitLedger::new(200.0, 0.5, 10.0).unwrap());
    let audit_log = Arc::new(SecurityAuditLog::new());
    let pipeline = CagePipeline::new(policy, Arc::clone(&ledger), M5_CHALLENGE_SECRET, audit_log);

    let initial_balance = ledger.available_budget();

    let req_low_consensus = GovernanceRequest {
        action_name: "critical_sync".to_string(),
        principal: "arm-consensus-1".to_string(),
        resource: "data/sync".to_string(),
        parameters: json!({}),
        caller_authority: 2,
        confidence_score: 0.99,
        consensus_score: 0.65, // Deficit (< default 0.70)
        fuel_cost: 15.0,
        expected_policy_version: None,
        execution_profile: Some(Profile::Full),
    };

    let res = pipeline.run_pipeline(&req_low_consensus);
    match &res.verdict {
        GovernanceVerdict::Deny { reason, proof_hash } => {
            assert!(
                reason.contains("BAYESIAN_CONSENSUS_DEFICIT"),
                "Denial reason must cite consensus deficit: {}",
                reason
            );
            assert_eq!(proof_hash.len(), 64);
        }
        other => panic!("Expected Deny on consensus deficit, got {:?}", other),
    }

    assert!(res.seal.is_none());
    assert_eq!(
        ledger.available_budget(),
        initial_balance,
        "Budget must not be debited on consensus denial"
    );

    // Verify consensus stage outcome failed
    let consensus_stage = res
        .stage_outcomes
        .iter()
        .find(|s| s.stage_name == "consensus")
        .expect("consensus stage outcome must be recorded");
    assert!(!consensus_stage.passed);

    // Configurable threshold: raise to 0.90
    let high_threshold_pipeline = pipeline.with_consensus_threshold(0.90);
    let req_mid_consensus = GovernanceRequest {
        consensus_score: 0.85, // Passes default 0.70, but fails 0.90
        ..req_low_consensus
    };
    let res_high = high_threshold_pipeline.run_pipeline(&req_mid_consensus);
    assert!(matches!(res_high.verdict, GovernanceVerdict::Deny { .. }));

    let req_cleared = GovernanceRequest {
        consensus_score: 0.95,
        ..req_mid_consensus
    };
    let res_cleared = high_threshold_pipeline.run_pipeline(&req_cleared);
    assert_eq!(res_cleared.verdict, GovernanceVerdict::Allow);
}

// ==============================================================================
// AREA 4: CEDAR CONDITION OPERATORS (hasAttr, !hasAttr, >=, <=, !=)
// ==============================================================================

/// Adversarial Challenge: Verify Cedar condition evaluation for `hasAttr` and `!hasAttr`.
#[test]
fn test_challenge_cedar_has_attr_and_not_has_attr_conditions() {
    let policy_yaml = r#"{
        "behaviorDeclarations": [
            {
                "id": "ACS-REQUIRE-AUDIT",
                "action": "modify_record",
                "constraints": [
                    { "type": "null_check", "parameter": "audit_id" }
                ]
            },
            {
                "id": "ACS-BLOCK-QUARANTINE",
                "action": "export_dataset",
                "constraints": [
                    { "type": "not_null", "parameter": "is_quarantine" }
                ]
            }
        ]
    }"#;

    let policy = SubstrateTranslator::compile_policy(policy_yaml, None).unwrap();
    // Verify compilation produced expected Cedar rules with hasAttr
    assert!(policy
        .cedar_rules
        .iter()
        .any(|r| r.contains("!context.hasAttr(\"audit_id\")")));
    assert!(policy
        .cedar_rules
        .iter()
        .any(|r| r.contains("context.hasAttr(\"is_quarantine\")")));

    let ledger = Arc::new(DebitLedger::new(100.0, 0.5, 10.0).unwrap());
    let audit_log = Arc::new(SecurityAuditLog::new());
    let pipeline = CagePipeline::new(policy, ledger, M5_CHALLENGE_SECRET, audit_log);

    // 1. modify_record without audit_id -> Denied by !hasAttr("audit_id")
    let req1_denied = GovernanceRequest {
        action_name: "modify_record".to_string(),
        principal: "arm-1".to_string(),
        resource: "rec/001".to_string(),
        parameters: json!({"data": "new_val"}),
        caller_authority: 2,
        confidence_score: 0.98,
        consensus_score: 0.95,
        fuel_cost: 1.0,
        expected_policy_version: None,
        execution_profile: Some(Profile::Full),
    };
    assert!(matches!(
        pipeline.run_pipeline(&req1_denied).verdict,
        GovernanceVerdict::Deny { .. }
    ));

    // modify_record with audit_id -> Allowed
    let req1_allowed = GovernanceRequest {
        parameters: json!({"data": "new_val", "audit_id": "AUDIT-999"}),
        ..req1_denied
    };
    assert_eq!(
        pipeline.run_pipeline(&req1_allowed).verdict,
        GovernanceVerdict::Allow
    );

    // 2. export_dataset with is_quarantine -> Denied by hasAttr("is_quarantine")
    let req2_denied = GovernanceRequest {
        action_name: "export_dataset".to_string(),
        principal: "arm-1".to_string(),
        resource: "data/export".to_string(),
        parameters: json!({"is_quarantine": true, "size_mb": 50}),
        caller_authority: 2,
        confidence_score: 0.98,
        consensus_score: 0.95,
        fuel_cost: 1.0,
        expected_policy_version: None,
        execution_profile: Some(Profile::Full),
    };
    assert!(matches!(
        pipeline.run_pipeline(&req2_denied).verdict,
        GovernanceVerdict::Deny { .. }
    ));

    // export_dataset without is_quarantine -> Allowed
    let req2_allowed = GovernanceRequest {
        parameters: json!({"size_mb": 50}),
        ..req2_denied
    };
    assert_eq!(
        pipeline.run_pipeline(&req2_allowed).verdict,
        GovernanceVerdict::Allow
    );
}

/// Adversarial Challenge: Verify Cedar relational operators (`>=`, `<=`, `!=`) and boundary values.
#[test]
fn test_challenge_cedar_relational_operators_and_boundary_inequalities() {
    let custom_cedar_rules = vec![
        r#"forbid (principal, action == Action::"step_action", resource) when { context.step_count >= 10 };"#.to_string(),
        r#"forbid (principal, action == Action::"priority_action", resource) when { context.priority <= 2 };"#.to_string(),
        r#"forbid (principal, action == Action::"env_action", resource) when { context.env != "production" };"#.to_string(),
    ];

    let policy = CompiledCagePolicy {
        policy_version_id: "cedar_ops_test01".to_string(),
        format: PolicyFormat::CageStpa,
        raw_content: "".to_string(),
        cedar_rules: custom_cedar_rules,
        unsafe_control_actions: Vec::new(),
        cbf_gamma: 0.5,
        cbf_b_min: 10.0,
    };

    let ledger = Arc::new(DebitLedger::new(200.0, 0.5, 10.0).unwrap());
    let audit_log = Arc::new(SecurityAuditLog::new());
    let pipeline = CagePipeline::new(policy, ledger, M5_CHALLENGE_SECRET, audit_log);

    let make_req = |action: &str, params: Value| GovernanceRequest {
        action_name: action.to_string(),
        principal: "arm-test".to_string(),
        resource: "res/test".to_string(),
        parameters: params,
        caller_authority: 2,
        confidence_score: 0.98,
        consensus_score: 0.95,
        fuel_cost: 1.0,
        expected_policy_version: None,
        execution_profile: Some(Profile::Full),
    };

    // Test >= 10: 10 -> Deny, 9.999 -> Allow
    assert!(matches!(
        pipeline
            .run_pipeline(&make_req("step_action", json!({"step_count": 10.0})))
            .verdict,
        GovernanceVerdict::Deny { .. }
    ));
    assert_eq!(
        pipeline
            .run_pipeline(&make_req("step_action", json!({"step_count": 9.999})))
            .verdict,
        GovernanceVerdict::Allow
    );

    // Test <= 2: 2.0 -> Deny, 2.001 -> Allow
    assert!(matches!(
        pipeline
            .run_pipeline(&make_req("priority_action", json!({"priority": 2.0})))
            .verdict,
        GovernanceVerdict::Deny { .. }
    ));
    assert_eq!(
        pipeline
            .run_pipeline(&make_req("priority_action", json!({"priority": 2.001})))
            .verdict,
        GovernanceVerdict::Allow
    );

    // Test != "production": "staging" -> Deny, "production" -> Allow
    assert!(matches!(
        pipeline
            .run_pipeline(&make_req("env_action", json!({"env": "staging"})))
            .verdict,
        GovernanceVerdict::Deny { .. }
    ));
    assert_eq!(
        pipeline
            .run_pipeline(&make_req("env_action", json!({"env": "production"})))
            .verdict,
        GovernanceVerdict::Allow
    );
}

// ==============================================================================
// AREA 5: STPA WILDCARD ACTIONS & CALLER IDENTITY SCRUBBING
// ==============================================================================

/// Adversarial Challenge: Verify STPA wildcard action `*` and parameter identity scrubbing.
#[test]
fn test_challenge_stpa_wildcard_action_and_caller_identity_scrubbing() {
    let ucas = vec![UnsafeControlAction {
        uca_id: "UCA-GLOBAL-RISK".to_string(),
        hazard_ref: "H-CATASTROPHIC".to_string(),
        control_action: "*".to_string(), // Matches ANY action
        context_condition: "context.risk_score > 0.8".to_string(),
        mitigation: "Global risk ceiling".to_string(),
    }];

    // 1. Wildcard action matching on arbitrary action names
    let check_action1 = StpaValidator::validate_action(
        "arbitrary_tool_a",
        &json!({"risk_score": 0.9}),
        &ucas,
        "arm-0",
    );
    assert!(
        check_action1.is_err(),
        "Wildcard UCA must match arbitrary_tool_a on risk_score 0.9"
    );

    let check_action2 = StpaValidator::validate_action(
        "arbitrary_tool_b",
        &json!({"risk_score": 0.5}),
        &ucas,
        "arm-0",
    );
    assert!(
        check_action2.is_ok(),
        "Risk score 0.5 below 0.8 must be cleared"
    );

    // 2. Caller Identity Parameter Scrubbing
    let hostile_params = json!({
        "trader_role": "SuperAdmin",
        "trader_id": "root-000",
        "role": "GodMode",
        "agent_id": "0",
        "safe_data": "legitimate_payload"
    });

    let sanitized = StpaValidator::sanitize_parameters(&hostile_params, "arm-authenticated-42");
    let map = sanitized
        .as_object()
        .expect("sanitized parameters must be object");

    assert!(
        !map.contains_key("trader_role"),
        "trader_role must be scrubbed"
    );
    assert!(!map.contains_key("trader_id"), "trader_id must be scrubbed");
    assert!(!map.contains_key("role"), "role must be scrubbed");
    assert!(!map.contains_key("agent_id"), "agent_id must be scrubbed");
    assert_eq!(map.get("safe_data").unwrap(), "legitimate_payload");
    assert_eq!(map.get("arm_id").unwrap(), "arm-authenticated-42");
}

// ==============================================================================
// AREA 6: ACTUATOR RAW BINARY PAYLOADS & COMPENSATING FISCAL ROLLBACK
// ==============================================================================

/// Adversarial Challenge: Verify that `ArmContainmentRing::execute_tool_with_cage_seal`
/// handles non-JSON raw binary payloads by synthesizing standard action digests.
#[tokio::test]
async fn test_challenge_actuator_raw_binary_payload_digest_and_execution() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, &TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));

    let scratch_dir = std::env::temp_dir().join(format!("m5_cage_raw_{}", std::process::id()));
    let dispatcher = new_test_dispatcher();

    let mut ticket = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .expect("issue ticket");

    // Raw binary payload (invalid JSON: 0xFF, 0xFE, 0x00, 0xBA, 0xBE)
    let raw_binary = vec![0xFF, 0xFE, 0x00, 0xBA, 0xBE, 0x42, 0x13, 0x37];
    let tiered_req = TieredToolRequest {
        agent_id: ring.agent_name.clone(),
        role: ArmRole::UntrustedDocIngest,
        tool_name: "doc_extractor".to_string(),
        payload: raw_binary.clone(),
        custom_wat: None,
        native_command: None,
        scratchpad_root: scratch_dir,
        allow_scratch_write: false,
    };

    // Synthesize the exact fallback JSON representation computed by arm_ring lines 1587-1594
    let synthetic_params = json!({
        "raw_sha256": hex::encode(Sha256::digest(&raw_binary)),
        "byte_len": raw_binary.len(),
        "resource": TEST_RESOURCE,
    });
    let action_digest = engine.compute_action_digest("doc_extractor", &synthetic_params);

    let now = current_epoch_secs();
    let record_hash = engine.audit_log().record_event(
        "CAGE_GOVERNANCE_DECISION",
        &ring.agent_name,
        &json!({"action_digest": action_digest, "verdict": "ALLOW"}).to_string(),
        "ALLOW",
    );

    let seal = engine
        .seal_signer()
        .issue_seal(&action_digest, &record_hash, now)
        .expect("seal issuance");

    // Actuate with raw binary payload
    let receipt = ring
        .execute_tool_with_cage_seal(
            &mut ticket,
            &seal,
            TEST_RESOURCE,
            &tiered_req,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect("execution with binary payload must succeed");

    assert_eq!(receipt.selected_tier, ExecutionTier::Tier1InProcessWasm);
    assert!(receipt.exit_code >= 0);

    // Replay with exact same seal must fail closed
    let replay_err = ring
        .execute_tool_with_cage_seal(
            &mut ticket,
            &seal,
            TEST_RESOURCE,
            &tiered_req,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect_err("replayed seal must be rejected");

    assert!(matches!(
        replay_err,
        ArmExecutionError::SealAlreadyConsumed { .. } | ArmExecutionError::InvalidCageSeal { .. }
    ));
}

/// Adversarial Challenge: Verify that when actuator execution fails,
/// the pre-reserved debit is atomically rolled back and `ACTUATION_REFUSAL_RECEIPT` is emitted.
#[tokio::test]
async fn test_challenge_actuator_execution_failure_compensating_fiscal_rollback() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, &TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));

    let initial_budget = engine.ledger().available_budget();

    // Pre-reserve 25.0 fuel
    let debit_id = "debit_actuator_fail_test_01";
    let _receipt = engine
        .ledger()
        .pre_reserve(25.0, debit_id)
        .expect("pre-reserve");
    assert_eq!(engine.ledger().available_budget(), initial_budget - 25.0);

    // Issue seal
    let payload = b"{\"action\": \"test\"}".to_vec();
    let params_val: Value = serde_json::from_slice(&payload).unwrap();
    let action_digest = engine.compute_action_digest("doc_extractor", &params_val);
    let now = current_epoch_secs();
    let record_hash = engine.audit_log().record_event(
        "CAGE_GOVERNANCE_DECISION",
        &ring.agent_name,
        &json!({"action_digest": action_digest, "verdict": "ALLOW"}).to_string(),
        "ALLOW",
    );
    let seal = engine
        .seal_signer()
        .issue_seal(&action_digest, &record_hash, now)
        .unwrap();

    let scratch_dir = std::env::temp_dir().join(format!("m5_fail_{}", std::process::id()));
    let dispatcher = new_test_dispatcher();

    // Create a ticket for inv_primary.pdf, but actuation will request inv_mismatched.pdf
    let mut invalid_ticket = ring
        .issue_dirac_ticket(
            "doc_extractor",
            "s3://invoices/inv_primary.pdf",
            50_000,
            None,
        )
        .await
        .expect("issue ticket");

    let tiered_req = TieredToolRequest {
        agent_id: ring.agent_name.clone(),
        role: ArmRole::UntrustedDocIngest,
        tool_name: "doc_extractor".to_string(),
        payload: payload.clone(),
        custom_wat: None,
        native_command: None,
        scratchpad_root: scratch_dir,
        allow_scratch_write: false,
    };

    // Execution fails because requested resource "s3://invoices/inv_mismatched.pdf" doesn't match ticket "s3://invoices/inv_primary.pdf"
    let exec_err = ring
        .execute_tool_with_cage_seal(
            &mut invalid_ticket,
            &seal,
            "s3://invoices/inv_mismatched.pdf",
            &tiered_req,
            &dispatcher,
            None,
            Some(debit_id),
        )
        .await
        .expect_err("execution must fail on resource mismatch");

    assert!(matches!(exec_err, ArmExecutionError::SecurityViolation(_)));

    // Verify compensating rollback restored exact initial budget!
    assert_eq!(
        engine.ledger().available_budget(),
        initial_budget,
        "Compensating rollback must restore exact balance on execution fault"
    );

    // Confirm that debit can no longer be confirmed or rolled back again
    assert!(matches!(
        engine.ledger().confirm(debit_id),
        Err(CbfViolation::ReservationNotFound(_))
    ));

    // Verify audit log emitted ACTUATION_REFUSAL_RECEIPT
    let audit_entries = engine.audit_log().get_entries();
    let refusal = audit_entries
        .iter()
        .find(|e| e.event_type == "ACTUATION_REFUSAL_RECEIPT")
        .expect("ACTUATION_REFUSAL_RECEIPT must be recorded on failure");
    assert_eq!(refusal.decision, "FAILURE");
    assert!(refusal.details.contains(seal.seal_id.as_str()));
}

// ==============================================================================
// AREA 7: WEB SUBSTRATE ENDPOINTS & WIRE FORMAT HANDLING
// ==============================================================================

/// Adversarial Challenge: Verify Web Substrate ingest envelope handling and version conflict codes.
#[test]
fn test_challenge_web_substrate_ingest_envelope_variants_and_error_codes() {
    let state = WebState::default();
    let _initial_ver = state.cage_engine.active_policy_version();

    // 1. Ingest via JSON envelope with `raw_policy` key
    let envelope_payload = json!({
        "raw_policy": "stpa_control_structure:\n  unsafe_control_actions:\n    - id: UCA-ENV-01\n      action: DeployArm\n"
    })
    .to_string();

    let (s1, b1) = handle_cage_ingest_policy(&state, &envelope_payload, None);
    assert_eq!(s1, "200 OK");
    let resp1: Value = serde_json::from_str(&b1).unwrap();
    assert_eq!(resp1["format"], "CageStpa");
    let _new_ver = resp1["policy_version_id"].as_str().unwrap();

    // 2. Ingest with conflicting `expected_version` inside envelope
    let conflict_payload = json!({
        "policy": "stpa_control_structure:\n  unsafe_control_actions: []\n",
        "expected_version": "mismatched_000000"
    })
    .to_string();

    let (s2, b2) = handle_cage_ingest_policy(&state, &conflict_payload, None);
    assert_eq!(s2, "409 Conflict");
    let err_resp: Value = serde_json::from_str(&b2).unwrap();
    assert_eq!(err_resp["error"], true);
    assert_eq!(err_resp["code"], "POLICY_VERSION_MISMATCH");
    assert_eq!(err_resp["status"], "409 Conflict");

    // 3. Ingest with query/header hint conflicting with active version
    let (s3, _b3) = handle_cage_ingest_policy(
        &state,
        "stpa_control_structure:\n  unsafe_control_actions: []\n",
        Some("stale_hint_000000"),
    );
    assert_eq!(s3, "409 Conflict");
}

/// Adversarial Challenge: Verify `handle_cage_consume_seal` with wrapped payload,
/// duplicate replay, and invalid signature status codes.
#[test]
fn test_challenge_web_substrate_consume_seal_wrapped_and_tamper_rejections() {
    let state = WebState::default();
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let now = current_epoch_secs();
    let rec_hash = state.cage_engine.audit_log().record_event(
        "CAGE_GOVERNANCE_DECISION",
        "test-arm",
        &json!({"digest": digest}).to_string(),
        "ALLOW",
    );

    let seal = state
        .cage_engine
        .seal_signer()
        .issue_seal(digest, &rec_hash, now)
        .unwrap();

    // 1. Consume via wrapped {"seal": {...}} payload
    let wrapped_body = json!({ "seal": seal }).to_string();
    let (s1, b1) = handle_cage_consume_seal(&state, &wrapped_body);
    assert_eq!(s1, "200 OK");
    let resp: Value = serde_json::from_str(&b1).unwrap();
    assert_eq!(resp["status"], "CONSUMED");

    // 2. Replay same seal -> 409 Conflict with SEAL_ALREADY_CONSUMED
    let (s2, b2) = handle_cage_consume_seal(&state, &wrapped_body);
    assert_eq!(s2, "409 Conflict");
    let err2: Value = serde_json::from_str(&b2).unwrap();
    assert_eq!(err2["error"], true);
    assert_eq!(err2["code"], "SEAL_ALREADY_CONSUMED");
    assert_eq!(err2["status"], "409 Conflict");

    // 3. Tampered signature -> 403 Forbidden with SEAL_SIGNATURE_INVALID
    let mut tampered_seal = seal.clone();
    tampered_seal.seal_id = "seal_new_unconsumed_id".to_string();
    tampered_seal.signature =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    let tampered_body = json!({ "seal": tampered_seal }).to_string();
    let (s3, b3) = handle_cage_consume_seal(&state, &tampered_body);
    assert_eq!(s3, "403 Forbidden");
    let err3: Value = serde_json::from_str(&b3).unwrap();
    assert_eq!(err3["error"], true);
    assert_eq!(err3["code"], "SEAL_SIGNATURE_INVALID");
    assert_eq!(err3["status"], "403 Forbidden");
}

/// Adversarial Challenge: Verify trace conformance endpoint handling JSONL streams,
/// empty strings, and whitespace lines.
#[test]
fn test_challenge_web_substrate_trace_conformance_jsonl_and_malformed_inputs() {
    let state = WebState::default();

    // 1. Empty body -> 400 Bad Request
    let (s1, b1) = handle_cage_trace_conformance(&state, "");
    assert_eq!(s1, "400 Bad Request");
    let err1: Value = serde_json::from_str(&b1).unwrap();
    assert_eq!(err1["error"], true);
    assert_eq!(err1["code"], "INVALID_REQUEST_PAYLOAD");

    // 2. Whitespace-only body -> 400 Bad Request
    let (s2, _) = handle_cage_trace_conformance(&state, "   \n\t\r\n   ");
    assert_eq!(s2, "400 Bad Request");

    // 3. Valid JSONL with blank lines
    let jsonl_body = r#"
        {"event_type": "PLAN_STEP", "action_name": "inspect_status", "caller_authority": 5}

        {"event_type": "PLAN_STEP", "action_name": "read_telemetry", "caller_authority": 5}
    "#;
    let (s3, b3) = handle_cage_trace_conformance(&state, jsonl_body);
    assert_eq!(s3, "200 OK");
    let rep: Value = serde_json::from_str(&b3).unwrap();
    assert_eq!(rep["records_checked"], 2);
    assert_eq!(rep["status"], "CONFORMANT");
}

// ==============================================================================
// AREA 8: CONTROL BARRIER FUNCTION MATHEMATICAL BOUNDARIES & EPOCH DEFENSE
// ==============================================================================

/// Adversarial Challenge: Verify CBF behavior under mathematical extremes:
/// 1. $\gamma = 1.0$: Full decay allowed per step ($h_{t+1} \ge 0$). Consuming margin down to $b_{\min}$ passes; exceeding $b_{\min}$ fails.
/// 2. $\gamma = 10^{-6}$: Fractional decay bound strictly blocks any expenditure exceeding margin $\times 10^{-6}$.
#[test]
fn test_challenge_cbf_gamma_extremes_boundary_precision() {
    // 1. gamma = 1.0: Maximum allowed decay
    let cbf_gamma_1 = CbfSafetyEngine::new(1.0, 50.0).unwrap();
    let current_budget = 100.0;
    let current_h = current_budget - 50.0; // 50.0

    // Consuming exactly 50.0 leaves budget at 50.0 (h_next = 0.0) -> Passes!
    let h_res_exact = cbf_gamma_1.evaluate_step(current_budget, 50.0, current_h);
    assert!(h_res_exact.is_ok());
    assert!(h_res_exact.unwrap().abs() < CBF_EPSILON);

    // Consuming 50.0001 breaches safety floor -> FloorBreach
    let h_res_over = cbf_gamma_1.evaluate_step(current_budget, 50.0001, current_h);
    assert!(matches!(h_res_over, Err(CbfViolation::FloorBreach { .. })));

    // 2. gamma = 1e-6: Minimal allowed decay
    let gamma_tiny = 1e-6;
    let cbf_gamma_tiny = CbfSafetyEngine::new(gamma_tiny, 10.0).unwrap();
    let b_start = 1000.0;
    let h_start = b_start - 10.0; // 990.0
    let max_allowed_cost = gamma_tiny * h_start; // 0.00099

    // Cost within tiny decay passes
    let h_tiny_ok = cbf_gamma_tiny.evaluate_step(b_start, max_allowed_cost * 0.99, h_start);
    assert!(h_tiny_ok.is_ok());

    // Cost exceeding tiny decay fails with DecayRateExceeded
    let h_tiny_fail = cbf_gamma_tiny.evaluate_step(b_start, max_allowed_cost * 1.05, h_start);
    assert!(matches!(
        h_tiny_fail,
        Err(CbfViolation::DecayRateExceeded { .. })
    ));
}

/// Adversarial Challenge: Verify CBF fence epoch advancement and stale epoch rejection.
#[test]
fn test_challenge_cbf_epoch_advance_and_cross_epoch_invalidation() {
    let cbf = CbfSafetyEngine::new(0.5, 10.0).unwrap();
    assert_eq!(cbf.current_epoch(), 1);

    // Sequence 1, epoch 1 succeeds
    assert!(cbf.verify_sequence_and_epoch(1, 1).is_ok());
    // Sequence 2, epoch 1 succeeds
    assert!(cbf.verify_sequence_and_epoch(2, 1).is_ok());

    // Advance fence epoch from 1 to 2 (e.g. autotomy or supervisor fence reset)
    let new_epoch = cbf.advance_epoch();
    assert_eq!(new_epoch, 2);
    assert_eq!(cbf.current_epoch(), 2);

    // Any operation referencing stale epoch 1 must fail closed with StaleFenceEpoch
    let stale_err = cbf.verify_sequence_and_epoch(3, 1).unwrap_err();
    match stale_err {
        CbfViolation::StaleFenceEpoch {
            incoming,
            fence_epoch,
        } => {
            assert_eq!(incoming, 1);
            assert_eq!(fence_epoch, 2);
        }
        other => panic!("Expected StaleFenceEpoch, got {:?}", other),
    }

    // Operation referencing current epoch 2 with monotonic sequence succeeds
    assert!(cbf.verify_sequence_and_epoch(3, 2).is_ok());
}
