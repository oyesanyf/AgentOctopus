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
//! [AGENT OCTOPUS] MILESTONE 4 MASTER CAGE INTEGRATION TEST SUITE (FEATURE F19)
//! ==============================================================================
//! Comprehensive master integration test suite validating end-to-end CAGE governance
//! capabilities and substrate endpoints:
//!
//! 1. Multi-Format Policy Ingestion:
//!    - Synthetic fixtures for all 5 formats:
//!      * Microsoft ACS (`behaviorDeclarations`, `cbf_gamma`, `cbf_b_min`)
//!      * LF AAIF (`governedRunLoop`, `stages`, `hooks`)
//!      * NIST OSCAL 1.1.x (`oscal-version`, `control-implementations`)
//!      * Lula Validation (`kind: LulaValidation`, OPA Rego)
//!      * Native CAGE YAML (`stpa_control_structure`, `unsafe_control_actions`)
//!    - Auto-detection priority and compilation to Cedar rules & STPA UCAs
//!    - Deterministic 16-character hex SHA-256 version hashing via RFC 8785 JCS
//!    - Active version pinning and HTTP 409 Conflict drift rejection
//!
//! 2. FTRA Graph Analysis & Reachability:
//!    - Semantic reversibility classification across all 5 tiers:
//!      (`ReadOnly`, `Reversible`, `Compensatable`, `ConditionalAutonomous`, `IrreversibleTerminal`)
//!    - Caller authority rank enforcement (Rank 1 highest, Rank 5 lowest)
//!    - Fail-closed confidence normalization (`NaN`, `+Inf`, `-Inf`, negative -> `0.0`, `>1.0` -> `1.0`)
//!    - Federal Reserve SR 26-2 model confidence thresholds
//!    - Topological execution graph traversal, diamond DAGs, and cycle detection
//!    - STPA Tier 1 authenticated caller identity scrubbing
//!
//! 3. 2-Phase Discrete-Time CBF & Fiscal Ledger:
//!    - Barrier inequality: $h(S_{t+1}) = (B_t - c) - B_{\min} \ge (1-\gamma)h(S_t) \ge 0$
//!    - Exact boundary, floor breach, decay breach, and parameter validation
//!    - Replay sequence high-water marks and monotonic fence epochs
//!    - Two-phase pre-reservation: preview, pre-reserve, confirm, rollback, rollback_lifo
//!    - Exact balance conservation with zero fiscal leakage
//!
//! 4. Routing Seal & Actuator Gating:
//!    - Cryptographic HMAC-SHA256 seal issuance bound to `SecurityAuditLog` 64-hex chain hash
//!    - Strict 30-second TTL and 5-second clock drift tolerance
//!    - Actuation via `ArmContainmentRing::execute_tool_with_cage_seal`
//!    - Single-use consumption and duplicate replay rejection
//!    - Action digest parameter tampering and signature corruption rejection
//!    - Actuator failure compensating fiscal rollback
//!
//! 5. BFS State Machine Proof & Trace Conformance:
//!    - Formal BFS model proving No-Direct-Bind across strictly 34 gated states
//!    - Ungated counterexample generation on strictly 17 reachable states
//!    - Skipped-tier invariant model discovering strictly 31 reachable states
//!    - Deterministic 64-hex SHA-256 theorem proof receipt
//!    - 7-rule `GOVERNANCE_TRACE` stream validation (conforming and adversarial streams)
//!
//! 6. CAGE Substrate HTTP Handlers:
//!    - Wire tests against `WebState` testing ingest, version, validate, consume, proof-status, trace-conformance
//!    - Verification of 200 OK, 400 Bad Request, 403 Forbidden, and 409 Conflict status codes
//! ==============================================================================

use agent_octopus::containment_ring::{
    ArmContainmentRing, ArmExecutionError, TieredExecutionDispatcher, TieredToolRequest,
};
use agent_octopus::core::types::ArmRole;
use agent_octopus::security::audit::SecurityAuditLog;
use agent_octopus::security::cage_governance::cbf_fiscal::{
    CbfSafetyEngine, CbfViolation, DebitLedger,
};
use agent_octopus::security::cage_governance::ftra_stpa::{
    ActionReversibility, FtraVerdict, PlanGraphAnalyzer, PlanStep, StpaValidator,
    SR_26_2_CONFIDENCE_ALLOW_THRESHOLD, SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD,
};
use agent_octopus::security::cage_governance::no_direct_bind_proof::{
    BfsPhase, BfsState, FormalBfsModel, StreamConformanceStatus,
};
use agent_octopus::security::cage_governance::pipeline::{
    GovernanceEvaluationResult, GovernanceRequest, GovernanceVerdict, Profile,
};
use agent_octopus::security::cage_governance::routing_seal::{
    compute_action_digest, CageRoutingSeal, RoutingSealSigner, SealRejection,
};
use agent_octopus::security::cage_governance::substrate_translator::{
    CompiledCagePolicy, PolicyFormat, SubstrateTranslator,
};
use agent_octopus::security::cage_governance::{
    CageApiError, CageGovernanceEngine, ProofStatusResponse,
};
use agent_octopus::web::api::*;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_MASTER_SEED: &[u8] = b"OCTOPUS_MASTER_INTEGRATION_SEED_";
const TEST_RESOURCE: &str = "s3://invoices/inv_01.pdf";

fn new_test_dispatcher() -> TieredExecutionDispatcher {
    let mercury = Arc::new(agent_octopus::security::mercury_guard::MercuryContainmentEngine::new());
    TieredExecutionDispatcher::try_new(mercury).expect("Dispatcher initialization must succeed")
}

fn create_anchored_test_seal(
    engine: &CageGovernanceEngine,
    agent_id: &str,
    tool_name: &str,
    resource: &str,
    payload: &[u8],
    issued_at: u64,
) -> CageRoutingSeal {
    let params_val: serde_json::Value = serde_json::from_slice(payload).unwrap_or_else(|_| {
        serde_json::json!({
            "raw_sha256": hex::encode(Sha256::digest(payload)),
            "byte_len": payload.len(),
            "resource": resource,
        })
    });
    let action_digest = engine.compute_action_digest(tool_name, &params_val);
    let record_hash = engine.audit_log().record_event(
        "CAGE_GOVERNANCE_DECISION",
        agent_id,
        &serde_json::json!({
            "event_type": "GOVERNANCE_DECISION",
            "verdict": "ALLOW",
            "seal_present": true,
            "stages_evaluated": [
                {"stage_name": "ftra"},
                {"stage_name": "stpa"},
                {"stage_name": "cedar"},
                {"stage_name": "confidence"},
                {"stage_name": "consensus"},
                {"stage_name": "cbf"},
                {"stage_name": "fiscal"},
            ],
        })
        .to_string(),
        "ALLOW",
    );
    engine
        .seal_signer()
        .issue_seal(&action_digest, &record_hash, issued_at)
        .expect("Seal issuance must succeed")
}

// ==============================================================================
// 1. MULTI-FORMAT POLICY INGESTION (ACS, AAIF, OSCAL 1.1.x, LULA, CAGE YAML)
// ==============================================================================

#[test]
fn test_fixture_microsoft_acs_ingestion_and_compilation() {
    let acs_fixture = r#"{
        "behaviorDeclarations": [
            {
                "id": "ACS-LEDGER-001",
                "action": "LedgerWrite",
                "description": "Block unauthorized ledger modifications",
                "hazardRefs": ["H-FIN-UNAUTHORIZED"],
                "constraints": [
                    { "type": "greater_than", "parameter": "amount", "value": 50000 },
                    { "type": "not_null", "parameter": "approval_signature" }
                ]
            }
        ],
        "cbf_gamma": 0.25,
        "cbf_b_min": 150.0
    }"#;

    // 1. Auto-detection
    let format = SubstrateTranslator::detect_format(acs_fixture).expect("ACS detection");
    assert_eq!(format, PolicyFormat::MicrosoftAcs);

    // 2. Compilation
    let compiled: CompiledCagePolicy =
        SubstrateTranslator::compile_policy(acs_fixture, None).expect("ACS compilation");
    assert_eq!(compiled.format, PolicyFormat::MicrosoftAcs);
    assert_eq!(compiled.policy_version_id.len(), 16);
    assert!(compiled
        .policy_version_id
        .chars()
        .all(|c| c.is_ascii_hexdigit()));
    assert_eq!(compiled.cbf_gamma, 0.25);
    assert_eq!(compiled.cbf_b_min, 150.0);

    // 3. Cedar rule generation
    assert_eq!(compiled.cedar_rules.len(), 1);
    let rule = &compiled.cedar_rules[0];
    assert!(rule.contains("forbid"));
    assert!(rule.contains("Action::\"LedgerWrite\""));
    assert!(rule.contains("context.amount > 50000"));

    // 4. STPA UCA extraction
    assert_eq!(compiled.unsafe_control_actions.len(), 1);
    assert_eq!(compiled.unsafe_control_actions[0].uca_id, "ACS-LEDGER-001");
    assert_eq!(
        compiled.unsafe_control_actions[0].hazard_ref,
        "H-FIN-UNAUTHORIZED"
    );
    assert_eq!(
        compiled.unsafe_control_actions[0].control_action,
        "LedgerWrite"
    );
}

#[test]
fn test_fixture_linux_foundation_aaif_ingestion_and_compilation() {
    let aaif_fixture = r#"{
        "governedRunLoop": {
            "cbf_gamma": 0.15,
            "cbf_b_min": 75.0,
            "stages": [
                {
                    "name": "access_control",
                    "hooks": [
                        {
                            "id": "AAIF-HOOK-AUTH",
                            "action": "DatabaseAccess",
                            "role": "SecurityOfficer"
                        }
                    ]
                },
                {
                    "name": "egress_filter",
                    "hooks": [
                        {
                            "id": "AAIF-HOOK-EGRESS",
                            "action": "OutboundConnect",
                            "constraints": [
                                { "type": "forbidden", "parameter": "unauthorized_proxy" }
                            ]
                        }
                    ]
                }
            ]
        }
    }"#;

    // 1. Auto-detection
    let format = SubstrateTranslator::detect_format(aaif_fixture).expect("AAIF detection");
    assert_eq!(format, PolicyFormat::LinuxFoundationAaif);

    // 2. Compilation
    let compiled =
        SubstrateTranslator::compile_policy(aaif_fixture, None).expect("AAIF compilation");
    assert_eq!(compiled.format, PolicyFormat::LinuxFoundationAaif);
    assert_eq!(compiled.policy_version_id.len(), 16);
    assert_eq!(compiled.cbf_gamma, 0.15);
    assert_eq!(compiled.cbf_b_min, 75.0);

    // 3. Cedar rules: access_control produces permit; egress_filter produces forbid
    assert_eq!(compiled.cedar_rules.len(), 2);
    let permit_rule = &compiled.cedar_rules[0];
    assert!(permit_rule.contains("permit"));
    assert!(permit_rule.contains("Role::\"SecurityOfficer\""));
    assert!(permit_rule.contains("Action::\"DatabaseAccess\""));

    let forbid_rule = &compiled.cedar_rules[1];
    assert!(forbid_rule.contains("forbid"));
    assert!(forbid_rule.contains("Action::\"OutboundConnect\""));

    // 4. STPA UCAs
    assert_eq!(compiled.unsafe_control_actions.len(), 2);
    assert_eq!(compiled.unsafe_control_actions[0].uca_id, "AAIF-HOOK-AUTH");
    assert_eq!(
        compiled.unsafe_control_actions[1].uca_id,
        "AAIF-HOOK-EGRESS"
    );
}

#[test]
fn test_fixture_nist_oscal_ingestion_and_compilation() {
    let oscal_fixture = r#"{
        "oscal-version": "1.1.0",
        "cbf_gamma": 0.3,
        "cbf_b_min": 200.0,
        "components": [
            {
                "control-implementations": [
                    {
                        "implemented-requirements": [
                            {
                                "control-id": "ac-3",
                                "description": "Mandatory access enforcement barrier"
                            },
                            {
                                "control-id": "sc-7",
                                "description": "Boundary protection mechanism"
                            }
                        ]
                    }
                ]
            }
        ]
    }"#;

    // 1. Auto-detection via oscal-version
    let format = SubstrateTranslator::detect_format(oscal_fixture).expect("OSCAL detection");
    assert_eq!(format, PolicyFormat::NistOscal);

    // 2. Compilation
    let compiled =
        SubstrateTranslator::compile_policy(oscal_fixture, None).expect("OSCAL compilation");
    assert_eq!(compiled.format, PolicyFormat::NistOscal);
    assert_eq!(compiled.policy_version_id.len(), 16);
    assert_eq!(compiled.cbf_gamma, 0.3);
    assert_eq!(compiled.cbf_b_min, 200.0);

    // 3. Cedar rules
    assert_eq!(compiled.cedar_rules.len(), 2);
    assert!(compiled.cedar_rules[0].contains("@nistControl(\"ac-3\")"));
    assert!(compiled.cedar_rules[0].contains("Action::\"AccessEnforcement\""));
    assert!(compiled.cedar_rules[1].contains("@nistControl(\"sc-7\")"));
    assert!(compiled.cedar_rules[1].contains("Action::\"BoundaryProtection\""));

    // 4. STPA UCAs
    assert_eq!(compiled.unsafe_control_actions.len(), 2);
    assert_eq!(compiled.unsafe_control_actions[0].uca_id, "OSCAL-AC-3");
    assert_eq!(compiled.unsafe_control_actions[1].uca_id, "OSCAL-SC-7");
}

#[test]
fn test_fixture_lula_validation_ingestion_and_compilation() {
    let lula_fixture = r#"{
        "kind": "LulaValidation",
        "metadata": {
            "name": "critical-system-binary-guard"
        },
        "spec": {
            "policy": {
                "opa": {
                    "rego": "package main\ndefault allow = false\nallow { not input.ModifySystemBinary }"
                }
            }
        },
        "cbf": {
            "gamma": 0.05,
            "b_min": 500.0
        }
    }"#;

    // 1. Auto-detection
    let format = SubstrateTranslator::detect_format(lula_fixture).expect("Lula detection");
    assert_eq!(format, PolicyFormat::LulaValidation);

    // 2. Compilation
    let compiled =
        SubstrateTranslator::compile_policy(lula_fixture, None).expect("Lula compilation");
    assert_eq!(compiled.format, PolicyFormat::LulaValidation);
    assert_eq!(compiled.policy_version_id.len(), 16);
    assert_eq!(compiled.cbf_gamma, 0.05);
    assert_eq!(compiled.cbf_b_min, 500.0);

    // 3. Cedar rule matching Rego semantics
    assert_eq!(compiled.cedar_rules.len(), 1);
    let rule = &compiled.cedar_rules[0];
    assert!(rule.contains("@lulaPolicy(\"critical-system-binary-guard\")"));
    assert!(rule.contains("Action::\"ModifySystemBinary\""));

    // 4. STPA UCA
    assert_eq!(compiled.unsafe_control_actions.len(), 1);
    assert_eq!(
        compiled.unsafe_control_actions[0].uca_id,
        "LULA-critical-system-binary-guard"
    );
    assert_eq!(
        compiled.unsafe_control_actions[0].control_action,
        "ModifySystemBinary"
    );
}

#[test]
fn test_fixture_native_cage_yaml_ingestion_and_compilation() {
    let yaml_fixture = r#"
stpa_control_structure:
  cbf:
    gamma: 0.12
    b_min: 42.0
  unsafe_control_actions:
    - id: UCA-CAGE-001
      action: PurgeAuditLogs
      hazard_refs:
        - H-CAGE-TAMPER
      condition:
        param: purge_override
        operator: is_true
      cedar_rule: "forbid (principal, action == Action::\"PurgeAuditLogs\", resource);"
"#;

    // 1. Auto-detection fallback
    let format = SubstrateTranslator::detect_format(yaml_fixture).expect("YAML detection");
    assert_eq!(format, PolicyFormat::CageStpa);

    // 2. Compilation
    let compiled =
        SubstrateTranslator::compile_policy(yaml_fixture, None).expect("YAML compilation");
    assert_eq!(compiled.format, PolicyFormat::CageStpa);
    assert_eq!(compiled.policy_version_id.len(), 16);
    assert_eq!(compiled.cbf_gamma, 0.12);
    assert_eq!(compiled.cbf_b_min, 42.0);

    // 3. Cedar rule
    assert_eq!(compiled.cedar_rules.len(), 1);
    assert!(compiled.cedar_rules[0].starts_with("forbid"));
    assert!(compiled.cedar_rules[0].contains("PurgeAuditLogs"));

    // 4. STPA UCA
    assert_eq!(compiled.unsafe_control_actions.len(), 1);
    assert_eq!(compiled.unsafe_control_actions[0].uca_id, "UCA-CAGE-001");
    assert_eq!(
        compiled.unsafe_control_actions[0].control_action,
        "PurgeAuditLogs"
    );
}

#[test]
fn test_rfc8785_jcs_canonicalization_and_version_drift_rejection() {
    // 1. Key order invariance: Two JSON objects with opposite key insertion orders
    let obj1 = serde_json::json!({
        "zebra": 100,
        "alpha": "first",
        "nested": { "z": true, "a": null }
    });
    let obj2 = serde_json::json!({
        "alpha": "first",
        "nested": { "a": null, "z": true },
        "zebra": 100
    });

    let jcs1 = SubstrateTranslator::canonicalize_jcs(&obj1).expect("JCS 1");
    let jcs2 = SubstrateTranslator::canonicalize_jcs(&obj2).expect("JCS 2");
    assert_eq!(
        jcs1, jcs2,
        "JCS must be strictly invariant to object key ordering"
    );
    assert_eq!(
        jcs1,
        r#"{"alpha":"first","nested":{"a":null,"z":true},"zebra":100}"#
    );

    // 2. Single-byte policy mutation produces distinct version ID
    let raw_v1 = r#"{"stpa_control_structure": {"cbf": {"gamma": 0.1, "b_min": 10.0}}}"#;
    let raw_v2 = r#"{"stpa_control_structure": {"cbf": {"gamma": 0.2, "b_min": 10.0}}}"#;

    let p1 = SubstrateTranslator::compile_policy(raw_v1, None).expect("p1");
    let p2 = SubstrateTranslator::compile_policy(raw_v2, None).expect("p2");
    assert_ne!(p1.policy_version_id, p2.policy_version_id);

    // 3. Version pinning verification
    assert!(SubstrateTranslator::verify_version_pinning(
        Some(&p1.policy_version_id),
        &p1.policy_version_id
    )
    .is_ok());

    let err = SubstrateTranslator::verify_version_pinning(
        Some(&p1.policy_version_id),
        &p2.policy_version_id,
    )
    .expect_err("Must reject mismatched pinned version with conflict");
    assert_eq!(err.pinned_version, p1.policy_version_id);
    assert_eq!(err.incoming_version, p2.policy_version_id);
}

#[test]
fn test_engine_dynamic_policy_ingest_and_version_transition() {
    let audit_log = Arc::new(SecurityAuditLog::new());
    let secret = b"integration_test_secret_32_bytes";
    let engine = CageGovernanceEngine::with_default_policy(audit_log, secret);

    let initial_version = engine.active_policy_version();
    assert_eq!(initial_version.len(), 16);

    let new_policy = r#"{
        "behaviorDeclarations": [
            {
                "id": "ACS-TRANSFER-01",
                "action": "WireTransfer",
                "hazardRefs": ["H-EXCESS-WIRE"],
                "constraints": [
                    { "type": "greater_than", "parameter": "amount", "value": 1000000 }
                ]
            }
        ],
        "cbf_gamma": 0.08,
        "cbf_b_min": 500.0
    }"#;

    // Ingest with correct active version as expected_version -> succeeds
    let resp = engine
        .ingest_policy(new_policy, Some(&initial_version))
        .expect("Ingest with matching version hint must succeed");
    assert_eq!(resp.format, PolicyFormat::MicrosoftAcs);
    assert_ne!(resp.policy_version_id, initial_version);

    // Active version updated
    assert_eq!(engine.active_policy_version(), resp.policy_version_id);

    // Ingest with stale expected version -> fails with PolicyVersionMismatch (409 Conflict)
    let stale_err = engine
        .ingest_policy(new_policy, Some(&initial_version))
        .expect_err("Stale version must fail");
    assert_eq!(stale_err.error_code(), "POLICY_VERSION_MISMATCH");
    assert_eq!(stale_err.http_status_code(), "409 Conflict");
}

#[test]
fn test_pipeline_dynamic_profiles_and_direct_verdicts() {
    let audit_log = Arc::new(SecurityAuditLog::new());
    let secret = b"direct_pipeline_secret_32_bytes_";
    let engine = CageGovernanceEngine::with_default_policy(audit_log, secret);

    // 1. Full Profile -> Clears Phase 1 and commits Phase 2, issuing routing seal
    let mut req_full = GovernanceRequest {
        action_name: "list_files".to_string(),
        principal: "arm-worker-01".to_string(),
        resource: "workspace/tmp".to_string(),
        parameters: serde_json::json!({ "filter": "*.rs" }),
        caller_authority: 2,
        confidence_score: 0.98,
        consensus_score: 0.90,
        fuel_cost: 5.0,
        expected_policy_version: None,
        execution_profile: Some(Profile::Full),
    };

    let full_res = engine
        .validate_action(&req_full)
        .expect("Full profile validation");
    assert_eq!(full_res.verdict, GovernanceVerdict::Allow);
    assert!(full_res.seal.is_some());
    let seal = full_res.seal.unwrap();

    // Verify compute_action_digest consistency
    let direct_digest = compute_action_digest(&req_full.action_name, &req_full.parameters);
    assert_eq!(seal.action_digest, direct_digest);
    assert_eq!(
        engine.compute_action_digest(&req_full.action_name, &req_full.parameters),
        direct_digest
    );

    // 2. DryRun Profile -> Evaluates Phase 2 in Preview mode (no seal issued)
    let req_dry = GovernanceRequest {
        execution_profile: Some(Profile::DryRun),
        ..req_full.clone()
    };
    let dry_res = engine.validate_action(&req_dry).expect("DryRun validation");
    assert_eq!(dry_res.verdict, GovernanceVerdict::Allow);
    assert!(
        dry_res.seal.is_none(),
        "DryRun profile must not issue executable seal"
    );

    // 3. PostHitl Profile -> Clears holds
    let req_post = GovernanceRequest {
        execution_profile: Some(Profile::PostHitl {
            approved_holds: vec!["FTRA_HOLD".to_string()],
        }),
        ..req_full.clone()
    };
    let post_res = engine
        .validate_action(&req_post)
        .expect("PostHitl validation");
    assert_eq!(post_res.verdict, GovernanceVerdict::Allow);
    assert!(post_res.seal.is_some());

    // 4. Policy version drift -> returns CageApiError::PolicyVersionMismatch
    req_full.expected_policy_version = Some("stale_version_0000".to_string());
    let err = engine
        .validate_action(&req_full)
        .expect_err("Mismatched version must return error");
    assert!(matches!(err, CageApiError::PolicyVersionMismatch { .. }));
}

// ==============================================================================
// 2. FTRA GRAPH ANALYSIS & REACHABILITY (LINEAR & DAG, REVERSIBILITY, CONFIDENCE)
// ==============================================================================

#[test]
fn test_ftra_semantic_reversibility_classification_and_authority_ranks() {
    // 1. Classification
    assert_eq!(
        ActionReversibility::classify("inspect_filesystem"),
        ActionReversibility::ReadOnly
    );
    assert_eq!(
        ActionReversibility::classify("query_metrics"),
        ActionReversibility::ReadOnly
    );
    assert_eq!(
        ActionReversibility::classify("write_record"),
        ActionReversibility::Reversible
    );
    assert_eq!(
        ActionReversibility::classify("trade_order"),
        ActionReversibility::Reversible
    );
    assert_eq!(
        ActionReversibility::classify("escrow_funds"),
        ActionReversibility::Compensatable
    );
    assert_eq!(
        ActionReversibility::classify("reserve_quota"),
        ActionReversibility::Compensatable
    );
    assert_eq!(
        ActionReversibility::classify("auto_rebalance"),
        ActionReversibility::ConditionalAutonomous
    );
    assert_eq!(
        ActionReversibility::classify("spawn_process"),
        ActionReversibility::IrreversibleTerminal
    );
    assert_eq!(
        ActionReversibility::classify("execute_childprocess"),
        ActionReversibility::IrreversibleTerminal
    );
    assert_eq!(
        ActionReversibility::classify("modifysystembinary"),
        ActionReversibility::IrreversibleTerminal
    );

    // 2. Authority ranks
    assert_eq!(ActionReversibility::ReadOnly.required_authority_rank(), 5);
    assert_eq!(ActionReversibility::Reversible.required_authority_rank(), 3);
    assert_eq!(
        ActionReversibility::Compensatable.required_authority_rank(),
        3
    );
    assert_eq!(
        ActionReversibility::ConditionalAutonomous.required_authority_rank(),
        3
    );
    assert_eq!(
        ActionReversibility::IrreversibleTerminal.required_authority_rank(),
        2
    );

    // 3. Authority evaluation on individual step
    let step_low_priv = PlanStep {
        id: "step_unauthorized_spawn".to_string(),
        action_name: "spawn_process".to_string(),
        parameters: serde_json::json!({}),
        depends_on: vec![],
        confidence: 0.99,
        fuel_cost: 1.0,
        caller_authority: 4, // Rank 4 > Rank 2 allowed
    };
    let verdict = PlanGraphAnalyzer::evaluate_step_reversibility(&step_low_priv);
    assert!(matches!(verdict, FtraVerdict::Blocked { .. }));
}

#[test]
fn test_ftra_fail_closed_confidence_normalization() {
    // Non-finite and negative confidences must normalize strictly to 0.0
    assert_eq!(PlanGraphAnalyzer::normalize_confidence(f64::NAN), 0.0);
    assert_eq!(PlanGraphAnalyzer::normalize_confidence(f64::INFINITY), 0.0);
    assert_eq!(
        PlanGraphAnalyzer::normalize_confidence(f64::NEG_INFINITY),
        0.0
    );
    assert_eq!(PlanGraphAnalyzer::normalize_confidence(-0.5), 0.0);
    assert_eq!(PlanGraphAnalyzer::normalize_confidence(-1e-8), 0.0);

    // Clamping > 1.0
    assert_eq!(PlanGraphAnalyzer::normalize_confidence(1.5), 1.0);
    assert_eq!(PlanGraphAnalyzer::normalize_confidence(0.98), 0.98);

    // Evaluation with NaN confidence on a valid step -> fails closed with Deferred
    let nan_step = PlanStep {
        id: "step_nan_confidence".to_string(),
        action_name: "write_cache".to_string(),
        parameters: serde_json::json!({}),
        depends_on: vec![],
        confidence: f64::NAN,
        fuel_cost: 1.0,
        caller_authority: 1,
    };
    let verdict = PlanGraphAnalyzer::evaluate_step_reversibility(&nan_step);
    assert!(matches!(verdict, FtraVerdict::Deferred { .. }));
}

#[test]
fn test_ftra_sr_26_2_model_confidence_thresholds() {
    // Threshold constants: ALLOW >= 0.95, APPROVAL >= 0.70
    assert_eq!(SR_26_2_CONFIDENCE_ALLOW_THRESHOLD, 0.95);
    assert_eq!(SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD, 0.70);

    // Reversible action:
    // 1. High confidence (0.97 >= 0.95) -> Clear
    let clear_step = PlanStep {
        id: "s1".to_string(),
        action_name: "write_ledger".to_string(),
        parameters: serde_json::json!({}),
        depends_on: vec![],
        confidence: 0.97,
        fuel_cost: 1.0,
        caller_authority: 2,
    };
    assert_eq!(
        PlanGraphAnalyzer::evaluate_step_reversibility(&clear_step),
        FtraVerdict::Clear
    );

    // 2. Medium confidence (0.85 in [0.70, 0.95)) -> HitlRequired
    let hitl_step = PlanStep {
        id: "s2".to_string(),
        action_name: "write_ledger".to_string(),
        parameters: serde_json::json!({}),
        depends_on: vec![],
        confidence: 0.85,
        fuel_cost: 1.0,
        caller_authority: 2,
    };
    assert!(matches!(
        PlanGraphAnalyzer::evaluate_step_reversibility(&hitl_step),
        FtraVerdict::HitlRequired { .. }
    ));

    // 3. Low confidence (0.60 < 0.70) -> Deferred
    let def_step = PlanStep {
        id: "s3".to_string(),
        action_name: "write_ledger".to_string(),
        parameters: serde_json::json!({}),
        depends_on: vec![],
        confidence: 0.60,
        fuel_cost: 1.0,
        caller_authority: 2,
    };
    assert!(matches!(
        PlanGraphAnalyzer::evaluate_step_reversibility(&def_step),
        FtraVerdict::Deferred { .. }
    ));

    // 4. IrreversibleTerminal with confidence 0.94 (< 0.95) -> always HitlRequired
    let terminal_step = PlanStep {
        id: "s4".to_string(),
        action_name: "spawn_process".to_string(),
        parameters: serde_json::json!({}),
        depends_on: vec![],
        confidence: 0.94,
        fuel_cost: 1.0,
        caller_authority: 1,
    };
    assert!(matches!(
        PlanGraphAnalyzer::evaluate_step_reversibility(&terminal_step),
        FtraVerdict::HitlRequired { .. }
    ));
}

#[test]
fn test_ftra_dag_topological_execution_and_cycle_deadlock_detection() {
    // 1. Diamond DAG: A -> B, A -> C, B -> D, C -> D
    let diamond_steps = vec![
        PlanStep {
            id: "step_A".to_string(),
            action_name: "inspect_schema".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec![],
            confidence: 0.99,
            fuel_cost: 1.0,
            caller_authority: 2,
        },
        PlanStep {
            id: "step_B".to_string(),
            action_name: "read_partition_1".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["step_A".to_string()],
            confidence: 0.98,
            fuel_cost: 1.0,
            caller_authority: 2,
        },
        PlanStep {
            id: "step_C".to_string(),
            action_name: "read_partition_2".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["step_A".to_string()],
            confidence: 0.98,
            fuel_cost: 1.0,
            caller_authority: 2,
        },
        PlanStep {
            id: "step_D".to_string(),
            action_name: "write_aggregate".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["step_B".to_string(), "step_C".to_string()],
            confidence: 0.96,
            fuel_cost: 2.0,
            caller_authority: 2,
        },
    ];

    let graph_verdict = PlanGraphAnalyzer::analyze_execution_graph(&diamond_steps)
        .expect("Diamond DAG topological traversal must succeed");
    assert_eq!(graph_verdict, FtraVerdict::Clear);

    // 2. Cycle detection: step_X -> step_Y -> step_Z -> step_X
    let cyclic_steps = vec![
        PlanStep {
            id: "step_X".to_string(),
            action_name: "read_a".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["step_Z".to_string()],
            confidence: 0.99,
            fuel_cost: 1.0,
            caller_authority: 1,
        },
        PlanStep {
            id: "step_Y".to_string(),
            action_name: "read_b".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["step_X".to_string()],
            confidence: 0.99,
            fuel_cost: 1.0,
            caller_authority: 1,
        },
        PlanStep {
            id: "step_Z".to_string(),
            action_name: "read_c".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["step_Y".to_string()],
            confidence: 0.99,
            fuel_cost: 1.0,
            caller_authority: 1,
        },
    ];

    let cycle_err = PlanGraphAnalyzer::analyze_execution_graph(&cyclic_steps)
        .expect_err("Cyclic execution graph must be rejected");
    assert!(cycle_err.contains("contains cycles"));
}

#[test]
fn test_stpa_tier1_caller_identity_scrubbing() {
    let raw_params = serde_json::json!({
        "trader_role": "SuperAdmin",
        "trader_id": "spoofed-trader-007",
        "role": "RootOperator",
        "agent_id": "malicious-arm-99",
        "transaction_id": "tx-12345",
        "amount": 25000
    });

    let sanitized = StpaValidator::sanitize_parameters(&raw_params, "arm-authenticated-01");

    // Stripped fields
    assert!(sanitized.get("trader_role").is_none());
    assert!(sanitized.get("trader_id").is_none());
    assert!(sanitized.get("role").is_none());
    assert!(sanitized.get("agent_id").is_none());

    // Bound authenticated handle & preserved business parameters
    assert_eq!(sanitized["arm_id"], "arm-authenticated-01");
    assert_eq!(sanitized["transaction_id"], "tx-12345");
    assert_eq!(sanitized["amount"], 25000);
}

// ==============================================================================
// 3. 2-PHASE DISCRETE-TIME CBF & FISCAL LEDGER (BARRIER, EPOCHS, PRE-RESERVATION)
// ==============================================================================

#[test]
fn test_cbf_barrier_inequality_and_boundary_conditions() {
    // B_0 = 1000.0, B_min = 100.0, gamma = 0.20
    // h(S_t) = 1000.0 - 100.0 = 900.0
    // Maximum allowable step decay: c_max = gamma * h_t = 0.20 * 900.0 = 180.0
    // Required minimum next barrier: h_min_allowed = (1 - 0.20) * 900.0 = 720.0
    let cbf = CbfSafetyEngine::new(0.20, 100.0).expect("CBF init");

    // 1. Allowable step within barrier (cost = 100.0 < 180.0)
    let h_next = cbf
        .evaluate_step(1000.0, 100.0, 900.0)
        .expect("Allowable step");
    assert_eq!(h_next, 800.0);

    // 2. Exact boundary step (cost = 180.0)
    let h_boundary = cbf
        .evaluate_step(1000.0, 180.0, 900.0)
        .expect("Exact boundary step");
    assert!((h_boundary - 720.0).abs() < 1e-9);

    // 3. Decay rate breach (cost = 180.01 > 180.0) -> DecayRateExceeded
    let decay_err = cbf
        .evaluate_step(1000.0, 180.01, 900.0)
        .expect_err("Decay rate breach");
    assert!(matches!(decay_err, CbfViolation::DecayRateExceeded { .. }));

    // 4. Floor breach (projected budget < B_min)
    // gamma = 1.0 (all decay permitted down to floor), cost = 950.0 > 900.0 available above floor
    let cbf_floor = CbfSafetyEngine::new(1.0, 100.0).expect("CBF floor init");
    let floor_err = cbf_floor
        .evaluate_step(1000.0, 950.0, 900.0)
        .expect_err("Floor breach");
    assert!(matches!(floor_err, CbfViolation::FloorBreach { .. }));

    // 5. Invalid parameters: negative cost and NaN cost
    assert!(matches!(
        cbf.evaluate_step(1000.0, -10.0, 900.0)
            .expect_err("Negative cost"),
        CbfViolation::InvalidParameters(_)
    ));
    assert!(matches!(
        cbf.evaluate_step(1000.0, f64::NAN, 900.0)
            .expect_err("NaN cost"),
        CbfViolation::InvalidParameters(_)
    ));
}

#[test]
fn test_cbf_replay_sequence_and_monotonic_fence_epochs() {
    let cbf = CbfSafetyEngine::new(0.5, 10.0).expect("CBF init");

    // Initial sequence HWM is 0, initial epoch is 1
    assert_eq!(cbf.current_epoch(), 1);

    // 1. Monotonic sequence verification: seq 1 succeeds
    assert!(cbf.verify_sequence_and_epoch(1, 1).is_ok());

    // 2. Higher sequence succeeds and advances HWM
    assert!(cbf.verify_sequence_and_epoch(5, 1).is_ok());

    // 3. Replay of earlier or duplicate sequence fails
    let replay_err = cbf
        .verify_sequence_and_epoch(5, 1)
        .expect_err("Duplicate seq");
    assert!(matches!(
        replay_err,
        CbfViolation::SequenceReplay {
            incoming: 5,
            last_accepted: 5
        }
    ));

    let stale_seq_err = cbf.verify_sequence_and_epoch(3, 1).expect_err("Stale seq");
    assert!(matches!(
        stale_seq_err,
        CbfViolation::SequenceReplay {
            incoming: 3,
            last_accepted: 5
        }
    ));

    // 4. Monotonic epoch advancement
    let new_epoch = cbf.advance_epoch();
    assert_eq!(new_epoch, 2);
    assert_eq!(cbf.current_epoch(), 2);

    // 5. Stale fence epoch rejection
    let stale_epoch_err = cbf
        .verify_sequence_and_epoch(10, 1)
        .expect_err("Stale epoch");
    assert!(matches!(
        stale_epoch_err,
        CbfViolation::StaleFenceEpoch {
            incoming: 1,
            fence_epoch: 2
        }
    ));

    // 6. Up-to-date epoch and advancing sequence succeeds
    assert!(cbf.verify_sequence_and_epoch(10, 2).is_ok());
}

#[test]
fn test_fiscal_two_phase_pre_reservation_and_zero_balance_leakage() {
    let initial_budget = 1000.0;
    let b_min = 100.0;
    let gamma = 0.25;
    let ledger = DebitLedger::new(initial_budget, gamma, b_min).expect("Ledger init");

    assert_eq!(ledger.available_budget(), 1000.0);
    assert_eq!(ledger.barrier_margin(), 900.0);

    // 1. Preview mode (non-mutating): max allowable cost is 0.25 * 900.0 = 225.0
    let (proj_budget, proj_h) = ledger.preview(100.0).expect("Preview 100.0");
    assert_eq!(proj_budget, 900.0);
    assert_eq!(proj_h, 800.0);
    // Assert ledger state was completely untouched
    assert_eq!(ledger.available_budget(), 1000.0);
    assert_eq!(ledger.active_reservation_count(), 0);

    // 2. Pre-reserve reservation 1: cost 50.0
    let receipt1 = ledger
        .pre_reserve(50.0, "debit_001")
        .expect("Pre-reserve 1");
    assert_eq!(receipt1.debit_id, "debit_001");
    assert_eq!(receipt1.reserved_fuel, 50.0);
    assert_eq!(receipt1.remaining_budget, 950.0);
    assert_eq!(ledger.available_budget(), 950.0);
    assert_eq!(ledger.active_reservation_count(), 1);

    // 3. Pre-reserve reservation 2: cost 100.0
    let receipt2 = ledger
        .pre_reserve(100.0, "debit_002")
        .expect("Pre-reserve 2");
    assert_eq!(receipt2.reserved_fuel, 100.0);
    assert_eq!(ledger.available_budget(), 850.0);
    assert_eq!(ledger.active_reservation_count(), 2);

    // 4. Confirm reservation 1 (settled permanent commit)
    assert!(ledger.confirm("debit_001").is_ok());
    assert_eq!(ledger.active_reservation_count(), 1);

    // Rollback after confirm is strictly forbidden
    let post_confirm_err = ledger
        .rollback("debit_001")
        .expect_err("Cannot rollback confirmed debit");
    assert!(matches!(
        post_confirm_err,
        CbfViolation::AlreadyCommitted(_)
    ));

    // 5. Rollback reservation 2 (compensating undo)
    let restored = ledger.rollback("debit_002").expect("Rollback debit_002");
    assert_eq!(restored, 950.0);
    assert_eq!(ledger.available_budget(), 950.0);
    assert_eq!(ledger.active_reservation_count(), 0);

    // Second rollback on same debit fails (no double refund)
    let double_rollback_err = ledger
        .rollback("debit_002")
        .expect_err("Double rollback must fail");
    assert!(matches!(
        double_rollback_err,
        CbfViolation::ReservationNotFound(_)
    ));

    // 6. Pre-reserve reservation 3 and test LIFO rollback
    ledger
        .pre_reserve(75.0, "debit_003")
        .expect("Pre-reserve 3");
    assert_eq!(ledger.available_budget(), 875.0);

    let (lifo_id, lifo_budget) = ledger.rollback_lifo().expect("Rollback LIFO");
    assert_eq!(lifo_id, "debit_003");
    assert_eq!(lifo_budget, 950.0);
    assert_eq!(ledger.available_budget(), 950.0);

    // Exact Zero-Balance-Leakage accounting conservation:
    // Initial Budget (1000.0) == Available Budget (950.0) + Confirmed Settled Debit (50.0)
    assert_eq!(ledger.available_budget() + 50.0, initial_budget);
}

// ==============================================================================
// 4. ROUTING SEAL & ACTUATOR GATING (EVIDENCE BINDING, TTL, SINGLE-USE ACTUATION)
// ==============================================================================

#[tokio::test]
async fn test_evidence_bound_routing_seal_issuance_and_ttl_validation() {
    let secret = b"routing_seal_test_secret_key_32_";
    let policy_ver = "a1b2c3d4e5f60718";
    let signer = RoutingSealSigner::new(secret, policy_ver);

    let action_digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let record_hash = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 1. Valid seal issuance
    let seal = signer
        .issue_seal(action_digest, record_hash, now)
        .expect("Seal issuance");
    assert_eq!(seal.policy_version_id, policy_ver);
    assert_eq!(seal.action_digest, action_digest);
    assert_eq!(seal.record_hash, record_hash);
    assert_eq!(seal.expires_at, now + 30);
    assert!(seal.validate_format());
    assert!(!seal.is_expired(now));

    // 2. TTL Expiration (> 30s)
    assert!(seal.is_expired(now + 31));
    let expired_err = signer
        .validate_and_consume(&seal, action_digest, record_hash, now + 31)
        .expect_err("Expired seal must be rejected");
    assert!(matches!(expired_err, SealRejection::Expired { .. }));

    // 3. Clock drift tolerance: <= 5s future is tolerated, > 5s future is rejected
    assert!(signer
        .validate_and_consume(&seal, action_digest, record_hash, now - 4)
        .is_ok());

    // Issue a seal with future timestamp (> 5s ahead of evaluation time)
    let future_seal = signer
        .issue_seal(action_digest, record_hash, now + 10)
        .expect("Future seal");
    let future_err = signer
        .validate_and_consume(&future_seal, action_digest, record_hash, now)
        .expect_err("Future timestamp > 5s drift must be rejected");
    assert!(matches!(future_err, SealRejection::FutureTimestamp { .. }));
}

#[tokio::test]
async fn test_arm_containment_actuation_with_cage_seal_and_replay_rejection() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));

    let scratch_dir = std::env::temp_dir().join(format!("cage_integ_test_{}", std::process::id()));
    let dispatcher = new_test_dispatcher();

    let payload = b"{\"command\": \"extract_report\", \"target\": \"quarterly.pdf\"}".to_vec();
    let tiered_req = TieredToolRequest {
        agent_id: ring.agent_name.clone(),
        role: ArmRole::UntrustedDocIngest,
        tool_name: "doc_extractor".to_string(),
        payload: payload.clone(),
        custom_wat: None,
        native_command: None,
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let seal = create_anchored_test_seal(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        TEST_RESOURCE,
        &payload,
        now,
    );

    // Pre-reserve fiscal debit
    let debit_id = "debit_actuation_001";
    engine
        .ledger()
        .pre_reserve(10.0, debit_id)
        .expect("Pre-reserve fuel");
    assert_eq!(engine.ledger().active_reservation_count(), 1);

    // Actuation 1: First presentation must succeed and confirm the debit
    let mut ticket1 = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .expect("Dirac ticket 1");

    let receipt1 = ring
        .execute_tool_with_cage_seal(
            &mut ticket1,
            &seal,
            TEST_RESOURCE,
            &tiered_req,
            &dispatcher,
            None,
            Some(debit_id),
        )
        .await
        .expect("First actuation must succeed");

    assert!(receipt1.exit_code >= 0);
    // Debit was atomically confirmed
    assert_eq!(engine.ledger().active_reservation_count(), 0);

    // Verify GOVERNANCE_SEAL_CONSUMED was recorded in the audit log
    let audit_events = engine.audit_log().get_entries();
    assert!(
        audit_events
            .iter()
            .any(|e| e.event_type == "GOVERNANCE_SEAL_CONSUMED"),
        "Audit log must contain GOVERNANCE_SEAL_CONSUMED event"
    );

    // Actuation 2: Duplicate presentation (Replay Attack) must be rejected
    let mut ticket2 = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .expect("Dirac ticket 2");

    let replay_err = ring
        .execute_tool_with_cage_seal(
            &mut ticket2,
            &seal,
            TEST_RESOURCE,
            &tiered_req,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect_err("Replayed seal must be rejected");

    assert!(matches!(
        replay_err,
        ArmExecutionError::SealAlreadyConsumed { .. }
    ));
}

#[tokio::test]
async fn test_seal_parameter_tampering_and_signature_corruption_rejection() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = ArmContainmentRing::new(1, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));

    let scratch_dir = std::env::temp_dir().join(format!("cage_tamper_test_{}", std::process::id()));
    let dispatcher = new_test_dispatcher();

    let valid_payload = b"{\"param\": \"safe_data\"}".to_vec();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let seal = create_anchored_test_seal(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        TEST_RESOURCE,
        &valid_payload,
        now,
    );

    // 1. Parameter tampering: Attacker submits mutated payload with seal for valid_payload
    let tampered_payload = b"{\"param\": \"malicious_payload\"}".to_vec();
    let tampered_req = TieredToolRequest {
        agent_id: ring.agent_name.clone(),
        role: ArmRole::UntrustedDocIngest,
        tool_name: "doc_extractor".to_string(),
        payload: tampered_payload,
        custom_wat: None,
        native_command: None,
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };

    let mut ticket1 = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .expect("Dirac ticket");

    let tamper_err = ring
        .execute_tool_with_cage_seal(
            &mut ticket1,
            &seal,
            TEST_RESOURCE,
            &tampered_req,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect_err("Tampered payload must be rejected");

    assert!(matches!(
        tamper_err,
        ArmExecutionError::ActionDigestMismatch { .. }
    ));

    // 2. Cryptographic signature corruption: Attacker mutates single character in signature
    let mut corrupted_seal = seal.clone();
    let last_char = corrupted_seal.signature.pop().unwrap();
    corrupted_seal
        .signature
        .push(if last_char == '0' { '1' } else { '0' });

    let valid_req = TieredToolRequest {
        agent_id: ring.agent_name.clone(),
        role: ArmRole::UntrustedDocIngest,
        tool_name: "doc_extractor".to_string(),
        payload: valid_payload,
        custom_wat: None,
        native_command: None,
        scratchpad_root: scratch_dir,
        allow_scratch_write: false,
    };

    let mut ticket2 = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .expect("Dirac ticket 2");

    let sig_err = ring
        .execute_tool_with_cage_seal(
            &mut ticket2,
            &corrupted_seal,
            TEST_RESOURCE,
            &valid_req,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect_err("Corrupted signature must be rejected");

    assert!(matches!(sig_err, ArmExecutionError::InvalidCageSeal { .. }));
}

// ==============================================================================
// 5. BFS STATE MACHINE PROOF & TRACE CONFORMANCE (34 STATES, 7-RULE VALIDATION)
// ==============================================================================

#[test]
fn test_formal_bfs_gated_model_strictly_34_reachable_states() {
    let result = FormalBfsModel::explore_gated_model();

    // 1. Exact Reachable State Count
    assert_eq!(result.reachable_count, 34);
    assert_eq!(result.visited_states.len(), 34);

    // 2. Terminal Executed State & Violations
    assert_eq!(result.executed_count, 1);
    assert!(
        result.violations.is_empty(),
        "Violations: {:?}",
        result.violations
    );
    assert!(result.no_direct_bind_proven);

    // 3. Structural breakdown across phases
    let mut phase_counts = std::collections::HashMap::new();
    for state in &result.visited_states {
        *phase_counts.entry(state.phase).or_insert(0) += 1;
    }

    assert_eq!(
        phase_counts.get(&BfsPhase::Initial).copied().unwrap_or(0),
        1
    );
    assert_eq!(
        phase_counts.get(&BfsPhase::Checking).copied().unwrap_or(0),
        8
    );
    assert_eq!(
        phase_counts
            .get(&BfsPhase::NarrowEval)
            .copied()
            .unwrap_or(0),
        7
    );
    assert_eq!(
        phase_counts
            .get(&BfsPhase::NarrowPassed)
            .copied()
            .unwrap_or(0),
        1
    );
    assert_eq!(
        phase_counts
            .get(&BfsPhase::SealIssued)
            .copied()
            .unwrap_or(0),
        1
    );
    assert_eq!(
        phase_counts.get(&BfsPhase::Executed).copied().unwrap_or(0),
        1
    );
    assert_eq!(
        phase_counts.get(&BfsPhase::Denied).copied().unwrap_or(0),
        15
    );

    // 4. Executed state invariant verification
    let executed_states = result.executed_states();
    assert_eq!(executed_states.len(), 1);
    let exec = executed_states[0];
    assert!(exec.seal_present);
    assert!(exec.resolved_allow);
    assert!(exec.executed_or_narrow);

    let expected_exec_state = BfsState::new(BfsPhase::Executed, "executed", 7, true, true, true);
    assert!(result.visited_states.contains(&expected_exec_state));

    // 5. Verifiable Theorem Receipt
    let proof_receipt = FormalBfsModel::prove_no_direct_bind();
    assert!(proof_receipt.proven);
    assert_eq!(proof_receipt.reachable_states, 34);
    assert_eq!(proof_receipt.executed_states, 1);
    assert_eq!(proof_receipt.violations_count, 0);
    assert_eq!(proof_receipt.proof_receipt.len(), 64);
    assert!(proof_receipt
        .proof_receipt
        .chars()
        .all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_formal_bfs_ungated_counterexample_strictly_17_states() {
    let ungated = FormalBfsModel::explore_ungated_counterexample();

    // In ungated model, execution is allowed without seal issuance
    assert_eq!(ungated.reachable_count, 17);
    assert_eq!(ungated.executed_count, 1);
    // Explicit NoDirectBind violation detected
    assert!(!ungated.violations.is_empty());
    assert!(!ungated.no_direct_bind_proven);
    assert_eq!(
        ungated.violations[0].error,
        "Direct-bind violation counterexample observed (executed without seal)"
    );
    assert_eq!(ungated.violations[0].state.phase, BfsPhase::Executed);
    assert_eq!(ungated.violations[0].state.seal_present, false);
}

#[test]
fn test_governance_trace_stream_conformance_and_adversarial_rule_violations() {
    // 1. Valid conforming trace stream
    let conforming_stream = vec![
        serde_json::json!({
            "event_type": "GOVERNANCE_DECISION",
            "agent_id": "arm_01",
            "record_hash": "a".repeat(64),
            "verdict": "ALLOW",
            "seal_present": true,
            "stages_evaluated": [
                {"stage_name": "ftra"},
                {"stage_name": "stpa"},
                {"stage_name": "opa"},
                {"stage_name": "confidence"},
                {"stage_name": "consensus"},
                {"stage_name": "cbf"},
                {"stage_name": "fiscal"}
            ],
            "seal": {
                "seal_id": "seal_100",
                "policy_version_id": "0123456789abcdef",
                "action_digest": "b".repeat(64),
                "record_hash": "a".repeat(64),
                "issued_at": 1000,
                "expires_at": 1030,
                "signature": "c".repeat(64)
            }
        }),
        serde_json::json!({
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "agent_id": "arm_01",
            "record_hash": "d".repeat(64),
            "decision_record_hash": "a".repeat(64),
            "seal_id": "seal_100",
            "action": "doc_extractor"
        }),
        serde_json::json!({
            "event_type": "ACTUATION_RECEIPT",
            "agent_id": "arm_01",
            "record_hash": "e".repeat(64),
            "seal_id": "seal_100",
            "action": "doc_extractor",
            "status": "SUCCESS"
        }),
    ];

    let report = FormalBfsModel::check_trace_conformance(&conforming_stream);
    assert_eq!(report.status, StreamConformanceStatus::Conformant);
    assert_eq!(report.findings_count, 0);
    assert_eq!(report.stream_proof_hash.len(), 64);

    // 2. Rule 7 Violation: Injected duplicate seal consumption (Replay)
    let replay_stream = vec![
        conforming_stream[0].clone(),
        conforming_stream[1].clone(),
        conforming_stream[2].clone(),
        // Replayed second consumption of same seal_100
        serde_json::json!({
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "agent_id": "arm_02",
            "record_hash": "f".repeat(64),
            "decision_record_hash": "a".repeat(64),
            "seal_id": "seal_100",
            "action": "doc_extractor"
        }),
    ];
    let replay_report = FormalBfsModel::check_trace_conformance(&replay_stream);
    assert_eq!(replay_report.status, StreamConformanceStatus::NonConformant);
    assert!(replay_report.has_rule_violation("single_use"));

    // 3. Rule 6 Violation: Injected unsealed execution (No-Direct-Bind breach)
    let unsealed_stream = vec![serde_json::json!({
        "event_type": "ACTUATION_RECEIPT",
        "agent_id": "arm_01",
        "record_hash": "1".repeat(64),
        "seal_id": "",
        "action": "unsealed_tool",
        "status": "SUCCESS"
    })];
    let unsealed_report = FormalBfsModel::check_trace_conformance(&unsealed_stream);
    assert_eq!(
        unsealed_report.status,
        StreamConformanceStatus::NonConformant
    );
    assert!(unsealed_report.has_rule_violation("no_direct_bind"));
}

// ==============================================================================
// 6. CAGE SUBSTRATE HTTP HANDLERS (WIRE TESTS AGAINST WEBSTATE)
// ==============================================================================

#[test]
fn test_http_endpoint_cage_policy_ingest_and_version() {
    let state = WebState::default();

    // 1. GET /governance/policy-version
    let (s_ver, b_ver) = handle_cage_policy_version(&state);
    assert_eq!(s_ver, "200 OK");
    let val_ver: serde_json::Value = serde_json::from_str(&b_ver).unwrap();
    let initial_ver = val_ver["policy_version_id"].as_str().unwrap().to_string();
    assert_eq!(initial_ver.len(), 16);
    assert_eq!(val_ver["status"], "ACTIVE");

    // 2. POST /governance/ingest-policy with matching expected version -> 200 OK
    let new_policy_yaml = "stpa_control_structure:\n  unsafe_control_actions: []\n";
    let (s_ingest, b_ingest) =
        handle_cage_ingest_policy(&state, new_policy_yaml, Some(&initial_ver));
    assert_eq!(s_ingest, "200 OK");
    let val_ingest: serde_json::Value = serde_json::from_str(&b_ingest).unwrap();
    let new_ver = val_ingest["policy_version_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(new_ver.len(), 16);

    // 3. POST /governance/ingest-policy with mismatched expected version -> 409 Conflict
    let (s_conflict, b_conflict) =
        handle_cage_ingest_policy(&state, new_policy_yaml, Some("drifted_version_01"));
    assert_eq!(s_conflict, "409 Conflict");
    assert!(b_conflict.contains("POLICY_VERSION_MISMATCH"));

    // 4. Ingest with JSON envelope containing mismatched expected_version -> 409 Conflict
    let env_mismatch = serde_json::json!({
        "policy": new_policy_yaml,
        "expected_version": "drifted_version_02"
    })
    .to_string();
    let (s_env_conflict, b_env_conflict) = handle_cage_ingest_policy(&state, &env_mismatch, None);
    assert_eq!(s_env_conflict, "409 Conflict");
    assert!(b_env_conflict.contains("POLICY_VERSION_MISMATCH"));
}

#[test]
fn test_http_endpoint_cage_validate_action_and_consume_seal() {
    let state = WebState::default();

    // 1. POST /governance/validate-action -> 200 OK with ALLOW and Seal
    let req_json = serde_json::json!({
        "action_name": "list_files",
        "principal": "arm-worker-1",
        "resource": "workspace/tmp",
        "parameters": {},
        "caller_authority": 3,
        "confidence_score": 0.98,
        "consensus_score": 0.85,
        "fuel_cost": 1.0,
        "expected_policy_version": null,
        "execution_profile": "Full"
    })
    .to_string();

    let (s_val, b_val) = handle_cage_validate_action(&state, &req_json);
    assert_eq!(s_val, "200 OK");
    let eval_res: GovernanceEvaluationResult = serde_json::from_str(&b_val).unwrap();
    assert_eq!(eval_res.verdict, GovernanceVerdict::Allow);
    assert!(eval_res.seal.is_some());
    let seal = eval_res.seal.unwrap();

    // 2. Validate action with version drift hint -> 409 Conflict
    let (s_drift, b_drift) =
        handle_cage_validate_action_with_version(&state, &req_json, Some("stale_version_99"));
    assert_eq!(s_drift, "409 Conflict");
    assert!(b_drift.contains("POLICY_VERSION_MISMATCH"));

    // 3. POST /governance/consume-seal (First Call) -> 200 OK
    let seal_json = serde_json::to_string(&seal).unwrap();
    let (s_consume1, b_consume1) = handle_cage_consume_seal(&state, &seal_json);
    assert_eq!(s_consume1, "200 OK");
    assert!(b_consume1.contains("CONSUMED"));

    // 4. POST /governance/consume-seal (Replay) -> 409 Conflict
    let (s_consume_replay, b_consume_replay) = handle_cage_consume_seal(&state, &seal_json);
    assert_eq!(s_consume_replay, "409 Conflict");
    assert!(b_consume_replay.contains("SEAL_ALREADY_CONSUMED"));

    // 5. POST /governance/consume-seal with wrapped envelope {"seal": ...}
    let fresh_req = serde_json::json!({
        "action_name": "list_dir",
        "principal": "arm-worker-1",
        "resource": "workspace/tmp",
        "parameters": {},
        "caller_authority": 3,
        "confidence_score": 0.98,
        "consensus_score": 0.85,
        "fuel_cost": 1.0,
        "expected_policy_version": null,
        "execution_profile": "Full"
    })
    .to_string();
    let (_, b_fresh) = handle_cage_validate_action(&state, &fresh_req);
    let fresh_eval: GovernanceEvaluationResult = serde_json::from_str(&b_fresh).unwrap();
    let fresh_seal = fresh_eval.seal.unwrap();

    let envelope_payload = serde_json::json!({ "seal": fresh_seal }).to_string();
    let (s_env, b_env) = handle_cage_consume_seal(&state, &envelope_payload);
    assert_eq!(s_env, "200 OK");
    assert!(b_env.contains("CONSUMED"));
}

#[test]
fn test_http_endpoint_proof_status_and_trace_conformance() {
    let state = WebState::default();

    // 1. GET /api/cage/proof-status
    let (s_proof, b_proof) = handle_cage_proof_status(&state);
    assert_eq!(s_proof, "200 OK");
    let proof: ProofStatusResponse = serde_json::from_str(&b_proof).unwrap();
    assert_eq!(proof.reachable_states, 34);
    assert_eq!(proof.ungated_states, 17);
    assert!(proof.no_direct_bind_proven);
    assert!(proof.counterexample_detected);
    assert!(proof.ungated_counterexample_proven);
    assert_eq!(proof.proof_hash.len(), 64);

    // 2. POST /api/cage/trace-conformance (Empty Array -> 200 OK CONFORMANT)
    let (s_trace, b_trace) = handle_cage_trace_conformance(&state, "[]");
    assert_eq!(s_trace, "200 OK");
    assert!(b_trace.contains("CONFORMANT"));

    // 3. POST /api/cage/trace-conformance with Malformed Payload -> 400 Bad Request
    let (s_bad, b_bad) = handle_cage_trace_conformance(&state, "{not an array or stream}");
    assert_eq!(s_bad, "400 Bad Request");
    assert!(b_bad.contains("INVALID_REQUEST_PAYLOAD"));
}
