//! ==============================================================================
//! [AGENT OCTOPUS] MILESTONE 3 ADVERSARIAL CHALLENGER SUITE (PART 2)
//! ==============================================================================
//! Empirical Stress-Testing for CAGE Milestone 3 HTTP Endpoints & Governance Engine:
//! 1. Multi-Format Policy Ingestion via HTTP Handler (`handle_cage_ingest_policy`):
//!    - Microsoft ACS, LF AAIF, NIST OSCAL 1.1.x, Lula Validation, Native CAGE YAML
//!    - Raw policy documents & JSON envelope payloads (`{"policy": "...", "expected_version": "..."}`)
//!    - Deterministic 16-character hex lowercase SHA-256 version IDs
//!    - Immediate active engine policy update reflection via `handle_cage_policy_version`
//!    - Version pinning enforcement: 200 OK on match, 409 Conflict on drift
//! 2. BFS Proof Status Endpoint (`handle_cage_proof_status`):
//!    - Invariant: reachable_states == 34 in gated model
//!    - Invariant: no_direct_bind_proven == true
//!    - Invariant: counterexample_detected == true and ungated_states == 17
//!    - Invariant: proof_hash format is strictly 64-hex lowercase SHA-256 receipt
//!    - Multi-trial determinism across repeated executions
//! 3. Trace Conformance Stream Parsing & 7-Rule Detection (`handle_cage_trace_conformance`):
//!    - Multi-format ingestion: JSON array, wrapper `{"traces": [...]}`, JSONL stream
//!    - Conforming trace stream validation (is_conformant() == true, 0 findings)
//!    - Malformed payload rejection (empty, invalid JSON -> 400 Bad Request)
//!    - Rule 1 (schema): missing event_type, malformed hash casing/length
//!    - Rule 2 (plan): authority rank insufficient for irreversible terminal action
//!    - Rule 3 (coverage): missing evaluation tiers from required 7 stages
//!    - Rule 4 (seal): ALLOW verdict missing seal_present flag
//!    - Rule 5 (reachable): invalid state transition outside 34 gated states
//!    - Rule 6 (no_direct_bind): unanchored actuation or unanchored seal consumption
//!    - Rule 7 (single_use): duplicate seal consumption detection (replay in trace)
//! 4. Concurrency Stress Testing:
//!    - Simultaneous execution of action validation, policy version reads, and policy ingestion
//!    - Deadlock, race condition, and memory consistency verification under high thread contention
//! ==============================================================================

use agent_octopus::security::cage_governance::{
    GovernanceEvaluationResult, GovernanceVerdict, ProofStatusResponse, StreamVerificationReport,
};
use agent_octopus::web::api::{
    handle_cage_consume_seal, handle_cage_ingest_policy, handle_cage_policy_version,
    handle_cage_proof_status, handle_cage_trace_conformance, handle_cage_validate_action, WebState,
};
use serde_json::Value;
use std::sync::Arc;
use std::thread;

// ==============================================================================
// FIXTURES: 5 CANONICAL POLICY SPECIFICATIONS
// ==============================================================================

const ACS_FIXTURE: &str = r#"{
    "behaviorDeclarations": [
        {
            "id": "ACS-SEC-001",
            "action": "ExecuteTrade",
            "hazardRefs": ["H-FINANCIAL-LOSS"],
            "constraints": [
                { "type": "greater_than", "parameter": "amount", "value": 50000 }
            ]
        }
    ],
    "cbf_gamma": 0.15,
    "cbf_b_min": 25.0
}"#;

const AAIF_FIXTURE: &str = r#"{
    "governedRunLoop": {
        "stages": [
            {
                "name": "containment_gate",
                "hooks": [
                    {
                        "id": "AAIF-HOOK-01",
                        "action": "NetworkSocketBind",
                        "role": "AgentWorker"
                    }
                ]
            }
        ]
    }
}"#;

const OSCAL_FIXTURE: &str = r#"{
    "oscal-version": "1.1.0",
    "components": [
        {
            "control-implementations": [
                {
                    "implemented-requirements": [
                        {
                            "control-id": "ac-3",
                            "description": "Access control enforcement for external sinks"
                        }
                    ]
                }
            ]
        }
    ]
}"#;

const LULA_FIXTURE: &str = r#"{
    "kind": "LulaValidation",
    "metadata": { "name": "sandboxed-workload-governance" },
    "spec": {
        "policy": {
            "opa": {
                "rego": "package main\ndefault allow = false\nallow { not input.DirectKernelAccess }"
            }
        }
    }
}"#;

const CAGE_YAML_FIXTURE: &str = "stpa_control_structure:\n  system_name: AgentOctopus\n  unsafe_control_actions:\n    - id: UCA-ADV-01\n      action: OverwriteFirmware\n      hazard: H-UNRECOVERABLE-STATE\n      condition:\n        param: physical_key\n        operator: is_null\n";

// Helper validator for 16-hex lowercase string
fn is_16_hex_lowercase(s: &str) -> bool {
    s.len() == 16
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

// Helper validator for 64-hex lowercase string
fn is_64_hex_lowercase(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

// ==============================================================================
// AREA 1: MULTI-FORMAT POLICY INGESTION & VERSION PINNING STRESS TESTS
// ==============================================================================

#[test]
fn test_adversarial_m3_policy_ingestion_5_formats_deterministic_hashing() {
    let state = WebState::default();

    // 1. Ingest Microsoft ACS
    let (s_acs, b_acs) = handle_cage_ingest_policy(&state, ACS_FIXTURE, None);
    assert_eq!(s_acs, "200 OK", "ACS ingestion must return 200 OK");
    let val_acs: Value = serde_json::from_str(&b_acs).expect("parse ACS response");
    assert_eq!(val_acs["format"], "MicrosoftAcs");
    let ver_acs = val_acs["policy_version_id"]
        .as_str()
        .expect("version string");
    assert!(
        is_16_hex_lowercase(ver_acs),
        "ACS version ID must be 16-hex lowercase"
    );

    // Verify active engine reflects ACS version
    let (s_ver, b_ver) = handle_cage_policy_version(&state);
    assert_eq!(s_ver, "200 OK");
    let val_ver: Value = serde_json::from_str(&b_ver).expect("parse version");
    assert_eq!(val_ver["policy_version_id"], ver_acs);

    // 2. Ingest LF AAIF
    let (s_aaif, b_aaif) = handle_cage_ingest_policy(&state, AAIF_FIXTURE, None);
    assert_eq!(s_aaif, "200 OK", "AAIF ingestion must return 200 OK");
    let val_aaif: Value = serde_json::from_str(&b_aaif).expect("parse AAIF response");
    assert_eq!(val_aaif["format"], "LinuxFoundationAaif");
    let ver_aaif = val_aaif["policy_version_id"]
        .as_str()
        .expect("version string");
    assert!(
        is_16_hex_lowercase(ver_aaif),
        "AAIF version ID must be 16-hex lowercase"
    );
    assert_ne!(
        ver_aaif, ver_acs,
        "Different formats must produce distinct versions"
    );

    // Verify active engine reflects AAIF version
    let (_, b_ver) = handle_cage_policy_version(&state);
    let val_ver: Value = serde_json::from_str(&b_ver).unwrap();
    assert_eq!(val_ver["policy_version_id"], ver_aaif);

    // 3. Ingest NIST OSCAL 1.1.x
    let (s_oscal, b_oscal) = handle_cage_ingest_policy(&state, OSCAL_FIXTURE, None);
    assert_eq!(s_oscal, "200 OK", "OSCAL ingestion must return 200 OK");
    let val_oscal: Value = serde_json::from_str(&b_oscal).expect("parse OSCAL response");
    assert_eq!(val_oscal["format"], "NistOscal");
    let ver_oscal = val_oscal["policy_version_id"]
        .as_str()
        .expect("version string");
    assert!(
        is_16_hex_lowercase(ver_oscal),
        "OSCAL version ID must be 16-hex lowercase"
    );

    // Verify active engine reflects OSCAL version
    let (_, b_ver) = handle_cage_policy_version(&state);
    let val_ver: Value = serde_json::from_str(&b_ver).unwrap();
    assert_eq!(val_ver["policy_version_id"], ver_oscal);

    // 4. Ingest Lula Validation
    let (s_lula, b_lula) = handle_cage_ingest_policy(&state, LULA_FIXTURE, None);
    assert_eq!(s_lula, "200 OK", "Lula ingestion must return 200 OK");
    let val_lula: Value = serde_json::from_str(&b_lula).expect("parse Lula response");
    assert_eq!(val_lula["format"], "LulaValidation");
    let ver_lula = val_lula["policy_version_id"]
        .as_str()
        .expect("version string");
    assert!(
        is_16_hex_lowercase(ver_lula),
        "Lula version ID must be 16-hex lowercase"
    );

    // Verify active engine reflects Lula version
    let (_, b_ver) = handle_cage_policy_version(&state);
    let val_ver: Value = serde_json::from_str(&b_ver).unwrap();
    assert_eq!(val_ver["policy_version_id"], ver_lula);

    // 5. Ingest Native CAGE YAML
    let (s_cage, b_cage) = handle_cage_ingest_policy(&state, CAGE_YAML_FIXTURE, None);
    assert_eq!(s_cage, "200 OK", "CAGE YAML ingestion must return 200 OK");
    let val_cage: Value = serde_json::from_str(&b_cage).expect("parse CAGE response");
    assert_eq!(val_cage["format"], "CageStpa");
    let ver_cage = val_cage["policy_version_id"]
        .as_str()
        .expect("version string");
    assert!(
        is_16_hex_lowercase(ver_cage),
        "CAGE YAML version ID must be 16-hex lowercase"
    );

    // Verify active engine reflects CAGE YAML version
    let (_, b_ver) = handle_cage_policy_version(&state);
    let val_ver: Value = serde_json::from_str(&b_ver).unwrap();
    assert_eq!(val_ver["policy_version_id"], ver_cage);

    // Multi-trial determinism check: fresh state ingestion yields identical hashes
    for trial in 1..=3 {
        let fresh_state = WebState::default();
        let (_, b1) = handle_cage_ingest_policy(&fresh_state, ACS_FIXTURE, None);
        let val1: Value = serde_json::from_str(&b1).unwrap();
        assert_eq!(
            val1["policy_version_id"], ver_acs,
            "Trial {trial}: ACS hash must be deterministic"
        );

        let (_, b2) = handle_cage_ingest_policy(&fresh_state, AAIF_FIXTURE, None);
        let val2: Value = serde_json::from_str(&b2).unwrap();
        assert_eq!(
            val2["policy_version_id"], ver_aaif,
            "Trial {trial}: AAIF hash must be deterministic"
        );

        let (_, b3) = handle_cage_ingest_policy(&fresh_state, OSCAL_FIXTURE, None);
        let val3: Value = serde_json::from_str(&b3).unwrap();
        assert_eq!(
            val3["policy_version_id"], ver_oscal,
            "Trial {trial}: OSCAL hash must be deterministic"
        );

        let (_, b4) = handle_cage_ingest_policy(&fresh_state, LULA_FIXTURE, None);
        let val4: Value = serde_json::from_str(&b4).unwrap();
        assert_eq!(
            val4["policy_version_id"], ver_lula,
            "Trial {trial}: Lula hash must be deterministic"
        );

        let (_, b5) = handle_cage_ingest_policy(&fresh_state, CAGE_YAML_FIXTURE, None);
        let val5: Value = serde_json::from_str(&b5).unwrap();
        assert_eq!(
            val5["policy_version_id"], ver_cage,
            "Trial {trial}: CAGE YAML hash must be deterministic"
        );
    }
}

#[test]
fn test_adversarial_m3_policy_envelope_and_version_drift_rejection() {
    let state = WebState::default();

    // Ingest initial ACS policy
    let (s_init, b_init) = handle_cage_ingest_policy(&state, ACS_FIXTURE, None);
    assert_eq!(s_init, "200 OK");
    let val_init: Value = serde_json::from_str(&b_init).unwrap();
    let initial_version = val_init["policy_version_id"].as_str().unwrap().to_string();

    // 1. Ingest via JSON envelope with matching expected_version -> 200 OK
    let envelope = serde_json::json!({
        "policy": AAIF_FIXTURE,
        "expected_version": initial_version
    })
    .to_string();
    let (s_env, b_env) = handle_cage_ingest_policy(&state, &envelope, None);
    assert_eq!(
        s_env, "200 OK",
        "Matching expected_version in envelope must succeed"
    );
    let val_env: Value = serde_json::from_str(&b_env).unwrap();
    let new_version = val_env["policy_version_id"].as_str().unwrap().to_string();
    assert_ne!(new_version, initial_version);

    // 2. Ingest with stale/mismatched expected_version -> 409 Conflict
    let stale_envelope = serde_json::json!({
        "policy": OSCAL_FIXTURE,
        "expected_version": initial_version // Already superseded by new_version
    })
    .to_string();
    let (s_stale, b_stale) = handle_cage_ingest_policy(&state, &stale_envelope, None);
    assert_eq!(
        s_stale, "409 Conflict",
        "Stale expected_version must trigger 409 Conflict"
    );
    assert!(b_stale.contains("POLICY_VERSION_MISMATCH"));

    // 3. Ingest with header hint mismatch -> 409 Conflict
    let (s_hint, b_hint) =
        handle_cage_ingest_policy(&state, LULA_FIXTURE, Some("0000deadbeef1111"));
    assert_eq!(
        s_hint, "409 Conflict",
        "Mismatched header hint must trigger 409 Conflict"
    );
    assert!(b_hint.contains("POLICY_VERSION_MISMATCH"));

    // 4. Ingest fallback behavior: unclassified text documents fall back to CageStpa
    // and synthesize root system default UCA CAGE-ROOT-001 (ExecuteChildProcess)
    let fallback_policy = "unrecognized_custom_key: some_value\n";
    let (s_fb, b_fb) = handle_cage_ingest_policy(&state, fallback_policy, None);
    assert_eq!(
        s_fb, "200 OK",
        "Fallback document compiles as CageStpa default"
    );
    let val_fb: Value = serde_json::from_str(&b_fb).unwrap();
    assert_eq!(val_fb["format"], "CageStpa");
    assert!(val_fb["stpa_ucas_count"].as_u64().unwrap() >= 1);
}

// ==============================================================================
// AREA 2: BFS PROOF STATUS ENDPOINT & INVARIANT VERIFICATION
// ==============================================================================

#[test]
fn test_adversarial_m3_bfs_proof_status_invariants_and_receipt() {
    let state = WebState::default();

    // Execute 10 consecutive trials to guarantee invariant stability and receipt determinism
    let mut initial_receipt = String::new();

    for trial in 1..=10 {
        let (status, body) = handle_cage_proof_status(&state);
        assert_eq!(status, "200 OK", "Proof status endpoint must return 200 OK");

        let proof: ProofStatusResponse =
            serde_json::from_str(&body).expect("parse ProofStatusResponse");

        // Mathematical invariant assertions
        assert_eq!(
            proof.reachable_states, 34,
            "Trial {trial}: Gated BFS model must prove strictly 34 reachable states"
        );
        assert!(
            proof.no_direct_bind_proven,
            "Trial {trial}: Invariant NoDirectBind must be formally proven (true)"
        );
        assert!(
            proof.counterexample_detected,
            "Trial {trial}: Ungated exploration must detect explicit counterexample"
        );
        assert_eq!(
            proof.ungated_states, 17,
            "Trial {trial}: Ungated BFS model must explore strictly 17 states"
        );
        assert!(
            proof.ungated_counterexample_proven,
            "Trial {trial}: Ungated counterexample must be proven"
        );

        // Theorem receipt format assertion
        assert!(
            is_64_hex_lowercase(&proof.proof_hash),
            "Trial {trial}: proof_hash must be strictly 64 lowercase hex characters, got '{}'",
            proof.proof_hash
        );

        if trial == 1 {
            initial_receipt = proof.proof_hash.clone();
        } else {
            assert_eq!(
                proof.proof_hash, initial_receipt,
                "Trial {trial}: Theorem receipt must be deterministic across executions"
            );
        }
    }
}

// ==============================================================================
// AREA 3: TRACE CONFORMANCE STREAM PARSING & 7-RULE DETECTION
// ==============================================================================

#[test]
fn test_adversarial_m3_trace_conformance_input_formats() {
    let state = WebState::default();

    // 1. Construct conforming trace event sequence
    let dec_hash = "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000";
    let trace_events = serde_json::json!([
        {
            "event_type": "PLAN_STEP",
            "action_name": "read_sensor",
            "caller_authority": 1
        },
        {
            "event_type": "GOVERNANCE_DECISION",
            "verdict": "ALLOW",
            "record_hash": dec_hash,
            "seal_present": true,
            "stages_evaluated": [
                { "stage_name": "ftra", "passed": true },
                { "stage_name": "stpa", "passed": true },
                { "stage_name": "cedar", "passed": true },
                { "stage_name": "confidence", "passed": true },
                { "stage_name": "cbf", "passed": true },
                { "stage_name": "fiscal", "passed": true },
                { "stage_name": "consensus", "passed": true }
            ]
        },
        {
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "seal_id": "SEAL-CONF-001",
            "decision_record_hash": dec_hash
        },
        {
            "event_type": "ACTUATION_RECEIPT",
            "seal_id": "SEAL-CONF-001",
            "action": "read_sensor"
        }
    ]);

    // Format A: Direct JSON Array
    let body_array = serde_json::to_string(&trace_events).unwrap();
    let (s_arr, b_arr) = handle_cage_trace_conformance(&state, &body_array);
    assert_eq!(s_arr, "200 OK");
    let rep_arr: StreamVerificationReport = serde_json::from_str(&b_arr).unwrap();
    assert!(
        rep_arr.is_conformant(),
        "Conforming array must pass all rules"
    );
    assert_eq!(rep_arr.findings_count, 0);

    // Format B: Wrapper Object `{"traces": [...]}`
    let body_wrapper = serde_json::json!({ "traces": trace_events }).to_string();
    let (s_wrap, b_wrap) = handle_cage_trace_conformance(&state, &body_wrapper);
    assert_eq!(s_wrap, "200 OK");
    let rep_wrap: StreamVerificationReport = serde_json::from_str(&b_wrap).unwrap();
    assert!(
        rep_wrap.is_conformant(),
        "Conforming wrapper must pass all rules"
    );
    assert_eq!(rep_wrap.findings_count, 0);

    // Format C: JSONL Stream (newline-delimited)
    let body_jsonl = format!(
        "{}\n{}\n{}\n{}",
        serde_json::to_string(&trace_events[0]).unwrap(),
        serde_json::to_string(&trace_events[1]).unwrap(),
        serde_json::to_string(&trace_events[2]).unwrap(),
        serde_json::to_string(&trace_events[3]).unwrap(),
    );
    let (s_jsonl, b_jsonl) = handle_cage_trace_conformance(&state, &body_jsonl);
    assert_eq!(s_jsonl, "200 OK");
    let rep_jsonl: StreamVerificationReport = serde_json::from_str(&b_jsonl).unwrap();
    assert!(
        rep_jsonl.is_conformant(),
        "Conforming JSONL stream must pass all rules"
    );
    assert_eq!(rep_jsonl.findings_count, 0);

    // Format D: Empty or unparseable payload -> 400 Bad Request
    let (s_empty, b_empty) = handle_cage_trace_conformance(&state, "");
    assert_eq!(s_empty, "400 Bad Request");
    assert!(b_empty.contains("INVALID_REQUEST_PAYLOAD"));

    let (s_bad, b_bad) = handle_cage_trace_conformance(&state, "{not_json");
    assert_eq!(s_bad, "400 Bad Request");
    assert!(b_bad.contains("INVALID_REQUEST_PAYLOAD"));
}

#[test]
fn test_adversarial_m3_trace_conformance_7_rules_stress() {
    let state = WebState::default();
    let valid_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    // --------------------------------------------------------------------------
    // Rule 1: Schema Violation (missing event_type or uppercase hash)
    // --------------------------------------------------------------------------
    let r1_payload = serde_json::json!([
        { "record_hash": valid_hash }, // Missing event_type
        {
            "event_type": "PLAN_STEP",
            "record_hash": "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789" // Uppercase
        }
    ])
    .to_string();
    let (_, b_r1) = handle_cage_trace_conformance(&state, &r1_payload);
    let rep_r1: StreamVerificationReport = serde_json::from_str(&b_r1).unwrap();
    assert!(!rep_r1.is_conformant());
    assert!(rep_r1.has_rule_violation("schema"));

    // --------------------------------------------------------------------------
    // Rule 2: Plan Invariant Violation (authority rank insufficient for irreversible action)
    // --------------------------------------------------------------------------
    let r2_payload = serde_json::json!([
        {
            "event_type": "PLAN_STEP",
            "action_name": "delete_storage_partition", // Irreversible terminal action requires high authority (rank <= 1)
            "caller_authority": 5 // Rank 5 is low privilege -> violation!
        }
    ])
    .to_string();
    let (_, b_r2) = handle_cage_trace_conformance(&state, &r2_payload);
    let rep_r2: StreamVerificationReport = serde_json::from_str(&b_r2).unwrap();
    assert!(!rep_r2.is_conformant());
    assert!(rep_r2.has_rule_violation("plan"));

    // --------------------------------------------------------------------------
    // Rule 3: Coverage Invariant Violation (missing required pipeline stages)
    // --------------------------------------------------------------------------
    let r3_payload = serde_json::json!([
        {
            "event_type": "GOVERNANCE_DECISION",
            "verdict": "ALLOW",
            "record_hash": valid_hash,
            "seal_present": true,
            "stages_evaluated": [
                { "stage_name": "ftra", "passed": true },
                { "stage_name": "stpa", "passed": true }
                // Missing cedar, confidence, cbf, fiscal, consensus!
            ]
        }
    ])
    .to_string();
    let (_, b_r3) = handle_cage_trace_conformance(&state, &r3_payload);
    let rep_r3: StreamVerificationReport = serde_json::from_str(&b_r3).unwrap();
    assert!(!rep_r3.is_conformant());
    assert!(rep_r3.has_rule_violation("coverage"));

    // --------------------------------------------------------------------------
    // Rule 4: Seal Invariant Violation (ALLOW without seal_present)
    // --------------------------------------------------------------------------
    let r4_payload = serde_json::json!([
        {
            "event_type": "GOVERNANCE_DECISION",
            "verdict": "ALLOW",
            "record_hash": valid_hash,
            "seal_present": false // VIOLATION!
        }
    ])
    .to_string();
    let (_, b_r4) = handle_cage_trace_conformance(&state, &r4_payload);
    let rep_r4: StreamVerificationReport = serde_json::from_str(&b_r4).unwrap();
    assert!(!rep_r4.is_conformant());
    assert!(rep_r4.has_rule_violation("seal"));

    // --------------------------------------------------------------------------
    // Rule 5: Reachable State Invariant Violation (transition to unreachable state)
    // --------------------------------------------------------------------------
    let r5_payload = serde_json::json!([
        {
            "event_type": "STATE_TRANSITION",
            "phase": "EXECUTED",
            "label": "unauthorized_bypass_stage",
            "tier": 99
        }
    ])
    .to_string();
    let (_, b_r5) = handle_cage_trace_conformance(&state, &r5_payload);
    let rep_r5: StreamVerificationReport = serde_json::from_str(&b_r5).unwrap();
    assert!(!rep_r5.is_conformant());
    assert!(rep_r5.has_rule_violation("reachable"));

    // --------------------------------------------------------------------------
    // Rule 6: No-Direct-Bind Violation (unanchored seal or unsealed execution)
    // --------------------------------------------------------------------------
    let r6_payload = serde_json::json!([
        {
            // Seal consumed referencing non-existent decision
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "seal_id": "SEAL-ORPHAN-001",
            "decision_record_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        },
        {
            // Actuation receipt referencing seal without consumption record
            "event_type": "ACTUATION_RECEIPT",
            "seal_id": "SEAL-UNCONSUMED-999",
            "action": "delete_storage"
        }
    ])
    .to_string();
    let (_, b_r6) = handle_cage_trace_conformance(&state, &r6_payload);
    let rep_r6: StreamVerificationReport = serde_json::from_str(&b_r6).unwrap();
    assert!(!rep_r6.is_conformant());
    assert!(rep_r6.has_rule_violation("no_direct_bind"));

    // --------------------------------------------------------------------------
    // Rule 7: Single-Use Invariant Violation (Duplicate consumption / Replay)
    // --------------------------------------------------------------------------
    let r7_payload = serde_json::json!([
        {
            "event_type": "GOVERNANCE_DECISION",
            "verdict": "ALLOW",
            "record_hash": valid_hash,
            "seal_present": true,
            "stages_evaluated": [
                { "stage_name": "ftra", "passed": true },
                { "stage_name": "stpa", "passed": true },
                { "stage_name": "cedar", "passed": true },
                { "stage_name": "confidence", "passed": true },
                { "stage_name": "cbf", "passed": true },
                { "stage_name": "fiscal", "passed": true },
                { "stage_name": "consensus", "passed": true }
            ]
        },
        {
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "seal_id": "SEAL-REPLAY-TARGET-007",
            "decision_record_hash": valid_hash
        },
        {
            // DUPLICATE CONSUMPTION OF THE EXACT SAME SEAL!
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "seal_id": "SEAL-REPLAY-TARGET-007",
            "decision_record_hash": valid_hash
        }
    ])
    .to_string();
    let (_, b_r7) = handle_cage_trace_conformance(&state, &r7_payload);
    let rep_r7: StreamVerificationReport = serde_json::from_str(&b_r7).unwrap();
    assert!(
        !rep_r7.is_conformant(),
        "Replay trace must be non-compliant"
    );
    let single_use_finding = rep_r7
        .findings
        .iter()
        .find(|f| f.rule == "single_use")
        .expect("must detect Rule 7 single_use violation");
    assert!(
        single_use_finding.detail.contains("SEAL-REPLAY-TARGET-007"),
        "Finding must name replayed seal"
    );
    assert!(
        single_use_finding.detail.contains("replay detected"),
        "Finding must specify replay detected"
    );
}

// ==============================================================================
// AREA 4: HIGH-CONCURRENCY ACTION VALIDATION & POLICY READ/UPDATE STRESS
// ==============================================================================

#[test]
fn test_adversarial_m3_concurrency_race_resistance() {
    let state = Arc::new(WebState::default());

    // Ingest initial policy so engine is active
    let (s_init, _) = handle_cage_ingest_policy(&state, ACS_FIXTURE, None);
    assert_eq!(s_init, "200 OK");

    const NUM_VALIDATOR_THREADS: usize = 6;
    const NUM_READER_THREADS: usize = 6;
    const NUM_INGESTER_THREADS: usize = 2;
    const ITERATIONS_PER_THREAD: usize = 50;

    let mut handles = Vec::new();

    // 1. Validator threads (concurrent action evaluations)
    for t_id in 0..NUM_VALIDATOR_THREADS {
        let state_clone = Arc::clone(&state);
        handles.push(thread::spawn(move || {
            for i in 0..ITERATIONS_PER_THREAD {
                let req_payload = serde_json::json!({
                    "action_name": "list_directory",
                    "principal": format!("arm-worker-{}", t_id),
                    "resource": format!("workspace/file_{}.txt", i),
                    "parameters": {},
                    "caller_authority": 2,
                    "confidence_score": 0.96,
                    "consensus_score": 0.88,
                    "fuel_cost": 0.5,
                    "expected_policy_version": null,
                    "execution_profile": "Full"
                })
                .to_string();

                let (status, body) = handle_cage_validate_action(&state_clone, &req_payload);
                assert_eq!(
                    status, "200 OK",
                    "Thread {t_id} iteration {i}: action validation must succeed"
                );
                let eval: GovernanceEvaluationResult =
                    serde_json::from_str(&body).expect("parse eval result");
                assert_eq!(eval.verdict, GovernanceVerdict::Allow);
                assert!(eval.seal.is_some(), "ALLOW verdict must issue routing seal");

                // Immediately consume the issued seal
                let seal_json = serde_json::to_string(&eval.seal.unwrap()).unwrap();
                let (c_status, _) = handle_cage_consume_seal(&state_clone, &seal_json);
                assert_eq!(
                    c_status, "200 OK",
                    "Thread {t_id} iteration {i}: seal consumption must succeed"
                );
            }
        }));
    }

    // 2. Reader threads (concurrent policy version reads)
    for t_id in 0..NUM_READER_THREADS {
        let state_clone = Arc::clone(&state);
        handles.push(thread::spawn(move || {
            for i in 0..ITERATIONS_PER_THREAD {
                let (status, body) = handle_cage_policy_version(&state_clone);
                assert_eq!(
                    status, "200 OK",
                    "Reader {t_id} iteration {i}: policy-version read must return 200 OK"
                );
                let val: Value = serde_json::from_str(&body).expect("parse policy version");
                let ver = val["policy_version_id"].as_str().expect("version string");
                assert!(
                    is_16_hex_lowercase(ver),
                    "Reader {t_id} iteration {i}: version must be 16-hex lowercase, got '{}'",
                    ver
                );
                assert_eq!(val["status"], "ACTIVE");
            }
        }));
    }

    // 3. Ingester threads (concurrent policy updates cycling through formats)
    let policies = vec![
        ACS_FIXTURE,
        AAIF_FIXTURE,
        OSCAL_FIXTURE,
        LULA_FIXTURE,
        CAGE_YAML_FIXTURE,
    ];
    for t_id in 0..NUM_INGESTER_THREADS {
        let state_clone = Arc::clone(&state);
        let policies_clone = policies.clone();
        handles.push(thread::spawn(move || {
            for i in 0..ITERATIONS_PER_THREAD {
                let policy_doc = policies_clone[(t_id + i) % policies_clone.len()];
                let (status, body) = handle_cage_ingest_policy(&state_clone, policy_doc, None);
                assert_eq!(
                    status, "200 OK",
                    "Ingester {t_id} iteration {i}: ingest policy must return 200 OK"
                );
                let val: Value = serde_json::from_str(&body).expect("parse ingest response");
                let ver = val["policy_version_id"].as_str().expect("version string");
                assert!(
                    is_16_hex_lowercase(ver),
                    "Ingester {t_id} iteration {i}: version must be 16-hex lowercase"
                );
            }
        }));
    }

    // Wait for all threads to terminate and check for panics
    for h in handles {
        h.join()
            .expect("Thread joined cleanly with zero panics or deadlocks");
    }

    // Final consistency check
    let (final_status, final_body) = handle_cage_policy_version(&state);
    assert_eq!(final_status, "200 OK");
    let final_val: Value = serde_json::from_str(&final_body).unwrap();
    let final_ver = final_val["policy_version_id"].as_str().unwrap();
    assert!(is_16_hex_lowercase(final_ver));
}
