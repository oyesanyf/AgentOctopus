//! ==============================================================================
//! [AGENT OCTOPUS] MILESTONE 4 ADVERSARIAL CHALLENGER TEST SUITE
//! ==============================================================================
//! Code-executing adversarial challenge and empirical stress harness targeting
//! CAGE governance boundaries, Substrate Contract mechanics, and actuation gating:
//!
//! Challenge 1: Severe Policy Corruption, Malformed Payloads & RFC 8785 Drift
//! - Severe corruption: truncated JSON/YAML, unbalanced delimiters, syntax breakage
//! - Malformed payloads: illegal tabs, binary control characters, missing required schema
//! - Non-canonical whitespace: tabs, \r\n, extra spaces, trailing lines, key reordering
//! - RFC 8785 JCS invariance: whitespace/order immunity with exact version consistency
//! - RFC 8785 version drift injection: single-byte/parameter mutation -> 409 Conflict
//!
//! Challenge 2: Adversarial Discrete-Time CBF Barrier Step & Envelope Attacks
//! - Boundary condition attack: h(S_{t+1}) < (1 - gamma) * h(S_t) by tiny epsilon (10^-8)
//! - Multi-step trajectory: spending exceeding the decaying barrier envelope
//! - Reserve floor breach vs decay rate violation vs unsafe initial state
//! - Invalid parameters: NaN, +/-Inf, negative budgets, and cost bounds
//! - Sequence replay high-water marks and stale fence epoch rejection under concurrency
//!
//! Challenge 3: Cryptographic Routing Seal Forgery & Concurrent Replay Attacks
//! - HMAC signature corruption: bit-flips, byte substitution, truncation, bad charset
//! - Chain anchor tampering: mutated record_hash, unanchored/genesis audit hashes
//! - Temporal validation: TTL expiration (>30s), future skew (>5s), tampered expires_at
//! - High-concurrency race condition: 32 concurrent OS threads racing single seal
//! - Actuator containment ring race: concurrent async actuation tasks with single seal
//!
//! Challenge 4: GOVERNANCE_TRACE Stream Injection & Rule Conformance Attacks
//! - Injected actuation receipts (ACTUATION_RECEIPT, ACTUATION_EXECUTED, GOVERNANCE_EXECUTION)
//!   executed without preceding GOVERNANCE_SEAL_CONSUMED (Rule 6: no_direct_bind)
//! - Injected unsealed decisions with ALLOW/NARROW verdict (Rule 4: seal)
//! - Injected duplicate seal consumption in audit trail (Rule 7: single_use)
//! - Injected incomplete evaluation coverage omitting pipeline tiers (Rule 3: coverage)
//! - Injected illegal state machine transitions skipping tiers (Rule 5: reachable)
//! - Injected CBF rollback leakage and unledgered debit references
//! - Schema validation: malformed hex digests and non-lowercase hashes (Rule 1: schema)
//! ==============================================================================

use agent_octopus::containment_ring::{
    ArmContainmentRing, ArmExecutionError, TieredExecutionDispatcher, TieredToolRequest,
};
use agent_octopus::core::types::ArmRole;
use agent_octopus::security::cage_governance::cbf_fiscal::{
    CbfSafetyEngine, CbfViolation,
};
use agent_octopus::security::cage_governance::no_direct_bind_proof::{
    FormalBfsModel, StreamConformanceStatus,
};
use agent_octopus::security::cage_governance::routing_seal::{
    CageRoutingSeal, RoutingSealSigner, SealRejection,
};
use agent_octopus::security::cage_governance::substrate_translator::{
    PolicyFormat, PolicyIngestError, SubstrateTranslator,
};

use agent_octopus::security::cage_governance::CageGovernanceEngine;
use agent_octopus::web::api::*;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};

const CHALLENGER_MASTER_SEED: &[u8] = b"OCTOPUS_CHALLENGER_M4_SEED_2026_";
const CHALLENGER_RESOURCE: &str = "s3://invoices/inv_01.pdf";

fn test_dispatcher() -> TieredExecutionDispatcher {
    let mercury = Arc::new(agent_octopus::security::mercury_guard::MercuryContainmentEngine::new());
    TieredExecutionDispatcher::try_new(mercury).expect("Dispatcher initialization must succeed")
}

fn create_test_seal_anchored(
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
        .expect("Test seal issuance must succeed")
}

// ==============================================================================
// CHALLENGE 1: SEVERE POLICY CORRUPTION, MALFORMED PAYLOADS & RFC 8785 DRIFT
// ==============================================================================

#[test]
fn test_challenge1_severe_policy_corruption_and_malformed_syntax() {
    let state = WebState::default();

    // 1. Malformed YAML with missing colon in array item block (strict ParseError)
    let malformed_yaml = "stpa_control_structure:\n  unsafe_control_actions:\n    - id: \"UCA-01\"\n      illegal_line_without_colon_delimiter\n";
    let compile_err = SubstrateTranslator::compile_policy(malformed_yaml, None)
        .expect_err("YAML array item missing colon must return ParseError");
    assert!(
        matches!(compile_err, PolicyIngestError::ParseError(_)),
        "Expected ParseError, got: {:?}",
        compile_err
    );
    let (status1, body1) = handle_cage_ingest_policy(&state, malformed_yaml, None);
    assert_eq!(status1, "400 Bad Request", "Malformed YAML must return 400 Bad Request");
    assert!(body1.contains("INVALID_POLICY_FORMAT"));

    // 2. Malformed ACS schema: missing mandatory 'behaviorDeclarations' array
    let broken_acs = "description: \"ACS policy without behaviorDeclarations\"\n";
    let acs_err = SubstrateTranslator::compile_policy(broken_acs, Some(PolicyFormat::MicrosoftAcs))
        .expect_err("ACS missing behaviorDeclarations must fail");
    assert!(
        matches!(acs_err, PolicyIngestError::MalformedSchema(_)),
        "Expected MalformedSchema, got: {:?}",
        acs_err
    );

    // 3. Malformed AAIF schema: missing mandatory 'governedRunLoop'
    let broken_aaif = "title: \"AAIF policy without governedRunLoop\"\n";
    let aaif_err = SubstrateTranslator::compile_policy(broken_aaif, Some(PolicyFormat::LinuxFoundationAaif))
        .expect_err("AAIF missing governedRunLoop must fail");
    assert!(matches!(aaif_err, PolicyIngestError::MalformedSchema(_)));

    // 4. Malformed OSCAL schema: missing controls / component-definition
    let broken_oscal = "oscal-version: \"1.1.0\"\n";
    let oscal_err = SubstrateTranslator::compile_policy(broken_oscal, Some(PolicyFormat::NistOscal))
        .expect_err("OSCAL missing component-definition must fail");
    assert!(matches!(oscal_err, PolicyIngestError::MalformedSchema(_)));

    // 5. Ingest malformed YAML payload via HTTP endpoint -> strict 400 Bad Request
    let malformed_ingest_yaml = "behaviorDeclarations:\n  - name: test\n    syntax_error_no_colon\n";
    let (status5, body5) = handle_cage_ingest_policy(&state, malformed_ingest_yaml, None);
    assert_eq!(status5, "400 Bad Request");
    assert!(body5.contains("INVALID_POLICY_FORMAT"));
}

#[test]
fn test_challenge1_non_canonical_whitespace_and_jcs_invariance() {
    // 5 variants of the exact same policy with radically different formatting:
    // RFC 8785 JSON Canonicalization Scheme (JCS) must guarantee 100% hash invariance.

    // Variant 1: Compact JSON
    let v1 = r#"{"behaviorDeclarations":[{"name":"query_db","description":"DB query","allowedCallers":["arm_01"]}],"cbf_gamma":0.15,"cbf_b_min":25.0}"#;

    // Variant 2: Heavily indented JSON with extra whitespace, tabs, and newlines
    let v2 = r#"{
        "behaviorDeclarations"  :   [
            {
                "name" : "query_db" ,
                "description" : "DB query" ,
                "allowedCallers" : [ "arm_01" ]
            }
        ],
        "cbf_gamma" : 0.15 ,
        "cbf_b_min" : 25.0
    }"#;

    // Variant 3: Windows-style \r\n line endings and trailing spaces
    let v3 = "{\r\n  \"behaviorDeclarations\": [\r\n    {\r\n      \"name\": \"query_db\",   \r\n      \"description\": \"DB query\", \r\n      \"allowedCallers\": [\"arm_01\"]\r\n    }\r\n  ],\r\n  \"cbf_gamma\": 0.15,\r\n  \"cbf_b_min\": 25.0\r\n}";

    // Variant 4: Permuted object keys in JSON (RFC 8785 §3.2.3 requires UTF-16 code unit key sorting)
    let v4 = r#"{"cbf_b_min":25.0,"cbf_gamma":0.15,"behaviorDeclarations":[{"allowedCallers":["arm_01"],"description":"DB query","name":"query_db"}]}"#;

    // Compile all 4 variants
    let compiled1 = SubstrateTranslator::compile_policy(v1, None).expect("v1 compilation");
    let compiled2 = SubstrateTranslator::compile_policy(v2, None).expect("v2 compilation");
    let compiled3 = SubstrateTranslator::compile_policy(v3, None).expect("v3 compilation");
    let compiled4 = SubstrateTranslator::compile_policy(v4, None).expect("v4 compilation");

    // Exact Invariance Assertions:
    assert_eq!(compiled1.policy_version_id.len(), 16);
    assert_eq!(
        compiled1.policy_version_id, compiled2.policy_version_id,
        "Heavy indentation must not alter RFC 8785 version hash"
    );
    assert_eq!(
        compiled1.policy_version_id, compiled3.policy_version_id,
        "CRLF formatting must not alter RFC 8785 version hash"
    );
    assert_eq!(
        compiled1.policy_version_id, compiled4.policy_version_id,
        "JSON key permutations must be normalized by RFC 8785 key sorting"
    );
}

#[test]
fn test_challenge1_rfc8785_version_drift_injection_strict_409_conflict() {
    let state = WebState::default();
    let initial_ver = state.cage_engine.active_policy_version();

    let base_policy = r#"
stpa_control_structure:
  control_actions:
    - action: "doc_extractor"
      hazard: "H-01"
  unsafe_control_actions:
    - id: "UCA-01"
      action: "doc_extractor"
      hazard: "H-01"
      type: "NotProviding"
      context: "unauthenticated"
      mitigation: "require_token"
cbf_gamma: 0.10
cbf_b_min: 10.0
"#;

    let base_compiled = SubstrateTranslator::compile_policy(base_policy, None).expect("base compile");
    assert_eq!(base_compiled.policy_version_id.len(), 16);

    // Mutation A: Change a single character in action name ("doc_extractor" -> "doc_extractos")
    let mut_a = base_policy.replace("doc_extractor", "doc_extractos");
    let comp_a = SubstrateTranslator::compile_policy(&mut_a, None).expect("comp a");
    assert_ne!(
        base_compiled.policy_version_id, comp_a.policy_version_id,
        "Action name mutation must diverge version ID"
    );

    // Mutation B: Perturb CBF gamma by 1e-6 (0.10 -> 0.100001)
    let mut_b = base_policy.replace("cbf_gamma: 0.10", "cbf_gamma: 0.100001");
    let comp_b = SubstrateTranslator::compile_policy(&mut_b, None).expect("comp b");
    assert_ne!(
        base_compiled.policy_version_id, comp_b.policy_version_id,
        "Microscopic gamma perturbation must alter version ID"
    );

    // Mutation C: Perturb CBF b_min by 0.001 (10.0 -> 10.001)
    let mut_c = base_policy.replace("cbf_b_min: 10.0", "cbf_b_min: 10.001");
    let comp_c = SubstrateTranslator::compile_policy(&mut_c, None).expect("comp c");
    assert_ne!(
        base_compiled.policy_version_id, comp_c.policy_version_id,
        "Microscopic b_min perturbation must alter version ID"
    );

    // 1. Direct version pinning verification: SubstrateTranslator::verify_version_pinning
    for (name, mutated_comp) in [("MutA", &comp_a), ("MutB", &comp_b), ("MutC", &comp_c)] {
        let pin_err = SubstrateTranslator::verify_version_pinning(
            Some(&base_compiled.policy_version_id),
            &mutated_comp.policy_version_id,
        )
        .expect_err(&format!("{}: verify_version_pinning must fail on drifted version", name));
        assert_eq!(pin_err.pinned_version, base_compiled.policy_version_id);
        assert_eq!(pin_err.incoming_version, mutated_comp.policy_version_id);
    }

    // 2. Active version pinning on policy ingest via HTTP:
    // Pinned to initial_ver; caller provides mismatched drifted expected_version -> 409 Conflict
    let (s_conf1, b_conf1) = handle_cage_ingest_policy(
        &state,
        base_policy,
        Some("drift_hash_0000"),
    );
    assert_eq!(s_conf1, "409 Conflict");
    assert!(b_conf1.contains("POLICY_VERSION_MISMATCH"));

    // 3. Ingest with JSON envelope containing mismatched expected_version -> 409 Conflict
    let env_mismatch = serde_json::json!({
        "policy": base_policy,
        "expected_version": "drift_hash_1111"
    })
    .to_string();
    let (s_conf2, b_conf2) = handle_cage_ingest_policy(&state, &env_mismatch, None);
    assert_eq!(s_conf2, "409 Conflict");
    assert!(b_conf2.contains("POLICY_VERSION_MISMATCH"));

    // 4. Action validation version drift: request pins to drifted version -> 409 Conflict
    let req_drifted = serde_json::json!({
        "action_name": "doc_extractor",
        "principal": "arm_01",
        "resource": "s3://docs/test.pdf",
        "parameters": {},
        "caller_authority": 1,
        "confidence_score": 0.98,
        "consensus_score": 0.90,
        "fuel_cost": 5.0,
        "expected_policy_version": "drift_hash_2222"
    })
    .to_string();
    let (s_conf3, b_conf3) = handle_cage_validate_action(&state, &req_drifted);
    assert_eq!(s_conf3, "409 Conflict");
    assert!(b_conf3.contains("POLICY_VERSION_MISMATCH"));


    // 5. Ingest with matching expected_version -> succeeds 200 OK
    let (s_ok, b_ok) = handle_cage_ingest_policy(&state, base_policy, Some(&initial_ver));
    assert_eq!(s_ok, "200 OK");
    assert!(b_ok.contains(&base_compiled.policy_version_id));
}


// ==============================================================================
// CHALLENGE 2: ADVERSARIAL DISCRETE-TIME CBF BARRIER STEP & ENVELOPE ATTACKS
// ==============================================================================

#[test]
fn test_challenge2_adversarial_cbf_barrier_tiny_epsilon_boundary_attacks() {
    // Governed by discrete-time barrier condition:
    // h(S_{t+1}) = (B_t - c) - B_min >= (1 - gamma) * h(S_t) >= 0
    // With gamma = 0.10, B_min = 10.0, B_t = 100.0
    // h(S_t) = 100.0 - 10.0 = 90.0
    // (1 - gamma) * h(S_t) = 0.90 * 90.0 = 81.0
    // Theoretical maximum allowable cost: c_max = 9.0
    // If cost = 9.0: h_{t+1} = (100 - 9) - 10 = 81.0 (exact equality, permitted)

    let engine = CbfSafetyEngine::new(0.10, 10.0).expect("CBF init");
    let current_budget = 100.0;
    let current_h = 90.0;

    // 1. Exact boundary: cost = 9.0 -> succeeds
    let h_boundary = engine
        .evaluate_step(current_budget, 9.0, current_h)
        .expect("Exact boundary cost 9.0 must pass");
    assert!((h_boundary - 81.0).abs() < 1e-12);

    // 2. Sub-epsilon tolerance: cost = 9.0 + 1e-10 -> within CBF_EPSILON (1e-9) buffer
    let h_sub_eps = engine.evaluate_step(current_budget, 9.0 + 1e-10, current_h);
    assert!(h_sub_eps.is_ok(), "Cost within epsilon buffer must pass");

    // 3. ADVERSARIAL ATTACK: cost = 9.0 + 1e-8 (exceeds decay bound by tiny epsilon 10^-8)
    // h_{t+1} = 81.0 - 10^-8
    // With CBF_EPSILON = 10^-9: h_{t+1} + epsilon = 81.0 - 9e-9 < 81.0
    // MUST FAIL CLOSED with DecayRateExceeded!
    let eps_attack = engine.evaluate_step(current_budget, 9.00000001, current_h);
    assert!(
        eps_attack.is_err(),
        "Cost exceeding barrier by 1e-8 must fail closed"
    );
    match eps_attack.unwrap_err() {
        CbfViolation::DecayRateExceeded {
            h_next,
            h_min_allowed,
            gamma,
        } => {
            assert!(h_next < h_min_allowed);
            assert_eq!(h_min_allowed, 81.0);
            assert_eq!(gamma, 0.10);
        }
        other => panic!("Expected DecayRateExceeded, got: {:?}", other),
    }

    // 4. Multiple incremental epsilon attacks: 1e-7, 1e-6, 1e-5, 1e-3
    for delta in [1e-7, 1e-6, 1e-5, 1e-3, 0.1] {
        let err = engine
            .evaluate_step(current_budget, 9.0 + delta, current_h)
            .expect_err(&format!("Cost 9.0 + {} must be rejected", delta));
        assert!(matches!(err, CbfViolation::DecayRateExceeded { .. }));
    }
}

#[test]
fn test_challenge2_cbf_decaying_envelope_multi_step_trajectory() {
    // Multi-step trajectory starting at B_0 = 1000.0, B_min = 100.0, gamma = 0.20
    // Each step allows spending at most gamma * h(S_t)
    let engine = CbfSafetyEngine::new(0.20, 100.0).expect("CBF init");

    let mut budget = 1000.0;
    let mut h = budget - 100.0; // 900.0

    // Trajectory Step 1:
    // Max cost = 0.20 * 900.0 = 180.0
    // We spend 180.0 -> B_1 = 820.0, h_1 = 720.0
    let h1 = engine.evaluate_step(budget, 180.0, h).expect("Step 1 pass");
    budget -= 180.0;
    h = h1;
    assert_eq!(budget, 820.0);
    assert_eq!(h, 720.0);

    // Trajectory Step 2:
    // Available h is now 720.0. Max allowable cost is 0.20 * 720.0 = 144.0.
    // Adversary attempts to replay the Step 1 budget (180.0) under decayed envelope:
    // Projected h = (820 - 180) - 100 = 540.0.
    // Required minimum h = (1 - 0.20) * 720.0 = 576.0.
    // 540.0 < 576.0 -> MUST FAIL!
    let envelope_attack_1 = engine.evaluate_step(budget, 180.0, h);
    assert!(
        envelope_attack_1.is_err(),
        "Spending 180.0 in Step 2 violates decaying envelope"
    );
    assert!(matches!(
        envelope_attack_1.unwrap_err(),
        CbfViolation::DecayRateExceeded { .. }
    ));

    // Valid Step 2 spending: 144.0 -> B_2 = 676.0, h_2 = 576.0
    let h2 = engine.evaluate_step(budget, 144.0, h).expect("Step 2 pass");
    budget -= 144.0;
    h = h2;
    assert_eq!(budget, 676.0);
    assert_eq!(h, 576.0);

    // Trajectory Step 3:
    // Available h is 576.0. Max allowable cost is 0.20 * 576.0 = 115.2.
    // Adversary attempts 115.2 + 1e-8:
    let envelope_attack_2 = engine.evaluate_step(budget, 115.20000001, h);
    assert!(
        envelope_attack_2.is_err(),
        "Cost exceeding Step 3 envelope by 1e-8 must fail"
    );
    assert!(matches!(
        envelope_attack_2.unwrap_err(),
        CbfViolation::DecayRateExceeded { .. }
    ));
}

#[test]
fn test_challenge2_floor_breach_vs_decay_and_malformed_numerics() {
    let engine = CbfSafetyEngine::new(0.50, 10.0).expect("CBF init");

    // 1. Floor Breach: budget = 12.0, cost = 2.5 -> projected = 9.5 < 10.0
    // Even though h_next = -0.5, this is a FloorBreach
    let floor_err = engine
        .evaluate_step(12.0, 2.5, 2.0)
        .expect_err("Floor breach must be detected");
    match floor_err {
        CbfViolation::FloorBreach { projected_budget, b_min } => {
            assert_eq!(projected_budget, 9.5);
            assert_eq!(b_min, 10.0);
        }
        other => panic!("Expected FloorBreach, got {:?}", other),
    }

    // 2. Current State Unsafe: starting budget is already below floor
    let unsafe_err = engine
        .evaluate_step(9.0, 1.0, -1.0)
        .expect_err("Current state below floor must fail");
    assert!(matches!(unsafe_err, CbfViolation::CurrentStateUnsafe { .. }));

    // 3. Malformed numerics: NaN, +/-Infinity, negative cost
    assert!(matches!(
        engine.evaluate_step(100.0, f64::NAN, 90.0).unwrap_err(),
        CbfViolation::InvalidParameters(_)
    ));
    assert!(matches!(
        engine.evaluate_step(f64::INFINITY, 10.0, 90.0).unwrap_err(),
        CbfViolation::InvalidParameters(_)
    ));
    assert!(matches!(
        engine.evaluate_step(100.0, -5.0, 90.0).unwrap_err(),
        CbfViolation::InvalidParameters(_)
    ));
}

#[test]
fn test_challenge2_sequence_replay_and_fence_epoch_boundary_concurrency() {
    let engine = Arc::new(CbfSafetyEngine::new(0.10, 10.0).expect("CBF init"));

    // 1. Initial sequence and epoch check
    assert!(engine.verify_sequence_and_epoch(1, 1).is_ok());

    // 2. Duplicate sequence replay attack
    let replay_err = engine
        .verify_sequence_and_epoch(1, 1)
        .expect_err("Duplicate sequence 1 must fail");
    assert!(matches!(replay_err, CbfViolation::SequenceReplay { .. }));

    // 3. Sequence regression attack
    let regr_err = engine
        .verify_sequence_and_epoch(0, 1)
        .expect_err("Regressed sequence 0 must fail");
    assert!(matches!(regr_err, CbfViolation::SequenceReplay { .. }));

    // 4. Stale fence epoch attack: incoming epoch 0 when active epoch is 1
    let stale_err = engine
        .verify_sequence_and_epoch(10, 0)
        .expect_err("Stale epoch 0 must fail");
    assert!(matches!(stale_err, CbfViolation::StaleFenceEpoch { .. }));

    // 5. High-concurrency sequence test: 16 threads each submitting strictly monotonic blocks
    let num_threads = 16;
    let steps_per_thread = 50;
    let mut handles = Vec::new();

    for t in 0..num_threads {
        let eng = Arc::clone(&engine);
        handles.push(std::thread::spawn(move || {
            let start = 100 + (t * steps_per_thread) as u64;
            for i in 0..steps_per_thread as u64 {
                let seq = start + i;
                // Sequences within each thread block advance monotonically
                let _ = eng.verify_sequence_and_epoch(seq, 1);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

// ==============================================================================
// CHALLENGE 3: CRYPTOGRAPHIC ROUTING SEAL FORGERY & CONCURRENT REPLAY ATTACKS
// ==============================================================================

#[test]
fn test_challenge3_tampered_hmac_signature_and_chain_anchor_attacks() {
    let secret = b"challenger_m4_seal_secret_key32_";
    let policy_ver = "fedcba9876543210";
    let signer = RoutingSealSigner::new(secret, policy_ver);

    let action_digest = "11112222333344445555666677778888aaaabbbbccccddddeeeeffff00001111";
    let record_hash = "999988887777666655554444333322220000ffff1111eeee2222dddd3333cccc";
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let valid_seal = signer.issue_seal(action_digest, record_hash, now).expect("Seal issuance");
    assert!(valid_seal.validate_format());

    // 1. Attack: Single-bit flip in HMAC signature
    let mut bit_flipped_seal = valid_seal.clone();
    let last_byte = bit_flipped_seal.signature.pop().unwrap();
    bit_flipped_seal.signature.push(if last_byte == 'a' { 'b' } else { 'a' });
    let sig_err = signer
        .validate_and_consume(&bit_flipped_seal, action_digest, record_hash, now)
        .expect_err("Bit-flipped signature must be rejected");
    assert_eq!(sig_err, SealRejection::InvalidSignature);

    // 2. Attack: Truncated signature (63 hex chars instead of 64)
    let mut trunc_sig_seal = valid_seal.clone();
    trunc_sig_seal.signature.truncate(63);
    let trunc_err = signer
        .validate_and_consume(&trunc_sig_seal, action_digest, record_hash, now)
        .expect_err("Truncated signature must be rejected");
    assert!(matches!(trunc_err, SealRejection::InvalidSignature | SealRejection::MalformedSeal(_)));

    // 3. Attack: Single-nibble mutation in record_hash (audit anchor tampering)
    let mut tampered_anchor_seal = valid_seal.clone();
    tampered_anchor_seal.record_hash = "8".to_string() + &valid_seal.record_hash[1..];
    let anchor_err = signer
        .validate_and_consume(&tampered_anchor_seal, action_digest, record_hash, now)
        .expect_err("Tampered record_hash must be rejected");
    assert!(matches!(anchor_err, SealRejection::RecordHashMismatch { .. }));

    // 4. Attack: Issuing seal against unanchored / genesis audit hash (Tallam 2026 Evidence Sufficiency)
    let zeros_hash = "0".repeat(64);
    let unanchored_err1 = signer.issue_seal(action_digest, &zeros_hash, now);
    assert!(matches!(unanchored_err1, Err(SealRejection::UnanchoredEvidence(_))));

    let genesis_hash = format!("GENESIS_AUDIT_ROOT_{}", "0".repeat(45));
    let unanchored_err2 = signer.issue_seal(action_digest, &genesis_hash, now);
    assert!(matches!(unanchored_err2, Err(SealRejection::UnanchoredEvidence(_))));
}

#[test]
fn test_challenge3_temporal_ttl_skew_and_tampered_expires_at() {
    let secret = b"challenger_m4_temporal_secret32_";
    let policy_ver = "1234567890abcdef";
    let signer = RoutingSealSigner::new(secret, policy_ver);

    let action_digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let record_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let seal = signer.issue_seal(action_digest, record_hash, now).expect("Seal issuance");

    // 1. TTL Expiration: evaluation at now + 31s (> 30s TTL)
    let exp_err = signer
        .validate_and_consume(&seal, action_digest, record_hash, now + 31)
        .expect_err("Expired seal must be rejected");
    assert!(matches!(exp_err, SealRejection::Expired { .. }));

    // 2. Clock drift: seal issued in future > 5s (now + 6s)
    let future_seal = signer.issue_seal(action_digest, record_hash, now + 6).expect("future seal");
    let future_err = signer
        .validate_and_consume(&future_seal, action_digest, record_hash, now)
        .expect_err("Future seal with > 5s skew must be rejected");
    assert!(matches!(future_err, SealRejection::FutureTimestamp { .. }));

    // 3. Clock drift within tolerance: seal issued at now + 4s -> accepted
    let tol_seal = signer.issue_seal(action_digest, record_hash, now + 4).expect("tol seal");
    assert!(signer.validate_and_consume(&tol_seal, action_digest, record_hash, now).is_ok());

    // 4. Adversary tampers `expires_at` in seal struct (sets expires_at = now + 3600 to defeat TTL)
    let mut tampered_exp_seal = seal.clone();
    tampered_exp_seal.expires_at = now + 3600;
    let structural_err = signer
        .validate_and_consume(&tampered_exp_seal, action_digest, record_hash, now)
        .expect_err("Manipulated expires_at must fail structural TTL invariant check");
    assert!(matches!(structural_err, SealRejection::MalformedSeal(_)));
}

#[test]
fn test_challenge3_concurrent_multithreaded_race_replay_single_winner() {
    let secret = b"challenger_m4_race_secret_key32_";
    let policy_ver = "aabbccddeeff0011";
    let signer = Arc::new(RoutingSealSigner::new(secret, policy_ver));

    let action_digest = "ccccddddccccddddccccddddccccddddccccddddccccddddccccddddccccdddd";
    let record_hash = "eeeeffffeeeeffffeeeeffffeeeeffffeeeeffffeeeeffffeeeeffffeeeeffff";
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let seal = signer.issue_seal(action_digest, record_hash, now).expect("Seal issuance");

    // Launch 32 OS threads all racing to consume the exact same seal simultaneously
    let thread_count = 32;
    let barrier = Arc::new(Barrier::new(thread_count));
    let success_count = Arc::new(AtomicUsize::new(0));
    let replay_reject_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..thread_count {
        let s = Arc::clone(&signer);
        let b = Arc::clone(&barrier);
        let sc = Arc::clone(&success_count);
        let rc = Arc::clone(&replay_reject_count);
        let seal_clone = seal.clone();

        handles.push(std::thread::spawn(move || {
            b.wait(); // Synchronize all threads to hammer validate_and_consume simultaneously
            match s.validate_and_consume(&seal_clone, action_digest, record_hash, now) {
                Ok(_) => {
                    sc.fetch_add(1, Ordering::SeqCst);
                }
                Err(SealRejection::AlreadyConsumed(_)) => {
                    rc.fetch_add(1, Ordering::SeqCst);
                }
                Err(other) => {
                    panic!("Unexpected rejection: {:?}", other);
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // STRICT INVARIANT: Exactly 1 thread succeeds, exactly 31 threads are rejected with AlreadyConsumed
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        1,
        "Strictly 1 thread must win the consumption race"
    );
    assert_eq!(
        replay_reject_count.load(Ordering::SeqCst),
        thread_count - 1,
        "All other {} threads must be rejected with AlreadyConsumed",
        thread_count - 1
    );
}

#[tokio::test]
async fn test_challenge3_arm_containment_ring_async_race_single_actuation() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = Arc::new(
        ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, CHALLENGER_MASTER_SEED)
            .with_cage_engine(Arc::clone(&engine)),
    );

    let dispatcher = Arc::new(test_dispatcher());
    let scratch_root = std::env::temp_dir().join(format!("challenger_race_{}", std::process::id()));
    let payload = b"{\"action\": \"read_contract\"}".to_vec();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let seal = Arc::new(create_test_seal_anchored(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        CHALLENGER_RESOURCE,
        &payload,
        now,
    ));

    let task_count = 16;
    let barrier = Arc::new(tokio::sync::Barrier::new(task_count));
    let act_success = Arc::new(AtomicUsize::new(0));
    let act_replay = Arc::new(AtomicUsize::new(0));

    let mut tasks = Vec::new();
    for i in 0..task_count {
        let r = Arc::clone(&ring);
        let d = Arc::clone(&dispatcher);
        let s = Arc::clone(&seal);
        let bar = Arc::clone(&barrier);
        let succ = Arc::clone(&act_success);
        let rep = Arc::clone(&act_replay);
        let p = payload.clone();
        let s_root = scratch_root.clone();

        tasks.push(tokio::spawn(async move {
            let mut ticket = r
                .issue_dirac_ticket("doc_extractor", CHALLENGER_RESOURCE, 50_000, None)
                .await
                .expect("ticket");

            let req = TieredToolRequest {
                agent_id: r.agent_name.clone(),
                role: ArmRole::UntrustedDocIngest,
                tool_name: "doc_extractor".to_string(),
                payload: p,
                custom_wat: None,
                native_command: None,
                scratchpad_root: s_root,
                allow_scratch_write: false,
            };

            bar.wait().await;
            match r
                .execute_tool_with_cage_seal(
                    &mut ticket,
                    &s,
                    CHALLENGER_RESOURCE,
                    &req,
                    &d,
                    None,
                    None,
                )
                .await
            {
                Ok(_) => {
                    succ.fetch_add(1, Ordering::SeqCst);
                }
                Err(ArmExecutionError::SealAlreadyConsumed { .. }) => {
                    rep.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => {
                    panic!("Task {} unexpected error: {:?}", i, e);
                }
            }
        }));
    }

    for t in tasks {
        t.await.unwrap();
    }

    // STRICT INVARIANT: Exactly 1 actuation executes; exactly 15 fail with SealAlreadyConsumed
    assert_eq!(
        act_success.load(Ordering::SeqCst),
        1,
        "Exactly 1 async actuation must succeed"
    );
    assert_eq!(
        act_replay.load(Ordering::SeqCst),
        task_count - 1,
        "Exactly {} actuations must be rejected with SealAlreadyConsumed",
        task_count - 1
    );
}

// ==============================================================================
// CHALLENGE 4: GOVERNANCE_TRACE STREAM INJECTION & RULE CONFORMANCE ATTACKS
// ==============================================================================

#[test]
fn test_challenge4_trace_injection_actuation_without_seal_consumed_rule6() {
    // Attack 4.1: Inject ACTUATION_RECEIPT referencing a rogue seal that has no preceding
    // GOVERNANCE_SEAL_CONSUMED record in the trace stream.
    let injection_stream = vec![
        serde_json::json!({
            "event_type": "ACTUATION_RECEIPT",
            "agent_id": "arm_01",
            "record_hash": "a".repeat(64),
            "seal_id": "unconsumed_forged_seal_666",
            "action": "doc_extractor",
            "status": "SUCCESS"
        })
    ];

    let report = FormalBfsModel::check_trace_conformance(&injection_stream);
    assert_eq!(report.status, StreamConformanceStatus::NonConformant);
    assert!(
        report.has_rule_violation("no_direct_bind"),
        "Must violate Rule 6: no_direct_bind when actuation receipt lacks prior consumed seal"
    );

    // Attack 4.2: Inject ACTUATION_EXECUTED event type without consumed seal
    let exec_stream = vec![
        serde_json::json!({
            "event_type": "ACTUATION_EXECUTED",
            "agent_id": "arm_01",
            "record_hash": "b".repeat(64),
            "seal_id": "forged_exec_seal_777",
            "action": "doc_extractor",
            "status": "SUCCESS"
        })
    ];
    let report_exec = FormalBfsModel::check_trace_conformance(&exec_stream);
    assert_eq!(report_exec.status, StreamConformanceStatus::NonConformant);
    assert!(report_exec.has_rule_violation("no_direct_bind"));

    // Attack 4.3: Inject GOVERNANCE_EXECUTION event type with empty seal_id
    let empty_seal_stream = vec![
        serde_json::json!({
            "event_type": "GOVERNANCE_EXECUTION",
            "agent_id": "arm_01",
            "record_hash": "c".repeat(64),
            "seal_id": "",
            "action": "unauthorized_tool",
            "status": "SUCCESS"
        })
    ];
    let report_empty = FormalBfsModel::check_trace_conformance(&empty_seal_stream);
    assert_eq!(report_empty.status, StreamConformanceStatus::NonConformant);
    assert!(report_empty.has_rule_violation("no_direct_bind"));
}

#[test]
fn test_challenge4_trace_injection_missing_decision_and_unsealed_verdict() {
    // Attack 4.4: Inject GOVERNANCE_SEAL_CONSUMED referencing an unknown decision hash
    let orphan_seal_consumed = vec![
        serde_json::json!({
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "agent_id": "arm_01",
            "record_hash": "1".repeat(64),
            "decision_record_hash": "9".repeat(64), // Missing decision hash!
            "seal_id": "orphan_seal_101",
            "action": "doc_extractor"
        })
    ];
    let report_orphan = FormalBfsModel::check_trace_conformance(&orphan_seal_consumed);
    assert_eq!(report_orphan.status, StreamConformanceStatus::NonConformant);
    assert!(report_orphan.has_rule_violation("no_direct_bind"));

    // Attack 4.5: Inject GOVERNANCE_DECISION with ALLOW verdict but seal_present = false (Rule 4: seal)
    let unsealed_decision = vec![
        serde_json::json!({
            "event_type": "GOVERNANCE_DECISION",
            "agent_id": "arm_01",
            "record_hash": "2".repeat(64),
            "verdict": "ALLOW",
            "seal_present": false, // VIOLATION: ALLOW requires seal_present = true
            "stages_evaluated": [
                {"stage_name": "ftra"},
                {"stage_name": "stpa"},
                {"stage_name": "opa"},
                {"stage_name": "confidence"},
                {"stage_name": "consensus"},
                {"stage_name": "cbf"},
                {"stage_name": "fiscal"},
            ]
        })
    ];
    let report_seal = FormalBfsModel::check_trace_conformance(&unsealed_decision);
    assert_eq!(report_seal.status, StreamConformanceStatus::NonConformant);
    assert!(
        report_seal.has_rule_violation("seal"),
        "Must flag Rule 4: seal violation when ALLOW lacks seal_present"
    );
}

#[test]
fn test_challenge4_trace_injection_replay_coverage_and_illegal_state_transition() {
    let dec_hash = "3".repeat(64);
    let seal_id = "replayed_seal_888";

    // Attack 4.6: Injected duplicate seal consumption (Rule 7: single_use)
    let replay_trace = vec![
        serde_json::json!({
            "event_type": "GOVERNANCE_DECISION",
            "agent_id": "arm_01",
            "record_hash": dec_hash.clone(),
            "verdict": "ALLOW",
            "seal_present": true,
            "stages_evaluated": [
                {"stage_name": "ftra"},
                {"stage_name": "stpa"},
                {"stage_name": "opa"},
                {"stage_name": "confidence"},
                {"stage_name": "consensus"},
                {"stage_name": "cbf"},
                {"stage_name": "fiscal"},
            ]
        }),
        serde_json::json!({
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "agent_id": "arm_01",
            "record_hash": "4".repeat(64),
            "decision_record_hash": dec_hash.clone(),
            "seal_id": seal_id,
            "action": "doc_extractor"
        }),
        // Injected replay consumption of the same seal_id
        serde_json::json!({
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "agent_id": "arm_02",
            "record_hash": "5".repeat(64),
            "decision_record_hash": dec_hash,
            "seal_id": seal_id,
            "action": "doc_extractor"
        }),
    ];
    let report_replay = FormalBfsModel::check_trace_conformance(&replay_trace);
    assert_eq!(report_replay.status, StreamConformanceStatus::NonConformant);
    assert!(
        report_replay.has_rule_violation("single_use"),
        "Must flag Rule 7: single_use on duplicate seal consumption in audit trail"
    );

    // Attack 4.7: Incomplete stage coverage (Rule 3: coverage)
    let incomplete_coverage = vec![
        serde_json::json!({
            "event_type": "GOVERNANCE_DECISION",
            "agent_id": "arm_01",
            "record_hash": "6".repeat(64),
            "verdict": "ALLOW",
            "seal_present": true,
            "stages_evaluated": [
                {"stage_name": "ftra"},
                {"stage_name": "stpa"},
                {"stage_name": "opa"},
                // Omitted confidence, consensus, cbf, fiscal
            ]
        })
    ];
    let report_cov = FormalBfsModel::check_trace_conformance(&incomplete_coverage);
    assert_eq!(report_cov.status, StreamConformanceStatus::NonConformant);
    assert!(
        report_cov.has_rule_violation("coverage"),
        "Must flag Rule 3: coverage when tiers are missing from governance decision"
    );

    // Attack 4.8: Illegal state machine transition skipping all checking tiers (Rule 5: reachable)
    let illegal_transition = vec![
        serde_json::json!({
            "event_type": "STATE_TRANSITION",
            "phase": "EXECUTED",
            "label": "unauthorized_jump",
            "tier": 0
        })
    ];
    let report_reach = FormalBfsModel::check_trace_conformance(&illegal_transition);
    assert_eq!(report_reach.status, StreamConformanceStatus::NonConformant);
    assert!(
        report_reach.has_rule_violation("reachable"),
        "Must flag Rule 5: reachable on illegal state machine transition"
    );
}

#[test]
fn test_challenge4_trace_injection_cbf_budget_leakage_and_schema_violations() {
    // Attack 4.9: CBF Rollback budget leakage
    // Injected CBF_COMMIT of cost 50.0, but CBF_ROLLBACK restores only 40.0 (leakage 10.0)
    let leakage_trace = vec![
        serde_json::json!({
            "event_type": "CBF_COMMIT",
            "debit_id": "debit_leak_01",
            "state_before": 100.0,
            "cost": 50.0,
            "b_min": 10.0,
            "gamma": 0.5,
        }),
        serde_json::json!({
            "event_type": "CBF_ROLLBACK",
            "debit_id": "debit_leak_01",
            "status": "ROLLED_BACK",
            "restored_amount": 40.0, // LEAKAGE: committed 50 != restored 40
        }),
    ];
    let report_leak = FormalBfsModel::check_trace_conformance(&leakage_trace);
    assert_eq!(report_leak.status, StreamConformanceStatus::NonConformant);
    assert!(report_leak.findings.iter().any(|f| f.rule == "cbf_rollback"));

    // Attack 4.10: Schema violation with uppercase hex characters in record_hash (Rule 1: schema)
    let bad_schema_trace = vec![
        serde_json::json!({
            "event_type": "GOVERNANCE_DECISION",
            "record_hash": "A".repeat(64), // Uppercase hex violates ^[0-9a-f]{64}$
            "verdict": "DENY",
        })
    ];
    let report_schema = FormalBfsModel::check_trace_conformance(&bad_schema_trace);
    assert_eq!(report_schema.status, StreamConformanceStatus::NonConformant);
    assert!(report_schema.has_rule_violation("schema"));
}
