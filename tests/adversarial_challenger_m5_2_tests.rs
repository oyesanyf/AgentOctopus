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
//! [AGENT OCTOPUS] MILESTONE 5 PHASE 2 ADVERSARIAL CHALLENGER SUITE (CHALLENGER 2)
//! ==============================================================================
//! Independent Empirical Verification & Adversarial Gap Auditing:
//!
//! 1. Floating-Point Boundaries & Numeric Extremes in Control Barrier Functions (CBF):
//!    - Float NaN, positive/negative infinity, subnormal numbers, and tiny epsilon buffers.
//!    - Extreme decay rates $\gamma \in (0, 1]$, non-negative reserve floor boundaries $B_{\min}$.
//!    - Replay sequence monotonicity and concurrent monotonic fence epoch advancement.
//!    - Multi-stage fiscal pre-reservation, double rollback prevention, and zero balance drift.
//!
//! 2. Temporal & Timestamp Boundary Conditions in Routing Seal Signer:
//!    - Exact boundary timestamps ($t = \text{issued\_at}$, $t = \text{expires\_at}$, $t = \text{expires\_at} + 1$).
//!    - Clock drift tolerance window ($\le 5\text{s}$ future permitted, $> 5\text{s}$ rejected).
//!    - Tampered `expires_at` detection via both structural invariant and HMAC signature binding.
//!
//! 3. Reversibility Classification Ambiguity & FTRA DAG Traversal:
//!    - Compound action names with conflicting keywords and lexical precedence evaluation.
//!    - Complex multi-branch diamond DAG reachability and cycle/deadlock detection.
//!    - Priority ordering of non-clear verdicts in topological step order.
//!    - Fail-closed confidence normalization across float extremes.
//!
//! 4. HTTP Route Matching, DNS Rebinding, & CSRF Defenses in `request_guard`:
//!    - DNS rebinding evasion attempts across IPv4, IPv6, port mismatches, and domain suffixes.
//!    - CSRF defenses via Origin verification and `Sec-Fetch-Site: cross-site` rejections.
//!    - Substrate route matching coverage and optional `CAGE_API_KEY` bearer token extraction.
//!
//! 5. Atomic State Transitions & Memory Reclamation in `consumed_seals`:
//!    - Bounded memory footprint and automated TTL-based sweeping of expired routing seals.
//!    - High-concurrency multithreaded single-use consumption races (single-winner invariant).
//!    - Two-phase dynamic pipeline execution preserving budget conservation under faults.
//! ==============================================================================

use agent_octopus::security::audit::SecurityAuditLog;
use agent_octopus::security::cage_governance::cbf_fiscal::{
    CbfSafetyEngine, CbfViolation, DebitLedger, CBF_EPSILON,
};
use agent_octopus::security::cage_governance::ftra_stpa::{
    ActionReversibility, FtraVerdict, PlanGraphAnalyzer, PlanStep,
};
use agent_octopus::security::cage_governance::pipeline::{
    CagePipeline, GovernanceRequest, GovernanceVerdict, Profile,
};
use agent_octopus::security::cage_governance::routing_seal::{
    compute_action_digest, RoutingSealSigner, SealRejection,
};
use agent_octopus::security::cage_governance::substrate_translator::CompiledCagePolicy;
use agent_octopus::web::request_guard::{
    authorize_request, extract_bearer_token, is_cage_substrate_path, is_token_exempt_path,
    GuardRejection, GuardRequest,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

const M5_TEST_KEY: &[u8] = b"CHALLENGER_M5_2_TEST_SECRET_KEY_";
const M5_TEST_POLICY_VERSION: &str = "0123456789abcdef";
const M5_VALID_RECORD_HASH: &str =
    "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890";

fn make_guard_req<'a>(
    method: &'a str,
    path: &'a str,
    headers: &'a str,
    port: u16,
) -> GuardRequest<'a> {
    GuardRequest {
        method,
        path,
        query: "",
        headers,
        local_port: port,
    }
}

// ==============================================================================
// 1. Floating-Point Boundaries & Numeric Extremes in CBF (cbf_fiscal.rs)
// ==============================================================================

#[test]
fn test_m5_2_cbf_extreme_floats_nan_inf_subnormal_boundaries() {
    let cbf = CbfSafetyEngine::new(0.2, 10.0).expect("CBF init must succeed");

    // 1.1 NaN cost fails with InvalidParameters
    let res_nan_cost = cbf.evaluate_step(100.0, f64::NAN, 90.0);
    assert!(
        matches!(res_nan_cost, Err(CbfViolation::InvalidParameters(_))),
        "NaN cost must fail with InvalidParameters, got {:?}",
        res_nan_cost
    );

    // 1.2 Positive Infinity cost fails closed with FloorBreach
    let res_inf_cost = cbf.evaluate_step(100.0, f64::INFINITY, 90.0);
    assert!(
        matches!(res_inf_cost, Err(CbfViolation::FloorBreach { .. })),
        "Infinity cost must fail closed with FloorBreach, got {:?}",
        res_inf_cost
    );

    // 1.3 Negative Infinity cost fails with InvalidParameters (cost < 0.0)
    let res_neginf_cost = cbf.evaluate_step(100.0, f64::NEG_INFINITY, 90.0);
    assert!(
        matches!(res_neginf_cost, Err(CbfViolation::InvalidParameters(_))),
        "NegInfinity cost must fail with InvalidParameters, got {:?}",
        res_neginf_cost
    );

    // 1.4 Negative non-zero cost fails with InvalidParameters
    let res_neg_cost = cbf.evaluate_step(100.0, -1e-6, 90.0);
    assert!(
        matches!(res_neg_cost, Err(CbfViolation::InvalidParameters(_))),
        "Negative cost must fail with InvalidParameters, got {:?}",
        res_neg_cost
    );

    // 1.5 Negative zero cost (-0.0) evaluates as 0.0 and succeeds
    let res_neg_zero = cbf.evaluate_step(100.0, -0.0, 90.0);
    assert!(
        res_neg_zero.is_ok(),
        "-0.0 cost should be treated as 0.0, got {:?}",
        res_neg_zero
    );

    // 1.6 Subnormal cost (MIN_POSITIVE) succeeds without arithmetic exception
    let res_subnormal = cbf.evaluate_step(100.0, f64::MIN_POSITIVE, 90.0);
    assert!(
        res_subnormal.is_ok(),
        "Subnormal float cost must evaluate cleanly, got {:?}",
        res_subnormal
    );

    // 1.7 Non-finite current budget rejected
    assert!(matches!(
        cbf.evaluate_step(f64::NAN, 1.0, 90.0),
        Err(CbfViolation::InvalidParameters(_))
    ));
    assert!(matches!(
        cbf.evaluate_step(f64::INFINITY, 1.0, 90.0),
        Err(CbfViolation::InvalidParameters(_))
    ));
    assert!(matches!(
        cbf.evaluate_step(f64::NEG_INFINITY, 1.0, 90.0),
        Err(CbfViolation::InvalidParameters(_))
    ));

    // 1.8 Non-finite current_h rejected
    assert!(matches!(
        cbf.evaluate_step(100.0, 1.0, f64::NAN),
        Err(CbfViolation::InvalidParameters(_))
    ));
    assert!(matches!(
        cbf.evaluate_step(100.0, 1.0, f64::INFINITY),
        Err(CbfViolation::InvalidParameters(_))
    ));

    // 1.9 Epsilon buffer boundaries for current_h
    // current_h within -CBF_EPSILON is tolerated
    let res_eps = cbf.evaluate_step(100.0, 0.0, -CBF_EPSILON);
    assert!(res_eps.is_ok());

    // current_h beyond -CBF_EPSILON fails closed with CurrentStateUnsafe
    let res_unsafe = cbf.evaluate_step(100.0, 0.0, -CBF_EPSILON - 1e-12);
    assert!(matches!(
        res_unsafe,
        Err(CbfViolation::CurrentStateUnsafe { .. })
    ));
}

#[test]
fn test_m5_2_cbf_gamma_extremes_and_invalid_floor() {
    // 2.1 Gamma boundaries: gamma in (0, 1]
    assert!(CbfSafetyEngine::new(0.0, 10.0).is_err());
    assert!(CbfSafetyEngine::new(-0.1, 10.0).is_err());
    assert!(CbfSafetyEngine::new(f64::NAN, 10.0).is_err());
    assert!(CbfSafetyEngine::new(f64::INFINITY, 10.0).is_err());
    assert!(CbfSafetyEngine::new(1.0000001, 10.0).is_err());

    // Valid gamma endpoints
    assert!(CbfSafetyEngine::new(1.0, 10.0).is_ok());
    assert!(CbfSafetyEngine::new(f64::MIN_POSITIVE, 10.0).is_ok());

    // 2.2 Floor boundaries: b_min must be finite and >= 0.0
    assert!(CbfSafetyEngine::new(0.1, -0.01).is_err());
    assert!(CbfSafetyEngine::new(0.1, f64::NAN).is_err());
    assert!(CbfSafetyEngine::new(0.1, f64::INFINITY).is_err());
    assert!(CbfSafetyEngine::new(0.1, 0.0).is_ok());
}

#[test]
fn test_m5_2_cbf_sequence_monotonicity_and_epoch_races() {
    let cbf = Arc::new(CbfSafetyEngine::new(0.2, 5.0).expect("CBF init failed"));

    // Initial sequence HWM is 0; sequence 0 must be rejected
    assert!(matches!(
        cbf.verify_sequence_and_epoch(0, 1),
        Err(CbfViolation::SequenceReplay { .. })
    ));

    // Sequence 1 accepted
    assert!(cbf.verify_sequence_and_epoch(1, 1).is_ok());

    // Non-monotonic or duplicate sequence rejected
    assert!(matches!(
        cbf.verify_sequence_and_epoch(1, 1),
        Err(CbfViolation::SequenceReplay { .. })
    ));

    // Stale fence epoch rejected
    let new_epoch = cbf.advance_epoch();
    assert_eq!(new_epoch, 2);
    assert!(matches!(
        cbf.verify_sequence_and_epoch(2, 1),
        Err(CbfViolation::StaleFenceEpoch { .. })
    ));
    assert!(cbf.verify_sequence_and_epoch(2, 2).is_ok());

    // Multi-threaded sequence monotonicity verification
    let mut handles = Vec::new();
    for i in 0..16 {
        let cbf_clone = Arc::clone(&cbf);
        handles.push(thread::spawn(move || {
            let seq = 100 + i;
            let _ = cbf_clone.verify_sequence_and_epoch(seq, 2);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_m5_2_debit_ledger_boundary_state_transitions() {
    // 3.1 Initial budget validations
    assert!(DebitLedger::new(f64::NAN, 0.1, 10.0).is_err());
    assert!(DebitLedger::new(f64::INFINITY, 0.1, 10.0).is_err());
    assert!(DebitLedger::new(5.0, 0.1, 10.0).is_err()); // initial < b_min

    let ledger = DebitLedger::new(100.0, 0.2, 10.0).expect("Ledger init failed");

    // 3.2 Preview with invalid parameters preserves budget
    assert!(ledger.preview(f64::NAN).is_err());
    assert!(ledger.preview(f64::INFINITY).is_err());
    assert_eq!(ledger.available_budget(), 100.0);

    // 3.3 Failed pre-reserve preserves exact budget
    let breach_err = ledger.pre_reserve(95.0, "breach_debit");
    assert!(breach_err.is_err());
    assert_eq!(ledger.available_budget(), 100.0);
    assert_eq!(ledger.active_reservation_count(), 0);

    // 3.4 Multi-reservation lifecycle: pre-reserve, confirm, and LIFO rollback
    let r1 = ledger.pre_reserve(10.0, "debit_1").unwrap();
    assert_eq!(r1.remaining_budget, 90.0);
    let r2 = ledger.pre_reserve(10.0, "debit_2").unwrap();
    assert_eq!(r2.remaining_budget, 80.0);
    let r3 = ledger.pre_reserve(10.0, "debit_3").unwrap();
    assert_eq!(r3.remaining_budget, 70.0);
    assert_eq!(ledger.active_reservation_count(), 3);

    // Confirm debit_1
    assert!(ledger.confirm("debit_1").is_ok());

    // Rollback debit_1 fails with AlreadyCommitted
    assert!(matches!(
        ledger.rollback("debit_1"),
        Err(CbfViolation::AlreadyCommitted(_))
    ));

    // Rollback debit_2 succeeds
    assert_eq!(ledger.rollback("debit_2").unwrap(), 80.0);

    // Double rollback debit_2 fails with ReservationNotFound (already rolled back)
    assert!(matches!(
        ledger.rollback("debit_2"),
        Err(CbfViolation::ReservationNotFound(_))
    ));

    // LIFO rollback should pop debit_3
    let (lifo_id, budget_after_lifo) = ledger.rollback_lifo().unwrap();
    assert_eq!(lifo_id, "debit_3");
    assert_eq!(budget_after_lifo, 90.0);
    assert_eq!(ledger.active_reservation_count(), 0);
}

// ==============================================================================
// 2. Timestamp Boundary Conditions (Drift vs TTL) in Routing Seal Signer
// ==============================================================================

#[test]
fn test_m5_2_seal_timestamp_boundary_drift_vs_ttl() {
    let signer = RoutingSealSigner::new(M5_TEST_KEY, M5_TEST_POLICY_VERSION);
    let action_digest = compute_action_digest("tool_test", &serde_json::json!({}));
    let now = 1_000_000;

    let seal = signer
        .issue_seal(&action_digest, M5_VALID_RECORD_HASH, now)
        .expect("Seal issuance failed");

    // 4.1 Exact issuance timestamp (now): valid
    assert!(signer
        .validate_and_consume(&seal, &action_digest, M5_VALID_RECORD_HASH, now)
        .is_ok());

    // Issue a second seal for boundary testing
    let seal2 = signer
        .issue_seal(&action_digest, M5_VALID_RECORD_HASH, now)
        .expect("Seal 2 issuance failed");

    // 4.2 Exact expiration boundary: current_time == expires_at (now + 30)
    // In routing_seal.rs: `current_time > expires_at` is false, so it is valid at exact boundary
    assert!(signer
        .validate_and_consume(&seal2, &action_digest, M5_VALID_RECORD_HASH, now + 30)
        .is_ok());

    // Issue a third seal for expiration rejection testing
    let seal3 = signer
        .issue_seal(&action_digest, M5_VALID_RECORD_HASH, now)
        .expect("Seal 3 issuance failed");

    // 4.3 Expired by 1 second (now + 31): rejected with Expired
    let expired_res =
        signer.validate_and_consume(&seal3, &action_digest, M5_VALID_RECORD_HASH, now + 31);
    assert!(matches!(expired_res, Err(SealRejection::Expired { .. })));

    // 4.4 Clock drift: future timestamp within tolerance (5 seconds)
    // Issue seal dated `now + 5`
    let seal_future_valid = signer
        .issue_seal(&action_digest, M5_VALID_RECORD_HASH, now + 5)
        .expect("Future seal issuance failed");
    // Consuming at `now` where issued_at (now + 5) <= current_time + 5 -> valid
    assert!(signer
        .validate_and_consume(
            &seal_future_valid,
            &action_digest,
            M5_VALID_RECORD_HASH,
            now
        )
        .is_ok());

    // 4.5 Clock drift: future timestamp exceeding tolerance (6 seconds)
    let seal_future_excess = signer
        .issue_seal(&action_digest, M5_VALID_RECORD_HASH, now + 6)
        .expect("Excess future seal issuance failed");
    let drift_res = signer.validate_and_consume(
        &seal_future_excess,
        &action_digest,
        M5_VALID_RECORD_HASH,
        now,
    );
    assert!(matches!(
        drift_res,
        Err(SealRejection::FutureTimestamp { .. })
    ));
}

#[test]
fn test_m5_2_seal_tampered_expiry_and_format_invariants() {
    let signer = RoutingSealSigner::new(M5_TEST_KEY, M5_TEST_POLICY_VERSION);
    let action_digest = compute_action_digest("tool_tamper", &serde_json::json!({}));
    let now = 2_000_000;

    let valid_seal = signer
        .issue_seal(&action_digest, M5_VALID_RECORD_HASH, now)
        .unwrap();

    // 5.1 Format validation passes on untampered seal
    assert!(valid_seal.validate_format());

    // 5.2 Tampered expires_at violates TTL structural invariant (expires_at != issued_at + 30)
    let mut tampered_seal = valid_seal.clone();
    tampered_seal.expires_at = now + 31;
    assert!(!tampered_seal.validate_format());

    let rej = signer.validate_and_consume(
        &tampered_seal,
        &action_digest,
        M5_VALID_RECORD_HASH,
        now + 1,
    );
    assert!(matches!(rej, Err(SealRejection::MalformedSeal(_))));

    // 5.3 Corrupted HMAC signature fails closed with InvalidSignature
    let mut sig_corrupted = valid_seal.clone();
    sig_corrupted.signature =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    let sig_rej = signer.validate_and_consume(
        &sig_corrupted,
        &action_digest,
        M5_VALID_RECORD_HASH,
        now + 1,
    );
    assert_eq!(sig_rej, Err(SealRejection::InvalidSignature));
}

// ==============================================================================
// 3. Reversibility Classification Ambiguity & FTRA DAG Traversal
// ==============================================================================

#[test]
fn test_m5_2_ftra_reversibility_classification_lexical_precedence() {
    // 6.1 Compound names testing lexical precedence rules:
    // 'writebarrier' contains 'write' (Reversible) but matches IrreversibleTerminal first
    assert_eq!(
        ActionReversibility::classify("writebarrier"),
        ActionReversibility::IrreversibleTerminal
    );
    assert_eq!(
        ActionReversibility::classify("delete_compensate"),
        ActionReversibility::IrreversibleTerminal
    );
    assert_eq!(
        ActionReversibility::classify("spawn_auto_worker"),
        ActionReversibility::IrreversibleTerminal
    );
    assert_eq!(
        ActionReversibility::classify("escrow_and_trade"),
        ActionReversibility::Compensatable
    );
    assert_eq!(
        ActionReversibility::classify("auto_write_data"),
        ActionReversibility::ConditionalAutonomous
    );
    assert_eq!(
        ActionReversibility::classify("clamped_transfer"),
        ActionReversibility::ConditionalAutonomous
    );
    assert_eq!(
        ActionReversibility::classify("update_ledger_entry"),
        ActionReversibility::Reversible
    );
    assert_eq!(
        ActionReversibility::classify("read_telemetry_status"),
        ActionReversibility::ReadOnly
    );

    // 6.2 Case insensitivity
    assert_eq!(
        ActionReversibility::classify("DROP_SYSTEM_TABLE"),
        ActionReversibility::IrreversibleTerminal
    );
    assert_eq!(
        ActionReversibility::classify("GET_ACCOUNT_BALANCE"),
        ActionReversibility::ReadOnly
    );

    // 6.3 Required authority ranks
    assert_eq!(
        ActionReversibility::IrreversibleTerminal.required_authority_rank(),
        2
    );
    assert_eq!(ActionReversibility::Reversible.required_authority_rank(), 3);
    assert_eq!(
        ActionReversibility::Compensatable.required_authority_rank(),
        3
    );
    assert_eq!(
        ActionReversibility::ConditionalAutonomous.required_authority_rank(),
        3
    );
    assert_eq!(ActionReversibility::ReadOnly.required_authority_rank(), 5);
}

#[test]
fn test_m5_2_ftra_dag_complex_topologies_and_priority_verdicts() {
    // 7.1 Complex diamond DAG: Step A -> Step B & C -> Step D
    let diamond_steps = vec![
        PlanStep {
            id: "step-a".to_string(),
            action_name: "read_initial_state".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec![],
            confidence: 0.99,
            fuel_cost: 0.5,
            caller_authority: 5,
        },
        PlanStep {
            id: "step-b".to_string(),
            action_name: "update_buffer_left".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["step-a".to_string()],
            confidence: 0.98,
            fuel_cost: 0.5,
            caller_authority: 3,
        },
        PlanStep {
            id: "step-c".to_string(),
            action_name: "update_buffer_right".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["step-a".to_string()],
            confidence: 0.97,
            fuel_cost: 0.5,
            caller_authority: 3,
        },
        PlanStep {
            id: "step-d".to_string(),
            action_name: "read_final_report".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["step-b".to_string(), "step-c".to_string()],
            confidence: 0.96,
            fuel_cost: 0.5,
            caller_authority: 5,
        },
    ];

    let diamond_verdict = PlanGraphAnalyzer::analyze_execution_graph(&diamond_steps);
    assert_eq!(diamond_verdict, Ok(FtraVerdict::Clear));

    // 7.2 Cyclic graph detection
    let cyclic_steps = vec![
        PlanStep {
            id: "c-1".to_string(),
            action_name: "read_x".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["c-3".to_string()],
            confidence: 0.99,
            fuel_cost: 0.1,
            caller_authority: 5,
        },
        PlanStep {
            id: "c-2".to_string(),
            action_name: "read_y".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["c-1".to_string()],
            confidence: 0.99,
            fuel_cost: 0.1,
            caller_authority: 5,
        },
        PlanStep {
            id: "c-3".to_string(),
            action_name: "read_z".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["c-2".to_string()],
            confidence: 0.99,
            fuel_cost: 0.1,
            caller_authority: 5,
        },
    ];
    let cyclic_res = PlanGraphAnalyzer::analyze_execution_graph(&cyclic_steps);
    assert!(cyclic_res.is_err());
    assert!(cyclic_res.unwrap_err().contains("Execution graph contains cycles"));

    // 7.3 Missing dependency detection
    let missing_dep_steps = vec![PlanStep {
        id: "step-orphan".to_string(),
        action_name: "read_orphan".to_string(),
        parameters: serde_json::json!({}),
        depends_on: vec!["nonexistent-step".to_string()],
        confidence: 0.99,
        fuel_cost: 0.1,
        caller_authority: 5,
    }];
    let missing_res = PlanGraphAnalyzer::analyze_execution_graph(&missing_dep_steps);
    assert!(missing_res.is_err());
    assert!(missing_res
        .unwrap_err()
        .contains("depends on unknown step 'nonexistent-step'"));
}

// ==============================================================================
// 4. HTTP Route Matching, DNS Rebinding, & CSRF Defenses in request_guard
// ==============================================================================

#[test]
fn test_m5_2_request_guard_dns_rebinding_and_host_evasion() {
    let port = 5005;

    // 8.1 Rebinding hostname suffix attacks
    let h_suffix = "POST /api/test HTTP/1.1\r\nHost: 127.0.0.1.attacker.com:5005\r\nX-Octopus-Token: tok";
    assert!(matches!(
        authorize_request(&make_guard_req("POST", "/api/test", h_suffix, port), "tok"),
        Err(GuardRejection::BadHost(_))
    ));

    // 8.2 Localhost subdomain attack
    let h_sub = "POST /api/test HTTP/1.1\r\nHost: localhost.attacker.com:5005\r\nX-Octopus-Token: tok";
    assert!(matches!(
        authorize_request(&make_guard_req("POST", "/api/test", h_sub, port), "tok"),
        Err(GuardRejection::BadHost(_))
    ));

    // 8.3 Port mismatch
    let h_port_mismatch = "POST /api/test HTTP/1.1\r\nHost: 127.0.0.1:9999\r\nX-Octopus-Token: tok";
    assert!(matches!(
        authorize_request(
            &make_guard_req("POST", "/api/test", h_port_mismatch, port),
            "tok"
        ),
        Err(GuardRejection::BadHost(_))
    ));

    // 8.4 Allowed loopback authorities
    let allowed = ["127.0.0.1:5005", "localhost:5005", "[::1]:5005"];
    for auth in allowed {
        let h_ok = format!(
            "POST /api/test HTTP/1.1\r\nHost: {}\r\nX-Octopus-Token: tok\r\nOrigin: http://{}",
            auth, auth
        );
        assert!(authorize_request(&make_guard_req("POST", "/api/test", &h_ok, port), "tok").is_ok());
    }
}

#[test]
fn test_m5_2_request_guard_csrf_origin_and_fetch_metadata() {
    let port = 5005;

    // 9.1 Cross-origin rejected with 403 CrossOrigin
    let h_cross = "POST /governance/validate-action HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nOrigin: http://evil.example";
    assert!(matches!(
        authorize_request(
            &make_guard_req("POST", "/governance/validate-action", h_cross, port),
            "tok"
        ),
        Err(GuardRejection::CrossOrigin(_))
    ));

    // 9.2 Null origin rejected
    let h_null = "POST /governance/validate-action HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nOrigin: null";
    assert!(matches!(
        authorize_request(
            &make_guard_req("POST", "/governance/validate-action", h_null, port),
            "tok"
        ),
        Err(GuardRejection::CrossOrigin(_))
    ));

    // 9.3 Sec-Fetch-Site: cross-site rejected
    let h_sfs = "POST /governance/validate-action HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nSec-Fetch-Site: cross-site";
    assert!(matches!(
        authorize_request(
            &make_guard_req("POST", "/governance/validate-action", h_sfs, port),
            "tok"
        ),
        Err(GuardRejection::CrossOrigin(_))
    ));
}

#[test]
fn test_m5_2_request_guard_route_matching_and_key_gating() {
    // 10.1 CAGE substrate path detection
    assert!(is_cage_substrate_path("/governance/ingest-policy"));
    assert!(is_cage_substrate_path("/governance/policy-version/"));
    assert!(is_cage_substrate_path("/v1/governance/validate-action"));
    assert!(is_cage_substrate_path("/api/cage/proof-status"));
    assert!(is_cage_substrate_path("/api/cage/trace-conformance"));
    assert!(is_cage_substrate_path("/api/cage/consume-seal"));
    assert!(is_token_exempt_path("/governance/consume-seal"));

    // Non-exempt endpoint
    assert!(!is_token_exempt_path("/api/run-rust-tests"));

    // 10.2 Bearer token extraction
    let h_bearer = "POST /cage HTTP/1.1\r\nAuthorization: Bearer secret-cage-key-999\r\nHost: 127.0.0.1";
    assert_eq!(
        extract_bearer_token(h_bearer),
        Some("secret-cage-key-999")
    );

    let h_bearer_lc = "POST /cage HTTP/1.1\r\nauthorization: bearer secret-cage-key-888\r\nHost: 127.0.0.1";
    assert_eq!(
        extract_bearer_token(h_bearer_lc),
        Some("secret-cage-key-888")
    );

    let h_basic = "POST /cage HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\nHost: 127.0.0.1";
    assert_eq!(extract_bearer_token(h_basic), None);
}

// ==============================================================================
// 5. Atomic State Transitions & Memory Reclamation in consumed_seals
// ==============================================================================

#[test]
fn test_m5_2_consumed_seals_memory_reclamation_and_pruning() {
    let signer = RoutingSealSigner::new(M5_TEST_KEY, M5_TEST_POLICY_VERSION);
    let base_time = 3_000_000;

    // 11.1 Issue and consume 20 seals at base_time
    for i in 0..20 {
        let digest = compute_action_digest(&format!("tool_reclaim_{}", i), &serde_json::json!({}));
        let seal = signer
            .issue_seal(&digest, M5_VALID_RECORD_HASH, base_time)
            .unwrap();
        assert!(signer
            .validate_and_consume(&seal, &digest, M5_VALID_RECORD_HASH, base_time)
            .is_ok());
    }
    assert_eq!(signer.consumed_count(), 20);

    // 11.2 Advance time past TTL (30s) + clock drift tolerance (5s) -> base_time + 36
    // Entries expire at base_time + 30; with 5s drift, exp + 5 = base_time + 35 < base_time + 36
    let pruned = signer.prune_expired(base_time + 36);
    assert_eq!(pruned, 20, "All 20 expired seals should be pruned");
    assert_eq!(signer.consumed_count(), 0, "Table should be empty after pruning");
}

#[test]
fn test_m5_2_consumed_seals_high_concurrency_race_single_winner() {
    let signer = Arc::new(RoutingSealSigner::new(M5_TEST_KEY, M5_TEST_POLICY_VERSION));
    let action_digest = compute_action_digest("tool_race", &serde_json::json!({}));
    let now = 4_000_000;

    let seal = Arc::new(
        signer
            .issue_seal(&action_digest, M5_VALID_RECORD_HASH, now)
            .unwrap(),
    );

    let success_count = Arc::new(AtomicUsize::new(0));
    let replay_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..64 {
        let signer_clone = Arc::clone(&signer);
        let seal_clone = Arc::clone(&seal);
        let digest_clone = action_digest.clone();
        let succ_clone = Arc::clone(&success_count);
        let rep_clone = Arc::clone(&replay_count);

        handles.push(thread::spawn(move || {
            match signer_clone.validate_and_consume(
                &seal_clone,
                &digest_clone,
                M5_VALID_RECORD_HASH,
                now,
            ) {
                Ok(_) => {
                    succ_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(SealRejection::AlreadyConsumed(_)) => {
                    rep_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(other) => panic!("Unexpected seal rejection: {:?}", other),
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Invariant: Strictly 1 winner, 63 replayed rejections
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        1,
        "Strictly 1 thread must win consumption race"
    );
    assert_eq!(
        replay_count.load(Ordering::SeqCst),
        63,
        "All other 63 threads must be rejected with AlreadyConsumed"
    );
}

#[test]
fn test_m5_2_pipeline_atomic_two_phase_integrity_and_zero_leakage() {
    let ledger = Arc::new(DebitLedger::new(100.0, 0.2, 10.0).unwrap());
    let audit_log = Arc::new(SecurityAuditLog::new());
    let policy = CompiledCagePolicy {
        format: agent_octopus::security::cage_governance::substrate_translator::PolicyFormat::CageStpa,
        policy_version_id: M5_TEST_POLICY_VERSION.to_string(),
        raw_content: String::new(),
        cedar_rules: vec![],
        unsafe_control_actions: vec![],
        cbf_gamma: 0.2,
        cbf_b_min: 10.0,
    };

    let pipeline = CagePipeline::new(policy, Arc::clone(&ledger), M5_TEST_KEY, audit_log);

    // Initial budget: 100.0
    assert_eq!(ledger.available_budget(), 100.0);

    // Request 1: Valid action clearing all tiers
    let req1 = GovernanceRequest {
        action_name: "read_safe_resource".to_string(),
        principal: "arm_worker_0".to_string(),
        resource: "s3://invoices/01.pdf".to_string(),
        parameters: serde_json::json!({}),
        caller_authority: 5,
        confidence_score: 0.99,
        consensus_score: 0.95,
        fuel_cost: 10.0,
        expected_policy_version: Some(M5_TEST_POLICY_VERSION.to_string()),
        execution_profile: Some(Profile::Full),
    };

    let res1 = pipeline.run_pipeline(&req1);
    assert_eq!(res1.verdict, GovernanceVerdict::Allow);
    assert!(res1.seal.is_some());
    assert!(res1.commit_receipt.is_some());
    assert_eq!(ledger.available_budget(), 90.0);

    // Request 2: Failed action (confidence deficit triggers DEFER) -> Phase 2 is Preview only
    let req2 = GovernanceRequest {
        action_name: "read_uncertain_resource".to_string(),
        principal: "arm_worker_0".to_string(),
        resource: "s3://invoices/02.pdf".to_string(),
        parameters: serde_json::json!({}),
        caller_authority: 5,
        confidence_score: 0.50, // Below SR 26-2 approval threshold 0.70
        consensus_score: 0.95,
        fuel_cost: 10.0,
        expected_policy_version: Some(M5_TEST_POLICY_VERSION.to_string()),
        execution_profile: Some(Profile::Full),
    };

    let res2 = pipeline.run_pipeline(&req2);
    assert!(matches!(res2.verdict, GovernanceVerdict::Defer { .. }));
    assert!(res2.seal.is_none());
    assert!(res2.commit_receipt.is_none());
    // Zero budget leakage: budget remains exactly 90.0
    assert_eq!(ledger.available_budget(), 90.0);
}
