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

//! Adversarial Stress Test Suite for CAGE Governance Milestone 1 Core
//!
//! Empirically challenges and stress-tests:
//! 1. Discrete-Time CBF barrier inequalities ($h(S_{t+1}) = (B_t - c) - B_{\min} \ge (1-\gamma)h(S_t) \ge 0$),
//!    boundary precision, $\gamma$ spectrum, and extreme floating-point inputs.
//! 2. Two-phase DebitLedger pre-reservation concurrency, rapid LIFO rollbacks, partial confirms,
//!    and zero fiscal balance leakage.
//! 3. Evidence-bound routing seal single-use concurrency race conditions, TTL expiration, clock skew,
//!    HMAC signature tampering, and payload integrity.
//! 4. FTRA DAG execution plan reachability, cycle detection, self-loops, disconnected components,
//!    duplicate dependencies, and deep graphs.

use agent_octopus::security::cage_governance::cbf_fiscal::{
    CbfSafetyEngine, CbfViolation, DebitLedger,
};
use agent_octopus::security::cage_governance::ftra_stpa::{
    FtraVerdict, PlanGraphAnalyzer, PlanStep,
};
use agent_octopus::security::cage_governance::routing_seal::{
    compute_action_digest, CageRoutingSeal, RoutingSealSigner, SealRejection,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

// ============================================================================
// 1. DISCRETE-TIME CBF BARRIER INEQUALITIES ADVERSARIAL STRESS TESTS
// ============================================================================

#[test]
fn stress_test_cbf_barrier_exact_boundary_precision() {
    // B_t = 1000.0, B_min = 100.0, gamma = 0.25
    // h(S_t) = 900.0
    // h_min_allowed = (1 - 0.25) * 900.0 = 675.0
    // Max allowable cost = 900.0 - 675.0 = 225.0
    let cbf = CbfSafetyEngine::new(0.25, 100.0).expect("Valid CBF engine");

    // Exact boundary cost: c = 225.0 -> h_{t+1} = (1000 - 225) - 100 = 675.0 == 675.0
    let h_next = cbf
        .evaluate_step(1000.0, 225.0, 900.0)
        .expect("Exact boundary should pass");
    assert!((h_next - 675.0).abs() < 1e-12);

    // Epsilon-boundary test: cost = 225.0 + 1e-10 (within CBF_EPSILON = 1e-9)
    let h_eps = cbf
        .evaluate_step(1000.0, 225.0 + 1e-10, 900.0)
        .expect("Within epsilon buffer should pass");
    assert!((h_eps - (675.0 - 1e-10)).abs() < 1e-12);

    // Epsilon-breach test: cost = 225.0 + 1e-6 (exceeds CBF_EPSILON)
    let breach_err = match cbf.evaluate_step(1000.0, 225.0 + 1e-6, 900.0) {
        Err(e) => e,
        Ok(v) => panic!("Expected breach error, got {}", v),
    };
    assert!(matches!(breach_err, CbfViolation::DecayRateExceeded { .. }));

    // Non-negative floor boundary: gamma = 1.0 (all decay allowed down to B_min)
    // h_min_allowed = (1 - 1.0) * 900.0 = 0.0
    let cbf_full = CbfSafetyEngine::new(1.0, 100.0).expect("Valid gamma=1.0 engine");
    let h_floor = cbf_full
        .evaluate_step(1000.0, 900.0, 900.0)
        .expect("Exact floor should pass");
    assert_eq!(h_floor, 0.0);

    // Breach floor by 1e-6: cost = 900.0 + 1e-6
    let floor_err = match cbf_full.evaluate_step(1000.0, 900.0 + 1e-6, 900.0) {
        Err(e) => e,
        Ok(v) => panic!("Expected floor breach, got {}", v),
    };
    assert!(matches!(floor_err, CbfViolation::FloorBreach { .. }));
}

#[test]
fn stress_test_cbf_gamma_spectrum_and_validation() {
    // Valid gamma range: (0.0, 1.0]
    let test_gammas = [0.001, 0.05, 0.1, 0.25, 0.5, 0.75, 0.9, 0.999, 1.0];
    let budget = 10_000.0;
    let b_min = 1_000.0;
    let h_0 = budget - b_min; // 9000.0

    for &g in &test_gammas {
        let engine = CbfSafetyEngine::new(g, b_min).expect("Valid gamma");
        let max_cost = g * h_0;

        // Cost just under limit should pass
        let cost_pass = max_cost - 1e-5;
        assert!(
            engine.evaluate_step(budget, cost_pass, h_0).is_ok(),
            "Gamma {} failed valid step for cost {}",
            g,
            cost_pass
        );

        // Cost just over limit should fail with DecayRateExceeded (or FloorBreach if g=1.0)
        let cost_fail = max_cost + 1e-4;
        let err = match engine.evaluate_step(budget, cost_fail, h_0) {
            Err(e) => e,
            Ok(v) => panic!("Expected failure for cost {}, got {}", cost_fail, v),
        };
        if (g - 1.0).abs() < 1e-12 {
            assert!(matches!(err, CbfViolation::FloorBreach { .. }));
        } else {
            assert!(matches!(err, CbfViolation::DecayRateExceeded { .. }));
        }
    }

    // Invalid gammas must fail in constructor
    match CbfSafetyEngine::new(0.0, 100.0) {
        Err(CbfViolation::InvalidParameters(_)) => {}
        _ => panic!("Expected InvalidParameters for gamma = 0.0"),
    }
    match CbfSafetyEngine::new(-0.5, 100.0) {
        Err(CbfViolation::InvalidParameters(_)) => {}
        _ => panic!("Expected InvalidParameters for gamma = -0.5"),
    }
    match CbfSafetyEngine::new(1.0000001, 100.0) {
        Err(CbfViolation::InvalidParameters(_)) => {}
        _ => panic!("Expected InvalidParameters for gamma = 1.0000001"),
    }
    match CbfSafetyEngine::new(100.0, 100.0) {
        Err(CbfViolation::InvalidParameters(_)) => {}
        _ => panic!("Expected InvalidParameters for gamma = 100.0"),
    }

    // Negative floor must fail in constructor
    match CbfSafetyEngine::new(0.5, -10.0) {
        Err(CbfViolation::InvalidParameters(_)) => {}
        _ => panic!("Expected InvalidParameters for negative b_min"),
    }
}

#[test]
fn stress_test_cbf_extreme_floats_and_edge_inputs() {
    let cbf = CbfSafetyEngine::new(0.5, 100.0).unwrap();

    // Negative cost rejected
    let err_neg_cost = match cbf.evaluate_step(500.0, -10.0, 400.0) {
        Err(e) => e,
        Ok(v) => panic!("Expected neg cost error, got {}", v),
    };
    assert!(matches!(err_neg_cost, CbfViolation::InvalidParameters(_)));

    // Infinite cost rejected as FloorBreach
    let err_inf_cost = match cbf.evaluate_step(500.0, f64::INFINITY, 400.0) {
        Err(e) => e,
        Ok(v) => panic!("Expected inf cost error, got {}", v),
    };
    assert!(matches!(err_inf_cost, CbfViolation::FloorBreach { .. }));

    // Negative infinite cost rejected
    let err_neg_inf = match cbf.evaluate_step(500.0, f64::NEG_INFINITY, 400.0) {
        Err(e) => e,
        Ok(v) => panic!("Expected neg inf error, got {}", v),
    };
    assert!(matches!(err_neg_inf, CbfViolation::InvalidParameters(_)));

    // Unsafe current state: current_h < 0
    let err_unsafe_state = match cbf.evaluate_step(50.0, 5.0, -50.0) {
        Err(e) => e,
        Ok(v) => panic!("Expected unsafe state error, got {}", v),
    };
    assert!(matches!(
        err_unsafe_state,
        CbfViolation::CurrentStateUnsafe { .. }
    ));

    // Zero cost: should pass without modifying safety margin
    let h_zero_cost = cbf.evaluate_step(500.0, 0.0, 400.0).unwrap();
    assert_eq!(h_zero_cost, 400.0);

    // Negative zero cost (-0.0 == 0.0 in IEEE 754)
    let h_neg_zero = cbf.evaluate_step(500.0, -0.0, 400.0).unwrap();
    assert_eq!(h_neg_zero, 400.0);
}

// ============================================================================
// 2. TWO-PHASE DEBITLEDGER PRE-RESERVATION & ZERO FISCAL LEAKAGE
// ============================================================================

#[test]
fn stress_test_two_phase_debit_ledger_concurrent_zero_leakage() {
    // 50 concurrent threads competing for budget with random pre-reserves, commits, and rollbacks
    let initial_budget = 50_000.0;
    let b_min = 1_000.0;
    let ledger = Arc::new(DebitLedger::new(initial_budget, 1.0, b_min).unwrap());

    let num_threads = 50;
    let ops_per_thread = 20;

    let confirmed_sum_cents = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let mut handles = Vec::new();
    for thread_idx in 0..num_threads {
        let ledger_clone = Arc::clone(&ledger);
        let confirmed_acc = Arc::clone(&confirmed_sum_cents);

        handles.push(thread::spawn(move || {
            for op_idx in 0..ops_per_thread {
                let debit_id = format!("t{}_op{}", thread_idx, op_idx);
                let cost = 10.0 + (op_idx as f64);

                // Attempt pre-reserve
                match ledger_clone.pre_reserve(cost, &debit_id) {
                    Ok(_) => {
                        // 50% commit, 50% rollback
                        if (thread_idx + op_idx) % 2 == 0 {
                            ledger_clone
                                .confirm(&debit_id)
                                .expect("Confirm must succeed");
                            confirmed_acc
                                .fetch_add((cost * 100.0).round() as u64, Ordering::SeqCst);
                        } else {
                            ledger_clone
                                .rollback(&debit_id)
                                .expect("Rollback must succeed");
                        }
                    }
                    Err(CbfViolation::FloorBreach { .. }) => {
                        // Floor reached, safe rejection
                    }
                    Err(e) => {
                        panic!("Unexpected CBF error during concurrent stress: {:?}", e);
                    }
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Now roll back any remaining active uncommitted reservations (if any)
    while let Ok((id, _)) = ledger.rollback_lifo() {
        println!("Rolled back leftover reservation: {}", id);
    }

    let final_budget = ledger.available_budget();
    let total_confirmed = (confirmed_sum_cents.load(Ordering::SeqCst) as f64) / 100.0;

    let expected_budget = initial_budget - total_confirmed;
    let fiscal_drift = (final_budget - expected_budget).abs();

    println!(
        "Concurrent Fiscal Stress Test: Initial={}, Confirmed={}, Final={}, Expected={}, Drift={}",
        initial_budget, total_confirmed, final_budget, expected_budget, fiscal_drift
    );

    assert!(
        fiscal_drift < 1e-7,
        "Fiscal leakage detected! Drift = {}, Final = {}, Expected = {}",
        fiscal_drift,
        final_budget,
        expected_budget
    );
    assert_eq!(ledger.active_reservation_count(), 0);
}

#[test]
fn stress_test_debit_ledger_rapid_lifo_rollbacks() {
    let initial_budget = 50_000.0;
    let ledger = DebitLedger::new(initial_budget, 1.0, 500.0).unwrap();

    let n = 200;
    // Pre-reserve 200 items (total cost = 20,100 <= 50,000 - 500)
    for i in 0..n {
        let debit_id = format!("lifo-item-{}", i);
        let cost = (i + 1) as f64;
        ledger.pre_reserve(cost, &debit_id).unwrap();
    }

    assert_eq!(ledger.active_reservation_count(), n);

    // Rollback in LIFO order
    for i in (0..n).rev() {
        let expected_id = format!("lifo-item-{}", i);
        let (rolled_id, restored_budget) = ledger.rollback_lifo().unwrap();
        assert_eq!(rolled_id, expected_id, "LIFO order violation!");
        assert!(restored_budget <= initial_budget + 1e-9);
    }

    // Once empty, rollback_lifo must fail cleanly
    let empty_err = match ledger.rollback_lifo() {
        Err(e) => e,
        Ok((id, b)) => panic!(
            "Expected error on empty ledger, got {} with budget {}",
            id, b
        ),
    };
    assert!(matches!(empty_err, CbfViolation::ReservationNotFound(_)));

    // Budget must be exactly restored to initial_budget with zero leakage
    assert!((ledger.available_budget() - initial_budget).abs() < 1e-9);
}

#[test]
fn stress_test_debit_ledger_double_rollback_and_settlement_invariants() {
    let ledger = DebitLedger::new(1000.0, 1.0, 100.0).unwrap();

    // 1. Confirm then rollback -> AlreadyCommitted
    ledger.pre_reserve(50.0, "deb-settled").unwrap();
    ledger.confirm("deb-settled").unwrap();
    let err_committed = match ledger.rollback("deb-settled") {
        Err(e) => e,
        Ok(b) => panic!("Expected AlreadyCommitted, got {}", b),
    };
    assert!(matches!(err_committed, CbfViolation::AlreadyCommitted(_)));

    // 2. Rollback then rollback again -> ReservationNotFound
    ledger.pre_reserve(50.0, "deb-rolled").unwrap();
    ledger.rollback("deb-rolled").unwrap();
    let err_again = match ledger.rollback("deb-rolled") {
        Err(e) => e,
        Ok(b) => panic!("Expected ReservationNotFound, got {}", b),
    };
    assert!(matches!(err_again, CbfViolation::ReservationNotFound(_)));

    // 3. Rollback then confirm -> ReservationNotFound
    let err_confirm_after_rollback = match ledger.confirm("deb-rolled") {
        Err(e) => e,
        Ok(_) => panic!("Expected ReservationNotFound on confirm after rollback"),
    };
    assert!(matches!(
        err_confirm_after_rollback,
        CbfViolation::ReservationNotFound(_)
    ));

    // 4. Non-existent debit ID
    let err_non_existent = match ledger.rollback("deb-ghost") {
        Err(e) => e,
        Ok(b) => panic!("Expected ReservationNotFound, got {}", b),
    };
    assert!(matches!(
        err_non_existent,
        CbfViolation::ReservationNotFound(_)
    ));
}

// ============================================================================
// 3. ROUTING SEAL CONSUMPTION, EXPIRATION, REPLAY & INTEGRITY
// ============================================================================

#[test]
fn stress_test_routing_seal_single_use_concurrency_race() {
    let secret = b"challenger_cage_secret_key_12345";
    let policy_version = "abcdef0123456789";
    let signer = Arc::new(RoutingSealSigner::new(secret, policy_version));

    let action_digest =
        compute_action_digest("critical_actuation", &serde_json::json!({"target": "db"}));
    let record_hash = "9999888877776666555544443333222211110000aaaabbbbccccddddeeeeffff";
    let now = 1_000_000;

    let seal = signer.issue_seal(&action_digest, record_hash, now).unwrap();

    let num_threads = 50;
    let success_count = Arc::new(AtomicUsize::new(0));
    let replay_rejected_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..num_threads {
        let signer_clone = Arc::clone(&signer);
        let seal_clone = seal.clone();
        let action_clone = action_digest.clone();
        let record_clone = record_hash.to_string();
        let succ_acc = Arc::clone(&success_count);
        let replay_acc = Arc::clone(&replay_rejected_count);

        handles.push(thread::spawn(move || {
            match signer_clone.validate_and_consume(
                &seal_clone,
                &action_clone,
                &record_clone,
                now + 10,
            ) {
                Ok(_) => {
                    succ_acc.fetch_add(1, Ordering::SeqCst);
                }
                Err(SealRejection::AlreadyConsumed(_)) => {
                    replay_acc.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => {
                    panic!("Unexpected seal rejection in race: {:?}", e);
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        success_count.load(Ordering::SeqCst),
        1,
        "Strictly 1 thread must successfully consume single-use seal"
    );
    assert_eq!(
        replay_rejected_count.load(Ordering::SeqCst),
        num_threads - 1,
        "Exactly 49 threads must be rejected for replay"
    );
    assert_eq!(signer.consumed_count(), 1);
}

#[test]
fn stress_test_routing_seal_ttl_and_clock_skew_boundaries() {
    let secret = b"challenger_cage_secret_key_12345";
    let signer = RoutingSealSigner::new(secret, "abcdef0123456789");

    let action_digest = compute_action_digest("actuate", &serde_json::json!({}));
    let record_hash = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let issued_at = 1_000_000;

    // 1. Expiration exact boundaries: TTL is 30s
    let seal = signer
        .issue_seal(&action_digest, record_hash, issued_at)
        .unwrap();
    assert_eq!(seal.expires_at, issued_at + 30);

    // At issued_at + 30: Valid
    assert!(signer
        .validate_and_consume(&seal, &action_digest, record_hash, issued_at + 30)
        .is_ok());

    // Issue second seal to test +31s expiry
    let seal2 = signer
        .issue_seal(&action_digest, record_hash, issued_at)
        .unwrap();
    let err_expired =
        match signer.validate_and_consume(&seal2, &action_digest, record_hash, issued_at + 31) {
            Err(e) => e,
            Ok(_) => panic!("Expected Expired error at +31s"),
        };
    assert!(matches!(err_expired, SealRejection::Expired { .. }));

    // 2. Future timestamp / clock skew boundaries (tolerance = 5s)
    let current_time = 1_000_000;

    // Skew +5s: Valid
    let seal_future_ok = signer
        .issue_seal(&action_digest, record_hash, current_time + 5)
        .unwrap();
    assert!(signer
        .validate_and_consume(&seal_future_ok, &action_digest, record_hash, current_time)
        .is_ok());

    // Skew +6s: Rejected with FutureTimestamp
    let seal_future_bad = signer
        .issue_seal(&action_digest, record_hash, current_time + 6)
        .unwrap();
    let err_future = match signer.validate_and_consume(
        &seal_future_bad,
        &action_digest,
        record_hash,
        current_time,
    ) {
        Err(e) => e,
        Ok(_) => panic!("Expected FutureTimestamp at +6s skew"),
    };
    assert!(matches!(err_future, SealRejection::FutureTimestamp { .. }));
}

#[test]
fn stress_test_routing_seal_tamper_resistance_and_mismatches() {
    let secret = b"challenger_cage_secret_key_12345";
    let policy_ver = "abcdef0123456789";
    let signer = RoutingSealSigner::new(secret, policy_ver);

    let action_digest = compute_action_digest("tool_call", &serde_json::json!({"cmd": "whoami"}));
    let record_hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let now = 1000;

    let valid_seal = signer.issue_seal(&action_digest, record_hash, now).unwrap();

    // 1. Signature bit-flip tampering
    let mut tampered_sig_seal = valid_seal.clone();
    let last_char = if tampered_sig_seal.signature.ends_with('0') {
        '1'
    } else {
        '0'
    };
    tampered_sig_seal.signature.pop();
    tampered_sig_seal.signature.push(last_char);
    let err_sig =
        match signer.validate_and_consume(&tampered_sig_seal, &action_digest, record_hash, now) {
            Err(e) => e,
            Ok(_) => panic!("Expected InvalidSignature on bit-flip"),
        };
    assert!(matches!(err_sig, SealRejection::InvalidSignature));

    // 2. Action digest mismatch
    let wrong_action_digest = compute_action_digest("tool_call", &serde_json::json!({"cmd": "rm"}));
    let err_action =
        match signer.validate_and_consume(&valid_seal, &wrong_action_digest, record_hash, now) {
            Err(e) => e,
            Ok(_) => panic!("Expected ActionDigestMismatch"),
        };
    assert!(matches!(
        err_action,
        SealRejection::ActionDigestMismatch { .. }
    ));

    // 3. Record hash chain mismatch
    let wrong_record_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let err_record =
        match signer.validate_and_consume(&valid_seal, &action_digest, wrong_record_hash, now) {
            Err(e) => e,
            Ok(_) => panic!("Expected RecordHashMismatch"),
        };
    assert!(matches!(
        err_record,
        SealRejection::RecordHashMismatch { .. }
    ));

    // 4. Policy version drift
    signer.set_policy_version("0000000000000000");
    let err_policy =
        match signer.validate_and_consume(&valid_seal, &action_digest, record_hash, now) {
            Err(e) => e,
            Ok(_) => panic!("Expected PolicyVersionMismatch"),
        };
    assert!(matches!(
        err_policy,
        SealRejection::PolicyVersionMismatch { .. }
    ));
}

#[test]
fn stress_test_routing_seal_tampered_expires_at_exploration() {
    let secret = b"challenger_cage_secret_key_12345";
    let signer = RoutingSealSigner::new(secret, "abcdef0123456789");

    let action_digest = compute_action_digest("critical_action", &serde_json::json!({}));
    let record_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let issued_at = 1_000_000;

    let mut seal: CageRoutingSeal = signer
        .issue_seal(&action_digest, record_hash, issued_at)
        .unwrap();
    assert_eq!(seal.expires_at, issued_at + 30);

    // Current time is 2 hours later: t = 1,007,200 (well past 30s TTL)
    let current_time = 1_007_200;

    // Normal check: rejected as Expired
    let expired_err =
        match signer.validate_and_consume(&seal, &action_digest, record_hash, current_time) {
            Err(e) => e,
            Ok(_) => panic!("Expected Expired"),
        };
    assert!(matches!(expired_err, SealRejection::Expired { .. }));

    // Adversary tampers with expires_at field (e.g. in deserialized JSON payload)
    seal.expires_at = current_time + 100;

    // Check behavior: does validate_and_consume accept the tampered expires_at because expires_at is not in HMAC signature?
    let result = signer.validate_and_consume(&seal, &action_digest, record_hash, current_time);
    println!("Adversarial Tampered expires_at result: {:?}", result);
    let vulnerability_present = result.is_ok();
    println!(
        "VULNERABILITY VERDICT: Can expires_at be tampered to revive expired seals? {}",
        vulnerability_present
    );
    assert!(
        !vulnerability_present,
        "VULN-CAGE-M1-01: Tampering expires_at must not revive expired seals"
    );
    assert!(matches!(
        result,
        Err(SealRejection::MalformedSeal(_))
            | Err(SealRejection::InvalidSignature)
            | Err(SealRejection::Expired { .. })
    ));
}

// ============================================================================
// 4. FTRA DAG CYCLE DETECTION & COMPLEX GRAPH TOPOLOGIES
// ============================================================================

#[test]
fn stress_test_ftra_dag_self_loops_and_cycles() {
    // 1. Self-loop: A depends on A
    let self_loop = vec![PlanStep {
        id: "step-self".to_string(),
        action_name: "read_file".to_string(),
        parameters: serde_json::json!({}),
        depends_on: vec!["step-self".to_string()],
        confidence: 0.99,
        fuel_cost: 0.1,
        caller_authority: 1,
    }];
    let err_self = PlanGraphAnalyzer::analyze_execution_graph(&self_loop).unwrap_err();
    assert!(
        err_self.contains("cycles"),
        "Self loop must be detected as a cycle"
    );

    // 2. Three-node cycle: A -> B -> C -> A
    let three_cycle = vec![
        PlanStep {
            id: "A".to_string(),
            action_name: "read_a".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["C".to_string()],
            confidence: 0.99,
            fuel_cost: 0.1,
            caller_authority: 1,
        },
        PlanStep {
            id: "B".to_string(),
            action_name: "read_b".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["A".to_string()],
            confidence: 0.99,
            fuel_cost: 0.1,
            caller_authority: 1,
        },
        PlanStep {
            id: "C".to_string(),
            action_name: "read_c".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["B".to_string()],
            confidence: 0.99,
            fuel_cost: 0.1,
            caller_authority: 1,
        },
    ];
    let err_three = PlanGraphAnalyzer::analyze_execution_graph(&three_cycle).unwrap_err();
    assert!(err_three.contains("cycles"));

    // 3. 50-node ring cycle with clean feeder prefix
    let mut ring_graph = Vec::new();
    // Clean feeder prefix: feeder_0 -> feeder_1
    ring_graph.push(PlanStep {
        id: "feeder_0".to_string(),
        action_name: "read_feed0".to_string(),
        parameters: serde_json::json!({}),
        depends_on: vec![],
        confidence: 0.99,
        fuel_cost: 0.1,
        caller_authority: 1,
    });
    ring_graph.push(PlanStep {
        id: "feeder_1".to_string(),
        action_name: "read_feed1".to_string(),
        parameters: serde_json::json!({}),
        depends_on: vec!["feeder_0".to_string()],
        confidence: 0.99,
        fuel_cost: 0.1,
        caller_authority: 1,
    });
    // 50-node ring: node_0 depends on node_49 and feeder_1; node_i depends on node_{i-1}
    for i in 0..50 {
        let prev = if i == 0 {
            vec!["feeder_1".to_string(), "node_49".to_string()]
        } else {
            vec![format!("node_{}", i - 1)]
        };
        ring_graph.push(PlanStep {
            id: format!("node_{}", i),
            action_name: format!("read_{}", i),
            parameters: serde_json::json!({}),
            depends_on: prev,
            confidence: 0.99,
            fuel_cost: 0.1,
            caller_authority: 1,
        });
    }
    let err_ring = PlanGraphAnalyzer::analyze_execution_graph(&ring_graph).unwrap_err();
    assert!(
        err_ring.contains("cycles"),
        "50-node ring cycle must be detected"
    );
}

#[test]
fn stress_test_ftra_dag_disconnected_components_and_forest() {
    // Forest of 3 disconnected valid trees:
    // Tree 1: T1_A -> T1_B
    // Tree 2: T2_A -> T2_B -> T2_C
    // Tree 3: T3_Solo (isolated)
    let forest = vec![
        PlanStep {
            id: "T1_A".to_string(),
            action_name: "read_1".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec![],
            confidence: 0.98,
            fuel_cost: 0.1,
            caller_authority: 2,
        },
        PlanStep {
            id: "T1_B".to_string(),
            action_name: "read_2".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["T1_A".to_string()],
            confidence: 0.98,
            fuel_cost: 0.1,
            caller_authority: 2,
        },
        PlanStep {
            id: "T2_A".to_string(),
            action_name: "read_3".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec![],
            confidence: 0.98,
            fuel_cost: 0.1,
            caller_authority: 2,
        },
        PlanStep {
            id: "T2_B".to_string(),
            action_name: "read_4".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["T2_A".to_string()],
            confidence: 0.98,
            fuel_cost: 0.1,
            caller_authority: 2,
        },
        PlanStep {
            id: "T2_C".to_string(),
            action_name: "read_5".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["T2_B".to_string()],
            confidence: 0.98,
            fuel_cost: 0.1,
            caller_authority: 2,
        },
        PlanStep {
            id: "T3_Solo".to_string(),
            action_name: "read_solo".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec![],
            confidence: 0.98,
            fuel_cost: 0.1,
            caller_authority: 2,
        },
    ];

    let verdict = PlanGraphAnalyzer::analyze_execution_graph(&forest).expect("Valid forest DAG");
    assert_eq!(verdict, FtraVerdict::Clear);
}

#[test]
fn stress_test_ftra_dag_missing_dependencies_and_duplicate_edges() {
    // 1. Missing dependency
    let missing_dep = vec![PlanStep {
        id: "step_orphan".to_string(),
        action_name: "read".to_string(),
        parameters: serde_json::json!({}),
        depends_on: vec!["non_existent_step".to_string()],
        confidence: 0.99,
        fuel_cost: 0.1,
        caller_authority: 1,
    }];
    let err_missing = PlanGraphAnalyzer::analyze_execution_graph(&missing_dep).unwrap_err();
    assert!(err_missing.contains("depends on unknown step 'non_existent_step'"));

    // 2. Multi-edge / duplicate dependencies: B depends on A twice
    let duplicate_edge = vec![
        PlanStep {
            id: "node_A".to_string(),
            action_name: "read_a".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec![],
            confidence: 0.99,
            fuel_cost: 0.1,
            caller_authority: 1,
        },
        PlanStep {
            id: "node_B".to_string(),
            action_name: "read_b".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec!["node_A".to_string(), "node_A".to_string()],
            confidence: 0.99,
            fuel_cost: 0.1,
            caller_authority: 1,
        },
    ];
    let verdict = PlanGraphAnalyzer::analyze_execution_graph(&duplicate_edge)
        .expect("Should handle duplicate edges");
    assert_eq!(verdict, FtraVerdict::Clear);
}

#[test]
fn stress_test_ftra_dag_deep_linear_chain() {
    // Deep 200-step linear DAG S_0 -> S_1 -> ... -> S_199
    let mut chain = Vec::with_capacity(200);
    for i in 0..200 {
        let deps = if i == 0 {
            vec![]
        } else {
            vec![format!("step_{}", i - 1)]
        };
        chain.push(PlanStep {
            id: format!("step_{}", i),
            action_name: format!("read_{}", i),
            parameters: serde_json::json!({}),
            depends_on: deps,
            confidence: 0.98,
            fuel_cost: 0.05,
            caller_authority: 2,
        });
    }

    let verdict = PlanGraphAnalyzer::analyze_execution_graph(&chain)
        .expect("Deep linear DAG must not panic or cycle");
    assert_eq!(verdict, FtraVerdict::Clear);
}
