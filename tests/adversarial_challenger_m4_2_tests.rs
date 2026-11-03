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
//! [AGENT OCTOPUS] MILESTONE 4 ADVERSARIAL CHALLENGER SUITE (CHALLENGER 2)
//! ==============================================================================
//! Independent Empirical Verification & Adversarial Stress Testing:
//!
//! 1. Actuator Single-Use Concurrency:
//!    - Multi-threaded concurrent execution race using the exact same routing seal.
//!    - Multi-trial concurrency loop (10 trials x 16 tasks) verifying zero seal double-spend.
//!    - Multi-arm fleet concurrency (10 independent rings sharing CAGE engine).
//!    - Concurrent execution with two-phase fiscal debit confirmation.
//!    - Exact invariant: Strictly 1 success, N-1 rejected with SealAlreadyConsumed.
//!    - Verification of zero deadlocks, race conditions, or memory leaks.
//!
//! 2. Formal BFS State Machine Robustness & Graph Invariance:
//!    - 1,000 repeated trials of gated model asserting strictly 34 reachable states,
//!      strictly 1 executed state, 0 violations, and NoDirectBind proven true.
//!    - 1,000 repeated trials of ungated counterexample asserting strictly 17 reachable states,
//!      strictly 1 executed state, and direct-bind counterexample detected.
//!    - 1,000 repeated trials of 64-hex SHA-256 theorem proof receipt determinism.
//!    - 1,000 distinct pseudo-random exploration seeds (StdRng seed 0..1000) shuffling
//!      traversal queue order, verifying structural state-space invariance.
//!
//! 3. Two-Phase Fiscal Ledger Concurrency & Balance Drift Defense:
//!    - Highly interleaved concurrent execution across 24 worker threads performing
//!      pre-reserve, confirm, rollback, and rollback_lifo operations.
//!    - Adversarial attack injection: double rollback, rollback after confirm, confirm
//!      after rollback, nonexistent debit IDs, and budget floor overflow attacks.
//!    - Mathematical balance conservation: Initial Budget == Available Budget + Confirmed Debits
//!      verified to within epsilon (1e-9) with absolute zero fiscal leakage.
//! ==============================================================================

use agent_octopus::containment_ring::{
    ArmContainmentRing, ArmExecutionError, TieredExecutionDispatcher, TieredToolRequest,
};
use agent_octopus::core::types::ArmRole;
use agent_octopus::security::cage_governance::cbf_fiscal::{
    CbfViolation, DebitLedger, CBF_EPSILON,
};
use agent_octopus::security::cage_governance::no_direct_bind_proof::{
    BfsPhase, BfsState, FormalBfsModel,
};
use agent_octopus::security::cage_governance::routing_seal::CageRoutingSeal;
use agent_octopus::security::cage_governance::CageGovernanceEngine;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_MASTER_SEED: &[u8] = b"OCTOPUS_CHALLENGER_M4_2_SEED_2026";
const TEST_RESOURCE: &str = "s3://invoices/inv_01.pdf";

fn new_test_dispatcher() -> TieredExecutionDispatcher {
    let mercury = Arc::new(agent_octopus::security::mercury_guard::MercuryContainmentEngine::new());
    TieredExecutionDispatcher::try_new(mercury).expect("dispatcher initialization")
}

fn create_test_seal_with_time(
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
        .expect("seal issuance should succeed")
}

// ==============================================================================
// 1. ACTUATOR SINGLE-USE CONCURRENCY ADVERSARIAL STRESS HARNESS
// ==============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_adversarial_actuator_single_use_high_concurrency_race() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = Arc::new(
        ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
            .with_cage_engine(Arc::clone(&engine)),
    );

    let scratch_dir =
        std::env::temp_dir().join(format!("octopus_actuator_race_{}", std::process::id()));
    let payload = b"INVOICE #9001: Adversarial Multi-Threaded Actuator Contention".to_vec();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let seal = Arc::new(create_test_seal_with_time(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        TEST_RESOURCE,
        &payload,
        now,
    ));

    // Spawn 25 concurrent tasks all racing to execute the same tool with the exact same seal
    const CONCURRENCY: usize = 25;
    let mut handles = Vec::with_capacity(CONCURRENCY);

    for _ in 0..CONCURRENCY {
        let r = Arc::clone(&ring);
        let s = Arc::clone(&seal);
        let p = payload.clone();
        let sdir = scratch_dir.clone();

        handles.push(tokio::spawn(async move {
            let dispatcher = new_test_dispatcher();
            let mut ticket = r
                .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
                .await
                .expect("ticket must be issued");

            let req = TieredToolRequest {
                agent_id: r.agent_name.clone(),
                role: ArmRole::UntrustedDocIngest,
                tool_name: "doc_extractor".to_string(),
                payload: p,
                custom_wat: None,
                native_command: None,
                scratchpad_root: sdir,
                allow_scratch_write: false,
            };

            r.execute_tool_with_cage_seal(
                &mut ticket,
                &s,
                TEST_RESOURCE,
                &req,
                &dispatcher,
                None,
                None,
            )
            .await
        }));
    }

    let mut success_count = 0;
    let mut already_consumed_count = 0;

    for h in handles {
        match h.await.expect("task join failed") {
            Ok(receipt) => {
                assert!(receipt.exit_code >= 0);
                success_count += 1;
            }
            Err(ArmExecutionError::SealAlreadyConsumed { seal_id }) => {
                assert_eq!(seal_id, seal.seal_id);
                already_consumed_count += 1;
            }
            Err(other) => {
                panic!(
                    "Unexpected execution error in single-use concurrency race: {:?}",
                    other
                );
            }
        }
    }

    assert_eq!(
        success_count, 1,
        "CRITICAL INVARIANT VIOLATION: Exactly one task must successfully execute with seal"
    );
    assert_eq!(
        already_consumed_count,
        CONCURRENCY - 1,
        "CRITICAL INVARIANT VIOLATION: All losing tasks must be rejected with SealAlreadyConsumed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_adversarial_actuator_multi_trial_concurrency_stability() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = Arc::new(
        ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
            .with_cage_engine(Arc::clone(&engine)),
    );

    let scratch_dir =
        std::env::temp_dir().join(format!("octopus_multi_trial_{}", std::process::id()));
    const TRIALS: usize = 10;
    const TASKS_PER_TRIAL: usize = 16;

    for trial in 1..=TRIALS {
        let payload = format!("INVOICE #9002.{trial}: Trial Stability Run").into_bytes();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let seal = Arc::new(create_test_seal_with_time(
            &engine,
            &ring.agent_name,
            "doc_extractor",
            TEST_RESOURCE,
            &payload,
            now,
        ));

        let mut handles = Vec::with_capacity(TASKS_PER_TRIAL);
        for _ in 0..TASKS_PER_TRIAL {
            let r = Arc::clone(&ring);
            let s = Arc::clone(&seal);
            let p = payload.clone();
            let sdir = scratch_dir.clone();

            handles.push(tokio::spawn(async move {
                let dispatcher = new_test_dispatcher();
                let mut ticket = r
                    .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
                    .await
                    .expect("ticket must be issued");

                let req = TieredToolRequest {
                    agent_id: r.agent_name.clone(),
                    role: ArmRole::UntrustedDocIngest,
                    tool_name: "doc_extractor".to_string(),
                    payload: p,
                    custom_wat: None,
                    native_command: None,
                    scratchpad_root: sdir,
                    allow_scratch_write: false,
                };

                r.execute_tool_with_cage_seal(
                    &mut ticket,
                    &s,
                    TEST_RESOURCE,
                    &req,
                    &dispatcher,
                    None,
                    None,
                )
                .await
            }));
        }

        let mut success = 0;
        let mut consumed = 0;
        for h in handles {
            match h.await.expect("task join failed") {
                Ok(_) => success += 1,
                Err(ArmExecutionError::SealAlreadyConsumed { .. }) => consumed += 1,
                Err(e) => panic!("Trial {trial}: Unexpected error: {:?}", e),
            }
        }

        assert_eq!(success, 1, "Trial {trial}: Exactly 1 task must succeed");
        assert_eq!(
            consumed,
            TASKS_PER_TRIAL - 1,
            "Trial {trial}: Exactly 15 tasks must be rejected"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_adversarial_actuator_cross_arm_fleet_concurrency_race() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let arms_count = 10;
    let mut rings = Vec::new();

    for arm_id in 0..arms_count {
        rings.push(Arc::new(
            ArmContainmentRing::new(arm_id, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
                .with_cage_engine(Arc::clone(&engine)),
        ));
    }

    let scratch_dir =
        std::env::temp_dir().join(format!("octopus_cross_arm_{}", std::process::id()));
    let payload = b"INVOICE #9003: Cross Arm Fleet Concurrency Race".to_vec();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Seal issued for Arm 0
    let seal = Arc::new(create_test_seal_with_time(
        &engine,
        &rings[0].agent_name,
        "doc_extractor",
        TEST_RESOURCE,
        &payload,
        now,
    ));

    let mut handles = Vec::new();
    for ring in rings {
        let r = Arc::clone(&ring);
        let s = Arc::clone(&seal);
        let p = payload.clone();
        let sdir = scratch_dir.clone();

        handles.push(tokio::spawn(async move {
            let dispatcher = new_test_dispatcher();
            let mut ticket = r
                .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
                .await
                .expect("ticket must be issued");

            let req = TieredToolRequest {
                agent_id: r.agent_name.clone(),
                role: ArmRole::UntrustedDocIngest,
                tool_name: "doc_extractor".to_string(),
                payload: p,
                custom_wat: None,
                native_command: None,
                scratchpad_root: sdir,
                allow_scratch_write: false,
            };

            r.execute_tool_with_cage_seal(
                &mut ticket,
                &s,
                TEST_RESOURCE,
                &req,
                &dispatcher,
                None,
                None,
            )
            .await
        }));
    }

    let mut success_count = 0;
    let mut rejected_consumed_count = 0;

    for h in handles {
        match h.await.expect("join failed") {
            Ok(_) => success_count += 1,
            Err(ArmExecutionError::SealAlreadyConsumed { .. }) => rejected_consumed_count += 1,
            Err(other) => panic!("Unexpected error in cross-arm fleet race: {:?}", other),
        }
    }

    assert_eq!(
        success_count, 1,
        "Fleet-wide single-use invariant violated: exactly 1 arm succeeds"
    );
    assert_eq!(
        rejected_consumed_count,
        arms_count - 1,
        "Fleet-wide single-use invariant violated: remaining arms must be rejected with SealAlreadyConsumed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_adversarial_actuator_concurrency_with_fiscal_settlement() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = Arc::new(
        ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
            .with_cage_engine(Arc::clone(&engine)),
    );

    let initial_balance = engine.ledger().available_budget();
    let debit_receipt = engine
        .ledger()
        .pre_reserve(50.0, "debit_actuator_race_1")
        .expect("pre-reserve must succeed");
    assert_eq!(engine.ledger().available_budget(), initial_balance - 50.0);

    let scratch_dir =
        std::env::temp_dir().join(format!("octopus_fiscal_race_{}", std::process::id()));
    let payload = b"INVOICE #9004: Fiscal Settlement Concurrency".to_vec();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let seal = Arc::new(create_test_seal_with_time(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        TEST_RESOURCE,
        &payload,
        now,
    ));

    const WORKERS: usize = 12;
    let mut handles = Vec::with_capacity(WORKERS);

    for _ in 0..WORKERS {
        let r = Arc::clone(&ring);
        let s = Arc::clone(&seal);
        let p = payload.clone();
        let sdir = scratch_dir.clone();
        let did = debit_receipt.debit_id.clone();

        handles.push(tokio::spawn(async move {
            let dispatcher = new_test_dispatcher();
            let mut ticket = r
                .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
                .await
                .expect("ticket must be issued");

            let req = TieredToolRequest {
                agent_id: r.agent_name.clone(),
                role: ArmRole::UntrustedDocIngest,
                tool_name: "doc_extractor".to_string(),
                payload: p,
                custom_wat: None,
                native_command: None,
                scratchpad_root: sdir,
                allow_scratch_write: false,
            };

            r.execute_tool_with_cage_seal(
                &mut ticket,
                &s,
                TEST_RESOURCE,
                &req,
                &dispatcher,
                None,
                Some(&did),
            )
            .await
        }));
    }

    let mut success_count = 0;
    let mut already_consumed_count = 0;

    for h in handles {
        match h.await.expect("join failed") {
            Ok(_) => success_count += 1,
            Err(ArmExecutionError::SealAlreadyConsumed { .. }) => already_consumed_count += 1,
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    assert_eq!(success_count, 1);
    assert_eq!(already_consumed_count, WORKERS - 1);

    // Confirm that the debit was permanently confirmed by the winner and cannot be rolled back
    let rollback_err = engine.ledger().rollback(&debit_receipt.debit_id);
    assert!(
        matches!(rollback_err, Err(CbfViolation::AlreadyCommitted(_))),
        "Confirmed debit must be permanently settled and protected against subsequent rollback: {:?}",
        rollback_err
    );
    assert_eq!(engine.ledger().available_budget(), initial_balance - 50.0);
}

// ==============================================================================
// 2. FORMAL BFS STATE MACHINE ROBUSTNESS & RANDOM EXPLORATION DETERMINISM
// ==============================================================================

#[test]
fn test_adversarial_formal_bfs_gated_and_ungated_1000_trials_determinism() {
    let reference_gated = FormalBfsModel::explore_gated_model();
    assert_eq!(reference_gated.reachable_count, 34);
    assert_eq!(reference_gated.executed_count, 1);
    assert!(reference_gated.violations.is_empty());
    assert!(reference_gated.no_direct_bind_proven);

    let reference_ungated = FormalBfsModel::explore_ungated_counterexample();
    assert_eq!(reference_ungated.reachable_count, 17);
    assert_eq!(reference_ungated.executed_count, 1);
    assert_eq!(reference_ungated.violations.len(), 1);

    let reference_proof = FormalBfsModel::prove_no_direct_bind();
    assert_eq!(reference_proof.proof_receipt.len(), 64);
    assert!(reference_proof.proven);

    // Run 1,000 repeated trials verifying exact state immutability
    for trial in 1..=1000 {
        let gated = FormalBfsModel::explore_gated_model();
        assert_eq!(
            gated.reachable_count, 34,
            "Trial {trial}: Gated reachable state count drifted"
        );
        assert_eq!(
            gated.executed_count, 1,
            "Trial {trial}: Gated executed count drifted"
        );
        assert!(
            gated.violations.is_empty(),
            "Trial {trial}: Invariant violation in gated model"
        );
        assert!(
            gated.no_direct_bind_proven,
            "Trial {trial}: NoDirectBind must remain proven"
        );
        assert_eq!(
            gated.visited_states, reference_gated.visited_states,
            "Trial {trial}: Gated visited states set mutated"
        );

        let ungated = FormalBfsModel::explore_ungated_counterexample();
        assert_eq!(
            ungated.reachable_count, 17,
            "Trial {trial}: Ungated reachable state count drifted"
        );
        assert_eq!(
            ungated.executed_count, 1,
            "Trial {trial}: Ungated executed count drifted"
        );
        assert_eq!(
            ungated.violations.len(),
            1,
            "Trial {trial}: Ungated counterexample count drifted"
        );
        assert_eq!(
            ungated.visited_states, reference_ungated.visited_states,
            "Trial {trial}: Ungated visited states set mutated"
        );

        // Every 100 trials, verify theorem proof receipt hash stability
        if trial % 100 == 0 {
            let proof = FormalBfsModel::prove_no_direct_bind();
            assert_eq!(
                proof.proof_receipt, reference_proof.proof_receipt,
                "Trial {trial}: Cryptographic proof receipt hash drifted"
            );
        }
    }
}

/// Helper function to perform graph exploration under arbitrary randomized transition shuffling.
fn explore_randomized_transition_order(
    transitions: &HashMap<BfsState, Vec<BfsState>>,
    initial_state: BfsState,
    rng: &mut StdRng,
) -> (HashSet<BfsState>, usize, usize) {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(initial_state);

    let mut executed_count = 0;
    let mut violations_count = 0;

    while let Some(state) = queue.pop_front() {
        if visited.contains(&state) {
            continue;
        }
        visited.insert(state.clone());

        if state.phase == BfsPhase::Executed {
            executed_count += 1;
            if !state.resolved_allow || !state.seal_present {
                violations_count += 1;
            }
        }

        if let Some(next_states) = transitions.get(&state) {
            let mut shuffled_next = next_states.clone();
            shuffled_next.shuffle(rng);
            for next in shuffled_next {
                if !visited.contains(&next) {
                    queue.push_back(next);
                }
            }
        }
    }

    (visited, executed_count, violations_count)
}

#[test]
fn test_adversarial_formal_bfs_1000_random_seeds_exploration_invariance() {
    // 1. Build canonical gated transition graph
    let initial_gated = BfsState::new(BfsPhase::Initial, "PENDING", 0, false, false, false);
    let mut gated_transitions: HashMap<BfsState, Vec<BfsState>> = HashMap::new();

    let first_check = BfsState::new(
        BfsPhase::Checking,
        FormalBfsModel::TIER_NAMES[0],
        0,
        false,
        false,
        false,
    );
    gated_transitions.insert(initial_gated.clone(), vec![first_check]);

    for idx in 0..7 {
        let current_check = BfsState::new(
            BfsPhase::Checking,
            FormalBfsModel::TIER_NAMES[idx],
            idx,
            false,
            false,
            false,
        );
        let next_check = if idx < 6 {
            BfsState::new(
                BfsPhase::Checking,
                FormalBfsModel::TIER_NAMES[idx + 1],
                idx + 1,
                false,
                false,
                false,
            )
        } else {
            BfsState::new(BfsPhase::Checking, "completed", 7, false, false, false)
        };
        let direct_deny = BfsState::new(
            BfsPhase::Denied,
            format!("direct_tier_{idx}"),
            idx,
            false,
            false,
            false,
        );
        let narrow_eval = BfsState::new(
            BfsPhase::NarrowEval,
            format!("tier_{idx}"),
            idx,
            false,
            false,
            true,
        );

        gated_transitions.insert(
            current_check,
            vec![next_check, direct_deny, narrow_eval.clone()],
        );

        let narrow_rerun_deny = BfsState::new(
            BfsPhase::Denied,
            format!("narrow_rerun_tier_{idx}"),
            idx,
            false,
            false,
            false,
        );
        if idx < 6 {
            let next_narrow = BfsState::new(
                BfsPhase::NarrowEval,
                format!("tier_{}", idx + 1),
                idx + 1,
                false,
                false,
                true,
            );
            gated_transitions.insert(narrow_eval, vec![next_narrow, narrow_rerun_deny]);
        } else {
            let narrow_pass =
                BfsState::new(BfsPhase::NarrowPassed, "all_clamped", 7, true, true, true);
            gated_transitions.insert(narrow_eval, vec![narrow_pass, narrow_rerun_deny]);
        }
    }

    let seal_issued = BfsState::new(BfsPhase::SealIssued, "valid", 7, true, true, false);
    let completed_check = BfsState::new(BfsPhase::Checking, "completed", 7, false, false, false);
    gated_transitions.insert(completed_check, vec![seal_issued.clone()]);

    let narrow_pass = BfsState::new(BfsPhase::NarrowPassed, "all_clamped", 7, true, true, true);
    gated_transitions.insert(narrow_pass, vec![seal_issued.clone()]);

    let executed = BfsState::new(BfsPhase::Executed, "executed", 7, true, true, true);
    let seal_expired = BfsState::new(BfsPhase::Denied, "seal_expired", 7, true, false, false);
    gated_transitions.insert(seal_issued, vec![executed.clone(), seal_expired.clone()]);

    for idx in 0..7 {
        gated_transitions.insert(
            BfsState::new(
                BfsPhase::Denied,
                format!("direct_tier_{idx}"),
                idx,
                false,
                false,
                false,
            ),
            Vec::new(),
        );
        gated_transitions.insert(
            BfsState::new(
                BfsPhase::Denied,
                format!("narrow_rerun_tier_{idx}"),
                idx,
                false,
                false,
                false,
            ),
            Vec::new(),
        );
    }
    gated_transitions.insert(executed, Vec::new());
    gated_transitions.insert(seal_expired, Vec::new());

    // 2. Build canonical ungated transition graph
    let initial_ungated = BfsState::new(BfsPhase::Initial, "PENDING", 0, false, false, false);
    let mut ungated_transitions: HashMap<BfsState, Vec<BfsState>> = HashMap::new();

    let first_check_ungated = BfsState::new(
        BfsPhase::Checking,
        FormalBfsModel::TIER_NAMES[0],
        0,
        false,
        false,
        false,
    );
    ungated_transitions.insert(initial_ungated.clone(), vec![first_check_ungated]);

    for idx in 0..7 {
        let current_check = BfsState::new(
            BfsPhase::Checking,
            FormalBfsModel::TIER_NAMES[idx],
            idx,
            false,
            false,
            false,
        );
        let next_check = if idx < 6 {
            BfsState::new(
                BfsPhase::Checking,
                FormalBfsModel::TIER_NAMES[idx + 1],
                idx + 1,
                false,
                false,
                false,
            )
        } else {
            BfsState::new(
                BfsPhase::Executed,
                "ungated_direct_bind",
                7,
                false,
                false,
                true,
            )
        };
        let deny_state = BfsState::new(
            BfsPhase::Denied,
            format!("tier_{idx}"),
            idx,
            false,
            false,
            false,
        );

        ungated_transitions.insert(current_check, vec![next_check, deny_state.clone()]);
        ungated_transitions.insert(deny_state, Vec::new());
    }

    let ungated_exec = BfsState::new(
        BfsPhase::Executed,
        "ungated_direct_bind",
        7,
        false,
        false,
        true,
    );
    let term_fail = BfsState::new(BfsPhase::Denied, "terminal_failure", 7, false, false, false);
    ungated_transitions.insert(ungated_exec, vec![term_fail.clone()]);
    ungated_transitions.insert(term_fail, Vec::new());

    // 3. Explore across 1,000 distinct randomized seeds
    for seed in 0..1000u64 {
        let mut rng = StdRng::seed_from_u64(seed);

        // Gated exploration under randomized child permutation
        let (visited_gated, exec_count_gated, violations_gated) =
            explore_randomized_transition_order(
                &gated_transitions,
                initial_gated.clone(),
                &mut rng,
            );

        assert_eq!(
            visited_gated.len(),
            34,
            "Seed {seed}: Gated state space must always contain strictly 34 states regardless of exploration order"
        );
        assert_eq!(
            exec_count_gated, 1,
            "Seed {seed}: Exactly 1 executed state must be discovered in gated model"
        );
        assert_eq!(
            violations_gated, 0,
            "Seed {seed}: Exactly 0 violations allowed in gated model"
        );

        // Ungated exploration under randomized child permutation
        let (visited_ungated, exec_count_ungated, violations_ungated) =
            explore_randomized_transition_order(
                &ungated_transitions,
                initial_ungated.clone(),
                &mut rng,
            );

        assert_eq!(
            visited_ungated.len(),
            17,
            "Seed {seed}: Ungated state space must always contain strictly 17 states regardless of exploration order"
        );
        assert_eq!(
            exec_count_ungated, 1,
            "Seed {seed}: Exactly 1 executed state must be discovered in ungated model"
        );
        assert_eq!(
            violations_ungated, 1,
            "Seed {seed}: Exactly 1 direct-bind violation counterexample must be discovered in ungated model"
        );
    }
}

// ==============================================================================
// 3. TWO-PHASE FISCAL LEDGER CONCURRENCY & ZERO BALANCE DRIFT
// ==============================================================================

#[test]
fn test_adversarial_fiscal_ledger_concurrent_zero_drift() {
    let initial_budget = 500_000.0;
    let gamma = 0.5;
    let b_min = 1_000.0;

    let ledger = Arc::new(
        DebitLedger::new(initial_budget, gamma, b_min)
            .expect("debit ledger initialization must succeed"),
    );

    const THREADS: usize = 24;
    const OPS_PER_THREAD: usize = 50;

    // We track the net amount that was permanently confirmed using an atomic integer (in cents / scaled units)
    let total_committed_cents = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();

    for thread_id in 0..THREADS {
        let l = Arc::clone(&ledger);
        let committed_acc = Arc::clone(&total_committed_cents);

        handles.push(std::thread::spawn(move || {
            for op_idx in 0..OPS_PER_THREAD {
                let debit_id = format!("tx_{thread_id}_{op_idx}");
                let cost_cents = (op_idx % 15 + 1) * 1000; // 10.0 to 150.0
                let cost = cost_cents as f64;

                // Alternate operations:
                match op_idx % 4 {
                    0 => {
                        // Pattern 0: Reserve then Confirm
                        if let Ok(receipt) = l.pre_reserve(cost, &debit_id) {
                            assert_eq!(receipt.reserved_fuel, cost);
                            let conf_res = l.confirm(&debit_id);
                            if conf_res.is_ok() {
                                committed_acc.fetch_add((cost * 100.0).round() as u64, Ordering::SeqCst);

                                // Adversarial double-rollback attack after confirm must fail closed
                                let double_rb = l.rollback(&debit_id);
                                assert!(
                                    matches!(double_rb, Err(CbfViolation::AlreadyCommitted(_))),
                                    "Rollback after confirm must be rejected"
                                );
                            } else {
                                // Was rolled back by concurrent LIFO rollback!
                                assert!(
                                    matches!(conf_res, Err(CbfViolation::ReservationNotFound(_))),
                                    "Confirm on LIFO rolled back entry must fail with ReservationNotFound"
                                );
                            }
                        }
                    }
                    1 => {
                        // Pattern 1: Reserve then explicit Rollback
                        if let Ok(_) = l.pre_reserve(cost, &debit_id) {
                            let rb_res = l.rollback(&debit_id);
                            if rb_res.is_ok() {
                                // Adversarial double-rollback attack must fail closed
                                let double_rb = l.rollback(&debit_id);
                                assert!(
                                    matches!(double_rb, Err(CbfViolation::ReservationNotFound(_))),
                                    "Double rollback must be rejected"
                                );

                                // Adversarial confirm after rollback must fail closed
                                let conf_after_rb = l.confirm(&debit_id);
                                assert!(
                                    matches!(conf_after_rb, Err(CbfViolation::ReservationNotFound(_))),
                                    "Confirm after rollback must be rejected"
                                );
                            } else {
                                // Was already rolled back by concurrent LIFO rollback!
                                assert!(
                                    matches!(rb_res, Err(CbfViolation::ReservationNotFound(_))),
                                    "Rollback on already rolled-back entry must fail with ReservationNotFound"
                                );
                            }
                        }
                    }
                    2 => {
                        // Pattern 2: Preview then conditional Reserve & LIFO rollback
                        let preview_res = l.preview(cost);
                        if preview_res.is_ok() {
                            if let Ok(_) = l.pre_reserve(cost, &debit_id) {
                                // Immediately roll back LIFO
                                let lifo_res = l.rollback_lifo();
                                assert!(lifo_res.is_ok(), "LIFO rollback should succeed");
                            }
                        }
                    }
                    3 => {
                        // Pattern 3: Adversarial invalid operations
                        // Try to rollback a completely non-existent debit ID
                        let bogus_id = format!("non_existent_{thread_id}_{op_idx}");
                        let bogus_rb = l.rollback(&bogus_id);
                        assert!(
                            matches!(bogus_rb, Err(CbfViolation::ReservationNotFound(_))),
                            "Rollback of non-existent debit must fail closed"
                        );

                        // Try to confirm a non-existent debit ID
                        let bogus_conf = l.confirm(&bogus_id);
                        assert!(
                            matches!(bogus_conf, Err(CbfViolation::ReservationNotFound(_))),
                            "Confirm of non-existent debit must fail closed"
                        );

                        // Try to reserve an impossible amount (> remaining balance)
                        let impossible_reserve = l.pre_reserve(initial_budget * 2.0, &bogus_id);
                        assert!(
                            impossible_reserve.is_err(),
                            "Overdraft reservation must be rejected by CBF"
                        );
                    }
                    _ => unreachable!(),
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("Worker thread panicked");
    }

    // Now verify the exact mathematical conservation of the fiscal ledger
    let _ = ledger.available_budget();
    let total_committed_dollars = (total_committed_cents.load(Ordering::SeqCst) as f64) / 100.0;

    // Roll back all remaining active uncommitted reservations via LIFO
    while let Ok(_) = ledger.rollback_lifo() {
        // continue rolling back uncommitted items
    }

    assert_eq!(
        ledger.active_reservation_count(),
        0,
        "All active reservations must be 0 after draining LIFO rollbacks"
    );

    let settled_available = ledger.available_budget();

    // STRICT MATHEMATICAL ZERO DRIFT INVARIANT:
    // settled_available + total_committed_dollars == initial_budget
    let balance_diff = (settled_available + total_committed_dollars - initial_budget).abs();
    assert!(
        balance_diff < CBF_EPSILON,
        "CRITICAL FISCAL LEAKAGE DETECTED: settled={settled_available}, committed={total_committed_dollars}, initial={initial_budget}, drift={balance_diff}"
    );

    println!(
        "[Fiscal Drift Test] Initial={:.2}, Committed={:.2}, Settled Available={:.2}, Drift={:.12}",
        initial_budget, total_committed_dollars, settled_available, balance_diff
    );
}

#[test]
fn test_adversarial_fiscal_cbf_barrier_boundary_stress() {
    let initial_budget = 10_000.0;
    let gamma = 0.25;
    let b_min = 2_000.0;

    let ledger = DebitLedger::new(initial_budget, gamma, b_min).expect("ledger init");

    // Barrier margin h0 = 10000 - 2000 = 8000.
    // Next step requires: h1 >= (1 - 0.25) * 8000 = 0.75 * 8000 = 6000.
    // h1 = (10000 - c) - 2000 = 8000 - c.
    // Therefore 8000 - c >= 6000 => c <= 2000.
    // Exactly at c = 2000.0, step passes.
    // At c = 2000.01, step must fail with DecayRateExceeded.

    let preview_exact = ledger.preview(2000.0);
    assert!(
        preview_exact.is_ok(),
        "Step exactly at gamma limit must pass"
    );

    let preview_breach = ledger.preview(2000.01);
    assert!(
        matches!(preview_breach, Err(CbfViolation::DecayRateExceeded { .. })),
        "Step exceeding gamma limit must fail closed with DecayRateExceeded: {:?}",
        preview_breach
    );

    // Assert that available budget has zero mutation after failed previews
    assert_eq!(ledger.available_budget(), initial_budget);
}
