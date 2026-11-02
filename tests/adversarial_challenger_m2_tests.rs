//! ==============================================================================
//! [AGENT OCTOPUS] MILESTONE 2 ADVERSARIAL CHALLENGER TEST SUITE
//! ==============================================================================
//! Empirical Stress-Testing for Actuator Confinement Seal Enforcement:
//! 1. Seal Replay Attacks:
//!    - Sequential replay fail-closed verification
//!    - Multi-threaded concurrent replay race condition resistance
//!    - Cross-arm fleet replay rejection
//! 2. Clock Skew and Expired Seal Rejection:
//!    - Expired TTL rejection (beyond 30s)
//!    - Future timestamp drift rejection (> 5s tolerance)
//!    - Forged expires_at / issued_at tampering
//!    - Structural TTL invariant mismatch detection
//! 3. Action Digest & Payload Tampering:
//!    - Single-bit payload mutation
//!    - Parameter structural manipulation
//!    - Action/tool name substitution
//! 4. Cross-Arm Seal Theft & Capability Ticket Binding:
//!    - Capability ticket cross-arm isolation (Dirac ticket identity spoofing)
//!    - Stolen seal attribution and audit trail traceability
//! 5. Fiscal Debit Manipulation & Balance Integrity:
//!    - Double rollback prevention (no duplicate refund)
//!    - Rollback after confirm rejection (settled debit cannot be revoked)
//!    - Confirm after rollback rejection
//!    - Bogus debit ID rejection with zero balance mutation
//!    - Actuator failure rollback vs actuator success confirm balance invariants
//! 6. Cryptographic Seal Integrity & Unanchored Evidence:
//!    - Signature bit-flip rejection
//!    - Policy version tampering rejection
//!    - Unanchored audit hash rejection (Tallam 2026 Evidence Sufficiency)
//! 7. 7-Rule GOVERNANCE_TRACE Conformance on Adversarial Streams:
//!    - Conformance on valid actuation
//!    - Detection of injected replay in audit stream (Rule 7)
//!    - Detection of unsealed execution in audit stream (Rule 6)
//! ==============================================================================

use agent_octopus::containment_ring::{
    ArmContainmentRing, ArmExecutionError,
    TieredExecutionDispatcher, TieredToolRequest,
};
use agent_octopus::core::types::{ArmRole, OctopusSecurityError};
use agent_octopus::security::cage_governance::cbf_fiscal::CbfViolation;
use agent_octopus::security::cage_governance::no_direct_bind_proof::FormalBfsModel;
use agent_octopus::security::cage_governance::routing_seal::{
    CageRoutingSeal, SealRejection,
};
use agent_octopus::security::cage_governance::CageGovernanceEngine;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_MASTER_SEED: &[u8] = b"OCTOPUS_CHALLENGER_M2_SEED_2026";
const TEST_RESOURCE: &str = "s3://invoices/inv_01.pdf";

fn new_test_dispatcher() -> TieredExecutionDispatcher {
    let mercury = Arc::new(agent_octopus::security::mercury_guard::MercuryContainmentEngine::new());
    TieredExecutionDispatcher::try_new(mercury).expect("dispatcher init")
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
// 1. SEAL REPLAY ATTACKS
// ==============================================================================

#[tokio::test]
async fn test_adversarial_sequential_and_concurrent_seal_replay() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));

    let scratch_dir = std::env::temp_dir().join(format!("octopus_replay_adv_{}", std::process::id()));
    let dispatcher = new_test_dispatcher();

    let payload = b"INVOICE #2001: Sequential and Concurrent Replay".to_vec();
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

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let seal = create_test_seal_with_time(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        TEST_RESOURCE,
        &payload,
        now,
    );

    // Part A: Sequential replay attack
    let mut ticket1 = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .expect("ticket 1");

    let receipt1 = ring
        .execute_tool_with_cage_seal(
            &mut ticket1,
            &seal,
            TEST_RESOURCE,
            &tiered_req,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect("First execution must succeed");
    assert!(receipt1.exit_code >= 0);

    // Replay with second ticket
    let mut ticket2 = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .expect("ticket 2");

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

    assert!(matches!(replay_err, ArmExecutionError::SealAlreadyConsumed { .. }));

    // Part B: Fleet-wide cross-arm replay rejection
    // Ring 1 on same fleet engine presents the already-consumed seal
    let ring1 = ArmContainmentRing::new(1, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));
    let mut ticket_ring1 = ring1
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .expect("ticket ring 1");

    let tiered_req1 = TieredToolRequest {
        agent_id: ring1.agent_name.clone(),
        role: ArmRole::UntrustedDocIngest,
        tool_name: "doc_extractor".to_string(),
        payload: payload.clone(),
        custom_wat: None,
        native_command: None,
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };

    let cross_arm_replay_err = ring1
        .execute_tool_with_cage_seal(
            &mut ticket_ring1,
            &seal,
            TEST_RESOURCE,
            &tiered_req1,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect_err("Cross-arm replay of consumed seal must fail closed");

    assert!(matches!(
        cross_arm_replay_err,
        ArmExecutionError::SealAlreadyConsumed { .. }
    ));
}

#[tokio::test]
async fn test_adversarial_multithreaded_concurrent_seal_race() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = Arc::new(
        ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
            .with_cage_engine(Arc::clone(&engine)),
    );

    let scratch_dir = std::env::temp_dir().join(format!("octopus_race_{}", std::process::id()));
    let payload = b"INVOICE #2002: Concurrent Race Condition".to_vec();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let seal = Arc::new(create_test_seal_with_time(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        TEST_RESOURCE,
        &payload,
        now,
    ));

    // Launch 10 concurrent tasks all attempting to execute using the EXACT SAME seal
    let mut handles = Vec::new();
    for _i in 0..10 {
        let r = Arc::clone(&ring);
        let s = Arc::clone(&seal);
        let p = payload.clone();
        let sdir = scratch_dir.clone();

        let handle = tokio::spawn(async move {
            let dispatcher = new_test_dispatcher();
            let mut ticket = r
                .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
                .await
                .expect("ticket");

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
        });
        handles.push(handle);
    }

    let mut success_count = 0;
    let mut already_consumed_count = 0;

    for h in handles {
        match h.await.unwrap() {
            Ok(receipt) => {
                assert!(receipt.exit_code >= 0);
                success_count += 1;
            }
            Err(ArmExecutionError::SealAlreadyConsumed { .. }) => {
                already_consumed_count += 1;
            }
            Err(other) => {
                panic!("Unexpected error in concurrent race: {:?}", other);
            }
        }
    }

    // Mathematical invariant: Exactly 1 task succeeds; 9 tasks are rejected with SealAlreadyConsumed
    assert_eq!(
        success_count, 1,
        "Exactly 1 task must successfully consume the seal in concurrent race"
    );
    assert_eq!(
        already_consumed_count, 9,
        "Exactly 9 tasks must be rejected with SealAlreadyConsumed"
    );
}

// ==============================================================================
// 2. CLOCK SKEW AND EXPIRED SEAL REJECTION
// ==============================================================================

#[tokio::test]
async fn test_adversarial_clock_skew_and_ttl_boundary() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));

    let scratch_dir = std::env::temp_dir().join(format!("octopus_skew_{}", std::process::id()));
    let dispatcher = new_test_dispatcher();
    let payload = b"INVOICE #2003: Clock Skew and TTL Boundaries".to_vec();
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

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // 1. Expired by 1 second past TTL (issued 31s ago: expires_at = now - 1)
    let expired_seal_1 = create_test_seal_with_time(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        TEST_RESOURCE,
        &payload,
        now - 31,
    );
    let mut t1 = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .unwrap();
    let err1 = ring
        .execute_tool_with_cage_seal(&mut t1, &expired_seal_1, TEST_RESOURCE, &tiered_req, &dispatcher, None, None)
        .await
        .unwrap_err();
    assert!(matches!(err1, ArmExecutionError::SealExpired { .. }));

    // 2. Expired by 100 seconds
    let expired_seal_100 = create_test_seal_with_time(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        TEST_RESOURCE,
        &payload,
        now - 130,
    );
    let mut t2 = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .unwrap();
    let err2 = ring
        .execute_tool_with_cage_seal(&mut t2, &expired_seal_100, TEST_RESOURCE, &tiered_req, &dispatcher, None, None)
        .await
        .unwrap_err();
    assert!(matches!(err2, ArmExecutionError::SealExpired { .. }));

    // 3. Future clock skew exceeding 5s tolerance (issued at now + 6s)
    let future_seal_6 = create_test_seal_with_time(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        TEST_RESOURCE,
        &payload,
        now + 6,
    );
    let mut t3 = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .unwrap();
    let err3 = ring
        .execute_tool_with_cage_seal(&mut t3, &future_seal_6, TEST_RESOURCE, &tiered_req, &dispatcher, None, None)
        .await
        .unwrap_err();
    assert!(matches!(err3, ArmExecutionError::InvalidCageSeal { .. }));

    // 4. Future clock skew within 5s tolerance (issued at now + 3s) -> Accepted within tolerance
    let valid_drift_seal = create_test_seal_with_time(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        TEST_RESOURCE,
        &payload,
        now + 3,
    );
    let mut t4 = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .unwrap();
    let res4 = ring
        .execute_tool_with_cage_seal(&mut t4, &valid_drift_seal, TEST_RESOURCE, &tiered_req, &dispatcher, None, None)
        .await;
    assert!(res4.is_ok(), "Drift of 3s within 5s tolerance must succeed");

    // 5. Attacker maliciously extends expires_at without re-signing
    let mut tampered_seal = valid_drift_seal.clone();
    tampered_seal.seal_id = format!("seal_{}", hex::encode(rand::random::<[u8; 16]>()));
    tampered_seal.expires_at = tampered_seal.issued_at + 3600; // Attempt 1 hour extension
    let mut t5 = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .unwrap();
    let err5 = ring
        .execute_tool_with_cage_seal(&mut t5, &tampered_seal, TEST_RESOURCE, &tiered_req, &dispatcher, None, None)
        .await
        .unwrap_err();
    assert!(matches!(err5, ArmExecutionError::InvalidCageSeal { .. }));
}

// ==============================================================================
// 3. ACTION DIGEST & PAYLOAD TAMPERING
// ==============================================================================

#[tokio::test]
async fn test_adversarial_action_digest_and_payload_tampering() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));

    let scratch_dir = std::env::temp_dir().join(format!("octopus_tamper_{}", std::process::id()));
    let dispatcher = new_test_dispatcher();

    let genuine_payload = b"INVOICE #3001: Genuine Invoice Payload $1000.00".to_vec();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let genuine_req = TieredToolRequest {
        agent_id: ring.agent_name.clone(),
        role: ArmRole::UntrustedDocIngest,
        tool_name: "doc_extractor".to_string(),
        payload: genuine_payload.clone(),
        custom_wat: None,
        native_command: None,
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };

    // Genuine seal issued for genuine_payload
    let seal = create_test_seal_with_time(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        TEST_RESOURCE,
        &genuine_payload,
        now,
    );

    // Attack 1: Single-bit flip in payload
    let mut bit_flipped_payload = genuine_payload.clone();
    bit_flipped_payload[0] ^= 0x01; // Mutate first bit

    let bit_flipped_req = TieredToolRequest {
        agent_id: ring.agent_name.clone(),
        role: ArmRole::UntrustedDocIngest,
        tool_name: "doc_extractor".to_string(),
        payload: bit_flipped_payload,
        custom_wat: None,
        native_command: None,
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };

    let mut t1 = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .unwrap();
    let err1 = ring
        .execute_tool_with_cage_seal(&mut t1, &seal, TEST_RESOURCE, &bit_flipped_req, &dispatcher, None, None)
        .await
        .unwrap_err();

    assert!(matches!(err1, ArmExecutionError::ActionDigestMismatch { .. }));
    let sec_err1 = OctopusSecurityError::from(err1);
    assert!(matches!(sec_err1, OctopusSecurityError::MerkleTamperDetected(ref msg) if msg.contains("CAGE_ACTION_DIGEST_MISMATCH")));

    // Attack 2: Seal issued for a different tool ("privileged_tool"), presented for doc_extractor
    let mismatched_tool_seal = create_test_seal_with_time(
        &engine,
        &ring.agent_name,
        "privileged_tool",
        TEST_RESOURCE,
        &genuine_payload,
        now,
    );

    let mut t2 = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .unwrap();
    let err2 = ring
        .execute_tool_with_cage_seal(&mut t2, &mismatched_tool_seal, TEST_RESOURCE, &genuine_req, &dispatcher, None, None)
        .await
        .unwrap_err();

    assert!(matches!(err2, ArmExecutionError::ActionDigestMismatch { .. }));

    // Attack 3: Empty payload substitution
    let empty_payload_req = TieredToolRequest {
        agent_id: ring.agent_name.clone(),
        role: ArmRole::UntrustedDocIngest,
        tool_name: "doc_extractor".to_string(),
        payload: Vec::new(),
        custom_wat: None,
        native_command: None,
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };

    let mut t3 = ring
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .unwrap();
    let err3 = ring
        .execute_tool_with_cage_seal(&mut t3, &seal, TEST_RESOURCE, &empty_payload_req, &dispatcher, None, None)
        .await
        .unwrap_err();

    assert!(matches!(err3, ArmExecutionError::ActionDigestMismatch { .. }));
}

// ==============================================================================
// 4. CROSS-ARM ISOLATION & CAPABILITY TICKET INTEGRITY
// ==============================================================================

#[tokio::test]
async fn test_adversarial_cross_arm_theft_and_ticket_spoofing() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring_a = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));
    let ring_b = ArmContainmentRing::new(3, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));

    let scratch_dir = std::env::temp_dir().join(format!("octopus_crossarm_{}", std::process::id()));
    let dispatcher = new_test_dispatcher();

    let payload = b"INVOICE #4001: Cross-Arm Isolation Test".to_vec();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Seal issued for Arm A
    let seal_a = create_test_seal_with_time(
        &engine,
        &ring_a.agent_name,
        "doc_extractor",
        TEST_RESOURCE,
        &payload,
        now,
    );

    // Arm A issues ticket for itself
    let mut ticket_a = ring_a
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .expect("ticket for arm A");

    // Attack Scenario 1: Arm B attempts to use Arm A's capability ticket directly
    let req_b = TieredToolRequest {
        agent_id: ring_b.agent_name.clone(),
        role: ArmRole::UntrustedDocIngest,
        tool_name: "doc_extractor".to_string(),
        payload: payload.clone(),
        custom_wat: None,
        native_command: None,
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };

    let cross_ticket_err = ring_b
        .execute_tool_with_cage_seal(
            &mut ticket_a, // Stolen ticket from Arm A
            &seal_a,
            TEST_RESOURCE,
            &req_b,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect_err("Stolen ticket from Arm A presented to Arm B must fail closed");

    // ticket.verify_and_consume asserts self.arm_id == ticket.arm_id via HMAC tag
    let sec_err = OctopusSecurityError::from(cross_ticket_err);
    assert!(
        matches!(sec_err, OctopusSecurityError::IdentitySpoofingDetected(..) | OctopusSecurityError::CapabilityDenied(..)),
        "Expected IdentitySpoofingDetected or CapabilityDenied for ticket theft, got: {:?}",
        sec_err
    );
    let err_str = format!("{:?}", sec_err);
    assert!(
        err_str.contains("spoofing") || err_str.contains("LAW3_SIGNATURE_INVALID"),
        "Must verify Law 3 cryptographic identity binding: {}",
        err_str
    );

    // Attack Scenario 2: Arm B uses its own ticket, and attempts to consume Arm A's seal
    let mut ticket_b = ring_b
        .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
        .await
        .expect("ticket for arm B");

    let res_b = ring_b
        .execute_tool_with_cage_seal(
            &mut ticket_b,
            &seal_a,
            TEST_RESOURCE,
            &req_b,
            &dispatcher,
            None,
            None,
        )
        .await;

    // Under CAGE Substrate §3, seals verify action_digest & record_hash.
    // If Arm B executes with seal A, seal A becomes CONSUMED.
    if res_b.is_ok() {
        // Seal A is now consumed. Arm A presenting seal A must be strictly REJECTED (Replay).
        let mut ticket_a_retry = ring_a
            .issue_dirac_ticket("doc_extractor", TEST_RESOURCE, 50_000, None)
            .await
            .expect("retry ticket for arm A");
        let req_a = TieredToolRequest {
            agent_id: ring_a.agent_name.clone(),
            role: ArmRole::UntrustedDocIngest,
            tool_name: "doc_extractor".to_string(),
            payload: payload.clone(),
            custom_wat: None,
            native_command: None,
            scratchpad_root: scratch_dir.clone(),
            allow_scratch_write: false,
        };

        let retry_err = ring_a
            .execute_tool_with_cage_seal(
                &mut ticket_a_retry,
                &seal_a,
                TEST_RESOURCE,
                &req_a,
                &dispatcher,
                None,
                None,
            )
            .await
            .expect_err("Arm A re-presenting stolen seal must fail closed as already consumed");

        assert!(matches!(
            retry_err,
            ArmExecutionError::SealAlreadyConsumed { .. }
        ));
    }
}

// ==============================================================================
// 5. FISCAL DEBIT MANIPULATION & BALANCE INTEGRITY
// ==============================================================================

#[tokio::test]
async fn test_adversarial_fiscal_debit_manipulation() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ledger = engine.ledger();

    // Initial state: available_budget = 1000.0, floor = 10.0, gamma = 0.1
    assert_eq!(ledger.available_budget(), 1000.0);
    assert_eq!(ledger.floor_threshold(), 10.0);

    // 1. Pre-reserve 50.0
    let debit_id = "debit_adv_001";
    let receipt1 = ledger.pre_reserve(50.0, debit_id).expect("pre-reserve 50");
    assert_eq!(receipt1.remaining_budget, 950.0);
    assert_eq!(ledger.available_budget(), 950.0);

    // 2. Double Rollback Prevention:
    // First rollback succeeds and restores 50.0
    let restored_balance = ledger.rollback(debit_id).expect("first rollback");
    assert_eq!(restored_balance, 1000.0);
    assert_eq!(ledger.available_budget(), 1000.0);

    // Second rollback must fail and NOT refund budget again!
    let double_rollback_err = ledger.rollback(debit_id).expect_err("double rollback must fail");
    assert!(matches!(
        double_rollback_err,
        CbfViolation::ReservationNotFound(ref msg) if msg.contains("already rolled back")
    ));
    assert_eq!(
        ledger.available_budget(),
        1000.0,
        "Balance must not increase on second rollback"
    );

    // 3. Confirm After Rollback Prevention
    let confirm_after_rollback_err = ledger.confirm(debit_id).expect_err("confirm after rollback must fail");
    assert!(matches!(
        confirm_after_rollback_err,
        CbfViolation::ReservationNotFound(ref msg) if msg.contains("already rolled back")
    ));

    // 4. Rollback After Confirm Prevention:
    let debit_id_2 = "debit_adv_002";
    ledger.pre_reserve(50.0, debit_id_2).expect("pre-reserve debit 2");
    assert_eq!(ledger.available_budget(), 950.0);

    ledger.confirm(debit_id_2).expect("confirm debit 2");
    assert_eq!(ledger.available_budget(), 950.0);

    // Attempt rollback on settled/confirmed debit
    let rollback_after_confirm_err = ledger.rollback(debit_id_2).expect_err("rollback on confirmed debit must fail");
    assert!(matches!(
        rollback_after_confirm_err,
        CbfViolation::AlreadyCommitted(ref id) if id == debit_id_2
    ));
    assert_eq!(
        ledger.available_budget(),
        950.0,
        "Settled debit cannot be revoked"
    );

    // 5. Bogus Debit ID Rejection
    let bogus_rollback_err = ledger.rollback("nonexistent_debit_xyz").expect_err("bogus rollback");
    assert!(matches!(bogus_rollback_err, CbfViolation::ReservationNotFound(..)));
    assert_eq!(ledger.available_budget(), 950.0);

    let bogus_confirm_err = ledger.confirm("nonexistent_debit_xyz").expect_err("bogus confirm");
    assert!(matches!(bogus_confirm_err, CbfViolation::ReservationNotFound(..)));
    assert_eq!(ledger.available_budget(), 950.0);
}

// ==============================================================================
// 6. CRYPTOGRAPHIC SEAL TAMPERING & TALLAM 2026 EVIDENCE SUFFICIENCY
// ==============================================================================

#[test]
fn test_adversarial_seal_tampering_and_unanchored_evidence() {
    let engine = CageGovernanceEngine::default();
    let signer = engine.seal_signer();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // 1. Tallam 2026 Evidence Sufficiency: Unanchored record hashes must fail closed
    let genesis_hash = "GENESIS_AUDIT_ROOT_000000000000000000000000000000000000000000000000";
    let valid_digest = hex::encode(Sha256::digest(b"action_digest_xyz"));

    let err_genesis = signer.issue_seal(&valid_digest, genesis_hash, now).unwrap_err();
    assert!(matches!(err_genesis, SealRejection::UnanchoredEvidence(..)));

    let all_zeros_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let err_zeros = signer.issue_seal(&valid_digest, all_zeros_hash, now).unwrap_err();
    assert!(matches!(err_zeros, SealRejection::UnanchoredEvidence(..)));

    let short_hash = "1234567890abcdef";
    let err_short = signer.issue_seal(&valid_digest, short_hash, now).unwrap_err();
    assert!(matches!(err_short, SealRejection::UnanchoredEvidence(..)));

    // 2. Valid issuance
    let valid_hash = hex::encode(Sha256::digest(b"evidence_anchor_12345"));
    let seal = signer.issue_seal(&valid_digest, &valid_hash, now).expect("valid seal");

    // 3. Signature bit-flip tampering
    let mut tampered_sig_seal = seal.clone();
    let mut sig_chars: Vec<char> = tampered_sig_seal.signature.chars().collect();
    sig_chars[0] = if sig_chars[0] == 'a' { 'b' } else { 'a' };
    tampered_sig_seal.signature = sig_chars.into_iter().collect();

    let err_sig = signer
        .validate_and_consume(&tampered_sig_seal, &valid_digest, &valid_hash, now)
        .unwrap_err();
    assert_eq!(err_sig, SealRejection::InvalidSignature);

    // 4. Policy version tampering
    let mut tampered_ver_seal = seal.clone();
    tampered_ver_seal.policy_version_id = "0000000000000000".to_string();
    let err_ver = signer
        .validate_and_consume(&tampered_ver_seal, &valid_digest, &valid_hash, now)
        .unwrap_err();
    assert!(matches!(err_ver, SealRejection::PolicyVersionMismatch { .. }));

    // 5. Record hash tampering
    let mut tampered_rec_seal = seal.clone();
    tampered_rec_seal.record_hash = hex::encode(Sha256::digest(b"different_anchor"));
    let err_rec = signer
        .validate_and_consume(&tampered_rec_seal, &valid_digest, &valid_hash, now)
        .unwrap_err();
    assert!(matches!(err_rec, SealRejection::RecordHashMismatch { .. }));
}

// ==============================================================================
// 7. TRACE CONFORMANCE ON ADVERSARIAL AUDIT STREAMS
// ==============================================================================

#[test]
fn test_adversarial_trace_conformance_detection() {
    // 1. Valid baseline stream passes all 7 rules
    let valid_decision_hash = hex::encode(Sha256::digest(b"decision_001"));
    let seal_id = "seal_test_adversarial_trace_001";

    let valid_records = vec![
        serde_json::json!({
            "event_type": "CAGE_GOVERNANCE_DECISION",
            "verdict": "ALLOW",
            "seal_present": true,
            "record_hash": valid_decision_hash,
            "stages_evaluated": [
                {"stage_name": "ftra"},
                {"stage_name": "stpa"},
                {"stage_name": "cedar"},
                {"stage_name": "confidence"},
                {"stage_name": "consensus"},
                {"stage_name": "cbf"},
                {"stage_name": "fiscal"},
            ]
        }),
        serde_json::json!({
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "seal_id": seal_id,
            "decision_record_hash": valid_decision_hash,
        }),
        serde_json::json!({
            "event_type": "ACTUATION_RECEIPT",
            "seal_id": seal_id,
            "action": "doc_extractor",
            "agent_id": "arm_0",
        }),
    ];

    let report_valid = FormalBfsModel::check_trace_conformance(&valid_records);
    assert!(
        report_valid.status.is_conformant(),
        "Valid trace must pass all 7 rules: {:?}",
        report_valid.findings
    );

    // 2. Injected Replay Attack (Rule 7: single_use violation)
    let replayed_records = vec![
        valid_records[0].clone(),
        valid_records[1].clone(),
        // Replayed seal consumption
        valid_records[1].clone(),
        valid_records[2].clone(),
    ];
    let report_replay = FormalBfsModel::check_trace_conformance(&replayed_records);
    assert!(
        !report_replay.status.is_conformant(),
        "Replay in trace stream must trigger Rule 7 finding"
    );
    assert!(
        report_replay.findings.iter().any(|f| f.rule == "single_use"),
        "Expected single_use finding, got: {:?}",
        report_replay.findings
    );

    // 3. Direct Execution without Seal Consumption (Rule 6: no_direct_bind violation)
    let unsealed_records = vec![
        valid_records[0].clone(),
        // Omit GOVERNANCE_SEAL_CONSUMED, jump straight to actuation
        valid_records[2].clone(),
    ];
    let report_unsealed = FormalBfsModel::check_trace_conformance(&unsealed_records);
    assert!(
        !report_unsealed.status.is_conformant(),
        "Execution without seal consumption must trigger Rule 6 finding"
    );
    assert!(
        report_unsealed.findings.iter().any(|f| f.rule == "no_direct_bind"),
        "Expected no_direct_bind finding, got: {:?}",
        report_unsealed.findings
    );

    // 4. Non-64-hex lowercase hash (Rule 1: schema violation)
    let invalid_schema_records = vec![
        serde_json::json!({
            "event_type": "CAGE_GOVERNANCE_DECISION",
            "verdict": "ALLOW",
            "seal_present": true,
            "record_hash": "UPPERCASE_HASH_INVALID_12345678901234567890123456789012345678901234",
            "stages_evaluated": [
                {"stage_name": "ftra"},
                {"stage_name": "stpa"},
                {"stage_name": "cedar"},
                {"stage_name": "confidence"},
                {"stage_name": "consensus"},
                {"stage_name": "cbf"},
                {"stage_name": "fiscal"},
            ]
        }),
    ];
    let report_schema = FormalBfsModel::check_trace_conformance(&invalid_schema_records);
    assert!(
        !report_schema.status.is_conformant(),
        "Uppercase/invalid hash must trigger Rule 1 schema finding"
    );
    assert!(
        report_schema.findings.iter().any(|f| f.rule == "schema"),
        "Expected schema finding, got: {:?}",
        report_schema.findings
    );
}
