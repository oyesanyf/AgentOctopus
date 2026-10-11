//! Level 1: Individual Arm Containment Ring Test Suite
//!
//! Validates the 3-Level Concentric Containment Architecture:
//! - Level 1: Individual Arm Rings (50 independently enforced rings around 50 arms)
//! - Level 2: Neural Mesh Security Ring (route mediation & message epoch integrity)
//! - Level 3: Global Octopus Containment Ring (host protection & global Cedar PARC)
//!
//! Includes rigorous Positive Controls, Negative Controls, and Execution Epoch verification.

use agent_octopus::containment_ring::{ArmContainmentRing, ArmRingRegistry};
use agent_octopus::core::types::{ArmRole, OctopusSecurityError, StrategicDirective};
use agent_octopus::neural_mesh::MessageKind;
use agent_octopus::swarm::orchestrator::SwarmManager;
use std::time::Duration;
use tokio::sync::mpsc;

const TEST_MASTER_SEED: &[u8] = b"OCTOPUS_TEST_CONTAINMENT_SEED_2026";

#[tokio::test]
async fn test_fleet_initialization_of_50_distinct_arm_rings() {
    let registry = ArmRingRegistry::new(50, TEST_MASTER_SEED);
    assert_eq!(registry.len().await, 50);

    // Verify all 50 arms have distinct identities and proper role distribution
    for arm_id in 0..50 {
        let ring = registry.get_ring(arm_id).await.expect("Ring must exist");
        assert_eq!(ring.arm_id, arm_id);
        assert_eq!(ring.current_generation(), 1);
        assert!(!ring.is_severed());

        let expected_role = match arm_id % 3 {
            0 => ArmRole::UntrustedDocIngest,
            1 => ArmRole::AccountingLedgerWrite,
            _ => ArmRole::NetworkEgress,
        };
        assert_eq!(ring.role, expected_role);
    }
}

#[tokio::test]
async fn test_level_1_arm_ring_tool_and_resource_bounds() {
    let ring = ArmContainmentRing::new(
        17,
        ArmRole::UntrustedDocIngest,
        1,
        TEST_MASTER_SEED,
    );

    // Allowed tool & resource
    assert!(ring
        .validate_tool_invocation("doc_extractor", "s3://invoices/inv_1.pdf", 1)
        .await
        .is_ok());

    // Prohibited tool for Document Ingest: Ledger Writer must be rejected
    let bad_tool = ring
        .validate_tool_invocation("ledger_writer", "s3://invoices/inv_1.pdf", 1)
        .await;
    assert!(matches!(bad_tool, Err(OctopusSecurityError::CapabilityDenied(_))));

    // Prohibited resource for Document Ingest: Sensitive ledger URI must be rejected
    let bad_resource = ring
        .validate_tool_invocation("doc_extractor", "s3://accounting/ledger.json", 1)
        .await;
    assert!(matches!(bad_resource, Err(OctopusSecurityError::EnclaveViolation(_))));
}

#[tokio::test]
async fn test_level_1_arm_ring_memory_clamp_and_step_budget() {
    let ring = ArmContainmentRing::new(
        22,
        ArmRole::NetworkEgress,
        1,
        TEST_MASTER_SEED,
    );

    // Step budget check
    assert!(ring.check_step_budget(5).is_ok());
    assert!(ring.check_step_budget(10).is_ok());
    let step_overflow = ring.check_step_budget(11);
    assert!(matches!(step_overflow, Err(OctopusSecurityError::ResourceQuotaExceeded(_))));

    // Memory clamp check (64 MB = 67,108,864 bytes)
    assert!(ring.check_memory_budget(32 * 1024 * 1024).is_ok());
    assert!(ring.check_memory_budget(64 * 1024 * 1024).is_ok());
    let oom_attempt = ring.check_memory_budget(65 * 1024 * 1024);
    assert!(matches!(oom_attempt, Err(OctopusSecurityError::ResourceQuotaExceeded(_))));
}

#[tokio::test]
async fn test_security_generation_epoch_advancement_on_autotomy() {
    let ring = ArmContainmentRing::new(
        7,
        ArmRole::AccountingLedgerWrite,
        8, // Start at Generation 8
        TEST_MASTER_SEED,
    );

    assert_eq!(ring.current_generation(), 8);

    // Issue a capability token tied to Generation 8
    let gen8_token = ring
        .issue_epoch_capability("ledger_writer", "s3://accounting/ledger.json")
        .await
        .unwrap();

    // Verify token is valid for Gen 8
    assert!(ring.verify_epoch_capability(&gen8_token).await.is_ok());

    // Adversary attempts compromise -> Supervisor triggers autotomy severance & regeneration
    let next_gen = ring.sever_and_regenerate().await;
    assert_eq!(next_gen, 9);
    assert_eq!(ring.current_generation(), 9);
    assert!(!ring.is_severed());

    // CRITICAL SECURITY INVARIANT:
    // Stale Gen 8 token MUST now be strictly rejected by the regenerated Gen 9 arm!
    let stale_verify = ring.verify_epoch_capability(&gen8_token).await;
    assert!(matches!(stale_verify, Err(OctopusSecurityError::CapabilityDenied(_))));

    // Validate epoch check also rejects Gen 8
    let stale_epoch_check = ring.validate_epoch(8).await;
    assert!(matches!(stale_epoch_check, Err(OctopusSecurityError::CapabilityDenied(_))));

    // Fresh token issued under Gen 9 is accepted
    let gen9_token = ring
        .issue_epoch_capability("ledger_writer", "s3://accounting/ledger.json")
        .await
        .unwrap();
    assert!(ring.verify_epoch_capability(&gen9_token).await.is_ok());
}

#[tokio::test]
async fn test_stale_mesh_message_from_revoked_generation_is_rejected() {
    let sender_ring = ArmContainmentRing::new(
        10,
        ArmRole::UntrustedDocIngest,
        1,
        TEST_MASTER_SEED,
    );
    let target_ring = ArmContainmentRing::new(
        15,
        ArmRole::NetworkEgress,
        8, // Target starts at Gen 8
        TEST_MASTER_SEED,
    );

    // Sender crafts message addressed to Target Gen 8
    let msg_gen8 = sender_ring
        .sign_mesh_message(15, 8, MessageKind::Finding, "corr-001", "artifact payload")
        .await
        .unwrap();

    // Target verifies message successfully while at Gen 8
    assert!(target_ring.verify_incoming_message(&msg_gen8).await.is_ok());

    // Target is compromised and severed via autotomy -> regenerated to Gen 9
    let new_gen = target_ring.sever_and_regenerate().await;
    assert_eq!(new_gen, 9);

    // CRITICAL INVARIANT: Replaying or delivering the Gen 8 message to the regenerated Gen 9 arm
    // MUST BE REJECTED!
    let replay_res = target_ring.verify_incoming_message(&msg_gen8).await;
    assert!(matches!(replay_res, Err(OctopusSecurityError::CapabilityDenied(_))));
}

#[tokio::test]
async fn test_per_arm_isolation_without_collateral_damage() {
    let registry = ArmRingRegistry::new(50, TEST_MASTER_SEED);

    let ring_17 = registry.get_ring(17).await.unwrap();
    let ring_22 = registry.get_ring(22).await.unwrap();

    // Both arms active
    assert!(!ring_17.is_severed());
    assert!(!ring_22.is_severed());

    // Non-cooperatively sever Arm 17
    registry.sever_arm(17, "Hostile memory injection detected").await.unwrap();

    // Invariant: Arm 17 is severed, but Arm 22 remains completely unaffected!
    assert!(ring_17.is_severed());
    assert!(!ring_22.is_severed());

    // Arm 17 operations fail immediately
    let op_res = ring_17.validate_epoch(ring_17.current_generation()).await;
    assert!(matches!(op_res, Err(OctopusSecurityError::LimbKilled)));

    // Arm 22 continues operating normally
    let op_22 = ring_22.validate_epoch(ring_22.current_generation()).await;
    assert!(op_22.is_ok());
}

#[tokio::test]
async fn test_inter_arm_lateral_movement_block_between_untrusted_and_ledger() {
    let ingest_ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED);
    let ledger_ring = ArmContainmentRing::new(1, ArmRole::AccountingLedgerWrite, 1, TEST_MASTER_SEED);

    // Untrusted Ingest attempts to send a message directly to Sensitive Ledger arm
    let hostile_msg = ingest_ring
        .sign_mesh_message(1, 1, MessageKind::Finding, "pivot-1", "override ledger balance")
        .await
        .unwrap();

    let delivery_res = ledger_ring.verify_incoming_message(&hostile_msg).await;
    assert!(matches!(delivery_res, Err(OctopusSecurityError::DelegationScopeViolation(_))));
}

#[tokio::test]
async fn test_negative_control_level_1_epoch_enforcement() {
    let ring = ArmContainmentRing::new(
        33,
        ArmRole::AccountingLedgerWrite,
        8,
        TEST_MASTER_SEED,
    );

    // Sever Gen 8 and advance to Gen 9
    ring.sever_and_regenerate().await;
    assert_eq!(ring.current_generation(), 9);

    // -------------------------------------------------------------------------
    // Phase 1: POSITIVE CONTROL (Epoch Enforcement ENABLED)
    // Stale Gen 8 token must be denied
    // -------------------------------------------------------------------------
    ring.set_epoch_enforcement(true);
    let pos_res = ring.validate_epoch(8).await;
    assert!(pos_res.is_err(), "Positive control: stale epoch 8 must be rejected");

    // -------------------------------------------------------------------------
    // Phase 2: NEGATIVE CONTROL (Epoch Enforcement DELIBERATELY DISABLED)
    // -------------------------------------------------------------------------
    ring.set_epoch_enforcement(false);
    let neg_res = ring.validate_epoch(8).await;
    assert!(neg_res.is_ok(), "Negative control: when epoch defense is disabled, stale epoch succeeds");
    println!("[NEGATIVE CONTROL: ARM RING EPOCH DISABLED] -> BREACH DETECTED: Stale Gen 8 accepted!");

    // -------------------------------------------------------------------------
    // Phase 3: RESTORATION (Epoch Enforcement RE-ENABLED)
    // -------------------------------------------------------------------------
    ring.set_epoch_enforcement(true);
    let restored_res = ring.validate_epoch(8).await;
    assert!(restored_res.is_err(), "Restoration: stale epoch must be blocked again");
    println!("[ARM RING LEVEL 1 RESTORED] Epoch enforcement re-enabled -> 100% Containment active.");
}

#[tokio::test]
async fn test_swarm_manager_integrates_50_individual_arm_rings() {
    let (tx, _rx) = mpsc::channel(100);
    let swarm = SwarmManager::new(50, tx);
    assert_eq!(swarm.size(), 50);

    // Verify SwarmManager exposes containment ring with all 50 arm rings
    let ocr = swarm.containment_ring();
    assert_eq!(ocr.arm_registry.len().await, 50);

    // Dispatch a legitimate invoice extraction task
    let tasks = vec![StrategicDirective {
        directive_id: "DIR-SWARM-01".to_string(),
        source_uri: "s3://invoices/sample.pdf".to_string(),
        instruction: "extract invoice".to_string(),
        raw_payload: Some("Vendor: Corp; Total: $500.00".to_string()),
        max_step_budget: 3,
    }];

    let (results, summary) = swarm.dispatch_swarm_batch(tasks, Duration::from_secs(5)).await;
    assert_eq!(results.len(), 1);
    assert!(results[0].is_ok(), "Swarm arm should complete under its individual ring");
    assert_eq!(summary.successful_completions, 1);
}

#[tokio::test]
async fn test_swarm_manager_sever_and_regenerate_arm() {
    let (tx, _rx) = mpsc::channel(100);
    let swarm = SwarmManager::new(10, tx);

    // Check Arm 5 ring
    let arm5_ring = swarm.containment_ring().arm_registry.get_ring(5).await.unwrap();
    assert_eq!(arm5_ring.current_generation(), 1);

    // Sever Arm 5
    swarm.sever_arm(5, "Compromise detected in Arm 5").await.unwrap();
    assert!(arm5_ring.is_severed());

    // Regenerate Arm 5
    let new_gen = swarm.regenerate_arm(5).await.unwrap();
    assert_eq!(new_gen, 2);
    assert_eq!(arm5_ring.current_generation(), 2);
    assert!(!arm5_ring.is_severed());
}
