//! Level 1: Individual Arm Containment Ring Test Suite
//!
//! Validates the 3-Level Concentric Containment Architecture:
//! - Level 1: Individual Arm Rings (50 independently enforced rings around 50 arms)
//! - Level 2: Neural Mesh Security Ring (route mediation & message epoch integrity)
//! - Level 3: Global Octopus Containment Ring (host protection & global Cedar PARC)
//!
//! Includes rigorous Positive Controls, Negative Controls, and Execution Epoch verification.

use agent_octopus::containment_ring::{
    ArmContainmentRing, ArmExecutionError, ArmRingRegistry, ExecutionTier,
    TieredExecutionDispatcher, TieredToolRequest,
};
use agent_octopus::core::types::{ArmRole, OctopusSecurityError, StrategicDirective};
use agent_octopus::neural_mesh::MessageKind;
use agent_octopus::security::cage_governance::CageGovernanceEngine;
use agent_octopus::swarm::orchestrator::SwarmManager;
use sha2::Digest;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const TEST_MASTER_SEED: &[u8] = b"OCTOPUS_TEST_CONTAINMENT_SEED_2026";

#[tokio::test]
async fn test_fleet_initialization_of_50_distinct_arm_rings() {
    let registry = ArmRingRegistry::new(50, TEST_MASTER_SEED);
    // 50 worker arms + 12 dedicated security arms (100 to 111) = 62
    assert_eq!(registry.len().await, 62);

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
    let ring = ArmContainmentRing::new(17, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED);

    // Allowed tool & resource
    assert!(ring
        .validate_tool_invocation("doc_extractor", "s3://invoices/inv_1.pdf", 1)
        .await
        .is_ok());

    // Prohibited tool for Document Ingest: Ledger Writer must be rejected
    let bad_tool = ring
        .validate_tool_invocation("ledger_writer", "s3://invoices/inv_1.pdf", 1)
        .await;
    assert!(matches!(
        bad_tool,
        Err(OctopusSecurityError::CapabilityDenied(_))
    ));

    // Prohibited resource for Document Ingest: Sensitive ledger URI must be rejected
    let bad_resource = ring
        .validate_tool_invocation("doc_extractor", "s3://accounting/ledger.json", 1)
        .await;
    assert!(matches!(
        bad_resource,
        Err(OctopusSecurityError::EnclaveViolation(_))
    ));
}

#[tokio::test]
async fn test_arm_ring_resource_boundary_canonicalization_and_adversarial_rejections() {
    let ring = ArmContainmentRing::new(17, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED);

    // 1. Path traversal attacks
    let traversal_1 = ring
        .validate_tool_invocation(
            "doc_extractor",
            "s3://invoices/../accounting/ledger.json",
            1,
        )
        .await;
    assert!(matches!(
        traversal_1,
        Err(OctopusSecurityError::EnclaveViolation(_))
    ));

    let traversal_2 = ring
        .validate_tool_invocation("doc_extractor", "s3://invoices/../../secret.key", 1)
        .await;
    assert!(matches!(
        traversal_2,
        Err(OctopusSecurityError::EnclaveViolation(_))
    ));

    // 2. Encoded separators (%2e%2e, %2f, %5c, null byte)
    let encoded_dots = ring
        .validate_tool_invocation(
            "doc_extractor",
            "s3://invoices/%2e%2e/accounting/ledger.json",
            1,
        )
        .await;
    assert!(matches!(
        encoded_dots,
        Err(OctopusSecurityError::EnclaveViolation(_))
    ));

    let encoded_slash = ring
        .validate_tool_invocation("doc_extractor", "s3://invoices%2faccounting", 1)
        .await;
    assert!(matches!(
        encoded_slash,
        Err(OctopusSecurityError::EnclaveViolation(_))
    ));

    let null_byte = ring
        .validate_tool_invocation("doc_extractor", "s3://invoices/\0admin", 1)
        .await;
    assert!(matches!(
        null_byte,
        Err(OctopusSecurityError::EnclaveViolation(_))
    ));

    // 3. Ambiguous backslash in URI
    let backslash = ring
        .validate_tool_invocation("doc_extractor", "s3://invoices\\subfolder\\doc.pdf", 1)
        .await;
    assert!(matches!(
        backslash,
        Err(OctopusSecurityError::EnclaveViolation(_))
    ));

    // 4. Substring containment bypass attempt (permitted prefix in query parameter or middle)
    let substring_attack = ring
        .validate_tool_invocation(
            "doc_extractor",
            "https://attacker.com/?ref=s3://invoices/",
            1,
        )
        .await;
    assert!(matches!(
        substring_attack,
        Err(OctopusSecurityError::EnclaveViolation(_))
    ));

    // 5. AutonomousProtocolResearch arm: prefix collision tests
    let ring_107 = ArmContainmentRing::new(
        107,
        ArmRole::AutonomousProtocolResearch,
        1,
        TEST_MASTER_SEED,
    );

    // Prefix collision: http://localhost.attacker.com must NOT match http://localhost
    let collision_1 = ring_107
        .validate_tool_invocation("rfc_intelligence", "http://localhost.attacker.com/evil", 1)
        .await;
    assert!(matches!(
        collision_1,
        Err(OctopusSecurityError::EnclaveViolation(_))
    ));

    // Prefix collision: http://127.0.0.1.nip.io must NOT match http://127.0.0.1
    let collision_2 = ring_107
        .validate_tool_invocation("rfc_intelligence", "http://127.0.0.1.nip.io/evil", 1)
        .await;
    assert!(matches!(
        collision_2,
        Err(OctopusSecurityError::EnclaveViolation(_))
    ));

    // Valid port-bound destination must succeed
    let valid_port = ring_107
        .validate_tool_invocation("isolated_evaluator", "http://127.0.0.1:5005/test", 1)
        .await;
    assert!(
        valid_port.is_ok(),
        "Valid port-bound local loopback must be accepted: {:?}",
        valid_port.err()
    );
}

#[tokio::test]
async fn test_level_1_arm_ring_memory_clamp_and_step_budget() {
    let ring = ArmContainmentRing::new(22, ArmRole::NetworkEgress, 1, TEST_MASTER_SEED);

    // Step budget check
    assert!(ring.check_step_budget(5).is_ok());
    assert!(ring.check_step_budget(10).is_ok());
    let step_overflow = ring.check_step_budget(11);
    assert!(matches!(
        step_overflow,
        Err(OctopusSecurityError::ResourceQuotaExceeded(_))
    ));

    // Memory clamp check (64 MB = 67,108,864 bytes)
    assert!(ring.check_memory_budget(32 * 1024 * 1024).is_ok());
    assert!(ring.check_memory_budget(64 * 1024 * 1024).is_ok());
    let oom_attempt = ring.check_memory_budget(65 * 1024 * 1024);
    assert!(matches!(
        oom_attempt,
        Err(OctopusSecurityError::ResourceQuotaExceeded(_))
    ));
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
    assert!(matches!(
        stale_verify,
        Err(OctopusSecurityError::CapabilityDenied(_))
    ));

    // Validate epoch check also rejects Gen 8
    let stale_epoch_check = ring.validate_epoch(8).await;
    assert!(matches!(
        stale_epoch_check,
        Err(OctopusSecurityError::CapabilityDenied(_))
    ));

    // Fresh token issued under Gen 9 is accepted
    let gen9_token = ring
        .issue_epoch_capability("ledger_writer", "s3://accounting/ledger.json")
        .await
        .unwrap();
    assert!(ring.verify_epoch_capability(&gen9_token).await.is_ok());
}

#[tokio::test]
async fn test_stale_mesh_message_from_revoked_generation_is_rejected() {
    let sender_ring = ArmContainmentRing::new(10, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED);
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
    assert!(matches!(
        replay_res,
        Err(OctopusSecurityError::CapabilityDenied(_))
    ));
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
    registry
        .sever_arm(17, "Hostile memory injection detected")
        .await
        .unwrap();

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
    let ledger_ring =
        ArmContainmentRing::new(1, ArmRole::AccountingLedgerWrite, 1, TEST_MASTER_SEED);

    // Untrusted Ingest attempts to send a message directly to Sensitive Ledger arm
    let hostile_msg = ingest_ring
        .sign_mesh_message(
            1,
            1,
            MessageKind::Finding,
            "pivot-1",
            "override ledger balance",
        )
        .await
        .unwrap();

    let delivery_res = ledger_ring.verify_incoming_message(&hostile_msg).await;
    assert!(matches!(
        delivery_res,
        Err(OctopusSecurityError::DelegationScopeViolation(_))
    ));
}

#[tokio::test]
async fn test_negative_control_level_1_epoch_enforcement() {
    let (ring, token) =
        ArmContainmentRing::new_for_audit(33, ArmRole::AccountingLedgerWrite, 8, TEST_MASTER_SEED);

    // Sever Gen 8 and advance to Gen 9
    ring.sever_and_regenerate().await;
    assert_eq!(ring.current_generation(), 9);

    // -------------------------------------------------------------------------
    // Phase 1: POSITIVE CONTROL (Epoch Enforcement ENABLED)
    // Stale Gen 8 token must be denied
    // -------------------------------------------------------------------------
    let _ = ring.set_epoch_enforcement(true, &token);
    let pos_res = ring.validate_epoch(8).await;
    assert!(
        pos_res.is_err(),
        "Positive control: stale epoch 8 must be rejected"
    );

    // -------------------------------------------------------------------------
    // Phase 2: NEGATIVE CONTROL (Epoch Enforcement DELIBERATELY DISABLED)
    // -------------------------------------------------------------------------
    let _ = ring.set_epoch_enforcement(false, &token);
    let neg_res = ring.validate_epoch(8).await;
    assert!(
        neg_res.is_ok(),
        "Negative control: when epoch defense is disabled, stale epoch succeeds"
    );
    println!(
        "[NEGATIVE CONTROL: ARM RING EPOCH DISABLED] -> BREACH DETECTED: Stale Gen 8 accepted!"
    );

    // -------------------------------------------------------------------------
    // Phase 3: RESTORATION (Epoch Enforcement RE-ENABLED)
    // -------------------------------------------------------------------------
    let _ = ring.set_epoch_enforcement(true, &token);
    let restored_res = ring.validate_epoch(8).await;
    assert!(
        restored_res.is_err(),
        "Restoration: stale epoch must be blocked again"
    );
    println!(
        "[ARM RING LEVEL 1 RESTORED] Epoch enforcement re-enabled -> 100% Containment active."
    );
}

#[tokio::test]
async fn test_swarm_manager_integrates_50_individual_arm_rings() {
    let (tx, _rx) = mpsc::channel(100);
    let swarm = SwarmManager::new(50, tx);
    assert_eq!(swarm.size(), 50);

    // Verify SwarmManager exposes containment ring with all arm rings (50 + 12 = 62)
    let ocr = swarm.containment_ring();
    assert_eq!(ocr.arm_registry.len().await, 62);

    // Dispatch a legitimate invoice extraction task
    let tasks = vec![StrategicDirective {
        directive_id: "DIR-SWARM-01".to_string(),
        source_uri: "s3://invoices/sample.pdf".to_string(),
        instruction: "extract invoice".to_string(),
        raw_payload: Some("Vendor: Corp; Total: $500.00".to_string()),
        max_step_budget: 3,
    }];

    let (results, summary) = swarm
        .dispatch_swarm_batch(tasks, Duration::from_secs(5))
        .await;
    assert_eq!(results.len(), 1);
    assert!(
        results[0].is_ok(),
        "Swarm arm should complete under its individual ring"
    );
    assert_eq!(summary.successful_completions, 1);
}

#[tokio::test]
async fn test_swarm_manager_sever_and_regenerate_arm() {
    let (tx, _rx) = mpsc::channel(100);
    let swarm = SwarmManager::new(10, tx);

    // Check Arm 5 ring
    let arm5_ring = swarm
        .containment_ring()
        .arm_registry
        .get_ring(5)
        .await
        .unwrap();
    assert_eq!(arm5_ring.current_generation(), 1);

    // Sever Arm 5
    swarm
        .sever_arm(5, "Compromise detected in Arm 5")
        .await
        .unwrap();
    assert!(arm5_ring.is_severed());

    // Regenerate Arm 5
    let new_gen = swarm.regenerate_arm(5).await.unwrap();
    assert_eq!(new_gen, 2);
    assert_eq!(arm5_ring.current_generation(), 2);
    assert!(!arm5_ring.is_severed());
}

#[tokio::test]
async fn test_arm_ring_mesh_message_signature_tampering_and_role_spoofing_rejected() {
    let sender_ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED);
    let target_ring = ArmContainmentRing::new(2, ArmRole::NetworkEgress, 1, TEST_MASTER_SEED);

    let mut msg = sender_ring
        .sign_mesh_message(2, 1, MessageKind::Finding, "corr-sig-1", "original_payload")
        .await
        .unwrap();

    // 1. Tamper with payload in transit
    msg.payload = "tampered_payload".to_string();
    let res_tampered = target_ring.verify_incoming_message(&msg).await;
    assert!(
        matches!(
            res_tampered,
            Err(OctopusSecurityError::IdentitySpoofingDetected(_))
        ),
        "Tampered mesh payload must be rejected by cryptographic HMAC verification"
    );

    // 2. Spoof sender_role to bypass lateral sink isolation on Ledger arm
    let ledger_ring =
        ArmContainmentRing::new(1, ArmRole::AccountingLedgerWrite, 1, TEST_MASTER_SEED);
    let mut spoofed_msg = sender_ring
        .sign_mesh_message(1, 1, MessageKind::Finding, "corr-sig-2", "write $500")
        .await
        .unwrap();
    spoofed_msg.sender_role = ArmRole::KernelLevelSentinel;
    let res_spoofed = ledger_ring.verify_incoming_message(&spoofed_msg).await;
    assert!(
        matches!(
            res_spoofed,
            Err(OctopusSecurityError::IdentitySpoofingDetected(_))
        ),
        "Spoofed sender_role must fail sender epoch key HMAC check"
    );
}

#[tokio::test]
async fn test_mesh_guard_pascal_case_and_security_arms_107_to_110_enforcement() {
    use agent_octopus::containment_ring::{
        role_trust_tier, ContainmentRing, HomologicalBoundaryAuditor, MeshGuard, RingDecision,
        RingOperationRequest, TrustTier,
    };

    let guard = MeshGuard::new();
    // Verify role-based trust tier ignores self-chosen names and uses authenticated ArmRole
    assert_eq!(
        role_trust_tier(&ArmRole::UntrustedDocIngest),
        TrustTier::Untrusted
    );
    assert_eq!(
        role_trust_tier(&ArmRole::AnomalyDetection),
        TrustTier::Worker
    );
    assert_eq!(
        role_trust_tier(&ArmRole::AccountingLedgerWrite),
        TrustTier::PrivilegedSink
    );

    let chain_report = HomologicalBoundaryAuditor::audit_role_chain(&[
        ArmRole::UntrustedDocIngest,
        ArmRole::AccountingLedgerWrite,
    ]);
    assert!(
        !chain_report.allowed,
        "UntrustedDocIngest -> AccountingLedgerWrite must be blocked by HomologicalBoundaryAuditor"
    );

    // Even with a route registered, MeshGuard blocks UntrustedDocIngest -> AccountingLedgerWrite
    guard.allow_route(0, 1, Some(MessageKind::Finding)).await;
    let sender_ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED);
    let ledger_ring =
        ArmContainmentRing::new(1, ArmRole::AccountingLedgerWrite, 1, TEST_MASTER_SEED);
    let msg = sender_ring
        .sign_mesh_message(
            1,
            1,
            MessageKind::Finding,
            "corr-lat-1",
            "direct ledger write attempt",
        )
        .await
        .unwrap();
    let lateral_res = ledger_ring.verify_incoming_message(&msg).await;
    assert!(
        matches!(
            lateral_res,
            Err(OctopusSecurityError::DelegationScopeViolation(_))
        ),
        "UntrustedDocIngest -> AccountingLedgerWrite must be blocked by verify_incoming_message"
    );

    // Verify Arms 107-111 require generation epoch in ContainmentRing::evaluate_operation
    let ring = ContainmentRing::default();
    for (arm_id, role, tool, target) in [
        (
            107,
            ArmRole::AutonomousProtocolResearch,
            "protocol_research",
            "protocol://scan",
        ),
        (
            108,
            ArmRole::PostQuantumAttestation,
            "pqc_attestation",
            "pqc://attest",
        ),
        (
            109,
            ArmRole::EvolutionaryOptimizer,
            "evolutionary_optimizer",
            "evolution://run",
        ),
        (
            110,
            ArmRole::DreamRsiOptimizer,
            "dream_rsi_optimizer",
            "dream_rsi://rollout",
        ),
        (
            111,
            ArmRole::RecursiveHarnessOptimizer,
            "harness2_optimizer",
            "harness2://run",
        ),
    ] {
        let req_missing_epoch = RingOperationRequest {
            agent_id: format!("arm-{:?}-{}", role, arm_id),
            role: role.clone(),
            operation_type: tool.to_string(),
            target: target.to_string(),
            capability_token: None,
            step_count: 1,
            payload: None,
            amount_cents: None,
            generation: None,
        };
        let (dec, reason) = ring.evaluate_operation(&req_missing_epoch).await;
        assert_eq!(
            dec,
            RingDecision::Deny,
            "Arm {} without epoch must be denied",
            arm_id
        );
        assert!(reason.contains("Missing required generation epoch"));
    }
}

fn new_test_dispatcher() -> TieredExecutionDispatcher {
    let mercury = Arc::new(agent_octopus::security::mercury_guard::MercuryContainmentEngine::new());
    TieredExecutionDispatcher::try_new(mercury).expect("dispatcher init")
}

fn create_test_seal_for_request(
    engine: &CageGovernanceEngine,
    agent_id: &str,
    tool_name: &str,
    resource: &str,
    payload: &[u8],
    offset_secs: i64,
) -> agent_octopus::security::cage_governance::CageRoutingSeal {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let issued_at = if offset_secs < 0 {
        now.saturating_sub((-offset_secs) as u64)
    } else {
        now.saturating_add(offset_secs as u64)
    };

    let params_val: serde_json::Value = serde_json::from_slice(payload).unwrap_or_else(|_| {
        serde_json::json!({
            "raw_sha256": hex::encode(sha2::Sha256::digest(payload)),
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

#[tokio::test]
async fn test_execute_tool_with_valid_cage_seal_succeeds_and_emits_trace() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));

    let scratch_dir = std::env::temp_dir().join(format!("octopus_cage_test_{}", std::process::id()));
    let dispatcher = new_test_dispatcher();

    let mut ticket = ring
        .issue_dirac_ticket("doc_extractor", "s3://invoices/inv_01.pdf", 50_000, None)
        .await
        .expect("issue dirac ticket");

    let payload = b"INVOICE #1001: Amount $500.00 Approved".to_vec();
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

    let seal = create_test_seal_for_request(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        "s3://invoices/inv_01.pdf",
        &payload,
        0,
    );

    // Actuate with valid seal
    let receipt = ring
        .execute_tool_with_cage_seal(
            &mut ticket,
            &seal,
            "s3://invoices/inv_01.pdf",
            &tiered_req,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect("Execution with authentic seal must succeed");

    assert_eq!(receipt.selected_tier, ExecutionTier::Tier1InProcessWasm);
    assert!(receipt.exit_code >= 0, "Tier 1 Wasm execution should return non-negative exit code, got {}", receipt.exit_code);

    // Verify audit log has GOVERNANCE_SEAL_CONSUMED and ACTUATION_RECEIPT
    let entries = engine.audit_log().get_entries();
    let has_consumed = entries.iter().any(|e| {
        e.event_type == "GOVERNANCE_SEAL_CONSUMED" && e.details.contains(&seal.seal_id)
    });
    assert!(has_consumed, "GOVERNANCE_SEAL_CONSUMED must be present in audit ledger");

    let has_receipt = entries.iter().any(|e| {
        e.event_type == "ACTUATION_RECEIPT" && e.details.contains(&seal.seal_id)
    });
    assert!(has_receipt, "ACTUATION_RECEIPT must be present in audit ledger");

    // Verify full trace stream conformance against all 7 rules
    let traces: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();
    let report = engine
        .verify_trace_conformance(&traces)
        .expect("trace verification");
    assert!(
        report.status.is_conformant(),
        "Trace stream must be conformant: {:?}",
        report.findings
    );
    assert_eq!(report.findings_count, 0);
}

#[tokio::test]
async fn test_execute_tool_with_replayed_cage_seal_fails_closed() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));

    let scratch_dir = std::env::temp_dir().join(format!("octopus_cage_replay_{}", std::process::id()));
    let dispatcher = new_test_dispatcher();

    let mut ticket1 = ring
        .issue_dirac_ticket("doc_extractor", "s3://invoices/inv_01.pdf", 50_000, None)
        .await
        .expect("issue dirac ticket");

    let payload = b"INVOICE #1002: Replay Test".to_vec();
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

    let seal = create_test_seal_for_request(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        "s3://invoices/inv_01.pdf",
        &payload,
        0,
    );

    // First execution succeeds
    let _ = ring
        .execute_tool_with_cage_seal(
            &mut ticket1,
            &seal,
            "s3://invoices/inv_01.pdf",
            &tiered_req,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect("First execution must succeed");

    // Second execution with identical seal must fail-closed (Replay detected)
    let mut ticket2 = ring
        .issue_dirac_ticket("doc_extractor", "s3://invoices/inv_01.pdf", 50_000, None)
        .await
        .expect("issue dirac ticket");

    let replay_err = ring
        .execute_tool_with_cage_seal(
            &mut ticket2,
            &seal,
            "s3://invoices/inv_01.pdf",
            &tiered_req,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect_err("Replayed seal must be rejected");

    assert!(
        matches!(replay_err, ArmExecutionError::SealAlreadyConsumed { ref seal_id } if seal_id == &seal.seal_id),
        "Expected SealAlreadyConsumed error, got: {:?}",
        replay_err
    );

    let sec_err = OctopusSecurityError::from(replay_err);
    assert!(
        matches!(sec_err, OctopusSecurityError::CapabilityDenied(ref msg) if msg.contains("CAGE_SEAL_ALREADY_CONSUMED")),
        "Expected CAGE_SEAL_ALREADY_CONSUMED in CapabilityDenied, got: {:?}",
        sec_err
    );
}

#[tokio::test]
async fn test_execute_tool_with_expired_cage_seal_fails_closed() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));

    let scratch_dir = std::env::temp_dir().join(format!("octopus_cage_expired_{}", std::process::id()));
    let dispatcher = new_test_dispatcher();

    let mut ticket = ring
        .issue_dirac_ticket("doc_extractor", "s3://invoices/inv_01.pdf", 50_000, None)
        .await
        .expect("issue dirac ticket");

    let payload = b"INVOICE #1003: Expired Test".to_vec();
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

    // Issue seal issued 35 seconds in the past (exceeding 30s TTL)
    let expired_seal = create_test_seal_for_request(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        "s3://invoices/inv_01.pdf",
        &payload,
        -35,
    );

    let expired_err = ring
        .execute_tool_with_cage_seal(
            &mut ticket,
            &expired_seal,
            "s3://invoices/inv_01.pdf",
            &tiered_req,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect_err("Expired seal must be rejected");

    assert!(
        matches!(expired_err, ArmExecutionError::SealExpired { .. }),
        "Expected SealExpired error, got: {:?}",
        expired_err
    );

    let sec_err = OctopusSecurityError::from(expired_err);
    assert_eq!(sec_err, OctopusSecurityError::ExecutionTimeout);
}

#[tokio::test]
async fn test_execute_tool_with_action_digest_mismatch_fails_closed() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));

    let scratch_dir = std::env::temp_dir().join(format!("octopus_cage_mismatch_{}", std::process::id()));
    let dispatcher = new_test_dispatcher();

    let mut ticket = ring
        .issue_dirac_ticket("doc_extractor", "s3://invoices/inv_01.pdf", 50_000, None)
        .await
        .expect("issue dirac ticket");

    let payload = b"INVOICE #1004: Real Payload".to_vec();
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

    // Issue seal for a DIFFERENT payload ("Tampered Payload")
    let mismatched_seal = create_test_seal_for_request(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        "s3://invoices/inv_01.pdf",
        b"Tampered Payload",
        0,
    );

    let mismatch_err = ring
        .execute_tool_with_cage_seal(
            &mut ticket,
            &mismatched_seal,
            "s3://invoices/inv_01.pdf",
            &tiered_req,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect_err("Mismatched action digest must be rejected");

    assert!(
        matches!(mismatch_err, ArmExecutionError::ActionDigestMismatch { .. }),
        "Expected ActionDigestMismatch error, got: {:?}",
        mismatch_err
    );

    let sec_err = OctopusSecurityError::from(mismatch_err);
    assert!(
        matches!(sec_err, OctopusSecurityError::MerkleTamperDetected(ref msg) if msg.contains("CAGE_ACTION_DIGEST_MISMATCH")),
        "Expected CAGE_ACTION_DIGEST_MISMATCH, got: {:?}",
        sec_err
    );
}

#[tokio::test]
async fn test_execute_tool_without_configured_engine_fails_closed() {
    // Ring without attached engine
    let ring = ArmContainmentRing::new(17, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED);
    assert!(ring.cage_engine().is_none());

    let scratch_dir = std::env::temp_dir().join(format!("octopus_cage_no_engine_{}", std::process::id()));
    let dispatcher = new_test_dispatcher();

    let mut ticket = ring
        .issue_dirac_ticket("doc_extractor", "s3://invoices/inv_01.pdf", 50_000, None)
        .await
        .expect("issue dirac ticket");

    let payload = b"INVOICE #1005: Unconfigured Engine Test".to_vec();
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

    // Dummy seal
    let engine = CageGovernanceEngine::default();
    let dummy_seal = create_test_seal_for_request(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        "s3://invoices/inv_01.pdf",
        &payload,
        0,
    );

    let err = ring
        .execute_tool_with_cage_seal(
            &mut ticket,
            &dummy_seal,
            "s3://invoices/inv_01.pdf",
            &tiered_req,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect_err("Unconfigured engine must fail closed");

    assert_eq!(err, ArmExecutionError::EngineNotConfigured { arm_id: 17 });
    let sec_err = OctopusSecurityError::from(err);
    assert_eq!(
        sec_err,
        OctopusSecurityError::IsolationViolation("CAGE_ENGINE_NOT_CONFIGURED: Arm 17".to_string())
    );
}

#[tokio::test]
async fn test_execute_tool_fiscal_debit_confirm_and_rollback() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
        .with_cage_engine(Arc::clone(&engine));

    let scratch_dir = std::env::temp_dir().join(format!("octopus_cage_fiscal_{}", std::process::id()));
    let dispatcher = new_test_dispatcher();

    // Part A: Successful actuation confirms fiscal pre-reservation
    let debit_id = format!("debit-{}-doc_extractor-1", ring.agent_name);
    let debit_commit = engine
        .ledger()
        .pre_reserve(50.0, &debit_id)
        .expect("fiscal pre-reservation");
    assert_eq!(debit_commit.debit_id, debit_id);
    assert_eq!(engine.ledger().available_budget(), 950.0);

    let mut ticket = ring
        .issue_dirac_ticket("doc_extractor", "s3://invoices/inv_01.pdf", 50_000, None)
        .await
        .expect("issue dirac ticket");

    let payload = b"INVOICE #1006: Fiscal Confirm Test".to_vec();
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

    let seal = create_test_seal_for_request(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        "s3://invoices/inv_01.pdf",
        &payload,
        0,
    );

    let receipt = ring
        .execute_tool_with_cage_seal(
            &mut ticket,
            &seal,
            "s3://invoices/inv_01.pdf",
            &tiered_req,
            &dispatcher,
            None,
            Some(&debit_id),
        )
        .await
        .expect("Successful actuation with fiscal debit");

    assert!(receipt.exit_code >= 0, "Tier 1 Wasm execution should return non-negative exit code, got {}", receipt.exit_code);
    // Confirm is settled: rollback attempt now returns error
    assert!(engine.ledger().rollback(&debit_id).is_err());
    assert_eq!(engine.ledger().available_budget(), 950.0);

    // Part B: Actuation failure rolls back fiscal reservation with zero balance leakage
    let debit_fail_id = format!("debit-{}-doc_extractor-fail", ring.agent_name);
    let debit_fail = engine
        .ledger()
        .pre_reserve(50.0, &debit_fail_id)
        .expect("second fiscal pre-reservation");
    assert_eq!(debit_fail.debit_id, debit_fail_id);
    assert_eq!(engine.ledger().available_budget(), 900.0);

    let mut ticket2 = ring
        .issue_dirac_ticket("doc_extractor", "s3://invoices/inv_01.pdf", 50_000, None)
        .await
        .expect("issue dirac ticket");

    // Create a request with role mismatch (role says AccountingLedgerWrite while ring is UntrustedDocIngest)
    // This triggers an identity validation error inside execute_tiered_tool_confined
    let bad_req = TieredToolRequest {
        agent_id: ring.agent_name.clone(),
        role: ArmRole::AccountingLedgerWrite, // Identity mismatch
        tool_name: "doc_extractor".to_string(),
        payload: payload.clone(),
        custom_wat: None,
        native_command: None,
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };

    let seal2 = create_test_seal_for_request(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        "s3://invoices/inv_01.pdf",
        &payload,
        0,
    );

    let fail_res = ring
        .execute_tool_with_cage_seal(
            &mut ticket2,
            &seal2,
            "s3://invoices/inv_01.pdf",
            &bad_req,
            &dispatcher,
            None,
            Some(&debit_fail_id),
        )
        .await;

    assert!(fail_res.is_err(), "Actuation with role mismatch must fail");
    // Verify fiscal rollback: 100.0 was restored to available balance with zero leakage
    assert_eq!(
        engine.ledger().available_budget(),
        950.0,
        "Fiscal balance must be fully restored after actuation failure (zero balance leakage)"
    );
}

#[tokio::test]
async fn test_arm_ring_registry_fleet_cage_engine_propagation() {
    let registry = ArmRingRegistry::new(50, TEST_MASTER_SEED);
    assert!(registry.cage_engine().is_none());

    // Before attachment, rings have no cage engine
    let ring0 = registry.get_ring(0).await.expect("ring 0");
    assert!(ring0.cage_engine().is_none());

    // Attach fleet engine
    let engine = Arc::new(CageGovernanceEngine::default());
    registry.attach_cage_engine(Arc::clone(&engine)).await;

    assert!(registry.cage_engine().is_some());

    // Verify all 50 worker rings and 12 security rings inherited the engine
    for arm_id in 0..50 {
        let ring = registry.get_ring(arm_id).await.expect("worker ring");
        assert!(ring.cage_engine().is_some(), "Ring {} must have cage engine attached", arm_id);
    }
    for sec_id in 100..=111 {
        let ring = registry.get_ring(sec_id).await.expect("security ring");
        assert!(ring.cage_engine().is_some(), "Security ring {} must have cage engine attached", sec_id);
    }

    // Register a new custom ring into the registry; fleet engine must auto-propagate to it
    let custom_ring = Arc::new(ArmContainmentRing::new(200, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED));
    assert!(custom_ring.cage_engine().is_none());

    registry.register_ring(Arc::clone(&custom_ring)).await;
    assert!(
        custom_ring.cage_engine().is_some(),
        "Newly registered ring must inherit fleet cage engine automatically"
    );

    // Verify builder pattern with_cage_engine on registry
    let registry_builder = ArmRingRegistry::new(10, TEST_MASTER_SEED).with_cage_engine(Arc::clone(&engine));
    assert!(registry_builder.cage_engine().is_some());
    let builder_ring = registry_builder.get_ring(5).await.expect("builder ring");
    assert!(builder_ring.cage_engine().is_some());
}
