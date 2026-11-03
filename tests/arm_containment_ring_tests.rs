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
use agent_octopus::security::cage_governance::{CageGovernanceEngine, FormalBfsModel};
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

    let scratch_dir =
        std::env::temp_dir().join(format!("octopus_cage_test_{}", std::process::id()));
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
    assert!(
        receipt.exit_code >= 0,
        "Tier 1 Wasm execution should return non-negative exit code, got {}",
        receipt.exit_code
    );

    // Verify audit log has GOVERNANCE_SEAL_CONSUMED and ACTUATION_RECEIPT
    let entries = engine.audit_log().get_entries();
    let has_consumed = entries
        .iter()
        .any(|e| e.event_type == "GOVERNANCE_SEAL_CONSUMED" && e.details.contains(&seal.seal_id));
    assert!(
        has_consumed,
        "GOVERNANCE_SEAL_CONSUMED must be present in audit ledger"
    );

    let has_receipt = entries
        .iter()
        .any(|e| e.event_type == "ACTUATION_RECEIPT" && e.details.contains(&seal.seal_id));
    assert!(
        has_receipt,
        "ACTUATION_RECEIPT must be present in audit ledger"
    );

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

    let scratch_dir =
        std::env::temp_dir().join(format!("octopus_cage_replay_{}", std::process::id()));
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

    let scratch_dir =
        std::env::temp_dir().join(format!("octopus_cage_expired_{}", std::process::id()));
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

    let scratch_dir =
        std::env::temp_dir().join(format!("octopus_cage_mismatch_{}", std::process::id()));
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

    let scratch_dir =
        std::env::temp_dir().join(format!("octopus_cage_no_engine_{}", std::process::id()));
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

    let scratch_dir =
        std::env::temp_dir().join(format!("octopus_cage_fiscal_{}", std::process::id()));
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

    assert!(
        receipt.exit_code >= 0,
        "Tier 1 Wasm execution should return non-negative exit code, got {}",
        receipt.exit_code
    );
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
        assert!(
            ring.cage_engine().is_some(),
            "Ring {} must have cage engine attached",
            arm_id
        );
    }
    for sec_id in 100..=111 {
        let ring = registry.get_ring(sec_id).await.expect("security ring");
        assert!(
            ring.cage_engine().is_some(),
            "Security ring {} must have cage engine attached",
            sec_id
        );
    }

    // Register a new custom ring into the registry; fleet engine must auto-propagate to it
    let custom_ring = Arc::new(ArmContainmentRing::new(
        200,
        ArmRole::UntrustedDocIngest,
        1,
        TEST_MASTER_SEED,
    ));
    assert!(custom_ring.cage_engine().is_none());

    registry.register_ring(Arc::clone(&custom_ring)).await;
    assert!(
        custom_ring.cage_engine().is_some(),
        "Newly registered ring must inherit fleet cage engine automatically"
    );

    // Verify builder pattern with_cage_engine on registry
    let registry_builder =
        ArmRingRegistry::new(10, TEST_MASTER_SEED).with_cage_engine(Arc::clone(&engine));
    assert!(registry_builder.cage_engine().is_some());
    let builder_ring = registry_builder.get_ring(5).await.expect("builder ring");
    assert!(builder_ring.cage_engine().is_some());
}

// ==============================================================================
// CHALLENGER SUITE (challenger_m2_2): CONCURRENCY & FLEET-SCALE ADVERSARIAL TESTS
// ==============================================================================

#[tokio::test]
async fn test_challenger_fleet_scale_engine_propagation_and_autotomy_resilience() {
    let registry = ArmRingRegistry::new(50, TEST_MASTER_SEED);
    assert_eq!(registry.len().await, 62);
    assert!(registry.cage_engine().is_none());

    // 1. Initial State: Verify all 50 worker arms and 12 security arms have NO engine
    for arm_id in 0..50 {
        let ring = registry.get_ring(arm_id).await.expect("worker ring exists");
        assert!(
            ring.cage_engine().is_none(),
            "Worker ring {} must initially have no engine",
            arm_id
        );
    }
    for sec_id in 100..=111 {
        let ring = registry
            .get_ring(sec_id)
            .await
            .expect("security ring exists");
        assert!(
            ring.cage_engine().is_none(),
            "Security ring {} must initially have no engine",
            sec_id
        );
    }

    // 2. Attach fleet engine dynamically
    let engine = Arc::new(CageGovernanceEngine::default());
    registry.attach_cage_engine(Arc::clone(&engine)).await;
    assert!(registry.cage_engine().is_some());

    // 3. Verify engine propagation across all 50 worker arms and 12 security arms
    for arm_id in 0..50 {
        let ring = registry.get_ring(arm_id).await.expect("worker ring exists");
        assert!(
            ring.cage_engine().is_some(),
            "Worker ring {} must inherit fleet engine",
            arm_id
        );
    }
    for sec_id in 100..=111 {
        let ring = registry
            .get_ring(sec_id)
            .await
            .expect("security ring exists");
        assert!(
            ring.cage_engine().is_some(),
            "Security ring {} must inherit fleet engine",
            sec_id
        );
    }

    // 4. Verify synchronous fleet propagation on fresh registry
    let reg_sync = ArmRingRegistry::new(50, TEST_MASTER_SEED);
    reg_sync.attach_cage_engine_sync(Arc::clone(&engine));
    assert!(reg_sync.cage_engine().is_some());
    for arm_id in 0..50 {
        let ring = reg_sync.get_ring(arm_id).await.expect("worker ring exists");
        assert!(
            ring.cage_engine().is_some(),
            "Sync attached arm {} must have engine",
            arm_id
        );
    }
    for sec_id in 100..=111 {
        let ring = reg_sync
            .get_ring(sec_id)
            .await
            .expect("security ring exists");
        assert!(
            ring.cage_engine().is_some(),
            "Sync attached sec arm {} must have engine",
            sec_id
        );
    }

    // 5. Autotomy Regeneration & Engine Persistence (Worker Arm 6, UntrustedDocIngest)
    let arm6 = registry.get_ring(6).await.expect("arm 6 exists");
    assert_eq!(arm6.current_generation(), 1);

    // Issue ticket for Gen 1
    let mut ticket_gen1 = arm6
        .issue_dirac_ticket("doc_extractor", "s3://invoices/inv_01.pdf", 50_000, None)
        .await
        .expect("issue dirac ticket");

    // Sever and regenerate arm 6 via registry
    let next_gen = registry
        .sever_and_regenerate(6)
        .await
        .expect("sever and regenerate");
    assert_eq!(next_gen, 2);
    assert_eq!(arm6.current_generation(), 2);

    // Assert engine is retained across autotomy epoch bump
    assert!(
        arm6.cage_engine().is_some(),
        "Engine must persist after autotomy regeneration"
    );

    // Old ticket carried Gen 1 epoch; validate_epoch(1) must fail closed
    assert!(
        arm6.validate_epoch(1).await.is_err(),
        "Revoked Gen 1 epoch must fail validation"
    );

    let dispatcher = new_test_dispatcher();
    let scratch_dir = std::env::temp_dir().join(format!(
        "octopus_challenger_autotomy_{}",
        std::process::id()
    ));
    let payload = b"AUTOTOMY STALE TICKET".to_vec();
    let tiered_req = TieredToolRequest {
        agent_id: arm6.agent_name.clone(),
        role: arm6.role.clone(),
        tool_name: "doc_extractor".to_string(),
        payload: payload.clone(),
        custom_wat: None,
        native_command: None,
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };
    let seal_gen1 = create_test_seal_for_request(
        &engine,
        &arm6.agent_name,
        "doc_extractor",
        "s3://invoices/inv_01.pdf",
        &payload,
        0,
    );

    // Attempting execution with stale Gen 1 ticket on Gen 2 arm must fail closed
    let stale_err = arm6
        .execute_tool_with_cage_seal(
            &mut ticket_gen1,
            &seal_gen1,
            "s3://invoices/inv_01.pdf",
            &tiered_req,
            &dispatcher,
            None,
            None,
        )
        .await;
    assert!(
        stale_err.is_err(),
        "Execution with stale Gen 1 ticket must fail closed on regenerated arm"
    );

    // Fresh ticket issued for Gen 2 succeeds
    let mut ticket_gen2 = arm6
        .issue_dirac_ticket("doc_extractor", "s3://invoices/inv_01.pdf", 50_000, None)
        .await
        .expect("issue fresh dirac ticket for gen 2");
    let payload_fresh = b"AUTOTOMY FRESH TICKET SUCCESS".to_vec();
    let tiered_req_fresh = TieredToolRequest {
        agent_id: arm6.agent_name.clone(),
        role: arm6.role.clone(),
        tool_name: "doc_extractor".to_string(),
        payload: payload_fresh.clone(),
        custom_wat: None,
        native_command: None,
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };
    let seal_gen2 = create_test_seal_for_request(
        &engine,
        &arm6.agent_name,
        "doc_extractor",
        "s3://invoices/inv_01.pdf",
        &payload_fresh,
        0,
    );
    let receipt_fresh = arm6
        .execute_tool_with_cage_seal(
            &mut ticket_gen2,
            &seal_gen2,
            "s3://invoices/inv_01.pdf",
            &tiered_req_fresh,
            &dispatcher,
            None,
            None,
        )
        .await
        .expect("Execution on regenerated arm with fresh Gen 2 ticket must succeed");
    assert!(receipt_fresh.exit_code >= 0);
}

#[tokio::test]
async fn test_challenger_concurrent_tool_execution_with_distinct_seals() {
    let registry = ArmRingRegistry::new(50, TEST_MASTER_SEED);
    let engine = Arc::new(CageGovernanceEngine::default());
    registry.attach_cage_engine(Arc::clone(&engine)).await;

    // Use 15 distinct UntrustedDocIngest arms: arm_ids = i * 3 for i in 0..15 (0, 3, 6, ..., 42)
    let num_tasks = 15;
    let mut handles = Vec::new();

    for i in 0..num_tasks {
        let arm_id = i * 3;
        let ring = registry.get_ring(arm_id).await.expect("ring must exist");
        let engine_clone = Arc::clone(&engine);

        let handle = tokio::spawn(async move {
            let dispatcher = new_test_dispatcher();
            let scratch_dir = std::env::temp_dir().join(format!(
                "octopus_challenger_concurrency_{}_{}",
                std::process::id(),
                i
            ));
            let payload = format!("CONCURRENT_INVOICE_DATA_TASK_{}", i).into_bytes();

            let mut ticket = ring
                .issue_dirac_ticket("doc_extractor", "s3://invoices/inv_01.pdf", 50_000, None)
                .await
                .expect("issue dirac ticket");

            let seal = create_test_seal_for_request(
                &engine_clone,
                &ring.agent_name,
                "doc_extractor",
                "s3://invoices/inv_01.pdf",
                &payload,
                0,
            );

            let tiered_req = TieredToolRequest {
                agent_id: ring.agent_name.clone(),
                role: ring.role.clone(),
                tool_name: "doc_extractor".to_string(),
                payload: payload.clone(),
                custom_wat: None,
                native_command: None,
                scratchpad_root: scratch_dir,
                allow_scratch_write: false,
            };

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
                .expect("concurrent tool execution must succeed");

            (i, ring.arm_id, seal, receipt)
        });

        handles.push(handle);
    }

    let mut completed_seals = Vec::new();
    for handle in handles {
        let (task_idx, arm_id, seal, receipt) = handle.await.expect("task must join");
        assert_eq!(receipt.selected_tier, ExecutionTier::Tier1InProcessWasm);
        assert!(
            receipt.exit_code >= 0,
            "Task {} on Arm {} failed with exit_code {}",
            task_idx,
            arm_id,
            receipt.exit_code
        );
        completed_seals.push(seal);
    }

    assert_eq!(completed_seals.len(), num_tasks);

    // Verify all 15 seals are marked consumed and authentic replay attempts fail closed with SealAlreadyConsumed
    let arm0 = registry.get_ring(0).await.expect("arm 0 exists");
    let dispatcher = new_test_dispatcher();
    let scratch_dir = std::env::temp_dir().join(format!(
        "octopus_challenger_replay_check_{}",
        std::process::id()
    ));

    for seal in &completed_seals {
        let mut ticket = arm0
            .issue_dirac_ticket("doc_extractor", "s3://invoices/inv_01.pdf", 50_000, None)
            .await
            .expect("issue ticket");

        let payload = format!("CONCURRENT_INVOICE_DATA_TASK_0").into_bytes();
        let tiered_req = TieredToolRequest {
            agent_id: arm0.agent_name.clone(),
            role: arm0.role.clone(),
            tool_name: "doc_extractor".to_string(),
            payload,
            custom_wat: None,
            native_command: None,
            scratchpad_root: scratch_dir.clone(),
            allow_scratch_write: false,
        };

        let replay_res = arm0
            .execute_tool_with_cage_seal(
                &mut ticket,
                seal,
                "s3://invoices/inv_01.pdf",
                &tiered_req,
                &dispatcher,
                None,
                None,
            )
            .await;

        assert!(
            replay_res.is_err(),
            "Replaying seal {} must fail closed",
            seal.seal_id
        );
    }
}

#[tokio::test]
async fn test_challenger_concurrent_race_condition_on_single_seal() {
    let engine = Arc::new(CageGovernanceEngine::default());
    let ring = Arc::new(
        ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED)
            .with_cage_engine(Arc::clone(&engine)),
    );

    let payload = b"RACE CONDITION SEAL TEST".to_vec();
    let seal = Arc::new(create_test_seal_for_request(
        &engine,
        &ring.agent_name,
        "doc_extractor",
        "s3://invoices/inv_01.pdf",
        &payload,
        0,
    ));

    let num_competing_tasks = 10;
    let mut handles = Vec::new();

    for i in 0..num_competing_tasks {
        let ring_clone = Arc::clone(&ring);
        let seal_clone = Arc::clone(&seal);
        let payload_clone = payload.clone();

        let handle = tokio::spawn(async move {
            let dispatcher = new_test_dispatcher();
            let scratch_dir = std::env::temp_dir().join(format!(
                "octopus_challenger_race_{}_{}",
                std::process::id(),
                i
            ));

            let mut ticket = ring_clone
                .issue_dirac_ticket("doc_extractor", "s3://invoices/inv_01.pdf", 50_000, None)
                .await
                .expect("issue dirac ticket");

            let tiered_req = TieredToolRequest {
                agent_id: ring_clone.agent_name.clone(),
                role: ring_clone.role.clone(),
                tool_name: "doc_extractor".to_string(),
                payload: payload_clone,
                custom_wat: None,
                native_command: None,
                scratchpad_root: scratch_dir,
                allow_scratch_write: false,
            };

            ring_clone
                .execute_tool_with_cage_seal(
                    &mut ticket,
                    &seal_clone,
                    "s3://invoices/inv_01.pdf",
                    &tiered_req,
                    &dispatcher,
                    None,
                    None,
                )
                .await
        });

        handles.push(handle);
    }

    let mut success_count = 0;
    let mut failure_count = 0;

    for handle in handles {
        let result = handle.await.expect("task join");
        match result {
            Ok(receipt) => {
                success_count += 1;
                assert!(receipt.exit_code >= 0);
            }
            Err(e) => {
                failure_count += 1;
                assert!(
                    matches!(e, ArmExecutionError::SealAlreadyConsumed { .. }),
                    "Failure must be SealAlreadyConsumed, got: {:?}",
                    e
                );
            }
        }
    }

    // Invariant: Exactly 1 wins the race; exactly N-1 are rejected
    assert_eq!(
        success_count, 1,
        "Exactly one concurrent execution must succeed with a single-use seal"
    );
    assert_eq!(
        failure_count,
        num_competing_tasks - 1,
        "All other concurrent executions must fail closed"
    );

    // Audit log must contain exactly 1 GOVERNANCE_SEAL_CONSUMED and exactly 1 ACTUATION_RECEIPT for this seal
    let entries = engine.audit_log().get_entries();
    let consumed_events = entries
        .iter()
        .filter(|e| e.event_type == "GOVERNANCE_SEAL_CONSUMED" && e.details.contains(&seal.seal_id))
        .count();
    let receipt_events = entries
        .iter()
        .filter(|e| e.event_type == "ACTUATION_RECEIPT" && e.details.contains(&seal.seal_id))
        .count();

    assert_eq!(
        consumed_events, 1,
        "Audit log must contain exactly 1 seal consumption event"
    );
    assert_eq!(
        receipt_events, 1,
        "Audit log must contain exactly 1 actuation receipt event"
    );
}

#[tokio::test]
async fn test_challenger_unconfigured_engine_strict_fail_closed() {
    let test_roles = [
        (
            10,
            ArmRole::UntrustedDocIngest,
            "doc_extractor",
            "s3://invoices/inv_01.pdf",
        ),
        (
            11,
            ArmRole::AccountingLedgerWrite,
            "ledger_writer",
            "s3://accounting/ledger.json",
        ),
        (
            12,
            ArmRole::NetworkEgress,
            "http_egress",
            "https://api.example.com/v1",
        ),
    ];

    let dispatcher = new_test_dispatcher();
    let dummy_engine = CageGovernanceEngine::default();

    for (arm_id, role, tool, resource) in test_roles {
        let ring = ArmContainmentRing::new(arm_id, role.clone(), 1, TEST_MASTER_SEED);
        assert!(
            ring.cage_engine().is_none(),
            "Unconfigured ring must report cage_engine() == None"
        );

        let mut ticket = ring
            .issue_dirac_ticket(tool, resource, 50_000, None)
            .await
            .expect("issue dirac ticket");

        let payload = format!("UNCONFIGURED_ENGINE_TEST_ARM_{}", arm_id).into_bytes();
        let scratch_dir = std::env::temp_dir().join(format!(
            "octopus_challenger_unconfig_{}_{}",
            std::process::id(),
            arm_id
        ));

        let tiered_req = TieredToolRequest {
            agent_id: ring.agent_name.clone(),
            role,
            tool_name: tool.to_string(),
            payload: payload.clone(),
            custom_wat: None,
            native_command: None,
            scratchpad_root: scratch_dir,
            allow_scratch_write: false,
        };

        let dummy_seal = create_test_seal_for_request(
            &dummy_engine,
            &ring.agent_name,
            tool,
            resource,
            &payload,
            0,
        );

        let err = ring
            .execute_tool_with_cage_seal(
                &mut ticket,
                &dummy_seal,
                resource,
                &tiered_req,
                &dispatcher,
                None,
                None,
            )
            .await
            .expect_err("Execution without configured engine must fail closed");

        assert_eq!(err, ArmExecutionError::EngineNotConfigured { arm_id });
        let sec_err = OctopusSecurityError::from(err);
        assert_eq!(
            sec_err,
            OctopusSecurityError::IsolationViolation(format!(
                "CAGE_ENGINE_NOT_CONFIGURED: Arm {}",
                arm_id
            ))
        );
    }
}

#[tokio::test]
async fn test_challenger_conformance_verification_on_concurrent_trace_stream() {
    let registry = ArmRingRegistry::new(50, TEST_MASTER_SEED);
    let engine = Arc::new(CageGovernanceEngine::default());
    registry.attach_cage_engine(Arc::clone(&engine)).await;

    // Run 10 concurrent executions across 10 arms to produce an interleaved trace stream
    let num_tasks = 10;
    let mut handles = Vec::new();

    for i in 0..num_tasks {
        let arm_id = i * 3;
        let ring = registry.get_ring(arm_id).await.expect("ring exists");
        let engine_clone = Arc::clone(&engine);

        let handle = tokio::spawn(async move {
            let dispatcher = new_test_dispatcher();
            let scratch_dir = std::env::temp_dir().join(format!(
                "octopus_challenger_stream_{}_{}",
                std::process::id(),
                i
            ));
            let payload = format!("STREAM_CONFORMANCE_DATA_{}", i).into_bytes();

            let mut ticket = ring
                .issue_dirac_ticket("doc_extractor", "s3://invoices/inv_01.pdf", 50_000, None)
                .await
                .expect("ticket");

            let seal = create_test_seal_for_request(
                &engine_clone,
                &ring.agent_name,
                "doc_extractor",
                "s3://invoices/inv_01.pdf",
                &payload,
                0,
            );

            let tiered_req = TieredToolRequest {
                agent_id: ring.agent_name.clone(),
                role: ring.role.clone(),
                tool_name: "doc_extractor".to_string(),
                payload,
                custom_wat: None,
                native_command: None,
                scratchpad_root: scratch_dir,
                allow_scratch_write: false,
            };

            ring.execute_tool_with_cage_seal(
                &mut ticket,
                &seal,
                "s3://invoices/inv_01.pdf",
                &tiered_req,
                &dispatcher,
                None,
                None,
            )
            .await
            .expect("execution succeeds");
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("task join");
    }

    // Extract all interleaved audit log entries
    let entries = engine.audit_log().get_entries();
    assert!(
        entries.len() >= num_tasks * 3,
        "Expected at least 3 records per task (decision, consumed, receipt)"
    );

    let traces: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();

    // Verify trace stream conformance via engine facade
    let engine_report = engine
        .verify_trace_conformance(&traces)
        .expect("engine trace verification");
    assert!(
        engine_report.status.is_conformant(),
        "Interleaved concurrent trace stream must be conformant: {:?}",
        engine_report.findings
    );
    assert_eq!(engine_report.findings_count, 0);

    // Verify directly via FormalBfsModel::check_trace_conformance
    let bfs_report = FormalBfsModel::check_trace_conformance(&traces);
    assert!(
        bfs_report.status.is_conformant(),
        "Direct FormalBfsModel check must pass: {:?}",
        bfs_report.findings
    );
    assert_eq!(bfs_report.findings_count, 0);
    assert_eq!(bfs_report.records_checked, entries.len());
    assert_eq!(bfs_report.stream_proof_hash.len(), 64);
}

#[tokio::test]
async fn test_challenger_formal_bfs_trace_conformance_adversarial_oracle() {
    let dummy_engine = CageGovernanceEngine::default();
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, TEST_MASTER_SEED);
    let payload = b"ADVERSARIAL CONFORMANCE ORACLE".to_vec();

    // Build baseline authentic entries
    let valid_seal = create_test_seal_for_request(
        &dummy_engine,
        &ring.agent_name,
        "doc_extractor",
        "s3://invoices/inv_01.pdf",
        &payload,
        0,
    );

    let entries = dummy_engine.audit_log().get_entries();
    let mut baseline_traces: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();

    // Add consumed event
    baseline_traces.push(serde_json::json!({
        "event_type": "GOVERNANCE_SEAL_CONSUMED",
        "seal_id": valid_seal.seal_id,
        "decision_record_hash": valid_seal.record_hash,
        "action_digest": valid_seal.action_digest,
        "policy_version_id": valid_seal.policy_version_id,
        "action": "doc_extractor",
        "arm_id": 0,
        "record_hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    }));

    // Add receipt event
    baseline_traces.push(serde_json::json!({
        "event_type": "ACTUATION_RECEIPT",
        "seal_id": valid_seal.seal_id,
        "action": "doc_extractor",
        "agent_id": ring.agent_name,
        "tool_name": "doc_extractor",
        "selected_tier": "Tier1InProcessWasm",
        "exit_code": 38,
        "total_elapsed_us": 120,
        "record_hash": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
    }));

    // Baseline must pass conformance
    let base_report = FormalBfsModel::check_trace_conformance(&baseline_traces);
    assert!(
        base_report.status.is_conformant(),
        "Baseline traces must be conformant: {:?}",
        base_report.findings
    );

    // 1. Adversarial Test: Rule 1 - Schema Violation (record missing event_type)
    let mut bad_schema_traces = baseline_traces.clone();
    bad_schema_traces.push(serde_json::json!({
        "invalid_field": "no_event_type_provided",
    }));
    let rep1 = FormalBfsModel::check_trace_conformance(&bad_schema_traces);
    assert!(!rep1.status.is_conformant());
    assert!(
        rep1.has_rule_violation("schema"),
        "Must flag schema violation on missing event_type"
    );

    // 2. Adversarial Test: Rule 1 - Non-hex or uppercase hash in record_hash
    let mut bad_hash_traces = baseline_traces.clone();
    bad_hash_traces.push(serde_json::json!({
        "event_type": "ARBITRARY_EVENT",
        "record_hash": "UPPERCASE_AND_NOT_VALID_HEX_000000000000000000000000000000000000",
    }));
    let rep2 = FormalBfsModel::check_trace_conformance(&bad_hash_traces);
    assert!(!rep2.status.is_conformant());
    assert!(
        rep2.has_rule_violation("schema"),
        "Must flag schema violation on uppercase hash"
    );

    // 3. Adversarial Test: Rule 4 - Seal Violation (ALLOW verdict but seal_present = false)
    let mut unsealed_traces = baseline_traces.clone();
    unsealed_traces.push(serde_json::json!({
        "event_type": "GOVERNANCE_DECISION",
        "verdict": "ALLOW",
        "seal_present": false,
        "record_hash": "1111111111111111111111111111111111111111111111111111111111111111",
        "stages_evaluated": [
            {"stage_name": "ftra"},
            {"stage_name": "stpa"},
            {"stage_name": "cedar"},
            {"stage_name": "confidence"},
            {"stage_name": "consensus"},
            {"stage_name": "cbf"},
            {"stage_name": "fiscal"},
        ],
    }));
    let rep3 = FormalBfsModel::check_trace_conformance(&unsealed_traces);
    assert!(!rep3.status.is_conformant());
    assert!(
        rep3.has_rule_violation("seal"),
        "Must flag seal violation when ALLOW lacks seal_present"
    );

    // 4. Adversarial Test: Rule 3 - Coverage Violation (missing required tier, e.g. cbf)
    let mut incomplete_coverage_traces = baseline_traces.clone();
    incomplete_coverage_traces.push(serde_json::json!({
        "event_type": "GOVERNANCE_DECISION",
        "verdict": "ALLOW",
        "seal_present": true,
        "record_hash": "2222222222222222222222222222222222222222222222222222222222222222",
        "stages_evaluated": [
            {"stage_name": "ftra"},
            {"stage_name": "stpa"},
            {"stage_name": "cedar"},
            {"stage_name": "confidence"},
            {"stage_name": "consensus"},
            // cbf and fiscal missing!
        ],
    }));
    let rep4 = FormalBfsModel::check_trace_conformance(&incomplete_coverage_traces);
    assert!(!rep4.status.is_conformant());
    assert!(
        rep4.has_rule_violation("coverage"),
        "Must flag coverage violation when tier is missing"
    );

    // 5. Adversarial Test: Rule 5 - Reachable State Violation (illegal state transition)
    let mut unreachable_state_traces = baseline_traces.clone();
    unreachable_state_traces.push(serde_json::json!({
        "event_type": "STATE_TRANSITION",
        "phase": "BOGUS_PHASE",
        "label": "unreachable_label",
        "tier": 99,
        "record_hash": "3333333333333333333333333333333333333333333333333333333333333333",
    }));
    let rep5 = FormalBfsModel::check_trace_conformance(&unreachable_state_traces);
    assert!(!rep5.status.is_conformant());
    assert!(
        rep5.has_rule_violation("reachable"),
        "Must flag reachable violation on invalid state transition"
    );

    // 6. Adversarial Test: Rule 6 - No-Direct-Bind Violation (ACTUATION_RECEIPT without prior GOVERNANCE_SEAL_CONSUMED)
    let mut direct_bind_traces = baseline_traces.clone();
    direct_bind_traces.push(serde_json::json!({
        "event_type": "ACTUATION_RECEIPT",
        "seal_id": "unconsumed_rogue_seal_999",
        "action": "doc_extractor",
        "record_hash": "4444444444444444444444444444444444444444444444444444444444444444",
    }));
    let rep6 = FormalBfsModel::check_trace_conformance(&direct_bind_traces);
    assert!(!rep6.status.is_conformant());
    assert!(
        rep6.has_rule_violation("no_direct_bind"),
        "Must flag no_direct_bind when actuation lacks prior seal consumed"
    );

    // 7. Adversarial Test: Rule 7 - Single-Use Violation (duplicate seal consumption in audit log)
    let mut replay_trace = baseline_traces.clone();
    replay_trace.push(serde_json::json!({
        "event_type": "GOVERNANCE_SEAL_CONSUMED",
        "seal_id": valid_seal.seal_id, // Duplicate of already consumed seal!
        "decision_record_hash": valid_seal.record_hash,
        "action_digest": valid_seal.action_digest,
        "policy_version_id": valid_seal.policy_version_id,
        "action": "doc_extractor",
        "arm_id": 0,
        "record_hash": "5555555555555555555555555555555555555555555555555555555555555555",
    }));
    let rep7 = FormalBfsModel::check_trace_conformance(&replay_trace);
    assert!(!rep7.status.is_conformant());
    assert!(
        rep7.has_rule_violation("single_use"),
        "Must flag single_use violation when seal is consumed twice"
    );
}
