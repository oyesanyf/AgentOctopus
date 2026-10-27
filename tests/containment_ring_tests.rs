use agent_octopus::arm::ArmRuntime;
use agent_octopus::containment_ring::{
    ContainmentRing, Operation, RingDecision, RingError, RingOperationRequest, RingRequest,
};
use agent_octopus::core::circuit_breaker::KillSwitch;
use agent_octopus::core::types::{
    ArmRole, OctopusSecurityError, StrategicDirective, TelemetryPacket,
};
use agent_octopus::neural_mesh::MessageKind;
use agent_octopus::security::windows_sandbox::WindowsJobObject;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_outer_ring_denies_host_filesystem_and_traversal() {
    let ring = ContainmentRing::default();

    // 1. Path traversal attack
    let traversal_req = RingOperationRequest {
        agent_id: "arm-doc-001".to_string(),
        role: ArmRole::UntrustedDocIngest,
        operation_type: "filesystem".to_string(),
        target: "../../etc/passwd".to_string(),
        capability_token: None,
        step_count: 1,
        payload: None,
        amount_cents: None,
        generation: None,
    };
    let (decision, reason) = ring.evaluate_operation(&traversal_req).await;
    assert_eq!(decision, RingDecision::Deny);
    assert!(reason.contains("Path traversal"));

    // 2. Sensitive host directory (C:\Windows\System32)
    let sys_req = RingOperationRequest {
        agent_id: "arm-doc-001".to_string(),
        role: ArmRole::UntrustedDocIngest,
        operation_type: "filesystem".to_string(),
        target: "C:\\Windows\\System32\\cmd.exe".to_string(),
        capability_token: None,
        step_count: 1,
        payload: None,
        amount_cents: None,
        generation: None,
    };
    let (decision, reason) = ring.evaluate_operation(&sys_req).await;
    assert_eq!(decision, RingDecision::Deny);
    assert!(reason.contains("Host filesystem boundary violation"));
}

#[tokio::test]
async fn test_outer_ring_denies_unapproved_egress_and_ssrf() {
    let ring = ContainmentRing::default();

    // 1. SSRF probe to cloud metadata
    let metadata_req = RingOperationRequest {
        agent_id: "arm-net-001".to_string(),
        role: ArmRole::NetworkEgress,
        operation_type: "http_egress".to_string(),
        target: "https://169.254.169.254/latest/meta-data/".to_string(),
        capability_token: None,
        step_count: 1,
        payload: None,
        amount_cents: None,
        generation: None,
    };
    let (decision, reason) = ring.evaluate_operation(&metadata_req).await;
    assert_eq!(decision, RingDecision::Quarantine);
    assert!(reason.contains("SSRF"));

    // 2. Unapproved external destination
    let unapproved_req = RingOperationRequest {
        agent_id: "arm-net-001".to_string(),
        role: ArmRole::NetworkEgress,
        operation_type: "http_egress".to_string(),
        target: "https://unauthorized-data-sink.org/leak".to_string(),
        capability_token: None,
        step_count: 1,
        payload: None,
        amount_cents: None,
        generation: None,
    };
    let (decision, reason) = ring.evaluate_operation(&unapproved_req).await;
    assert_eq!(decision, RingDecision::Deny);
    assert!(reason.contains("not in the approved Containment Ring allowlist"));
}

#[tokio::test]
async fn test_inner_ring_detects_impersonation_and_role_spoofing() {
    let ring = ContainmentRing::default();

    // Enroll Arm A as UntrustedDocIngest
    ring.identity_gate
        .enroll("arm-doc-001", ArmRole::UntrustedDocIngest, b"seed_a")
        .await;

    // Verify legitimate role passes
    let ok_res = ring
        .identity_gate
        .assert_role("arm-doc-001", &ArmRole::UntrustedDocIngest)
        .await;
    assert!(ok_res.is_ok());

    // Impersonation: Arm A claiming to be AccountingLedgerWrite
    let spoof_res = ring
        .identity_gate
        .assert_role("arm-doc-001", &ArmRole::AccountingLedgerWrite)
        .await;
    assert!(matches!(
        spoof_res,
        Err(OctopusSecurityError::IdentitySpoofingDetected(_))
    ));
}

#[tokio::test]
async fn test_capability_gate_rejects_revoked_tokens() {
    let ring = ContainmentRing::default();

    // Issue a capability token for a ledger write
    let token = ring.capability_gate.issue_capability(
        "brain",
        "arm-ledger-001",
        ArmRole::AccountingLedgerWrite,
        "ledger_writer",
        "s3://accounting/ledger.json",
    );

    // Initial verification succeeds
    let verify_res = ring
        .capability_gate
        .verify_capability(
            &token,
            "arm-ledger-001",
            "ledger_writer",
            "s3://accounting/ledger.json",
        )
        .await;
    assert!(verify_res.is_ok());

    // Revoke the token
    ring.capability_gate.revoke_token(&token.token_id).await;

    // Subsequent verification must fail
    let post_revoke = ring
        .capability_gate
        .verify_capability(
            &token,
            "arm-ledger-001",
            "ledger_writer",
            "s3://accounting/ledger.json",
        )
        .await;
    assert!(matches!(
        post_revoke,
        Err(OctopusSecurityError::CapabilityDenied(_))
    ));
}

#[tokio::test]
async fn test_atomic_binding_prevents_unauthorized_ledger_write() {
    let ring = ContainmentRing::default();
    let ledger_modified = Arc::new(AtomicBool::new(false));

    // Arm Doc Ingest attempts to write to ledger without capability
    let req = RingOperationRequest {
        agent_id: "arm-doc-001".to_string(),
        role: ArmRole::UntrustedDocIngest,
        operation_type: "ledger_writer".to_string(),
        target: "s3://accounting/general_ledger.json".to_string(),
        capability_token: None,
        step_count: 1,
        payload: Some("malicious ledger modification".to_string()),
        amount_cents: Some(500000),
        generation: None,
    };

    let ledger_flag = ledger_modified.clone();
    let exec_res = ring
        .execute_with_containment(&req, || async move {
            ledger_flag.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await;

    // Operation must be denied
    assert!(exec_res.is_err());
    // Independent Invariant: The ledger modification MUST NOT have occurred!
    assert_eq!(ledger_modified.load(Ordering::SeqCst), false);
}

#[tokio::test]
async fn test_non_cooperative_autotomy_halts_terminated_arm() {
    let ring = ContainmentRing::default();
    let kill_switch = KillSwitch::new();

    ring.isolation_manager
        .register_kill_switch("arm-compromised-001", kill_switch.clone())
        .await;
    assert_eq!(
        ring.isolation_manager
            .is_arm_active("arm-compromised-001")
            .await,
        true
    );

    // Supervisor terminates the arm without arm cooperation
    ring.isolation_manager
        .terminate_arm("arm-compromised-001", "Detected memory manipulation")
        .await
        .unwrap();

    // Verify kill switch tripped instantly
    assert_eq!(kill_switch.is_tripped(), true);
    assert_eq!(
        ring.isolation_manager
            .is_arm_active("arm-compromised-001")
            .await,
        false
    );

    // Subsequent operation through the ring must be rejected
    let req = RingOperationRequest {
        agent_id: "arm-compromised-001".to_string(),
        role: ArmRole::NetworkEgress,
        operation_type: "http_egress".to_string(),
        target: "https://www.google.com/search?q=test".to_string(),
        capability_token: None,
        step_count: 1,
        payload: None,
        amount_cents: None,
        generation: None,
    };
    let (decision, reason) = ring.evaluate_operation(&req).await;
    assert_eq!(decision, RingDecision::Deny);
    assert!(reason.contains("terminated or quarantined"));
}

#[tokio::test]
async fn test_negative_control_policy_tampering_triggers_failure() {
    let ring = ContainmentRing::default();

    // Verify initial attestation passes
    assert!(ring.attestation.verify_attestation().await);

    let req = RingOperationRequest {
        agent_id: "arm-doc-001".to_string(),
        role: ArmRole::UntrustedDocIngest,
        operation_type: "doc_extractor".to_string(),
        target: "s3://invoices/inv.pdf".to_string(),
        capability_token: None,
        step_count: 1,
        payload: None,
        amount_cents: None,
        generation: None,
    };

    // 1. Positive Control: Authentic attestation allows the request
    let (decision_ok, _) = ring.evaluate_operation(&req).await;
    assert_eq!(decision_ok, RingDecision::Allow);

    // 2. NEGATIVE CONTROL: Simulate an adversary tampering with active policies / attestation signature
    ring.attestation
        .tamper_with_signature("corrupted_forged_signature_0xDEAD")
        .await;

    // The ring must detect the attestation mismatch and reject execution with Terminate
    let (decision_tampered, reason) = ring.evaluate_operation(&req).await;
    assert_eq!(decision_tampered, RingDecision::Terminate);
    assert!(reason.contains("Attestation failure"));

    let exec_res = ring
        .execute_with_containment(&req, || async { Ok(()) })
        .await;
    assert!(matches!(exec_res, Err(OctopusSecurityError::LimbKilled)));

    // 3. Restoration: Restoring authentic attestation restores normal containment operation for active arms
    ring.attestation.restore_authentic_attestation().await;
    let req_active = RingOperationRequest {
        agent_id: "arm-doc-002".to_string(),
        role: ArmRole::UntrustedDocIngest,
        operation_type: "doc_extractor".to_string(),
        target: "s3://invoices/inv.pdf".to_string(),
        capability_token: None,
        step_count: 1,
        payload: None,
        amount_cents: None,
        generation: None,
    };
    let (decision_restored, _) = ring.evaluate_operation(&req_active).await;
    assert_eq!(decision_restored, RingDecision::Allow);
}

#[tokio::test]
async fn test_mesh_guard_prevents_ambient_privilege_inheritance() {
    use agent_octopus::containment_ring::ArmContainmentRing;

    let ring = ContainmentRing::default();
    let master_seed = b"test_master_seed_32_bytes_000001";
    let doc_ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, master_seed);
    let atlas_ring = ArmContainmentRing::new(2, ArmRole::AnomalyDetection, 1, master_seed);

    // Allow Finding message from arm 0 (doc ingest) to arm 2 (atlas)
    ring.mesh_guard
        .allow_route(0, 2, Some(MessageKind::Finding))
        .await;

    // Doc ingest sending HMAC-authenticated finding to atlas is permitted when route is registered
    let signed_valid = doc_ring
        .sign_mesh_message(2, 1, MessageKind::Finding, "corr-1", "found line items")
        .await
        .unwrap();
    let verified_valid = atlas_ring
        .verify_incoming_message(&signed_valid)
        .await
        .unwrap();
    let valid_msg = ring.mesh_guard.validate_message(&verified_valid).await;
    assert!(valid_msg.is_ok());

    // Boundary Invariant: Ingestion arm attempting to message ledger arm (arm 1) is strictly forbidden
    let ledger_ring = ArmContainmentRing::new(1, ArmRole::AccountingLedgerWrite, 1, master_seed);
    let signed_lateral = doc_ring
        .sign_mesh_message(1, 1, MessageKind::Finding, "corr-2", "execute transfer")
        .await
        .unwrap();
    let lateral_verify = ledger_ring.verify_incoming_message(&signed_lateral).await;
    assert!(matches!(
        lateral_verify,
        Err(OctopusSecurityError::DelegationScopeViolation(_))
    ));
}

#[tokio::test]
async fn test_end_to_end_cedar_trusted_arm_handle_authorization_and_revocation() {
    let ring = ContainmentRing::default();

    // 1. Enroll document ingestion arm with DocumentRead operation
    let doc_arm = ring
        .trusted_controller
        .enroll(
            "arm-doc-e2e".to_string(),
            "ingest".to_string(),
            HashSet::from([Operation::DocumentRead]),
        )
        .await
        .expect("Arm enrolled");

    // Legitimate DocumentRead: Cedar authorizes extraction, broker executes safe enclave extractor
    let valid_doc_req = RingRequest {
        operation: Operation::DocumentRead,
        resource: "s3://invoices/inv-001.pdf".to_string(),
        body: b"INVOICE: INV-100\nVendor: Acme\nTotal: $150.00".to_vec(),
    };
    let doc_res = doc_arm.request(valid_doc_req.clone()).await;
    assert!(
        doc_res.is_ok(),
        "Authorized tool invocation through ring must succeed"
    );

    // Unauthorized Tool Call: Document arm attempting privileged LedgerWrite must fail with RingError::Denied
    let illegal_ledger_req = RingRequest {
        operation: Operation::LedgerWrite,
        resource: "s3://accounting/ledger.json".to_string(),
        body: b"ACC-100-USD".to_vec(),
    };
    let ledger_res = doc_arm.request(illegal_ledger_req).await;
    assert_eq!(ledger_res.unwrap_err(), RingError::Denied);

    // 2. Enroll network egress arm with HttpEgress operation
    let net_arm = ring
        .trusted_controller
        .enroll(
            "arm-net-e2e".to_string(),
            "egress".to_string(),
            HashSet::from([Operation::HttpEgress]),
        )
        .await
        .expect("Network arm enrolled");

    // Unapproved destination (unauthorized domain) fails with RingError::Denied
    let unapproved_egress = RingRequest {
        operation: Operation::HttpEgress,
        resource: "https://evil-exfiltration.net/leak".to_string(),
        body: b"payload".to_vec(),
    };
    let unapproved_res = net_arm.request(unapproved_egress).await;
    assert_eq!(unapproved_res.unwrap_err(), RingError::Denied);

    // Approved Google egress succeeds through Cedar and EgressProxy
    let approved_egress = RingRequest {
        operation: Operation::HttpEgress,
        resource: "https://www.google.com/search?q=test".to_string(),
        body: b"".to_vec(),
    };
    let approved_res = net_arm.request(approved_egress.clone()).await;
    assert!(approved_res.is_ok(), "Approved Google egress must succeed");

    // 3. Supervisor non-cooperatively revokes the arm
    ring.trusted_controller
        .revoke("arm-net-e2e")
        .await
        .expect("Arm revoked");

    // Subsequent request on revoked handle fails immediately with RingError::Revoked
    let post_revoke_res = net_arm.request(approved_egress).await;
    assert_eq!(post_revoke_res.unwrap_err(), RingError::Revoked);
}

#[tokio::test]
async fn test_end_to_end_arm_runtime_forced_containment_routing() {
    let (telemetry_tx, _telemetry_rx) = mpsc::channel::<TelemetryPacket>(100);
    let (directive_tx, directive_rx) = mpsc::channel(16);
    let kill_switch = KillSwitch::new();
    let ring = Arc::new(ContainmentRing::default());

    // Enroll with ring to get a TrustedArmHandle
    let handle = ring
        .trusted_controller
        .enroll(
            "arm-doc-routed".to_string(),
            "ingest".to_string(),
            HashSet::from([Operation::DocumentRead]),
        )
        .await
        .expect("Handle enrolled");

    let arm = ArmRuntime::new(
        ArmRole::UntrustedDocIngest,
        directive_rx,
        telemetry_tx,
        kill_switch.clone(),
    )
    .with_custom_agent_id("arm-doc-routed".to_string())
    .with_containment_ring(ring.clone())
    .with_trusted_handle(handle);

    let arm_handle = tokio::spawn(arm.run());

    // 1. Send legitimate directive: executes through containment ring
    let (resp_tx1, resp_rx1) = tokio::sync::oneshot::channel();
    let valid_directive = StrategicDirective {
        directive_id: "DIR-ROUTED-01".to_string(),
        source_uri: "s3://invoices/bill.pdf".to_string(),
        instruction: "Parse total".to_string(),
        raw_payload: Some("INVOICE: INV-500\nVendor: SafeCorp\nTotal: $250.00".to_string()),
        max_step_budget: 5,
    };
    directive_tx
        .send((valid_directive, resp_tx1))
        .await
        .unwrap();
    let rep1 = resp_rx1.await.unwrap();
    if let Err(ref e) = rep1 {
        panic!("Tool routed through ring failed with error: {:?}", e);
    }
    let report = rep1.unwrap();
    assert!(report.success);
    assert!(report.verified_data.is_some());

    // 2. Non-cooperative Autotomy: Supervisor terminates the arm in the isolation manager
    ring.isolation_manager
        .terminate_arm("arm-doc-routed", "Supervisor triggered quarantine")
        .await
        .unwrap();
    assert_eq!(kill_switch.is_tripped(), true);
    assert_eq!(
        ring.isolation_manager.is_arm_active("arm-doc-routed").await,
        false
    );

    // 3. Send subsequent directive: arm must reject with LimbKilled and halt loop
    let (resp_tx2, resp_rx2) = tokio::sync::oneshot::channel();
    let next_directive = StrategicDirective {
        directive_id: "DIR-ROUTED-02".to_string(),
        source_uri: "s3://invoices/bill2.pdf".to_string(),
        instruction: "Parse total".to_string(),
        raw_payload: Some("INVOICE: INV-501\nVendor: SafeCorp\nTotal: $100.00".to_string()),
        max_step_budget: 5,
    };
    directive_tx.send((next_directive, resp_tx2)).await.unwrap();
    let rep2 = resp_rx2.await.unwrap();
    assert_eq!(rep2.unwrap_err(), OctopusSecurityError::LimbKilled);

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        arm_handle.is_finished(),
        "Terminated arm must not persist in background"
    );
}

#[tokio::test]
async fn test_end_to_end_independent_os_process_and_token_revocation() {
    let ring = ContainmentRing::default();
    let kill_switch = KillSwitch::new();
    let job_object = Arc::new(
        WindowsJobObject::create("OctopusE2ETestJob", 2, 64 * 1024 * 1024)
            .expect("Job object created"),
    );

    // Issue capability token to arm
    let token = ring.capability_gate.issue_capability(
        "supervisor",
        "arm-sandbox-victim",
        ArmRole::AccountingLedgerWrite,
        "ledger_writer",
        "s3://accounting/ledger.json",
    );

    // Enroll in trusted controller
    let _handle = ring
        .trusted_controller
        .enroll(
            "arm-sandbox-victim".to_string(),
            "ledger".to_string(),
            HashSet::from([Operation::LedgerWrite]),
        )
        .await
        .expect("Arm enrolled in ring controller");

    // Register with IsolationManager
    ring.isolation_manager
        .register_arm(
            "arm-sandbox-victim",
            kill_switch.clone(),
            Some(job_object.clone()),
        )
        .await;

    // Verify initially active and authorized
    assert_eq!(
        ring.isolation_manager
            .is_arm_active("arm-sandbox-victim")
            .await,
        true
    );
    assert_eq!(job_object.is_terminated.load(Ordering::SeqCst), false);
    assert!(ring
        .capability_gate
        .verify_capability(
            &token,
            "arm-sandbox-victim",
            "ledger_writer",
            "s3://accounting/ledger.json"
        )
        .await
        .is_ok());

    // Non-cooperative Autotomy Triggered by Supervisor
    ring.isolation_manager
        .terminate_arm("arm-sandbox-victim", "Kernel anomaly detected")
        .await
        .unwrap();

    // 1. Hardware/atomic kill switch tripped
    assert_eq!(kill_switch.is_tripped(), true);

    // 2. OS Process terminated at kernel level via Windows Job Object
    assert_eq!(job_object.is_terminated.load(Ordering::SeqCst), true);

    // 3. Isolation manager records arm as inactive
    assert_eq!(
        ring.isolation_manager
            .is_arm_active("arm-sandbox-victim")
            .await,
        false
    );

    // 4. Capability tokens instantly revoked without agent consent
    let cap_res = ring
        .capability_gate
        .verify_capability(
            &token,
            "arm-sandbox-victim",
            "ledger_writer",
            "s3://accounting/ledger.json",
        )
        .await;
    assert!(matches!(
        cap_res,
        Err(OctopusSecurityError::CapabilityDenied(_))
    ));

    // 5. Ring controller handle revoked
    assert_eq!(
        ring.trusted_controller
            .is_revoked("arm-sandbox-victim")
            .await
            .unwrap(),
        true
    );
}
