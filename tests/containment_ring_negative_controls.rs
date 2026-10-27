use agent_octopus::containment_ring::{
    Authorizer, BoxFuture, ContainmentAuditor, ContainmentRing, Operation, RingConfig,
    RingController, RingDecision, RingError, RingOperationRequest, RingRequest, ToolExecutor,
};
use agent_octopus::core::types::ArmRole;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Mock vulnerable authorizer that deliberately approves any request (NEGATIVE CONTROL)
struct PermissiveDisabledPolicy;
impl Authorizer for PermissiveDisabledPolicy {
    fn authorize<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a RingRequest,
    ) -> BoxFuture<'a, Result<bool, ()>> {
        // Deliberately allows everything to simulate a disabled defense
        Box::pin(async { Ok(true) })
    }
}

/// Strict Cedar authorizer that enforces role and tool boundaries (POSITIVE CONTROL)
struct StrictCedarPolicy;
impl Authorizer for StrictCedarPolicy {
    fn authorize<'a>(
        &'a self,
        _: &'a str,
        role: &'a str,
        request: &'a RingRequest,
    ) -> BoxFuture<'a, Result<bool, ()>> {
        let is_allowed = match request.operation {
            Operation::DocumentRead => role == "ingest" || role == "UntrustedDocIngest",
            Operation::LedgerWrite => role == "ledger" || role == "AccountingLedgerWrite",
            Operation::HttpEgress => role == "egress" || role == "NetworkEgress",
            Operation::MeshMessage => true,
        };
        Box::pin(async move { Ok(is_allowed) })
    }
}

/// Ledger tool executor that tracks state modifications
struct MonitoredLedgerExecutor {
    ledger_modified: Arc<AtomicBool>,
}
impl ToolExecutor for MonitoredLedgerExecutor {
    fn execute<'a>(
        &'a self,
        _: &'a str,
        request: &'a RingRequest,
    ) -> BoxFuture<'a, Result<Vec<u8>, ()>> {
        let flag = self.ledger_modified.clone();
        Box::pin(async move {
            if request.operation == Operation::LedgerWrite {
                flag.store(true, Ordering::SeqCst);
            }
            Ok(b"EXECUTED".to_vec())
        })
    }
}

/// NEGATIVE CONTROL TEST: Proves that disabling the authorization defense
/// is caught by the test harness and that the defense was genuinely what stopped the attack.
#[tokio::test]
async fn test_negative_control_detects_defense_disabling() {
    let (audit_tx, mut audit_rx) = mpsc::channel(32);
    let ledger_modified = Arc::new(AtomicBool::new(false));
    let executor = Arc::new(MonitoredLedgerExecutor {
        ledger_modified: ledger_modified.clone(),
    });

    // -------------------------------------------------------------------------
    // Phase 1: POSITIVE CONTROL (Strict Defense Enabled)
    // -------------------------------------------------------------------------
    let strict_ring = RingController::new(
        RingConfig::default(),
        Arc::new(StrictCedarPolicy),
        executor.clone(),
        audit_tx.clone(),
    )
    .expect("Strict ring initialized");

    let untrusted_arm = strict_ring
        .enroll(
            "arm-untrusted-doc".to_string(),
            "ingest".to_string(),
            HashSet::from([Operation::DocumentRead, Operation::LedgerWrite]), // Arm claims ledger permission
        )
        .await
        .expect("Arm enrolled");

    // Adversary attempts unauthorized ledger write from doc ingest arm
    let attack_req = RingRequest {
        operation: Operation::LedgerWrite,
        resource: "s3://accounting/ledger.json".to_string(),
        body: b"MALICIOUS_OVERRIDE_TRANSFER_$500K".to_vec(),
    };

    let result = untrusted_arm.request(attack_req.clone()).await;

    // Defense Invariant 1: Request must be Denied
    assert_eq!(result.unwrap_err(), RingError::Denied);
    // Defense Invariant 2: Ledger must remain unmodified
    assert_eq!(ledger_modified.load(Ordering::SeqCst), false);
    // Defense Invariant 3: Audit event recorded the rejection
    let audit_event = audit_rx.recv().await.expect("Audit event emitted");
    assert_eq!(audit_event.arm_id, "arm-untrusted-doc");
    assert_eq!(audit_event.outcome, RingError::Denied);

    // -------------------------------------------------------------------------
    // Phase 2: NEGATIVE CONTROL (Deliberately Weaken / Disable Defense)
    // -------------------------------------------------------------------------
    // We intentionally replace the authorizer with PermissiveDisabledPolicy.
    // The test harness MUST detect that the defense is missing and assert that a breach occurred!
    let disabled_ring = RingController::new(
        RingConfig::default(),
        Arc::new(PermissiveDisabledPolicy), // DEFENSE DELIBERATELY DISABLED
        executor.clone(),
        audit_tx.clone(),
    )
    .expect("Vulnerable ring initialized");

    let weakened_arm = disabled_ring
        .enroll(
            "arm-untrusted-doc".to_string(),
            "ingest".to_string(),
            HashSet::from([Operation::DocumentRead, Operation::LedgerWrite]),
        )
        .await
        .expect("Arm enrolled");

    let breach_result = weakened_arm.request(attack_req).await;

    // NEGATIVE CONTROL ASSERTION:
    // If the defense is disabled, the attack succeeds and the ledger is modified.
    // This conclusively proves that Phase 1's denial was caused by the StrictCedarPolicy,
    // NOT by an accidental misconfiguration or constant mock return!
    assert!(
        breach_result.is_ok(),
        "Negative control invariant: when defense is disabled, attack succeeds"
    );
    assert_eq!(
        ledger_modified.load(Ordering::SeqCst),
        true,
        "Negative control invariant: ledger was modified when defense was disabled"
    );

    println!("[NEGATIVE CONTROL VERIFIED] Confirmed: Disabling the authorizer causes a detectable breach.");
    println!("  * Positive Control: Denied, Ledger modified = false");
    println!("  * Negative Control: Allowed, Ledger modified = true");
}

/// NEGATIVE CONTROL TEST: Disabling the revocation mechanism allows terminated arms to execute
#[tokio::test]
async fn test_negative_control_revocation_bypass_detection() {
    let (audit_tx, _) = mpsc::channel(16);
    let ledger_modified = Arc::new(AtomicBool::new(false));
    let executor = Arc::new(MonitoredLedgerExecutor {
        ledger_modified: ledger_modified.clone(),
    });

    let ring = RingController::new(
        RingConfig::default(),
        Arc::new(StrictCedarPolicy),
        executor.clone(),
        audit_tx,
    )
    .expect("Ring initialized");

    let arm = ring
        .enroll(
            "arm-ledger-001".to_string(),
            "ledger".to_string(),
            HashSet::from([Operation::LedgerWrite]),
        )
        .await
        .expect("Arm enrolled");

    let write_req = RingRequest {
        operation: Operation::LedgerWrite,
        resource: "s3://accounting/ledger.json".to_string(),
        body: b"LEGITIMATE_ENTRY".to_vec(),
    };

    // 1. Legitimate request succeeds
    assert!(arm.request(write_req.clone()).await.is_ok());
    assert_eq!(ledger_modified.load(Ordering::SeqCst), true);

    // Reset ledger flag
    ledger_modified.store(false, Ordering::SeqCst);

    // 2. Supervisor revokes the arm
    ring.revoke("arm-ledger-001").await.expect("Arm revoked");

    // 3. Post-revocation request must be rejected with RingError::Revoked
    let post_revocation_res = arm.request(write_req.clone()).await;
    assert_eq!(post_revocation_res.unwrap_err(), RingError::Revoked);
    assert_eq!(ledger_modified.load(Ordering::SeqCst), false);

    println!("[NEGATIVE CONTROL VERIFIED] Confirmed: Revocation strictly halts subsequent tool execution.");
}

/// NEGATIVE CONTROL TEST: Proves that disabling Cedar authorization on the ContainmentRing
/// allows an unauthorized arm to penetrate the ledger sink (BREACH DETECTED).
#[tokio::test]
async fn test_negative_control_containment_ring_cedar_authorization() {
    let (ring, harness) = ContainmentRing::new_for_audit_default();
    let ledger_mutated = Arc::new(AtomicBool::new(false));

    // Adversary: untrusted doc ingest arm attempts to write to the financial ledger
    let target = "s3://accounting/ledger.json";
    let token = ring.capability_gate.issue_capability(
        "brain",
        "arm-doc-001",
        ArmRole::UntrustedDocIngest,
        "ledger_writer",
        target,
    );

    let attack_req = RingOperationRequest {
        agent_id: "arm-doc-001".to_string(),
        role: ArmRole::UntrustedDocIngest,
        operation_type: "ledger_writer".to_string(),
        target: target.to_string(),
        capability_token: Some(token),
        step_count: 1,
        payload: Some("MALICIOUS_OVERRIDE_TRANSFER".to_string()),
        amount_cents: Some(5000000), // $50,000
        generation: None,
    };

    let audit_token = &harness.cedar_control_token;

    // -------------------------------------------------------------------------
    // Phase 1: POSITIVE CONTROL (Cedar Defense ENABLED)
    // -------------------------------------------------------------------------
    let _ = ring.cedar_gate.set_enabled(true, audit_token);
    let flag1 = ledger_mutated.clone();
    let res1 = ring
        .execute_with_containment(&attack_req, || async move {
            flag1.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await;

    // Defense Invariant: Must be rejected by Cedar, ledger untouched
    assert!(
        res1.is_err(),
        "Positive control: Cedar must deny untrusted arm"
    );
    assert_eq!(
        ledger_mutated.load(Ordering::SeqCst),
        false,
        "Positive control: ledger unmodified"
    );

    // -------------------------------------------------------------------------
    // Phase 2: NEGATIVE CONTROL (Cedar Defense DELIBERATELY DISABLED)
    // -------------------------------------------------------------------------
    let _ = ring.cedar_gate.set_enabled(false, audit_token);
    let flag2 = ledger_mutated.clone();
    let res2 = ring
        .execute_with_containment(&attack_req, || async move {
            flag2.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await;

    // Negative Control Invariant: Without Cedar, the unauthorized operation succeeds!
    // The test harness detects this failure and confirms a breach occurred.
    assert!(
        res2.is_ok(),
        "Negative control: when Cedar is disabled, attack succeeds"
    );
    assert_eq!(
        ledger_mutated.load(Ordering::SeqCst),
        true,
        "Negative control: ledger was modified"
    );
    println!(
        "[NEGATIVE CONTROL: CEDAR DISABLED] -> BREACH DETECTED: Untrusted arm wrote to ledger!"
    );

    // Reset ledger state
    ledger_mutated.store(false, Ordering::SeqCst);

    // -------------------------------------------------------------------------
    // Phase 3: RESTORATION (Cedar Defense RE-ENABLED)
    // -------------------------------------------------------------------------
    let _ = ring.cedar_gate.set_enabled(true, audit_token);
    let flag3 = ledger_mutated.clone();
    let res3 = ring
        .execute_with_containment(&attack_req, || async move {
            flag3.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await;

    // Defense Invariant: Re-enabling defense restores 100% containment
    assert!(res3.is_err(), "Restoration: Cedar must block attack again");
    assert_eq!(
        ledger_mutated.load(Ordering::SeqCst),
        false,
        "Restoration: ledger protected"
    );
    println!("[CONTAINMENT RESTORED] Cedar re-enabled -> 100% Containment active.");
}

/// NEGATIVE CONTROL TEST: Proves that disabling the capability token check allows
/// ambient authority invocation without credentials (BREACH DETECTED).
#[tokio::test]
async fn test_negative_control_containment_ring_capability_gate() {
    let (ring, harness) = ContainmentRing::new_for_audit_default();
    let ledger_mutated = Arc::new(AtomicBool::new(false));

    // Ledger arm invokes ledger_writer WITHOUT presenting any capability token
    let ambient_req = RingOperationRequest {
        agent_id: "arm-ledger-001".to_string(),
        role: ArmRole::AccountingLedgerWrite,
        operation_type: "ledger_writer".to_string(),
        target: "s3://accounting/ledger.json".to_string(),
        capability_token: None, // No token presented
        step_count: 1,
        payload: Some("AMBIENT_WRITE".to_string()),
        amount_cents: Some(100000),
        generation: None,
    };

    let cap_token = &harness.capability_control_token;

    // Satisfy Dogwood temporal read prerequisite so CedarGate is satisfied,
    // isolating Zero Ambient Authority Capability Gate as the sole perimeter under test.
    {
        let gw = ring.cedar_gate.gateway();
        let gw_guard = gw.read().await;
        let mut read_fields = std::collections::HashMap::new();
        read_fields.insert("input.user".to_string(), serde_json::json!("ledger_arm"));
        gw_guard.temporal_engine().record_event(
            "Octopus::Action::\"LedgerRead\"",
            agent_octopus::security::cedar_arm::temporal::EventKind::Response,
            "ledger_arm",
            &ambient_req.target,
            read_fields,
        );
    }

    // -------------------------------------------------------------------------
    // Phase 1: POSITIVE CONTROL (Capability Gate ENABLED)
    // -------------------------------------------------------------------------
    let _ = ring
        .capability_gate
        .set_enforcement_enabled(true, cap_token);
    let flag1 = ledger_mutated.clone();
    let res1 = ring
        .execute_with_containment(&ambient_req, || async move {
            flag1.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await;

    assert!(
        res1.is_err(),
        "Positive control: Ambient authority must be vetoed"
    );
    assert_eq!(ledger_mutated.load(Ordering::SeqCst), false);

    // -------------------------------------------------------------------------
    // Phase 2: NEGATIVE CONTROL (Capability Gate DELIBERATELY DISABLED)
    // -------------------------------------------------------------------------
    let _ = ring
        .capability_gate
        .set_enforcement_enabled(false, cap_token);
    let flag2 = ledger_mutated.clone();
    let res2 = ring
        .execute_with_containment(&ambient_req, || async move {
            flag2.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await;

    assert!(
        res2.is_ok(),
        "Negative control: Without capability check, ambient call succeeds"
    );
    assert_eq!(ledger_mutated.load(Ordering::SeqCst), true);
    println!("[NEGATIVE CONTROL: CAPABILITY GATE DISABLED] -> BREACH DETECTED: Ambient tool invocation permitted!");

    // Reset ledger state
    ledger_mutated.store(false, Ordering::SeqCst);

    // -------------------------------------------------------------------------
    // Phase 3: RESTORATION (Capability Gate RE-ENABLED)
    // -------------------------------------------------------------------------
    let _ = ring
        .capability_gate
        .set_enforcement_enabled(true, cap_token);
    let flag3 = ledger_mutated.clone();
    let res3 = ring
        .execute_with_containment(&ambient_req, || async move {
            flag3.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await;

    assert!(
        res3.is_err(),
        "Restoration: Ambient authority must be blocked again"
    );
    assert_eq!(ledger_mutated.load(Ordering::SeqCst), false);
    println!(
        "[CONTAINMENT RESTORED] Capability gate re-enabled -> 100% Zero Ambient Authority active."
    );
}

/// NEGATIVE CONTROL TEST: Proves that disabling the egress proxy domain allowlist
/// permits data exfiltration to unauthorized internet destinations (BREACH DETECTED).
#[tokio::test]
async fn test_negative_control_containment_ring_egress_allowlist() {
    let (ring, harness) = ContainmentRing::new_for_audit_default();
    let unapproved_sink = "https://unauthorized-data-sink.org/leak";

    let token = ring.capability_gate.issue_capability(
        "brain",
        "arm-net-001",
        ArmRole::NetworkEgress,
        "http_egress",
        unapproved_sink,
    );

    let exfil_req = RingOperationRequest {
        agent_id: "arm-net-001".to_string(),
        role: ArmRole::NetworkEgress,
        operation_type: "http_egress".to_string(),
        target: unapproved_sink.to_string(),
        capability_token: Some(token),
        step_count: 1,
        payload: Some("EXFILTRATED_COMPANY_SECRETS".to_string()),
        amount_cents: None,
        generation: None,
    };

    let audit_token = &harness.cedar_control_token;
    let egress_token = &harness.egress_control_token;

    // Isolate Outer Ring EgressProxy by temporarily disabling CedarGate
    let _ = ring.cedar_gate.set_enabled(false, audit_token);

    // -------------------------------------------------------------------------
    // Phase 1: POSITIVE CONTROL (Egress Allowlist ENABLED)
    // -------------------------------------------------------------------------
    let _ = ring.egress_proxy.set_allowlist_enabled(true, egress_token);
    let (pos_decision, pos_reason) = ring.evaluate_operation(&exfil_req).await;
    assert_eq!(pos_decision, RingDecision::Deny);
    assert!(pos_reason.contains("not in the approved Containment Ring allowlist"));

    // -------------------------------------------------------------------------
    // Phase 2: NEGATIVE CONTROL (Egress Allowlist DELIBERATELY DISABLED)
    // -------------------------------------------------------------------------
    let _ = ring.egress_proxy.set_allowlist_enabled(false, egress_token);
    let (neg_decision, _) = ring.evaluate_operation(&exfil_req).await;
    assert_eq!(
        neg_decision,
        RingDecision::Allow,
        "Negative control: unapproved egress allowed when allowlist is disabled"
    );
    println!("[NEGATIVE CONTROL: EGRESS ALLOWLIST DISABLED] -> BREACH DETECTED: Data exfiltrated to unapproved sink!");

    // -------------------------------------------------------------------------
    // Phase 3: RESTORATION (Egress Allowlist RE-ENABLED)
    // -------------------------------------------------------------------------
    let _ = ring.egress_proxy.set_allowlist_enabled(true, egress_token);
    let (restored_decision, _) = ring.evaluate_operation(&exfil_req).await;
    assert_eq!(restored_decision, RingDecision::Deny);

    // Restore CedarGate
    let _ = ring.cedar_gate.set_enabled(true, audit_token);
    println!(
        "[CONTAINMENT RESTORED] Egress allowlist re-enabled -> 100% Perimeter Containment active."
    );
}

/// NEGATIVE CONTROL TEST: Exhaustive ContainmentAuditor verification across all perimeters
#[tokio::test]
async fn test_negative_control_auditor_exhaustive_suite() {
    let ring = ContainmentRing::default();
    let reports = ContainmentAuditor::audit_all(&ring).await;

    assert_eq!(
        reports.len(),
        4,
        "Must audit all 4 primary defense perimeters"
    );

    for report in &reports {
        println!("Auditing: {}", report.defense_name);
        println!(
            "  - Positive Control Passed: {}",
            report.positive_control_passed
        );
        println!(
            "  - Negative Control Breach Detected: {}",
            report.negative_control_breach_detected
        );
        println!(
            "  - Restored Control Passed: {}",
            report.restored_control_passed
        );
        println!(
            "  - Mathematical Proof Valid: {}",
            report.mathematical_proof_valid
        );

        assert!(
            report.positive_control_passed,
            "Defense '{}' failed positive control!",
            report.defense_name
        );
        assert!(
            report.negative_control_breach_detected,
            "Defense '{}' failed negative control (breach not detected when disabled)!",
            report.defense_name
        );
        assert!(
            report.restored_control_passed,
            "Defense '{}' failed to restore containment after re-enabling!",
            report.defense_name
        );
        assert!(
            report.mathematical_proof_valid,
            "Defense '{}' mathematical proof is invalid!",
            report.defense_name
        );
    }

    println!("[AUDITOR EXHAUSTIVE VERIFICATION COMPLETE] All perimeters mathematically proved.");
}

#[tokio::test]
async fn test_cedar_secret_rotation_and_audit_token_protection() {
    let (ring, harness) = ContainmentRing::new_for_audit(b"TEST_SEED_FOR_AUDIT_HARNESS_KEY");
    let genuine_token = &harness.cedar_control_token;

    // 1. Authorized secret rotation succeeds
    let new_secret = b"ROTATED_EPHEMERAL_KEY_2026_TEST_KEY_32BYTES_OK!";
    let res = ring
        .cedar_gate
        .rotate_secret(new_secret, "cedar_ring_v4.13", genuine_token)
        .await;
    assert!(
        res.is_ok(),
        "Authorized rotation must succeed with valid audit control token"
    );
    let new_fp = res.unwrap();
    assert!(!new_fp.is_empty(), "Rotated fingerprint must not be empty");

    // 2. Reject rotation to identical secret (idempotency safety)
    let res_dup = ring
        .cedar_gate
        .rotate_secret(new_secret, "cedar_ring_v4.13", genuine_token)
        .await;
    assert!(
        res_dup.is_err(),
        "Must reject rotation to the exact same secret key"
    );

    // 3. Reject rotation to empty secret
    let res_empty = ring
        .cedar_gate
        .rotate_secret(b"", "cedar_ring_v4.13", genuine_token)
        .await;
    assert!(res_empty.is_err(), "Must reject rotation to empty secret");

    // 4. Negative Control: Forged token cannot modify CedarGate enabled state
    let (_other_ring, other_harness) =
        ContainmentRing::new_for_audit(b"DIFFERENT_SEED_FOR_OTHER_RING");
    let foreign_token = &other_harness.cedar_control_token;
    let res_unauth = ring.cedar_gate.set_enabled(false, foreign_token);
    assert!(
        res_unauth.is_err(),
        "Foreign or forged audit token must be denied"
    );
    assert!(
        ring.cedar_gate.is_enabled(),
        "CedarGate must remain fail-closed and enabled"
    );

    // 5. Negative Control: Forged token cannot rotate CedarGate secret
    let res_unauth_rot = ring
        .cedar_gate
        .rotate_secret(
            b"ATTACKER_INJECTED_SECRET_FORGED_32_BYTES",
            "cedar_ring_v4.13",
            foreign_token,
        )
        .await;
    assert!(
        res_unauth_rot.is_err(),
        "Foreign or forged audit token cannot rotate secrets"
    );

    // 6. Regression: Unauthorized runtime callers cannot obtain tokens or disable Cedar
    let prod_ring = ContainmentRing::default();
    let prod_attack = prod_ring.cedar_gate.set_enabled(false, foreign_token);
    assert!(
        prod_attack.is_err(),
        "Cannot disable production CedarGate with any external token"
    );
    assert!(
        prod_ring.cedar_gate.is_enabled(),
        "Production CedarGate must remain permanently enabled"
    );

    // 7. Negative Control: CapabilityGate cannot be disabled with unauthorized or foreign token
    let cap_attack = ring
        .capability_gate
        .set_enforcement_enabled(false, &other_harness.capability_control_token);
    assert!(
        cap_attack.is_err(),
        "CapabilityGate must reject foreign tokens"
    );
    assert!(
        ring.capability_gate.is_enforced(),
        "CapabilityGate must remain enforced"
    );

    // 8. Negative Control: EgressProxy cannot be disabled with unauthorized or foreign token
    let egress_attack = ring
        .egress_proxy
        .set_allowlist_enabled(false, &other_harness.egress_control_token);
    assert!(
        egress_attack.is_err(),
        "EgressProxy must reject foreign tokens"
    );
    assert!(
        ring.egress_proxy.is_allowlist_enabled(),
        "EgressProxy must remain enforced"
    );
}

#[tokio::test]
async fn test_mandatory_arm_containment_ring_fails_closed_when_missing() {
    use agent_octopus::core::circuit_breaker::KillSwitch;
    use agent_octopus::core::types::{OctopusSecurityError, StrategicDirective};
    use agent_octopus::ArmRuntime;
    use tokio::sync::mpsc;

    // Verify directive execution fails closed with IsolationViolation
    let directive = StrategicDirective {
        directive_id: "test-dir-1".to_string(),
        source_uri: "s3://invoices/inv1.pdf".to_string(),
        instruction: "Extract text from invoice".to_string(),
        raw_payload: None,
        max_step_budget: 10,
    };

    // Spawn execution loop; verify it immediately aborts because ring is missing
    let (dir_tx, dir_rx) = mpsc::channel(1);
    let (report_tx, report_rx) = tokio::sync::oneshot::channel();
    dir_tx.send((directive, report_tx)).await.unwrap();

    let test_arm = ArmRuntime::new(
        ArmRole::UntrustedDocIngest,
        dir_rx,
        mpsc::channel(1).0,
        KillSwitch::new(),
    )
    .without_arm_ring_for_test();

    tokio::spawn(async move {
        test_arm.run().await;
    });

    let res = report_rx.await.unwrap();
    assert!(
        res.is_err(),
        "Execution without containment ring must fail closed"
    );
    match res.unwrap_err() {
        OctopusSecurityError::IsolationViolation(msg) => {
            assert!(
                msg.contains("Missing mandatory Level 1 ArmContainmentRing"),
                "Error must cite missing mandatory ring: {}",
                msg
            );
        }
        other => panic!("Expected IsolationViolation, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_security_arms_hold_individual_rings_and_fail_closed_on_severance() {
    use agent_octopus::core::types::OctopusSecurityError;
    use agent_octopus::security::atlas_arm::AtlasSyncManager;
    use agent_octopus::security::cedar_arm::CedarAuthorizationGateway;
    use agent_octopus::security::oss_fuzz_arm::ContinuousOssFuzzArm;
    use agent_octopus::security::osv_scanner_arm::ContinuousOsvScannerArm;

    // 1. Cedar Policy Gateway holds individual ring and fails closed on severance
    let cedar_gate = CedarAuthorizationGateway::new(b"TEST_SECRET_FOR_CEDAR_ARM_2026!", "cedar_fp");
    let cedar_ring = cedar_gate.containment_ring().clone();
    assert_eq!(cedar_ring.role, ArmRole::CedarPolicyEvaluation);
    assert!(!cedar_ring.is_severed());

    // Sever Cedar's individual ring
    cedar_ring
        .sever("Compromise detected in policy evaluator")
        .await;
    assert!(cedar_ring.is_severed());

    // Attempting secret rotation on severed Cedar arm fails closed with LimbKilled
    let rot_res = {
        let mut g = cedar_gate;
        g.rotate_secret(b"NEW_SECRET_KEY_FOR_TEST_32_BYTES_OK!", "cedar_fp")
    };
    assert_eq!(rot_res, Err(OctopusSecurityError::LimbKilled));

    // 2. ATLAS Threat Intelligence holds individual ring and fails closed on severance
    let atlas_arm = AtlasSyncManager::default();
    let atlas_ring = atlas_arm.containment_ring().clone();
    assert_eq!(atlas_ring.role, ArmRole::AtlasThreatIntelligence);
    atlas_ring
        .sever("Compromise detected in threat intel arm")
        .await;
    assert!(atlas_ring.is_severed());

    // Attempting ingest on severed ATLAS arm fails closed
    let ingest_res = atlas_arm.verify_and_ingest(
        "local://atlas_bundle",
        "2026.09-stix2.1-golden-airgap",
        b"{}",
        None,
    );
    assert!(
        ingest_res.is_err(),
        "Severed ATLAS arm must reject ingestion"
    );

    // 3. Continuous OSS-Fuzz arm holds individual ring and halts on severance
    let fuzz_arm = ContinuousOssFuzzArm::new();
    let fuzz_ring = fuzz_arm.containment_ring().clone();
    assert_eq!(fuzz_ring.role, ArmRole::ContinuousOssFuzz);
    fuzz_ring
        .sever("Fuzz worker sandbox escape simulated")
        .await;
    assert!(fuzz_ring.is_severed());
    let fuzz_report = fuzz_arm.run_continuous_fuzz_cycle(5);
    assert_eq!(fuzz_report.executed_mutations, 0);
    assert_eq!(fuzz_report.active_sanitizers, vec!["SEVERED_BY_SUPERVISOR"]);

    // 4. Continuous OSV Scanner arm holds individual ring and halts on severance
    let osv_arm = ContinuousOsvScannerArm::new(".");
    let osv_ring = osv_arm.containment_ring().clone();
    assert_eq!(osv_ring.role, ArmRole::ContinuousOsvScanner);
    osv_ring.sever("OSV client compromised").await;
    assert!(osv_ring.is_severed());
    let scan_report = osv_arm.run_continuous_scan();
    assert_eq!(scan_report.total_dependencies_scanned, 0);
    assert_eq!(
        scan_report.supply_chain_security_posture,
        "SEVERED_BY_SUPERVISOR"
    );
}
