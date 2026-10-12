//! Comprehensive Integration & Negative Control Test Suite
//! Verifying authoritative Level 1 containment ring quarantine, scoring calibration,
//! zero false positives, and fail-closed isolation for Arm 106 (DifferentialProtocolAnalyzer).

use agent_octopus::containment_ring::arm_ring::ArmRingRegistry;
use agent_octopus::security::audit::SecurityAuditLog;
use agent_octopus::security::differential_protocol::{
    DifferentialAction, DifferentialProtocolEngine,
};
use std::sync::Arc;

#[tokio::test]
async fn test_differential_engine_authoritative_quarantine_with_arm106() {
    let seed = ArmRingRegistry::generate_master_seed();
    let registry = Arc::new(ArmRingRegistry::new(50, &seed));
    let audit_log = Arc::new(SecurityAuditLog::new());
    let engine = DifferentialProtocolEngine::with_containment(Arc::clone(&registry), Arc::clone(&audit_log));

    // Exploits PortSwigger Research CL.0 desync trigger (multipart/byteranges in request)
    let raw_payload = b"POST /api/checkout HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nContent-Type: multipart/byteranges; boundary=SEC_BOUND\r\nContent-Length: 128\r\n\r\n--SEC_BOUND\r\n";

    let report = engine.evaluate_raw_stream(raw_payload).await;

    // 1. Scoring & Decision
    assert!(report.divergence_vector.novelty_score >= 0.65, "Score: {}", report.divergence_vector.novelty_score);
    assert_eq!(report.action, DifferentialAction::QuarantineAndSever);
    assert_eq!(report.quarantined_in_arm, Some(106));
    assert_eq!(report.primary_verdict, "HIGH_DIVERGENCE_NOVEL_ATTACK_QUARANTINED");

    // 2. Authoritative Ring 1 Containment Evidence
    assert_eq!(report.quarantined_generation, Some(1));
    assert!(report.containment_proof_hmac.is_some(), "Cryptographic HMAC containment proof must be present");
    let hmac_hex = report.containment_proof_hmac.unwrap();
    assert_eq!(hmac_hex.len(), 64, "HMAC-SHA256 hex proof must be exactly 64 characters");

    // 3. Immutable Tamper-Evident Audit Record
    assert!(report.audit_record_hash.is_some(), "Audit record hash must be present");
    assert!(report.isolation_details.is_some(), "Isolation constraints details must be present");
    assert!(report.isolation_details.as_ref().unwrap().contains("Windows NT Job Object (64MB) + AppContainer"));

    // 4. Verify in-memory audit log contains the tamper-evident entry
    let records = audit_log.get_entries();
    let quarantine_record = records.iter().find(|r| r.event_type == "DIFFERENTIAL_PROTOCOL_ARM106_QUARANTINE" && r.decision == "PROCESS_ISOLATED");
    assert!(quarantine_record.is_some(), "PROCESS_ISOLATED event must be recorded in SecurityAuditLog");
    let rec = quarantine_record.unwrap();
    assert_eq!(rec.agent_id, "arm-DifferentialProtocolAnalyzer-106");
    assert_eq!(rec.decision, "PROCESS_ISOLATED");
    assert!(rec.details.contains(&hmac_hex));

    // 5. Verify Genuine AppContainer SID format (starts with S-1-15-2-)
    let iso_str = report.isolation_details.unwrap();
    assert!(iso_str.contains("S-1-15-2-"), "Isolation details must contain authentic AppContainer SID: {}", iso_str);
    assert!(iso_str.contains("PID:"), "Isolation details must contain real process PID");

    // 6. Verify Active Process Lifecycle Tracking (Supervisor owns handles; no mem::forget leaks)
    let arm106 = registry.get_ring_or_fail(106).await.unwrap();
    let active_count = arm106.active_quarantines_count().await;
    assert!(active_count >= 1, "Arm 106 must actively own at least 1 quarantined process instance");

    // Cleanly terminate instance by report ID
    let term_res = arm106.terminate_quarantined_instance(&report.report_id).await;
    assert!(term_res.is_ok(), "Supervisor must be able to actively terminate quarantined worker");
    assert_eq!(arm106.active_quarantines_count().await, active_count - 1);
}

#[tokio::test]
async fn test_quarantine_fails_closed_when_worker_is_missing() {
    let non_existent_worker = std::path::PathBuf::from("does_not_exist_worker.exe");
    let job = Arc::new(agent_octopus::security::windows_sandbox::WindowsJobObject::create(
        "TestMissingWorkerJob",
        1,
        64 * 1024 * 1024,
    ).unwrap());

    let res = agent_octopus::security::windows_sandbox::spawn_quarantined_worker_in_job_and_appcontainer(
        &non_existent_worker,
        106,
        "test-missing-1",
        "doc_ingest",
        &job,
    );

    assert!(res.is_err(), "Must fail closed if worker binary is missing");
    let err_str = format!("{:?}", res.err().unwrap());
    assert!(err_str.contains("Zero fallback execution allowed"), "Error was: {}", err_str);
}

#[tokio::test]
async fn test_quarantine_fails_closed_when_arm106_is_severed() {
    let seed = ArmRingRegistry::generate_master_seed();
    let registry = Arc::new(ArmRingRegistry::new(50, &seed));
    let audit_log = Arc::new(SecurityAuditLog::new());
    let engine = DifferentialProtocolEngine::with_containment(Arc::clone(&registry), Arc::clone(&audit_log));

    let raw_payload = b"POST /api/pay HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nTransfer-Encoding: gzip\r\nContent-Length: 60\r\n\r\n";

    // Non-cooperatively sever Arm 106
    registry.sever_arm(106, "Adversarial breach test").await.unwrap();

    // Stream must fail closed with explicit fail-closed verdict
    let report = engine.evaluate_raw_stream(raw_payload).await;
    assert_eq!(report.action, DifferentialAction::QuarantineAndSever);
    assert_eq!(report.primary_verdict, "HIGH_DIVERGENCE_QUARANTINE_FAIL_CLOSED");
    assert!(report.containment_proof_hmac.is_none());

    // Regenerate Arm 106 via supervisor autotomy -> advances to Gen 2
    let new_gen = registry.sever_and_regenerate(106).await.unwrap();
    assert_eq!(new_gen, 2);

    // Re-evaluate: quarantine now executes under active Generation 2
    let report2 = engine.evaluate_raw_stream(raw_payload).await;
    assert_eq!(report2.action, DifferentialAction::QuarantineAndSever);
    assert_eq!(report2.primary_verdict, "HIGH_DIVERGENCE_NOVEL_ATTACK_QUARANTINED");
    assert_eq!(report2.quarantined_generation, Some(2));
    assert!(report2.containment_proof_hmac.is_some());
}

#[tokio::test]
async fn test_quarantined_arm106_cannot_laterally_message_sensitive_arms() {
    let seed = ArmRingRegistry::generate_master_seed();
    let registry = Arc::new(ArmRingRegistry::new(50, &seed));

    let arm106 = registry.get_ring_or_fail(106).await.unwrap();
    let arm1_ledger = registry.get_ring_or_fail(1).await.unwrap();

    // Workload inside Arm 106 attempts lateral escape to Arm 1 (AccountingLedgerWrite)
    let lateral_msg = arm106.sign_mesh_message(
        1,
        1,
        agent_octopus::neural_mesh::MessageKind::Alert,
        "corr-leak-001",
        "ATTEMPTED_LATERAL_LEDGER_WRITE",
    ).await.unwrap();

    // Recipient ring on Arm 1 MUST reject the lateral message from Arm 106
    let verify_res = arm1_ledger.verify_incoming_message(&lateral_msg).await;
    assert!(verify_res.is_err());
    let err = verify_res.unwrap_err();
    assert!(matches!(err, agent_octopus::core::types::OctopusSecurityError::DelegationScopeViolation(_)));
}

#[tokio::test]
async fn test_arm106_memory_clamp_enforcement() {
    let seed = ArmRingRegistry::generate_master_seed();
    let registry = Arc::new(ArmRingRegistry::new(50, &seed));
    let arm106 = registry.get_ring_or_fail(106).await.unwrap();

    // 64MB clamp (64 * 1024 * 1024 = 67,108,864 bytes)
    let oversized_payload_len = 65 * 1024 * 1024;
    let res = arm106.execute_quarantine_containment(
        "diff-oversized",
        "mock-sha256",
        oversized_payload_len,
        0.95,
    ).await;

    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(matches!(err, agent_octopus::core::types::OctopusSecurityError::ResourceQuotaExceeded(_)));
}

#[tokio::test]
async fn test_calibrated_scoring_zero_false_positives_on_complex_legitimate_traffic() {
    let seed = ArmRingRegistry::generate_master_seed();
    let registry = Arc::new(ArmRingRegistry::new(50, &seed));
    let audit_log = Arc::new(SecurityAuditLog::new());
    let engine = DifferentialProtocolEngine::with_containment(Arc::clone(&registry), Arc::clone(&audit_log));

    let legitimate_streams: Vec<&[u8]> = vec![
        // Standard clean GET
        b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nAccept: application/json\r\n\r\n",
        // GET with complex query parameters
        b"GET /api/status?subsystem=Cedar-Policy&format=detailed&limit=50 HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n",
        // POST with legitimate JSON body and exact Content-Length
        b"POST /api/governor/evaluate HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"action\":\"audit_verify\"}",
        // Legal HTTP Range request
        b"GET /static/logo.svg HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nRange: bytes=0-1024\r\nAccept: image/svg+xml\r\n\r\n",
        // Standard submenus
        b"GET /api/breakout/status HTTP/1.1\r\nHost: 127.0.0.1:5005\r\n\r\n",
        b"GET /api/cedar/policies HTTP/1.1\r\nHost: 127.0.0.1:5005\r\n\r\n",
        b"GET /api/containment-rings HTTP/1.1\r\nHost: 127.0.0.1:5005\r\n\r\n",
    ];

    for (i, stream) in legitimate_streams.iter().enumerate() {
        let report = engine.evaluate_raw_stream(stream).await;
        assert!(
            report.divergence_vector.novelty_score < 0.30,
            "False positive on legitimate stream {}: score was {}",
            i, report.divergence_vector.novelty_score
        );
        assert_eq!(
            report.action,
            DifferentialAction::Allow,
            "Legitimate stream {} was not allowed", i
        );
        assert_eq!(report.quarantined_in_arm, None);
        assert_eq!(report.primary_verdict, "CONCORDANT_STREAM_PERMITTED");
    }
}

#[tokio::test]
async fn test_calibrated_scoring_hundred_percent_true_positives_on_novel_attacks() {
    let seed = ArmRingRegistry::generate_master_seed();
    let registry = Arc::new(ArmRingRegistry::new(50, &seed));
    let audit_log = Arc::new(SecurityAuditLog::new());
    let engine = DifferentialProtocolEngine::with_containment(Arc::clone(&registry), Arc::clone(&audit_log));

    let adversarial_streams: Vec<(&'static str, &[u8])> = vec![
        (
            "MultipartByterangesSharedParserConfusion",
            b"POST /api/pay HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nContent-Type: multipart/byteranges; boundary=XYZ\r\nContent-Length: 50\r\n\r\n",
        ),
        (
            "TransferEncodingGzipNovelDesyncTrigger",
            b"POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nTransfer-Encoding: gzip\r\nContent-Length: 30\r\n\r\n",
        ),
        (
            "EarlyDataSmugglingGadget",
            b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nEarly-Data: 1\r\n\r\n",
        ),
        (
            "ContentRangeInRequestSharedParserConfusion",
            b"POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nContent-Range: bytes 0-10/50\r\nContent-Length: 10\r\n\r\n",
        ),
        (
            "ConflictingCLTESmuggling",
            b"POST /api/order HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nContent-Length: 25\r\nTransfer-Encoding: chunked\r\n\r\n",
        ),
    ];

    for (name, stream) in adversarial_streams {
        let report = engine.evaluate_raw_stream(stream).await;
        assert!(
            report.divergence_vector.novelty_score >= 0.65,
            "Failed detection for {}: score was {}", name, report.divergence_vector.novelty_score
        );
        assert_eq!(
            report.action,
            DifferentialAction::QuarantineAndSever,
            "Adversarial stream {} was not quarantined", name
        );
        assert_eq!(report.quarantined_in_arm, Some(106));
        assert!(report.containment_proof_hmac.is_some());
    }
}

#[tokio::test]
async fn test_moderate_divergence_triggers_observe_tier() {
    let engine = DifferentialProtocolEngine::new();

    // Path traversal and normalization divergence
    let path_divergence_stream = b"GET /api/../admin;role=root/keys HTTP/1.1\r\nHost: 127.0.0.1:5005\r\n\r\n";
    let report = engine.evaluate_raw_stream(path_divergence_stream).await;

    assert!(
        report.divergence_vector.novelty_score >= 0.30 && report.divergence_vector.novelty_score < 0.65,
        "Score should be in Observe range [0.30, 0.65), got: {}", report.divergence_vector.novelty_score
    );
    assert_eq!(report.action, DifferentialAction::Observe);
    assert_eq!(report.primary_verdict, "MODERATE_PARSER_DIVERGENCE_OBSERVED");
    assert_eq!(report.quarantined_in_arm, None);
}

#[tokio::test]
async fn test_to_status_dto_reports_live_os_telemetry_without_hardcoding() {
    let seed = ArmRingRegistry::generate_master_seed();
    let registry = Arc::new(ArmRingRegistry::new(50, &seed));
    let arm106 = registry.get_ring_or_fail(106).await.unwrap();

    // 1. Initial Standby state (no active worker process)
    let dto_before = arm106.to_status_dto().await;
    assert_eq!(dto_before.job_object_clamped, false, "Initial standby state must not report clamped");
    assert_eq!(dto_before.appcontainer_sid, "None (No Active OS Process)", "Initial SID must indicate no active OS process");
    assert_eq!(dto_before.os_isolation, "Standby (Pre-allocated Ring Boundary)");

    // 2. Perform quarantine
    let audit_log = Arc::new(SecurityAuditLog::new());
    let engine = DifferentialProtocolEngine::with_containment(Arc::clone(&registry), Arc::clone(&audit_log));
    let raw_payload = b"POST /api/checkout HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nContent-Type: multipart/byteranges; boundary=SEC_BOUND\r\nContent-Length: 128\r\n\r\n--SEC_BOUND\r\n";
    let report = engine.evaluate_raw_stream(raw_payload).await;
    assert_eq!(report.action, DifferentialAction::QuarantineAndSever);

    // 3. Active quarantine state: real live OS telemetry
    let dto_active = arm106.to_status_dto().await;
    assert_eq!(dto_active.job_object_clamped, true, "Active quarantine must report job object clamped");
    assert!(dto_active.appcontainer_sid.starts_with("S-1-15-2-"), "Authentic SID expected: {}", dto_active.appcontainer_sid);
    assert!(dto_active.os_isolation.contains("Windows NT Job Object (64MB) + AppContainer"));
    assert!(dto_active.os_isolation.contains("PID:"));

    // 4. Terminate quarantine: clamps and processes cleaned up
    let term_res = arm106.terminate_quarantined_instance(&report.report_id).await;
    assert!(term_res.is_ok());

    let dto_after = arm106.to_status_dto().await;
    assert_eq!(dto_after.job_object_clamped, false, "After termination, clamped must be false");
    assert_eq!(dto_after.appcontainer_sid, "None (No Active OS Process)");
    assert_eq!(dto_after.os_isolation, "Standby (Pre-allocated Ring Boundary)");
}
