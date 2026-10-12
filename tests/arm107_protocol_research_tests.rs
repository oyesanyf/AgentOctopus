use agent_octopus::containment_ring::arm_ring::ArmRingRegistry;
use agent_octopus::core::types::ArmRole;
use agent_octopus::security::cedar_arm::temporal::DogwoodTemporalEngine;
use agent_octopus::security::cedar_arm::CedarPolicyEngine;
use agent_octopus::security::differential_protocol::DifferentialProtocolEngine;
use agent_octopus::security::protocol_research::{
    Arm106ValidationHandoff, CandidateProbeDto, EvaluationRequest, ProtocolResearchSupervisor,
    RfcIndexSynchronizer, RfcKnowledgeBase,
};
use agent_octopus::security::SecurityAuditLog;
use std::sync::Arc;

#[tokio::test]
async fn test_arm107_dedicated_database_isolation() {
    let temp_dir = std::env::temp_dir().join(format!("octopus_research_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db_path = temp_dir.join("isolated_research.db");

    // Initialize dedicated knowledge base at custom isolated path
    let kb = RfcKnowledgeBase::from_path(&db_path);
    assert_eq!(kb.db_path(), db_path.as_path());

    // Record sample evaluation into the separate DB
    kb.record_evaluation(
        "eval-test-001",
        "probe-001",
        "127.0.0.1",
        5005,
        true,
        "LABORATORY_RESEARCH_FINDING",
        "Chunked Transfer-Encoding differential divergence observed",
        true,
    );

    // Record Arm 106 validation outcome
    kb.record_arm106_validation(
        "val-test-001",
        "eval-test-001",
        "QUARANTINE_SEVER",
        "Proxy (ATS) vs Origin (Go) discrepancy confirmed",
        true,
    );

    let (_, _, _, evals) = kb.get_full_counts();
    assert_eq!(evals, 1, "Evaluation record must persist in isolated database");

    // Clean up test database
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_arm107_cedar_target_allowlist_enforcement() {
    let secret_seed = b"cedar_arm107_test_secret_32bytes_long!";
    let rings = Arc::new(ArmRingRegistry::new(50, secret_seed));
    let cedar = Arc::new(CedarPolicyEngine::default());
    let dogwood = Arc::new(DogwoodTemporalEngine::new_simulation());
    let audit_log = Arc::new(SecurityAuditLog::default());
    let diff_engine = Arc::new(DifferentialProtocolEngine::with_containment(
        Arc::clone(&rings),
        Arc::clone(&audit_log),
    ));

    let supervisor = ProtocolResearchSupervisor::new(rings, cedar, dogwood, diff_engine);

    // Positive Control: Local loopback 127.0.0.1 must be permitted through Cedar Policy 8
    let local_req = EvaluationRequest {
        raw_request: "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n".to_string(),
        target_host: "127.0.0.1".to_string(),
        target_port: 5005,
        baseline_request: Some("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_string()),
    };

    let result = supervisor.evaluate_probe(local_req).await;
    assert!(result.is_ok(), "Local loopback evaluation must be authorized by Cedar Policy 8: {:?}", result.as_ref().err());
    let finding = result.unwrap();
    assert!(finding.is_anomalous, "Chunked and Content-Length conflict must be detected as anomaly");
    assert_eq!(finding.finding_status, "LABORATORY_RESEARCH_FINDING");
    assert!(finding.baseline_subtracted);

    // Negative Control: External host must be blocked fail-closed
    let external_req = EvaluationRequest {
        raw_request: "GET / HTTP/1.1\r\nHost: unauthorized-target.com\r\n\r\n".to_string(),
        target_host: "unauthorized-target.com".to_string(),
        target_port: 80,
        baseline_request: None,
    };

    let ext_result = supervisor.evaluate_probe(external_req).await;
    assert!(ext_result.is_err(), "External host must be rejected fail-closed");
    let err_msg = format!("{}", ext_result.unwrap_err());
    assert!(
        err_msg.contains("not authorized by Cedar Policy 8") || err_msg.contains("FAIL-CLOSED"),
        "Error message must specify Cedar allowlist rejection: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_arm107_handoff_to_arm106_differential_engine() {
    let secret_seed = b"cedar_arm107_handoff_test_seed_32bytes!";
    let rings = Arc::new(ArmRingRegistry::new(50, secret_seed));
    let cedar = Arc::new(CedarPolicyEngine::default());
    let dogwood = Arc::new(DogwoodTemporalEngine::new_simulation());
    let audit_log = Arc::new(SecurityAuditLog::default());
    let diff_engine = Arc::new(DifferentialProtocolEngine::with_containment(
        Arc::clone(&rings),
        Arc::clone(&audit_log),
    ));

    let supervisor = ProtocolResearchSupervisor::new(rings, cedar, dogwood, diff_engine);

    let handoff = Arm106ValidationHandoff {
        handoff_id: "handoff-unit-001".to_string(),
        finding_id: "eval-unit-001".to_string(),
        candidate_probe: CandidateProbeDto {
            id: "probe-candidate-001".to_string(),
            rfc_number: 7230,
            raw_request: "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: \tchunked\r\n\r\n0\r\n\r\n".to_string(),
            mutation_type: "tab_prefixed_chunked".to_string(),
            hypothesis: "Proxy parses single header while backend parses second header".to_string(),
            status: "CANDIDATE".to_string(),
        },
        preliminary_tier: "LABORATORY_RESEARCH_FINDING".to_string(),
        requires_independent_reproduction: true,
        target_endpoints: vec!["http://127.0.0.1:8080".to_string(), "http://127.0.0.1:8081".to_string()],
    };

    let report = supervisor.handoff_to_arm106(handoff).await;
    assert!(report.is_ok(), "Handoff to Arm 106 differential engine must complete");
    let diff_report = report.unwrap();
    assert!(!diff_report.report_id.is_empty());
    assert!(!diff_report.primary_verdict.is_empty());
}

#[tokio::test]
async fn test_arm107_containment_ring_allocation() {
    let secret_seed = b"cedar_ring107_test_seed_32bytes!";
    let rings = ArmRingRegistry::new(50, secret_seed);

    let ring = rings.get_ring(107).await;
    assert!(ring.is_some(), "Ring #107 must be pre-allocated in registry");
    let ring_arc = ring.unwrap();
    assert_eq!(ring_arc.role, ArmRole::AutonomousProtocolResearch);
    assert_eq!(ring_arc.arm_id, 107);
}

#[tokio::test]
async fn test_arm107_rfc_index_synchronization() {
    let temp_dir = std::env::temp_dir().join(format!("octopus_sync_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db_path = temp_dir.join("sync_research.db");

    let kb = Arc::new(RfcKnowledgeBase::from_path(&db_path));
    let sync = RfcIndexSynchronizer::new(Arc::clone(&kb));

    let report = sync.sync_index().await.expect("Sync pass must succeed");
    assert!(report.total_rfcs_in_db > 0, "Synchronizer must index RFC specifications");
    assert!(report.fragments_indexed > 0, "Synchronizer must extract normative statements");
    assert_eq!(report.status, "SYNCHRONIZATION_SUCCESSFUL");

    let _ = std::fs::remove_dir_all(&temp_dir);
}
