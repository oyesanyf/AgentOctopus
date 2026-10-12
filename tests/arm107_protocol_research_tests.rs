use agent_octopus::containment_ring::arm_ring::ArmRingRegistry;
use agent_octopus::core::types::ArmRole;
use agent_octopus::security::cedar_arm::temporal::DogwoodTemporalEngine;
use agent_octopus::security::cedar_arm::CedarPolicyEngine;
use agent_octopus::security::differential_protocol::DifferentialProtocolEngine;
use agent_octopus::security::protocol_research::{
    Arm106ValidationHandoff, CandidateProbeDto, EvaluationRequest, ProtocolResearchSupervisor,
    RfcIndexSynchronizer, RfcKnowledgeBase, TransportOutcome,
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("Bind test listener");
    let test_port = listener.local_addr().expect("Get local addr").port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                if let Ok(n) = stream.read(&mut buf).await {
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.contains("Transfer-Encoding: chunked") && req.contains("Content-Length:") {
                        let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
                    } else {
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK").await;
                    }
                }
            }
        }
    });

    let local_req = EvaluationRequest {
        raw_request: "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n".to_string(),
        target_host: "127.0.0.1".to_string(),
        target_port: test_port,
        baseline_request: Some("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_string()),
        repetition_count: None,
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
        repetition_count: None,
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

#[tokio::test]
async fn test_arm107_destination_egress_and_dns_rebinding_defense() {
    let secret_seed = b"cedar_arm107_boundary_test_32bytes!";
    let rings = Arc::new(ArmRingRegistry::new(50, secret_seed));
    let cedar = Arc::new(CedarPolicyEngine::default());
    let dogwood = Arc::new(DogwoodTemporalEngine::new_simulation());
    let audit_log = Arc::new(SecurityAuditLog::default());
    let diff_engine = Arc::new(DifferentialProtocolEngine::with_containment(
        Arc::clone(&rings),
        Arc::clone(&audit_log),
    ));
    let supervisor = ProtocolResearchSupervisor::new(rings, cedar, dogwood, diff_engine);

    // 1. Authorized loopback target must resolve and pass
    let valid_dest = supervisor.validate_and_resolve_destination("127.0.0.1", 5005);
    assert!(valid_dest.is_ok(), "127.0.0.1 loopback must resolve");
    assert!(valid_dest.unwrap().ip().is_loopback());

    // 2. Localhost alias must resolve and pass
    let localhost_dest = supervisor.validate_and_resolve_destination("localhost", 5005);
    assert!(localhost_dest.is_ok(), "localhost loopback must resolve");
    assert!(localhost_dest.unwrap().ip().is_loopback());

    // 3. Link-local cloud metadata (169.254.169.254) must be blocked fail-closed
    let metadata_dest = supervisor.validate_and_resolve_destination("169.254.169.254", 80);
    assert!(metadata_dest.is_err(), "Cloud metadata destination must be rejected");

    // 4. Non-standard dword/integer IP format (2130706433) must be blocked fail-closed
    let dword_dest = supervisor.validate_and_resolve_destination("2130706433", 80);
    assert!(dword_dest.is_err(), "Dword-encoded IP must be rejected");

    // 5. Port 0 must be rejected
    let port0_dest = supervisor.validate_and_resolve_destination("127.0.0.1", 0);
    assert!(port0_dest.is_err(), "Port 0 must be rejected");
}

#[tokio::test]
async fn test_arm107_structured_transport_outcomes_no_synthetic_http() {
    let secret_seed = b"cedar_arm107_transport_seed_32bytes";
    let rings = Arc::new(ArmRingRegistry::new(50, secret_seed));
    let cedar = Arc::new(CedarPolicyEngine::default());
    let dogwood = Arc::new(DogwoodTemporalEngine::new_simulation());
    let audit_log = Arc::new(SecurityAuditLog::default());
    let diff_engine = Arc::new(DifferentialProtocolEngine::with_containment(
        Arc::clone(&rings),
        Arc::clone(&audit_log),
    ));
    let supervisor = ProtocolResearchSupervisor::new(rings, cedar, dogwood, diff_engine);

    // Negative connection: closed port (e.g. port 19876)
    // Must return ConnectionRefused and raw_response must be EMPTY (NO synthetic 502/504 HTTP string)
    let closed_port_req = EvaluationRequest {
        raw_request: "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_string(),
        target_host: "127.0.0.1".to_string(),
        target_port: 19876,
        baseline_request: None,
        repetition_count: None,
    };

    let result = supervisor.evaluate_probe(closed_port_req).await;
    assert!(result.is_ok(), "Evaluation must execute and return structured outcome");
    let finding = result.unwrap();

    // Verify structured transport outcome
    assert!(matches!(finding.transport_outcome, TransportOutcome::ConnectionRefused { .. }));
    // Verify raw_response does NOT contain fabricated HTTP status lines
    assert!(!finding.raw_response.contains("HTTP/1.1 504 Gateway Timeout"), "Must NOT synthesize 504 response");
    assert!(!finding.raw_response.contains("HTTP/1.1 502 Bad Gateway"), "Must NOT synthesize 502 response");
    assert_eq!(finding.raw_response, "", "Failed connection must leave actual received bytes empty");
}

#[tokio::test]
async fn test_arm107_differential_baseline_response_comparison() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Spin up a genuine loopback TCP server for protocol research differential testing
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("Bind test listener");
    let server_addr = listener.local_addr().expect("Get local addr");
    let port = server_addr.port();

    // Handle incoming connections: baseline gets 200 OK, probe gets 400 Bad Request
    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                if let Ok(n) = stream.read(&mut buf).await {
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.contains("Transfer-Encoding: chunked") && req.contains("Content-Length:") {
                        let resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 15\r\n\r\nFraming Conflict";
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else {
                        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                        let _ = stream.write_all(resp.as_bytes()).await;
                    }
                }
            }
        }
    });

    let secret_seed = b"cedar_arm107_diff_seed_32bytes_long!";
    let rings = Arc::new(ArmRingRegistry::new(50, secret_seed));
    let cedar = Arc::new(CedarPolicyEngine::default());
    let dogwood = Arc::new(DogwoodTemporalEngine::new_simulation());
    let audit_log = Arc::new(SecurityAuditLog::default());
    let diff_engine = Arc::new(DifferentialProtocolEngine::with_containment(
        Arc::clone(&rings),
        Arc::clone(&audit_log),
    ));
    let supervisor = ProtocolResearchSupervisor::new(rings, cedar, dogwood, diff_engine);

    let eval_req = EvaluationRequest {
        raw_request: "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n".to_string(),
        target_host: "127.0.0.1".to_string(),
        target_port: port,
        baseline_request: Some("POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n".to_string()),
        repetition_count: None,
    };

    let result = supervisor.evaluate_probe(eval_req).await;
    assert!(result.is_ok(), "Differential probe evaluation must succeed: {:?}", result.as_ref().err());
    let finding = result.unwrap();

    assert!(finding.is_anomalous, "Divergence between baseline (200) and probe (400) must be detected");
    assert!(finding.baseline_subtracted, "Baseline subtraction must be flagged as active");
    assert!(matches!(finding.transport_outcome, TransportOutcome::ResponseReceived { .. }));
    assert!(finding.raw_response.contains("HTTP/1.1 400 Bad Request"));
    assert!(finding.baseline_response.as_ref().unwrap().contains("HTTP/1.1 200 OK"));
    assert_eq!(finding.confirmation_count, 2, "Reproducible divergence must have confirmation count of 2");
}

#[tokio::test]
async fn test_arm107_transient_non_reproducible_anomaly_downgrade() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Server returns divergent response on 1st request, but concordant response on repeat request
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("Bind test listener");
    let server_addr = listener.local_addr().expect("Get local addr");
    let port = server_addr.port();
    let probe_attempts = Arc::new(AtomicUsize::new(0));
    let attempts_clone = Arc::clone(&probe_attempts);

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                if let Ok(n) = stream.read(&mut buf).await {
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.contains("X-Transient-Test:") {
                        let count = attempts_clone.fetch_add(1, Ordering::SeqCst);
                        if count == 0 {
                            // First attempt: trigger transient divergence
                            let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nError";
                            let _ = stream.write_all(resp.as_bytes()).await;
                        } else {
                            // Repeat confirmation: converges with baseline 200 OK
                            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                    } else {
                        // Baseline response
                        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                        let _ = stream.write_all(resp.as_bytes()).await;
                    }
                }
            }
        }
    });

    let secret_seed = b"cedar_arm107_transient_seed_32b!";
    let rings = Arc::new(ArmRingRegistry::new(50, secret_seed));
    let cedar = Arc::new(CedarPolicyEngine::default());
    let dogwood = Arc::new(DogwoodTemporalEngine::new_simulation());
    let audit_log = Arc::new(SecurityAuditLog::default());
    let diff_engine = Arc::new(DifferentialProtocolEngine::with_containment(
        Arc::clone(&rings),
        Arc::clone(&audit_log),
    ));
    let supervisor = ProtocolResearchSupervisor::new(rings, cedar, dogwood, diff_engine);

    let eval_req = EvaluationRequest {
        raw_request: "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Transient-Test: 1\r\n\r\n".to_string(),
        target_host: "127.0.0.1".to_string(),
        target_port: port,
        baseline_request: Some("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_string()),
        repetition_count: None,
    };

    let result = supervisor.evaluate_probe(eval_req).await;
    assert!(result.is_ok(), "Evaluation must execute");
    let finding = result.unwrap();

    // Verification: Transient non-reproducible divergence must be downgraded!
    assert!(!finding.is_anomalous, "Non-reproducible anomaly must be downgraded to is_anomalous: false");
    assert_eq!(finding.finding_status, "NON_REPRODUCIBLE_TRANSIENT", "Status must be downgraded to NON_REPRODUCIBLE_TRANSIENT");
    assert!(finding.details.contains("Downgraded"), "Details must explain downgrade due to failed reproducibility");
}

#[tokio::test]
async fn test_arm107_rfc_sync_transactional_deduplication() {
    let temp_dir = std::env::temp_dir().join(format!("octopus_dedup_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db_path = temp_dir.join("dedup_research.db");

    let kb = Arc::new(RfcKnowledgeBase::from_path(&db_path));
    let sync = RfcIndexSynchronizer::new(Arc::clone(&kb));

    // First synchronization pass
    let report1 = sync.sync_index().await.expect("1st sync pass");
    let initial_frags = report1.fragments_indexed;
    assert!(initial_frags > 0, "Fragments must be indexed on first pass");

    // Second synchronization pass (must NOT duplicate fragments!)
    let _report2 = sync.sync_index().await.expect("2nd sync pass");
    let (_, total_frags_after_second_sync, _, _) = kb.get_full_counts();

    assert_eq!(
        total_frags_after_second_sync, initial_frags,
        "Repeated sync must deduplicate fragments transactionally: expected {}, found {}",
        initial_frags, total_frags_after_second_sync
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_arm107_worker_packaging_validation_and_fail_closed() {
    use agent_octopus::security::protocol_research::PythonWorkerBridge;
    use std::path::PathBuf;

    // 1. Valid worker directory validation
    let valid_dir = PathBuf::from("vendor").join("rfchunt");
    if valid_dir.exists() {
        let hash_res = PythonWorkerBridge::validate_worker_packaging(&valid_dir);
        assert!(hash_res.is_ok(), "Managed worker packaging validation must succeed: {:?}", hash_res.err());
        let hash = hash_res.unwrap();
        assert_eq!(hash.len(), 64, "SHA-256 hash must be 64 hexadecimal characters");
    }

    // 2. Corrupt / Missing worker directory must fail closed
    let invalid_dir = PathBuf::from("nonexistent_worker_directory_xyz");
    let corrupt_res = PythonWorkerBridge::validate_worker_packaging(&invalid_dir);
    assert!(corrupt_res.is_err(), "Non-existent directory must fail closed");

    // 3. Incomplete packaging (missing required dependencies) must fail closed
    let temp_incomplete = std::env::temp_dir().join(format!("incomplete_worker_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_incomplete);
    let _ = std::fs::write(temp_incomplete.join("mcp_server.py"), "#!/usr/bin/env python3\nprint('hello')\n");
    // Missing database.py, rfc_chunker.py, rfc_fetcher.py
    let incomplete_res = PythonWorkerBridge::validate_worker_packaging(&temp_incomplete);
    assert!(incomplete_res.is_err(), "Worker directory with missing modules must fail closed");
    let _ = std::fs::remove_dir_all(&temp_incomplete);
}

#[tokio::test]
async fn test_arm107_multi_trial_repetition_stable_baseline_and_arm106_confirmation() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("Bind test listener");
    let test_port = listener.local_addr().expect("Get local addr").port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                if let Ok(n) = stream.read(&mut buf).await {
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.contains("Transfer-Encoding: chunked") && req.contains("Content-Length:") {
                        let resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 16\r\n\r\nFraming Anomaly!";
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else {
                        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                        let _ = stream.write_all(resp.as_bytes()).await;
                    }
                }
            }
        }
    });

    let secret_seed = b"cedar_arm107_multi_trial_seed_32";
    let rings = Arc::new(ArmRingRegistry::new(50, secret_seed));
    let cedar = Arc::new(CedarPolicyEngine::default());
    let dogwood = Arc::new(DogwoodTemporalEngine::new_simulation());
    let audit_log = Arc::new(SecurityAuditLog::default());
    let diff_engine = Arc::new(DifferentialProtocolEngine::with_containment(
        Arc::clone(&rings),
        Arc::clone(&audit_log),
    ));
    let supervisor = ProtocolResearchSupervisor::new(rings, cedar, dogwood, diff_engine);

    // Configure 5 repeated trials with baseline request
    let eval_req = EvaluationRequest {
        raw_request: "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n".to_string(),
        target_host: "127.0.0.1".to_string(),
        target_port: test_port,
        baseline_request: Some("POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n".to_string()),
        repetition_count: Some(5),
    };

    let result = supervisor.evaluate_probe(eval_req).await;
    assert!(result.is_ok(), "Multi-trial evaluation must succeed: {:?}", result.as_ref().err());
    let finding = result.unwrap();

    assert!(finding.is_anomalous, "Anomaly must be detected across trials");
    assert_eq!(finding.total_trials, 5, "Total trials must equal requested 5");
    assert_eq!(finding.confirmation_count, 5, "All 5 trials must confirm the anomaly");
    assert!(finding.baseline_stable, "Baseline response must be confirmed stable across all 5 trials");
    assert!((finding.reproducibility_rate - 1.0).abs() < 1e-6, "Reproducibility rate must be 100%");
    assert!(finding.ci95_low > 0.40, "95% confidence interval lower bound must be positive");
    assert!(finding.ci95_high <= 1.0, "95% confidence interval upper bound must be <= 1.0");
    assert!(finding.arm106_validated, "Arm 106 differential analysis must validate the framing anomaly");
    assert_eq!(
        finding.finding_status,
        "CONFIRMED_VULNERABILITY",
        "Finding must be classified as CONFIRMED_VULNERABILITY after 5 trials, stable baseline, and Arm 106 validation"
    );
    assert!(finding.details.contains("CONFIRMED VULNERABILITY"));
}

#[test]
fn test_rfc_http_response_parsing_and_chunked_body_decoding() {
    use agent_octopus::security::protocol_research::{
        chunk_rfc_content, decode_chunked_body, parse_http_wire_response,
    };

    // 1. Multiple header blocks (e.g. 100 Continue preceding 200 OK)
    let multi_block = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nHello, World!";
    let (status, headers, body) = parse_http_wire_response(multi_block);
    assert_eq!(status, 200, "Must extract 200 OK from secondary header block");
    assert_eq!(headers.get("content-type"), Some(&"text/plain".to_string()));
    assert_eq!(headers.get("content-length"), Some(&"13".to_string()));
    assert_eq!(body, "Hello, World!");

    // 2. HTTP/1.1 Chunked Transfer-Encoding wire stream
    let chunked_stream = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nWiki\r\n6;ext=foo\r\npedia \r\n0\r\n\r\n";
    let (chunk_status, chunk_headers, chunk_body) = parse_http_wire_response(chunked_stream);
    assert_eq!(chunk_status, 200);
    assert_eq!(chunk_headers.get("transfer-encoding"), Some(&"chunked".to_string()));
    assert_eq!(chunk_body, "Wikipedia ");

    // 3. Raw decode_chunked_body unit verification
    let raw_chunks = "5\r\nAgent\r\n8\r\n Octopus\r\n0\r\n\r\n";
    let decoded = decode_chunked_body(raw_chunks);
    assert_eq!(decoded, "Agent Octopus");

    // 4. RFC normative chunking with RFC 2119 keywords
    let sample_rfc = "This is a non-normative introduction paragraph.\n\nAn HTTP server MUST NOT send a Content-Length header with chunked transfer.\n\nClients SHOULD close connections when timeouts occur.";
    let chunks = chunk_rfc_content(9112, "HTTP/1.1", sample_rfc, 2000);
    assert_eq!(chunks.len(), 1, "Short RFC must produce 1 chunk");
    assert!(chunks[0].2, "Chunk with MUST NOT and SHOULD must be flagged as normative");
}


