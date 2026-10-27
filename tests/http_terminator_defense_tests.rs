//! Exhaustive Integration & Adversarial Verification Test Suite
//! Testing Agent Octopus defenses against novel HTTP attacks discovered by PortSwigger Research
//! (The HTTP Terminator Arsenal - James Kettle, Black Hat USA / DEF CON 2026).

use agent_octopus::containment_ring::arm_ring::ArmRingRegistry;
use agent_octopus::core::types::ArmRole;
use agent_octopus::security::differential_protocol::{
    DifferentialAction, DifferentialProtocolEngine,
};
use agent_octopus::web::strict_http::{validate_complete_body, validate_header, Signal};

#[tokio::test]
async fn test_shared_parser_confusion_multipart_byteranges_quarantine() {
    let engine = DifferentialProtocolEngine::new();

    // PortSwigger Research primary desync trigger: Content-Type: multipart/byteranges
    // sent in request, exploiting shared request/response parser code (CL.0 desync on >200 sites).
    let raw_payload = b"POST /api/payment HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nContent-Type: multipart/byteranges; boundary=BOUND\r\nContent-Length: 123\r\n\r\n--BOUND\r\n";

    // 1. Strict parser must reject fail-closed
    let strict_res = validate_header(
        &raw_payload[..raw_payload
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap()],
    );
    assert!(strict_res.is_err());
    assert_eq!(
        strict_res.unwrap_err().signal,
        Signal::SharedParserConfusion
    );

    // 2. Differential engine must compute high novelty score and quarantine in Arm 106
    let report = engine.evaluate_raw_stream(raw_payload).await;
    assert!(report.divergence_vector.shared_parser_confusion);
    assert!(
        report.divergence_vector.novelty_score >= 0.70,
        "Score was {}",
        report.divergence_vector.novelty_score
    );
    assert_eq!(report.action, DifferentialAction::QuarantineAndSever);
    assert_eq!(report.quarantined_in_arm, Some(106));
}

#[tokio::test]
async fn test_novel_desync_trigger_transfer_encoding_gzip() {
    let engine = DifferentialProtocolEngine::new();

    // PortSwigger Research trigger: Transfer-Encoding: gzip (CL.0 desync on F5 Big-IP)
    let raw_payload = b"POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nTransfer-Encoding: gzip\r\nContent-Length: 45\r\n\r\n";

    // 1. Strict parser must reject
    let header_pos = raw_payload
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap();
    let strict_res = validate_header(&raw_payload[..header_pos]);
    assert!(strict_res.is_err());
    assert_eq!(
        strict_res.unwrap_err().signal,
        Signal::TransferEncodingPresent
    );

    // 2. Differential engine must detect framing conflict
    let report = engine.evaluate_raw_stream(raw_payload).await;
    assert!(report.divergence_vector.framing_conflict);
    assert_eq!(report.action, DifferentialAction::QuarantineAndSever);
    assert_eq!(report.quarantined_in_arm, Some(106));
}

#[tokio::test]
async fn test_dual_matching_content_length_citrix_sso_exploit() {
    // PortSwigger Research discovery: Dual matching CL headers (Content-Length: 28 + Content-Length: 28)
    // caused Citrix NetScaler and SSO servers to treat body length as 0.
    let raw_payload = b"POST /api/sso HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nContent-Length: 28\r\nContent-Length: 28\r\n\r\n";
    let header_pos = raw_payload
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap();

    let strict_res = validate_header(&raw_payload[..header_pos]);
    assert!(strict_res.is_err());
    assert_eq!(
        strict_res.unwrap_err().signal,
        Signal::DuplicateContentLength
    );
}

#[tokio::test]
async fn test_the_dangling_byte_technique_defense() {
    // PortSwigger Research weaponization technique: holding connection open with 1 dangling byte
    // missing (Content-Length: 3, but client only sent 2 bytes).
    let buffered_body_bytes = 2;
    let expected_content_length = 3;

    // Fail-closed boundary check must instantly reject stalled/dangling byte bodies
    let boundary_res = validate_complete_body(buffered_body_bytes, expected_content_length);
    assert!(boundary_res.is_err());
    assert_eq!(
        boundary_res.unwrap_err().signal,
        Signal::UnexpectedTrailingBytes
    );

    // Exact match must pass
    assert!(validate_complete_body(3, 3).is_ok());
}

#[tokio::test]
async fn test_status_line_injection_cow_protocol_defense() {
    // PortSwigger Research vector: GET / COW< HTTP/1.1 status-line injection
    let status_inj = b"GET / COW< HTTP/1.1\r\nHost: 127.0.0.1:5005";
    let res = validate_header(status_inj);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().signal, Signal::InvalidRequestLine);
}

#[tokio::test]
async fn test_options_asterisk_early_response_gadget_defense() {
    // PortSwigger Research early-response gadget: OPTIONS *?xyz HTTP/1.1
    let gadget = b"OPTIONS *?xyz HTTP/1.1\r\nHost: 127.0.0.1:5005";
    let res = validate_header(gadget);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().signal, Signal::AsteriskUriAnomaly);
}

#[tokio::test]
async fn test_response_forking_desync_correlator_detection() {
    let engine = DifferentialProtocolEngine::new();
    let correlator = engine.correlator();
    let conn_id = correlator.next_connection_id();

    // Register 1 request in flight
    correlator.record_request(conn_id, "req-hash-001").await;

    // First response arrives -> normal pairing
    let event1 = correlator.record_response(conn_id).await;
    assert!(event1.is_none(), "First response is properly paired");

    // Second response arrives for the SAME single request -> Response Forking Anomaly detected!
    let event2 = correlator.record_response(conn_id).await;
    assert!(event2.is_some(), "Response forking must be flagged");
    let anomaly = event2.unwrap();
    assert_eq!(anomaly.anomaly_kind, "ORPHANED_RESPONSE_DESYNC");
    assert_eq!(anomaly.severity, "CRITICAL");
}

#[tokio::test]
async fn test_pipelined_smuggling_residue_tracking() {
    let engine = DifferentialProtocolEngine::new();
    let correlator = engine.correlator();
    let conn_id = correlator.next_connection_id();

    let extra_residue = b"GET /smuggled HTTP/1.1\r\nHost: evil.com\r\n\r\n";
    let residue_event = correlator
        .record_residue(conn_id, extra_residue.len(), extra_residue)
        .await;

    assert_eq!(residue_event.anomaly_kind, "PIPELINED_SMUGGLING_RESIDUE");
    assert!(residue_event
        .details
        .contains(&format!("{} bytes remaining", extra_residue.len())));
    assert_eq!(correlator.total_desync_count(), 1);
}

#[tokio::test]
async fn test_concordant_clean_requests_score_zero_divergence() {
    let engine = DifferentialProtocolEngine::new();
    let clean_req = b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:5005\r\n\r\n";

    let report = engine.evaluate_raw_stream(clean_req).await;
    assert_eq!(report.divergence_vector.novelty_score, 0.0);
    assert_eq!(report.action, DifferentialAction::Allow);
    assert_eq!(report.quarantined_in_arm, None);
    assert_eq!(report.primary_verdict, "CONCORDANT_STREAM_PERMITTED");
}

#[tokio::test]
async fn test_arm_106_sandbox_containment_properties() {
    let seed = ArmRingRegistry::generate_master_seed();
    let registry = ArmRingRegistry::new(50, &seed);

    // Retrieve Arm ID 106 (DifferentialProtocolAnalyzer)
    let arm_ring = registry
        .get_security_ring(ArmRole::DifferentialProtocolAnalyzer)
        .await;
    assert!(
        arm_ring.is_some(),
        "Arm ID 106 containment ring must be registered"
    );

    let ring = arm_ring.unwrap();
    assert_eq!(ring.arm_id, 106);
    assert_eq!(ring.role, ArmRole::DifferentialProtocolAnalyzer);
    assert_eq!(ring.current_generation(), 1);
    assert!(!ring.is_severed());

    // Authoritative execution of Level 1 Ring quarantine operation
    let (hmac_proof, _job_name, _ac_sid, _mem, _pid) = ring
        .execute_quarantine_containment("diff-test-001", "mock-sha256-hash", 512, 0.85)
        .await
        .expect("Quarantine containment must succeed on active Arm 106");
    assert_eq!(hmac_proof.len(), 64, "Containment HMAC must be 64-char hex");
}
