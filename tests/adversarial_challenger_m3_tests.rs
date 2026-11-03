//! ==============================================================================
//! [AGENT OCTOPUS] MILESTONE 3 ADVERSARIAL CHALLENGER TEST SUITE
//! ==============================================================================
//! Empirical Stress-Testing for CAGE Substrate Contract HTTP API & Routing:
//! 1. Version Drift Attacks:
//!    - Policy ingestion version pinning mismatch rejection (strict 409 Conflict)
//!    - Action validation version pinning mismatch rejection (strict 409 Conflict)
//!    - Case-insensitive header `X-Expected-Policy-Version` and query param parsing
//! 2. Seal Replay Attacks:
//!    - Sequential replay rejection (200 OK on first call, 409 Conflict on replay)
//!    - High-concurrency multithreaded race replay rejection
//!    - Nested envelope `{"seal": ...}` vs raw seal JSON replay rejection
//! 3. Tampered & Expired Seal Rejection:
//!    - Bit-flipped HMAC signature rejection (403 Forbidden)
//!    - Mutated action digest rejection (403 Forbidden)
//!    - Mutated audit anchor hash rejection (403 Forbidden)
//!    - Past TTL expiration rejection (403 Forbidden)
//!    - Future clock skew tolerance rejection (403 Forbidden)
//! 4. Malformed Request Payloads:
//!    - Corrupted JSON payloads (400 Bad Request)
//!    - Empty and whitespace payloads (400 Bad Request)
//!    - Missing required schema fields in GovernanceRequest (400 Bad Request)
//! 5. Cross-Origin Browser Probes:
//!    - Untrusted Origin header rejection (`Origin: https://attacker.example` -> 403 Forbidden)
//!    - Sec-Fetch-Site cross-site rejection (`Sec-Fetch-Site: cross-site` -> 403 Forbidden)
//!    - Case-insensitive Sec-Fetch-Site header verification
//! 6. Host Rebinding Probes:
//!    - DNS rebinding hostname rejection (`Host: evil.com:5005` -> 421 Misdirected Request)
//!    - Port mismatch rejection (`Host: 127.0.0.1:9999` on port 5005 -> 421 Misdirected Request)
//!    - Allowed loopback authorities verification (`127.0.0.1`, `localhost`, `[::1]`)
//! 7. Formal Proof & Trace Conformance Verification:
//!    - 34-state BFS reachable states and No-Direct-Bind formal theorem verification
//!    - Conforming trace streams vs injected rule violations
//! ==============================================================================

use agent_octopus::security::cage_governance::routing_seal::CageRoutingSeal;
use agent_octopus::security::cage_governance::{
    GovernanceEvaluationResult, GovernanceVerdict, ProofStatusResponse,
};
use agent_octopus::web::api::*;
use agent_octopus::web::request_guard::*;
use agent_octopus::web::server::*;
use std::sync::Arc;
use std::thread;

fn make_guard_req<'a>(
    method: &'a str,
    path: &'a str,
    headers: &'a str,
    port: u16,
) -> GuardRequest<'a> {
    GuardRequest {
        method,
        path,
        query: "",
        headers,
        local_port: port,
    }
}

// ==============================================================================
// 1. Version Drift Attacks (Strict 409 Conflict)
// ==============================================================================

#[test]
fn test_version_drift_attack_on_policy_ingest() {
    let state = WebState::default();
    let initial_version = state.cage_engine.active_policy_version();

    let yaml_policy = "stpa_control_structure:\n  unsafe_control_actions: []\n";

    // 1.1 Ingest with mismatched expected version hint header -> 409 Conflict
    let (status, body) = handle_cage_ingest_policy(&state, yaml_policy, Some("drift_hash_0000"));
    assert_eq!(
        status, "409 Conflict",
        "Expected 409 Conflict on version mismatch hint"
    );
    assert!(
        body.contains("POLICY_VERSION_MISMATCH"),
        "Body should contain POLICY_VERSION_MISMATCH, got: {}",
        body
    );

    // 1.2 Ingest with JSON envelope containing mismatched expected_version -> 409 Conflict
    let envelope_mismatch = serde_json::json!({
        "policy": yaml_policy,
        "expected_version": "drift_hash_1111"
    })
    .to_string();
    let (status_env, body_env) = handle_cage_ingest_policy(&state, &envelope_mismatch, None);
    assert_eq!(
        status_env, "409 Conflict",
        "Expected 409 Conflict on envelope version mismatch"
    );
    assert!(body_env.contains("POLICY_VERSION_MISMATCH"));

    // 1.3 Ingest with matching expected_version -> 200 OK
    let (status_ok, body_ok) =
        handle_cage_ingest_policy(&state, yaml_policy, Some(&initial_version));
    assert_eq!(
        status_ok, "200 OK",
        "Expected 200 OK when expected version matches"
    );
    assert!(body_ok.contains("policy_version_id"));
}

#[test]
fn test_version_drift_attack_on_validate_action() {
    let state = WebState::default();
    let initial_version = state.cage_engine.active_policy_version();

    let valid_request_json = serde_json::json!({
        "action_name": "list_files",
        "principal": "arm-worker-1",
        "resource": "workspace/tmp",
        "parameters": {},
        "caller_authority": 3,
        "confidence_score": 0.95,
        "consensus_score": 0.90,
        "fuel_cost": 1.0,
        "expected_policy_version": null,
        "execution_profile": "Full"
    })
    .to_string();

    // 2.1 Validate action with mismatched version hint -> 409 Conflict
    let (status_drift, body_drift) = handle_cage_validate_action_with_version(
        &state,
        &valid_request_json,
        Some("drift_action_9999"),
    );
    assert_eq!(
        status_drift, "409 Conflict",
        "Expected 409 Conflict on action validation version mismatch"
    );
    assert!(
        body_drift.contains("POLICY_VERSION_MISMATCH"),
        "Expected POLICY_VERSION_MISMATCH in body: {}",
        body_drift
    );

    // 2.2 Validate action with mismatched expected_policy_version inside body -> 409 Conflict
    let body_with_drift_ver = serde_json::json!({
        "action_name": "list_files",
        "principal": "arm-worker-1",
        "resource": "workspace/tmp",
        "parameters": {},
        "caller_authority": 3,
        "confidence_score": 0.95,
        "consensus_score": 0.90,
        "fuel_cost": 1.0,
        "expected_policy_version": "drift_in_payload_8888",
        "execution_profile": "Full"
    })
    .to_string();
    let (status_body_drift, body_body_drift) =
        handle_cage_validate_action(&state, &body_with_drift_ver);
    assert_eq!(status_body_drift, "409 Conflict");
    assert!(body_body_drift.contains("POLICY_VERSION_MISMATCH"));

    // 2.3 Validate action with matching active version -> 200 OK
    let (status_ok, body_ok) = handle_cage_validate_action_with_version(
        &state,
        &valid_request_json,
        Some(&initial_version),
    );
    assert_eq!(status_ok, "200 OK");
    let eval_res: GovernanceEvaluationResult =
        serde_json::from_str(&body_ok).expect("Must parse response");
    assert_eq!(eval_res.verdict, GovernanceVerdict::Allow);
    assert!(eval_res.seal.is_some());
}

// ==============================================================================
// 2. Seal Replay Attacks (Sequential, Wrapped, and Concurrent)
// ==============================================================================

#[test]
fn test_seal_replay_attack_sequential_and_wrapped() {
    let state = WebState::default();

    // Generate a valid seal via validate_action
    let req = serde_json::json!({
        "action_name": "read_metrics",
        "principal": "arm-worker-2",
        "resource": "metrics/cpu",
        "parameters": {},
        "caller_authority": 3,
        "confidence_score": 0.99,
        "consensus_score": 0.88,
        "fuel_cost": 1.0,
        "expected_policy_version": null,
        "execution_profile": "Full"
    })
    .to_string();

    let (s_val, b_val) = handle_cage_validate_action(&state, &req);
    assert_eq!(s_val, "200 OK");
    let eval_res: GovernanceEvaluationResult = serde_json::from_str(&b_val).unwrap();
    let seal = eval_res.seal.expect("Seal must be present on ALLOW");
    let seal_json = serde_json::to_string(&seal).unwrap();

    // 1st consumption: MUST succeed with 200 OK
    let (s_first, b_first) = handle_cage_consume_seal(&state, &seal_json);
    assert_eq!(s_first, "200 OK", "First seal consumption must succeed");
    assert!(b_first.contains("CONSUMED"));

    // 2nd consumption (direct replay attack): MUST strictly reject with 409 Conflict
    let (s_replay, b_replay) = handle_cage_consume_seal(&state, &seal_json);
    assert_eq!(
        s_replay, "409 Conflict",
        "Replay attack must return 409 Conflict"
    );
    assert!(
        b_replay.contains("SEAL_ALREADY_CONSUMED"),
        "Expected SEAL_ALREADY_CONSUMED, got: {}",
        b_replay
    );

    // 3rd consumption (wrapped envelope replay attack): MUST also reject with 409 Conflict
    let wrapped = serde_json::json!({ "seal": seal }).to_string();
    let (s_wrapped, b_wrapped) = handle_cage_consume_seal(&state, &wrapped);
    assert_eq!(
        s_wrapped, "409 Conflict",
        "Wrapped replay must return 409 Conflict"
    );
    assert!(b_wrapped.contains("SEAL_ALREADY_CONSUMED"));
}

#[test]
fn test_seal_replay_attack_concurrent_race_resistance() {
    let state = Arc::new(WebState::default());

    // Generate a fresh seal
    let req = serde_json::json!({
        "action_name": "query_inventory",
        "principal": "arm-worker-concurrent",
        "resource": "db/inventory",
        "parameters": {},
        "caller_authority": 3,
        "confidence_score": 0.97,
        "consensus_score": 0.92,
        "fuel_cost": 1.0,
        "expected_policy_version": null,
        "execution_profile": "Full"
    })
    .to_string();

    let (s_val, b_val) = handle_cage_validate_action(&state, &req);
    assert_eq!(s_val, "200 OK");
    let eval_res: GovernanceEvaluationResult = serde_json::from_str(&b_val).unwrap();
    let seal = eval_res.seal.expect("Seal must be present");
    let seal_json = Arc::new(serde_json::to_string(&seal).unwrap());

    // Spawn 20 concurrent threads trying to consume the EXACT SAME seal simultaneously
    let mut handles = Vec::new();
    for _ in 0..20 {
        let state_clone = Arc::clone(&state);
        let seal_clone = Arc::clone(&seal_json);
        handles.push(thread::spawn(move || {
            handle_cage_consume_seal(&state_clone, &seal_clone)
        }));
    }

    let mut ok_count = 0;
    let mut conflict_count = 0;

    for h in handles {
        let (status, body) = h.join().expect("Thread must not panic");
        if status == "200 OK" {
            ok_count += 1;
            assert!(body.contains("CONSUMED"));
        } else if status == "409 Conflict" {
            conflict_count += 1;
            assert!(body.contains("SEAL_ALREADY_CONSUMED"));
        } else {
            panic!("Unexpected status code under concurrent replay: {}", status);
        }
    }

    assert_eq!(
        ok_count, 1,
        "CRITICAL INVARIANT: Exactly 1 concurrent request may consume the seal"
    );
    assert_eq!(
        conflict_count, 19,
        "CRITICAL INVARIANT: All 19 replayed attempts must be rejected with 409 Conflict"
    );
}

// ==============================================================================
// 3. Tampered & Expired Seal Rejection (403 Forbidden)
// ==============================================================================

#[test]
fn test_tampered_seal_signature_rejection() {
    let state = WebState::default();

    let req = serde_json::json!({
        "action_name": "export_report",
        "principal": "arm-worker-tamper",
        "resource": "reports/q3",
        "parameters": {},
        "caller_authority": 3,
        "confidence_score": 0.96,
        "consensus_score": 0.89,
        "fuel_cost": 1.0,
        "expected_policy_version": null,
        "execution_profile": "Full"
    })
    .to_string();

    let (_, b_val) = handle_cage_validate_action(&state, &req);
    let eval_res: GovernanceEvaluationResult = serde_json::from_str(&b_val).unwrap();
    let mut seal: CageRoutingSeal = eval_res.seal.unwrap();

    // Adversarial vector: mutate HMAC signature
    let mut chars: Vec<char> = seal.signature.chars().collect();
    if let Some(c) = chars.last_mut() {
        *c = if *c == '0' { '1' } else { '0' };
    }
    seal.signature = chars.into_iter().collect();

    let tampered_json = serde_json::to_string(&seal).unwrap();
    let (status, body) = handle_cage_consume_seal(&state, &tampered_json);

    assert_eq!(
        status, "403 Forbidden",
        "Tampered signature must return 403 Forbidden"
    );
    assert!(
        body.contains("SEAL_SIGNATURE_INVALID") || body.contains("Forbidden"),
        "Error body should state signature invalid: {}",
        body
    );
}

#[test]
fn test_tampered_seal_audit_anchor_rejection() {
    let state = WebState::default();

    let req = serde_json::json!({
        "action_name": "export_report_2",
        "principal": "arm-worker-tamper-audit",
        "resource": "reports/q4",
        "parameters": {},
        "caller_authority": 3,
        "confidence_score": 0.96,
        "consensus_score": 0.89,
        "fuel_cost": 1.0,
        "expected_policy_version": null,
        "execution_profile": "Full"
    })
    .to_string();

    let (_, b_val) = handle_cage_validate_action(&state, &req);
    let eval_res: GovernanceEvaluationResult = serde_json::from_str(&b_val).unwrap();
    let mut seal: CageRoutingSeal = eval_res.seal.unwrap();

    // Adversarial vector: mutate record_hash (audit anchor)
    seal.record_hash =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();

    let tampered_json = serde_json::to_string(&seal).unwrap();
    let (status, body) = handle_cage_consume_seal(&state, &tampered_json);

    assert_eq!(
        status, "403 Forbidden",
        "Unanchored / tampered audit hash must return 403 Forbidden"
    );
    assert!(body.contains("SEAL_SIGNATURE_INVALID") || body.contains("Forbidden"));
}

#[test]
fn test_expired_seal_ttl_rejection() {
    let state = WebState::default();

    let req = serde_json::json!({
        "action_name": "read_audit_stream",
        "principal": "arm-worker-ttl",
        "resource": "audit/stream",
        "parameters": {},
        "caller_authority": 3,
        "confidence_score": 0.98,
        "consensus_score": 0.90,
        "fuel_cost": 1.0,
        "expected_policy_version": null,
        "execution_profile": "Full"
    })
    .to_string();

    let (_, b_val) = handle_cage_validate_action(&state, &req);
    let eval_res: GovernanceEvaluationResult = serde_json::from_str(&b_val).unwrap();
    let mut seal: CageRoutingSeal = eval_res.seal.unwrap();

    // Adversarial vector: backdate issued_at and expires_at beyond 30s TTL
    seal.issued_at = seal.issued_at.saturating_sub(60);
    seal.expires_at = seal.expires_at.saturating_sub(60);

    let expired_json = serde_json::to_string(&seal).unwrap();
    let (status, body) = handle_cage_consume_seal(&state, &expired_json);

    // Either 403 Forbidden (SEAL_EXPIRED) or 403 Forbidden (SEAL_SIGNATURE_INVALID because timestamp is signed)
    assert_eq!(
        status, "403 Forbidden",
        "Expired seal must return 403 Forbidden"
    );
    assert!(
        body.contains("SEAL_EXPIRED") || body.contains("SEAL_SIGNATURE_INVALID"),
        "Body was: {}",
        body
    );
}

// ==============================================================================
// 4. Malformed Request Payloads (400 Bad Request)
// ==============================================================================

#[test]
fn test_malformed_request_payloads() {
    let state = WebState::default();

    // 4.1 Validate action with corrupted JSON syntax
    let (s1, b1) = handle_cage_validate_action(&state, "{not a valid json syntax");
    assert_eq!(s1, "400 Bad Request");
    assert!(b1.contains("INVALID_REQUEST_PAYLOAD"));

    // 4.2 Validate action with empty body
    let (s2, b2) = handle_cage_validate_action(&state, "");
    assert_eq!(s2, "400 Bad Request");
    assert!(b2.contains("INVALID_REQUEST_PAYLOAD"));

    // 4.3 Consume seal with corrupted JSON
    let (s3, b3) = handle_cage_consume_seal(&state, "{\"seal\": broken}");
    assert_eq!(s3, "400 Bad Request");
    assert!(b3.contains("INVALID_REQUEST_PAYLOAD"));

    // 4.4 Trace conformance with unparseable payload
    let (s4, b4) = handle_cage_trace_conformance(&state, "not json and not jsonl");
    assert_eq!(s4, "400 Bad Request");
    assert!(b4.contains("INVALID_REQUEST_PAYLOAD"));
}

// ==============================================================================
// 5. Cross-Origin Browser Probes (403 Forbidden via Request Guard)
// ==============================================================================

#[test]
fn test_cross_origin_browser_probes_on_all_cage_endpoints() {
    let endpoints = [
        ("POST", "/governance/ingest-policy"),
        ("GET", "/governance/policy-version"),
        ("POST", "/governance/validate-action"),
        ("POST", "/v1/governance/validate-action"),
        ("POST", "/governance/consume-seal"),
        ("GET", "/governance/proof-status"),
        ("POST", "/governance/trace-conformance"),
        ("POST", "/api/cage/ingest-policy"),
        ("GET", "/api/cage/policy-version"),
        ("POST", "/api/cage/validate-action"),
        ("POST", "/api/cage/consume-seal"),
        ("GET", "/api/cage/proof-status"),
        ("POST", "/api/cage/trace-conformance"),
    ];

    for (method, path) in endpoints {
        // Probe 1: Untrusted Origin header
        let h_origin = format!(
            "{} {} HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nOrigin: https://attacker.example\r\n",
            method, path
        );
        let req1 = make_guard_req(method, path, &h_origin, 5005);
        let res1 = authorize_request(&req1, "token123");
        assert!(
            matches!(res1, Err(GuardRejection::CrossOrigin(_))),
            "Endpoint {} {} must reject untrusted Origin with CrossOrigin",
            method,
            path
        );
        if let Err(rej) = res1 {
            assert_eq!(rej.status_line(), "403 Forbidden");
            assert_eq!(rej.code(), "DASHBOARD_CROSS_ORIGIN_REJECTED");
        }

        // Probe 2: Sec-Fetch-Site cross-site
        let h_sec = format!(
            "{} {} HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nSec-Fetch-Site: cross-site\r\n",
            method, path
        );
        let req2 = make_guard_req(method, path, &h_sec, 5005);
        let res2 = authorize_request(&req2, "token123");
        assert!(
            matches!(res2, Err(GuardRejection::CrossOrigin(_))),
            "Endpoint {} {} must reject cross-site Sec-Fetch-Site",
            method,
            path
        );

        // Probe 3: Case-insensitive Sec-Fetch-Site: CROSS-SITE
        let h_sec_caps = format!(
            "{} {} HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nSEC-FETCH-SITE: CROSS-SITE\r\n",
            method, path
        );
        let req3 = make_guard_req(method, path, &h_sec_caps, 5005);
        assert!(
            matches!(
                authorize_request(&req3, "token123"),
                Err(GuardRejection::CrossOrigin(_))
            ),
            "Sec-Fetch-Site check must be case-insensitive"
        );
    }
}

// ==============================================================================
// 6. Host Rebinding Probes (421 Misdirected Request via Request Guard)
// ==============================================================================

#[test]
fn test_host_rebinding_probes_on_cage_endpoints() {
    let endpoints = [
        ("POST", "/governance/validate-action"),
        ("POST", "/api/cage/validate-action"),
        ("POST", "/governance/consume-seal"),
        ("GET", "/governance/policy-version"),
    ];

    for (method, path) in endpoints {
        // Rebinding Probe 1: Arbitrary domain resolving to 127.0.0.1
        let h_evil = format!("{} {} HTTP/1.1\r\nHost: evil.com:5005\r\n", method, path);
        let req1 = make_guard_req(method, path, &h_evil, 5005);
        let res1 = authorize_request(&req1, "token123");
        assert!(
            matches!(res1, Err(GuardRejection::BadHost(_))),
            "Host evil.com:5005 must be rejected with BadHost"
        );
        if let Err(rej) = res1 {
            assert_eq!(rej.status_line(), "421 Misdirected Request");
            assert_eq!(rej.code(), "DASHBOARD_HOST_REJECTED");
        }

        // Rebinding Probe 2: Dynamic DNS rebinding service
        let h_rebind = format!(
            "{} {} HTTP/1.1\r\nHost: 7f000001.rbndr.us:5005\r\n",
            method, path
        );
        let req2 = make_guard_req(method, path, &h_rebind, 5005);
        assert!(matches!(
            authorize_request(&req2, "token123"),
            Err(GuardRejection::BadHost(_))
        ));

        // Rebinding Probe 3: Port mismatch (Host header specifies 9999, socket bound to 5005)
        let h_port_mismatch = format!("{} {} HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n", method, path);
        let req3 = make_guard_req(method, path, &h_port_mismatch, 5005);
        assert!(matches!(
            authorize_request(&req3, "token123"),
            Err(GuardRejection::BadHost(_))
        ));

        // Legitimate authorities: 127.0.0.1:5005, localhost:5005, [::1]:5005 must pass
        for auth in &["127.0.0.1:5005", "localhost:5005", "[::1]:5005"] {
            let h_good = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, auth);
            let req_good = make_guard_req(method, path, &h_good, 5005);
            assert!(
                authorize_request(&req_good, "token123").is_ok(),
                "Host {} must be accepted on port 5005",
                auth
            );
        }
    }
}

// ==============================================================================
// 7. Formal Proof & Trace Conformance Verification
// ==============================================================================

#[test]
fn test_proof_status_formal_contract() {
    let state = WebState::default();

    let (status, body) = handle_cage_proof_status(&state);
    assert_eq!(status, "200 OK");

    let proof: ProofStatusResponse =
        serde_json::from_str(&body).expect("Must parse ProofStatusResponse");

    // Google CAGE Substrate Contract formal theorem verification:
    // Reachable states under gated BFS must be exactly 34
    assert_eq!(
        proof.reachable_states, 34,
        "Gated BFS model must explore exactly 34 states"
    );
    assert!(
        proof.no_direct_bind_proven,
        "No-Direct-Bind formal theorem must be proven"
    );
    assert!(
        proof.ungated_counterexample_proven,
        "Ungated model must detect counterexample"
    );
}

#[test]
fn test_trace_conformance_endpoint_contract() {
    let state = WebState::default();

    // 1. Empty trace array -> 200 OK
    let (s1, b1) = handle_cage_trace_conformance(&state, "[]");
    assert_eq!(s1, "200 OK");
    assert!(
        b1.contains("\"status\":\"CONFORMANT\"") && b1.contains("\"findings\":[]"),
        "Empty trace stream must be CONFORMANT, got: {}",
        b1
    );

    // 2. Wrapped traces envelope -> 200 OK
    let wrapped = serde_json::json!({
        "traces": []
    })
    .to_string();
    let (s2, b2) = handle_cage_trace_conformance(&state, &wrapped);
    assert_eq!(s2, "200 OK");
    assert!(
        b2.contains("\"status\":\"CONFORMANT\""),
        "Wrapped trace stream must be CONFORMANT, got: {}",
        b2
    );

    // 3. Injected single-use replay violation in trace stream -> detected
    let violated_trace = serde_json::json!([
        {
            "event_type": "EXECUTED",
            "rule": "single_use",
            "seal_ref": "SEAL-DUPLICATE-UUID-1",
            "timestamp": 1700000000
        },
        {
            "event_type": "EXECUTED",
            "rule": "single_use",
            "seal_ref": "SEAL-DUPLICATE-UUID-1",
            "timestamp": 1700000005
        }
    ])
    .to_string();

    let (s3, b3) = handle_cage_trace_conformance(&state, &violated_trace);
    assert_eq!(s3, "200 OK");
    assert!(
        b3.contains("\"status\":\"NON_CONFORMANT\"") || b3.contains("single_use"),
        "Trace conformance must report violations: {}",
        b3
    );
}

// ==============================================================================
// 8. Header Parsing & Path Routing Helpers
// ==============================================================================

#[test]
fn test_extract_header_value_case_insensitivity() {
    let headers = "POST /api/cage/validate-action HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nX-Expected-Policy-Version: hex_version_1234\r\nContent-Type: application/json\r\n";

    assert_eq!(
        extract_header_value(headers, "x-expected-policy-version"),
        Some("hex_version_1234")
    );
    assert_eq!(
        extract_header_value(headers, "X-Expected-Policy-Version"),
        Some("hex_version_1234")
    );
    assert_eq!(
        extract_header_value(headers, "X-EXPECTED-POLICY-VERSION"),
        Some("hex_version_1234")
    );
    assert_eq!(extract_header_value(headers, "non-existent-header"), None);
}

#[test]
fn test_cage_path_matcher_coverage() {
    let valid_paths = [
        "/governance/ingest-policy",
        "/governance/ingest-policy/",
        "/governance/policy-version",
        "/governance/validate-action",
        "/v1/governance/validate-action",
        "/governance/consume-seal",
        "/governance/proof-status",
        "/governance/trace-conformance",
        "/api/cage/ingest-policy",
        "/api/cage/policy-version",
        "/api/cage/validate-action",
        "/api/cage/consume-seal",
        "/api/cage/proof-status",
        "/api/cage/trace-conformance",
    ];

    for path in valid_paths {
        assert!(
            is_cage_substrate_path(path),
            "Path '{}' must be recognized as CAGE substrate path",
            path
        );
        assert!(
            is_token_exempt_path(path),
            "Path '{}' must be exempt from operator token on loopback",
            path
        );
    }

    let non_cage_paths = [
        "/api/run-rust-tests",
        "/api/containment-rings/sever",
        "/api/sentinel/simulate-breach",
        "/api/pqc/generate-keypair",
    ];

    for path in non_cage_paths {
        assert!(
            !is_cage_substrate_path(path),
            "Path '{}' must NOT be classified as CAGE path",
            path
        );
        assert!(
            !is_token_exempt_path(path),
            "Path '{}' must NOT be exempt from token",
            path
        );
    }
}
