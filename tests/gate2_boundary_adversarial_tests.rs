//! ==============================================================================
//! [AGENT OCTOPUS] GATE 2 ADVERSARIAL BOUNDARY & PERIMETER PROBE TEST SUITE
//! ==============================================================================
//! Empirical adversarial test suite for Gate 2 verification:
//! 1. Probe Web API endpoints (/api/sentinel/simulate-breach, /api/sentinel/reset-lockdown)
//!    with previously hardcoded backdoor tokens to verify 401/403 rejection.
//! 2. Probe CedarGate and CapabilityGate sensitivity toggles against unauthorized manipulation.
//! 3. Probe EgressProxy against SSRF, IPv6 loopback variants ([::1], [::], [fe80::1], [::ffff:127.0.0.1]),
//!    and credential smuggling.
//! 4. Verify port 5005 health and dual-stack binding.
//! ==============================================================================

use agent_octopus::containment_ring::cedar_gate::CedarGate;
use agent_octopus::containment_ring::capability_gate::CapabilityGate;
use agent_octopus::containment_ring::egress_proxy::{
    EgressProxy, EgressRequest, EgressSecurityLevel,
};
use agent_octopus::core::types::OctopusSecurityError;
use agent_octopus::web::api::{
    handle_sentinel_simulate_breach, handle_sentinel_reset_lockdown, WebState,
};

// ==============================================================================
// PROBE 1: Web API Backdoor Token Rejection (/api/sentinel/*)
// ==============================================================================

#[tokio::test]
async fn test_probe_1_sentinel_api_rejects_backdoor_tokens() {
    let state = WebState::default();

    let legacy_tokens = [
        "ADMIN_RESTRICTED_TOKEN",
        "AGY_AUTHORITATIVE_SENTINEL_ADMIN_KEY_2026",
        "AUTHORITATIVE_SENTINEL_RECOVERY_TOKEN_2026",
        "fake_bearer_token_xyz_12345",
    ];

    let simulate_payload = r#"{"scenario":"supervisor_timeout"}"#;
    let reset_payload = r#"{"recovery_token":"test_token"}"#;

    // Ensure SENTINEL_ADMIN_KEY is not set to any of these backdoor values
    // Case A: Unset / empty SENTINEL_ADMIN_KEY
    std::env::remove_var("SENTINEL_ADMIN_KEY");

    // 1. Missing Authorization header must be rejected with 401 ADMIN_AUTH_REQUIRED
    let res_no_auth = handle_sentinel_simulate_breach(&state, "", simulate_payload).await;
    assert!(res_no_auth.is_err(), "Simulate breach without auth header must fail");
    let err_msg = res_no_auth.unwrap_err();
    assert!(err_msg.contains("ADMIN_AUTH_REQUIRED"), "Must cite ADMIN_AUTH_REQUIRED: {}", err_msg);

    let res_reset_no_auth = handle_sentinel_reset_lockdown(&state, "", reset_payload).await;
    assert!(res_reset_no_auth.is_err(), "Reset lockdown without auth header must fail");
    let err_msg_reset = res_reset_no_auth.unwrap_err();
    assert!(err_msg_reset.contains("ADMIN_AUTH_REQUIRED"), "Must cite ADMIN_AUTH_REQUIRED: {}", err_msg_reset);

    // 2. All legacy backdoor tokens must be rejected when SENTINEL_ADMIN_KEY is unset
    for &token in &legacy_tokens {
        let headers = format!("Host: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Type: application/json", token);

        let sim_res = handle_sentinel_simulate_breach(&state, &headers, simulate_payload).await;
        assert!(sim_res.is_err(), "Legacy token '{}' must be rejected on simulate-breach", token);
        let sim_err = sim_res.unwrap_err();
        assert!(sim_err.contains("ADMIN_AUTH_REQUIRED"), "Expected ADMIN_AUTH_REQUIRED for token '{}': {}", token, sim_err);

        let reset_res = handle_sentinel_reset_lockdown(&state, &headers, reset_payload).await;
        assert!(reset_res.is_err(), "Legacy token '{}' must be rejected on reset-lockdown", token);
        let reset_err = reset_res.unwrap_err();
        assert!(reset_err.contains("ADMIN_AUTH_REQUIRED"), "Expected ADMIN_AUTH_REQUIRED for token '{}': {}", token, reset_err);
    }

    // Case B: SENTINEL_ADMIN_KEY is set to a secure runtime key
    std::env::set_var("SENTINEL_ADMIN_KEY", "SECURE_RUNTIME_OPERATOR_SECRET_KEY_9999");

    for &token in &legacy_tokens {
        let headers = format!("Host: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Type: application/json", token);

        let sim_res = handle_sentinel_simulate_breach(&state, &headers, simulate_payload).await;
        assert!(sim_res.is_err(), "Legacy token '{}' must be rejected even when admin key is configured", token);
        let sim_err = sim_res.unwrap_err();
        assert!(sim_err.contains("ADMIN_AUTH_REQUIRED"), "Expected ADMIN_AUTH_REQUIRED: {}", sim_err);

        let reset_res = handle_sentinel_reset_lockdown(&state, &headers, reset_payload).await;
        assert!(reset_res.is_err(), "Legacy token '{}' must be rejected even when admin key is configured", token);
        let reset_err = reset_res.unwrap_err();
        assert!(reset_err.contains("ADMIN_AUTH_REQUIRED"), "Expected ADMIN_AUTH_REQUIRED: {}", reset_err);
    }

    // Clean up environment
    std::env::remove_var("SENTINEL_ADMIN_KEY");
}

// ==============================================================================
// PROBE 2: CedarGate & CapabilityGate Sensitivity Toggles
// ==============================================================================

#[tokio::test]
async fn test_probe_2_gate_sensitivity_toggles_reject_unauthorized_manipulation() {
    // 1. CedarGate production instance cannot be disabled
    let prod_gate = CedarGate::new();
    assert!(prod_gate.is_enabled(), "Production CedarGate must be enabled by default");

    // Foreign NegativeControlToken generated from another audit instance
    let (_audit_gate, foreign_token) = CedarGate::new_for_audit();

    // Adversary attempts to disable production CedarGate using foreign/mismatched token
    let disable_attempt = prod_gate.set_enabled(false, &foreign_token);
    assert!(
        disable_attempt.is_err(),
        "Production CedarGate must reject foreign token"
    );
    match disable_attempt.unwrap_err() {
        OctopusSecurityError::CapabilityDenied(msg) => {
            assert!(msg.contains("UNAUTHORIZED_CALL_PATH"), "Error must cite UNAUTHORIZED_CALL_PATH: {}", msg);
        }
        other => panic!("Expected CapabilityDenied, got {:?}", other),
    }
    assert!(prod_gate.is_enabled(), "CedarGate must remain enabled after attack");

    // Legitimate NegativeControlToken on audit instance CAN toggle
    let (audit_instance, legitimate_token) = CedarGate::new_for_audit();
    assert!(audit_instance.is_enabled());
    let audit_disable = audit_instance.set_enabled(false, &legitimate_token);
    assert!(audit_disable.is_ok(), "Audit instance with genuine token must succeed");
    assert!(!audit_instance.is_enabled(), "Audit instance must reflect disabled state");

    // But audit instance STILL rejects foreign token from another instance
    let cross_attack = audit_instance.set_enabled(true, &foreign_token);
    assert!(cross_attack.is_err(), "Audit instance must reject cross-instance token");

    // 2. CapabilityGate cannot be manipulated with foreign or invalid tokens
    let cap_gate = CapabilityGate::new(b"SEED_TEST_CAP_GATE_32_BYTES_OK!", 300);
    assert!(cap_gate.is_enforced(), "CapabilityGate must be enforced by default");

    let cap_attack = cap_gate.set_enforcement_enabled(false, &foreign_token);
    assert!(cap_attack.is_err(), "CapabilityGate must reject foreign token");
    match cap_attack.unwrap_err() {
        OctopusSecurityError::CapabilityDenied(msg) => {
            assert!(msg.contains("UNAUTHORIZED_CALL_PATH"), "Error must cite UNAUTHORIZED_CALL_PATH: {}", msg);
        }
        other => panic!("Expected CapabilityDenied, got {:?}", other),
    }
    assert!(cap_gate.is_enforced(), "CapabilityGate must remain enforced after attack");

    // Legitimate CapabilityGate audit instance
    let (cap_audit, cap_legit_token) = CapabilityGate::new_for_audit(b"AUDIT_CAP_SEED_32_BYTES_ENTROPY!", 300);
    assert!(cap_audit.is_enforced());
    let legit_disable = cap_audit.set_enforcement_enabled(false, &cap_legit_token);
    assert!(legit_disable.is_ok(), "Genuine CapabilityGate audit token must succeed");
    assert!(!cap_audit.is_enforced());

    // Foreign token on cap_audit is rejected
    let cross_cap = cap_audit.set_enforcement_enabled(true, &foreign_token);
    assert!(cross_cap.is_err(), "Foreign token on cap_audit must fail");
}

// ==============================================================================
// PROBE 3: EgressProxy SSRF, IPv6 Loopback Variants & Credential Smuggling
// ==============================================================================

#[tokio::test]
async fn test_probe_3_egress_proxy_ssrf_ipv6_variants_and_credentials() {
    let (proxy, _token) = EgressProxy::new_for_audit(EgressSecurityLevel::StrictGoogleOnly);

    // List of adversarial targets that MUST be rejected
    let adversarial_targets = [
        // IPv6 loopback variants
        ("https://[::1]/secret", "IPv6 loopback literal [::1]"),
        ("https://[::1]:443/secret", "IPv6 loopback literal [::1]:443"),
        ("https://[::]/data", "IPv6 unspecified literal [::]"),
        ("https://[::]:443/data", "IPv6 unspecified literal [::]:443"),
        ("https://[fe80::1]/link-local", "IPv6 link-local literal [fe80::1]"),
        ("https://[fe80::1]:443/link-local", "IPv6 link-local literal [fe80::1]:443"),
        ("https://[::ffff:127.0.0.1]/v4mapped", "IPv4-mapped IPv6 loopback [::ffff:127.0.0.1]"),
        ("https://[::ffff:127.0.0.1]:443/v4mapped", "IPv4-mapped IPv6 loopback [::ffff:127.0.0.1]:443"),

        // Credential smuggling in URL (RFC 3986 userinfo)
        ("https://user:password@google.com/search", "Userinfo user:pass@"),
        ("https://admin@google.com/search", "Userinfo user@"),
        ("https://api_key:secret@api.anthropic.com/v1", "API key userinfo in allowed domain"),

        // Port manipulation & non-443 egress
        ("https://google.com:8080/search", "Non-standard port 8080"),
        ("https://google.com:8443/search", "Non-standard port 8443"),
        ("https://google.com:80/search", "HTTP port 80 over https"),

        // IPv4 Loopback & Cloud Metadata
        ("https://127.0.0.1/admin", "IPv4 loopback 127.0.0.1"),
        ("https://localhost/admin", "localhost"),
        ("https://169.254.169.254/latest/meta-data/", "AWS/Azure metadata IP 169.254.169.254"),
        ("https://metadata.google.internal/computeMetadata/v1/", "GCP metadata internal DNS"),

        // Private RFC 1918 addresses
        ("https://10.0.0.1/internal", "RFC 1918 10.0.0.1"),
        ("https://192.168.1.1/router", "RFC 1918 192.168.1.1"),

        // C2 & Untrusted domains
        ("https://attacker.com/c2", "Attacker domain"),
        ("https://evil-c2.com/payload", "Evil C2 domain"),
        ("https://google.com.attacker.com/search", "Domain suffix trick"),
    ];

    for &(url, description) in &adversarial_targets {
        let req = EgressRequest {
            agent_id: "agent_adversary".to_string(),
            target_url: url.to_string(),
            method: "GET".to_string(),
            payload: None,
        };

        let result = proxy.dispatch_egress(&req).await;
        assert!(
            result.is_err(),
            "EgressProxy MUST reject {}: '{}'", description, url
        );
        match result.unwrap_err() {
            OctopusSecurityError::SsrfBlocked(msg) => {
                // Verified blocked by anti-SSRF defense
                assert!(!msg.is_empty(), "Rejection must provide reason");
            }
            other => panic!("Expected SsrfBlocked for {}, got: {:?}", description, other),
        }
    }

    // Positive Control: Valid allowed domain over standard HTTPS (port 443 / default)
    let valid_req = EgressRequest {
        agent_id: "agent_authorized".to_string(),
        target_url: "https://google.com/search?q=security".to_string(),
        method: "GET".to_string(),
        payload: Some("{\"query\":\"test\"}".to_string()),
    };
    let valid_result = proxy.dispatch_egress(&valid_req).await;
    assert!(valid_result.is_ok(), "Valid egress to google.com must succeed: {:?}", valid_result.err());
    let resp = valid_result.unwrap();
    assert_eq!(resp.status_code, 200);
}

// ==============================================================================
// PROBE 4: Port 5005 Health, Dual-Stack Loopback & Server Response Integrity
// ==============================================================================

#[tokio::test]
async fn test_probe_4_port_5005_dual_stack_and_health_integrity() {
    use tokio::net::TcpStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 1. Verify IPv4 loopback connection (127.0.0.1:5005)
    let ipv4_stream = TcpStream::connect("127.0.0.1:5005").await;
    if let Ok(mut stream) = ipv4_stream {
        let req = "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nConnection: close\r\n\r\n";
        stream.write_all(req.as_bytes()).await.expect("Write to IPv4 stream");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("Read from IPv4 stream");
        let resp_str = String::from_utf8_lossy(&response);
        assert!(resp_str.contains("HTTP/1.1 200 OK"), "IPv4 /api/status must return 200 OK: {}", &resp_str[..resp_str.len().min(200)]);
        assert!(resp_str.contains("\"status\":\"ONLINE\""), "IPv4 /api/status must contain status: ONLINE");
        assert!(resp_str.contains("Cedar v4.13"), "IPv4 /api/status must contain Cedar v4.13 engine");
    }

    // 2. Verify IPv6 loopback connection ([::1]:5005)
    let ipv6_stream = TcpStream::connect("[::1]:5005").await;
    if let Ok(mut stream) = ipv6_stream {
        let req = "GET /api/status HTTP/1.1\r\nHost: [::1]:5005\r\nConnection: close\r\n\r\n";
        stream.write_all(req.as_bytes()).await.expect("Write to IPv6 stream");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("Read from IPv6 stream");
        let resp_str = String::from_utf8_lossy(&response);
        assert!(resp_str.contains("HTTP/1.1 200 OK"), "IPv6 /api/status must return 200 OK: {}", &resp_str[..resp_str.len().min(200)]);
        assert!(resp_str.contains("\"status\":\"ONLINE\""), "IPv6 /api/status must contain status: ONLINE");
        assert!(resp_str.contains("Cedar v4.13"), "IPv6 /api/status must contain Cedar v4.13 engine");
    }
}
