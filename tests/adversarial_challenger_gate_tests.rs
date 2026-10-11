//! ==============================================================================
//! [AGENT OCTOPUS] ADVERSARIAL CHALLENGER GATE TEST SUITE
//! ==============================================================================
//! Empirical adversarial challenge suite validating:
//! 1. CedarGate authorization bypass elimination & NegativeControlToken gating.
//! 2. Dynamic secret rotation, invalid entropy rejection, rollback safety,
//!    preserved revocations, and 300s grace-period dual verification.
//! 3. Strict RFC 3986 URL validation, path anchoring, port checks, credential
//!    rejection, ISO calendar versioning, and IPv6 loopback anti-SSRF defenses.
//! ==============================================================================

use agent_octopus::containment_ring::{
    ArmContainmentRing, CapabilityGate, CedarGate,
    EgressProxy, EgressRequest, EgressSecurityLevel,
};
use agent_octopus::core::types::{ArmRole, OctopusSecurityError};
use agent_octopus::security::atlas_arm::atlas_sync::{
    validate_atlas_version, AtlasSyncManager,
};
use agent_octopus::security::atlas_arm::EMBEDDED_GOLDEN_STIX;
use agent_octopus::security::cedar_arm::authorization::load_or_generate_cedar_secret;
use agent_octopus::security::cedar_arm::CedarAuthorizationGateway;
use serde_json::json;

// ==============================================================================
// CHALLENGE 1: CedarGate & NegativeControlToken Adversarial Stress Testing
// ==============================================================================

#[tokio::test]
async fn test_adversarial_r1_cedargate_token_gating_and_bypass_resistance() {
    // 1. Production instance cannot be disabled with arbitrary or foreign tokens
    let prod_gate = CedarGate::new();
    assert!(prod_gate.is_enabled(), "Production CedarGate must be enabled by default");

    // Create an unrelated audit token from another instance to simulate forged/stolen token
    let (_audit_gate, foreign_token) = CedarGate::new_for_audit();

    // Adversary attempts to disable production CedarGate using foreign token
    let unauth_disable = prod_gate.set_enabled(false, &foreign_token);
    assert!(
        matches!(unauth_disable, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("UNAUTHORIZED_CALL_PATH")),
        "CedarGate must reject disable attempt with foreign NegativeControlToken: {:?}",
        unauth_disable
    );
    assert!(prod_gate.is_enabled(), "CedarGate must remain enabled after failed attack");

    // Verify Cedar evaluation remains fully active and enforces policy
    let unauthorized_eval = prod_gate.evaluate_authorization(
        "arm-untrusted-doc",
        &ArmRole::UntrustedDocIngest,
        "write",
        "s3://accounting/ledger.json",
        Some(50_000),
    ).await;
    assert!(
        matches!(unauthorized_eval, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("Cedar Zero-Trust Policy Veto")),
        "Cedar policy must deny unauthorized write from doc ingest arm with CapabilityDenied: {:?}",
        unauthorized_eval
    );

    // Hard spending cap check ($100,000 ceiling = 10,000,000 cents)
    let ceiling_violation = prod_gate.evaluate_authorization(
        "arm-accounting-ledger",
        &ArmRole::AccountingLedgerWrite,
        "write",
        "s3://accounting/ledger.json",
        Some(15_000_000), // $150,000
    ).await;
    assert!(
        matches!(ceiling_violation, Err(OctopusSecurityError::DeterministicLayerViolation(ref msg)) if msg.contains("strict hard spending ceiling")),
        "Spending ceiling over $100k must trigger DeterministicLayerViolation: {:?}",
        ceiling_violation
    );

    // 2. CapabilityGate cannot be disabled with unauthorized token
    let cap_gate = CapabilityGate::new(b"SEED_TEST_CAP_GATE_32_BYTES_OK!", 300);
    assert!(cap_gate.is_enforced(), "CapabilityGate must be enforced by default");
    let unauth_cap_disable = cap_gate.set_enforcement_enabled(false, &foreign_token);
    assert!(
        matches!(unauth_cap_disable, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("UNAUTHORIZED_CALL_PATH")),
        "CapabilityGate must reject foreign NegativeControlToken: {:?}",
        unauth_cap_disable
    );
    assert!(cap_gate.is_enforced(), "CapabilityGate must remain enforced");

    // 3. EgressProxy cannot be disabled with unauthorized token
    let egress_proxy = EgressProxy::new(EgressSecurityLevel::StrictGoogleOnly);
    assert!(egress_proxy.is_allowlist_enabled(), "EgressProxy allowlist must be enabled by default");
    let unauth_egress_disable = egress_proxy.set_allowlist_enabled(false, &foreign_token);
    assert!(
        matches!(unauth_egress_disable, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("UNAUTHORIZED_CALL_PATH")),
        "EgressProxy must reject foreign NegativeControlToken: {:?}",
        unauth_egress_disable
    );
    assert!(egress_proxy.is_allowlist_enabled(), "EgressProxy must remain enabled");

    // 4. ArmContainmentRing sensitivity toggles cannot be modified with unauthorized token
    let arm_ring = ArmContainmentRing::new(
        1,
        ArmRole::UntrustedDocIngest,
        1,
        b"SEED_TEST_ARM_RING_32_BYTES_OK!!",
    );
    assert!(arm_ring.set_epoch_enforcement(false, &foreign_token).is_err());
    assert!(arm_ring.set_tool_enforcement(false, &foreign_token).is_err());
    assert!(arm_ring.set_budget_enforcement(false, &foreign_token).is_err());

    // 5. Positive Control: Authorized sensitivity modification using authentic token
    let (audit_gate_genuine, authentic_token) = CedarGate::new_for_audit();
    assert!(audit_gate_genuine.is_enabled());

    let auth_disable = audit_gate_genuine.set_enabled(false, &authentic_token);
    assert!(auth_disable.is_ok(), "Authorized disable with authentic token must succeed");
    assert!(!audit_gate_genuine.is_enabled(), "Audit gate must be disabled");

    // While disabled, evaluate_authorization returns Ok(true) for negative-control probing
    let probe_eval = audit_gate_genuine.evaluate_authorization(
        "arm-untrusted-doc",
        &ArmRole::UntrustedDocIngest,
        "write",
        "s3://accounting/ledger.json",
        Some(50_000),
    ).await;
    assert_eq!(probe_eval.unwrap(), true, "Disabled gate permits negative control probe");

    // Re-enable using authentic token
    let auth_enable = audit_gate_genuine.set_enabled(true, &authentic_token);
    assert!(auth_enable.is_ok(), "Re-enabling with authentic token must succeed");
    assert!(audit_gate_genuine.is_enabled());

    // Policy enforcement is restored
    let restored_eval = audit_gate_genuine.evaluate_authorization(
        "arm-untrusted-doc",
        &ArmRole::UntrustedDocIngest,
        "write",
        "s3://accounting/ledger.json",
        Some(50_000),
    ).await;
    assert!(
        matches!(restored_eval, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("Cedar Zero-Trust Policy Veto")),
        "Policy enforcement restored after re-enable: {:?}",
        restored_eval
    );
}

// ==============================================================================
// CHALLENGE 2: Secret Rotation & Rollback Adversarial Stress Testing
// ==============================================================================

#[tokio::test]
async fn test_adversarial_r2_secret_rotation_entropy_rollback_and_grace_period() {
    let secret_a = b"INITIAL_SECRET_ALPHA_32_BYTES_OK!";
    let mut gateway = CedarAuthorizationGateway::new(secret_a, "cedar_ring_v4.13");

    // 1. Invalid secret length rejection
    let empty_res = gateway.rotate_secret(b"", "cedar_ring_v4.13");
    assert!(
        matches!(empty_res, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("Cannot rotate to an empty secret key")),
        "Empty secret must be rejected: {:?}",
        empty_res
    );

    let short_1 = gateway.rotate_secret(b"X", "cedar_ring_v4.13");
    assert!(
        matches!(short_1, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("minimum 256 bits")),
        "1-byte secret must be rejected: {:?}",
        short_1
    );

    let short_16 = gateway.rotate_secret(b"16_byte_password", "cedar_ring_v4.13");
    assert!(
        matches!(short_16, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("minimum 256 bits")),
        "16-byte secret must be rejected: {:?}",
        short_16
    );

    let short_31 = gateway.rotate_secret(b"31_bytes_almost_valid_key_here!", "cedar_ring_v4.13");
    assert!(
        matches!(short_31, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("minimum 256 bits")),
        "31-byte secret must be rejected: {:?}",
        short_31
    );

    // 2. Identical secret rejection
    let ident_res = gateway.rotate_secret(secret_a, "cedar_ring_v4.13");
    assert!(
        matches!(ident_res, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("New secret matches active secret")),
        "Identical secret must be rejected: {:?}",
        ident_res
    );

    // 3. Issue in-flight token and supervisor receipt under Secret A
    let token_a = gateway.auth_engine().issue_capability(
        "supervisor",
        "ledger_arm",
        ArmRole::AccountingLedgerWrite,
        "ledger_writer",
        "corporate_ledger",
    );
    let receipt_a = gateway.issue_supervisor_approval(
        "supervisor_1",
        "ledger_arm",
        "corporate_ledger",
        100_000,
        300,
    ).expect("Issued supervisor receipt");

    // Verify token_a and receipt_a work under initial secret
    let eval_a = gateway.authorize_tool_invocation_with_approval(
        &token_a,
        "ledger_arm",
        "ledger_writer",
        "corporate_ledger",
        json!({ "amount_cents": 50000, "approved": true }),
        Some(&receipt_a),
    );
    assert!(eval_a.is_ok(), "Initial token and receipt must verify");

    // 4. Rotate to valid Secret B (32+ bytes)
    let secret_b = b"ROTATED_SECRET_BETA__32_BYTES_OK!";
    let fp_b = gateway.rotate_secret(secret_b, "cedar_ring_v4.13").expect("Rotation succeeded");
    assert_eq!(gateway.active_epoch().fingerprint, fp_b);
    assert!(gateway.previous_epoch().is_some());

    // 5. Dual verification during 300s grace window: Token A and Receipt A still accepted!
    let eval_grace = gateway.authorize_tool_invocation_with_approval(
        &token_a,
        "ledger_arm",
        "ledger_writer",
        "corporate_ledger",
        json!({ "amount_cents": 50000, "approved": true }),
        Some(&receipt_a),
    );
    assert!(
        eval_grace.is_ok(),
        "In-flight token_a must succeed during 300s grace window: {:?}",
        eval_grace.err()
    );

    // Issue Token B and Receipt B under Secret B
    let token_b = gateway.auth_engine().issue_capability(
        "supervisor",
        "ledger_arm",
        ArmRole::AccountingLedgerWrite,
        "ledger_writer",
        "corporate_ledger",
    );
    let receipt_b = gateway.issue_supervisor_approval(
        "supervisor_1",
        "ledger_arm",
        "corporate_ledger",
        100_000,
        300,
    ).expect("Issued receipt under B");

    let eval_b = gateway.authorize_tool_invocation_with_approval(
        &token_b,
        "ledger_arm",
        "ledger_writer",
        "corporate_ledger",
        json!({ "amount_cents": 50000, "approved": true }),
        Some(&receipt_b),
    );
    assert!(eval_b.is_ok(), "Token B must verify under active Secret B");

    // 6. Rollback Secret to Secret A
    let fp_restored = gateway.rollback_secret().expect("Rollback succeeded");
    assert_eq!(gateway.secret_seed(), secret_a);
    assert_eq!(gateway.active_epoch().fingerprint, fp_restored);
    assert!(gateway.previous_epoch().is_none(), "Previous epoch must be cleared after rollback");

    // Under rolled back secret A: Token A works as primary active secret!
    let eval_restored_a = gateway.authorize_tool_invocation_with_approval(
        &token_a,
        "ledger_arm",
        "ledger_writer",
        "corporate_ledger",
        json!({ "amount_cents": 50000, "approved": true }),
        Some(&receipt_a),
    );
    assert!(eval_restored_a.is_ok(), "Token A must verify under restored Secret A");

    // Token B (signed with Secret B, now rolled back) MUST be rejected!
    let eval_rolled_b = gateway.authorize_tool_invocation_with_approval(
        &token_b,
        "ledger_arm",
        "ledger_writer",
        "corporate_ledger",
        json!({ "amount_cents": 50000, "approved": true }),
        Some(&receipt_b),
    );
    assert!(eval_rolled_b.is_err(), "Token B must fail after rollback to Secret A");

    // Second consecutive rollback attempt must fail closed
    let double_rollback = gateway.rollback_secret();
    assert!(
        matches!(double_rollback, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("No previous secret epoch exists")),
        "Second rollback must fail closed: {:?}",
        double_rollback
    );

    // 7. Revocation persistence across rotations
    let token_rev_test = gateway.auth_engine().issue_capability(
        "supervisor",
        "ledger_arm",
        ArmRole::AccountingLedgerWrite,
        "ledger_writer",
        "corporate_ledger",
    );
    // Explicitly revoke token
    gateway.auth_engine().revoke_token(&token_rev_test.token_id);

    // Rotate secret to Secret C
    let secret_c = b"ROTATED_SECRET_GAMMA_32_BYTES_OK!";
    gateway.rotate_secret(secret_c, "cedar_ring_v4.13").expect("Rotation to C succeeded");

    // Revoked token must remain revoked after rotation!
    let revoked_verdict = gateway.authorize_tool_invocation(
        &token_rev_test,
        "ledger_arm",
        "ledger_writer",
        "corporate_ledger",
        json!({ "amount_cents": 50000, "approved": true }),
    );
    assert!(
        revoked_verdict.is_err(),
        "Revoked token must remain revoked across rotations: {:?}",
        revoked_verdict
    );

    // 8. Secret loader resilience (OCTOPUS_CEDAR_SECRET & CSPRNG)
    // Dynamic CSPRNG generation
    let dynamic_secret = load_or_generate_cedar_secret();
    assert_eq!(dynamic_secret.len(), 32, "CSPRNG secret must be exactly 32 bytes");
    assert_ne!(dynamic_secret, [0u8; 32], "CSPRNG secret cannot be all zeros");

    // Process-scoped environment loading: short key stretching
    std::env::set_var("OCTOPUS_CEDAR_SECRET", "short_secret_to_stretch");
    let stretched_secret = load_or_generate_cedar_secret();
    assert_eq!(stretched_secret.len(), 32, "Stretched secret must be 32 bytes");
    std::env::remove_var("OCTOPUS_CEDAR_SECRET");

    // Process-scoped environment loading: 32+ byte key
    std::env::set_var("OCTOPUS_CEDAR_SECRET", "EXACTLY_32_BYTES_PASSPHRASE_TEST!");
    let exact_secret = load_or_generate_cedar_secret();
    assert_eq!(exact_secret, b"EXACTLY_32_BYTES_PASSPHRASE_TEST!");
    std::env::remove_var("OCTOPUS_CEDAR_SECRET");
}

// ==============================================================================
// CHALLENGE 3: Strict RFC 3986 URL Validation & Threat Provenance
// ==============================================================================

#[tokio::test]
async fn test_adversarial_r3_rfc3986_threat_provenance_and_url_validation() {
    let sync_mgr = AtlasSyncManager::default();
    let golden_payload = EMBEDDED_GOLDEN_STIX.as_bytes();

    // 1. MITRE ATLAS URL Anchoring: Spoofed prefixes and substring attacks
    let spoofed_urls = [
        // Subpath injection into other repository
        "https://release-assets.githubusercontent.com/evil-attacker/repo/mitre-atlas/atlas-data/stix.json",
        // Subdomain spoofing
        "https://release-assets.githubusercontent.com.attacker.com/mitre-atlas/atlas-data/stix.json",
        // Prefix trick
        "https://release-assets.githubusercontent.com/mitre-atlas/atlas-data-fake/stix.json",
        // Raw github wrong repo
        "https://raw.githubusercontent.com/attacker/atlas-data/mitre-atlas/atlas-data/stix.json",
        // Insecure scheme
        "http://release-assets.githubusercontent.com/mitre-atlas/atlas-data/stix.json",
    ];

    for bad_url in &spoofed_urls {
        let res = sync_mgr.verify_and_ingest(bad_url, "2026.09", golden_payload, None);
        assert!(
            res.is_err(),
            "Spoofed URL '{}' must be rejected by provenance validation",
            bad_url
        );
    }

    // Valid anchored URLs must pass
    let valid_assets = sync_mgr.verify_and_ingest(
        "https://release-assets.githubusercontent.com/mitre-atlas/atlas-data/stix-atlas.json",
        "2026.09",
        golden_payload,
        None,
    );
    assert!(valid_assets.is_ok(), "Anchored release asset URL must succeed");

    let valid_raw = sync_mgr.verify_and_ingest(
        "https://raw.githubusercontent.com/mitre-atlas/atlas-data/stix-atlas.json",
        "2026.09",
        golden_payload,
        None,
    );
    assert!(valid_raw.is_ok(), "Anchored raw.githubusercontent.com URL must succeed");

    // 2. Non-standard ports rejection
    let bad_ports = [
        "https://release-assets.githubusercontent.com:8443/mitre-atlas/atlas-data/stix.json",
        "https://release-assets.githubusercontent.com:80/mitre-atlas/atlas-data/stix.json",
        "https://atlas.mitre.org:8080/api/v1/matrix",
        "https://atlas.mitre.org:9000/",
    ];
    for bad_port_url in &bad_ports {
        let res = sync_mgr.verify_and_ingest(bad_port_url, "2026.09", golden_payload, None);
        assert!(res.is_err(), "Non-443 port URL '{}' must be rejected", bad_port_url);
    }

    // 3. Embedded userinfo credentials rejection
    let credential_urls = [
        "https://user:password@release-assets.githubusercontent.com/mitre-atlas/atlas-data/stix.json",
        "https://admin@atlas.mitre.org/api/v1/matrix",
        "https://:emptyuser@atlas.mitre.org/api/v1/matrix",
    ];
    for cred_url in &credential_urls {
        let res = sync_mgr.verify_and_ingest(cred_url, "2026.09", golden_payload, None);
        assert!(res.is_err(), "Embedded userinfo URL '{}' must be rejected", cred_url);
    }

    // 4. Strict ISO Calendar Version Formatting (`validate_atlas_version`)
    // Valid formats
    assert!(validate_atlas_version("2024.01"));
    assert!(validate_atlas_version("2026.09"));
    assert!(validate_atlas_version("2030.12"));
    assert!(validate_atlas_version("2025.06-stix2.1"));
    assert!(validate_atlas_version("2027.11-rc.1_golden"));

    // Invalid formats
    let invalid_versions = [
        "2026.1",        // single digit month
        "26.09",         // 2-digit year
        "+2026.09",      // leading sign
        "-2026.09",      // leading minus
        "2023.12",       // year < 2024
        "2031.01",       // year > 2030
        "2025.00",       // month 00
        "2025.13",       // month 13
        "2025.01.01",    // extra sub-parts
        "2025-09",       // dash instead of dot in date
        "2025.09-",      // empty variant tag
        "2025.09-bad tag!", // invalid character in tag
        "",              // empty string
    ];
    for bad_ver in &invalid_versions {
        assert!(
            !validate_atlas_version(bad_ver),
            "Version '{}' must be rejected as invalid",
            bad_ver
        );
    }

    // 5. EgressProxy IPv6 Literals & Anti-SSRF
    let (proxy, _) = EgressProxy::new_for_audit(EgressSecurityLevel::StrictGoogleOnly);

    let blocked_egress = [
        "https://[::1]/internal",
        "https://[::1]:443/internal",
        "https://[::]/internal",
        "https://[fe80::1]/internal",
        "https://[::ffff:127.0.0.1]/internal",
        "https://127.0.0.1/admin",
        "https://localhost/admin",
        "https://169.254.169.254/latest/meta-data",
        "https://metadata.google.internal/computeMetadata/v1",
        "https://evil-c2.com/callback",
        // Embedded credentials in egress
        "https://user:pass@www.google.com/search",
        // Non-standard port in egress
        "https://www.google.com:8443/search",
        "http://www.google.com/search", // insecure scheme
    ];

    for target in &blocked_egress {
        let req = EgressRequest {
            agent_id: "arm-adversary-test".to_string(),
            target_url: target.to_string(),
            method: "GET".to_string(),
            payload: None,
        };
        let egress_res = proxy.dispatch_egress(&req).await;
        assert!(
            egress_res.is_err(),
            "Egress request to '{}' must be blocked by containment proxy",
            target
        );
    }

    // Allowed legitimate request
    let allowed_req = EgressRequest {
        agent_id: "arm-legit-test".to_string(),
        target_url: "https://www.google.com/search?q=security".to_string(),
        method: "GET".to_string(),
        payload: None,
    };
    let allowed_res = proxy.dispatch_egress(&allowed_req).await;
    assert!(allowed_res.is_ok(), "Legitimate allowlisted HTTPS request must succeed");
}

// ==============================================================================
// CHALLENGE 4: CedarGate Direct Rotation, Rollback & Dual-Stack IPv6 Port Parsing
// ==============================================================================

#[tokio::test]
async fn test_adversarial_r4_cedargate_direct_rotation_rollback_and_server_ipv6() {
    let (gate, token) = CedarGate::new_for_audit();
    let (_foreign_gate, foreign_token) = CedarGate::new_for_audit();

    // 1. CedarGate::rotate_secret rejected with foreign token
    let secret_1 = b"CEDAR_GATE_DYNAMIC_ROTATION_KEY_1_32B!";
    let unauth_rot = gate.rotate_secret(secret_1, "cedar_ring_v4.13", &foreign_token).await;
    assert!(
        matches!(unauth_rot, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("UNAUTHORIZED_CALL_PATH")),
        "CedarGate direct rotation must reject foreign token: {:?}",
        unauth_rot
    );

    // 2. CedarGate::rotate_secret succeeds with authentic token
    let auth_rot = gate.rotate_secret(secret_1, "cedar_ring_v4.13", &token).await;
    assert!(auth_rot.is_ok(), "CedarGate direct rotation with authentic token must succeed");

    // 3. CedarGate::rollback_secret rejected with foreign token
    let unauth_rollback = gate.rollback_secret(&foreign_token).await;
    assert!(
        matches!(unauth_rollback, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("UNAUTHORIZED_CALL_PATH")),
        "CedarGate direct rollback must reject foreign token: {:?}",
        unauth_rollback
    );

    // 4. CedarGate::rollback_secret succeeds with authentic token
    let auth_rollback = gate.rollback_secret(&token).await;
    assert!(auth_rollback.is_ok(), "CedarGate direct rollback with authentic token must succeed");

    // Second consecutive rollback must fail closed
    let double_rollback = gate.rollback_secret(&token).await;
    assert!(
        matches!(double_rollback, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("No previous secret epoch exists")),
        "CedarGate double rollback must fail closed: {:?}",
        double_rollback
    );

    // 5. Dual-Stack IPv6 Port Extraction Logic (matching src/web/server.rs)
    fn parse_port(addr: &str) -> &str {
        match addr.rsplit(':').next() {
            Some(p) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => p,
            _ => "5005",
        }
    }

    assert_eq!(parse_port("[::1]:5005"), "5005", "IPv6 loopback literal port extraction");
    assert_eq!(parse_port("[::]:5005"), "5005", "IPv6 wildcard port extraction");
    assert_eq!(parse_port("127.0.0.1:5005"), "5005", "IPv4 loopback port extraction");
    assert_eq!(parse_port("[::1]:8080"), "8080", "Non-default port extraction");
    assert_eq!(parse_port("[::1]"), "5005", "Missing port defaults to 5005");
    assert_eq!(parse_port("invalid_address"), "5005", "Malformed address defaults to 5005");

    // 6. Supervisor Approval Receipt Segregation of Duties
    let gw = CedarAuthorizationGateway::new(b"SEED_SUPERVISOR_TEST_32_BYTES_OK!", "fp_test");

    // Self-approval attempt must be rejected
    let self_approval = gw.issue_supervisor_approval(
        "rogue_supervisor",
        "rogue_supervisor", // same agent requesting and approving
        "corporate_ledger",
        50000,
        300,
    );
    assert!(
        matches!(self_approval, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("Segregation of duties violation")),
        "Supervisor self-approval must be strictly forbidden: {:?}",
        self_approval
    );

    // Valid supervisor approval
    let valid_receipt = gw.issue_supervisor_approval(
        "supervisor_lead",
        "worker_arm_1",
        "corporate_ledger",
        50000,
        300,
    ).expect("Issued valid receipt");

    // Presented by a different agent -> rejected
    let wrong_agent_verify = gw.verify_supervisor_approval(
        &valid_receipt,
        "impostor_agent_2",
        "corporate_ledger",
        50000,
    );
    assert!(
        wrong_agent_verify.is_err(),
        "Receipt presented by different agent must be rejected"
    );

    // Amount exceeds approved ceiling -> rejected
    let ceiling_exceeded_verify = gw.verify_supervisor_approval(
        &valid_receipt,
        "worker_arm_1",
        "corporate_ledger",
        99999, // approved only 50000
    );
    assert!(
        ceiling_exceeded_verify.is_err(),
        "Requested amount exceeding approved receipt limit must be rejected"
    );
}

