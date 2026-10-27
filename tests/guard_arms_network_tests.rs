use agent_octopus::core::types::{ArmRole, OctopusSecurityError};
use agent_octopus::ledger::receipt::SignedExecutionReceipt;
use agent_octopus::security::audit::SecurityAuditLog;
use agent_octopus::security::guard_arms::{
    CapabilityGuard, ContainmentGuard, GuardCoordinator, GuardStatus, IdentityGuard,
    IntegrityGuard, NetworkGuard, SentinelGuard,
};
use agent_octopus::security::identity::AgentIdentity;
use agent_octopus::security::windows_sandbox::{
    WindowsAppContainerProfile, WindowsJobObject, WindowsRestrictedTokenPolicy,
};

#[test]
fn test_sentinel_guard_step_budget_and_memory_clamping() {
    let mut sentinel = SentinelGuard::new("test_sentinel", 5000);
    sentinel.register_arm("arm_doc", 3, 1024 * 1024);

    // Steps 1, 2, 3 should succeed
    assert!(sentinel.record_heartbeat("arm_doc", 100_000).is_ok());
    assert!(sentinel.record_heartbeat("arm_doc", 100_000).is_ok());
    assert!(sentinel.record_heartbeat("arm_doc", 100_000).is_ok());

    // Step 4 exceeds budget (max 3)
    let res = sentinel.record_heartbeat("arm_doc", 100_000);
    assert!(matches!(
        res,
        Err(OctopusSecurityError::ResourceQuotaExceeded(_))
    ));

    // Subsequent call fails because arm was marked dead
    assert!(matches!(
        sentinel.record_heartbeat("arm_doc", 10),
        Err(OctopusSecurityError::LimbKilled)
    ));
}

#[test]
fn test_identity_guard_signature_and_replay_rejection() {
    let mut guard = IdentityGuard::new("test_identity");
    let identity = AgentIdentity::new("agent_1", ArmRole::UntrustedDocIngest, b"test_seed_123");
    guard.register_trusted_identity(identity.clone());

    // 1. Valid signed message
    let msg1 = identity.sign_message("supervisor", 1, "extract_doc");
    assert!(guard.verify_message(&msg1).is_ok());

    // 2. Replay attack with same nonce should fail
    let replay_msg = identity.sign_message("supervisor", 1, "extract_doc");
    let replay_res = guard.verify_message(&replay_msg);
    assert!(matches!(
        replay_res,
        Err(OctopusSecurityError::IdentitySpoofingDetected(_))
    ));

    // 3. Forged sender ID should fail
    let mut forged_msg = identity.sign_message("supervisor", 2, "extract_doc");
    forged_msg.sender_id = "agent_2".to_string();
    let forged_res = guard.verify_message(&forged_msg);
    assert!(matches!(
        forged_res,
        Err(OctopusSecurityError::IdentitySpoofingDetected(_))
    ));
}

#[test]
fn test_capability_guard_least_privilege_and_revocation() {
    let mut guard = CapabilityGuard::new("test_cap", b"master_auth_seed_999", "policy_v1");

    let token = guard.auth_engine().issue_capability(
        "brain",
        "doc_agent",
        ArmRole::UntrustedDocIngest,
        "doc_extractor",
        "s3://invoices/",
    );

    // 1. Legitimate invocation passes
    assert!(guard
        .verify_capability(&token, "doc_agent", "doc_extractor", "s3://invoices/batch1")
        .is_ok());

    // 2. Unauthorized tool access fails
    assert!(matches!(
        guard.verify_capability(&token, "doc_agent", "ledger_writer", "s3://invoices/batch1"),
        Err(OctopusSecurityError::CapabilityDenied(_))
    ));

    // 3. Unauthorized resource prefix fails
    assert!(matches!(
        guard.verify_capability(&token, "doc_agent", "doc_extractor", "s3://secret_keys/"),
        Err(OctopusSecurityError::CapabilityDenied(_))
    ));

    // 4. Token revocation immediately denies access
    guard.revoke_token(&token.token_id);
    assert!(matches!(
        guard.verify_capability(&token, "doc_agent", "doc_extractor", "s3://invoices/batch1"),
        Err(OctopusSecurityError::CapabilityDenied(_))
    ));
}

#[test]
fn test_network_guard_google_egress_and_ssrf_blocking() {
    let mut guard = NetworkGuard::new("test_network");

    // Permitted Google destinations
    assert!(guard.validate_egress("https://google.com").is_ok());
    assert!(guard.validate_egress("https://www.google.com").is_ok());
    assert!(guard
        .validate_egress("https://www.google.com/search?q=rust")
        .is_ok());
    assert!(guard.validate_egress("s3://invoices/2026/").is_ok());

    // Blocked: Substring bypasses
    assert!(matches!(
        guard.validate_egress("https://google.com.attacker.example/collect"),
        Err(OctopusSecurityError::SsrfBlocked(_))
    ));
    assert!(matches!(
        guard.validate_egress("https://attacker-google.com/exfil"),
        Err(OctopusSecurityError::SsrfBlocked(_))
    ));

    // Blocked: AWS / Cloud IMDS metadata
    assert!(matches!(
        guard.validate_egress("https://169.254.169.254/latest/meta-data/"),
        Err(OctopusSecurityError::SsrfBlocked(_))
    ));

    // Blocked: Private RFC 1918 subnets
    assert!(matches!(
        guard.validate_egress("https://192.168.1.1/admin"),
        Err(OctopusSecurityError::SsrfBlocked(_))
    ));

    // Blocked: Insecure HTTP scheme
    assert!(matches!(
        guard.validate_egress("http://www.google.com"),
        Err(OctopusSecurityError::SsrfBlocked(_))
    ));

    // Blocked: Embedded credentials
    assert!(matches!(
        guard.validate_egress("https://admin:pass@google.com"),
        Err(OctopusSecurityError::SsrfBlocked(_))
    ));

    // Blocked: Custom port evasion
    assert!(matches!(
        guard.validate_egress("https://google.com:8443/api"),
        Err(OctopusSecurityError::SsrfBlocked(_))
    ));
}

#[test]
fn test_integrity_guard_audit_chain_and_receipt_validation() {
    let guard = IntegrityGuard::new("test_integrity");
    let audit_log = SecurityAuditLog::new();

    audit_log.record_event("BOOT", "supervisor", "System initialized", "ALLOW");
    audit_log.record_event("TASK", "agent_doc", "Ingesting invoice 1", "ALLOW");
    audit_log.record_event("TASK", "agent_doc", "Ingesting invoice 2", "ALLOW");

    // Hash chain verification succeeds
    let count = guard.verify_audit_trail_integrity(&audit_log).unwrap();
    assert_eq!(count, 3);

    let mut csprng = rand::rngs::OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);

    let receipt = SignedExecutionReceipt::create_and_sign(
        1,
        "doc_agent",
        "doc_extractor",
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
        &signing_key,
    );
    assert!(guard.verify_execution_receipt(&receipt).is_ok());
}

#[test]
fn test_containment_guard_appcontainer_and_job_object_boundaries() {
    let guard = ContainmentGuard::new("test_containment", 64 * 1024 * 1024);

    let profile = WindowsAppContainerProfile::new("agent_isolated", true, true);
    assert!(guard.verify_appcontainer_confinement(&profile).is_ok());

    let token_policy = WindowsRestrictedTokenPolicy::default();
    assert!(guard.verify_restricted_token_policy(&token_policy).is_ok());

    let job = WindowsJobObject::create("Octopus_Test_Job", 1, 32 * 1024 * 1024).unwrap();
    assert!(guard.verify_job_object_limits(&job).is_ok());
}

#[test]
fn test_guard_coordinator_peer_mutual_supervision_and_quorum_isolation() {
    let mut coordinator = GuardCoordinator::new(b"coordinator_seed_555", "policy_v1");

    assert_eq!(
        coordinator.get_guard_status("guard_network"),
        Some(&GuardStatus::Healthy)
    );

    // First accusation: suspected status
    let isolated = coordinator
        .report_peer_anomaly(
            "guard_sentinel",
            "guard_network",
            "Inconsistent egress log detected",
            100,
        )
        .unwrap();
    assert!(!isolated);
    assert_eq!(
        coordinator.get_guard_status("guard_network"),
        Some(&GuardStatus::Suspected)
    );

    // Second accusation
    let isolated2 = coordinator
        .report_peer_anomaly(
            "guard_identity",
            "guard_network",
            "Unauthenticated network token",
            101,
        )
        .unwrap();
    assert!(!isolated2);

    // Third accusation reaches strict majority quorum (> 50% of 5 peers = 3)
    let isolated3 = coordinator
        .report_peer_anomaly(
            "guard_capability",
            "guard_network",
            "Bypassed capability authorization",
            102,
        )
        .unwrap();
    assert!(isolated3);
    assert_eq!(
        coordinator.get_guard_status("guard_network"),
        Some(&GuardStatus::IsolatedByPeerQuorum)
    );

    // Pre-execution guard check now fails closed because guard_network is isolated!
    let res = coordinator.pre_execution_swarm_guard_check(Some("https://google.com"), 1024);
    assert!(matches!(
        res,
        Err(OctopusSecurityError::IsolationViolation(_))
    ));
}
