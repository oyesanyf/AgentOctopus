use agent_octopus::core::types::{ArmRole, OctopusSecurityError};
use agent_octopus::security::audit::SecurityAuditLog;
use agent_octopus::security::capabilities::CapabilityToken;
use agent_octopus::security::cedar_arm::*;
use serde_json::json;

#[test]
fn test_cedar_engine_initialization() {
    let engine = CedarPolicyEngine::new();
    assert!(engine.is_ok(), "Engine failed to initialize: {:?}", engine.err());
    let engine = engine.unwrap();
    assert!(engine.policy_count() >= 4, "Expected at least 4 baseline policies");
}

#[test]
fn test_document_extraction_and_ledger_permit() {
    let engine = CedarPolicyEngine::new().unwrap();

    // 1. Document Extraction by document_arm should be permitted
    let doc_verdict = engine.evaluate(
        "document_arm",
        "extract",
        "doc_001",
        "Document",
        json!({}),
    ).unwrap();
    assert!(doc_verdict.is_allowed, "Expected document extraction to be permitted: {:?}", doc_verdict);

    // 2. Ledger Writing under limit ($500.00 = 50,000 cents) with approval
    let ledger_verdict = engine.evaluate(
        "ledger_arm",
        "write",
        "ledger_001",
        "Ledger",
        json!({
            "amount_cents": 50000,
            "approved": true
        }),
    ).unwrap();
    assert!(ledger_verdict.is_allowed, "Expected ledger write to be permitted: {:?}", ledger_verdict);
}

#[test]
fn test_financial_ceiling_enforcement() {
    let engine = CedarPolicyEngine::new().unwrap();

    // 1. Transaction exceeding $100,000.00 ceiling ($150,000.00 = 15,000,000 cents) must be DENIED
    let over_limit_verdict = engine.evaluate(
        "ledger_arm",
        "write",
        "ledger_001",
        "Ledger",
        json!({
            "amount_cents": 15000000,
            "approved": true
        }),
    ).unwrap();
    assert!(!over_limit_verdict.is_allowed, "Transaction over $100,000 limit must be denied");

    // 2. Transaction under ceiling but lacking approval must be DENIED
    let unapproved_verdict = engine.evaluate(
        "ledger_arm",
        "write",
        "ledger_001",
        "Ledger",
        json!({
            "amount_cents": 50000,
            "approved": false
        }),
    ).unwrap();
    assert!(!unapproved_verdict.is_allowed, "Unapproved ledger write must be denied");

    // 3. Unauthorized agent attempting to write to ledger must be DENIED
    let rogue_verdict = engine.evaluate(
        "untrusted_agent",
        "write",
        "ledger_001",
        "Ledger",
        json!({
            "amount_cents": 1000,
            "approved": true
        }),
    ).unwrap();
    assert!(!rogue_verdict.is_allowed, "Untrusted agent ledger write must be denied");
}

#[test]
fn test_explicit_forbid_overrides_permit() {
    let engine = CedarPolicyEngine::new().unwrap();

    // 1. Any attempt to modify security policy without quorum authorization is explicitly FORBIDDEN
    let tamper_verdict = engine.evaluate(
        "compromised_arm",
        "change_security_policy",
        "policy_001",
        "SystemPolicy",
        json!({}),
    ).unwrap();
    assert!(!tamper_verdict.is_allowed, "Tampering with policy must be denied");

    // 2. Attempt with quorum_authorized: false must still be FORBIDDEN
    let false_quorum_verdict = engine.evaluate(
        "compromised_arm",
        "change_security_policy",
        "policy_001",
        "SystemPolicy",
        json!({
            "quorum_authorized": false
        }),
    ).unwrap();
    assert!(!false_quorum_verdict.is_allowed, "Policy change without true quorum must be denied");

    // 3. When quorum_authorized: true, the explicit forbid condition is satisfied, permitting controlled update
    // Note: Default policy set requires an explicit permit for the update if one exists, or default-denies unless permitted
    let quorum_verdict = engine.evaluate(
        "security_supervisor",
        "change_security_policy",
        "policy_001",
        "SystemPolicy",
        json!({
            "quorum_authorized": true
        }),
    ).unwrap();
    // Default set has forbid unless quorum_authorized, but no blanket permit for change_security_policy unless added
    // So without a permit policy, it default-denies (or permits if policy added)
    assert!(!quorum_verdict.is_allowed, "Without explicit permit, policy change remains default-denied");
}

#[test]
fn test_strict_schema_validation() {
    let validator = CedarPolicyValidator::default();

    // 1. Valid Cedar policy conforming strictly to schema
    let valid_policy = r#"
        permit (
            principal == Octopus::Agent::"document_arm",
            action == Octopus::Action::"extract",
            resource is Octopus::Document
        );
    "#;
    let report = validator.validate_policy_text(valid_policy);
    assert!(report.is_valid, "Valid policy should pass schema validation: {:?}", report.validation_errors);

    // 2. Policy referencing non-existent action in schema must FAIL validation
    let invalid_action_policy = r#"
        permit (
            principal == Octopus::Agent::"rogue_agent",
            action == Octopus::Action::"execute_remote_code",
            resource is Octopus::Document
        );
    "#;
    let invalid_report = validator.validate_policy_text(invalid_action_policy);
    assert!(!invalid_report.is_valid, "Policy with non-existent action must fail validation");

    // 3. Policy with syntax error must FAIL validation
    let syntax_error_policy = r#"
        permit this is completely broken syntax;
    "#;
    let syntax_report = validator.validate_policy_text(syntax_error_policy);
    assert!(!syntax_report.is_valid, "Policy with syntax error must fail validation");
}

#[test]
fn test_network_egress_domain_restriction() {
    let engine = CedarPolicyEngine::new().unwrap();

    // 1. Egress to approved domain google.com is permitted
    let google_verdict = engine.evaluate(
        "network_arm",
        "egress",
        "target_google",
        "NetworkTarget",
        json!({
            "destination_domain": "google.com"
        }),
    ).unwrap();
    assert!(google_verdict.is_allowed, "Egress to google.com must be permitted: {:?}", google_verdict);

    // 2. Egress to approved domain www.google.com is permitted
    let www_google_verdict = engine.evaluate(
        "network_arm",
        "egress",
        "target_www_google",
        "NetworkTarget",
        json!({
            "destination_domain": "www.google.com"
        }),
    ).unwrap();
    assert!(www_google_verdict.is_allowed, "Egress to www.google.com must be permitted");

    // 3. Egress to unauthorized domain must be DENIED
    let malicious_verdict = engine.evaluate(
        "network_arm",
        "egress",
        "target_c2",
        "NetworkTarget",
        json!({
            "destination_domain": "malicious-c2.attacker.com"
        }),
    ).unwrap();
    assert!(!malicious_verdict.is_allowed, "Egress to unauthorized domain must be denied");

    // 4. Substring bypass attempt (e.g. google.com.attacker.org) must be DENIED
    let bypass_verdict = engine.evaluate(
        "network_arm",
        "egress",
        "target_bypass",
        "NetworkTarget",
        json!({
            "destination_domain": "google.com.attacker.org"
        }),
    ).unwrap();
    assert!(!bypass_verdict.is_allowed, "Egress domain substring bypass must be denied");
}

#[test]
fn test_delegation_chain_depth_guard() {
    let delegation_guard = CedarDelegationPolicyGuard::new(2);

    // 1. Direct delegation (1 hop: brain -> document_arm) is permitted
    let one_hop = vec!["brain".to_string()];
    let res1 = delegation_guard.validate_delegation(
        "document_arm",
        &one_hop,
        "document_arm",
        "doc_extractor",
        "doc_contract_01",
    );
    assert!(res1.is_ok(), "1-hop delegation should be permitted: {:?}", res1);

    // 2. 2-hop delegation (brain -> coord -> document_arm) is permitted
    let two_hops = vec!["brain".to_string(), "coordinator".to_string()];
    let res2 = delegation_guard.validate_delegation(
        "document_arm",
        &two_hops,
        "document_arm",
        "doc_extractor",
        "doc_contract_02",
    );
    assert!(res2.is_ok(), "2-hop delegation should be permitted: {:?}", res2);

    // 3. 3-hop delegation exceeds max allowable depth of 2 -> must FAIL
    let three_hops = vec![
        "brain".to_string(),
        "proxy_1".to_string(),
        "proxy_2".to_string(),
    ];
    let res3 = delegation_guard.validate_delegation(
        "document_arm",
        &three_hops,
        "document_arm",
        "doc_extractor",
        "doc_contract_03",
    );
    assert!(matches!(res3, Err(OctopusSecurityError::DelegationScopeViolation(_))));
}

#[test]
fn test_quorum_approved_policy_mutation() {
    let engine = CedarPolicyEngine::new().unwrap();
    let initial_count = engine.policy_count();

    // 1. Initially, notifier_arm cannot call notify
    let initial_verdict = engine.evaluate(
        "notifier_arm",
        "notify",
        "target_agent",
        "Agent",
        json!({}),
    ).unwrap();
    assert!(!initial_verdict.is_allowed, "Notifier should be denied by default");

    // 2. Quorum-approved policy addition: Permit notifier_arm to notify
    let new_policy = r#"
        permit (
            principal == Octopus::Agent::"notifier_arm",
            action == Octopus::Action::"notify",
            resource is Octopus::Agent
        );
    "#;
    let add_res = engine.add_policy(Some("notify_permit_01"), new_policy);
    assert!(add_res.is_ok(), "Policy addition should succeed: {:?}", add_res);
    assert_eq!(engine.policy_count(), initial_count + 1);

    // 3. Now notifier_arm is permitted
    let after_verdict = engine.evaluate(
        "notifier_arm",
        "notify",
        "target_agent",
        "Agent",
        json!({}),
    ).unwrap();
    assert!(after_verdict.is_allowed, "Notifier should now be permitted by new policy");
}

#[test]
fn test_cryptographic_audit_bridge() {
    let secret_seed = b"test_secret_seed_32_bytes_long!!";
    let policy_fingerprint = "cedar_v1_fingerprint";
    let audit_log = SecurityAuditLog::new();

    let gateway = CedarAuthorizationGateway::new(secret_seed, policy_fingerprint)
        .with_audit_log(audit_log);

    // 1. Issue a valid capability token for document_arm -> doc_extractor
    let valid_token = gateway.auth_engine().issue_capability(
        "brain",
        "document_arm",
        ArmRole::UntrustedDocIngest,
        "doc_extractor",
        "invoice_",
    );

    // 2. Authorize legitimate invocation
    let auth_res = gateway.authorize_tool_invocation(
        &valid_token,
        "document_arm",
        "doc_extractor",
        "invoice_2026_001",
        json!({}),
    );
    assert!(auth_res.is_ok(), "Legitimate tool invocation should be authorized: {:?}", auth_res);

    // 3. Verify audit log captured the authorization event and hash chain is intact
    let audit_ref = gateway.audit_log().expect("Audit log should be present");
    let entries = audit_ref.get_entries();
    assert!(!entries.is_empty(), "Audit log should have recorded the event");
    assert!(audit_ref.verify_integrity(), "Audit log cryptographic chain must be valid");

    let last_event = entries.last().unwrap();
    assert_eq!(last_event.event_type, "CEDAR_AUTHORIZATION");
    assert_eq!(last_event.agent_id, "document_arm");
    assert_eq!(last_event.decision, "ALLOW");

    // 4. Forged token attempt (tampered signature) must be rejected before Cedar
    let mut tampered_token = valid_token.clone();
    tampered_token.signature_hex = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    let forged_res = gateway.authorize_tool_invocation(
        &tampered_token,
        "document_arm",
        "doc_extractor",
        "invoice_2026_001",
        json!({}),
    );
    assert!(matches!(forged_res, Err(OctopusSecurityError::CapabilityDenied(_))));
}

// ============================================================================
// RED-TEAM BOUNDARY & ESCALATION TEST SUITE (10 ADVERSARIAL ATTACK PATHS)
// ============================================================================

#[test]
fn test_redteam_1_context_manipulation_untrusted_approval() {
    let secret_seed = b"test_secret_seed_32_bytes_long!!";
    let policy_fingerprint = "cedar_v1_fingerprint";
    let gateway = CedarAuthorizationGateway::new(secret_seed, policy_fingerprint);

    let token = gateway.auth_engine().issue_capability(
        "brain",
        "ledger_arm",
        ArmRole::AccountingLedgerWrite,
        "ledger_writer",
        "corporate_ledger",
    );

    // 1. ATTACK: Compromised agent self-asserts "approved: true" and "amount_cents: 95000" in untrusted context
    let unverified_context = json!({
        "approved": true,
        "amount_cents": 95000
    });

    let attack_result = gateway.authorize_tool_invocation(
        &token,
        "ledger_arm",
        "ledger_writer",
        "corporate_ledger",
        unverified_context,
    );
    assert!(
        matches!(attack_result, Err(OctopusSecurityError::CapabilityDenied(_))),
        "Authorization-context injection must be DENIED without verified supervisor receipt: {:?}",
        attack_result
    );

    // 2. DEFENSE: Provide genuine cryptographic SupervisorApprovalReceipt and satisfy Dogwood temporal read prerequisite
    let receipt = gateway.issue_supervisor_approval(
        "security_supervisor",
        "ledger_arm",
        "corporate_ledger",
        100000,
        300,
    ).expect("Supervisor should be able to issue approval for another agent");

    gateway.temporal_engine().record_event(
        "LedgerRead",
        agent_octopus::security::cedar_arm::temporal::EventKind::Response,
        "ledger_arm",
        "corporate_ledger",
        std::collections::HashMap::new(),
    );

    let verified_result = gateway.authorize_tool_invocation_with_approval(
        &token,
        "ledger_arm",
        "ledger_writer",
        "corporate_ledger",
        json!({ "amount_cents": 95000 }),
        Some(&receipt),
    );
    assert!(
        verified_result.is_ok(),
        "Properly attested supervisor approval must be ALLOWED: {:?}",
        verified_result
    );
}

#[test]
fn test_redteam_2_identity_spoofing_claim_another_arm() {
    let secret_seed = b"test_secret_seed_32_bytes_long!!";
    let policy_fingerprint = "cedar_v1_fingerprint";
    let gateway = CedarAuthorizationGateway::new(secret_seed, policy_fingerprint);

    // Token issued specifically to ledger_arm
    let token = gateway.auth_engine().issue_capability(
        "brain",
        "ledger_arm",
        ArmRole::AccountingLedgerWrite,
        "ledger_writer",
        "corporate_ledger",
    );

    // ATTACK: Rogue arm steals/presents token claiming to be ledger_arm
    let attack_result = gateway.authorize_tool_invocation(
        &token,
        "rogue_arm_intruder",
        "ledger_writer",
        "corporate_ledger",
        json!({ "amount_cents": 1000 }),
    );
    assert!(
        matches!(attack_result, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("Token bearer mismatch")),
        "Identity spoofing must be DENIED by bearer binding: {:?}",
        attack_result
    );
}

#[test]
fn test_redteam_3_confused_deputy_delegation_unauthorized_ledger_write() {
    let secret_seed = b"test_secret_seed_32_bytes_long!!";
    let policy_fingerprint = "cedar_v1_fingerprint";
    let gateway = CedarAuthorizationGateway::new(secret_seed, policy_fingerprint);

    // Token issued to ledger_arm
    let token = gateway.auth_engine().issue_capability(
        "document_arm",
        "ledger_arm",
        ArmRole::AccountingLedgerWrite,
        "ledger_writer",
        "corporate_ledger",
    );

    let receipt = gateway.issue_supervisor_approval(
        "security_supervisor",
        "ledger_arm",
        "corporate_ledger",
        50000,
        300,
    ).unwrap();

    // ATTACK: Document Arm (only authorized for extract on Document) delegates ledger_writer to Ledger Arm
    // Even though ledger_arm has write capability, document_arm (originator) does NOT!
    let chain = vec!["document_arm".to_string(), "ledger_arm".to_string()];
    let attack_result = gateway.authorize_delegated_invocation(
        &token,
        "document_arm",
        &chain,
        "ledger_arm",
        "ledger_writer",
        "corporate_ledger",
        json!({ "amount_cents": 25000 }),
        Some(&receipt),
    );

    assert!(
        attack_result.is_err(),
        "Cross-arm privilege laundering / confused deputy must be DENIED because originator lacks write permission"
    );
}

#[test]
fn test_redteam_4_altered_resource_identity() {
    let secret_seed = b"test_secret_seed_32_bytes_long!!";
    let policy_fingerprint = "cedar_v1_fingerprint";
    let gateway = CedarAuthorizationGateway::new(secret_seed, policy_fingerprint);

    // Token issued only for prefix "s3://invoices/2026/"
    let token = gateway.auth_engine().issue_capability(
        "brain",
        "document_arm",
        ArmRole::UntrustedDocIngest,
        "doc_extractor",
        "s3://invoices/2026/",
    );

    // ATTACK: Attacker presents token to read payroll data outside authorized prefix
    let attack_result = gateway.authorize_tool_invocation(
        &token,
        "document_arm",
        "doc_extractor",
        "s3://private_payroll/salaries.csv",
        json!({}),
    );

    assert!(
        matches!(attack_result, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("Resource scope violation")),
        "Access to altered resource outside token prefix must be DENIED: {:?}",
        attack_result
    );
}

#[test]
fn test_redteam_5_toctou_resource_replaced_before_execution() {
    // Authorized digest computed at time-of-check
    let authorized_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    // Maliciously swapped content digest at time-of-use
    let swapped_execution_digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    // ATTACK: Resource content changed between authorization and execution
    let toctou_check = CedarAuthorizationGateway::verify_toctou_digest(
        authorized_digest,
        swapped_execution_digest,
    );

    assert!(
        matches!(toctou_check, Err(OctopusSecurityError::MerkleTamperDetected(ref msg)) if msg.contains("TOCTOU violation")),
        "TOCTOU resource tampering must be DENIED immediately: {:?}",
        toctou_check
    );

    // Legitimate unaltered execution
    let legitimate_check = CedarAuthorizationGateway::verify_toctou_digest(
        authorized_digest,
        authorized_digest,
    );
    assert!(legitimate_check.is_ok(), "Unaltered resource execution must be ALLOWED");
}

#[test]
fn test_redteam_6_tool_invocation_bypasses_cedar_gateway() {
    let secret_seed = b"test_secret_seed_32_bytes_long!!";
    let policy_fingerprint = "cedar_v1_fingerprint";
    let gateway = CedarAuthorizationGateway::new(secret_seed, policy_fingerprint);

    // ATTACK: Worker tries to execute unmediated tool action without obtaining a capability token
    let forged_token = CapabilityToken {
        token_id: "UNAUTHORIZED_NO_KEY".to_string(),
        originator_agent: "untrusted_worker".to_string(),
        bearer_agent: "untrusted_worker".to_string(),
        permitted_role: ArmRole::AccountingLedgerWrite,
        permitted_tool: "ledger_writer".to_string(),
        resource_uri_prefix: "corporate_ledger".to_string(),
        issued_at_secs: 1000,
        expires_at_secs: 9999999999,
        policy_fingerprint: policy_fingerprint.to_string(),
        signature_hex: "deadbeef00000000deadbeef".to_string(),
    };

    let bypass_result = gateway.authorize_tool_invocation(
        &forged_token,
        "untrusted_worker",
        "ledger_writer",
        "corporate_ledger",
        json!({}),
    );

    assert!(
        matches!(bypass_result, Err(OctopusSecurityError::CapabilityDenied(_))),
        "Unmediated tool execution bypassing authorization must be BLOCKED: {:?}",
        bypass_result
    );
}

#[test]
fn test_redteam_7_fail_closed_when_cedar_policy_becomes_unavailable() {
    let secret_seed = b"test_secret_seed_32_bytes_long!!";
    let policy_fingerprint = "cedar_v1_fingerprint";
    let gateway = CedarAuthorizationGateway::new(secret_seed, policy_fingerprint);

    let token = gateway.auth_engine().issue_capability(
        "brain",
        "document_arm",
        ArmRole::UntrustedDocIngest,
        "non_existent_tool_xyz",
        "resource_01",
    );

    // ATTACK: Request an unregistered tool action that cannot be resolved in policy
    let fail_closed_result = gateway.authorize_tool_invocation(
        &token,
        "document_arm",
        "non_existent_tool_xyz",
        "resource_01",
        json!({}),
    );

    assert!(
        matches!(fail_closed_result, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("Unrecognized tool action")),
        "System must FAIL-CLOSED when tool action is unregistered or policy engine cannot resolve: {:?}",
        fail_closed_result
    );
}

#[test]
fn test_redteam_8_agent_requests_policy_change() {
    let secret_seed = b"test_secret_seed_32_bytes_long!!";
    let policy_fingerprint = "cedar_v1_fingerprint";
    let gateway = CedarAuthorizationGateway::new(secret_seed, policy_fingerprint);

    let token = gateway.auth_engine().issue_capability(
        "brain",
        "rogue_agent",
        ArmRole::UntrustedDocIngest,
        "change_security_policy",
        "system_policy_01",
    );

    // ATTACK: Rogue agent attempts to mutate security policy without 2-of-3 quorum consensus
    let attack_result = gateway.authorize_tool_invocation(
        &token,
        "rogue_agent",
        "change_security_policy",
        "system_policy_01",
        json!({ "quorum_authorized": false }),
    );

    assert!(
        attack_result.is_err(),
        "Agent policy change request without quorum consensus must be explicitly FORBIDDEN: {:?}",
        attack_result
    );
}

#[test]
fn test_redteam_9_compromised_guard_self_approval() {
    let secret_seed = b"test_secret_seed_32_bytes_long!!";
    let policy_fingerprint = "cedar_v1_fingerprint";
    let gateway = CedarAuthorizationGateway::new(secret_seed, policy_fingerprint);

    // ATTACK: Compromised guard attempts to approve its own ledger write action (Segregation of Duties breach)
    let self_approval_result = gateway.issue_supervisor_approval(
        "rogue_guard_1",
        "rogue_guard_1", // supervisor == requesting_agent!
        "corporate_ledger",
        50000,
        300,
    );

    assert!(
        matches!(self_approval_result, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("Segregation of duties violation")),
        "Self-approval by compromised guard must be DENIED: {:?}",
        self_approval_result
    );
}

#[test]
fn test_redteam_10_signed_capability_replayed_after_revocation() {
    let secret_seed = b"test_secret_seed_32_bytes_long!!";
    let policy_fingerprint = "cedar_v1_fingerprint";
    let gateway = CedarAuthorizationGateway::new(secret_seed, policy_fingerprint);

    let token = gateway.auth_engine().issue_capability(
        "brain",
        "document_arm",
        ArmRole::UntrustedDocIngest,
        "doc_extractor",
        "invoice_doc_1",
    );

    // 1. Initial valid invocation succeeds
    let initial_res = gateway.authorize_tool_invocation(
        &token,
        "document_arm",
        "doc_extractor",
        "invoice_doc_1",
        json!({}),
    );
    assert!(initial_res.is_ok(), "Initial invocation with valid capability must succeed");

    // 2. Security supervisor revokes the capability token
    gateway.auth_engine().revoke_token(&token.token_id);
    assert!(gateway.auth_engine().is_revoked(&token.token_id));

    // 3. ATTACK: Attacker attempts to replay the revoked capability token
    let replay_result = gateway.authorize_tool_invocation(
        &token,
        "document_arm",
        "doc_extractor",
        "invoice_doc_1",
        json!({}),
    );

    assert!(
        matches!(replay_result, Err(OctopusSecurityError::CapabilityDenied(ref msg)) if msg.contains("has been revoked")),
        "Replay of revoked capability token must be DENIED: {:?}",
        replay_result
    );
}

#[test]
fn test_tarpit_arm_authorization_and_quarantine() {
    let engine = CedarPolicyEngine::new().unwrap();

    // 1. Tarpit Arm is permitted to quarantine DecoyTrap
    let verdict = engine.evaluate(
        "tarpit_arm",
        "quarantine",
        "trap_001",
        "DecoyTrap",
        json!({
            "adversary_ip": "192.168.1.100",
            "attack_type": "prompt_injection"
        }),
    ).unwrap();
    assert!(verdict.is_allowed, "Expected tarpit_arm quarantine action to be permitted: {:?}", verdict);

    // 2. Unauthorized untrusted agent attempting quarantine must be DENIED
    let denied = engine.evaluate(
        "untrusted_agent",
        "quarantine",
        "trap_001",
        "DecoyTrap",
        json!({}),
    ).unwrap();
    assert!(!denied.is_allowed, "Untrusted agent must not be permitted to quarantine decoy trap");
}

#[test]
fn test_cedar_engine_panic_boundary_and_malformed_context() {
    let engine = CedarPolicyEngine::new().unwrap();

    // 1. Missing schema fields returns structured ContextError without panicking
    let malformed_schema_json = json!({
        "deep": {
            "nested": {
                "layers": [1, 2, 3, {"null_val": null, "bool": false}]
            }
        },
        "amount_cents": "not_an_integer",
        "special_chars": "\u{0000}\n\r\t\"\\'--/*"
    });

    let res = engine.evaluate(
        "ledger_arm",
        "write",
        "ledger_001",
        "Ledger",
        malformed_schema_json,
    );
    assert!(
        matches!(res, Err(CedarEngineError::ContextError(_))),
        "Malformed schema context should return structured ContextError: {:?}",
        res
    );

    // 2. Schema-compliant fields with adversarial values returns Ok(verdict) with is_allowed == false
    let adversarial_context = json!({
        "amount_cents": -999999,
        "approved": false
    });

    let res2 = engine.evaluate(
        "ledger_arm",
        "write",
        "ledger_001",
        "Ledger",
        adversarial_context,
    );
    assert!(res2.is_ok(), "Valid schema structure must evaluate safely: {:?}", res2);
    let verdict = res2.unwrap();
    assert!(!verdict.is_allowed, "Adversarial amount must be denied");

    // 3. Extra/duplicate key semantic must fail Cedar schema validation
    let extra_key_context = json!({
        "amount_cents": 50000,
        "amount_cents_2": 99999999,
        "approved": true
    });
    let res3 = engine.evaluate(
        "ledger_arm",
        "write",
        "ledger_001",
        "Ledger",
        extra_key_context,
    );
    assert!(
        matches!(res3, Err(CedarEngineError::ContextError(_))),
        "Extra or duplicate context keys must be rejected by schema: {:?}",
        res3
    );
}




#[test]
fn test_secret_rotation_entropy_and_rollback() {
    let initial_secret = b"INITIAL_SECRET_32_BYTES_FOR_AUTH";
    let mut gateway = CedarAuthorizationGateway::new(initial_secret, "cedar_policy_v1");

    assert_eq!(gateway.active_epoch().generation, 1);
    assert!(gateway.previous_epoch().is_none());

    // 1. Rejects empty secret
    let err_empty = gateway.rotate_secret(b"", "cedar_policy_v1");
    assert!(err_empty.is_err(), "Must reject empty secret key");

    // 2. Rejects secret with insufficient entropy (< 32 bytes)
    let err_short = gateway.rotate_secret(b"too_short_secret", "cedar_policy_v1");
    assert!(err_short.is_err(), "Must reject secret under 32 bytes");

    // 3. Rejects identical secret (idempotency violation)
    let err_identical = gateway.rotate_secret(initial_secret, "cedar_policy_v1");
    assert!(err_identical.is_err(), "Must reject identical secret");

    // 4. Successful rotation
    let new_secret = b"NEW_ROTATED_SECRET_32_BYTES_KEY1";
    let rotate_res = gateway.rotate_secret(new_secret, "cedar_policy_v1");
    assert!(rotate_res.is_ok());
    assert_eq!(gateway.active_epoch().generation, 2);
    assert!(gateway.previous_epoch().is_some());
    assert_eq!(gateway.previous_epoch().unwrap().generation, 1);

    // 5. Rollback to previous epoch
    let rollback_res = gateway.rollback_secret();
    assert!(rollback_res.is_ok());
    assert_eq!(gateway.active_epoch().generation, 3);
    assert_eq!(gateway.active_epoch().secret, initial_secret.to_vec());
    assert!(gateway.previous_epoch().is_none());

    // 6. Secondary rollback fails safely (fail closed: no previous epoch)
    let second_rollback = gateway.rollback_secret();
    assert!(second_rollback.is_err(), "Second rollback must fail closed");
}

#[test]
fn test_secret_rotation_grace_period_dual_verification() {
    let secret_a = b"SECRET_A_INITIAL_32_BYTES_KEY_01";
    let secret_b = b"SECRET_B_ROTATED_32_BYTES_KEY_02";
    let mut gateway = CedarAuthorizationGateway::new(secret_a, "cedar_policy_v1");

    // Issue supervisor approval receipt with Secret A
    let receipt = gateway.issue_supervisor_approval(
        "security_supervisor",
        "ledger_arm",
        "corporate_ledger",
        100000,
        300,
    ).unwrap();

    // Issue capability token with Secret A
    let token = gateway.auth_engine().issue_capability(
        "security_supervisor",
        "ledger_arm",
        ArmRole::AccountingLedgerWrite,
        "ledger_writer",
        "corporate_ledger",
    );

    // Rotate to Secret B
    gateway.rotate_secret(secret_b, "cedar_policy_v1").unwrap();

    // Verify supervisor approval receipt still passes under grace period
    let verify_receipt = gateway.verify_supervisor_approval(
        &receipt,
        "ledger_arm",
        "corporate_ledger",
        50000,
    );
    assert!(verify_receipt.is_ok(), "Supervisor approval must pass during 300s grace window");

    // Record prerequisite read in Dogwood temporal trace
    gateway.temporal_engine().record_event(
        "LedgerRead",
        agent_octopus::security::cedar_arm::temporal::EventKind::Response,
        "ledger_arm",
        "corporate_ledger",
        std::collections::HashMap::new(),
    );

    // Verify capability invocation still passes under grace period
    let verdict = gateway.authorize_tool_invocation_with_approval(
        &token,
        "ledger_arm",
        "ledger_writer",
        "corporate_ledger",
        json!({
            "amount_cents": 50000,
            "approved": true
        }),
        Some(&receipt),
    );
    assert!(verdict.is_ok(), "Capability token must pass during 300s grace window: {:?}", verdict.err());

    // Revoke token; verify revocation persists across subsequent rotation
    gateway.auth_engine().revoke_token(&token.token_id);
    let secret_c = b"SECRET_C_ROTATED_32_BYTES_KEY_03";
    gateway.rotate_secret(secret_c, "cedar_policy_v1").unwrap();

    let revoked_verdict = gateway.authorize_tool_invocation_with_approval(
        &token,
        "ledger_arm",
        "ledger_writer",
        "corporate_ledger",
        json!({
            "amount_cents": 50000,
            "approved": true
        }),
        Some(&receipt),
    );
    assert!(revoked_verdict.is_err(), "Revoked token must remain revoked across rotations");
}

#[tokio::test]
async fn test_rfc3986_atlas_version_and_egress_hardening() {
    use agent_octopus::security::atlas_arm::atlas_sync::{validate_atlas_version, AtlasSyncManager};
    use agent_octopus::containment_ring::egress_proxy::{EgressProxy, EgressRequest, EgressSecurityLevel};

    // 1. Strict ISO Calendar Version Formatting
    assert!(validate_atlas_version("2026.02"), "Valid YYYY.MM");
    assert!(validate_atlas_version("2024.12-stix2.1"), "Valid YYYY.MM with tag");
    assert!(!validate_atlas_version("2026.2"), "Single-digit month must be rejected");
    assert!(!validate_atlas_version("26.02"), "2-digit year must be rejected");
    assert!(!validate_atlas_version("+2026.02"), "Leading signs must be rejected");
    assert!(!validate_atlas_version("2023.12"), "Year before 2024 must be rejected");
    assert!(!validate_atlas_version("2031.01"), "Year after 2030 must be rejected");
    assert!(!validate_atlas_version("2026.00"), "Month 00 must be rejected");
    assert!(!validate_atlas_version("2026.13"), "Month 13 must be rejected");

    // 2. MITRE ATLAS Provenance URL Anchoring and Port Validation
    let sync_mgr = AtlasSyncManager::default();
    let golden_payload = agent_octopus::security::atlas_arm::EMBEDDED_GOLDEN_STIX.as_bytes();

    // Release assets with anchored prefix succeeds
    let valid_asset = sync_mgr.verify_and_ingest(
        "https://release-assets.githubusercontent.com/mitre-atlas/atlas-data/stix-atlas.json",
        "2026.09",
        golden_payload,
        None,
    );
    assert!(valid_asset.is_ok(), "Anchored release asset URL must succeed");

    // Release assets without anchored prefix (path traversal/subpath trick) fails
    let unanchored_asset = sync_mgr.verify_and_ingest(
        "https://release-assets.githubusercontent.com/attacker/repo/mitre-atlas/atlas-data/stix-atlas.json",
        "2026.09",
        golden_payload,
        None,
    );
    assert!(unanchored_asset.is_err(), "Unanchored release asset URL must be rejected");

    // Embedded userinfo credentials fails
    let creds_asset = sync_mgr.verify_and_ingest(
        "https://admin:secret@release-assets.githubusercontent.com/mitre-atlas/atlas-data/stix-atlas.json",
        "2026.09",
        golden_payload,
        None,
    );
    assert!(creds_asset.is_err(), "Embedded credentials must be rejected");

    // Non-443 port fails
    let port_asset = sync_mgr.verify_and_ingest(
        "https://release-assets.githubusercontent.com:8443/mitre-atlas/atlas-data/stix-atlas.json",
        "2026.09",
        golden_payload,
        None,
    );
    assert!(port_asset.is_err(), "Non-standard port must be rejected");

    // 3. Egress Proxy Anti-SSRF and IPv6 Loopback Protection
    let (proxy, _token) = EgressProxy::new_for_audit(EgressSecurityLevel::StrictGoogleOnly);

    // IPv6 Loopback literal
    let req_v6 = EgressRequest {
        agent_id: "agent_1".to_string(),
        target_url: "https://[::1]/secret".to_string(),
        method: "GET".to_string(),
        payload: None,
    };
    assert!(proxy.dispatch_egress(&req_v6).await.is_err(), "IPv6 [::1] must be blocked");

    // IPv4-mapped IPv6 loopback
    let req_v4_mapped = EgressRequest {
        agent_id: "agent_1".to_string(),
        target_url: "https://[::ffff:127.0.0.1]/secret".to_string(),
        method: "GET".to_string(),
        payload: None,
    };
    assert!(proxy.dispatch_egress(&req_v4_mapped).await.is_err(), "IPv4-mapped [::ffff:127.0.0.1] must be blocked");

    // Userinfo credentials in egress URL
    let req_creds = EgressRequest {
        agent_id: "agent_1".to_string(),
        target_url: "https://user:pass@google.com/search".to_string(),
        method: "GET".to_string(),
        payload: None,
    };
    assert!(proxy.dispatch_egress(&req_creds).await.is_err(), "Userinfo credentials in egress must be blocked");
}
