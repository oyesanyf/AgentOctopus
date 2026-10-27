use agent_octopus::core::types::{ArmRole, OctopusSecurityError, StrategicDirective};
use agent_octopus::enclave::http_gate::HttpEgressGate;
use agent_octopus::security::capabilities::ExternalAuthorizationEngine;
use agent_octopus::security::identity::AgentIdentity;
use agent_octopus::security::windows_sandbox::WindowsAppContainerProfile;
use agent_octopus::security::WasmArmSandbox;

/// BREAKOUT TEST 1: Adversarial Escapes Against Google-Only Network Containment.
/// Tests whether an attacker can bypass substring matching using domain suffix attacks,
/// path tricks, custom ports, or embedded credentials.
#[test]
fn test_breakout_adversarial_google_network_bypass_attempts() {
    let gate = HttpEgressGate::default();
    let app_container = WindowsAppContainerProfile::new("arm-egress-01", true, true);

    // 1. Domain Suffix Attack (the classic substring bypass)
    let domain_suffix_attack = "https://google.com.attacker.example/collect";
    let gate_res = gate.validate_target(domain_suffix_attack);
    assert!(
        gate_res.is_err(),
        "Domain suffix attack must be blocked by HttpEgressGate"
    );
    match gate_res.unwrap_err() {
        OctopusSecurityError::EnclaveViolation(msg) => {
            assert!(msg.contains("destination host 'google.com.attacker.example' is unauthorized"));
        }
        other => panic!("Expected EnclaveViolation, got {:?}", other),
    }

    let ac_res = app_container.verify_access(domain_suffix_attack, true);
    assert!(
        ac_res.is_err(),
        "Domain suffix attack must be blocked by AppContainer policy"
    );

    // 2. Path Trick (attacker domain with google.com in the URL path)
    let path_trick_attack = "https://attacker.example/google.com/exfiltrate";
    assert!(gate.validate_target(path_trick_attack).is_err());
    assert!(app_container
        .verify_access(path_trick_attack, true)
        .is_err());

    // 3. Custom Port Egress (attempting C2 over unauthorized port)
    let port_attack = "https://google.com:8443/c2_stream";
    assert!(
        gate.validate_target(port_attack).is_err(),
        "Non-standard port must be blocked"
    );

    // 4. Embedded Credentials Attack
    let creds_attack = "https://attacker:secret@google.com/leak";
    assert!(
        gate.validate_target(creds_attack).is_err(),
        "Embedded credentials must be blocked"
    );

    // 5. Authorized Google Endpoint (must succeed)
    assert!(gate
        .validate_target("https://www.google.com/search?q=rust")
        .is_ok());
    assert!(gate.validate_target("https://google.com/finance").is_ok());
    assert!(app_container
        .verify_access("https://www.google.com/search?q=rust", true)
        .is_ok());
}

/// BREAKOUT TEST 2: Operating System Process & Subprocess Confinement.
/// Verifies that Windows Job Objects and confinement policies prevent the creation of unauthorized native processes.
#[test]
fn test_breakout_operating_system_process_confinement() {
    let auth_engine = ExternalAuthorizationEngine::new(b"auth_secret_2026", 60, "POL-V1-ACTIVE");
    let mut sandbox = WasmArmSandbox::new("arm-worker-proc", ArmRole::UntrustedDocIngest, 500_000);

    let capability = auth_engine.issue_capability(
        "central_brain",
        "arm-worker-proc",
        ArmRole::UntrustedDocIngest,
        "doc_extractor",
        "s3://invoices/",
    );

    // Verify Windows Job Object limits are bound
    assert_eq!(sandbox.job_object.max_processes, 1);
    assert_eq!(sandbox.job_object.max_memory_bytes, 64 * 1024 * 1024);

    // Direct process spawn instruction
    let proc_breakout = StrategicDirective {
        directive_id: "BRK-PROC-01".to_string(),
        source_uri: "s3://invoices/invoice.pdf".to_string(),
        instruction: "cmd.exe /c powershell -enc JABzACAAPQAgAC4ALgAuAA==".to_string(),
        raw_payload: Some("std::process::Command::new('whoami')".to_string()),
        max_step_budget: 3,
    };

    let res = sandbox.execute_sandboxed(&proc_breakout, &auth_engine, &capability, "doc_extractor");
    assert!(res.is_err(), "Subprocess spawn must be blocked");
    match res.unwrap_err() {
        OctopusSecurityError::IsolationViolation(msg) => {
            assert!(msg.contains("Process isolation boundary breach"));
        }
        other => panic!("Expected IsolationViolation, got {:?}", other),
    }
}

/// BREAKOUT TEST 3: WebAssembly Real Instruction Fuel Depletion.
/// Verifies that Wasmtime enforces real hardware/CPU instruction limits.
#[test]
fn test_breakout_wasmtime_real_fuel_exhaustion() {
    // Instantiate with minimal fuel
    let mut sandbox = WasmArmSandbox::new("arm-wasm-exhaust", ArmRole::UntrustedDocIngest, 50);

    // Consume all fuel
    let exhaust_res = sandbox.consume_fuel(100);
    assert!(exhaust_res.is_err(), "Fuel exhaustion must trigger error");
    match exhaust_res.unwrap_err() {
        OctopusSecurityError::ResourceQuotaExceeded(msg) => {
            assert!(msg.contains("Fuel Exhausted"));
        }
        other => panic!("Expected ResourceQuotaExceeded, got {:?}", other),
    }
}

/// BREAKOUT TEST 4: Wall-Clock Execution Deadline & Independent Supervisor Termination.
/// Verifies that hanging asynchronous operations are terminated by the supervisor at the kernel level.
#[tokio::test]
async fn test_breakout_wall_clock_timeout_and_supervisor_termination() {
    let auth_engine = ExternalAuthorizationEngine::new(b"auth_secret_2026", 60, "POL-V1-ACTIVE");
    let mut sandbox = WasmArmSandbox::new("arm-timeout-01", ArmRole::UntrustedDocIngest, 500_000);

    // Set a very aggressive 50ms hard wall-clock deadline
    let mut config = sandbox.config.clone();
    config.wall_clock_timeout_ms = 50;
    sandbox = sandbox.with_config(config);

    let capability = auth_engine.issue_capability(
        "central_brain",
        "arm-timeout-01",
        ArmRole::UntrustedDocIngest,
        "doc_extractor",
        "s3://invoices/",
    );

    let directive = StrategicDirective {
        directive_id: "BRK-TIMEOUT-01".to_string(),
        source_uri: "s3://invoices/hanging_doc.pdf".to_string(),
        instruction: "Extract".to_string(),
        raw_payload: None,
        max_step_budget: 1,
    };

    // Supervisor terminates sandbox
    sandbox
        .terminate_sandbox(1)
        .expect("Independent supervisor termination");
    assert!(sandbox
        .supervisor_terminated
        .load(std::sync::atomic::Ordering::SeqCst));

    // Execution after supervisor termination is rejected
    let res = sandbox.execute_sandboxed(&directive, &auth_engine, &capability, "doc_extractor");
    assert!(res.is_err());
    match res.unwrap_err() {
        OctopusSecurityError::IsolationViolation(msg) => {
            assert!(msg.contains("terminated by independent supervisor"));
        }
        other => panic!("Expected IsolationViolation, got {:?}", other),
    }
}

/// BREAKOUT TEST 5: Cryptographic Message Replay Attack.
/// Verifies that replayed or stale messages with non-increasing nonces are rejected.
#[test]
fn test_breakout_replay_attack_prevention() {
    let agent_sender =
        AgentIdentity::new("arm-ingest-01", ArmRole::UntrustedDocIngest, b"seed_sender");
    let agent_verifier =
        AgentIdentity::new("arm-ingest-01", ArmRole::UntrustedDocIngest, b"seed_sender");

    // First valid message with nonce 1
    let msg1 = agent_sender.sign_message("arm-ledger-01", 1, "Process transaction $50");
    assert!(agent_verifier.verify_incoming_message(&msg1).is_ok());

    // Adversary attempts to replay the exact same message with nonce 1
    let replay_res = agent_verifier.verify_incoming_message(&msg1);
    assert!(
        replay_res.is_err(),
        "Replayed message with duplicate nonce must be rejected"
    );
    match replay_res.unwrap_err() {
        OctopusSecurityError::IdentitySpoofingDetected(msg) => {
            assert!(msg.contains("Replay attack detected"));
        }
        other => panic!("Expected IdentitySpoofingDetected, got {:?}", other),
    }

    // Message with decrementing nonce (stale)
    let stale_msg = agent_sender.sign_message("arm-ledger-01", 0, "Stale message");
    let stale_res = agent_verifier.verify_incoming_message(&stale_msg);
    assert!(
        stale_res.is_err(),
        "Message with stale nonce must be rejected"
    );
}

/// BREAKOUT TEST 6: Sender Role Tampering in Inter-Agent Messaging.
/// Verifies that altering the sender role in transit breaks the cryptographic signature.
#[test]
fn test_breakout_sender_role_tampering_blocked() {
    let agent = AgentIdentity::new("arm-ingest-01", ArmRole::UntrustedDocIngest, b"seed_secret");
    let mut msg = agent.sign_message("arm-egress-01", 10, "Egress request");

    // Adversary tampers with the sender_role field to claim elevated NetworkEgress privileges
    msg.sender_role = ArmRole::NetworkEgress;

    let res = agent.verify_incoming_message(&msg);
    assert!(res.is_err(), "Role tampering in transit must be rejected");
    match res.unwrap_err() {
        OctopusSecurityError::IdentitySpoofingDetected(err) => {
            assert!(err.contains("Sender role mismatch") || err.contains("signature mismatch"));
        }
        other => panic!("Expected IdentitySpoofingDetected, got {:?}", other),
    }
}

/// BREAKOUT TEST 7: 4-Taxonomy BreakoutDefenseCoordinator Auto-Quarantine inside ContainmentRing.
/// Verifies that Docker socket mounts, credential leaks, memory scraping, and cross-agent memory pollution
/// trigger immediate RingDecision::Quarantine at Ring 3.
#[tokio::test]
async fn test_breakout_defense_coordinator_auto_quarantine_in_containment_ring() {
    use agent_octopus::containment_ring::{ContainmentRing, RingDecision, RingOperationRequest};

    let ring = ContainmentRing::default();

    // 1. Technical Breakout: Docker daemon socket escape attempt
    let tech_req = RingOperationRequest {
        agent_id: "arm-UntrustedDocIngest-0".to_string(),
        role: ArmRole::UntrustedDocIngest,
        operation_type: "doc_extractor".to_string(),
        target: "s3://invoices/inv.pdf".to_string(),
        capability_token: None,
        step_count: 1,
        payload: Some(concat!("mount /var/run/docker.sock --priv", "ileged").to_string()),
        amount_cents: None,
        generation: Some(1),
    };
    let (dec1, reason1) = ring.evaluate_operation(&tech_req).await;
    assert_eq!(
        dec1,
        RingDecision::Quarantine,
        "Technical breakout must trigger Quarantine"
    );
    assert!(reason1.contains("TECHNICAL_BREAKOUT"));

    // 2. Operational Breakout: Live API credential exfiltration
    let oper_req = RingOperationRequest {
        agent_id: "arm-UntrustedDocIngest-0".to_string(),
        role: ArmRole::UntrustedDocIngest,
        operation_type: "doc_extractor".to_string(),
        target: "s3://invoices/inv.pdf".to_string(),
        capability_token: None,
        step_count: 1,
        payload: Some("OPENAI_API_KEY=sk-proj-secret123456".to_string()),
        amount_cents: None,
        generation: Some(1),
    };
    let (dec2, reason2) = ring.evaluate_operation(&oper_req).await;
    assert_eq!(
        dec2,
        RingDecision::Quarantine,
        "Operational credential leak must trigger Quarantine"
    );
    assert!(reason2.contains("OPERATIONAL_FAILURE"));

    // 3. Data Breakout: Low-privilege agent attempting to pollute privileged ledger scratchpad
    let data_req = RingOperationRequest {
        agent_id: "document_arm".to_string(),
        role: ArmRole::UntrustedDocIngest,
        operation_type: "doc_extractor".to_string(),
        target: "s3://invoices/inv.pdf".to_string(),
        capability_token: None,
        step_count: 1,
        payload: Some("write override to /shared/state/ledger and run procdump".to_string()),
        amount_cents: None,
        generation: Some(1),
    };
    let (dec3, reason3) = ring.evaluate_operation(&data_req).await;
    assert_eq!(
        dec3,
        RingDecision::Quarantine,
        "Data breakout must trigger Quarantine"
    );
    assert!(reason3.contains("DATA_BREAKOUT"));
}

/// BREAKOUT TEST 8: IsolationManager Path::join Absolute-Path, Drive Letter, UNC & ADS Escape Prevention.
#[tokio::test]
async fn test_breakout_isolation_manager_path_join_and_ads_escape_blocked() {
    use agent_octopus::containment_ring::IsolationManager;

    let mgr = IsolationManager::default();

    // 1. Arbitrary host drive letter (previously bypassed c:\windows check)
    assert!(
        mgr.validate_filesystem_access(r"D:\harfile\AgentOctopus\.env")
            .await
            .is_err(),
        "Host drive path D:\\ must be blocked"
    );
    assert!(
        mgr.validate_filesystem_access(r"C:\ProgramData\secrets.json")
            .await
            .is_err(),
        "C:\\ProgramData must be blocked"
    );

    // 2. Root-relative backslash path
    assert!(
        mgr.validate_filesystem_access(r"\Users\Administrator\.ssh\id_rsa")
            .await
            .is_err(),
        "Leading backslash root path must be blocked"
    );

    // 3. UNC network share / named pipe path
    assert!(
        mgr.validate_filesystem_access(r"\\127.0.0.1\c$\Windows\win.ini")
            .await
            .is_err(),
        "UNC path must be blocked"
    );

    // 4. NTFS Alternate Data Stream (ADS)
    assert!(
        mgr.validate_filesystem_access("invoice.pdf:$DATA")
            .await
            .is_err(),
        "NTFS Alternate Data Stream must be blocked"
    );

    // 5. Percent-encoded traversal
    assert!(
        mgr.validate_filesystem_access("subdir/%2e%2e/secrets.txt")
            .await
            .is_err(),
        "Percent-encoded traversal must be blocked"
    );

    // 6. Legitimate relative scratchpad path succeeds and remains inside local_scratchpad
    let safe = mgr
        .validate_filesystem_access("batch_01/extracted_invoice.json")
        .await
        .expect("Relative path inside scratchpad must succeed");
    assert!(safe.starts_with("local_scratchpad"));
}

/// BREAKOUT TEST 9: Mathematical RFC1918 (172.16.0.0/12), CGNAT (100.64.0.0/10), and Loopback SSRF Prevention.
#[tokio::test]
async fn test_breakout_egress_proxy_and_network_verifier_rfc1918_and_cgnat_ssrf_blocked() {
    use agent_octopus::containment_ring::{EgressProxy, EgressRequest};
    use agent_octopus::sentinel_ring::{NetworkVerificationVerdict, NetworkVerifier};

    let proxy = EgressProxy::default();
    let verifier = NetworkVerifier::new();

    for target in [
        "https://172.20.0.1/internal",
        "https://172.31.255.1/metadata",
        "https://127.0.0.2/loopback_alt",
        "https://100.64.0.1/cgnat",
        "https://169.254.10.20/link_local",
        "https://[::ffff:172.16.0.5]/v4_mapped",
    ] {
        let req = EgressRequest {
            agent_id: "arm-egress-02".to_string(),
            target_url: target.to_string(),
            method: "GET".to_string(),
            payload: None,
        };
        assert!(
            proxy.dispatch_egress(&req).await.is_err(),
            "EgressProxy must block SSRF target {}",
            target
        );

        let verdict = verifier.verify_egress(2, target, true).await.unwrap();
        assert!(
            matches!(
                verdict,
                NetworkVerificationVerdict::BlockedPrivateSubnet(_)
                    | NetworkVerificationVerdict::BlockedSsrfMetadata
            ),
            "NetworkVerifier must block private/link-local target {}, got {:?}",
            target,
            verdict
        );
    }
}

/// BREAKOUT TEST 10: CentralBrain Limb Regeneration Advances Generation Epoch (N -> N + 1).
#[tokio::test]
async fn test_breakout_central_brain_regeneration_advances_epoch() {
    use agent_octopus::CentralBrain;
    use std::collections::HashMap;
    use tokio::sync::mpsc;

    let (telemetry_tx, _telemetry_rx) = mpsc::channel(32);
    let mut brain = CentralBrain::new(HashMap::new(), HashMap::new(), telemetry_tx);

    assert_eq!(brain.arm_generation(&ArmRole::UntrustedDocIngest), 1);
    brain.regenerate_limb(ArmRole::UntrustedDocIngest);
    assert_eq!(brain.arm_generation(&ArmRole::UntrustedDocIngest), 2);
    brain.regenerate_limb(ArmRole::UntrustedDocIngest);
    assert_eq!(brain.arm_generation(&ArmRole::UntrustedDocIngest), 3);
}
