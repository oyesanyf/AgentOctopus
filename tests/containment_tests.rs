use agent_octopus::{
    AgentIdentity, ArmRole, ArmRuntime, DelegationScopeGuard,
    ExternalAuthorizationEngine, KillSwitch,
    OctopusSecurityError, SandboxConfinementPolicy, SecurityAuditLog, StrategicDirective,
    TelemetryPacket,
};
use std::time::Duration;
use tokio::sync::mpsc;

#[test]
fn test_confused_deputy_privilege_laundering_blocked() {
    let guard = DelegationScopeGuard::default();

    // 1. Legitimate delegation within authority:
    // UntrustedDocIngest asks another Ingest worker for doc_extractor -> Permitted
    assert!(guard
        .validate_delegation(
            &ArmRole::UntrustedDocIngest,
            &[ArmRole::UntrustedDocIngest],
            &ArmRole::UntrustedDocIngest,
            "doc_extractor",
        )
        .is_ok());

    // 2. Confused Deputy attack:
    // UntrustedDocIngest attempts to launder authority by asking NetworkEgress to invoke http_egress.
    // Invariant: The originator (UntrustedDocIngest) has NO http_egress rights!
    let laundering_attempt = guard.validate_delegation(
        &ArmRole::UntrustedDocIngest,
        &[ArmRole::UntrustedDocIngest],
        &ArmRole::NetworkEgress,
        "http_egress",
    );

    assert!(laundering_attempt.is_err());
    match laundering_attempt.unwrap_err() {
        OctopusSecurityError::DelegationScopeViolation(msg) => {
            assert!(msg.contains("Privilege laundering attempt detected"));
        }
        other => panic!("Expected DelegationScopeViolation, got {:?}", other),
    }

    // 3. AccountingLedgerWrite attempts to launder authority by asking NetworkEgress to exfiltrate
    let ledger_laundering = guard.validate_delegation(
        &ArmRole::AccountingLedgerWrite,
        &[ArmRole::AccountingLedgerWrite],
        &ArmRole::NetworkEgress,
        "http_egress",
    );
    assert!(ledger_laundering.is_err());
}

#[test]
fn test_agent_identity_spoofing_blocked() {
    let agent_a = AgentIdentity::new("arm-ingest-01", ArmRole::UntrustedDocIngest, b"seed_a");
    let agent_b = AgentIdentity::new("arm-egress-01", ArmRole::NetworkEgress, b"seed_b");

    // Legitimate message signed by Agent A
    let valid_msg = agent_a.sign_message("arm-ledger-01", 1, "Extracted verified artifact");
    assert!(agent_a.verify_incoming_message(&valid_msg).is_ok());

    // Adversary attempts identity spoofing: claiming to be Agent A while using Agent B's key
    let forged_msg = agent_b.sign_message("arm-ledger-01", 2, "Forged command");
    // Verify against Agent A fails because signature does not match Agent A's key
    let spoof_result = agent_a.verify_incoming_message(&forged_msg);
    assert!(spoof_result.is_err());
    match spoof_result.unwrap_err() {
        OctopusSecurityError::IdentitySpoofingDetected(_) => {}
        other => panic!("Expected IdentitySpoofingDetected, got {:?}", other),
    }

    // Tampered payload in transit
    let mut tampered_msg = valid_msg;
    tampered_msg.payload = "Modified payload injected by adversary".to_string();
    assert!(agent_a.verify_incoming_message(&tampered_msg).is_err());
}

#[test]
fn test_tool_privilege_escalation_blocked_by_capability_engine() {
    let auth_engine = ExternalAuthorizationEngine::new(b"master_secret_2026", 30, "POL-V1-ACTIVE");

    // Central brain issues token specifically for doc_extractor on s3://invoices/
    let valid_token = auth_engine.issue_capability(
        "central_brain",
        "arm-ingest-01",
        ArmRole::UntrustedDocIngest,
        "doc_extractor",
        "s3://invoices/",
    );

    // 1. Authorized action succeeds
    assert!(auth_engine
        .verify_capability(&valid_token, "arm-ingest-01", "doc_extractor", "s3://invoices/inv1.pdf")
        .is_ok());

    // 2. Privilege escalation attempt: Agent tries to use the token to call ledger_writer
    let tool_escalation =
        auth_engine.verify_capability(&valid_token, "arm-ingest-01", "ledger_writer", "s3://invoices/inv1.pdf");
    assert!(tool_escalation.is_err());
    match tool_escalation.unwrap_err() {
        OctopusSecurityError::CapabilityDenied(msg) => {
            assert!(msg.contains("Tool privilege escalation"));
        }
        other => panic!("Expected CapabilityDenied, got {:?}", other),
    }

    // 3. Resource scope breach: Agent tries to access an unassigned resource path
    let scope_breach =
        auth_engine.verify_capability(&valid_token, "arm-ingest-01", "doc_extractor", "s3://financial_secrets/keys.pem");
    assert!(scope_breach.is_err());
    match scope_breach.unwrap_err() {
        OctopusSecurityError::CapabilityDenied(msg) => {
            assert!(msg.contains("Resource scope violation"));
        }
        other => panic!("Expected CapabilityDenied, got {:?}", other),
    }

    // 4. Token transfer breach: Another agent attempts to present the token
    let transfer_breach =
        auth_engine.verify_capability(&valid_token, "rogue-agent-99", "doc_extractor", "s3://invoices/inv1.pdf");
    assert!(transfer_breach.is_err());
}

#[test]
fn test_operating_system_process_and_filesystem_confinement() {
    let sandbox = SandboxConfinementPolicy::default();

    // 1. OS Process execution attempts must be blocked (max_child_processes = 0)
    assert!(sandbox.validate_process_confinement("cmd.exe /c whoami").is_err());
    assert!(sandbox.validate_process_confinement("powershell.exe -enc AAAA").is_err());
    assert!(sandbox.validate_process_confinement("bash -c 'cat /etc/shadow'").is_err());
    assert!(sandbox.validate_process_confinement("/bin/sh").is_err());

    // 2. Path traversal attempts must be blocked
    assert!(sandbox.validate_filesystem_confinement("../../../etc/shadow").is_err());
    assert!(sandbox.validate_filesystem_confinement("..\\..\\Windows\\System32").is_err());
    assert!(sandbox.validate_filesystem_confinement("/etc/passwd").is_err());
    assert!(sandbox.validate_filesystem_confinement("C:\\Windows\\System32\\cmd.exe").is_err());
    assert!(sandbox.validate_filesystem_confinement("file:///root/.ssh/id_rsa").is_err());

    // 3. Authorized sandbox paths pass
    assert!(sandbox.validate_filesystem_confinement("s3://invoices/january.pdf").is_ok());
    assert!(sandbox.validate_filesystem_confinement("sandbox://scratchpad/temp.txt").is_ok());
}

#[tokio::test]
async fn test_persistence_prevented_on_termination() {
    let (telemetry_tx, _telemetry_rx) = mpsc::channel::<TelemetryPacket>(100);
    let (directive_tx, directive_rx) = mpsc::channel(16);
    let kill_switch = KillSwitch::new();

    let arm = ArmRuntime::new(
        ArmRole::UntrustedDocIngest,
        directive_rx,
        telemetry_tx,
        kill_switch.clone(),
    );

    let handle = tokio::spawn(arm.run());

    // Trigger kill switch (autotomy termination)
    kill_switch.trip();
    assert!(kill_switch.is_tripped());

    // Send directive: arm immediately evaluates kill switch, responds with LimbKilled, and halts
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    let directive = StrategicDirective {
        directive_id: "T-PERSIST-01".to_string(),
        source_uri: "s3://invoices/v.pdf".to_string(),
        instruction: "parse".to_string(),
        raw_payload: None,
        max_step_budget: 5,
    };
    directive_tx.send((directive, resp_tx)).await.unwrap();
    let res = resp_rx.await.unwrap();
    assert_eq!(res.unwrap_err(), OctopusSecurityError::LimbKilled);

    // Verify task terminates immediately and does NOT persist in background
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(handle.is_finished(), "Terminated agent must not persist in background");

    // Any subsequent attempt to communicate with terminated agent fails (channel severed)
    let (resp_tx2, _resp_rx2) = tokio::sync::oneshot::channel();
    let directive2 = StrategicDirective {
        directive_id: "T-PERSIST-02".to_string(),
        source_uri: "s3://invoices/v2.pdf".to_string(),
        instruction: "parse".to_string(),
        raw_payload: None,
        max_step_budget: 5,
    };
    assert!(directive_tx.send((directive2, resp_tx2)).await.is_err());
}

#[test]
fn test_security_audit_log_hash_chain() {
    let log = SecurityAuditLog::new();

    let h1 = log.record_event("AUTH_CHECK", "arm-ingest-01", "Tool: doc_extractor", "PERMIT");
    let h2 = log.record_event("DELEGATION_CHECK", "arm-egress-01", "Laundering attempt", "DENY");

    assert_eq!(log.total_records(), 2);
    assert_ne!(h1, h2);
    assert_eq!(log.latest_hash(), h2);
}

#[test]
fn test_openshell_wasm_fuel_metering_and_confinement() {
    let auth_engine = ExternalAuthorizationEngine::new(b"master_secret_2026", 30, "POL-V1-ACTIVE");

    let mut wasm_arm = agent_octopus::WasmArmSandbox::new("arm-ingest-01", ArmRole::UntrustedDocIngest, 100_000);
    assert_eq!(wasm_arm.fuel_remaining(), 100_000);

    let capability = auth_engine.issue_capability(
        "central_brain",
        "arm-ingest-01",
        ArmRole::UntrustedDocIngest,
        "doc_extractor",
        "s3://invoices/",
    );

    // 1. Authorized execution within fuel budget (costs 50,000 fuel units)
    let valid_directive = StrategicDirective {
        directive_id: "WASM-01".to_string(),
        source_uri: "s3://invoices/valid.pdf".to_string(),
        instruction: "Extract totals".to_string(),
        raw_payload: Some("INVOICE: INV-100\nVendor: Safe\nTotal: $100.00".to_string()),
        max_step_budget: 5,
    };

    let result = wasm_arm.execute_sandboxed(&valid_directive, &auth_engine, &capability, "doc_extractor");
    assert!(result.is_ok());
    assert_eq!(wasm_arm.fuel_remaining(), 50_000);

    // 2. Fuel exhaustion (infinite loop / recursion bomb) blocks execution
    // Running second task consumes remaining 50,000
    let res2 = wasm_arm.execute_sandboxed(&valid_directive, &auth_engine, &capability, "doc_extractor");
    assert!(res2.is_ok());
    assert_eq!(wasm_arm.fuel_remaining(), 0);

    // Third task attempts execution with 0 fuel remaining -> Blocked by fuel limiter!
    let res3 = wasm_arm.execute_sandboxed(&valid_directive, &auth_engine, &capability, "doc_extractor");
    assert!(res3.is_err());
    match res3.unwrap_err() {
        OctopusSecurityError::ResourceQuotaExceeded(msg) => {
            assert!(msg.contains("WASM Fuel Exhausted"));
        }
        other => panic!("Expected ResourceQuotaExceeded, got {:?}", other),
    }

    // 3. Reset fuel and test process escape attempt inside WASM
    wasm_arm.reset_fuel();
    let escape_directive = StrategicDirective {
        directive_id: "WASM-ESCAPE".to_string(),
        source_uri: "s3://invoices/valid.pdf".to_string(),
        instruction: "cmd.exe /c calc".to_string(),
        raw_payload: Some("cmd.exe /c calc".to_string()),
        max_step_budget: 5,
    };
    let escape_result = wasm_arm.execute_sandboxed(&escape_directive, &auth_engine, &capability, "doc_extractor");
    assert!(escape_result.is_err());
    match escape_result.unwrap_err() {
        OctopusSecurityError::IsolationViolation(msg) => {
            assert!(msg.contains("Process isolation boundary breach"));
        }
        other => panic!("Expected IsolationViolation, got {:?}", other),
    }
}

#[test]
fn test_openshell_windows_experimental_mode() {
    let auth_engine = ExternalAuthorizationEngine::new(b"master_secret_2026", 30, "POL-V1-ACTIVE");

    // Configure NVIDIA OpenShell in Windows Experimental Mode without WSL
    let windows_config = agent_octopus::OpenShellConfig {
        mode: agent_octopus::OpenShellMode::WindowsExperimental {
            pipe_name: r"\\.\pipe\openshell-supervisor-octopus".to_string(),
            enforce_no_wsl: true,
            fail_closed_on_driver_fault: true,
        },
        supervisor_gateway_uri: r"\\.\pipe\openshell-supervisor-octopus".to_string(),
        enforce_filesystem_confinement: true,
        enforce_process_confinement: true,
        default_network_deny: true,
        wasm_fuel_limit: 500_000,
        wasm_epoch_deadline: 1,
        wall_clock_timeout_ms: 2_000,
        allowed_egress_domains: vec![
            "https://www.google.com".to_string(),
            "https://google.com".to_string(),
        ],
    };

    let mut sandbox = agent_octopus::WasmArmSandbox::new("arm-ingest-win01", ArmRole::UntrustedDocIngest, 500_000)
        .with_config(windows_config);

    let capability = auth_engine.issue_capability(
        "central_brain",
        "arm-ingest-win01",
        ArmRole::UntrustedDocIngest,
        "doc_extractor",
        "s3://invoices/",
    );

    // 1. Authorized directive succeeds on Windows x86-64 without WSL
    let valid_directive = StrategicDirective {
        directive_id: "WIN-EXP-01".to_string(),
        source_uri: "s3://invoices/win_invoice.pdf".to_string(),
        instruction: "Extract totals".to_string(),
        raw_payload: Some("INVOICE: INV-WIN-01\nVendor: SafeWin\nTotal: $100.00".to_string()),
        max_step_budget: 5,
    };
    let win_res = sandbox.execute_sandboxed(&valid_directive, &auth_engine, &capability, "doc_extractor");
    assert!(win_res.is_ok());
    let desc = win_res.unwrap();
    assert!(desc.contains("Windows Agent Octopus Containment Runtime"));
    assert!(desc.contains("No-WSL: true"));

    // 2. Windows PowerShell execution attempt is blocked by Windows process confinement
    let ps_directive = StrategicDirective {
        directive_id: "WIN-EXP-PS".to_string(),
        source_uri: "s3://invoices/win_invoice.pdf".to_string(),
        instruction: "powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest".to_string(),
        raw_payload: Some("powershell.exe -Command Get-Process".to_string()),
        max_step_budget: 5,
    };
    let ps_res = sandbox.execute_sandboxed(&ps_directive, &auth_engine, &capability, "doc_extractor");
    assert!(ps_res.is_err());
    match ps_res.unwrap_err() {
        OctopusSecurityError::IsolationViolation(msg) => {
            assert!(msg.contains("Process isolation boundary breach"));
        }
        other => panic!("Expected IsolationViolation, got {:?}", other),
    }

    // 3. Windows SAM credential access attempt is blocked by filesystem sandbox
    let sam_directive = StrategicDirective {
        directive_id: "WIN-EXP-SAM".to_string(),
        source_uri: r"C:\Windows\System32\config\SAM".to_string(),
        instruction: "Extract totals".to_string(),
        raw_payload: None,
        max_step_budget: 5,
    };
    let sam_res = sandbox.execute_sandboxed(&sam_directive, &auth_engine, &capability, "doc_extractor");
    assert!(sam_res.is_err());
    match sam_res.unwrap_err() {
        OctopusSecurityError::IsolationViolation(msg) => {
            assert!(msg.contains("Host filesystem access denied") || msg.contains("kernel ACL blocked"));
        }
        other => panic!("Expected IsolationViolation, got {:?}", other),
    }
}

#[test]
fn test_windows_job_object_and_appcontainer_kernel_isolation() {
    use agent_octopus::security::windows_sandbox::{
        WindowsAppContainerProfile, WindowsJobObject, WindowsRestrictedTokenPolicy,
    };

    // 1. Verify Windows Job Object creation and limits
    let job = WindowsJobObject::create("TestJob-Octopus", 5, 64 * 1024 * 1024).expect("Job creation");
    assert_eq!(job.max_processes, 5);
    assert_eq!(job.max_memory_bytes, 64 * 1024 * 1024);

    // 2. Breakaway containment verification: verify kernel limits block process breakaway
    let breakaway_contained = job.verify_breakaway_contained().expect("Breakaway containment check");
    assert!(breakaway_contained, "Job Object must enforce breakaway containment and kill-on-close");

    // 3. Real Job Object membership verification using Win32 IsProcessInJob (positive & negative controls)
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "ping -n 5 127.0.0.1 > nul"])
            .spawn()
            .expect("Spawn test child process");
        let child_handle = child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        let assign_res = job.assign_process(child_handle);
        assert!(assign_res.is_ok(), "Process must be assigned to Job Object: {:?}", assign_res);
        let in_job = job.verify_process_in_job(child_handle).expect("IsProcessInJob check");
        assert!(in_job, "Child process must be kernel-verified inside Job Object via IsProcessInJob");
        let _ = child.kill();
        let _ = child.wait();

        // Negative control: unassigned child process must return false
        let mut unassigned_child = std::process::Command::new("cmd.exe")
            .args(["/c", "ping -n 5 127.0.0.1 > nul"])
            .spawn()
            .expect("Spawn unassigned child process");
        let unassigned_handle = unassigned_child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        let unassigned_in_job = job.verify_process_in_job(unassigned_handle).expect("IsProcessInJob check on unassigned child");
        assert!(!unassigned_in_job, "Unassigned process must NOT be reported as inside Job Object");
        let _ = unassigned_child.kill();
        let _ = unassigned_child.wait();
    }

    // 4. Verify AppContainer LPAC profile security checks
    let app_container = WindowsAppContainerProfile::new("arm-worker-lpac", true, true);
    assert!(app_container.is_lpac);
    assert!(app_container.package_sid.starts_with("S-1-15-2-"));

    // Google egress permitted under AppContainer policy
    assert!(app_container.verify_access("https://www.google.com/search?q=test", true).is_ok());

    // Non-Google external egress blocked by AppContainer policy
    let blocked_egress = app_container.verify_access("https://attacker-c2.com/exfil", true);
    assert!(blocked_egress.is_err());

    // Access to C:\Windows blocked by AppContainer policy
    let blocked_fs = app_container.verify_access(r"C:\Windows\System32\cmd.exe", false);
    assert!(blocked_fs.is_err());

    // 5. Verify Windows Restricted Token privilege stripping and genuine token creation
    let token_policy = WindowsRestrictedTokenPolicy::default();
    assert!(token_policy.stripped_privileges.contains(&"SeDebugPrivilege".to_string()));
    assert!(token_policy.stripped_privileges.contains(&"SeTcbPrivilege".to_string()));
    assert_eq!(token_policy.token_integrity_level, "Low");

    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let mut current_token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        unsafe {
            agent_octopus::security::windows_sandbox::win32::OpenProcessToken(
                GetCurrentProcess(),
                0x0008, // TOKEN_QUERY
                &mut current_token,
            );
        }
        let original_restricted = unsafe { agent_octopus::security::windows_sandbox::win32::IsTokenRestricted(current_token) };
        unsafe { CloseHandle(current_token); }
        assert_eq!(original_restricted, 0, "Primary process token should not be restricted initially");

        let restricted_token = token_policy.create_restricted_token().expect("Real Win32 restricted token creation");
        assert!(!restricted_token.is_null());
        assert_ne!(restricted_token, INVALID_HANDLE_VALUE);
        let is_restricted = unsafe { agent_octopus::security::windows_sandbox::win32::IsTokenRestricted(restricted_token) };
        assert_ne!(is_restricted, 0, "Restricted token must be confirmed restricted via IsTokenRestricted");
        unsafe { CloseHandle(restricted_token); }
    }
}

#[test]
fn test_supervisor_independent_termination_and_wallclock_timeout() {
    let auth_engine = ExternalAuthorizationEngine::new(b"master_secret_2026", 30, "POL-V1-ACTIVE");
    let mut sandbox = agent_octopus::WasmArmSandbox::new("arm-supervised-01", ArmRole::UntrustedDocIngest, 500_000);

    let capability = auth_engine.issue_capability(
        "central_brain",
        "arm-supervised-01",
        ArmRole::UntrustedDocIngest,
        "doc_extractor",
        "s3://invoices/",
    );

    let directive = StrategicDirective {
        directive_id: "DIR-SUP-01".to_string(),
        source_uri: "s3://invoices/inv01.pdf".to_string(),
        instruction: "Extract totals".to_string(),
        raw_payload: Some("valid invoice".to_string()),
        max_step_budget: 5,
    };

    // Before termination, execution succeeds
    let res1 = sandbox.execute_sandboxed(&directive, &auth_engine, &capability, "doc_extractor");
    assert!(res1.is_ok());

    // Supervisor executes independent emergency abort
    sandbox.terminate_sandbox(1).expect("Termination must succeed");

    // After supervisor termination, all subsequent execution is immediately rejected
    let res2 = sandbox.execute_sandboxed(&directive, &auth_engine, &capability, "doc_extractor");
    assert!(res2.is_err());
    match res2.unwrap_err() {
        OctopusSecurityError::IsolationViolation(msg) => {
            assert!(msg.contains("terminated by independent supervisor"));
        }
        other => panic!("Expected IsolationViolation for terminated sandbox, got {:?}", other),
    }
}


