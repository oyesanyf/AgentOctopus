//! Empirical Challenge Test Suite for Milestone 2 Migration (R1-R6, R8) in AgentOctopus.
//! Stress-testing DLP, Safe Slicing, Path Normalization, WFP 24 Layers, and Process Lineage Immunity.

use agent_octopus::security::host_network_isolation::{
    discover_active_octopus_ports, HostKillSwitchManager, FWPM_LAYER_IPFORWARD_V4,
    FWPM_LAYER_IPFORWARD_V6,
};
use agent_octopus::security::process_immunity::{
    inspect_process_lineage, is_developer_or_agent_runtime, is_immutable_os_kernel_pid,
};
use agent_octopus::security::semantic_dlp::{
    safe_utf8_slice, RedactXStructuredValidator, SemanticDlpEngine,
};
use agent_octopus::security::sensitive_paths::{
    classify_sensitive_system_path, normalize_path_for_inspection, SensitiveCredentialStoreKind,
};

#[test]
fn test_semantic_dlp_deal_values_empirical() {
    let engine = SemanticDlpEngine::new();

    // Case 1: Formatted "$1,500,000 acquisition" (>= $1M) -> MUST BE QUARANTINE / CROWN JEWEL
    let v_1_5m = engine
        .evaluate_verdict_fail_closed("The acquisition deal value is $1,500,000 for AlphaCorp");
    eprintln!("[EMPIRICAL] v_1_5m: {:?}", v_1_5m);

    // Case 2: ISO Currency "EUR 2,000,000" (>= $1M) -> MUST BE DETECTED AND QUARANTINED
    let v_eur =
        engine.evaluate_verdict_fail_closed("Target valuation EUR 2,000,000 in acquisition");
    eprintln!("[EMPIRICAL] v_eur: {:?}", v_eur);

    // Case 3: Compact "$1.5M acquisition" (>= $1M) -> QUARANTINE / CROWN JEWEL
    let v_compact =
        engine.evaluate_verdict_fail_closed("The acquisition deal value is $1.5M for AlphaCorp");
    eprintln!("[EMPIRICAL] v_compact: {:?}", v_compact);
    assert!(v_compact.is_deny());

    // Case 4: Formatted "$500,000 contract" (< $1M) -> BLOCK / CONFIDENTIAL
    let v_500k =
        engine.evaluate_verdict_fail_closed("The contract deal value is $500,000 for BetaCorp");
    eprintln!("[EMPIRICAL] v_500k: {:?}", v_500k);
    assert!(v_500k.is_restricted());

    // Strict empirical verification of requirements:
    // Assert 1: $1,500,000 must result in Deny (Quarantine)
    assert!(
        v_1_5m.is_deny(),
        "FAIL: '$1,500,000 acquisition' was not quarantined! Got verdict: {:?}",
        v_1_5m
    );

    // Assert 2: EUR 2,000,000 must result in Deny (Quarantine)
    assert!(
        v_eur.is_deny(),
        "FAIL: 'EUR 2,000,000' was not detected as >= $1M deal value! Got verdict: {:?}",
        v_eur
    );
}

#[test]
fn test_hipaa_redactx_validators_empirical() {
    // 1. Luhn NPI 80840: standard valid 10-digit NPIs
    // A known valid NPI: 1234567893 (prefixed: 808401234567893)
    let valid_npi = "1234567893";
    assert!(RedactXStructuredValidator::npi_valid(valid_npi));
    assert!(!RedactXStructuredValidator::npi_valid("1234567890"));
    assert!(!RedactXStructuredValidator::npi_valid("12345"));

    // Check if SemanticDlpEngine actually detects NPI in clinical context
    let engine = SemanticDlpEngine::new();
    let npi_payload = "Attending physician Dr. Alice Smith NPI 1234567893 authorized treatment";
    let matches = engine.scan_payload(npi_payload);
    let npi_detected = matches.iter().any(|m| {
        m.kind == agent_octopus::security::semantic_dlp::SemanticEntityKind::PhiMedicalRecord
    });
    eprintln!(
        "[EMPIRICAL] NPI in clinical payload detected: {}",
        npi_detected
    );
    assert!(npi_detected, "FAIL: Valid NPI 1234567893 in clinical context was NOT detected by SemanticDlpEngine::scan_payload");

    // 2. Mod-11 MRN
    // Testing weighted sum calculation for Mod-11:
    // digits: [1, 2, 3, 4, 5, 7] -> sum = 2+6+12+20+30 = 70. 70 % 11 = 4. (11 - 4) % 10 = 7.
    assert!(RedactXStructuredValidator::mod11_valid("123457"));
    assert!(!RedactXStructuredValidator::mod11_valid("123458"));
    assert!(!RedactXStructuredValidator::mod11_valid("123")); // too short (< 6)

    // 3. SSN
    assert!(RedactXStructuredValidator::ssn_valid("123", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("000", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("666", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("900", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("123", "00", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("123", "45", "0000"));

    // 4. PAN (Payment Card Number)
    let visa_pan = "4532015112830366";
    let pans = RedactXStructuredValidator::pan_scan(&format!("Card number is {}", visa_pan));
    assert_eq!(pans.len(), 1);
    assert_eq!(pans[0], visa_pan);

    // 5. Depth-8 Base64/Hex nested unwrapping
    let secret = "SECRET_PATIENT_RECORD_99";
    let hex_1 = hex::encode(secret);
    use base64::Engine;
    let b64_2 = base64::engine::general_purpose::STANDARD.encode(hex_1.as_bytes());
    let hex_3 = hex::encode(b64_2.as_bytes());
    let b64_4 = base64::engine::general_purpose::STANDARD.encode(hex_3.as_bytes());

    let unwrapped = RedactXStructuredValidator::unwrap_encoded_layers(&b64_4);
    assert!(unwrapped.len() >= 4);
    assert!(unwrapped.iter().any(|layer| layer.contains(secret)));
}

#[test]
fn test_safe_utf8_slicing_empirical() {
    let s = "Hello 🦀 World 🌍, testing UTF-8 🚀 multi-byte boundaries!";
    let crab = safe_utf8_slice(s, 6, 1);
    assert_eq!(crab, "🦀");

    let world = safe_utf8_slice(s, 8, 5);
    assert_eq!(world, "World");

    let globe = safe_utf8_slice(s, 14, 1);
    assert_eq!(globe, "🌍");

    // Slicing out of bounds should gracefully clamp without panic:
    let out_of_bounds = safe_utf8_slice(s, 1000, 10);
    assert_eq!(out_of_bounds, "");

    // Large char_len should slice to the end without panic:
    let to_end = safe_utf8_slice(s, 6, 1000);
    assert!(to_end.starts_with("🦀"));
    assert!(to_end.ends_with('!'));
}

#[test]
fn test_sensitive_path_normalization_empirical() {
    // 1. Linux /etc/shadow
    let p1 = normalize_path_for_inspection("/etc/shadow");
    assert_eq!(p1, "/etc/shadow");
    assert_eq!(
        classify_sensitive_system_path("/etc/shadow"),
        Some(SensitiveCredentialStoreKind::UnixShadow)
    );

    // 2. Traversal & casing
    assert_eq!(
        classify_sensitive_system_path("/var/log/../../etc/shadow"),
        Some(SensitiveCredentialStoreKind::UnixShadow)
    );

    // 3. Percent encoding
    assert_eq!(
        classify_sensitive_system_path("%2fetc%2fshadow"),
        Some(SensitiveCredentialStoreKind::UnixShadow)
    );

    // 4. Windows SAM & SYSTEM hives
    assert_eq!(
        classify_sensitive_system_path(r"C:\Windows\System32\config\SAM"),
        Some(SensitiveCredentialStoreKind::WindowsSamHive)
    );
    assert_eq!(
        classify_sensitive_system_path(r"\\?\C:\Windows\System32\config\SYSTEM"),
        Some(SensitiveCredentialStoreKind::WindowsSystemHive)
    );

    // 5. Windows ADS (Alternate Data Streams)
    assert_eq!(
        classify_sensitive_system_path(r"C:\Windows\System32\config\SAM::$DATA"),
        Some(SensitiveCredentialStoreKind::WindowsSamHive)
    );

    // 6. NTDS.dit
    assert_eq!(
        classify_sensitive_system_path(r"C:\Windows\NTDS\ntds.dit"),
        Some(SensitiveCredentialStoreKind::WindowsNtdsDit)
    );

    // 7. WSL UNC path \\wsl$\... and \\wsl.localhost\...
    assert_eq!(
        classify_sensitive_system_path(r"\\wsl$\Ubuntu\etc\shadow"),
        Some(SensitiveCredentialStoreKind::UnixShadow)
    );
    assert_eq!(
        classify_sensitive_system_path(r"\\wsl.localhost\Ubuntu\etc\shadow"),
        Some(SensitiveCredentialStoreKind::UnixShadow)
    );
}

#[test]
fn test_wfp_24_layer_guids_and_rfc5737_isolation() {
    // Verify FWPM_LAYER_IPFORWARD_V4: {444543b6-9046-4246-ab81-9b06227e243d}
    assert_eq!(FWPM_LAYER_IPFORWARD_V4.data1, 0x444543b6);
    assert_eq!(FWPM_LAYER_IPFORWARD_V4.data2, 0x9046);
    assert_eq!(FWPM_LAYER_IPFORWARD_V4.data3, 0x4246);
    assert_eq!(
        FWPM_LAYER_IPFORWARD_V4.data4,
        [0xab, 0x81, 0x9b, 0x06, 0x22, 0x7e, 0x24, 0x3d]
    );

    // Verify FWPM_LAYER_IPFORWARD_V6: {12fe69b5-485a-40e7-912a-82b818121294}
    assert_eq!(FWPM_LAYER_IPFORWARD_V6.data1, 0x12fe69b5);
    assert_eq!(FWPM_LAYER_IPFORWARD_V6.data2, 0x485a);
    assert_eq!(FWPM_LAYER_IPFORWARD_V6.data3, 0x40e7);
    assert_eq!(
        FWPM_LAYER_IPFORWARD_V6.data4,
        [0x91, 0x2a, 0x82, 0xb8, 0x18, 0x12, 0x12, 0x94]
    );

    // Verify active port discovery never includes port 5000
    let ports = discover_active_octopus_ports();
    assert!(!ports.contains(&5000));

    // Verify simulated mode execution preserves runner TCP sockets
    let tmp_ledger =
        std::env::temp_dir().join(format!("octopus_ks_test_{}.json", std::process::id()));
    let _ = std::fs::remove_file(&tmp_ledger);
    let mgr = HostKillSwitchManager::new(Some(tmp_ledger.clone()));
    let status = mgr.status();
    assert_eq!(status.wfp_kernel_layers_enforced, 24);

    let receipt = mgr
        .engage(
            "empirical_challenger",
            "Testing 24-layer forward shield against RFC 5737 198.51.100.1",
        )
        .expect("Engage must succeed in simulated mode");
    assert!(receipt.isolated);

    // Disarm to restore state
    let disarmed = mgr
        .disarm("empirical_challenger", "Restoring network state")
        .expect("Disarm must succeed");
    assert!(!disarmed.isolated);
    let _ = std::fs::remove_file(&tmp_ledger);
}

#[test]
fn test_process_immunity_synthetic_pids_empirical() {
    // Non-colliding synthetic PIDs >= 4_000_001
    let synth_pid = 4_000_101;

    // Developer / agent runtimes must NEVER get immunity
    for name in &[
        "node",
        "node.exe",
        "python",
        "python3.exe",
        "powershell.exe",
        "wsl.exe",
        "bash",
    ] {
        assert!(
            is_developer_or_agent_runtime(name),
            "Expected {} to be developer runtime",
            name
        );
        let verdict = inspect_process_lineage(synth_pid, Some(name));
        assert!(
            !verdict.is_immune(),
            "Expected non-immunity for {}, got {:?}",
            name,
            verdict
        );
    }

    // Immutable OS kernel anchors
    assert!(is_immutable_os_kernel_pid(0, "System Idle Process"));
    assert!(is_immutable_os_kernel_pid(4, "System"));
    assert!(is_immutable_os_kernel_pid(
        std::process::id(),
        "agent_octopus.exe"
    ));
    assert!(is_immutable_os_kernel_pid(1234, "csrss.exe"));
    assert!(is_immutable_os_kernel_pid(1235, "smss.exe"));

    // Verify synthetic PID with non-kernel name is not immune
    let non_immune_verdict = inspect_process_lineage(synth_pid, Some("random_worker.exe"));
    assert!(!non_immune_verdict.is_immune());
}

#[test]
fn test_privilege_equivalence_and_command_ast_r3() {
    use agent_octopus::security::command_line::encode_utf16le_base64;
    use agent_octopus::security::semantic_command::{
        classify_action_class, parse_semantic_command, PrivilegeEquivalenceClass,
    };

    // 1. Nested env invocation: env -S sudo bash -c "whoami"
    let cmd1 = r#"env -S sudo bash -c "whoami""#;
    let sem1 = parse_semantic_command(cmd1);
    eprintln!("[EMPIRICAL] cmd1 sem: {:?}", sem1);
    assert_eq!(
        sem1.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert_eq!(classify_action_class(cmd1), "PRIVILEGED_EXECUTION");

    // 2. WSL invocation: wsl -u root
    let cmd2 = "wsl -u root";
    let sem2 = parse_semantic_command(cmd2);
    eprintln!("[EMPIRICAL] cmd2 sem: {:?}", sem2);
    assert_eq!(
        sem2.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert!(sem2.is_cross_boundary);
    assert_eq!(classify_action_class(cmd2), "PRIVILEGED_EXECUTION");

    // 3. powershell.exe -Command (unwrapped)
    let cmd3 = r#"powershell.exe -Command "wsl -u root id""#;
    let sem3 = parse_semantic_command(cmd3);
    eprintln!("[EMPIRICAL] cmd3 sem: {:?}", sem3);
    assert_eq!(
        sem3.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert_eq!(classify_action_class(cmd3), "PRIVILEGED_EXECUTION");

    // 4. powershell.exe -EncodedCommand observation
    let b64 = encode_utf16le_base64("wsl -u root id");
    let cmd4 = format!("powershell.exe -EncodedCommand {}", b64);
    let class4 = classify_action_class(&cmd4);
    eprintln!("[EMPIRICAL] cmd4 classify_action_class: {}", class4);
}

#[test]
fn test_siquery_quadruple_read_only_and_timeout_r8() {
    use agent_octopus::security::siquery::{SiqueryEngine, SiqueryOutputFormat};

    let engine = SiqueryEngine::new();

    // 1. Guard 1: String prefix rejection
    let r_create = engine.execute_query("CREATE TABLE test(x INTEGER);");
    assert!(r_create.is_err(), "CREATE TABLE must be rejected");
    assert!(r_create
        .unwrap_err()
        .contains("Mutating SQL statements are forbidden"));

    let r_drop = engine.execute_query("DROP TABLE processes;");
    assert!(r_drop.is_err(), "DROP TABLE must be rejected");
    assert!(r_drop
        .unwrap_err()
        .contains("Mutating SQL statements are forbidden"));

    let r_insert = engine.execute_query("INSERT INTO processes (pid) VALUES (1);");
    assert!(r_insert.is_err(), "INSERT INTO must be rejected");
    assert!(r_insert
        .unwrap_err()
        .contains("Mutating SQL statements are forbidden"));

    // 2. Guard 2: Authorizer callback catching CTE mutations that bypass prefix check
    let r_cte_insert = engine.execute_query(
        "WITH cte AS (SELECT 1 AS x) INSERT INTO processes (pid) SELECT x FROM cte;",
    );
    assert!(
        r_cte_insert.is_err(),
        "CTE INSERT must be rejected by authorizer"
    );
    let err_cte = r_cte_insert.unwrap_err();
    eprintln!("[EMPIRICAL] CTE insert error: {}", err_cte);
    assert!(
        err_cte.contains("not authorized"),
        "Expected 'not authorized', got: {}",
        err_cte
    );

    // 3. Recursive CTE read-only permission (AuthAction::Recursive)
    let r_recursive = engine.execute_query_formatted(
        "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x < 5) SELECT x FROM cnt;",
        SiqueryOutputFormat::Json,
    );
    assert!(
        r_recursive.is_ok(),
        "Read-only recursive CTE must be allowed via AuthAction::Recursive"
    );
    let json_rec = r_recursive.unwrap();
    assert!(
        json_rec.contains("\"x\": 5") || json_rec.contains("\"x\":5"),
        "Recursive CTE output must contain 5"
    );

    // 4. Comment-prefixed write statements bypassing prefix filter
    let r_comment_create = engine.execute_query("/* bypass */ CREATE TABLE evil(x);");
    assert!(
        r_comment_create.is_err(),
        "Comment-prefixed CREATE must be rejected by authorizer"
    );
    assert!(r_comment_create.unwrap_err().contains("not authorized"));

    // 5. 15-second execution timeout via progress handler
    let start = std::time::Instant::now();
    let r_infinite = engine.execute_query("WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt) SELECT count(*) FROM cnt;");
    let elapsed = start.elapsed();
    eprintln!("[EMPIRICAL] Infinite query elapsed: {:?}", elapsed);
    let err_inf = r_infinite.unwrap_err();
    eprintln!("[EMPIRICAL] err_inf: {}", err_inf);
    assert!(
        err_inf.contains("interrupted"),
        "Expected 'interrupted', got: {}",
        err_inf
    );
    assert!(
        elapsed.as_secs() >= 14 && elapsed.as_secs() <= 20,
        "Timeout should occur at ~15s, got: {:?}",
        elapsed
    );

    // 6. 41+ tables exist and telemetry tables queryable
    let tables = SiqueryEngine::list_tables();
    eprintln!("[EMPIRICAL] Table count: {}", tables.len());
    assert!(
        tables.len() >= 41,
        "Must expose at least 41 tables, got {}",
        tables.len()
    );

    assert!(engine
        .execute_query("SELECT count(*) FROM processes;")
        .is_ok());
    assert!(engine
        .execute_query("SELECT count(*) FROM listening_ports;")
        .is_ok());
    assert!(engine
        .execute_query("SELECT count(*) FROM agent_interceptions;")
        .is_ok());
    assert!(engine
        .execute_query("SELECT count(*) FROM exec_events;")
        .is_ok());
    assert!(engine
        .execute_query("SELECT count(*) FROM circumvention_events;")
        .is_ok());
    assert!(engine
        .execute_query("SELECT count(*) FROM dlp_semantic_events;")
        .is_ok());
}

#[tokio::test]
async fn test_peer_pid_anti_spoofing_and_auth_r4() {
    use agent_octopus::web::api::{handle_siquery_query, WebState};
    use agent_octopus::web::request_guard::{authorize_request, GuardRequest};
    use serde_json::json;

    let state = WebState::default();

    // 1. Loopback TCP connection setup
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let local_port = listener.local_addr().unwrap().port();
    let client = std::net::TcpStream::connect(("127.0.0.1", local_port)).unwrap();
    let peer_addr = client.local_addr().unwrap();
    let (_accepted, _) = listener.accept().unwrap();

    let actual_pid = std::process::id();

    // 2. Request Guard Token Check on /api/siquery/*
    let req_unauth = GuardRequest {
        method: "POST",
        path: "/api/siquery/query",
        query: "",
        headers: &format!(
            "POST /api/siquery/query HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            local_port
        ),
        local_port,
    };
    let rej_unauth = authorize_request(&req_unauth, "master_token_12345");
    assert!(rej_unauth.is_err(), "Missing token must be rejected");
    assert_eq!(rej_unauth.unwrap_err().status_line(), "401 Unauthorized");

    let req_bad_token = GuardRequest {
        method: "POST",
        path: "/api/siquery/query",
        query: "",
        headers: &format!("POST /api/siquery/query HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Octopus-Token: invalid_secret\r\n\r\n", local_port),
        local_port,
    };
    let rej_bad = authorize_request(&req_bad_token, "master_token_12345");
    assert!(rej_bad.is_err(), "Invalid token must be rejected");
    assert_eq!(rej_bad.unwrap_err().status_line(), "401 Unauthorized");

    // 3. Caller PID Spoofing check on /api/siquery/query
    let spoofed_pid = actual_pid.wrapping_add(88888);
    let spoof_body = json!({
        "query": "SELECT 1;",
        "caller_pid": spoofed_pid,
        "operator": "spoofed_actor"
    })
    .to_string();

    let (st_spoof, body_spoof) =
        handle_siquery_query(&state, &spoof_body, Some(peer_addr), local_port);
    eprintln!(
        "[EMPIRICAL] Siquery spoof status: {}, body: {}",
        st_spoof, body_spoof
    );
    assert_eq!(st_spoof, "403 Forbidden");
    assert!(body_spoof.contains("CALLER_PID_SPOOF_DETECTED"));

    // 4. Unresolvable connection check (non-loopback or bogus port)
    let bogus_peer: std::net::SocketAddr = "192.0.2.1:54321".parse().unwrap();
    let unres_body = json!({
        "query": "SELECT 1;",
        "caller_pid": actual_pid,
        "operator": "unres_actor"
    })
    .to_string();

    let (st_unres, body_unres) =
        handle_siquery_query(&state, &unres_body, Some(bogus_peer), local_port);
    eprintln!(
        "[EMPIRICAL] Unresolvable status: {}, body: {}",
        st_unres, body_unres
    );
    assert_eq!(st_unres, "403 Forbidden");
    assert!(body_unres.contains("PEER_PID_VERIFICATION_FAILED"));

    // 5. Quarantined Operator check
    for _ in 0..3 {
        state
            .tarpit
            .engage_adversary("quarantined_operator", "test_vector", "test_payload")
            .await;
    }
    assert!(state.tarpit.is_quarantined("quarantined_operator"));

    let q_body = json!({
        "query": "SELECT 1;",
        "caller_pid": actual_pid,
        "operator": "quarantined_operator"
    })
    .to_string();

    let (st_q, body_q) = handle_siquery_query(&state, &q_body, Some(peer_addr), local_port);
    eprintln!("[EMPIRICAL] Quarantined status: {}, body: {}", st_q, body_q);
    assert_eq!(st_q, "403 Forbidden");
    assert!(body_q.contains("CALLER_QUARANTINED"));

    // 6. Genuine authenticated call succeeds
    let valid_body = json!({
        "query": "SELECT 1 AS num;",
        "caller_pid": actual_pid,
        "operator": "clean_operator"
    })
    .to_string();
    let (st_ok, body_ok) = handle_siquery_query(&state, &valid_body, Some(peer_addr), local_port);
    assert_eq!(st_ok, "200 OK");
    assert!(
        body_ok.contains("\"status\":\"success\"") || body_ok.contains("\"status\": \"success\"")
    );
}
