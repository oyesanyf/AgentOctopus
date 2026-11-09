//! ==============================================================================
//! [AGENT OCTOPUS] MILESTONE 4 MIGRATION ADVERSARIAL STRESS TEST SUITE (CHALLENGER M4-2)
//! ==============================================================================
//! Empirical stress tests, edge case mining, bypass attempts, boundary conditions,
//! and adversarial fuzz payloads targeting Milestone 4 (R1-R6, R8) in AgentOctopus:
//!
//! 1. Hook synonym permutations & malformed JSON-RPC payloads (src/security/agent_hooks.rs)
//! 2. TOCTOU stem checks & PID boundary testing (src/security/process_immunity.rs)
//! 3. Obfuscated command parsing & shell unwrapping (src/security/semantic_command.rs)
//! 4. Deal values with internal commas, multi-currency tokens & clinical NPI/MRN checksums (src/security/semantic_dlp.rs)
//! 5. Siquery 15s execution timeout & relational host discovery (src/security/siquery.rs)
//! 6. 24-layer WFP network isolation & loopback peer PID anti-spoofing (src/security/host_network_isolation.rs & src/web/api.rs)
//! ==============================================================================

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Instant;

// ------------------------------------------------------------------------------
// Vector 1: Hook Synonym Permutations and Malformed JSON-RPC Payloads
// ------------------------------------------------------------------------------

#[test]
fn test_adv_hook_synonym_permutations_and_malformed_json_rpc() {
    use agent_octopus::security::agent_hooks::{
        evaluate_hook_synchronously, format_claude_response, format_copilot_response,
        format_cursor_response, format_mcp_error_response, format_opencode_response,
        parse_claude_request, parse_cursor_request, parse_mcp_call_request,
    };
    use serde_json::json;

    // 1.1 Malformed JSON-RPC Syntax Payloads (Clean Err)
    let syntax_errors = [
        "",
        "{",
        "{\"jsonrpc\": \"2.0\", \"method\":",
        "{\"jsonrpc\": \"2.0\", \"id\": 1, \"params\": {invalid}}",
    ];

    for bad_payload in syntax_errors {
        let res = parse_mcp_call_request(bad_payload);
        assert!(
            res.is_err(),
            "Malformed syntax payload should fail to parse gracefully: '{}'",
            bad_payload
        );
    }

    // 1.1b Remediated: Non-object JSON roots (null, primitive, array) must fail object check
    // JSON-RPC 2.0 §4 states requests MUST be objects.
    assert!(
        parse_mcp_call_request("null").is_err(),
        "Non-object 'null' must be rejected"
    );
    assert!(
        parse_mcp_call_request("12345").is_err(),
        "Non-object '12345' must be rejected"
    );
    assert!(
        parse_mcp_call_request("[\"array\"]").is_err(),
        "Non-object '[\"array\"]' must be rejected"
    );

    // 1.2 JSON-RPC 2.0 Request ID Preservation across types (Number, String, Null, Notification)
    // A: Numeric ID
    let json_num_id = json!({
        "jsonrpc": "2.0",
        "id": 424242,
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": { "command": "sudo rm -rf /" }
        }
    })
    .to_string();
    let parsed_num = parse_mcp_call_request(&json_num_id).expect("Should parse valid JSON-RPC");
    assert_eq!(parsed_num.rpc_id, Some(json!(424242)));
    let dec_num = evaluate_hook_synchronously(&parsed_num);
    assert!(!dec_num.allowed, "Sudo command must be denied");
    let err_resp_num = format_mcp_error_response(&parsed_num.rpc_id.unwrap(), &dec_num);
    let val_resp_num: serde_json::Value = serde_json::from_str(&err_resp_num).unwrap();
    assert_eq!(val_resp_num["id"], json!(424242));
    assert_eq!(val_resp_num["error"]["code"], -32000);

    // B: String ID
    let json_str_id = json!({
        "jsonrpc": "2.0",
        "id": "req-uuid-987654321",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": { "file_path": "/etc/shadow" }
        }
    })
    .to_string();
    let parsed_str = parse_mcp_call_request(&json_str_id).expect("Should parse string ID");
    assert_eq!(parsed_str.rpc_id, Some(json!("req-uuid-987654321")));
    let dec_str = evaluate_hook_synchronously(&parsed_str);
    assert!(!dec_str.allowed, "Access to /etc/shadow must be denied");
    let err_resp_str = format_mcp_error_response(&parsed_str.rpc_id.unwrap(), &dec_str);
    let val_resp_str: serde_json::Value = serde_json::from_str(&err_resp_str).unwrap();
    assert_eq!(val_resp_str["id"], json!("req-uuid-987654321"));

    // C: Null ID
    let json_null_id = json!({
        "jsonrpc": "2.0",
        "id": null,
        "method": "tools/call",
        "params": {
            "tool": "file_reader",
            "args": { "path": "C:\\Windows\\System32\\config\\SAM" }
        }
    })
    .to_string();
    let parsed_null = parse_mcp_call_request(&json_null_id).expect("Should parse null ID");
    assert_eq!(parsed_null.rpc_id, Some(serde_json::Value::Null));
    let dec_null = evaluate_hook_synchronously(&parsed_null);
    assert!(!dec_null.allowed, "Access to SAM hive must be denied");
    let err_resp_null = format_mcp_error_response(&serde_json::Value::Null, &dec_null);
    let val_resp_null: serde_json::Value = serde_json::from_str(&err_resp_null).unwrap();
    assert_eq!(val_resp_null["id"], serde_json::Value::Null);

    // D: Notification (missing id)
    let json_notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": { "token": "abc" }
    })
    .to_string();
    let parsed_notify = parse_mcp_call_request(&json_notify).expect("Should parse notification");
    assert!(parsed_notify.rpc_id.is_none());

    // 1.3 Wire Synonym Permutations across all 9 canonical synonym groups
    // Group 1: command: "cursor_command", "copilot_action", "subcommand", "command", "cmd", "action", and string array
    for (syn_key, syn_val) in [
        ("cursor_command", json!("whoami")),
        ("copilot_action", json!("whoami")),
        ("subcommand", json!("whoami")),
        ("command", json!("whoami")),
        ("cmd", json!("whoami")),
        ("action", json!("whoami")),
        ("command", json!(["whoami", "--version"])),
    ] {
        let payload = json!({ syn_key: syn_val }).to_string();
        let cursor_req = parse_cursor_request(&payload, "beforeShellExecution").unwrap();
        assert!(
            cursor_req.command.is_some(),
            "Failed for syn_key: {}",
            syn_key
        );
        assert!(cursor_req.command.unwrap().contains("whoami"));
    }

    // Group 2: tool_name: "tool_name", "name", "tool"
    for syn_key in ["tool_name", "name", "tool"] {
        let payload = json!({ syn_key: "custom_analyzer" }).to_string();
        let req = parse_claude_request(&payload, false).unwrap();
        assert_eq!(req.tool_name, Some("custom_analyzer".to_string()));
    }

    // Group 3: arguments: "arguments", "tool_input", "args", "parameters", "input"
    for syn_key in ["arguments", "tool_input", "args", "parameters", "input"] {
        let payload = json!({ syn_key: { "target": "database.sql" } }).to_string();
        let req = parse_claude_request(&payload, false).unwrap();
        assert!(req.arguments.is_some());
        assert_eq!(req.arguments.unwrap()["target"], "database.sql");
    }

    // Group 4: file_path: "file_path", "path", "filePath", "uri", "working_file", "editor_context", "file", "context_paths"
    for syn_key in [
        "file_path",
        "path",
        "filePath",
        "uri",
        "working_file",
        "editor_context",
        "file",
    ] {
        let payload = json!({ syn_key: "src/security/mod.rs" }).to_string();
        let req = parse_cursor_request(&payload, "beforeReadFile").unwrap();
        assert_eq!(req.file_path, Some("src/security/mod.rs".to_string()));
    }
    // context_paths as array:
    let payload_ctx_arr =
        json!({ "context_paths": ["src/security/agent_hooks.rs", "src/lib.rs"] }).to_string();
    let req_ctx_arr = parse_cursor_request(&payload_ctx_arr, "beforeReadFile").unwrap();
    assert_eq!(
        req_ctx_arr.file_path,
        Some("src/security/agent_hooks.rs".to_string())
    );

    // Group 5: session_id: "session_id", "sessionId", "conversation_id", "cursor_trace_id", "tool_use_id"
    for syn_key in [
        "session_id",
        "sessionId",
        "conversation_id",
        "cursor_trace_id",
        "tool_use_id",
    ] {
        let payload = json!({ syn_key: "session-xyz-123" }).to_string();
        let req = parse_claude_request(&payload, false).unwrap();
        assert_eq!(req.session_id, Some("session-xyz-123".to_string()));
    }

    // Group 6: exit_code: "exit_code", "exitCode"
    for syn_key in ["exit_code", "exitCode"] {
        let payload = json!({ syn_key: 127 }).to_string();
        let req = parse_claude_request(&payload, true).unwrap();
        assert_eq!(req.exit_code, Some(127));
    }

    // Group 7: stderr: "stderr", "error"
    for syn_key in ["stderr", "error"] {
        let payload = json!({ syn_key: "Permission denied (EACCES)" }).to_string();
        let req = parse_claude_request(&payload, true).unwrap();
        assert_eq!(req.stderr, Some("Permission denied (EACCES)".to_string()));
    }

    // Group 8: cwd: "cwd", "working_dir", "workingDirectory"
    for syn_key in ["cwd", "working_dir", "workingDirectory"] {
        let payload = json!({ syn_key: "/home/developer/workspace" }).to_string();
        let req = parse_claude_request(&payload, false).unwrap();
        assert_eq!(req.cwd, Some("/home/developer/workspace".to_string()));
    }

    // 1.4 Output Formatters for Claude, Cursor, Copilot, OpenCode
    let allow_decision =
        agent_octopus::security::agent_hooks::HookEvaluationDecision::allow("Allowed by test", 15);
    let deny_decision = agent_octopus::security::agent_hooks::HookEvaluationDecision::deny(
        "Blocked by test",
        Some("TestLayer"),
        Some("TestRemediation"),
        25,
    );

    // Claude
    let (code_allow, msg_allow) = format_claude_response(&allow_decision);
    assert_eq!(code_allow, 0);
    assert!(msg_allow.is_empty());
    let (code_deny, msg_deny) = format_claude_response(&deny_decision);
    assert_eq!(code_deny, 2);
    assert!(msg_deny.contains("Blocked by test"));

    // Cursor
    let (_, cursor_allow_json) = format_cursor_response(&allow_decision);
    assert!(cursor_allow_json.contains("\"permission\":\"allow\""));
    let (_, cursor_deny_json) = format_cursor_response(&deny_decision);
    assert!(cursor_deny_json.contains("\"permission\":\"deny\""));

    // Copilot
    let (_, copilot_allow_json) = format_copilot_response(&allow_decision);
    assert!(copilot_allow_json.contains("\"permissionDecision\":\"allow\""));
    let (_, copilot_deny_json) = format_copilot_response(&deny_decision);
    assert!(copilot_deny_json.contains("\"permissionDecision\":\"deny\""));

    // OpenCode
    let (_, opencode_allow_json) = format_opencode_response(&allow_decision);
    assert!(opencode_allow_json.contains("\"allow\":true"));
    let (_, opencode_deny_json) = format_opencode_response(&deny_decision);
    assert!(opencode_deny_json.contains("\"allow\":false"));
}

// ------------------------------------------------------------------------------
// Vector 2: TOCTOU Stem Checks and PID Boundary Testing
// ------------------------------------------------------------------------------

#[test]
fn test_adv_toctou_stem_checks_and_pid_boundaries() {
    use agent_octopus::security::process_immunity::{
        extract_proc_stem, inspect_process_lineage, is_developer_or_agent_runtime,
        is_immutable_os_kernel_pid,
    };

    // 2.1 PID Boundaries (0, 1, 4, Self PID)
    assert!(is_immutable_os_kernel_pid(0, "System Idle Process"));
    assert!(is_immutable_os_kernel_pid(1, "init"));
    assert!(is_immutable_os_kernel_pid(4, "System"));
    assert!(is_immutable_os_kernel_pid(
        std::process::id(),
        "agent_octopus.exe"
    ));

    // 2.2 Non-colliding synthetic PIDs >= 4_000_001
    for synth_pid in [4_000_101, 4_000_202, 4_000_303, 4_000_999] {
        assert!(synth_pid >= 4_000_001);
        let v = inspect_process_lineage(synth_pid, Some("worker_task.exe"));
        assert!(
            !v.is_immune(),
            "Synthetic PID {} must not receive immunity",
            synth_pid
        );
    }

    // 2.3 Elimination of blanket process immunity
    let blanket_runtimes = [
        "wsl.exe",
        "wslservice.exe",
        "wslhost.exe",
        "vmmem",
        "vmmemwsl",
        "sudo",
        "su",
        "bash",
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "python.exe",
        "python3.exe",
        "node.exe",
        "cursor.exe",
        "code.exe",
    ];
    for rt in blanket_runtimes {
        assert!(
            is_developer_or_agent_runtime(rt),
            "Expected {} to be identified as developer/agent runtime",
            rt
        );
        let verdict = inspect_process_lineage(4_000_555, Some(rt));
        assert!(
            !verdict.is_immune(),
            "Runtime {} must NEVER receive blanket immunity, got {:?}",
            rt,
            verdict
        );
    }

    // 2.4 Stem Extraction Robustness & Empirical Findings
    assert_eq!(
        extract_proc_stem(r#"C:\Windows\System32\csrss.exe"#),
        "csrss"
    );
    assert_eq!(extract_proc_stem("/usr/bin/bash -c id"), "bash");
    assert_eq!(extract_proc_stem("'cmd.exe'"), "cmd");
    assert_eq!(extract_proc_stem(r#""python.exe""#), "python");
    assert_eq!(extract_proc_stem("   "), "");

    // Remediated: Quoted executables and paths containing spaces are tokenized cleanly
    let single_quoted_cmd = extract_proc_stem("'cmd.exe' /c dir");
    assert_eq!(
        single_quoted_cmd, "cmd",
        "Quoted executable stem should be 'cmd'"
    );

    let double_quoted_cmd = extract_proc_stem(r#""cmd.exe" /c dir"#);
    assert_eq!(
        double_quoted_cmd, "cmd",
        "Double-quoted executable stem should be 'cmd'"
    );

    let space_stem = extract_proc_stem(r#""D:\Program Files\Python310\python.exe" -m http.server"#);
    assert_eq!(
        space_stem, "python",
        "Space-in-path stem should be 'python'"
    );

    // 2.5 Live TOCTOU Stem Mismatch Verification
    // Current test process is live. If we query inspect_process_lineage with the real current PID,
    // but pass a deliberately mismatched expected name (e.g. "totally_different_malicious.exe"):
    let current_pid = std::process::id();
    let toctou_verdict = inspect_process_lineage(current_pid, Some("mismatched_target_name.exe"));
    // Even though current_pid is self, the direct stem TOCTOU verification handles it
    eprintln!(
        "[EMPIRICAL TOCTOU] Verdict for self PID: {:?}",
        toctou_verdict
    );
}

// ------------------------------------------------------------------------------
// Vector 3: Obfuscated Command Parsing and Shell Unwrapping
// ------------------------------------------------------------------------------

#[test]
fn test_adv_obfuscated_command_parsing_and_shell_unwrapping() {
    use agent_octopus::security::command_line::encode_utf16le_base64;
    use agent_octopus::security::semantic_command::{
        classify_action_class, parse_semantic_command, tokenize_command, unwrap_env_invocation,
        unwrap_shell_and_env_nesting, unwrap_shell_invocation, PrivilegeEquivalenceClass,
    };

    // 3.1 Tokenization with complex escaping, quotes, whitespace
    let complex_cmd = r#"git commit -m "feat(security): fix 'injection' \"nested\"" --author='Alice <alice@test.org>'"#;
    let tokens = tokenize_command(complex_cmd);
    assert_eq!(tokens[0], "git");
    assert_eq!(tokens[1], "commit");
    assert_eq!(tokens[2], "-m");
    assert_eq!(tokens[3], r#"feat(security): fix 'injection' "nested""#);
    assert_eq!(tokens[4], "--author=Alice <alice@test.org>");

    // 3.2 Shell Unwrapping
    // A: bash -c
    let bash_cmd = tokenize_command(r#"bash -c "sudo systemctl restart nginx""#);
    let unwrapped_bash = unwrap_shell_invocation(&bash_cmd).unwrap();
    assert_eq!(unwrapped_bash, "sudo systemctl restart nginx");

    // B: cmd.exe /c
    let cmd_cmd = tokenize_command(r#"cmd.exe /c "runas /user:Administrator cmd.exe""#);
    let unwrapped_cmd = unwrap_shell_invocation(&cmd_cmd).unwrap();
    assert_eq!(unwrapped_cmd, "runas /user:Administrator cmd.exe");

    // C: powershell -Command
    let ps_cmd = tokenize_command(r#"powershell.exe -Command "wsl -u root cat /etc/shadow""#);
    let unwrapped_ps = unwrap_shell_invocation(&ps_cmd).unwrap();
    assert_eq!(unwrapped_ps, "wsl -u root cat /etc/shadow");

    // D: powershell -EncodedCommand (UTF-16LE Base64)
    let raw_inner = "wsl -u root whoami";
    let b64_payload = encode_utf16le_base64(raw_inner);
    let ps_enc = tokenize_command(&format!("powershell.exe -EncodedCommand {}", b64_payload));
    let unwrapped_ps_enc = unwrap_shell_invocation(&ps_enc).unwrap();
    assert_eq!(unwrapped_ps_enc, raw_inner);

    // 3.3 GNU env -S / --split-string Unnesting
    let env_cmd = tokenize_command(r#"env -S sudo bash -c "whoami""#);
    let (tail, _envs) = unwrap_env_invocation(&env_cmd).unwrap();
    assert_eq!(tail[0], "sudo");
    assert_eq!(tail[1], "bash");

    // 3.4 Deep Multi-Layer Shell & Env Nesting Unwrapping (up to 5 levels)
    let deep_nested = r#"env -S sh -c "env -S bash -c 'sudo whoami'""#;
    let unwrapped_deep = unwrap_shell_and_env_nesting(deep_nested);
    assert_eq!(unwrapped_deep, "sudo whoami");

    // 3.5 PrivilegeEquivalenceClass Taxonomy
    // RootOrAdminElevation
    for root_cmd in [
        "sudo apt update",
        "sudo -n id",
        "su -",
        "su root",
        "doas reboot",
        "pkexec bash",
        "runas /user:Administrator cmd.exe",
        "wsl -u root id",
        "wsl -u 0 id",
    ] {
        let sem = parse_semantic_command(root_cmd);
        assert_eq!(
            sem.privilege_class,
            PrivilegeEquivalenceClass::RootOrAdminElevation,
            "Command should be RootOrAdminElevation: '{}'",
            root_cmd
        );
        assert_eq!(classify_action_class(root_cmd), "PRIVILEGED_EXECUTION");
    }

    // TargetUserDelegation
    for del_cmd in [
        "sudo -u www-data php worker.php",
        "su alice",
        "runas /user:bob notepad.exe",
        "wsl -u charlie ls",
    ] {
        let sem = parse_semantic_command(del_cmd);
        assert_eq!(
            sem.privilege_class,
            PrivilegeEquivalenceClass::TargetUserDelegation,
            "Command should be TargetUserDelegation: '{}'",
            del_cmd
        );
        assert_eq!(classify_action_class(del_cmd), "PRIVILEGED_EXECUTION");
    }

    // PrivilegeQueryOrBenign
    for benign_cmd in [
        "sudo -l",
        "sudo -V",
        "sudo -h",
        "pkexec --version",
        "wsl --status",
        "wsl -l -v",
        "su --help",
    ] {
        let sem = parse_semantic_command(benign_cmd);
        assert_eq!(
            sem.privilege_class,
            PrivilegeEquivalenceClass::PrivilegeQueryOrBenign,
            "Command should be PrivilegeQueryOrBenign: '{}'",
            benign_cmd
        );
        assert_eq!(classify_action_class(benign_cmd), "UNPRIVILEGED_EXECUTION");
    }

    // UnprivilegedStandard
    for std_cmd in ["ls -la", "cargo test", "git status", "node server.js"] {
        let sem = parse_semantic_command(std_cmd);
        assert_eq!(
            sem.privilege_class,
            PrivilegeEquivalenceClass::UnprivilegedStandard,
            "Command should be UnprivilegedStandard: '{}'",
            std_cmd
        );
        assert_eq!(classify_action_class(std_cmd), "UNPRIVILEGED_EXECUTION");
    }
}

// ------------------------------------------------------------------------------
// Vector 4: Deal Values with Internal Commas, Multi-Currency & Clinical Checksums
// ------------------------------------------------------------------------------

#[test]
fn test_adv_semantic_dlp_deal_values_and_hipaa_checksums() {
    use agent_octopus::security::semantic_dlp::{
        safe_utf8_slice, RedactXStructuredValidator, SemanticDlpEngine, SemanticEntityKind,
    };

    let engine = SemanticDlpEngine::new();

    // 4.1 Internal commas in deal values (>= $1M -> Quarantine / CrownJewel)
    let deal_cases_1m = [
        "The acquisition deal value is $1,500,000 for AlphaCorp",
        "M&A transaction value is $15,000,000 for BetaCorp",
        "Acquisition purchase price $1,000,000,000 for MegaCorp",
        "Target valuation EUR 2,000,000 in acquisition deal",
        "The merger transaction is GBP 1,500,000 for DeltaCorp",
        "The deal amount is CAD 5,000,000 for NorthernCorp",
        "The acquisition deal value is AUD 4,000,000 for PacificCorp",
        "Deal size is €2,500,000 for EuroCorp",
        "Acquisition valuation is £1,800,000 for BritishCorp",
        "The purchase price is ¥200,000,000 in transaction deal",
        "Deal value is $1.5M for MicroCorp",
        "The acquisition deal value is $2.5B for GlobalCorp",
    ];

    for deal_str in deal_cases_1m {
        let verdict = engine.evaluate_verdict_fail_closed(deal_str);
        assert!(
            verdict.is_deny(),
            "Deal >= $1M must be quarantined: '{}', got {:?}",
            deal_str,
            verdict
        );
    }

    // 4.2 Sub-threshold deals (< $1M -> Restricted / Confidential)
    let deal_cases_sub_1m = [
        "The contract deal value is $500,000 for BetaCorp",
        "Acquisition deal value is $750,000 for SeedCorp",
        "Deal amount is EUR 800,000 for StartupCorp",
        "The transaction deal value is $999,999 for BoundaryCorp",
    ];

    for deal_str in deal_cases_sub_1m {
        let verdict = engine.evaluate_verdict_fail_closed(deal_str);
        assert!(
            verdict.is_restricted(),
            "Deal < $1M must be restricted/blocked, got {:?}",
            verdict
        );
    }

    // 4.3 10-digit NPI with 80840 Luhn validation
    let valid_npi = "1234567893";
    let valid_npi_2 = "1801831870";
    let invalid_npi = "1234567890";
    assert!(RedactXStructuredValidator::npi_valid(valid_npi));
    assert!(RedactXStructuredValidator::npi_valid(valid_npi_2));
    assert!(!RedactXStructuredValidator::npi_valid(invalid_npi));

    let npi_clinical = format!(
        "Attending physician Dr. Smith authorized prescription NPI {}",
        valid_npi
    );
    let npi_matches = engine.scan_payload(&npi_clinical);
    assert!(
        npi_matches
            .iter()
            .any(|m| m.kind == SemanticEntityKind::PhiMedicalRecord),
        "Valid NPI in clinical context must be detected as PHI"
    );

    // 4.4 Mod-11 MRN
    let valid_mrn = "123457";
    let invalid_mrn = "123458";
    assert!(RedactXStructuredValidator::mod11_valid(valid_mrn));
    assert!(!RedactXStructuredValidator::mod11_valid(invalid_mrn));

    let mrn_clinical = format!("Hospital inpatient clinical chart MRN-{}", valid_mrn);
    let mrn_matches = engine.scan_payload(&mrn_clinical);
    assert!(
        mrn_matches
            .iter()
            .any(|m| m.kind == SemanticEntityKind::PhiMedicalRecord),
        "Valid MRN in clinical context must be detected as PHI"
    );

    // 4.5 SSN structural validation
    assert!(RedactXStructuredValidator::ssn_valid("123", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("000", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("666", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("900", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("123", "00", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("123", "45", "0000"));

    // 4.6 Safe UTF-8 character boundary slicing (Zero Panics, Safe Multi-byte)
    let multi_byte_text = "Security 🛡️ Agent 🐙 Octopus 🚀 — 漢字テスト — Cyrillic Тест!";
    let s1 = safe_utf8_slice(multi_byte_text, 0, 8);
    assert_eq!(s1, "Security");
    let s2 = safe_utf8_slice(multi_byte_text, 9, 1);
    assert_eq!(s2, "🛡");
    let s_out = safe_utf8_slice(multi_byte_text, 5000, 10);
    assert_eq!(s_out, "");
    let s_tail = safe_utf8_slice(multi_byte_text, 0, 10000);
    assert!(s_tail.ends_with('!'));

    // 4.7 Depth-8 Recursive Encoding Unwrapping
    let raw_secret = "PATIENT_PHI_SECRET_KEY_1234";
    let h1 = hex::encode(raw_secret);
    use base64::Engine;
    let b2 = base64::engine::general_purpose::STANDARD.encode(h1.as_bytes());
    let u3 = format!("%20{}%20", b2);
    let layers = RedactXStructuredValidator::unwrap_encoded_layers(&u3);
    assert!(layers.iter().any(|l| l.contains(raw_secret)));
}

// ------------------------------------------------------------------------------
// Vector 5: Siquery 15s Execution Timeout and Relational Host Discovery
// ------------------------------------------------------------------------------

#[test]
fn test_adv_siquery_15s_timeout_and_host_discovery() {
    use agent_octopus::security::siquery::{SiqueryEngine, SiqueryOutputFormat};

    let engine = SiqueryEngine::new();

    // 5.1 Guard 1 & 2: Quadruple read-only SQLite checks
    // Direct mutators
    for forbidden in [
        "INSERT INTO processes (pid) VALUES (9999);",
        "UPDATE processes SET pid = 1;",
        "DELETE FROM processes WHERE pid = 1;",
        "DROP TABLE processes;",
        "CREATE TABLE backdoor (x text);",
        "ALTER TABLE processes ADD COLUMN evil text;",
        "REPLACE INTO processes (pid) VALUES (1);",
        "ATTACH DATABASE 'evil.db' AS evil;",
    ] {
        let res = engine.execute_query(forbidden);
        assert!(
            res.is_err(),
            "Forbidden statement must be rejected: '{}'",
            forbidden
        );
    }

    // Comment bypass attempts caught by authorizer
    let comment_create = "/* comment bypass */ CREATE TABLE evil(x);";
    let res_comment = engine.execute_query(comment_create);
    assert!(
        res_comment.is_err(),
        "Comment-prefixed CREATE must be rejected by authorizer"
    );

    // CTE mutation bypass attempts caught by authorizer
    let cte_insert = "WITH cte AS (SELECT 1 AS x) INSERT INTO processes (pid) SELECT x FROM cte;";
    let res_cte = engine.execute_query(cte_insert);
    assert!(
        res_cte.is_err(),
        "CTE INSERT must be rejected by authorizer"
    );

    // Read-only recursive CTE allowed via AuthAction::Recursive
    let rec_res = engine.execute_query_formatted(
        "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x < 5) SELECT x FROM cnt;",
        SiqueryOutputFormat::Json,
    );
    assert!(rec_res.is_ok(), "Read-only recursive CTE must be permitted");
    let rec_str = rec_res.unwrap();
    assert!(rec_str.contains("\"x\": 5") || rec_str.contains("\"x\":5"));

    // 5.2 15-second execution timeout via progress handler
    let start = Instant::now();
    let infinite_res = engine.execute_query(
        "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt) SELECT count(*) FROM cnt;"
    );
    let elapsed = start.elapsed();
    eprintln!("[EMPIRICAL SIQUERY] Infinite query elapsed: {:?}", elapsed);
    assert!(
        infinite_res.is_err(),
        "Infinite query must be interrupted by timeout"
    );
    let err_str = infinite_res.unwrap_err();
    assert!(
        err_str.contains("interrupted"),
        "Expected SQLite interrupted error, got: {}",
        err_str
    );
    assert!(
        elapsed.as_secs() >= 14 && elapsed.as_secs() <= 20,
        "Timeout must occur at ~15s, got: {:?}",
        elapsed
    );

    // 5.3 41 Tables Verification
    let tables = SiqueryEngine::list_tables();
    assert!(
        tables.len() >= 41,
        "Must expose at least 41 tables, got {}",
        tables.len()
    );

    // Security telemetry tables exist and query without error
    let telemetry_tables = [
        "agent_interceptions",
        "exec_events",
        "circumvention_events",
        "dlp_semantic_events",
        "listening_ports",
        "processes",
    ];
    for tbl in telemetry_tables {
        let query = format!("SELECT count(*) FROM {};", tbl);
        let res = engine.execute_query(&query);
        assert!(
            res.is_ok(),
            "Table {} must be queryable: {:?}",
            tbl,
            res.err()
        );
    }
}

// ------------------------------------------------------------------------------
// Vector 6: 24-Layer WFP Network Isolation & Loopback Peer PID Anti-Spoofing
// ------------------------------------------------------------------------------

#[tokio::test]
async fn test_adv_wfp_24_layer_isolation_and_peer_pid_spoofing() {
    use agent_octopus::security::host_network_isolation::{
        discover_active_octopus_ports, HostKillSwitchManager, BLOCKED_L2_ETHERTYPES,
        FWPM_LAYER_IPFORWARD_V4, FWPM_LAYER_IPFORWARD_V6,
    };
    use agent_octopus::web::api::{handle_siquery_query, WebState};
    use agent_octopus::web::request_guard::{authorize_request, GuardRequest};
    use serde_json::json;

    // 6.1 24-Layer WFP Forward Shield Verification
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

    // Verify active port discovery strictly excludes port 5000
    let active_ports = discover_active_octopus_ports();
    assert!(
        !active_ports.contains(&5000),
        "Port 5000 must never be preserved"
    );

    // Verify Hardware Layer-2 EtherTypes
    assert_eq!(BLOCKED_L2_ETHERTYPES, [0x88E5, 0x88F7, 0x8809, 0xAEFE]);

    // Simulated Non-Elevated Host Kill Switch Lifecycle
    let tmp_ledger =
        std::env::temp_dir().join(format!("octopus_adv_m4_2_ks_{}.json", std::process::id()));
    let _ = std::fs::remove_file(&tmp_ledger);
    let ks_mgr = HostKillSwitchManager::new(Some(tmp_ledger.clone()));
    let status = ks_mgr.status();
    assert_eq!(status.wfp_kernel_layers_enforced, 24);

    let rcpt = ks_mgr
        .engage(
            "m4_2_adversary",
            "Adversarial 24-layer shield check against RFC 5737 198.51.100.1",
        )
        .expect("Engage must succeed in simulated mode");
    assert!(rcpt.isolated);

    let disarmed = ks_mgr
        .disarm("m4_2_adversary", "Restoring network state")
        .expect("Disarm must succeed");
    assert!(!disarmed.isolated);
    let _ = std::fs::remove_file(&tmp_ledger);

    // 6.2 Loopback Peer PID Anti-Spoofing & Constant-Time Token Checks
    let state = WebState::default();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local_port = listener.local_addr().unwrap().port();
    let client = TcpStream::connect(("127.0.0.1", local_port)).unwrap();
    let peer_addr = client.local_addr().unwrap();
    let (_accepted, _) = listener.accept().unwrap();

    let actual_pid = std::process::id();

    // Missing token -> 401
    let req_no_tok = GuardRequest {
        method: "POST",
        path: "/api/siquery/query",
        query: "",
        headers: &format!(
            "POST /api/siquery/query HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            local_port
        ),
        local_port,
    };
    let unauth_res = authorize_request(&req_no_tok, "expected_secret_token_123");
    assert_eq!(unauth_res.unwrap_err().status_line(), "401 Unauthorized");

    // Spoofed caller_pid -> 403 Forbidden with CALLER_PID_SPOOF_DETECTED
    let spoofed_pid = actual_pid.wrapping_add(99999);
    let spoof_body = json!({
        "query": "SELECT 1;",
        "caller_pid": spoofed_pid,
        "operator": "adversary_actor"
    })
    .to_string();

    let (st_spoof, body_spoof) =
        handle_siquery_query(&state, &spoof_body, Some(peer_addr), local_port);
    assert_eq!(st_spoof, "403 Forbidden");
    assert!(body_spoof.contains("CALLER_PID_SPOOF_DETECTED"));

    // Unresolvable peer address (e.g. documentation IP 192.0.2.1) -> 403 Forbidden
    let bogus_addr: SocketAddr = "192.0.2.1:44444".parse().unwrap();
    let unres_body = json!({
        "query": "SELECT 1;",
        "caller_pid": actual_pid,
        "operator": "clean_operator"
    })
    .to_string();

    let (st_unres, body_unres) =
        handle_siquery_query(&state, &unres_body, Some(bogus_addr), local_port);
    assert_eq!(st_unres, "403 Forbidden");
    assert!(body_unres.contains("PEER_PID_VERIFICATION_FAILED"));

    // Quarantined caller or operator -> 403 Forbidden
    for _ in 0..3 {
        state
            .tarpit
            .engage_adversary("quarantined_bad_guy", "attack_vector", "payload")
            .await;
    }
    assert!(state.tarpit.is_quarantined("quarantined_bad_guy"));

    let q_body = json!({
        "query": "SELECT 1;",
        "caller_pid": actual_pid,
        "operator": "quarantined_bad_guy"
    })
    .to_string();
    let (st_q, body_q) = handle_siquery_query(&state, &q_body, Some(peer_addr), local_port);
    assert_eq!(st_q, "403 Forbidden");
    assert!(body_q.contains("CALLER_QUARANTINED"));

    // Legitimate authenticated request -> 200 OK
    let ok_body = json!({
        "query": "SELECT 42 AS answer;",
        "caller_pid": actual_pid,
        "operator": "clean_actor"
    })
    .to_string();
    let (st_ok, body_ok) = handle_siquery_query(&state, &ok_body, Some(peer_addr), local_port);
    assert_eq!(st_ok, "200 OK");
    assert!(
        body_ok.contains("\"status\":\"success\"") || body_ok.contains("\"status\": \"success\"")
    );
}
