//! Integration tests for all OshoosiClaw AgentOctopus containment, mathematical laws,
//! physical models, console hardening, port fallback, and 5-policy RL benchmark capabilities.

use agent_octopus::containment_ring::{
    is_restricted_rebinding_ip, validate_agent_egress_url, ArmContainmentRing, ArmRingRegistry,
    DiracDeltaCapabilityTicket, HomologicalBoundaryAuditor, IndependentTrustBoundaryVerifier,
    PinnedToolObjectBinding, VanishingPolynomialTraceVerifier, ZeroCopyImmutableToolBuffer,
};
use agent_octopus::security::rl_defense::AdaptiveRlDefenseEngine;
use agent_octopus::security::{
    compute_hardened_console_mode, evaluate_pre_resume_confinement_gate, harden_windows_console,
    is_console_mode_hardened, validate_agent_filesystem_access, validate_sandbox_relative_path,
    DynamicAgentClassifier, FileLineageTracker, HostActuationPore, MercuryContainmentEngine,
    OrbWebContainmentEngine, ProcessBehavioralTelemetry, RuntimeAlignmentScanner, SilkRegime,
    ToolCallTraceStep, WindowsConfinementPolicy, ZeroMutualInformationProjector, CREATE_NO_WINDOW,
    ENABLE_EXTENDED_FLAGS, ENABLE_INSERT_MODE, ENABLE_MOUSE_INPUT, ENABLE_QUICK_EDIT_MODE,
};
use agent_octopus::web::{is_loopback_port_available, select_available_loopback_port};

#[test]
fn test_law1_homological_boundary_exactness_and_2simplex_veto() {
    let safe = HomologicalBoundaryAuditor::audit_simplex_transition(
        "worker_relay",
        None,
        "worker_relay",
    );
    assert!(safe.boundary_squared_zero);
    assert!(!safe.proxy_laundering_detected);
    assert!(safe.allowed);

    let laundering = HomologicalBoundaryAuditor::audit_simplex_transition(
        "untrusted_ingest",
        Some("worker_relay"),
        "accounting_ledger_write",
    );
    assert!(laundering.boundary_squared_zero);
    assert!(
        laundering.proxy_laundering_detected,
        "2-simplex confused-deputy proxy laundering must be detected by Law 1"
    );
    assert!(!laundering.allowed);
}

#[test]
fn test_law2_vanishing_polynomial_trace_verifier_mersenne127() {
    let valid_proof = VanishingPolynomialTraceVerifier::verify_execution_trace(
        &[100, 142, 200],
        &[42, 58],
    );
    assert!(valid_proof.verified);
    assert_eq!(valid_proof.quotient_remainder, 0);

    let tampered_proof = VanishingPolynomialTraceVerifier::verify_execution_trace(
        &[100, 999, 200],
        &[42, 58],
    );
    assert!(
        !tampered_proof.verified,
        "Tampered execution trace must fail vanishing polynomial verification"
    );
}

#[test]
fn test_law3_dirac_delta_capability_ticket_and_law5_zero_copy_buffer() {
    let secret = [0x5Au8; 32];
    let mut ticket = DiracDeltaCapabilityTicket::issue(
        "arm-101",
        1,
        "read_invoice",
        "sha256:abc123",
        500_000,
        &secret,
        Some("CANARY_TRAP_99".to_string()),
    );

    // Law 5: Zero-Copy hardware page-locked buffer
    let buf = ZeroCopyImmutableToolBuffer::create_and_lock(b"{\"invoice\":100}")
        .expect("Page-aligned buffer allocation and PAGE_READONLY lock");
    assert!(buf.is_locked_readonly());
    assert_eq!(buf.delta_t_toctou_ns, 0);
    assert_eq!(buf.as_verified_slice().unwrap(), b"{\"invoice\":100}");

    // First consumption succeeds
    let derived_secret = ticket
        .consume_once("read_invoice", "sha256:abc123", 1, &secret, None)
        .expect("First impulse consumption must succeed");
    assert_ne!(derived_secret, [0u8; 32]);
    assert!(ticket.is_consumed());

    // Second consumption fails closed (replay blocked)
    let replay = ticket.consume_once("read_invoice", "sha256:abc123", 1, &secret, None);
    assert!(replay.is_err(), "Replay of DiracDeltaCapabilityTicket must fail closed");
}

#[test]
fn test_descriptor_pinning_and_3layer_non_circular_trust_gate() {
    let tmp = std::env::temp_dir().join(format!("octopus_pin_test_{}.txt", std::process::id()));
    std::fs::write(&tmp, b"trusted_tool_binary_v1").unwrap();

    let pinned = PinnedToolObjectBinding::pin_at_check(&tmp).expect("Must pin regular file");
    let mut opened = std::fs::File::open(&tmp).unwrap();
    pinned
        .verify_open_descriptor(&mut opened, &tmp)
        .expect("Unmodified descriptor must match pinned identity");

    // Modify file mid-flight (simulate TOCTOU swap)
    std::fs::write(&tmp, b"compromised_payload_v2_longer").unwrap();
    let mut swapped = std::fs::File::open(&tmp).unwrap();
    assert!(
        pinned.verify_open_descriptor(&mut swapped, &tmp).is_err(),
        "Modified file must fail descriptor identity check"
    );
    let _ = std::fs::remove_file(&tmp);

    // 3-layer orthogonal non-circular trust gate
    let gate = IndependentTrustBoundaryVerifier::new(b"master_seed_for_orthogonal_3layr");
    let l1 = gate.compute_layer1_token("arm-101", 1);
    let l2 = gate.compute_layer2_token("merkle-root-01", 1);
    let l3 = gate.compute_layer3_token("job-container-01", 1);

    let pass_verdict = gate.evaluate_three_layer_gate(
        "arm-101",
        "merkle-root-01",
        "job-container-01",
        &l1,
        &l2,
        &l3,
        true,
    );
    assert!(pass_verdict.allowed);

    let fail_verdict = gate.evaluate_three_layer_gate(
        "arm-101",
        "merkle-root-01",
        "job-container-01",
        &l1,
        &l2,
        &l3,
        false,
    );
    assert!(!fail_verdict.allowed);
}

#[test]
fn test_sec_ring_01_pid_guard_and_mesh_watchout_broadcast() {
    assert!(ArmContainmentRing::verify_terminable_child_pid(0).is_err());
    assert!(ArmContainmentRing::verify_terminable_child_pid(4).is_err());
    assert!(ArmContainmentRing::verify_terminable_child_pid(std::process::id()).is_err());
    assert!(ArmContainmentRing::verify_terminable_child_pid(std::process::id() + 10_000).is_ok());

    let registry = ArmRingRegistry::new();
    let severed = registry
        .sever_arm(1, "Canary Tripwire Activated")
        .expect("Must sever arm 1");
    assert!(severed);
    let watchouts = registry.list_watchout_signals();
    assert!(!watchouts.is_empty());
    assert_eq!(watchouts[0].severed_arm_id, 1);
}

#[test]
fn test_law8_zero_mi_projector_and_path_egress_guards() {
    let dirty = "{\"z\":1,\"a\":\"secret\u{200B}text Alpha Bravo Charlie Delta Echo\"}";
    let projected = ZeroMutualInformationProjector::project_output(dirty, 1_700_000_000_333);
    assert!(!projected.projected_payload.contains('\u{200B}'));
    assert_eq!(projected.quantized_timestamp_ms % 100, 0);

    let sandbox = std::env::temp_dir();
    assert!(validate_sandbox_relative_path(&sandbox, "C:\\Windows\\System32\\cmd.exe").is_err());
    assert!(validate_sandbox_relative_path(&sandbox, "..\\..\\etc\\passwd").is_err());
    assert!(validate_sandbox_relative_path(&sandbox, "reports/summary.json").is_ok());

    let tmp_sub = sandbox.join("octopus_fs_test_dir");
    let _ = std::fs::create_dir_all(&tmp_sub);
    let test_file = tmp_sub.join("summary.json");
    std::fs::write(&test_file, b"{}").unwrap();
    assert!(validate_agent_filesystem_access(&tmp_sub, "summary.json", &[]).is_ok());
    let _ = std::fs::remove_file(&test_file);

    let allowed = vec!["google.com".to_string(), "www.google.com".to_string()];
    assert!(validate_agent_egress_url("https://www.google.com/search", &allowed).is_ok());
    assert!(validate_agent_egress_url("http://[::1]:5005/api/status", &allowed).is_err());
    assert!(validate_agent_egress_url("http://[::ffff:169.254.169.254]/latest", &allowed).is_err());
    assert!(is_restricted_rebinding_ip(&"100.64.0.1".parse().unwrap()));
}

#[test]
fn test_file_lineage_immunity_and_console_defense_and_port_fallback() {
    let tracker = FileLineageTracker::default();
    let payload = b"poisoned_external_content";
    tracker.record_file_ingest(
        "downloads/untrusted_macro.docm",
        payload,
        "ingest_arm",
        "external_email",
        true,
    );
    // Hard repository/toolchain immunity must be checked BEFORE poisoned_digests
    let cargo_verdict = tracker.evaluate_lineage("Cargo.toml", Some(payload));
    assert!(cargo_verdict.allowed);
    assert!(cargo_verdict.is_immune_repository_or_toolchain);

    let src_verdict = tracker.evaluate_lineage("src/lib.rs", Some(payload));
    assert!(src_verdict.allowed);

    let tainted_verdict = tracker.evaluate_lineage("downloads/untrusted_macro.docm", Some(payload));
    assert!(!tainted_verdict.allowed);
    assert!(tainted_verdict.is_poisoned_lineage);

    // EDR-VEC-23 console defense
    let raw_mode = ENABLE_QUICK_EDIT_MODE | ENABLE_INSERT_MODE | ENABLE_MOUSE_INPUT | 0x0007;
    let hardened = compute_hardened_console_mode(raw_mode);
    assert!(is_console_mode_hardened(hardened));
    assert_eq!(hardened & ENABLE_EXTENDED_FLAGS, ENABLE_EXTENDED_FLAGS);
    assert_eq!(CREATE_NO_WINDOW, 0x0800_0000);
    let _ = harden_windows_console();

    // Windows pre-resume confinement gate
    let policy = WindowsConfinementPolicy::default();
    assert!(evaluate_pre_resume_confinement_gate(&policy, true, true, true, true).is_ok());
    assert!(evaluate_pre_resume_confinement_gate(&policy, true, false, true, true).is_err());

    // Port fallback: if a port is bound, select_available_loopback_port must pick another free port
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    assert!(!is_loopback_port_available(occupied_port));
    assert!(!is_loopback_port_available(5000));
    let fallback_port = select_available_loopback_port(occupied_port);
    assert_ne!(fallback_port, occupied_port);
    assert_ne!(fallback_port, 5000);
}

#[test]
fn test_alignment_mercury_spider_classifier_and_5policy_rl_benchmark() {
    // 1. RuntimeAlignmentScanner
    let scanner = RuntimeAlignmentScanner::default();
    scanner.pin_session_intent(
        "sess-01",
        "Summarize Q3 accounting ledger",
        vec!["read_ledger".to_string(), "summarize".to_string()],
        vec!["reports/".to_string()],
    );
    let verdict = scanner.evaluate_tool_step(
        "sess-01",
        ToolCallTraceStep {
            step_index: 0,
            tool_name: "read_ledger".to_string(),
            target_resource: "reports/ledger_q3.csv".to_string(),
            arguments_preview: "reports/ledger_q3.csv".to_string(),
            triggered_by_external_data: false,
        },
    );
    assert!(verdict.aligned);

    // 2. MercuryContainmentEngine
    let mercury = MercuryContainmentEngine::new();
    let m_res = mercury.evaluate_pore_pressure(
        "arm-101",
        HostActuationPore::NetworkSocketEgress,
        950_000.0,
        25.0,
        0.001,
        1.5,
    );
    assert!(m_res.pore_breached || m_res.droplet_shattering_detected);

    // 3. OrbWebContainmentEngine
    let orb = OrbWebContainmentEngine::default();
    let o_res = orb.evaluate_impact(0.01, 5.0, 0.002, 0.003, 10.0, Some(100), Some(1));
    assert_eq!(o_res.regime, SilkRegime::Regime1LinearElastic);
    assert!(!o_res.exposure_bound_violated);

    // 4. DynamicAgentClassifier
    let c_verdict = DynamicAgentClassifier::classify_process(&ProcessBehavioralTelemetry {
        pid: 4242,
        process_label: "autonomous_coder.exe".to_string(),
        has_mcp_jsonrpc_stdio_framing: true,
        has_llm_inference_endpoint_socket: true,
        sub_50ms_tool_dispatch_burst_rate: 1.2,
        autonomous_file_mutation_entropy: 0.85,
        has_interactive_conpty_human_keystrokes: false,
        signed_vendor_toolchain_verified: false,
    });
    assert!(c_verdict.is_autonomous_agent);

    // 5. Standardized 5-Policy RL Benchmark (RULE[rl_benchmarking_and_evaluation.md])
    let rl_path = std::env::temp_dir().join("octopus_rl_bench_test.json");
    let rl_engine = AdaptiveRlDefenseEngine::new(rl_path.to_str().unwrap());
    let report = rl_engine.run_standardized_5policy_benchmark(10, 2026);
    assert!(report.learned_superior_over_all_4_baselines);
    let _ = std::fs::remove_file(&rl_path);
}
