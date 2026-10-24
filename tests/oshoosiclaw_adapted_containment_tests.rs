//! Integration tests for all OshoosiClaw AgentOctopus containment, mathematical laws,
//! physical models, console hardening, port fallback, and 5-policy RL benchmark capabilities.

use agent_octopus::containment_ring::{
    is_restricted_rebinding_ip, validate_agent_egress_url, ArmContainmentRing, ArmRingRegistry,
    DiracDeltaCapabilityTicket, HomologicalBoundaryAuditor, IndependentTrustBoundaryVerifier,
    PinnedToolObjectBinding, VanishingPolynomialTraceVerifier, ZeroCopyImmutableToolBuffer,
};
use agent_octopus::security::{
    compute_hardened_console_mode, evaluate_pre_resume_confinement_gate, harden_windows_console,
    is_console_mode_hardened, run_standardized_5policy_benchmark, validate_agent_filesystem_access,
    validate_sandbox_relative_path, DynamicAgentClassifier, FileLineageTracker, HostActuationPore,
    MercuryContainmentEngine, OrbWebContainmentEngine, ProcessBehavioralTelemetry,
    RuntimeAlignmentScanner, SessionIntentContract, SilkRegime, ToolCallTraceStep,
    WindowsConfinementPolicy, ZeroMutualInformationProjector, CREATE_NO_WINDOW,
    ENABLE_EXTENDED_FLAGS, ENABLE_INSERT_MODE, ENABLE_MOUSE_INPUT, ENABLE_QUICK_EDIT_MODE,
};
use agent_octopus::web::{is_loopback_port_available, select_available_loopback_port};
use agent_octopus::ArmRole;

#[test]
fn test_law1_homological_boundary_exactness_and_2simplex_veto() {
    let mut auditor = HomologicalBoundaryAuditor::new(32);
    auditor.set_node_potential("untrusted_ingest", 0);
    auditor.set_node_potential("worker_relay", 5);
    auditor.set_node_potential("accounting_ledger_write", 10);

    let report = auditor.verify_boundary_operator_exactness();
    assert!(report.boundary_squared_zero);
    assert!(report.coboundary_curl_zero);

    let safe = auditor.record_and_audit_edge("worker_relay", "worker_relay");
    assert!(safe.passed);

    let laundering = auditor.record_and_audit_edge("untrusted_ingest", "worker_relay");
    let laundering2 = auditor.record_and_audit_edge("worker_relay", "accounting_ledger_write");
    assert!(
        !laundering.passed || !laundering2.passed,
        "2-simplex confused-deputy proxy laundering must be vetoed by Law 1"
    );
}

#[test]
fn test_law2_vanishing_polynomial_trace_verifier_mersenne127() {
    let verifier = VanishingPolynomialTraceVerifier::default();
    let valid_proof = verifier.prove_and_verify_trace(101, 3, "read_invoice", true);
    assert!(valid_proof.verified);
    assert_eq!(valid_proof.quotient_remainder_hex, "0x00000000000000000000000000000000");

    let tampered = verifier.verify_external_commitment(
        valid_proof.trace_commitment_u128 ^ 0x1337,
        valid_proof.constraint_eval_u128,
        101,
        3,
    );
    assert!(!tampered, "Tampered trace commitment must fail vanishing polynomial verification");
}

#[test]
fn test_law3_dirac_delta_capability_ticket_and_law5_zero_copy_buffer() {
    let secret = [0x5Au8; 32];
    let ticket = DiracDeltaCapabilityTicket::issue(
        101,
        1,
        "read_invoice",
        "sha256:abc123",
        5_000,
        "CANARY_TRAP_99",
        &secret,
    );

    // Law 5: Zero-Copy hardware page-locked buffer
    let mut buf = ZeroCopyImmutableToolBuffer::allocate_and_populate(b"{\"invoice\":100}")
        .expect("Page-aligned buffer allocation");
    buf.lock_read_only().expect("VirtualProtect/mprotect PAGE_READONLY");
    assert!(buf.is_locked_read_only());
    assert_eq!(buf.delta_t_toctou_ns(), 0);
    assert_eq!(buf.as_slice().unwrap(), b"{\"invoice\":100}");

    // First consumption succeeds
    ticket
        .consume_once(101, 1, "read_invoice", "sha256:abc123", b"{\"invoice\":100}", &secret)
        .expect("First impulse consumption must succeed");

    // Second consumption fails closed (replay blocked)
    let replay = ticket.consume_once(
        101,
        1,
        "read_invoice",
        "sha256:abc123",
        b"{\"invoice\":100}",
        &secret,
    );
    assert!(replay.is_err(), "Replay of DiracDeltaCapabilityTicket must fail closed");
}

#[test]
fn test_descriptor_pinning_and_3layer_non_circular_trust_gate() {
    let tmp = std::env::temp_dir().join(format!("octopus_pin_test_{}.txt", std::process::id()));
    std::fs::write(&tmp, b"trusted_tool_binary_v1").unwrap();

    let pinned = PinnedToolObjectBinding::pin_regular_file(&tmp).expect("Must pin regular file");
    let opened = std::fs::File::open(&tmp).unwrap();
    pinned
        .verify_opened_handle(&opened)
        .expect("Unmodified descriptor must match pinned identity");

    // Modify file mid-flight (simulate TOCTOU swap)
    std::fs::write(&tmp, b"compromised_payload_v2_longer").unwrap();
    let swapped = std::fs::File::open(&tmp).unwrap();
    assert!(
        pinned.verify_opened_handle(&swapped).is_err(),
        "Modified file must fail descriptor identity check"
    );
    let _ = std::fs::remove_file(&tmp);

    // 3-layer orthogonal non-circular trust gate
    let gate = IndependentTrustBoundaryVerifier::new(
        b"layer1_key_seed_0000000000000001",
        b"layer2_key_seed_0000000000000002",
        b"layer3_key_seed_0000000000000003",
    );
    assert!(gate.are_domains_orthogonal());
    let pass_verdict = gate.evaluate_orthogonal_gates(true, true, true, "actuate_tool");
    assert!(pass_verdict.overall_allowed);
    let fail_verdict = gate.evaluate_orthogonal_gates(true, true, false, "actuate_tool");
    assert!(!fail_verdict.overall_allowed);
}

#[test]
fn test_sec_ring_01_pid_guard_and_mesh_watchout_broadcast() {
    assert!(ArmContainmentRing::verify_terminable_child_pid(0).is_err());
    assert!(ArmContainmentRing::verify_terminable_child_pid(4).is_err());
    assert!(ArmContainmentRing::verify_terminable_child_pid(std::process::id()).is_err());
    assert!(ArmContainmentRing::verify_terminable_child_pid(std::process::id() + 10_000).is_ok());

    let registry = ArmRingRegistry::new();
    let signal = registry.sever_arm(1, "Canary Tripwire Activated").expect("Must sever arm 1");
    assert_eq!(signal.severed_arm_id, 1);
    let watchouts = registry.list_watchout_signals();
    assert!(!watchouts.is_empty());
    assert_eq!(watchouts[0].severed_arm_id, 1);
}

#[test]
fn test_law8_zero_mi_projector_and_path_egress_guards() {
    let projector = ZeroMutualInformationProjector::default();
    let dirty = "{\"z\":1,\"a\":\"secret\\u200Btext Alpha Bravo Charlie Delta Echo\"}";
    let projected = projector.project(dirty, 1_700_000_000_333);
    assert!(!projected.projected_payload.contains('\u{200B}'));
    assert_eq!(projected.quantized_release_ms % 100, 0);
    assert_eq!(projected.estimated_mutual_information_bits, 0.0);

    let sandbox = std::env::temp_dir();
    assert!(validate_sandbox_relative_path(&sandbox, "C:\\Windows\\System32\\cmd.exe").is_err());
    assert!(validate_sandbox_relative_path(&sandbox, "..\\..\\etc\\passwd").is_err());
    assert!(validate_sandbox_relative_path(&sandbox, "reports/summary.json").is_ok());
    assert!(validate_agent_filesystem_access(&sandbox, "reports/summary.json", false).is_ok());

    let allowed = vec!["google.com".to_string(), "www.google.com".to_string()];
    assert!(validate_agent_egress_url("https://www.google.com/search", &allowed).is_ok());
    assert!(validate_agent_egress_url("http://[::1]:5005/api/status", &allowed).is_err());
    assert!(validate_agent_egress_url("http://[::ffff:169.254.169.254]/latest", &allowed).is_err());
    assert!(is_restricted_rebinding_ip(&"100.64.0.1".parse().unwrap()));
}

#[test]
fn test_file_lineage_immunity_and_console_defense_and_port_fallback() {
    let mut tracker = FileLineageTracker::new();
    let digest = "deadbeefcafe0123456789abcdef0123456789abcdef0123456789abcdef0123";
    tracker.mark_digest_poisoned(digest);
    // Hard repository/toolchain immunity must be checked BEFORE poisoned_digests
    assert!(!tracker.is_file_tainted("Cargo.toml", digest));
    assert!(!tracker.is_file_tainted("src/lib.rs", digest));
    assert!(tracker.is_file_tainted("downloads/untrusted_macro.docm", digest));

    // EDR-VEC-23 console defense
    let raw_mode = ENABLE_QUICK_EDIT_MODE | ENABLE_INSERT_MODE | ENABLE_MOUSE_INPUT | 0x0007;
    let hardened = compute_hardened_console_mode(raw_mode);
    assert!(is_console_mode_hardened(hardened));
    assert_eq!(hardened & ENABLE_EXTENDED_FLAGS, ENABLE_EXTENDED_FLAGS);
    assert_eq!(CREATE_NO_WINDOW, 0x0800_0000);
    let _ = harden_windows_console();

    // Windows pre-resume confinement gate
    let policy = WindowsConfinementPolicy::strict_default("arm-101");
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
    let contract = SessionIntentContract::new(
        "sess-01",
        "Summarize Q3 accounting ledger",
        vec!["read_ledger".to_string(), "summarize".to_string()],
        vec!["shell_exec".to_string(), "exfiltrate".to_string()],
    );
    let scanner = RuntimeAlignmentScanner::new(contract);
    let benign_trace = vec![ToolCallTraceStep {
        step_index: 0,
        tool_name: "read_ledger".to_string(),
        arguments_summary: "ledger_q3.csv".to_string(),
        contains_untrusted_output: false,
    }];
    assert!(scanner.scan_trace(&benign_trace).aligned);

    // 2. MercuryContainmentEngine
    let mercury = MercuryContainmentEngine::default();
    let m_res = mercury.evaluate_actuation(HostActuationPore::RawSocketSend, 950_000.0, 25.0, 0.001, true);
    assert!(m_res.blocked);

    // 3. OrbWebContainmentEngine
    let orb = OrbWebContainmentEngine::default();
    let o_res = orb.evaluate_strain_and_exposure(0.05, 5.0, 0.002, 0.003, 10.0);
    assert_eq!(o_res.regime, SilkRegime::LinearElastic);
    assert!(o_res.exposure_invariant_satisfied);

    // 4. DynamicAgentClassifier
    let classifier = DynamicAgentClassifier::default();
    let verdict = classifier.classify(&ProcessBehavioralTelemetry {
        pid: 4242,
        process_name: "autonomous_coder.exe".to_string(),
        llm_egress_connections: 6,
        json_rpc_stdio_frames: 40,
        rapid_tool_fanout_per_sec: 12.0,
        prompt_context_env_vars: 2,
        has_interactive_human_conpty: false,
    });
    assert!(verdict.is_autonomous_agent);

    // 5. Standardized 5-Policy RL Benchmark (RULE[rl_benchmarking_and_evaluation.md])
    let report = run_standardized_5policy_benchmark(6, 2026);
    assert_eq!(report.policies.len(), 5);
    assert!(report.learned_superiority_verified);
}
