use agent_octopus::core::circuit_breaker::KillSwitch;
use agent_octopus::core::types::ArmRole;
use agent_octopus::security::agentmesh::{AgentMeshConfig, AgentMeshEngine};
use agent_octopus::security::rl_defense::AdaptiveRlDefenseEngine;
use agent_octopus::security::wasm_tier1::WasmMeshBridgeContext;
use agent_octopus::security::{WasmSandboxLimits, WasmTier1Executor, WASM_DOC_EXTRACTOR_WAT};
use agent_octopus::{
    extract_sbom_features, parse_cyclonedx_sbom_bounded, AgentRuntimeGuard, CedarPolicyEngine,
    ComponentProperty, CycloneDxSbom, GuardVerdict, LatentShieldError, LatentWorldModel,
    LicenseChoice, LicenseDetail, LiveRuntimeMonitor, OctopusSecurityError, RuntimeEventKind,
    RuntimeTelemetry, SbomComponent, SbomDependency, SbomIntent, SbomSupplyChainGuard,
    UnifiedSecurityShield, DEFAULT_EMBEDDED_WEIGHTS_JSON, DEFAULT_LATENT_DIM, MAX_SBOM_COMPONENTS,
    MAX_SBOM_DEPENDENCIES, MAX_SBOM_EDGES, MAX_SBOM_JSON_BYTES, MAX_SBOM_LICENSES_PER_COMPONENT,
    MAX_SBOM_PROPERTIES_PER_COMPONENT, MAX_SBOM_STRING_LEN, MAX_WEIGHTS_JSON_BYTES,
    RUNTIME_ACTION_DIM, RUNTIME_OBS_DIM, SBOM_ACTION_DIM, SBOM_OBS_DIM,
};
use ndarray::Array1;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempTestDir {
    path: PathBuf,
}

impl TempTestDir {
    fn new(prefix: &str) -> Self {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("ao_m5b_{}_{}_{}", prefix, std::process::id(), id));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp test dir");
        Self { path: p }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn clean_comp(name: &str, version: &str, purl_prefix: &str, license: &str) -> SbomComponent {
    SbomComponent {
        name: name.to_string(),
        version: version.to_string(),
        purl: Some(format!("{}{}@{}", purl_prefix, name, version)),
        licenses: vec![LicenseChoice {
            license: Some(LicenseDetail {
                id: Some(license.to_string()),
            }),
        }],
        properties: Vec::new(),
    }
}

fn baseline_sbom() -> CycloneDxSbom {
    CycloneDxSbom {
        components: vec![
            clean_comp("serde", "1.0.200", "pkg:cargo/", "MIT"),
            clean_comp("tokio", "1.38.0", "pkg:cargo/", "MIT"),
            clean_comp("sha2", "0.10.8", "pkg:cargo/", "Apache-2.0"),
            clean_comp("hex", "0.4.3", "pkg:cargo/", "MIT"),
        ],
        dependencies: vec![SbomDependency {
            component_ref: "app".to_string(),
            depends_on: vec!["serde".to_string(), "tokio".to_string()],
        }],
    }
}

fn clean_patch_sbom() -> CycloneDxSbom {
    CycloneDxSbom {
        components: vec![
            clean_comp("serde", "1.0.201", "pkg:cargo/", "MIT"),
            clean_comp("tokio", "1.38.0", "pkg:cargo/", "MIT"),
            clean_comp("sha2", "0.10.8", "pkg:cargo/", "Apache-2.0"),
            clean_comp("hex", "0.4.3", "pkg:cargo/", "MIT"),
        ],
        dependencies: vec![SbomDependency {
            component_ref: "app".to_string(),
            depends_on: vec!["serde".to_string(), "tokio".to_string()],
        }],
    }
}

fn poisoned_sbom() -> CycloneDxSbom {
    CycloneDxSbom {
        components: vec![
            clean_comp("serde", "1.0.201", "pkg:cargo/", "MIT"),
            clean_comp("tokio", "1.38.0", "pkg:cargo/", "MIT"),
            clean_comp("sha2", "0.10.8", "pkg:cargo/", "Apache-2.0"),
            clean_comp("hex", "0.4.3", "pkg:cargo/", "MIT"),
            SbomComponent {
                name: "evil-exfil-sys".to_string(),
                version: "0.0.1".to_string(),
                purl: Some("pkg:raw/evil-exfil-sys@0.0.1".to_string()),
                licenses: Vec::new(),
                properties: vec![ComponentProperty {
                    name: "capability".to_string(),
                    value: "network,process,build-script,ffi".to_string(),
                }],
            },
        ],
        dependencies: vec![SbomDependency {
            component_ref: "app".to_string(),
            depends_on: vec![
                "serde".to_string(),
                "tokio".to_string(),
                "evil-exfil-sys".to_string(),
            ],
        }],
    }
}

fn sbom_to_cyclonedx_json(sbom: &CycloneDxSbom) -> String {
    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": sbom.components,
        "dependencies": sbom.dependencies,
    })
    .to_string()
}

fn octopus_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_octopus"))
}

fn run_octopus_cli(args: &[&str], cwd: &Path) -> std::process::Output {
    let posture_path =
        std::env::temp_dir().join(format!("ao_m5b_cli_posture_{}.json", std::process::id()));
    Command::new(octopus_bin())
        .args(args)
        .current_dir(cwd)
        .env_remove("ANTHROPIC_BASE_URL")
        .env_remove("OPENAI_BASE_URL")
        .env("AGENT_OCTOPUS_SHIELD_POSTURE_PATH", posture_path)
        .output()
        .expect("execute octopus binary")
}

#[test]
fn test_r8_case1_clean_sbom_and_normal_rag_execution_allowed() {
    let shield = UnifiedSecurityShield::from_embedded_defaults().expect("embedded defaults");
    let base = baseline_sbom();
    let cand = clean_patch_sbom();
    let intent = SbomIntent::Patch.to_action_array();

    let prev_rt = RuntimeTelemetry::baseline_rag();
    let tool_action = Array1::from_vec(vec![1.0, 0.0, 0.0]);
    let next_rt = RuntimeTelemetry {
        file_reads_norm: 0.10,
        file_writes_norm: 0.02,
        child_procs_norm: 0.0,
        net_sockets_norm: 0.06,
        mem_delta_norm: 0.04,
        prompt_entropy_norm: 0.24,
    };

    let res = shield.authorize_and_step(&base, &intent, &cand, &prev_rt, &tool_action, &next_rt);
    let verdict = res.expect("Case 1 clean SBOM + normal RAG must be allowed");
    assert!(!verdict.block_execution);
    assert_eq!(verdict.domain, "AGENT_OCTOPUS_RUNTIME");
    assert!(verdict.surprise_score.is_finite());
    assert!(verdict.surprise_score <= verdict.threshold);
}

#[test]
fn test_r8_case2_poisoned_sbom_injection_blocked() {
    let shield = UnifiedSecurityShield::from_embedded_defaults().expect("embedded defaults");
    let base = baseline_sbom();
    let cand = poisoned_sbom();
    let intent = SbomIntent::Patch.to_action_array();

    let prev_rt = RuntimeTelemetry::baseline_rag();
    let tool_action = Array1::from_vec(vec![1.0, 0.0, 0.0]);

    let res = shield.authorize_and_step(&base, &intent, &cand, &prev_rt, &tool_action, &prev_rt);
    let err = res.expect_err("Case 2 poisoned SBOM must be blocked at Gate 1");
    assert!(err.block_execution);
    assert_eq!(err.domain, "SBOM_SUPPLY_CHAIN");
    assert!(err.surprise_score.is_finite());
    assert!(err.surprise_score > err.threshold);
}

#[test]
fn test_r8_case3_clean_sbom_runtime_breakout_telemetry_spike_blocked() {
    let shield = UnifiedSecurityShield::from_embedded_defaults().expect("embedded defaults");
    let base = baseline_sbom();
    let cand = clean_patch_sbom();
    let intent = SbomIntent::Patch.to_action_array();
    let prev_rt = RuntimeTelemetry::baseline_rag();

    // Test multiple breakout spike vectors: child spawn spike, net exfil spike, memory spike.
    let spikes = [
        (
            vec![1.0, 0.0, 0.0],
            RuntimeTelemetry {
                file_reads_norm: 0.15,
                file_writes_norm: 0.10,
                child_procs_norm: 1.0,
                net_sockets_norm: 0.05,
                mem_delta_norm: 0.10,
                prompt_entropy_norm: 0.25,
            },
        ),
        (
            vec![0.0, 0.0, 1.0],
            RuntimeTelemetry {
                file_reads_norm: 0.08,
                file_writes_norm: 0.04,
                child_procs_norm: 0.0,
                net_sockets_norm: 1.25,
                mem_delta_norm: 0.10,
                prompt_entropy_norm: 0.25,
            },
        ),
        (
            vec![1.0, 0.0, 0.0],
            RuntimeTelemetry {
                file_reads_norm: 0.05,
                file_writes_norm: 0.02,
                child_procs_norm: 0.0,
                net_sockets_norm: 0.02,
                mem_delta_norm: 1.4,
                prompt_entropy_norm: 0.22,
            },
        ),
    ];

    for (act, spike_rt) in spikes {
        let res = shield.authorize_and_step(
            &base,
            &intent,
            &cand,
            &prev_rt,
            &Array1::from_vec(act),
            &spike_rt,
        );
        let err = res.expect_err("Case 3 breakout telemetry spike must be blocked");
        assert!(err.block_execution);
        assert_eq!(err.domain, "AGENT_OCTOPUS_RUNTIME");
        assert!(err.surprise_score > err.threshold);
    }
}

#[test]
fn test_r8_json_weights_roundtrip_and_embedded_parity() {
    let trained = UnifiedSecurityShield::train_deterministic_default(42);
    let embedded = UnifiedSecurityShield::from_embedded_defaults().expect("embedded defaults");
    let cached = UnifiedSecurityShield::cached_default().expect("cached default");

    assert!(!DEFAULT_EMBEDDED_WEIGHTS_JSON.trim().is_empty());

    let serialized = serde_json::to_string(&trained).expect("serialize shield");
    let roundtripped =
        UnifiedSecurityShield::parse_weights_json_bounded(&serialized).expect("roundtrip parse");

    let base_f = extract_sbom_features(&baseline_sbom());
    let cand_f = extract_sbom_features(&clean_patch_sbom());
    let act = SbomIntent::Patch.to_action_array();

    let s_trained = trained
        .sbom_guard
        .model()
        .try_compute_surprise(&base_f, &act, &cand_f)
        .unwrap();
    let s_roundtrip = roundtripped
        .sbom_guard
        .model()
        .try_compute_surprise(&base_f, &act, &cand_f)
        .unwrap();
    let s_embedded = embedded
        .sbom_guard
        .model()
        .try_compute_surprise(&base_f, &act, &cand_f)
        .unwrap();
    let s_cached = cached
        .sbom_guard
        .model()
        .try_compute_surprise(&base_f, &act, &cand_f)
        .unwrap();

    assert!((s_trained - s_roundtrip).abs() < 1e-12);
    assert!((s_trained - s_embedded).abs() < 1e-12);
    assert!((s_embedded - s_cached).abs() < 1e-12);
}

#[test]
fn test_r8_fail_closed_nan_inf_and_dimension_mismatches() {
    let shield = UnifiedSecurityShield::from_embedded_defaults().expect("embedded defaults");
    let prev = RuntimeTelemetry::baseline_rag();
    let good_act = Array1::from_vec(vec![1.0, 0.0, 0.0]);

    // 1. NaN / +Inf / -Inf in RuntimeTelemetry must ALWAYS block and serialize finite JSON
    for bad_val in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let bad_rt = RuntimeTelemetry {
            file_reads_norm: bad_val,
            ..prev.clone()
        };
        let v: GuardVerdict = shield
            .runtime_guard
            .evaluate_step(&prev, &good_act, &bad_rt);
        assert!(v.block_execution, "non-finite telemetry must fail closed");
        let json_str = serde_json::to_string(&v).expect("serialize verdict");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed["surprise_score"].is_f64());
        assert!(parsed["threshold"].is_f64());

        // Non-finite action vector
        let bad_act = Array1::from_vec(vec![bad_val, 0.0, 0.0]);
        let v_act = shield.runtime_guard.evaluate_step(&prev, &bad_act, &prev);
        assert!(v_act.block_execution, "non-finite action must fail closed");

        // Non-finite threshold
        let bad_thresh_guard =
            AgentRuntimeGuard::new(shield.runtime_guard.model().clone(), bad_val);
        let v_th = bad_thresh_guard.evaluate_step(&prev, &good_act, &prev);
        assert!(
            v_th.block_execution,
            "non-finite threshold must fail closed"
        );
    }

    // Negative threshold must fail closed
    let neg_sbom_guard = SbomSupplyChainGuard::new(shield.sbom_guard.model().clone(), -0.01);
    let v_neg = neg_sbom_guard.evaluate_sbom_diff(
        &baseline_sbom(),
        &SbomIntent::Patch.to_action_array(),
        &clean_patch_sbom(),
    );
    assert!(v_neg.block_execution);

    // 2. Dimension mismatches must fail closed with zero panics
    let wrong_act = Array1::from_vec(vec![1.0, 0.0]);
    let v_dim = shield.runtime_guard.evaluate_step(&prev, &wrong_act, &prev);
    assert!(v_dim.block_execution);

    let wrong_sbom_act = Array1::from_vec(vec![1.0, 0.0, 0.0, 0.0]);
    let v_sbom_dim = shield.sbom_guard.evaluate_sbom_diff(
        &baseline_sbom(),
        &wrong_sbom_act,
        &clean_patch_sbom(),
    );
    assert!(v_sbom_dim.block_execution);

    // 3. Mismatched / zero-dim / NaN deserialized model weights must fail validation and fail closed
    let bad_model = LatentWorldModel::new(SBOM_OBS_DIM, SBOM_ACTION_DIM, 0, 1);
    assert!(bad_model.validate_integrity().is_err());

    let wrong_obs_model = LatentWorldModel::new(4, RUNTIME_ACTION_DIM, 4, 1);
    let wrong_obs_guard = AgentRuntimeGuard::new(wrong_obs_model, 0.5);
    assert!(wrong_obs_guard.validate_integrity().is_err());
    assert!(
        wrong_obs_guard
            .evaluate_step(&prev, &good_act, &prev)
            .block_execution
    );

    // Tampered weights JSON with NaN / mismatched shape
    let mut tampered_json: serde_json::Value =
        serde_json::from_str(DEFAULT_EMBEDDED_WEIGHTS_JSON).unwrap();
    tampered_json["runtime_guard"]["model"]["enc_ln"]["eps"] = serde_json::json!(-1.0);
    let tampered_str = serde_json::to_string(&tampered_json).unwrap();
    assert!(UnifiedSecurityShield::parse_weights_json_bounded(&tampered_str).is_err());

    let mut wrong_shape_json: serde_json::Value =
        serde_json::from_str(DEFAULT_EMBEDDED_WEIGHTS_JSON).unwrap();
    wrong_shape_json["sbom_guard"]["model"]["latent_dim"] = serde_json::json!(99);
    let wrong_shape_str = serde_json::to_string(&wrong_shape_json).unwrap();
    assert!(UnifiedSecurityShield::parse_weights_json_bounded(&wrong_shape_str).is_err());

    let _ = (RUNTIME_OBS_DIM, MAX_SBOM_LICENSES_PER_COMPONENT);
}

#[test]
fn test_r8_fail_closed_malformed_and_bounded_sboms() {
    // Empty object {} must NOT silently decode into an empty valid SBOM
    assert!(parse_cyclonedx_sbom_bounded("{}").is_err());
    assert!(parse_cyclonedx_sbom_bounded("[]").is_err());
    assert!(parse_cyclonedx_sbom_bounded("{\"foo\":123}").is_err());
    assert!(parse_cyclonedx_sbom_bounded("{\"components\":{}}").is_err());
    assert!(parse_cyclonedx_sbom_bounded("{\"components\":[]}\0").is_err());

    // Empty component name must fail closed
    assert!(
        parse_cyclonedx_sbom_bounded(r#"{"components":[{"name":"   ","version":"1.0"}]}"#).is_err()
    );

    // Oversized JSON > MAX_SBOM_JSON_BYTES must fail closed
    let oversized = " ".repeat(MAX_SBOM_JSON_BYTES + 1);
    assert!(parse_cyclonedx_sbom_bounded(&oversized).is_err());

    // Exceeding MAX_SBOM_COMPONENTS must fail closed
    let mut comps = Vec::with_capacity(MAX_SBOM_COMPONENTS + 1);
    for idx in 0..=MAX_SBOM_COMPONENTS {
        comps.push(format!(r#"{{"name":"pkg{}","version":"1.0"}}"#, idx));
    }
    let too_many_comps = format!(r#"{{"components":[{}]}}"#, comps.join(","));
    assert!(parse_cyclonedx_sbom_bounded(&too_many_comps).is_err());

    // Exceeding MAX_SBOM_DEPENDENCIES must fail closed
    let mut deps = Vec::with_capacity(MAX_SBOM_DEPENDENCIES + 1);
    for idx in 0..=MAX_SBOM_DEPENDENCIES {
        deps.push(format!(r#"{{"ref":"r{}","dependsOn":[]}}"#, idx));
    }
    let too_many_deps = format!(r#"{{"components":[],"dependencies":[{}]}}"#, deps.join(","));
    assert!(parse_cyclonedx_sbom_bounded(&too_many_deps).is_err());

    // Exceeding MAX_SBOM_EDGES must fail closed
    let edges: Vec<String> = (0..=MAX_SBOM_EDGES)
        .map(|i| format!(r#""e{}""#, i))
        .collect();
    let too_many_edges = format!(
        r#"{{"components":[],"dependencies":[{{"ref":"root","dependsOn":[{}]}}]}}"#,
        edges.join(",")
    );
    assert!(parse_cyclonedx_sbom_bounded(&too_many_edges).is_err());

    // Exceeding MAX_SBOM_PROPERTIES_PER_COMPONENT must fail closed
    let props: Vec<String> = (0..=MAX_SBOM_PROPERTIES_PER_COMPONENT)
        .map(|i| format!(r#"{{"name":"k{}","value":"v"}}"#, i))
        .collect();
    let too_many_props = format!(
        r#"{{"components":[{{"name":"c","version":"1.0","properties":[{}]}}]}}"#,
        props.join(",")
    );
    assert!(parse_cyclonedx_sbom_bounded(&too_many_props).is_err());

    // Exceeding MAX_SBOM_STRING_LEN must fail closed
    let long_name = "a".repeat(MAX_SBOM_STRING_LEN + 1);
    let too_long_str = format!(
        r#"{{"components":[{{"name":"{}","version":"1.0"}}]}}"#,
        long_name
    );
    assert!(parse_cyclonedx_sbom_bounded(&too_long_str).is_err());
}

#[test]
fn test_r8_microsecond_inference_latency_sla() {
    let shield = UnifiedSecurityShield::cached_default().expect("cached default");
    let base_f = extract_sbom_features(&baseline_sbom());
    let cand_f = extract_sbom_features(&clean_patch_sbom());
    let sbom_act = SbomIntent::Patch.to_action_array();

    let prev = RuntimeTelemetry::baseline_rag();
    let rt_act = Array1::from_vec(vec![1.0, 0.0, 0.0]);
    let next = RuntimeTelemetry {
        file_reads_norm: 0.12,
        ..prev.clone()
    };

    // Warmup
    for _ in 0..20 {
        let _ = shield
            .sbom_guard
            .model()
            .try_compute_surprise(&base_f, &sbom_act, &cand_f)
            .unwrap();
        let _ = shield.runtime_guard.evaluate_step(&prev, &rt_act, &next);
    }

    let iters = 1000;
    let t0 = Instant::now();
    for _ in 0..iters {
        let verdict = shield.runtime_guard.evaluate_step(&prev, &rt_act, &next);
        assert!(!verdict.block_execution);
    }
    let elapsed_us = t0.elapsed().as_micros() as f64;
    let mean_us = elapsed_us / iters as f64;
    assert!(
        mean_us < 500.0,
        "Gate 2 per-step inference took {:.2} us (expected sub-500us microsecond range)",
        mean_us
    );
}

#[test]
fn test_r8_tighten_only_monotonicity_and_d3qn_independence() {
    // 1. D3QN remains disabled by default and untouched by UnifiedSecurityShield
    let rl = AdaptiveRlDefenseEngine::default();
    assert!(!rl.is_enabled(), "D3QN must remain disabled by default");

    // 2. Clean SBOM + clean runtime verdict can NEVER override a deterministic Cedar forbid
    let cedar_src = r#"
forbid (
    principal,
    action == Octopus::Action::"exec",
    resource is Octopus::Command
) when {
    context has stem && context.stem == "rm"
};
"#;
    let cedar = CedarPolicyEngine::from_custom_policy_set(cedar_src).expect("cedar parse");
    let cedar_verdict = cedar
        .evaluate(
            "cli_runner",
            "exec",
            "rm",
            "Command",
            serde_json::json!({
                "executable": "rm",
                "stem": "rm",
                "args_joined": "rm -rf /",
                "cwd": "/tmp",
                "sandbox_mode": "standard",
                "is_wasm": false,
                "is_packed": false,
                "has_wx_violation": false,
                "direct_syscall_count": 0i64,
                "obfuscation_entropy_x100": 0i64,
                "high_obfuscation_entropy": false,
                "is_authenticode_signed": true,
                "binary_format": "elf"
            }),
        )
        .expect("cedar eval");
    assert!(!cedar_verdict.is_allowed);

    let shield = UnifiedSecurityShield::cached_default().expect("cached default");
    let shield_res = shield.authorize_and_step(
        &baseline_sbom(),
        &SbomIntent::Patch.to_action_array(),
        &clean_patch_sbom(),
        &RuntimeTelemetry::baseline_rag(),
        &Array1::from_vec(vec![1.0, 0.0, 0.0]),
        &RuntimeTelemetry::baseline_rag(),
    );
    assert!(shield_res.is_ok());

    // Monotonic conjunction: DeterministicPillars && UnifiedSecurityShield
    let final_allowed = cedar_verdict.is_allowed && shield_res.is_ok();
    assert!(
        !final_allowed,
        "Clean UnifiedSecurityShield must never override Cedar deny"
    );
}

#[test]
fn test_r8_live_wasmtime_gate2_allows_benign_and_traps_breakout_spike() {
    let executor = WasmTier1Executor::try_new().expect("wasm executor");

    // 1. Benign built-in modules pass Gate 2 with zero false positives
    let doc_receipt = executor
        .execute_doc_extractor(b"hello clean wasm document\n", WasmSandboxLimits::default())
        .expect("benign doc extractor passes Gate 2");
    assert_eq!(doc_receipt.exit_code, 26);
    assert!(doc_receipt
        .runtime_guard_verdict
        .as_ref()
        .is_some_and(|v| !v.block_execution));

    let ledger_receipt = executor
        .execute_ledger_validator(b"{\"tx\":\"ok\"}", WasmSandboxLimits::default())
        .expect("benign ledger validator passes Gate 2");
    assert!(ledger_receipt
        .runtime_guard_verdict
        .as_ref()
        .is_some_and(|v| !v.block_execution));

    // 2. Breakout WAT module attempting 16 MiB linear memory spike (256 pages) inside 64 MiB limit:
    // Deterministic ResourceLimiter allows up to 64 MiB, so Gate 2 AgentRuntimeGuard traps it!
    let mem_spike_wat = r#"
    (module
        (memory (export "memory") 1)
        (func (export "octopus_run") (result i32)
            (drop (memory.grow (i32.const 256)))
            (i32.const 0)
        )
    )
    "#;
    let err = executor
        .execute_wat(
            "breakout_mem_spike",
            mem_spike_wat.as_bytes(),
            b"",
            WasmSandboxLimits::default(),
        )
        .expect_err("Gate 2 must block Wasm memory spike mid-execution");
    match err {
        OctopusSecurityError::BreakoutDetected(msg)
        | OctopusSecurityError::ResourceQuotaExceeded(msg)
        | OctopusSecurityError::IsolationViolation(msg) => {
            assert!(
                msg.contains("GATE2")
                    || msg.contains("MEMORY")
                    || msg.contains("memory")
                    || msg.contains("Breakout"),
                "unexpected error message: {}",
                msg
            );
        }
        other => panic!("unexpected error variant: {:?}", other),
    }
}

#[test]
fn test_r8_cli_sbom_guard_subcommand_and_octopus_run_gate1_e2e() {
    let ws = TempTestDir::new("cli_e2e");
    let base_path = ws.path().join("baseline.bom.json");
    let clean_path = ws.path().join("clean_v2.bom.json");
    let poisoned_path = ws.path().join("poisoned_v2.bom.json");
    let malformed_path = ws.path().join("malformed.bom.json");
    let weights_path = ws.path().join("custom_weights.json");
    let bad_weights_path = ws.path().join("bad_weights.json");
    let normal_tele_path = ws.path().join("normal_step.json");
    let spike_tele_path = ws.path().join("spike_step.json");

    std::fs::write(&base_path, sbom_to_cyclonedx_json(&baseline_sbom())).unwrap();
    std::fs::write(&clean_path, sbom_to_cyclonedx_json(&clean_patch_sbom())).unwrap();
    std::fs::write(&poisoned_path, sbom_to_cyclonedx_json(&poisoned_sbom())).unwrap();
    std::fs::write(&malformed_path, "{}").unwrap();
    std::fs::write(&weights_path, DEFAULT_EMBEDDED_WEIGHTS_JSON).unwrap();
    std::fs::write(&bad_weights_path, "{\"broken\":true}").unwrap();

    std::fs::write(
        &normal_tele_path,
        serde_json::json!({
            "prev_state": RuntimeTelemetry::baseline_rag(),
            "action": [1.0, 0.0, 0.0],
            "observed_state": RuntimeTelemetry {
                file_reads_norm: 0.10,
                file_writes_norm: 0.02,
                child_procs_norm: 0.0,
                net_sockets_norm: 0.05,
                mem_delta_norm: 0.04,
                prompt_entropy_norm: 0.24,
            }
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        &spike_tele_path,
        serde_json::json!({
            "prev_state": RuntimeTelemetry::baseline_rag(),
            "action": [0.0, 0.0, 1.0],
            "observed_state": RuntimeTelemetry {
                file_reads_norm: 0.10,
                file_writes_norm: 0.05,
                child_procs_norm: 1.0,
                net_sockets_norm: 1.3,
                mem_delta_norm: 0.9,
                prompt_entropy_norm: 0.85,
            }
        })
        .to_string(),
    )
    .unwrap();

    // 1. Help flags
    let help_out = run_octopus_cli(&["sbom-guard", "--help"], ws.path());
    assert_eq!(help_out.status.code(), Some(0));
    let alias_help = run_octopus_cli(&["latent-shield", "--help"], ws.path());
    assert_eq!(alias_help.status.code(), Some(0));

    // 2. Subcommand Mode 1: Clean SBOM -> exit 0
    let clean_out = run_octopus_cli(
        &[
            "sbom-guard",
            "--baseline-sbom",
            base_path.to_str().unwrap(),
            "--sbom",
            clean_path.to_str().unwrap(),
            "--sbom-intent",
            "patch",
            "--latent-weights",
            weights_path.to_str().unwrap(),
            "--json",
        ],
        ws.path(),
    );
    assert_eq!(
        clean_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&clean_out.stderr)
    );
    let clean_json: serde_json::Value =
        serde_json::from_slice(&clean_out.stdout).expect("valid clean json");
    assert_eq!(clean_json["block_execution"], false);
    assert_eq!(clean_json["domain"], "SBOM_SUPPLY_CHAIN");
    assert_eq!(clean_json["audit_merkle_root"].as_str().unwrap().len(), 64);

    // 3. Subcommand Mode 1: Poisoned SBOM -> exit 2
    let pois_out = run_octopus_cli(
        &[
            "latent-shield",
            "--baseline-sbom",
            base_path.to_str().unwrap(),
            "--sbom",
            poisoned_path.to_str().unwrap(),
            "--intent",
            "patch",
            "--json",
        ],
        ws.path(),
    );
    assert_eq!(pois_out.status.code(), Some(2));
    let pois_json: serde_json::Value =
        serde_json::from_slice(&pois_out.stdout).expect("valid poisoned json");
    assert_eq!(pois_json["block_execution"], true);
    assert_eq!(pois_json["domain"], "SBOM_SUPPLY_CHAIN");

    // 4. Subcommand Mode 2: Normal step -> exit 0; Spike step -> exit 2
    let rt_ok = run_octopus_cli(
        &[
            "sbom-guard",
            "--check-step",
            "--telemetry",
            normal_tele_path.to_str().unwrap(),
            "--json",
        ],
        ws.path(),
    );
    assert_eq!(rt_ok.status.code(), Some(0));
    let rt_ok_json: serde_json::Value = serde_json::from_slice(&rt_ok.stdout).unwrap();
    assert_eq!(rt_ok_json["block_execution"], false);

    let rt_spike = run_octopus_cli(
        &[
            "sbom-guard",
            "--check-step",
            "--telemetry",
            spike_tele_path.to_str().unwrap(),
            "--json",
        ],
        ws.path(),
    );
    assert_eq!(rt_spike.status.code(), Some(2));
    let rt_spike_json: serde_json::Value = serde_json::from_slice(&rt_spike.stdout).unwrap();
    assert_eq!(rt_spike_json["block_execution"], true);
    assert_eq!(rt_spike_json["domain"], "AGENT_OCTOPUS_RUNTIME");

    // 5. Malformed SBOM & corrupt weights -> exit 2
    let bad_sbom_out = run_octopus_cli(
        &[
            "sbom-guard",
            "--baseline-sbom",
            base_path.to_str().unwrap(),
            "--sbom",
            malformed_path.to_str().unwrap(),
            "--json",
        ],
        ws.path(),
    );
    assert_eq!(bad_sbom_out.status.code(), Some(2));

    let bad_w_out = run_octopus_cli(
        &[
            "sbom-guard",
            "--baseline-sbom",
            base_path.to_str().unwrap(),
            "--sbom",
            clean_path.to_str().unwrap(),
            "--latent-weights",
            bad_weights_path.to_str().unwrap(),
            "--json",
        ],
        ws.path(),
    );
    assert_eq!(bad_w_out.status.code(), Some(2));

    // 6. `octopus run` pre-Wasmtime Gate 1 allow + poisoned block
    let policy_path = ws.path().join("policy.json");
    std::fs::write(
        &policy_path,
        r#"{"allowed_domains":[],"commands":{"allow":["echo","cmd","sh","python","python3"]},"filesystem":{"allow_read":["."],"allow_write":["."],"deny":[]}}"#,
    )
    .unwrap();

    let wat_path = ws.path().join("benign_doc.wat");
    std::fs::write(&wat_path, WASM_DOC_EXTRACTOR_WAT).unwrap();

    // Clean SBOM + Wasm guest -> exit 5 (WASM_DOC_EXTRACTOR_WAT returns emitted byte count)
    let run_clean = run_octopus_cli(
        &[
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--baseline-sbom",
            base_path.to_str().unwrap(),
            "--sbom",
            clean_path.to_str().unwrap(),
            "--sbom-intent",
            "patch",
            "--json",
            "--",
            wat_path.to_str().unwrap(),
            "hello",
        ],
        ws.path(),
    );
    assert_eq!(
        run_clean.status.code(),
        Some(5),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&run_clean.stdout),
        String::from_utf8_lossy(&run_clean.stderr)
    );
    let run_clean_json: serde_json::Value = serde_json::from_slice(&run_clean.stdout).unwrap();
    assert_eq!(run_clean_json["exit_code"], 5);
    assert_eq!(run_clean_json["stdout"], "hello");
    assert_eq!(run_clean_json["sbom_guard"]["block_execution"], false);
    assert_eq!(run_clean_json["runtime_guard"]["block_execution"], false);
    assert!(
        run_clean_json["runtime_guard"]["surprise_score"]
            .as_f64()
            .unwrap()
            < run_clean_json["runtime_guard"]["threshold"]
                .as_f64()
                .unwrap(),
        "expected benign Wasm doc extractor below threshold, got {:?}",
        run_clean_json["runtime_guard"]
    );

    // Poisoned SBOM + Wasm guest -> exit 2 BEFORE Wasmtime starts
    let run_poisoned = run_octopus_cli(
        &[
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--baseline-sbom",
            base_path.to_str().unwrap(),
            "--sbom",
            poisoned_path.to_str().unwrap(),
            "--sbom-intent",
            "patch",
            "--json",
            "--",
            wat_path.to_str().unwrap(),
            "hello",
        ],
        ws.path(),
    );
    assert_eq!(run_poisoned.status.code(), Some(2));
    let run_pois_json: serde_json::Value = serde_json::from_slice(&run_poisoned.stdout).unwrap();
    assert_eq!(run_pois_json["status"], "denied_preflight");
    assert_eq!(run_pois_json["backend"], "preflight");
    assert_eq!(run_pois_json["sbom_guard"]["block_execution"], true);
    assert_eq!(run_pois_json["stdout"], "");

    // Missing paired --baseline-sbom -> exit 2
    let unpaired_out = run_octopus_cli(
        &[
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--sbom",
            clean_path.to_str().unwrap(),
            "--json",
            "--",
            wat_path.to_str().unwrap(),
        ],
        ws.path(),
    );
    assert_eq!(unpaired_out.status.code(), Some(2));

    // Poisoned SBOM + native child command -> exit 2 BEFORE child spawns (marker never created!)
    let marker_path = ws.path().join("child_spawned_marker.txt");
    let script_path = ws.path().join("write_marker.py");
    std::fs::write(
        &script_path,
        format!(
            "import pathlib; pathlib.Path(r'{}').write_text('ran')\n",
            marker_path.display()
        ),
    )
    .unwrap();
    let native_pois = run_octopus_cli(
        &[
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--baseline-sbom",
            base_path.to_str().unwrap(),
            "--sbom",
            poisoned_path.to_str().unwrap(),
            "--sbom-intent",
            "patch",
            "--json",
            "--",
            "python",
            script_path.to_str().unwrap(),
        ],
        ws.path(),
    );
    assert_eq!(native_pois.status.code(), Some(2));
    assert!(
        !marker_path.exists(),
        "poisoned SBOM must block BEFORE spawning native child process"
    );

    // 7. Tighten-only Cedar deny + clean SBOM -> still exit 2 (Cedar wins)
    let cedar_deny_path = ws.path().join("deny.cedar");
    std::fs::write(
        &cedar_deny_path,
        r#"
forbid (
    principal,
    action == Octopus::Action::"exec",
    resource is Octopus::Command
) when {
    context has stem && context.stem == "cmd"
};
"#,
    )
    .unwrap();
    let cedar_deny_out = run_octopus_cli(
        &[
            "run",
            "--policy",
            cedar_deny_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--baseline-sbom",
            base_path.to_str().unwrap(),
            "--sbom",
            clean_path.to_str().unwrap(),
            "--json",
            "--",
            "cmd",
            "/c",
            "echo",
            "should_not_run",
        ],
        ws.path(),
    );
    assert_eq!(cedar_deny_out.status.code(), Some(2));
    let cedar_deny_json: serde_json::Value =
        serde_json::from_slice(&cedar_deny_out.stdout).unwrap();
    assert_eq!(cedar_deny_json["status"], "denied_preflight");
    assert!(cedar_deny_json["sbom_guard"].is_null());

    // 8. Ensure NO implicit logs/ or config/rl_defense_policy.json was created in ws
    assert!(!ws.path().join("logs").exists());
    assert!(!ws.path().join("config").exists());
}

fn flat_clean_sbom(n: usize, version_bump: &str, shared_prefix: Option<&str>) -> CycloneDxSbom {
    let components = (0..n)
        .map(|idx| {
            let name = match shared_prefix {
                Some(prefix) => format!("{}-mod{}", prefix, idx),
                None => format!("pkg{}-crate", idx),
            };
            let ver = if idx == 0 {
                version_bump.to_string()
            } else {
                "1.0.0".to_string()
            };
            clean_comp(&name, &ver, "pkg:cargo/", "MIT")
        })
        .collect();
    CycloneDxSbom {
        components,
        dependencies: Vec::new(),
    }
}

#[test]
fn test_r8_it2_flat_and_identical_small_sboms_allowed_and_poisoned_blocked() {
    let shield = UnifiedSecurityShield::cached_default().expect("cached default");

    // 1. Identical & flat SBOMs (N = 1..100, dependencies: []) across Patch, Minor, Refactor
    for n in [1_usize, 2, 3, 4, 10, 50, 100] {
        let base = flat_clean_sbom(n, "1.0.0", None);
        let bumped = flat_clean_sbom(n, "1.0.1", None);
        for intent in [SbomIntent::Patch, SbomIntent::Minor, SbomIntent::Refactor] {
            let v_ident =
                shield
                    .sbom_guard
                    .evaluate_sbom_diff(&base, &intent.to_action_array(), &base);
            assert!(
                !v_ident.block_execution,
                "clean identical flat SBOM N={} intent={:?} blocked: {:?}",
                n, intent, v_ident
            );
            let v_bump =
                shield
                    .sbom_guard
                    .evaluate_sbom_diff(&base, &intent.to_action_array(), &bumped);
            assert!(
                !v_bump.block_execution,
                "clean bumped flat SBOM N={} intent={:?} blocked: {:?}",
                n, intent, v_bump
            );
        }
    }

    // 2. Shared namespace N=3 flat identical + N=1->2 clean patch + N=1->4 clean minor
    let shared_3 = flat_clean_sbom(3, "1.0.0", Some("acme"));
    for intent in [SbomIntent::Patch, SbomIntent::Minor, SbomIntent::Refactor] {
        let v =
            shield
                .sbom_guard
                .evaluate_sbom_diff(&shared_3, &intent.to_action_array(), &shared_3);
        assert!(
            !v.block_execution,
            "shared namespace N=3 blocked for {:?}: {:?}",
            intent, v
        );
    }

    let n1 = flat_clean_sbom(1, "1.0.0", None);
    let n2 = flat_clean_sbom(2, "1.0.0", None);
    let n4 = flat_clean_sbom(4, "1.0.0", None);
    assert!(
        !shield
            .sbom_guard
            .evaluate_sbom_diff(&n1, &SbomIntent::Patch.to_action_array(), &n2)
            .block_execution
    );
    assert!(
        !shield
            .sbom_guard
            .evaluate_sbom_diff(&n1, &SbomIntent::Minor.to_action_array(), &n4)
            .block_execution
    );

    // 3. Poisoned variants at N=1 and N=4: sneaky-crate (elevated capability), unknown-src (pkg:raw),
    //    edge injection, and empty components: [] must ALL block
    for n in [1_usize, 4] {
        let base = flat_clean_sbom(n, "1.0.0", None);

        let mut sneaky = base.clone();
        sneaky.components.push(SbomComponent {
            name: "sneaky-crate".to_string(),
            version: "0.1.0".to_string(),
            purl: Some("pkg:cargo/sneaky-crate@0.1.0".to_string()),
            licenses: vec![LicenseChoice {
                license: Some(LicenseDetail {
                    id: Some("MIT".to_string()),
                }),
            }],
            properties: vec![ComponentProperty {
                name: "capability".to_string(),
                value: "network,process,ffi".to_string(),
            }],
        });
        let v_sneaky = shield.sbom_guard.evaluate_sbom_diff(
            &base,
            &SbomIntent::Patch.to_action_array(),
            &sneaky,
        );
        assert!(
            v_sneaky.block_execution,
            "N={} sneaky-crate must block: {:?}",
            n, v_sneaky
        );

        let mut unknown = base.clone();
        unknown.components.push(SbomComponent {
            name: "unknown-src".to_string(),
            version: "0.0.1".to_string(),
            purl: Some("pkg:raw/unknown-src@0.0.1".to_string()),
            licenses: Vec::new(),
            properties: Vec::new(),
        });
        let v_unknown = shield.sbom_guard.evaluate_sbom_diff(
            &base,
            &SbomIntent::Patch.to_action_array(),
            &unknown,
        );
        assert!(
            v_unknown.block_execution,
            "N={} unknown-src must block: {:?}",
            n, v_unknown
        );

        let mut edge_inj = base.clone();
        edge_inj.dependencies.push(SbomDependency {
            component_ref: "app".to_string(),
            depends_on: (0..(n * 3).max(3)).map(|i| format!("dep-{}", i)).collect(),
        });
        let v_edge = shield.sbom_guard.evaluate_sbom_diff(
            &base,
            &SbomIntent::Patch.to_action_array(),
            &edge_inj,
        );
        assert!(
            v_edge.block_execution,
            "N={} edge injection must block: {:?}",
            n, v_edge
        );

        let empty_sbom = CycloneDxSbom {
            components: Vec::new(),
            dependencies: Vec::new(),
        };
        let v_empty = shield.sbom_guard.evaluate_sbom_diff(
            &base,
            &SbomIntent::Patch.to_action_array(),
            &empty_sbom,
        );
        assert!(
            v_empty.block_execution,
            "N={} empty components must block: {:?}",
            n, v_empty
        );
    }

    // 4. CLI parity with N=1 identical flat SBOM -> exit 0
    let ws = TempTestDir::new("flat_sbom_cli");
    let s1_path = ws.path().join("s1.bom.json");
    let policy_path = ws.path().join("policy.json");
    std::fs::write(&s1_path, sbom_to_cyclonedx_json(&n1)).unwrap();
    std::fs::write(
        &policy_path,
        r#"{"allowed_domains":[],"commands":{"allow":["cmd","sh","echo"]},"filesystem":{"allow_read":["."],"allow_write":["."],"deny":[]}}"#,
    )
    .unwrap();
    let guard_out = run_octopus_cli(
        &[
            "sbom-guard",
            "--baseline-sbom",
            s1_path.to_str().unwrap(),
            "--sbom",
            s1_path.to_str().unwrap(),
            "--sbom-intent",
            "patch",
            "--json",
        ],
        ws.path(),
    );
    assert_eq!(
        guard_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&guard_out.stdout),
        String::from_utf8_lossy(&guard_out.stderr)
    );
    let run_out = run_octopus_cli(
        &[
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--baseline-sbom",
            s1_path.to_str().unwrap(),
            "--sbom",
            s1_path.to_str().unwrap(),
            "--sbom-intent",
            "patch",
            "--json",
            "--",
            "cmd",
            "/c",
            "echo",
            "flat_ok",
        ],
        ws.path(),
    );
    assert_eq!(run_out.status.code(), Some(0));
}

#[test]
fn test_r8_it2_action_dim_mismatch_and_oversized_weights_rejected() {
    // 1. Direct API validation rejects action_dim != 3
    let bad_sbom_guard = SbomSupplyChainGuard::new(
        LatentWorldModel::new(SBOM_OBS_DIM, 4, DEFAULT_LATENT_DIM, 7),
        0.035,
    );
    assert!(matches!(
        bad_sbom_guard.validate_integrity(),
        Err(LatentShieldError::DimensionMismatch {
            expected: 3,
            actual: 4,
            context: "SbomSupplyChainGuard.action_dim",
        })
    ));

    let bad_rt_guard = AgentRuntimeGuard::new(
        LatentWorldModel::new(RUNTIME_OBS_DIM, 4, DEFAULT_LATENT_DIM, 7),
        0.085,
    );
    assert!(matches!(
        bad_rt_guard.validate_integrity(),
        Err(LatentShieldError::DimensionMismatch {
            expected: 3,
            actual: 4,
            context: "AgentRuntimeGuard.action_dim",
        })
    ));

    // 2. JSON weights with action_dim == 4 on either guard rejected by parse_weights_json_bounded
    let bad_dim4_model = LatentWorldModel::new(SBOM_OBS_DIM, 4, DEFAULT_LATENT_DIM, 11);
    let mut bad_sbom_json: serde_json::Value =
        serde_json::from_str(DEFAULT_EMBEDDED_WEIGHTS_JSON).unwrap();
    bad_sbom_json["sbom_guard"]["model"] = serde_json::to_value(&bad_dim4_model).unwrap();
    let bad_sbom_str = serde_json::to_string(&bad_sbom_json).unwrap();
    assert!(matches!(
        UnifiedSecurityShield::parse_weights_json_bounded(&bad_sbom_str),
        Err(LatentShieldError::DimensionMismatch {
            expected: 3,
            actual: 4,
            ..
        })
    ));

    let mut bad_rt_json: serde_json::Value =
        serde_json::from_str(DEFAULT_EMBEDDED_WEIGHTS_JSON).unwrap();
    bad_rt_json["runtime_guard"]["model"] = serde_json::to_value(&bad_dim4_model).unwrap();
    let bad_rt_str = serde_json::to_string(&bad_rt_json).unwrap();
    assert!(matches!(
        UnifiedSecurityShield::parse_weights_json_bounded(&bad_rt_str),
        Err(LatentShieldError::DimensionMismatch {
            expected: 3,
            actual: 4,
            ..
        })
    ));

    // 3. CLI rejection (exit 2) for action_dim != 3 weights file
    let ws = TempTestDir::new("bad_action_dim_and_oversized");
    let bad_w_path = ws.path().join("bad_action_dim4.json");
    let base_path = ws.path().join("base.bom.json");
    let policy_path = ws.path().join("policy.json");
    std::fs::write(&bad_w_path, &bad_rt_str).unwrap();
    std::fs::write(&base_path, sbom_to_cyclonedx_json(&baseline_sbom())).unwrap();
    std::fs::write(
        &policy_path,
        r#"{"allowed_domains":[],"commands":{"allow":["cmd","sh","echo"]},"filesystem":{"allow_read":["."],"allow_write":["."],"deny":[]}}"#,
    )
    .unwrap();

    assert!(matches!(
        UnifiedSecurityShield::from_weights_file(&bad_w_path),
        Err(LatentShieldError::DimensionMismatch {
            expected: 3,
            actual: 4,
            ..
        })
    ));

    let cli_guard = run_octopus_cli(
        &[
            "sbom-guard",
            "--baseline-sbom",
            base_path.to_str().unwrap(),
            "--sbom",
            base_path.to_str().unwrap(),
            "--latent-weights",
            bad_w_path.to_str().unwrap(),
            "--json",
        ],
        ws.path(),
    );
    assert_eq!(cli_guard.status.code(), Some(2));

    let cli_run = run_octopus_cli(
        &[
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--latent-weights",
            bad_w_path.to_str().unwrap(),
            "--json",
            "--",
            "cmd",
            "/c",
            "echo",
            "nope",
        ],
        ws.path(),
    );
    assert_eq!(cli_run.status.code(), Some(2));

    // 4. Oversized weights file returns LatentShieldError::WeightsParseError
    let oversized_path = ws.path().join("oversized_weights.json");
    std::fs::write(&oversized_path, vec![b' '; MAX_WEIGHTS_JSON_BYTES + 1]).unwrap();
    let oversized_err = UnifiedSecurityShield::from_weights_file(&oversized_path)
        .expect_err("oversized weights file must fail");
    assert!(
        matches!(oversized_err, LatentShieldError::WeightsParseError(_)),
        "expected WeightsParseError, got {:?}",
        oversized_err
    );
}

#[test]
fn test_r8_it2_single_axis_child_procs_and_incremental_ramp_blocked() {
    let shield = UnifiedSecurityShield::cached_default().expect("cached default");
    let guard = &shield.runtime_guard;
    let actions = [
        Array1::from_vec(vec![1.0, 0.0, 0.0]),
        Array1::from_vec(vec![0.0, 1.0, 0.0]),
        Array1::from_vec(vec![0.0, 0.0, 1.0]),
    ];

    // 1. Single-axis child_procs_norm = 0.8 & 1.0 from both baseline_rag() and idle_initial()
    for (anchor_name, anchor) in [
        ("baseline_rag", RuntimeTelemetry::baseline_rag()),
        ("idle_initial", RuntimeTelemetry::idle_initial()),
    ] {
        for c_val in [0.8_f64, 1.0] {
            let obs = RuntimeTelemetry {
                child_procs_norm: c_val,
                ..anchor.clone()
            };
            for act in &actions {
                let v = guard.evaluate_step(&anchor, act, &obs);
                assert!(
                    v.block_execution,
                    "single-axis child={} from {} action={:?} must block: {:?}",
                    c_val, anchor_name, act, v
                );
            }
        }
    }

    // 2. +0.15 incremental ramp blocks immediately at step 1 and at every ratcheted step
    let mut prev = RuntimeTelemetry::idle_initial();
    for step in 1..=10 {
        let next = RuntimeTelemetry {
            child_procs_norm: (step as f64 * 0.15).min(1.5),
            ..RuntimeTelemetry::idle_initial()
        };
        let v = guard.evaluate_step(&prev, &actions[0], &next);
        assert!(
            v.block_execution,
            "+0.15 ramp step {} ({} -> {}) must block: {:?}",
            step, prev.child_procs_norm, next.child_procs_norm, v
        );
        prev = next;
    }

    // 3. LiveRuntimeMonitor::evaluate_snapshot also blocks 0.15 ramp immediately
    let mon = LiveRuntimeMonitor::new(std::sync::Arc::new(guard.clone()));
    let snap_v = mon.evaluate_snapshot(0.15, 0.0);
    assert!(snap_v.block_execution && mon.is_tripped());
}

#[test]
fn test_r8_it2_wasm_escape_100_traps_while_4_denials_pass() {
    let executor = WasmTier1Executor::try_new().expect("wasm executor");

    // 1. escape_100.wat: 100 blocked scratch_read("../secret.txt") calls -> traps with TIER1_GATE2_RUNTIME_GUARD_BLOCKED
    let escape_100_wat = r#"
    (module
        (import "octopus_wasi" "scratch_read" (func $sread (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1)
        (data (i32.const 0) "../secret.txt")
        (func (export "octopus_run") (result i32)
            (local $i i32)
            (local.set $i (i32.const 0))
            (loop $lp
                (drop (call $sread (i32.const 0) (i32.const 13) (i32.const 256) (i32.const 64)))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br_if $lp (i32.lt_s (local.get $i) (i32.const 100)))
            )
            (i32.const 0)
        )
    )
    "#;
    let err = executor
        .execute_wat(
            "escape_100",
            escape_100_wat.as_bytes(),
            b"",
            WasmSandboxLimits::default(),
        )
        .expect_err("escape_100.wat must trap via Gate 2");
    match err {
        OctopusSecurityError::BreakoutDetected(msg) => {
            assert!(
                msg.contains("TIER1_GATE2_RUNTIME_GUARD_BLOCKED"),
                "expected TIER1_GATE2_RUNTIME_GUARD_BLOCKED, got: {}",
                msg
            );
        }
        other => panic!("expected BreakoutDetected, got {:?}", other),
    }

    // 2. CLI `octopus run` on escape_100.wat -> exits non-zero and reports Gate 2 block
    let ws = TempTestDir::new("escape_100_cli");
    let wat_path = ws.path().join("escape_100.wat");
    let policy_path = ws.path().join("policy.json");
    std::fs::write(&wat_path, escape_100_wat).unwrap();
    std::fs::write(
        &policy_path,
        r#"{"allowed_domains":[],"commands":{"allow":[]},"filesystem":{"allow_read":["."],"allow_write":["."],"deny":[]}}"#,
    )
    .unwrap();
    let cli_out = run_octopus_cli(
        &[
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--json",
            "--",
            wat_path.to_str().unwrap(),
        ],
        ws.path(),
    );
    assert_ne!(cli_out.status.code(), Some(0));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&cli_out.stdout),
        String::from_utf8_lossy(&cli_out.stderr)
    );
    assert!(
        combined.contains("TIER1_GATE2_RUNTIME_GUARD_BLOCKED"),
        "expected TIER1_GATE2_RUNTIME_GUARD_BLOCKED in CLI output: {}",
        combined
    );

    // 3. <= 4 blocked calls + benign emit_output still passes cleanly
    let benign_4_wat = r#"
    (module
        (import "octopus_wasi" "scratch_read" (func $sread (param i32 i32 i32 i32) (result i32)))
        (import "octopus_wasi" "emit_output" (func $emit (param i32 i32) (result i32)))
        (memory (export "memory") 1)
        (data (i32.const 0) "../secret.txt")
        (data (i32.const 64) "ok")
        (func (export "octopus_run") (result i32)
            (local $i i32)
            (local.set $i (i32.const 0))
            (loop $lp
                (drop (call $sread (i32.const 0) (i32.const 13) (i32.const 256) (i32.const 64)))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br_if $lp (i32.lt_s (local.get $i) (i32.const 4)))
            )
            (drop (call $emit (i32.const 64) (i32.const 2)))
            (i32.const 0)
        )
    )
    "#;
    let ok_receipt = executor
        .execute_wat(
            "benign_4_denials",
            benign_4_wat.as_bytes(),
            b"",
            WasmSandboxLimits::default(),
        )
        .expect("<= 4 blocked calls must remain allowed");
    assert_eq!(ok_receipt.blocked_escape_attempts.len(), 4);
    assert_eq!(ok_receipt.raw_output, "ok");
    assert!(ok_receipt
        .runtime_guard_verdict
        .as_ref()
        .is_some_and(|v| !v.block_execution));
}

#[tokio::test]
async fn test_r8_it2_wasm_stream_exfil_and_mesh_call_flood_trapped_while_stream_client_passes() {
    let ks = std::sync::Arc::new(KillSwitch::new());
    let engine = std::sync::Arc::new(
        AgentMeshEngine::new(AgentMeshConfig::default(), std::sync::Arc::clone(&ks))
            .await
            .unwrap(),
    );

    // 1. Clean STREAM_CLIENT_WAT passes Gate 2
    let clean_stream_wat = r#"
    (module
      (import "octopus_wasi" "mesh_stream_open" (func $open (param i32 i32 i32) (result i32)))
      (import "octopus_wasi" "mesh_stream_write" (func $write (param i32 i32 i32) (result i32)))
      (import "octopus_wasi" "mesh_stream_read" (func $read (param i32 i32 i32) (result i32)))
      (import "octopus_wasi" "mesh_stream_close" (func $close (param i32) (result i32)))
      (import "octopus_wasi" "emit_output" (func $emit (param i32 i32) (result i32)))
      (memory (export "memory") 1 2)
      (data (i32.const 64) "mcp://calc")
      (data (i32.const 128) "{\"op\":\"mul\",\"a\":6,\"b\":7}")
      (func (export "octopus_run") (result i32)
        (local $fd i32)
        (local $n i32)
        (local.set $fd (call $open (i32.const 64) (i32.const 10) (i32.const 0)))
        (if (i32.lt_s (local.get $fd) (i32.const 0)) (then (return (local.get $fd))))
        (drop (call $write (local.get $fd) (i32.const 128) (i32.const 24)))
        (local.set $n (call $read (local.get $fd) (i32.const 512) (i32.const 4096)))
        (drop (call $close (local.get $fd)))
        (if (i32.lt_s (local.get $n) (i32.const 0)) (then (return (local.get $n))))
        (drop (call $emit (i32.const 512) (local.get $n)))
        (local.get $n)
      )
    )
    "#;
    let pep1 = std::sync::Arc::clone(engine.pep_bridge());
    let wasm1 = std::sync::Arc::clone(engine.wasm_executor());
    let clean_receipt = tokio::task::spawn_blocking(move || {
        let ctx = WasmMeshBridgeContext::new("arm_calc", 0, ArmRole::NetworkEgress, pep1);
        wasm1.execute_wat_with_context(
            "clean_stream_client",
            clean_stream_wat,
            b"",
            WasmSandboxLimits::default(),
            Some(ctx),
        )
    })
    .await
    .unwrap()
    .expect("clean STREAM_CLIENT_WAT must pass Gate 2");
    assert!(clean_receipt
        .runtime_guard_verdict
        .as_ref()
        .is_some_and(|v| !v.block_execution));

    // 2. 2.5 MiB mesh_stream_write exfiltration spike (40 x 64 KiB) traps with TIER1_GATE2_RUNTIME_GUARD_BLOCKED
    let stream_exfil_wat = r#"
    (module
      (import "octopus_wasi" "mesh_stream_open" (func $open (param i32 i32 i32) (result i32)))
      (import "octopus_wasi" "mesh_stream_write" (func $write (param i32 i32 i32) (result i32)))
      (memory (export "memory") 2 4)
      (data (i32.const 0) "mcp://calc")
      (func (export "octopus_run") (result i32)
        (local $fd i32)
        (local $i i32)
        (local.set $fd (call $open (i32.const 0) (i32.const 10) (i32.const 0)))
        (local.set $i (i32.const 0))
        (loop $lp
          (drop (call $write (local.get $fd) (i32.const 1024) (i32.const 65536)))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br_if $lp (i32.lt_s (local.get $i) (i32.const 40)))
        )
        (i32.const 0)
      )
    )
    "#;
    let pep2 = std::sync::Arc::clone(engine.pep_bridge());
    let wasm2 = std::sync::Arc::clone(engine.wasm_executor());
    let stream_err = tokio::task::spawn_blocking(move || {
        let ctx = WasmMeshBridgeContext::new("arm_calc", 0, ArmRole::NetworkEgress, pep2);
        wasm2.execute_wat_with_context(
            "stream_exfil_spike",
            stream_exfil_wat,
            b"",
            WasmSandboxLimits::default(),
            Some(ctx),
        )
    })
    .await
    .unwrap()
    .expect_err("2+ MiB mesh_stream_write spike must trap via Gate 2");
    match stream_err {
        OctopusSecurityError::BreakoutDetected(msg) => {
            assert!(
                msg.contains("TIER1_GATE2_RUNTIME_GUARD_BLOCKED"),
                "unexpected msg: {}",
                msg
            );
        }
        other => panic!("expected BreakoutDetected, got {:?}", other),
    }

    // 3. 25+ mesh_call flood (30 calls) traps with TIER1_GATE2_RUNTIME_GUARD_BLOCKED
    let mesh_flood_wat = r#"
    (module
      (import "octopus_wasi" "mesh_call" (func $mcall (param i32 i32 i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1 2)
      (data (i32.const 0) "mcp://calc")
      (data (i32.const 64) "{\"op\":\"add\",\"a\":1,\"b\":2}")
      (func (export "octopus_run") (result i32)
        (local $i i32)
        (local.set $i (i32.const 0))
        (loop $lp
          (drop (call $mcall (i32.const 0) (i32.const 10) (i32.const 64) (i32.const 24) (i32.const 512) (i32.const 256)))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br_if $lp (i32.lt_s (local.get $i) (i32.const 30)))
        )
        (i32.const 0)
      )
    )
    "#;
    let pep3 = std::sync::Arc::clone(engine.pep_bridge());
    let wasm3 = std::sync::Arc::clone(engine.wasm_executor());
    let flood_err = tokio::task::spawn_blocking(move || {
        let mut ctx = WasmMeshBridgeContext::new("arm_calc", 0, ArmRole::NetworkEgress, pep3);
        ctx.max_mesh_calls = 100;
        wasm3.execute_wat_with_context(
            "mesh_call_flood",
            mesh_flood_wat,
            b"",
            WasmSandboxLimits::default(),
            Some(ctx),
        )
    })
    .await
    .unwrap()
    .expect_err("25+ mesh_call flood must trap via Gate 2");
    match flood_err {
        OctopusSecurityError::BreakoutDetected(msg) => {
            assert!(
                msg.contains("TIER1_GATE2_RUNTIME_GUARD_BLOCKED"),
                "unexpected msg: {}",
                msg
            );
        }
        other => panic!("expected BreakoutDetected, got {:?}", other),
    }

    engine.stop_serving_node().await.unwrap();
}

#[test]
fn test_r8_it2_live_runtime_monitor_post_trip_latch_preserved() {
    let shield = UnifiedSecurityShield::cached_default().expect("cached default");
    let guard = std::sync::Arc::new(shield.runtime_guard.clone());

    // 1. Trip via evaluate_snapshot -> subsequent benign FileRead remains latched
    let mon_snap = LiveRuntimeMonitor::new(std::sync::Arc::clone(&guard));
    let trip_v = mon_snap.evaluate_snapshot(1.5, 0.10);
    assert!(trip_v.block_execution && mon_snap.is_tripped());
    let benign_after = mon_snap.record_and_evaluate(RuntimeEventKind::FileRead, 0, 0.02, 0.22);
    assert!(benign_after.block_execution);
    assert!(mon_snap
        .last_verdict()
        .is_some_and(|v| v.block_execution && v.surprise_score == trip_v.surprise_score));

    // 2. Trip via 5 ChildProcess spawns -> subsequent benign IPC calls remain latched
    let mon_spawn = LiveRuntimeMonitor::new(guard);
    for _ in 0..5 {
        let _ = mon_spawn.record_and_evaluate(RuntimeEventKind::ChildProcess, 0, 0.02, 0.22);
    }
    assert!(mon_spawn.is_tripped());
    assert!(mon_spawn.trip_reason().is_some());
    for kind in [
        RuntimeEventKind::FileRead,
        RuntimeEventKind::FileWrite,
        RuntimeEventKind::NetworkEgress,
    ] {
        let v = mon_spawn.record_and_evaluate(kind, 64, 0.02, 0.22);
        assert!(v.block_execution);
    }
    assert!(mon_spawn.last_verdict().is_some_and(|v| v.block_execution));
}

#[test]
fn test_r8_it3_disarm_rejects_shield_lock_despite_test_env_vars() {
    use agent_octopus::security::virtual_patch_shield::{
        KernelShieldPosture, VirtualPatchShieldStore,
    };

    let tmp_dir = std::env::temp_dir().join(format!(
        "ao_r8_it3_disarm_guard_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let logs_dir = tmp_dir.join("logs");
    std::fs::create_dir_all(&logs_dir).expect("create temp logs dir");

    let mut locked = KernelShieldPosture::default_fail_closed();
    locked.reboot_pending = true;
    locked.livepatch_active = false;
    locked.shield_locked_until_reboot = true;

    // 1. Explicit AGENT_OCTOPUS_SHIELD_POSTURE_PATH locked -> octopus.exe restore & killswitch disarm
    //    MUST reject even when RUST_TEST_THREADS=1, OCTOPUS_SELF_DIAGNOSTIC=1, CARGO_TARGET_TMPDIR,
    //    and CARGO are all set in the environment.
    let explicit_posture_path = tmp_dir.join("locked_posture.json");
    let store = VirtualPatchShieldStore::new(Some(explicit_posture_path.clone()));
    store
        .apply_posture(locked.clone())
        .expect("persist locked posture");
    assert!(store.current().shield_locked_until_reboot);

    for subcmd in [&["restore"][..], &["killswitch", "disarm"][..]] {
        let out = Command::new(octopus_bin())
            .args(subcmd)
            .current_dir(&tmp_dir)
            .env_remove("ANTHROPIC_BASE_URL")
            .env_remove("OPENAI_BASE_URL")
            .env_remove("OCTOPUS_LIVE_WFP_TEST")
            .env("AGENT_OCTOPUS_SHIELD_POSTURE_PATH", &explicit_posture_path)
            .env("RUST_TEST_THREADS", "1")
            .env("OCTOPUS_SELF_DIAGNOSTIC", "1")
            .env("CARGO_TARGET_TMPDIR", &tmp_dir)
            .env("CARGO", "cargo")
            .output()
            .expect("run octopus binary");
        assert!(
            !out.status.success(),
            "octopus {:?} must reject disarm when shield_locked_until_reboot=true despite test env vars; stdout={} stderr={}",
            subcmd,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("Monotonic violation: cannot disarm host perimeter while shield_locked_until_reboot is active"),
            "Expected monotonic violation error for {:?}, got stderr: {}",
            subcmd,
            stderr
        );
    }

    // 2. AGENT_OCTOPUS_SHIELD_POSTURE_PATH unset -> default logs/kernel_shield_posture.json in cwd
    //    MUST still be resolved and enforce shield_locked_until_reboot in !cfg!(test) binaries
    //    even when RUST_TEST_THREADS=1, OCTOPUS_SELF_DIAGNOSTIC=1, CARGO_TARGET_TMPDIR, CARGO are set.
    let default_cwd_posture = logs_dir.join("kernel_shield_posture.json");
    let default_store = VirtualPatchShieldStore::new(Some(default_cwd_posture));
    default_store
        .apply_posture(locked)
        .expect("persist default cwd locked posture");

    let out_default = Command::new(octopus_bin())
        .arg("restore")
        .current_dir(&tmp_dir)
        .env_remove("ANTHROPIC_BASE_URL")
        .env_remove("OPENAI_BASE_URL")
        .env_remove("OCTOPUS_LIVE_WFP_TEST")
        .env_remove("AGENT_OCTOPUS_SHIELD_POSTURE_PATH")
        .env("RUST_TEST_THREADS", "1")
        .env("OCTOPUS_SELF_DIAGNOSTIC", "1")
        .env("CARGO_TARGET_TMPDIR", &tmp_dir)
        .env("CARGO", "cargo")
        .output()
        .expect("run octopus restore with default posture path");
    assert!(
        !out_default.status.success(),
        "octopus restore must reject disarm using default posture path despite test env vars; stdout={} stderr={}",
        String::from_utf8_lossy(&out_default.stdout),
        String::from_utf8_lossy(&out_default.stderr)
    );
    let stderr_default = String::from_utf8_lossy(&out_default.stderr);
    assert!(
        stderr_default.contains("Monotonic violation: cannot disarm host perimeter while shield_locked_until_reboot is active"),
        "Expected monotonic violation error on default posture path, got stderr: {}",
        stderr_default
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_m7_corrupt_and_tampered_posture_files_lock_disarm_while_missing_does_not() {
    use agent_octopus::security::virtual_patch_shield::KernelShieldPosture;

    let tmp_dir = TempTestDir::new("m7_corrupt_posture_disarm");
    let logs_dir = tmp_dir.path().join("logs");
    std::fs::create_dir_all(&logs_dir).expect("create temp logs dir");

    // 1. Clean missing posture (NotFound on default logs/kernel_shield_posture.json) -> octopus.exe --verify exits 0
    let verify_out = Command::new(octopus_bin())
        .arg("--verify")
        .current_dir(tmp_dir.path())
        .env_remove("ANTHROPIC_BASE_URL")
        .env_remove("OPENAI_BASE_URL")
        .env_remove("AGENT_OCTOPUS_SHIELD_POSTURE_PATH")
        .output()
        .expect("run octopus --verify on clean temp dir");
    assert!(
        verify_out.status.success(),
        "octopus --verify must succeed with clean NotFound posture; stdout={} stderr={}",
        String::from_utf8_lossy(&verify_out.stdout),
        String::from_utf8_lossy(&verify_out.stderr)
    );

    // 2. Corrupt malformed JSON & SHA-256-tampered JSON via AGENT_OCTOPUS_SHIELD_POSTURE_PATH
    let malformed_path = tmp_dir.path().join("malformed_posture.json");
    std::fs::write(&malformed_path, "{corrupt_json").expect("write malformed posture");

    let mut valid_locked = KernelShieldPosture::default_fail_closed();
    valid_locked.shield_locked_until_reboot = true;
    valid_locked.finalize();
    let mut tampered_val = serde_json::to_value(&valid_locked).expect("serialize posture");
    tampered_val["shield_locked_until_reboot"] = serde_json::Value::Bool(false);
    let tampered_sha_path = tmp_dir.path().join("tampered_sha_posture.json");
    std::fs::write(
        &tampered_sha_path,
        serde_json::to_string_pretty(&tampered_val).expect("serialize tampered posture"),
    )
    .expect("write tampered sha posture");

    for bad_path in [&malformed_path, &tampered_sha_path] {
        for subcmd in [&["restore"][..], &["killswitch", "disarm"][..]] {
            let out = Command::new(octopus_bin())
                .args(subcmd)
                .current_dir(tmp_dir.path())
                .env_remove("ANTHROPIC_BASE_URL")
                .env_remove("OPENAI_BASE_URL")
                .env_remove("OCTOPUS_LIVE_WFP_TEST")
                .env("AGENT_OCTOPUS_SHIELD_POSTURE_PATH", bad_path)
                .output()
                .expect("run octopus disarm with tampered posture");
            assert!(
                !out.status.success(),
                "octopus {:?} must reject disarm on {:?}; stdout={} stderr={}",
                subcmd,
                bad_path,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("Monotonic violation: cannot disarm host perimeter while shield_locked_until_reboot is active"),
                "Expected monotonic violation error for {:?} on {:?}, got stderr: {}",
                subcmd,
                bad_path,
                stderr
            );
        }
    }

    // 3. Corrupt default logs/kernel_shield_posture.json with AGENT_OCTOPUS_SHIELD_POSTURE_PATH unset
    let default_corrupt = logs_dir.join("kernel_shield_posture.json");
    std::fs::write(&default_corrupt, "{truncated").expect("write corrupt default posture");
    let out_default = Command::new(octopus_bin())
        .arg("restore")
        .current_dir(tmp_dir.path())
        .env_remove("ANTHROPIC_BASE_URL")
        .env_remove("OPENAI_BASE_URL")
        .env_remove("OCTOPUS_LIVE_WFP_TEST")
        .env_remove("AGENT_OCTOPUS_SHIELD_POSTURE_PATH")
        .output()
        .expect("run octopus restore with corrupt default logs/kernel_shield_posture.json");
    assert!(
        !out_default.status.success(),
        "octopus restore must reject disarm on corrupt default posture; stdout={} stderr={}",
        String::from_utf8_lossy(&out_default.stdout),
        String::from_utf8_lossy(&out_default.stderr)
    );
    let stderr_default = String::from_utf8_lossy(&out_default.stderr);
    assert!(
        stderr_default.contains("Monotonic violation: cannot disarm host perimeter while shield_locked_until_reboot is active"),
        "Expected monotonic violation on corrupt default posture, got stderr: {}",
        stderr_default
    );
}
