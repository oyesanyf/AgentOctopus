//! Comprehensive End-to-End Integration Test Suite (`tests/agentmesh_integration_tests.rs`)
//!
//! Validates the full `google/agentmesh` x `AgentOctopus` (`wasmtime v49.0.4`) architecture:
//! 1. OIDC Discovery, RFC 7515 `ES256` `P-256` JWKS, and key rotation (`current` + `retired`).
//! 2. Outbound `octopus_wasi::mesh_call` (`arm_calc -> mcp://calc` & `mcp://echo_headers`) with
//!    out-of-sandbox RFC 8693 token exchange and zero-secret linear memory verification.
//! 3. Sibling identity isolation (`arm_rogue` denied `mcp://payroll` and `mcp://calc` with `-5`).
//! 4. Virtual WASI stream descriptors (`mesh_stream_open` / `write` / `read` / `close`).
//! 5. Ed25519 monotonic `AttenuatedMandate` delegation hops and mathematical SSRF URI blocking.
//! 6. Inbound published Wasm tools (`mcp://octopus/doc_extractor`, `mcp://octopus/ledger_validator`)
//!    gated by `X-Mesh-Authentication` + single-use CAGE `CageRoutingSeal` (`401` / `200` / `409`).
//! 7. Mid-execution `KillSwitch` + `wasmtime::Engine::increment_epoch()` trapping non-cooperative
//!    infinite-loop Wasm guests and purging host token vaults in `< 1ms`.
//! 8. Linux/Windows Tier 2 confinement posture & BPF syscall simulator + DPAPI/IPC key broker +
//!    Post-Quantum `ML-KEM-768` WAN transport.

use agent_octopus::core::circuit_breaker::KillSwitch;
use agent_octopus::core::types::ArmRole;
use agent_octopus::security::agentmesh::{
    validate_mesh_uri, AgentMeshConfig, AgentMeshEngine, AgentMeshWanTransport, AttenuatedMandate,
    MeshKeyBroker, OsProtectedKeyBroker,
};
use agent_octopus::security::linux_sandbox::{
    build_socket_filter_bpf, describe_tier2_host_confinement_posture, evaluate_bpf_filter,
    AUDIT_ARCH_AARCH64, AUDIT_ARCH_X86_64, LINUX_EACCES, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_PROCESS, X86_64_BLOCKED_SOCKET_SYSCALLS,
};
use agent_octopus::security::wasm_tier1::{
    WasmMeshBridgeContext, WasmSandboxLimits, WASI_ERR_ACCESS_DENIED,
};
use agent_octopus::web::api::{
    handle_agentmesh_inbound_mcp_call, handle_agentmesh_killswitch_reset,
    handle_agentmesh_killswitch_trip, handle_agentmesh_mandate_attenuate,
    handle_agentmesh_mint_inbound_seal, handle_agentmesh_openid_config, handle_agentmesh_status,
    handle_agentmesh_wasm_call, handle_merged_well_known_jwks, WebState,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const STREAM_CLIENT_WAT: &str = r#"
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
    (if (i32.lt_s (local.get $fd) (i32.const 0))
      (then (return (local.get $fd)))
    )
    (drop (call $write (local.get $fd) (i32.const 128) (i32.const 24)))
    (local.set $n (call $read (local.get $fd) (i32.const 512) (i32.const 4096)))
    (drop (call $close (local.get $fd)))
    (if (i32.lt_s (local.get $n) (i32.const 0))
      (then (return (local.get $n)))
    )
    (drop (call $emit (i32.const 512) (local.get $n)))
    (local.get $n)
  )
)
"#;

const INFINITE_SPIN_WAT: &str = r#"
(module
  (memory (export "memory") 1 2)
  (func (export "octopus_run") (result i32)
    (loop $inf
      br $inf
    )
    i32.const 0
  )
)
"#;

#[tokio::test]
async fn test_oidc_discovery_es256_jwks_and_key_rotation() {
    let ks = Arc::new(KillSwitch::new());
    let engine = AgentMeshEngine::new(AgentMeshConfig::default(), ks)
        .await
        .unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let initial_kid = engine.issuer().active_key_id();
    let jwt_v1 = engine
        .issuer()
        .mint_arm_token_with_time("arm_calc", 0, &ArmRole::NetworkEgress, now)
        .unwrap();

    // Rotate key within grace window; both v1 (retired) and v2 (current) remain verifiable
    let rotated_kid = engine.issuer().rotate_key_with_time(now);
    assert_ne!(initial_kid, rotated_kid);

    let jwks = engine.issuer().get_jwks(now);
    assert_eq!(jwks.keys.len(), 2);
    assert!(engine.issuer().verify_arm_token(&jwt_v1, now + 1).is_ok());

    engine.stop_serving_node().await.unwrap();
}

#[tokio::test]
async fn test_outbound_wasm_mesh_call_allowed_header_hygiene_and_zero_secret_memory() {
    let ks = Arc::new(KillSwitch::new());
    let engine = AgentMeshEngine::new(AgentMeshConfig::default(), ks)
        .await
        .unwrap();

    let calc = engine
        .execute_sandbox_wasm_mesh_call(
            "arm_calc",
            0,
            &ArmRole::NetworkEgress,
            "mcp://calc",
            br#"{"op":"add","a":19,"b":23}"#,
        )
        .await
        .unwrap();
    assert!(calc.allowed);
    assert!(calc.wasm_exit_code > 0);
    assert!(calc.linear_memory_zero_secret_verified);
    assert_eq!(calc.mesh_calls_succeeded, 1);

    let echo = engine
        .execute_sandbox_wasm_mesh_call(
            "arm_calc",
            0,
            &ArmRole::NetworkEgress,
            "mcp://echo_headers",
            br#"{"check":"headers"}"#,
        )
        .await
        .unwrap();
    assert!(echo.allowed);
    assert!(echo.linear_memory_zero_secret_verified);
    assert!(echo
        .sanitized_response
        .contains("authorization_stripped"));
    assert!(!echo.sanitized_response.contains("mesh_tok_"));

    engine.stop_serving_node().await.unwrap();
}

#[tokio::test]
async fn test_outbound_wasm_sibling_isolation_denies_rogue_arm() {
    let ks = Arc::new(KillSwitch::new());
    let engine = AgentMeshEngine::new(AgentMeshConfig::default(), ks)
        .await
        .unwrap();

    for target in ["mcp://payroll", "mcp://calc"] {
        let rep = engine
            .execute_sandbox_wasm_mesh_call(
                "arm_rogue",
                0,
                &ArmRole::UntrustedDocIngest,
                target,
                b"{}",
            )
            .await
            .unwrap();
        assert!(!rep.allowed, "arm_rogue must be denied on {}", target);
        assert_eq!(rep.wasm_exit_code, WASI_ERR_ACCESS_DENIED);
        assert!(rep.linear_memory_zero_secret_verified);
    }

    engine.stop_serving_node().await.unwrap();
}

#[tokio::test]
async fn test_virtual_wasi_stream_descriptors_end_to_end() {
    let ks = Arc::new(KillSwitch::new());
    let engine = Arc::new(
        AgentMeshEngine::new(AgentMeshConfig::default(), Arc::clone(&ks))
            .await
            .unwrap(),
    );

    let pep = Arc::clone(engine.pep_bridge());
    let wasm = Arc::clone(engine.wasm_executor());
    let ks_clone = (*ks).clone();

    let receipt = tokio::task::spawn_blocking(move || {
        let ctx = WasmMeshBridgeContext::new("arm_calc", 0, ArmRole::NetworkEgress, pep)
            .with_killswitch(ks_clone);
        wasm.execute_wat_with_context(
            "stream_client_guest",
            STREAM_CLIENT_WAT,
            b"",
            WasmSandboxLimits::default(),
            Some(ctx),
        )
    })
    .await
    .unwrap()
    .unwrap();

    assert!(receipt.exit_code > 0);
    assert_eq!(receipt.mesh_calls_succeeded, 1);
    assert!(receipt.linear_memory_zero_secret_verified);

    // Verify arm_rogue fails stream read with WASI_ERR_ACCESS_DENIED (-5)
    let pep_rogue = Arc::clone(engine.pep_bridge());
    let wasm_rogue = Arc::clone(engine.wasm_executor());
    let rogue_receipt = tokio::task::spawn_blocking(move || {
        let ctx =
            WasmMeshBridgeContext::new("arm_rogue", 0, ArmRole::UntrustedDocIngest, pep_rogue);
        wasm_rogue.execute_wat_with_context(
            "stream_rogue_guest",
            STREAM_CLIENT_WAT,
            b"",
            WasmSandboxLimits::default(),
            Some(ctx),
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(rogue_receipt.exit_code, WASI_ERR_ACCESS_DENIED);

    engine.stop_serving_node().await.unwrap();
}

#[test]
fn test_ed25519_mandate_attenuation_and_mathematical_ssrf_uri_guard() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let root_sk = SigningKey::generate(&mut OsRng);
    let hop1_sk = SigningKey::generate(&mut OsRng);
    let hop2_sk = SigningKey::generate(&mut OsRng);
    let root_vk = root_sk.verifying_key().to_bytes();

    let svcs: BTreeSet<String> = ["mcp://calc", "inference://ollama/gemma4"]
        .into_iter()
        .map(String::from)
        .collect();
    let pubs: BTreeSet<String> = ["mcp://octopus/doc_extractor"]
        .into_iter()
        .map(String::from)
        .collect();

    let root = AttenuatedMandate::create_root(
        &root_sk,
        "spiffe://octopus.local/root",
        "spiffe://octopus.local/arm/hop1",
        hop1_sk.verifying_key().to_bytes(),
        svcs,
        pubs,
        now,
        now + 300,
    )
    .unwrap();

    let child_svcs: BTreeSet<String> = ["mcp://calc"].into_iter().map(String::from).collect();
    let leaf = root
        .attenuate(
            &hop1_sk,
            "spiffe://octopus.local/arm/hop2",
            hop2_sk.verifying_key().to_bytes(),
            child_svcs,
            BTreeSet::new(),
            now + 60,
            now,
        )
        .unwrap();
    assert!(leaf.verify_chain(&root_vk, now).is_ok());

    // Reject SSRF & raw IP/port tricks
    for forbidden in [
        "http://example.com/tool",
        "mcp://127.0.0.1/tool",
        "mcp://10.0.0.1:8080/tool",
        "mcp://169.254.169.254/meta",
        "mcp://[::1]/tool",
        "mcp://calc:8080/bypass",
        "mcp://calc/../admin",
    ] {
        assert!(
            validate_mesh_uri(forbidden).is_err(),
            "Must reject forbidden URI: {}",
            forbidden
        );
    }
}

#[tokio::test]
async fn test_inbound_published_wasm_tool_cage_seal_and_replay_rejection() {
    let ks = Arc::new(KillSwitch::new());
    let engine = AgentMeshEngine::new(AgentMeshConfig::default(), ks)
        .await
        .unwrap();

    let payload = b"Ledger entry #4092: debit=120.00 credit=120.00 balanced=true";
    let seal = engine
        .mint_inbound_cage_seal("mcp://octopus/ledger_validator", payload)
        .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let jwt = engine
        .issuer()
        .mint_arm_token_with_time("arm_publisher", 0, &ArmRole::CedarPolicyEvaluation, now)
        .unwrap();
    let auth = format!("Bearer {}", jwt);

    let first = engine
        .execute_inbound_mesh_call_detailed(
            "mcp://octopus/ledger_validator",
            Some(&auth),
            &seal,
            payload,
        )
        .await
        .unwrap();
    assert_eq!(first.http_status, 200);
    assert_eq!(first.wasm_tool_name, "wasm_ledger_validator");
    assert!(first.linear_memory_zero_secret_verified);

    let jwt_2 = engine
        .issuer()
        .mint_arm_token_with_time("arm_publisher", 0, &ArmRole::CedarPolicyEvaluation, now)
        .unwrap();
    let auth_2 = format!("Bearer {}", jwt_2);
    let second = engine
        .execute_inbound_mesh_call_detailed(
            "mcp://octopus/ledger_validator",
            Some(&auth_2),
            &seal,
            payload,
        )
        .await
        .unwrap_err();
    assert_eq!(second.0, 409);

    engine.stop_serving_node().await.unwrap();
}

#[tokio::test]
async fn test_non_cooperative_infinite_loop_wasm_trapped_by_killswitch_epoch() {
    let ks = Arc::new(KillSwitch::new());
    let engine = Arc::new(
        AgentMeshEngine::new(AgentMeshConfig::default(), Arc::clone(&ks))
            .await
            .unwrap(),
    );

    let wasm = Arc::clone(engine.wasm_executor());
    let handle = std::thread::spawn(move || {
        let mut limits = WasmSandboxLimits::default();
        limits.fuel_budget = u64::MAX / 2;
        wasm.execute_wat_with_context("spin_forever", INFINITE_SPIN_WAT, b"", limits, None)
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    let latency = engine.trip_killswitch_autotomy("arm_calc").await;
    let trap_res = handle.join().unwrap();

    assert!(trap_res.is_err());
    assert!(latency < Duration::from_millis(1));

    engine.reset_killswitch().await;
    let recovered = engine
        .execute_sandbox_wasm_mesh_call(
            "arm_calc",
            1,
            &ArmRole::NetworkEgress,
            "mcp://calc",
            br#"{"op":"add","a":2,"b":3}"#,
        )
        .await
        .unwrap();
    assert!(recovered.allowed);
    assert_eq!(recovered.generation_epoch, 1);

    engine.stop_serving_node().await.unwrap();
}

#[test]
fn test_tier2_linux_bpf_simulator_key_broker_and_pqc_wan_transport() {
    let posture = describe_tier2_host_confinement_posture();
    assert!(!posture.is_empty());

    // x86_64 BPF filter blocks SYS_socket (41) & SYS_connect (42), allows SYS_write (1), kills arch mismatch
    let prog = build_socket_filter_bpf(
        AUDIT_ARCH_X86_64,
        X86_64_BLOCKED_SOCKET_SYSCALLS,
        LINUX_EACCES,
    );
    assert_eq!(
        evaluate_bpf_filter(&prog, AUDIT_ARCH_X86_64, 41),
        SECCOMP_RET_ERRNO | LINUX_EACCES
    );
    assert_eq!(
        evaluate_bpf_filter(&prog, AUDIT_ARCH_X86_64, 42),
        SECCOMP_RET_ERRNO | LINUX_EACCES
    );
    assert_eq!(
        evaluate_bpf_filter(&prog, AUDIT_ARCH_X86_64, 1),
        SECCOMP_RET_ALLOW
    );
    assert_eq!(
        evaluate_bpf_filter(&prog, AUDIT_ARCH_AARCH64, 1),
        SECCOMP_RET_KILL_PROCESS
    );

    // OS-protected KeyBroker signs ES256 payloads without exposing raw private scalar
    let broker = OsProtectedKeyBroker::new_in_memory("http://127.0.0.1:5005").unwrap();
    let sig = broker.sign_es256(b"oidc-header.oidc-claims").unwrap();
    assert_eq!(sig.len(), 64);

    // Post-Quantum ML-KEM-768 + Ed25519 + ChaCha20-Poly1305 WAN session
    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_vk = alice_key.verifying_key();
    let bob_vk = bob_key.verifying_key();
    let alice = AgentMeshWanTransport::new(alice_key);
    let bob = AgentMeshWanTransport::new(bob_key);
    let (init, alice_dk) = alice.initiate_pqc_handshake(&bob.peer_id);
    let (resp, bob_keys) = bob.respond_pqc_handshake(&init, &alice_vk).unwrap();
    let alice_keys = alice
        .complete_pqc_handshake(&init, &resp, &alice_dk, &bob_vk)
        .unwrap();
    let frame = alice_keys.encrypt_frame(b"hello-pqc-mesh");
    let pt = bob_keys.decrypt_frame(&frame[4..]).unwrap();
    assert_eq!(pt, b"hello-pqc-mesh");
}

#[tokio::test]
async fn test_web_api_agentmesh_handlers_end_to_end() {
    let state = WebState::default();

    let (s_oidc, b_oidc) = handle_agentmesh_openid_config(&state);
    assert_eq!(s_oidc, "200 OK");
    assert!(b_oidc.contains("ES256"));

    let (s_jwks, b_jwks) = handle_merged_well_known_jwks(&state);
    assert_eq!(s_jwks, "200 OK");
    assert!(b_jwks.contains("Ed25519"));
    assert!(b_jwks.contains("P-256"));

    let (s_st, b_st) = handle_agentmesh_status(&state).await;
    assert_eq!(s_st, "200 OK");
    assert!(b_st.contains("serving_node_active"));

    let (s_ok, b_ok) = handle_agentmesh_wasm_call(
        &state,
        r#"{"arm_id":"arm_calc","target_uri":"mcp://calc","payload":"{\"a\":1}"}"#,
    )
    .await;
    assert_eq!(s_ok, "200 OK");
    assert!(b_ok.contains("\"linear_memory_zero_secret_verified\":true"));

    let (s_deny, _b_deny) = handle_agentmesh_wasm_call(
        &state,
        r#"{"arm_id":"arm_rogue","target_uri":"mcp://payroll","payload":"{}"}"#,
    )
    .await;
    assert_eq!(s_deny, "403 Forbidden");

    let (s_mint, b_mint) = handle_agentmesh_mint_inbound_seal(
        &state,
        r#"{"tool_uri":"mcp://octopus/doc_extractor","payload":"Clause 9","arm_id":"arm_publisher"}"#,
    )
    .await;
    assert_eq!(s_mint, "200 OK");
    let minted: serde_json::Value = serde_json::from_str(&b_mint).unwrap();
    let bearer = minted["bearer_token"].as_str().unwrap();
    let seal_b64 = minted["cage_seal_b64"].as_str().unwrap();

    let (s_in1, _b_in1) = handle_agentmesh_inbound_mcp_call(
        &state,
        "/mesh/mcp/octopus/doc_extractor",
        Some(bearer),
        Some(seal_b64),
        b"Clause 9",
    )
    .await;
    assert_eq!(s_in1, "200 OK");

    let (s_in2, _b_in2) = handle_agentmesh_inbound_mcp_call(
        &state,
        "/mesh/mcp/octopus/doc_extractor",
        Some(bearer),
        Some(seal_b64),
        b"Clause 9",
    )
    .await;
    assert_eq!(s_in2, "409 Conflict");

    let (s_mandate, _) = handle_agentmesh_mandate_attenuate(
        &state,
        r#"{"parent_services":["mcp://calc"],"child_services":["mcp://payroll"]}"#,
    );
    assert_eq!(s_mandate, "403 Forbidden");

    let (s_ks, b_ks) = handle_agentmesh_killswitch_trip(&state, r#"{"arm_id":"arm_calc"}"#).await;
    assert_eq!(s_ks, "200 OK");
    assert!(b_ks.contains("\"sub_millisecond_verified\":true"));

    let (s_rst, _) = handle_agentmesh_killswitch_reset(&state).await;
    assert_eq!(s_rst, "200 OK");

    let _ = state.agentmesh_engine.stop_serving_node().await;
}
