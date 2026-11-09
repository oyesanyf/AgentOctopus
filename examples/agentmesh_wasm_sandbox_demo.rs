//! Runnable End-to-End Demonstration: Google AgentMesh x AgentOctopus Wasmtime v49.0.4 Sandbox
//!
//! Run with:
//!   cargo run --example agentmesh_wasm_sandbox_demo
//!
//! Optional upstream `agentmesh-node` interop (`v0.2.0`):
//!   AGENTMESH_UPSTREAM_URL=http://127.0.0.1:8080 cargo run --example agentmesh_wasm_sandbox_demo

use agent_octopus::core::circuit_breaker::KillSwitch;
use agent_octopus::core::types::ArmRole;
use agent_octopus::security::agentmesh::{
    validate_mesh_uri, AgentMeshConfig, AgentMeshEngine, AttenuatedMandate,
};
use agent_octopus::security::wasm_tier1::{WasmSandboxLimits, WASI_ERR_ACCESS_DENIED};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const INFINITE_LOOP_WAT: &str = r#"
(module
  (memory (export "memory") 1 2)
  (func (export "octopus_run") (result i32)
    (loop $spin
      br $spin
    )
    i32.const 0
  )
)
"#;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("================================================================================");
    println!("  Google AgentMesh x AgentOctopus (Wasmtime v49.0.4) Sandbox Integration Demo");
    println!("================================================================================");

    let ks = Arc::new(KillSwitch::new());
    let engine = Arc::new(AgentMeshEngine::new(AgentMeshConfig::default(), Arc::clone(&ks)).await?);
    let init_status = engine.status().await;

    println!(
        "[1/6] OIDC Actor Discovery & ES256 JWKS Online\n      Node Port: {:?} | Active P-256 KID: {}\n      Tier 2 Host Confinement: {}",
        init_status.serving_node_port,
        init_status.active_jwks_kid,
        init_status.tier2_confinement_posture
    );
    let jwks = engine.issuer().jwks_response();
    assert!(!jwks.keys.is_empty());
    assert_eq!(jwks.keys[0].crv, "P-256");
    assert_eq!(jwks.keys[0].alg, "ES256");

    // 2. Authorized Outbound Call: arm_calc -> mcp://calc & mcp://echo_headers
    let calc_report = engine
        .execute_sandbox_wasm_mesh_call(
            "arm_calc",
            0,
            &ArmRole::NetworkEgress,
            "mcp://calc",
            br#"{"op":"add","a":21,"b":21}"#,
        )
        .await?;
    assert!(calc_report.allowed);
    assert!(calc_report.linear_memory_zero_secret_verified);

    let hygiene_report = engine
        .execute_sandbox_wasm_mesh_call(
            "arm_calc",
            0,
            &ArmRole::NetworkEgress,
            "mcp://echo_headers",
            br#"{"probe":"header_hygiene"}"#,
        )
        .await?;
    assert!(hygiene_report.allowed);
    assert!(hygiene_report.linear_memory_zero_secret_verified);
    assert!(hygiene_report
        .sanitized_response
        .contains("authorization_stripped"));

    println!(
        "[2/6] Outbound Sandbox -> Mesh Authorized (arm_calc -> mcp://calc & mcp://echo_headers)\n      Wasm Exit: {} | Fuel: {} | Linear Memory Zero-Secret Scan: {}",
        calc_report.wasm_exit_code,
        calc_report.fuel_consumed,
        calc_report.linear_memory_zero_secret_verified
    );

    // 3. Unauthorized Outbound Call: arm_rogue -> mcp://payroll & mcp://calc (No shared gateway identity)
    let rogue_payroll = engine
        .execute_sandbox_wasm_mesh_call(
            "arm_rogue",
            0,
            &ArmRole::UntrustedDocIngest,
            "mcp://payroll",
            br#"{"exfiltrate":"salaries"}"#,
        )
        .await?;
    assert!(!rogue_payroll.allowed);
    assert_eq!(rogue_payroll.wasm_exit_code, WASI_ERR_ACCESS_DENIED);

    let rogue_calc = engine
        .execute_sandbox_wasm_mesh_call(
            "arm_rogue",
            0,
            &ArmRole::UntrustedDocIngest,
            "mcp://calc",
            br#"{"op":"add","a":1,"b":1}"#,
        )
        .await?;
    assert!(!rogue_calc.allowed);
    assert_eq!(rogue_calc.wasm_exit_code, WASI_ERR_ACCESS_DENIED);

    println!(
        "[3/6] Sibling Identity Isolation Verified (arm_rogue -> mcp://payroll & mcp://calc)\n      Verdict: DENIED inside Wasm (exit_code = {} WASI_ERR_ACCESS_DENIED)",
        rogue_payroll.wasm_exit_code
    );

    // 4. Ed25519 Monotonic Capability Mandate Attenuation & SSRF URI Guard
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let root_sk = SigningKey::generate(&mut OsRng);
    let parent_sk = SigningKey::generate(&mut OsRng);
    let child_sk = SigningKey::generate(&mut OsRng);
    let root_vk = root_sk.verifying_key().to_bytes();

    let parent_services: BTreeSet<String> = ["mcp://calc", "mcp://echo_headers"]
        .into_iter()
        .map(String::from)
        .collect();
    let parent_publish: BTreeSet<String> = ["mcp://octopus/doc_extractor"]
        .into_iter()
        .map(String::from)
        .collect();

    let root_mandate = AttenuatedMandate::create_root(
        &root_sk,
        "spiffe://octopus.local/supervisor",
        "spiffe://octopus.local/arm/arm_calc",
        parent_sk.verifying_key().to_bytes(),
        parent_services,
        parent_publish,
        now,
        now + 300,
    )?;

    let narrowed: BTreeSet<String> = ["mcp://calc"].into_iter().map(String::from).collect();
    let child_mandate = root_mandate.attenuate(
        &parent_sk,
        "spiffe://octopus.local/arm/arm_calc_worker",
        child_sk.verifying_key().to_bytes(),
        narrowed,
        BTreeSet::new(),
        now + 120,
        now,
    )?;
    child_mandate.verify_chain(&root_vk, now)?;

    let escalation: BTreeSet<String> = ["mcp://payroll"].into_iter().map(String::from).collect();
    assert!(root_mandate
        .attenuate(
            &parent_sk,
            "spiffe://octopus.local/arm/arm_calc_worker",
            child_sk.verifying_key().to_bytes(),
            escalation,
            BTreeSet::new(),
            now + 120,
            now,
        )
        .is_err());
    assert!(validate_mesh_uri("http://169.254.169.254/latest/meta-data").is_err());
    assert!(validate_mesh_uri("mcp://127.0.0.1:8080/admin").is_err());

    println!(
        "[4/6] Ed25519 Monotonic Mandate Chain & Mathematical SSRF URI Filter Verified\n      Mandate Depth: {} | Allowed Services: {:?} | Escalation & Raw IP Blocked",
        child_mandate.depth, child_mandate.allowed_services
    );

    // 5. Inbound Mesh -> Published Wasm Tool with Single-Use CAGE RoutingSeal
    let inbound_payload = b"Contract Clause 4.2: Mutual mTLS and task-scoped authorization.";
    let seal = engine.mint_inbound_cage_seal("mcp://octopus/doc_extractor", inbound_payload)?;
    let pub_jwt = engine.issuer().mint_arm_token_with_time(
        "arm_publisher",
        0,
        &ArmRole::CedarPolicyEvaluation,
        now,
    )?;
    let bearer = format!("Bearer {}", pub_jwt);

    // Missing auth -> 401
    let unauth_err = engine
        .execute_inbound_mesh_call_detailed(
            "mcp://octopus/doc_extractor",
            None,
            &seal,
            inbound_payload,
        )
        .await
        .expect_err("Missing bearer must fail with 401");
    assert_eq!(unauth_err.0, 401);

    // Expired JWT -> 401
    let expired_jwt = engine.issuer().mint_arm_token_with_time(
        "arm_publisher",
        0,
        &ArmRole::CedarPolicyEvaluation,
        now.saturating_sub(7200),
    )?;
    let expired_err = engine
        .execute_inbound_mesh_call_detailed(
            "mcp://octopus/doc_extractor",
            Some(&format!("Bearer {}", expired_jwt)),
            &seal,
            inbound_payload,
        )
        .await
        .expect_err("Expired JWT must fail with 401");
    assert_eq!(expired_err.0, 401);

    // First valid call -> 200 OK (real Wasm execution)
    let inbound_ok = engine
        .execute_inbound_mesh_call_detailed(
            "mcp://octopus/doc_extractor",
            Some(&bearer),
            &seal,
            inbound_payload,
        )
        .await
        .expect("Valid inbound CAGE + JWT call must succeed");
    assert_eq!(inbound_ok.http_status, 200);
    assert!(inbound_ok.linear_memory_zero_secret_verified);

    // Replay of consumed single-use CAGE seal (even with a fresh valid workload JWT) -> 409 Conflict
    let pub_jwt_fresh = engine.issuer().mint_arm_token_with_time(
        "arm_publisher",
        0,
        &ArmRole::CedarPolicyEvaluation,
        now,
    )?;
    let bearer_fresh = format!("Bearer {}", pub_jwt_fresh);
    let replay_err = engine
        .execute_inbound_mesh_call_detailed(
            "mcp://octopus/doc_extractor",
            Some(&bearer_fresh),
            &seal,
            inbound_payload,
        )
        .await
        .expect_err("Replayed CAGE seal must fail with 409");
    assert_eq!(replay_err.0, 409);

    println!(
        "[5/6] Inbound Mesh -> Published Wasm Tool (mcp://octopus/doc_extractor) Verified\n      Unauth: 401 | Expired JWT: 401 | Valid Seal: 200 (fuel={}) | Replay: 409 Conflict",
        inbound_ok.fuel_consumed
    );

    // 6. Non-Cooperative Infinite-Loop Wasm Guest Trapped via Sub-Millisecond KillSwitch Autotomy
    let wasm_exec = Arc::clone(engine.wasm_executor());
    let spin_handle = std::thread::spawn(move || {
        let mut high_fuel = WasmSandboxLimits::default();
        high_fuel.fuel_budget = u64::MAX / 2;
        wasm_exec.execute_wat_with_context(
            "infinite_spin_guest",
            INFINITE_LOOP_WAT,
            b"",
            high_fuel,
            None,
        )
    });

    tokio::time::sleep(Duration::from_millis(25)).await;
    let revocation_elapsed = engine.trip_killswitch_autotomy("arm_calc").await;
    let spin_result = spin_handle.join().expect("Spin worker thread join");
    assert!(
        spin_result.is_err(),
        "Infinite loop Wasm guest must trap immediately on KillSwitch epoch increment"
    );
    assert!(revocation_elapsed < Duration::from_millis(1));

    let post_ks = engine
        .execute_sandbox_wasm_mesh_call("arm_calc", 0, &ArmRole::NetworkEgress, "mcp://calc", b"{}")
        .await;
    assert!(post_ks.is_err());

    let final_status = engine.status().await;
    println!(
        "[6/6] Sub-Millisecond KillSwitch Autotomy & Wasm Epoch Trap Verified\n      Revocation Latency: {:.2} us (< 1,000 us SLA) | New Epoch: {} | Cached Vault Tokens: {}",
        revocation_elapsed.as_nanos() as f64 / 1000.0,
        final_status.generation_epoch,
        final_status.cached_credentials_count
    );

    engine.stop_serving_node().await?;
    println!("================================================================================");
    println!("  ALL 6 GOOGLE AGENTMESH X WASMTIME V49.0.4 INVARIANTS VERIFIED SUCCESSFULLY");
    println!("================================================================================");
    Ok(())
}
