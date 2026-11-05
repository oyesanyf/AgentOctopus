//! Integration test wrapper around `examples/agentmesh_live_v020_e2e.rs`.
//!
//! Automatically executes the full 8-case live `google/agentmesh v0.2.0` multi-node E2E suite
//! whenever `agentmesh-one` and `agentmesh-node` are available via `AGENTMESH_BIN_DIR`,
//! `examples/agentmesh-wasm-sandbox/.run/bin`, or `PATH`.

#[path = "../examples/agentmesh_live_v020_e2e.rs"]
mod live_v020;

#[tokio::test]
async fn test_live_google_agentmesh_v020_multi_node_e2e() {
    let Some((one_bin, node_bin)) = live_v020::locate_agentmesh_binaries() else {
        eprintln!(
            "Skipping live `google/agentmesh v0.2.0` binary test because `AGENTMESH_BIN_DIR` is not set \
             and binaries are not present in `examples/agentmesh-wasm-sandbox/.run/bin` or `PATH`."
        );
        return;
    };

    live_v020::run_live_v020_suite(&one_bin, &node_bin)
        .await
        .expect("Live google/agentmesh v0.2.0 multi-node E2E suite must pass");
}
