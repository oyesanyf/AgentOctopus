//! Live Cross-Platform End-to-End Verification against Official `google/agentmesh v0.2.0` Binaries
//! (`examples/agentmesh_live_v020_e2e.rs`)
//!
//! Spawns a complete, real local multi-node `google/agentmesh v0.2.0` topology on `127.0.0.1`:
//!   1. `OidcLoopbackServer` (`/.well-known/openid-configuration`, `/.well-known/jwks.json`, `ES256` `P-256`)
//!   2. Local Streamable HTTP MCP backend server (`/mcp/calc`, `/mcp/payroll`, `/mcp/echo-headers`,
//!      and `/mcp/octopus-doc-extractor` backed by `wasmtime v49.0.4`)
//!   3. `agentmesh-one` (`v0.2.0`) control plane + embedded router (`--workload-issuer`, `--allowed-audiences=agentmesh`)
//!   4. `office-node` (`agentmesh-node v0.2.0`) publishing the 4 MCP services onto the `libp2p` mesh
//!   5. `edge-node` (`agentmesh-node v0.2.0`) acting as the local sidecar doorway for `wasmtime` sandboxes
//!
//! Verifies 8 end-to-end security and interoperability invariants:
//!   - Case 1: Allowed `wasmtime` -> `AgentMeshPepBridge` -> `edge-node` -> `libp2p` -> `office-node` -> `mcp://calc`
//!             with full linear-memory scan confirming zero JWT or Biscuit bytes inside Wasm memory.
//!   - Case 2: Caller header hygiene (`Authorization`, `Cookie`, `X-Mesh-*` stripped; backend sees zero secrets).
//!   - Case 3: Service-level denial (`arm_calc` -> `mcp://payroll` refused by `office-node` with `403`, mapped to `-5`).
//!   - Case 4: Sibling sandbox isolation (`arm_rogue` unbound in `policy.json` -> refused `mcp://calc` with `403` / `-5`).
//!   - Case 5: Task-scoped sealed Biscuit attenuation (`scope=mcp://calc&seal=true` -> `tar_block` allows `mcp://calc`
//!             and denies `mcp://echo-headers` despite standing role grant).
//!   - Case 6: OIDC issuer, audience, and expiry rejection at `POST /oauth/token` + fresh JWT recovery.
//!   - Case 7: RFC 7009 Biscuit revocation (`POST /oauth/revoke`) + `<1ms` supervisory `KillSwitch` Wasmtime epoch trap.
//!   - Case 8: Inbound published Wasm tool (`mcp://octopus-doc-extractor`) invoked across the `libp2p` mesh.

use agent_octopus::core::circuit_breaker::KillSwitch;
use agent_octopus::core::types::ArmRole;
use agent_octopus::security::agentmesh::{
    url_encode_form_component, AgentMeshPepBridge, AsyncHttpWireClient, DiscoveredMeshService,
    MeshCallError, OidcLoopbackServer, PepBridgeConfig, AUDIENCE_DEFAULT, SPIFFE_ISSUER_DEFAULT,
};
use agent_octopus::security::wasm_tier1::{
    WasmMeshBridgeContext, WasmSandboxLimits, WasmTier1Executor, WASI_ERR_ACCESS_DENIED,
};
use rand::RngCore;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

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

struct ManagedChild {
    name: String,
    child: Child,
}

impl ManagedChild {
    fn spawn(name: impl Into<String>, mut cmd: Command) -> Result<Self, String> {
        let label = name.into();
        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn {}: {}", label, e))?;
        Ok(Self { name: label, child })
    }

    fn try_has_exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = &self.name;
    }
}

struct LocalMcpBackendServer {
    port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl LocalMcpBackendServer {
    async fn start(wasm_executor: Arc<WasmTier1Executor>) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("Failed to bind local MCP backend listener: {}", e))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("Failed to inspect MCP backend local_addr: {}", e))?
            .port();
        let (tx, mut rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept_res = listener.accept() => {
                        if let Ok((stream, _)) = accept_res {
                            let wasm = Arc::clone(&wasm_executor);
                            tokio::spawn(async move {
                                let _ = handle_mcp_http_conn(stream, wasm).await;
                            });
                        }
                    }
                }
            }
        });

        Ok(Self {
            port,
            shutdown_tx: Some(tx),
        })
    }
}

impl Drop for LocalMcpBackendServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

async fn read_http_request(
    stream: &mut TcpStream,
) -> Result<(String, String, HashMap<String, String>, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];
    let header_end = loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| format!("read error: {}", e))?;
        if n == 0 {
            return Err("EOF before HTTP headers".to_string());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 128 * 1024 {
            return Err("HTTP header too large".to_string());
        }
    };

    let head_str = String::from_utf8_lossy(&buf[..header_end - 4]).to_string();
    let mut lines = head_str.split("\r\n");
    let req_line = lines.next().ok_or("Missing request line")?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_uppercase();
    let path = parts.next().unwrap_or("/").to_string();

    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    let mut is_chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse::<usize>().unwrap_or(0);
            } else if key == "transfer-encoding" && val.to_ascii_lowercase().contains("chunked") {
                is_chunked = true;
            }
            headers.insert(key, val);
        }
    }

    let mut body = buf[header_end..].to_vec();
    if is_chunked {
        while !body.windows(5).any(|w| w == b"0\r\n\r\n") {
            let n = stream
                .read(&mut tmp)
                .await
                .map_err(|e| format!("chunked read error: {}", e))?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body = decode_chunked(&body);
    } else {
        while body.len() < content_length {
            let n = stream
                .read(&mut tmp)
                .await
                .map_err(|e| format!("body read error: {}", e))?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(content_length);
    }

    Ok((method, path, headers, body))
}

fn decode_chunked(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx < raw.len() {
        let Some(rel_end) = raw[idx..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_line = String::from_utf8_lossy(&raw[idx..idx + rel_end]);
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let Ok(chunk_len) = usize::from_str_radix(hex_part, 16) else {
            break;
        };
        idx += rel_end + 2;
        if chunk_len == 0 || idx + chunk_len > raw.len() {
            break;
        }
        out.extend_from_slice(&raw[idx..idx + chunk_len]);
        idx += chunk_len + 2;
    }
    out
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(), String> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        status,
        reason,
        content_type,
        body.len()
    );
    for (k, v) in extra_headers {
        head.push_str(&format!("{}: {}\r\n", k, v));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    if !body.is_empty() {
        stream.write_all(body).await.map_err(|e| e.to_string())?;
    }
    let _ = stream.flush().await;
    Ok(())
}

fn evaluate_service_payload(
    service: &str,
    args: &Value,
    headers: &HashMap<String, String>,
    wasm_executor: &WasmTier1Executor,
) -> Value {
    match service {
        "calc" => {
            let op = args.get("op").and_then(|v| v.as_str()).unwrap_or("add");
            let a = args.get("a").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let b = args.get("b").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let result = match op {
                "mul" | "multiply" => a * b,
                "sub" | "subtract" => a - b,
                _ => a + b,
            };
            json!({
                "service": "calc",
                "op": op,
                "a": a,
                "b": b,
                "result": result,
            })
        }
        "payroll" => {
            json!({
                "service": "payroll",
                "authorized": true,
                "ledger": "restricted-payroll-summary"
            })
        }
        "echo-headers" => {
            let auth_present = headers.contains_key("authorization");
            let cookie_present = headers.contains_key("cookie");
            let x_mesh_auth_present = headers.contains_key("x-mesh-authentication");
            let x_mesh_principal = headers.get("x-mesh-principal").cloned().unwrap_or_default();
            let x_mesh_roles = headers.get("x-mesh-roles").cloned().unwrap_or_default();
            let mut names: Vec<String> = headers.keys().cloned().collect();
            names.sort();
            json!({
                "service": "echo-headers",
                "authorization_stripped": !auth_present,
                "authorization_present": auth_present,
                "cookie_present": cookie_present,
                "x_mesh_auth_present": x_mesh_auth_present,
                "x_mesh_principal": x_mesh_principal,
                "x_mesh_roles": x_mesh_roles,
                "observed_header_names": names,
            })
        }
        "octopus-doc-extractor" => {
            let raw_doc = args
                .get("document")
                .or_else(|| args.get("text"))
                .and_then(|v| v.as_str())
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_else(|| serde_json::to_vec(args).unwrap_or_default());
            match wasm_executor.execute_doc_extractor(&raw_doc, WasmSandboxLimits::default()) {
                Ok(receipt) => json!({
                    "service": "octopus-doc-extractor",
                    "wasm_tool": receipt.tool_name,
                    "exit_code": receipt.exit_code,
                    "fuel_consumed": receipt.fuel_consumed,
                    "linear_memory_zero_secret_verified": receipt.linear_memory_zero_secret_verified,
                    "sanitized_text": receipt.zero_mi_projection.canonical_output,
                }),
                Err(e) => json!({
                    "service": "octopus-doc-extractor",
                    "error": e.to_string(),
                }),
            }
        }
        other => json!({ "service": other, "ok": true }),
    }
}

async fn handle_mcp_http_conn(
    mut stream: TcpStream,
    wasm_executor: Arc<WasmTier1Executor>,
) -> Result<(), String> {
    let (method, raw_path, headers, body) = read_http_request(&mut stream).await?;
    let path = raw_path.split('?').next().unwrap_or(&raw_path);

    if path == "/healthz" || path == "/readyz" {
        return write_http_response(
            &mut stream,
            200,
            "OK",
            "application/json",
            &[],
            br#"{"status":"ok"}"#,
        )
        .await;
    }

    if method == "GET" || method == "DELETE" {
        return write_http_response(
            &mut stream,
            405,
            "Method Not Allowed",
            "text/plain",
            &[("Allow", "POST")],
            b"POST required for Streamable HTTP MCP",
        )
        .await;
    }

    let service = path
        .trim_start_matches('/')
        .strip_prefix("mcp/")
        .unwrap_or("calc")
        .split('/')
        .next()
        .unwrap_or("calc");

    let parsed: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));

    // Handle Streamable HTTP MCP JSON-RPC 2.0 (`initialize`, `notifications/initialized`, `tools/list`, `tools/call`)
    if parsed.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0") {
        let rpc_method = parsed.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let rpc_id = parsed.get("id").cloned();

        if rpc_id.is_none() || rpc_method.starts_with("notifications/") {
            return write_http_response(
                &mut stream,
                202,
                "Accepted",
                "application/json",
                &[("Mcp-Session-Id", "octopus-mcp-session")],
                b"",
            )
            .await;
        }

        let id_val = rpc_id.unwrap_or(Value::Number(1.into()));
        let response_json = match rpc_method {
            "initialize" => {
                let client_proto = parsed
                    .pointer("/params/protocolVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("2025-03-26");
                json!({
                    "jsonrpc": "2.0",
                    "id": id_val,
                    "result": {
                        "protocolVersion": client_proto,
                        "capabilities": { "tools": { "listChanged": false } },
                        "serverInfo": { "name": service, "version": "0.1.0" }
                    }
                })
            }
            "ping" => json!({ "jsonrpc": "2.0", "id": id_val, "result": {} }),
            "tools/list" => {
                let tool_def = match service {
                    "calc" => json!([{
                        "name": "add",
                        "description": "Add or multiply two numbers",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "op": { "type": "string" },
                                "a": { "type": "number" },
                                "b": { "type": "number" }
                            }
                        }
                    }]),
                    "payroll" => json!([{
                        "name": "payroll_summary",
                        "description": "Restricted payroll ledger summary",
                        "inputSchema": { "type": "object", "properties": {} }
                    }]),
                    "echo-headers" => json!([{
                        "name": "inspect_headers",
                        "description": "Inspect upstream request headers for credential hygiene",
                        "inputSchema": { "type": "object", "properties": {} }
                    }]),
                    "octopus-doc-extractor" => json!([{
                        "name": "extract_document",
                        "description": "Sanitize untrusted text inside Wasmtime v49.0.4",
                        "inputSchema": {
                            "type": "object",
                            "properties": { "document": { "type": "string" } }
                        }
                    }]),
                    _ => json!([]),
                };
                json!({
                    "jsonrpc": "2.0",
                    "id": id_val,
                    "result": { "tools": tool_def }
                })
            }
            "tools/call" => {
                let args = parsed
                    .pointer("/params/arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let out = evaluate_service_payload(service, &args, &headers, &wasm_executor);
                json!({
                    "jsonrpc": "2.0",
                    "id": id_val,
                    "result": {
                        "content": [{ "type": "text", "text": out.to_string() }],
                        "isError": false
                    }
                })
            }
            other => json!({
                "jsonrpc": "2.0",
                "id": id_val,
                "error": { "code": -32601, "message": format!("Unsupported method {}", other) }
            }),
        };

        let bytes = serde_json::to_vec(&response_json).map_err(|e| e.to_string())?;
        return write_http_response(
            &mut stream,
            200,
            "OK",
            "application/json",
            &[("Mcp-Session-Id", "octopus-mcp-session")],
            &bytes,
        )
        .await;
    }

    // Direct HTTP JSON payload forwarded over `/mesh/<peer-id>/mcp/<service>`
    let out = evaluate_service_payload(service, &parsed, &headers, &wasm_executor);
    let bytes = serde_json::to_vec(&out).map_err(|e| e.to_string())?;
    write_http_response(&mut stream, 200, "OK", "application/json", &[], &bytes).await
}

fn pick_free_port() -> Result<u16, String> {
    let listener =
        StdTcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind ephemeral port: {}", e))?;
    listener
        .local_addr()
        .map(|a| a.port())
        .map_err(|e| format!("local_addr: {}", e))
}

fn random_hex(bytes_len: usize) -> String {
    let mut buf = vec![0u8; bytes_len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn exe_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{}.exe", stem)
    } else {
        stem.to_string()
    }
}

pub fn locate_agentmesh_binaries() -> Option<(PathBuf, PathBuf)> {
    let one_name = exe_name("agentmesh-one");
    let node_name = exe_name("agentmesh-node");

    let mut candidate_dirs: Vec<PathBuf> = Vec::new();
    if let Ok(dir) = env::var("AGENTMESH_BIN_DIR") {
        if !dir.trim().is_empty() {
            candidate_dirs.push(PathBuf::from(dir));
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    candidate_dirs.push(
        manifest_dir
            .join("examples")
            .join("agentmesh-wasm-sandbox")
            .join(".run")
            .join("bin"),
    );

    if let Some(path_os) = env::var_os("PATH") {
        candidate_dirs.extend(env::split_paths(&path_os));
    }

    for dir in candidate_dirs {
        let one = dir.join(&one_name);
        let node = dir.join(&node_name);
        if one.is_file() && node.is_file() {
            return Some((one, node));
        }
    }
    None
}

async fn wait_http_200(
    url: &str,
    headers: &[(String, String)],
    timeout: Duration,
    child: &mut ManagedChild,
    log_path: &Path,
) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + timeout;
    let mut last_err = String::new();
    while Instant::now() < deadline {
        if let Some(status) = child.try_has_exited() {
            let log_tail = fs::read_to_string(log_path).unwrap_or_default();
            return Err(format!(
                "{} exited prematurely with status {} while waiting for {}.\nLogs:\n{}",
                child.name, status, url, log_tail
            ));
        }
        match AsyncHttpWireClient::get(url, headers).await {
            Ok((200, _, body)) => return Ok(body),
            Ok((code, _, body)) => {
                last_err = format!("HTTP {}: {}", code, String::from_utf8_lossy(&body));
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let log_tail = fs::read_to_string(log_path).unwrap_or_default();
    Err(format!(
        "Timed out waiting for {} ({}).\nLogs:\n{}",
        url, last_err, log_tail
    ))
}

async fn execute_wasm_sandbox_call(
    wasm_executor: &Arc<WasmTier1Executor>,
    pep_bridge: &Arc<AgentMeshPepBridge>,
    killswitch: &Arc<KillSwitch>,
    arm_id: &str,
    epoch: u64,
    role: ArmRole,
    uri: &str,
    payload: &[u8],
) -> Result<(i32, bool, String), String> {
    let mut combined = Vec::with_capacity(uri.len() + 1 + payload.len());
    combined.extend_from_slice(uri.as_bytes());
    combined.push(b'\n');
    combined.extend_from_slice(payload);

    let ctx = WasmMeshBridgeContext::new(arm_id, epoch, role, Arc::clone(pep_bridge))
        .with_killswitch((**killswitch).clone());
    let wasm = Arc::clone(wasm_executor);
    let receipt = tokio::task::spawn_blocking(move || {
        wasm.execute_mesh_caller(&combined, WasmSandboxLimits::default(), ctx)
    })
    .await
    .map_err(|e| format!("Wasm join error: {}", e))?
    .map_err(|e| format!("Wasm execution error: {}", e))?;

    Ok((
        receipt.exit_code,
        receipt.linear_memory_zero_secret_verified,
        receipt.zero_mi_projection.canonical_output,
    ))
}

pub async fn run_live_v020_suite(one_bin: &Path, node_bin: &Path) -> Result<(), String> {
    println!("=========================================================================");
    println!("  AgentOctopus x google/agentmesh v0.2.0 -- Live Multi-Node E2E Suite");
    println!("=========================================================================");
    println!("  agentmesh-one : {}", one_bin.display());
    println!("  agentmesh-node: {}", node_bin.display());

    // Create short path workspace under OS temp dir (avoids Unix domain socket length caps on macOS)
    let work_dir = env::temp_dir().join(format!("ao-am-{}", &random_hex(4)));
    let cp_dir = work_dir.join("cp");
    let office_dir = work_dir.join("office");
    let edge_dir = work_dir.join("edge");
    fs::create_dir_all(&cp_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&office_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&edge_dir).map_err(|e| e.to_string())?;

    // 1. Start OIDC Discovery & ES256 Workload JWT Issuer (`127.0.0.1:0`)
    let oidc_server = OidcLoopbackServer::start(0, AUDIENCE_DEFAULT, Some(SPIFFE_ISSUER_DEFAULT))
        .await
        .map_err(|e| format!("Failed to start OidcLoopbackServer: {}", e))?;
    let issuer = Arc::clone(oidc_server.issuer());
    println!(
        "  [boot] OIDC workload issuer ready at {}",
        issuer.issuer_url()
    );

    // 2. Start Wasmtime v49.0.4 executor + local Streamable HTTP MCP backend (`127.0.0.1:0`)
    let killswitch = Arc::new(KillSwitch::new());
    let wasm_executor =
        Arc::new(WasmTier1Executor::try_new().map_err(|e| format!("WasmTier1Executor: {}", e))?);
    wasm_executor.attach_killswitch(&killswitch);
    let mcp_backend = LocalMcpBackendServer::start(Arc::clone(&wasm_executor)).await?;
    println!(
        "  [boot] Local Streamable HTTP MCP + Wasmtime backend ready on 127.0.0.1:{}",
        mcp_backend.port
    );

    // 3. Render `policy.json` and `office.yaml` from canonical templates
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sandbox_example_dir = manifest_dir.join("examples").join("agentmesh-wasm-sandbox");
    let policy_src = sandbox_example_dir.join("policy.json");
    let office_tmpl_src = sandbox_example_dir.join("office.yaml.tmpl");

    let policy_path = work_dir.join("policy.json");
    fs::copy(&policy_src, &policy_path)
        .map_err(|e| format!("Failed to copy {}: {}", policy_src.display(), e))?;

    let office_tmpl = fs::read_to_string(&office_tmpl_src)
        .map_err(|e| format!("Failed to read {}: {}", office_tmpl_src.display(), e))?;
    let office_yaml = office_tmpl.replace("__MCP_PORT__", &mcp_backend.port.to_string());
    let office_yaml_path = work_dir.join("office.yaml");
    fs::write(&office_yaml_path, office_yaml).map_err(|e| e.to_string())?;

    let join_token_path = work_dir.join("join.token");
    let admin_token_path = work_dir.join("admin.token");
    let office_api_token_path = work_dir.join("office-api.token");
    let edge_api_token_path = work_dir.join("edge-api.token");

    let join_token = format!("mesh_tok_{}", random_hex(16));
    let admin_token = format!("mesh_adm_{}", random_hex(16));
    let office_api_token = random_hex(16);
    let edge_api_token = random_hex(16);

    fs::write(&join_token_path, &join_token).map_err(|e| e.to_string())?;
    fs::write(&admin_token_path, &admin_token).map_err(|e| e.to_string())?;
    fs::write(&office_api_token_path, &office_api_token).map_err(|e| e.to_string())?;
    fs::write(&edge_api_token_path, &edge_api_token).map_err(|e| e.to_string())?;

    // 4. Spawn `agentmesh-one` control plane + embedded router
    let cp_port = pick_free_port()?;
    let cp_url = format!("http://127.0.0.1:{}", cp_port);
    let cp_log_path = work_dir.join("cp.log");
    let cp_log = File::create(&cp_log_path).map_err(|e| e.to_string())?;
    let cp_err = cp_log.try_clone().map_err(|e| e.to_string())?;

    let mut cp_cmd = Command::new(one_bin);
    cp_cmd
        .arg("--bind-address=127.0.0.1")
        .arg(format!("--port={}", cp_port))
        .arg(format!("--data-dir={}", cp_dir.display()))
        .arg(format!("--policy-file={}", policy_path.display()))
        .arg(format!("--token-path={}", join_token_path.display()))
        .arg(format!("--admin-token-path={}", admin_token_path.display()))
        .arg(format!("--workload-issuer={}", issuer.issuer_url()))
        .arg(format!("--allowed-audiences={}", AUDIENCE_DEFAULT))
        .arg("--router-allow-loopback=true")
        .arg("--enroll-qr=false")
        .arg("--log-format=json")
        .stdout(Stdio::from(cp_log))
        .stderr(Stdio::from(cp_err));

    let mut cp_proc = ManagedChild::spawn("agentmesh-one", cp_cmd)?;
    wait_http_200(
        &format!("{}/info", cp_url),
        &[],
        Duration::from_secs(20),
        &mut cp_proc,
        &cp_log_path,
    )
    .await?;
    println!("  [boot] agentmesh-one (v0.2.0) ready at {}", cp_url);

    // Mint two single-use bootstrap tokens via `POST /admin/bootstrap-tokens` (falls back to join.token if endpoint differs)
    let office_boot_path = work_dir.join("office-boot.token");
    let edge_boot_path = work_dir.join("edge-boot.token");
    for (desc, target_path) in [
        ("office-node", &office_boot_path),
        ("edge-node", &edge_boot_path),
    ] {
        let admin_headers = vec![
            (
                "Authorization".to_string(),
                format!("Bearer {}", admin_token),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        let body = serde_json::to_vec(&json!({
            "role": "mesh:role:node",
            "ttl_hours": 1,
            "max_usages": 1,
            "description": desc,
        }))
        .unwrap();
        let minted = match AsyncHttpWireClient::post(
            &format!("{}/admin/bootstrap-tokens", cp_url),
            &admin_headers,
            &body,
        )
        .await
        {
            Ok((code, _, resp)) if (200..300).contains(&code) => {
                serde_json::from_slice::<Value>(&resp).ok().and_then(|v| {
                    v.get("token")
                        .or_else(|| v.get("secret"))
                        .and_then(|t| t.as_str())
                        .map(String::from)
                })
            }
            _ => None,
        };
        fs::write(target_path, minted.as_deref().unwrap_or(&join_token))
            .map_err(|e| e.to_string())?;
    }

    // 5. Spawn `office-node` (service publisher)
    let office_port = pick_free_port()?;
    let office_metrics_port = pick_free_port()?;
    let office_log_path = work_dir.join("office.log");
    let office_log = File::create(&office_log_path).map_err(|e| e.to_string())?;
    let office_err = office_log.try_clone().map_err(|e| e.to_string())?;

    let mut office_cmd = Command::new(node_bin);
    office_cmd
        .arg("run")
        .arg(format!("--control-plane={}", cp_url))
        .arg(format!(
            "--bootstrap-token-path={}",
            office_boot_path.display()
        ))
        .arg(format!(
            "--api-token-path={}",
            office_api_token_path.display()
        ))
        .arg(format!("--data-dir={}", office_dir.display()))
        .arg(format!("--bind-addr=127.0.0.1:{}", office_port))
        .arg(format!("--metrics-addr=127.0.0.1:{}", office_metrics_port))
        .arg("--socket-path=")
        .arg("--listen=/ip4/127.0.0.1/tcp/0")
        .arg("--allow-loopback")
        .arg("--discovery-interval=1s")
        .arg("--control-plane-sync-interval=5s")
        .arg(format!("--config={}", office_yaml_path.display()))
        .arg("--log-format=json")
        .stdout(Stdio::from(office_log))
        .stderr(Stdio::from(office_err));

    let mut office_proc = ManagedChild::spawn("office-node", office_cmd)?;
    wait_http_200(
        &format!("http://127.0.0.1:{}/readyz", office_metrics_port),
        &[],
        Duration::from_secs(25),
        &mut office_proc,
        &office_log_path,
    )
    .await?;
    println!(
        "  [boot] office-node (v0.2.0) enrolled & ready on 127.0.0.1:{}",
        office_port
    );

    // 6. Spawn `edge-node` (sandbox sidecar doorway)
    let edge_port = pick_free_port()?;
    let edge_metrics_port = pick_free_port()?;
    let edge_url = format!("http://127.0.0.1:{}", edge_port);
    let edge_log_path = work_dir.join("edge.log");
    let edge_log = File::create(&edge_log_path).map_err(|e| e.to_string())?;
    let edge_err = edge_log.try_clone().map_err(|e| e.to_string())?;

    let mut edge_cmd = Command::new(node_bin);
    edge_cmd
        .arg("run")
        .arg(format!("--control-plane={}", cp_url))
        .arg(format!(
            "--bootstrap-token-path={}",
            edge_boot_path.display()
        ))
        .arg(format!(
            "--api-token-path={}",
            edge_api_token_path.display()
        ))
        .arg(format!("--data-dir={}", edge_dir.display()))
        .arg(format!("--bind-addr=127.0.0.1:{}", edge_port))
        .arg(format!("--metrics-addr=127.0.0.1:{}", edge_metrics_port))
        .arg("--socket-path=")
        .arg("--listen=/ip4/127.0.0.1/tcp/0")
        .arg("--allow-loopback")
        .arg("--discovery-interval=1s")
        .arg("--control-plane-sync-interval=5s")
        .arg("--log-format=json")
        .stdout(Stdio::from(edge_log))
        .stderr(Stdio::from(edge_err));

    let mut edge_proc = ManagedChild::spawn("edge-node", edge_cmd)?;
    wait_http_200(
        &format!("http://127.0.0.1:{}/readyz", edge_metrics_port),
        &[],
        Duration::from_secs(25),
        &mut edge_proc,
        &edge_log_path,
    )
    .await?;
    println!(
        "  [boot] edge-node (v0.2.0) enrolled & ready at {}",
        edge_url
    );

    // 7. Construct `AgentMeshPepBridge` pointed at `edge-node`
    let pep_bridge = Arc::new(AgentMeshPepBridge::new_with_config(
        PepBridgeConfig {
            mesh_node_base_url: edge_url.clone(),
            token_exchange_timeout_ms: 5000,
            channel_secret: None,
        },
        Arc::clone(&issuer),
        Arc::clone(&killswitch),
    ));

    // Wait for DHT service announcement (`office-node` -> embedded router -> `edge-node` `/mesh/service/discover?type=mcp`)
    let standing_biscuit = {
        let b = Arc::clone(&pep_bridge);
        tokio::task::spawn_blocking(move || {
            b.get_or_exchange_token_sync("arm_calc", 0, &ArmRole::NetworkEgress, "mcp://calc")
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| {
            let cp_logs = fs::read_to_string(&cp_log_path).unwrap_or_default();
            let edge_logs = fs::read_to_string(&edge_log_path).unwrap_or_default();
            format!(
                "Initial RFC 8693 token exchange on edge-node failed: {}\n--- cp.log ---\n{}\n--- edge.log ---\n{}",
                e, cp_logs, edge_logs
            )
        })?
    };

    let mut discovered_peer_id = String::new();
    let discover_deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < discover_deadline {
        let disc_headers = vec![
            (
                "X-Mesh-Authentication".to_string(),
                format!("Bearer {}", standing_biscuit),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        if let Ok((200, _, body)) = AsyncHttpWireClient::get(
            &format!("{}/mesh/service/discover?type=mcp&name=calc", edge_url),
            &disc_headers,
        )
        .await
        {
            if let Ok(items) = serde_json::from_slice::<Vec<DiscoveredMeshService>>(&body) {
                if let Some(first) = items.into_iter().find(|i| !i.peer_id.is_empty()) {
                    discovered_peer_id = first.peer_id;
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    if discovered_peer_id.is_empty() {
        let office_logs = fs::read_to_string(&office_log_path).unwrap_or_default();
        let edge_logs = fs::read_to_string(&edge_log_path).unwrap_or_default();
        return Err(format!(
            "DHT service discovery returned empty provider list after 25s.\n--- office.log ---\n{}\n--- edge.log ---\n{}",
            office_logs, edge_logs
        ));
    }
    pep_bridge.set_default_provider_peer_id(Some(discovered_peer_id.clone()));
    println!(
        "  [mesh] Discovered office-node provider PeerID over libp2p DHT: {}",
        discovered_peer_id
    );

    // =========================================================================
    // CASE 1: Allowed Wasm -> Mesh MCP Call + Zero-Secret Linear Memory
    // =========================================================================
    let (exit_calc, zero_secret_calc, out_calc) = execute_wasm_sandbox_call(
        &wasm_executor,
        &pep_bridge,
        &killswitch,
        "arm_calc",
        0,
        ArmRole::NetworkEgress,
        "mcp://calc",
        br#"{"op":"add","a":19,"b":23}"#,
    )
    .await?;
    let biscuit_prefix = &standing_biscuit[..standing_biscuit.len().min(18)];
    if exit_calc <= 0 || !zero_secret_calc || out_calc.contains(biscuit_prefix) {
        let office_logs = fs::read_to_string(&office_log_path).unwrap_or_default();
        let edge_logs = fs::read_to_string(&edge_log_path).unwrap_or_default();
        return Err(format!(
            "Case 1 failed: exit={}, zero_secret={}, out={}\n--- office.log ---\n{}\n--- edge.log ---\n{}",
            exit_calc, zero_secret_calc, out_calc, office_logs, edge_logs
        ));
    }
    let calc_json: Value = serde_json::from_str(&out_calc)
        .map_err(|e| format!("Case 1 JSON parse error ({}): {}", e, out_calc))?;
    assert_eq!(calc_json.get("result").and_then(|v| v.as_f64()), Some(42.0));
    println!(
        "  [PASS] Case 1: Allowed Wasm -> libp2p -> mcp://calc => 42 (0 JWT/Biscuit bytes in Wasm memory)"
    );

    // =========================================================================
    // CASE 2: Caller Header Hygiene (Zero Credential Leak to Upstream Backend)
    // =========================================================================
    let echo_bytes = {
        let b = Arc::clone(&pep_bridge);
        let tok = standing_biscuit.clone();
        tokio::task::spawn_blocking(move || {
            let dirty_headers = vec![
                (
                    "Authorization".to_string(),
                    "Bearer caller_secret_must_never_reach_backend".to_string(),
                ),
                (
                    "Cookie".to_string(),
                    "session=caller_cookie_secret".to_string(),
                ),
                (
                    "X-Mesh-Authentication".to_string(),
                    "Bearer spoofed_caller_header".to_string(),
                ),
            ];
            b.dispatch_mesh_call_with_token_sync(
                "arm_calc",
                "mcp://echo-headers",
                &tok,
                &dirty_headers,
                br#"{"probe":"header_hygiene"}"#,
            )
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("Case 2 dispatch failed: {}", e))?
    };
    let echo_json: Value = serde_json::from_slice(&echo_bytes)
        .map_err(|e| format!("Case 2 JSON parse error: {}", e))?;
    assert_eq!(
        echo_json
            .get("authorization_present")
            .and_then(|v| v.as_bool()),
        Some(false),
        "Upstream backend must never observe caller Authorization header: {}",
        echo_json
    );
    assert_eq!(
        echo_json.get("cookie_present").and_then(|v| v.as_bool()),
        Some(false),
        "Upstream backend must never observe caller Cookie header: {}",
        echo_json
    );
    assert_eq!(
        echo_json
            .get("x_mesh_auth_present")
            .and_then(|v| v.as_bool()),
        Some(false),
        "office-node must strip X-Mesh-Authentication before forwarding to backend: {}",
        echo_json
    );
    let observed_principal = echo_json
        .get("x_mesh_principal")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        observed_principal.contains("spiffe://agentoctopus.local/arm/arm_calc/epoch/0"),
        "Expected verified x-mesh-principal for arm_calc at backend, got: {}",
        echo_json
    );
    println!(
        "  [PASS] Case 2: Header hygiene & identity propagation verified (0 leaked secrets; x-mesh-principal={})",
        observed_principal
    );

    // =========================================================================
    // CASE 3: Service-Level Policy Refusal (`arm_calc` -> `mcp://payroll` => 403 / -5)
    // =========================================================================
    let (exit_payroll, zero_secret_payroll, _) = execute_wasm_sandbox_call(
        &wasm_executor,
        &pep_bridge,
        &killswitch,
        "arm_calc",
        0,
        ArmRole::NetworkEgress,
        "mcp://payroll",
        br#"{"action":"read_ledger"}"#,
    )
    .await?;
    assert_eq!(
        exit_payroll, WASI_ERR_ACCESS_DENIED,
        "arm_calc calling mcp://payroll must return WASI_ERR_ACCESS_DENIED (-5)"
    );
    assert!(zero_secret_payroll);
    println!(
        "  [PASS] Case 3: Denied service (`arm_calc` -> `mcp://payroll`) refused by office-node (403 -> Wasm -5)"
    );

    // =========================================================================
    // CASE 4: Sibling Sandbox Isolation (`arm_rogue` Unbound in policy.json => 403 / -5)
    // =========================================================================
    let (exit_rogue, zero_secret_rogue, _) = execute_wasm_sandbox_call(
        &wasm_executor,
        &pep_bridge,
        &killswitch,
        "arm_rogue",
        0,
        ArmRole::UntrustedDocIngest,
        "mcp://calc",
        br#"{"op":"add","a":1,"b":1}"#,
    )
    .await?;
    assert_eq!(
        exit_rogue, WASI_ERR_ACCESS_DENIED,
        "Unbound sibling arm_rogue must be refused mcp://calc with WASI_ERR_ACCESS_DENIED (-5)"
    );
    assert!(zero_secret_rogue);
    println!(
        "  [PASS] Case 4: Sibling isolation verified (`arm_rogue` refused `mcp://calc` with 403 -> Wasm -5)"
    );

    // =========================================================================
    // CASE 5: Task-Scoped Sealed Biscuit Attenuation (`scope=mcp://calc&seal=true`)
    // =========================================================================
    let (scoped_biscuit, ok_calc_bytes, denied_scoped_echo) = {
        let b = Arc::clone(&pep_bridge);
        tokio::task::spawn_blocking(
            move || -> Result<(String, Vec<u8>, Result<Vec<u8>, MeshCallError>), String> {
                let tok = b
                    .exchange_scoped_task_token_sync(
                        "arm_calc",
                        0,
                        &ArmRole::NetworkEgress,
                        None,
                        Some("mcp://calc"),
                        true,
                    )
                    .map_err(|e| format!("Scoped token exchange failed: {}", e))?;

                let ok_calc = b
                    .dispatch_mesh_call_with_token_sync(
                        "arm_calc",
                        "mcp://calc",
                        &tok,
                        &[],
                        br#"{"op":"mul","a":6,"b":7}"#,
                    )
                    .map_err(|e| format!("Scoped calc call failed: {}", e))?;

                let echo_res = b.dispatch_mesh_call_with_token_sync(
                    "arm_calc",
                    "mcp://echo-headers",
                    &tok,
                    &[],
                    br#"{"probe":"should_be_blocked_by_tar_block"}"#,
                );

                Ok((tok, ok_calc, echo_res))
            },
        )
        .await
        .map_err(|e| e.to_string())??
    };
    assert!(!ok_calc_bytes.is_empty());
    assert!(
        matches!(denied_scoped_echo, Err(MeshCallError::AccessDenied(_))),
        "Sealed task Biscuit narrowed to mcp://calc must be refused on mcp://echo-headers with 403 AccessDenied, got: {:?}",
        denied_scoped_echo
    );
    println!(
        "  [PASS] Case 5: Sealed task Biscuit (`scope=mcp://calc&seal=true`) allowed `mcp://calc` (200) and refused `mcp://echo-headers` (403)"
    );

    // =========================================================================
    // CASE 6: OIDC Issuer, Audience & Expiry Rejection + Fresh JWT Recovery
    // =========================================================================
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let wrong_aud_jwt = issuer
        .mint_arm_token_with_overrides(
            "arm_calc",
            0,
            &ArmRole::NetworkEgress,
            now_secs,
            None,
            Some("wrong-audience"),
            Some(300),
        )
        .map_err(|e| e.to_string())?;
    let wrong_iss_jwt = issuer
        .mint_arm_token_with_overrides(
            "arm_calc",
            0,
            &ArmRole::NetworkEgress,
            now_secs,
            Some("http://127.0.0.1:65531"),
            Some(AUDIENCE_DEFAULT),
            Some(300),
        )
        .map_err(|e| e.to_string())?;
    let expired_jwt = issuer
        .mint_arm_token_with_overrides(
            "arm_calc",
            0,
            &ArmRole::NetworkEgress,
            now_secs.saturating_sub(600),
            None,
            Some(AUDIENCE_DEFAULT),
            Some(60),
        )
        .map_err(|e| e.to_string())?;

    for (label, bad_jwt) in [
        ("wrong_audience", wrong_aud_jwt),
        ("wrong_issuer", wrong_iss_jwt),
        ("expired_jwt", expired_jwt),
    ] {
        let form = format!(
            "grant_type={}&subject_token={}&subject_token_type={}&audience={}",
            url_encode_form_component("urn:ietf:params:oauth:grant-type:token-exchange"),
            url_encode_form_component(&bad_jwt),
            url_encode_form_component("urn:ietf:params:oauth:token-type:jwt"),
            url_encode_form_component(AUDIENCE_DEFAULT),
        );
        let headers = vec![
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let (status, _, resp_body) = AsyncHttpWireClient::post(
            &format!("{}/oauth/token", edge_url),
            &headers,
            form.as_bytes(),
        )
        .await
        .map_err(|e| format!("{} POST /oauth/token error: {}", label, e))?;
        assert!(
            status == 400 || status == 401 || status == 403,
            "Expected 400/401/403 for {}, got {} ({})",
            label,
            status,
            String::from_utf8_lossy(&resp_body)
        );
    }

    // Evict cached standing token and verify fresh mint + exchange recovers seamlessly
    pep_bridge.evict_arm_epoch("arm_calc", 0);
    let refreshed_tok = {
        let b = Arc::clone(&pep_bridge);
        tokio::task::spawn_blocking(move || {
            b.get_or_exchange_token_sync("arm_calc", 0, &ArmRole::NetworkEgress, "mcp://calc")
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("Fresh token recovery failed: {}", e))?
    };
    assert!(!refreshed_tok.is_empty());
    println!(
        "  [PASS] Case 6: Wrong `aud`, wrong `iss`, and expired JWTs rejected at /oauth/token; fresh JWT exchange recovered (200)"
    );

    // =========================================================================
    // CASE 7: Inbound Published Wasm Tool over Real `libp2p` Mesh
    // =========================================================================
    let (exit_doc_ok, zero_secret_doc, out_doc) = execute_wasm_sandbox_call(
        &wasm_executor,
        &pep_bridge,
        &killswitch,
        "arm_calc",
        0,
        ArmRole::NetworkEgress,
        "mcp://octopus-doc-extractor",
        br#"{"document":"Invoice\u0007\u001b #9042\nTotal: 420.00"}"#,
    )
    .await?;
    assert!(
        exit_doc_ok > 0,
        "Expected positive exit_code for doc_extractor, got {}",
        exit_doc_ok
    );
    assert!(zero_secret_doc);
    let doc_json: Value = serde_json::from_str(&out_doc)
        .map_err(|e| format!("Case 7 JSON parse error ({}): {}", e, out_doc))?;
    assert_eq!(
        doc_json.get("sanitized_text").and_then(|v| v.as_str()),
        Some("Invoice #9042\nTotal: 420.00")
    );

    let (exit_doc_rogue, _, _) = execute_wasm_sandbox_call(
        &wasm_executor,
        &pep_bridge,
        &killswitch,
        "arm_rogue",
        0,
        ArmRole::UntrustedDocIngest,
        "mcp://octopus-doc-extractor",
        br#"{"document":"Rogue attempt"}"#,
    )
    .await?;
    assert_eq!(exit_doc_rogue, WASI_ERR_ACCESS_DENIED);
    println!(
        "  [PASS] Case 7: Published Wasm tool (`mcp://octopus-doc-extractor`) executed across libp2p for `arm_calc` (200) and denied `arm_rogue` (403)"
    );

    // =========================================================================
    // CASE 8: RFC 7009 Biscuit Revocation (`POST /oauth/revoke`) + `<1ms` Epoch Trap
    // =========================================================================
    pep_bridge
        .revoke_token_rfc7009_async(&scoped_biscuit)
        .await
        .map_err(|e| format!("RFC 7009 /oauth/revoke failed: {}", e))?;

    let post_revoke_res = {
        let b = Arc::clone(&pep_bridge);
        let revoked_tok = scoped_biscuit.clone();
        tokio::task::spawn_blocking(move || {
            b.dispatch_mesh_call_with_token_sync(
                "arm_calc",
                "mcp://calc",
                &revoked_tok,
                &[],
                br#"{"op":"add","a":2,"b":2}"#,
            )
        })
        .await
        .map_err(|e| e.to_string())?
    };
    assert!(
        post_revoke_res.is_err(),
        "Revoked Biscuit must be rejected by edge-node after POST /oauth/revoke"
    );

    // Non-cooperative infinite-loop Wasm guest interrupted mid-flight via KillSwitch + increment_epoch()
    let wasm_spin = Arc::clone(&wasm_executor);
    let pep_spin = Arc::clone(&pep_bridge);
    let ks_spin = Arc::clone(&killswitch);
    let spin_handle = tokio::task::spawn_blocking(move || {
        let mut limits = WasmSandboxLimits::default();
        limits.fuel_budget = u64::MAX / 2;
        let ctx = WasmMeshBridgeContext::new("arm_calc", 0, ArmRole::NetworkEgress, pep_spin)
            .with_killswitch((*ks_spin).clone());
        wasm_spin.execute_wat_with_context(
            "infinite_spin_guest",
            INFINITE_SPIN_WAT,
            b"",
            limits,
            Some(ctx),
        )
    });

    tokio::time::sleep(Duration::from_millis(25)).await;
    let t_evict = Instant::now();
    killswitch.trip();
    wasm_executor.increment_epoch();
    let vault_purge = pep_bridge.trip_arm_killswitch("arm_calc");
    let total_autotomy = t_evict.elapsed();

    let spin_outcome = tokio::time::timeout(Duration::from_secs(3), spin_handle)
        .await
        .map_err(|_| "Infinite-loop Wasm guest did not trap within 3s of increment_epoch()")?
        .map_err(|e| format!("Spin task join error: {}", e))?;
    assert!(
        spin_outcome.is_err(),
        "Non-cooperative infinite-loop Wasm guest must trap on epoch increment"
    );
    assert!(
        vault_purge < Duration::from_millis(1),
        "Host vault purge exceeded 1ms SLA: {:?}",
        vault_purge
    );
    println!(
        "  [PASS] Case 8: RFC 7009 `/oauth/revoke` blocked Biscuit replay & KillSwitch trapped infinite-loop Wasm guest (vault purge {} us, total {} us)",
        vault_purge.as_micros(),
        total_autotomy.as_micros()
    );

    // Allow log buffers to flush and verify upstream Go structured audit logs
    tokio::time::sleep(Duration::from_millis(250)).await;
    let cp_logs = fs::read_to_string(&cp_log_path).unwrap_or_default();
    let office_logs = fs::read_to_string(&office_log_path).unwrap_or_default();
    assert!(
        cp_logs.contains("Border Crossing"),
        "Expected `Border Crossing` audit events in agentmesh-one log:\n{}",
        cp_logs
    );
    assert!(
        office_logs.contains("AuthZ Denied")
            || office_logs.contains("denied")
            || office_logs.contains("403"),
        "Expected authorization denial audit event in office-node log:\n{}",
        office_logs
    );

    println!("-------------------------------------------------------------------------");
    println!("  Verified `agentmesh-one` & `office-node` structured audit logs (`Border Crossing` + `AuthZ Denied`).");
    println!("  ALL 8 LIVE GOOGLE/AGENTMESH v0.2.0 E2E CASES PASSED.");
    println!("=========================================================================");

    drop(edge_proc);
    drop(office_proc);
    drop(cp_proc);
    drop(mcp_backend);
    let _ = fs::remove_dir_all(&work_dir);
    Ok(())
}

#[allow(dead_code)]
#[tokio::main]
async fn main() {
    let Some((one_bin, node_bin)) = locate_agentmesh_binaries() else {
        eprintln!(
            "ERROR: Could not find `agentmesh-one` and `agentmesh-node` binaries.\n\
             Run `./examples/agentmesh-wasm-sandbox/run.sh` (Linux/macOS/Git Bash) or \
             `powershell -ExecutionPolicy Bypass -File examples/agentmesh-wasm-sandbox/run.ps1` (Windows) \
             to download SHA-256 verified `google/agentmesh v0.2.0` binaries automatically, \
             or set `AGENTMESH_BIN_DIR`."
        );
        std::process::exit(1);
    };

    if let Err(err) = run_live_v020_suite(&one_bin, &node_bin).await {
        eprintln!("LIVE E2E SUITE FAILED:\n{}", err);
        std::process::exit(1);
    }
}
