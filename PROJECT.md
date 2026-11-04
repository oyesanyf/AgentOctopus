# Project: Google AgentMesh (#734) × AgentOctopus Tier 1 Wasm, CAGE & KillSwitch Production Integration

## Architecture
AgentOctopus integrates Google AgentMesh (`google/agentmesh#734`, `sam-mesh.dev`, Apache-2.0) with its `wasmtime v49.0` WebAssembly sandboxes (`WasmTier1Executor`), CAGE governance (`CageGovernanceEngine`), cephalopod autotomy circuit breaker (`KillSwitch`), and inter-arm neural mesh (`src/neural_mesh.rs`, `src/containment_ring/mesh_guard.rs`).

### Invariant: Zero Prototypes / Complete Production Maturity (Zero "POC" / "PoC" Artifacts)
Every AgentMesh component—including OIDC `ES256` workload identity (`oidc_actor_issuer`), RFC 8693 token exchange, Biscuit-style `tar_block` mandate attenuation (`mandate_attenuation`), `AgentMeshPepBridge` (`pep_bridge`), `AgentMeshServingNode` (`serving_node`), `AgentMeshEngine` (`mod.rs`), AND AgentOctopus's existing inter-arm mesh (`src/neural_mesh.rs` / `src/containment_ring/mesh_guard.rs`)—must be **fully production-matured**.
- Canonical production module: **`src/security/agentmesh/`** (`pub mod agentmesh;`).
- Zero `poc` / `PoC` substrings in any struct, function, enum, route, filename, test, or WebUI label.

### Data Flow & Component Interfaces
1. **Host-Only Secret Vault & RFC 8693 Token Exchange (`src/security/agentmesh/`)**:
   - `OctopusOidcActorIssuer`: Mints RFC 7515 `ES256` P-256 JWTs (`spiffe://agentoctopus.local/arm/{arm_id}/epoch/{epoch}`) and publishes RFC 7517 EC JWKS at `/.well-known/jwks.json` and OpenID discovery at `/.well-known/openid-configuration` with `current` + `retired` key rotation grace overlap, bounded `jti` replay cache, and strict `<= 5s` clock-skew tolerance.
   - `AgentMeshPepBridge`: Acts as out-of-sandbox policy enforcement point and secret vault. Strips caller `Authorization`, `Cookie`, and `X-Mesh-*` headers; performs RFC 8693 Token Exchange (`POST /oauth/token`); injects `X-Mesh-Authentication: Bearer <token>`; and purges arm tokens in `<1ms` on `KillSwitch::trip()`. Enforces bounded capacity on token vault (no memory leak).
   - `AttenuatedMeshMandate`: Enforces capability attenuation with Ed25519 signature chaining, strict URI schemes (`mcp://`, `a2a://`, `inference://`, `egress://`), segregated `allowed_services` + `allowed_publish`, zero holder-supplied Datalog rules, and monotonic intersection.
   - `AgentMeshServingNode`: Embedded loopback HTTP node implementing AgentMesh `policy.json` (`roles`, `allowed_services`, `allowed_publish`, `bindings`), JWKS verification, active revocation/epoch-list enforcement (dual-side #734 defense), and `/mesh/` service routing. Supports upstream cluster routing via `AGENTMESH_UPSTREAM_URL`.
   - `AgentMeshEngine`: Unified production runtime coordinator coordinating issuer, bridge, mandate attenuation, and serving node.
2. **Production-Matured `NeuralMesh` Inter-Arm Integration (`src/neural_mesh.rs`, `src/containment_ring/mesh_guard.rs`)**:
   - Upgrades `NeuralMesh` from prototype to production maturity:
     - Supports typed `agentmesh` URI schemes (`mcp://`, `a2a://`, `inference://`, `egress://`).
     - Enforces dual `allowed_publish` + `allowed_services` capability grants, preventing tool/model discovery spoofing.
     - Implements bounded LRU/capacity eviction on `seen_nonces` (preventing unbounded memory growth / OOM).
     - Uses constant-time MAC and signature verification.
3. **Zero-Socket Mesh Pore on Tier 1 Wasm Sandbox (`src/security/wasm_tier1.rs`)**:
   - Guest `.wasm` / `.wat` modules execute with zero ambient authority (no sockets, no raw IP access, zero tokens/keys in 64 MiB linear memory).
   - Host import `octopus_wasi::mesh_call(uri_ptr, uri_len, req_ptr, req_len, resp_ptr, resp_cap) -> i32` accepts only logical `mcp://`, `a2a://`, `inference://`, `egress://` URIs and request bytes.
   - Host reads request from guest memory, checks `KillSwitch`, delegates to `AgentMeshPepBridge`, projects upstream response through `ZeroMutualInformationProjector` ($\Pi_0$), and copies only sanitized bytes into guest memory (`WASI_ERR_ACCESS_DENIED = -5` on refusal). Zero `.unwrap()` / `.expect()` panics.
4. **Sub-Millisecond KillSwitch Eviction & Non-Cooperative Wasm Trapping (`#734` Solution)**:
   - On `KillSwitch::trip()`, atomic store occurs in ~10ns.
   - Simultaneously calls `engine.increment_epoch()`, trapping active Wasm guest loops immediately via `epoch_interruption(true)`.
   - Evicts cached `(arm_id, epoch)` mesh credentials from `AgentMeshPepBridge` in `<1ms`, closing the 5-minute token expiry window identified in #734. Advances generation epoch $N \to N + 1$. Serving node additionally rejects revoked arm credentials.
5. **Bidirectional Mesh Routing & Dual-Boundary Isolation (`src/containment_ring/`, `src/security/openshell.rs`)**:
   - Outbound (`Sandbox -> Mesh`): `TieredExecutionDispatcher` routes `arm_calc` (200 OK) vs `arm_rogue` (403 denied) with zero sibling permission borrowing, feeding `mesh_bytes_exchanged` into `MercuryContainmentEngine` (`HostActuationPore::InterAgentMeshIpc`).
   - Inbound (`Mesh -> Sandbox`): Published tools `mcp://octopus/doc_extractor` and `mcp://octopus/ledger_validator` gate requests via `X-Mesh-Authentication` and single-use CAGE `RoutingSeal` consumption (`execute_tool_with_cage_seal`).
   - `OpenShellRuntime`: Enforces dual-boundary containment with `default_network_deny: true`, `wasm_fuel_limit`, and `wasm_epoch_deadline`.
6. **Interactive Production WebUI & Submenu Verification (`src/web/`)**:
   - Exempts `/.well-known/openid-configuration`, `/jwks`, and `/mesh/*` from browser session tokens in `request_guard.rs`.
   - Exposes REST endpoints in `api.rs` and `server.rs` (`/api/agentmesh/status`, `/api/agentmesh/wasm-call`, `/api/agentmesh/killswitch/trip`, etc.).
   - Adds Tab 17 (`agentmesh-runtime`) to `static_files.rs` with live interactive buttons and telemetry (zero dummy mocks, zero "PoC" labels).
   - Automated submenu testing in `scripts/test_all_submenus.py` and headless Chrome screen captures in `scripts/capture_dashboard_screens.py`.
7. **WiX v5 MSI Release Package & GitHub Solo Ship**:
   - WiX v5 MSI in `wix/AgentOctopus.wxs` strictly without `<Environment Id="PATH">`.
   - Production bundle `AgentOctopus-windows-x64.zip` with `SHA256SUMS.txt`.
   - Solo PR ship and GitHub release overwrite with clean UTF-8 notes.

---

## Feature Inventory

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F01 | Pure-Rust P-256 & Base64url Dependencies | Add `p256` (v0.13, ecdsa) and `base64` (v0.22) to `Cargo.toml` | M1 | Plan §1 |
| F02 | RFC 7515 `ES256` & RFC 7517 JWKS OIDC Actor Issuer | Mint SPIFFE workload JWTs (`spiffe://agentoctopus.local/arm/{arm_id}/epoch/{epoch}`) and publish EC JWKS with key rotation overlap & bounded jti cache | M1 | Survey & User Directive |
| F03 | RFC 8693 OAuth 2.0 Token Exchange | Implement `POST /oauth/token` exchange for workload JWTs with bounded vault cache | M1 | Survey |
| F04 | Mandate Attenuation & Strict URI Filter | Ed25519-signed capability chains, strict `mcp://`/`a2a://`/`inference://`/`egress://`, zero holder Datalog rules, monotonic intersection | M1 | Survey |
| F05 | Host PEP Header Hygiene | Strip caller `Authorization`, `Cookie`, `X-Mesh-*` headers; inject verified `X-Mesh-Authentication` | M1 | Survey |
| F06 | Zero-Mutual-Information Response Sanitization | Sanitize upstream responses with `ZeroMutualInformationProjector` before copying to Wasm memory | M1 | Survey |
| F07 | Native Production AgentMesh Serving Node | Embedded HTTP node implementing `policy.json` (`roles`, `allowed_services`, `allowed_publish`, `bindings`), STS, active revocation list, and `/mesh/` routing | M1 | Survey & User Directive |
| F08 | Production Matured NeuralMesh & MeshGuard | Upgrade `src/neural_mesh.rs` and `src/containment_ring/mesh_guard.rs` with typed URIs, dual capability grants, bounded LRU nonces, and constant-time MAC | M1 | User Directive |
| F09 | Zero-Secret `WasmMeshBridgeContext` Host Binding | Host-only storage in `Store<WasmHostState>`, keeping 64 MiB linear memory free of secrets | M2 | Survey |
| F10 | `octopus_wasi::mesh_call` Capability Pore | Narrow host import filtering schemes, returning `WASI_ERR_ACCESS_DENIED = -5` on refusal | M2 | Survey |
| F11 | Built-in `WASM_MESH_CALLER_WAT` & Receipts | Built-in WAT guest module and execution receipt telemetry (`mesh_calls_attempted`, `mesh_calls_succeeded`, `mesh_bytes_exchanged`) | M2 | Survey |
| F12 | Sub-Millisecond KillSwitch Eviction (<1ms) | Evict cached `(arm_id, epoch)` tokens in `<1ms` upon circuit breaker trip | M2 | Survey |
| F13 | Wasm Engine Epoch Trapping | Trigger `engine.increment_epoch()` to immediately trap in-flight Wasm guest loops via `epoch_interruption(true)` | M2 | Survey |
| F14 | Outbound Mesh Routing (`Sandbox -> Mesh`) | Route isolated sandboxes (`arm_calc` vs `arm_rogue`) under distinct identities with zero sibling borrowing | M2 | Survey |
| F15 | Mercury Pore Pressure Egress Feedback | Feed `mesh_bytes_exchanged` into `MercuryContainmentEngine` (`HostActuationPore::InterAgentMeshIpc`) | M2 | Survey |
| F16 | Inbound Published Tools & CAGE Seal Gating | Gate inbound `mcp://octopus/doc_extractor` and `ledger_validator` via `X-Mesh-Authentication` and CAGE `RoutingSeal` | M2 | Survey |
| F17 | OpenShell Dual-Boundary Containment | Enforce `default_network_deny: true`, `wasm_fuel_limit`, and `wasm_epoch_deadline` over mesh pore | M2 | Survey |
| F18 | Web Request Guard Loopback & Mesh Exemptions | Exempt `/.well-known/openid-configuration`, `/jwks`, and `/mesh/*` in `request_guard.rs` | M3 | Survey |
| F19 | AgentMesh Production REST Web API Handlers | Expose discovery, jwks, wasm-call, inbound tools, killswitch trip, and status in `api.rs` and `server.rs` | M3 | Survey & User Directive |
| F20 | Interactive WebUI Dashboard Panel (Tab 17) | Production zero-mock dashboard panel with interactive controls for mesh calls, CAGE seals, autotomy, and JWKS | M3 | Survey |
| F21 | Automated Submenu Verification Suite | Extend `scripts/test_all_submenus.py` to systematically verify all Tab 17 endpoints against running server | M4 | Survey |
| F22 | Automated Headless Screen Capture | Script `scripts/capture_dashboard_screens.py` capturing live PNG screenshots of all active dashboard panels | M4 | Survey |
| F23 | WiX v5 MSI Installer Definition | Author `wix/AgentOctopus.wxs` with ZERO `<Environment Id="PATH">` tags, shortcuts to Program Menu/Desktop | M5 | Survey |
| F24 | Production Release Packaging & Checksums | `cargo build --release`, compile MSI, package `AgentOctopus-windows-x64.zip` with `SHA256SUMS.txt` | M5 | Survey |
| F25 | Solo GitHub Release Overwrite | Publish/overwrite release assets on `oyesanyf/AgentOctopus` using clean UTF-8 release notes | M5 | Survey |
| F26 | Comprehensive End-to-End Production Test Suite | Implement `tests/agentmesh_production_integration_tests.rs` covering all 8 core scenarios | M5 | Survey & User Directive |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | AgentMesh Production Core Engine & Matured NeuralMesh | `Cargo.toml`, `src/security/agentmesh/` (`oidc_actor_issuer.rs`, `mandate_attenuation.rs`, `pep_bridge.rs`, `serving_node.rs`, `key_broker.rs`, `wan_transport.rs`, `mod.rs`), `src/neural_mesh.rs`, `src/containment_ring/mesh_guard.rs`, registered in `src/security/mod.rs` (F01–F08, Weaknesses 1, 3, 4, 5) | none | DONE |
| M2 | Tier 1 Wasm Sandbox Mesh Pore & Sub-ms KillSwitch | `src/security/wasm_tier1.rs`, `src/containment_ring/tiered_executor.rs`, `src/security/openshell.rs`, `src/containment_ring/arm_ring.rs` (F09–F17) | M1 | PLANNED |
| M3 | Web API Endpoints & Zero-Mock Interactive Dashboard | `src/web/request_guard.rs`, `src/web/api.rs`, `src/web/server.rs`, `src/web/static_files.rs` Tab 17 (F18–F20) | M1, M2 | PLANNED |
| M4 | Automated Submenu Verification & Headless Screen Capture | `scripts/test_all_submenus.py` Tab 17 expansion, `scripts/capture_dashboard_screens.py`, live execution against server (F21–F22) | M1, M2, M3 | PLANNED |
| M5 | Final Milestone: 100% E2E Pass, WiX MSI Build & Solo GitHub Release | `tests/agentmesh_production_integration_tests.rs`, `wix/AgentOctopus.wxs`, `scripts/build_release_msi.ps1`, `scripts/publish_release.ps1`, ZIP + SHA256, GitHub release overwrite (F23–F26) | M4 | PLANNED |

---

## Interface Contracts

### M1 Core ↔ M2 Wasm Sandbox & Containment
- `AgentMeshPepBridge::dispatch_mesh_call_sync(&self, arm_id: &str, epoch: u64, role: &ArmRole, uri: &str, req_bytes: &[u8]) -> Result<Vec<u8>, MeshCallError>`
- `AgentMeshPepBridge::trip_arm_killswitch(&self, arm_id: &str) -> Duration`
- `WasmTier1Executor::increment_epoch(&self)`
- `WasmMeshBridgeContext`: Holds `arm_id`, `generation_epoch`, `role`, `killswitch`, `pep_bridge`, quotas.

### M1 Core ↔ NeuralMesh / MeshGuard
- `NeuralMesh::send_mesh_message(&self, msg: &NeuralMeshMessage) -> Result<(), NeuralMeshError>`
- `MeshGuard::verify_message(&self, msg: &NeuralMeshMessage) -> Result<bool, MeshGuardError>`
- Bounded LRU on `seen_nonces` with max capacity (e.g. 10,000 nonces) and constant-time HMAC-SHA256 comparison.

### M1/M2 ↔ M3 Web API
- `AgentMeshEngine::oidc_issuer(&self) -> &OctopusOidcActorIssuer`
- `AgentMeshEngine::pep_bridge(&self) -> &Arc<AgentMeshPepBridge>`
- `AgentMeshEngine::status(&self) -> AgentMeshStatus`
- `WebState::agentmesh_engine`: `Arc<AgentMeshEngine>`
- `TOKEN_EXEMPT_PATHS`: `"/.well-known/openid-configuration"`, `"/jwks"`, `/mesh/*`

### M3 Web ↔ M4 Submenu Verification & Screen Captures
- `GET http://127.0.0.1:<port>/?tab=agentmesh-runtime`
- `POST /api/agentmesh/wasm-call`
- `POST /api/agentmesh/killswitch/trip`
- `POST /mesh/mcp/octopus/doc_extractor`
- `reports/screenshots/`: `01_agentmesh_dashboard.png`, `02_wasm_outbound_allowed.png`, `03_wasm_outbound_denied.png`, `04_killswitch_autotomy.png`, `05_inbound_doc_extractor.png`

### M4 Verification ↔ M5 Packaging & Release
- All automated submenu tests pass (17/17 tabs, 0 failures).
- `cargo test --test agentmesh_production_integration_tests` passes (all 8 scenarios green).
- WiX v5 command: `& $WixCmd build wix\AgentOctopus.wxs -arch x64 -out AgentOctopus.msi`.
- Release archive: `AgentOctopus-windows-x64.zip` with `SHA256SUMS.txt`.
- GitHub CLI: `d:\tools\gh.exe release create v0.1.0 ... --notes-file <file> --clobber`.

---

## Code Layout

```
d:\harfile\AgentOctopus\
├── Cargo.toml                                         # [MODIFIED] Add p256, base64
├── src/
│   ├── security/
│   │   ├── mod.rs                                     # [MODIFIED] Register agentmesh
│   │   ├── agentmesh/                                 # [NEW] AgentMesh Production Engine
│   │   │   ├── mod.rs                                 # AgentMeshEngine coordinator
│   │   │   ├── oidc_actor_issuer.rs                   # ES256 P-256 JWT & EC JWKS
│   │   │   ├── mandate_attenuation.rs                 # Ed25519 mandate chains & URI filter
│   │   │   ├── pep_bridge.rs                          # Header hygiene, token vault, <1ms eviction
│   │   │   └── serving_node.rs                        # Production serving node & upstream bridge
│   │   ├── wasm_tier1.rs                              # [MODIFIED] octopus_wasi::mesh_call & context
│   │   └── openshell.rs                               # [MODIFIED] Dual-boundary mesh execution
│   ├── neural_mesh.rs                                 # [MODIFIED] Mature inter-arm mesh (bounded nonces, URIs)
│   ├── containment_ring/
│   │   ├── mesh_guard.rs                              # [MODIFIED] Constant-time MAC & dual capability grants
│   │   ├── tiered_executor.rs                         # [MODIFIED] Sandbox->Mesh routing & Mercury pore
│   │   └── arm_ring.rs                                # [MODIFIED] Autotomy & CAGE seal inbound gating
│   └── web/
│       ├── request_guard.rs                           # [MODIFIED] Exempt openid-config, jwks, /mesh/*
│       ├── api.rs                                     # [MODIFIED] WebState & 6 AgentMesh handlers
│       ├── server.rs                                  # [MODIFIED] Route dispatch matching
│       └── static_files.rs                            # [MODIFIED] Tab 17 AgentMesh interactive SPA
├── scripts/
│   ├── test_all_submenus.py                           # [MODIFIED] Tab 17 submenu test suite
│   ├── capture_dashboard_screens.py                   # [NEW] Headless Chrome screenshot automation
│   ├── build_release_msi.ps1                          # [NEW] Release binaries, WiX MSI, ZIP, SHA256
│   └── publish_release.ps1                            # [NEW] Solo GitHub release script
├── wix/
│   └── AgentOctopus.wxs                               # [NEW] WiX v5 installer definition (ZERO PATH)
├── tests/
│   └── agentmesh_integration_tests.rs                 # [NEW] Comprehensive E2E production test suite
└── PROJECT.md                                         # Global Project Index & Living Architecture
```

---

## Resume Checkpoint (`2026-11-04` — Paused on Hold)

- **Completed & Pushed**:
  - **Milestone 1 (`f601d86`, `5dbca73`)**: 100% passed `5/5` gate verification (`77/77` tests, `0` `PoC` tokens, Ubuntu & Windows CI green). Includes `oidc_actor_issuer.rs`, `mandate_attenuation.rs`, `pep_bridge.rs` (**W1** `CancellationToken` stream abort + **W4** mutual PEP-to-Node channel proofs), `serving_node.rs` (`POST /mesh/revoke`), `key_broker.rs` (**W5** Windows DPAPI + IPC broker), `wan_transport.rs` (**W3** pure-Rust `ML-KEM-768` + `ChaCha20-Poly1305` + AutoNAT + DCUtR), and matured `src/neural_mesh.rs`.
  - **Milestone 2 Part 1**: Implemented `octopus_wasi::mesh_call`, **W6** virtual WASI stream descriptors (`mesh_stream_open`/`write`/`read`/`close`), and `WasmMeshBridgeContext` in `src/security/wasm_tier1.rs` (`wasmtime v49.0.4`), plus synchronous `KillSwitch::trip()` -> `wasmtime::Engine::increment_epoch()` callback in `src/core/circuit_breaker.rs`.
- **Remaining Next Steps on Resume**:
  1. **Milestone 2 Part 2**: Wire CAGE `RoutingSeal` + Mercury + `OpenShellRuntime` + **W6** Tier 1 -> Tier 2 fallback (`arm_ring.rs`, `tiered_executor.rs`, `openshell.rs`) and **W2** Linux Tier 2 kernel confinement (`src/security/linux_sandbox.rs` Landlock + seccomp + `rlimit` + `CLONE_NEWNET` wired into `windows_sandbox.rs`).
  2. **Milestone 3**: Production WebUI AgentMesh controls (`src/web/`), `scripts/test_all_submenus.py` button verification, and live browser screenshots.
  3. **Milestone 4**: `tests/agentmesh_integration_tests.rs` + `docs/AGENTMESH_PRODUCTION_GUIDE.md` (`wasmtime v49.0.4`, constructive complementary framing for `@aojea` on `google/agentmesh#734`).
  4. **Milestone 5**: `cargo build --release`, zero-touch-`PATH` `AgentOctopus.msi` + `AgentOctopus-windows-x64.zip` + `SHA256SUMS.txt`, and GitHub release overwrite on `oyesanyf/AgentOctopus`.
