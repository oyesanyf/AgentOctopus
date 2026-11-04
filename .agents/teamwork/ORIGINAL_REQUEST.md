# Original User Request

## Initial Request — 2026-11-04T17:35:05Z

Integrate Google AgentMesh (google/agentmesh#734) with AgentOctopus's wasmtime Tier 1 WebAssembly sandboxes, CAGE governance, and KillSwitch natively in Rust for production deployment across multi-agent environments, complete with an interactive WebUI, automated screen captures, full button/submenu testing, and an updated WiX MSI release build.

Working directory: d:\harfile\AgentOctopus
Integrity mode: development

Reference:
- google/agentmesh#734: https://github.com/google/agentmesh/issues/734
- Architectural Plan: C:\Users\oyesanyf\.gemini\antigravity\brain\fa6f75de-b8c5-4c80-a440-d7d12a44e713\agentmesh_killswitch_poc_plan.md

## Requirements

### R1. Zero-Socket Mesh Pore on `octopus_wasi` (Tier 1 Wasm Sandbox)
- Guest `.wasm` / `.wat` modules in `WasmTier1Executor` have zero ambient authority (no raw OS syscalls, sockets, environment variables, or `wasi_snapshot_preview1`).
- Add narrow host import `octopus_wasi::mesh_call` accepting only logical agentmesh URIs (`mcp://calc`, `a2a://...`, `inference://...`, `egress://...`) and request bytes—never raw IPs, DNS, or TCP sockets.

### R2. Host-Only Secret Vault, RFC 8693 Token Exchange & Zero-Mutual-Information Projection
- Per-invocation identity (`agent_id`, `ArmRole`, `generation_epoch`) and CAGE `RoutingSeal` stay strictly in Rust host state (`Store<WasmHostState>`), never entering the 64 MiB Wasm linear memory.
- On `mesh_call`, the host exchanges the arm's `ES256` workload JWT via RFC 8693 `POST /oauth/token`, injects `X-Mesh-Authentication` via `AgentMeshPepBridge`, strips incoming sensitive caller headers (`Authorization`, `Cookie`, `X-Mesh-*`), runs the upstream response through `ZeroMutualInformationProjector`, and copies only the sanitized result slice into guest linear memory (`WASI_ERR_ACCESS_DENIED = -5` on 403 mesh refusal).

### R3. Sub-Millisecond KillSwitch Eviction & Wasm Epoch Trapping
- Tripping `KillSwitch` simultaneously calls `engine.increment_epoch()` (trapping any running `.wasm` loop immediately via `epoch_interruption(true)`), cancels any in-flight host `mesh_call`, and evicts the arm's cached `X-Mesh-Authentication` token in `<1ms`, closing the 5-minute token-expiry window noted in #734.

### R4. Bidirectional Tier 1 Wasm Mesh Routing in `TieredExecutionDispatcher` & `ArmContainmentRing`
- Outbound (`Sandbox -> Mesh`): Two isolated Tier 1 `.wat` / `.wasm` sandboxes (`arm_calc` vs `arm_rogue`) call `mcp://calc` and `mcp://payroll` under distinct per-sandbox workload identities (`200` allowed vs `403` / `WASI_ERR_ACCESS_DENIED = -5` refused, zero sibling permission borrowing).
- Inbound (`Mesh -> Sandbox`): Publish AgentOctopus's SHA-256-cached Tier 1 Wasm tools (`mcp://octopus/doc_extractor`, `mcp://octopus/ledger_validator`) onto agentmesh, gating every inbound mesh request through `X-Mesh-Authentication` verification and `ArmContainmentRing::execute_tool_with_cage_seal` before executing in `ExecutionTier::Tier1InProcessWasm`.
- Implement a native loopback HTTP `AgentMeshReferenceNode` in Rust conforming to the agentmesh specification (`POST /oauth/token`, `GET /.well-known/jwks.json`, `/mesh/` routing) so all tests execute fully self-contained. Integrate `OpenShellRuntime` with `AgentMeshPepBridge` enforcing `default_network_deny: true`, `wasm_fuel_limit`, and `wasm_epoch_deadline`.

### R5. Interactive Production WebUI Dashboard & Submenu Verification (Zero Mocks)
- Wire the AgentMesh + Tier 1 Wasm + CAGE + KillSwitch integration directly into the live `AgentOctopus` WebUI (`src/web/` frontend and REST handlers in `src/web/api.rs` and `src/web/server.rs`).
- Every button and interactive control across the WebUI (including all existing submenus and the new AgentMesh/Wasm/CAGE/KillSwitch controls: triggering real outbound/inbound mesh Wasm tasks, inspecting live `ES256` JWKS & RFC 8693 token exchange, validating CAGE policies/seals, and tripping/regenerating `<1ms` KillSwitch epochs) must execute genuine backend operations with zero dummy placeholders or fake mocks.
- Extend and run automated UI / submenu tests (`scripts/test_all_submenus.py` and browser automation checks) against the running server to verify every button and endpoint behaves correctly.

### R6. Real Screen Capture Verification
- Launch the live `AgentOctopus` WebUI and capture real browser screenshots of the active dashboard panels demonstrating working interactive buttons, successful allowed mesh executions, denied/quarantined mesh attempts, and `<1ms` KillSwitch revocation in action.

### R7. Solo Release Build, WiX MSI (`AgentOctopus.msi`), and GitHub Release Overwrite
- Build production release binaries (`cargo build --release`), package a genuine Windows Installer `AgentOctopus.msi` via WiX and archive bundle (`AgentOctopus-windows-x64.zip`) with `SHA256SUMS.txt`.
- Mandatory Invariants:
  - WiX configuration must never use `<Environment Id="PATH" ...>` in any `.wxs`/`.wxi` file—rely exclusively on application folder shortcuts and launcher batch files so user/system `PATH` is never modified or wiped.
  - Never leave `.msi` or `.zip` files untracked in the git working tree.
  - Ship exclusively in `d:\harfile\AgentOctopus` (`https://github.com/oyesanyf/AgentOctopus`), verifying `git rev-parse --show-toplevel` and origin remote before write.
  - Overwrite/update the existing GitHub release on `oyesanyf/AgentOctopus` (`gh release upload --clobber` or release replacement using UTF-8 `--notes-file`, never inline backtick-corrupted `--notes`).

## Acceptance Criteria

### Wasm Sandbox Mesh Pore & Secret Isolation
- [ ] Guest `.wasm` modules have zero sockets, environment variables, or mesh credentials inside the 64 MiB linear memory.
- [ ] Host bridge exposes `octopus_wasi::mesh_call` accepting only logical `mcp://`, `a2a://`, `inference://`, and `egress://` URIs and returns `WASI_ERR_ACCESS_DENIED = -5` on unauthorized access or mesh refusal.
- [ ] Out-of-sandbox `AgentMeshPepBridge` strips sensitive incoming caller headers (`Authorization`, `Cookie`, `X-Mesh-*`), injects `X-Mesh-Authentication`, and projects response payloads through `ZeroMutualInformationProjector`.

### Sub-Millisecond KillSwitch Autotomy & Revocation
- [ ] Tripping `KillSwitch` traps running Wasm guest loops via `engine.increment_epoch()` and evicts cached `X-Mesh-Authentication` credentials in `<1ms`.
- [ ] Post-KillSwitch mesh calls fail closed (`WASI_ERR_ACCESS_DENIED = -5` / HTTP 403), advancing generation epoch `N -> N + 1`.

### Bidirectional Routing & Sibling Sandbox Isolation
- [ ] Outbound mesh calls from isolated sandboxes (`arm_calc` vs `arm_rogue`) enforce distinct workload identities without sibling permission borrowing.
- [ ] Inbound mesh requests to published tools (`mcp://octopus/doc_extractor`, `mcp://octopus/ledger_validator`) require valid `X-Mesh-Authentication` and unconsumed CAGE `RoutingSeal`.
- [ ] `OpenShellRuntime` enforces dual-boundary containment with `default_network_deny: true`, `wasm_fuel_limit`, and `wasm_epoch_deadline`.
- [ ] Native loopback conformance node supports RFC 8693 token exchange, JWKS verification, and mesh tool routing.

### Production WebUI & Submenu Verification (Zero Mocks)
- [ ] All AgentMesh, Wasm, CAGE, and KillSwitch WebUI controls connect to live backend endpoints and perform real operations with no hardcoded mocks.
- [ ] Every WebUI button and submenu functions correctly when tested against the running server via `scripts/test_all_submenus.py` or browser automation.
- [ ] Live browser screenshots are captured showing active WebUI panels, successful operations, policy denials, and KillSwitch autotomy.

### Release Packaging & Distribution
- [ ] Release binaries compile cleanly (`cargo build --release`) and all tests in `tests/agentmesh_killswitch_poc_tests.rs` pass.
- [ ] WiX MSI installer (`AgentOctopus.msi`) builds without `<Environment Id="PATH" ...>` tags and produces a clean `AgentOctopus-windows-x64.zip` bundle with `SHA256SUMS.txt`.
- [ ] GitHub release on `oyesanyf/AgentOctopus` is updated/overwritten with new release assets and clean UTF-8 notes, leaving a clean git working tree.


## Follow-up — 2026-11-04T18:06:35Z

mature any agentmesh compoment that is not matured

Actionable requirements for Project Orchestrator and all M1–M5 workers/reviewers/auditors:
1. **Production-Grade Maturity (Zero Prototypes / Zero Dev-Only Shortcuts)**:
   - Every AgentMesh component implemented or touched—including OIDC `ES256` workload identity (`oidc_actor_issuer`), RFC 8693 token exchange, Biscuit-style `tar_block` mandate attenuation (`mandate_attenuation`), `AgentMeshPepBridge` (`pep_bridge`), `AgentMeshReferenceNode`, AND AgentOctopus's existing inter-arm mesh (`src/neural_mesh.rs` / `src/containment_ring/mesh_guard.rs`)—must be **fully production-matured**, never left as a prototype or stub.
2. **Specifically Mature Every Upstream `agentmesh` v0.2.0 / `#734` & `NeuralMesh` Gap**:
   - **Mature `src/neural_mesh.rs` Integration**: Upgrade/bridge `NeuralMesh` beyond its prototype comments so it supports typed `agentmesh` URI schemes (`mcp://`, `a2a://`, `inference://`, `egress://`), dual `publish` + `call` capability grants (preventing tool/model discovery spoofing), bounded LRU/capacity eviction on `seen_nonces` (preventing unbounded memory growth), and constant-time MAC/signature verification.
   - **Mature OIDC / STS / Token Lifecycle**:
     - Production `ES256` key rotation (`current` + `retired` overlap grace period with `kid` dispatch and automatic retirement cleanup).
     - Bounded `jti` replay-prevention cache and bounded token vault capacity (zero unbounded `HashMap`/`HashSet` OOM vectors).
     - Proactive pre-expiry token refresh + strict `<= 5s` clock-skew handling returning clean RFC-compliant `401 Unauthorized` (`WWW-Authenticate: Bearer`) rather than `400` leeway mismatches.
   - **Mature Revocation & Fault Tolerance**:
     - Close `agentmesh`'s 5-minute exchanged-token revocation gap on BOTH sides: `<1ms` host vault purge + `engine.increment_epoch()` Wasm trap on `KillSwitch::trip()`, PLUS active revocation/epoch-list enforcement on the serving node so a stolen token cannot be replayed externally either.
     - Zero `.unwrap()` / `.expect()` panics on untrusted network, HTTP, JWT, or Wasm guest inputs; strict payload size caps, timeouts, and fail-closed behavior when upstream nodes are unreachable.


## Follow-up Directive — 2026-11-04T18:06:56Z

User message:
> mature any agentmesh compoment that is not matured

Actionable requirements across M1–M5:
1. **Production-Grade Maturity (Zero Prototypes / Zero Dev-Only Shortcuts)**:
   - Every AgentMesh component implemented or touched—including OIDC `ES256` workload identity (`oidc_actor_issuer`), RFC 8693 token exchange, Biscuit-style `tar_block` mandate attenuation (`mandate_attenuation`), `AgentMeshPepBridge` (`pep_bridge`), `AgentMeshReferenceNode`, AND AgentOctopus's existing inter-arm mesh (`src/neural_mesh.rs` / `src/containment_ring/mesh_guard.rs`)—must be **fully production-matured**, never left as a prototype or stub.
2. **Specifically Mature Every Upstream `agentmesh` v0.2.0 / `#734` & `NeuralMesh` Gap**:
   - **Mature `src/neural_mesh.rs` Integration**: Upgrade/bridge `NeuralMesh` beyond its prototype comments so it supports typed `agentmesh` URI schemes (`mcp://`, `a2a://`, `inference://`, `egress://`), dual `publish` + `call` capability grants (preventing tool/model discovery spoofing), bounded LRU/capacity eviction on `seen_nonces` (preventing unbounded memory growth), and constant-time MAC/signature verification.
   - **Mature OIDC / STS / Token Lifecycle**:
     - Production `ES256` key rotation (`current` + `retired` overlap grace period with `kid` dispatch and automatic retirement cleanup).
     - Bounded `jti` replay-prevention cache and bounded token vault capacity (zero unbounded `HashMap`/`HashSet` OOM vectors).
     - Proactive pre-expiry token refresh + strict `<= 5s` clock-skew handling returning clean RFC-compliant `401 Unauthorized` (`WWW-Authenticate: Bearer`) rather than `400` leeway mismatches.
   - **Mature Revocation & Fault Tolerance**:
     - Close `agentmesh`'s 5-minute exchanged-token revocation gap on BOTH sides: `<1ms` host vault purge + `engine.increment_epoch()` Wasm trap on `KillSwitch::trip()`, PLUS active revocation/epoch-list enforcement on the serving node so a stolen token cannot be replayed externally either.
     - Zero `.unwrap()` / `.expect()` panics on untrusted network, HTTP, JWT, or Wasm guest inputs; strict payload size caps, timeouts, and fail-closed behavior when upstream nodes are unreachable.


## Follow-up — 2026-11-04T18:33:52Z

this is not a POC  I wanted production grade integration

Mandatory architectural and naming requirements across entire codebase, API, WebUI, tests, and release:
1. **Eliminate ALL `poc` / `PoC` / `Proof of Concept` Naming & Framing Everywhere**:
   - Module directory & Rust module name MUST be `src/security/agentmesh/` (`pub mod agentmesh;`), NOT `src/security/agentmesh_poc/`.
   - Public structs & types MUST use canonical production names: e.g., `AgentMeshEngine`, `AgentMeshServingNode` / `AgentMeshGatewayNode`, `OctopusOidcActorIssuer`, `AttenuatedMeshMandate`, `AgentMeshPepBridge` — ZERO `Poc` or `poc` substrings in any struct, function, enum, route, filename, or WebUI label.
   - Production HTTP routes: use `/api/agentmesh/status`, `/api/agentmesh/wasm-call`, `/api/agentmesh/killswitch/trip`, `/api/agentmesh/mandates/attenuate`, `/oauth/token`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/mesh/mcp/octopus/doc_extractor`, and `/mesh/mcp/octopus/ledger_validator`.
   - Test suite & docs naming: use production names such as `tests/agentmesh_production_integration_tests.rs` and `docs/AGENTMESH_PRODUCTION_GUIDE.md` — never `*_poc_*`. Zero `"PoC"` / `"Proof of Concept"` strings in WebUI dashboard, docstrings, or GitHub release notes.
2. **True Production-Grade Engineering Depth**:
   - `AgentMeshPepBridge` and `AgentMeshEngine` must operate as first-class production subsystems wired into `ArmContainmentRing`, `WasmTier1Executor`, `TieredExecutionDispatcher`, `OpenShellRuntime`, `NeuralMesh`, `SecurityAuditLog`, and `WebState` by default in live `agent_octopus` server deployments.
   - Support both embedded/local `AgentMeshServingNode` operation AND configurable remote upstream `agentmesh` cluster endpoints (`AGENTMESH_UPSTREAM_URL` / runtime config) over real HTTP with timeouts, payload bounds, active revocation lists, key rotation (`current` + `retired`), bounded caches, and `<1ms` `KillSwitch` + `increment_epoch()` enforcement.
   - Auditors must explicitly grep and verify zero `poc` / `PoC` identifiers or prototype shortcuts remain anywhere in the AgentMesh integration.


## Follow-up Directive — 2026-11-04T18:34:17Z

User message:
> this is not a POC  I wanted production grade integration

Mandatory requirements across M1–M5:
1. **Eliminate ALL `poc` / `PoC` / `Proof of Concept` Naming & Framing Everywhere**:
   - Module directory & Rust module name MUST be **`src/security/agentmesh/`** (`pub mod agentmesh;`), **NOT** `src/security/agentmesh_poc/`.
   - Public structs & types MUST use canonical production names: `AgentMeshEngine` (or `AgentMeshRuntime`), `AgentMeshServingNode` / `AgentMeshGatewayNode`, `OctopusOidcActorIssuer`, `AttenuatedMeshMandate`, `AgentMeshPepBridge` — **ZERO `Poc` or `poc` substrings in any struct, function, enum, route, filename, or WebUI label**.
   - Production HTTP routes: use `/api/agentmesh/status` (NOT `/api/agentmesh/poc-status`), `/api/agentmesh/wasm-call`, `/api/agentmesh/killswitch/trip`, `/api/agentmesh/mandates/attenuate`, `/oauth/token`, `/.well-known/openid-configuration`, `/.well-known/jwks.json` (`/jwks`), `/mesh/mcp/octopus/doc_extractor`, and `/mesh/mcp/octopus/ledger_validator`.
   - Test suite & docs naming: use production names such as `tests/agentmesh_production_integration_tests.rs` (or `tests/agentmesh_integration_tests.rs`) and `docs/AGENTMESH_PRODUCTION_GUIDE.md` — never `*_poc_*`, and ensure zero `"PoC"` / `"Proof of Concept"` strings appear in the WebUI dashboard, docstrings, or GitHub release notes.
2. **True Production-Grade Engineering Depth**:
   - `AgentMeshPepBridge` and `AgentMeshEngine` must operate as first-class production subsystems wired into `ArmContainmentRing`, `WasmTier1Executor`, `TieredExecutionDispatcher`, `OpenShellRuntime`, `NeuralMesh`, `SecurityAuditLog`, and `WebState` by default in live `agent_octopus` server deployments.
   - Support both embedded/local `AgentMeshServingNode` operation AND configurable remote upstream `agentmesh` cluster endpoints (`AGENTMESH_UPSTREAM_URL` / runtime config) over real HTTP with timeouts, payload bounds, active revocation lists, key rotation (`current` + `retired`), bounded caches, and `<1ms` `KillSwitch` + `increment_epoch()` enforcement.
   - Auditors (`auditor_m1`..`m5` and victory auditor) must explicitly grep and verify zero `poc` / `PoC` identifiers or prototype shortcuts remain anywhere in the AgentMesh integration.


## Follow-up — 2026-11-04T19:13:53Z

STRATEGIC & ARCHITECTURAL REFINEMENT DECISION — Incorporate into M1–M5, WebUI, Documentation, and Release Notes:

1. **Complementary Two-Layer Stack (Never Framed as Competitors)**:
   - **`google/agentmesh` (Transport, Discovery & WAN `libp2p` Relay Layer)**: Built around `agentmesh-node` (including official Windows binaries in `agentmesh_Windows_x86_64.zip` -> `agentmesh-node.exe`), `agentmesh-control-plane`, and `agentmesh-router` for cross-machine encrypted `libp2p` discovery, NAT traversal, and OIDC->Biscuit routing.
   - **`AgentOctopus` (Zero-Socket Execution & Runtime Governance Substrate Beneath `agentmesh-node`)**: Sits directly beneath `agentmesh-node`, trapping untrusted workloads in a 64 MiB zero-socket `Wasmtime` Tier 1 sandbox or native Windows `AppContainer` (Tier 2) with zero credentials in linear memory, gating every consequential call through the 7-tier `CAGE` pipeline (`RoutingSeal` + CBF + Fiscal), and revoking cached mesh credentials + trapping Wasm execution in `<1ms` via `KillSwitch` + `engine.increment_epoch()`.

2. **Dual-Backend Plug-In Architecture in `AgentMeshPepBridge` & WebUI**:
   - **Standalone / Single-Host Mode (Default)**: Uses the built-in pure-Rust `AgentMeshServingNode` with zero external binary dependencies.
   - **External `agentmesh-node` / `agentmesh-node.exe` Sidecar Mode (`AGENTMESH_NODE_URL` / `AGENTMESH_UPSTREAM_URL` or configurable in WebUI)**: Plugs directly into a running upstream `agentmesh-node` / `agentmesh-node.exe` over localhost HTTP (`POST /oauth/token` RFC 8693 exchange + `/mesh/` proxy with `X-Mesh-Authentication`) so users automatically gain `agentmesh`'s WAN `libp2p` relay and NAT traversal while `AgentOctopus` enforces local Wasmtime/AppContainer isolation, CAGE governance, and `<1ms` `KillSwitch` cut-off.
   - Expose this live transport topology indicator & upstream node URL selector/probe in the WebUI AgentMesh panel (`Embedded Rust Mesh Node` vs `Connected to External agentmesh-node`).

3. **Accurate, Constructive Upstream Framing in Docs & Release Notes**:
   - Explicitly note that upstream `google/agentmesh` ships `agentmesh_Windows_x86_64.zip` (`agentmesh-node.exe`) for Windows alongside Linux builds (do NOT claim `agentmesh` cannot run on Windows).
   - Frame `AgentOctopus` constructively as the complementary zero-socket Wasmtime/AppContainer execution and CAGE/`KillSwitch` governance substrate that pairs seamlessly with `agentmesh-node` so neither layer has to compromise.


## Follow-up — 2026-11-04T19:18:46Z

CRITICAL ARCHITECTURAL HARDENING DIRECTIVE — Remediate All 6 Validated Security & Ergonomic Weaknesses Across M1–M5:

1. **Weakness 1: Active In-Flight Stream Abort + Signed Remote Cancellation (`pep_bridge.rs` & `serving_node.rs`)**:
   - In-flight cancellation via `tokio_util::sync::CancellationToken` dropping TCP/HTTP stream in `<1ms` on `KillSwitch::trip()`.
   - Signed `POST /mesh/revoke` (`SignedEpochRevocationSignal { arm_id, revoked_up_to_epoch, jti_list, timestamp_ms, signature }`) to serving node and remote sidecar.

2. **Weakness 2: Linux Tier 2 Kernel Confinement Parity (`src/security/linux_sandbox.rs` + `src/security/windows_sandbox.rs:1690`)**:
   - `src/security/linux_sandbox.rs` (`#[cfg(target_os = "linux")]`) via `libc` and `CommandExt::pre_exec`: `PR_SET_NO_NEW_PRIVS`, deterministic `setrlimit`, Linux Landlock LSM, and seccomp-BPF zero-socket enforcement (`socket(AF_INET, ...)` -> `EACCES`).
   - Clean compilation on both Windows MSVC and Ubuntu Linux.

3. **Weakness 3: Pure-Rust Cross-WAN P2P Relay, AutoNAT & Hole-Punch Transport (`src/security/agentmesh/wan_transport.rs`)**:
   - Native pure-Rust `AgentMeshWanTransport` using `chacha20poly1305`, `zeroize`, `ed25519-dalek`, `ml-kem`, and `tokio::net`: AutoNAT dial-back probing, Circuit Relay v2 with post-quantum ML-KEM-768 + Ed25519 + ChaCha20-Poly1305 AEAD, and DCUtR-style direct connection hole-punching.

4. **Weakness 4: Localhost Daemon Mutual Authentication & IPC Lockdown (`pep_bridge.rs` & `serving_node.rs`)**:
   - Ephemeral mutual channel secret (`X-Octopus-Pep-Channel-Proof`, `X-Octopus-Pep-Nonce`, `X-Octopus-Pep-Timestamp`, `X-Octopus-Node-Proof`) binding HTTP method, path, body hash, and CAGE seal in constant time. Fail-closed (`403 PEP_CHANNEL_AUTH_REQUIRED`) on unauthenticated local callers.
   - In-process `tokio::io::duplex` anonymous IPC pipe mode for zero-open-port deployments.

5. **Weakness 5: Privilege-Separated Key Broker & OS Key Protection (`src/security/agentmesh/key_broker.rs`)**:
   - `MeshKeyBroker` trait with `OsProtectedKeyBroker` (Windows DPAPI / `CryptProtectData` via `windows-sys`, Linux kernel keyring / `memfd_secret`, `zeroize`) and `OutOfProcessIpcKeyBroker` (zero raw private keys in Wasmtime worker process).

6. **Weakness 6: Virtual WASI Mesh Stream Shim + Seamless Tier 2 Confined Fallback (`wasm_tier1.rs` & `tiered_executor.rs`)**:
   - Virtual WASI stream descriptors on `"octopus_wasi"` (`mesh_stream_open`, `mesh_stream_read`, `mesh_stream_write`, `mesh_stream_close`) with bounded virtual FD table (max 16).
   - Seamless Tier 1 -> Tier 2 confined mesh fallback in `TieredExecutionDispatcher` mediated via `AgentMeshPepBridge` and CAGE `RoutingSeal`.

7. **Pre-Submission & Documentation Precision (`docs/AGENTMESH_PRODUCTION_GUIDE.md` & WebUI)**:
   - Pin `wasmtime v49.0.4`.
   - ZERO `poc` / `PoC` substrings everywhere; integration test suite named `tests/agentmesh_integration_tests.rs`.
   - Surface live telemetry & controls in WebUI AgentMesh panel.
   - Constructive upstream framing to `@aojea` and maintainers.
