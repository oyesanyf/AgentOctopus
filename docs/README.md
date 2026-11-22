# AgentOctopus Documentation Hub and Index

**Docs:** [Hub](README.md) | [Architecture & Security](ARCHITECTURE_AND_SECURITY_MODEL.md) | [Kernel Shield](KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md) | [CLI & Policy](CLI_AND_POLICY_REFERENCE.md) | [Operations & API](OPERATIONS_AND_API_GUIDE.md) | [AgentMesh + Wasm](AGENTMESH_WASM_INTEGRATION.md) | [Red Teaming](ADVERSARIAL_DEFENSE_AND_RED_TEAMING.md) | [Root README](../README.md)

**AgentOctopus** is a single-binary Rust deterministic agent containment runtime (`AWS Cedar v4.13` + `Wasmtime v49.0.4` + native `OS Kernel Sandboxes` + `RT-ASP Sanitizers`), hardened with **R6** multi-OS kernel patching & zero-reboot virtual patching, **R7** `<2ms` pre-spawn REA binary gating, and **R8** pure-Rust `UnifiedSecurityShield` (`LatentWorldModel` SBOM & runtime guards).

---

## Role-Based Reading Paths

### 1. 5-Minute Quickstart
1. Read the [Root Quickstart](../README.md#30-second-1-command-cli-quickstart) and run `octopus run --policy examples/quickstart/policy.json -- python examples/quickstart/my_agent.py`.
2. Inspect [CLI and Policy Reference](CLI_AND_POLICY_REFERENCE.md#policy-recipes) for `.json`, `.cedar`, `.wasm`/`.wat`, `octopus hook`, and `octopus sbom-guard` recipes.

### 2. Staff Security Engineers and Threat-Model Reviewers
1. Start with [Architecture and Security Model](ARCHITECTURE_AND_SECURITY_MODEL.md#end-to-end-deterministic-containment-pipeline) for the deterministic enforcement graph and [Threat Model](ARCHITECTURE_AND_SECURITY_MODEL.md#threat-model).
2. Inspect [R7 Pre-Spawn REA Binary Gate](ARCHITECTURE_AND_SECURITY_MODEL.md#r7-pre-spawn-rea-binary-gate-under-2ms) and [R8 Pure-Rust UnifiedSecurityShield](ARCHITECTURE_AND_SECURITY_MODEL.md#r8-pure-rust-unifiedsecurityshield) (strictly tighten-only and distinct from optional offline D3QN).
3. Review [AWS Cedar v4.13 Schema (11 Entities and 13 Actions)](CLI_AND_POLICY_REFERENCE.md#aws-cedar-v413-schema-11-entities-and-13-actions) and [Vassilev Mathematical Validation](../reports/vassilev_mathematical_validation.md).

### 3. Platform, Ops, and Kernel Shield Engineers
1. Read [Kernel Patching and Zero-Breakout Shield](KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md) covering all 6 OS families, 17 Linux distributions, rebootless livepatch engines, and the 5 Foolproof Invariants (`shield_locked_until_reboot`, `telemetry_degraded_fail_closed`).
2. Follow [Operations and API Guide](OPERATIONS_AND_API_GUIDE.md) for the `127.0.0.1:3030` Web Dashboard, `X-Octopus-Token` REST API, Host KillSwitch (`isolate`/`restore`), `build_start_signed.ps1`, and Windows AppContainer ACL troubleshooting.

### 4. AgentMesh and Wasm Integrators
1. Read [Google AgentMesh x Wasm Integration](AGENTMESH_WASM_INTEGRATION.md) for OIDC/JWKS workload identity, Biscuit attenuation, `octopus_wasi` hostcalls, and `<1ms` epoch autotomy.
2. Run [`examples/agentmesh-wasm-sandbox/`](../examples/agentmesh-wasm-sandbox/README.md) (`run.sh` / `run.ps1`) or `cargo run --example agentmesh_wasm_sandbox_demo`.

### 5. Contributors and Red-Team Evaluators
1. Review [Adversarial Defense and Red Teaming](ADVERSARIAL_DEFENSE_AND_RED_TEAMING.md) for the multi-arm enclave, `TarpitArm`, and 19 red-teaming suites.
2. Run `cargo test`, `cargo doc --no-deps --all-features`, and `python -m tests.e2e_release --tier all`.

---

## Documentation and Example Map

| Resource | Audience | Summary |
|---|---|---|
| [`docs/README.md`](README.md) | All Users | Documentation Hub, role reading paths, source module map, and A–Z topic index. |
| [`docs/ARCHITECTURE_AND_SECURITY_MODEL.md`](ARCHITECTURE_AND_SECURITY_MODEL.md) | Security Engineers | End-to-end deterministic pipeline, 4 containment pillars, R7 `<2ms` REA gate, R8 `UnifiedSecurityShield`, threat model. |
| [`docs/KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md`](KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md) | Ops & Kernel Security | R6 multi-OS kernel CVE/KEV scanner & patcher (6 OS families, 17 Linux distros), No Break-Out / No Break-In shields, 5 Foolproof Invariants. |
| [`docs/CLI_AND_POLICY_REFERENCE.md`](CLI_AND_POLICY_REFERENCE.md) | Developers & Policy Authors | All `octopus` subcommands/aliases, `run` flags, exit codes (`0`/`1`/`2`/`124`/`5`), 14-field `JsonRunSummary`, 11-field `OctopusRunPolicy`, 11-entity / 13-action Cedar schema, recipes. |
| [`docs/OPERATIONS_AND_API_GUIDE.md`](OPERATIONS_AND_API_GUIDE.md) | Operators & Release Engineers | `127.0.0.1:3030` Dashboard, `X-Octopus-Token` REST API routes, Host KillSwitch, `octopus service`, signed release builds, PR shipping, troubleshooting. |
| [`docs/AGENTMESH_WASM_INTEGRATION.md`](AGENTMESH_WASM_INTEGRATION.md) | Mesh & Wasm Integrators | `google/agentmesh v0.2.0` x `wasmtime v49.0.4` topology, OIDC/PEP bridge, 8 live cases, traceability matrix. |
| [`docs/ADVERSARIAL_DEFENSE_AND_RED_TEAMING.md`](ADVERSARIAL_DEFENSE_AND_RED_TEAMING.md) | Red-Team & QA | Multi-arm enclave, 19 adversarial frameworks, 74-language determinism, `TarpitArm` honey-tokens. |
| [`README.md`](../README.md) | First-Time Visitors | Project positioning (`google/agentmesh` complement, CAGE contrast), 30s quickstart, platform matrix, doc index. |
| [`examples/quickstart/`](../examples/quickstart/policy.json) | New Users | Minimal zero-dependency Python quickstart (`policy.json`, [`policy.cedar`](../examples/quickstart/policy.cedar), [`my_agent.py`](../examples/quickstart/my_agent.py)). |
| [`examples/agentmesh-wasm-sandbox/`](../examples/agentmesh-wasm-sandbox/README.md) | Mesh Integrators | Multi-node `agentmesh v0.2.0` launch scripts (`run.sh`, `run.ps1`, `office.yaml.tmpl`, `policy.json`). |
| [`examples/agentmesh_live_v020_e2e.rs`](../examples/agentmesh_live_v020_e2e.rs) & [`agentmesh_wasm_sandbox_demo.rs`](../examples/agentmesh_wasm_sandbox_demo.rs) | Rust Integrators | Live 8-case AgentMesh E2E runner and offline 6-stage embedded Wasm sandbox demo. |
| [`reports/vassilev_mathematical_validation.md`](../reports/vassilev_mathematical_validation.md) | Reviewers & Researchers | Mathematical validation report scoping optional D3QN strictly to offline/advisory simulation. |

---

## Rust Source Module Map

| Source Path | Subsystem / Role |
|---|---|
| [`src/lib.rs`](../src/lib.rs) | Crate root (`agent_octopus`), top-level `//!` documentation, 22 `pub mod` exports & re-exports. |
| [`src/cli/`](../src/cli/) | `octopus` CLI parser (`mod.rs`), `run` orchestrator (`run.rs`), `OctopusRunPolicy` (`policy.rs`), loopback proxy (`proxy.rs`), Wasm runner (`wasm_runner.rs`), SBOM/runtime shield CLI (`latent_shield.rs`). |
| [`src/security/cedar_arm/`](../src/security/cedar_arm/) | AWS Cedar v4.13 PARC engine, 11-entity / 13-action schema (`policy_schema.rs`), Dogwood temporal guard (`temporal/`). |
| [`src/security/wasm_tier1.rs`](../src/security/wasm_tier1.rs) | Wasmtime v49.0.4 Tier-1 sandbox, fuel/epoch `KillSwitch`, `octopus_wasi` hostcalls, Gate 2 telemetry hook. |
| [`src/security/rasp/`](../src/security/rasp/) | RT-ASP sanitizers, Agentjacking/GhostJacking, EchoLeak, taint checks (paired with `sensitive_paths.rs`, `atif_scan.rs`, `semantic_dlp.rs`). |
| [`src/security/linux_sandbox.rs`](../src/security/linux_sandbox.rs) | Linux `PR_SET_NO_NEW_PRIVS`, Landlock LSM, `seccomp-BPF` (sockets + R6 CVE/escape syscalls), `RLIMIT_*`. |
| [`src/security/windows_sandbox.rs`](../src/security/windows_sandbox.rs) | Windows `WindowsJobObject`, AppContainer, mitigation policy mask (paired with `token_posture.rs` de-elevation). |
| [`src/security/macos_sandbox.rs`](../src/security/macos_sandbox.rs) | macOS Seatbelt SBPL (`system-kext-load` / `iokit-open` clamps) and `libproc` descendant freeze. |
| [`src/security/bsd_sandbox.rs`](../src/security/bsd_sandbox.rs) | OpenBSD `unveil`/`pledge`, FreeBSD `procctl`/Capsicum `cap_enter`, NetBSD `setrlimit`. |
| [`src/security/host_network_isolation.rs`](../src/security/host_network_isolation.rs) | Zero-subprocess WFP, Netlink/SOCK_DESTROY, `nftables`, and `/dev/pf` Host KillSwitch & R6 inbound shields. |
| [`src/security/kernel_patcher/`](../src/security/kernel_patcher/) | R6 multi-OS CVE/KEV scanner, CPE 2.3 mapper, livepatch & native patch orchestrator, `shield_state.rs`, `validation.rs`. |
| [`src/security/virtual_patch_shield.rs`](../src/security/virtual_patch_shield.rs) | R6 `KernelShieldPosture`, `shield_locked_until_reboot`, `telemetry_degraded_fail_closed`, `AGENT_OCTOPUS_SHIELD_POSTURE_PATH`. |
| [`src/arm/kernel_sentinel_arm.rs`](../src/arm/kernel_sentinel_arm.rs) | Windows `\\.\OsoosiDriver` ring-0 `DeviceIoControl` driver rule push & `BYOVD_VULNERABLE_DRIVERS` blocklist. |
| [`src/security/rea_binary_gate.rs`](../src/security/rea_binary_gate.rs) | R7 `<2ms` pure-Rust PE/ELF/Mach-O/Wasm pre-spawn header, packer, `W^X`, signature & direct-syscall scanner. |
| [`src/security/executable_identity.rs`](../src/security/executable_identity.rs) | TOCTOU-safe `open_and_lock_executable_for_cli` handle locking and `KernelFileIdentityKey` caching. |
| [`src/security/rate_limit_backoff.rs`](../src/security/rate_limit_backoff.rs) | `ReteEngine` RETE REA fact bridge (`ReaBinaryFact`, `evaluate_pre_spawn_rea_gate`). |
| [`src/security/latent_shield.rs`](../src/security/latent_shield.rs) | R8 pure-Rust `UnifiedSecurityShield`, `LatentWorldModel`, `SbomSupplyChainGuard`, `AgentRuntimeGuard`, embedded weights. |
| [`src/web/`](../src/web/) | Dual-stack loopback Web Dashboard, `X-Octopus-Token` request guard, REST API handlers (`api.rs`, `server.rs`). |
| [`src/core/merkle.rs`](../src/core/merkle.rs) | RFC 6962 SHA-256 Merkle trees and inclusion proof verification. |
| [`src/security/rl_defense/`](../src/security/rl_defense/) | **Optional offline/advisory-only** D3QN scorer (`enabled: false` default, opt-in `OCTOPUS_ENABLE_RL_ADVISORY=1`, zero gating authority). |

---

## Topic and Anchor Index (A to Z)

| Topic | Guide and Section |
|---|---|
| **AgentMesh (`google/agentmesh`) Integration** | [Topology and Security Boundaries](AGENTMESH_WASM_INTEGRATION.md#1-topology--end-to-end-security-boundaries) |
| **AppContainer ACL (`S-1-15-2-1`, `0xC0000135`)** | [Windows `--sandbox strict` Troubleshooting](OPERATIONS_AND_API_GUIDE.md#troubleshooting) |
| **Audit Log (RFC 6962 SHA-256 Merkle)** | [SHA-256 Merkle Audit Log](ARCHITECTURE_AND_SECURITY_MODEL.md#sha-256-merkle-audit-log) |
| **AWS Cedar v4.13 Schema (11 Entities, 13 Actions)** | [Cedar Schema Reference](CLI_AND_POLICY_REFERENCE.md#aws-cedar-v413-schema-11-entities-and-13-actions) |
| **`binary_integrity` Policy Config (R7)** | [`OctopusRunPolicy` JSON Schema](CLI_AND_POLICY_REFERENCE.md#octopusrunpolicy-json-schema-11-top-level-fields) |
| **BSD Sandboxes (`freebsd-update`, `syspatch`, `sysupgrade`)** | [6 OS Families & 17 Linux Distros](KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md#supported-6-os-families-and-17-linux-distributions) |
| **BYOVD Driver Blocking (`\\.\OsoosiDriver`)** | [No Break-Out Virtual Patching](KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md#zero-reboot-virtual-patching-shield-no-break-out-and-no-break-in) |
| **CLI Subcommands (`verify`, `hook`, `mcp-proxy`, `siquery`, `sbom-guard`, `kernel-patch`)** | [`octopus` Subcommands and Aliases](CLI_AND_POLICY_REFERENCE.md#octopus-subcommands-and-aliases) |
| **`CredentialSentinelMasker` (`ao_mask_*`)** | [Tier-2 OS Sandboxes and Loopback Proxy](ARCHITECTURE_AND_SECURITY_MODEL.md#4-tier-2-os-kernel-sandboxes-and-loopback-policy-proxy) |
| **D3QN Optional Offline / Advisory Boundary** | [Root Appendix](../README.md#appendix-optional-offline--advisory-telemetry-scoring-d3qn), [Distinction from `UnifiedSecurityShield`](ARCHITECTURE_AND_SECURITY_MODEL.md#tighten-only-monotonicity-and-distinction-from-d3qn) |
| **Exit Codes (`0`, `1`, `2`, `124`, `5`)** | [`octopus run` Options and Exit Codes](CLI_AND_POLICY_REFERENCE.md#octopus-run-options-and-exit-codes) |
| **Foolproof Invariants (5 Kernel Shield Guarantees)** | [The 5 Foolproof Invariants](KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md#the-5-foolproof-invariants) |
| **`JsonRunSummary` (`--json` Output Schema)** | [`JsonRunSummary` Schema](CLI_AND_POLICY_REFERENCE.md#jsonrunsummary-schema---json) |
| **Kernel Patching (R6 Multi-OS Orchestrator)** | [Universal All-OS Host Kernel Scanner & Patcher](KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md#universal-all-os-host-kernel-cvekev-scanner-and-patch-orchestrator) |
| **KillSwitch (`isolate`, `restore`, WFP/Netlink/`/dev/pf`)** | [Host KillSwitch and Service Management](OPERATIONS_AND_API_GUIDE.md#host-killswitch-and-native-service-management) |
| **`LatentWorldModel` & Embedded Weights (R8)** | [R8 Pure-Rust `UnifiedSecurityShield`](ARCHITECTURE_AND_SECURITY_MODEL.md#r8-pure-rust-unifiedsecurityshield) |
| **Livepatch Engines (`canonical-livepatch`, `kpatch`, `ksplice`, `klp`, Hotpatch)** | [6 OS Families & 17 Linux Distros](KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md#supported-6-os-families-and-17-linux-distributions) |
| **`NVD_API_KEY` (Env-Only) & `telemetry_degraded_fail_closed`** | [Troubleshooting](OPERATIONS_AND_API_GUIDE.md#troubleshooting), [5 Foolproof Invariants](KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md#the-5-foolproof-invariants) |
| **Policy Recipes (Python, Hooks, Wasm, Air-Gapped SBOM)** | [Policy Recipes](CLI_AND_POLICY_REFERENCE.md#policy-recipes) |
| **REA `<2ms` Pre-Spawn Binary Gate (R7)** | [R7 Pre-Spawn REA Binary Gate](ARCHITECTURE_AND_SECURITY_MODEL.md#r7-pre-spawn-rea-binary-gate-under-2ms) |
| **Red-Teaming Suites (19 Frameworks, 74 Languages)** | [Integrated Red-Teaming Suites](ADVERSARIAL_DEFENSE_AND_RED_TEAMING.md#integrated-multi-framework-red-teaming-suites) |
| **REST API (`127.0.0.1:3030`, `X-Octopus-Token`, `/api/kernel-patcher/status`)** | [REST API Route Groups](OPERATIONS_AND_API_GUIDE.md#rest-api-route-groups) |
| **Ring-0 Binary Splicing (Why Excluded)** | [Why Unsafe Ring-0 Binary Splicing Is Avoided](KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md#why-unsafe-ring-0-binary-splicing-is-intentionally-avoided) |
| **RT-ASP Sanitizers & Mandatory Write-Deny** | [RT-ASP Sanitizers and Path Guards](ARCHITECTURE_AND_SECURITY_MODEL.md#1-rt-asp-sanitizers-and-mandatory-write-deny-guards) |
| **`sbom-guard` / `--baseline-sbom` / `--sbom` / `--latent-weights`** | [`octopus run` Options](CLI_AND_POLICY_REFERENCE.md#octopus-run-options-and-exit-codes) |
| **`shield_locked_until_reboot` & `logs/kernel_shield_posture.json`** | [The 5 Foolproof Invariants](KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md#the-5-foolproof-invariants) |
| **Signed Release Build (`build_start_signed.ps1`) & `solo_pr_ship.ps1`** | [Solo-Developer Signed Build & PR Shipping](OPERATIONS_AND_API_GUIDE.md#solo-developer-signed-release-build-and-pr-shipping) |
| **`TarpitArm` Honeypot & Canary Tokens** | [The Tarpit Decoy Defense Arm](ADVERSARIAL_DEFENSE_AND_RED_TEAMING.md#the-tarpit-decoy-defense-arm-tarpitarm) |
| **Threat Model & Platform Prerequisites** | [Threat Model](ARCHITECTURE_AND_SECURITY_MODEL.md#threat-model) |
| **`UnifiedSecurityShield` (Tighten-Only Monotonicity)** | [Tighten-Only Monotonicity](ARCHITECTURE_AND_SECURITY_MODEL.md#tighten-only-monotonicity-and-distinction-from-d3qn) |
| **`virtual_patch_shield` Policy & `promote_wasm_on_cve`** | [`OctopusRunPolicy` JSON Schema](CLI_AND_POLICY_REFERENCE.md#octopusrunpolicy-json-schema-11-top-level-fields) |
| **Wasmtime Tier-1 Sandbox (`--sandbox wasm-strict`, `--wasm-promote`)** | [Wasmtime Tier-1 Capability Sandbox](ARCHITECTURE_AND_SECURITY_MODEL.md#3-wasmtime-v4904-tier-1-capability-sandbox) |
