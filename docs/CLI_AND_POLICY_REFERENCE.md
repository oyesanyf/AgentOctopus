# CLI and Policy Reference

**Docs:** [Hub](README.md) | [Architecture & Security](ARCHITECTURE_AND_SECURITY_MODEL.md) | [Kernel Shield](KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md) | [CLI & Policy](CLI_AND_POLICY_REFERENCE.md) | [Operations & API](OPERATIONS_AND_API_GUIDE.md) | [AgentMesh + Wasm](AGENTMESH_WASM_INTEGRATION.md) | [Red Teaming](ADVERSARIAL_DEFENSE_AND_RED_TEAMING.md) | [Root README](../README.md)

This reference covers every subcommand, flag, exit code, JSON summary field, `OctopusRunPolicy` option, and AWS Cedar v4.13 schema element implemented in `octopus` ([`src/bin/octopus.rs`](../src/bin/octopus.rs), [`src/cli/`](../src/cli/)).

---

## `octopus` Subcommands and Aliases

| Subcommand | Aliases (`parse_octopus_cli`) | Arguments and Behavior | Help Parity Note |
|---|---|---|---|
| `run` | — | Runs a native command, Python script, or `.wasm`/`.wat` guest under deterministic policy containment (`src/cli/run.rs`). | Documented in `octopus --help` & `octopus run --help` |
| `verify` | `--verify`, `--check`, `-v` | Runs `SubsystemVerifier::run_all()` 7-phase cryptographic and containment self-diagnostics. | Aliases omitted from `octopus --help` |
| `status` | — | Prints `HostKillSwitchStatus` JSON. | Documented in `octopus --help` |
| `protocols` | — | Prints `UniversalProtocolCatalog` JSON. | Documented in `octopus --help` |
| `hook` | — | `evaluate [--agent <claude\|cursor\|copilot\|opencode\|mcp>] [--event <NAME>] [--post]`, `install [--workspace\|-w <DIR>] [--agents\|-a <list>]`, `--help`/`-h`/`help`. | Documented in `octopus --help` |
| `mcp-proxy` | — | Reads JSON-RPC lines on stdin and enforces deterministic Cedar/RT-ASP MCP gating. | Documented in `octopus --help` |
| `siquery` | — | `octopus siquery [SQL_QUERY]` (defaults to `SELECT pid, name, cmdline FROM processes LIMIT 10;`). | `octopus siquery` reads only `cli_args.get(2)` in `Pretty` format, whereas `agent_octopus siquery` supports `--tables`/`-t`, `--sweep`/`-s`, `--format`/`-f <json\|csv\|pretty>`, and `--query`/`-q`. |
| `sbom-guard` | `latent-shield` | R8 CycloneDX SBOM & runtime telemetry gate (`src/cli/latent_shield.rs`). Mode 1: `--baseline-sbom <PATH> --sbom <PATH> [--sbom-intent\|--intent <patch\|minor\|refactor>] [--latent-weights <PATH>] [--json]`. Mode 2: `--check-step --telemetry <PATH\|-> [--latent-weights <PATH>] [--json]`. | Documented in `octopus --help` |
| `kernel-patch` | `patch-kernel` | R6 All-OS Kernel CVE/KEV scanner & patcher (`src/security/kernel_patcher/mod.rs`): `[status\|--status] [--dry-run] [--apply\|--execute] [--kev-only] [--min-cvss <SCORE>] [--cpe <CPE23>] [--timeout-secs <SECS>] [--json] [-h\|--help]`. Uses `NVD_API_KEY` env var only (`--api-key`/`--nvd-api-key` forbidden). | Alias `patch-kernel` omitted from `octopus --help` |
| `isolate` | `engage` | Engages the native host KillSwitch (WFP / Netlink / `/dev/pf`). | Alias `engage` omitted from `octopus --help` |
| `restore` | `disarm` | Disarms host network isolation (`execute_host_disarm_unauthenticated`). | Alias `disarm` omitted from `octopus --help` |
| `killswitch` | — | `[status\|isolate\|engage\|restore\|disarm\|protocols\|--help]`. | Dispatched by `parse_octopus_cli`, omitted from `octopus --help` |
| `service` | `--service` | `[install\|delete\|uninstall\|remove\|rm\|start\|stop\|restart\|status\|run]` (default `status`). | Alias `--service` omitted from `octopus --help` |
| `start` | `serve`, `ui` | Launches the Web Dashboard & REST API (`[--port\|-p <PORT>] [--open-browser\|--browser] [--help\|-h]`, default `127.0.0.1:3030`; ignores `0` and `5000`). | Dispatched by `parse_octopus_cli`, omitted from `octopus --help` |
| `help` | `--help`, `-h`; `--version`, `-V` | Prints CLI help (`0`) or `octopus 0.1.0` (`0`). | `--version` / `-V` omitted from `octopus --help` |

---

## `octopus run` Options and Exit Codes

### Synopsis

```text
octopus run --policy <PATH> [--sandbox <strict|standard|wasm-strict>] [--wasm-promote] [--timeout <SECS>] [--cwd <DIR>] [--baseline-sbom <PATH> --sbom <PATH>] [--sbom-intent <patch|minor|refactor>] [--latent-weights <PATH>] [--json] -- <COMMAND> [ARGS...]
```

### Flags

| Flag | Default | Validation and Behavior |
|---|---|---|
| `--policy <PATH>` / `--policy=<PATH>` | Required | Non-empty path to an `OctopusRunPolicy` `.json` or AWS Cedar `.cedar` file. |
| `--sandbox <MODE>` / `--sandbox=<MODE>` | `standard` | `standard`, `strict`, or `wasm-strict`. When the R6 Virtual-Patch Shield is active, `wasm-strict` fails closed with exit `2` unless the target is `.wasm`/`.wat`; otherwise enforces strict OS confinement. |
| `--wasm-promote` | `false` | Boolean flag requiring `.wasm`/`.wat` execution when the R6 Virtual-Patch Shield is active (fails closed exit `2` on native commands). |
| `--timeout <SECS>` / `--timeout=<SECS>` | Policy `limits.timeout_secs` or `60` | Non-negative integer seconds; `0` disables the wall-clock timeout. |
| `--cwd <DIR>` / `--cwd=<DIR>` | Current working directory | Must exist as a directory, pass `check_no_reparse_or_symlink`, and not target sensitive system directories. |
| `--baseline-sbom <PATH>` | `None` | Baseline CycloneDX JSON path for R8 Gate 1. Must be paired with `--sbom` (supplying only one fails closed exit `2`). |
| `--sbom <PATH>` | `None` | Candidate CycloneDX JSON path evaluated by `SbomSupplyChainGuard` strictly before Wasmtime instantiation or child spawn. |
| `--sbom-intent <KIND>` | `patch` | `patch`, `minor`, or `refactor`. Requires `--baseline-sbom` and `--sbom`. |
| `--latent-weights <PATH>` | Embedded `latent_shield_weights.json` | Custom `UnifiedSecurityShield` JSON weights file (`<= 2 MiB`, validated for finiteness and dimensions). |
| `--json` | `false` | Emits a single-line `JsonRunSummary` JSON object. |
| `-h`, `--help` | — | Prints `octopus run` help and exits `0`. |

### Exit Codes

| Exit Code | Constant / Source | Meaning |
|---|---|---|
| `0` (or child exit code) | `src/cli/run.rs`, `src/cli/latent_shield.rs` | Workload or guard check succeeded (for `octopus run`, propagates the child's exit code). |
| `1` | `EXIT_SANDBOX_FAILURE` (`src/cli/mod.rs`) | Runtime sandbox or operational failure (`verify`, `isolate`, `restore`, `service`, `kernel-patch`, `hook`, Wasm/OS spawn failure, or Gate 2 runtime guard kill). |
| `2` | `EXIT_PREFLIGHT_DENIED` (`src/cli/mod.rs`) | Fail-closed pre-flight denial: invalid CLI syntax, missing `--` or `--policy`, invalid policy, sensitive `--cwd`/path, Wasm promotion denial, R7 REA binary gate rejection, Cedar `exec` denial, R8 Gate 1 SBOM / Gate 2 telemetry denial, or invalid `kernel-patch` flags. |
| `124` | `EXIT_TIMEOUT` (`src/cli/mod.rs`) | Wall-clock timeout termination (Windows JobObject terminate, Unix child kill, or Wasmtime epoch `KillSwitch::trip()`). |
| `5` | `src/main.rs`, `src/bin/start.rs` | Legacy `agent_octopus` / `start` direct-launch de-elevation refusal (`relaunch_deelevated_or_fail` fail-closed). |

---

## `JsonRunSummary` Schema (`--json`)

When `--json` is passed, `octopus run` emits a JSON object with these 14 fields:

| Field | Type | Values / Notes |
|---|---|---|
| `status` | `string` | One of 7 values: `"ok"`, `"exited_nonzero"`, `"error"`, `"timeout"`, `"denied_preflight"`, `"sandbox_error"`, `"wasm_error"`. |
| `exit_code` | `i32` | Final CLI exit code (`0`, `1`, `2`, `124`, or child exit code). |
| `timed_out` | `bool` | `true` if terminated by `--timeout` / epoch trap. |
| `sandbox` | `string` | `"standard"`, `"strict"`, or `"wasm-strict"`. |
| `backend` | `string` | One of 14 values: `"wasmtime-tier1"`, `"windows-appcontainer+job"`, `"windows-deelevated+job"`, `"linux-landlock+seccomp"`, `"macos-seatbelt-sbpl"`, `"bsd-freebsd"`, `"bsd-openbsd"`, `"bsd-netbsd"`, `"preflight"`, `"windows-appcontainer"`, `"cedar-fs-ipc"`, `"loopback-proxy"`, `"python-audit-guard"`, `"os-sandbox"`. |
| `pid` | `u32 \| null` | Child OS process ID when spawned. |
| `duration_ms` | `u64` | Total execution duration in milliseconds. |
| `stdout` | `string` | Captured child stdout. |
| `stderr` | `string` | Captured child stderr. |
| `egress_events` | `array` | Array of `{ decision, method, target, status, reason }`. |
| `diagnostic` | `string` (optional) | Present when pre-flight, sandbox, or proxy diagnostics are recorded. |
| `virtual_patch_shield` | `bool` (optional) | Present when R6 Virtual-Patch Shield state is active during the run. |
| `sbom_guard` | `object` (optional) | Present when `--sbom` ran Gate 1: `{ domain, intent, surprise_score, threshold, block_execution, reason, audit_merkle_root, audit_record_hash }`. |
| `runtime_guard` | `object` (optional) | Present when R8 Gate 2 evaluates: `{ domain, surprise_score, threshold, block_execution, reason }`. |

---

## `OctopusRunPolicy` JSON Schema (11 Top-Level Fields)

Source: [`src/cli/policy.rs`](../src/cli/policy.rs).

| Top-Level Field | Type / Subfields | Default | Validation and Enforcement |
|---|---|---|---|
| `allowed_domains` | `string[]` | `[]` | Exact `host` or `host:port` (no scheme, path, query, userinfo, or `*`/`*:*`/`*.*` wildcards). Loopback targets require explicit `127.0.0.1:<port>` or `localhost:<port>`. |
| `denied_domains` | `string[]` | `[]` | Same format as `allowed_domains`; takes strict precedence over `allowed_domains`. |
| `denied_resolved_addresses` | `string[]` | `[]` | `IpCidr` strings (`"169.254.169.254/32"`). Proxy unconditionally blocks Cloud IMDS, unspecified IPs, proxy self-loop, Cedar IPC port, and restricted IPs. |
| `commands` | `{ allow: string[], deny: string[], max_child_processes?: u32 }` | `allow: []`, `deny: []`, `None` | Executable/stem allowlist and denylist (`deny` wins). `max_child_processes` defaults to `16` on Windows JobObject. |
| `filesystem` | `{ allow_read: string[], allow_write: string[], deny: string[] }` | `[]` | Pre-flight rejects `allow_read`/`allow_write` entries matching sensitive system/credential stores (`sensitive_paths.rs`) and rejects `allow_write` on mandatory write-deny targets (`.bashrc`, `.git/hooks`, `.git/config`, `.mcp.json`, `.vscode/`, `.idea/`, `.claude/commands/`, etc.). |
| `credentials` | `{ mask_env: string[], inject_hosts: string[], allow_plaintext_inject: bool }` | `[]`, `[]`, `false` | `mask_env` vars are replaced with `ao_mask_*` sentinels in child env; real secrets are injected only to `inject_hosts` over HTTPS (unless `allow_plaintext_inject: true`). |
| `limits` | `{ memory_mb?: usize, timeout_secs?: u64, wasm_fuel?: u64 }` | `None` | Wasm memory clamped to `64 KiB..=64 MiB` (default `64 MiB`); `timeout_secs` defaults to `60`; `wasm_fuel` defaults to `2_000_000`. |
| `virtual_patch_shield` | `{ promote_wasm_on_cve: bool, disallow_win32k: bool, block_exotic_sockets: bool, fail_closed_on_degraded_telemetry: bool }` | `false`, `false`, `true`, `true` | Controls R6 Zero-Reboot Virtual-Patch Shield clamps (`promote_wasm_on_cve` requires `.wasm`/`.wat` when shield is active). |
| `binary_integrity` | `{ enabled: bool, require_signed_binaries: bool, block_packed: bool, block_wx_sections: bool, block_direct_syscalls: bool, entropy_threshold: f64, max_allowed_direct_syscalls: u32, allow_direct_syscalls_for: string[] }` | `true`, `false`, `true`, `true`, `true`, `6.4`, `0`, `[]` | Controls R7 `<2ms` pre-spawn REA binary gate (`entropy_threshold` validated finite in `0.0..=8.0`). |
| `cedar_policy` | `string \| null` | `None` | Inline AWS Cedar v4.13 policy text validated under `ValidationMode::Strict`. |
| `cedar_file` | `string \| null` | `None` | Path to `.cedar` file (resolved relative to the `.json` policy directory if relative) merged with `cedar_policy`. |

---

## AWS Cedar v4.13 Schema (11 Entities and 13 Actions)

Source: [`src/security/cedar_arm/policy_schema.rs`](../src/security/cedar_arm/policy_schema.rs) (namespace `Octopus`).

### 11 Entity Types

| Entity Type | Attributes |
|---|---|
| `Agent` | `{ role?: String, is_trusted_supervisor?: Boolean }` |
| `Document` | `{ uri?: String }` |
| `Ledger` | `{ account_id?: String }` |
| `NetworkTarget` | `{ domain?: String }` |
| `SystemPolicy` | `{ policy_id?: String }` |
| `DecoyTrap` | `{ trap_id?: String }` |
| `KernelSubstrate` | `{ substrate_id?: String, enforcement_tier?: String }` |
| `Command` | `{ executable?: String, stem?: String, sandbox_mode?: String }` |
| `FilePath` | `{ path?: String, is_sensitive?: Boolean }` |
| `Tool` | `{ tool_name?: String, tier?: String }` |
| `Host` | `{ domain?: String, port?: Long }` |

### 13 Actions

| Action | Principal -> Resource | Context Attributes |
|---|---|---|
| `extract` | `Agent -> Document` | `{ delegation_depth?: Long }` |
| `write` | `Agent -> Ledger` | `{ amount_cents: Long (req), approved: Boolean (req) }` *(Web API `/api/evaluate-cedar` also accepts `instruction_language`, `translated_prompt`, `language_code`, `sender_agent`, `target_agent`, `inter_agent_message`, `originator`)* |
| `egress` | `Agent -> NetworkTarget \| Host` | `{ destination_domain: String (req), destination_host?: String, destination_port?: Long, scheme?: String, method?: String, path?: String, cve_id?: String, is_cisa_kev?: Boolean, kernel_surface?: String, reboot_pending?: Boolean, telemetry_degraded_fail_closed?: Boolean, inbound_port?: Long, protocol?: String }` |
| `notify` | `Agent -> Agent` | `{}` |
| `change_security_policy` | `Agent -> SystemPolicy` | `{ quorum_authorized?: Boolean }` |
| `quarantine` | `Agent -> DecoyTrap` | `{ adversary_ip?: String, attack_type?: String }` |
| `kernel_enforce` | `Agent -> KernelSubstrate` | `{ enforcement_tier?: String, target_pid?: Long }` |
| `evaluate` | `Agent -> NetworkTarget` | `{ destination_host: String (req), destination_port?: Long, cve_id?: String, is_cisa_kev?: Boolean, kernel_surface?: String, reboot_pending?: Boolean, telemetry_degraded_fail_closed?: Boolean }` |
| `inbound_perimeter` | `Agent -> Host \| NetworkTarget` | `{ inbound_port: Long (req), protocol?: String, cve_id?: String, is_cisa_kev?: Boolean, kernel_surface?: String, reboot_pending?: Boolean, telemetry_degraded_fail_closed?: Boolean }` |
| `exec` | `Agent -> Command` | `{ executable: String (req), stem?: String, args_joined?: String, cwd?: String, sandbox_mode?: String, is_wasm?: Boolean, is_packed?: Boolean, has_wx_violation?: Boolean, direct_syscall_count?: Long, obfuscation_entropy_x100?: Long, high_obfuscation_entropy?: Boolean, is_authenticode_signed?: Boolean, binary_format?: String, cve_id?: String, is_cisa_kev?: Boolean, kernel_surface?: String, reboot_pending?: Boolean, telemetry_degraded_fail_closed?: Boolean }` |
| `fs_read` | `Agent -> FilePath \| Document` | `{ path: String (req), normalized_path?: String, is_sensitive?: Boolean }` |
| `fs_write` | `Agent -> FilePath \| Ledger` | `{ path: String (req), normalized_path?: String, is_mandatory_deny?: Boolean }` |
| `tool_call` | `Agent -> Tool` | `{ tool_name: String (req), arguments_json?: String, target?: String, cve_id?: String, is_cisa_kev?: Boolean, kernel_surface?: String, reboot_pending?: Boolean, telemetry_degraded_fail_closed?: Boolean }` |

---

## Policy Recipes

### Recipe 1: Quickstart Python Agent (Allow Workspace Read, Block Cloud IMDS)

See [`examples/quickstart/policy.json`](../examples/quickstart/policy.json) and [`examples/quickstart/policy.cedar`](../examples/quickstart/policy.cedar):

```bash
octopus run --policy examples/quickstart/policy.json -- python examples/quickstart/my_agent.py
```

### Recipe 2: Claude / Cursor / Copilot Hook and MCP Proxy Guard

```bash
# Install deterministic pre-tool hooks into a project workspace
octopus hook install --workspace . --agents claude,cursor,copilot,opencode

# Evaluate a hook payload from stdin
octopus hook evaluate --agent claude --event PreToolUse

# Guard an MCP stdio JSON-RPC server stream
octopus mcp-proxy
```

### Recipe 3: `.wasm` / `.wat` Guest Tool with Strict Fuel and Memory Caps

```json
{
  "allowed_domains": [],
  "limits": {
    "memory_mb": 32,
    "timeout_secs": 10,
    "wasm_fuel": 1000000
  },
  "virtual_patch_shield": {
    "promote_wasm_on_cve": true
  }
}
```

```bash
octopus run --policy wasm_policy.json --sandbox wasm-strict --wasm-promote -- my_tool.wat
```

### Recipe 4: Strict Air-Gapped Runner with Signed Binary Gate and SBOM Supply-Chain Guard

```json
{
  "allowed_domains": [],
  "denied_resolved_addresses": ["169.254.169.254/32"],
  "commands": { "allow": ["python", "python3"], "max_child_processes": 2 },
  "filesystem": { "allow_read": ["."], "allow_write": [] },
  "binary_integrity": {
    "enabled": true,
    "require_signed_binaries": true,
    "block_packed": true,
    "block_wx_sections": true,
    "block_direct_syscalls": true
  }
}
```

```bash
# Evaluate SBOM diff standalone (exit 0 allow, exit 2 block)
octopus sbom-guard --baseline-sbom baseline.cdx.json --sbom candidate.cdx.json --sbom-intent patch --json

# Or enforce Gate 1 pre-spawn inside octopus run
octopus run --policy airgap.json --sandbox strict --baseline-sbom baseline.cdx.json --sbom candidate.cdx.json --sbom-intent patch -- python agent.py
```
