# Operations and API Guide

**Docs:** [Hub](README.md) | [Architecture & Security](ARCHITECTURE_AND_SECURITY_MODEL.md) | [Kernel Shield](KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md) | [CLI & Policy](CLI_AND_POLICY_REFERENCE.md) | [Operations & API](OPERATIONS_AND_API_GUIDE.md) | [AgentMesh + Wasm](AGENTMESH_WASM_INTEGRATION.md) | [Red Teaming](ADVERSARIAL_DEFENSE_AND_RED_TEAMING.md) | [Root README](../README.md)

This runbook covers the AgentOctopus Web Dashboard (`127.0.0.1:3030`), authenticated REST API, Host KillSwitch operations, native OS service management, Solo-Developer Signed Release Builds, PR shipping, and platform troubleshooting.

---

## Web Dashboard and Authenticated REST API

Sources: [`src/web/server.rs`](../src/web/server.rs), [`src/web/request_guard.rs`](../src/web/request_guard.rs), [`src/web/api.rs`](../src/web/api.rs).

### Startup, Port Discovery, and Request Guard

Launch the Web Dashboard and REST API on dual-stack loopback (`127.0.0.1` + `[::1]`, default port `3030`, never port `5000`):

```bash
# Via octopus CLI (aliases: serve, ui)
octopus start --port 3030

# Via agent_octopus or the dedicated start binary target
cargo run --bin agent_octopus -- start --port 3030
cargo run --bin start -- --console --port 3030
```

- **Runtime files**: Writes the active listening port to `logs/active_port.txt` and a per-session operator token to `logs/.octopus_operator_token`.
- **CSRF & Host/Origin Guard (`request_guard.rs`)**: Enforces exact loopback `Host` (`127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`), `Origin` / `Sec-Fetch-Site` validation, and `X-Octopus-Token` (`x-octopus-token`) authentication on all `/api/*` routes (exempting only `/health`, `/api/health`, OIDC/JWKS discovery, and CAGE Substrate routes), or an `Octopus-Session` cookie bootstrapped via `POST /api/session/bootstrap-nonce` (`?bootstrap=<nonce>`). SSE streams (`/api/test-stream`, `/api/runtime-activity/stream`) accept `?token=<operator_token>`.

### REST API Route Groups

| Route Group | Key Endpoints | Purpose |
|---|---|---|
| **Core Status, Audit & Cedar** | `GET /api/status` (`/api/system/status`, `/api/health`), `GET /api/audit-log`, `GET /api/download-audit-log`, `POST /api/evaluate-cedar`, `GET\|POST /api/egress-domains`, `GET /api/breakout-guards/status`, `GET /api/resilience/metrics` | Health, live Cedar PARC evaluation, egress allowlist inspection, and SHA-256 Merkle audit log retrieval. |
| **Kernel Patcher & Shield (R6)** | `GET /api/kernel-patcher/status`, `GET /api/kernel-stats` | Host kernel CPE/KEV/CVE posture, `livepatch`, `reboot_pending`, `shield_locked_until_reboot`, `telemetry_degraded_fail_closed`, `virtual_patch_shield`, `merkle_root_hex`, and `latest_scan`. |
| **Containment Rings, Sentinel & KillSwitch** | `GET /api/containment-rings`, `POST /api/containment-rings/{sever,regenerate,stale-replay}`, `POST /api/sentinel/{simulate-breach,reset-lockdown}`, `GET /api/tarpit-stats`, `GET /api/killswitch/status`, `POST /api/killswitch/{engage,isolate,disarm,restore}`, `GET /api/killswitch/protocols` | Ring sever/regeneration, Tarpit decoy stats, and host network KillSwitch control. |
| **Governor, RT-ASP & Siquery** | `GET /api/governor/status`, `POST /api/governor/{inject-sample,reset}`, `GET /api/rasp/{status,telemetry}`, `POST /api/rasp/{intercept-prompt,intercept-tool,intercept-memory,canary,mitigation-tier}`, `GET /api/hidden-processes`, `GET /api/siquery/{tables,edr-status}`, `POST /api/siquery/{query,protect-sweep,sweep}` | Deterministic Governor, RT-ASP interceptors, and OS process/table telemetry (`siquery`). |
| **AgentMesh & CAGE Compat** | `GET /api/agentmesh/status`, `POST /api/agentmesh/{wasm-call,mint-inbound-seal,killswitch/trip,killswitch/reset,mandates/attenuate}`, `POST /mcp/...`, `/governance/*`, `/api/cage/*`, `/api/v1/cage/*` | `google/agentmesh` Wasm PEP bridge, mandate attenuation, and CAGE `RoutingSeal` wire compatibility. |
| **Verification, Threat Intel & Optional RL** | `/api/pqc/*`, `/api/atlas/*`, `/api/oss-fuzz/*`, `/api/osv-scanner/*`, `/api/math/*`, `/api/otel/{sessions,spans}`, `/api/rl-defense/{status,train-cycle,latest-cycle,evaluate-action}` | PQC, MITRE ATLAS, OSV, Vassilev math validation, OTel spans, and optional offline/advisory D3QN endpoints (disabled by default). |

Example authenticated status and kernel-shield check:

```bash
TOKEN="$(cat logs/.octopus_operator_token)"
curl -H "X-Octopus-Token: ${TOKEN}" http://127.0.0.1:3030/api/status
curl -H "X-Octopus-Token: ${TOKEN}" http://127.0.0.1:3030/api/kernel-patcher/status
```

---

## Host KillSwitch and Native Service Management

Sources: [`src/security/host_network_isolation.rs`](../src/security/host_network_isolation.rs), [`src/service.rs`](../src/service.rs).

- **Engage Host Network Isolation** (`octopus isolate` or `octopus killswitch isolate`): Installs zero-subprocess kernel isolation rules (Windows Filtering Platform 22/24-layer filters + BFE enforcement; Linux `AF_NETLINK` blackhole routes + `SOCK_DESTROY`; macOS/BSD `/dev/pf` binary `ioctl` anchors) while keeping loopback dashboard control reachable.
- **Restore Host Network** (`octopus restore` or `octopus killswitch restore`): Removes AgentOctopus isolation anchors and persists a clean disarm receipt.
- **Native Service Management** (`octopus service [install|delete|start|stop|restart|status|run]`): Registers, starts, stops, and inspects the AgentOctopus background service (`SERVICE_NAME`) on Windows SCM, systemd, or launchd.

---

## Solo-Developer Signed Release Build and PR Shipping

### Signed Release Build (`build_start_signed.ps1`)

Build all release binaries (`octopus`, `agent_octopus`, and the `start` binary target) and apply WDAC Authenticode signing (certificate thumbprint `9A6D3B509500813058EC63183476464FAC8F015B` via `signtool.exe`):

```powershell
# Run the signed build script for the start binary target
powershell -ExecutionPolicy Bypass -File .\build_start_signed.ps1

# Build all release binary targets cleanly
cargo build --release --bins

# Verify formatting, clippy, and zero-warning rustdoc (matching CI)
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
$env:RUSTDOCFLAGS = "-D warnings"
cargo doc --no-deps --all-features
```

*(Note: If the hardware/store signing certificate `9A6D3B509500813058EC63183476464FAC8F015B` is not present in the local Windows certificate store, `build_start_signed.ps1` fails closed rather than emitting an unsigned artifact claiming to be signed.)*

### Solo-Developer PR Shipping (`scripts/solo_pr_ship.ps1`)

For intermediate local commits on `main`, set `$env:AGENT_OCTOPUS_SKIP_POST_COMMIT_HOOK = "1"`. To ship to `origin/main` cleanly through `.github/workflows/ci.yml`, `auto-review-bot.yml`, and `witness-sdlc.yml`, use:

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/solo_pr_ship.ps1 -Title "feat: ..." -BodyFile pr_body.md
```

---

## Troubleshooting

### 1. Windows `--sandbox strict` Fails With `0xC0000135` (`STATUS_DLL_NOT_FOUND`)

In `--sandbox strict` (`windows-appcontainer+job`), the child runs inside an ephemeral Windows AppContainer (`S-1-15-2-...`). Windows requires the target executable/interpreter directory (e.g., your Python installation folder) to grant **`ALL APPLICATION PACKAGES` (`S-1-15-2-1`)** `(RX)` read-and-execute ACLs:

```powershell
# Inspect current ACLs on the Python directory
icacls (Split-Path (Get-Command python).Source)

# Grant S-1-15-2-1 (ALL APPLICATION PACKAGES) RX if missing (elevated PowerShell)
icacls "C:\Path\To\Python" /grant "*S-1-15-2-1:(OI)(CI)(RX)"
```

If modifying system ACLs is not possible, use `--sandbox standard` (`windows-deelevated+job`), which enforces a de-elevated restricted token + `WindowsJobObject` + loopback policy proxy without AppContainer directory ACL requirements.

### 2. NIST NVD API Rate Limiting and `NVD_API_KEY`

- `octopus kernel-patch` and `/api/kernel-patcher/status` accept `NVD_API_KEY` **strictly from the process environment** (`$env:NVD_API_KEY` / `export NVD_API_KEY=...`). Passing `--api-key` or `--nvd-api-key` on the CLI fails closed to prevent secret exposure in process listings.
- If the host is offline or NVD returns HTTP `429`/`5xx`, `telemetry_degraded_fail_closed` becomes `true` and R6 virtual-patch shields remain deterministically active.

### 3. `logs/kernel_shield_posture.json` and `shield_locked_until_reboot`

- When a kernel update sets `reboot_required` without livepatch confirmation, `shield_locked_until_reboot` latches `true` in `logs/kernel_shield_posture.json` (self-signed with `posture_sha256`).
- Automated test harnesses can isolate posture persistence to a temporary file via `AGENT_OCTOPUS_SHIELD_POSTURE_PATH` so the working repository's `logs/` directory stays untouched.
- Once the host actually reboots into the newer kernel (`uname -r` / OS build advances and `reboot_required == false`), the latch clears cleanly on verification.
