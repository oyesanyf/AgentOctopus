# Sandboxed Wasmtime Workloads on `google/agentmesh` (`v0.2.0`)

Runnable, cross-platform (`Linux`, `macOS`, `Windows`) end-to-end integration demonstrating isolated [`wasmtime` v49.0.4](https://github.com/bytecodealliance/wasmtime) sandboxes discovering and calling remote MCP tools over an unmodified [`google/agentmesh` v0.2.0](https://github.com/google/agentmesh/releases/tag/v0.2.0) mesh (`agentmesh-one` + `office-node` + `edge-node`) under per-sandbox workload identities.

No Docker daemon, Kubernetes cluster, or host `PATH` changes are required. Everything binds strictly to `127.0.0.1` on ephemeral ports and cleans up on exit.

## Quick Start

### Linux & macOS (or Windows Git Bash)

```bash
./examples/agentmesh-wasm-sandbox/run.sh
```

Or with `make`:

```bash
make -C examples/agentmesh-wasm-sandbox test
```

### Windows PowerShell

```powershell
powershell -ExecutionPolicy Bypass -File examples\agentmesh-wasm-sandbox\run.ps1
```

`run.sh` and `run.ps1` automatically download the official `google/agentmesh v0.2.0` release archive for your OS/architecture into `examples/agentmesh-wasm-sandbox/.run/bin/`, verify its exact SHA-256 digest against upstream `checksums.txt`, and run `cargo run --example agentmesh_live_v020_e2e`.

## Topology & Security Boundaries

```text
+-------------------------------------------------------------------+
| Host Process (AgentOctopus Supervisor)                            |
|                                                                   |
|  +-----------------------------+                                  |
|  | Wasmtime v49.0.4 Guest      |  Zero WASI sockets/env/files;    |
|  | - arm_calc  (bound role)    |  imports only:                   |
|  | - arm_rogue (unbound)       |  `octopus_wasi::mesh_call`       |
|  +--------------+--------------+                                  |
|                 | logical URI (`mcp://calc`) + JSON payload       |
|                 v                                                 |
|  +-----------------------------+     OIDC Discovery + ES256 JWKS  |
|  | Host PEP Bridge & Vault     |     `OidcLoopbackServer`         |
|  | - RFC 8693 /oauth/token     |     `iss=http://127.0.0.1:<p>`   |
|  | - RFC 7009 /oauth/revoke    |     `aud=agentmesh`              |
|  | - Strips caller auth/cookie |     `sub=spiffe://agentoctopus`  |
|  | - Injects X-Mesh-Auth       |          `.local/arm/<id>/...`   |
|  +--------------+--------------+                 ^                |
+-----------------|--------------------------------|----------------+
                  | 127.0.0.1 HTTP                 | JWKS fetch
                  v                                |
     +----------------------------+    +-----------+----------------+
     | edge-node                  |--->| agentmesh-one (v0.2.0)     |
     | (agentmesh-node v0.2.0)    |    | --workload-issuer=...      |
     +--------------+-------------+    | --allowed-audiences=...    |
                    |                  | --policy-file=policy.json  |
                    | libp2p + Biscuit +-----------+----------------+
                    v                              ^
     +----------------------------+                |
     | office-node                |----------------+
     | (agentmesh-node v0.2.0)    |
     | publishes `office.yaml`    |
     +--------------+-------------+
                    | 127.0.0.1 Streamable HTTP MCP
                    v
     +----------------------------+
     | Local MCP Backend          |
     | - /mcp/calc                |
     | - /mcp/payroll             |
     | - /mcp/echo-headers        |
     | - /mcp/octopus-doc-extractor (runs Wasmtime v49.0.4)
     +----------------------------+
```

### Responsibility Split

1. **Sandbox Isolation (`wasmtime v49.0.4`)**:
   - Guests compile with zero WASI network sockets, filesystem mounts, or environment variables.
   - Neither the short-lived `ES256` workload JWT nor the exchanged Agent Mesh Biscuit ever enters Wasm linear memory (`linear_memory_zero_secret_verified = true`).
   - Only logical mesh URIs (`mcp://`, `a2a://`, `inference://`, `egress://`) are accepted; raw `http://`, `https://`, `file://`, and IP literals are rejected before any network I/O.
2. **Workload Identity (`OidcLoopbackServer`)**:
   - Mints per-sandbox `ES256` (`P-256`, raw 64-byte IEEE P1363 signature) JWTs with `sub = spiffe://agentoctopus.local/arm/<arm_id>/epoch/<epoch>` and `aud = agentmesh`.
   - `agentmesh-one` verifies them directly via `--workload-issuer` OIDC discovery (`/.well-known/openid-configuration` -> `/.well-known/jwks.json`).
3. **Mesh Authorization & Transport (`google/agentmesh v0.2.0`)**:
   - `edge-node` exchanges the caller's JWT at `POST /oauth/token` (`urn:ietf:params:oauth:grant-type:token-exchange`) for a Biscuit attenuated to the caller's bound roles (or further narrowed per task via `scope` + `seal=true`).
   - `office-node` verifies the Biscuit over `libp2p` before forwarding to any published MCP backend, and strips `X-Mesh-Authentication` before upstream delivery.

## What the 8 Live Cases Verify

| # | Case | Expected Outcome |
|---|---|---|
| 1 | `arm_calc` calls `mcp://calc` from Wasm | `200 OK` (`19 + 23 = 42`); full Wasm linear memory scan confirms `0` JWT/Biscuit bytes |
| 2 | Caller header hygiene on `mcp://echo-headers` | Dirty `Authorization`, `Cookie`, and `X-Mesh-Authentication` headers never reach the MCP backend |
| 3 | Denied service (`arm_calc` -> `mcp://payroll`) | Refused by `office-node` Biscuit authorizer (`403 AuthZ Denied`), mapped to `WASI_ERR_ACCESS_DENIED (-5)` |
| 4 | Sibling sandbox isolation (`arm_rogue` -> `mcp://calc`) | Valid OIDC signature from unbound sibling identity refused (`403` -> Wasm `-5`) |
| 5 | Task-scoped sealed Biscuit (`scope=mcp://calc&seal=true`) | `tar_block` allows `mcp://calc` (`200`) and refuses `mcp://echo-headers` (`403`) despite standing role |
| 6 | Wrong `aud`, wrong `iss`, and expired `exp` JWTs | Rejected at `edge-node` `POST /oauth/token` (`400`/`401` + `Border Crossing` `deny` audit log); fresh JWT recovers |
| 7 | Inbound published Wasm tool (`mcp://octopus-doc-extractor`) | Invoked across `edge-node -> libp2p -> office-node -> Wasmtime`, sanitizing control bytes (`200` for `arm_calc`, `403` for `arm_rogue`) |
| 8 | RFC 7009 revocation (`POST /oauth/revoke`) + epoch trap | Revoked Biscuit immediately rejected on replay; non-cooperative infinite-loop Wasm guest trapped via `increment_epoch()` with `< 1ms` host vault purge |
