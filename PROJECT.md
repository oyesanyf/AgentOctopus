# Project: SafeAgents Integration & Native OshoosiClaw Migration

## Architecture
The system unites the SafeAgents tool-call security inspection framework with AgentOctopus and migrates it natively into OshoosiClaw's Rust runtime.

```
+-----------------------------------------------------------------------------------+
| Multi-Agent Harness (Claude / OpenCode / AgentOctopus / Multi-Tenant Agents)      |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| Track 1 (R1): AgentOctopus Sidecar Interception Test Harness                      |
| - Persistent HTTP/2 Connection Pool (reqwest::Client, TCP_NODELAY, keep-alive)    |
| - Tokio multi-thread runtime + Rayon threadpool for CPU serialization             |
| - Sidecar Proxy at http://127.0.0.1:8787 with --allow-host & ANTHROPIC/OPENAI URLs|
| - Dedicated Lock-Free Background Journal File Watcher (~/.safeagents/calls.jsonl) |
| - Sub-15ms Replacement of Blocked Calls with Synthetic Text Notices               |
+-----------------------------------------------------------------------------------+
                                         |
                                         v Native Rust Migration
+-----------------------------------------------------------------------------------+
| Track 2 (R2): Native OshoosiClaw Inspection & Scrubbing Pipeline                  |
|                                                                                   |
| [Incoming Tool Call / Stream via TieredExecutionDispatcher::dispatch]             |
|                                         |                                         |
|                                         v                                         |
| +-------------------------------------------------------------------------------+ |
| | Stage 1: RequestValidator                                                     | |
| | - Zero-copy SSE/JSON parsing (serde_json + memchr)                            | |
| | - Declared tools schema validation (reject undeclared)                        | |
| | - URL authority & bare IPv4 literal extraction from arguments                 | |
| | - Strips assistant turns: verifies host exists in user prompt turns or allowlist| |
| +-------------------------------------------------------------------------------+ |
|                                         | Allowed                                 |
|                                         v                                         |
| +-------------------------------------------------------------------------------+ |
| | Stage 2: NativeAtifScanner                                                    | |
| | - Precompiled RegexSet & AhoCorasick state machine (<500µs scan latency)      | |
| | - Matches /proc/1/environ, curl --noproxy, unshare/nsenter, k8s tokens, IMDS   | |
| | - Severity threshold: HIGH/CRITICAL -> Immediate Block (<15ms)                | |
| |                       MEDIUM -> Mark Suspicious, forward to Stage 3           | |
| +-------------------------------------------------------------------------------+ |
|                                         | Suspicious                              |
|                                         v                                         |
| +-------------------------------------------------------------------------------+ |
| | Stage 3: Isolated Judge & OshoosiScrubber                                     | |
| | - Isolated prompt to Ollama (http://127.0.0.1:11434, qwen2.5)                 | |
| | - Stripped context (<task>, <tool_call>, <scanner_findings>, no agent thoughts)| |
| | - OshoosiScrubber redacts API keys, env secrets, emails, homes, public IPs    | |
| | - Structured JSONL telemetry written to ~/.safeagents/calls.jsonl             | |
| | - KillSwitch::kill() & CAGE governance trip on high-severity findings         | |
| +-------------------------------------------------------------------------------+ |
|                                         | Allowed                                 |
|                                         v                                         |
| +-------------------------------------------------------------------------------+ |
| | TieredExecutionDispatcher: Wasmtime Sandbox / AppContainer Confinement        | |
| +-------------------------------------------------------------------------------+ |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| Track 3 (R3): Cross-Platform OS Builds & CI/CD Verification                       |
| - Target architectures: Linux (x86_64, aarch64), Windows (x86_64), macOS          |
| - Target gating: #[cfg(target_os = "...")] for eBPF (Linux), WFP (Win), PF (macOS)|
| - CI Matrix: Linux, Windows, macOS runners with zero clippy/fmt/test failures     |
| - 562-case misuse simulation suite regression verification                        |
+-----------------------------------------------------------------------------------+
```

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Cargo Manifest & Dependencies Update | Add `reqwest`, `rayon`, `notify`, `crossbeam-channel`, `aho-corasick`, `memchr` to AgentOctopus `Cargo.toml` | M1 | Survey (Explorer 1) |
| 2 | Multi-Threaded Tokio Runtime Configuration | Annotate all binary entry points with `#[tokio::main(flavor = "multi_thread")]` in AgentOctopus | M1 | Survey (Explorer 1) |
| 3 | Rayon Serialization Dispatcher | Offload JSON/ATIF serialization and AST operations to Rayon threadpool | M1 | Survey (Explorer 1) |
| 4 | Persistent HTTP/2 Connection Pool | Implement `SafeAgentsClient` with keep-alive, TCP_NODELAY, and HTTP/2 prior knowledge | M1 | Survey (Explorer 1) |
| 5 | Egress Proxy Loopback Sidecar Permit | Permit authenticated proxy traffic to `http://127.0.0.1:8787` while preserving SSRF blocks | M1 | Survey (Explorer 1) |
| 6 | Lock-Free Journal File Watcher | Dedicated OS background thread tailing `~/.safeagents/calls.jsonl` using `notify` and bounded channels | M1 | Survey (Explorer 1) |
| 7 | Sidecar Test Harness & Sub-15ms Benchmarks | Automated benchmarks simulating clean calls, undeclared tools, exfil, and ATIF patterns with <15ms replacement | M1 | Survey (Explorer 1) |
| 8 | Stage 1 Request-Only Validator | Zero-copy JSON/SSE parser validating declared tools and argument URLs/IPs verbatim against user prompt turns | M2 | Survey (Spec Miner 2 / Explorer 3) |
| 9 | Assistant Turn Context Stripping | Strips `role == "assistant"` messages before validating host sourcing to prevent self-citation escapes | M2 | Survey (Spec Miner 2 / Explorer 3) |
| 10 | Stage 2 Native ATIF-Scan State Machine | Precompiled `RegexSet` and `AhoCorasick` state machine running in <500µs on worker pool | M2 | Survey (Spec Miner 2 / Explorer 3) |
| 11 | High-Severity Breakout Detectors | Precompiled detectors for `/proc/1/environ`, `curl --noproxy`, `unshare`/`nsenter`, k8s tokens, and IMDS | M2 | Survey (Spec Miner 2 / Explorer 3) |
| 12 | Stage 3 Isolated Judge Engine | Isolated decision client querying Ollama (`127.0.0.1:11434`) with stripped XML context and strict schema | M2 | Survey (Spec Miner 2 / Explorer 3) |
| 13 | Native OshoosiScrubber | Port `safeagents scrub` rules: API keys, env secrets, emails (`<email>`), home paths (`{root}<user>`), public IPs (`<ip>`) | M2 | Survey (Spec Miner 2 / Explorer 3) |
| 14 | Calls Journal Emitter | Append-only structured JSONL logger emitting `~/.safeagents/calls.jsonl` per `docs/journal.md` schema | M2 | Survey (Spec Miner 2 / Explorer 3) |
| 15 | Middleware Pipeline Dispatcher Integration | Wire 3-stage inspection into `crates/osoosi-sandbox/src/tiered_executor.rs` before Wasmtime/AppContainer execution | M2 | Survey (Explorer 3) |
| 16 | KillSwitch & CAGE Governance Wiring | High-severity findings or Judge blocks invoke `kill_switch.kill()` and trip CAGE CBF violations | M2 | Survey (Explorer 3) |
| 17 | AgentOctopus to OshoosiClaw Workspace Migration | Migrate routing (`osoosi-dashboard`), skills (`osoosi-sandbox`), and gateway with hierarchical semaphores | M2 | Survey (Explorer 3) |
| 18 | Strict OS-Conditional Compilation | Guard all platform-specific bindings with `#[cfg(target_os = "...")]` (eBPF Linux, WFP Windows, PF macOS) | M3 | Survey (Explorer 3) |
| 19 | Cross-Platform CI/CD Matrix | Expand `.github/workflows/ci.yml` to Linux, Windows, and macOS runners with `--all-features` | M3 | Survey (Explorer 3) |
| 20 | Code Formatting & Clippy Zero-Warnings Pass | `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` | M3 | Survey (Explorer 3) |
| 21 | Full Workspace & 562-Case Misuse Simulation Verification | Run full `cargo test --workspace --all-features` including concurrent stress tests and the 562-case benchmark | M3 | Survey (Spec Miner 2 / Explorer 3) |
| 22 | E2E Opaque-Box Test Harness (Tiers 1-4) | Comprehensive opaque-box test runner validating all features independently of internal structure | E2E | Survey (Project Pattern) |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Multithreaded AgentOctopus + SafeAgents Harness | Features 1–7: Dependencies, Tokio multi-thread, Rayon pool, HTTP/2 client, Egress proxy bypass, Journal file watcher, Sub-15ms benchmarks | none | DONE |
| M2 | Native Rust Inspection & OshoosiClaw Migration | Features 8–17: Stage 1 RequestValidator, Stage 2 Native ATIF-scan, Stage 3 Judge & OshoosiScrubber, Journal emitter, Middleware wiring, CAGE hooks, Workspace migration | none | IN_PROGRESS |
| M3 | Cross-Platform Builds & CI/CD Verification | Features 18–21: Target OS gating, 3-OS CI matrix, Clippy zero-warnings, Formatting, Full test suite with 562-case misuse bench | M1, M2 | PLANNED |
| E2E | E2E Testing Track | Feature 22: Opaque-box test suite across Tiers 1-4, publish TEST_READY.md | none | DONE |
| M4 | Final Acceptance & Adversarial Hardening | Phase 1: 100% E2E test pass (Tiers 1-4); Phase 2: Tier 5 Adversarial Coverage Hardening | M1, M2, M3, E2E | PLANNED |

---

## Interface Contracts

### 1. SafeAgentsClient ↔ SafeAgents Sidecar Proxy (M1)
- **Protocol**: HTTP/2 over cleartext (h2c) with `TCP_NODELAY` and persistent keep-alive.
- **Base URLs**:
  - Anthropic: `http://127.0.0.1:8787/v1/messages`
  - OpenAI: `http://127.0.0.1:8787/v1/chat/completions`
- **Streaming Contract**: Text generation tokens stream transparently. Blocked tool calls are replaced in-stream with synthetic text delta events:
  `[safeagents] blocked call to `<tool_name>`: <reason>`.

### 2. RequestValidator ↔ NativeAtifScanner ↔ TieredExecutionDispatcher (M2)
```rust
pub struct ToolInspectionRequest<'a> {
    pub tool_name: &'a str,
    pub arguments_json: &'a str,
    pub declared_tools: &'a [String],
    pub user_prompt_turns: &'a [String],
    pub allowed_hosts: &'a [String],
}

pub enum ToolInspectionVerdict {
    Allow,
    Blocked {
        reason: String,
        notice: String,
        signals: Vec<AtifSignal>,
    },
    Suspicious {
        signals: Vec<AtifSignal>,
        judge_verdict: Option<JudgeVerdict>,
    },
}
```

### 3. IsolatedJudge ↔ Ollama Local Instance (M2)
- **Endpoint**: `POST http://127.0.0.1:11434/api/chat` or `/v1/chat/completions`
- **Payload Schema**:
  ```json
  {
    "model": "qwen2.5",
    "messages": [
      {"role": "system", "content": "You review tool calls an AI agent is about to run... Answer with JSON only: {\"verdict\": \"allow\" or \"block\", \"reason\": \"<one short sentence>\"}"},
      {"role": "user", "content": "<task>...</task>\n<tool_call name=\"...\">...</tool_call>\n<scanner_findings>...</scanner_findings>"}
    ],
    "temperature": 0.0,
    "format": "json"
  }
  ```

### 4. OshoosiScrubber ↔ CallsJournal (M2)
- Emits structured JSONL telemetry to `~/.safeagents/calls.jsonl`:
  `{"id": u64, "time": f64, "verdict": "blocked"|"flagged"|"suspicious", "tool": String, "arguments": String, "reason": Option<String>, "signals": [AtifSignal], "judge": Option<String>, "model": String, "task": String}`

---

## Code Layout

### AgentOctopus (`d:\harfile\AgentOctopus`)
```
src/
├── main.rs                                 # #[tokio::main(flavor = "multi_thread")]
├── bin/                                    # All binary targets with multi_thread flavor
├── security/
│   ├── safeagents_client.rs                # Persistent HTTP/2 client for sidecar proxy
│   ├── journal_watcher.rs                  # Lock-free notify + crossbeam background file watcher
│   ├── cpu_pool.rs                         # Rayon threadpool dispatcher for JSON/ATIF
│   └── atif_scan.rs                        # Local pattern detector for harness benchmarks
├── containment_ring/
│   └── egress_proxy.rs                     # Authenticated loopback exception for 127.0.0.1:8787
tests/
└── safeagents_multithreaded_harness_tests.rs # Benchmarks & latency tests
```

### OshoosiClaw (`d:\harfile\OshoosiClaw`)
```
crates/
├── osoosi-sandbox/src/
│   ├── tiered_executor.rs                  # Pre-execution inspection interceptor hook
│   └── safeagents/                         # Native 3-stage Rust inspection pipeline
│       ├── mod.rs                          # Pipeline coordinator & verdict types
│       ├── request_validator.rs            # Stage 1: Zero-copy JSON/SSE & host validator
│       ├── atif_scanner.rs                 # Stage 2: Precompiled RegexSet & AhoCorasick
│       ├── judge.rs                        # Stage 3: Isolated Ollama judge client
│       ├── scrubber.rs                     # Native OshoosiScrubber trajectory redaction
│       └── journal.rs                      # CallsJournal JSONL file emitter
├── osoosi-dashboard/src/                   # Migrated AgentOctopus API routes & Axum server
├── osoosi-policy/src/cage/                 # CAGE governance CBF trip hooks
tests/
└── safeagents_misuse_suite.rs              # 562-case misuse simulation suite
.github/workflows/
└── ci.yml                                  # 3-OS matrix (Linux, Windows, macOS)
```
