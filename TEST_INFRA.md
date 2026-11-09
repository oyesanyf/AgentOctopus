# SafeAgents Integration & Native OshoosiClaw Migration Test Infrastructure (`TEST_INFRA.md`)

## 1. Executive Summary & Test Architecture

This document specifies the end-to-end testing architecture, 4-tier test case methodology, feature traceability matrix, and verification infrastructure for the **SafeAgents Tool-Call Security Interception & Native OshoosiClaw Migration** within `AgentOctopus` and `OshoosiClaw`.

The test infrastructure provides complete opaque-box verification across the entire tool inspection, interception, and containment lifecycle:
1. **Track 1 (R1) Interception & Test Harness**:
   - Multi-producer, multi-consumer async Tokio runtime (`#[tokio::main(flavor = "multi_thread")]`) paired with Rayon work-stealing threadpool for CPU-bound JSON/ATIF serialization.
   - Persistent HTTP/2 connection pooling (`reqwest::Client` with keep-alive, TCP_NODELAY, and h2c prior knowledge) to the local proxy (`http://127.0.0.1:8787`).
   - Lock-free background journal file watcher (`notify` with bounded `crossbeam_channel` queues) tailing `~/.safeagents/calls.jsonl` without blocking main agent loops.
   - Sub-15ms replacement of blocked tool calls with synthetic text notices in both Anthropic Messages and OpenAI Chat Completions streaming protocols.
2. **Track 2 (R2) Native Rust Middleware Pipeline**:
   - **Stage 1 (Request-Only Validation)**: Zero-copy JSON/SSE stream parsing (`serde_json` + `memchr`) verifying declared tool schemas and verbatim host sourcing against user prompt turns (strictly stripping assistant turns to prevent self-citation escapes).
   - **Stage 2 (Native ATIF-Scan)**: Precompiled `regex::RegexSet` and `aho_corasick::AhoCorasick` state machine executing in <500µs per tool call, matching high-severity breakouts (`/proc/1/environ`, `curl --noproxy`, `unshare`/`nsenter`, k8s tokens, cloud IMDS) and severity threshold gating.
   - **Stage 3 (Isolated Judge & Trajectory Scrubber)**: Decision model routing to Ollama (`127.0.0.1:11434`, `qwen2.5`) with stripped context (<task>, <tool_call>, <scanner_findings>, no agent thoughts), native `OshoosiScrubber` redacting API keys, env secrets, emails, home paths, and public IPs into the 10-field `calls.jsonl` schema.
   - **Governance & Confinement**: KillSwitch epoch increments and CAGE Control Barrier Function (CBF) trip hooks triggering immediate host containment.
3. **Track 3 (R3) Cross-Platform OS Builds & Verification**:
   - Strict target gating (`#[cfg(target_os = "...")]`) for platform-specific bindings: eBPF (Linux), WFP (Windows), PF (macOS).
   - Cross-platform CI matrix across Linux, Windows, and macOS with zero warnings on `cargo clippy --all-targets --all-features -- -D warnings`.
   - Full regression verification on the 562-case misuse simulation suite from `safeagents-judge-bench`.

---

## 2. 4-Tier Test Case Design Methodology

The test suite is structured around a rigorous 4-tier opaque-box methodology guaranteeing full structural, boundary, combinatoric, and end-to-end real-world coverage:

### Tier 1: Feature Coverage (Core Functional Verification)
- Verifies every core functional path across all 21 inventoried features (F01–F21) in isolation.
- Each feature must be covered by **at least 5 independent, self-contained test cases** (105+ tests total).
- Verifies happy paths, expected return values, schema adherence, and canonical error rejections.

### Tier 2: Boundary & Corner Case Analysis
- Verifies edge cases, stress limits, and adversarial boundary conditions for each feature (F01–F21).
- Each feature must be covered by **at least 5 boundary/corner test cases** (105+ tests total).
- Covers:
  - **Numerical & Size Bounds**: Empty strings, 0-byte frames, 10MB payloads, 4000-char arg limits, 6000-char task limits.
  - **Network & IP Bounds**: Port 8787 vs 8788, IPv6 loopback `[::1]`, IPv4-mapped IPv6 `::ffff:127.0.0.1`, malformed IP literals (`999.1.1.1`, `1.2.3.4.5`), cloud IMDS `169.254.169.254`.
  - **Concurrency & Confinement Bounds**: 1-thread vs multi-thread pools, 65,536 multiplexed streams, 100,000 rapid file notifications, channel queue backpressure.
  - **Encoding & Escaping Integrity**: Split SSE tokens across TCP chunk boundaries, percent-encoded authorities, Unicode paths, null-byte injection.

### Tier 3: Cross-Feature Combinations & Pairwise Interactions
- Systematically exercises complex inter-module interactions across features:
  - **F04 x F07 x F08**: Multiplexed HTTP/2 stream concurrency with interleaved clean calls, undeclared tool blocks, and unapproved host blocks.
  - **F08 x F09 x F10**: Adversarial assistant turn self-citation injection paired with proxy-bypass flags.
  - **F06 x F14 x F02**: Lock-free journal file watcher tailing concurrent multithreaded journal appends.
  - **F10 x F12 x F13**: Stage 2 medium-severity detection forwarding to Stage 3 stripped judge context and trajectory scrubber.
  - **F11 x F15 x F16**: High-severity breakout detection triggering KillSwitch epoch increment and CAGE CBF trip.
  - **F02 x F03 x F17**: Rayon threadpool serialization coupled with Tokio hierarchical semaphores under load.
  - **F18 x F20 x F21**: Multi-OS target-conditional compilation under clippy zero-warnings.

### Tier 4: Real-World Application Scenarios
- End-to-end integration and benchmark simulations derived from production and research workloads:
  1. **Multi-Agent Coding Swarm Simulation**: 16 concurrent agents executing 15 interleaved benign and adversarial turns (matching upstream `scripts/simulate.py`).
  2. **Terminal-Bench 2.1 Misuse Suite (562 Cases)**: Real-world tool call trajectories across 7 categories (237 eval gaming, 271 harness introspection, 10 credential misuse, 4 sandbox escape, 1 other overreach, 39 legit).
  3. **Self-Citation Prompt Injection & Lateral Exfiltration Gauntlet**: Adversarial multi-turn evasion probes attempting to bypass host validation through LLM reasoning and DNS rebinding.
  4. **End-to-End Journal File Watcher & Incident Response Pipeline**: Closed-loop detection, redaction, telemetry journal emission, watcher alert, and killswitch actuation.

---

## 3. Feature Traceability Matrix (F01 – F21)

| Feature ID | Feature Name | Primary Scope | Test Target & Suite | Tier 1 Count | Tier 2 Count | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F01** | Cargo Manifest & Dependencies Update | M1 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f01_dependencies` | 5 | 5 | VERIFIED |
| **F02** | Multi-Threaded Tokio Runtime Configuration | M1 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f02_tokio_multithread` | 5 | 5 | VERIFIED |
| **F03** | Rayon Serialization Dispatcher | M1 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f03_rayon_serialization` | 5 | 5 | VERIFIED |
| **F04** | Persistent HTTP/2 Connection Pool | M1 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f04_http2_client_pool` | 5 | 5 | VERIFIED |
| **F05** | Egress Proxy Loopback Sidecar Permit | M1 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f05_egress_sidecar_permit` | 5 | 5 | VERIFIED |
| **F06** | Lock-Free Journal File Watcher | M1 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f06_journal_file_watcher` | 5 | 5 | VERIFIED |
| **F07** | Sidecar Test Harness & Sub-15ms Benchmarks | M1 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f07_sidecar_benchmarks` | 5 | 5 | VERIFIED |
| **F08** | Stage 1 Request-Only Validator | M2 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f08_stage1_validator` | 5 | 5 | VERIFIED |
| **F09** | Assistant Turn Context Stripping | M2 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f09_assistant_turn_stripping` | 5 | 5 | VERIFIED |
| **F10** | Stage 2 Native ATIF-Scan State Machine | M2 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f10_stage2_atif_scanner` | 5 | 5 | VERIFIED |
| **F11** | High-Severity Breakout Detectors | M2 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f11_breakout_detectors` | 5 | 5 | VERIFIED |
| **F12** | Stage 3 Isolated Judge Engine | M2 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f12_stage3_judge_engine` | 5 | 5 | VERIFIED |
| **F13** | Native OshoosiScrubber | M2 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f13_native_scrubber` | 5 | 5 | VERIFIED |
| **F14** | Calls Journal Emitter | M2 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f14_calls_journal_emitter` | 5 | 5 | VERIFIED |
| **F15** | Middleware Pipeline Dispatcher Integration | M2 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f15_middleware_pipeline` | 5 | 5 | VERIFIED |
| **F16** | KillSwitch & CAGE Governance Wiring | M2 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f16_killswitch_governance` | 5 | 5 | VERIFIED |
| **F17** | AgentOctopus to OshoosiClaw Migration | M2 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f17_workspace_migration` | 5 | 5 | VERIFIED |
| **F18** | Strict OS-Conditional Compilation | M3 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f18_os_conditional_compilation` | 5 | 5 | VERIFIED |
| **F19** | Cross-Platform CI/CD Matrix | M3 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f19_cicd_matrix` | 5 | 5 | VERIFIED |
| **F20** | Code Formatting & Clippy Zero-Warnings Pass | M3 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f20_clippy_zero_warnings` | 5 | 5 | VERIFIED |
| **F21** | Full Workspace & 562-Case Misuse Verification| M3 | `safeagents_e2e_opaque_box_tests::tier1_feature_coverage::f21_misuse_suite_verification` | 5 | 5 | VERIFIED |

---

## 4. Expected Output Derivation & Verification Oracles

All expected values in this test suite are derived authoritatively from:
1. **Upstream SafeAgents Specification**: Commit SHA verified from `https://github.com/huggingface/safeagents` (`src/safeagents/rewrite.py`, `policy.py`, `scan.py`, `judge.py`, `scrub.py`, `journal.py`).
2. **Upstream atif-scan Taxonomy**: Commit SHA verified from `https://github.com/huggingface/atif-scan` (`detectors/side_channel.py`, `detectors/orchestrator.py`).
3. **Reference Benchmark**: `https://huggingface.co/datasets/harness-hub/safeagents-judge-bench` (562 test samples, 523 block, 39 allow).
4. **Mathematical & Deterministic Rules**:
   - Monotonic ID increment: $\text{ID}_{t+1} = \max(\text{ID}_t) + 1$.
   - Sub-15ms Latency Bound: $\Delta t_{\text{replace}} < 15.0\,\text{ms}$.
   - Sub-500µs Scan Latency: $\Delta t_{\text{atif\_scan}} < 500\,\mu\text{s}$.
   - RFC 1918 Private Ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, Loopback `127.0.0.0/8`.
   - Public IP Redaction: `ipaddress.is_global == true` -> `<ip>`.

---

## 5. Test Runner & Execution Protocol

### Automated Runner Command
To execute the complete E2E opaque-box test battery:
```powershell
cargo test --test safeagents_e2e_opaque_box_tests -- --nocapture
```

### Filtering Specific Tiers
```powershell
# Run Tier 1 Feature Coverage
cargo test --test safeagents_e2e_opaque_box_tests tier1 -- --nocapture

# Run Tier 2 Boundary & Corner Cases
cargo test --test safeagents_e2e_opaque_box_tests tier2 -- --nocapture

# Run Tier 3 Cross-Feature Combinations
cargo test --test safeagents_e2e_opaque_box_tests tier3 -- --nocapture

# Run Tier 4 Real-World Workloads & Misuse Suite
cargo test --test safeagents_e2e_opaque_box_tests tier4 -- --nocapture
```
