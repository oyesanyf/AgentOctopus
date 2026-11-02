# Project: Google CAGE Native Rust Governance Engine Integration for AgentOctopus

## Architecture
AgentOctopus integrates Google Cybernetic Agent Governance Engine (CAGE v4.0.0, arXiv:2606.12320, Apache-2.0) natively in pure Rust without external Docker or Python sidecar dependencies. The architecture provides complete wire compatibility with the CAGE Substrate Contract v1.0, embedding a 7-tier two-phase governance pipeline directly within the security and containment fabric.

### Data Flow & Component Interfaces
1. **Policy Ingestion (`substrate_translator.rs`)**:
   - Ingests Microsoft ACS, LF AAIF, NIST OSCAL 1.1.x, Lula Validation, and Native CAGE YAML via G4 auto-detection priority.
   - Compiles policies into Cedar forbid rules, STPA Unsafe Control Actions (UCAs), and optional Control Barrier Function parameters.
   - Serializes compiled policies via pure-Rust RFC 8785 JSON Canonicalization Scheme (JCS) to generate a deterministic 16-hex SHA-256 `policy_version_id`.
   - Enforces HTTP 409 Conflict (`POLICY_VERSION_MISMATCH`) on version drift.
2. **Phase 1 Read-Only Verification (`ftra_stpa.rs`, `pipeline.rs`)**:
   - Tier 0.5 FTRA: Analyzes execution graphs for reversibility (`Reversible`, `Compensatable`, `ConditionalAutonomous`, `IrreversibleTerminal`), enforces caller authority rank, and normalizes NaN/Inf confidence to 0.0 fail-closed.
   - Tier 1 STPA: Validates UCAs against 4 Leveson hazard categories and strips caller identities, binding strictly to authenticated `TrustedArmHandle`.
   - Tier 3b Cedar Gate: Evaluates compiled Cedar policies against proposed actions.
   - Tier 2 Confidence Gate: Evaluates SR 26-2 model confidence thresholds (0.95 ALLOW candidate, 0.70 REQUIRE_APPROVAL, <0.70 DEFER).
   - Tier 5 Consensus Gate: Evaluates Bayesian consensus quorum.
3. **Phase 2 Mutating Control (`cbf_fiscal.rs`, `pipeline.rs`)**:
   - Dynamic `phase2_mode()`: `Skip` on Phase 1 HARD deny, `Preview` on deferral/approval/dry-run, `Commit` on clean Phase 1.
   - Tier 3a Discrete-Time CBF: Enforces $h(S_{t+1}) = (B_t - c) - B_{\min} \ge (1 - \gamma) h(S_t) \ge 0$, monotonic sequence high-water marks, and monotonic fence epochs.
   - Tier 4 Two-Phase Fiscal Pre-Reservation: Atomically executes `preview`, `commit`, `rollback`, and `confirm` with zero fiscal leakage.
4. **Evidence-Bound Cryptographic Routing Seal (`routing_seal.rs`)**:
   - Issues HMAC-SHA256 routing seals bound to `SecurityAuditLog::record_event` SHA-256 chain hashes (`record_hash`) enforcing Tallam 2026 *Evidence Sufficiency*.
   - Enforces 30-second TTL, 5-second clock skew tolerance, and atomic single-use consumption.
5. **Formal BFS State Machine & Trace Conformance (`no_direct_bind_proof.rs`)**:
   - Pure-Rust BFS state machine proving No-Direct-Bind ($\text{NoDirectBind} \iff (\text{phase} = \text{EXECUTED}) \implies (\text{resolvedAllow} = \text{TRUE})$) across 34 gated states.
   - Generates counterexample in ungated model (17 states) and proves skipped-tier blocking (31 states).
   - Verifies audit logs against all 7 `GOVERNANCE_TRACE` v1 conformance rules.
6. **Actuator Confinement Integration (`arm_ring.rs`)**:
   - Enforces `execute_tool_with_cage_seal` in `ArmContainmentRing` before Tier-1 Wasm or Tier-2 AppContainer actuation, recording `GOVERNANCE_TRACE` `EXECUTED` events.
7. **HTTP Substrate Server (`src/web/`)**:
   - Exposes `/governance/*`, `/v1/governance/*`, and `/api/cage/*` endpoints in `src/web/api.rs` and `src/web/server.rs` with `request_guard` exemptions.

---

## Feature Inventory

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F01 | Multi-Format Policy Auto-Detection | Detects ACS, AAIF, OSCAL 1.1.x, Lula, and CAGE YAML via G4 priority order | M1 | Survey |
| F02 | Cedar & STPA Rule Compilation | Compiles ingested policies into Cedar forbid rules and STPA UCAs | M1 | Survey |
| F03 | RFC 8785 JCS & 16-Hex Version Pinning | Canonicalizes policy JSON and extracts 16-hex SHA-256 policy_version_id | M1 | Survey |
| F04 | HTTP 409 Version Drift Conflict | Enforces HTTP 409 Conflict on pinned policy version mismatch | M1 | Survey |
| F05 | Tier 0.5 FTRA Reachability & Irreversibility | DAG traversal with Reversible/Compensatable/ConditionalAutonomous/IrreversibleTerminal classification | M1 | Survey |
| F06 | Fail-Closed Confidence Normalization | Maps NaN/Inf confidence to 0.0 and evaluates SR 26-2 thresholds | M1 | Survey |
| F07 | Tier 1 STPA Validator & Identity Binding | Validates UCAs across 4 hazard categories bound to TrustedArmHandle | M1 | Survey |
| F08 | Tier 3a Discrete-Time CBF & Epoch Defense | Discrete-time CBF $h(S_{t+1}) \ge (1-\gamma)h(S_t) \ge 0$, sequence replay high-water marks, fence epochs | M1 | Survey |
| F09 | Tier 4 Two-Phase Fiscal Pre-Reservation | Transactional preview, commit, rollback, and confirm with zero balance leakage | M1 | Survey |
| F10 | Evidence-Bound Cryptographic Routing Seals | HMAC-SHA256 seals bound to SecurityAuditLog record_hash, 30s TTL, atomic single-use | M1 | Survey |
| F11 | 2-Phase 7-Tier Dynamic Pipeline | Pipeline execution with dynamic phase2_mode (Skip/Preview/Commit) and canonical verdicts | M1 | Survey |
| F12 | Pure-Rust BFS State Machine Proof | Exhaustive BFS model proving No-Direct-Bind on 34 states, 17-state ungated counterexample | M1 | Survey |
| F13 | 7-Rule GOVERNANCE_TRACE Conformance Verifier | Validates trace streams against schema, plan, coverage, seal, reachable, no_direct_bind, single_use | M1 | Survey |
| F14 | Unified CageGovernanceEngine Module Exports | Exports unified engine struct and types in security/cage_governance/ and security/mod.rs | M1 | Survey |
| F15 | Actuator Confinement Seal Gating | execute_tool_with_cage_seal requiring valid unconsumed seal before Tier 1/2 actuation | M2 | Survey |
| F16 | Actuator GOVERNANCE_TRACE Emission | Emits conforming EXECUTED trace events bound to consumed seal reference | M2 | Survey |
| F17 | CAGE Substrate Contract HTTP Handlers | Implements ingest-policy, policy-version, validate-action, consume-seal, proof-status, trace-conformance | M3 | Survey |
| F18 | Web Server Routing & Guard Exemption | Routes substrate endpoints in server.rs and exempts from token in request_guard.rs | M3 | Survey |
| F19 | Comprehensive Integration Test Suite | Full integration tests in tests/cage_governance_integration_tests.rs covering all requirements | M4 | Survey |
| F20 | E2E Opaque-Box Suite & Adversarial Hardening | End-to-end requirement validation (Tiers 1-4) and Tier 5 adversarial coverage hardening | M5 | Survey |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Native Rust CAGE Governance Engine Core | Implement `src/security/cage_governance/` (all 6 core submodules + `mod.rs`), register in `src/security/mod.rs` and `src/lib.rs` (Features F01-F14) | none | DONE (32 unit + 14 stress + 9 challenger tests pass, commit 5696218) |
| M2 | Actuator Confinement Seal Enforcement | Integrate `execute_tool_with_cage_seal` and `GOVERNANCE_TRACE` `EXECUTED` emission into `src/containment_ring/arm_ring.rs` (Features F15-F16) | M1 | DONE (26 containment ring + 8 challenger tests pass, commits aa6ba08 & 1a041fa) |
| M3 | CAGE Substrate Contract HTTP Endpoints | Wire `CageGovernanceEngine` into `WebState` (`src/web/api.rs`), implement substrate handlers, route in `src/web/server.rs`, exempt in `src/web/request_guard.rs` (Features F17-F18) | M1, M2 | IN_PROGRESS |
| M4 | Comprehensive Integration Test Suite | Implement `tests/cage_governance_integration_tests.rs` verifying 5 formats, FTRA, CBF, seals, single-use actuation, 34-state BFS proof, trace conformance (Feature F19) | M1, M2, M3 | PLANNED |
| M5 | Final Milestone: 100% E2E Pass & Adversarial Hardening | Pass 100% of E2E test suite (Tiers 1-4) published by E2E Testing Track, followed by Phase 2 adversarial coverage hardening (Tier 5) (Feature F20) | M4, E2E Track | PLANNED |

---

## Interface Contracts

### M1 Core ↔ M2 Containment Ring
- `CageGovernanceEngine::verify_and_consume_seal(&self, seal: &CageRoutingSeal, expected_action: &str, expected_digest: &str) -> Result<(), SealRejection>`
- `CageGovernanceEngine::record_actuation_trace(&self, seal_ref: &str, action: &str, receipt: &TieredExecutionReceipt) -> Result<String, GovernanceTraceError>`
- `CageGovernanceEngine::confirm_fiscal_reservation(&self, debit_id: &str) -> Result<(), CbfViolation>`

### M1 Core ↔ M3 Web API
- `CageGovernanceEngine::ingest_policy(&self, raw_policy: &str, expected_version: Option<&str>) -> Result<IngestPolicyResponse, CageApiError>`
- `CageGovernanceEngine::active_policy_version(&self) -> String`
- `CageGovernanceEngine::validate_action(&self, req: &GovernanceRequest) -> Result<GovernanceEvaluationResult, CageApiError>`
- `CageGovernanceEngine::verify_and_consume_seal_direct(&self, seal_json: &str) -> Result<ConsumeSealResponse, CageApiError>`
- `CageGovernanceEngine::proof_status(&self) -> ProofStatusResponse`
- `CageGovernanceEngine::verify_trace_conformance(&self, traces: &[serde_json::Value]) -> Result<StreamVerificationReport, CageApiError>`

---

## Code Layout

```
d:\harfile\AgentOctopus\
├── src/
│   ├── security/
│   │   ├── mod.rs                                    # Module registration & re-exports
│   │   └── cage_governance/                          # [NEW] CAGE Native Core
│   │       ├── mod.rs                                # Public exports & CageGovernanceEngine
│   │       ├── substrate_translator.rs              # 5-format policy translator & RFC 8785 JCS
│   │       ├── ftra_stpa.rs                          # Tier 0.5 FTRA DAG analyzer & Tier 1 STPA validator
│   │       ├── cbf_fiscal.rs                         # Tier 3a Discrete-Time CBF & Tier 4 DebitLedger
│   │       ├── routing_seal.rs                       # CAGE Substrate §3 evidence-bound routing seal
│   │       ├── pipeline.rs                           # 7-tier 2-phase dynamic governance pipeline
│   │       └── no_direct_bind_proof.rs               # BFS 34-state state machine model & trace verifier
│   ├── containment_ring/
│   │   └── arm_ring.rs                               # [MODIFIED] execute_tool_with_cage_seal & trace emission
│   ├── web/
│   │   ├── api.rs                                    # [MODIFIED] WebState registration & CAGE handlers
│   │   ├── server.rs                                 # [MODIFIED] Substrate route dispatch
│   │   └── request_guard.rs                          # [MODIFIED] Loopback path token exemptions
│   └── lib.rs                                        # [MODIFIED] Library re-exports
├── tests/
│   └── cage_governance_integration_tests.rs          # [NEW] Comprehensive integration test suite
└── PROJECT.md                                        # Living Project Architecture & Milestone Index
```
