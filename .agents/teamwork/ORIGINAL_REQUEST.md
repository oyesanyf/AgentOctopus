# Original User Request

## Initial Request — 2026-11-02T15:39:11Z

Integrate Google Cybernetic Agent Governance Engine (CAGE) with AgentOctopus natively in Rust for production use, implementing the 7-tier two-phase governance pipeline, CAGE Substrate Contract v1.0, and evidence-bound routing seal verification.

Working directory: d:\harfile\AgentOctopus
Integrity mode: development

Reference:
- Google CAGE: https://github.com/google/cybernetic-agent-governance-engine (Apache-2.0, arXiv:2606.12320)
- Integration Plan: C:\Users\oyesanyf\.gemini\antigravity\brain\fa6f75de-b8c5-4c80-a440-d7d12a44e713\cage_integration_plan.md

## Requirements

### R1. Native Rust CAGE Governance Engine Core
Implement the core CAGE governance module under `src/security/cage_governance/` with Apache-2.0 attribution notices:
- `substrate_translator.rs`: Implement CAGE Substrate Contract v1.0 multi-format policy translation auto-detecting Microsoft ACS, LF AAIF, NIST OSCAL 1.1.x, Lula Validation, and Native CAGE YAML formats. Compile ingested policies into Cedar policies, STPA Unsafe Control Action (UCA) rules, and a deterministic 16-character hex SHA-256 `policy_version_id`, enforcing HTTP 409 Conflict on version mismatch.
- `ftra_stpa.rs`: Implement Tier 0.5 Forward-Looking Trajectory Reachability Analyzer (`PlanGraphAnalyzer`) traversing linear or DAG execution steps with reversibility classification (`Reversible`, `Compensatable`, `ConditionalAutonomous`, `IrreversibleTerminal`) and fail-closed NaN/Inf confidence normalization. Implement Tier 1 STPA/STAMP UCA validation (`StpaValidator`) bound to authenticated `TrustedArmHandle` identities.
- `cbf_fiscal.rs`: Implement Tier 3a Discrete-Time Control Barrier Function (`CbfSafetyEngine`) enforcing $h(S_{t+1}) \ge (1-\gamma)h(S_t) \ge 0$, sequence replay high-water marks, and monotonic fence epochs. Implement Tier 4 two-phase fiscal and resource pre-reservation (`DebitLedger` & `ReservationScope`) supporting `preview`, `commit`, `rollback`, and `confirm`.
- `routing_seal.rs`: Implement CAGE Substrate Contract §3 Evidence-Bound Cryptographic Routing Seals bound to `SecurityAuditLog` SHA-256 chain hashes (`record_hash`) with a 30-second default TTL and atomic single-use consumption.
- `pipeline.rs`: Implement the 7-tier two-phase pipeline (`run_pipeline`) across `Profile::{Full, PostHitl, DryRun}`, dynamically selecting `phase2_mode()` (`Skip`, `Preview`, `Commit`) and producing canonical CAGE verdicts (`ALLOW`, `NARROW`, `REQUIRE_APPROVAL`, `DEFER`, `DENY`).
- `no_direct_bind_proof.rs`: Native Rust port of the BFS state machine formal model verifying the No-Direct-Bind invariant ($\text{NoDirectBind} \iff (\text{phase} = \text{EXECUTED}) \implies (\text{resolvedAllow} = \text{TRUE})$) across 34 gated states, generating counterexamples for ungated configurations, and verifying `GOVERNANCE_TRACE` schema v1 conformance across all 7 rules.
- `mod.rs`: Export unified `CageGovernanceEngine` struct and public types.

### R2. Actuator Confinement Seal Enforcement
Integrate CAGE seal enforcement into `ArmContainmentRing` (`src/containment_ring/arm_ring.rs`) and register the module in `src/security/mod.rs` and `src/lib.rs`:
- Add `execute_tool_with_cage_seal` requiring an unconsumed, valid evidence-bound `CageRoutingSeal` before Tier-1 Wasm or Tier-2 AppContainer execution proceeds.
- Record and emit `GOVERNANCE_TRACE` `EXECUTED` events tied to the consumed seal reference.

### R3. CAGE Substrate Contract HTTP Endpoints
Expose CAGE Substrate Contract v1.0 and proof endpoints in `src/web/api.rs` and route them in `src/web/server.rs`:
- `POST /governance/ingest-policy` and `POST /api/cage/ingest-policy`
- `GET /governance/policy-version` and `GET /api/cage/policy-version`
- `POST /governance/validate-action`, `POST /v1/governance/validate-action`, and `POST /api/cage/validate-action`
- `POST /governance/consume-seal` and `POST /api/cage/consume-seal`
- `GET /api/cage/proof-status` and `POST /api/cage/trace-conformance`

### R4. Comprehensive Integration Test Suite
Implement an end-to-end integration test suite in `tests/cage_governance_integration_tests.rs`:
- Provide synthetic policy fixtures for all 5 formats and verify compilation, version hashing, and 409 drift rejection.
- Test FTRA graph analysis and irreversibility classification.
- Test 2-phase CBF barrier validation and fiscal preview/commit/rollback cycles.
- Test evidence-bound routing seal issuance, successful actuation, and replay rejection on duplicate consumption.
- Test BFS state machine proof (confirming 34 gated states) and 7-rule trace conformance validation.

## Acceptance Criteria

### Governance Core & Policy Translation
- [ ] Substrate policy ingestion auto-detects and parses ACS, AAIF, OSCAL 1.1.x, Lula, and CAGE YAML formats into Cedar policies and STPA rules.
- [ ] Ingestion computes a deterministic 16-character hex SHA-256 `policy_version_id` and rejects mismatched pinned versions with HTTP 409 Conflict.
- [ ] FTRA graph reachability analyzer traverses execution plans, treats NaN/Inf confidence as 0.0 fail-closed, and flags irreversible terminal steps with `HitlRequired` or `Blocked`.
- [ ] Discrete-Time Control Barrier Function enforces $h(S_{t+1}) \ge (1-\gamma)h(S_t) \ge 0$, rejects sequence replay regression, and verifies monotonic fence epochs.
- [ ] Two-phase resource pre-reservation correctly performs `preview`, `commit`, `rollback`, and `confirm` without balance leakage.

### Routing Seal & Containment Actuation
- [ ] Cryptographic routing seals bind to `SecurityAuditLog` chain hash (`record_hash`) and enforce a 30s TTL.
- [ ] `ArmContainmentRing::execute_tool_with_cage_seal` succeeds on first execution with a valid seal and atomically marks it consumed.
- [ ] Replayed, duplicate, or expired routing seals are rejected before actuator invocation.
- [ ] Actuator execution emits conforming `GOVERNANCE_TRACE` `EXECUTED` records.

### Formal Proof & Trace Conformance
- [ ] BFS state machine verifier exhaustively checks reachable states and proves No-Direct-Bind across exactly 34 gated states.
- [ ] BFS verifier detects an explicit counterexample when run in ungated mode (17 reachable states).
- [ ] Trace conformance verifier validates `GOVERNANCE_TRACE` streams against all 7 rules (`schema`, `plan`, `coverage`, `seal`, `reachable`, `no_direct_bind`, `single_use`).

### HTTP Endpoints & Clean Build
- [ ] Substrate HTTP endpoints in `src/web/server.rs` (`/governance/ingest-policy`, `/governance/policy-version`, `/governance/validate-action`, `/governance/consume-seal`, `/api/cage/proof-status`, `/api/cage/trace-conformance`) are wired and respond correctly.
- [ ] `cargo test --test cage_governance_integration_tests` compiles and passes with all tests green.
