# Google CAGE Governance Engine Native Rust Test Infrastructure (`TEST_INFRA.md`)

## 1. Executive Summary & Test Architecture

This document specifies the testing architecture, 4-tier test case methodology, feature traceability matrix, and verification infrastructure for the **Google Cybernetic Agent Governance Engine (CAGE v4.0.0, arXiv:2606.12320, Apache-2.0)** native Rust integration within `AgentOctopus`.

The test infrastructure provides complete end-to-end verification across the entire governance lifecycle:
1. **Multi-Format Ingress**: Microsoft ACS, LF AAIF, NIST OSCAL 1.1.x, Lula Validation, and Native CAGE YAML compilation into Cedar and STPA rules with deterministic RFC 8785 JSON Canonicalization Scheme (JCS) SHA-256 version pinning and HTTP 409 Conflict drift rejection.
2. **Phase 1 Read-Only Verification**: Tier 0.5 FTRA DAG reachability analysis, reversibility classification, fail-closed NaN/Inf confidence normalization, and Tier 1 STPA identity-sanitized UCA validation.
3. **Phase 2 Mutating Control**: Tier 3a Discrete-Time Control Barrier Functions ($h(S_{t+1}) \ge (1-\gamma)h(S_t) \ge 0$), replay sequence high-water marks, monotonic fence epochs, and Tier 4 transactional fiscal pre-reservation (`preview`, `commit`, `rollback`, `confirm`).
4. **Evidence-Bound Cryptographic Routing Seals**: HMAC-SHA256 tokens cryptographically bound to `SecurityAuditLog` SHA-256 hash chains (`record_hash`), enforcing 30-second TTLs and atomic single-use consumption.
5. **Actuator Confinement Integration**: `ArmContainmentRing` tool gating requiring valid seals before Tier-1 Wasm or Tier-2 AppContainer execution and emitting `GOVERNANCE_TRACE` `EXECUTED` events.
6. **Substrate HTTP Server**: Wire-compatible REST endpoints (`/governance/*`, `/v1/governance/*`, `/api/cage/*`) protected by loopback request guard token exemptions.
7. **Formal Verification & Stream Conformance**: Pure-Rust BFS state machine proving the No-Direct-Bind invariant across strictly 34 gated states, discovering 17-state ungated counterexamples, and validating audit streams against all 7 `GOVERNANCE_TRACE` v1 rules.

---

## 2. 4-Tier Test Case Design Methodology

The test suite is structured around a rigorous 4-tier methodology guaranteeing full structural, boundary, combinatoric, and end-to-end real-world coverage:

### Tier 1: Feature Coverage (Core Functional Verification)
- Verifies every core functional path across all 20 inventoried features (F01–F20).
- Auto-detection priority and AST translation for all 5 specification formats.
- Complete execution of the 7-tier two-phase governance pipeline under `Full`, `PostHitl`, and `DryRun` profiles.
- Direct-binding enforcement and canonical verdict generation (`ALLOW`, `NARROW`, `REQUIRE_APPROVAL`, `DEFER`, `DENY`).

### Tier 2: Boundary & Corner Case Analysis
- **Numerical Edge Cases**: Float NaN, positive/negative infinity, zero division, tiny epsilon decay boundary values ($h \approx 10^{-12}$), and out-of-range $\gamma \notin (0, 1)$ validation in Control Barrier Functions.
- **Temporal & Clock Skew**: Expiration at exact boundary ($t = \text{expires\_at}$), clock drift within 5-second tolerance vs. outside tolerance ($t > 30\text{s}$), and future-dated issuance.
- **Graph Topology Edge Cases**: Disconnected components, cyclic dependency deadlocks, self-loops, and deep linear DAG chains in FTRA reachability analysis.
- **Identity & Protocol Sanitization**: Caller-injected spoofed credentials (`trader_role`, `trader_id`) stripped in Tier 1 STPA, and malicious non-canonical whitespace in RFC 8785 JCS canonicalization.

### Tier 3: Cross-Feature Combinations & Pairwise Interactions
- **JCS Canonicalization $\times$ Version Drift Rejection**: Permuted JSON keys across all 5 formats canonicalizing to identical hashes, while single-byte modifications trigger immediate HTTP 409 Conflict.
- **FTRA DAG $\times$ STPA UCA $\times$ Fiscal Pre-Reservation**: Multi-step execution plans containing mixed reversible and irreversible terminal actions correctly triggering `REQUIRE_APPROVAL` with Phase 2 switching to side-effect-free `Phase2Mode::Preview`.
- **Audit Hash Chain $\times$ Routing Seal $\times$ Actuator Consumption**: Routing seal issuance cryptographically binding `record_hash` from committed `SecurityAuditLog` entries, verified and consumed atomically by `ArmContainmentRing`.
- **Trace Conformance $\times$ BFS Formal Model**: Generated execution traces verified against all 7 formal rules matching the 34 reachable states of the BFS state space.

### Tier 4: Real-World Workload Scenarios & Concurrency Stress
- **Multithreaded Seal Racing**: 50–100 concurrent threads attempting to consume the same evidence-bound routing seal simultaneously; verified that exactly 1 thread succeeds and all others fail closed.
- **Multi-Arm Swarm Fleet Isolation**: 50 autonomous agent limbs (`ArmContainmentRing`) executing distinct tools with discrete routing seals without cross-arm ticket leakage or state corruption.
- **Autotomy & Fleet Re-generation**: Severing compromised limbs, advancing generational epochs, and verifying that revoked limb handles cannot replay seals or send lateral mesh messages.
- **Formal BFS 1,000-Trial Invariance**: 1,000 random-seed iterations verifying that the gated BFS model deterministically reaches exactly 34 states and the ungated model generates an explicit counterexample in 17 states.

---

## 3. Feature Traceability Matrix (F01 – F20)

| Feature ID | Feature Name | Primary Implementation Module | Test Target & Suite | Test Count | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **F01** | Multi-Format Policy Auto-Detection | `src/security/cage_governance/substrate_translator.rs` | `cage_governance_integration_tests`, `cage_governance::tests` | 10 | VERIFIED |
| **F02** | Cedar & STPA Rule Compilation | `src/security/cage_governance/substrate_translator.rs` | `cage_governance_integration_tests`, `cage_governance::tests` | 8 | VERIFIED |
| **F03** | RFC 8785 JCS & 16-Hex Version Pinning | `src/security/cage_governance/substrate_translator.rs` | `adversarial_challenger_m1_tests`, `adversarial_challenger_m4_tests` | 6 | VERIFIED |
| **F04** | HTTP 409 Version Drift Conflict | `src/security/cage_governance/substrate_translator.rs` | `adversarial_challenger_m3_tests`, `cage_governance_integration_tests` | 6 | VERIFIED |
| **F05** | Tier 0.5 FTRA Reachability & Irreversibility | `src/security/cage_governance/ftra_stpa.rs` | `cage_governance_integration_tests`, `cage_m1_adversarial_stress_tests` | 8 | VERIFIED |
| **F06** | Fail-Closed Confidence Normalization | `src/security/cage_governance/ftra_stpa.rs` | `cage_governance_integration_tests`, `cage_governance::tests` | 4 | VERIFIED |
| **F07** | Tier 1 STPA Validator & Identity Binding | `src/security/cage_governance/ftra_stpa.rs` | `adversarial_challenger_m1_tests`, `cage_governance_integration_tests` | 5 | VERIFIED |
| **F08** | Tier 3a Discrete-Time CBF & Epoch Defense | `src/security/cage_governance/cbf_fiscal.rs` | `cage_m1_adversarial_stress_tests`, `adversarial_challenger_m4_tests` | 10 | VERIFIED |
| **F09** | Tier 4 Two-Phase Fiscal Pre-Reservation | `src/security/cage_governance/cbf_fiscal.rs` | `cage_governance_integration_tests`, `adversarial_challenger_m4_2_tests` | 8 | VERIFIED |
| **F10** | Evidence-Bound Cryptographic Routing Seals | `src/security/cage_governance/routing_seal.rs` | `cage_m1_adversarial_stress_tests`, `adversarial_challenger_m2_tests` | 12 | VERIFIED |
| **F11** | 2-Phase 7-Tier Dynamic Pipeline | `src/security/cage_governance/pipeline.rs` | `cage_governance_integration_tests`, `cage_governance::tests` | 8 | VERIFIED |
| **F12** | Pure-Rust BFS State Machine Proof | `src/security/cage_governance/no_direct_bind_proof.rs` | `adversarial_challenger_m1_tests`, `adversarial_challenger_m4_2_tests` | 8 | VERIFIED |
| **F13** | 7-Rule GOVERNANCE_TRACE Conformance Verifier | `src/security/cage_governance/no_direct_bind_proof.rs` | `adversarial_challenger_m4_tests`, `adversarial_challenger_m3_2_tests` | 9 | VERIFIED |
| **F14** | Unified CageGovernanceEngine Module Exports | `src/security/cage_governance/mod.rs` | `cage_governance_integration_tests`, `security::cage_governance` | 6 | VERIFIED |
| **F15** | Actuator Confinement Seal Gating | `src/containment_ring/arm_ring.rs` | `arm_containment_ring_tests`, `adversarial_challenger_m4_2_tests` | 14 | VERIFIED |
| **F16** | Actuator GOVERNANCE_TRACE Emission | `src/containment_ring/arm_ring.rs` | `arm_containment_ring_tests`, `adversarial_challenger_m2_tests` | 8 | VERIFIED |
| **F17** | CAGE Substrate Contract HTTP Handlers | `src/web/api.rs` | `adversarial_challenger_m3_tests`, `web::api::tests` | 12 | VERIFIED |
| **F18** | Web Server Routing & Guard Exemption | `src/web/server.rs`, `src/web/request_guard.rs` | `adversarial_challenger_m3_tests`, `web::request_guard::tests` | 10 | VERIFIED |
| **F19** | Comprehensive Integration Test Suite | `tests/cage_governance_integration_tests.rs` | `tests/cage_governance_integration_tests.rs` | 25 | VERIFIED |
| **F20** | E2E Opaque-Box Suite & Adversarial Hardening | `tests/adversarial_challenger_m4*.rs` | `adversarial_challenger_m4_tests`, `adversarial_challenger_m4_2_tests` | 23 | VERIFIED |

---

## 4. Comprehensive Test Suite Catalog (179 Tests)

The test battery spans 12 distinct compilation and execution targets with a total of **179 passing tests and 0 failures**:

### 1. `tests/cage_governance_integration_tests.rs` (25 Tests)
Integration tests validating the end-to-end multi-format ingestion, 7-tier pipeline, CBF barriers, fiscal ledger, routing seals, formal proofs, and HTTP wire contracts:
- `test_cbf_barrier_inequality_and_boundary_conditions`: Validates $h(S_{t+1}) \ge (1-\gamma)h(S_t) \ge 0$.
- `test_cbf_replay_sequence_and_monotonic_fence_epochs`: Enforces monotonic sequence numbers and fence epochs.
- `test_ftra_fail_closed_confidence_normalization`: Enforces fail-closed normalization of NaN/Inf floats to 0.0.
- `test_ftra_semantic_reversibility_classification_and_authority_ranks`: Verifies reversibility classification hierarchy.
- `test_fiscal_two_phase_pre_reservation_and_zero_balance_leakage`: Verifies commit, rollback, and confirm without leaks.
- `test_ftra_sr_26_2_model_confidence_thresholds`: Verifies ALLOW (>=0.95), APPROVAL (0.70-0.95), and DEFER (<0.70).
- `test_ftra_dag_topological_execution_and_cycle_deadlock_detection`: Validates DAG dependency traversal and cycle rejection.
- `test_fixture_lula_validation_ingestion_and_compilation`: Parses Lula Validation manifest into rules and version hash.
- `test_fixture_native_cage_yaml_ingestion_and_compilation`: Ingests native CAGE YAML format with STPA control structures.
- `test_fixture_nist_oscal_ingestion_and_compilation`: Ingests NIST OSCAL 1.1.x component definitions.
- `test_formal_bfs_ungated_counterexample_strictly_17_states`: Proves ungated execution yields counterexample in 17 states.
- `test_stpa_tier1_caller_identity_scrubbing`: Strips untrusted caller roles and binds authenticated handle identities.
- `test_fixture_linux_foundation_aaif_ingestion_and_compilation`: Ingests Linux Foundation AAIF governed run loop policies.
- `test_fixture_microsoft_acs_ingestion_and_compilation`: Ingests Microsoft ACS behavior declarations.
- `test_rfc8785_jcs_canonicalization_and_version_drift_rejection`: Enforces RFC 8785 canonicalization and version drift rejection.
- `test_evidence_bound_routing_seal_issuance_and_ttl_validation`: Validates 30-second TTL and audit log hash binding.
- `test_engine_dynamic_policy_ingest_and_version_transition`: Verifies runtime policy updates and version transitions.
- `test_formal_bfs_gated_model_strictly_34_reachable_states`: Formally proves No-Direct-Bind across 34 gated states.
- `test_governance_trace_stream_conformance_and_adversarial_rule_violations`: Verifies trace streams against all 7 rules.
- `test_pipeline_dynamic_profiles_and_direct_verdicts`: Verifies pipeline execution across Full, PostHitl, and DryRun profiles.
- `test_seal_parameter_tampering_and_signature_corruption_rejection`: Rejects tampered action digests and invalid HMAC signatures.
- `test_arm_containment_actuation_with_cage_seal_and_replay_rejection`: Validates actuation execution and single-use seal rejection.
- `test_http_endpoint_cage_policy_ingest_and_version`: Tests `/governance/ingest-policy` and `/governance/policy-version`.
- `test_http_endpoint_cage_validate_action_and_consume_seal`: Tests action validation and atomic seal consumption via HTTP.
- `test_http_endpoint_proof_status_and_trace_conformance`: Tests proof status and trace conformance HTTP endpoints.

### 2. `tests/adversarial_challenger_m4_tests.rs` (15 Tests)
Opaque-box adversarial challenger tests targeting mathematical, cryptographic, temporal, and race condition boundaries:
- `test_challenge2_cbf_decaying_envelope_multi_step_trajectory`: Evaluates multi-step decaying state trajectories.
- `test_challenge2_adversarial_cbf_barrier_tiny_epsilon_boundary_attacks`: Precision testing on $10^{-12}$ margin boundaries.
- `test_challenge2_floor_breach_vs_decay_and_malformed_numerics`: Defends against floor breaches and numeric corruption.
- `test_challenge3_temporal_ttl_skew_and_tampered_expires_at`: Enforces strict TTL expiration and clock skew bounds.
- `test_challenge3_tampered_hmac_signature_and_chain_anchor_attacks`: Detects corrupted signatures and unanchored hashes.
- `test_challenge1_non_canonical_whitespace_and_jcs_invariance`: Asserts whitespace invariance in RFC 8785 canonicalization.
- `test_challenge4_trace_injection_missing_decision_and_unsealed_verdict`: Detects injected traces missing decision records.
- `test_challenge4_trace_injection_cbf_budget_leakage_and_schema_violations`: Enforces schema and budget balance conformance.
- `test_challenge4_trace_injection_actuation_without_seal_consumed_rule6`: Detects unconsumed seal references on actuation.
- `test_challenge4_trace_injection_replay_coverage_and_illegal_state_transition`: Rejects replayed coverage and invalid state steps.
- `test_challenge2_sequence_replay_and_fence_epoch_boundary_concurrency`: Concurrent sequence numbers and epoch boundaries.
- `test_challenge3_concurrent_multithreaded_race_replay_single_winner`: Multi-threaded single-winner seal consumption race.
- `test_challenge3_arm_containment_ring_async_race_single_actuation`: Async race on `ArmContainmentRing` tool actuation.
- `test_challenge1_rfc8785_version_drift_injection_strict_409_conflict`: Injects mutated policies to trigger HTTP 409 Conflict.
- `test_challenge1_severe_policy_corruption_and_malformed_syntax`: Rejects malformed policy structures and syntax errors.

### 3. `tests/adversarial_challenger_m4_2_tests.rs` (8 Tests)
Multi-trial statistical stability and high-concurrency gauntlet tests:
- `test_adversarial_fiscal_cbf_barrier_boundary_stress`: Stresses combined CBF barrier and fiscal limits.
- `test_adversarial_fiscal_ledger_concurrent_zero_drift`: Verifies exact zero balance drift under concurrent load.
- `test_adversarial_actuator_concurrency_with_fiscal_settlement`: Verifies atomic settlement during actuator concurrency.
- `test_adversarial_actuator_cross_arm_fleet_concurrency_race`: Stresses multi-arm fleet execution concurrency.
- `test_adversarial_actuator_single_use_high_concurrency_race`: High-concurrency race on single-use seal consumption.
- `test_adversarial_formal_bfs_1000_random_seeds_exploration_invariance`: 1,000-seed invariant verification of BFS model.
- `test_adversarial_formal_bfs_gated_and_ungated_1000_trials_determinism`: 1,000 trials verifying 34-state vs 17-state counts.
- `test_adversarial_actuator_multi_trial_concurrency_stability`: Statistical multi-trial confirmation of single-winner invariant.

### 4. `tests/arm_containment_ring_tests.rs` (26 Tests)
Containment ring, actuator gating, autotomy, and mesh guard tests:
- `test_negative_control_level_1_epoch_enforcement`
- `test_level_1_arm_ring_memory_clamp_and_step_budget`
- `test_inter_arm_lateral_movement_block_between_untrusted_and_ledger`
- `test_level_1_arm_ring_tool_and_resource_bounds`
- `test_arm_ring_mesh_message_signature_tampering_and_role_spoofing_rejected`
- `test_arm_ring_resource_boundary_canonicalization_and_adversarial_rejections`
- `test_security_generation_epoch_advancement_on_autotomy`
- `test_stale_mesh_message_from_revoked_generation_is_rejected`
- `test_fleet_initialization_of_50_distinct_arm_rings`
- `test_per_arm_isolation_without_collateral_damage`
- `test_arm_ring_registry_fleet_cage_engine_propagation`
- `test_execute_tool_without_configured_engine_fails_closed`
- `test_execute_tool_with_action_digest_mismatch_fails_closed`
- `test_execute_tool_with_expired_cage_seal_fails_closed`
- `test_challenger_unconfigured_engine_strict_fail_closed`
- `test_challenger_formal_bfs_trace_conformance_adversarial_oracle`
- `test_execute_tool_with_valid_cage_seal_succeeds_and_emits_trace`
- `test_execute_tool_fiscal_debit_confirm_and_rollback`
- `test_challenger_fleet_scale_engine_propagation_and_autotomy_resilience`
- `test_execute_tool_with_replayed_cage_seal_fails_closed`
- `test_mesh_guard_pascal_case_and_security_arms_107_to_110_enforcement`
- `test_challenger_concurrent_race_condition_on_single_seal`
- `test_swarm_manager_sever_and_regenerate_arm`
- `test_challenger_conformance_verification_on_concurrent_trace_stream`
- `test_challenger_concurrent_tool_execution_with_distinct_seals`
- `test_swarm_manager_integrates_50_individual_arm_rings`

### 5. `tests/adversarial_challenger_m2_tests.rs` (8 Tests)
Milestone 2 actuator containment adversarial challenger tests:
- `test_adversarial_fiscal_debit_manipulation`
- `test_adversarial_seal_tampering_and_unanchored_evidence`
- `test_adversarial_trace_conformance_detection`
- `test_adversarial_action_digest_and_payload_tampering`
- `test_adversarial_cross_arm_theft_and_ticket_spoofing`
- `test_adversarial_clock_skew_and_ttl_boundary`
- `test_adversarial_sequential_and_concurrent_seal_replay`
- `test_adversarial_multithreaded_concurrent_seal_race`

### 6. `tests/adversarial_challenger_m3_tests.rs` (14 Tests)
Milestone 3 HTTP endpoint security and substrate contract tests:
- `test_cage_path_matcher_coverage`
- `test_extract_header_value_case_insensitivity`
- `test_host_rebinding_probes_on_cage_endpoints`
- `test_cross_origin_browser_probes_on_all_cage_endpoints`
- `test_version_drift_attack_on_policy_ingest`
- `test_malformed_request_payloads`
- `test_trace_conformance_endpoint_contract`
- `test_proof_status_formal_contract`
- `test_tampered_seal_signature_rejection`
- `test_seal_replay_attack_sequential_and_wrapped`
- `test_expired_seal_ttl_rejection`
- `test_seal_replay_attack_concurrent_race_resistance`
- `test_version_drift_attack_on_validate_action`
- `test_tampered_seal_audit_anchor_rejection`

### 7. `tests/adversarial_challenger_m3_2_tests.rs` (6 Tests)
Milestone 3 Phase 2 deep contract and trace stream validation tests:
- `test_adversarial_m3_policy_envelope_and_version_drift_rejection`
- `test_adversarial_m3_trace_conformance_input_formats`
- `test_adversarial_m3_trace_conformance_7_rules_stress`
- `test_adversarial_m3_bfs_proof_status_invariants_and_receipt`
- `test_adversarial_m3_concurrency_race_resistance`
- `test_adversarial_m3_policy_ingestion_5_formats_deterministic_hashing`

### 8. `tests/cage_m1_adversarial_stress_tests.rs` (14 Tests)
Milestone 1 core engine stress and boundary tests:
- `stress_test_cbf_barrier_exact_boundary_precision`
- `stress_test_cbf_extreme_floats_and_edge_inputs`
- `stress_test_cbf_gamma_spectrum_and_validation`
- `stress_test_debit_ledger_double_rollback_and_settlement_invariants`
- `stress_test_ftra_dag_missing_dependencies_and_duplicate_edges`
- `stress_test_routing_seal_tamper_resistance_and_mismatches`
- `stress_test_debit_ledger_rapid_lifo_rollbacks`
- `stress_test_ftra_dag_disconnected_components_and_forest`
- `stress_test_routing_seal_tampered_expires_at_exploration`
- `stress_test_ftra_dag_self_loops_and_cycles`
- `stress_test_routing_seal_ttl_and_clock_skew_boundaries`
- `stress_test_ftra_dag_deep_linear_chain`
- `stress_test_routing_seal_single_use_concurrency_race`
- `stress_test_two_phase_debit_ledger_concurrent_zero_leakage`

### 9. `tests/adversarial_challenger_m1_tests.rs` (9 Tests)
Milestone 1 formal proofs and JCS canonicalization stress tests:
- `test_stress_jcs_adversarial_keys_and_utf16_ordering`
- `test_adversarial_challenge_stpa_field_silence_vulnerability`
- `test_stress_ungated_bfs_counterexample_strictly_17_states`
- `test_stress_version_drift_rejection_http_409`
- `test_stress_jcs_permutation_invariance`
- `test_stress_single_byte_mutation_version_divergence_all_formats`
- `test_stress_gated_bfs_strictly_34_states`
- `test_stress_skipped_tier_models_strictly_31_states`
- `test_stress_theorem_receipt_deterministic_64_hex`

### 10. `src/security/cage_governance/` Unit Tests (32 Tests)
Unit tests for all 6 core submodules and public engine facade:
- `cbf_fiscal::tests::test_cbf_barrier_satisfaction`
- `cbf_fiscal::tests::test_sequence_and_epoch_defense`
- `ftra_stpa::tests::test_ftra_confidence_normalization`
- `no_direct_bind_proof::tests::test_stage_name_alias_normalization`
- `cbf_fiscal::tests::test_cbf_nan_and_infinity_defense`
- `no_direct_bind_proof::tests::test_formal_bfs_ungated_counterexample`
- `routing_seal::tests::test_unanchored_evidence_rejection`
- `ftra_stpa::tests::test_stpa_identity_sanitization`
- `ftra_stpa::tests::test_ftra_authority_rank_enforcement`
- `ftra_stpa::tests::test_ftra_dag_traversal_and_cycle_detection`
- `no_direct_bind_proof::tests::test_formal_bfs_theorem_receipt`
- `no_direct_bind_proof::tests::test_stream_verifier_no_direct_bind_violation`
- `substrate_translator::tests::test_detect_and_compile_oscal`
- `no_direct_bind_proof::tests::test_stream_verifier_valid_trace`
- `no_direct_bind_proof::tests::test_formal_bfs_34_states_and_no_direct_bind`
- `no_direct_bind_proof::tests::test_stream_verifier_coverage_with_cedar_alias`
- `cbf_fiscal::tests::test_two_phase_pre_reservation_and_lifo_rollback`
- `substrate_translator::tests::test_rfc_8785_jcs_canonicalization`
- `substrate_translator::tests::test_detect_and_compile_aaif`
- `routing_seal::tests::test_routing_seal_expiration`
- `substrate_translator::tests::test_detect_and_compile_acs`
- `routing_seal::tests::test_consumed_seals_ttl_pruning`
- `substrate_translator::tests::test_version_pinning_verification`
- `routing_seal::tests::test_tampered_expires_at_rejection`
- `substrate_translator::tests::test_detect_and_compile_lula`
- `pipeline::tests::test_pipeline_confidence_findings`
- `routing_seal::tests::test_routing_seal_issue_and_consume_cycle`
- `no_direct_bind_proof::tests::test_formal_bfs_skipped_tier_models`
- `pipeline::tests::test_pipeline_full_allow_and_seal_issuance`
- `pipeline::tests::test_cedar_forbid_unconditional_denies_target_action`
- `tests::test_cage_governance_engine_end_to_end`
- `pipeline::tests::test_cedar_forbid_action_specific_conditional_matching`

### 11. `src/web/` Unit Tests (22 Tests)
HTTP layer, request guard, and substrate contract handler unit tests:
- `web::api::tests::test_api_error_payload_struct`
- `web::request_guard::tests::rejects_missing_token`
- `web::request_guard::tests::accepts_same_origin_with_token`
- `web::api::tests::test_json_error_payload_schema`
- `web::request_guard::tests::rejects_cage_substrate_cross_origin`
- `web::request_guard::tests::rejects_cage_substrate_cross_site_fetch`
- `web::request_guard::tests::accepts_cage_substrate_loopback_without_token`
- `web::request_guard::tests::rejects_cage_substrate_rebinding_host`
- `web::request_guard::tests::rejects_cross_origin`
- `web::request_guard::tests::strictly_enforces_non_exempt_api_token`
- `web::request_guard::tests::rejects_rebinding_host`
- `web::strict_http::tests::detect_unusual_but_nonfatal_headers`
- `web::strict_http::tests::normal_requests`
- `web::strict_http::tests::reject_ambiguous_framing`
- `web::strict_http::tests::reject_request_pipelining`
- `web::strict_http::tests::reject_novel_desync_triggers`
- `web::strict_http::tests::reject_shared_parser_confusion_attacks`
- `web::api::tests::test_handle_rl_evaluate_action_malformed_json`
- `web::api::tests::test_handle_evaluate_cedar_duplicate_key_schema_tampering`
- `web::api::tests::test_handle_update_egress_domains_malformed_json_and_errors`
- `web::api::tests::test_handle_evaluate_cedar_malformed_json_returns_error_payload`
- `web::api::tests::test_cage_handlers_end_to_end`

---

## 5. Execution Matrix & Unified Runner Commands

To execute the entire 179-test CAGE governance battery with strict compiler verification:

```powershell
# 1. Compiler Invariant Check (0 warnings, 0 errors)
cargo check --lib

# 2. Comprehensive CAGE Integration Suite (25 tests)
cargo test --test cage_governance_integration_tests

# 3. Adversarial Challenger Suites (M4, M4.2, M2, M3, M3.2, M1)
cargo test --test adversarial_challenger_m4_tests       # 15 tests
cargo test --test adversarial_challenger_m4_2_tests     # 8 tests
cargo test --test arm_containment_ring_tests           # 26 tests
cargo test --test adversarial_challenger_m2_tests       # 8 tests
cargo test --test adversarial_challenger_m3_tests       # 14 tests
cargo test --test adversarial_challenger_m3_2_tests     # 6 tests
cargo test --test cage_m1_adversarial_stress_tests      # 14 tests
cargo test --test adversarial_challenger_m1_tests       # 9 tests

# 4. Core Engine & Web Substrate Unit Tests
cargo test --lib security::cage_governance             # 32 tests
cargo test --lib web                                   # 22 tests
```

---

## 6. Coverage Summary & Verification Attestation

- **Total CAGE Tests**: 179
- **Passing**: 179 (100.0%)
- **Failing**: 0
- **Ignored / Filtered**: 0
- **Compiler Warnings**: 0
- **Compiler Errors**: 0
- **Verification Result**: Clean Green
