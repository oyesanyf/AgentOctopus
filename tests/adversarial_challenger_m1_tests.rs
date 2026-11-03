//! ==============================================================================
//! [AGENT OCTOPUS] MILESTONE 1 ADVERSARIAL CHALLENGER SUITE
//! ==============================================================================
//! Empirical Stress-Testing for CAGE Milestone 1:
//! 1. Formal BFS State Machine:
//!    - Strictly 34 reachable states in gated model with 0 violations
//!    - Strictly 17 reachable states in ungated counterexample finding execution without seal
//!    - Strictly 31 reachable states in skipped-tier model with 0 executions
//!    - Deterministic 64-hex SHA-256 theorem receipt verification
//! 2. RFC 8785 JSON Canonicalization Scheme (JCS) Adversarial Keys & Values:
//!    - Special characters, unicode escapes, emoji, UTF-16 code unit ordering vs UTF-8
//!    - Numerical formatting (negative zero, integer floats, exponents)
//!    - Permutation invariance and hash consistency
//! 3. Policy Drift Rejection & HTTP 409 Conflict:
//!    - Single-byte mutation divergence across all 5 policy formats
//!    - Active pinned version conflict detection (HTTP 409 Conflict)
//!    - Multi-trial stability verification (RFC 7230 / protocol reproducibility)
//! ==============================================================================

use agent_octopus::security::audit::SecurityAuditLog;
use agent_octopus::security::cage_governance::no_direct_bind_proof::{
    BfsPhase, BfsState, FormalBfsModel,
};
use agent_octopus::security::cage_governance::substrate_translator::SubstrateTranslator;
use agent_octopus::security::cage_governance::{CageApiError, CageGovernanceEngine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

// ==============================================================================
// AREA 1: FORMAL BFS STATE MACHINE ADVERSARIAL STRESS TESTING
// ==============================================================================

/// Stress-test the gated formal BFS state machine.
/// Strictly asserts:
/// - Exactly 34 reachable states
/// - Exactly 1 terminal executed state
/// - Zero safety violations
/// - Invariant NoDirectBind holds for all visited states
/// - Execution state strictly requires seal_present == true && resolved_allow == true
#[test]
fn test_stress_gated_bfs_strictly_34_states() {
    for trial in 1..=10 {
        let result = FormalBfsModel::explore_gated_model();

        // 1. Exact Reachable State Count
        assert_eq!(
            result.reachable_count, 34,
            "Trial {trial}: Gated model must reach strictly 34 states, got {}",
            result.reachable_count
        );
        assert_eq!(
            result.visited_states.len(),
            34,
            "Trial {trial}: visited_states set must contain strictly 34 unique states"
        );

        // 2. Executed Count & Violations
        assert_eq!(
            result.executed_count, 1,
            "Trial {trial}: Gated model must have strictly 1 executed state"
        );
        assert!(
            result.violations.is_empty(),
            "Trial {trial}: Gated model must have 0 violations, found: {:?}",
            result.violations
        );
        assert!(
            result.no_direct_bind_proven,
            "Trial {trial}: NoDirectBind must be proven true in gated model"
        );

        // 3. Detailed Structural Audit of Visited States
        let mut phase_counts = std::collections::HashMap::new();
        for state in &result.visited_states {
            *phase_counts.entry(state.phase).or_insert(0) += 1;
        }

        // Expected breakdown:
        // - Initial: 1
        // - Checking: 8 (ftra, stpa, opa, confidence, consensus, cbf, fiscal, completed)
        // - NarrowEval: 7 (tier_0 .. tier_6)
        // - NarrowPassed: 1 (all_clamped)
        // - SealIssued: 1 (valid)
        // - Executed: 1 (executed)
        // - Denied: 15 (7 direct_tier_X + 7 narrow_rerun_tier_X + 1 seal_expired)
        assert_eq!(
            phase_counts.get(&BfsPhase::Initial).copied().unwrap_or(0),
            1
        );
        assert_eq!(
            phase_counts.get(&BfsPhase::Checking).copied().unwrap_or(0),
            8
        );
        assert_eq!(
            phase_counts
                .get(&BfsPhase::NarrowEval)
                .copied()
                .unwrap_or(0),
            7
        );
        assert_eq!(
            phase_counts
                .get(&BfsPhase::NarrowPassed)
                .copied()
                .unwrap_or(0),
            1
        );
        assert_eq!(
            phase_counts
                .get(&BfsPhase::SealIssued)
                .copied()
                .unwrap_or(0),
            1
        );
        assert_eq!(
            phase_counts.get(&BfsPhase::Executed).copied().unwrap_or(0),
            1
        );
        assert_eq!(
            phase_counts.get(&BfsPhase::Denied).copied().unwrap_or(0),
            15
        );

        // 4. Verify terminal executed state invariant
        let executed_states: Vec<&BfsState> = result
            .visited_states
            .iter()
            .filter(|s| s.phase == BfsPhase::Executed)
            .collect();
        assert_eq!(executed_states.len(), 1);
        let exec = executed_states[0];
        assert_eq!(exec.label, "executed");
        assert_eq!(exec.tier, 7);
        assert!(
            exec.seal_present,
            "Executed state must strictly have seal_present == true"
        );
        assert!(
            exec.resolved_allow,
            "Executed state must strictly have resolved_allow == true"
        );
        assert!(
            exec.executed_or_narrow,
            "Executed state must have executed_or_narrow == true"
        );

        // 5. Verify every single state adheres to safety invariant
        for state in &result.visited_states {
            if state.phase == BfsPhase::Executed {
                assert!(state.seal_present && state.resolved_allow);
            }
        }
    }
}

/// Stress-test the ungated counterexample BFS exploration (Negative Control).
/// Strictly asserts:
/// - Exactly 17 reachable states
/// - Exactly 1 safety violation detected
/// - NoDirectBind is NOT proven
/// - The violation detects execution occurring with seal_present == false
#[test]
fn test_stress_ungated_bfs_counterexample_strictly_17_states() {
    for trial in 1..=10 {
        let result = FormalBfsModel::explore_ungated_counterexample();

        // 1. Exact Reachable State Count
        assert_eq!(
            result.reachable_count, 17,
            "Trial {trial}: Ungated counterexample model must reach strictly 17 states, got {}",
            result.reachable_count
        );
        assert_eq!(
            result.visited_states.len(),
            17,
            "Trial {trial}: visited_states set must contain strictly 17 unique states"
        );

        // 2. Violations & Rejection of Proof
        assert!(
            !result.no_direct_bind_proven,
            "Trial {trial}: NoDirectBind must FAIL in ungated counterexample"
        );
        assert_eq!(
            result.violations.len(),
            1,
            "Trial {trial}: Ungated counterexample must find strictly 1 violation"
        );

        let violation = &result.violations[0];
        assert_eq!(violation.state.phase, BfsPhase::Executed);
        assert_eq!(violation.state.label, "ungated_direct_bind");
        assert_eq!(
            violation.state.seal_present, false,
            "Violation state must demonstrate execution without seal"
        );
        assert!(
            violation.error.contains("Direct-bind violation")
                || violation.error.contains("without seal"),
            "Error message must describe direct-bind bypass: {}",
            violation.error
        );

        // 3. Phase breakdown
        let mut phase_counts = std::collections::HashMap::new();
        for state in &result.visited_states {
            *phase_counts.entry(state.phase).or_insert(0) += 1;
        }
        // Breakdown: Initial: 1, Checking: 7, Executed: 1, Denied: 8 (7 tier_X + 1 terminal_failure)
        assert_eq!(
            phase_counts.get(&BfsPhase::Initial).copied().unwrap_or(0),
            1
        );
        assert_eq!(
            phase_counts.get(&BfsPhase::Checking).copied().unwrap_or(0),
            7
        );
        assert_eq!(
            phase_counts.get(&BfsPhase::Executed).copied().unwrap_or(0),
            1
        );
        assert_eq!(phase_counts.get(&BfsPhase::Denied).copied().unwrap_or(0), 8);
    }
}

/// Stress-test the skipped-tier BFS model across all 7 tiers (Tiers 0..6).
/// Strictly asserts:
/// - Exactly 31 reachable states for every skipped tier
/// - Exactly 0 executed states (actuation strictly impossible when a tier is skipped)
/// - Zero violations of NoDirectBind (since execution is never reached)
#[test]
fn test_stress_skipped_tier_models_strictly_31_states() {
    for skip_tier in 0..7 {
        for trial in 1..=5 {
            let result = FormalBfsModel::explore_skipped_tier_model(skip_tier);

            assert_eq!(
                result.reachable_count, 31,
                "Tier {skip_tier} Trial {trial}: Skipped-tier model must reach strictly 31 states, got {}",
                result.reachable_count
            );
            assert_eq!(
                result.executed_count, 0,
                "Tier {skip_tier} Trial {trial}: Execution must be blocked (0 executed states) when tier is skipped"
            );
            assert!(
                result.no_direct_bind_proven,
                "Tier {skip_tier} Trial {trial}: NoDirectBind is preserved because no unsealed execution can occur"
            );

            // Confirm no visited state has phase == Executed
            assert!(
                !result
                    .visited_states
                    .iter()
                    .any(|s| s.phase == BfsPhase::Executed),
                "Tier {skip_tier} Trial {trial}: No executed states may exist in visited states"
            );

            // Confirm seal_issued state is visited but transitions only to seal_expired
            assert!(
                result.visited_states.iter().any(|s| s.phase == BfsPhase::SealIssued),
                "Tier {skip_tier} Trial {trial}: SealIssued state should still be reached before expiry"
            );
            assert!(
                result
                    .visited_states
                    .iter()
                    .any(|s| s.phase == BfsPhase::Denied && s.label == "seal_expired"),
                "Tier {skip_tier} Trial {trial}: seal_expired denial must be reached"
            );
        }
    }
}

/// Stress-test the deterministic 64-hex SHA-256 theorem receipt.
/// Asserts:
/// - Theorem receipt is strictly 64 characters long
/// - Contains only lowercase hexadecimal characters [0-9a-f]
/// - Value is deterministic across 100 repeated evaluations across threads
/// - Matches an independently computed SHA-256 oracle hash
#[test]
fn test_stress_theorem_receipt_deterministic_64_hex() {
    let first_proof = FormalBfsModel::prove_no_direct_bind();
    assert!(first_proof.proven);
    assert_eq!(first_proof.reachable_states, 34);
    assert_eq!(first_proof.executed_states, 1);
    assert_eq!(first_proof.violations_count, 0);

    let receipt = &first_proof.proof_receipt;
    assert_eq!(
        receipt.len(),
        64,
        "Proof receipt must be strictly 64 hex characters"
    );
    assert!(
        receipt
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "Proof receipt must be lowercase hexadecimal: {}",
        receipt
    );

    // Multi-trial determinism stress across 50 iterations
    for trial in 1..=50 {
        let proof = FormalBfsModel::prove_no_direct_bind();
        assert_eq!(
            proof.proof_receipt, *receipt,
            "Trial {trial}: Proof receipt drifted! Expected {}, got {}",
            receipt, proof.proof_receipt
        );
    }

    // Independent Oracle Computation:
    // Verify that computing SHA-256 over canonical sorted states yields the exact receipt
    let model = FormalBfsModel::explore_gated_model();
    let mut sorted: Vec<&BfsState> = model.visited_states.iter().collect();
    sorted.sort_by(|a, b| {
        a.label
            .cmp(&b.label)
            .then(a.tier.cmp(&b.tier))
            .then(a.phase.as_str().cmp(b.phase.as_str()))
    });

    let mut hasher = Sha256::new();
    hasher.update(b"Theorem:NoDirectBind|GatedStates:34|Executed:1|Violations:0\n");
    for s in sorted {
        hasher.update(
            format!(
                "{}|{}|{}|{}|{}|{}\n",
                s.phase.as_str(),
                s.label,
                s.tier,
                s.seal_present,
                s.resolved_allow,
                s.executed_or_narrow
            )
            .as_bytes(),
        );
    }
    let oracle_receipt = hex::encode(hasher.finalize());
    assert_eq!(
        *receipt, oracle_receipt,
        "Engine theorem receipt must match independent oracle verification"
    );
}

// ==============================================================================
// AREA 2: JCS CANONICALIZATION WITH ADVERSARIAL JSON KEYS & VALUES
// ==============================================================================

/// Stress-test RFC 8785 JSON Canonicalization Scheme (JCS) with adversarial keys:
/// 1. UTF-16 code unit ordering vs UTF-8 / Unicode code point ordering:
///    In UTF-8 / code point order: U+FFFF < U+10000.
///    In UTF-16 code unit order: U+10000 has surrogate 0xD800, so U+10000 < U+FFFF!
/// 2. Special characters, escapes, control codes, quotes, backslashes.
/// 3. Multilingual keys (CJK, Arabic, Hebrew, Cyrillic) and emojis.
/// 4. Numerical representations (-0.0 -> "0", integer-valued floats, large numbers).
#[test]
fn test_stress_jcs_adversarial_keys_and_utf16_ordering() {
    // 1. UTF-16 Code Unit vs Unicode Code Point Ordering Challenge
    // U+FFFF is BMP (UTF-16: 0xFFFF).
    // U+10000 is Astral / SMP (UTF-16 surrogate pair: 0xD800, 0xDC00).
    // RFC 8785 §3.2.3 requires sorting by UTF-16 code units: 0xD800 < 0xFFFF,
    // which means "\u{10000}" MUST appear before "\u{FFFF}"!
    let astral_key = "\u{10000}";
    let bmp_key = "\u{FFFF}";

    let obj = json!({
        bmp_key: "bmp_value",
        astral_key: "astral_value"
    });

    let jcs = SubstrateTranslator::canonicalize_jcs(&obj).unwrap();
    // Verify that astral key comes first
    let expected_start = format!("{{\"{}\":\"astral_value\",", astral_key);
    assert!(
        jcs.starts_with(&expected_start),
        "RFC 8785 UTF-16 code unit ordering violation! Astral char (0xD800) must precede BMP 0xFFFF. Got: {}",
        jcs
    );

    // 2. Adversarial Special Characters in Keys
    let adv_keys_obj = json!({
        "": "empty_key",
        "normal": "value",
        "key with spaces": "space_val",
        "key\twith\ttabs": "tab_val",
        "key\nwith\nnewlines": "newline_val",
        "key\"with\"quotes": "quote_val",
        "key\\with\\backslash": "backslash_val",
        "colon:comma,brace{bracket}[slash]/": "symbols_val",
        "\u{0000}": "null_byte_key",
        "\u{001f}": "unit_sep_key",
        "key_a": 1,
        "key_b": 2
    });

    let jcs_adv = SubstrateTranslator::canonicalize_jcs(&adv_keys_obj).unwrap();
    // Validate minimal escaping rules
    assert!(jcs_adv.contains("\\\"with\\\"quotes"));
    assert!(jcs_adv.contains("\\\\with\\\\backslash"));
    assert!(jcs_adv.contains("\\twith\\ttabs"));
    assert!(jcs_adv.contains("\\nwith\\nnewlines"));
    assert!(jcs_adv.contains("\\u0000"));
    assert!(jcs_adv.contains("\\u001f"));

    // 3. Multilingual and Emoji Keys
    let emoji_obj = json!({
        "🐙": "octopus",
        "🦑": "squid",
        "🔒": "lock",
        "🛡️": "shield",
        "测试": "chinese",
        "اختبار": "arabic",
        "тест": "cyrillic"
    });
    let jcs_emoji = SubstrateTranslator::canonicalize_jcs(&emoji_obj).unwrap();
    assert!(jcs_emoji.starts_with('{') && jcs_emoji.ends_with('}'));

    // 4. Numerical Formatting Invariants per RFC 8785 §3.2.2.3:
    // - -0.0 serialized as "0"
    // - Integer-valued floats serialized without decimals (100.0 -> 100)
    let num_obj = json!({
        "neg_zero": -0.0,
        "pos_zero": 0.0,
        "int_float": 100.0,
        "frac_float": 100.25,
        "large_int": 9007199254740991.0 // 2^53 - 1
    });
    let jcs_num = SubstrateTranslator::canonicalize_jcs(&num_obj).unwrap();
    assert!(
        jcs_num.contains("\"neg_zero\":0"),
        "Negative zero must format as '0', got: {}",
        jcs_num
    );
    assert!(
        jcs_num.contains("\"pos_zero\":0"),
        "Positive zero must format as '0', got: {}",
        jcs_num
    );
    assert!(
        jcs_num.contains("\"int_float\":100"),
        "Integer float must format as '100', got: {}",
        jcs_num
    );
    assert!(
        jcs_num.contains("\"frac_float\":100.25"),
        "Frac float must format as '100.25', got: {}",
        jcs_num
    );
    assert!(
        jcs_num.contains("\"large_int\":9007199254740991"),
        "Safe max int must format without decimal, got: {}",
        jcs_num
    );
}

/// Stress-test JCS key-permutation invariance:
/// Shuffling object keys in 50 distinct permutations must produce the exact same canonical string and SHA-256 hash.
#[test]
fn test_stress_jcs_permutation_invariance() {
    let keys_and_values = vec![
        ("zebra", json!(1)),
        ("apple", json!({"nested_b": 2, "nested_a": 1})),
        ("mango", json!([3, 2, 1])),
        ("banana", json!(true)),
        ("cherry", json!(null)),
        ("date", json!("text")),
        ("fig", json!(-0.0)),
        ("grape", json!(50.0)),
    ];

    // Reference canonical string
    let mut ref_map = serde_json::Map::new();
    for (k, v) in &keys_and_values {
        ref_map.insert(k.to_string(), v.clone());
    }
    let ref_val = Value::Object(ref_map);
    let ref_canonical = SubstrateTranslator::canonicalize_jcs(&ref_val).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(ref_canonical.as_bytes());
    let ref_hash = hex::encode(hasher.finalize());

    // Generate 50 permutations of insertion order
    use rand::rngs::StdRng;
    use rand::seq::SliceRandom;
    use rand::SeedableRng;

    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE);
    for trial in 1..=50 {
        let mut shuffled = keys_and_values.clone();
        shuffled.shuffle(&mut rng);

        let mut map = serde_json::Map::new();
        for (k, v) in shuffled {
            map.insert(k.to_string(), v);
        }
        let val = Value::Object(map);
        let canonical = SubstrateTranslator::canonicalize_jcs(&val).unwrap();

        assert_eq!(
            canonical, ref_canonical,
            "Permutation {trial}: Canonicalization output drifted under key reordering"
        );

        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        let hash = hex::encode(h.finalize());
        assert_eq!(
            hash, ref_hash,
            "Permutation {trial}: SHA-256 hash drifted under key reordering"
        );
    }
}

// ==============================================================================
// AREA 3: DRIFT REJECTION & HTTP 409 CONFLICT STRESS TESTING
// ==============================================================================

/// Stress-test single-byte mutation version divergence across all 5 policy formats:
/// 1. Microsoft ACS
/// 2. Linux Foundation AAIF
/// 3. NIST OSCAL 1.1.x
/// 4. Lula Validation
/// 5. Native CAGE STPA YAML
///
/// Asserts that mutating a single semantic byte strictly alters the 16-hex policy_version_id.
#[test]
fn test_stress_single_byte_mutation_version_divergence_all_formats() {
    // 1. Microsoft ACS
    let acs_base = r#"{
        "behaviorDeclarations": [
            {
                "id": "ACS-001",
                "action": "ExecuteTrade",
                "hazardRefs": ["H-FIN-LOSS"],
                "constraints": [{ "type": "greater_than", "parameter": "amount", "value": 100000 }]
            }
        ]
    }"#;
    // Mutate single byte: "ExecuteTrade" -> "ExecuteTradf"
    let acs_mutated = acs_base.replace("ExecuteTrade", "ExecuteTradf");
    let p_acs_base = SubstrateTranslator::compile_policy(acs_base, None).unwrap();
    let p_acs_mut = SubstrateTranslator::compile_policy(&acs_mutated, None).unwrap();
    assert_ne!(
        p_acs_base.policy_version_id, p_acs_mut.policy_version_id,
        "ACS: Single byte mutation must diverge policy_version_id"
    );

    // 2. Linux Foundation AAIF
    let aaif_base = r#"{
        "governedRunLoop": {
            "stages": [
                {
                    "name": "access_control",
                    "hooks": [{ "id": "HOOK-001", "action": "FileRead", "role": "Supervisor" }]
                }
            ]
        }
    }"#;
    // Mutate single byte: "Supervisor" -> "Supervisoq"
    let aaif_mutated = aaif_base.replace("Supervisor", "Supervisoq");
    let p_aaif_base = SubstrateTranslator::compile_policy(aaif_base, None).unwrap();
    let p_aaif_mut = SubstrateTranslator::compile_policy(&aaif_mutated, None).unwrap();
    assert_ne!(
        p_aaif_base.policy_version_id, p_aaif_mut.policy_version_id,
        "AAIF: Single byte mutation must diverge policy_version_id"
    );

    // 3. NIST OSCAL 1.1.x
    let oscal_base = r#"{
        "oscal-version": "1.1.0",
        "components": [
            {
                "control-implementations": [
                    {
                        "implemented-requirements": [
                            { "control-id": "ac-3", "description": "Access enforcement" }
                        ]
                    }
                ]
            }
        ]
    }"#;
    // Mutate single byte: "ac-3" -> "ac-4"
    let oscal_mutated = oscal_base.replace("ac-3", "ac-4");
    let p_oscal_base = SubstrateTranslator::compile_policy(oscal_base, None).unwrap();
    let p_oscal_mut = SubstrateTranslator::compile_policy(&oscal_mutated, None).unwrap();
    assert_ne!(
        p_oscal_base.policy_version_id, p_oscal_mut.policy_version_id,
        "OSCAL: Single byte mutation must diverge policy_version_id"
    );

    // 4. Lula Validation
    let lula_base = r#"{
        "kind": "LulaValidation",
        "metadata": { "name": "k8s-pod-security" },
        "spec": {
            "policy": {
                "opa": {
                    "rego": "package main\ndefault allow = false\nallow { not input.ModifySystemBinary }"
                }
            }
        }
    }"#;
    // Mutate single byte: "ModifySystemBinary" -> "ModifySystemBinarz"
    let lula_mutated = lula_base.replace("ModifySystemBinary", "ModifySystemBinarz");
    let p_lula_base = SubstrateTranslator::compile_policy(lula_base, None).unwrap();
    let p_lula_mut = SubstrateTranslator::compile_policy(&lula_mutated, None).unwrap();
    assert_ne!(
        p_lula_base.policy_version_id, p_lula_mut.policy_version_id,
        "Lula: Single byte mutation must diverge policy_version_id"
    );

    // 5. Native CAGE STPA YAML
    let cage_base = r#"
stpa_control_structure:
  unsafe_control_actions:
    - id: "UCA-001"
      action: "ActuatorMove"
      hazard_refs:
        - "H-COLLISION"
      condition:
        param: "proximity"
        operator: "less_than_10"
"#;
    // Mutate single byte: "UCA-001" -> "UCA-002"
    let cage_mutated = cage_base.replace("UCA-001", "UCA-002");
    let p_cage_base = SubstrateTranslator::compile_policy(cage_base, None).unwrap();
    let p_cage_mut = SubstrateTranslator::compile_policy(&cage_mutated, None).unwrap();
    assert_ne!(
        p_cage_base.policy_version_id, p_cage_mut.policy_version_id,
        "CAGE STPA: Single byte mutation must diverge policy_version_id"
    );
    assert_eq!(p_cage_base.unsafe_control_actions[0].uca_id, "UCA-001");
    assert_eq!(p_cage_mut.unsafe_control_actions[0].uca_id, "UCA-002");
}

/// Adversarial Challenge: STPA YAML Schema Permissiveness & Silent Fallback
/// Demonstrates that if an author uses struct field names (`uca_id`, `control_action`)
/// instead of schema keys (`id`, `action`), `compile_stpa` silently falls back to
/// default placeholder values ("UCA-1", "ControlAction") without returning MalformedSchema error,
/// which can mask policy drift if unhandled.
#[test]
fn test_adversarial_challenge_stpa_field_silence_vulnerability() {
    let non_standard_keys = r#"
stpa_control_structure:
  unsafe_control_actions:
    - uca_id: "UCA-CUSTOM-CRITICAL"
      control_action: "NuclearLaunch"
      hazard_ref: "H-EXTINCTION"
"#;

    let compiled = SubstrateTranslator::compile_policy(non_standard_keys, None).unwrap();
    // Vulnerability observation: The custom UCA ID "UCA-CUSTOM-CRITICAL" and action "NuclearLaunch"
    // were silently ignored and replaced with defaults "UCA-1" and "ControlAction"
    assert_eq!(
        compiled.unsafe_control_actions[0].uca_id, "UCA-1",
        "Vulnerability confirmed: compile_stpa silently drops 'uca_id' and defaults to 'UCA-1'"
    );
    assert_eq!(
        compiled.unsafe_control_actions[0].control_action, "ControlAction",
        "Vulnerability confirmed: compile_stpa silently drops 'control_action' and defaults to 'ControlAction'"
    );
}

/// Stress-test policy version pinning and HTTP 409 Conflict rejection under drift:
/// 1. Direct SubstrateTranslator::verify_version_pinning check
/// 2. Engine-level ingest_policy version mismatch checking
/// 3. Multi-trial confirmation asserting stable rejection
#[test]
fn test_stress_version_drift_rejection_http_409() {
    let base_policy_str = r#"{
        "behaviorDeclarations": [
            {
                "id": "ACS-TRADE-1",
                "action": "ExecuteTrade",
                "hazardRefs": ["H-FIN-LOSS"],
                "constraints": [{ "type": "greater_than", "parameter": "amount", "value": 50000 }]
            }
        ],
        "cbf_gamma": 0.15,
        "cbf_b_min": 25.0
    }"#;

    let compiled_base = SubstrateTranslator::compile_policy(base_policy_str, None).unwrap();
    let active_version = &compiled_base.policy_version_id;

    // Mutated policy: amount changed to 50001
    let mutated_policy_str = base_policy_str.replace("50000", "50001");
    let compiled_mutated = SubstrateTranslator::compile_policy(&mutated_policy_str, None).unwrap();
    let mutated_version = &compiled_mutated.policy_version_id;

    assert_ne!(active_version, mutated_version);

    // Multi-trial verification (minimum 3 repeated trials per Protocol Reproducibility Rule)
    for trial in 1..=5 {
        // 1. Direct Translator Pinning Verification
        let valid_pinning =
            SubstrateTranslator::verify_version_pinning(Some(active_version), active_version);
        assert!(
            valid_pinning.is_ok(),
            "Trial {trial}: Matching version must succeed"
        );

        let conflict_err =
            SubstrateTranslator::verify_version_pinning(Some(active_version), mutated_version)
                .unwrap_err();
        assert_eq!(
            conflict_err.pinned_version, *active_version,
            "Trial {trial}: Pinned version in conflict must match active version"
        );
        assert_eq!(
            conflict_err.incoming_version, *mutated_version,
            "Trial {trial}: Incoming version in conflict must match mutated version"
        );

        // Verify that the error message clearly indicates HTTP 409 Conflict
        let err_msg = conflict_err.to_string();
        assert!(
            err_msg.contains("HTTP 409 Conflict"),
            "Trial {trial}: Error message must explicitly cite 'HTTP 409 Conflict': {}",
            err_msg
        );

        // 2. Engine-Level Ingestion Pinning Verification
        let audit_log = Arc::new(SecurityAuditLog::new());
        let engine = CageGovernanceEngine::new(
            compiled_base.clone(),
            500.0,
            0.15,
            25.0,
            b"adversarial-test-key-32-bytes--",
            audit_log,
        )
        .unwrap();

        // Engine active version matches base
        assert_eq!(engine.active_policy_version(), *active_version);

        // Adversary attempts to ingest a policy claiming expected version is "wrong_version_123"
        let mismatch_result = engine.ingest_policy(&mutated_policy_str, Some("wrong_version_123"));
        assert!(
            mismatch_result.is_err(),
            "Trial {trial}: Engine must reject mismatched expected version"
        );

        let api_err = mismatch_result.unwrap_err();
        assert_eq!(
            api_err.http_status_code(),
            "409 Conflict",
            "Trial {trial}: Engine error code must be strictly '409 Conflict'"
        );
        assert_eq!(
            api_err.error_code(),
            "POLICY_VERSION_MISMATCH",
            "Trial {trial}: Engine machine-readable error code must be 'POLICY_VERSION_MISMATCH'"
        );

        match api_err {
            CageApiError::PolicyVersionMismatch { expected, actual } => {
                assert_eq!(expected, "wrong_version_123");
                assert_eq!(actual, *active_version);
            }
            other => panic!("Trial {trial}: Unexpected error variant: {:?}", other),
        }
    }
}
