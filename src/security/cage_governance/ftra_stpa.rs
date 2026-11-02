// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Reference: Google Cybernetic Agent Governance Engine (CAGE), arXiv:2606.12320

//! Tier 0.5 Forward-Looking Trajectory Reachability Analyzer (FTRA) & Tier 1 STPA Validator
//!
//! Enforces pre-execution trajectory screening over execution step graphs (linear or DAG):
//! - Evaluates action criticality across 5 reversibility tiers.
//! - Enforces caller authority rank requirements (Rank 1 highest, Rank 5 lowest).
//! - Implements fail-closed confidence normalization (`NaN`, `+Inf`, `-Inf` -> `0.0`).
//! - Evaluates Federal Reserve SR 26-2 model confidence thresholds.
//! - Enforces Tier 1 STPA/STAMP Unsafe Control Action (UCA) constraints bound to authenticated
//!   `TrustedArmHandle` identities, scrubbing unauthenticated caller identity fields.

use super::substrate_translator::UnsafeControlAction;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Federal Reserve SR 26-2 (§IV.B) model confidence threshold for direct ALLOW clearance.
pub const SR_26_2_CONFIDENCE_ALLOW_THRESHOLD: f64 = 0.95;

/// Federal Reserve SR 26-2 model confidence threshold for HITL approval escalation before DEFER.
pub const SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD: f64 = 0.70;

/// Action reversibility and criticality tiers for FTRA graph analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionReversibility {
    /// Read-only inspection, telemetry polling, or status check. Authority <= 5.
    ReadOnly,
    /// Operations fully undoable via standard compensation (e.g. scratchpad write, temp cache). Authority <= 3.
    Reversible,
    /// Financial or state changes with registered compensating sagas (e.g. pre-auth, escrow hold). Authority <= 3.
    Compensatable,
    /// Automated execution governed by bounded parameters. Authority <= 3.
    ConditionalAutonomous,
    /// Terminal, non-undoable operations (process spawn, driver load, system binary mutation, raw socket). Authority <= 2.
    IrreversibleTerminal,
}

impl ActionReversibility {
    /// Classifies an action into its reversibility tier based on name semantics.
    pub fn classify(action_name: &str) -> Self {
        let name_lower = action_name.to_ascii_lowercase();

        // High-risk irreversible terminal operations
        if name_lower.contains("exec")
            || name_lower.contains("spawn")
            || name_lower.contains("launch")
            || name_lower.contains("driver")
            || name_lower.contains("delete")
            || name_lower.contains("purge")
            || name_lower.contains("socket")
            || name_lower.contains("bind")
            || name_lower.contains("childprocess")
            || name_lower.contains("modifysystembinary")
            || name_lower.contains("writebarrier")
            || name_lower.contains("format")
            || name_lower.contains("drop")
        {
            ActionReversibility::IrreversibleTerminal
        } else if name_lower.contains("escrow")
            || name_lower.contains("compensate")
            || name_lower.contains("reserve")
            || name_lower.contains("hold")
        {
            ActionReversibility::Compensatable
        } else if name_lower.contains("autonomous")
            || name_lower.contains("auto_")
            || name_lower.contains("clamped_")
        {
            ActionReversibility::ConditionalAutonomous
        } else if name_lower.contains("write")
            || name_lower.contains("update")
            || name_lower.contains("modify")
            || name_lower.contains("trade")
            || name_lower.contains("transfer")
            || name_lower.contains("insert")
        {
            ActionReversibility::Reversible
        } else {
            ActionReversibility::ReadOnly
        }
    }

    /// Returns the required caller authority rank for this tier.
    /// (1 is highest authority/root, 5 is untrusted).
    pub fn required_authority_rank(&self) -> u8 {
        match self {
            ActionReversibility::ReadOnly => 5,
            ActionReversibility::Reversible => 3,
            ActionReversibility::Compensatable => 3,
            ActionReversibility::ConditionalAutonomous => 3,
            ActionReversibility::IrreversibleTerminal => 2,
        }
    }
}

/// A discrete step within a proposed plan execution graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub id: String,
    pub action_name: String,
    pub parameters: serde_json::Value,
    pub depends_on: Vec<String>,
    pub confidence: f64,
    pub fuel_cost: f64,
    pub caller_authority: u8,
}

/// Verdict returned by FTRA reachability analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FtraVerdict {
    /// Step or entire plan is within autonomous boundaries and cleared for Phase 1 continuation.
    Clear,
    /// Execution requires Human-In-The-Loop approval before proceeding.
    HitlRequired { reason: String, step_id: String },
    /// Model confidence is below threshold; deferred with exponential backoff.
    Deferred { backoff_ms: u64, reason: String },
    /// Invariant or authority breach; execution blocked fail-closed.
    Blocked { reason: String, step_id: String },
}

/// Plan Graph Reachability Analyzer (Tier 0.5).
pub struct PlanGraphAnalyzer;

impl PlanGraphAnalyzer {
    /// Normalizes model confidence floats fail-closed:
    /// - NaN, +Inf, -Inf, and negative values map to 0.0.
    /// - Values > 1.0 clamp to 1.0.
    pub fn normalize_confidence(conf: f64) -> f64 {
        if conf.is_nan() || conf.is_infinite() || conf < 0.0 {
            0.0
        } else if conf > 1.0 {
            1.0
        } else {
            conf
        }
    }

    /// Evaluates reversibility and authority for an individual step.
    pub fn evaluate_step_reversibility(step: &PlanStep) -> FtraVerdict {
        let reversibility = ActionReversibility::classify(&step.action_name);
        let required_rank = reversibility.required_authority_rank();

        if step.caller_authority > required_rank {
            return FtraVerdict::Blocked {
                reason: format!(
                    "FTRA_AUTHORITY_VIOLATION: Action '{}' classified as {:?} requires authority rank <= {}, got {}",
                    step.action_name, reversibility, required_rank, step.caller_authority
                ),
                step_id: step.id.clone(),
            };
        }

        let normalized_conf = Self::normalize_confidence(step.confidence);

        // Irreversible terminal actions with confidence < 0.95 always require HITL
        if reversibility == ActionReversibility::IrreversibleTerminal {
            if normalized_conf < SR_26_2_CONFIDENCE_ALLOW_THRESHOLD {
                return FtraVerdict::HitlRequired {
                    reason: format!(
                        "Irreversible terminal action '{}' with confidence {:.4} requires human sign-off",
                        step.action_name, normalized_conf
                    ),
                    step_id: step.id.clone(),
                };
            }
        } else if normalized_conf < SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD {
            let deficit = (SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD - normalized_conf).max(0.0);
            let backoff_ms = (1000.0 * (1.0 + deficit * 5.0)) as u64;
            return FtraVerdict::Deferred {
                backoff_ms,
                reason: format!(
                    "Step '{}' confidence {:.4} below SR 26-2 approval threshold {:.2}",
                    step.id, normalized_conf, SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD
                ),
            };
        } else if normalized_conf < SR_26_2_CONFIDENCE_ALLOW_THRESHOLD {
            return FtraVerdict::HitlRequired {
                reason: format!(
                    "Step '{}' confidence {:.4} in [{:.2}, {:.2}); requires approval",
                    step.id, normalized_conf, SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD, SR_26_2_CONFIDENCE_ALLOW_THRESHOLD
                ),
                step_id: step.id.clone(),
            };
        }

        FtraVerdict::Clear
    }

    /// Traverses and validates a complete DAG of plan steps.
    /// Checks for cycle freedom, resolves dependencies in topological order, and evaluates each step.
    pub fn analyze_execution_graph(steps: &[PlanStep]) -> Result<FtraVerdict, String> {
        if steps.is_empty() {
            return Ok(FtraVerdict::Clear);
        }

        // Build adjacency and in-degree maps for DAG validation
        let mut in_degrees: HashMap<&str, usize> = HashMap::new();
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut step_map: HashMap<&str, &PlanStep> = HashMap::new();

        for s in steps {
            step_map.insert(&s.id, s);
            in_degrees.entry(&s.id).or_insert(0);
            dependents.entry(&s.id).or_insert_with(Vec::new);
        }

        for s in steps {
            for dep in &s.depends_on {
                if !step_map.contains_key(dep.as_str()) {
                    return Err(format!("Step '{}' depends on unknown step '{}'", s.id, dep));
                }
                dependents.get_mut(dep.as_str()).unwrap().push(&s.id);
                *in_degrees.get_mut(s.id.as_str()).unwrap() += 1;
            }
        }

        // Topological Kahn's algorithm
        let mut queue: VecDeque<&str> = in_degrees
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&id, _)| id)
            .collect();

        let mut processed_count = 0;
        let mut top_order: Vec<&PlanStep> = Vec::with_capacity(steps.len());

        while let Some(step_id) = queue.pop_front() {
            processed_count += 1;
            top_order.push(step_map[step_id]);

            if let Some(children) = dependents.get(step_id) {
                for &child_id in children {
                    let deg = in_degrees.get_mut(child_id).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(child_id);
                    }
                }
            }
        }

        if processed_count != steps.len() {
            return Err("Execution graph contains cycles (dependency deadlock)".to_string());
        }

        // Evaluate steps in topological dependency order
        for step in top_order {
            let verdict = Self::evaluate_step_reversibility(step);
            match verdict {
                FtraVerdict::Clear => continue,
                _ => return Ok(verdict),
            }
        }

        Ok(FtraVerdict::Clear)
    }
}

/// The 4 Leveson STPA/STAMP Hazard Categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LevesonHazardCategory {
    /// Control action not provided causes hazard.
    NotProvidedCausesHazard,
    /// Control action provided causes hazard.
    ProvidedCausesHazard,
    /// Control action provided too early, too late, or out of order.
    WrongTimingOrOrder,
    /// Control action stopped too soon or applied too long.
    StoppedTooSoonOrAppliedTooLong,
}

/// Tier 1 STPA Validator.
pub struct StpaValidator;

impl StpaValidator {
    /// Sanitizes caller parameters by stripping spoofed caller identity fields
    /// (`trader_role`, `trader_id`, `role`, `agent_id`) and strictly binding
    /// the authenticated supervisor-verified `arm_id`.
    pub fn sanitize_parameters(
        params: &serde_json::Value,
        authenticated_arm_id: &str,
    ) -> serde_json::Value {
        let mut sanitized = match params {
            serde_json::Value::Object(map) => map.clone(),
            _ => serde_json::Map::new(),
        };

        // Strip spoofable caller-supplied identity parameters
        sanitized.remove("trader_role");
        sanitized.remove("trader_id");
        sanitized.remove("role");
        sanitized.remove("agent_id");

        // Bind authenticated handle
        sanitized.insert(
            "arm_id".to_string(),
            serde_json::Value::String(authenticated_arm_id.to_string()),
        );

        serde_json::Value::Object(sanitized)
    }

    /// Evaluates proposed action against compiled UCAs.
    pub fn validate_action(
        action_name: &str,
        parameters: &serde_json::Value,
        ucas: &[UnsafeControlAction],
        authenticated_arm_id: &str,
    ) -> Result<(), (String, String)> {
        let sanitized = Self::sanitize_parameters(parameters, authenticated_arm_id);

        for uca in ucas {
            if uca.control_action.eq_ignore_ascii_case(action_name) || uca.control_action == "*" {
                if Self::matches_uca_context(&uca.context_condition, &sanitized) {
                    let reason = format!(
                        "STPA_UCA_BREACH: Unsafe Control Action '{}' violated for hazard '{}': {}. Mitigation: {}",
                        uca.uca_id, uca.hazard_ref, uca.context_condition, uca.mitigation
                    );
                    return Err((uca.uca_id.clone(), reason));
                }
            }
        }

        Ok(())
    }

    fn matches_uca_context(condition: &str, params: &serde_json::Value) -> bool {
        let cond_lower = condition.trim().to_ascii_lowercase();
        if cond_lower.is_empty() || cond_lower == "unconditional" {
            return false;
        }

        if cond_lower.contains("is_null") {
            let param_name = cond_lower.replace("is_null", "").trim().to_string();
            return match params.get(&param_name) {
                None => true,
                Some(serde_json::Value::Null) => true,
                Some(serde_json::Value::String(s)) => s.is_empty(),
                _ => false,
            };
        }

        if let Some(val) = params.get(cond_lower.as_str()) {
            if let Some(b) = val.as_bool() {
                return b;
            }
        }

        if cond_lower.contains('>') {
            let parts: Vec<&str> = cond_lower.split('>').collect();
            if parts.len() == 2 {
                let key = parts[0].trim().replace("context.", "");
                let threshold: f64 = parts[1].trim().parse().unwrap_or(f64::MAX);
                if let Some(val) = params.get(&key).and_then(|v| v.as_f64()) {
                    return val > threshold;
                }
            }
        }

        if cond_lower.contains('<') {
            let parts: Vec<&str> = cond_lower.split('<').collect();
            if parts.len() == 2 {
                let key = parts[0].trim().replace("context.", "");
                let threshold: f64 = parts[1].trim().parse().unwrap_or(f64::MIN);
                if let Some(val) = params.get(&key).and_then(|v| v.as_f64()) {
                    return val < threshold;
                }
            }
        }

        if cond_lower.contains("==") {
            let parts: Vec<&str> = cond_lower.split("==").collect();
            if parts.len() == 2 {
                let key = parts[0].trim().replace("context.", "");
                let expected = parts[1].trim().trim_matches('"').trim_matches('\'');
                if let Some(actual) = params.get(&key).and_then(|v| v.as_str()) {
                    return actual == expected;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ftra_confidence_normalization() {
        assert_eq!(PlanGraphAnalyzer::normalize_confidence(f64::NAN), 0.0);
        assert_eq!(PlanGraphAnalyzer::normalize_confidence(f64::INFINITY), 0.0);
        assert_eq!(PlanGraphAnalyzer::normalize_confidence(f64::NEG_INFINITY), 0.0);
        assert_eq!(PlanGraphAnalyzer::normalize_confidence(-0.5), 0.0);
        assert_eq!(PlanGraphAnalyzer::normalize_confidence(1.5), 1.0);
        assert_eq!(PlanGraphAnalyzer::normalize_confidence(0.85), 0.85);
    }

    #[test]
    fn test_ftra_authority_rank_enforcement() {
        let step = PlanStep {
            id: "step-1".to_string(),
            action_name: "spawn_process".to_string(),
            parameters: serde_json::json!({}),
            depends_on: vec![],
            confidence: 0.99,
            fuel_cost: 1.0,
            caller_authority: 4, // Rank 4 > Rank 2 allowed for IrreversibleTerminal
        };
        let verdict = PlanGraphAnalyzer::evaluate_step_reversibility(&step);
        assert!(matches!(verdict, FtraVerdict::Blocked { .. }));
    }

    #[test]
    fn test_ftra_dag_traversal_and_cycle_detection() {
        let steps = vec![
            PlanStep {
                id: "step-1".to_string(),
                action_name: "read_config".to_string(),
                parameters: serde_json::json!({}),
                depends_on: vec![],
                confidence: 0.98,
                fuel_cost: 0.5,
                caller_authority: 3,
            },
            PlanStep {
                id: "step-2".to_string(),
                action_name: "update_cache".to_string(),
                parameters: serde_json::json!({}),
                depends_on: vec!["step-1".to_string()],
                confidence: 0.96,
                fuel_cost: 0.5,
                caller_authority: 3,
            },
        ];
        let verdict = PlanGraphAnalyzer::analyze_execution_graph(&steps).unwrap();
        assert_eq!(verdict, FtraVerdict::Clear);

        // Cyclic dependency
        let cyclic_steps = vec![
            PlanStep {
                id: "A".to_string(),
                action_name: "read_a".to_string(),
                parameters: serde_json::json!({}),
                depends_on: vec!["B".to_string()],
                confidence: 0.99,
                fuel_cost: 0.1,
                caller_authority: 1,
            },
            PlanStep {
                id: "B".to_string(),
                action_name: "read_b".to_string(),
                parameters: serde_json::json!({}),
                depends_on: vec!["A".to_string()],
                confidence: 0.99,
                fuel_cost: 0.1,
                caller_authority: 1,
            },
        ];
        let err = PlanGraphAnalyzer::analyze_execution_graph(&cyclic_steps).unwrap_err();
        assert!(err.contains("cycles"));
    }

    #[test]
    fn test_stpa_identity_sanitization() {
        let spoofed_params = serde_json::json!({
            "trader_role": "admin",
            "agent_id": "root_operator",
            "amount": 500
        });
        let sanitized = StpaValidator::sanitize_parameters(&spoofed_params, "arm-verified-42");
        assert!(sanitized.get("trader_role").is_none());
        assert!(sanitized.get("agent_id").is_none());
        assert_eq!(sanitized.get("arm_id").unwrap().as_str().unwrap(), "arm-verified-42");
        assert_eq!(sanitized.get("amount").unwrap().as_i64().unwrap(), 500);
    }
}
