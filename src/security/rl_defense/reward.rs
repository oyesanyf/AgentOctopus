use super::action::AdaptiveDefenseAction;
use super::state::AdaptiveStateVector;
use serde::{Deserialize, Serialize};

/// Multi-objective reward engine for agent active defense (inspired by OshoosiClaw EdrRewardEngine).
/// Rewards true positive containment and early elevation; penalizes false positives, breaches, and latency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveRewardEngine {
    pub reward_true_containment: f32,
    pub reward_early_elevation: f32,
    pub reward_clean_execution: f32,
    pub penalty_false_alarm: f32,
    pub penalty_breach_leakage: f32,
    pub penalty_latency_per_100ms: f32,
}

impl Default for AdaptiveRewardEngine {
    fn default() -> Self {
        Self {
            reward_true_containment: 100.0,
            reward_early_elevation: 25.0,
            reward_clean_execution: 10.0,
            penalty_false_alarm: 50.0,
            penalty_breach_leakage: 500.0,
            penalty_latency_per_100ms: 2.0,
        }
    }
}

impl AdaptiveRewardEngine {
    /// Computes the scalar reward R_t for an action given the state and ground truth outcome.
    pub fn compute_reward(
        &self,
        state: &AdaptiveStateVector,
        action: AdaptiveDefenseAction,
        is_actual_threat: bool,
        was_contained: bool,
        latency_ms: f64,
    ) -> f32 {
        let latency_penalty = (latency_ms as f32 / 100.0) * self.penalty_latency_per_100ms;
        let threat_severity = state.composite_threat_severity();

        let base_reward = if is_actual_threat {
            if was_contained {
                match action {
                    // Highest reward when high threat is proactively quarantined or terminated
                    AdaptiveDefenseAction::HardMitigation if threat_severity >= 0.8 => {
                        self.reward_true_containment + 20.0
                    }
                    AdaptiveDefenseAction::MicroContainment if threat_severity >= 0.4 => {
                        self.reward_true_containment
                    }
                    AdaptiveDefenseAction::MemoryIntrospection
                    | AdaptiveDefenseAction::TraceElevation => self.reward_early_elevation,
                    AdaptiveDefenseAction::PassiveObserve => {
                        // Threat present but system stayed completely passive without containment!
                        -self.penalty_breach_leakage * 0.5
                    }
                    _ => self.reward_true_containment * 0.8,
                }
            } else {
                // Catastrophic failure: actual threat occurred and breached containment!
                -self.penalty_breach_leakage
            }
        } else {
            // Clean benign agent execution
            match action {
                AdaptiveDefenseAction::PassiveObserve => self.reward_clean_execution,
                AdaptiveDefenseAction::TraceElevation => self.reward_clean_execution * 0.8,
                AdaptiveDefenseAction::MemoryIntrospection => self.reward_clean_execution * 0.5,
                // False alarm containment disrupts legitimate agent task!
                AdaptiveDefenseAction::MicroContainment => -self.penalty_false_alarm * 0.5,
                AdaptiveDefenseAction::HardMitigation => -self.penalty_false_alarm,
            }
        };

        base_reward - latency_penalty
    }
}
