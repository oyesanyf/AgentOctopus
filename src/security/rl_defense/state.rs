use serde::{Deserialize, Serialize};

/// 10-dimensional structured feature vector representing agent behavioral state (S_t).
/// Directly addresses the six failure mechanisms from "Beyond One and Done: Agent Breakouts".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveStateVector {
    /// 1. Cumulative execution steps / context drift: captures long-horizon decay (0.0 to 1.0).
    pub step_count_drift: f32,
    /// 2. Token burn velocity: tokens consumed per second normalized to quota.
    pub token_burn_velocity: f32,
    /// 3. Execution error frequency: rate of unhandled exceptions or failed tool executions.
    pub error_frequency: f32,
    /// 4. Egress divergence: attempts to connect to unapproved domains, IP addresses, or route probing.
    pub egress_divergence: f32,
    /// 5. Credential access pressure: attempts to read env vars, secrets, or unmasked Docker sockets.
    pub credential_access_pressure: f32,
    /// 6. Cross-agent scratchpad leak: unauthorized temporary file/scratchpad sharing across trust tiers.
    pub cross_agent_scratchpad_leak: f32,
    /// 7. Schema tamper score: parameter type mismatches, float amounts, or injection attempts.
    pub schema_tamper_score: f32,
    /// 8. Evaluation harness tamper signal: attempts to modify test scripts, harnesses, or reporting files.
    pub eval_harness_tamper_signal: f32,
    /// 9. Kernel memory clamp pressure: current memory usage relative to 64MB Job Object limit.
    pub kernel_memory_clamp_pressure: f32,
    /// 10. Prompt injection / semantic anomaly score: indirect prompt injection or jailbreak indicators.
    pub prompt_injection_semantic_anomaly: f32,
}

impl Default for AdaptiveStateVector {
    fn default() -> Self {
        Self {
            step_count_drift: 0.0,
            token_burn_velocity: 0.0,
            error_frequency: 0.0,
            egress_divergence: 0.0,
            credential_access_pressure: 0.0,
            cross_agent_scratchpad_leak: 0.0,
            schema_tamper_score: 0.0,
            eval_harness_tamper_signal: 0.0,
            kernel_memory_clamp_pressure: 0.0,
            prompt_injection_semantic_anomaly: 0.0,
        }
    }
}

impl AdaptiveStateVector {
    pub const DIMENSION: usize = 10;

    pub fn to_array(&self) -> [f32; Self::DIMENSION] {
        [
            self.step_count_drift.clamp(0.0, 1.0),
            self.token_burn_velocity.clamp(0.0, 1.0),
            self.error_frequency.clamp(0.0, 1.0),
            self.egress_divergence.clamp(0.0, 1.0),
            self.credential_access_pressure.clamp(0.0, 1.0),
            self.cross_agent_scratchpad_leak.clamp(0.0, 1.0),
            self.schema_tamper_score.clamp(0.0, 1.0),
            self.eval_harness_tamper_signal.clamp(0.0, 1.0),
            self.kernel_memory_clamp_pressure.clamp(0.0, 1.0),
            self.prompt_injection_semantic_anomaly.clamp(0.0, 1.0),
        ]
    }

    /// Discretizes the 10-dimensional continuous state vector into a composite state bucket
    /// for tabular Q-learning and contextual bandit indexing.
    pub fn discretize_bucket(&self) -> usize {
        let arr = self.to_array();
        let mut bucket = 0usize;
        for (i, &val) in arr.iter().enumerate() {
            let bit = if val >= 0.5 { 1 } else { 0 };
            bucket |= bit << i;
        }
        bucket
    }

    /// Computes overall threat severity magnitude in [0.0, 1.0].
    pub fn composite_threat_severity(&self) -> f32 {
        let arr = self.to_array();
        let max_signal = arr.iter().copied().fold(0.0f32, f32::max);
        let mean_signal: f32 = arr.iter().sum::<f32>() / (Self::DIMENSION as f32);
        // Weighted blend of peak anomaly and general anomalous ambient level
        0.7 * max_signal + 0.3 * mean_signal
    }
}
