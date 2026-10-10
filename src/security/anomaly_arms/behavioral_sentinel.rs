use std::collections::HashMap;
use std::time::Instant;

/// Layer 1: Lightweight Statistical / ML Behavioral Sentinel Arm.
/// Continuously tracks execution metrics (invocation velocity, token rate,
/// inter-arrival times, payload Shannon entropy) to detect statistical anomalies.
pub struct BehavioralSentinelArm {
    pub arm_id: String,
    agent_histories: HashMap<String, AgentTelemetryHistory>,
    anomaly_threshold: f64,
}

#[derive(Debug, Clone)]
struct AgentTelemetryHistory {
    invocation_timestamps: Vec<Instant>,
    token_usage_history: Vec<usize>,
    entropy_samples: Vec<f64>,
}

#[derive(Debug, Clone)]
pub struct BehavioralAnomalyReport {
    pub agent_id: String,
    pub is_anomalous: bool,
    pub anomaly_score: f64,
    pub reasons: Vec<String>,
}

impl BehavioralSentinelArm {
    pub fn new(arm_id: &str, anomaly_threshold: f64) -> Self {
        Self {
            arm_id: arm_id.to_string(),
            agent_histories: HashMap::new(),
            anomaly_threshold,
        }
    }

    /// Ingests a new execution telemetry event for an agent.
    pub fn record_event(
        &mut self,
        agent_id: &str,
        tokens_consumed: usize,
        payload_entropy: f64,
    ) -> BehavioralAnomalyReport {
        let now = Instant::now();
        let history = self
            .agent_histories
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentTelemetryHistory {
                invocation_timestamps: Vec::new(),
                token_usage_history: Vec::new(),
                entropy_samples: Vec::new(),
            });

        history.invocation_timestamps.push(now);
        history.token_usage_history.push(tokens_consumed);
        history.entropy_samples.push(payload_entropy);

        // Keep rolling window of last 20 events
        if history.invocation_timestamps.len() > 20 {
            history.invocation_timestamps.remove(0);
            history.token_usage_history.remove(0);
            history.entropy_samples.remove(0);
        }

        let mut anomaly_score = 0.0;
        let mut reasons = Vec::new();

        // 1. Invocation burst velocity check: > 10 calls in last 1 second
        if history.invocation_timestamps.len() >= 10 {
            let elapsed = now.duration_since(history.invocation_timestamps[0]).as_secs_f64();
            if elapsed < 1.0 {
                anomaly_score += 4.0;
                reasons.push(format!("Burst call frequency: {} calls in {:.2}s", history.invocation_timestamps.len(), elapsed));
            }
        }

        // 2. Token spike check: > 5,000 tokens in single call
        if tokens_consumed > 5000 {
            anomaly_score += 3.5;
            reasons.push(format!("Excessive token spike: {} tokens consumed", tokens_consumed));
        }

        // 3. High Shannon entropy: > 7.5 bits/byte (indicative of encrypted/obfuscated payload)
        if payload_entropy > 7.5 {
            anomaly_score += 3.0;
            reasons.push(format!("Abnormal payload entropy: {:.2} bits/byte", payload_entropy));
        }

        let is_anomalous = anomaly_score >= self.anomaly_threshold;

        BehavioralAnomalyReport {
            agent_id: agent_id.to_string(),
            is_anomalous,
            anomaly_score,
            reasons,
        }
    }
}
