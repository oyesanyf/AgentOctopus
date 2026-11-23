//! Law 6 — Nuclear Physics (Red-Team Upgrade #1): Radioactive Half-Life & Dead-Man's Switch Decay.
//!
//! Solves the **Cloud-to-Cloud Silent Disconnect** gap: if a developer's laptop loses Wi-Fi,
//! loses battery, or crashes silently without emitting a screen-lock event, any standing
//! OAuth/MCP token decays exponentially from the last verified human heartbeat:
//!
//! $$N(t) = N_0 \cdot e^{-\lambda (t - t_{\text{heartbeat}})}, \qquad \lambda = \frac{\ln 2}{T_{1/2}}$$
//!
//! Once $N(t) < N_{\text{crit}}$ (default $0.25$, i.e. $2 \cdot T_{1/2}$ without interactive
//! human renewal), capability activity self-destructs and all remote/cloud tool calls fail closed.

use serde::{Deserialize, Serialize};

/// Verdict produced by Law 6 (Radioactive Half-Life Decay Gate).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HalfLifeVerdict {
    pub allowed: bool,
    pub remaining_activity: f64,
    pub critical_threshold: f64,
    pub half_life_secs: u64,
    pub elapsed_secs: u64,
    pub decay_constant_lambda: f64,
    pub reason: String,
}

/// Evaluates continuous exponential Radioactive Half-Life token decay.
#[derive(Debug, Clone, Copy)]
pub struct RadioactiveHalfLifeEngine {
    pub default_half_life_secs: u64,
    pub high_risk_half_life_secs: u64,
    pub critical_threshold: f64,
}

impl Default for RadioactiveHalfLifeEngine {
    fn default() -> Self {
        Self {
            // 5-minute half-life for normal SaaS connectors -> auto-revokes after ~10 min silence
            default_half_life_secs: 300,
            // 60-second half-life for high-risk shell/finance/delete connectors -> auto-revokes after ~2 min silence
            high_risk_half_life_secs: 60,
            critical_threshold: 0.25,
        }
    }
}

impl RadioactiveHalfLifeEngine {
    /// Evaluates remaining radioactive token activity $N(t) = e^{-\lambda \Delta t}$.
    #[must_use]
    pub fn evaluate(
        &self,
        last_heartbeat_unix: u64,
        now_unix: u64,
        custom_half_life_secs: Option<u64>,
        is_high_risk_tool: bool,
    ) -> HalfLifeVerdict {
        let half_life = custom_half_life_secs
            .unwrap_or(if is_high_risk_tool {
                self.high_risk_half_life_secs
            } else {
                self.default_half_life_secs
            })
            .max(10);
        let lambda = std::f64::consts::LN_2 / (half_life as f64);
        let elapsed = now_unix.saturating_sub(last_heartbeat_unix);
        let activity = (-lambda * (elapsed as f64)).exp();
        let allowed = activity >= self.critical_threshold;

        let reason = if allowed {
            format!(
                "LAW6_HALF_LIFE_ACTIVE: Activity N(t)={activity:.3} >= N_crit={:.2} (T_1/2={half_life}s, dt={elapsed}s)",
                self.critical_threshold
            )
        } else {
            format!(
                "LAW6_DEADMAN_DECAY_DENY: Silent heartbeat decay N(t)={activity:.4} < N_crit={:.2} (T_1/2={half_life}s, dt={elapsed}s); capability auto-revoked",
                self.critical_threshold
            )
        };

        HalfLifeVerdict {
            allowed,
            remaining_activity: activity,
            critical_threshold: self.critical_threshold,
            half_life_secs: half_life,
            elapsed_secs: elapsed,
            decay_constant_lambda: lambda,
            reason,
        }
    }
}
