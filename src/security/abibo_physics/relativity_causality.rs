//! Law 1 — Special Relativity: Minkowski Causal Light-Cone & Spacetime Event-Horizon Gate.
//!
//! Directly mitigates ABIBO Unconsented Control-Plane Activation (e.g., background
//! cloud/vendor polling while a workstation is locked or asleep) by requiring every
//! tool invocation to lie strictly inside the causal future light-cone of a live human
//! consent event within the active `human_session_epoch`:
//!
//! $$\Delta s^2 = \left(c_{\text{auth}} \cdot \tau_{\text{rem}}\right)^2 - d_{\text{trust}}^2 \ge 0$$
//!
//! where $\tau_{\text{rem}} = \max(0, T_{\max} - (t_{\text{req}} - t_{\text{human}}))$ is the
//! remaining causal consent budget and $d_{\text{trust}}$ is the trust-hop distance from the
//! local human workstation to the requested execution target. Crossing a workstation lock,
//! lid-close, or sleep event triggers an irreversible Spacetime Event Horizon (`epoch -> epoch + 1`),
//! pushing all prior-epoch tokens spacelike outside the cone.

use crate::security::artemis_dfir::WorkstationLivenessSnapshot;
use serde::{Deserialize, Serialize};

/// Verdict produced by the Law 1 Minkowski Causal Light-Cone Gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelativityVerdict {
    pub allowed: bool,
    pub delta_s_squared: f64,
    pub c_auth: f64,
    pub tau_remaining_secs: f64,
    pub elapsed_since_human_secs: u64,
    pub d_trust: f64,
    pub request_epoch: u64,
    pub current_epoch: u64,
    pub event_horizon_crossed: bool,
    pub reason: String,
}

/// Configuration for the Relativistic Causal Light-Cone Gate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RelativityConfig {
    /// Speed of authority propagation $c_{\text{auth}}$ (trust-hops per second of remaining budget).
    pub c_auth: f64,
    /// Hard maximum elapsed time (seconds) after last verified human heartbeat before cone collapses.
    pub max_causal_horizon_secs: u64,
    /// Maximum allowed clock skew (seconds) if a request timestamp is slightly earlier than heartbeat.
    pub max_clock_skew_secs: u64,
}

impl Default for RelativityConfig {
    fn default() -> Self {
        Self {
            // At c_auth = 0.05 hops/sec, a remote write (d_trust = 3.0) requires >= 60s remaining
            // consent budget, whereas a local read (d_trust = 0.25) requires >= 5s remaining.
            c_auth: 0.05,
            max_causal_horizon_secs: 300,
            max_clock_skew_secs: 2,
        }
    }
}

/// Evaluates Law 1 (Special Relativity Causal Light-Cone & Spacetime Event-Horizon Gate).
#[derive(Debug, Clone)]
pub struct RelativityCausalityGate {
    config: RelativityConfig,
}

impl Default for RelativityCausalityGate {
    fn default() -> Self {
        Self::new(RelativityConfig::default())
    }
}

impl RelativityCausalityGate {
    #[must_use]
    pub fn new(config: RelativityConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn config(&self) -> RelativityConfig {
        self.config
    }

    /// Evaluates whether a request at `request_ts_unix` carrying `request_epoch` and trust-hop
    /// distance `d_trust` lies strictly inside the causal light-cone of the live human workstation.
    #[must_use]
    pub fn evaluate(
        &self,
        liveness: &WorkstationLivenessSnapshot,
        request_epoch: u64,
        request_ts_unix: u64,
        d_trust: f64,
    ) -> RelativityVerdict {
        let d_trust = d_trust.max(0.0);
        let c = self.config.c_auth.max(1e-6);

        // 1. Spacetime Event-Horizon check: workstation locked or epoch superseded
        let event_horizon_crossed = liveness.workstation_locked || request_epoch != liveness.epoch;
        if event_horizon_crossed {
            return RelativityVerdict {
                allowed: false,
                delta_s_squared: -(d_trust * d_trust).max(1.0),
                c_auth: c,
                tau_remaining_secs: 0.0,
                elapsed_since_human_secs: request_ts_unix
                    .saturating_sub(liveness.last_heartbeat_unix),
                d_trust,
                request_epoch,
                current_epoch: liveness.epoch,
                event_horizon_crossed: true,
                reason: format!(
                    "LAW1_EVENT_HORIZON_DENY: Workstation locked={} or stale epoch (req={}, active={}); prior causal cone severed",
                    liveness.workstation_locked, request_epoch, liveness.epoch
                ),
            };
        }

        // 2. Acausal backwards-in-time timestamp check
        if request_ts_unix + self.config.max_clock_skew_secs < liveness.last_heartbeat_unix {
            return RelativityVerdict {
                allowed: false,
                delta_s_squared: -(d_trust * d_trust).max(1.0),
                c_auth: c,
                tau_remaining_secs: 0.0,
                elapsed_since_human_secs: 0,
                d_trust,
                request_epoch,
                current_epoch: liveness.epoch,
                event_horizon_crossed: false,
                reason: format!(
                    "LAW1_ACAUSAL_TIMESTAMP_DENY: Request ts ({request_ts_unix}) precedes verified human consent anchor ({})",
                    liveness.last_heartbeat_unix
                ),
            };
        }

        // 3. Minkowski causal interval over remaining consent budget
        let horizon = self
            .config
            .max_causal_horizon_secs
            .min(liveness.max_idle_secs.max(10));
        let elapsed = request_ts_unix.saturating_sub(liveness.last_heartbeat_unix);
        let tau_rem = horizon.saturating_sub(elapsed) as f64;
        let delta_s_squared = (c * tau_rem).powi(2) - d_trust.powi(2);

        let allowed = liveness.human_live && elapsed <= horizon && delta_s_squared >= 0.0;
        let reason = if allowed {
            format!(
                "LAW1_TIMELIKE_ALLOW: Inside causal light-cone (ds^2={delta_s_squared:.3} >= 0, tau_rem={tau_rem:.1}s, d_trust={d_trust:.2}, epoch={})",
                liveness.epoch
            )
        } else {
            format!(
                "LAW1_SPACELIKE_DENY: Outside causal light-cone (ds^2={delta_s_squared:.3}, elapsed={elapsed}s, horizon={horizon}s, d_trust={d_trust:.2}, human_live={})",
                liveness.human_live
            )
        };

        RelativityVerdict {
            allowed,
            delta_s_squared,
            c_auth: c,
            tau_remaining_secs: tau_rem,
            elapsed_since_human_secs: elapsed,
            d_trust,
            request_epoch,
            current_epoch: liveness.epoch,
            event_horizon_crossed: false,
            reason,
        }
    }
}
