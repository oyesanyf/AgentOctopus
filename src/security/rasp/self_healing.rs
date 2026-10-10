use super::context::{RaspDecision, RaspInterceptionEvent};
use super::policy::{AdaptiveMitigationTier, RaspPolicyEngine};
use crate::security::rl_defense::{AdaptiveDefenseAction, AdaptiveRlDefenseEngine, AdaptiveStateVector};
use crate::telemetry::otel::{OtelSessionTelemetry, OtelSpanKind, OtelStatusCode};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Real-time self-healing feedback controller integrating RT-ASP with RL defense and OTel.
pub struct RaspSelfHealingController {
    rl_defense: Arc<AdaptiveRlDefenseEngine>,
    otel_telemetry: Arc<OtelSessionTelemetry>,
    consecutive_breaches: AtomicUsize,
    last_escalation_secs: AtomicUsize,
}

impl RaspSelfHealingController {
    pub fn new(
        rl_defense: Arc<AdaptiveRlDefenseEngine>,
        otel_telemetry: Arc<OtelSessionTelemetry>,
    ) -> Self {
        Self {
            rl_defense,
            otel_telemetry,
            consecutive_breaches: AtomicUsize::new(0),
            last_escalation_secs: AtomicUsize::new(0),
        }
    }

    /// Handles an interception event by updating the RL policy and dispatching OpenTelemetry spans.
    pub fn handle_event(&self, event: &RaspInterceptionEvent, policy_engine: &RaspPolicyEngine) {
        let now_nano = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let start_nano = now_nano.saturating_sub((event.latency_micros * 1000) as u64);

        // 1. Record distributed OTel span
        let mut attributes = HashMap::new();
        attributes.insert("rasp.event_id".to_string(), event.event_id.clone());
        attributes.insert("rasp.interceptor".to_string(), event.interceptor_name.clone());
        attributes.insert("rasp.agent_id".to_string(), event.subject.agent_id.clone());
        attributes.insert("rasp.verdict".to_string(), event.decision.verdict_str().to_string());
        if let Some(cat) = event.threat_category {
            attributes.insert("rasp.threat_category".to_string(), cat.to_string());
        }

        let (otel_status, status_msg) = match &event.decision {
            RaspDecision::Allow { .. } => (OtelStatusCode::Ok, None),
            RaspDecision::Sanitize { .. } => (OtelStatusCode::Ok, Some("Sanitized inline".to_string())),
            RaspDecision::Deny { reason, .. } => (OtelStatusCode::Error, Some(reason.clone())),
            RaspDecision::Tarpit { reason, .. } => (OtelStatusCode::Error, Some(reason.clone())),
            RaspDecision::Quarantine { reason, .. } => (OtelStatusCode::Error, Some(reason.clone())),
        };

        self.otel_telemetry.record_span(
            &event.trace_id,
            None,
            &format!("rt_asp.{}", event.interceptor_name),
            OtelSpanKind::Internal,
            start_nano,
            now_nano,
            otel_status,
            status_msg,
            attributes,
            Vec::new(),
        );

        // 2. Closed-loop RL self-tuning and adaptive remediation
        if event.decision.is_blocked() {
            let breaches = self.consecutive_breaches.fetch_add(1, Ordering::Relaxed) + 1;

            // Formulate state vector
            let mut state = AdaptiveStateVector::default();
            state.schema_tamper_score = (breaches as f32 * 0.2).min(1.0);
            state.prompt_injection_semantic_anomaly = (breaches as f32 * 0.25).min(1.0);
            state.credential_access_pressure = (breaches as f32 * 0.3).min(1.0);
            state.error_frequency = (breaches as f32 * 0.2).min(1.0);

            let bucket = state.discretize_bucket();

            // Penalize passive action (0) and boost HardMitigation (4)
            self.rl_defense.tune_on_failure(
                bucket,
                AdaptiveDefenseAction::PassiveObserve.to_index(),
                AdaptiveDefenseAction::HardMitigation.to_index(),
                -100.0,
            );

            // Record breach and remediation in OTel session metrics
            let mttd_ms = (event.latency_micros as f64) / 1000.0;
            let mttr_ms = mttd_ms + 0.5; // immediate in-process remediation
            self.otel_telemetry.record_resilience_event(mttd_ms, mttr_ms, Some(&event.subject.session_id));

            // Dynamic escalation ladder: if consecutive breaches spike, raise mitigation tier
            let now_secs = (now_nano / 1_000_000_000) as usize;
            let last_esc = self.last_escalation_secs.load(Ordering::Relaxed);
            if breaches >= 3 && (now_secs.saturating_sub(last_esc) > 5) {
                let current_tier = policy_engine.config().active_mitigation_tier;
                let next_tier = match current_tier {
                    AdaptiveMitigationTier::Level0Monitor => AdaptiveMitigationTier::Level1Sanitize,
                    AdaptiveMitigationTier::Level1Sanitize => AdaptiveMitigationTier::Level2SyntheticDecoy,
                    AdaptiveMitigationTier::Level2SyntheticDecoy => AdaptiveMitigationTier::Level3TarpitStall,
                    AdaptiveMitigationTier::Level3TarpitStall => AdaptiveMitigationTier::Level4HardRevoke,
                    AdaptiveMitigationTier::Level4HardRevoke => AdaptiveMitigationTier::Level4HardRevoke,
                };
                policy_engine.set_mitigation_tier(next_tier);
                self.last_escalation_secs.store(now_secs, Ordering::Relaxed);
            }
        } else {
            // Clean interaction: reset consecutive breaches and reward system
            self.consecutive_breaches.store(0, Ordering::Relaxed);
        }
    }
}
