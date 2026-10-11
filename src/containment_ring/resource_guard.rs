use crate::core::types::OctopusSecurityError;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct BudgetQuota {
    pub max_step_budget: usize,
    pub max_duration: Duration,
    pub max_calls_per_minute: usize,
}

impl Default for BudgetQuota {
    fn default() -> Self {
        Self {
            max_step_budget: 10,
            max_duration: Duration::from_secs(5),
            max_calls_per_minute: 60,
        }
    }
}

struct ArmTracker {
    call_timestamps: Vec<Instant>,
    total_steps_executed: usize,
}

/// Outer Ring Resource Guard:
/// Enforces wall-clock execution deadlines, step limits, and request quotas
/// completely outside the agent's runtime.
#[derive(Clone)]
pub struct ResourceGuard {
    quotas: Arc<RwLock<HashMap<String, BudgetQuota>>>,
    trackers: Arc<RwLock<HashMap<String, ArmTracker>>>,
}

impl Default for ResourceGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceGuard {
    pub fn new() -> Self {
        Self {
            quotas: Arc::new(RwLock::new(HashMap::new())),
            trackers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn set_quota(&self, agent_id: &str, quota: BudgetQuota) {
        let mut quotas = self.quotas.write().await;
        quotas.insert(agent_id.to_string(), quota);
    }

    /// Verifies step budget and rate limits before an arm begins execution.
    pub async fn check_admission(
        &self,
        agent_id: &str,
        requested_steps: usize,
    ) -> Result<Duration, OctopusSecurityError> {
        let quotas = self.quotas.read().await;
        let quota = quotas.get(agent_id).cloned().unwrap_or_default();

        if requested_steps > quota.max_step_budget {
            return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
                "Requested step budget {} exceeds strict containment ring limit of {}",
                requested_steps, quota.max_step_budget
            )));
        }

        let mut trackers = self.trackers.write().await;
        let tracker = trackers.entry(agent_id.to_string()).or_insert(ArmTracker {
            call_timestamps: Vec::new(),
            total_steps_executed: 0,
        });

        // Prune calls older than 60s
        let now = Instant::now();
        tracker.call_timestamps.retain(|&t| now.duration_since(t) < Duration::from_secs(60));

        if tracker.call_timestamps.len() >= quota.max_calls_per_minute {
            return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
                "Rate limit exceeded for agent '{}': {} calls in past 60s exceeds quota of {}",
                agent_id, tracker.call_timestamps.len(), quota.max_calls_per_minute
            )));
        }

        tracker.call_timestamps.push(now);
        tracker.total_steps_executed += requested_steps;

        Ok(quota.max_duration)
    }
}
