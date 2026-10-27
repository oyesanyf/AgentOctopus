use crate::core::types::OctopusSecurityError;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Telemetry and health state recorded by the Sentinel Guard.
#[derive(Debug, Clone)]
pub struct ArmHealthState {
    pub arm_id: String,
    pub last_heartbeat: Instant,
    pub step_count: usize,
    pub max_step_budget: usize,
    pub memory_allocated_bytes: usize,
    pub memory_limit_bytes: usize,
    pub is_alive: bool,
}

/// Sentinel Guard: Monitors system metrics, process constraints, memory limits,
/// and heartbeat liveness across the swarm.
pub struct SentinelGuard {
    guard_id: String,
    heartbeat_timeout: Duration,
    arm_registry: HashMap<String, ArmHealthState>,
}

impl SentinelGuard {
    pub fn new(guard_id: &str, heartbeat_timeout_millis: u64) -> Self {
        Self {
            guard_id: guard_id.to_string(),
            heartbeat_timeout: Duration::from_millis(heartbeat_timeout_millis),
            arm_registry: HashMap::new(),
        }
    }

    pub fn guard_id(&self) -> &str {
        &self.guard_id
    }

    /// Registers a monitored arm with initial step budget and memory bounds.
    pub fn register_arm(
        &mut self,
        arm_id: &str,
        max_step_budget: usize,
        memory_limit_bytes: usize,
    ) {
        self.arm_registry.insert(
            arm_id.to_string(),
            ArmHealthState {
                arm_id: arm_id.to_string(),
                last_heartbeat: Instant::now(),
                step_count: 0,
                max_step_budget,
                memory_allocated_bytes: 0,
                memory_limit_bytes,
                is_alive: true,
            },
        );
    }

    /// Records an execution step heartbeat from an arm and verifies step budget.
    pub fn record_heartbeat(
        &mut self,
        arm_id: &str,
        delta_memory_bytes: usize,
    ) -> Result<(), OctopusSecurityError> {
        let state = self.arm_registry.get_mut(arm_id).ok_or_else(|| {
            OctopusSecurityError::EnclaveViolation(format!("Unregistered arm: {}", arm_id))
        })?;

        if !state.is_alive {
            return Err(OctopusSecurityError::LimbKilled);
        }

        state.last_heartbeat = Instant::now();
        state.step_count += 1;
        state.memory_allocated_bytes += delta_memory_bytes;

        if state.step_count > state.max_step_budget {
            state.is_alive = false;
            return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
                "Arm {} exceeded step budget: {} > {}",
                arm_id, state.step_count, state.max_step_budget
            )));
        }

        if state.memory_allocated_bytes > state.memory_limit_bytes {
            state.is_alive = false;
            return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
                "Arm {} exceeded memory clamp: {} > {} bytes",
                arm_id, state.memory_allocated_bytes, state.memory_limit_bytes
            )));
        }

        Ok(())
    }

    /// Verifies that all registered arms are actively reporting within the heartbeat deadline.
    pub fn audit_swarm_liveness(&mut self) -> Result<Vec<String>, OctopusSecurityError> {
        let now = Instant::now();
        let mut timed_out_arms = Vec::new();

        for (arm_id, state) in self.arm_registry.iter_mut() {
            if state.is_alive && now.duration_since(state.last_heartbeat) > self.heartbeat_timeout {
                state.is_alive = false;
                timed_out_arms.push(arm_id.clone());
            }
        }

        if !timed_out_arms.is_empty() {
            return Err(OctopusSecurityError::ExecutionTimeout);
        }

        Ok(timed_out_arms)
    }

    pub fn get_health(&self, arm_id: &str) -> Option<&ArmHealthState> {
        self.arm_registry.get(arm_id)
    }
}
