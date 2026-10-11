use crate::containment_ring::capability_gate::CapabilityGate;
use crate::containment_ring::trusted_controller::RingController;
use crate::core::circuit_breaker::KillSwitch;
use crate::core::types::OctopusSecurityError;
use crate::security::windows_sandbox::WindowsJobObject;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct SandboxConstraints {
    pub max_memory_bytes: usize,
    pub max_child_processes: usize,
    pub scratchpad_root: PathBuf,
}

impl Default for SandboxConstraints {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024, // 64 MB
            max_child_processes: 0,
            scratchpad_root: PathBuf::from("local_scratchpad"),
        }
    }
}

/// Outer Ring Isolation Manager:
/// Governs process sandboxing, scratchpad filesystem boundaries,
/// Windows Job Object OS process confinement, and independent,
/// non-cooperative autotomy termination.
#[derive(Clone)]
pub struct IsolationManager {
    constraints: Arc<RwLock<SandboxConstraints>>,
    arm_kill_switches: Arc<RwLock<HashMap<String, KillSwitch>>>,
    arm_job_objects: Arc<RwLock<HashMap<String, Arc<WindowsJobObject>>>>,
    quarantined_arms: Arc<RwLock<HashMap<String, String>>>,
    pub capability_gate: Arc<RwLock<Option<Arc<CapabilityGate>>>>,
    pub ring_controller: Arc<RwLock<Option<RingController>>>,
}

impl Default for IsolationManager {
    fn default() -> Self {
        Self::new(SandboxConstraints::default())
    }
}

impl IsolationManager {
    pub fn new(constraints: SandboxConstraints) -> Self {
        Self {
            constraints: Arc::new(RwLock::new(constraints)),
            arm_kill_switches: Arc::new(RwLock::new(HashMap::new())),
            arm_job_objects: Arc::new(RwLock::new(HashMap::new())),
            quarantined_arms: Arc::new(RwLock::new(HashMap::new())),
            capability_gate: Arc::new(RwLock::new(None)),
            ring_controller: Arc::new(RwLock::new(None)),
        }
    }

    /// Constructs an IsolationManager directly wired with CapabilityGate and RingController.
    pub fn with_controllers(
        constraints: SandboxConstraints,
        capability_gate: Arc<CapabilityGate>,
        ring_controller: RingController,
    ) -> Self {
        Self {
            constraints: Arc::new(RwLock::new(constraints)),
            arm_kill_switches: Arc::new(RwLock::new(HashMap::new())),
            arm_job_objects: Arc::new(RwLock::new(HashMap::new())),
            quarantined_arms: Arc::new(RwLock::new(HashMap::new())),
            capability_gate: Arc::new(RwLock::new(Some(capability_gate))),
            ring_controller: Arc::new(RwLock::new(Some(ring_controller))),
        }
    }

    /// Registers an arm's dedicated hardware-style kill switch.
    pub async fn register_kill_switch(&self, agent_id: &str, kill_switch: KillSwitch) {
        let mut map = self.arm_kill_switches.write().await;
        map.insert(agent_id.to_string(), kill_switch);
    }

    /// Registers a Windows Job Object bound to the arm's OS process.
    pub async fn register_job_object(&self, agent_id: &str, job_object: Arc<WindowsJobObject>) {
        let mut map = self.arm_job_objects.write().await;
        map.insert(agent_id.to_string(), job_object);
    }

    /// Registers both kill switch and optional OS process job object for an arm.
    pub async fn register_arm(
        &self,
        agent_id: &str,
        kill_switch: KillSwitch,
        job_object: Option<Arc<WindowsJobObject>>,
    ) {
        self.register_kill_switch(agent_id, kill_switch).await;
        if let Some(job) = job_object {
            self.register_job_object(agent_id, job).await;
        }
    }

    /// Connects the CapabilityGate so autotomy immediately revokes capabilities.
    pub async fn set_capability_gate(&self, gate: Arc<CapabilityGate>) {
        let mut cap = self.capability_gate.write().await;
        *cap = Some(gate);
    }

    /// Connects the RingController so autotomy immediately revokes trusted arm handles.
    pub async fn set_ring_controller(&self, controller: RingController) {
        let mut rc = self.ring_controller.write().await;
        *rc = Some(controller);
    }

    /// Validates that a requested file path strictly adheres to the sandbox filesystem boundary.
    pub async fn validate_filesystem_access(&self, requested_path: &str) -> Result<PathBuf, OctopusSecurityError> {
        // 1. Path Traversal Invariant
        if requested_path.contains("..") || requested_path.contains("/../") || requested_path.contains("\\..\\") {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "Path traversal attempt blocked: '{}' attempts directory traversal",
                requested_path
            )));
        }

        // 2. Sensitive Host / Windows Directories & Registry Invariant
        let lower = requested_path.to_lowercase();
        if lower.starts_with("c:\\windows")
            || lower.starts_with("/etc")
            || lower.starts_with("/sys")
            || lower.contains("system32")
            || lower.contains("hklm")
            || lower.contains("hkcu")
            || lower.contains("registry")
            || lower.starts_with("c:\\users\\") && !lower.contains("scratch")
        {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "Host filesystem boundary violation: Access to sensitive path '{}' is denied",
                requested_path
            )));
        }

        let constraints = self.constraints.read().await;
        let safe_path = constraints.scratchpad_root.join(requested_path);
        Ok(safe_path)
    }

    /// Non-cooperative autotomy: supervisor terminates the arm immediately.
    /// Does NOT require the arm's consent or cooperation.
    /// Instantly trips the hardware kill switch, terminates the OS process via Job Object,
    /// revokes all capability tokens, and revokes ring handles.
    pub async fn terminate_arm(&self, agent_id: &str, reason: &str) -> Result<(), OctopusSecurityError> {
        // 1. Trip the software/atomic kill switch
        let switches = self.arm_kill_switches.read().await;
        if let Some(ks) = switches.get(agent_id) {
            ks.trip();
        }

        // 2. Kernel-enforced OS process termination via Windows Job Object
        let jobs = self.arm_job_objects.read().await;
        if let Some(job) = jobs.get(agent_id) {
            let _ = job.terminate(1);
        }

        // 3. Revoke all capability tokens without agent cooperation
        let cap_opt = self.capability_gate.read().await;
        if let Some(ref cap) = *cap_opt {
            cap.revoke_for_agent(agent_id).await;
        }

        // 4. Revoke RingController handle
        let ring_opt = self.ring_controller.read().await;
        if let Some(ref ring) = *ring_opt {
            let _ = ring.revoke(agent_id).await;
        }

        // 5. Record quarantine entry
        let mut quarantined = self.quarantined_arms.write().await;
        quarantined.insert(agent_id.to_string(), reason.to_string());

        Ok(())
    }

    /// Checks if an arm is currently active (not quarantined, not killed, not OS terminated).
    pub async fn is_arm_active(&self, agent_id: &str) -> bool {
        let quarantined = self.quarantined_arms.read().await;
        if quarantined.contains_key(agent_id) {
            return false;
        }

        let switches = self.arm_kill_switches.read().await;
        if let Some(ks) = switches.get(agent_id) {
            if ks.is_tripped() {
                return false;
            }
        }

        let jobs = self.arm_job_objects.read().await;
        if let Some(job) = jobs.get(agent_id) {
            if job.is_terminated.load(Ordering::SeqCst) {
                return false;
            }
        }

        true
    }

    /// Retrieves quarantine reason if arm is quarantined.
    pub async fn quarantine_reason(&self, agent_id: &str) -> Option<String> {
        self.quarantined_arms.read().await.get(agent_id).cloned()
    }

    /// Resets quarantine state for an arm (e.g. after limb regeneration by supervisor).
    pub async fn reset_quarantine(&self, agent_id: &str) {
        let mut quarantined = self.quarantined_arms.write().await;
        quarantined.remove(agent_id);
        let switches = self.arm_kill_switches.read().await;
        if let Some(ks) = switches.get(agent_id) {
            ks.reset();
        }
    }
}
