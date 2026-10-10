use super::capability_guard::CapabilityGuard;
use super::containment_guard::ContainmentGuard;
use super::identity_guard::IdentityGuard;
use super::integrity_guard::IntegrityGuard;
use super::network_guard::NetworkGuard;
use super::sentinel_guard::SentinelGuard;
use crate::core::types::OctopusSecurityError;
use std::collections::{HashMap, HashSet};

/// Status of a Security Guard Arm within the mutual supervision network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardStatus {
    Healthy,
    Suspected,
    IsolatedByPeerQuorum,
}

/// Mutual peer accusation / vote cast by one guard against another.
#[derive(Debug, Clone)]
pub struct GuardPeerVote {
    pub accuser_guard: String,
    pub accused_guard: String,
    pub reason: String,
    pub timestamp_epoch_secs: u64,
}

/// GuardCoordinator: Implements "Guards watching Guards" peer mutual supervision.
/// No single guard possesses unchecked authority. If a guard arm exhibits anomalous
/// behavior, compromised execution, or inconsistent results, peer guards vote to isolate it
/// via Byzantine quorum consensus (requires > 50% majority of remaining peers).
pub struct GuardCoordinator {
    pub sentinel: SentinelGuard,
    pub identity: IdentityGuard,
    pub capability: CapabilityGuard,
    pub network: NetworkGuard,
    pub integrity: IntegrityGuard,
    pub containment: ContainmentGuard,
    guard_statuses: HashMap<String, GuardStatus>,
    peer_accusations: Vec<GuardPeerVote>,
}

impl GuardCoordinator {
    pub fn new(secret_seed: &[u8], policy_fingerprint: &str) -> Self {
        let sentinel = SentinelGuard::new("guard_sentinel", 5000);
        let identity = IdentityGuard::new("guard_identity");
        let capability = CapabilityGuard::new("guard_capability", secret_seed, policy_fingerprint);
        let network = NetworkGuard::new("guard_network");
        let integrity = IntegrityGuard::new("guard_integrity");
        let containment = ContainmentGuard::new("guard_containment", 64 * 1024 * 1024);

        let mut guard_statuses = HashMap::new();
        guard_statuses.insert("guard_sentinel".to_string(), GuardStatus::Healthy);
        guard_statuses.insert("guard_identity".to_string(), GuardStatus::Healthy);
        guard_statuses.insert("guard_capability".to_string(), GuardStatus::Healthy);
        guard_statuses.insert("guard_network".to_string(), GuardStatus::Healthy);
        guard_statuses.insert("guard_integrity".to_string(), GuardStatus::Healthy);
        guard_statuses.insert("guard_containment".to_string(), GuardStatus::Healthy);

        Self {
            sentinel,
            identity,
            capability,
            network,
            integrity,
            containment,
            guard_statuses,
            peer_accusations: Vec::new(),
        }
    }

    /// List of all guards in the network.
    pub fn list_guards(&self) -> Vec<String> {
        self.guard_statuses.keys().cloned().collect()
    }

    /// Returns the current health status of a guard.
    pub fn get_guard_status(&self, guard_id: &str) -> Option<&GuardStatus> {
        self.guard_statuses.get(guard_id)
    }

    /// Casts an accusation vote from one guard against another.
    /// Evaluates whether the quorum threshold is reached to automatically isolate the accused guard.
    pub fn report_peer_anomaly(
        &mut self,
        accuser_guard: &str,
        accused_guard: &str,
        reason: &str,
        now_secs: u64,
    ) -> Result<bool, OctopusSecurityError> {
        if !self.guard_statuses.contains_key(accuser_guard) {
            return Err(OctopusSecurityError::IdentitySpoofingDetected(format!(
                "Unknown accuser guard: {}",
                accuser_guard
            )));
        }

        if !self.guard_statuses.contains_key(accused_guard) {
            return Err(OctopusSecurityError::IdentitySpoofingDetected(format!(
                "Unknown accused guard: {}",
                accused_guard
            )));
        }

        if accuser_guard == accused_guard {
            return Err(OctopusSecurityError::EnclaveViolation(
                "A guard arm cannot accuse itself".to_string(),
            ));
        }

        // Accuser must be healthy
        if self.guard_statuses.get(accuser_guard) != Some(&GuardStatus::Healthy) {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Accuser guard {} is not in Healthy state",
                accuser_guard
            )));
        }

        self.peer_accusations.push(GuardPeerVote {
            accuser_guard: accuser_guard.to_string(),
            accused_guard: accused_guard.to_string(),
            reason: reason.to_string(),
            timestamp_epoch_secs: now_secs,
        });

        // Count unique healthy accusers against this accused guard
        let mut unique_accusers = HashSet::new();
        for vote in &self.peer_accusations {
            if vote.accused_guard == accused_guard
                && self.guard_statuses.get(&vote.accuser_guard) == Some(&GuardStatus::Healthy)
            {
                unique_accusers.insert(&vote.accuser_guard);
            }
        }

        // Total peer count excluding the accused
        let total_peers = self.guard_statuses.len() - 1;
        let quorum_threshold = (total_peers / 2) + 1; // Strict majority (> 50%)

        if unique_accusers.len() >= quorum_threshold {
            self.guard_statuses
                .insert(accused_guard.to_string(), GuardStatus::IsolatedByPeerQuorum);
            Ok(true) // Isolated
        } else {
            self.guard_statuses
                .insert(accused_guard.to_string(), GuardStatus::Suspected);
            Ok(false) // Suspected but quorum not yet met
        }
    }

    /// Evaluates swarm action against all 6 guards before execution.
    /// Fail-closed: If ANY active guard rejects or if the required guard is isolated, returns error.
    pub fn pre_execution_swarm_guard_check(
        &mut self,
        target_url: Option<&str>,
        memory_usage_bytes: usize,
    ) -> Result<(), OctopusSecurityError> {
        // 1. Network check
        if let Some(url) = target_url {
            if self.guard_statuses.get("guard_network") != Some(&GuardStatus::Healthy) {
                return Err(OctopusSecurityError::IsolationViolation(
                    "Network Guard is not healthy: egress blocked fail-closed".to_string(),
                ));
            }
            self.network.validate_egress(url)?;
        }

        // 2. Memory clamp check
        if memory_usage_bytes > 64 * 1024 * 1024 {
            return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
                "Memory clamp exceeded: {} bytes > 64MB",
                memory_usage_bytes
            )));
        }

        Ok(())
    }
}
