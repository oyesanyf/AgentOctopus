//! Component 4: Independent Revocation Authority (`epoch_registry.rs`)
//!
//! Maintains an authoritative, tamper-proof record of active arm identities,
//! execution epochs, capability delegations, and revoked generations.
//! Guarantees that when Arm 17 is terminated, credentials from its old generation
//! (e.g. Gen 8) cannot authorize new work in Gen 9 or anywhere in the swarm.

use crate::core::types::OctopusSecurityError;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Active arm generation state managed independently by Sentinel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmEpochState {
    pub arm_id: u64,
    pub current_generation: u64,
    pub is_severed: bool,
    pub revoked_epochs: HashSet<u64>,
    pub last_updated_secs: u64,
    pub severance_reason: Option<String>,
}

/// Independent Revocation Authority for the Octopus Sentinel Ring.
pub struct EpochRegistry {
    arm_states: Arc<RwLock<HashMap<u64, ArmEpochState>>>,
    revoked_tokens: Arc<RwLock<HashSet<String>>>, // Revoked token IDs
}

impl EpochRegistry {
    /// Creates a new EpochRegistry pre-seeded with initial arm states.
    pub fn new(total_arms: usize) -> Self {
        let mut map = HashMap::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for arm_id in 0..total_arms as u64 {
            let initial_gen = if arm_id == 17 { 8 } else { 1 };
            map.insert(
                arm_id,
                ArmEpochState {
                    arm_id,
                    current_generation: initial_gen,
                    is_severed: false,
                    revoked_epochs: HashSet::new(),
                    last_updated_secs: now,
                    severance_reason: None,
                },
            );
        }

        Self {
            arm_states: Arc::new(RwLock::new(map)),
            revoked_tokens: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Checks if a presented generation epoch is currently active and authorized for an arm.
    pub async fn is_generation_active(
        &self,
        arm_id: u64,
        presented_generation: u64,
    ) -> Result<(), OctopusSecurityError> {
        let states = self.arm_states.read().await;
        if let Some(state) = states.get(&arm_id) {
            if state.is_severed {
                return Err(OctopusSecurityError::LimbKilled);
            }

            if state.revoked_epochs.contains(&presented_generation) {
                return Err(OctopusSecurityError::CapabilityDenied(format!(
                    "Sentinel Revocation: Arm {} epoch {} was permanently revoked after autotomy",
                    arm_id, presented_generation
                )));
            }

            if state.current_generation != presented_generation {
                return Err(OctopusSecurityError::CapabilityDenied(format!(
                    "Sentinel Epoch Mismatch: Arm {} active generation is {}, but presented {}",
                    arm_id, state.current_generation, presented_generation
                )));
            }

            Ok(())
        } else {
            Err(OctopusSecurityError::CapabilityDenied(format!(
                "Sentinel Revocation: Arm {} not found in authoritative registry",
                arm_id
            )))
        }
    }

    /// Revokes an arm's active generation, trips its severance state, and archives old epochs.
    pub async fn revoke_arm_generation(
        &self,
        arm_id: u64,
        reason: &str,
    ) -> Result<u64, OctopusSecurityError> {
        let mut states = self.arm_states.write().await;
        if let Some(state) = states.get_mut(&arm_id) {
            let revoked_gen = state.current_generation;
            state.revoked_epochs.insert(revoked_gen);
            state.is_severed = true;
            state.severance_reason = Some(reason.to_string());
            state.last_updated_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            Ok(revoked_gen)
        } else {
            Err(OctopusSecurityError::CapabilityDenied(format!(
                "Arm {} not registered",
                arm_id
            )))
        }
    }

    /// Advances an arm's generation epoch upon safe autotomy recovery (e.g. Gen 8 -> Gen 9).
    pub async fn advance_generation(&self, arm_id: u64) -> Result<u64, OctopusSecurityError> {
        let mut states = self.arm_states.write().await;
        if let Some(state) = states.get_mut(&arm_id) {
            let old_gen = state.current_generation;
            state.revoked_epochs.insert(old_gen);
            state.current_generation += 1;
            state.is_severed = false;
            state.severance_reason = None;
            state.last_updated_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            Ok(state.current_generation)
        } else {
            Err(OctopusSecurityError::CapabilityDenied(format!(
                "Arm {} not registered",
                arm_id
            )))
        }
    }

    /// Explicitly revokes a single capability token ID.
    pub async fn revoke_token(&self, token_id: &str) {
        let mut tokens = self.revoked_tokens.write().await;
        tokens.insert(token_id.to_string());
    }

    /// Checks if a capability token has been explicitly revoked.
    pub async fn is_token_revoked(&self, token_id: &str) -> bool {
        let tokens = self.revoked_tokens.read().await;
        tokens.contains(token_id)
    }

    /// Retrieves telemetry for all managed arms.
    pub async fn get_all_states(&self) -> Vec<ArmEpochState> {
        let states = self.arm_states.read().await;
        states.values().cloned().collect()
    }

    /// Retrieves an individual arm's current generation.
    pub async fn get_generation(&self, arm_id: u64) -> Option<u64> {
        let states = self.arm_states.read().await;
        states.get(&arm_id).map(|s| s.current_generation)
    }
}
