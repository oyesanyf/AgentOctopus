use crate::core::types::OctopusSecurityError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArmState {
    Created,
    DirectiveAccepted,
    EnclaveDigesting,
    MerkleSealed,
    Completed,
    Quarantined,
}

impl std::fmt::Display for ArmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Finite State Machine Transition Guard.
/// Guarantees that an arm cannot jump out of order (e.g. skipping sanitization
/// or Merkle sealing to trigger payouts).
#[derive(Debug, Clone)]
pub struct FsmTransitionGuard {
    current_state: ArmState,
}

impl Default for FsmTransitionGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl FsmTransitionGuard {
    pub fn new() -> Self {
        Self {
            current_state: ArmState::Created,
        }
    }

    pub fn state(&self) -> ArmState {
        self.current_state
    }

    /// Attempts a formal state transition. Returns Err on any illegal jump.
    pub fn transition_to(&mut self, next: ArmState) -> Result<(), OctopusSecurityError> {
        let is_valid = match (self.current_state, next) {
            // Standard deterministic progression
            (ArmState::Created, ArmState::DirectiveAccepted) => true,
            (ArmState::DirectiveAccepted, ArmState::EnclaveDigesting) => true,
            (ArmState::EnclaveDigesting, ArmState::MerkleSealed) => true,
            (ArmState::MerkleSealed, ArmState::Completed) => true,

            // Any state can transition to Quarantined upon circuit break / autotomy
            (_, ArmState::Quarantined) => true,

            // Quarantined limbs cannot transition back directly without regeneration
            (ArmState::Quarantined, _) => false,

            // All other transitions (skipping states, backward jumps) are forbidden
            _ => false,
        };

        if !is_valid {
            return Err(OctopusSecurityError::IllegalStateTransition {
                from: self.current_state.to_string(),
                to: next.to_string(),
            });
        }

        self.current_state = next;
        Ok(())
    }
}
