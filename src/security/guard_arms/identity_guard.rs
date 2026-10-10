use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::security::identity::{AgentIdentity, SignedAgentMessage};
use std::collections::HashMap;

/// Identity Guard: Verifies cryptographic token IDs, authenticates agent identities,
/// enforces monotonic sequence numbers, and blocks message replay attacks.
pub struct IdentityGuard {
    guard_id: String,
    trusted_identities: HashMap<String, AgentIdentity>,
}

impl IdentityGuard {
    pub fn new(guard_id: &str) -> Self {
        Self {
            guard_id: guard_id.to_string(),
            trusted_identities: HashMap::new(),
        }
    }

    pub fn guard_id(&self) -> &str {
        &self.guard_id
    }

    /// Registers a trusted agent identity within the identity guard.
    pub fn register_trusted_identity(&mut self, identity: AgentIdentity) {
        self.trusted_identities
            .insert(identity.agent_id().to_string(), identity);
    }

    /// Verifies the authenticity, cryptographic signature, and replay freshness of an incoming agent message.
    pub fn verify_message(
        &self,
        message: &SignedAgentMessage,
    ) -> Result<(), OctopusSecurityError> {
        // 1. Check if identity is known
        let identity = self
            .trusted_identities
            .get(&message.sender_id)
            .ok_or_else(|| {
                OctopusSecurityError::IdentitySpoofingDetected(format!(
                    "Unknown or untrusted agent: {}",
                    message.sender_id
                ))
            })?;

        // 2. Delegate to the agent's cryptographic verification which enforces HMAC and monotonic nonces
        identity.verify_incoming_message(message)
    }

    /// Validates whether a designated agent is authorized to take on a specific role.
    pub fn validate_agent_role(
        &self,
        agent_id: &str,
        expected_role: &ArmRole,
    ) -> Result<(), OctopusSecurityError> {
        let identity = self.trusted_identities.get(agent_id).ok_or_else(|| {
            OctopusSecurityError::IdentitySpoofingDetected(format!("Unknown agent: {}", agent_id))
        })?;

        if identity.role() != expected_role {
            return Err(OctopusSecurityError::IdentitySpoofingDetected(format!(
                "Agent {} role '{:?}' does not match expected role '{:?}'",
                agent_id, identity.role(), expected_role
            )));
        }

        Ok(())
    }
}
