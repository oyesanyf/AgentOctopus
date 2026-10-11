use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::security::{AgentIdentity, SignedAgentMessage};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Inner Ring Identity Gate: Verifies agent identity and prevents identity spoofing across the swarm.
#[derive(Clone)]
pub struct IdentityGate {
    enrolled_identities: Arc<RwLock<HashMap<String, AgentIdentity>>>,
}

impl Default for IdentityGate {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityGate {
    pub fn new() -> Self {
        Self {
            enrolled_identities: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Enrolls a new authenticated agent identity into the Inner Ring trust plane.
    pub async fn enroll(&self, agent_id: &str, role: ArmRole, seed: &[u8]) -> AgentIdentity {
        let identity = AgentIdentity::new(agent_id, role, seed);
        let mut map = self.enrolled_identities.write().await;
        map.insert(agent_id.to_string(), identity.clone());
        identity
    }

    /// Verifies that an incoming message or operation genuinely originated from the claimed agent.
    pub async fn verify_signed_message(
        &self,
        message: &SignedAgentMessage,
    ) -> Result<(), OctopusSecurityError> {
        let map = self.enrolled_identities.read().await;
        let identity = map.get(&message.sender_id).ok_or_else(|| {
            OctopusSecurityError::IdentitySpoofingDetected(format!(
                "Unenrolled agent identity '{}' attempted to communicate across the Inner Ring",
                message.sender_id
            ))
        })?;

        identity.verify_incoming_message(message)
    }

    /// Checks if an agent is authorized for a specific role without impersonation.
    pub async fn assert_role(&self, agent_id: &str, expected_role: &ArmRole) -> Result<(), OctopusSecurityError> {
        let map = self.enrolled_identities.read().await;
        let identity = map.get(agent_id).ok_or_else(|| {
            OctopusSecurityError::IdentitySpoofingDetected(format!(
                "Agent '{}' is not registered in the Containment Ring identity directory",
                agent_id
            ))
        })?;

        if identity.role() != expected_role {
            return Err(OctopusSecurityError::IdentitySpoofingDetected(format!(
                "Role impersonation detected: Agent '{}' claims role {:?} but is registered as {:?}",
                agent_id, expected_role, identity.role()
            )));
        }

        Ok(())
    }
}
