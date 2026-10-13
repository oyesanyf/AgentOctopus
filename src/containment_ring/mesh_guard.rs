use crate::core::types::OctopusSecurityError;
use crate::neural_mesh::MessageKind;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Inner Ring Neural Mesh Guard:
/// Mediates inter-arm communication, preventing privilege escalation,
/// message forgery, and unauthorized lateral movement.
#[derive(Clone)]
pub struct MeshGuard {
    allowed_routes: Arc<RwLock<HashSet<(String, String, Option<MessageKind>)>>>,
}

impl Default for MeshGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshGuard {
    pub fn new() -> Self {
        Self {
            allowed_routes: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Allows a specific route and message kind between two endpoints.
    pub async fn allow_route(&self, sender: &str, recipient: &str, kind: Option<MessageKind>) {
        let mut routes = self.allowed_routes.write().await;
        routes.insert((sender.to_string(), recipient.to_string(), kind));
    }

    /// Validates an inter-agent message crossing the Inner Ring.
    ///
    /// INVARIANT: An inter-agent message passes data, NEVER authority.
    /// An untrusted ingest arm sending an artifact to a ledger arm CANNOT
    /// grant the sender or recipient ledger-writing capabilities.
    pub async fn validate_message(
        &self,
        sender: &str,
        recipient: &str,
        kind: &MessageKind,
        correlation_id: &str,
        content: &str,
    ) -> Result<(), OctopusSecurityError> {
        // 1. Metadata bounds
        if correlation_id.len() > 128 {
            return Err(OctopusSecurityError::EnclaveViolation(
                "Inter-arm message correlation_id exceeds strict 128-byte limit".to_string(),
            ));
        }

        if content.len() > 16 * 1024 {
            return Err(OctopusSecurityError::EnclaveViolation(
                "Inter-arm message payload exceeds 16KB neural mesh capacity".to_string(),
            ));
        }

        // 2. High-trust inter-arm boundary: Untrusted/fuzzing/quarantine arms cannot message Ledger arms directly
        let sender_lower = sender.to_ascii_lowercase();
        let recipient_lower = recipient.to_ascii_lowercase();
        let is_untrusted_sender = sender_lower.contains("ingest")
            || sender_lower.contains("doc")
            || sender_lower.contains("fuzz")
            || sender_lower.contains("tarpit")
            || sender_lower.contains("differential")
            || sender_lower.contains("protocolresearch");
        let is_ledger_sink = recipient_lower.contains("ledger")
            || recipient_lower.contains("accounting");

        if is_untrusted_sender && is_ledger_sink {
            return Err(OctopusSecurityError::DelegationScopeViolation(format!(
                "Inner Ring Boundary Violation: Untrusted Arm '{}' is forbidden from direct lateral messaging to Sensitive Sink Arm '{}'",
                sender, recipient
            )));
        }

        // 3. Route authorization
        let routes = self.allowed_routes.read().await;
        let permitted = routes.contains(&(sender.to_string(), recipient.to_string(), Some(kind.clone())))
            || routes.contains(&(sender.to_string(), recipient.to_string(), None));

        if !permitted && !routes.is_empty() {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Inner Ring Route Veto: Route ({}) -> ({}) for kind {:?} is not authorized",
                sender, recipient, kind
            )));
        }

        Ok(())
    }
}
