use super::cedar_gate::NegativeControlToken;
use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::security::{CapabilityToken, ExternalAuthorizationEngine};
use rand::RngCore;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Enforces the Zero Ambient Authority Law:
/// No agent possesses ambient authority. Every privileged operation must present
/// a valid, unforgeable, unexpired, and non-revoked CapabilityToken.
#[derive(Clone)]
pub struct CapabilityGate {
    auth_engine: Arc<ExternalAuthorizationEngine>,
    revoked_token_ids: Arc<RwLock<HashSet<String>>>,
    enforcement_enabled: Arc<AtomicBool>,
    audit_control_token: Arc<String>,
}

impl CapabilityGate {
    pub fn new(secret_seed: &[u8], token_ttl_secs: u64) -> Self {
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let control_token = Arc::new(hex::encode(token_bytes));
        Self::with_audit_token(secret_seed, token_ttl_secs, control_token)
    }

    /// Creates a CapabilityGate alongside an authoritative NegativeControlToken for audit and verification harnesses.
    pub fn new_for_audit(secret_seed: &[u8], token_ttl_secs: u64) -> (Self, NegativeControlToken) {
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let control_token = Arc::new(hex::encode(token_bytes));
        let gate = Self::with_audit_token(secret_seed, token_ttl_secs, control_token.clone());
        let token = NegativeControlToken::new(control_token);
        (gate, token)
    }

    pub(crate) fn with_audit_token(secret_seed: &[u8], token_ttl_secs: u64, audit_token: Arc<String>) -> Self {
        Self {
            auth_engine: Arc::new(ExternalAuthorizationEngine::new(secret_seed, token_ttl_secs, "ring_policy_v1")),
            revoked_token_ids: Arc::new(RwLock::new(HashSet::new())),
            enforcement_enabled: Arc::new(AtomicBool::new(true)),
            audit_control_token: audit_token,
        }
    }

    /// Returns whether capability token verification is actively enforced.
    pub fn is_enforced(&self) -> bool {
        self.enforcement_enabled.load(Ordering::SeqCst)
    }

    /// Enables or deliberately disables capability token enforcement for negative-control sensitivity tests.
    /// FAIL-CLOSED: Requires presenting the cryptographically unforgeable `NegativeControlToken`.
    pub fn set_enforcement_enabled(&self, enabled: bool, token: &NegativeControlToken) -> Result<(), OctopusSecurityError> {
        if !crate::security::constant_time_eq(token.as_str().as_bytes(), self.audit_control_token.as_bytes()) {
            return Err(OctopusSecurityError::CapabilityDenied(
                "UNAUTHORIZED_CALL_PATH: Modification of capability gate enforcement state requires authoritative NegativeControlToken".to_string(),
            ));
        }
        self.enforcement_enabled.store(enabled, Ordering::SeqCst);
        Ok(())
    }

    /// Issues a strictly scoped, short-lived capability token.
    pub fn issue_capability(
        &self,
        issuer_id: &str,
        subject_id: &str,
        role: ArmRole,
        tool: &str,
        target_resource: &str,
    ) -> CapabilityToken {
        self.auth_engine.issue_capability(issuer_id, subject_id, role, tool, target_resource)
    }

    /// Verifies that a capability token is valid, matches the subject, tool, and target resource,
    /// and has not been revoked.
    pub async fn verify_capability(
        &self,
        token: &CapabilityToken,
        agent_id: &str,
        tool: &str,
        target_resource: &str,
    ) -> Result<(), OctopusSecurityError> {
        if !self.is_enforced() {
            // Defense deliberately disabled for negative-control sensitivity verification
            return Ok(());
        }

        let revoked = self.revoked_token_ids.read().await;
        if revoked.contains(&token.token_id)
            || revoked.contains(&format!("ALL_TOKENS_FOR_{}", agent_id))
            || revoked.contains(&format!("ALL_TOKENS_FOR_{}", token.bearer_agent))
        {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Capability token '{}' for agent '{}' has been revoked by supervisor autotomy",
                token.token_id, agent_id
            )));
        }

        self.auth_engine.verify_capability(token, agent_id, tool, target_resource)
    }

    /// Revokes a specific capability token instantly.
    pub async fn revoke_token(&self, token_id: &str) {
        let mut revoked = self.revoked_token_ids.write().await;
        revoked.insert(token_id.to_string());
    }

    /// Revokes all outstanding capability tokens for an arm (used during autotomy).
    pub async fn revoke_for_agent(&self, agent_id: &str) {
        // Any subsequent request by this agent will be rejected
        let mut revoked = self.revoked_token_ids.write().await;
        revoked.insert(format!("ALL_TOKENS_FOR_{}", agent_id));
    }
}
