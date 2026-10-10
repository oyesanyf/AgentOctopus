use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::security::capabilities::{CapabilityToken, ExternalAuthorizationEngine};
use crate::security::delegation::DelegationScopeGuard;
use std::collections::HashSet;

/// Capability Guard: Enforces least-privilege capability permissions, token verification,
/// tool boundary restrictions, and cross-agent delegation limits.
pub struct CapabilityGuard {
    guard_id: String,
    auth_engine: ExternalAuthorizationEngine,
    delegation_guard: DelegationScopeGuard,
    revoked_tokens: HashSet<String>,
}

impl CapabilityGuard {
    pub fn new(guard_id: &str, secret_seed: &[u8], policy_fingerprint: &str) -> Self {
        Self {
            guard_id: guard_id.to_string(),
            auth_engine: ExternalAuthorizationEngine::new(secret_seed, 300, policy_fingerprint),
            delegation_guard: DelegationScopeGuard::new(2),
            revoked_tokens: HashSet::new(),
        }
    }

    pub fn guard_id(&self) -> &str {
        &self.guard_id
    }

    /// Revokes a capability token immediately.
    pub fn revoke_token(&mut self, token_id: &str) {
        self.revoked_tokens.insert(token_id.to_string());
    }

    /// Verifies capability token for tool invocation and resource access.
    pub fn verify_capability(
        &self,
        token: &CapabilityToken,
        requesting_agent: &str,
        requested_tool: &str,
        target_resource: &str,
    ) -> Result<(), OctopusSecurityError> {
        if self.revoked_tokens.contains(&token.token_id) {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Token {} has been revoked",
                token.token_id
            )));
        }

        self.auth_engine
            .verify_capability(token, requesting_agent, requested_tool, target_resource)
    }

    /// Validates multi-step delegation chains.
    pub fn validate_delegation_chain(
        &self,
        originator_role: &ArmRole,
        delegation_chain: &[ArmRole],
        target_role: &ArmRole,
        requested_tool: &str,
    ) -> Result<(), OctopusSecurityError> {
        self.delegation_guard.validate_delegation(
            originator_role,
            delegation_chain,
            target_role,
            requested_tool,
        )
    }

    pub fn auth_engine(&self) -> &ExternalAuthorizationEngine {
        &self.auth_engine
    }
}
