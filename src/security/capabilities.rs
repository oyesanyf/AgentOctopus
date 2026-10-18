use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::security::identity::hmac_sha256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TOKEN_ENTROPY_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Short-lived, unforgeable capability token required for every tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityToken {
    pub token_id: String,
    pub originator_agent: String,
    pub bearer_agent: String,
    pub permitted_role: ArmRole,
    pub permitted_tool: String,
    pub resource_uri_prefix: String,
    pub issued_at_secs: u64,
    pub expires_at_secs: u64,
    pub policy_fingerprint: String,
    pub signature_hex: String,
}

impl CapabilityToken {
    pub fn is_expired(&self, current_time_secs: u64) -> bool {
        current_time_secs > self.expires_at_secs
    }
}

/// Independent External Authorization Engine.
/// Sits strictly outside the agent swarm to prevent agents from approving their own actions.
#[derive(Clone)]
pub struct ExternalAuthorizationEngine {
    master_key: [u8; 32],
    capability_ttl_secs: u64,
    policy_fingerprint: String,
    revoked_tokens: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
}

impl ExternalAuthorizationEngine {
    pub fn new(secret_seed: &[u8], capability_ttl_secs: u64, policy_fingerprint: &str) -> Self {
        let master_key = hmac_sha256(secret_seed, b"OCTOPUS_MASTER_AUTHORIZATION_KEY_V1");
        Self {
            master_key,
            capability_ttl_secs,
            policy_fingerprint: policy_fingerprint.to_string(),
            revoked_tokens: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        }
    }

    pub fn with_revoked_tokens(
        secret_seed: &[u8],
        capability_ttl_secs: u64,
        policy_fingerprint: &str,
        revoked_tokens: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
    ) -> Self {
        let master_key = hmac_sha256(secret_seed, b"OCTOPUS_MASTER_AUTHORIZATION_KEY_V1");
        Self {
            master_key,
            capability_ttl_secs,
            policy_fingerprint: policy_fingerprint.to_string(),
            revoked_tokens,
        }
    }

    pub fn revoked_tokens_arc(&self) -> std::sync::Arc<std::sync::RwLock<std::collections::HashSet<String>>> {
        self.revoked_tokens.clone()
    }

    pub fn revoke_token(&self, token_id: &str) {
        let mut set = self.revoked_tokens.write().unwrap();
        set.insert(token_id.to_string());
    }

    pub fn is_revoked(&self, token_id: &str) -> bool {
        self.revoked_tokens.read().unwrap().contains(token_id)
    }

    /// Issues a cryptographic capability token bound to the agent, tool, and resource scope.
    /// Generates unpredictable, cryptographically random token IDs (no predictable timestamp collisions).
    pub fn issue_capability(
        &self,
        originator_agent: &str,
        bearer_agent: &str,
        permitted_role: ArmRole,
        permitted_tool: &str,
        resource_uri_prefix: &str,
    ) -> CapabilityToken {
        let now_duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let now_secs = now_duration.as_secs();
        let now_nanos = now_duration.as_nanos();
        let counter = TOKEN_ENTROPY_COUNTER.fetch_add(1, Ordering::SeqCst);

        // Derive cryptographically secure, unpredictable token ID
        let mut id_hasher = Sha256::new();
        id_hasher.update(&self.master_key);
        id_hasher.update(now_nanos.to_le_bytes());
        id_hasher.update(counter.to_le_bytes());
        id_hasher.update(originator_agent.as_bytes());
        id_hasher.update(bearer_agent.as_bytes());
        let id_hash = id_hasher.finalize();
        let token_id = format!("CAP-{}", hex::encode(&id_hash[0..12]));

        let expires_at_secs = now_secs + self.capability_ttl_secs;

        let signing_content = format!(
            "{}:{}:{}:{:?}:{}:{}:{}:{}:{}",
            token_id,
            originator_agent,
            bearer_agent,
            permitted_role,
            permitted_tool,
            resource_uri_prefix,
            now_secs,
            expires_at_secs,
            self.policy_fingerprint
        );

        let sig = hmac_sha256(&self.master_key, signing_content.as_bytes());
        let signature_hex = hex::encode(sig);

        CapabilityToken {
            token_id,
            originator_agent: originator_agent.to_string(),
            bearer_agent: bearer_agent.to_string(),
            permitted_role,
            permitted_tool: permitted_tool.to_string(),
            resource_uri_prefix: resource_uri_prefix.to_string(),
            issued_at_secs: now_secs,
            expires_at_secs,
            policy_fingerprint: self.policy_fingerprint.clone(),
            signature_hex,
        }
    }

    /// Verifies that a presented capability token is genuine, unexpired, and authorizes the exact action.
    pub fn verify_capability(
        &self,
        token: &CapabilityToken,
        bearer_agent: &str,
        tool: &str,
        resource_uri: &str,
    ) -> Result<(), OctopusSecurityError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Expiration check (fail-closed)
        if token.is_expired(now) {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Capability token '{}' expired at {} (current: {})",
                token.token_id, token.expires_at_secs, now
            )));
        }

        // 1b. Revocation check (replay after revocation prevention)
        if self.is_revoked(&token.token_id) {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Capability token '{}' has been revoked",
                token.token_id
            )));
        }

        // 2. Cryptographic signature check (cannot be forged or modified)
        let signing_content = format!(
            "{}:{}:{}:{:?}:{}:{}:{}:{}:{}",
            token.token_id,
            token.originator_agent,
            token.bearer_agent,
            token.permitted_role,
            token.permitted_tool,
            token.resource_uri_prefix,
            token.issued_at_secs,
            token.expires_at_secs,
            token.policy_fingerprint
        );
        let expected_sig = hmac_sha256(&self.master_key, signing_content.as_bytes());
        let expected_hex = hex::encode(expected_sig);

        if !crate::security::identity::constant_time_eq_hex(&expected_hex, &token.signature_hex) {
            return Err(OctopusSecurityError::CapabilityDenied(
                "Tampered or forged capability token signature!".to_string(),
            ));
        }

        // 3. Bearer binding check (token cannot be transferred to another agent)
        if token.bearer_agent != bearer_agent {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Token bearer mismatch: token bound to '{}', presented by '{}'",
                token.bearer_agent, bearer_agent
            )));
        }

        // 4. Tool authorization check
        if token.permitted_tool != tool && token.permitted_tool != "*" {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Tool privilege escalation blocked: Token does not permit tool '{}': token allows '{}'",
                tool, token.permitted_tool
            )));
        }

        // 5. Resource URI scope prefix & traversal check
        let lower_uri = resource_uri.to_ascii_lowercase();
        if resource_uri.contains("..")
            || lower_uri.contains("%2e")
            || lower_uri.contains("%2f")
            || lower_uri.contains("%5c")
            || lower_uri.contains("%00")
            || resource_uri.contains('\0')
        {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Resource URI traversal sequence rejected in '{}'",
                resource_uri
            )));
        }

        if !resource_uri.starts_with(&token.resource_uri_prefix) && token.resource_uri_prefix != "*" {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Resource scope violation: Target resource '{}' is outside token authorized prefix '{}'",
                resource_uri, token.resource_uri_prefix
            )));
        }

        Ok(())
    }

    /// Verifies capability token including strict caller role authorization.
    pub fn verify_capability_with_role(
        &self,
        token: &CapabilityToken,
        bearer_agent: &str,
        caller_role: ArmRole,
        tool: &str,
        resource_uri: &str,
    ) -> Result<(), OctopusSecurityError> {
        if token.permitted_role != caller_role {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Capability role mismatch: token authorizes '{:?}', but caller has role '{:?}'",
                token.permitted_role, caller_role
            )));
        }
        self.verify_capability(token, bearer_agent, tool, resource_uri)
    }
}
