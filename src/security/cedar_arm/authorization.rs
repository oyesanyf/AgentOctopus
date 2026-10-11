use super::delegation_policy::CedarDelegationPolicyGuard;
use super::policy_engine::{CedarEvaluationVerdict, CedarPolicyEngine};
use crate::core::types::OctopusSecurityError;
use crate::security::audit::SecurityAuditLog;
use crate::security::capabilities::{CapabilityToken, ExternalAuthorizationEngine};
use crate::security::identity::hmac_sha256;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Verifiable cryptographic supervisor approval receipt.
/// Prevents authorization-context injection by binding supervisor approval
/// cryptographically rather than trusting untrusted agent context fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SupervisorApprovalReceipt {
    pub supervisor_id: String,
    pub requesting_agent: String,
    pub target_resource: String,
    pub max_amount_cents: u64,
    pub issued_at_secs: u64,
    pub expires_at_secs: u64,
    pub signature_hex: String,
}

/// High-level authorization gateway interfacing Agent Octopus arms with Cedar.
pub struct CedarAuthorizationGateway {
    engine: CedarPolicyEngine,
    auth_engine: ExternalAuthorizationEngine,
    audit_log: Option<SecurityAuditLog>,
    secret_seed: Vec<u8>,
}

impl CedarAuthorizationGateway {
    pub fn new(secret_seed: &[u8], policy_fingerprint: &str) -> Self {
        Self {
            engine: CedarPolicyEngine::default(),
            auth_engine: ExternalAuthorizationEngine::new(secret_seed, 300, policy_fingerprint),
            audit_log: None,
            secret_seed: secret_seed.to_vec(),
        }
    }

    pub fn with_audit_log(mut self, log: SecurityAuditLog) -> Self {
        self.audit_log = Some(log);
        self
    }

    pub fn engine(&self) -> &CedarPolicyEngine {
        &self.engine
    }

    pub fn auth_engine(&self) -> &ExternalAuthorizationEngine {
        &self.auth_engine
    }

    pub fn audit_log(&self) -> Option<&SecurityAuditLog> {
        self.audit_log.as_ref()
    }

    /// Rotates the cryptographic authorization secret with verification and audit logging.
    /// Supports safe rotation: tokens signed with previous secret can optionally be verified
    /// or revoked according to key lifecycle policy.
    pub fn rotate_secret(
        &mut self,
        new_secret: &[u8],
        policy_fingerprint: &str,
    ) -> Result<String, OctopusSecurityError> {
        if new_secret.is_empty() {
            return Err(OctopusSecurityError::CapabilityDenied(
                "Cannot rotate to an empty secret key".to_string(),
            ));
        }
        if new_secret == self.secret_seed.as_slice() {
            return Err(OctopusSecurityError::CapabilityDenied(
                "New secret matches active secret: rotation requires a distinct cryptographic key".to_string(),
            ));
        }

        use sha2::Digest;
        let old_fingerprint = hex::encode(sha2::Sha256::digest(&self.secret_seed));
        self.secret_seed = new_secret.to_vec();
        self.auth_engine = ExternalAuthorizationEngine::new(new_secret, 300, policy_fingerprint);
        let new_fingerprint = hex::encode(sha2::Sha256::digest(&self.secret_seed));

        if let Some(log) = &self.audit_log {
            log.record_event(
                "SECRET_ROTATION",
                "system::security_admin",
                &format!("Rotated Cedar authorization secret from sha256:{} to sha256:{}", &old_fingerprint[..8], &new_fingerprint[..8]),
                "COMPLETED",
            );
        }

        Ok(new_fingerprint)
    }

    /// Issues an authenticated supervisor approval receipt.
    /// Invariant: Segregation of duties - a supervisor CANNOT approve its own request.
    pub fn issue_supervisor_approval(
        &self,
        supervisor_id: &str,
        requesting_agent: &str,
        target_resource: &str,
        max_amount_cents: u64,
        ttl_secs: u64,
    ) -> Result<SupervisorApprovalReceipt, OctopusSecurityError> {
        if supervisor_id == requesting_agent {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Segregation of duties violation: supervisor '{}' cannot approve its own request",
                supervisor_id
            )));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires_at_secs = now + ttl_secs;

        let content = format!(
            "{}:{}:{}:{}:{}",
            supervisor_id, requesting_agent, target_resource, max_amount_cents, expires_at_secs
        );
        let sig = hmac_sha256(&self.secret_seed, content.as_bytes());

        Ok(SupervisorApprovalReceipt {
            supervisor_id: supervisor_id.to_string(),
            requesting_agent: requesting_agent.to_string(),
            target_resource: target_resource.to_string(),
            max_amount_cents,
            issued_at_secs: now,
            expires_at_secs,
            signature_hex: hex::encode(sig),
        })
    }

    /// Verifies the cryptographic signature, validity, and scope of an approval receipt.
    pub fn verify_supervisor_approval(
        &self,
        receipt: &SupervisorApprovalReceipt,
        requesting_agent: &str,
        target_resource: &str,
        requested_amount_cents: u64,
    ) -> Result<(), OctopusSecurityError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Expiration check
        if now > receipt.expires_at_secs {
            return Err(OctopusSecurityError::CapabilityDenied(
                "Supervisor approval receipt expired".to_string(),
            ));
        }

        // 2. Segregation of duties: self-approval check
        if receipt.supervisor_id == receipt.requesting_agent || receipt.supervisor_id == requesting_agent {
            return Err(OctopusSecurityError::CapabilityDenied(
                "Segregation of duties violation: self-approval is forbidden".to_string(),
            ));
        }

        // 3. Requesting agent binding
        if receipt.requesting_agent != requesting_agent {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Approval receipt issued for agent '{}', but presented by '{}'",
                receipt.requesting_agent, requesting_agent
            )));
        }

        // 4. Target resource binding
        if receipt.target_resource != target_resource && !target_resource.starts_with(&receipt.target_resource) {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Approval receipt target '{}' does not match requested resource '{}'",
                receipt.target_resource, target_resource
            )));
        }

        // 5. Amount check
        if requested_amount_cents > receipt.max_amount_cents {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Requested amount {} exceeds approved ceiling {}",
                requested_amount_cents, receipt.max_amount_cents
            )));
        }

        // 6. Signature check
        let content = format!(
            "{}:{}:{}:{}:{}",
            receipt.supervisor_id,
            receipt.requesting_agent,
            receipt.target_resource,
            receipt.max_amount_cents,
            receipt.expires_at_secs
        );
        let expected_sig = hmac_sha256(&self.secret_seed, content.as_bytes());
        if hex::encode(expected_sig) != receipt.signature_hex {
            return Err(OctopusSecurityError::CapabilityDenied(
                "Forged or tampered supervisor approval receipt signature".to_string(),
            ));
        }

        Ok(())
    }

    /// Verifies TOCTOU (Time-of-Check to Time-of-Use) integrity between authorized digest and execution digest.
    pub fn verify_toctou_digest(
        authorized_resource_digest: &str,
        execution_resource_digest: &str,
    ) -> Result<(), OctopusSecurityError> {
        if authorized_resource_digest != execution_resource_digest {
            return Err(OctopusSecurityError::MerkleTamperDetected(format!(
                "TOCTOU violation: resource digest changed from '{}' at authorization to '{}' at execution",
                authorized_resource_digest, execution_resource_digest
            )));
        }
        Ok(())
    }

    /// Authorizes a tool invocation with optional supervisor approval receipt.
    /// Enforces independent context verification against authorization-context injection.
    pub fn authorize_tool_invocation_with_approval(
        &self,
        token: &CapabilityToken,
        requesting_agent: &str,
        tool_name: &str,
        target_resource: &str,
        untrusted_context: serde_json::Value,
        approval_receipt: Option<&SupervisorApprovalReceipt>,
    ) -> Result<CedarEvaluationVerdict, OctopusSecurityError> {
        // 1. Verify capability token (unforgeable HMAC signature, TTL, bearer, tool, resource, revocation)
        self.auth_engine
            .verify_capability(token, requesting_agent, tool_name, target_resource)?;

        // 2. Map tool name to Cedar Action and Resource Type
        let (action_name, resource_type) = match tool_name {
            "doc_extractor" => ("extract", "Document"),
            "ledger_writer" => ("write", "Ledger"),
            "http_egress" => ("egress", "NetworkTarget"),
            "notifier" => ("notify", "Agent"),
            "change_security_policy" => ("change_security_policy", "SystemPolicy"),
            "quarantine" => ("quarantine", "DecoyTrap"),
            "kernel_sentinel" => ("kernel_enforce", "KernelSubstrate"),
            _ => {
                return Err(OctopusSecurityError::CapabilityDenied(format!(
                    "Unrecognized tool action: {}",
                    tool_name
                )))
            }
        };

        // 3. Construct verified Cedar Context (Sanitizing untrusted agent context & preventing context injection)
        let verified_context = match tool_name {
            "ledger_writer" => {
                if let Some(map) = untrusted_context.as_object() {
                    let allowed = [
                        "amount_cents",
                        "approved",
                        "instruction_language",
                        "translated_prompt",
                        "language_code",
                        "sender_agent",
                        "target_agent",
                        "inter_agent_message",
                        "originator",
                    ];
                    if map.keys().any(|k| !allowed.contains(&k.as_str())) {
                        return Err(OctopusSecurityError::DeterministicLayerViolation(
                            "Ledger write context contains undeclared attributes or parameter tampering according to schema".to_string(),
                        ));
                    }
                }

                let requested_amount = untrusted_context
                    .get("amount_cents")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                let agent_claims_approved = untrusted_context
                    .get("approved")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                // Invariant: If agent claims 'approved: true' without valid supervisor receipt, abort immediately
                if agent_claims_approved && approval_receipt.is_none() {
                    return Err(OctopusSecurityError::CapabilityDenied(
                        "Authorization-context injection blocked: unverified 'approved: true' claim without supervisor receipt".to_string(),
                    ));
                }

                let approved = if let Some(receipt) = approval_receipt {
                    self.verify_supervisor_approval(
                        receipt,
                        requesting_agent,
                        target_resource,
                        requested_amount,
                    )?;
                    true
                } else {
                    false
                };

                serde_json::json!({
                    "amount_cents": requested_amount,
                    "approved": approved
                })
            }
            "http_egress" => {
                let domain = untrusted_context
                    .get("destination_domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                serde_json::json!({
                    "destination_domain": domain
                })
            }
            "doc_extractor" => {
                let depth = untrusted_context
                    .get("delegation_depth")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                serde_json::json!({
                    "delegation_depth": depth
                })
            }
            "change_security_policy" => {
                let quorum = untrusted_context
                    .get("quorum_authorized")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                serde_json::json!({
                    "quorum_authorized": quorum
                })
            }
            "kernel_sentinel" => {
                let tier = untrusted_context
                    .get("enforcement_tier")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Ring0");
                let pid = untrusted_context
                    .get("target_pid")
                    .and_then(|v| v.as_i64());
                let mut ctx_map = serde_json::Map::new();
                ctx_map.insert("enforcement_tier".to_string(), serde_json::Value::String(tier.to_string()));
                if let Some(p) = pid {
                    ctx_map.insert("target_pid".to_string(), serde_json::Value::Number(p.into()));
                }
                serde_json::Value::Object(ctx_map)
            }
            _ => untrusted_context,
        };

        // 4. Evaluate with Cedar PARC engine
        let verdict = self
            .engine
            .evaluate(
                requesting_agent,
                action_name,
                target_resource,
                resource_type,
                verified_context,
            )
            .map_err(|e| OctopusSecurityError::CapabilityDenied(format!("Cedar evaluation error: {}", e)))?;

        // 5. Record decision in audit trail
        let decision_str = if verdict.is_allowed { "ALLOW" } else { "DENY" };
        let details = format!(
            "Tool: {}, Resource: {}, Determining: {:?}",
            tool_name, target_resource, verdict.determining_policies
        );

        if let Some(ref audit) = self.audit_log {
            audit.record_event(
                "CEDAR_AUTHORIZATION",
                requesting_agent,
                &details,
                decision_str,
            );
        }

        if !verdict.is_allowed {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Action '{}' on '{}' denied by Cedar policy: errors={:?}",
                tool_name, target_resource, verdict.diagnostic_errors
            )));
        }

        Ok(verdict)
    }

    /// Primary authorization check for tool invocation.
    pub fn authorize_tool_invocation(
        &self,
        token: &CapabilityToken,
        requesting_agent: &str,
        tool_name: &str,
        target_resource: &str,
        context_json: serde_json::Value,
    ) -> Result<CedarEvaluationVerdict, OctopusSecurityError> {
        self.authorize_tool_invocation_with_approval(
            token,
            requesting_agent,
            tool_name,
            target_resource,
            context_json,
            None,
        )
    }

    /// Authorizes a cross-agent delegated invocation.
    /// Strictly verifies that the originating agent possesses the required permissions before evaluating bearer action.
    pub fn authorize_delegated_invocation(
        &self,
        token: &CapabilityToken,
        originator_agent: &str,
        delegation_chain: &[String],
        bearer_agent: &str,
        tool_name: &str,
        target_resource: &str,
        untrusted_context: serde_json::Value,
        approval_receipt: Option<&SupervisorApprovalReceipt>,
    ) -> Result<CedarEvaluationVerdict, OctopusSecurityError> {
        // 1. Cross-arm delegation check: Verify originator and intermediate chain permissions
        let guard = CedarDelegationPolicyGuard::default();
        guard.validate_delegation(
            originator_agent,
            delegation_chain,
            bearer_agent,
            tool_name,
            target_resource,
        )?;

        // 2. Authorize bearer invocation with full context and approval verification
        self.authorize_tool_invocation_with_approval(
            token,
            bearer_agent,
            tool_name,
            target_resource,
            untrusted_context,
            approval_receipt,
        )
    }
}

