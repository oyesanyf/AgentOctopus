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

/// An active or historic secret epoch in the key rotation ring.
#[derive(Clone, Debug)]
pub struct SecretEpoch {
    pub generation: u64,
    pub secret: Vec<u8>,
    pub fingerprint: String,
    pub activated_at_secs: u64,
}

/// Securely loads an authorization secret from OCTOPUS_CEDAR_SECRET or generates 32 bytes from CSPRNG.
pub fn load_or_generate_cedar_secret() -> Vec<u8> {
    if let Ok(env_val) = std::env::var("OCTOPUS_CEDAR_SECRET") {
        let trimmed = env_val.trim();
        if !trimmed.is_empty() {
            if trimmed.len() >= 32 {
                return trimmed.as_bytes().to_vec();
            } else {
                use sha2::Digest;
                return sha2::Sha256::digest(trimmed.as_bytes()).to_vec();
            }
        }
    }
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
    seed.to_vec()
}

/// High-level authorization gateway interfacing Agent Octopus arms with Cedar.
pub struct CedarAuthorizationGateway {
    engine: CedarPolicyEngine,
    auth_engine: ExternalAuthorizationEngine,
    audit_log: Option<SecurityAuditLog>,
    secret_seed: Vec<u8>,
    active_epoch: SecretEpoch,
    previous_epoch: Option<SecretEpoch>,
    previous_auth_engine: Option<ExternalAuthorizationEngine>,
    grace_period_secs: u64,
    generation: u64,
    arm_ring: std::sync::Arc<crate::containment_ring::ArmContainmentRing>,
    temporal_engine: std::sync::Arc<crate::security::cedar_arm::temporal::DogwoodTemporalEngine>,
    temporal_policies: std::sync::RwLock<std::collections::HashMap<String, String>>,
}

impl CedarAuthorizationGateway {
    pub fn new(secret_seed: &[u8], policy_fingerprint: &str) -> Self {
        use sha2::Digest;
        let fp = hex::encode(sha2::Sha256::digest(secret_seed));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let active_epoch = SecretEpoch {
            generation: 1,
            secret: secret_seed.to_vec(),
            fingerprint: fp,
            activated_at_secs: now,
        };
        let arm_ring = std::sync::Arc::new(crate::containment_ring::ArmContainmentRing::new(
            100,
            crate::core::types::ArmRole::CedarPolicyEvaluation,
            1,
            secret_seed,
        ));

        let temporal_engine = std::sync::Arc::new(
            crate::security::cedar_arm::temporal::DogwoodTemporalEngine::new_simulation()
        );

        let mut default_temporal_policies = std::collections::HashMap::new();
        // Mandatory temporal prerequisite for ledger writes: must have performed a read/extract within 1 hour
        default_temporal_policies.insert(
            "protocol_research_eval".to_string(),
            r#"when temporal { formerly exactly < 30 within 5m (Octopus::Action::"evaluate"::response{ callerPrincipal: principal }) };"#.to_string(),
        );
        default_temporal_policies.insert(
            "ledger_writer".to_string(),
            r#"when temporal { formerly within 1h (Octopus::Action::"LedgerRead"::response{ callerPrincipal: principal } || Octopus::Action::"extract"::response{ callerPrincipal: principal } || Octopus::Action::"Read"::response{ callerPrincipal: principal }) };"#.to_string(),
        );
        default_temporal_policies.insert(
            "write".to_string(),
            r#"when temporal { formerly within 1h (Octopus::Action::"LedgerRead"::response{ callerPrincipal: principal } || Octopus::Action::"extract"::response{ callerPrincipal: principal } || Octopus::Action::"Read"::response{ callerPrincipal: principal }) };"#.to_string(),
        );
        // Mandatory temporal prerequisite for kernel enforcement: must be preceded by authentication step within 60s
        default_temporal_policies.insert(
            "kernel_sentinel".to_string(),
            r#"when temporal { formerly within 60s (Octopus::Action::"AuthenticateStep"::response{ callerPrincipal: principal } || Octopus::Action::"CredentialsVerified"::response{ callerPrincipal: principal }) };"#.to_string(),
        );
        default_temporal_policies.insert(
            "kernel_enforce".to_string(),
            r#"when temporal { formerly within 60s (Octopus::Action::"AuthenticateStep"::response{ callerPrincipal: principal } || Octopus::Action::"CredentialsVerified"::response{ callerPrincipal: principal }) };"#.to_string(),
        );

        Self {
            engine: CedarPolicyEngine::default(),
            auth_engine: ExternalAuthorizationEngine::new(secret_seed, 300, policy_fingerprint),
            audit_log: None,
            secret_seed: secret_seed.to_vec(),
            active_epoch,
            previous_epoch: None,
            previous_auth_engine: None,
            grace_period_secs: 300,
            generation: 1,
            arm_ring,
            temporal_engine,
            temporal_policies: std::sync::RwLock::new(default_temporal_policies),
        }
    }

    pub fn with_containment_ring(mut self, ring: std::sync::Arc<crate::containment_ring::ArmContainmentRing>) -> Self {
        self.arm_ring = ring;
        self
    }

    pub fn containment_ring(&self) -> &std::sync::Arc<crate::containment_ring::ArmContainmentRing> {
        &self.arm_ring
    }

    pub fn with_audit_log(mut self, log: SecurityAuditLog) -> Self {
        self.audit_log = Some(log);
        self
    }

    pub fn with_temporal_engine(mut self, engine: std::sync::Arc<crate::security::cedar_arm::temporal::DogwoodTemporalEngine>) -> Self {
        self.temporal_engine = engine;
        self
    }

    pub fn temporal_engine(&self) -> &std::sync::Arc<crate::security::cedar_arm::temporal::DogwoodTemporalEngine> {
        &self.temporal_engine
    }

    pub fn temporal_policies(&self) -> &std::sync::RwLock<std::collections::HashMap<String, String>> {
        &self.temporal_policies
    }

    pub fn register_temporal_policy(&self, action_or_tool: &str, policy_clause: &str) {
        self.temporal_policies.write().unwrap().insert(action_or_tool.to_string(), policy_clause.to_string());
    }

    pub fn remove_temporal_policy(&self, action_or_tool: &str) {
        self.temporal_policies.write().unwrap().remove(action_or_tool);
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

    pub fn secret_seed(&self) -> &[u8] {
        &self.secret_seed
    }

    pub fn active_epoch(&self) -> &SecretEpoch {
        &self.active_epoch
    }

    pub fn previous_epoch(&self) -> Option<&SecretEpoch> {
        self.previous_epoch.as_ref()
    }

    /// Rotates the cryptographic authorization secret with verification, rollback safety, and audit logging.
    /// Preserves revoked tokens and enables dual verification during the 300s grace window.
    pub fn rotate_secret(
        &mut self,
        new_secret: &[u8],
        policy_fingerprint: &str,
    ) -> Result<String, OctopusSecurityError> {
        if self.arm_ring.is_severed() {
            return Err(OctopusSecurityError::LimbKilled);
        }
        if new_secret.is_empty() {
            return Err(OctopusSecurityError::CapabilityDenied(
                "Cannot rotate to an empty secret key".to_string(),
            ));
        }
        if new_secret.len() < 32 {
            return Err(OctopusSecurityError::CapabilityDenied(
                "Cryptographic secret requires minimum 256 bits (32 bytes) of entropy".to_string(),
            ));
        }
        if new_secret == self.secret_seed.as_slice() {
            return Err(OctopusSecurityError::CapabilityDenied(
                "New secret matches active secret: rotation requires a distinct cryptographic key".to_string(),
            ));
        }

        use sha2::Digest;
        let old_fingerprint = self.active_epoch.fingerprint.clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Preserve previous epoch for rollback and in-flight token grace period
        self.previous_epoch = Some(self.active_epoch.clone());
        self.previous_auth_engine = Some(self.auth_engine.clone());

        self.generation += 1;
        let new_fingerprint = hex::encode(sha2::Sha256::digest(new_secret));
        self.secret_seed = new_secret.to_vec();
        self.active_epoch = SecretEpoch {
            generation: self.generation,
            secret: new_secret.to_vec(),
            fingerprint: new_fingerprint.clone(),
            activated_at_secs: now,
        };

        // Preserve revoked tokens across rotation epochs
        let revoked_tokens = self.auth_engine.revoked_tokens_arc();
        self.auth_engine = ExternalAuthorizationEngine::with_revoked_tokens(
            new_secret,
            300,
            policy_fingerprint,
            revoked_tokens,
        );

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

    /// Atomically rolls back the authorization secret to the previous epoch with audit logging.
    pub fn rollback_secret(&mut self) -> Result<String, OctopusSecurityError> {
        let prev = self.previous_epoch.take().ok_or_else(|| {
            OctopusSecurityError::CapabilityDenied(
                "Rollback failed: No previous secret epoch exists in rotation ring".to_string(),
            )
        })?;

        let old_fingerprint = self.active_epoch.fingerprint.clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.generation += 1;
        let restored_fingerprint = prev.fingerprint.clone();
        self.secret_seed = prev.secret.clone();
        self.active_epoch = SecretEpoch {
            generation: self.generation,
            secret: prev.secret.clone(),
            fingerprint: restored_fingerprint.clone(),
            activated_at_secs: now,
        };

        let revoked_tokens = self.auth_engine.revoked_tokens_arc();
        self.auth_engine = ExternalAuthorizationEngine::with_revoked_tokens(
            &prev.secret,
            300,
            "cedar_ring_v4.13",
            revoked_tokens,
        );
        self.previous_auth_engine = None;

        if let Some(log) = &self.audit_log {
            log.record_event(
                "SECRET_ROLLBACK",
                "system::security_admin",
                &format!("Rolled back Cedar authorization secret from sha256:{} to sha256:{}", &old_fingerprint[..8], &restored_fingerprint[..8]),
                "COMPLETED",
            );
        }

        Ok(restored_fingerprint)
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

        // 6. Signature check (with grace period dual verification for recent rotation)
        let content = format!(
            "{}:{}:{}:{}:{}",
            receipt.supervisor_id,
            receipt.requesting_agent,
            receipt.target_resource,
            receipt.max_amount_cents,
            receipt.expires_at_secs
        );
        let expected_sig = hmac_sha256(&self.secret_seed, content.as_bytes());
        if !crate::security::constant_time_eq_hex(&hex::encode(expected_sig), &receipt.signature_hex) {
            let in_grace_period = if let Some(prev) = &self.previous_epoch {
                let elapsed = now.saturating_sub(self.active_epoch.activated_at_secs);
                if elapsed <= self.grace_period_secs {
                    let prev_sig = hmac_sha256(&prev.secret, content.as_bytes());
                    crate::security::constant_time_eq_hex(&hex::encode(prev_sig), &receipt.signature_hex)
                } else {
                    false
                }
            } else {
                false
            };

            if !in_grace_period {
                return Err(OctopusSecurityError::CapabilityDenied(
                    "Forged or tampered supervisor approval receipt signature".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Verifies TOCTOU (Time-of-Check to Time-of-Use) integrity between authorized digest and execution digest.
    pub fn verify_toctou_digest(
        authorized_resource_digest: &str,
        execution_resource_digest: &str,
    ) -> Result<(), OctopusSecurityError> {
        if !crate::security::constant_time_eq_hex(authorized_resource_digest, execution_resource_digest) {
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
        // Level 1: Mandatory Arm Containment Ring check on the Cedar authorization engine
        if self.arm_ring.is_severed() {
            return Err(OctopusSecurityError::LimbKilled);
        }

        // 1. Verify capability token (with dual verification during 300s grace window)
        let token_result = self.auth_engine
            .verify_capability(token, requesting_agent, tool_name, target_resource);
        if let Err(e) = token_result {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let in_grace = if let Some(prev_engine) = &self.previous_auth_engine {
                let elapsed = now.saturating_sub(self.active_epoch.activated_at_secs);
                if elapsed <= self.grace_period_secs {
                    prev_engine.verify_capability(token, requesting_agent, tool_name, target_resource).is_ok()
                } else {
                    false
                }
            } else {
                false
            };

            if !in_grace {
                return Err(e);
            }
        }

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
                verified_context.clone(),
            )
            .map_err(|e| OctopusSecurityError::CapabilityDenied(format!("Cedar evaluation error: {}", e)))?;

        if !verdict.is_allowed {
            let decision_str = "DENY";
            let details = format!(
                "Tool: {}, Resource: {}, Cedar DENY: {:?}",
                tool_name, target_resource, verdict.diagnostic_errors
            );
            if let Some(ref audit) = self.audit_log {
                audit.record_event(
                    "CEDAR_AUTHORIZATION",
                    requesting_agent,
                    &details,
                    decision_str,
                );
            }
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Action '{}' on '{}' denied by Cedar policy: errors={:?}",
                tool_name, target_resource, verdict.diagnostic_errors
            )));
        }

        // 5. JOINT DOGWOOD TEMPORAL ENFORCEMENT (FAIL-CLOSED)
        let temporal_rules = self
            .temporal_policies
            .read()
            .map_err(|_| OctopusSecurityError::CapabilityDenied("Temporal policy lock poisoned".to_string()))?;
        if let Some(temporal_policy) = temporal_rules.get(tool_name).or_else(|| temporal_rules.get(action_name)) {
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let mut ctx_fields = std::collections::HashMap::new();
            if let Some(obj) = verified_context.as_object() {
                for (k, v) in obj {
                    ctx_fields.insert(k.clone(), v.clone());
                }
            }

            let decision_ctx = crate::security::cedar_arm::temporal::DecisionContext {
                current_time_secs: now_sec,
                principal: requesting_agent.to_string(),
                resource: target_resource.to_string(),
                context_fields: ctx_fields,
            };

            let temporal_verdict = self.temporal_engine.evaluate_policy(temporal_policy, &decision_ctx);
            match temporal_verdict {
                Ok(true) => {
                    // Both Cedar and Dogwood temporal preconditions satisfied
                }
                Ok(false) => {
                    if let Some(ref audit) = self.audit_log {
                        audit.record_event(
                            "DOGWOOD_TEMPORAL_AUTHORIZATION",
                            requesting_agent,
                            &format!("Tool: {}, Resource: {}, Temporal policy '{}' unsatisfied", tool_name, target_resource, temporal_policy),
                            "FORBID",
                        );
                    }
                    return Err(OctopusSecurityError::CapabilityDenied(format!(
                        "Dogwood temporal policy prerequisite unsatisfied for action '{}' on resource '{}'",
                        tool_name, target_resource
                    )));
                }
                Err(err) => {
                    // Evaluation error fails closed
                    if let Some(ref audit) = self.audit_log {
                        audit.record_event(
                            "DOGWOOD_TEMPORAL_ERROR",
                            requesting_agent,
                            &format!("Tool: {}, Resource: {}, Error: {}", tool_name, target_resource, err),
                            "FORBID",
                        );
                    }
                    return Err(OctopusSecurityError::CapabilityDenied(format!(
                        "Dogwood temporal evaluation error (failing closed): {}",
                        err
                    )));
                }
            }
        }

        // 6. Joint approval granted: Commit approved action into production temporal history trace
        let mut event_fields = std::collections::HashMap::new();
        if let Some(obj) = verified_context.as_object() {
            for (k, v) in obj {
                event_fields.insert(k.clone(), v.clone());
            }
        }
        self.temporal_engine.record_event(
            &format!("Octopus::Action::\"{}\"", action_name),
            crate::security::cedar_arm::temporal::EventKind::Request,
            requesting_agent,
            target_resource,
            event_fields,
        );

        // 7. Record joint decision in audit trail
        let decision_str = "ALLOW";
        let details = format!(
            "Tool: {}, Resource: {}, Cedar+Dogwood JOINT ALLOW: {:?}",
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

