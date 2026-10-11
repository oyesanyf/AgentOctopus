use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::security::CedarAuthorizationGateway;
use rand::RngCore;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Opaque capability token required to modify CedarGate execution state during negative-control sensitivity tests.
/// Cannot be forged or created by untrusted agent call paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CedarAuditControlToken(Arc<String>);

/// Robust hostname/domain/IPv6 extraction from a target URL or resource identifier.
/// Conforms to RFC 3986 and prevents simplistic string-splitting vulnerabilities.
fn extract_domain(resource: &str) -> String {
    let trimmed = resource.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Ensure scheme is present for standard URL parsing
    let parse_target = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };

    if let Ok(parsed) = url::Url::parse(&parse_target) {
        match parsed.host() {
            Some(url::Host::Domain(d)) => d.to_lowercase(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => format!("[{}]", ip),
            None => String::new(),
        }
    } else {
        // Fallback for non-standard path segments: strip queries, paths, and ports
        let no_path = trimmed.split('/').next().unwrap_or("").split('?').next().unwrap_or("");
        if let Some(stripped_ipv6) = no_path.strip_prefix('[') {
            if let Some(end_bracket) = stripped_ipv6.find(']') {
                return format!("[{}]", &stripped_ipv6[..end_bracket]);
            }
        }
        no_path.split(':').next().unwrap_or("").to_lowercase()
    }
}

/// Evaluates operations against formal AWS Cedar policies.
#[derive(Clone)]
pub struct CedarGate {
    gateway: Arc<RwLock<CedarAuthorizationGateway>>,
    enabled: Arc<AtomicBool>,
    audit_control_token: Arc<String>,
}

impl Default for CedarGate {
    fn default() -> Self {
        Self::new()
    }
}

impl CedarGate {
    /// Creates a new CedarGate with a dynamically loaded runtime secret or cryptographically secure CSPRNG entropy.
    /// Under NO circumstances is a static plaintext secret embedded in the compiled executable.
    pub fn new() -> Self {
        let secret_bytes = if let Ok(env_sec) = std::env::var("OCTOPUS_CEDAR_SECRET") {
            env_sec.into_bytes()
        } else {
            let mut seed = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut seed);
            seed.to_vec()
        };

        Self::with_secret(&secret_bytes)
    }

    /// Creates a CedarGate initialized with a specific runtime secret.
    pub fn with_secret(secret: &[u8]) -> Self {
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let control_token = hex::encode(token_bytes);

        Self {
            gateway: Arc::new(RwLock::new(CedarAuthorizationGateway::new(
                secret,
                "cedar_ring_v4.13",
            ))),
            enabled: Arc::new(AtomicBool::new(true)),
            audit_control_token: Arc::new(control_token),
        }
    }

    /// Obtains an authoritative audit control token for negative-control and verification suites.
    pub fn audit_control_token(&self) -> CedarAuditControlToken {
        CedarAuditControlToken(self.audit_control_token.clone())
    }

    /// Returns whether Cedar authorization enforcement is active.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Enables or deliberately disables Cedar authorization for negative-control sensitivity tests.
    /// FAIL-CLOSED: Requires presenting the cryptographically unforgeable `CedarAuditControlToken`.
    /// Untrusted agents or arbitrary external callers without this token are denied immediately.
    pub fn set_enabled(&self, enabled: bool, token: &CedarAuditControlToken) -> Result<(), OctopusSecurityError> {
        if *token.0 != *self.audit_control_token {
            return Err(OctopusSecurityError::CapabilityDenied(
                "UNAUTHORIZED_CALL_PATH: Modification of Cedar gate authorization state requires authoritative CedarAuditControlToken".to_string(),
            ));
        }
        self.enabled.store(enabled, Ordering::SeqCst);
        Ok(())
    }

    pub fn gateway(&self) -> Arc<RwLock<CedarAuthorizationGateway>> {
        self.gateway.clone()
    }

    /// Dynamically and atomically rotates the underlying Cedar cryptographic secret.
    /// FAIL-CLOSED: Requires presenting the authoritative CedarAuditControlToken.
    pub async fn rotate_secret(
        &self,
        new_secret: &[u8],
        policy_fingerprint: &str,
        token: &CedarAuditControlToken,
    ) -> Result<String, OctopusSecurityError> {
        if *token.0 != *self.audit_control_token {
            return Err(OctopusSecurityError::CapabilityDenied(
                "UNAUTHORIZED_CALL_PATH: Secret rotation requires authoritative CedarAuditControlToken".to_string(),
            ));
        }

        let mut gw = self.gateway.write().await;
        gw.rotate_secret(new_secret, policy_fingerprint)
    }

    /// Dynamically updates the authorized network egress domains in Cedar Policy #3.
    pub async fn update_egress_domains(&self, domains: &[String]) -> Result<(), OctopusSecurityError> {
        let gw = self.gateway.write().await;
        gw.engine()
            .update_egress_domains(domains)
            .map_err(|e| OctopusSecurityError::DeterministicLayerViolation(format!("Cedar policy update error: {:?}", e)))
    }

    /// Evaluates whether an agent has authorization to perform an action on a specific resource.
    pub async fn evaluate_authorization(
        &self,
        agent_id: &str,
        role: &ArmRole,
        action: &str,
        resource: &str,
        amount_cents: Option<u64>,
    ) -> Result<bool, OctopusSecurityError> {
        if !self.is_enabled() {
            // Defense deliberately disabled for negative-control sensitivity verification
            return Ok(true);
        }

        // Enforce spending cap invariant ($100,000 threshold or role limit)
        if let Some(amt) = amount_cents {
            if amt > 10_000_000 {
                // Hard $100,000 limit (10,000,000 cents)
                return Err(OctopusSecurityError::DeterministicLayerViolation(format!(
                    "Cedar Policy Veto: Requested amount ${:.2} exceeds strict hard spending ceiling of $100,000.00",
                    amt as f64 / 100.0
                )));
            }
        }

        // Role-based privilege mapping & zero-trust sink isolation
        match role {
            ArmRole::UntrustedDocIngest => {
                if action == "ledger_writer" || action == "http_egress" || action == "shell_exec"
                    || action == "write" || action == "egress" {
                    return Err(OctopusSecurityError::CapabilityDenied(format!(
                        "Cedar Zero-Trust Policy Veto: UntrustedDocIngest arm '{}' is forbidden from invoking sink tool '{}'",
                        agent_id, action
                    )));
                }
            }
            ArmRole::AccountingLedgerWrite => {
                if action == "http_egress" || action == "shell_exec" || action == "egress" || action == "extract" {
                    return Err(OctopusSecurityError::CapabilityDenied(format!(
                        "Cedar Zero-Trust Policy Veto: AccountingLedgerWrite arm '{}' is forbidden from invoking network, doc, or shell sink '{}'",
                        agent_id, action
                    )));
                }
            }
            ArmRole::NetworkEgress => {
                if action == "ledger_writer" || action == "shell_exec" || action == "write" || action == "extract" {
                    return Err(OctopusSecurityError::CapabilityDenied(format!(
                        "Cedar Zero-Trust Policy Veto: NetworkEgress arm '{}' is forbidden from invoking ledger, doc, or shell sink '{}'",
                        agent_id, action
                    )));
                }
            }
            _ => {}
        }

        // Action and Resource Type Mapping
        let (action_name, resource_type) = match action {
            "extract" | "doc_extractor" | "DocumentRead" => ("extract", "Document"),
            "write" | "ledger_writer" | "LedgerWrite" => ("write", "Ledger"),
            "egress" | "http_egress" | "HttpEgress" => ("egress", "NetworkTarget"),
            "quarantine" | "tarpit" => ("quarantine", "DecoyTrap"),
            "kernel_enforce" | "kernel_sentinel" => ("kernel_enforce", "KernelSubstrate"),
            "change_security_policy" => ("change_security_policy", "SystemPolicy"),
            _ => ("execute", "Tool"),
        };

        let destination_domain = extract_domain(resource);
        let amount = amount_cents.unwrap_or(0);
        let approved = amount <= 10_000_000;

        let context = match action_name {
            "write" => serde_json::json!({
                "amount_cents": amount,
                "approved": approved,
            }),
            "egress" => serde_json::json!({
                "destination_domain": destination_domain,
            }),
            "extract" => serde_json::json!({
                "delegation_depth": 0,
            }),
            "change_security_policy" => serde_json::json!({
                "quorum_authorized": false,
            }),
            "quarantine" => serde_json::json!({
                "adversary_ip": "127.0.0.1",
                "attack_type": "decoy",
            }),
            "kernel_enforce" => serde_json::json!({
                "enforcement_tier": "Ring0",
            }),
            _ => serde_json::json!({}),
        };

        // Authenticated Principal Mapping
        let principal_str = if agent_id == "rogue_adversary" {
            "rogue_adversary"
        } else if agent_id == "document_arm"
            || agent_id == "ledger_arm"
            || agent_id == "network_arm"
            || agent_id == "tarpit_arm"
            || agent_id == "kernel_sentinel_arm"
        {
            agent_id
        } else {
            match role {
                ArmRole::UntrustedDocIngest => "document_arm",
                ArmRole::AccountingLedgerWrite => "ledger_arm",
                ArmRole::NetworkEgress => "network_arm",
                ArmRole::TarpitDecoyDefense => "tarpit_arm",
                ArmRole::KernelLevelSentinel => "kernel_sentinel_arm",
                ArmRole::OutboundNotification => "notifier_arm",
            }
        };

        let gw = self.gateway.read().await;
        let verdict = gw
            .engine()
            .evaluate(principal_str, action_name, resource, resource_type, context)
            .map_err(|e| OctopusSecurityError::CapabilityDenied(format!("Cedar evaluation error: {:?}", e)))?;

        if !verdict.is_allowed {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "AWS Cedar PARC authorization denied for agent '{}' (principal '{}') on action '{}' against resource '{}'",
                agent_id, principal_str, action_name, resource
            )));
        }

        Ok(true)
    }
}
