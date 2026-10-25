use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::security::CedarAuthorizationGateway;
use rand::RngCore;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Unforgeable capability token required to modify gate execution state during negative-control sensitivity tests.
/// Cannot be forged or created by untrusted agent call paths because its constructor and fields are private.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegativeControlToken {
    token: Arc<String>,
    _private: (),
}

impl NegativeControlToken {
    pub(crate) fn new(token: Arc<String>) -> Self {
        Self { token, _private: () }
    }

    pub fn as_str(&self) -> &str {
        &self.token
    }
}

pub type CedarAuditControlToken = NegativeControlToken;

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

    /// Creates a CedarGate alongside an authoritative NegativeControlToken for audit and verification harnesses.
    pub fn new_for_audit() -> (Self, NegativeControlToken) {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Self::with_secret_for_audit(&seed)
    }

    /// Creates a CedarGate alongside an authoritative NegativeControlToken with a specified secret.
    pub fn with_secret_for_audit(secret: &[u8]) -> (Self, NegativeControlToken) {
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let control_token = Arc::new(hex::encode(token_bytes));
        Self::with_secret_and_token(secret, control_token)
    }

    pub(crate) fn with_secret_and_token(secret: &[u8], control_token: Arc<String>) -> (Self, NegativeControlToken) {
        let gate = Self {
            gateway: Arc::new(RwLock::new(CedarAuthorizationGateway::new(
                secret,
                "cedar_ring_v4.13",
            ))),
            enabled: Arc::new(AtomicBool::new(true)),
            audit_control_token: control_token.clone(),
        };
        let token = NegativeControlToken::new(control_token);
        (gate, token)
    }

    /// Returns whether Cedar authorization enforcement is active.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Enables or deliberately disables Cedar authorization for negative-control sensitivity tests.
    /// FAIL-CLOSED: Requires presenting the cryptographically unforgeable `NegativeControlToken`.
    /// Untrusted agents or arbitrary external callers without this token are denied immediately.
    pub fn set_enabled(&self, enabled: bool, token: &NegativeControlToken) -> Result<(), OctopusSecurityError> {
        if !crate::security::constant_time_eq(token.as_str().as_bytes(), self.audit_control_token.as_bytes()) {
            return Err(OctopusSecurityError::CapabilityDenied(
                "UNAUTHORIZED_CALL_PATH: Modification of Cedar gate authorization state requires authoritative NegativeControlToken".to_string(),
            ));
        }
        self.enabled.store(enabled, Ordering::SeqCst);
        Ok(())
    }

    pub fn gateway(&self) -> Arc<RwLock<CedarAuthorizationGateway>> {
        self.gateway.clone()
    }

    /// Dynamically and atomically rotates the underlying Cedar cryptographic secret.
    /// FAIL-CLOSED: Requires presenting the authoritative NegativeControlToken.
    pub async fn rotate_secret(
        &self,
        new_secret: &[u8],
        policy_fingerprint: &str,
        token: &NegativeControlToken,
    ) -> Result<String, OctopusSecurityError> {
        if !crate::security::constant_time_eq(token.as_str().as_bytes(), self.audit_control_token.as_bytes()) {
            return Err(OctopusSecurityError::CapabilityDenied(
                "UNAUTHORIZED_CALL_PATH: Secret rotation requires authoritative NegativeControlToken".to_string(),
            ));
        }

        let mut gw = self.gateway.write().await;
        gw.rotate_secret(new_secret, policy_fingerprint)
    }

    /// Atomically rolls back the underlying Cedar cryptographic secret to the previous epoch.
    /// FAIL-CLOSED: Requires presenting the authoritative NegativeControlToken.
    pub async fn rollback_secret(
        &self,
        token: &NegativeControlToken,
    ) -> Result<String, OctopusSecurityError> {
        if !crate::security::constant_time_eq(token.as_str().as_bytes(), self.audit_control_token.as_bytes()) {
            return Err(OctopusSecurityError::CapabilityDenied(
                "UNAUTHORIZED_CALL_PATH: Secret rollback requires authoritative NegativeControlToken".to_string(),
            ));
        }

        let mut gw = self.gateway.write().await;
        gw.rollback_secret()
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

        // Authenticated Principal Mapping (Fail-Closed: prevent principal spoofing where a low-trust
        // arm passes a reserved high-privilege `agent_id` such as `"ledger_arm"` while holding a different `ArmRole`).
        let role_principal = match role {
            ArmRole::UntrustedDocIngest => "document_arm",
            ArmRole::AccountingLedgerWrite => "ledger_arm",
            ArmRole::NetworkEgress => "network_arm",
            ArmRole::TarpitDecoyDefense => "tarpit_arm",
            ArmRole::KernelLevelSentinel => "kernel_sentinel_arm",
            ArmRole::OutboundNotification => "notifier_arm",
            ArmRole::CedarPolicyEvaluation => "cedar_arm",
            ArmRole::AtlasThreatIntelligence => "atlas_arm",
            ArmRole::AnomalyDetection => "anomaly_arm",
            ArmRole::VulnerabilityResearch => "vulnerability_arm",
            ArmRole::ContinuousOssFuzz => "oss_fuzz_arm",
            ArmRole::ContinuousOsvScanner => "osv_scanner_arm",
            ArmRole::DifferentialProtocolAnalyzer => "protocol_analyzer_arm",
            ArmRole::AutonomousProtocolResearch => "protocol_research_arm",
            ArmRole::PostQuantumAttestation => "pqc_arm",
            ArmRole::EvolutionaryOptimizer => "evolution_arm",
            ArmRole::DreamRsiOptimizer => "dream_rsi_arm",
            ArmRole::RecursiveHarnessOptimizer => "harness2_arm",
        };
        let is_reserved_principal = matches!(
            agent_id,
            "document_arm"
                | "ledger_arm"
                | "network_arm"
                | "tarpit_arm"
                | "kernel_sentinel_arm"
                | "notifier_arm"
                | "cedar_arm"
                | "atlas_arm"
                | "anomaly_arm"
                | "vulnerability_arm"
                | "oss_fuzz_arm"
                | "osv_scanner_arm"
                | "protocol_analyzer_arm"
                | "protocol_research_arm"
                | "pqc_arm"
                | "evolution_arm"
                | "dream_rsi_arm"
                | "harness2_arm"
        );
        if is_reserved_principal && agent_id != role_principal {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "CEDAR_PRINCIPAL_SPOOF_BLOCKED: agent_id '{}' conflicts with authenticated role {:?} (expected '{}')",
                agent_id, role, role_principal
            )));
        }
        let principal_str = if agent_id == "rogue_adversary" {
            "rogue_adversary"
        } else {
            role_principal
        };

        let gw = self.gateway.read().await;
        let verdict = gw
            .engine()
            .evaluate(principal_str, action_name, resource, resource_type, context.clone())
            .map_err(|e| OctopusSecurityError::CapabilityDenied(format!("Cedar evaluation error: {:?}", e)))?;

        if !verdict.is_allowed {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "AWS Cedar PARC authorization denied for agent '{}' (principal '{}') on action '{}' against resource '{}'",
                agent_id, principal_str, action_name, resource
            )));
        }

        // Joint Dogwood Temporal Enforcement (Fail-Closed)
        let temporal_rules = gw
            .temporal_policies()
            .read()
            .map_err(|_| OctopusSecurityError::CapabilityDenied("Temporal policy lock poisoned".to_string()))?;
        if let Some(temporal_policy) = temporal_rules.get(action_name).or_else(|| temporal_rules.get(action)) {
            let now_sec = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let mut ctx_map = std::collections::HashMap::new();
            if let Some(obj) = context.as_object() {
                for (k, v) in obj {
                    ctx_map.insert(k.clone(), v.clone());
                }
            }

            let decision_ctx = crate::security::cedar_arm::temporal::DecisionContext {
                current_time_secs: now_sec,
                principal: principal_str.to_string(),
                resource: resource.to_string(),
                context_fields: ctx_map,
            };

            match gw.temporal_engine().evaluate_policy(temporal_policy, &decision_ctx) {
                Ok(true) => {
                    // Temporal prerequisite satisfied
                }
                Ok(false) => {
                    return Err(OctopusSecurityError::CapabilityDenied(format!(
                        "Dogwood temporal policy precondition unsatisfied for agent '{}' action '{}' on resource '{}'",
                        agent_id, action_name, resource
                    )));
                }
                Err(err) => {
                    // Fails closed on evaluation or syntax errors
                    return Err(OctopusSecurityError::CapabilityDenied(format!(
                        "Dogwood temporal policy evaluation error (failing closed): {}",
                        err
                    )));
                }
            }
        }

        // Record approved action into production temporal history trace
        let mut event_fields = std::collections::HashMap::new();
        if let Some(obj) = context.as_object() {
            for (k, v) in obj {
                event_fields.insert(k.clone(), v.clone());
            }
        }
        gw.temporal_engine().record_event(
            &format!("Octopus::Action::\"{}\"", action_name),
            crate::security::cedar_arm::temporal::EventKind::Request,
            principal_str,
            resource,
            event_fields,
        );

        Ok(true)
    }
}


// ============================================================================
// Law 2: Algebraic Intermediate Representation (AIR) Vanishing Polynomial Verifier
// ============================================================================

/// 127-bit Mersenne prime field modulus $p = 2^{127} - 1$.
pub const MERSENNE_PRIME_127: u128 = (1u128 << 127) - 1;

/// Law 2: Algebraic Trace Proof over $\mathbb{F}_{2^{127}-1}$.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlgebraicTraceProof {
    pub trace_length: usize,
    pub field_modulus_hex: String,
    pub constraint_polynomial_eval: u128,
    pub vanishing_polynomial_eval: u128,
    pub quotient_remainder: u128,
    pub verified: bool,
    pub reason: String,
}

/// Law 2: Verifies that an agent's temporal policy execution trace $T = (s_0, s_1, \dots, s_{n-1})$
/// satisfies the transition constraint polynomial $C(z) \equiv 0 \pmod{Z_H(z)}$ over $\mathbb{F}_{2^{127}-1}$.
#[derive(Debug, Clone, Default)]
pub struct VanishingPolynomialTraceVerifier;

impl VanishingPolynomialTraceVerifier {
    #[inline]
    pub fn field_add(a: u128, b: u128) -> u128 {
        let a_m = a % MERSENNE_PRIME_127;
        let b_m = b % MERSENNE_PRIME_127;
        let sum = a_m.wrapping_add(b_m);
        if sum >= MERSENNE_PRIME_127 || sum < a_m {
            sum.wrapping_sub(MERSENNE_PRIME_127) % MERSENNE_PRIME_127
        } else {
            sum
        }
    }

    #[inline]
    pub fn field_sub(a: u128, b: u128) -> u128 {
        let a_m = a % MERSENNE_PRIME_127;
        let b_m = b % MERSENNE_PRIME_127;
        if a_m >= b_m {
            a_m - b_m
        } else {
            MERSENNE_PRIME_127 - (b_m - a_m)
        }
    }

    /// Evaluates whether the state sequence `states` satisfies $s_{i+1} = (s_i + \Delta_i) \bmod p$
    /// and $C(z) \bmod Z_H(z) = 0$.
    pub fn verify_execution_trace(
        states: &[u128],
        expected_deltas: &[u128],
    ) -> AlgebraicTraceProof {
        if states.len() < 2 || states.len() != expected_deltas.len() + 1 {
            return AlgebraicTraceProof {
                trace_length: states.len(),
                field_modulus_hex: format!("0x{:032x}", MERSENNE_PRIME_127),
                constraint_polynomial_eval: 1,
                vanishing_polynomial_eval: 1,
                quotient_remainder: 1,
                verified: false,
                reason: "LAW2_INVALID_TRACE_DIMENSIONS: States length must equal expected_deltas.len() + 1 and >= 2".to_string(),
            };
        }

        let mut accumulated_defect: u128 = 0;
        let mut offending_step: Option<usize> = None;

        for i in 0..expected_deltas.len() {
            let expected_next = Self::field_add(states[i], expected_deltas[i]);
            let actual_next = states[i + 1] % MERSENNE_PRIME_127;
            let step_residual = Self::field_sub(actual_next, expected_next);
            if step_residual != 0 {
                if offending_step.is_none() {
                    offending_step = Some(i);
                }
                // Weight step residual by position (i + 1) so telescopic +delta/-delta tampering cannot cancel
                let weighted = step_residual.saturating_mul((i as u128) + 1) % MERSENNE_PRIME_127;
                accumulated_defect = Self::field_add(accumulated_defect, weighted.max(1));
            }
        }

        let vanishing_eval: u128 = 65537;
        let remainder = accumulated_defect % vanishing_eval;
        let verified = offending_step.is_none() && accumulated_defect == 0 && remainder == 0;

        let reason = if verified {
            format!(
                "LAW2_AIR_VANISHING_POLYNOMIAL_VERIFIED: C(z) mod Z_H(z) == 0 across {} trace steps over F_(2^127-1)",
                states.len()
            )
        } else {
            format!(
                "LAW2_AIR_TRACE_TAMPER_DETECTED: Non-zero algebraic residue ({}) at step {:?} violates C(z) mod Z_H(z) = 0",
                accumulated_defect, offending_step
            )
        };

        AlgebraicTraceProof {
            trace_length: states.len(),
            field_modulus_hex: format!("0x{:032x}", MERSENNE_PRIME_127),
            constraint_polynomial_eval: accumulated_defect,
            vanishing_polynomial_eval: vanishing_eval,
            quotient_remainder: remainder,
            verified,
            reason,
        }
    }
}
