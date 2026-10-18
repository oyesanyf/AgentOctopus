//! Level 1: Individual Arm Containment Ring
//!
//! An independently enforced security ring surrounding an individual Arm.
//! Managed by the trusted supervisor outside the agent worker processes.
//!
//! Enforces:
//! 1. Identity: Cryptographically bound to its worker, arm_id, and assigned role.
//! 2. Capability set: Strictly scoped tools and resources.
//! 3. Execution sandbox: Memory clamp (64MB), zero child processes, filesystem isolation.
//! 4. Resource budget: CPU, memory, step budget, and execution deadlines.
//! 5. Revocation state: Supervisor can sever/disable one arm without disabling others.
//! 6. Audit identity: Every action attributed to responsible arm, role, generation, and policy.
//! 7. Security Generation Number (Execution Epoch):
//!    When an arm is compromised and severed via autotomy, its generation number (e.g. Gen 8)
//!    is revoked and all capabilities/messages bound to that epoch are invalidated.
//!    Regenerated arm starts at Gen 9; stale messages or tokens from Gen 8 are rejected.

use crate::containment_ring::cedar_gate::NegativeControlToken;
use crate::containment_ring::isolation_manager::SandboxConstraints;
use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::neural_mesh::MessageKind;
use crate::security::CapabilityToken;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Configuration for an individual arm containment ring.
#[derive(Debug, Clone)]
pub struct ArmRingConfig {
    pub max_memory_bytes: usize,
    pub step_limit: usize,
    pub max_execution_time: Duration,
    pub sandbox_constraints: SandboxConstraints,
}

impl Default for ArmRingConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024, // Strict 64 MB clamp
            step_limit: 10,
            max_execution_time: Duration::from_secs(5),
            sandbox_constraints: SandboxConstraints::default(),
        }
    }
}

/// Strongly typed, epoch-tagged inter-arm neural mesh message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmRingMeshMessage {
    pub sender_arm_id: usize,
    pub sender_role: ArmRole,
    pub sender_generation: u64,
    pub target_arm_id: usize,
    pub target_generation: u64,
    pub kind: MessageKind,
    pub correlation_id: String,
    pub payload: String,
    pub signature_hex: String,
}

/// Telemetry and state DTO representing an arm containment ring for UI/API monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmRingStatusDto {
    pub arm_id: usize,
    pub agent_name: String,
    pub role: String,
    pub generation: u64,
    pub is_severed: bool,
    pub memory_limit_mb: usize,
    pub step_limit: usize,
    pub allowed_tools: Vec<String>,
    pub allowed_resource_prefixes: Vec<String>,
    pub os_isolation: String,
    pub job_object_clamped: bool,
    pub appcontainer_sid: String,
}

/// Compute HMAC-SHA256 for Level 1 ring epoch verification.
fn compute_ring_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hash = Sha256::digest(key);
        k[..32].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let outer_hash = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer_hash);
    out
}

/// Canonicalizes and enforces exact, resource-type-aware boundaries for arm resources.
/// Strictly rejects ambiguous paths, directory traversals, encoded separators, and prefix collisions.
pub fn validate_resource_boundary(
    resource: &str,
    allowed_prefixes: &[String],
) -> Result<(), OctopusSecurityError> {
    let trimmed = resource.trim();
    if trimmed.is_empty() {
        return Err(OctopusSecurityError::EnclaveViolation(
            "Empty or whitespace-only resource identifier rejected".to_string(),
        ));
    }

    // 1. Control character / null byte rejection
    if trimmed.chars().any(|c| (c as u32) < 0x20 || (c as u32) == 0x7f) {
        return Err(OctopusSecurityError::EnclaveViolation(
            "Resource contains illegal ASCII control characters or null bytes".to_string(),
        ));
    }

    // 2. Reject ambiguous encodings and traversal tokens
    let lower = trimmed.to_lowercase();
    if lower.contains("%00") || lower.contains("%2e%2e") || lower.contains("%2f") || lower.contains("%5c") || lower.contains("%25") {
        return Err(OctopusSecurityError::EnclaveViolation(
            "Ambiguous or malicious percent-encoding detected in resource identifier".to_string(),
        ));
    }

    // Reject directory traversal sequences
    if lower.contains("..") {
        return Err(OctopusSecurityError::EnclaveViolation(
            "Path traversal sequence '..' detected in resource identifier".to_string(),
        ));
    }

    // Reject backslashes in URI-style resources (e.g. s3://..., http://...)
    if trimmed.contains("://") && trimmed.contains('\\') {
        return Err(OctopusSecurityError::EnclaveViolation(
            "Ambiguous separator '\\' detected in URI resource identifier".to_string(),
        ));
    }

    // 3. For HTTP/HTTPS URLs, validate structure and parse authority
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let parsed = url::Url::parse(trimmed).map_err(|e| {
            OctopusSecurityError::EnclaveViolation(format!(
                "Malformed HTTP/HTTPS URL resource '{}': {}",
                trimmed, e
            ))
        })?;

        // Prohibit embedded credentials
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(OctopusSecurityError::EnclaveViolation(
                "Resource URL contains embedded credentials (user:pass@host)".to_string(),
            ));
        }

        // Canonicalize host
        let host_str = match parsed.host() {
            Some(url::Host::Domain(d)) => d.to_lowercase(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => format!("[{}]", ip),
            None => {
                return Err(OctopusSecurityError::EnclaveViolation(
                    "Resource URL is missing valid host".to_string(),
                ));
            }
        };

        // Reject non-standard octal/hex IP evasion
        if host_str.chars().all(|c| c.is_ascii_digit()) && !host_str.contains('.') {
            return Err(OctopusSecurityError::EnclaveViolation(
                "Dword/integer-encoded IP address format rejected in resource".to_string(),
            ));
        }
    }

    // 4. Strict resource-type-aware prefix matching
    // Never allow substring containment (resource.contains(p))
    let mut matched = false;
    for prefix in allowed_prefixes {
        let p = prefix.trim();
        if p.is_empty() {
            continue;
        }

        // Exact match
        if trimmed == p {
            matched = true;
            break;
        }

        // Scheme prefix: e.g. "kernel://", "stix://", "protocol://", "tarpit://"
        if p.ends_with("://") {
            if trimmed.starts_with(p) {
                matched = true;
                break;
            }
            continue;
        }

        // Path-terminated prefix: e.g. "s3://invoices/", "https://raw.githubusercontent.com/mitre-atlas/"
        if p.ends_with('/') {
            if trimmed.starts_with(p) {
                matched = true;
                break;
            }
            continue;
        }

        // URI host prefix without trailing slash: e.g. "http://127.0.0.1", "http://localhost", "http://[::1]"
        if p.starts_with("http://") || p.starts_with("https://") {
            if trimmed.starts_with(p) {
                // Must be followed by a path separator ('/'), port separator (':'), or query/fragment
                let remainder = &trimmed[p.len()..];
                if remainder.is_empty() || remainder.starts_with('/') || remainder.starts_with(':') || remainder.starts_with('?') || remainder.starts_with('#') {
                    // Check if port separator, ensure port doesn't have suffix collision
                    if let Some(port_rest) = remainder.strip_prefix(':') {
                        let port_digits: String = port_rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                        if !port_digits.is_empty() {
                            let after_port = &port_rest[port_digits.len()..];
                            if after_port.is_empty() || after_port.starts_with('/') || after_port.starts_with('?') || after_port.starts_with('#') {
                                matched = true;
                                break;
                            }
                        }
                    } else {
                        matched = true;
                        break;
                    }
                }
            }
            continue;
        }

        // Token or local resource identifier: e.g. "local_scratchpad"
        if trimmed.starts_with(p) {
            let remainder = &trimmed[p.len()..];
            if remainder.is_empty() || remainder.starts_with('/') || remainder.starts_with(':') {
                matched = true;
                break;
            }
        }
    }

    if !matched {
        return Err(OctopusSecurityError::EnclaveViolation(format!(
            "Resource '{}' violates containment boundaries (not within permitted namespaces)",
            resource
        )));
    }

    Ok(())
}

/// Level 1: An individual Arm Containment Ring.
/// Operates as an independent security perimeter around a single arm worker.
#[derive(Clone)]
pub struct ArmContainmentRing {
    pub arm_id: usize,
    pub agent_name: String,
    pub role: ArmRole,
    pub generation: Arc<AtomicU64>,
    master_seed: [u8; 32],
    allowed_tools: Arc<RwLock<HashSet<String>>>,
    allowed_resource_prefixes: Arc<RwLock<Vec<String>>>,
    is_severed: Arc<AtomicBool>,
    revoked_epochs: Arc<RwLock<HashSet<u64>>>,
    step_counter: Arc<AtomicU64>,
    pub config: ArmRingConfig,

    // Sensitivity switches for negative-control testing
    epoch_enforcement_enabled: Arc<AtomicBool>,
    tool_enforcement_enabled: Arc<AtomicBool>,
    budget_enforcement_enabled: Arc<AtomicBool>,
    audit_control_token: Arc<String>,
    pub(crate) quarantined_instances: Arc<RwLock<HashMap<String, Arc<crate::security::windows_sandbox::QuarantinedProcessInstance>>>>,
}

impl ArmContainmentRing {
    /// Creates a new individual arm containment ring at a specified starting generation.
    pub fn new(
        arm_id: usize,
        role: ArmRole,
        initial_generation: u64,
        master_seed: &[u8],
    ) -> Self {
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let control_token = Arc::new(hex::encode(token_bytes));
        Self::with_audit_token(arm_id, role, initial_generation, master_seed, control_token)
    }

    pub(crate) fn with_audit_token(
        arm_id: usize,
        role: ArmRole,
        initial_generation: u64,
        master_seed: &[u8],
        audit_token: Arc<String>,
    ) -> Self {
        let mut seed = [0u8; 32];
        if master_seed.len() >= 32 {
            seed.copy_from_slice(&master_seed[..32]);
        } else {
            let hash = Sha256::digest(master_seed);
            seed.copy_from_slice(&hash);
        }

        let agent_name = format!("arm-{:?}-{}", role, arm_id);

        // Define default allowed tools and resources strictly scoped to this arm's assigned role
        let mut tools = HashSet::new();
        let mut prefixes = Vec::new();

        match role {
            ArmRole::UntrustedDocIngest => {
                tools.insert("doc_extractor".to_string());
                tools.insert("peripheral_digest".to_string());
                prefixes.push("s3://invoices/".to_string());
                prefixes.push("s3://raw-docs/".to_string());
                prefixes.push("local_scratchpad".to_string());
            }
            ArmRole::AccountingLedgerWrite => {
                tools.insert("ledger_writer".to_string());
                prefixes.push("s3://accounting/".to_string());
                prefixes.push("local_scratchpad".to_string());
            }
            ArmRole::NetworkEgress => {
                tools.insert("http_egress".to_string());
                prefixes.push("https://".to_string());
                prefixes.push("http://".to_string());
            }
            ArmRole::OutboundNotification => {
                tools.insert("notifier".to_string());
                prefixes.push("notification://".to_string());
            }
            ArmRole::TarpitDecoyDefense => {
                tools.insert("quarantine".to_string());
                prefixes.push("tarpit://".to_string());
            }
            ArmRole::KernelLevelSentinel => {
                tools.insert("kernel_sentinel".to_string());
                prefixes.push("kernel://".to_string());
            }
            ArmRole::CedarPolicyEvaluation => {
                tools.insert("cedar_evaluator".to_string());
                tools.insert("policy_compiler".to_string());
                prefixes.push("cedar://".to_string());
                prefixes.push("policy://".to_string());
            }
            ArmRole::AtlasThreatIntelligence => {
                tools.insert("atlas_sync".to_string());
                tools.insert("stix_parser".to_string());
                tools.insert("threat_matrix".to_string());
                prefixes.push("https://raw.githubusercontent.com/mitre-atlas/".to_string());
                prefixes.push("stix://".to_string());
                prefixes.push("atlas://".to_string());
            }
            ArmRole::AnomalyDetection => {
                tools.insert("behavioral_sentinel".to_string());
                tools.insert("entropy_calc".to_string());
                tools.insert("drift_auditor".to_string());
                prefixes.push("telemetry://".to_string());
                prefixes.push("behavior://".to_string());
            }
            ArmRole::VulnerabilityResearch => {
                tools.insert("vulnerability_scanner".to_string());
                tools.insert("attack_chain".to_string());
                tools.insert("risk_scorer".to_string());
                prefixes.push("vuln://".to_string());
                prefixes.push("cve://".to_string());
            }
            ArmRole::ContinuousOssFuzz => {
                tools.insert("fuzz_mutator".to_string());
                tools.insert("corpus_manager".to_string());
                tools.insert("crash_monitor".to_string());
                prefixes.push("fuzz://".to_string());
                prefixes.push("corpus://".to_string());
            }
            ArmRole::ContinuousOsvScanner => {
                tools.insert("osv_client".to_string());
                tools.insert("dep_advisor".to_string());
                tools.insert("advisory_db".to_string());
                prefixes.push("https://api.osv.dev/".to_string());
                prefixes.push("osv://".to_string());
                prefixes.push("advisories://".to_string());
            }
            ArmRole::DifferentialProtocolAnalyzer => {
                tools.insert("protocol_analyzer".to_string());
                tools.insert("fuzz_divergence".to_string());
                prefixes.push("protocol://".to_string());
                prefixes.push("differential://".to_string());
            }
            ArmRole::AutonomousProtocolResearch => {
                tools.insert("protocol_research".to_string());
                tools.insert("rfc_intelligence".to_string());
                tools.insert("generate_probes".to_string());
                tools.insert("isolated_evaluator".to_string());
                tools.insert("discovery_cascade".to_string());
                prefixes.push("protocol://".to_string());
                prefixes.push("terminator://".to_string());
                prefixes.push("http://127.0.0.1".to_string());
                prefixes.push("http://localhost".to_string());
                prefixes.push("http://[::1]".to_string());
            }
            ArmRole::PostQuantumAttestation => {
                tools.insert("pqc_attestation".to_string());
                tools.insert("pqc_kem_encapsulate".to_string());
                tools.insert("pqc_kem_decapsulate".to_string());
                tools.insert("pqc_dsa_sign".to_string());
                tools.insert("pqc_dsa_verify".to_string());
                tools.insert("pqc_cbom_scanner".to_string());
                prefixes.push("pqc://".to_string());
                prefixes.push("quantum://".to_string());
                prefixes.push("kem://".to_string());
                prefixes.push("dsa://".to_string());
                prefixes.push("cbom://".to_string());
            }
            ArmRole::EvolutionaryOptimizer => {
                tools.insert("evolutionary_optimizer".to_string());
                tools.insert("openevolve_run".to_string());
                tools.insert("openevolve_evaluate".to_string());
                tools.insert("openevolve_stage_candidate".to_string());
                tools.insert("openevolve_audit_invariant".to_string());
                tools.insert("openevolve_promote".to_string());
                prefixes.push("evolution://".to_string());
                prefixes.push("openevolve://".to_string());
                prefixes.push("candidate://".to_string());
                prefixes.push("staging://".to_string());
            }
            ArmRole::DreamRsiOptimizer => {
                tools.insert("dream_rsi_optimizer".to_string());
                tools.insert("dream_rsi_replay".to_string());
                tools.insert("dream_rsi_train_world_model".to_string());
                tools.insert("dream_rsi_policy_rollout".to_string());
                tools.insert("dream_rsi_recommend_priorities".to_string());
                tools.insert("dream_rsi_ingest_trajectories".to_string());
                prefixes.push("dream_rsi://".to_string());
                prefixes.push("replay://".to_string());
                prefixes.push("world_model://".to_string());
                prefixes.push("policy://".to_string());
            }
            ArmRole::RecursiveHarnessOptimizer => {
                tools.insert("harness2_optimizer".to_string());
                tools.insert("harness2_propose_probe_compose".to_string());
                tools.insert("harness2_validate_tree".to_string());
                tools.insert("harness2_experience_library".to_string());
                prefixes.push("harness2://".to_string());
                prefixes.push("library://".to_string());
                prefixes.push("context://".to_string());
            }
        }

        Self {
            arm_id,
            agent_name,
            role,
            generation: Arc::new(AtomicU64::new(initial_generation)),
            master_seed: seed,
            allowed_tools: Arc::new(RwLock::new(tools)),
            allowed_resource_prefixes: Arc::new(RwLock::new(prefixes)),
            is_severed: Arc::new(AtomicBool::new(false)),
            revoked_epochs: Arc::new(RwLock::new(HashSet::new())),
            step_counter: Arc::new(AtomicU64::new(0)),
            config: ArmRingConfig::default(),
            epoch_enforcement_enabled: Arc::new(AtomicBool::new(true)),
            tool_enforcement_enabled: Arc::new(AtomicBool::new(true)),
            budget_enforcement_enabled: Arc::new(AtomicBool::new(true)),
            audit_control_token: audit_token,
            quarantined_instances: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates an arm containment ring alongside an authoritative NegativeControlToken for audit harnesses.
    pub fn new_for_audit(
        arm_id: usize,
        role: ArmRole,
        initial_generation: u64,
        master_seed: &[u8],
    ) -> (Self, NegativeControlToken) {
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let control_token = Arc::new(hex::encode(token_bytes));
        let ring = Self::with_audit_token(arm_id, role, initial_generation, master_seed, control_token.clone());
        let token = NegativeControlToken::new(control_token);
        (ring, token)
    }

    /// Returns the 32-byte master seed bound to this containment ring.
    pub fn master_seed(&self) -> &[u8; 32] {
        &self.master_seed
    }

    /// Derives an epoch-specific cryptographic secret key for any arm sharing this master seed.
    fn derive_arm_epoch_key(&self, arm_id: usize, epoch: u64, role: &ArmRole) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.master_seed);
        hasher.update(arm_id.to_le_bytes());
        hasher.update(epoch.to_le_bytes());
        hasher.update(format!("{:?}", role).as_bytes());
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        key
    }

    /// Derives an epoch-specific cryptographic secret key for this arm.
    fn epoch_key(&self, epoch: u64) -> [u8; 32] {
        self.derive_arm_epoch_key(self.arm_id, epoch, &self.role)
    }

    /// Returns the current active generation epoch for this arm.
    pub fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Returns whether this individual arm ring has been severed.
    pub fn is_severed(&self) -> bool {
        self.is_severed.load(Ordering::SeqCst)
    }

    /// Non-cooperatively severs this arm without affecting any other arm in the swarm.
    pub async fn sever(&self, _reason: &str) {
        let current_gen = self.current_generation();
        self.is_severed.store(true, Ordering::SeqCst);
        let mut revoked = self.revoked_epochs.write().await;
        revoked.insert(current_gen);

        // Terminate and clean up all active quarantined worker processes
        let mut instances = self.quarantined_instances.write().await;
        for (_, inst) in instances.drain() {
            let _ = inst.terminate(1);
        }
    }

    /// Autotomy regeneration: Revokes the current generation epoch, advances to Gen N+1,
    /// and resets the execution counter for the newly regenerated arm.
    /// Returns the new generation epoch.
    pub async fn sever_and_regenerate(&self) -> u64 {
        let old_gen = self.current_generation();
        {
            let mut revoked = self.revoked_epochs.write().await;
            revoked.insert(old_gen);
        }
        let next_gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        self.step_counter.store(0, Ordering::SeqCst);
        self.is_severed.store(false, Ordering::SeqCst);

        // Terminate any stale quarantined instances before regeneration
        let mut instances = self.quarantined_instances.write().await;
        for (_, inst) in instances.drain() {
            let _ = inst.terminate(1);
        }

        next_gen
    }

    /// Validates that an operation, token, or message carries the active generation epoch.
    /// Stale epochs from severed incarnations are strictly rejected!
    pub async fn validate_epoch(&self, epoch: u64) -> Result<(), OctopusSecurityError> {
        if !self.epoch_enforcement_enabled.load(Ordering::SeqCst) {
            return Ok(());
        }

        if self.is_severed.load(Ordering::SeqCst) {
            return Err(OctopusSecurityError::LimbKilled);
        }

        let revoked = self.revoked_epochs.read().await;
        if revoked.contains(&epoch) {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Arm {} generation epoch {} has been permanently revoked by supervisor autotomy",
                self.arm_id, epoch
            )));
        }

        let active_gen = self.current_generation();
        if epoch != active_gen {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Arm {} epoch mismatch: presented generation {} != active generation {}",
                self.arm_id, epoch, active_gen
            )));
        }

        Ok(())
    }

    /// Validates that a requested tool invocation complies with this arm ring's capability scope.
    pub async fn validate_tool_invocation(
        &self,
        tool: &str,
        resource: &str,
        epoch: u64,
    ) -> Result<(), OctopusSecurityError> {
        self.validate_epoch(epoch).await?;

        if !self.tool_enforcement_enabled.load(Ordering::SeqCst) {
            return Ok(());
        }

        let tools = self.allowed_tools.read().await;
        if !tools.contains(tool) {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Arm {} (role {:?}) attempted unauthorized tool '{}'",
                self.arm_id, self.role, tool
            )));
        }

        let prefixes = self.allowed_resource_prefixes.read().await;
        validate_resource_boundary(resource, &prefixes).map_err(|e| {
            OctopusSecurityError::EnclaveViolation(format!(
                "Arm {} (role {:?}) attempted out-of-scope resource access: '{}' ({})",
                self.arm_id, self.role, resource, e
            ))
        })?;

        Ok(())
    }

    /// Validates execution step budget under the individual arm ring.
    pub fn check_step_budget(&self, step: usize) -> Result<(), OctopusSecurityError> {
        if !self.budget_enforcement_enabled.load(Ordering::SeqCst) {
            return Ok(());
        }

        if step > self.config.step_limit {
            return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
                "Arm {} exceeded maximum step budget (step {} > limit {})",
                self.arm_id, step, self.config.step_limit
            )));
        }
        self.step_counter.store(step as u64, Ordering::SeqCst);
        Ok(())
    }

    /// Validates memory clamp (64MB) under the individual arm ring.
    pub fn check_memory_budget(&self, memory_bytes: usize) -> Result<(), OctopusSecurityError> {
        if !self.budget_enforcement_enabled.load(Ordering::SeqCst) {
            return Ok(());
        }

        if memory_bytes > self.config.max_memory_bytes {
            return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
                "Arm {} exceeded strict 64MB memory clamp ({} bytes > clamp {} bytes)",
                self.arm_id, memory_bytes, self.config.max_memory_bytes
            )));
        }
        Ok(())
    }

    /// Issues an epoch-bound cryptographic capability token for this arm ring.
    pub async fn issue_epoch_capability(
        &self,
        tool: &str,
        resource: &str,
    ) -> Result<CapabilityToken, OctopusSecurityError> {
        let current_gen = self.current_generation();
        self.validate_tool_invocation(tool, resource, current_gen).await?;

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires_at_secs = now_secs + 300; // 5-minute capability

        let epoch_key = self.epoch_key(current_gen);
        let token_id = format!("ARM-CAP-{}-{}-{}", self.arm_id, current_gen, tool);
        let policy_fingerprint = format!(
            "arm_ring:epoch={}:arm={}:role={:?}:tool={}",
            current_gen, self.arm_id, self.role, tool
        );
        let originator = "supervisor";
        let signing_content = format!(
            "{}:{}:{}:{:?}:{}:{}:{}:{}:{}",
            token_id,
            originator,
            self.agent_name,
            self.role,
            tool,
            resource,
            now_secs,
            expires_at_secs,
            policy_fingerprint
        );

        let sig = compute_ring_hmac(&epoch_key, signing_content.as_bytes());
        let sig_hex = hex::encode(sig);

        Ok(CapabilityToken {
            token_id,
            originator_agent: "supervisor".to_string(),
            bearer_agent: self.agent_name.clone(),
            permitted_role: self.role.clone(),
            permitted_tool: tool.to_string(),
            resource_uri_prefix: resource.to_string(),
            issued_at_secs: now_secs,
            expires_at_secs,
            policy_fingerprint,
            signature_hex: sig_hex,
        })
    }

    /// Verifies that a presented capability token is bound to this arm's active generation epoch.
    pub async fn verify_epoch_capability(
        &self,
        token: &CapabilityToken,
    ) -> Result<(), OctopusSecurityError> {
        let current_gen = self.current_generation();
        self.validate_epoch(current_gen).await?;

        // Extract epoch from policy fingerprint
        let prefix = format!("arm_ring:epoch={}:arm={}:", current_gen, self.arm_id);
        if !token.policy_fingerprint.starts_with(&prefix) {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Capability token policy fingerprint mismatch: token was not issued for arm {} generation {}",
                self.arm_id, current_gen
            )));
        }

        // Verify cryptographic signature against epoch key
        let epoch_key = self.epoch_key(current_gen);
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

        let expected_sig = compute_ring_hmac(&epoch_key, signing_content.as_bytes());
        let expected_hex = hex::encode(expected_sig);

        if !crate::security::constant_time_eq_hex(&token.signature_hex, &expected_hex) {
            return Err(OctopusSecurityError::CapabilityDenied(
                "Invalid capability token signature for active epoch".to_string(),
            ));
        }

        Ok(())
    }

    /// Signs an outbound Neural Mesh message tagged with sender and target generation epochs.
    pub async fn sign_mesh_message(
        &self,
        target_arm_id: usize,
        target_generation: u64,
        kind: MessageKind,
        correlation_id: &str,
        payload: &str,
    ) -> Result<ArmRingMeshMessage, OctopusSecurityError> {
        let current_gen = self.current_generation();
        self.validate_epoch(current_gen).await?;

        let epoch_key = self.epoch_key(current_gen);
        let data = format!(
            "{}:{}:{}:{}:{:?}:{}:{}",
            self.arm_id, current_gen, target_arm_id, target_generation, kind, correlation_id, payload
        );
        let sig = compute_ring_hmac(&epoch_key, data.as_bytes());
        let sig_hex = hex::encode(sig);

        Ok(ArmRingMeshMessage {
            sender_arm_id: self.arm_id,
            sender_role: self.role.clone(),
            sender_generation: current_gen,
            target_arm_id,
            target_generation,
            kind,
            correlation_id: correlation_id.to_string(),
            payload: payload.to_string(),
            signature_hex: sig_hex,
        })
    }

    /// Verifies an incoming Neural Mesh message at the recipient's Level 1 arm ring.
    /// Verifies target arm ID, recipient active epoch, sender cryptographic HMAC signature,
    /// and Level 2 lateral sink isolation.
    pub async fn verify_incoming_message(
        &self,
        msg: &ArmRingMeshMessage,
    ) -> Result<(), OctopusSecurityError> {
        if msg.target_arm_id != self.arm_id {
            return Err(OctopusSecurityError::IdentitySpoofingDetected(format!(
                "Message misrouted: target_arm_id {} != receiver arm_id {}",
                msg.target_arm_id, self.arm_id
            )));
        }

        if msg.sender_generation == 0 {
            return Err(OctopusSecurityError::IdentitySpoofingDetected(
                "Invalid sender generation epoch 0 in incoming mesh message".to_string(),
            ));
        }

        // Validate recipient epoch: will reject if msg.target_generation is revoked or obsolete
        self.validate_epoch(msg.target_generation).await?;

        // Verify cryptographic HMAC-SHA256 signature bound to sender_arm_id, sender_generation, and sender_role
        let sender_epoch_key = self.derive_arm_epoch_key(
            msg.sender_arm_id,
            msg.sender_generation,
            &msg.sender_role,
        );
        let expected_data = format!(
            "{}:{}:{}:{}:{:?}:{}:{}",
            msg.sender_arm_id,
            msg.sender_generation,
            msg.target_arm_id,
            msg.target_generation,
            msg.kind,
            msg.correlation_id,
            msg.payload
        );
        let expected_sig = hex::encode(compute_ring_hmac(&sender_epoch_key, expected_data.as_bytes()));
        if !crate::security::constant_time_eq_hex(&msg.signature_hex, &expected_sig) {
            return Err(OctopusSecurityError::IdentitySpoofingDetected(format!(
                "Cryptographic mesh signature mismatch from sender arm {} ({:?}, gen {}): payload tampering or role spoofing detected",
                msg.sender_arm_id, msg.sender_role, msg.sender_generation
            )));
        }

        // Level 2 lateral boundary: Untrusted, fuzzing, and quarantine arms cannot message Ledger directly
        let is_untrusted_or_quarantine_sender = matches!(
            msg.sender_role,
            ArmRole::UntrustedDocIngest
                | ArmRole::DifferentialProtocolAnalyzer
                | ArmRole::AutonomousProtocolResearch
                | ArmRole::ContinuousOssFuzz
                | ArmRole::TarpitDecoyDefense
        );
        if self.role == ArmRole::AccountingLedgerWrite && is_untrusted_or_quarantine_sender {
            return Err(OctopusSecurityError::DelegationScopeViolation(format!(
                "Ring Boundary Violation: Arm {} ({:?}) is forbidden from direct lateral messaging to Sensitive Sink Arm {}",
                msg.sender_arm_id, msg.sender_role, self.arm_id
            )));
        }

        Ok(())
    }

    /// Executes an authoritative Level 1 containment ring quarantine operation on an arm.
    /// Validates active epoch, tool permissions, step budget, and 64MB memory clamp,
    /// launches the quarantined worker inside a Windows Job Object and AppContainer boundary,
    /// verifies kernel containment before execution, and outputs an HMAC containment proof.
    pub async fn execute_quarantine_containment(
        &self,
        report_id: &str,
        payload_sha256: &str,
        payload_len: usize,
        novelty_score: f64,
    ) -> Result<(String, String, String, usize, u32), OctopusSecurityError> {
        let current_gen = self.current_generation();
        self.validate_epoch(current_gen).await?;
        self.validate_tool_invocation("protocol_analyzer", "protocol://differential-quarantine", current_gen).await?;
        self.check_step_budget(1)?;
        self.check_memory_budget(payload_len)?;

        // Apply OS Isolation: Create Windows Job Object with strict 64MB clamp & 1 active process limit
        let job_name = format!("QuarantineJob_Arm{}_{}_{}", self.arm_id, report_id, rand::random::<u32>());
        let job = Arc::new(crate::security::windows_sandbox::WindowsJobObject::create(
            &job_name,
            1,
            self.config.max_memory_bytes,
        )?);

        // Resolve quarantined worker binary: strictly fail-closed if missing (zero fallback)
        let mut worker_path = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("octopus-worker.exe"));
        if worker_path.is_absolute() {
            worker_path.pop();
            if worker_path.file_name().and_then(|n| n.to_str()) == Some("deps") {
                worker_path.pop();
            }
            worker_path.push("octopus-worker.exe");
        }
        if !worker_path.exists() {
            let cwd_worker = std::path::PathBuf::from("octopus-worker.exe");
            if cwd_worker.exists() {
                worker_path = cwd_worker;
            } else {
                let release_worker = std::path::PathBuf::from("target/release/octopus-worker.exe");
                if release_worker.exists() {
                    worker_path = release_worker;
                }
            }
        }

        if !worker_path.exists() {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: Quarantined worker binary does not exist at '{}'. Fallback execution strictly forbidden.",
                worker_path.display()
            )));
        }

        // Spawn suspended in genuine AppContainer and assign to Job Object before resuming
        let quarantined_proc = crate::security::windows_sandbox::spawn_quarantined_worker_in_job_and_appcontainer(
            &worker_path,
            self.arm_id as u64,
            report_id,
            "doc_ingest",
            &job,
        )?;

        let pid = quarantined_proc.pid;
        let ac_sid = quarantined_proc.package_sid.clone();

        // Supervisor owns the active quarantined instance (retains handle, NO std::mem::forget)
        {
            let mut instances = self.quarantined_instances.write().await;
            instances.insert(report_id.to_string(), Arc::new(quarantined_proc));
        }

        let epoch_key = self.epoch_key(current_gen);
        let signing_content = format!(
            "RING1_QUARANTINE:{}:{}:{}:{:.4}",
            report_id, payload_sha256, current_gen, novelty_score
        );
        let sig = compute_ring_hmac(&epoch_key, signing_content.as_bytes());
        Ok((hex::encode(sig), job_name, ac_sid, self.config.max_memory_bytes, pid))
    }

    /// Returns the number of active quarantined processes held by this ring.
    pub async fn active_quarantines_count(&self) -> usize {
        let instances = self.quarantined_instances.read().await;
        instances.len()
    }

    /// Explicitly terminates a quarantined worker instance by its report ID.
    pub async fn terminate_quarantined_instance(&self, report_id: &str) -> Result<(), OctopusSecurityError> {
        let mut instances = self.quarantined_instances.write().await;
        if let Some(inst) = instances.remove(report_id) {
            inst.terminate(0)?;
            Ok(())
        } else {
            Err(OctopusSecurityError::IsolationViolation(format!(
                "No active quarantined instance found for report ID '{}'",
                report_id
            )))
        }
    }

    /// Retrieves an active quarantined process instance by its report ID.
    pub async fn get_quarantined_instance(&self, report_id: &str) -> Option<Arc<crate::security::windows_sandbox::QuarantinedProcessInstance>> {
        let instances = self.quarantined_instances.read().await;
        instances.get(report_id).cloned()
    }

    // Negative-control test hook methods
    pub fn set_epoch_enforcement(&self, enabled: bool, token: &NegativeControlToken) -> Result<(), OctopusSecurityError> {
        if token.as_str() != self.audit_control_token.as_str() {
            return Err(OctopusSecurityError::CapabilityDenied(
                "UNAUTHORIZED_CALL_PATH: Modification of arm epoch enforcement state requires authoritative NegativeControlToken".to_string(),
            ));
        }
        self.epoch_enforcement_enabled.store(enabled, Ordering::SeqCst);
        Ok(())
    }

    pub fn set_tool_enforcement(&self, enabled: bool, token: &NegativeControlToken) -> Result<(), OctopusSecurityError> {
        if token.as_str() != self.audit_control_token.as_str() {
            return Err(OctopusSecurityError::CapabilityDenied(
                "UNAUTHORIZED_CALL_PATH: Modification of arm tool enforcement state requires authoritative NegativeControlToken".to_string(),
            ));
        }
        self.tool_enforcement_enabled.store(enabled, Ordering::SeqCst);
        Ok(())
    }

    pub fn set_budget_enforcement(&self, enabled: bool, token: &NegativeControlToken) -> Result<(), OctopusSecurityError> {
        if token.as_str() != self.audit_control_token.as_str() {
            return Err(OctopusSecurityError::CapabilityDenied(
                "UNAUTHORIZED_CALL_PATH: Modification of arm budget enforcement state requires authoritative NegativeControlToken".to_string(),
            ));
        }
        self.budget_enforcement_enabled.store(enabled, Ordering::SeqCst);
        Ok(())
    }

    /// Converts this arm containment ring's live configuration and telemetry to a DTO for monitoring.
    pub async fn to_status_dto(&self) -> ArmRingStatusDto {
        let tools: Vec<String> = self.allowed_tools.read().await.iter().cloned().collect();
        let prefixes: Vec<String> = self.allowed_resource_prefixes.read().await.clone();

        let instances = self.quarantined_instances.read().await;
        let (os_isolation, job_object_clamped, appcontainer_sid) = if let Some(inst) = instances.values().next() {
            let is_active = !inst.job.is_terminated.load(Ordering::SeqCst);
            let desc = if instances.len() == 1 {
                format!("Windows NT Job Object (64MB) + AppContainer [{}] PID: {}", inst.package_sid, inst.pid)
            } else {
                let pids: Vec<String> = instances.values().map(|i| i.pid.to_string()).collect();
                format!("Windows NT Job Object (64MB) + AppContainer [{}] PIDs: {}", inst.package_sid, pids.join(","))
            };
            (desc, is_active, inst.package_sid.clone())
        } else {
            (
                if self.is_severed() {
                    "Severed (Unattached)".to_string()
                } else {
                    "Standby (Pre-allocated Ring Boundary)".to_string()
                },
                false,
                "None (No Active OS Process)".to_string(),
            )
        };

        ArmRingStatusDto {
            arm_id: self.arm_id,
            agent_name: self.agent_name.clone(),
            role: format!("{:?}", self.role),
            generation: self.current_generation(),
            is_severed: self.is_severed(),
            memory_limit_mb: self.config.max_memory_bytes / (1024 * 1024),
            step_limit: self.config.step_limit,
            allowed_tools: tools,
            allowed_resource_prefixes: prefixes,
            os_isolation,
            job_object_clamped,
            appcontainer_sid,
        }
    }
}

/// A supervisor-managed registry containing the Level 1 containment rings
/// for all 50 arms in the Agent Octopus swarm.
#[derive(Clone)]
pub struct ArmRingRegistry {
    pub rings: Arc<RwLock<std::collections::HashMap<usize, Arc<ArmContainmentRing>>>>,
    master_seed: [u8; 32],
}

impl ArmRingRegistry {
    /// Non-blocking synchronous lookup for an arm ring.
    pub fn get_ring_sync(&self, arm_id: usize) -> Option<Arc<ArmContainmentRing>> {
        self.rings.try_read().ok()?.get(&arm_id).cloned()
    }
    /// Initializes Level 1 containment rings for `size` arms (default: 50).
    pub fn new(size: usize, master_seed: &[u8]) -> Self {
        let mut seed = [0u8; 32];
        if master_seed.len() >= 32 {
            seed.copy_from_slice(&master_seed[..32]);
        } else {
            let hash = Sha256::digest(master_seed);
            seed.copy_from_slice(&hash);
        }

        let mut map = std::collections::HashMap::new();
        for arm_id in 0..size {
            let role = match arm_id % 3 {
                0 => ArmRole::UntrustedDocIngest,
                1 => ArmRole::AccountingLedgerWrite,
                _ => ArmRole::NetworkEgress,
            };
            let ring = Arc::new(ArmContainmentRing::new(arm_id, role, 1, &seed));
            map.insert(arm_id, ring);
        }

        // Pre-allocate dedicated individual containment rings for specialized security arms (Arm IDs 100-105)
        let security_arm_roles = [
            (100, ArmRole::CedarPolicyEvaluation),
            (101, ArmRole::AtlasThreatIntelligence),
            (102, ArmRole::AnomalyDetection),
            (103, ArmRole::VulnerabilityResearch),
            (104, ArmRole::ContinuousOssFuzz),
            (105, ArmRole::ContinuousOsvScanner),
            (106, ArmRole::DifferentialProtocolAnalyzer),
            (107, ArmRole::AutonomousProtocolResearch),
            (108, ArmRole::PostQuantumAttestation),
            (109, ArmRole::EvolutionaryOptimizer),
            (110, ArmRole::DreamRsiOptimizer),
            (111, ArmRole::RecursiveHarnessOptimizer),
        ];
        for (sec_id, sec_role) in security_arm_roles {
            let sec_ring = Arc::new(ArmContainmentRing::new(sec_id, sec_role, 1, &seed));
            map.insert(sec_id, sec_ring);
        }

        Self {
            rings: Arc::new(RwLock::new(map)),
            master_seed: seed,
        }
    }

    /// Generates a cryptographically strong 32-byte master seed for ring derivations.
    pub fn generate_master_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        seed
    }

    /// Retrieves a specialized security arm's individual containment ring by its role.
    pub async fn get_security_ring(&self, role: ArmRole) -> Option<Arc<ArmContainmentRing>> {
        let rings = self.rings.read().await;
        rings.values().find(|r| r.role == role).cloned()
    }

    /// Retrieves an arm's containment ring, returning an explicit IsolationViolation error if missing.
    pub async fn get_ring_or_fail(&self, arm_id: usize) -> Result<Arc<ArmContainmentRing>, OctopusSecurityError> {
        let rings = self.rings.read().await;
        rings.get(&arm_id).cloned().ok_or_else(|| {
            OctopusSecurityError::IsolationViolation(format!(
                "Execution halted: Missing mandatory Level 1 ArmContainmentRing for Arm {}",
                arm_id
            ))
        })
    }

    /// Returns the supervisor master seed used to derive arm ring epoch keys.
    pub fn master_seed(&self) -> &[u8; 32] {
        &self.master_seed
    }

    /// Retrieves an arm's individual containment ring.
    pub async fn get_ring(&self, arm_id: usize) -> Option<Arc<ArmContainmentRing>> {
        let rings = self.rings.read().await;
        rings.get(&arm_id).cloned()
    }

    /// Retrieves an arm's individual containment ring by agent name (e.g. "arm-UntrustedDocIngest-0").
    pub async fn get_ring_by_name(&self, agent_name: &str) -> Option<Arc<ArmContainmentRing>> {
        let rings = self.rings.read().await;
        rings.values().find(|r| r.agent_name == agent_name).cloned()
    }

    /// Registers a new or custom arm containment ring into the fleet registry.
    pub async fn register_ring(&self, ring: Arc<ArmContainmentRing>) {
        let mut rings = self.rings.write().await;
        rings.insert(ring.arm_id, ring);
    }

    /// Severs an arm's individual ring without affecting any other arm.
    pub async fn sever_arm(&self, arm_id: usize, reason: &str) -> Result<(), OctopusSecurityError> {
        let rings = self.rings.read().await;
        if let Some(ring) = rings.get(&arm_id) {
            ring.sever(reason).await;
            Ok(())
        } else {
            Err(OctopusSecurityError::CapabilityDenied(format!(
                "Arm {} not found in registry",
                arm_id
            )))
        }
    }

    /// Regenerates an arm after autotomy, advancing its generation epoch and revoking old credentials.
    pub async fn sever_and_regenerate(&self, arm_id: usize) -> Result<u64, OctopusSecurityError> {
        let rings = self.rings.read().await;
        if let Some(ring) = rings.get(&arm_id) {
            Ok(ring.sever_and_regenerate().await)
        } else {
            Err(OctopusSecurityError::CapabilityDenied(format!(
                "Arm {} not found in registry",
                arm_id
            )))
        }
    }

    /// Returns the total number of managed arm rings in the registry.
    pub async fn len(&self) -> usize {
        let rings = self.rings.read().await;
        rings.len()
    }

    /// Returns true if the registry contains no arm rings.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Returns the complete list of arm ring statuses across all arms.
    pub async fn list_rings(&self) -> Vec<ArmRingStatusDto> {
        let rings = self.rings.read().await;
        let mut list = Vec::new();
        let mut ids: Vec<usize> = rings.keys().cloned().collect();
        ids.sort();
        for id in ids {
            if let Some(ring) = rings.get(&id) {
                list.push(ring.to_status_dto().await);
            }
        }
        list
    }
}
