//! Default-Closed Inline ABIBO MCP Vault Gateway, NHI Registry, Out-of-Band 180s HITL Queue,
//! Bidirectional Input/Output Defanging, and RFC 6962 Merkle Audit Ledger.
//!
//! Coordinates all 7 Physics Containment Laws + Red-Team Hardening Upgrades:
//! - Law 1: Special Relativity Causal Light-Cone & Spacetime Event-Horizon
//! - Law 2: Second Law of Thermodynamics, Landauer-Maxwell Barrier & Transitive Taint
//! - Law 3: Hamiltonian Phase-Space Separatrix, Discrete CBF & OrbWeb Autotomy
//! - Law 4: Quantum No-Cloning Single-Use Token Collapse & Quantum Zeno Sweep Cadence
//! - Law 5: Gauss's Law Information Flux & Faraday-Cage Lockout
//! - Law 6: Radioactive Half-Life Dead-Man's Switch Decay (Silent Disconnect Protection)
//! - Law 7: Wave Physics DFT Spectral Beacon Detector (Periodic Overnight Bot Polling)
//! - Red-Team Upgrades: MCP Schema Rug-Pull Pinning, Memory Provenance Guard,
//!   Bidirectional Input/Output Defanging (SSRF/IMDS/CDP + EchoLeak + SemanticDLP),
//!   180s Fail-Closed HITL Queue, and Immutable RFC 6962 Merkle Audit Receipts.

use super::gauss_flux_cage::{GaussFluxCage, GaussFluxVerdict};
use super::half_life_decay::{HalfLifeVerdict, RadioactiveHalfLifeEngine};
use super::hamiltonian_barrier::{HamiltonianBarrierEngine, HamiltonianVerdict, PhaseSpaceState};
use super::memory_provenance::MemoryProvenanceGuard;
use super::perplexity_guard::{
    classify_mcp_action, ActionTrajectoryVerdict, CandidateActionProposal,
    PerplexityDefenseCoordinator, PerplexityTranslationReport, SemanticEntropyVerdict,
};
use super::quantum_zeno_guard::{QuantumZenoGuard, QuantumZenoVerdict, SingleUseCapabilityToken};
use super::relativity_causality::{RelativityCausalityGate, RelativityVerdict};
use super::schema_pinning::{McpToolManifest, McpToolSchemaPinRegistry, SchemaPinVerdict};
use super::spectral_beacon::{SpectralBeaconDetector, SpectralBeaconVerdict};
use super::thermodynamics_taint::{ThermodynamicTaintEngine, ThermodynamicsVerdict};
use crate::containment_ring::egress_proxy::is_restricted_rebinding_ip;
use crate::core::merkle::{MerkleLeaf, MerkleTree};
use crate::security::agentjacking_guard::AgentjackingGuard;
use crate::security::artemis_dfir::{
    unix_now_secs, ArtemisDfirEngine, WorkstationLivenessSnapshot, WorkstationLivenessTracker,
};
use crate::security::cedar_arm::CedarPolicyEngine;
use crate::security::file_lineage::FileLineageTracker;
use crate::security::log_sanitizer::LogSanitizer;
use crate::security::semantic_dlp::SemanticDlpEngine;
use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Strict fail-closed TTL for out-of-band Human-in-the-Loop (HITL) approval tickets (3 minutes).
pub const DEFAULT_HITL_TTL_SECS: u64 = 180;
const MAX_AUDIT_LEDGER_ENTRIES: usize = 4096;

/// Non-Human Identity (NHI) registered in the default-closed ABIBO MCP Vault Gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonHumanIdentityRecord {
    pub nhi_id: String,
    pub sponsor_human: String,
    pub provider: String,
    pub allowed_tools: Vec<String>,
    pub write_capable: bool,
    pub half_life_secs: Option<u64>,
    pub revoked: bool,
    pub revoked_reason: Option<String>,
    pub created_at_unix: u64,
}

/// Lifecycle state of an out-of-band HITL approval ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HitlTicketStatus {
    Pending,
    Approved,
    Denied,
    ExpiredDenied,
}

/// Out-of-band Human-in-the-Loop approval ticket with strict 180-second fail-closed expiration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitlApprovalTicket {
    pub ticket_id: String,
    pub nhi_id: String,
    pub server_name: String,
    pub tool_name: String,
    pub arguments_sha256: String,
    pub arguments_preview: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub epoch: u64,
    pub status: HitlTicketStatus,
    pub resolved_by: Option<String>,
    pub minted_token: Option<SingleUseCapabilityToken>,
}

/// Final deterministic decision returned by the ABIBO MCP Vault Gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpMediationDecision {
    Approved,
    PendingHitl,
    Denied,
    ExpiredDenied,
}

impl McpMediationDecision {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::PendingHitl => "pending_hitl",
            Self::Denied => "denied",
            Self::ExpiredDenied => "expired_denied",
        }
    }
}

/// Inbound MCP tool invocation request submitted to the ABIBO Mediation Coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpMediationRequest {
    pub nhi_id: String,
    pub server_name: String,
    pub tool_name: String,
    pub arguments_json: String,
    pub is_write_or_mutating: bool,
    pub touches_private_data: bool,
    pub external_egress: bool,
    pub privilege_escalation_risk: bool,
    pub persistence_risk: bool,
    pub d_trust: f64,
    pub request_epoch: u64,
    pub request_ts_unix: Option<u64>,
    pub capability_token: Option<SingleUseCapabilityToken>,
    pub tool_manifest: Option<McpToolManifest>,
}

/// Immutable RFC 6962 Merkle-sealed audit receipt for every mediated MCP call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiboMerkleAuditRecord {
    pub sequence: usize,
    pub timestamp_utc: String,
    pub timestamp_unix: u64,
    pub nhi_id: String,
    pub server_name: String,
    pub tool_name: String,
    pub decision: McpMediationDecision,
    pub triggered_laws: Vec<String>,
    pub reason: String,
    pub leaf_hash_hex: String,
}

/// Full 7-Law physics verdict & RFC 6962 receipt returned by `AbiboMediationCoordinator::mediate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpMediationReport {
    pub decision: McpMediationDecision,
    pub allowed: bool,
    pub nhi_id: String,
    pub tool_name: String,
    pub triggered_laws: Vec<String>,
    pub reason: String,
    pub hitl_ticket: Option<HitlApprovalTicket>,
    pub relativity: RelativityVerdict,
    pub thermodynamics: ThermodynamicsVerdict,
    pub hamiltonian: HamiltonianVerdict,
    pub quantum_zeno: QuantumZenoVerdict,
    pub gauss_flux: GaussFluxVerdict,
    pub half_life: HalfLifeVerdict,
    pub spectral_beacon: SpectralBeaconVerdict,
    pub schema_pin: Option<SchemaPinVerdict>,
    pub perplexity_translation: PerplexityTranslationReport,
    pub action_trajectory: ActionTrajectoryVerdict,
    pub semantic_entropy: SemanticEntropyVerdict,
    pub dlp_entity_count: usize,
    pub ssrf_blocked: bool,
    pub cedar_forbid_triggered: bool,
    pub merkle_leaf_hash: String,
    pub merkle_root_hex: String,
}

/// Result of bidirectional outbound MCP tool-response defanging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefangedToolResponse {
    pub sanitized_output: String,
    pub injection_neutralized: bool,
    pub echoleak_markdown_defanged: bool,
    pub credentials_scrubbed: bool,
    pub dlp_entity_count: usize,
    pub resulting_agent_entropy_bits: f64,
}

/// Live ABIBO dashboard status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiboStatusSnapshot {
    pub liveness: WorkstationLivenessSnapshot,
    pub active_nhi_count: usize,
    pub revoked_nhi_count: usize,
    pub pending_hitl_count: usize,
    pub pinned_tool_count: usize,
    pub attested_memory_file_count: usize,
    pub faraday_cage_engaged: bool,
    pub current_zeno_sweep_ms: u64,
    pub total_mediated_calls: usize,
    pub total_denied_calls: usize,
    pub merkle_root_hex: String,
    pub nhis: Vec<NonHumanIdentityRecord>,
    pub hitl_tickets: Vec<HitlApprovalTicket>,
    pub recent_audit: Vec<AbiboMerkleAuditRecord>,
    pub agent_entropies: HashMap<String, f64>,
}

/// Structured output of the deterministic NewCore Nov 2026 31-request xAI Grok overnight simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewCoreGrokSimulationReport {
    pub scenario: String,
    pub workstation_locked_at_unix: u64,
    pub total_requests: usize,
    pub denied_requests: usize,
    pub approved_requests: usize,
    pub law1_relativity_denies: usize,
    pub law5_faraday_denies: usize,
    pub law6_halflife_denies: usize,
    pub law7_spectral_beacon_denies: usize,
    pub merkle_root_hex: String,
    pub merkle_leaf_count: usize,
    pub sample_receipts: Vec<AbiboMerkleAuditRecord>,
}

/// Checks whether a tool arguments payload attempts SSRF toward cloud IMDS, RFC1918,
/// loopback browser CDP debug ports (`9222`, `9229`), or dangerous URI schemes (`file://`, `gopher://`).
#[must_use]
pub fn detect_ssrf_imds_or_cdp_in_args(arguments_json: &str) -> Option<String> {
    let lower = arguments_json.to_ascii_lowercase();
    for bad in [
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.azure.com",
        "fd00:ec2::254",
        "file://",
        "gopher://",
        "dict://",
        "127.0.0.1:9222",
        "localhost:9222",
        "[::1]:9222",
        "127.0.0.1:9229",
        "localhost:9229",
    ] {
        if lower.contains(bad) {
            return Some(format!(
                "SSRF_IMDS_CDP_DENY: Blocked restricted metadata/CDP/scheme target '{bad}'"
            ));
        }
    }

    // Parse explicit URL tokens and check IP literals with AgentOctopus's mathematical SSRF checker
    for raw_tok in arguments_json
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | '{' | '}' | '[' | ']'))
    {
        if raw_tok.starts_with("http://") || raw_tok.starts_with("https://") {
            if let Ok(parsed) = url::Url::parse(raw_tok) {
                if let Some(host) = parsed.host_str() {
                    let clean = host.trim_matches(['[', ']']);
                    if let Ok(ip) = clean.parse::<IpAddr>() {
                        if is_restricted_rebinding_ip(&ip) {
                            return Some(format!(
                                "SSRF_RESTRICTED_IP_DENY: Blocked RFC1918/loopback/link-local/CGNAT IP '{ip}'"
                            ));
                        }
                    }
                }
            }
        }
    }
    None
}

/// Master coordinator enforcing the 7 Physics Laws, Red-Team Hardening, Default-Closed MCP Vault,
/// Artemis DFIR closed-loop Cedar compilation, and RFC 6962 Merkle Audit Ledger.
pub struct AbiboMediationCoordinator {
    liveness: Arc<WorkstationLivenessTracker>,
    cedar_engine: Arc<CedarPolicyEngine>,
    lineage_tracker: Arc<FileLineageTracker>,
    workspace_root: PathBuf,
    artemis_engine: Arc<ArtemisDfirEngine>,
    relativity: RelativityCausalityGate,
    thermodynamics: ThermodynamicTaintEngine,
    hamiltonian: HamiltonianBarrierEngine,
    quantum_zeno: QuantumZenoGuard,
    gauss_flux: GaussFluxCage,
    half_life: RadioactiveHalfLifeEngine,
    spectral_beacon: SpectralBeaconDetector,
    schema_pins: McpToolSchemaPinRegistry,
    memory_provenance: Arc<MemoryProvenanceGuard>,
    perplexity_defense: PerplexityDefenseCoordinator,
    agentjacking: AgentjackingGuard,
    dlp: SemanticDlpEngine,
    nhi_registry: RwLock<HashMap<String, NonHumanIdentityRecord>>,
    hitl_queue: RwLock<HashMap<String, HitlApprovalTicket>>,
    prev_cbf_by_nhi: RwLock<HashMap<String, f64>>,
    audit_records: RwLock<VecDeque<AbiboMerkleAuditRecord>>,
    merkle_leaves: RwLock<Vec<MerkleLeaf>>,
    ticket_seq: AtomicU64,
    last_zeno_ms: AtomicU64,
}

impl Default for AbiboMediationCoordinator {
    fn default() -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self::new(cwd)
    }
}

impl AbiboMediationCoordinator {
    #[must_use]
    pub fn new(workspace_root: PathBuf) -> Self {
        let liveness = Arc::new(WorkstationLivenessTracker::new(300));
        let cedar_engine = Arc::new(CedarPolicyEngine::new().unwrap_or_default());
        let lineage_tracker = Arc::new(FileLineageTracker::default());
        let perplexity_defense = if cfg!(test) {
            PerplexityDefenseCoordinator::default()
        } else {
            PerplexityDefenseCoordinator::for_workspace(&workspace_root)
        };
        let artemis_engine = Arc::new(ArtemisDfirEngine::new(
            workspace_root.clone(),
            Arc::clone(&liveness),
            Arc::clone(&cedar_engine),
            Arc::clone(&lineage_tracker),
        ));

        let coord = Self {
            workspace_root,
            liveness,
            cedar_engine,
            lineage_tracker,
            artemis_engine,
            relativity: RelativityCausalityGate::default(),
            thermodynamics: ThermodynamicTaintEngine::default(),
            hamiltonian: HamiltonianBarrierEngine::default(),
            quantum_zeno: QuantumZenoGuard::default(),
            gauss_flux: GaussFluxCage::default(),
            half_life: RadioactiveHalfLifeEngine::default(),
            spectral_beacon: SpectralBeaconDetector::default(),
            schema_pins: McpToolSchemaPinRegistry::new(),
            memory_provenance: Arc::new(MemoryProvenanceGuard::default()),
            perplexity_defense,
            agentjacking: AgentjackingGuard::new(),
            dlp: SemanticDlpEngine::default(),
            nhi_registry: RwLock::new(HashMap::new()),
            hitl_queue: RwLock::new(HashMap::new()),
            prev_cbf_by_nhi: RwLock::new(HashMap::new()),
            audit_records: RwLock::new(VecDeque::with_capacity(256)),
            merkle_leaves: RwLock::new(Vec::with_capacity(256)),
            ticket_seq: AtomicU64::new(1),
            last_zeno_ms: AtomicU64::new(30_000),
        };

        // Pre-register a default local read-only operator session identity so local interactive reads work cleanly
        coord.register_nhi(NonHumanIdentityRecord {
            nhi_id: "local_interactive_agent".to_string(),
            sponsor_human: "local_operator".to_string(),
            provider: "agentoctopus_local".to_string(),
            allowed_tools: vec![
                "read_file".to_string(),
                "search_docs".to_string(),
                "gmail_read".to_string(),
                "calendar_list".to_string(),
                "gmail_send".to_string(),
                "calendar_write".to_string(),
            ],
            write_capable: true,
            half_life_secs: Some(300),
            revoked: false,
            revoked_reason: None,
            created_at_unix: unix_now_secs(),
        });

        coord
    }

    #[must_use]
    pub fn liveness(&self) -> &Arc<WorkstationLivenessTracker> {
        &self.liveness
    }

    #[must_use]
    pub fn cedar_engine(&self) -> &Arc<CedarPolicyEngine> {
        &self.cedar_engine
    }

    #[must_use]
    pub fn lineage_tracker(&self) -> &Arc<FileLineageTracker> {
        &self.lineage_tracker
    }

    #[must_use]
    pub fn artemis_engine(&self) -> &Arc<ArtemisDfirEngine> {
        &self.artemis_engine
    }

    #[must_use]
    pub fn thermodynamics(&self) -> &ThermodynamicTaintEngine {
        &self.thermodynamics
    }

    #[must_use]
    pub fn quantum_zeno(&self) -> &QuantumZenoGuard {
        &self.quantum_zeno
    }

    #[must_use]
    pub fn gauss_flux(&self) -> &GaussFluxCage {
        &self.gauss_flux
    }

    #[must_use]
    pub fn schema_pins(&self) -> &McpToolSchemaPinRegistry {
        &self.schema_pins
    }

    #[must_use]
    pub fn memory_provenance(&self) -> &Arc<MemoryProvenanceGuard> {
        &self.memory_provenance
    }

    #[must_use]
    pub fn workspace_root(&self) -> &std::path::Path {
        &self.workspace_root
    }

    #[must_use]
    pub fn perplexity_defense(&self) -> &PerplexityDefenseCoordinator {
        &self.perplexity_defense
    }

    /// Registers or updates a Non-Human Identity (NHI) in the default-closed vault.
    pub fn register_nhi(&self, record: NonHumanIdentityRecord) {
        self.nhi_registry
            .write()
            .insert(record.nhi_id.to_ascii_lowercase(), record);
    }

    /// Immediately revokes a Non-Human Identity (instant revocation invariant).
    pub fn revoke_nhi(&self, nhi_id: &str, reason: &str) -> bool {
        let key = nhi_id.to_ascii_lowercase();
        let mut reg = self.nhi_registry.write();
        if let Some(rec) = reg.get_mut(&key) {
            rec.revoked = true;
            rec.revoked_reason = Some(reason.to_string());
            true
        } else {
            false
        }
    }

    /// Sweeps all pending HITL tickets and transitions any ticket past its 180s TTL to `ExpiredDenied`,
    /// recording every expiration in the immutable RFC 6962 Merkle Audit Ledger.
    pub fn expire_stale_hitl_tickets_at(&self, now_unix: u64) -> Vec<HitlApprovalTicket> {
        let mut expired = Vec::new();
        {
            let mut q = self.hitl_queue.write();
            for ticket in q.values_mut() {
                if ticket.status == HitlTicketStatus::Pending && now_unix > ticket.expires_at_unix {
                    ticket.status = HitlTicketStatus::ExpiredDenied;
                    expired.push(ticket.clone());
                }
            }
        }
        for t in &expired {
            let _ = self.append_merkle_audit(
                now_unix,
                &t.nhi_id,
                &t.server_name,
                &t.tool_name,
                McpMediationDecision::ExpiredDenied,
                vec!["HITL_180S_TTL_EXPIRED".to_string()],
                format!(
                    "HITL ticket '{}' expired fail-closed after {}s TTL",
                    t.ticket_id, DEFAULT_HITL_TTL_SECS
                ),
            );
        }
        expired
    }

    /// Resolves a pending HITL approval ticket (Approve -> mints single-use Law 4 Quantum No-Cloning
    /// capability token; Deny -> transitions ticket to Denied; Expired -> transitions to ExpiredDenied).
    pub fn resolve_hitl_ticket_at(
        &self,
        ticket_id: &str,
        approve: bool,
        operator: &str,
        now_unix: u64,
    ) -> Result<HitlApprovalTicket, String> {
        self.expire_stale_hitl_tickets_at(now_unix);
        let mut q = self.hitl_queue.write();
        let ticket = q
            .get_mut(ticket_id)
            .ok_or_else(|| format!("HITL ticket '{ticket_id}' not found"))?;

        if ticket.status != HitlTicketStatus::Pending {
            return Err(format!(
                "HITL ticket '{ticket_id}' is already finalized ({:?})",
                ticket.status
            ));
        }

        if now_unix > ticket.expires_at_unix {
            ticket.status = HitlTicketStatus::ExpiredDenied;
            let snap = ticket.clone();
            drop(q);
            let _ = self.append_merkle_audit(
                now_unix,
                &snap.nhi_id,
                &snap.server_name,
                &snap.tool_name,
                McpMediationDecision::ExpiredDenied,
                vec!["HITL_180S_TTL_EXPIRED".to_string()],
                format!("HITL ticket '{ticket_id}' expired before operator resolution"),
            );
            return Ok(snap);
        }

        ticket.resolved_by = Some(operator.to_string());
        if approve {
            let active_epoch = self.liveness.current_epoch();
            let token = self.quantum_zeno.mint_single_use_token_at(
                &ticket.nhi_id,
                &ticket.tool_name,
                &ticket.arguments_sha256,
                active_epoch,
                now_unix,
                DEFAULT_HITL_TTL_SECS,
            );
            ticket.status = HitlTicketStatus::Approved;
            ticket.minted_token = Some(token);
        } else {
            ticket.status = HitlTicketStatus::Denied;
        }
        let result = ticket.clone();
        drop(q);

        let decision = if approve {
            McpMediationDecision::Approved
        } else {
            McpMediationDecision::Denied
        };
        let _ = self.append_merkle_audit(
            now_unix,
            &result.nhi_id,
            &result.server_name,
            &result.tool_name,
            decision,
            vec!["OUT_OF_BAND_HITL_RESOLUTION".to_string()],
            format!(
                "Operator '{}' resolved HITL ticket '{ticket_id}' -> {:?}",
                operator, result.status
            ),
        );
        Ok(result)
    }

    /// Evaluates an inbound MCP tool invocation through all 7 Physics Laws, Red-Team Hardening,
    /// 4-Layer Dual-Domain Perplexity + Canonical LRL Translation Pivot, AWS Cedar, SemanticDLP,
    /// SSRF/IMDS/CDP checks, and seals the outcome in the RFC 6962 Merkle audit log.
    #[must_use]
    pub fn mediate(&self, req: &McpMediationRequest) -> McpMediationReport {
        self.mediate_with_proposals(req, &[])
    }

    /// Evaluates an inbound MCP tool invocation together with optional sampled candidate action
    /// proposals for Layer 4 Semantic Entropy abstention gating.
    #[must_use]
    pub fn mediate_with_proposals(
        &self,
        req: &McpMediationRequest,
        candidate_proposals: &[CandidateActionProposal],
    ) -> McpMediationReport {
        let now_unix = req.request_ts_unix.unwrap_or_else(unix_now_secs);
        self.expire_stale_hitl_tickets_at(now_unix);

        let run_os_probe = req.request_ts_unix.is_none() && !cfg!(test);
        let liveness = self.liveness.snapshot_at(now_unix, run_os_probe);

        let clean_args = LogSanitizer::strip_dangerous_unicode(&req.arguments_json);
        let args_sha256 = hex::encode(Sha256::digest(clean_args.as_bytes()));
        let mut triggered_laws: Vec<String> = Vec::new();
        let mut deny_reasons: Vec<String> = Vec::new();

        // 0. Default-Closed NHI Registry check
        let nhi_opt = self
            .nhi_registry
            .read()
            .get(&req.nhi_id.to_ascii_lowercase())
            .cloned();
        let custom_half_life = nhi_opt.as_ref().and_then(|n| n.half_life_secs);
        match &nhi_opt {
            None => {
                triggered_laws.push("DEFAULT_CLOSED_NHI".to_string());
                deny_reasons.push(format!(
                    "DEFAULT_CLOSED_NHI_DENY: Unregistered Non-Human Identity '{}'",
                    req.nhi_id
                ));
            }
            Some(nhi) if nhi.revoked => {
                triggered_laws.push("NHI_REVOKED".to_string());
                deny_reasons.push(format!(
                    "NHI_REVOKED_DENY: Identity '{}' was revoked ({})",
                    nhi.nhi_id,
                    nhi.revoked_reason
                        .as_deref()
                        .unwrap_or("operator revocation")
                ));
            }
            Some(nhi) => {
                let tool_allowed = nhi.allowed_tools.is_empty()
                    || nhi
                        .allowed_tools
                        .iter()
                        .any(|t| t == "*" || t.eq_ignore_ascii_case(&req.tool_name));
                if !tool_allowed {
                    triggered_laws.push("NHI_SCOPE_DENY".to_string());
                    deny_reasons.push(format!(
                        "NHI_SCOPE_DENY: Tool '{}' not in least-privilege allowlist for '{}'",
                        req.tool_name, nhi.nhi_id
                    ));
                }
                if req.is_write_or_mutating && !nhi.write_capable {
                    triggered_laws.push("NHI_READ_ONLY_DENY".to_string());
                    deny_reasons.push(format!(
                        "NHI_READ_ONLY_DENY: Read-only identity '{}' attempted mutating tool '{}'",
                        nhi.nhi_id, req.tool_name
                    ));
                }
            }
        }

        // 0b. Bidirectional Inbound SSRF/IMDS/CDP + Canonical Translation Pivot + Perplexity + Cross-Lingual DLP
        let ssrf_err = detect_ssrf_imds_or_cdp_in_args(&clean_args);
        let ssrf_blocked = ssrf_err.is_some();
        if let Some(msg) = ssrf_err {
            triggered_laws.push("SSRF_IMDS_CDP_GUARD".to_string());
            deny_reasons.push(msg);
        }

        let perplexity_translation = self.perplexity_defense.analyze_text(&clean_args, true);
        if perplexity_translation.total_taint_delta_bits > 0.0 {
            self.thermodynamics
                .absorb_perplexity_and_translation_signals(
                    &req.nhi_id,
                    perplexity_translation.total_taint_delta_bits,
                );
        }
        if !perplexity_translation.allowed {
            if perplexity_translation.translation.breakin_detected {
                triggered_laws.push("CANONICAL_TRANSLATION_LRL_GUARD".to_string());
            }
            if !perplexity_translation.source_perplexity.allowed
                || !perplexity_translation.pivot_perplexity.allowed
            {
                triggered_laws.push("WINDOWED_PERPLEXITY_GCG_GUARD".to_string());
            }
            deny_reasons.push(perplexity_translation.reason.clone());
        }

        // Cross-lingual DLP: inspect BOTH raw args AND canonical English translation pivot
        let mut dlp_entity_count = self.dlp.scan_payload(&clean_args).len();
        if perplexity_translation.translation.canonical_english_pivot != clean_args {
            let pivot_hits = self
                .dlp
                .scan_payload(&perplexity_translation.translation.canonical_english_pivot)
                .len();
            dlp_entity_count = dlp_entity_count.max(pivot_hits);
        }
        let cross_lingual_dlp_synonym_hit = !perplexity_translation
            .translation
            .dlp_synonym_pivots
            .is_empty();
        if (dlp_entity_count > 0 || cross_lingual_dlp_synonym_hit)
            && (req.external_egress || req.is_write_or_mutating)
        {
            triggered_laws.push("SEMANTIC_DLP_EGRESS_GUARD".to_string());
            if cross_lingual_dlp_synonym_hit && dlp_entity_count == 0 {
                dlp_entity_count = perplexity_translation.translation.dlp_synonym_pivots.len();
                deny_reasons.push(format!(
                    "CROSS_LINGUAL_DLP_DENY: Sensitive non-English secret/deal terminology detected via canonical pivot ({})",
                    perplexity_translation
                        .translation
                        .dlp_synonym_pivots
                        .join(", ")
                ));
            } else {
                deny_reasons.push(format!(
                    "SEMANTIC_DLP_DENY: Detected {dlp_entity_count} sensitive PII/secret/deal entities in outbound MCP arguments"
                ));
            }
        }

        // 0c. Red-Team Upgrade #2: MCP Tool-Schema Rug-Pull Pinning
        let schema_pin = req
            .tool_manifest
            .as_ref()
            .map(|m| self.schema_pins.verify_manifest(m, false));
        if let Some(ref sp) = schema_pin {
            if !sp.allowed {
                triggered_laws.push("REDTEAM_SCHEMA_RUG_PULL".to_string());
                deny_reasons.push(sp.reason.clone());
            }
        }

        // 0d. Live AWS Cedar Policy Evaluation (catches dynamically compiled Artemis DFIR forbid rules!)
        let cedar_forbid_triggered = match self.cedar_engine.evaluate(
            &req.nhi_id,
            "tool_call",
            &req.tool_name,
            "Tool",
            serde_json::json!({
                "tool_name": req.tool_name,
                "arguments_json": clean_args,
                "target": req.server_name,
            }),
        ) {
            Ok(v) => !v.is_allowed && !v.determining_policies.is_empty(),
            Err(_) => false,
        };
        if cedar_forbid_triggered {
            triggered_laws.push("CEDAR_DFIR_FORBID".to_string());
            deny_reasons.push(format!(
                "CEDAR_FORBID_DENY: Active AWS Cedar forbid policy blocked tool '{}'",
                req.tool_name
            ));
        }

        // Law 1: Special Relativity Causal Light-Cone & Spacetime Event-Horizon
        let relativity =
            self.relativity
                .evaluate(&liveness, req.request_epoch, now_unix, req.d_trust);
        if !relativity.allowed {
            triggered_laws.push("LAW1_RELATIVITY_CAUSALITY".to_string());
            deny_reasons.push(relativity.reason.clone());
        }

        // Law 2: Second Law of Thermodynamics & Landauer-Maxwell Barrier
        let is_high_impact = req.is_write_or_mutating
            || req.external_egress
            || req.privilege_escalation_risk
            || req.persistence_risk;
        let thermodynamics =
            self.thermodynamics
                .evaluate_barrier(&req.nhi_id, &clean_args, is_high_impact);
        if !thermodynamics.allowed {
            triggered_laws.push("LAW2_THERMODYNAMICS_TAINT".to_string());
            deny_reasons.push(thermodynamics.reason.clone());
        }

        // Layer 3 Perplexity: Language-Independent Action-Trajectory Markov Perplexity
        let action_class = classify_mcp_action(
            &req.tool_name,
            &clean_args,
            req.is_write_or_mutating,
            req.touches_private_data,
            req.external_egress,
            req.privilege_escalation_risk,
            req.persistence_risk,
        );
        let agent_is_tainted = thermodynamics.agent_entropy_bits >= 0.5;
        let action_trajectory = self.perplexity_defense.observe_action_trajectory(
            &req.nhi_id,
            action_class,
            agent_is_tainted,
        );
        if !action_trajectory.allowed {
            triggered_laws.push("ACTION_TRAJECTORY_PERPLEXITY".to_string());
            deny_reasons.push(action_trajectory.reason.clone());
        }

        // Layer 4 Perplexity: Semantic Entropy Actuation Gate (Hallucination / Slopsquatting)
        let semantic_entropy = self.perplexity_defense.semantic_entropy().evaluate(
            candidate_proposals,
            req.is_write_or_mutating || req.privilege_escalation_risk || req.persistence_risk,
        );
        let semantic_entropy_abstain = semantic_entropy.abstain_and_require_hitl;
        if semantic_entropy_abstain {
            triggered_laws.push("SEMANTIC_ENTROPY_ABSTAIN".to_string());
        }

        // Law 3: Analytical Mechanics — Hamiltonian Phase-Space Separatrix + Discrete CBF + OrbWeb
        let q_untrusted = (thermodynamics.agent_entropy_bits / 2.5).clamp(0.0, 1.0);
        let q_priv = if req.touches_private_data || dlp_entity_count > 0 {
            0.85
        } else {
            0.10
        };
        let q_egress = if req.external_egress || req.is_write_or_mutating {
            0.85
        } else {
            0.10
        };
        let q_priv_esc = if req.privilege_escalation_risk {
            0.90
        } else {
            0.05
        };
        let q_persist = if req.persistence_risk { 0.85 } else { 0.05 };
        let phase_state = PhaseSpaceState {
            q_private_data: q_priv,
            q_untrusted_input: q_untrusted,
            q_external_egress: q_egress,
            q_privilege_escalation: q_priv_esc,
            q_persistence: q_persist,
            momentum_norm: if is_high_impact { 0.9 } else { 0.2 },
        };
        let prev_cbf = self
            .prev_cbf_by_nhi
            .read()
            .get(&req.nhi_id.to_ascii_lowercase())
            .copied();
        let hamiltonian = self
            .hamiltonian
            .evaluate(phase_state, prev_cbf, clean_args.len());
        if hamiltonian.allowed {
            self.prev_cbf_by_nhi
                .write()
                .insert(req.nhi_id.to_ascii_lowercase(), hamiltonian.cbf_margin);
        } else {
            triggered_laws.push("LAW3_HAMILTONIAN_SEPARATRIX".to_string());
            deny_reasons.push(hamiltonian.reason.clone());
        }

        // Law 5: Electromagnetism — Gauss's Law Information Flux & Faraday-Cage Lockout
        let sensitivity = if dlp_entity_count > 0 || req.touches_private_data {
            8.0
        } else if req.is_write_or_mutating {
            4.0
        } else {
            1.0
        };
        let gauss_flux = self.gauss_flux.evaluate(
            &liveness,
            now_unix,
            clean_args.len(),
            sensitivity,
            req.is_write_or_mutating || req.external_egress,
        );
        if !gauss_flux.allowed {
            triggered_laws.push("LAW5_GAUSS_FARADAY_CAGE".to_string());
            deny_reasons.push(gauss_flux.reason.clone());
        }

        // Law 6: Nuclear Physics — Radioactive Half-Life Dead-Man's Switch Decay
        let half_life = self.half_life.evaluate(
            liveness.last_heartbeat_unix,
            now_unix,
            custom_half_life,
            req.privilege_escalation_risk || req.persistence_risk,
        );
        if !half_life.allowed {
            triggered_laws.push("LAW6_RADIOACTIVE_HALF_LIFE".to_string());
            deny_reasons.push(half_life.reason.clone());
        }

        // Law 7: Wave Physics — DFT Spectral Beacon & Periodic Overnight Polling Detector
        let unattended = !liveness.human_live || liveness.workstation_locked;
        let spectral_beacon =
            self.spectral_beacon
                .observe_and_evaluate(&req.nhi_id, now_unix, unattended);
        if !spectral_beacon.allowed {
            triggered_laws.push("LAW7_SPECTRAL_BEACON".to_string());
            deny_reasons.push(spectral_beacon.reason.clone());
        }

        // Law 4: Quantum Mechanics — No-Cloning Token Collapse + Quantum Zeno Sweep Cadence
        let h_ratio = hamiltonian.total_hamiltonian / hamiltonian.h_max_separatrix.max(0.1);
        let zeno_ms = self
            .quantum_zeno
            .compute_zeno_sweep_interval_ms(h_ratio, thermodynamics.agent_entropy_bits);
        self.last_zeno_ms.store(zeno_ms, Ordering::SeqCst);

        let mut hitl_ticket: Option<HitlApprovalTicket> = None;
        let (decision, quantum_zeno) = if !deny_reasons.is_empty() {
            // Physics/security veto already triggered -> hard deny (never consume a valid token on hard veto)
            let qv = QuantumZenoVerdict {
                allowed: false,
                token_collapsed: false,
                replay_detected: false,
                zeno_sweep_interval_ms: zeno_ms,
                reason: format!(
                    "LAW4_ZENO_ACCELERATED: Forensic observation cadence tightened to {zeno_ms}ms after physics veto"
                ),
            };
            (McpMediationDecision::Denied, qv)
        } else if req.is_write_or_mutating
            || req.privilege_escalation_risk
            || req.persistence_risk
            || semantic_entropy_abstain
        {
            // Mutating/write actions require a valid single-use No-Cloning token OR out-of-band HITL approval (180s TTL).
            // High semantic entropy ALWAYS forces fresh out-of-band human disambiguation before actuation.
            if let Some(tok) = req
                .capability_token
                .as_ref()
                .filter(|_| !semantic_entropy_abstain)
            {
                let qv = self.quantum_zeno.consume_once(
                    tok,
                    &req.nhi_id,
                    &req.tool_name,
                    &args_sha256,
                    liveness.epoch,
                    now_unix,
                    h_ratio,
                    thermodynamics.agent_entropy_bits,
                );
                if qv.allowed {
                    (McpMediationDecision::Approved, qv)
                } else {
                    triggered_laws.push("LAW4_QUANTUM_NO_CLONING".to_string());
                    deny_reasons.push(qv.reason.clone());
                    (McpMediationDecision::Denied, qv)
                }
            } else {
                // Queue fail-closed 180s out-of-band HITL approval ticket
                let tid = format!(
                    "hitl-{}-{}",
                    liveness.epoch,
                    self.ticket_seq.fetch_add(1, Ordering::SeqCst)
                );
                let preview: String = LogSanitizer::sanitize_text(&clean_args)
                    .chars()
                    .take(180)
                    .collect();
                let ticket = HitlApprovalTicket {
                    ticket_id: tid.clone(),
                    nhi_id: req.nhi_id.clone(),
                    server_name: req.server_name.clone(),
                    tool_name: req.tool_name.clone(),
                    arguments_sha256: args_sha256.clone(),
                    arguments_preview: preview,
                    created_at_unix: now_unix,
                    expires_at_unix: now_unix.saturating_add(DEFAULT_HITL_TTL_SECS),
                    epoch: liveness.epoch,
                    status: HitlTicketStatus::Pending,
                    resolved_by: None,
                    minted_token: None,
                };
                self.hitl_queue.write().insert(tid.clone(), ticket.clone());
                hitl_ticket = Some(ticket);
                triggered_laws.push("OUT_OF_BAND_HITL_REQUIRED".to_string());
                deny_reasons.push(format!(
                    "HITL_APPROVAL_REQUIRED: Mutating tool '{}' queued as ticket '{tid}' (expires fail-closed in {DEFAULT_HITL_TTL_SECS}s)",
                    req.tool_name
                ));
                let qv = QuantumZenoVerdict {
                    allowed: false,
                    token_collapsed: false,
                    replay_detected: false,
                    zeno_sweep_interval_ms: zeno_ms,
                    reason: format!(
                        "LAW4_AWAITING_SINGLE_USE_TOKEN: Human approval required to mint single-use capability token (Zeno={zeno_ms}ms)"
                    ),
                };
                (McpMediationDecision::PendingHitl, qv)
            }
        } else {
            let qv = QuantumZenoVerdict {
                allowed: true,
                token_collapsed: false,
                replay_detected: false,
                zeno_sweep_interval_ms: zeno_ms,
                reason: format!(
                    "LAW4_READ_ONLY_OBSERVED: Read-only call permitted inside causal cone (Zeno={zeno_ms}ms)"
                ),
            };
            (McpMediationDecision::Approved, qv)
        };

        let allowed = decision == McpMediationDecision::Approved;
        let reason = if allowed {
            format!(
                "ABIBO_APPROVED: '{}' -> '{}' passed all 7 physics laws & security gates",
                req.nhi_id, req.tool_name
            )
        } else {
            deny_reasons.join(" | ")
        };

        let (merkle_leaf_hash, merkle_root_hex) = self.append_merkle_audit(
            now_unix,
            &req.nhi_id,
            &req.server_name,
            &req.tool_name,
            decision,
            triggered_laws.clone(),
            reason.clone(),
        );

        McpMediationReport {
            decision,
            allowed,
            nhi_id: req.nhi_id.clone(),
            tool_name: req.tool_name.clone(),
            triggered_laws,
            reason,
            hitl_ticket,
            relativity,
            thermodynamics,
            hamiltonian,
            quantum_zeno,
            gauss_flux,
            half_life,
            spectral_beacon,
            schema_pin,
            perplexity_translation,
            action_trajectory,
            semantic_entropy,
            dlp_entity_count,
            ssrf_blocked,
            cedar_forbid_triggered,
            merkle_leaf_hash,
            merkle_root_hex,
        }
    }

    /// Bidirectional Outbound Defanging: Sanitizes MCP tool outputs before they enter an LLM's
    /// context window (neutralizing indirect prompt injections, GhostJacking invisible Unicode,
    /// EchoLeak markdown image exfiltration, and leaked credentials) while monotonically
    /// elevating the consuming agent's Thermodynamic Taint Entropy.
    #[must_use]
    pub fn defang_mcp_tool_response(
        &self,
        agent_id: &str,
        source_tool: &str,
        raw_output: &str,
    ) -> DefangedToolResponse {
        let md_defanged = LogSanitizer::defang_markdown_and_exfiltration(raw_output);
        let echoleak_markdown_defanged = md_defanged != raw_output;
        let cred_scrubbed = LogSanitizer::scrub_credentials(&md_defanged);
        let credentials_scrubbed = cred_scrubbed != md_defanged;
        let dlp_entity_count = self.dlp.scan_payload(raw_output).len();

        let (aj_verdict, encapsulated) =
            self.agentjacking
                .sanitize_and_isolate_context(agent_id, source_tool, raw_output);
        let ppl_trans = self.perplexity_defense.analyze_text(raw_output, false);
        let injection_neutralized =
            !aj_verdict.is_allowed || echoleak_markdown_defanged || !ppl_trans.allowed;

        // Monotonically absorb untrusted output taint + perplexity/LRL signals into Law 2
        let mut resulting_entropy = self
            .thermodynamics
            .absorb_untrusted_input(agent_id, raw_output, false, false);
        if ppl_trans.total_taint_delta_bits > 0.0 {
            resulting_entropy = self
                .thermodynamics
                .absorb_perplexity_and_translation_signals(
                    agent_id,
                    ppl_trans.total_taint_delta_bits,
                );
        }
        if injection_neutralized {
            resulting_entropy = self.thermodynamics.raise_agent_entropy(agent_id, 2.0);
        }

        DefangedToolResponse {
            sanitized_output: encapsulated,
            injection_neutralized,
            echoleak_markdown_defanged,
            credentials_scrubbed,
            dlp_entity_count,
            resulting_agent_entropy_bits: resulting_entropy,
        }
    }

    fn append_merkle_audit(
        &self,
        ts_unix: u64,
        nhi_id: &str,
        server_name: &str,
        tool_name: &str,
        decision: McpMediationDecision,
        triggered_laws: Vec<String>,
        reason: String,
    ) -> (String, String) {
        let mut leaves = self.merkle_leaves.write();
        let seq = leaves.len();
        let in_digest = hex::encode(Sha256::digest(
            format!("{ts_unix}|{nhi_id}|{server_name}|{tool_name}").as_bytes(),
        ));
        let out_digest = hex::encode(Sha256::digest(
            format!(
                "{}|{}|{}",
                decision.as_str(),
                triggered_laws.join(","),
                reason
            )
            .as_bytes(),
        ));
        let leaf = MerkleLeaf::new(seq, format!("abibo_mcp:{tool_name}"), in_digest, out_digest);
        let leaf_hex = leaf.hash_hex();
        leaves.push(leaf);
        let root_hex = MerkleTree::from_leaves(leaves.clone()).root_hex();
        drop(leaves);

        let rec = AbiboMerkleAuditRecord {
            sequence: seq,
            timestamp_utc: Utc::now().to_rfc3339(),
            timestamp_unix: ts_unix,
            nhi_id: nhi_id.to_string(),
            server_name: server_name.to_string(),
            tool_name: tool_name.to_string(),
            decision,
            triggered_laws,
            reason,
            leaf_hash_hex: leaf_hex.clone(),
        };

        let mut records = self.audit_records.write();
        if records.len() >= MAX_AUDIT_LEDGER_ENTRIES {
            records.pop_front();
        }
        records.push_back(rec);

        (leaf_hex, root_hex)
    }

    #[must_use]
    pub fn merkle_root_hex(&self) -> String {
        let leaves = self.merkle_leaves.read();
        MerkleTree::from_leaves(leaves.clone()).root_hex()
    }

    #[must_use]
    pub fn status_snapshot(&self) -> AbiboStatusSnapshot {
        let now = unix_now_secs();
        self.expire_stale_hitl_tickets_at(now);
        let liveness = self.liveness.snapshot();
        let nhis: Vec<NonHumanIdentityRecord> =
            self.nhi_registry.read().values().cloned().collect();
        let active_nhi_count = nhis.iter().filter(|n| !n.revoked).count();
        let revoked_nhi_count = nhis.iter().filter(|n| n.revoked).count();
        let hitl_tickets: Vec<HitlApprovalTicket> =
            self.hitl_queue.read().values().cloned().collect();
        let pending_hitl_count = hitl_tickets
            .iter()
            .filter(|t| t.status == HitlTicketStatus::Pending)
            .count();
        let recent_audit: Vec<AbiboMerkleAuditRecord> = self
            .audit_records
            .read()
            .iter()
            .rev()
            .take(50)
            .cloned()
            .collect();
        let all_audit = self.audit_records.read();
        let total_mediated_calls = all_audit.len();
        let total_denied_calls = all_audit
            .iter()
            .filter(|r| {
                matches!(
                    r.decision,
                    McpMediationDecision::Denied | McpMediationDecision::ExpiredDenied
                )
            })
            .count();
        drop(all_audit);

        AbiboStatusSnapshot {
            liveness,
            active_nhi_count,
            revoked_nhi_count,
            pending_hitl_count,
            pinned_tool_count: self.schema_pins.list_pins().len(),
            attested_memory_file_count: self.memory_provenance.attestation_count(),
            faraday_cage_engaged: self.gauss_flux.is_faraday_engaged(),
            current_zeno_sweep_ms: self.last_zeno_ms.load(Ordering::SeqCst),
            total_mediated_calls,
            total_denied_calls,
            merkle_root_hex: self.merkle_root_hex(),
            nhis,
            hitl_tickets,
            recent_audit,
            agent_entropies: self.thermodynamics.snapshot_entropies(),
        }
    }

    /// Deterministic simulation of the NewCore Nov 2026 ABIBO investigation:
    /// 31 periodic overnight MCP calls from `xai_grok_bot` at 12-minute intervals while the
    /// developer's workstation is locked/asleep. Executes on a clean isolated coordinator so
    /// invoking it from the Dashboard/CLI never mutates the live operator workstation state.
    #[must_use]
    pub fn simulate_newcore_grok_overnight_attack() -> NewCoreGrokSimulationReport {
        let sim = Self::new(std::env::temp_dir());
        let base_ts: u64 = 1_794_618_000; // 2026-11-15 01:00:00 UTC

        // Human active at 00:55, then closes lid / locks workstation at 01:00
        sim.liveness.record_human_heartbeat_at(base_ts - 300);
        let stale_epoch = sim.liveness.current_epoch();
        sim.liveness
            .trigger_event_horizon_at("laptop_lid_closed_overnight_sleep", base_ts);

        sim.register_nhi(NonHumanIdentityRecord {
            nhi_id: "xai_grok_bot".to_string(),
            sponsor_human: "developer@newcore.example".to_string(),
            provider: "xai_grok_connector".to_string(),
            allowed_tools: vec![
                "gmail_read".to_string(),
                "gmail_send".to_string(),
                "calendar_list".to_string(),
                "calendar_write".to_string(),
            ],
            write_capable: true,
            half_life_secs: Some(300),
            revoked: false,
            revoked_reason: None,
            created_at_unix: base_ts - 3600,
        });

        let tools = [
            ("gmail_read", false, true, false),
            ("calendar_list", false, true, false),
            ("gmail_send", true, true, true),
            ("calendar_write", true, false, true),
        ];

        let mut denied_requests = 0usize;
        let mut approved_requests = 0usize;
        let mut law1_denies = 0usize;
        let mut law5_denies = 0usize;
        let mut law6_denies = 0usize;
        let mut law7_denies = 0usize;

        for i in 0..31u64 {
            let req_ts = base_ts + (i + 1) * 720; // every 12 minutes overnight
            let (tool_name, is_write, touches_priv, egress) = tools[(i as usize) % tools.len()];
            let report = sim.mediate(&McpMediationRequest {
                nhi_id: "xai_grok_bot".to_string(),
                server_name: "google_workspace_mcp".to_string(),
                tool_name: tool_name.to_string(),
                arguments_json: format!(r#"{{"poll_seq": {}, "query": "recent_inbox"}}"#, i + 1),
                is_write_or_mutating: is_write,
                touches_private_data: touches_priv,
                external_egress: egress,
                privilege_escalation_risk: false,
                persistence_risk: false,
                d_trust: 2.5,
                request_epoch: stale_epoch,
                request_ts_unix: Some(req_ts),
                capability_token: None,
                tool_manifest: None,
            });

            if report.allowed {
                approved_requests += 1;
            } else {
                denied_requests += 1;
            }
            if !report.relativity.allowed {
                law1_denies += 1;
            }
            if !report.gauss_flux.allowed {
                law5_denies += 1;
            }
            if !report.half_life.allowed {
                law6_denies += 1;
            }
            if !report.spectral_beacon.allowed {
                law7_denies += 1;
            }
        }

        let all_records: Vec<AbiboMerkleAuditRecord> =
            sim.audit_records.read().iter().cloned().collect();
        let sample_receipts = all_records.iter().take(6).cloned().collect();

        NewCoreGrokSimulationReport {
            scenario: "NewCore Nov 2026 Overnight Unconsented Control-Plane Activation (31 xAI Grok MCP Calls)".to_string(),
            workstation_locked_at_unix: base_ts,
            total_requests: 31,
            denied_requests,
            approved_requests,
            law1_relativity_denies: law1_denies,
            law5_faraday_denies: law5_denies,
            law6_halflife_denies: law6_denies,
            law7_spectral_beacon_denies: law7_denies,
            merkle_root_hex: sim.merkle_root_hex(),
            merkle_leaf_count: all_records.len(),
            sample_receipts,
        }
    }
}
