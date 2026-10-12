use serde::{Deserialize, Serialize};

/// Target configuration for protocol research evaluations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchTarget {
    pub host: String,
    pub port: u16,
    pub scheme: String,
}

impl Default for ResearchTarget {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 5005,
            scheme: "http".to_string(),
        }
    }
}

/// DTO for an RFC document or normative fragment stored in the separate Octopus DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RfcChunkDto {
    pub id: i64,
    pub rfc_number: u32,
    pub title: String,
    pub chunk_index: usize,
    pub content: String,
    pub is_normative: bool,
}

/// DTO for candidate HTTP probes synthesized from RFC specifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateProbeDto {
    pub id: String,
    pub rfc_number: u32,
    pub raw_request: String,
    pub mutation_type: String,
    pub hypothesis: String,
    pub status: String,
}

/// Classification tiers for research discoveries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResearchFindingStatus {
    HeuristicAnomaly,
    ReproducibleDivergence,
    LaboratoryResearchFinding,
    IndependentlyValidated,
}

impl ToString for ResearchFindingStatus {
    fn to_string(&self) -> String {
        match self {
            Self::HeuristicAnomaly => "HEURISTIC_ANOMALY".to_string(),
            Self::ReproducibleDivergence => "REPRODUCIBLE_DIVERGENCE".to_string(),
            Self::LaboratoryResearchFinding => "LABORATORY_RESEARCH_FINDING".to_string(),
            Self::IndependentlyValidated => "INDEPENDENTLY_VALIDATED".to_string(),
        }
    }
}

/// Structured finding produced by Arm 107 research probes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchFinding {
    pub finding_id: String,
    pub probe_id: String,
    pub is_anomalous: bool,
    pub finding_status: String,
    pub details: String,
    pub baseline_subtracted: bool,
    pub raw_response: String,
    pub confirmation_count: u32,
}

/// Structured handoff from Arm 107 (Hypothesis/Probe) to Arm 106 (Differential Protocol Analyzer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Arm106ValidationHandoff {
    pub handoff_id: String,
    pub finding_id: String,
    pub candidate_probe: CandidateProbeDto,
    pub preliminary_tier: String,
    pub requires_independent_reproduction: bool,
    pub target_endpoints: Vec<String>,
}

/// Status and telemetry for Arm 107 Autonomous Protocol Research subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolResearchStatus {
    pub arm_role: String,
    pub containment_ring_id: usize,
    pub database_mode: String,
    pub database_path: String,
    pub is_database_isolated: bool,
    pub rfc_count: usize,
    pub fragment_count: usize,
    pub probe_count: usize,
    pub evaluations_recorded: usize,
    pub memory_clamp_mb: usize,
    pub cedar_policy_bound: String,
    pub dogwood_velocity_bound: String,
    pub active_worker_sandboxed: bool,
}

/// Incoming evaluation request submitted to Arm 107.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationRequest {
    pub raw_request: String,
    pub target_host: String,
    pub target_port: u16,
    pub baseline_request: Option<String>,
}
