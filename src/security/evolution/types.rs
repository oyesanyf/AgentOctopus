use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionState {
    QuarantinedPendingHitl,
    ApprovedActive,
    Rejected,
    VetoedInvariantViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMetrics {
    pub combined_score: f64,
    pub coverage_score: f64,
    pub false_positive_rate: f64,
    pub reproducibility: f64,
    pub latency_ms: f64,
    pub security_clean: bool,
}

impl Default for EvolutionMetrics {
    fn default() -> Self {
        Self {
            combined_score: 0.0,
            coverage_score: 0.0,
            false_positive_rate: 0.0,
            reproducibility: 1.0,
            latency_ms: 0.0,
            security_clean: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditResult {
    pub passed: bool,
    pub violations: Vec<String>,
    pub audited_tokens: usize,
    pub audit_timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionCandidate {
    pub candidate_id: String,
    pub target_module: String,
    pub target_path: String,
    pub generation: usize,
    pub created_at: u64,
    pub metrics: EvolutionMetrics,
    pub security_audit: SecurityAuditResult,
    pub promotion_state: PromotionState,
    pub code_diff: String,
    pub source_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionJobStatus {
    pub job_id: String,
    pub target_module: String,
    pub status: String,
    pub current_generation: usize,
    pub max_iterations: usize,
    pub baseline_score: f64,
    pub best_score: f64,
    pub staged_candidates_count: usize,
    pub start_time: u64,
    pub last_update: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionArmStatus {
    pub arm_id: usize,
    pub role: String,
    pub status: String,
    pub is_contained: bool,
    pub is_severed: bool,
    pub active_generation: u64,
    pub whitelisted_modules: Vec<String>,
    pub total_candidates_evaluated: usize,
    pub total_candidates_staged: usize,
    pub total_promotions_approved: usize,
    pub active_job: Option<EvolutionJobStatus>,
    pub best_pareto_score: f64,
}
