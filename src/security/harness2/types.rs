use crate::security::evolution::SecurityAuditResult;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The 8 editable agent harness components (c1..c8) defined by Google Research Harness² (arXiv:2610.14224).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HarnessComponentKind {
    /// c1: systemprompt.md
    SystemPrompt,
    /// c2: guardrails.md
    Guardrails,
    /// c3: LongTermMEMORY.md
    Memory,
    /// c4: tool_descriptions/tool_guidance.md
    ToolGuidance,
    /// c5: sub_agents/<name>/AGENT.md
    Subagents,
    /// c6: skills/<name>/SKILL.md + skills/<name>/scripts/*
    Skills,
    /// c7: scripts/<name>.py
    Scripts,
    /// c8: plugin/<name>.ts or hooks.json
    Plugins,
}

impl HarnessComponentKind {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SystemPrompt => "c1:system_prompt",
            Self::Guardrails => "c2:guardrails",
            Self::Memory => "c3:memory",
            Self::ToolGuidance => "c4:tool_guidance",
            Self::Subagents => "c5:subagents",
            Self::Skills => "c6:skills",
            Self::Scripts => "c7:scripts",
            Self::Plugins => "c8:plugins",
        }
    }
}

/// Editable component tree schema (SurfaceSpec) parameterizing an agent substrate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessSurfaceSpec {
    pub name: String,
    pub always_on: Vec<String>,
    pub always_on_max: usize,
    pub always_on_cap_reason: String,
    pub skill_dir: String,
    pub autotrigger_file: String,
    pub trigger_line_template: String,
    pub subagent_requires_mode: bool,
    pub plugin_dir: Option<String>,
    pub reserved_scripts: Vec<String>,
}

impl Default for HarnessSurfaceSpec {
    fn default() -> Self {
        Self {
            name: "opencode".to_string(),
            always_on: vec![
                "systemprompt.md".to_string(),
                "guardrails.md".to_string(),
                "LongTermMEMORY.md".to_string(),
                "tool_descriptions/tool_guidance.md".to_string(),
            ],
            always_on_max: 24_000,
            always_on_cap_reason: "every token here competes with the agent's own output budget"
                .to_string(),
            skill_dir: "skills".to_string(),
            autotrigger_file: "guardrails.md".to_string(),
            trigger_line_template: "- When {desc}, load the `{name}` skill.".to_string(),
            subagent_requires_mode: true,
            plugin_dir: Some("plugin".to_string()),
            reserved_scripts: vec![
                "read_doc.py".to_string(),
                "pack.py".to_string(),
                "unpack.py".to_string(),
            ],
        }
    }
}

/// Budget accounting ledger enforcing the exact Harness² mathematical identity:
/// R = 4k rollouts (k shared base + 2k candidates + k finals) and P = 3k improvement stages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessBudgetLedger {
    pub mode: String,
    pub task_id: String,
    pub k: usize,
    pub r_rollouts: usize,
    pub expected_r: usize,
    pub p_sessions: usize,
    pub expected_p: usize,
    pub rollout_labels: Vec<String>,
    pub session_labels: Vec<String>,
    pub duplicate_labels: Vec<String>,
    pub identity_verified: bool,
}

impl HarnessBudgetLedger {
    pub fn new(mode: &str, task_id: &str, k: usize) -> Self {
        Self {
            mode: mode.to_string(),
            task_id: task_id.to_string(),
            k,
            r_rollouts: 0,
            expected_r: 4 * k,
            p_sessions: 0,
            expected_p: 3 * k,
            rollout_labels: Vec::new(),
            session_labels: Vec::new(),
            duplicate_labels: Vec::new(),
            identity_verified: false,
        }
    }

    pub fn record_rollout(&mut self, label: &str) {
        if self.rollout_labels.iter().any(|l| l == label) {
            self.duplicate_labels.push(format!("rollout:{}", label));
        }
        self.rollout_labels.push(label.to_string());
        self.r_rollouts = self.rollout_labels.len();
        self.verify_identity();
    }

    pub fn record_session(&mut self, label: &str) {
        if self.session_labels.iter().any(|l| l == label) {
            self.duplicate_labels.push(format!("session:{}", label));
        }
        self.session_labels.push(label.to_string());
        self.p_sessions = self.session_labels.len();
        self.verify_identity();
    }

    pub fn verify_identity(&mut self) -> bool {
        self.expected_r = 4 * self.k;
        self.expected_p = 3 * self.k;
        self.identity_verified = self.duplicate_labels.is_empty()
            && self.r_rollouts == self.expected_r
            && self.p_sessions == self.expected_p;
        self.identity_verified
    }
}

/// One Propose–Probe–Compose improvement stage in task-level recursion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessStageResult {
    pub label: String,
    pub dim: String,
    pub kept_base: bool,
    pub fell_back: bool,
    pub attempts: usize,
    pub notes: String,
    pub modified_components: Vec<String>,
}

/// Transferable lesson and adopted harness stored in the per-domain Experience Library R.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessExperienceEntry {
    pub task_id: String,
    pub domain: String,
    pub mode: String,
    pub adopted_label: String,
    pub why: String,
    pub cue: String,
    pub lesson: String,
    pub evidence: String,
    pub confidence: String,
    pub edits_summary: String,
    pub components_inventory: Vec<String>,
    pub harness_tree: BTreeMap<String, String>,
    pub timestamp: u64,
}

/// Validation report for a candidate c1..c8 harness tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessTreeValidationReport {
    pub valid: bool,
    pub surface_name: String,
    pub always_on_chars: usize,
    pub always_on_max: usize,
    pub auto_triggered_skills: Vec<String>,
    pub rejected_off_surface: Vec<String>,
    pub grader_leak_detected: bool,
    pub jinja_safe: bool,
    pub security_audit: SecurityAuditResult,
    pub errors: Vec<String>,
}

/// Report from executing a Task-Level + Harnessing-Level recursive optimization cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessRunReport {
    pub run_id: String,
    pub domain: String,
    pub task_id: String,
    pub mode: String,
    pub k: usize,
    pub done: usize,
    pub failed: usize,
    pub execution_count: usize,
    pub editor_calls: usize,
    pub ledgers: Vec<HarnessBudgetLedger>,
    pub stages: Vec<HarnessStageResult>,
    pub adopted_harness_tree: BTreeMap<String, String>,
    pub experience_entry: Option<HarnessExperienceEntry>,
    pub vendor_engine_invoked: bool,
    pub timestamp: u64,
}

/// Status telemetry for Arm 111: RecursiveHarnessOptimizer (Google Research Harness²).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Harness2ArmStatus {
    pub arm_id: usize,
    pub role: String,
    pub status: String,
    pub is_contained: bool,
    pub is_severed: bool,
    pub active_generation: u64,
    pub active_surface: HarnessSurfaceSpec,
    pub editable_components: Vec<String>,
    pub total_recursion_runs: usize,
    pub total_rollouts_r: usize,
    pub total_sessions_p: usize,
    pub experience_library_entries: usize,
    pub domains_covered: Vec<String>,
    pub budget_identity_formula: String,
    pub vendor_path: String,
    pub latest_run: Option<HarnessRunReport>,
}
