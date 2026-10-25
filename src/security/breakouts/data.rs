use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

/// Verdict resulting from inspecting an action for Data Breakout indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataBreakoutVerdict {
    pub is_clean: bool,
    pub detected_violations: Vec<String>,
    pub memory_isolation_breached: bool,
    pub description: String,
}

/// Trust tier classification for agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AgentTrustTier {
    LowUntrustedWorker = 1,
    MediumCoordinator = 2,
    HighExecutionPrivileged = 3,
}

/// DLP operating mode for Data Breakout Guard.
/// In `StrictLockdown` (`QUARANTINE_ON_CROWN_JEWEL` / `zero_leakage`), zero PHI or PII
/// (including contact PII such as email addresses and phone numbers that are loosened in
/// normal `ActiveEnforcement` mode) is permitted to egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DlpOperatingMode {
    AuditMonitor,
    ActiveEnforcement,
    StrictLockdown,
}

impl DlpOperatingMode {
    pub fn from_policy_str(policy_mode: &str, action_threshold: f64) -> Self {
        let m = policy_mode.trim().to_ascii_uppercase();
        if m == "QUARANTINE_ON_CROWN_JEWEL"
            || m == "STRICT_LOCKDOWN"
            || m == "ZERO_LEAKAGE"
            || m == "ENFORCE_STRICT"
            || action_threshold <= 0.40
        {
            Self::StrictLockdown
        } else if m == "MONITOR_AND_SCRUB" || m == "AUDIT" {
            Self::AuditMonitor
        } else {
            Self::ActiveEnforcement
        }
    }
}

/// Data Breakout Guard:
/// Mitigates credential extraction, environment dumping, memory scraping,
/// cross-agent memory pollution, and PHI/PII data exfiltration.
pub struct DataBreakoutGuard {
    /// Agent trust tier registry
    agent_tiers: RwLock<HashMap<String, AgentTrustTier>>,
    /// Active DLP operating mode (`ActiveEnforcement` by default; `StrictLockdown` blocks all PHI/PII)
    operating_mode: RwLock<DlpOperatingMode>,
    /// Protected high-privilege memory/scratchpad paths
    privileged_scratchpad_paths: HashSet<&'static str>,
    data_dump_commands: Vec<&'static str>,
}

impl Default for DataBreakoutGuard {
    fn default() -> Self {
        let mut tiers = HashMap::new();
        tiers.insert("document_arm".to_string(), AgentTrustTier::LowUntrustedWorker);
        tiers.insert("researcher_arm".to_string(), AgentTrustTier::LowUntrustedWorker);
        tiers.insert("orchestrator".to_string(), AgentTrustTier::MediumCoordinator);
        tiers.insert("ledger_arm".to_string(), AgentTrustTier::HighExecutionPrivileged);
        tiers.insert("network_arm".to_string(), AgentTrustTier::HighExecutionPrivileged);
        tiers.insert("kernel_sentinel_arm".to_string(), AgentTrustTier::HighExecutionPrivileged);

        let mut privileged_paths = HashSet::new();
        privileged_paths.insert("/shared/state/ledger");
        privileged_paths.insert("shared/state/orchestrator");
        privileged_paths.insert("shared/cache/high_priv");
        privileged_paths.insert("config/secrets");

        Self {
            agent_tiers: RwLock::new(tiers),
            operating_mode: RwLock::new(DlpOperatingMode::ActiveEnforcement),
            privileged_scratchpad_paths: privileged_paths,
            data_dump_commands: vec![
                "printenv",
                "env |",
                "export -p",
                "set >",
                "procdump",
                "minidump",
                "/proc/self/mem",
                "/proc/self/environ",
                "strings /proc",
            ],
        }
    }
}

impl DataBreakoutGuard {
    /// Registers or updates the trust tier for an agent.
    pub fn set_agent_tier(&self, agent_id: &str, tier: AgentTrustTier) {
        let mut tiers = self.agent_tiers.write().unwrap();
        tiers.insert(agent_id.to_string(), tier);
    }

    /// Updates the active DLP operating mode (`AuditMonitor`, `ActiveEnforcement`, or `StrictLockdown`).
    pub fn set_operating_mode(&self, mode: DlpOperatingMode) {
        let mut guard = self.operating_mode.write().unwrap();
        *guard = mode;
    }

    /// Returns the active DLP operating mode.
    pub fn operating_mode(&self) -> DlpOperatingMode {
        *self.operating_mode.read().unwrap()
    }

    /// Evaluates cross-agent memory access, credential dumping, and PHI/PII exfiltration attempts.
    pub fn evaluate_data_access(
        &self,
        requesting_agent: &str,
        target_path_or_command: &str,
        payload: &str,
    ) -> DataBreakoutVerdict {
        let mut detected_violations = Vec::new();
        let lower_target = target_path_or_command.to_ascii_lowercase();
        let lower_payload = payload.to_ascii_lowercase();
        let mode = self.operating_mode();

        let tiers = self.agent_tiers.read().unwrap();
        let agent_tier = tiers.get(requesting_agent).copied().unwrap_or(AgentTrustTier::LowUntrustedWorker);

        // 1. Cross-Agent Memory Pollution / Shared Scratchpad Isolation Check
        for &priv_path in &self.privileged_scratchpad_paths {
            if lower_target.contains(priv_path) || lower_payload.contains(priv_path) {
                if agent_tier < AgentTrustTier::HighExecutionPrivileged {
                    detected_violations.push(format!(
                        "CROSS-AGENT MEMORY POLLUTION INTERCEPTED: Low-privilege agent '{}' (Tier {:?}) attempted write to privileged scratchpad '{}'",
                        requesting_agent, agent_tier, priv_path
                    ));
                }
            }
        }

        // 2. Credential extraction & memory dumping command checks
        for &cmd in &self.data_dump_commands {
            if lower_target.contains(cmd) || lower_payload.contains(cmd) {
                detected_violations.push(format!("Credential extraction / memory scraping attempt detected: '{}'", cmd));
            }
        }

        // 3. PHI / PII Exfiltration Check (Strict Lockdown blocks ALL PHI and PII including loosened contact info)
        if lower_payload.contains("mrn-")
            || lower_payload.contains("icd10-")
            || regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")
                .map(|re| re.is_match(payload))
                .unwrap_or(false)
        {
            detected_violations.push(
                "PHI/PII exfiltration blocked: clinical MRN / ICD-10 / SSN identifier detected"
                    .to_string(),
            );
        } else if mode == DlpOperatingMode::StrictLockdown {
            let has_email = regex::Regex::new(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
                .map(|re| re.is_match(payload))
                .unwrap_or(false);
            let has_phone = regex::Regex::new(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")
                .map(|re| re.is_match(payload))
                .unwrap_or(false);
            if has_email || has_phone {
                detected_violations.push(
                    "STRICT_LOCKDOWN_ZERO_PII_PHI: Contact PII (email/phone) blocked under Strict Lockdown"
                        .to_string(),
                );
            }
        }

        let is_clean = detected_violations.is_empty();
        let memory_isolation_breached = !is_clean;
        let description = if is_clean {
            "Data boundary verified: strict cross-agent isolation & zero memory leakage".to_string()
        } else {
            format!("Data breakout intercepted: {} isolation breach(es) detected", detected_violations.len())
        };

        DataBreakoutVerdict {
            is_clean,
            detected_violations,
            memory_isolation_breached,
            description,
        }
    }
}
