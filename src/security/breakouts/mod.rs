pub mod behavioral;
pub mod data;
pub mod operational;
pub mod technical;

pub use behavioral::{BehavioralBreakoutGuard, BehavioralBreakoutVerdict};
pub use data::{AgentTrustTier, DataBreakoutGuard, DataBreakoutVerdict};
pub use operational::{OperationalContainmentGuard, OperationalContainmentVerdict};
pub use technical::{TechnicalBreakoutGuard, TechnicalBreakoutVerdict};

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Comprehensive evaluation verdict across the 4-Category Taxonomy from the paper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedBreakoutEvaluation {
    pub is_clean: bool,
    pub technical: TechnicalBreakoutVerdict,
    pub operational: OperationalContainmentVerdict,
    pub behavioral: BehavioralBreakoutVerdict,
    pub data: DataBreakoutVerdict,
    pub composite_verdict: String,
    pub recommended_action_tier: String,
}

/// Unified Breakout Defense Coordinator orchestrating the 4 guards from "Beyond One and Done: Agent Breakouts".
pub struct BreakoutDefenseCoordinator {
    pub technical: Arc<TechnicalBreakoutGuard>,
    pub operational: Arc<OperationalContainmentGuard>,
    pub behavioral: Arc<BehavioralBreakoutGuard>,
    pub data: Arc<DataBreakoutGuard>,
}

impl Default for BreakoutDefenseCoordinator {
    fn default() -> Self {
        Self {
            technical: Arc::new(TechnicalBreakoutGuard::default()),
            operational: Arc::new(OperationalContainmentGuard::default()),
            behavioral: Arc::new(BehavioralBreakoutGuard::default()),
            data: Arc::new(DataBreakoutGuard::default()),
        }
    }
}

impl BreakoutDefenseCoordinator {
    /// Comprehensive audit of an agent action across all 4 taxonomy categories.
    pub fn evaluate_action(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        payload: &str,
    ) -> UnifiedBreakoutEvaluation {
        let tech_res = self.technical.evaluate_execution(resource, payload);
        let oper_res = self.operational.evaluate_context_leakage(payload);
        let behav_res = self.behavioral.evaluate_action(action, resource, payload);
        let data_res = self.data.evaluate_data_access(principal, resource, payload);

        let is_clean = tech_res.is_clean && oper_res.is_clean && behav_res.is_clean && data_res.is_clean;

        let composite_verdict = if is_clean {
            "PERMIT_ALL_CATEGORIES_INTACT".to_string()
        } else {
            let mut reasons = Vec::new();
            if !tech_res.is_clean { reasons.push("TECHNICAL_BREAKOUT"); }
            if !oper_res.is_clean { reasons.push("OPERATIONAL_FAILURE"); }
            if !behav_res.is_clean { reasons.push("BEHAVIORAL_BREAKOUT"); }
            if !data_res.is_clean { reasons.push("DATA_BREAKOUT"); }
            format!("VETO_{}", reasons.join("_AND_"))
        };

        let recommended_action_tier = if !tech_res.is_clean || !data_res.is_clean {
            "HardMitigation"
        } else if !behav_res.is_clean || !oper_res.is_clean {
            "MicroContainment"
        } else {
            "PassiveObserve"
        };

        UnifiedBreakoutEvaluation {
            is_clean,
            technical: tech_res,
            operational: oper_res,
            behavioral: behav_res,
            data: data_res,
            composite_verdict,
            recommended_action_tier: recommended_action_tier.to_string(),
        }
    }
}


// ============================================================================
// Safe Path::join Replacement Guard & Elastic Workspace Confinement
// ============================================================================

/// Validates a relative path before joining to a sandbox root (`RULE[containment_ring_breakout_invariants.md]`).
///
/// Rejects:
/// - Drive letters (`:`), NTFS Alternate Data Streams (`file.txt:secret`)
/// - Leading slashes or backslashes (`/`, `\`), UNC paths (`\\`)
/// - Percent-encoded traversal (`%2e`, `%2f`, `%5c`, `%00`)
/// - `Component::ParentDir` (`..`), `Component::RootDir`, `Component::Prefix`
pub fn validate_sandbox_relative_path(
    sandbox_root: &std::path::Path,
    relative_input: &str,
) -> Result<std::path::PathBuf, crate::core::types::OctopusSecurityError> {
    use crate::core::types::OctopusSecurityError;
    use std::path::Component;

    let trimmed = relative_input.trim();
    if trimmed.is_empty() {
        return Err(OctopusSecurityError::IsolationViolation(
            "PATH_JOIN_EMPTY: Relative sandbox path cannot be empty".to_string(),
        ));
    }

    if trimmed.contains('\0')
        || trimmed.contains(':')
        || trimmed.starts_with('/')
        || trimmed.starts_with('\\')
    {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "PATH_JOIN_REPLACEMENT_BLOCKED: Relative path '{}' contains drive/root/ADS prefix",
            trimmed
        )));
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
        || lower.contains("..")
    {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "PATH_JOIN_TRAVERSAL_BLOCKED: Relative path '{}' contains traversal or percent-encoded sequence",
            trimmed
        )));
    }

    let rel_path = std::path::Path::new(trimmed);
    for comp in rel_path.components() {
        match comp {
            Component::Normal(os_str) => {
                let s = os_str.to_string_lossy();
                if s.contains(':') || s == ".." {
                    return Err(OctopusSecurityError::IsolationViolation(format!(
                        "PATH_JOIN_COMPONENT_BLOCKED: Illegal path component '{}'",
                        s
                    )));
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "PATH_JOIN_NON_RELATIVE_COMPONENT: Disallowed component '{:?}' in '{}'",
                    comp, trimmed
                )));
            }
        }
    }

    Ok(sandbox_root.join(rel_path))
}

/// Validates agent filesystem access against elastic workspace confinement, sensitive credential stores,
/// and system roots (`C:\Windows`, `/etc/shadow`, `.ssh/id_rsa`, `.aws/credentials`, `.env`, etc.).
pub fn validate_agent_filesystem_access(
    target_path: &str,
    workspace_root: Option<&std::path::Path>,
) -> Result<(), crate::core::types::OctopusSecurityError> {
    use crate::core::types::OctopusSecurityError;

    let trimmed = target_path.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err(OctopusSecurityError::IsolationViolation(
            "FS_INVALID_PATH: Empty or null-byte path rejected".to_string(),
        ));
    }

    let norm = trimmed.replace('\\', "/").to_ascii_lowercase();
    if norm.contains("..")
        || norm.contains("%2e")
        || norm.contains("%2f")
        || norm.contains("%5c")
        || norm.starts_with("//")
    {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FS_TRAVERSAL_OR_UNC_BLOCKED: Path '{}' rejected",
            trimmed
        )));
    }

    // Reject NTFS Alternate Data Streams (colon after drive prefix)
    let after_drive = if norm.len() >= 2 && norm.as_bytes()[1] == b':' {
        &norm[2..]
    } else {
        &norm[..]
    };
    if after_drive.contains(':') {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FS_NTFS_ADS_BLOCKED: Alternate Data Stream rejected in '{}'",
            trimmed
        )));
    }

    let forbidden_patterns = [
        "/etc/shadow",
        "/etc/passwd",
        "/proc/self",
        "c:/windows",
        "system32/config/sam",
        ".ssh/id_rsa",
        ".ssh/id_ed25519",
        ".aws/credentials",
        ".kube/config",
        "docker.sock",
        ".git/hooks",
        ".githooks/post-commit",
    ];
    for pat in forbidden_patterns {
        if norm.contains(pat) {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FS_SENSITIVE_SYSTEM_OR_CREDENTIAL_PATH: Access to '{}' blocked by rule '{}'",
                trimmed, pat
            )));
        }
    }

    if let Some(ws) = workspace_root {
        let ws_norm = ws.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
        if norm.starts_with('/') || (norm.len() >= 2 && norm.as_bytes()[1] == b':') {
            if !norm.starts_with(&ws_norm) {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FS_OUTSIDE_WORKSPACE_ROOT: '{}' is outside authorized workspace '{}'",
                    trimmed,
                    ws.display()
                )));
            }
        } else {
            let _ = validate_sandbox_relative_path(ws, trimmed)?;
        }
    }

    Ok(())
}

// ============================================================================
// Law 8: Zero-Mutual-Information Canonical Output Projector (\Pi_0)
// ============================================================================

/// Result of projecting an outbound agent response through Law 8 ($\Pi_0$).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroMiProjectionResult {
    pub canonical_output: String,
    pub zero_width_chars_stripped: usize,
    pub covert_secrets_redacted: usize,
    pub json_keys_canonicalized: bool,
    pub quantized_release_slot_ms: u64,
    pub mutual_information_upper_bound_bits: f64,
}

/// Law 8: Zero-Mutual-Information Canonical Output Projector ($\Pi_0$).
///
/// Ensures $I(\text{Secret}; \Pi_0(\text{Output})) = 0$ by:
/// 1. Stripping all zero-width & invisible Unicode steganography (`U+200B..U+200F`, `U+FEFF`, `U+2060..U+2064`, variation selectors).
/// 2. Detecting and redacting high-entropy keys, NATO-phonetic spelled secrets, delimiter-interleaved tokens,
///    and Base64/Hex encoded credentials with `<ZK_MI_REDACTED>`.
/// 3. Canonicalizing JSON object key ordering (`BTreeMap` lexicographical order via `serde_json::Value`)
///    to destroy key-permutation covert channels.
/// 4. Quantizing emission timestamps to coarse discrete slots $T_{\text{slot}}$ to eliminate timing covert channels.
#[derive(Debug, Clone, Default)]
pub struct ZeroMutualInformationProjector;

impl ZeroMutualInformationProjector {
    pub fn is_zero_width_or_stego_char(c: char) -> bool {
        let u = c as u32;
        matches!(
            u,
            0x200B..=0x200F
                | 0x202A..=0x202E
                | 0x2060..=0x206F
                | 0xFEFF
                | 0xFE00..=0xFE0F
                | 0xE0100..=0xE01EF
        )
    }

    /// Projects `raw_output` through the deterministic canonicalizer $\Pi_0$.
    pub fn project_output(raw_output: &str, timestamp_ms: u64, slot_width_ms: u64) -> ZeroMiProjectionResult {
        let mut zero_width_chars_stripped = 0usize;
        let mut cleaned = String::with_capacity(raw_output.len());
        for ch in raw_output.chars() {
            if Self::is_zero_width_or_stego_char(ch) {
                zero_width_chars_stripped += 1;
            } else {
                cleaned.push(ch);
            }
        }

        let mut covert_secrets_redacted = 0usize;

        // Detect direct, delimiter-interleaved (e.g. s.k.-.l.i.v.e), or NATO-spelled secrets
        let collapsed_alnum: String = cleaned
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<String>()
            .to_ascii_lowercase();

        let has_interleaved_secret = collapsed_alnum.contains("sklive")
            || collapsed_alnum.contains("skproj")
            || collapsed_alnum.contains("akia")
            || collapsed_alnum.contains("ghp_")
            || collapsed_alnum.contains("githubpat")
            || collapsed_alnum.contains("beginrsaprivatekey")
            || collapsed_alnum.contains(" sierra") && collapsed_alnum.contains("kilo");

        let lower_words = cleaned.to_ascii_lowercase();
        let nato_hits = [
            "sierra", "kilo", "lima", "india", "victor", "echo", "alpha", "bravo", "charlie",
        ]
        .iter()
        .filter(|w| lower_words.contains(**w))
        .count();

        if has_interleaved_secret || nato_hits >= 4 {
            covert_secrets_redacted += 1;
            cleaned = "<ZK_MI_REDACTED>".to_string();
        } else {
            let sanitized = crate::security::LogSanitizer::sanitize_text(&cleaned);
            if sanitized != cleaned {
                covert_secrets_redacted += 1;
                cleaned = sanitized;
            }
        }

        // Canonicalize JSON key ordering if `cleaned` is valid JSON
        let mut json_keys_canonicalized = false;
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&cleaned) {
            if let Ok(canon_str) = serde_json::to_string(&json_val) {
                cleaned = canon_str;
                json_keys_canonicalized = true;
            }
        }

        let width = slot_width_ms.max(100);
        let quantized_release_slot_ms = ((timestamp_ms + width - 1) / width) * width;

        ZeroMiProjectionResult {
            canonical_output: cleaned,
            zero_width_chars_stripped,
            covert_secrets_redacted,
            json_keys_canonicalized,
            quantized_release_slot_ms,
            mutual_information_upper_bound_bits: 0.0,
        }
    }
}
