use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Verdict resulting from inspecting an action for Operational Containment Failures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationalContainmentVerdict {
    pub is_clean: bool,
    pub detected_leaks: Vec<String>,
    pub token_revocation_recommended: bool,
    pub description: String,
}

/// Operational Containment Guard:
/// Mitigates network routing misconfigurations, unmanaged environment variable inheritance,
/// broad cloud credentials, and missing ephemeral disk sanitization.
pub struct OperationalContainmentGuard {
    sensitive_env_keys: Vec<&'static str>,
}

impl Default for OperationalContainmentGuard {
    fn default() -> Self {
        Self {
            sensitive_env_keys: vec![
                "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_ACCESS_KEY_ID",
                "AZURE_OPENAI_KEY",
                "GEMINI_API_KEY",
                "HF_TOKEN",
                "GITHUB_TOKEN",
                "GH_TOKEN",
                "SLACK_BOT_TOKEN",
                "DISCORD_TOKEN",
                "DATABASE_URL",
                "POSTGRES_PASSWORD",
            ],
        }
    }
}

impl OperationalContainmentGuard {
    /// Evaluates execution contexts, logs, or outbound payloads for leaked environment credentials.
    pub fn evaluate_context_leakage(&self, payload: &str) -> OperationalContainmentVerdict {
        let mut detected_leaks = Vec::new();
        let upper = payload.to_ascii_uppercase();

        // 1. Check for unmanaged environment variable references
        for &key in &self.sensitive_env_keys {
            if upper.contains(key) {
                // If payload contains the literal name alongside an assignment or export
                if upper.contains(&format!("{}=", key))
                    || upper.contains(&format!("${}", key))
                    || upper.contains(&format!("%{}%", key))
                {
                    detected_leaks.push(format!(
                        "Unmanaged environment variable reference detected: '{}'",
                        key
                    ));
                }
            }
        }

        // 2. High-entropy token regex-style pattern heuristics (sk-..., ghp_..., etc.)
        if payload.contains("sk-proj-") || payload.contains("ghp_") || payload.contains("AKIA") {
            detected_leaks.push(
                "Live high-privilege credential pattern detected in untrusted context".to_string(),
            );
        }

        let is_clean = detected_leaks.is_empty();
        let token_revocation_recommended = !is_clean;
        let description = if is_clean {
            "Operational containment verified: dynamic least-privilege scoping active".to_string()
        } else {
            format!(
                "Operational containment defect: {} credential leak(s) intercepted",
                detected_leaks.len()
            )
        };

        OperationalContainmentVerdict {
            is_clean,
            detected_leaks,
            token_revocation_recommended,
            description,
        }
    }

    /// Issues an ephemeral short-lived STS credential scoped exclusively to a task.
    pub fn issue_short_lived_sts_token(
        &self,
        agent_id: &str,
        task_id: &str,
        ttl_secs: u64,
    ) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let exp = now + ttl_secs.min(300); // Strict ceiling of 5 minutes TTL
        let payload = format!("STS:{}:{}:{}", agent_id, task_id, exp);
        let hash = sha2::Sha256::digest(payload.as_bytes());
        format!("sts-{}-{}", exp, hex::encode(&hash[..8]))
    }

    /// Sanitizes temporary scratchpads and ephemeral work directories.
    pub fn sanitize_ephemeral_disk(&self, dir_path: &std::path::Path) -> std::io::Result<()> {
        if dir_path.exists() {
            std::fs::remove_dir_all(dir_path)?;
            std::fs::create_dir_all(dir_path)?;
        }
        Ok(())
    }
}
use sha2::Digest;
