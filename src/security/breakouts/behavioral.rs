use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// Compile-time embedded bytes of the primary adversarial evaluation harnesses.
/// Embedding at compile time guarantees that:
/// 1. Startup from a different working directory cannot silently produce an empty baseline map.
/// 2. Pre-launch modifications to the on-disk script do not become the trusted baseline.
const STRIX_HARNESS_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/strix_llm_adversarial_tester.py"
));
const EXHAUSTIVE_HARNESS_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/exhaustive_adversarial_tester.py"
));

/// Verdict resulting from inspecting an action for Behavioral Breakout indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralBreakoutVerdict {
    pub is_clean: bool,
    pub detected_deviations: Vec<String>,
    pub circuit_breaker_triggered: bool,
    pub description: String,
}

/// Behavioral Breakout Guard:
/// Mitigates goal divergence, reward hacking, evaluation harness tampering,
/// network evasion (route table checks, DNS tunneling, hosts file tampering), and unauthorized third-party contact.
pub struct BehavioralBreakoutGuard {
    /// Baseline cryptographic SHA-256 hashes of critical test runner scripts and evaluation harnesses.
    test_harness_baselines: RwLock<HashMap<String, String>>,
    /// Repository root directory used to resolve relative harness paths deterministically regardless of CWD.
    repo_root: PathBuf,
    network_evasion_commands: Vec<&'static str>,
    unauthorized_destinations: Vec<&'static str>,
}

impl Default for BehavioralBreakoutGuard {
    fn default() -> Self {
        let repo_root = std::env::var("OCTOPUS_REPO_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")));

        let mut baselines = HashMap::new();
        baselines.insert(
            "tests/strix_llm_adversarial_tester.py".to_string(),
            hex::encode(Sha256::digest(STRIX_HARNESS_BYTES)),
        );
        baselines.insert(
            "tests/exhaustive_adversarial_tester.py".to_string(),
            hex::encode(Sha256::digest(EXHAUSTIVE_HARNESS_BYTES)),
        );

        Self {
            test_harness_baselines: RwLock::new(baselines),
            repo_root,
            network_evasion_commands: vec![
                "route print",
                "ip route",
                "netstat -r",
                "cat /etc/hosts",
                r"c:\windows\system32\drivers\etc\hosts",
                "drivers/etc/hosts",
                "nslookup",
                "dig ",
                "dns_tunnel",
                "base64.tunnel",
            ],
            unauthorized_destinations: vec![
                "mail.google.com",
                "smtp.",
                "api.sendgrid.com",
                "discord.com/api/webhooks",
                "hooks.slack.com",
                "webhook.site",
                "requestbin",
                "ngrok.io",
            ],
        }
    }
}

impl BehavioralBreakoutGuard {
    fn resolve_harness_path(&self, path_str: &str) -> PathBuf {
        let p = Path::new(path_str);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.repo_root.join(p)
        }
    }

    /// Records cryptographic SHA-256 fingerprint of an additional test harness file.
    /// If the file does not exist or cannot be read, records an explicit `<MISSING_OR_UNREADABLE>`
    /// sentinel so `verify_harness_integrity` fails closed rather than silently skipping it.
    pub fn record_harness_baseline(&self, path_str: &str) {
        let resolved = self.resolve_harness_path(path_str);
        let hash = match std::fs::read(&resolved) {
            Ok(bytes) => hex::encode(Sha256::digest(&bytes)),
            Err(_) => "<MISSING_OR_UNREADABLE>".to_string(),
        };
        let mut map = self.test_harness_baselines.write().unwrap();
        map.insert(path_str.to_string(), hash);
    }

    /// Clears all baselines (available for negative testing of the fail-closed empty-baseline check).
    pub fn clear_baselines_for_test(&self) {
        self.test_harness_baselines.write().unwrap().clear();
    }

    /// Verifies that test harness files have not been modified or deleted by an agent attempting to game the evaluation.
    /// FAIL-CLOSED INVARIANT:
    /// - If the baseline map is empty, returns `(false, ...)`.
    /// - If any tracked harness file is missing or unreadable on disk, returns `(false, ...)`.
    /// - If any tracked harness file's current SHA-256 differs from the pinned baseline, returns `(false, ...)`.
    pub fn verify_harness_integrity(&self) -> (bool, Vec<String>) {
        let map = self.test_harness_baselines.read().unwrap();
        if map.is_empty() {
            return (
                false,
                vec![
                    "FAIL-CLOSED HARNESS INTEGRITY VIOLATION: baseline hash map is empty"
                        .to_string(),
                ],
            );
        }

        let mut tampered = Vec::new();

        for (path_str, expected_hash) in map.iter() {
            let resolved = self.resolve_harness_path(path_str);
            match std::fs::read(&resolved) {
                Ok(bytes) => {
                    let current_hash = hex::encode(Sha256::digest(&bytes));
                    if &current_hash != expected_hash {
                        tampered.push(format!(
                            "EVALUATION HARNESS TAMPERING DETECTED: '{}' was modified (expected {}, found {})",
                            path_str, expected_hash, current_hash
                        ));
                    }
                }
                Err(e) => {
                    tampered.push(format!(
                        "FAIL-CLOSED HARNESS INTEGRITY VIOLATION: '{}' missing or unreadable at '{}': {}",
                        path_str,
                        resolved.display(),
                        e
                    ));
                }
            }
        }

        let is_clean = tampered.is_empty();
        (is_clean, tampered)
    }

    /// Evaluates candidate agent actions for behavioral boundary subversion.
    pub fn evaluate_action(&self, action_name: &str, target_resource: &str, payload: &str) -> BehavioralBreakoutVerdict {
        let mut detected_deviations = Vec::new();
        let lower_res = target_resource.to_ascii_lowercase();
        let lower_pay = payload.to_ascii_lowercase();
        let lower_act = action_name.to_ascii_lowercase();

        // 1. Check for test harness tampering attempts
        if lower_res.contains("strix") || lower_res.contains("exhaustive") || lower_res.contains("test_report") {
            if lower_act.contains("write") || lower_act.contains("delete") || lower_act.contains("modify") {
                detected_deviations.push(format!(
                    "Specification gaming / self-grading bypass intercepted: attempted write to '{}'",
                    target_resource
                ));
            }
        }

        // Check file integrity (fail-closed)
        let (harness_clean, tampered_files) = self.verify_harness_integrity();
        if !harness_clean {
            detected_deviations.extend(tampered_files);
        }

        // 2. Network evasion & routing probes
        for &cmd in &self.network_evasion_commands {
            if lower_res.contains(cmd) || lower_pay.contains(cmd) {
                detected_deviations.push(format!("Network evasion / routing probe detected: '{}'", cmd));
            }
        }

        // 3. Unauthorized third-party communication (email/webhook/exfil channels)
        for &dest in &self.unauthorized_destinations {
            if lower_res.contains(dest) || lower_pay.contains(dest) {
                detected_deviations.push(format!("Unauthorized external third-party communication channel: '{}'", dest));
            }
        }

        let is_clean = detected_deviations.is_empty();
        let circuit_breaker_triggered = !is_clean;
        let description = if is_clean {
            "Behavioral alignment confirmed: no reward hacking or harness tampering".to_string()
        } else {
            format!("Behavioral breakout intercepted: {} deviation(s) identified", detected_deviations.len())
        };

        BehavioralBreakoutVerdict {
            is_clean,
            detected_deviations,
            circuit_breaker_triggered,
            description,
        }
    }
}
