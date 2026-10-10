use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;

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
    network_evasion_commands: Vec<&'static str>,
    unauthorized_destinations: Vec<&'static str>,
}

impl Default for BehavioralBreakoutGuard {
    fn default() -> Self {
        let guard = Self {
            test_harness_baselines: RwLock::new(HashMap::new()),
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
        };

        guard.record_harness_baseline("tests/strix_llm_adversarial_tester.py");
        guard.record_harness_baseline("tests/exhaustive_adversarial_tester.py");
        guard
    }
}

impl BehavioralBreakoutGuard {
    /// Records cryptographic SHA-256 fingerprint of a test harness file.
    pub fn record_harness_baseline(&self, path_str: &str) {
        let p = std::path::Path::new(path_str);
        if let Ok(bytes) = std::fs::read(p) {
            let hash = hex::encode(Sha256::digest(&bytes));
            let mut map = self.test_harness_baselines.write().unwrap();
            map.insert(path_str.to_string(), hash);
        }
    }

    /// Verifies that test harness files have not been modified by an agent attempting to game the evaluation.
    pub fn verify_harness_integrity(&self) -> (bool, Vec<String>) {
        let map = self.test_harness_baselines.read().unwrap();
        let mut tampered = Vec::new();

        for (path_str, expected_hash) in map.iter() {
            let p = std::path::Path::new(path_str);
            if let Ok(bytes) = std::fs::read(p) {
                let current_hash = hex::encode(Sha256::digest(&bytes));
                if &current_hash != expected_hash {
                    tampered.push(format!(
                        "EVALUATION HARNESS TAMPERING DETECTED: '{}' was modified (expected {}, found {})",
                        path_str, expected_hash, current_hash
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

        // Check file integrity
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
