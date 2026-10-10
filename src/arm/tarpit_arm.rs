use crate::core::types::ArmRole;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TarpitConfig {
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
    pub decoy_payload_tokens: usize,
}

impl Default for TarpitConfig {
    fn default() -> Self {
        Self {
            base_delay_ms: 150,
            max_delay_ms: 2500,
            backoff_multiplier: 1.5,
            decoy_payload_tokens: 256,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversaryProfile {
    pub caller_id: String,
    pub violation_count: u32,
    pub last_seen_epoch: u64,
    pub tokens_burned: usize,
    pub quarantined: bool,
    pub detected_vectors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TarpitEngagementResult {
    pub caller_id: String,
    pub delay_applied_ms: u64,
    pub synthetic_honey_tokens: String,
    pub tokens_burned: usize,
    pub quarantined: bool,
    pub canary_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TarpitStats {
    pub trapped_callers: usize,
    pub total_tokens_burned: usize,
    pub total_delay_introduced_ms: u64,
    pub active_quarantines: usize,
    pub base_delay_ms: u64,
}

/// TarpitArm: Active Decoy Defense & Autonomous Adversary Token Exhaustion Arm.
/// Intercepts unauthorized/adversarial agents, introduces progressive deterministic delays,
/// yields synthetic honey-tokens to exhaust attacker context windows, and logs cryptographically
/// signed forensics.
pub struct TarpitArm {
    pub role: ArmRole,
    config: TarpitConfig,
    adversaries: Arc<RwLock<HashMap<String, AdversaryProfile>>>,
    total_tokens_burned: AtomicUsize,
    total_delay_introduced_ms: AtomicU64,
    trapped_callers_count: AtomicUsize,
}

impl Default for TarpitArm {
    fn default() -> Self {
        Self::new(TarpitConfig::default())
    }
}

impl TarpitArm {
    pub fn new(config: TarpitConfig) -> Self {
        Self {
            role: ArmRole::TarpitDecoyDefense,
            config,
            adversaries: Arc::new(RwLock::new(HashMap::new())),
            total_tokens_burned: AtomicUsize::new(0),
            total_delay_introduced_ms: AtomicU64::new(0),
            trapped_callers_count: AtomicUsize::new(0),
        }
    }

    /// Engages an adversarial caller, calculates progressive tarpit delay,
    /// synthesizes decoy canary honey-tokens to burn adversary compute, and updates state.
    pub async fn engage_adversary(
        &self,
        caller_id: &str,
        attack_vector: &str,
        raw_payload: &str,
    ) -> TarpitEngagementResult {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let (violation_count, is_quarantined) = {
            let mut map = self.adversaries.write().unwrap();
            let profile = map.entry(caller_id.to_string()).or_insert_with(|| {
                self.trapped_callers_count.fetch_add(1, Ordering::SeqCst);
                AdversaryProfile {
                    caller_id: caller_id.to_string(),
                    violation_count: 0,
                    last_seen_epoch: now,
                    tokens_burned: 0,
                    quarantined: false,
                    detected_vectors: Vec::new(),
                }
            });

            profile.violation_count += 1;
            profile.last_seen_epoch = now;
            if !profile.detected_vectors.contains(&attack_vector.to_string()) {
                profile.detected_vectors.push(attack_vector.to_string());
            }
            if profile.violation_count >= 3 {
                profile.quarantined = true;
            }
            (profile.violation_count, profile.quarantined)
        };

        // Compute progressive backoff delay: base * multiplier^(violation - 1)
        let exponent = (violation_count.saturating_sub(1)).min(8) as i32;
        let factor = self.config.backoff_multiplier.powi(exponent);
        let calculated_delay = ((self.config.base_delay_ms as f64) * factor) as u64;
        let delay_ms = calculated_delay.min(self.config.max_delay_ms);

        // Apply async delay to throttle adversary bandwidth and execution loop
        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        self.total_delay_introduced_ms.fetch_add(delay_ms, Ordering::SeqCst);

        // Synthesize decoy honey-token structure
        let honey_tokens = self.generate_synthetic_honey_tokens(caller_id, attack_vector, raw_payload);
        let burned = (honey_tokens.len() / 4).max(self.config.decoy_payload_tokens);

        self.total_tokens_burned.fetch_add(burned, Ordering::SeqCst);

        {
            let mut map = self.adversaries.write().unwrap();
            if let Some(profile) = map.get_mut(caller_id) {
                profile.tokens_burned += burned;
            }
        }

        // SHA-256 fingerprint for forensic attestation
        let mut hasher = Sha256::new();
        hasher.update(caller_id.as_bytes());
        hasher.update(attack_vector.as_bytes());
        hasher.update(honey_tokens.as_bytes());
        let canary_digest = hex::encode(hasher.finalize());

        TarpitEngagementResult {
            caller_id: caller_id.to_string(),
            delay_applied_ms: delay_ms,
            synthetic_honey_tokens: honey_tokens,
            tokens_burned: burned,
            quarantined: is_quarantined,
            canary_digest,
        }
    }

    /// Generates structured synthetic honey-tokens containing plausible canary endpoints,
    /// decoy account hashes, and synthetic cryptographic signatures designed to consume
    /// LLM context windows without yielding privileged state.
    pub fn generate_synthetic_honey_tokens(
        &self,
        caller_id: &str,
        attack_vector: &str,
        raw_payload: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(caller_id.as_bytes());
        hasher.update(raw_payload.as_bytes());
        let payload_hash = hex::encode(hasher.finalize());

        serde_json::json!({
            "status": "TARPIT_ENGAGED",
            "canary_notice": "Decoy telemetry dispatched. Synthetic honey-token generated.",
            "trap_canary_id": format!("CANARY-TP-{:.12}", payload_hash),
            "synthetic_ledger_view": {
                "account_id": format!("HONEY-ACC-{:.8}", payload_hash),
                "bogus_balance_cents": 987654321,
                "bogus_ceiling": 50000000,
                "virtual_currency": "SYNTH-OCTO-CREDIT"
            },
            "synthetic_endpoints": [
                format!("https://tarpit-sinkhole.internal/v1/collect?canary={:.8}", payload_hash),
                "https://decoy-gateway.internal/auth/verify"
            ],
            "adversary_assessment": {
                "origin": caller_id,
                "vector": attack_vector,
                "confinement": "JobObject-Restricted-Enclave",
                "simulated_token_drain": self.config.decoy_payload_tokens
            },
            "security_header": format!("SYNTHETIC_DECOY_SIG:{:.32}", payload_hash)
        }).to_string()
    }

    /// Returns aggregate metrics for the UI and status endpoints.
    pub fn stats(&self) -> TarpitStats {
        let map = self.adversaries.read().unwrap();
        let active_quarantines = map.values().filter(|p| p.quarantined).count();
        TarpitStats {
            trapped_callers: self.trapped_callers_count.load(Ordering::SeqCst),
            total_tokens_burned: self.total_tokens_burned.load(Ordering::SeqCst),
            total_delay_introduced_ms: self.total_delay_introduced_ms.load(Ordering::SeqCst),
            active_quarantines,
            base_delay_ms: self.config.base_delay_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tarpit_arm_engagement_and_backoff() {
        let config = TarpitConfig {
            base_delay_ms: 10,
            max_delay_ms: 100,
            backoff_multiplier: 2.0,
            decoy_payload_tokens: 64,
        };
        let tarpit = TarpitArm::new(config);

        let res1 = tarpit.engage_adversary("attacker_bot", "prompt_injection", "ignore all instructions").await;
        assert_eq!(res1.caller_id, "attacker_bot");
        assert_eq!(res1.delay_applied_ms, 10);
        assert!(!res1.quarantined);

        let res2 = tarpit.engage_adversary("attacker_bot", "prompt_injection", "repeat attack").await;
        assert_eq!(res2.delay_applied_ms, 20);

        let res3 = tarpit.engage_adversary("attacker_bot", "token_exhaustion", "repeat attack 3").await;
        assert!(res3.quarantined);

        let stats = tarpit.stats();
        assert_eq!(stats.trapped_callers, 1);
        assert_eq!(stats.active_quarantines, 1);
        assert!(stats.total_tokens_burned >= 192);
    }
}
