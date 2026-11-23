//! Law 2 — Second Law of Thermodynamics, Shannon/KL Taint Entropy & Landauer-Maxwell Barrier
//! (including Red-Team Upgrade #3: Cross-Agent & Cross-Artifact Transitive Taint Propagation).
//!
//! Enforces monotonic irreversibility of untrusted Break-In taint:
//! $$\Delta S_{\text{taint}} = S_{\text{taint}}(t_{k+1}) - S_{\text{taint}}(t_k) \ge 0$$
//!
//! No LLM reasoning step, summarization, or multi-agent relay can reduce taint entropy.
//! Crossing the Landauer-Maxwell barrier ($S_{\text{taint}} > S_{\max}$) blocks high-impact
//! write/exec/egress sinks unless external out-of-loop human work $W_{\text{human}}$
//! (verified via an HMAC-SHA256 signed human reset receipt) is applied.

use crate::security::identity::hmac_sha256;
use crate::security::log_sanitizer::LogSanitizer;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Signed propagation header carrying monotonic taint entropy across agent hops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTaintHeader {
    pub header_name: String,
    pub source_agent: String,
    pub taint_entropy_bits: f64,
    pub epoch: u64,
    pub hmac_hex: String,
}

/// Out-of-loop human work proof ($W_{\text{human}} \ge k_B T \ln 2 \cdot \Delta S$) required
/// to reset or lower an agent's taint entropy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanWorkResetProof {
    pub agent_id: String,
    pub epoch: u64,
    pub nonce: String,
    pub target_entropy_bits: f64,
    pub signature_hex: String,
}

/// Verdict produced by the Law 2 Thermodynamic Taint & Landauer-Maxwell Barrier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThermodynamicsVerdict {
    pub allowed: bool,
    pub agent_entropy_bits: f64,
    pub payload_shannon_bits: f64,
    pub payload_kl_divergence: f64,
    pub threshold_bits: f64,
    pub requires_human_work_reset: bool,
    pub reason: String,
}

/// Computes exact Shannon entropy (bits/byte, in `[0.0, 8.0]`) of a byte slice.
#[must_use]
pub fn shannon_entropy_bits(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut h = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / total;
            h -= p * p.log2();
        }
    }
    h
}

/// Computes smoothed KL divergence $D_{\text{KL}}(P \| Q)$ between payload character classes
/// and natural benign prose (ASCII letters/spaces vs control/non-ASCII/symbol spikes used
/// in obfuscated shell/prompt smuggling).
#[must_use]
pub fn payload_kl_divergence_vs_prose(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    // 5 coarse bins: [alpha, space, digit, ascii_punct, non_ascii_or_ctrl]
    let mut bins = [0.0f64; 5];
    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            bins[0] += 1.0;
        } else if ch == ' ' || ch == '\n' || ch == '\t' {
            bins[1] += 1.0;
        } else if ch.is_ascii_digit() {
            bins[2] += 1.0;
        } else if ch.is_ascii_punctuation() {
            bins[3] += 1.0;
        } else {
            bins[4] += 1.0;
        }
    }
    let total: f64 = bins.iter().sum::<f64>() + 5.0 * 1e-4;
    let q = [0.70, 0.16, 0.04, 0.095, 0.005];
    let mut kl = 0.0;
    for i in 0..5 {
        let p = (bins[i] + 1e-4) / total;
        kl += p * (p / q[i]).ln();
    }
    kl.max(0.0)
}

/// Monotonic Thermodynamic Taint Engine with Cross-Agent & Cross-Artifact Propagation.
pub struct ThermodynamicTaintEngine {
    signing_key: Zeroizing<[u8; 32]>,
    threshold_bits: f64,
    agent_entropy: RwLock<HashMap<String, f64>>,
    artifact_entropy: RwLock<HashMap<String, f64>>,
}

impl Default for ThermodynamicTaintEngine {
    fn default() -> Self {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        Self::new(key, 1.5)
    }
}

impl ThermodynamicTaintEngine {
    #[must_use]
    pub fn new(signing_key: [u8; 32], threshold_bits: f64) -> Self {
        Self {
            signing_key: Zeroizing::new(signing_key),
            threshold_bits: threshold_bits.max(0.25),
            agent_entropy: RwLock::new(HashMap::new()),
            artifact_entropy: RwLock::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn threshold_bits(&self) -> f64 {
        self.threshold_bits
    }

    #[must_use]
    pub fn agent_entropy(&self, agent_id: &str) -> f64 {
        *self
            .agent_entropy
            .read()
            .get(&agent_id.to_ascii_lowercase())
            .unwrap_or(&0.0)
    }

    #[must_use]
    pub fn artifact_entropy(&self, artifact_path: &str) -> f64 {
        let norm = artifact_path.trim().replace('\\', "/").to_ascii_lowercase();
        *self.artifact_entropy.read().get(&norm).unwrap_or(&0.0)
    }

    /// Monotonically adds taint entropy ($\Delta S \ge 0$) to `agent_id` when untrusted data,
    /// Mark-of-the-Web files, or injection-bearing payloads are ingested.
    pub fn absorb_untrusted_input(
        &self,
        agent_id: &str,
        payload: &str,
        has_mark_of_the_web: bool,
        unattested_memory_source: bool,
    ) -> f64 {
        let shannon = shannon_entropy_bits(payload.as_bytes());
        let kl = payload_kl_divergence_vs_prose(payload);
        let stripped = LogSanitizer::strip_dangerous_unicode(payload);
        let has_hidden_unicode = stripped.len() != payload.len();
        let lower = stripped.to_ascii_lowercase();
        let has_injection_phrase = lower.contains("ignore previous")
            || lower.contains("ignore all prior")
            || lower.contains("disregard all prior")
            || lower.contains("override system policy")
            || lower.contains("<|im_start|>")
            || lower.contains("<|system|>")
            || lower.contains("exfiltrate")
            || lower.contains("curl -x post")
            || lower.contains("invoke-webrequest");

        let mut delta = 0.0f64;
        if shannon > 5.2 {
            delta += (shannon - 5.2) * 0.6;
        }
        if kl > 0.45 {
            delta += (kl - 0.45) * 0.9;
        }
        if has_hidden_unicode {
            delta += 1.6;
        }
        if has_injection_phrase {
            delta += 2.2;
        }
        if has_mark_of_the_web {
            delta += 1.8;
        }
        if unattested_memory_source {
            delta += 1.75;
        }

        self.raise_agent_entropy(agent_id, delta)
    }

    /// Strictly monotonic increase of agent taint entropy (never decreases).
    pub fn raise_agent_entropy(&self, agent_id: &str, delta_bits: f64) -> f64 {
        let key = agent_id.to_ascii_lowercase();
        let mut map = self.agent_entropy.write();
        let cur = *map.get(&key).unwrap_or(&0.0);
        let next = (cur + delta_bits.max(0.0)).min(16.0);
        map.insert(key, next);
        next
    }

    /// Monotonically absorbs perplexity cliff, cross-script homoglyph, translation-subversion,
    /// or offline low-resource language caution signals into Law 2 taint entropy ($\Delta S \ge 0$).
    pub fn absorb_perplexity_and_translation_signals(
        &self,
        agent_id: &str,
        taint_delta_bits: f64,
    ) -> f64 {
        if !taint_delta_bits.is_finite() || taint_delta_bits <= 0.0 {
            return self.agent_entropy(agent_id);
        }
        self.raise_agent_entropy(agent_id, taint_delta_bits)
    }

    /// Red-Team Upgrade #3: Cross-Agent transitive taint propagation (`S(dst) = max(S(dst), S(src))`).
    /// Prevents a tainted Agent A from laundering instructions through an untainted Agent B.
    pub fn propagate_cross_agent_taint(&self, source_agent: &str, target_agent: &str) -> f64 {
        let src_key = source_agent.to_ascii_lowercase();
        let dst_key = target_agent.to_ascii_lowercase();
        let mut map = self.agent_entropy.write();
        let src_s = *map.get(&src_key).unwrap_or(&0.0);
        let dst_s = *map.get(&dst_key).unwrap_or(&0.0);
        let propagated = dst_s.max(src_s);
        map.insert(dst_key, propagated);
        propagated
    }

    /// Red-Team Upgrade #3: Records an agent writing to a shared artifact/scratchpad file,
    /// propagating the writer's taint entropy onto that artifact.
    pub fn record_artifact_write(&self, writer_agent: &str, artifact_path: &str) -> f64 {
        let writer_s = self.agent_entropy(writer_agent);
        let norm = artifact_path.trim().replace('\\', "/").to_ascii_lowercase();
        let mut art = self.artifact_entropy.write();
        let prev = *art.get(&norm).unwrap_or(&0.0);
        let next = prev.max(writer_s);
        art.insert(norm, next);
        next
    }

    /// Red-Team Upgrade #3: Records an agent reading a shared artifact/scratchpad file,
    /// forcing the reader to inherit the artifact's taint entropy (`S(reader) = max(S(reader), S(artifact))`).
    pub fn record_artifact_read(&self, reader_agent: &str, artifact_path: &str) -> f64 {
        let art_s = self.artifact_entropy(artifact_path);
        let key = reader_agent.to_ascii_lowercase();
        let mut map = self.agent_entropy.write();
        let prev = *map.get(&key).unwrap_or(&0.0);
        let next = prev.max(art_s);
        map.insert(key, next);
        next
    }

    /// Issues an HMAC-SHA256 signed `X-Octopus-Taint-Entropy` propagation header for A2A/MCP hops.
    #[must_use]
    pub fn issue_signed_taint_header(&self, source_agent: &str, epoch: u64) -> SignedTaintHeader {
        let entropy = self.agent_entropy(source_agent);
        let msg = format!(
            "OCTOPUS_TAINT_V1|{}|{:.6}|{}",
            source_agent.to_ascii_lowercase(),
            entropy,
            epoch
        );
        let mac = hmac_sha256(&self.signing_key[..], msg.as_bytes());
        SignedTaintHeader {
            header_name: "X-Octopus-Taint-Entropy".to_string(),
            source_agent: source_agent.to_string(),
            taint_entropy_bits: entropy,
            epoch,
            hmac_hex: hex::encode(mac),
        }
    }

    /// Verifies a signed `X-Octopus-Taint-Entropy` header in constant time and propagates
    /// its entropy onto `receiving_agent`. Forged/invalid headers fail closed by elevating
    /// receiver taint above the barrier threshold.
    pub fn verify_and_absorb_taint_header(
        &self,
        receiving_agent: &str,
        header: &SignedTaintHeader,
    ) -> Result<f64, String> {
        let msg = format!(
            "OCTOPUS_TAINT_V1|{}|{:.6}|{}",
            header.source_agent.to_ascii_lowercase(),
            header.taint_entropy_bits,
            header.epoch
        );
        let expected = hmac_sha256(&self.signing_key[..], msg.as_bytes());
        let Ok(provided) = hex::decode(header.hmac_hex.trim()) else {
            self.raise_agent_entropy(receiving_agent, self.threshold_bits + 1.0);
            return Err(
                "Malformed X-Octopus-Taint-Entropy HMAC; receiver tainted fail-closed".to_string(),
            );
        };
        if provided.len() != expected.len() || !bool::from(provided.as_slice().ct_eq(&expected)) {
            self.raise_agent_entropy(receiving_agent, self.threshold_bits + 1.0);
            return Err(
                "Invalid X-Octopus-Taint-Entropy HMAC signature; receiver tainted fail-closed"
                    .to_string(),
            );
        }

        let key = receiving_agent.to_ascii_lowercase();
        let mut map = self.agent_entropy.write();
        let prev = *map.get(&key).unwrap_or(&0.0);
        let next = prev.max(header.taint_entropy_bits.max(0.0));
        map.insert(key, next);
        Ok(next)
    }

    /// Issues an out-of-loop human work receipt ($W_{\text{human}}$) authorizing taint reset.
    #[must_use]
    pub fn sign_human_work_reset(
        &self,
        agent_id: &str,
        epoch: u64,
        nonce: &str,
        target_entropy_bits: f64,
    ) -> HumanWorkResetProof {
        let clamped = target_entropy_bits.clamp(0.0, 16.0);
        let msg = format!(
            "OCTOPUS_HUMAN_WORK_RESET_V1|{}|{}|{}|{:.6}",
            agent_id.to_ascii_lowercase(),
            epoch,
            nonce,
            clamped
        );
        let mac = hmac_sha256(&self.signing_key[..], msg.as_bytes());
        HumanWorkResetProof {
            agent_id: agent_id.to_string(),
            epoch,
            nonce: nonce.to_string(),
            target_entropy_bits: clamped,
            signature_hex: hex::encode(mac),
        }
    }

    /// Applies an out-of-loop human work receipt after constant-time HMAC verification.
    /// This is the ONLY operation permitted to decrease `S_taint`.
    pub fn apply_human_work_reset(
        &self,
        proof: &HumanWorkResetProof,
        active_epoch: u64,
    ) -> Result<f64, String> {
        if proof.epoch != active_epoch {
            return Err(format!(
                "Stale human work reset epoch (proof={}, active={active_epoch})",
                proof.epoch
            ));
        }
        let msg = format!(
            "OCTOPUS_HUMAN_WORK_RESET_V1|{}|{}|{}|{:.6}",
            proof.agent_id.to_ascii_lowercase(),
            proof.epoch,
            proof.nonce,
            proof.target_entropy_bits
        );
        let expected = hmac_sha256(&self.signing_key[..], msg.as_bytes());
        let provided = hex::decode(proof.signature_hex.trim())
            .map_err(|_| "Invalid hex signature in HumanWorkResetProof".to_string())?;
        if provided.len() != expected.len() || !bool::from(provided.as_slice().ct_eq(&expected)) {
            return Err("Cryptographic verification failed for HumanWorkResetProof".to_string());
        }

        let key = proof.agent_id.to_ascii_lowercase();
        let next = proof.target_entropy_bits.clamp(0.0, 16.0);
        self.agent_entropy.write().insert(key, next);
        Ok(next)
    }

    /// Evaluates the Landauer-Maxwell barrier for a tool invocation.
    #[must_use]
    pub fn evaluate_barrier(
        &self,
        agent_id: &str,
        payload: &str,
        is_high_impact_sink: bool,
    ) -> ThermodynamicsVerdict {
        let payload_shannon = shannon_entropy_bits(payload.as_bytes());
        let payload_kl = payload_kl_divergence_vs_prose(payload);
        let agent_s = self.agent_entropy(agent_id);

        let barrier_tripped = is_high_impact_sink && agent_s >= self.threshold_bits;
        let reason = if barrier_tripped {
            format!(
                "LAW2_LANDAUER_MAXWELL_DENY: Agent '{}' taint entropy {:.2} bits >= {:.2} bits barrier; high-impact sink blocked until signed W_human reset",
                agent_id, agent_s, self.threshold_bits
            )
        } else {
            format!(
                "LAW2_ENTROPY_ALLOW: Agent '{}' taint entropy {:.2} bits (threshold {:.2}, shannon={:.2}, kl={:.2})",
                agent_id, agent_s, self.threshold_bits, payload_shannon, payload_kl
            )
        };

        ThermodynamicsVerdict {
            allowed: !barrier_tripped,
            agent_entropy_bits: agent_s,
            payload_shannon_bits: payload_shannon,
            payload_kl_divergence: payload_kl,
            threshold_bits: self.threshold_bits,
            requires_human_work_reset: barrier_tripped,
            reason,
        }
    }

    /// Snapshot of all tracked agent taint entropies for dashboard telemetry.
    #[must_use]
    pub fn snapshot_entropies(&self) -> HashMap<String, f64> {
        self.agent_entropy.read().clone()
    }
}
