//! Law 4 — Quantum Mechanics: No-Cloning Single-Use Capability Collapse &
//! Quantum Zeno Adaptive Forensic Observation Cadence.
//!
//! 1. **No-Cloning Theorem**: Capability tokens authorizing write/exec/egress actions are
//!    bound via HMAC-SHA256 to `(token_id, nhi_id, tool_name, canonical_args_sha256, epoch, expires_at)`
//!    and atomically destroyed upon first verification (`consume_once`). Replaying a cloned
//!    or captured token deterministically fails closed.
//! 2. **Quantum Zeno Effect**: Continuous adaptive forensic measurement freezes Break-In /
//!    Break-Out state transitions by shrinking observation cadence exponentially with
//!    Hamiltonian risk energy $H$ and Thermodynamic taint entropy $S_{\text{taint}}$:
//!    $$\Delta t_{\text{sweep}}(H, S_{\text{taint}}) = \Delta t_{\max} \cdot \exp\left(-\alpha \frac{H}{H_{\max}} - \beta S_{\text{taint}}\right)$$

use crate::security::artemis_dfir::unix_now_secs;
use crate::security::identity::hmac_sha256;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAX_CONSUMED_HISTORY: usize = 4096;

/// Single-use No-Cloning capability token bound to exact action arguments and session epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleUseCapabilityToken {
    pub token_id: String,
    pub nhi_id: String,
    pub tool_name: String,
    pub args_sha256: String,
    pub epoch: u64,
    pub expires_at_unix: u64,
    pub mac_hex: String,
}

/// Verdict produced by Law 4 (Quantum No-Cloning & Zeno Guard).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumZenoVerdict {
    pub allowed: bool,
    pub token_collapsed: bool,
    pub replay_detected: bool,
    pub zeno_sweep_interval_ms: u64,
    pub reason: String,
}

#[derive(Default)]
struct TokenLedger {
    active: HashMap<String, SingleUseCapabilityToken>,
    consumed_set: HashSet<String>,
    consumed_fifo: VecDeque<String>,
}

/// Enforces Quantum No-Cloning single-use capability consumption and computes
/// Quantum Zeno adaptive forensic sweep cadence.
pub struct QuantumZenoGuard {
    secret_key: Zeroizing<[u8; 32]>,
    seq: AtomicU64,
    ledger: Mutex<TokenLedger>,
    pub min_sweep_ms: u64,
    pub max_sweep_ms: u64,
    pub alpha_energy: f64,
    pub beta_entropy: f64,
}

impl Default for QuantumZenoGuard {
    fn default() -> Self {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        Self::new(key)
    }
}

impl QuantumZenoGuard {
    #[must_use]
    pub fn new(secret_key: [u8; 32]) -> Self {
        Self {
            secret_key: Zeroizing::new(secret_key),
            seq: AtomicU64::new(1),
            ledger: Mutex::new(TokenLedger::default()),
            min_sweep_ms: 250,
            max_sweep_ms: 30_000,
            alpha_energy: 2.2,
            beta_entropy: 0.9,
        }
    }

    fn compute_mac(
        &self,
        token_id: &str,
        nhi_id: &str,
        tool_name: &str,
        args_sha256: &str,
        epoch: u64,
        expires_at_unix: u64,
    ) -> [u8; 32] {
        let payload = format!(
            "OCTOPUS_QUANTUM_NOCLONE_V1|{token_id}|{}|{}|{}|{epoch}|{expires_at_unix}",
            nhi_id.to_ascii_lowercase(),
            tool_name.to_ascii_lowercase(),
            args_sha256.to_ascii_lowercase()
        );
        hmac_sha256(&self.secret_key[..], payload.as_bytes())
    }

    /// Mints a fresh single-use No-Cloning capability token valid for `ttl_secs`.
    #[must_use]
    pub fn mint_single_use_token(
        &self,
        nhi_id: &str,
        tool_name: &str,
        args_sha256: &str,
        epoch: u64,
        ttl_secs: u64,
    ) -> SingleUseCapabilityToken {
        self.mint_single_use_token_at(
            nhi_id,
            tool_name,
            args_sha256,
            epoch,
            unix_now_secs(),
            ttl_secs,
        )
    }

    /// Deterministic timestamp variant for minting single-use tokens.
    #[must_use]
    pub fn mint_single_use_token_at(
        &self,
        nhi_id: &str,
        tool_name: &str,
        args_sha256: &str,
        epoch: u64,
        now_unix: u64,
        ttl_secs: u64,
    ) -> SingleUseCapabilityToken {
        let n = self.seq.fetch_add(1, Ordering::SeqCst);
        let mut rnd = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rnd);
        let token_id = format!("qcap-{epoch}-{n}-{}", hex::encode(rnd));
        let expires_at_unix = now_unix.saturating_add(ttl_secs.clamp(5, 600));
        let mac = self.compute_mac(
            &token_id,
            nhi_id,
            tool_name,
            args_sha256,
            epoch,
            expires_at_unix,
        );
        let token = SingleUseCapabilityToken {
            token_id: token_id.clone(),
            nhi_id: nhi_id.to_string(),
            tool_name: tool_name.to_string(),
            args_sha256: args_sha256.to_string(),
            epoch,
            expires_at_unix,
            mac_hex: hex::encode(mac),
        };
        self.ledger.lock().active.insert(token_id, token.clone());
        token
    }

    /// Computes Quantum Zeno adaptive forensic sweep cadence (milliseconds).
    #[must_use]
    pub fn compute_zeno_sweep_interval_ms(
        &self,
        hamiltonian_ratio: f64,
        taint_entropy_bits: f64,
    ) -> u64 {
        let r = hamiltonian_ratio.clamp(0.0, 4.0);
        let s = taint_entropy_bits.clamp(0.0, 16.0);
        let raw =
            (self.max_sweep_ms as f64) * (-self.alpha_energy * r - self.beta_entropy * s).exp();
        (raw.round() as u64).clamp(self.min_sweep_ms, self.max_sweep_ms)
    }

    /// Atomically verifies and collapses a single-use capability token (`consume_once`).
    /// Any replay, epoch mismatch, expiration, or argument tampering fails closed.
    #[must_use]
    pub fn consume_once(
        &self,
        token: &SingleUseCapabilityToken,
        expected_nhi_id: &str,
        expected_tool_name: &str,
        expected_args_sha256: &str,
        active_epoch: u64,
        now_unix: u64,
        hamiltonian_ratio: f64,
        taint_entropy_bits: f64,
    ) -> QuantumZenoVerdict {
        let zeno_ms = self.compute_zeno_sweep_interval_ms(hamiltonian_ratio, taint_entropy_bits);

        let mut guard = self.ledger.lock();
        if guard.consumed_set.contains(&token.token_id) {
            return QuantumZenoVerdict {
                allowed: false,
                token_collapsed: true,
                replay_detected: true,
                zeno_sweep_interval_ms: zeno_ms.min(500),
                reason: format!(
                    "LAW4_NO_CLONING_REPLAY_DENY: Capability token '{}' was already collapsed on first use",
                    token.token_id
                ),
            };
        }

        let Some(issued) = guard.active.remove(&token.token_id) else {
            return QuantumZenoVerdict {
                allowed: false,
                token_collapsed: false,
                replay_detected: false,
                zeno_sweep_interval_ms: zeno_ms,
                reason: format!(
                    "LAW4_UNKNOWN_CAPABILITY_DENY: Capability token '{}' is not registered in active quantum ledger",
                    token.token_id
                ),
            };
        };

        // Mark token ID collapsed regardless of subsequent field checks so failed probes cannot retry it
        if guard.consumed_fifo.len() >= MAX_CONSUMED_HISTORY {
            if let Some(old) = guard.consumed_fifo.pop_front() {
                guard.consumed_set.remove(&old);
            }
        }
        guard.consumed_set.insert(token.token_id.clone());
        guard.consumed_fifo.push_back(token.token_id.clone());
        drop(guard);

        // Verify constant-time HMAC
        let expected_mac = self.compute_mac(
            &issued.token_id,
            &issued.nhi_id,
            &issued.tool_name,
            &issued.args_sha256,
            issued.epoch,
            issued.expires_at_unix,
        );
        let Ok(provided_mac) = hex::decode(token.mac_hex.trim()) else {
            return QuantumZenoVerdict {
                allowed: false,
                token_collapsed: true,
                replay_detected: false,
                zeno_sweep_interval_ms: zeno_ms,
                reason: "LAW4_BAD_MAC_ENCODING_DENY: Malformed capability token HMAC".to_string(),
            };
        };
        if provided_mac.len() != expected_mac.len()
            || !bool::from(provided_mac.as_slice().ct_eq(&expected_mac))
        {
            return QuantumZenoVerdict {
                allowed: false,
                token_collapsed: true,
                replay_detected: false,
                zeno_sweep_interval_ms: zeno_ms,
                reason: "LAW4_INVALID_MAC_DENY: Constant-time HMAC verification failed".to_string(),
            };
        }

        if issued.epoch != active_epoch {
            return QuantumZenoVerdict {
                allowed: false,
                token_collapsed: true,
                replay_detected: false,
                zeno_sweep_interval_ms: zeno_ms,
                reason: format!(
                    "LAW4_STALE_EPOCH_DENY: Token epoch {} != active epoch {active_epoch}",
                    issued.epoch
                ),
            };
        }

        if now_unix > issued.expires_at_unix {
            return QuantumZenoVerdict {
                allowed: false,
                token_collapsed: true,
                replay_detected: false,
                zeno_sweep_interval_ms: zeno_ms,
                reason: format!(
                    "LAW4_EXPIRED_CAPABILITY_DENY: Token expired at {} (now={now_unix})",
                    issued.expires_at_unix
                ),
            };
        }

        if !issued.nhi_id.eq_ignore_ascii_case(expected_nhi_id)
            || !issued.tool_name.eq_ignore_ascii_case(expected_tool_name)
            || !issued
                .args_sha256
                .eq_ignore_ascii_case(expected_args_sha256)
        {
            return QuantumZenoVerdict {
                allowed: false,
                token_collapsed: true,
                replay_detected: false,
                zeno_sweep_interval_ms: zeno_ms,
                reason: "LAW4_CAPABILITY_BINDING_MISMATCH_DENY: Token bound to different principal, tool, or arguments".to_string(),
            };
        }

        QuantumZenoVerdict {
            allowed: true,
            token_collapsed: true,
            replay_detected: false,
            zeno_sweep_interval_ms: zeno_ms,
            reason: format!(
                "LAW4_QUANTUM_COLLAPSE_ALLOW: Single-use token '{}' verified & destroyed; next Zeno sweep in {zeno_ms}ms",
                token.token_id
            ),
        }
    }

    #[must_use]
    pub fn active_token_count(&self) -> usize {
        self.ledger.lock().active.len()
    }
}
