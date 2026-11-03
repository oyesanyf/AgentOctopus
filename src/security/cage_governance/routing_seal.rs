// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Reference: Google Cybernetic Agent Governance Engine (CAGE), arXiv:2606.12320

//! CAGE Substrate §3 Evidence-Bound Cryptographic Routing Seals & Single-Use Consumption Verifier
//!
//! Enforces the foundational No-Direct-Bind safety invariant:
//!
//! $$\text{NoDirectBind} \iff (\text{phase} = \text{EXECUTED}) \implies (\text{resolvedAllow} = \text{TRUE} \land \text{seal\_present} = \text{TRUE})$$
//!
//! Routing seals are issued exclusively upon unanimous governance clearance (`ALLOW` or `NARROW`).
//! Each seal cryptographically binds an approved action to its parameters, active policy version,
//! and the immutable `SecurityAuditLog` SHA-256 chain hash (`record_hash`).
//! Enforces strict 30-second TTL (`expires_at = issued_at + 30`), 5-second clock drift tolerance,
//! and thread-safe atomic single-use consumption to prevent replay attacks.

use super::substrate_translator::SubstrateTranslator;
use crate::security::identity::{constant_time_eq_hex, hmac_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Strict 30-second TTL duration for all CAGE routing seals.
pub const ROUTING_SEAL_TTL_SECS: u64 = 30;

/// Maximum allowable clock drift tolerance in seconds.
pub const CLOCK_DRIFT_TOLERANCE_SECS: u64 = 5;

/// Evidence-Bound Cryptographic Routing Seal (CAGE Substrate §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CageRoutingSeal {
    /// Unique single-use seal identifier.
    pub seal_id: String,
    /// 16-hex lowercase SHA-256 policy version under which the action cleared.
    pub policy_version_id: String,
    /// 64-hex lowercase SHA-256 action and parameter digest.
    pub action_digest: String,
    /// 64-hex lowercase SHA-256 chain hash from `SecurityAuditLog::record_event`.
    pub record_hash: String,
    /// Unix epoch seconds when the seal was issued.
    pub issued_at: u64,
    /// Expiration timestamp (`issued_at + 30`).
    pub expires_at: u64,
    /// 64-hex lowercase HMAC-SHA256 cryptographic signature.
    pub signature: String,
}

impl CageRoutingSeal {
    /// Checks whether the seal has expired relative to current epoch seconds.
    ///
    /// Evaluates against both `expires_at` and `issued_at + ROUTING_SEAL_TTL_SECS`
    /// to prevent reliance on tampered deserialized expiration timestamps.
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.expires_at
            || current_time > self.issued_at.saturating_add(ROUTING_SEAL_TTL_SECS)
    }

    /// Verifies that all fields meet length, character set, format, and TTL invariants.
    pub fn validate_format(&self) -> bool {
        self.policy_version_id.len() == 16
            && self
                .policy_version_id
                .chars()
                .all(|c| c.is_ascii_hexdigit())
            && self.action_digest.len() == 64
            && self
                .action_digest
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
            && self.record_hash.len() == 64
            && self
                .record_hash
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
            && !self.seal_id.is_empty()
            && !self.signature.is_empty()
            && self.expires_at == self.issued_at.saturating_add(ROUTING_SEAL_TTL_SECS)
    }
}

/// Rejection reasons returned when a routing seal fails validation or consumption.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum SealRejection {
    #[error("Routing seal signature is invalid or tampered")]
    InvalidSignature,

    #[error("Routing seal has expired: current_time={current_time} > expires_at={expires_at} (TTL exceeded)")]
    Expired { current_time: u64, expires_at: u64 },

    #[error("Routing seal issued in future (clock drift > 5s): current_time={current_time} < issued_at={issued_at}")]
    FutureTimestamp { current_time: u64, issued_at: u64 },

    #[error("Routing seal already consumed (single-use replay detected): {0}")]
    AlreadyConsumed(String),

    #[error(
        "Policy version mismatch: expected active version '{expected}', seal specifies '{actual}'"
    )]
    PolicyVersionMismatch { expected: String, actual: String },

    #[error("Action digest mismatch: expected '{expected}', seal contains '{actual}'")]
    ActionDigestMismatch { expected: String, actual: String },

    #[error("Record hash chain mismatch: expected '{expected}', seal contains '{actual}'")]
    RecordHashMismatch { expected: String, actual: String },

    #[error("Evidence unanchored or invalid audit record hash: {0}")]
    UnanchoredEvidence(String),

    #[error("Malformed routing seal: {0}")]
    MalformedSeal(String),
}

/// Computes the 64-hex lowercase SHA-256 action digest over an action and its canonical JSON parameters.
pub fn compute_action_digest(action_name: &str, params: &serde_json::Value) -> String {
    let canonical_params =
        SubstrateTranslator::canonicalize_jcs(params).unwrap_or_else(|_| params.to_string());
    let mut hasher = Sha256::new();
    hasher.update(action_name.as_bytes());
    hasher.update(b":");
    hasher.update(canonical_params.as_bytes());
    hex::encode(hasher.finalize())
}

/// Signer and single-use verifier for evidence-bound routing seals.
pub struct RoutingSealSigner {
    secret_key: Vec<u8>,
    policy_version_id: RwLock<String>,
    consumed_seals: Arc<RwLock<HashMap<String, u64>>>,
    last_prune_time: Arc<AtomicU64>,
}

impl RoutingSealSigner {
    /// Creates a new seal signer with the specified secret key and active policy version ID.
    pub fn new(secret_key: &[u8], policy_version_id: &str) -> Self {
        Self {
            secret_key: secret_key.to_vec(),
            policy_version_id: RwLock::new(policy_version_id.to_string()),
            consumed_seals: Arc::new(RwLock::new(HashMap::new())),
            last_prune_time: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Creates a signer with a shared consumed seals map, enabling synchronized single-use tracking.
    pub fn with_shared_consumed(
        secret_key: &[u8],
        policy_version_id: &str,
        consumed_seals: Arc<RwLock<HashMap<String, u64>>>,
    ) -> Self {
        Self {
            secret_key: secret_key.to_vec(),
            policy_version_id: RwLock::new(policy_version_id.to_string()),
            consumed_seals,
            last_prune_time: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns a reference-counted clone of the consumed seals map for cross-module sharing.
    pub fn shared_consumed_seals(&self) -> Arc<RwLock<HashMap<String, u64>>> {
        Arc::clone(&self.consumed_seals)
    }

    /// Returns the currently active policy version ID.
    pub fn active_policy_version(&self) -> String {
        self.policy_version_id.read().unwrap().clone()
    }

    /// Updates the active policy version ID.
    pub fn set_policy_version(&self, new_version: &str) {
        let mut w = self.policy_version_id.write().unwrap();
        *w = new_version.to_string();
    }

    /// Computes the HMAC-SHA256 signature over the evidence-bound seal payload:
    ///
    /// `seal_id|action_digest|policy_version_id|record_hash|issued_at|expires_at`
    pub fn compute_signature(
        secret_key: &[u8],
        seal_id: &str,
        action_digest: &str,
        policy_version_id: &str,
        record_hash: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> String {
        let payload = format!(
            "{}|{}|{}|{}|{}|{}",
            seal_id, action_digest, policy_version_id, record_hash, issued_at, expires_at
        );
        let tag = hmac_sha256(secret_key, payload.as_bytes());
        hex::encode(tag)
    }

    /// Issues an evidence-bound cryptographic routing seal.
    ///
    /// Enforces Tallam 2026 Evidence Sufficiency: seal issuance fails closed with
    /// `SealRejection::UnanchoredEvidence` if `record_hash` is not a valid 64-hex string.
    pub fn issue_seal(
        &self,
        action_digest: &str,
        record_hash: &str,
        now: u64,
    ) -> Result<CageRoutingSeal, SealRejection> {
        // Tallam 2026 Evidence Sufficiency verification
        if record_hash.len() != 64
            || !record_hash
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
            || record_hash == "0000000000000000000000000000000000000000000000000000000000000000"
            || record_hash.starts_with("GENESIS_AUDIT_ROOT")
        {
            return Err(SealRejection::UnanchoredEvidence(format!(
                "Invalid or uncommitted audit chain record hash: '{}'",
                record_hash
            )));
        }

        let nonce: [u8; 16] = rand::random();
        let seal_id = format!("seal_{}", hex::encode(nonce));
        let version_id = self.active_policy_version();
        let expires_at = now + ROUTING_SEAL_TTL_SECS;

        let signature = Self::compute_signature(
            &self.secret_key,
            &seal_id,
            action_digest,
            &version_id,
            record_hash,
            now,
            expires_at,
        );

        Ok(CageRoutingSeal {
            seal_id,
            policy_version_id: version_id,
            action_digest: action_digest.to_string(),
            record_hash: record_hash.to_string(),
            issued_at: now,
            expires_at,
            signature,
        })
    }

    /// Issues a seal using system clock timestamp.
    pub fn issue_seal_now(
        &self,
        action_digest: &str,
        record_hash: &str,
    ) -> Result<CageRoutingSeal, SealRejection> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.issue_seal(action_digest, record_hash, now)
    }

    /// Validates seal signature in constant time.
    pub fn verify_signature(&self, seal: &CageRoutingSeal) -> bool {
        let expected = Self::compute_signature(
            &self.secret_key,
            &seal.seal_id,
            &seal.action_digest,
            &seal.policy_version_id,
            &seal.record_hash,
            seal.issued_at,
            seal.expires_at,
        );
        constant_time_eq_hex(&seal.signature, &expected)
    }

    /// Validates format, policy version, action digest, record hash, TTL window,
    /// cryptographic signature, and atomically consumes the seal in a thread-safe set.
    ///
    /// Subsequent presentation of the same seal fails closed with `SealRejection::AlreadyConsumed`.
    pub fn validate_and_consume(
        &self,
        seal: &CageRoutingSeal,
        expected_action_digest: &str,
        expected_record_hash: &str,
        current_time: u64,
    ) -> Result<(), SealRejection> {
        // 1. Format check (enforces hex length, charset, and TTL invariant)
        if !seal.validate_format() {
            return Err(SealRejection::MalformedSeal(
                "Seal fields do not meet hex length, character requirements, or TTL invariant"
                    .to_string(),
            ));
        }

        // 1b. Structural TTL invariant check (fail closed if expires_at != issued_at + TTL)
        if seal.expires_at != seal.issued_at.saturating_add(ROUTING_SEAL_TTL_SECS) {
            return Err(SealRejection::MalformedSeal(
                "Seal expires_at does not match issued_at + ROUTING_SEAL_TTL_SECS".to_string(),
            ));
        }

        // 2. Policy version check
        let active_ver = self.active_policy_version();
        if seal.policy_version_id != active_ver {
            return Err(SealRejection::PolicyVersionMismatch {
                expected: active_ver,
                actual: seal.policy_version_id.clone(),
            });
        }

        // 3. Action digest check (constant-time)
        if !constant_time_eq_hex(&seal.action_digest, expected_action_digest) {
            return Err(SealRejection::ActionDigestMismatch {
                expected: expected_action_digest.to_string(),
                actual: seal.action_digest.clone(),
            });
        }

        // 4. Record hash chain check (constant-time)
        if !constant_time_eq_hex(&seal.record_hash, expected_record_hash) {
            return Err(SealRejection::RecordHashMismatch {
                expected: expected_record_hash.to_string(),
                actual: seal.record_hash.clone(),
            });
        }

        // 5. Clock drift check (reject seals issued > 5s in the future)
        if seal.issued_at > current_time.saturating_add(CLOCK_DRIFT_TOLERANCE_SECS) {
            return Err(SealRejection::FutureTimestamp {
                current_time,
                issued_at: seal.issued_at,
            });
        }

        // 6. Expiry check against both seal.expires_at and issued_at + ROUTING_SEAL_TTL_SECS
        if current_time > seal.expires_at
            || current_time > seal.issued_at.saturating_add(ROUTING_SEAL_TTL_SECS)
        {
            return Err(SealRejection::Expired {
                current_time,
                expires_at: seal.expires_at,
            });
        }

        // 7. Signature verification (constant-time) - binds expires_at in HMAC
        if !self.verify_signature(seal) {
            return Err(SealRejection::InvalidSignature);
        }

        // 8. Atomic single-use consumption & bounded memory TTL pruning
        let mut consumed = self.consumed_seals.write().unwrap();

        // Amortized periodic pruning: sweep expired entries at most once per second or when table grows large
        let last_prune = self.last_prune_time.load(Ordering::Relaxed);
        if current_time > last_prune || consumed.len() > 1024 {
            consumed.retain(|_, &mut exp| {
                exp.saturating_add(CLOCK_DRIFT_TOLERANCE_SECS) >= current_time
            });
            self.last_prune_time.store(current_time, Ordering::Relaxed);
        }

        if consumed.contains_key(&seal.seal_id) {
            return Err(SealRejection::AlreadyConsumed(seal.seal_id.clone()));
        }
        consumed.insert(seal.seal_id.clone(), seal.expires_at);

        Ok(())
    }

    /// Convenience wrapper consuming seal against current system time.
    pub fn validate_and_consume_now(
        &self,
        seal: &CageRoutingSeal,
        expected_action_digest: &str,
        expected_record_hash: &str,
    ) -> Result<(), SealRejection> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.validate_and_consume(seal, expected_action_digest, expected_record_hash, now)
    }

    /// Returns the number of consumed seals currently tracked in memory.
    pub fn consumed_count(&self) -> usize {
        self.consumed_seals.read().unwrap().len()
    }

    /// Explicitly prunes expired seals from memory whose lifetime plus clock drift tolerance has elapsed.
    /// Returns the count of pruned entries.
    pub fn prune_expired(&self, current_time: u64) -> usize {
        let mut consumed = self.consumed_seals.write().unwrap();
        let initial_len = consumed.len();
        consumed
            .retain(|_, &mut exp| exp.saturating_add(CLOCK_DRIFT_TOLERANCE_SECS) >= current_time);
        self.last_prune_time.store(current_time, Ordering::Relaxed);
        initial_len.saturating_sub(consumed.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_seal_issue_and_consume_cycle() {
        let secret = b"super_secret_cage_key_12345678";
        let signer = RoutingSealSigner::new(secret, "0123456789abcdef");

        let action_digest =
            compute_action_digest("execute_tool", &serde_json::json!({"command": "ls"}));
        let record_hash = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff";

        let now = 1_000_000;
        let seal = signer.issue_seal(&action_digest, record_hash, now).unwrap();
        assert!(seal.validate_format());
        assert_eq!(seal.expires_at, now + 30);

        // First validation and consumption: Success
        assert!(signer
            .validate_and_consume(&seal, &action_digest, record_hash, now + 5)
            .is_ok());

        // Second validation and consumption: Replay rejected!
        let replay_err = signer
            .validate_and_consume(&seal, &action_digest, record_hash, now + 6)
            .unwrap_err();
        assert!(matches!(replay_err, SealRejection::AlreadyConsumed(_)));
    }

    #[test]
    fn test_routing_seal_expiration() {
        let secret = b"super_secret_cage_key_12345678";
        let signer = RoutingSealSigner::new(secret, "0123456789abcdef");

        let action_digest = compute_action_digest("execute_tool", &serde_json::json!({}));
        let record_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let now = 1_000_000;
        let seal = signer.issue_seal(&action_digest, record_hash, now).unwrap();

        // Expired after 31 seconds
        let expired_err = signer
            .validate_and_consume(&seal, &action_digest, record_hash, now + 31)
            .unwrap_err();
        assert!(matches!(expired_err, SealRejection::Expired { .. }));
    }

    #[test]
    fn test_unanchored_evidence_rejection() {
        let secret = b"super_secret_cage_key_12345678";
        let signer = RoutingSealSigner::new(secret, "0123456789abcdef");

        let action_digest = compute_action_digest("execute_tool", &serde_json::json!({}));
        let empty_hash = "";
        let err = signer
            .issue_seal(&action_digest, empty_hash, 1000)
            .unwrap_err();
        assert!(matches!(err, SealRejection::UnanchoredEvidence(_)));
    }

    #[test]
    fn test_tampered_expires_at_rejection() {
        let secret = b"super_secret_cage_key_12345678";
        let signer = RoutingSealSigner::new(secret, "0123456789abcdef");

        let action_digest = compute_action_digest("execute_tool", &serde_json::json!({}));
        let record_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let now = 1_000_000;

        let mut seal = signer.issue_seal(&action_digest, record_hash, now).unwrap();

        // Attacker tampers with expires_at
        seal.expires_at = now + 100;

        // 1. validate_format rejects it
        assert!(!seal.validate_format());

        // 2. validate_and_consume rejects it as MalformedSeal
        let err = signer
            .validate_and_consume(&seal, &action_digest, record_hash, now + 10)
            .unwrap_err();
        assert!(matches!(err, SealRejection::MalformedSeal(_)));
    }

    #[test]
    fn test_consumed_seals_ttl_pruning() {
        let secret = b"super_secret_cage_key_12345678";
        let signer = RoutingSealSigner::new(secret, "0123456789abcdef");

        let action_digest = compute_action_digest("execute_tool", &serde_json::json!({}));
        let record_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let now = 1_000_000;

        let seal1 = signer.issue_seal(&action_digest, record_hash, now).unwrap();
        assert!(signer
            .validate_and_consume(&seal1, &action_digest, record_hash, now + 5)
            .is_ok());
        assert_eq!(signer.consumed_count(), 1);

        // Before TTL + clock drift: entry preserved
        assert_eq!(signer.prune_expired(now + 30), 0);
        assert_eq!(signer.consumed_count(), 1);

        // After TTL (30s) + clock drift (5s): entry pruned at now + 36
        assert_eq!(signer.prune_expired(now + 36), 1);
        assert_eq!(signer.consumed_count(), 0);

        // Replaying pruned seal after its TTL is still rejected as Expired, never accepted!
        let replay_after_prune = signer
            .validate_and_consume(&seal1, &action_digest, record_hash, now + 36)
            .unwrap_err();
        assert!(matches!(replay_after_prune, SealRejection::Expired { .. }));
    }
}
