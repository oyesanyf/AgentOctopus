use crate::core::types::{ArmRole, OctopusSecurityError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Constant-time byte slice equality comparison (`CWE-208` mitigation).
/// Prevents timing side-channel attacks on HMAC tags and cryptographic digests.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= std::hint::black_box(x ^ y);
    }
    std::hint::black_box(diff) == 0
}

/// Constant-time case-insensitive hex string equality comparison (`CWE-208` mitigation).
#[inline]
pub fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    let a_bytes = a.trim().as_bytes();
    let b_bytes = b.trim().as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= std::hint::black_box(x.to_ascii_lowercase() ^ y.to_ascii_lowercase());
    }
    std::hint::black_box(diff) == 0
}

/// Standard HMAC-SHA256 implementation utilizing the sha2 primitive.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let h = Sha256::digest(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize().into()
}

/// Cryptographically authenticated agent identity preventing identity spoofing and message replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub role: ArmRole,
    #[serde(skip)]
    secret_key: [u8; 32],
    #[serde(skip)]
    last_seen_nonce: Arc<AtomicU64>,
}

impl AgentIdentity {
    pub fn new(agent_id: impl Into<String>, role: ArmRole, seed: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"OCTOPUS_AGENT_IDENTITY_V1");
        hasher.update(seed);
        let secret_key: [u8; 32] = hasher.finalize().into();

        Self {
            agent_id: agent_id.into(),
            role,
            secret_key,
            last_seen_nonce: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn role(&self) -> &ArmRole {
        &self.role
    }

    /// Signs an outgoing message with sender_id, sender_role, recipient_id, nonce, and payload.
    pub fn sign_message(&self, recipient_id: &str, nonce: u64, payload: &str) -> SignedAgentMessage {
        let signature_payload = format!(
            "{}:{:?}:{}:{}:{}",
            self.agent_id, self.role, recipient_id, nonce, payload
        );
        let sig = hmac_sha256(&self.secret_key, signature_payload.as_bytes());
        let signature_hex = hex::encode(sig);

        SignedAgentMessage {
            sender_id: self.agent_id.clone(),
            sender_role: self.role.clone(),
            recipient_id: recipient_id.to_string(),
            nonce,
            payload: payload.to_string(),
            signature_hex,
        }
    }

    /// Verifies that an incoming message was genuinely signed by this agent identity and protects against replay attacks.
    pub fn verify_incoming_message(&self, msg: &SignedAgentMessage) -> Result<(), OctopusSecurityError> {
        if msg.sender_id != self.agent_id {
            return Err(OctopusSecurityError::IdentitySpoofingDetected(format!(
                "Message sender '{}' does not match identity '{}'",
                msg.sender_id, self.agent_id
            )));
        }

        if msg.sender_role != self.role {
            return Err(OctopusSecurityError::IdentitySpoofingDetected(format!(
                "Sender role mismatch: claimed '{:?}', actual identity has role '{:?}'",
                msg.sender_role, self.role
            )));
        }

        // Replay Protection: Nonce must be strictly monotonically increasing
        let prev_nonce = self.last_seen_nonce.load(Ordering::SeqCst);
        if msg.nonce <= prev_nonce && prev_nonce > 0 {
            return Err(OctopusSecurityError::IdentitySpoofingDetected(format!(
                "Replay attack detected: message nonce {} is stale or duplicated (last verified: {})",
                msg.nonce, prev_nonce
            )));
        }

        let signature_payload = format!(
            "{}:{:?}:{}:{}:{}",
            msg.sender_id, msg.sender_role, msg.recipient_id, msg.nonce, msg.payload
        );
        let expected_sig = hmac_sha256(&self.secret_key, signature_payload.as_bytes());
        let expected_hex = hex::encode(expected_sig);

        if !constant_time_eq_hex(&expected_hex, &msg.signature_hex) {
            return Err(OctopusSecurityError::IdentitySpoofingDetected(format!(
                "Cryptographic signature mismatch for agent '{}': forged message rejected!",
                self.agent_id
            )));
        }

        // Update verified monotonic nonce watermark
        self.last_seen_nonce.store(msg.nonce, Ordering::SeqCst);

        Ok(())
    }
}

/// Cryptographically signed envelope for inter-agent communication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedAgentMessage {
    pub sender_id: String,
    pub sender_role: ArmRole,
    pub recipient_id: String,
    pub nonce: u64,
    pub payload: String,
    pub signature_hex: String,
}
