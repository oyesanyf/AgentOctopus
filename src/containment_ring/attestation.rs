use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyAttestationRecord {
    pub attestation_id: String,
    pub timestamp_ms: u64,
    pub policy_root_hash: String,
    pub sandbox_profile_hash: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone)]
pub struct RingAttestation {
    secret_key: Arc<[u8; 32]>,
    active_attestation: Arc<RwLock<PolicyAttestationRecord>>,
}

impl RingAttestation {
    pub fn new(seed: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"RING_ATTESTATION_SECRET_V1");
        hasher.update(seed);
        let secret: [u8; 32] = hasher.finalize().into();

        let initial_record = Self::compute_record(
            &secret,
            "default_cedar_policy_v4.13",
            "hardened_job_object_v1",
        );

        Self {
            secret_key: Arc::new(secret),
            active_attestation: Arc::new(RwLock::new(initial_record)),
        }
    }

    fn compute_record(
        secret: &[u8; 32],
        policy_spec: &str,
        sandbox_spec: &str,
    ) -> PolicyAttestationRecord {
        let policy_hash = hex::encode(Sha256::digest(policy_spec.as_bytes()));
        let sandbox_hash = hex::encode(Sha256::digest(sandbox_spec.as_bytes()));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let payload = format!("{}:{}:{}", now, policy_hash, sandbox_hash);
        let sig = crate::security::hmac_sha256(secret, payload.as_bytes());

        PolicyAttestationRecord {
            attestation_id: format!("ATTEST-{:x}", now),
            timestamp_ms: now,
            policy_root_hash: policy_hash,
            sandbox_profile_hash: sandbox_hash,
            signature_hex: hex::encode(sig),
        }
    }

    pub async fn verify_attestation(&self) -> bool {
        let record = self.active_attestation.read().await;
        let payload = format!(
            "{}:{}:{}",
            record.timestamp_ms, record.policy_root_hash, record.sandbox_profile_hash
        );
        let expected = crate::security::hmac_sha256(&self.secret_key[..], payload.as_bytes());
        crate::security::constant_time_eq_hex(&hex::encode(expected), &record.signature_hex)
    }

    pub async fn update_policies(&self, policy_spec: &str, sandbox_spec: &str) {
        let new_rec = Self::compute_record(&self.secret_key, policy_spec, sandbox_spec);
        *self.active_attestation.write().await = new_rec;
    }

    pub async fn current_attestation(&self) -> PolicyAttestationRecord {
        self.active_attestation.read().await.clone()
    }

    /// Deliberately corrupts the active attestation signature (for negative-control attestation failure testing).
    pub async fn tamper_with_signature(&self, forged_signature: &str) {
        let mut rec = self.active_attestation.write().await;
        rec.signature_hex = forged_signature.to_string();
    }

    /// Restores a valid cryptographic attestation signature.
    pub async fn restore_authentic_attestation(&self) {
        let rec = Self::compute_record(
            &self.secret_key,
            "default_cedar_policy_v4.13",
            "hardened_job_object_v1",
        );
        *self.active_attestation.write().await = rec;
    }
}
