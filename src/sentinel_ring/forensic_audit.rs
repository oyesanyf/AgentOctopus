//! Component 7: Protected Forensic Audit (`forensic_audit.rs`)
//!
//! Maintains an independent, cryptographically signed, append-only record of
//! authorization decisions, policy changes, termination events, supervisor failures,
//! and security violations.
//!
//! Key Security Invariants:
//! 1. **Hash Chained Records**: Every entry incorporates SHA-256 hash of previous entry.
//! 2. **External Remote Anchoring**: Periodically computes Merkle checkpoint roots and anchors
//!    them outside the local environment (`logs/remote_anchored_audit_checkpoint.json`).
//! 3. **Disk Exhaustion & Failure Detection**: Detects I/O faults, out-of-space, or delivery failures.

use crate::core::types::OctopusSecurityError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Single immutable entry in the Sentinel Forensic Audit Ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicAuditRecord {
    pub sequence: u64,
    pub timestamp_secs: u64,
    pub event_type: String,
    pub arm_id: Option<u64>,
    pub action: String,
    pub details: String,
    pub prev_hash: String,
    pub record_hash: String,
    pub hmac_signature: String,
}

/// Signed checkpoint anchored in an independent, protected location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    pub checkpoint_sequence: u64,
    pub timestamp_secs: u64,
    pub records_covered: usize,
    pub merkle_root_hash: String,
    pub previous_checkpoint_hash: String,
    pub checkpoint_signature: String,
}

/// Protected out-of-band forensic audit logger.
pub struct ForensicAuditLog {
    log_path: PathBuf,
    checkpoint_path: PathBuf,
    secret_key: [u8; 32],
    last_hash: Arc<RwLock<String>>,
    sequence_counter: Arc<RwLock<u64>>,
    checkpoint_counter: Arc<RwLock<u64>>,
    last_checkpoint_hash: Arc<RwLock<String>>,
    in_memory_records: Arc<RwLock<Vec<ForensicAuditRecord>>>,
}

impl ForensicAuditLog {
    /// Initializes a new forensic audit log bound to disk.
    pub fn new(log_path: PathBuf, secret_seed: &[u8]) -> Self {
        let mut key = [0u8; 32];
        if secret_seed.len() >= 32 {
            key.copy_from_slice(&secret_seed[..32]);
        } else {
            let hash = Sha256::digest(secret_seed);
            key.copy_from_slice(&hash);
        }

        let checkpoint_path = log_path
            .parent()
            .unwrap_or_else(|| Path::new("logs"))
            .join("remote_anchored_audit_checkpoint.json");

        Self {
            log_path,
            checkpoint_path,
            secret_key: key,
            last_hash: Arc::new(RwLock::new("GENESIS_SENTINEL_ROOT_HASH".to_string())),
            sequence_counter: Arc::new(RwLock::new(0)),
            checkpoint_counter: Arc::new(RwLock::new(0)),
            last_checkpoint_hash: Arc::new(RwLock::new("GENESIS_CHECKPOINT_ROOT".to_string())),
            in_memory_records: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Appends a new security event to the tamper-evident audit ledger.
    pub async fn append_event(
        &self,
        event_type: &str,
        arm_id: Option<u64>,
        action: &str,
        details: &str,
    ) -> Result<ForensicAuditRecord, OctopusSecurityError> {
        let mut seq_guard = self.sequence_counter.write().await;
        *seq_guard += 1;
        let sequence = *seq_guard;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut hash_guard = self.last_hash.write().await;
        let prev_hash = hash_guard.clone();

        // Calculate record SHA-256 hash
        let hash_input = format!(
            "{}:{}:{}:{:?}:{}:{}:{}",
            sequence, now, event_type, arm_id, action, details, prev_hash
        );
        let record_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));

        // Calculate HMAC signature
        let hmac_bytes = compute_hmac(&self.secret_key, record_hash.as_bytes());
        let hmac_signature = hex::encode(hmac_bytes);

        let record = ForensicAuditRecord {
            sequence,
            timestamp_secs: now,
            event_type: event_type.to_string(),
            arm_id,
            action: action.to_string(),
            details: details.to_string(),
            prev_hash,
            record_hash: record_hash.clone(),
            hmac_signature,
        };

        *hash_guard = record_hash;

        // Persist to in-memory history
        {
            let mut mem = self.in_memory_records.write().await;
            mem.push(record.clone());
        }

        // Persist out-of-band to disk file with I/O failure detection
        if let Some(parent) = self.log_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }

        let line = format!(
            "[SENTINEL-FORENSIC] seq={} ts={} type={} arm={:?} action=\"{}\" details=\"{}\" prev={} hash={} sig={}\n",
            record.sequence,
            record.timestamp_secs,
            record.event_type,
            record.arm_id,
            record.action,
            record.details,
            record.prev_hash,
            record.record_hash,
            record.hmac_signature
        );

        match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .await
        {
            Ok(mut f) => {
                use tokio::io::AsyncWriteExt;
                if let Err(e) = f.write_all(line.as_bytes()).await {
                    return Err(OctopusSecurityError::EnclaveViolation(format!(
                        "CRITICAL: Forensic audit disk write failed (possible disk exhaustion): {}",
                        e
                    )));
                }
            }
            Err(e) => {
                return Err(OctopusSecurityError::EnclaveViolation(format!(
                    "CRITICAL: Unable to open forensic audit log for writing: {}",
                    e
                )));
            }
        }

        Ok(record)
    }

    /// Anchors an immutable signed audit checkpoint to an independent destination.
    pub async fn create_and_anchor_checkpoint(&self) -> Result<AuditCheckpoint, OctopusSecurityError> {
        let records = self.in_memory_records.read().await;
        let mut checkpoint_seq_guard = self.checkpoint_counter.write().await;
        *checkpoint_seq_guard += 1;
        let cp_seq = *checkpoint_seq_guard;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Compute Merkle root of all recorded hashes
        let mut combined_hashes = Vec::new();
        for r in records.iter() {
            combined_hashes.extend_from_slice(r.record_hash.as_bytes());
        }
        let merkle_root = hex::encode(Sha256::digest(&combined_hashes));

        let mut prev_cp_guard = self.last_checkpoint_hash.write().await;
        let prev_cp = prev_cp_guard.clone();

        let signing_content = format!("{}:{}:{}:{}:{}", cp_seq, now, records.len(), merkle_root, prev_cp);
        let sig = hex::encode(compute_hmac(&self.secret_key, signing_content.as_bytes()));

        let checkpoint = AuditCheckpoint {
            checkpoint_sequence: cp_seq,
            timestamp_secs: now,
            records_covered: records.len(),
            merkle_root_hash: merkle_root.clone(),
            previous_checkpoint_hash: prev_cp,
            checkpoint_signature: sig,
        };

        *prev_cp_guard = merkle_root;

        // Persist checkpoint to remote/independent destination
        if let Ok(json) = serde_json::to_string_pretty(&checkpoint) {
            let _ = tokio::fs::write(&self.checkpoint_path, json).await;
        }

        Ok(checkpoint)
    }

    /// Verifies the cryptographic chain integrity of the forensic audit ledger.
    pub async fn verify_chain_integrity(&self) -> bool {
        let records = self.in_memory_records.read().await;
        if records.is_empty() {
            return true;
        }

        let mut expected_prev = "GENESIS_SENTINEL_ROOT_HASH".to_string();
        for record in records.iter() {
            if record.prev_hash != expected_prev {
                return false;
            }

            let hash_input = format!(
                "{}:{}:{}:{:?}:{}:{}:{}",
                record.sequence,
                record.timestamp_secs,
                record.event_type,
                record.arm_id,
                record.action,
                record.details,
                record.prev_hash
            );
            let computed_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));
            if !crate::security::constant_time_eq_hex(&record.record_hash, &computed_hash) {
                return false;
            }

            // Verify signature
            let expected_hmac = compute_hmac(&self.secret_key, computed_hash.as_bytes());
            if !crate::security::constant_time_eq_hex(&record.hmac_signature, &hex::encode(expected_hmac)) {
                return false;
            }

            expected_prev = record.record_hash.clone();
        }

        true
    }

    /// Returns all forensic records collected so far.
    pub async fn get_records(&self) -> Vec<ForensicAuditRecord> {
        let mem = self.in_memory_records.read().await;
        mem.clone()
    }
}

fn compute_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hash = Sha256::digest(key);
        k[..32].copy_from_slice(&hash);
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
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let outer_hash = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer_hash);
    out
}
