use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    pub timestamp_secs: u64,
    pub event_type: String,
    pub agent_id: String,
    pub details: String,
    pub decision: String,
    pub prev_hash: String,
    pub record_hash: String,
}

/// Append-only, tamper-evident security audit log with in-memory hash-chaining
/// and external append-only disk persistence to survive process compromise.
pub struct SecurityAuditLog {
    records: Mutex<Vec<AuditRecord>>,
    last_hash: Mutex<String>,
    log_file_path: Option<PathBuf>,
}

impl Clone for SecurityAuditLog {
    fn clone(&self) -> Self {
        Self {
            records: Mutex::new(self.records.lock().unwrap_or_else(|e| e.into_inner()).clone()),
            last_hash: Mutex::new(self.last_hash.lock().unwrap_or_else(|e| e.into_inner()).clone()),
            log_file_path: self.log_file_path.clone(),
        }
    }
}

impl Default for SecurityAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityAuditLog {
    pub fn new() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            last_hash: Mutex::new("GENESIS_AUDIT_ROOT_000000000000000000000000000000000000000000000000".to_string()),
            log_file_path: None,
        }
    }

    pub fn with_disk_persistence(log_path: impl Into<PathBuf>) -> Self {
        let path = log_path.into();
        Self {
            records: Mutex::new(Vec::new()),
            last_hash: Mutex::new("GENESIS_AUDIT_ROOT_000000000000000000000000000000000000000000000000".to_string()),
            log_file_path: Some(path),
        }
    }

    pub fn record_event(
        &self,
        event_type: &str,
        agent_id: &str,
        details: &str,
        decision: &str,
    ) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut last_hash_lock = self.last_hash.lock().unwrap_or_else(|e| e.into_inner());
        let prev_hash = last_hash_lock.clone();

        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(event_type.as_bytes());
        hasher.update(agent_id.as_bytes());
        hasher.update(details.as_bytes());
        hasher.update(decision.as_bytes());
        hasher.update(&now.to_le_bytes());
        let record_hash = hex::encode(hasher.finalize());

        *last_hash_lock = record_hash.clone();

        let record = AuditRecord {
            timestamp_secs: now,
            event_type: event_type.to_string(),
            agent_id: agent_id.to_string(),
            details: details.to_string(),
            decision: decision.to_string(),
            prev_hash,
            record_hash: record_hash.clone(),
        };

        // 1. In-memory append
        let mut records_lock = self.records.lock().unwrap_or_else(|e| e.into_inner());
        records_lock.push(record.clone());

        // 2. External Append-Only Disk Persistence
        if let Some(ref path) = self.log_file_path {
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                if let Ok(serialized) = serde_json::to_string(&record) {
                    let _ = writeln!(file, "{}", serialized);
                    let _ = file.sync_all();
                }
            }
        }

        record_hash
    }

    /// Verifies the cryptographic integrity of the entire audit chain.
    pub fn verify_integrity(&self) -> bool {
        let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        let mut current_expected_prev = "GENESIS_AUDIT_ROOT_000000000000000000000000000000000000000000000000".to_string();

        for record in records.iter() {
            if record.prev_hash != current_expected_prev {
                return false;
            }

            let mut hasher = Sha256::new();
            hasher.update(record.prev_hash.as_bytes());
            hasher.update(record.event_type.as_bytes());
            hasher.update(record.agent_id.as_bytes());
            hasher.update(record.details.as_bytes());
            hasher.update(record.decision.as_bytes());
            hasher.update(&record.timestamp_secs.to_le_bytes());
            let computed_hash = hex::encode(hasher.finalize());

            if computed_hash != record.record_hash {
                return false;
            }

            current_expected_prev = record.record_hash.clone();
        }

        true
    }

    pub fn record_count(&self) -> usize {
        self.records.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn total_records(&self) -> usize {
        self.record_count()
    }

    pub fn latest_hash(&self) -> String {
        self.last_hash.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn get_entries(&self) -> Vec<AuditRecord> {
        self.records.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}
