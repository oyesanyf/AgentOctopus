use super::types::{EventKind, TemporalEvent};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::security::audit::SecurityAuditLog;
use sha2::{Digest, Sha256};

/// Sliding window event store for historical temporal evaluation.
/// Enforces strong separation between production (tamper-resistant, durable, cryptographically authenticated)
/// and simulation (isolated, in-memory, non-polluting) history traces.
pub struct TemporalEventTrace {
    events: RwLock<Vec<TemporalEvent>>,
    max_retention_secs: u64,
    audit_log: Option<Arc<SecurityAuditLog>>,
    durable_log_path: Option<PathBuf>,
    is_simulation: bool,
}

impl Default for TemporalEventTrace {
    fn default() -> Self {
        Self::new_simulation()
    }
}

impl TemporalEventTrace {
    /// Creates an in-memory simulation trace for sandbox experimentation and what-if evaluation.
    /// Simulated events NEVER touch the audit log or durable disk.
    pub fn new_simulation() -> Self {
        Self {
            events: RwLock::new(Vec::new()),
            max_retention_secs: 86400 * 7,
            audit_log: None,
            durable_log_path: None,
            is_simulation: true,
        }
    }

    /// Creates an authoritative production trace anchored to the cryptographic SecurityAuditLog
    /// and durably persisted to an append-only JSONL log. Automatically recovers existing events on startup.
    pub fn new_production<P: AsRef<Path>>(audit_log: Arc<SecurityAuditLog>, durable_path: P) -> Self {
        let path_buf = durable_path.as_ref().to_path_buf();
        let mut recovered_events = Vec::new();

        if path_buf.exists() {
            if let Ok(file) = File::open(&path_buf) {
                let reader = BufReader::new(file);
                for line in reader.lines().flatten() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Ok(event) = serde_json::from_str::<TemporalEvent>(trimmed) {
                        recovered_events.push(event);
                    }
                }
            }
        }

        Self {
            events: RwLock::new(recovered_events),
            max_retention_secs: 86400 * 30, // 30-day retention for production
            audit_log: Some(audit_log),
            durable_log_path: Some(path_buf),
            is_simulation: false,
        }
    }

    pub fn with_audit_log(mut self, audit_log: Arc<SecurityAuditLog>) -> Self {
        self.audit_log = Some(audit_log);
        self
    }

    pub fn is_simulation(&self) -> bool {
        self.is_simulation
    }

    pub fn durable_log_path(&self) -> Option<&PathBuf> {
        self.durable_log_path.as_ref()
    }

    /// Records an authentic security event in the production trace.
    /// Automatically derives timestamp from system clock (SystemTime::now()) to prevent caller forgery.
    /// Cryptographically commits the event to SecurityAuditLog and appends to durable disk.
    pub fn record_event(
        &self,
        action: &str,
        kind: EventKind,
        caller_principal: &str,
        caller_resource: &str,
        fields: HashMap<String, serde_json::Value>,
    ) -> u64 {
        let timestamp_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let record_hash = if let Some(ref audit) = self.audit_log {
            audit.record_event(
                &format!("TEMPORAL_EVENT_{:?}", kind),
                caller_principal,
                &format!("Action: {} | Resource: {}", action, caller_resource),
                "RECORDED",
            )
        } else {
            // Standalone cryptographic hash
            let mut hasher = Sha256::new();
            hasher.update(timestamp_secs.to_le_bytes());
            hasher.update(action.as_bytes());
            hasher.update(caller_principal.as_bytes());
            hasher.update(caller_resource.as_bytes());
            if let Ok(fields_json) = serde_json::to_string(&fields) {
                hasher.update(fields_json.as_bytes());
            }
            hex::encode(hasher.finalize())
        };

        let mut trace = self.events.write().unwrap();
        let id = trace.len() as u64;
        let event = TemporalEvent {
            id,
            timestamp_secs,
            action: action.to_string(),
            kind,
            caller_principal: caller_principal.to_string(),
            caller_resource: caller_resource.to_string(),
            fields,
            record_hash,
        };

        // Durably append to disk if durable_log_path is configured
        if let Some(ref path) = self.durable_log_path {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                if let Ok(serialized) = serde_json::to_string(&event) {
                    let _ = writeln!(file, "{}", serialized);
                    let _ = file.flush();
                }
            }
        }

        trace.push(event);

        // Prune events older than max_retention_secs (memory bounds)
        if trace.len() > 5000 {
            if let Some(cutoff) = timestamp_secs.checked_sub(self.max_retention_secs) {
                trace.retain(|e| e.timestamp_secs >= cutoff);
            }
        }
        id
    }

    /// Records a simulated event for testing and UI sandbox experimentation.
    /// Strictly forbidden from polluting production audit logs or persistent storage.
    pub fn record_simulated_event(
        &self,
        timestamp_secs: u64,
        action: &str,
        kind: EventKind,
        caller_principal: &str,
        caller_resource: &str,
        fields: HashMap<String, serde_json::Value>,
    ) -> u64 {
        // If this is a production trace, reject arbitrary caller-supplied timestamps and route safely
        if !self.is_simulation {
            return self.record_event(action, kind, caller_principal, caller_resource, fields);
        }

        let mut hasher = Sha256::new();
        hasher.update(b"SIMULATION_NONCE_V1:");
        hasher.update(timestamp_secs.to_le_bytes());
        hasher.update(action.as_bytes());
        let record_hash = format!("SIMULATED:{}", hex::encode(hasher.finalize()));

        let mut trace = self.events.write().unwrap();
        let id = trace.len() as u64;
        let event = TemporalEvent {
            id,
            timestamp_secs,
            action: action.to_string(),
            kind,
            caller_principal: caller_principal.to_string(),
            caller_resource: caller_resource.to_string(),
            fields,
            record_hash,
        };

        trace.push(event);
        id
    }

    /// Attempts to clear the event trace.
    /// Invariant: Production security event history is tamper-resistant and cannot be wiped.
    /// Only isolated simulation traces may be cleared.
    pub fn clear(&self) -> Result<(), &'static str> {
        if !self.is_simulation {
            return Err("TAMPER_PROTECTION: Production temporal event history cannot be erased or cleared");
        }
        self.events.write().unwrap().clear();
        Ok(())
    }

    /// Returns a copy of the full trace up to timepoint index i (inclusive).
    pub fn get_history_up_to(&self, max_id: Option<u64>) -> Vec<TemporalEvent> {
        let trace = self.events.read().unwrap();
        match max_id {
            Some(max) => trace.iter().filter(|e| e.id <= max).cloned().collect(),
            None => trace.clone(),
        }
    }

    /// Slices history by principal (key-local semantics) up to max_id.
    pub fn slice_by_principal(&self, principal: &str, max_id: Option<u64>) -> Vec<TemporalEvent> {
        let trace = self.events.read().unwrap();
        trace
            .iter()
            .filter(|e| e.caller_principal == principal && max_id.map(|m| e.id <= m).unwrap_or(true))
            .cloned()
            .collect()
    }

    /// Returns total count of recorded events.
    pub fn len(&self) -> usize {
        self.events.read().unwrap().len()
    }

    /// Checks if trace is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
