use super::RingDecision;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RingAuditEntry {
    pub sequence_number: u64,
    pub timestamp_ms: u64,
    pub agent_id: String,
    pub ring_layer: String, // "InnerRing" or "OuterRing"
    pub operation: String,
    pub target: String,
    pub decision: RingDecision,
    pub reason: String,
    pub parent_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone)]
pub struct RingAuditLedger {
    entries: Arc<Mutex<Vec<RingAuditEntry>>>,
    latest_root: Arc<Mutex<String>>,
}

impl Default for RingAuditLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl RingAuditLedger {
    pub fn new() -> Self {
        let genesis_hash =
            hex::encode(Sha256::digest(b"OCTOPUS_CONTAINMENT_RING_AUDIT_GENESIS_V1"));
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            latest_root: Arc::new(Mutex::new(genesis_hash)),
        }
    }

    pub async fn record(
        &self,
        agent_id: &str,
        ring_layer: &str,
        operation: &str,
        target: &str,
        decision: RingDecision,
        reason: &str,
    ) -> RingAuditEntry {
        let mut entries = self.entries.lock().await;
        let mut root = self.latest_root.lock().await;

        let seq = entries.len() as u64 + 1;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let payload = format!(
            "{}:{}:{}:{}:{}:{:?}:{}:{}",
            seq, now, agent_id, ring_layer, operation, decision, reason, *root
        );
        let entry_hash = hex::encode(Sha256::digest(payload.as_bytes()));

        let entry = RingAuditEntry {
            sequence_number: seq,
            timestamp_ms: now,
            agent_id: agent_id.to_string(),
            ring_layer: ring_layer.to_string(),
            operation: operation.to_string(),
            target: target.to_string(),
            decision,
            reason: reason.to_string(),
            parent_hash: root.clone(),
            entry_hash: entry_hash.clone(),
        };

        *root = entry_hash;
        entries.push(entry.clone());
        entry
    }

    pub async fn verify_integrity(&self) -> bool {
        let entries = self.entries.lock().await;
        let mut current_hash =
            hex::encode(Sha256::digest(b"OCTOPUS_CONTAINMENT_RING_AUDIT_GENESIS_V1"));

        for entry in entries.iter() {
            if entry.parent_hash != current_hash {
                return false;
            }
            let payload = format!(
                "{}:{}:{}:{}:{}:{:?}:{}:{}",
                entry.sequence_number,
                entry.timestamp_ms,
                entry.agent_id,
                entry.ring_layer,
                entry.operation,
                entry.decision,
                entry.reason,
                entry.parent_hash
            );
            let expected_hash = hex::encode(Sha256::digest(payload.as_bytes()));
            if entry.entry_hash != expected_hash {
                return false;
            }
            current_hash = entry.entry_hash.clone();
        }
        true
    }

    pub async fn count(&self) -> usize {
        self.entries.lock().await.len()
    }

    pub async fn get_entries(&self) -> Vec<RingAuditEntry> {
        self.entries.lock().await.clone()
    }
}
