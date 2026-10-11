//! Request-Response Desync Correlator for Differential Protocol Security.
//! Monitors sliding connection transaction states to detect HTTP response splitting,
//! orphaned response streams, pipelined desynchronization residues, and multiplexed desync.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// An anomaly event detected across the request-response correlation lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesyncEvent {
    pub event_id: String,
    pub timestamp_epoch_secs: u64,
    pub connection_id: u64,
    pub anomaly_kind: String,
    pub severity: String,
    pub details: String,
    pub request_hash: String,
}

/// State of an active TCP connection being tracked for desync anomalies.
#[derive(Debug, Clone)]
struct TrackedConnection {
    in_flight_requests: Vec<String>,
    total_requests: u64,
    total_responses: u64,
    last_activity_epoch: u64,
}

/// The Desync Correlator tracks connection lifecycles in real-time.
#[derive(Clone)]
pub struct DesyncCorrelator {
    connections: Arc<RwLock<HashMap<u64, TrackedConnection>>>,
    recent_events: Arc<RwLock<Vec<DesyncEvent>>>,
    connection_counter: Arc<AtomicU64>,
    total_desync_detected: Arc<AtomicU64>,
}

impl Default for DesyncCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl DesyncCorrelator {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            recent_events: Arc::new(RwLock::new(Vec::with_capacity(100))),
            connection_counter: Arc::new(AtomicU64::new(1)),
            total_desync_detected: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Allocates a new tracked connection ID.
    pub fn next_connection_id(&self) -> u64 {
        self.connection_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Records the ingress of a request on a connection.
    pub async fn record_request(&self, connection_id: u64, request_hash: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut conns = self.connections.write().await;
        let conn = conns.entry(connection_id).or_insert(TrackedConnection {
            in_flight_requests: Vec::new(),
            total_requests: 0,
            total_responses: 0,
            last_activity_epoch: now,
        });

        conn.total_requests += 1;
        conn.in_flight_requests.push(request_hash.to_string());
        conn.last_activity_epoch = now;
    }

    /// Records the egress of a response on a connection.
    /// Flags orphaned responses or desync if response count exceeds in-flight requests.
    pub async fn record_response(&self, connection_id: u64) -> Option<DesyncEvent> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut conns = self.connections.write().await;
        if let Some(conn) = conns.get_mut(&connection_id) {
            conn.total_responses += 1;
            conn.last_activity_epoch = now;

            if conn.in_flight_requests.is_empty() {
                // Response without a matching in-flight request: Orphaned Response (Desync)
                self.total_desync_detected.fetch_add(1, Ordering::SeqCst);
                let event = DesyncEvent {
                    event_id: format!("desync-{}", self.total_desync_detected.load(Ordering::SeqCst)),
                    timestamp_epoch_secs: now,
                    connection_id,
                    anomaly_kind: "ORPHANED_RESPONSE_DESYNC".to_string(),
                    severity: "CRITICAL".to_string(),
                    details: format!(
                        "Response generated on connection {} with zero in-flight requests (total req={}, resp={})",
                        connection_id, conn.total_requests, conn.total_responses
                    ),
                    request_hash: "none".to_string(),
                };

                let mut events = self.recent_events.write().await;
                if events.len() >= 100 {
                    events.remove(0);
                }
                events.push(event.clone());
                return Some(event);
            } else {
                conn.in_flight_requests.remove(0);
            }
        }
        None
    }

    /// Records trailing bytes or pipelining residue on a connection.
    pub async fn record_residue(&self, connection_id: u64, residue_bytes: usize, sample: &[u8]) -> DesyncEvent {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.total_desync_detected.fetch_add(1, Ordering::SeqCst);
        let sample_snippet = String::from_utf8_lossy(&sample[..sample.len().min(32)]).to_string();

        let event = DesyncEvent {
            event_id: format!("residue-{}", self.total_desync_detected.load(Ordering::SeqCst)),
            timestamp_epoch_secs: now,
            connection_id,
            anomaly_kind: "PIPELINED_SMUGGLING_RESIDUE".to_string(),
            severity: "HIGH".to_string(),
            details: format!(
                "Unconsumed pipelined residue on connection {}: {} bytes remaining. Snippet: {:?}",
                connection_id, residue_bytes, sample_snippet
            ),
            request_hash: format!("{:x}", md5_or_simple_hash(sample)),
        };

        let mut events = self.recent_events.write().await;
        if events.len() >= 100 {
            events.remove(0);
        }
        events.push(event.clone());
        event
    }

    /// Closes and cleans up a connection tracking record.
    pub async fn close_connection(&self, connection_id: u64) {
        let mut conns = self.connections.write().await;
        conns.remove(&connection_id);
    }

    /// Returns the recent desync events.
    pub async fn get_events(&self) -> Vec<DesyncEvent> {
        self.recent_events.read().await.clone()
    }

    /// Total count of detected desync events.
    pub fn total_desync_count(&self) -> u64 {
        self.total_desync_detected.load(Ordering::Relaxed)
    }
}

fn md5_or_simple_hash(data: &[u8]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    let mut hasher = DefaultHasher::new();
    hasher.write(data);
    hasher.finish()
}
