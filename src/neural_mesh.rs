//! Agent Octopus inter-arm neural mesh (trusted-process prototype).
//! This module transports typed messages; it is NOT an OS security boundary.
//! Actual process isolation, endpoint authentication and tool authorization
//! must be provided by the trusted supervisor and OS outside this module.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex};

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

pub const MAX_METADATA_BYTES: usize = 128;
pub const MAX_ENDPOINTS: usize = 1024;
pub const MAX_CONTENT_BYTES: usize = 16 * 1024;
pub const MAX_CLOCK_SKEW_MS: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageKind {
    Finding,
    ThreatMapping,
    ChainCandidate,
    Alert,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeuralMessage {
    pub sender: String,
    pub recipient: String,
    pub kind: MessageKind,
    pub correlation_id: String,
    pub content: String,
    pub nonce: u64,
    pub timestamp_ms: u64,
    pub signature: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MeshError {
    UnknownSender,
    UnknownRecipient,
    ForbiddenRoute,
    Full,
    Closed,
    Oversize,
    OversizeMetadata,
    AuthenticationFailed,
    ReplayDetected,
    MaxEndpointsExceeded,
}

fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
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
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let outer_hash = outer.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(&outer_hash);
    result
}

fn build_sign_payload(
    sender: &str,
    recipient: &str,
    kind: &MessageKind,
    correlation_id: &str,
    content: &str,
    nonce: u64,
    timestamp_ms: u64,
) -> Vec<u8> {
    format!(
        "{}:{}:{:?}:{}:{}:{}:{}",
        sender, recipient, kind, correlation_id, content, nonce, timestamp_ms
    )
    .into_bytes()
}

struct MeshState {
    routes: HashSet<(String, String, Option<MessageKind>)>,
    senders: HashMap<String, mpsc::Sender<NeuralMessage>>,
    seen_nonces: HashSet<(String, u64)>,
    hmac_key: [u8; 32],
}

/// Router and enrolled endpoints must be created and held by a trusted host.
#[derive(Clone)]
pub struct NeuralMesh {
    inner: Arc<Mutex<MeshState>>,
}

/// A host-bound sender identity; do NOT serialize or expose to untrusted code.
#[derive(Clone)]
pub struct ArmEndpoint {
    id: String,
    mesh: NeuralMesh,
}

impl NeuralMesh {
    pub fn new(allowed_routes: impl IntoIterator<Item = (String, String)>) -> Self {
        let routes = allowed_routes
            .into_iter()
            .map(|(s, r)| (s, r, None))
            .collect();
        Self::with_routes_and_key(routes, *b"octo-mesh-default-hmac-key-2026!")
    }

    pub fn new_with_typed_routes(
        allowed_routes: impl IntoIterator<Item = (String, String, MessageKind)>,
    ) -> Self {
        let routes = allowed_routes
            .into_iter()
            .map(|(s, r, k)| (s, r, Some(k)))
            .collect();
        Self::with_routes_and_key(routes, *b"octo-mesh-default-hmac-key-2026!")
    }

    pub fn new_with_rules(
        allowed_routes: impl IntoIterator<Item = (String, String, Option<MessageKind>)>,
        hmac_key: [u8; 32],
    ) -> Self {
        Self::with_routes_and_key(allowed_routes.into_iter().collect(), hmac_key)
    }

    fn with_routes_and_key(
        routes: HashSet<(String, String, Option<MessageKind>)>,
        hmac_key: [u8; 32],
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MeshState {
                routes,
                senders: HashMap::new(),
                seen_nonces: HashSet::new(),
                hmac_key,
            })),
        }
    }

    /// Enrollment is trusted-host-only. Bounded at MAX_ENDPOINTS (1024).
    pub async fn enroll(
        &self,
        id: &str,
        capacity: usize,
    ) -> Option<(ArmEndpoint, mpsc::Receiver<NeuralMessage>)> {
        if capacity == 0 || id.is_empty() || id.len() > MAX_METADATA_BYTES {
            return None;
        }
        let mut state = self.inner.lock().await;
        if state.senders.len() >= MAX_ENDPOINTS {
            return None;
        }
        if state.senders.contains_key(id) {
            return None;
        }
        let (tx, rx) = mpsc::channel(capacity);
        state.senders.insert(id.to_string(), tx);
        Some((
            ArmEndpoint {
                id: id.to_string(),
                mesh: self.clone(),
            },
            rx,
        ))
    }

    /// Verifies cryptographic signature, freshness, and anti-replay status of a received message.
    pub async fn verify_message(&self, message: &NeuralMessage) -> Result<(), MeshError> {
        let state = self.inner.lock().await;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        if message.timestamp_ms.abs_diff(now_ms) > MAX_CLOCK_SKEW_MS {
            return Err(MeshError::AuthenticationFailed);
        }

        let expected_payload = build_sign_payload(
            &message.sender,
            &message.recipient,
            &message.kind,
            &message.correlation_id,
            &message.content,
            message.nonce,
            message.timestamp_ms,
        );
        let expected_sig = hex::encode(compute_hmac_sha256(&state.hmac_key, &expected_payload));

        if !crate::security::constant_time_eq_hex(&message.signature, &expected_sig) {
            return Err(MeshError::AuthenticationFailed);
        }

        Ok(())
    }
}

impl ArmEndpoint {
    pub async fn send(
        &self,
        recipient: &str,
        kind: MessageKind,
        correlation_id: &str,
        content: &str,
    ) -> Result<(), MeshError> {
        // Enforce string length bounds
        if content.len() > MAX_CONTENT_BYTES {
            return Err(MeshError::Oversize);
        }
        if correlation_id.len() > MAX_METADATA_BYTES || recipient.len() > MAX_METADATA_BYTES {
            return Err(MeshError::Oversize);
        }

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let nonce = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);

        let (target_tx, signature) = {
            let mut state = self.mesh.inner.lock().await;
            if !state.senders.contains_key(&self.id) {
                return Err(MeshError::UnknownSender);
            }

            // Route authorization checking: sender, recipient, and message_kind
            let exact_route = (self.id.clone(), recipient.to_string(), Some(kind.clone()));
            let wildcard_route = (self.id.clone(), recipient.to_string(), None);
            if !state.routes.contains(&exact_route) && !state.routes.contains(&wildcard_route) {
                return Err(MeshError::ForbiddenRoute);
            }

            // Replay protection: check and record (sender, nonce)
            let nonce_key = (self.id.clone(), nonce);
            if state.seen_nonces.contains(&nonce_key) {
                return Err(MeshError::ReplayDetected);
            }
            state.seen_nonces.insert(nonce_key);

            let payload = build_sign_payload(
                &self.id,
                recipient,
                &kind,
                correlation_id,
                content,
                nonce,
                timestamp_ms,
            );
            let sig = hex::encode(compute_hmac_sha256(&state.hmac_key, &payload));

            let tx = state
                .senders
                .get(recipient)
                .cloned()
                .ok_or(MeshError::UnknownRecipient)?;
            (tx, sig)
        };

        target_tx
            .try_send(NeuralMessage {
                sender: self.id.clone(),
                recipient: recipient.to_string(),
                kind,
                correlation_id: correlation_id.to_string(),
                content: content.to_string(),
                nonce,
                timestamp_ms,
                signature,
            })
            .map_err(|err| match err {
                mpsc::error::TrySendError::Full(_) => MeshError::Full,
                mpsc::error::TrySendError::Closed(_) => MeshError::Closed,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_a_permitted_interarm_message_with_hmac_auth() {
        let mesh = NeuralMesh::new([(String::from("vulnerability"), String::from("atlas"))]);
        let (vuln, _) = mesh.enroll("vulnerability", 2).await.unwrap();
        let (_, mut atlas_rx) = mesh.enroll("atlas", 2).await.unwrap();
        vuln.send("atlas", MessageKind::Finding, "case-1", "policy weakness")
            .await
            .unwrap();
        let msg = atlas_rx.recv().await.unwrap();
        assert_eq!(msg.sender, "vulnerability");
        assert_eq!(msg.content, "policy weakness");
        assert!(!msg.signature.is_empty());
        assert!(mesh.verify_message(&msg).await.is_ok());
    }

    #[tokio::test]
    async fn denies_a_forbidden_route() {
        let mesh = NeuralMesh::new([]);
        let (vuln, _) = mesh.enroll("vulnerability", 2).await.unwrap();
        let (_, _) = mesh.enroll("ledger", 2).await.unwrap();
        assert_eq!(
            vuln.send("ledger", MessageKind::Finding, "case-2", "write ledger")
                .await,
            Err(MeshError::ForbiddenRoute)
        );
    }

    #[tokio::test]
    async fn denies_forbidden_message_kind_on_typed_route() {
        let mesh = NeuralMesh::new_with_typed_routes([(
            "sentinel".to_string(),
            "supervisor".to_string(),
            MessageKind::Alert,
        )]);
        let (sentinel, _) = mesh.enroll("sentinel", 2).await.unwrap();
        let (_, mut sup_rx) = mesh.enroll("supervisor", 2).await.unwrap();

        // Finding is forbidden on Alert-only route
        let res = sentinel
            .send("supervisor", MessageKind::Finding, "c-1", "not alert")
            .await;
        assert_eq!(res, Err(MeshError::ForbiddenRoute));

        // Alert is allowed
        let res_alert = sentinel
            .send("supervisor", MessageKind::Alert, "c-2", "alert msg")
            .await;
        assert!(res_alert.is_ok());
        let received = sup_rx.recv().await.unwrap();
        assert_eq!(received.kind, MessageKind::Alert);
    }

    #[tokio::test]
    async fn enforces_string_bounds_on_metadata() {
        let mesh = NeuralMesh::new([("a".to_string(), "b".to_string())]);
        let (a, _) = mesh.enroll("a", 2).await.unwrap();
        let (_, _) = mesh.enroll("b", 2).await.unwrap();

        let long_corr_id = "X".repeat(129);
        let res = a.send("b", MessageKind::Alert, &long_corr_id, "test").await;
        assert_eq!(res, Err(MeshError::Oversize));
    }

    #[tokio::test]
    async fn rejects_tampered_signature() {
        let mesh = NeuralMesh::new([("a".to_string(), "b".to_string())]);
        let (a, _) = mesh.enroll("a", 2).await.unwrap();
        let (_, mut b_rx) = mesh.enroll("b", 2).await.unwrap();

        a.send("b", MessageKind::Finding, "c-1", "authentic")
            .await
            .unwrap();
        let mut msg = b_rx.recv().await.unwrap();
        assert!(mesh.verify_message(&msg).await.is_ok());

        msg.content = "forged content".to_string();
        assert_eq!(
            mesh.verify_message(&msg).await,
            Err(MeshError::AuthenticationFailed)
        );
    }

    #[tokio::test]
    async fn enforces_bounded_inbox() {
        let mesh = NeuralMesh::new([(String::from("a"), String::from("b"))]);
        let (a, _) = mesh.enroll("a", 1).await.unwrap();
        let (_, _b_rx) = mesh.enroll("b", 1).await.unwrap();
        a.send("b", MessageKind::Alert, "1", "first").await.unwrap();
        assert_eq!(
            a.send("b", MessageKind::Alert, "2", "second").await,
            Err(MeshError::Full)
        );
    }
}
