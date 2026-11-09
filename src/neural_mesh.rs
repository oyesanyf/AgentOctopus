//! Agent Octopus Inter-Arm Neural Mesh (Production-Matured Transport Layer).
//!
//! Provides authenticated, anti-replay, and capability-gated communication across arms.
//! Features:
//! - Typed AgentMesh URI schemes (`mcp://`, `a2a://`, `inference://`, `egress://`).
//! - Dual capability grants (`Call` vs `Publish`), preventing tool/model discovery spoofing.
//! - Bounded LRU/FIFO eviction on `seen_nonces` (max capacity 10,000, preventing memory leaks and OOM).
//! - Constant-time HMAC-SHA256 authentication.
//! - Strict payload size and metadata boundary enforcement.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex};

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

pub const MAX_METADATA_BYTES: usize = 128;
pub const MAX_ENDPOINTS: usize = 1024;
pub const MAX_CONTENT_BYTES: usize = 16 * 1024;
pub const MAX_CLOCK_SKEW_MS: u64 = 60_000;
pub const MAX_SEEN_NONCES: usize = 10_000;

pub const ALLOWED_MESH_SCHEMES: &[&str] = &["mcp://", "a2a://", "inference://", "egress://"];

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageKind {
    Finding,
    ThreatMapping,
    ChainCandidate,
    Alert,
}

/// Dual Capability Grant: Segregates Call authorization from Publish/Hosting authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MeshCapabilityGrant {
    Call(String),
    Publish(String),
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
    pub uri: Option<String>,
    pub grant: Option<MeshCapabilityGrant>,
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
    InvalidUriScheme,
    UnauthorizedCapabilityGrant,
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
    uri: Option<&str>,
    grant: Option<&MeshCapabilityGrant>,
) -> Vec<u8> {
    format!(
        "{}:{}:{:?}:{}:{}:{}:{}:{}:{:?}",
        sender,
        recipient,
        kind,
        correlation_id,
        content,
        nonce,
        timestamp_ms,
        uri.unwrap_or(""),
        grant
    )
    .into_bytes()
}

struct MeshState {
    routes: HashSet<(String, String, Option<MessageKind>)>,
    senders: HashMap<String, mpsc::Sender<NeuralMessage>>,
    seen_nonces: HashSet<(String, u64)>,
    nonce_queue: VecDeque<(String, u64)>,
    grants: HashMap<String, HashSet<MeshCapabilityGrant>>,
    hmac_key: [u8; 32],
}

/// Production-matured router held by trusted host.
#[derive(Clone)]
pub struct NeuralMesh {
    inner: Arc<Mutex<MeshState>>,
}

/// Host-bound sender endpoint.
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
                seen_nonces: HashSet::with_capacity(MAX_SEEN_NONCES),
                nonce_queue: VecDeque::with_capacity(MAX_SEEN_NONCES),
                grants: HashMap::new(),
                hmac_key,
            })),
        }
    }

    /// Grants a capability (Call or Publish) to an enrolled arm endpoint.
    pub async fn grant_capability(&self, arm_id: &str, grant: MeshCapabilityGrant) {
        let mut state = self.inner.lock().await;
        state
            .grants
            .entry(arm_id.to_string())
            .or_insert_with(HashSet::new)
            .insert(grant);
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
        let mut state = self.inner.lock().await;
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
            message.uri.as_deref(),
            message.grant.as_ref(),
        );
        let expected_sig = hex::encode(compute_hmac_sha256(&state.hmac_key, &expected_payload));

        if !crate::security::constant_time_eq_hex(&message.signature, &expected_sig) {
            return Err(MeshError::AuthenticationFailed);
        }

        // Receiver Anti-Replay: check and record seen nonces per sender (bounded FIFO queue)
        let nonce_key = (message.sender.clone(), message.nonce);
        if state.seen_nonces.contains(&nonce_key) {
            return Err(MeshError::ReplayDetected);
        }
        if state.seen_nonces.len() >= MAX_SEEN_NONCES {
            if let Some(oldest) = state.nonce_queue.pop_front() {
                state.seen_nonces.remove(&oldest);
            }
        }
        state.seen_nonces.insert(nonce_key.clone());
        state.nonce_queue.push_back(nonce_key);

        Ok(())
    }
}

impl ArmEndpoint {
    /// Standard dispatch for backwards compatibility
    pub async fn send(
        &self,
        recipient: &str,
        kind: MessageKind,
        correlation_id: &str,
        content: &str,
    ) -> Result<(), MeshError> {
        self.send_mesh(recipient, kind, correlation_id, content, None, None)
            .await
    }

    /// Production-matured dispatch supporting AgentMesh URI schemes and dual capability grants
    pub async fn send_mesh(
        &self,
        recipient: &str,
        kind: MessageKind,
        correlation_id: &str,
        content: &str,
        uri: Option<&str>,
        grant: Option<MeshCapabilityGrant>,
    ) -> Result<(), MeshError> {
        // Enforce string length bounds
        if content.len() > MAX_CONTENT_BYTES {
            return Err(MeshError::Oversize);
        }
        if correlation_id.len() > MAX_METADATA_BYTES || recipient.len() > MAX_METADATA_BYTES {
            return Err(MeshError::Oversize);
        }

        // Validate URI scheme if provided
        if let Some(target_uri) = uri {
            let valid_scheme = ALLOWED_MESH_SCHEMES
                .iter()
                .any(|s| target_uri.starts_with(s));
            if !valid_scheme {
                return Err(MeshError::InvalidUriScheme);
            }
        }

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let nonce = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);

        let (target_tx, signature) = {
            let state = self.mesh.inner.lock().await;
            if !state.senders.contains_key(&self.id) {
                return Err(MeshError::UnknownSender);
            }

            // Route authorization checking: sender, recipient, and message_kind
            let exact_route = (self.id.clone(), recipient.to_string(), Some(kind.clone()));
            let wildcard_route = (self.id.clone(), recipient.to_string(), None);
            if !state.routes.contains(&exact_route) && !state.routes.contains(&wildcard_route) {
                return Err(MeshError::ForbiddenRoute);
            }

            // Capability grant verification if grant is claimed
            if let Some(ref g) = grant {
                let authorized = state
                    .grants
                    .get(&self.id)
                    .map(|arm_grants| arm_grants.contains(g))
                    .unwrap_or(false);
                if !authorized {
                    return Err(MeshError::UnauthorizedCapabilityGrant);
                }
            }

            let payload = build_sign_payload(
                &self.id,
                recipient,
                &kind,
                correlation_id,
                content,
                nonce,
                timestamp_ms,
                uri,
                grant.as_ref(),
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
                uri: uri.map(|u| u.to_string()),
                grant,
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

    #[tokio::test]
    async fn test_typed_agentmesh_uris_and_dual_grants() {
        let mesh = NeuralMesh::new([("worker".to_string(), "service".to_string())]);
        let (worker, _) = mesh.enroll("worker", 4).await.unwrap();
        let (_, mut service_rx) = mesh.enroll("service", 4).await.unwrap();

        let call_grant = MeshCapabilityGrant::Call("mcp://calc".to_string());
        mesh.grant_capability("worker", call_grant.clone()).await;

        // Calling with valid URI and granted capability succeeds
        worker
            .send_mesh(
                "service",
                MessageKind::Finding,
                "corr-1",
                "calc_request",
                Some("mcp://calc"),
                Some(call_grant),
            )
            .await
            .unwrap();

        let received = service_rx.recv().await.unwrap();
        assert_eq!(received.uri, Some("mcp://calc".to_string()));
        assert!(mesh.verify_message(&received).await.is_ok());

        // Calling with ungranted publish capability fails
        let ungranted_publish =
            MeshCapabilityGrant::Publish("mcp://octopus/ledger_validator".to_string());
        let res = worker
            .send_mesh(
                "service",
                MessageKind::Finding,
                "corr-2",
                "publish_req",
                Some("mcp://octopus/ledger_validator"),
                Some(ungranted_publish),
            )
            .await;
        assert_eq!(res, Err(MeshError::UnauthorizedCapabilityGrant));
    }

    #[tokio::test]
    async fn test_invalid_uri_scheme_rejected() {
        let mesh = NeuralMesh::new([("a".to_string(), "b".to_string())]);
        let (a, _) = mesh.enroll("a", 2).await.unwrap();
        let (_, _) = mesh.enroll("b", 2).await.unwrap();

        let res = a
            .send_mesh(
                "b",
                MessageKind::Alert,
                "c",
                "msg",
                Some("http://evil.com"),
                None,
            )
            .await;
        assert_eq!(res, Err(MeshError::InvalidUriScheme));
    }
}
