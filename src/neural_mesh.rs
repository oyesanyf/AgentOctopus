//! Agent Octopus inter-arm neural mesh (trusted-process prototype).
//! This module transports typed messages; it is NOT an OS security boundary.
//! Actual process isolation, endpoint authentication and tool authorization
//! must be provided by the trusted supervisor and OS outside this module.
use std::collections::{HashMap, HashSet};
use tokio::sync::{mpsc, Mutex};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageKind { Finding, ThreatMapping, ChainCandidate, Alert }

#[derive(Debug, Clone)]
pub struct NeuralMessage {
    pub sender: String,
    pub recipient: String,
    pub kind: MessageKind,
    pub correlation_id: String,
    pub content: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MeshError { UnknownSender, UnknownRecipient, ForbiddenRoute, Full, Closed, Oversize }

struct MeshState {
    routes: HashSet<(String, String)>,
    senders: HashMap<String, mpsc::Sender<NeuralMessage>>,
}

/// Router and enrolled endpoints must be created and held by a trusted host.
#[derive(Clone)]
pub struct NeuralMesh { inner: Arc<Mutex<MeshState>> }

/// A host-bound sender identity; do NOT serialize or expose to untrusted code.
#[derive(Clone)]
pub struct ArmEndpoint { id: String, mesh: NeuralMesh }

impl NeuralMesh {
    pub fn new(allowed_routes: impl IntoIterator<Item = (String, String)>) -> Self {
        Self { inner: Arc::new(Mutex::new(MeshState {
            routes: allowed_routes.into_iter().collect(),
            senders: HashMap::new(),
        })) }
    }

    /// Enrollment is trusted-host-only. All receivers are bounded.
    pub async fn enroll(&self, id: &str, capacity: usize) -> Option<(ArmEndpoint, mpsc::Receiver<NeuralMessage>)> {
        if capacity == 0 { return None; }
        let mut state = self.inner.lock().await;
        if state.senders.contains_key(id) { return None; }
        let (tx, rx) = mpsc::channel(capacity);
        state.senders.insert(id.to_string(), tx);
        Some((ArmEndpoint { id: id.to_string(), mesh: self.clone() }, rx))
    }
}

impl ArmEndpoint {
    pub async fn send(&self, recipient: &str, kind: MessageKind, correlation_id: &str, content: &str) -> Result<(), MeshError> {
        const MAX_CONTENT_BYTES: usize = 16 * 1024;
        if content.len() > MAX_CONTENT_BYTES { return Err(MeshError::Oversize); }
        let sender = {
            let state = self.mesh.inner.lock().await;
            if !state.senders.contains_key(&self.id) { return Err(MeshError::UnknownSender); }
            if !state.routes.contains(&(self.id.clone(), recipient.to_string())) { return Err(MeshError::ForbiddenRoute); }
            state.senders.get(recipient).cloned().ok_or(MeshError::UnknownRecipient)?
        };
        sender.try_send(NeuralMessage {
            sender: self.id.clone(), recipient: recipient.to_string(),
            kind, correlation_id: correlation_id.to_string(), content: content.to_string(),
        }).map_err(|err| match err {
            mpsc::error::TrySendError::Full(_) => MeshError::Full,
            mpsc::error::TrySendError::Closed(_) => MeshError::Closed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_a_permitted_interarm_message() {
        let mesh = NeuralMesh::new([(String::from("vulnerability"), String::from("atlas"))]);
        let (vuln, _) = mesh.enroll("vulnerability", 2).await.unwrap();
        let (_, mut atlas_rx) = mesh.enroll("atlas", 2).await.unwrap();
        vuln.send("atlas", MessageKind::Finding, "case-1", "policy weakness").await.unwrap();
        let msg = atlas_rx.recv().await.unwrap();
        assert_eq!(msg.sender, "vulnerability");
        assert_eq!(msg.content, "policy weakness");
    }

    #[tokio::test]
    async fn denies_a_forbidden_route() {
        let mesh = NeuralMesh::new([]);
        let (vuln, _) = mesh.enroll("vulnerability", 2).await.unwrap();
        let (_, _) = mesh.enroll("ledger", 2).await.unwrap();
        assert_eq!(vuln.send("ledger", MessageKind::Finding, "case-2", "write ledger").await, Err(MeshError::ForbiddenRoute));
    }

    #[tokio::test]
    async fn enforces_bounded_inbox() {
        let mesh = NeuralMesh::new([(String::from("a"), String::from("b"))]);
        let (a, _) = mesh.enroll("a", 1).await.unwrap();
        let (_, _b_rx) = mesh.enroll("b", 1).await.unwrap();
        a.send("b", MessageKind::Alert, "1", "first").await.unwrap();
        assert_eq!(a.send("b", MessageKind::Alert, "2", "second").await, Err(MeshError::Full));
    }
}
