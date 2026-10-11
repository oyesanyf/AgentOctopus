//! Agent Octopus Containment Ring: trusted-host reference implementation.
//!
//! SECURITY BOUNDARY: This module is a policy/dispatch gateway, NOT a sandbox.
//! Only the trusted supervisor may hold `RingController` or `TrustedArmHandle`.
//! Untrusted agents must run in separate OS-constrained processes with no direct
//! filesystem, network, ledger, or privileged IPC handles. All privileged work
//! must go through a supervisor-owned ToolExecutor implementation.
use std::{collections::{HashMap, HashSet}, future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::{sync::{mpsc, Mutex, Semaphore}, time::{timeout, Instant}};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output=T> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Operation { DocumentRead, LedgerWrite, HttpEgress, MeshMessage }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RingRequest {
    pub operation: Operation,
    pub resource: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RingError { Denied, UnknownArm, Revoked, Oversize, Busy, Deadline, PolicyUnavailable, ToolFailed }

#[derive(Debug, Clone)]
pub struct RingConfig {
    pub max_request_bytes: usize,
    pub max_resource_bytes: usize,
    pub max_in_flight: usize,
    pub request_deadline: Duration,
}
impl Default for RingConfig {
    fn default() -> Self { Self {
        max_request_bytes: 16 * 1024, max_resource_bytes: 2048,
        max_in_flight: 50, request_deadline: Duration::from_secs(5),
    }}
}

#[derive(Debug, Clone)]
pub struct AuditEvent { pub arm_id: String, pub operation: Operation, pub outcome: RingError }

/// Adapter to Cedar. Deny by default if Cedar is unavailable or errors.
/// Implementation MUST map the authenticated identity, operation and resource
/// to a Cedar authorization request, not accept a principal from agent data.
pub trait Authorizer: Send + Sync {
    fn authorize<'a>(&'a self, arm_id: &'a str, role: &'a str,
        request: &'a RingRequest) -> BoxFuture<'a, Result<bool, ()>>;
}

/// Trusted broker is solely responsible for I/O. It MUST recheck revocation
/// immediately before irreversible side effects and provide OS isolation.
pub trait ToolExecutor: Send + Sync {
    fn execute<'a>(&'a self, arm_id: &'a str, request: &'a RingRequest)
        -> BoxFuture<'a, Result<Vec<u8>, ()>>;
}

struct ArmState { role: String, operations: HashSet<Operation>, revoked: bool }
struct Inner {
    arms: Mutex<HashMap<String, ArmState>>,
    capacity: Semaphore,
    config: RingConfig,
    authorizer: Arc<dyn Authorizer>,
    executor: Arc<dyn ToolExecutor>,
    audit: mpsc::Sender<AuditEvent>,
}

/// Supervisor-owned ring. Do not share with untrusted plugin/agent code.
#[derive(Clone)]
pub struct RingController { inner: Arc<Inner> }
/// A non-serializable identity-bound entry point, created by trusted enrollment.
#[derive(Clone)]
pub struct TrustedArmHandle { id: String, ring: RingController }

impl RingController {
    pub fn new(config: RingConfig, authorizer: Arc<dyn Authorizer>,
        executor: Arc<dyn ToolExecutor>, audit: mpsc::Sender<AuditEvent>) -> Result<Self, RingError> {
        if config.max_in_flight == 0 || config.max_request_bytes == 0 ||
           config.max_resource_bytes == 0 || config.request_deadline.is_zero() {
            return Err(RingError::Denied);
        }
        Ok(Self { inner: Arc::new(Inner {
            arms: Mutex::new(HashMap::new()), capacity: Semaphore::new(config.max_in_flight),
            config, authorizer, executor, audit,
        }) })
    }

    /// Call only after supervisor has authenticated/attested the arm process.
    pub async fn enroll(&self, id: String, role: String,
        operations: HashSet<Operation>) -> Result<TrustedArmHandle, RingError> {
        if id.is_empty() || role.is_empty() || id.len() > 128 || role.len() > 128 {
            return Err(RingError::Denied);
        }
        let mut arms = self.inner.arms.lock().await;
        if arms.contains_key(&id) { return Err(RingError::Denied); }
        arms.insert(id.clone(), ArmState { role, operations, revoked: false });
        Ok(TrustedArmHandle { id, ring: self.clone() })
    }

    /// Fail closed on the next request. Process destruction and credential
    /// invalidation are the *outer supervisor's* responsibility.
    pub async fn revoke(&self, id: &str) -> Result<(), RingError> {
        let mut arms = self.inner.arms.lock().await;
        let arm = arms.get_mut(id).ok_or(RingError::UnknownArm)?;
        arm.revoked = true;
        Ok(())
    }

    pub async fn is_revoked(&self, id: &str) -> Result<bool, RingError> {
        Ok(self.inner.arms.lock().await.get(id).ok_or(RingError::UnknownArm)?.revoked)
    }
}

impl TrustedArmHandle {
    pub fn arm_id(&self) -> &str { &self.id }

    pub async fn request(&self, request: RingRequest) -> Result<Vec<u8>, RingError> {
        let op = request.operation.clone();
        let outcome = self.process(request).await;
        if let Err(error) = &outcome {
            // Nonblocking audit; never let a dead telemetry consumer hang authorization.
            // Production deployments should use durable supervisor-side logging.
            let _ = self.ring.inner.audit.try_send(AuditEvent {
                arm_id: self.id.clone(), operation: op, outcome: error.clone(),
            });
        }
        outcome
    }

    async fn process(&self, request: RingRequest) -> Result<Vec<u8>, RingError> {
        let cfg = &self.ring.inner.config;
        if request.body.len() > cfg.max_request_bytes ||
           request.resource.len() > cfg.max_resource_bytes || request.resource.is_empty() {
            return Err(RingError::Oversize);
        }
        // Deadline covers semaphore wait, authorization and broker execution.
        let deadline = Instant::now() + cfg.request_deadline;
        timeout(cfg.request_deadline, self.process_before(deadline, request))
            .await.map_err(|_| RingError::Deadline)?
    }

    async fn process_before(&self, deadline: Instant, request: RingRequest)
        -> Result<Vec<u8>, RingError> {
        let _permit = self.ring.inner.capacity.acquire().await.map_err(|_| RingError::Busy)?;
        let role = {
            let arms = self.ring.inner.arms.lock().await;
            let arm = arms.get(&self.id).ok_or(RingError::UnknownArm)?;
            if arm.revoked { return Err(RingError::Revoked); }
            if !arm.operations.contains(&request.operation) { return Err(RingError::Denied); }
            arm.role.clone()
        };
        let allowed = self.ring.inner.authorizer.authorize(&self.id, &role, &request)
            .await.map_err(|_| RingError::PolicyUnavailable)?;
        if !allowed { return Err(RingError::Denied); }
        if Instant::now() >= deadline { return Err(RingError::Deadline); }
        if self.ring.is_revoked(&self.id).await? { return Err(RingError::Revoked); }
        // Execution is in a trusted broker, not performed by the caller.
        // Cancellation of this Future does NOT guarantee termination of I/O;
        // the external broker must enforce the same deadline and revocation.
        self.ring.inner.executor.execute(&self.id, &request)
            .await.map_err(|_| RingError::ToolFailed)
    }
}

/// Native implementation of Authorizer using AWS Cedar v4.13
pub struct CedarAuthorizer {
    cedar_gate: Arc<super::CedarGate>,
}

impl CedarAuthorizer {
    pub fn new(cedar_gate: Arc<super::CedarGate>) -> Self {
        Self { cedar_gate }
    }
}

impl Authorizer for CedarAuthorizer {
    fn authorize<'a>(&'a self, arm_id: &'a str, role_str: &'a str, request: &'a RingRequest)
        -> BoxFuture<'a, Result<bool, ()>> {
        Box::pin(async move {
            let role = match role_str {
                "ingest" | "doc_extractor" | "UntrustedDocIngest" | "DocumentRead" => crate::core::types::ArmRole::UntrustedDocIngest,
                "ledger" | "ledger_writer" | "AccountingLedgerWrite" | "LedgerWrite" => crate::core::types::ArmRole::AccountingLedgerWrite,
                "egress" | "http_egress" | "NetworkEgress" | "HttpEgress" => crate::core::types::ArmRole::NetworkEgress,
                "tarpit" | "TarpitDecoyDefense" => crate::core::types::ArmRole::TarpitDecoyDefense,
                "sentinel" | "kernel" | "KernelLevelSentinel" => crate::core::types::ArmRole::KernelLevelSentinel,
                "notifier" | "OutboundNotification" => crate::core::types::ArmRole::OutboundNotification,
                _ => crate::core::types::ArmRole::UntrustedDocIngest,
            };

            let action = match request.operation {
                Operation::DocumentRead => "extract",
                Operation::LedgerWrite => "write",
                Operation::HttpEgress => "egress",
                Operation::MeshMessage => "message",
            };

            // Extract amount_cents if payload contains JSON
            let amount_cents = if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&request.body) {
                val.get("amount_cents").and_then(|v| v.as_u64())
            } else {
                None
            };

            match self.cedar_gate.evaluate_authorization(arm_id, &role, action, &request.resource, amount_cents).await {
                Ok(allowed) => Ok(allowed),
                Err(crate::core::types::OctopusSecurityError::CapabilityDenied(_))
                | Err(crate::core::types::OctopusSecurityError::DeterministicLayerViolation(_)) => Ok(false),
                Err(_) => Err(()),
            }
        })
    }
}

/// Native implementation of ToolExecutor using trusted enclaves
pub struct EnclaveToolExecutor {
    egress_proxy: Arc<super::EgressProxy>,
}

impl EnclaveToolExecutor {
    pub fn new(egress_proxy: Arc<super::EgressProxy>) -> Self {
        Self { egress_proxy }
    }
}

impl ToolExecutor for EnclaveToolExecutor {
    fn execute<'a>(&'a self, arm_id: &'a str, request: &'a RingRequest)
        -> BoxFuture<'a, Result<Vec<u8>, ()>> {
        Box::pin(async move {
            match request.operation {
                Operation::DocumentRead => {
                    // Safe document parsing
                    let content = String::from_utf8_lossy(&request.body);
                    let extractor = crate::enclave::SafeDocumentExtractor::new();
                    use sha2::Digest;
                    let merkle_root = hex::encode(sha2::Sha256::digest(request.resource.as_bytes()));
                    match extractor.extract_artifact(&content, merkle_root, 1) {
                        Ok(artifact) => Ok(serde_json::to_vec(&artifact).unwrap_or_default()),
                        Err(_) => Err(()),
                    }
                }
                Operation::LedgerWrite => {
                    let content = String::from_utf8_lossy(&request.body);
                    let writer = crate::enclave::SafeLedgerWriter::new();
                    use crate::enclave::SafeTool;
                    match writer.execute(&content) {
                        Ok(res) => Ok(res.into_bytes()),
                        Err(_) => Err(()),
                    }
                }
                Operation::HttpEgress => {
                    let egress_req = super::EgressRequest {
                        agent_id: arm_id.to_string(),
                        target_url: request.resource.clone(),
                        method: "GET".to_string(),
                        payload: Some(String::from_utf8_lossy(&request.body).to_string()),
                    };
                    match self.egress_proxy.dispatch_egress(&egress_req).await {
                        Ok(resp) => Ok(resp.sanitized_body.into_bytes()),
                        Err(_) => Err(()),
                    }
                }
                Operation::MeshMessage => {
                    // Echo validated message bytes
                    Ok(request.body.clone())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct AllowPolicy;
    impl Authorizer for AllowPolicy {
        fn authorize<'a>(&'a self, _: &'a str, _: &'a str, _: &'a RingRequest)
            -> BoxFuture<'a, Result<bool, ()>> { Box::pin(async { Ok(true) }) }
    }
    struct EchoBroker;
    impl ToolExecutor for EchoBroker {
        fn execute<'a>(&'a self, _: &'a str, request: &'a RingRequest)
            -> BoxFuture<'a, Result<Vec<u8>, ()>> {
            Box::pin(async move { Ok(request.body.clone()) })
        }
    }
    async fn fixture() -> (RingController, TrustedArmHandle) {
        let (tx, _rx) = mpsc::channel(16);
        let ring = RingController::new(RingConfig::default(),
            Arc::new(AllowPolicy), Arc::new(EchoBroker), tx).unwrap();
        let handle = ring.enroll("ingest-1".into(), "ingest".into(),
            HashSet::from([Operation::DocumentRead])).await.unwrap();
        (ring, handle)
    }
    fn req(operation: Operation) -> RingRequest {
        RingRequest { operation, resource: "doc/1".into(), body: b"sample".to_vec() }
    }
    #[tokio::test]
    async fn allows_only_approved_operation() {
        let (_, arm) = fixture().await;
        assert_eq!(arm.request(req(Operation::DocumentRead)).await.unwrap(), b"sample");
        assert_eq!(arm.request(req(Operation::LedgerWrite)).await.unwrap_err(), RingError::Denied);
    }
    #[tokio::test]
    async fn revocation_denies_next_operation() {
        let (ring, arm) = fixture().await;
        ring.revoke("ingest-1").await.unwrap();
        assert_eq!(arm.request(req(Operation::DocumentRead)).await.unwrap_err(), RingError::Revoked);
    }
    #[tokio::test]
    async fn rejects_oversized_body() {
        let (_, arm) = fixture().await;
        let mut r = req(Operation::DocumentRead);
        r.body = vec![0u8; 16385];
        assert_eq!(arm.request(r).await.unwrap_err(), RingError::Oversize);
    }
    struct UnavailablePolicy;
    impl Authorizer for UnavailablePolicy {
        fn authorize<'a>(&'a self, _: &'a str, _: &'a str, _: &'a RingRequest)
            -> BoxFuture<'a, Result<bool, ()>> { Box::pin(async { Err(()) }) }
    }
    #[tokio::test]
    async fn denies_when_authorizer_is_unavailable() {
        let (tx, _rx) = mpsc::channel(1);
        let ring = RingController::new(RingConfig::default(),
            Arc::new(UnavailablePolicy), Arc::new(EchoBroker), tx).unwrap();
        let arm = ring.enroll("a".into(), "ingest".into(),
            HashSet::from([Operation::DocumentRead])).await.unwrap();
        assert_eq!(arm.request(req(Operation::DocumentRead)).await.unwrap_err(), RingError::PolicyUnavailable);
    }
    #[tokio::test]
    async fn duplicate_enrollment_is_rejected() {
        let (ring, _) = fixture().await;
        assert!(ring.enroll("ingest-1".into(), "ingest".into(), HashSet::new()).await.is_err());
    }
}
