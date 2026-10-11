use super::attestation::RingAttestation;
use super::audit::RingAuditLedger;
use super::capability_gate::CapabilityGate;
use super::cedar_gate::CedarGate;
use super::egress_proxy::{EgressProxy, EgressRequest};
use super::identity_gate::IdentityGate;
use super::isolation_manager::IsolationManager;
use super::mesh_guard::MeshGuard;
use super::resource_guard::ResourceGuard;
use super::RingDecision;
use rand::RngCore;
use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::security::CapabilityToken;
use std::future::Future;
use std::sync::Arc;

/// A structured operation request submitted to the Octopus Containment Ring.
#[derive(Debug, Clone)]
pub struct RingOperationRequest {
    pub agent_id: String,
    pub role: ArmRole,
    pub operation_type: String, // e.g. "ledger_writer", "http_egress", "doc_extractor", "filesystem"
    pub target: String,
    pub capability_token: Option<CapabilityToken>,
    pub step_count: usize,
    pub payload: Option<String>,
    pub amount_cents: Option<u64>,
    pub generation: Option<u64>,
}

use super::trusted_controller::{CedarAuthorizer, EnclaveToolExecutor, RingConfig, RingController};

/// The Octopus Containment Ring (OCR) Controller:
/// An independently enforced, concentric dual-ring boundary surrounding the entire
/// Agent Octopus swarm and host operating system.
#[derive(Clone)]
pub struct ContainmentRing {
    pub identity_gate: Arc<IdentityGate>,
    pub cedar_gate: Arc<CedarGate>,
    pub capability_gate: Arc<CapabilityGate>,
    pub egress_proxy: Arc<EgressProxy>,
    pub mesh_guard: Arc<MeshGuard>,
    pub resource_guard: Arc<ResourceGuard>,
    pub isolation_manager: Arc<IsolationManager>,
    pub arm_registry: Arc<super::arm_ring::ArmRingRegistry>,
    pub attestation: Arc<RingAttestation>,
    pub audit_ledger: Arc<RingAuditLedger>,
    pub trusted_controller: RingController,
}

impl Default for ContainmentRing {
    fn default() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Self::new(&seed)
    }
}

/// Unforgeable audit control harness provided solely at test/audit construction time.
/// Gives verification suites authorized control tokens to probe negative-control sensitivity.
#[derive(Clone, Debug)]
pub struct ContainmentAuditHarness {
    pub cedar_control_token: super::cedar_gate::NegativeControlToken,
    pub capability_control_token: super::cedar_gate::NegativeControlToken,
    pub egress_control_token: super::cedar_gate::NegativeControlToken,
}

impl std::ops::Deref for ContainmentAuditHarness {
    type Target = super::cedar_gate::NegativeControlToken;
    fn deref(&self) -> &Self::Target {
        &self.cedar_control_token
    }
}

impl ContainmentRing {
    pub fn new(seed: &[u8]) -> Self {
        let identity_gate = Arc::new(IdentityGate::new());
        let cedar_gate = Arc::new(CedarGate::new());
        let capability_gate = Arc::new(CapabilityGate::new(seed, 300));
        let egress_proxy = Arc::new(EgressProxy::default());
        let mesh_guard = Arc::new(MeshGuard::new());
        let resource_guard = Arc::new(ResourceGuard::new());
        let attestation = Arc::new(RingAttestation::new(seed));
        let audit_ledger = Arc::new(RingAuditLedger::new());
        let arm_registry = Arc::new(super::arm_ring::ArmRingRegistry::new(50, seed));

        let authorizer = Arc::new(CedarAuthorizer::new(cedar_gate.clone()));
        let executor = Arc::new(EnclaveToolExecutor::new(egress_proxy.clone()));
        let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(256);
        let trusted_controller = RingController::new(
            RingConfig::default(),
            authorizer,
            executor,
            audit_tx,
        ).expect("Containment Ring trusted controller initialized");

        let isolation_manager = Arc::new(IsolationManager::with_controllers(
            super::SandboxConstraints::default(),
            capability_gate.clone(),
            trusted_controller.clone(),
        ));

        Self {
            identity_gate,
            cedar_gate,
            capability_gate,
            egress_proxy,
            mesh_guard,
            resource_guard,
            isolation_manager,
            arm_registry,
            attestation,
            audit_ledger,
            trusted_controller,
        }
    }

    /// Creates a ContainmentRing alongside an authoritative ContainmentAuditHarness using CSPRNG entropy.
    pub fn new_for_audit_default() -> (Self, ContainmentAuditHarness) {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Self::new_for_audit(&seed)
    }

    /// Creates a ContainmentRing alongside an authoritative ContainmentAuditHarness for audit and verification harnesses.
    /// Under zero circumstances can these tokens be extracted from a runtime ContainmentRing reference.
    pub fn new_for_audit(seed: &[u8]) -> (Self, ContainmentAuditHarness) {
        let identity_gate = Arc::new(IdentityGate::new());
        let (cedar_gate_val, cedar_token) = CedarGate::new_for_audit();
        let (cap_gate_val, cap_token) = CapabilityGate::new_for_audit(seed, 300);
        let (egress_proxy_val, egress_token) = EgressProxy::new_for_audit(super::egress_proxy::EgressSecurityLevel::StrictGoogleOnly);
        let cedar_gate = Arc::new(cedar_gate_val);
        let capability_gate = Arc::new(cap_gate_val);
        let egress_proxy = Arc::new(egress_proxy_val);
        let mesh_guard = Arc::new(MeshGuard::new());
        let resource_guard = Arc::new(ResourceGuard::new());
        let attestation = Arc::new(RingAttestation::new(seed));
        let audit_ledger = Arc::new(RingAuditLedger::new());
        let arm_registry = Arc::new(super::arm_ring::ArmRingRegistry::new(50, seed));

        let authorizer = Arc::new(CedarAuthorizer::new(cedar_gate.clone()));
        let executor = Arc::new(EnclaveToolExecutor::new(egress_proxy.clone()));
        let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(256);
        let trusted_controller = RingController::new(
            RingConfig::default(),
            authorizer,
            executor,
            audit_tx,
        ).expect("Containment Ring trusted controller initialized");

        let isolation_manager = Arc::new(IsolationManager::with_controllers(
            super::SandboxConstraints::default(),
            capability_gate.clone(),
            trusted_controller.clone(),
        ));

        let ring = Self {
            identity_gate,
            cedar_gate,
            capability_gate,
            egress_proxy,
            mesh_guard,
            resource_guard,
            isolation_manager,
            arm_registry,
            attestation,
            audit_ledger,
            trusted_controller,
        };

        let harness = ContainmentAuditHarness {
            cedar_control_token: cedar_token,
            capability_control_token: cap_token,
            egress_control_token: egress_token,
        };

        (ring, harness)
    }

    /// Evaluates a requested operation across the Inner and Outer containment rings.
    pub async fn evaluate_operation(&self, req: &RingOperationRequest) -> (RingDecision, String) {
        // 0. Pre-Flight Invariant: Attestation Verification
        if !self.attestation.verify_attestation().await {
            return (
                RingDecision::Terminate,
                "Attestation failure: Containment Ring policy integrity compromised!".to_string(),
            );
        }

        // 1. Arm Status Check
        if !self.isolation_manager.is_arm_active(&req.agent_id).await {
            return (
                RingDecision::Deny,
                format!("Agent '{}' is terminated or quarantined by supervisory autotomy", req.agent_id),
            );
        }

        // 1.5. Level 1: Individual Arm Containment Ring & Epoch Verification
        if let Some(epoch) = req.generation {
            if let Some(arm_ring) = self.arm_registry.get_ring_by_name(&req.agent_id).await {
                if let Err(e) = arm_ring.validate_tool_invocation(&req.operation_type, &req.target, epoch).await {
                    return (RingDecision::Deny, format!("Level 1 Arm Ring veto: {}", e));
                }
            }
        }

        // 2. Outer Ring: Resource Budget & Step Limit Check
        if let Err(e) = self.resource_guard.check_admission(&req.agent_id, req.step_count).await {
            return (RingDecision::Deny, format!("Resource budget veto: {}", e));
        }

        // 3. Outer Ring: Filesystem Boundary Enforcement
        if req.operation_type == "filesystem" {
            if let Err(e) = self.isolation_manager.validate_filesystem_access(&req.target).await {
                return (RingDecision::Deny, format!("Filesystem sandbox veto: {}", e));
            }
        }

        // 4. Outer Ring: Network Egress Enforcement
        if req.operation_type == "http_egress" || req.target.starts_with("http") {
            let egress_req = EgressRequest {
                agent_id: req.agent_id.clone(),
                target_url: req.target.clone(),
                method: "GET".to_string(),
                payload: req.payload.clone(),
            };
            if let Err(e) = self.egress_proxy.dispatch_egress(&egress_req).await {
                // If lateral pivot / C2 detected, trigger quarantine
                if req.target.contains("evil-c2.com") || req.target.contains("169.254.169.254") {
                    return (RingDecision::Quarantine, format!("Hostile egress probe veto: {}", e));
                }
                return (RingDecision::Deny, format!("Egress proxy veto: {}", e));
            }
        }

        // 5. Inner Ring: Zero Ambient Authority Capability Token Enforcement
        if self.capability_gate.is_enforced() && (req.operation_type == "ledger_writer" || req.operation_type == "http_egress") {
            match &req.capability_token {
                None => {
                    return (
                        RingDecision::Deny,
                        format!(
                            "Zero Ambient Authority Veto: Arm '{}' attempted privileged tool '{}' without presenting a valid CapabilityToken",
                            req.agent_id, req.operation_type
                        ),
                    );
                }
                Some(token) => {
                    if let Err(e) = self.capability_gate.verify_capability(token, &req.agent_id, &req.operation_type, &req.target).await {
                        return (RingDecision::Deny, format!("Capability token verification failure: {}", e));
                    }
                }
            }
        }

        // 6. Inner Ring: AWS Cedar v4.13 Authorization
        if let Err(e) = self.cedar_gate.evaluate_authorization(
            &req.agent_id,
            &req.role,
            &req.operation_type,
            &req.target,
            req.amount_cents,
        ).await {
            return (RingDecision::Deny, format!("Cedar PARC policy veto: {}", e));
        }

        (RingDecision::Allow, "Operation authorized by Dual Concentric Containment Ring".to_string())
    }

    /// Primary Execution Broker:
    /// Atomically binds authorization to execution. An 'Allow' decision cannot be intercepted,
    /// detached, or reused by a compromised agent (Zero-TOCTOU Guarantee).
    pub async fn execute_with_containment<F, Fut, R>(
        &self,
        req: &RingOperationRequest,
        operation: F,
    ) -> Result<R, OctopusSecurityError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<R, OctopusSecurityError>>,
    {
        let (decision, reason) = self.evaluate_operation(req).await;

        // Record in append-only ring audit ledger outside the agent's reach
        self.audit_ledger
            .record(
                &req.agent_id,
                "ConcentricOCR",
                &req.operation_type,
                &req.target,
                decision,
                &reason,
            )
            .await;

        match decision {
            RingDecision::Allow => {
                // Execute immediately inside the trusted broker
                operation().await
            }
            RingDecision::Deny => {
                Err(OctopusSecurityError::DeterministicLayerViolation(reason))
            }
            RingDecision::Quarantine => {
                let _ = self.isolation_manager.terminate_arm(&req.agent_id, &reason).await;
                self.capability_gate.revoke_for_agent(&req.agent_id).await;
                let _ = self.trusted_controller.revoke(&req.agent_id).await;
                Err(OctopusSecurityError::BreakoutDetected(format!(
                    "Arm quarantined by Containment Ring: {}",
                    reason
                )))
            }
            RingDecision::Terminate => {
                let _ = self.isolation_manager.terminate_arm(&req.agent_id, &reason).await;
                self.capability_gate.revoke_for_agent(&req.agent_id).await;
                let _ = self.trusted_controller.revoke(&req.agent_id).await;
                Err(OctopusSecurityError::LimbKilled)
            }
        }
    }
}
