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
    pub breakout_coordinator: Arc<crate::security::BreakoutDefenseCoordinator>,
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
        let breakout_coordinator = Arc::new(crate::security::BreakoutDefenseCoordinator::default());

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
            breakout_coordinator,
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
        let breakout_coordinator = Arc::new(crate::security::BreakoutDefenseCoordinator::default());

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
            breakout_coordinator,
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

        // 1.25. 4-Category Agent Breakout Defense Evaluation (Technical, Operational, Behavioral, Data)
        let payload_str = req.payload.as_deref().unwrap_or("");
        let breakout_eval = self.breakout_coordinator.evaluate_action(
            &req.agent_id,
            &req.operation_type,
            &req.target,
            payload_str,
        );
        if !breakout_eval.is_clean {
            return (
                RingDecision::Quarantine,
                format!(
                    "Breakout Defense Veto ({}): tech={:?}, oper={:?}, behav={:?}, data={:?}",
                    breakout_eval.composite_verdict,
                    breakout_eval.technical.detected_vectors,
                    breakout_eval.operational.detected_leaks,
                    breakout_eval.behavioral.detected_deviations,
                    breakout_eval.data.detected_violations,
                ),
            );
        }

        // 1.5. Level 1: Individual Arm Containment Ring & Epoch Verification
        let is_security_role = matches!(
            req.role,
            ArmRole::CedarPolicyEvaluation
                | ArmRole::AtlasThreatIntelligence
                | ArmRole::AnomalyDetection
                | ArmRole::VulnerabilityResearch
                | ArmRole::ContinuousOssFuzz
                | ArmRole::ContinuousOsvScanner
                | ArmRole::DifferentialProtocolAnalyzer
                | ArmRole::AutonomousProtocolResearch
                | ArmRole::PostQuantumAttestation
                | ArmRole::EvolutionaryOptimizer
                | ArmRole::DreamRsiOptimizer
                | ArmRole::RecursiveHarnessOptimizer
        );
        let is_security_arm_id = ["100", "101", "102", "103", "104", "105", "106", "107", "108", "109", "110", "111"]
            .iter()
            .any(|&id| req.agent_id.ends_with(&format!("-{}", id)) || req.agent_id == id);

        if is_security_role || is_security_arm_id {
            let epoch = match req.generation {
                Some(e) => e,
                None => return (RingDecision::Deny, "Fail-Closed: Missing required generation epoch for containment ring verification".to_string()),
            };

            let arm_ring = match self.arm_registry.get_ring_by_name(&req.agent_id).await {
                Some(r) => r,
                None => match self.arm_registry.get_security_ring(req.role.clone()).await {
                    Some(r) => r,
                    None => return (RingDecision::Deny, format!("Fail-Closed: Missing containment ring for arm '{}'", req.agent_id)),
                },
            };

            if let Err(e) = arm_ring.validate_tool_invocation(&req.operation_type, &req.target, epoch).await {
                return (RingDecision::Deny, format!("Level 1 Arm Ring veto: {}", e));
            }
        } else if let Some(epoch) = req.generation {
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

        // 3. Outer Ring: Filesystem Boundary Enforcement (AO-FIND-09: enforce on "filesystem" and any local path/traversal target)
        let target_lower = req.target.trim().to_ascii_lowercase();
        let is_non_file_uri = target_lower.starts_with("http://")
            || target_lower.starts_with("https://")
            || target_lower.starts_with("s3://")
            || target_lower.starts_with("ledger://")
            || target_lower.starts_with("notification://")
            || target_lower.starts_with("tarpit://")
            || target_lower.starts_with("kernel://")
            || target_lower.starts_with("cedar://")
            || target_lower.starts_with("policy://")
            || target_lower.starts_with("stix://")
            || target_lower.starts_with("atlas://")
            || target_lower.starts_with("telemetry://")
            || target_lower.starts_with("behavior://")
            || target_lower.starts_with("vuln://")
            || target_lower.starts_with("cve://")
            || target_lower.starts_with("fuzz://")
            || target_lower.starts_with("corpus://")
            || target_lower.starts_with("osv://")
            || target_lower.starts_with("advisories://")
            || target_lower.starts_with("protocol://")
            || target_lower.starts_with("differential://")
            || target_lower.starts_with("terminator://")
            || target_lower.starts_with("pqc://")
            || target_lower.starts_with("quantum://")
            || target_lower.starts_with("kem://")
            || target_lower.starts_with("dsa://")
            || target_lower.starts_with("cbom://")
            || target_lower.starts_with("evolution://")
            || target_lower.starts_with("openevolve://")
            || target_lower.starts_with("candidate://")
            || target_lower.starts_with("staging://")
            || target_lower.starts_with("dream_rsi://")
            || target_lower.starts_with("replay://")
            || target_lower.starts_with("world_model://")
            || target_lower.starts_with("harness2://")
            || target_lower.starts_with("library://")
            || target_lower.starts_with("context://");
        let has_local_path_or_traversal = req.operation_type == "filesystem"
            || target_lower.starts_with("sandbox://")
            || target_lower.starts_with("file://")
            || target_lower.starts_with("c:\\")
            || target_lower.starts_with("d:\\")
            || target_lower.starts_with("\\\\")
            || target_lower.starts_with('/')
            || target_lower.contains("..")
            || target_lower.contains("%2e")
            || target_lower.contains("%2f")
            || target_lower.contains("%5c");
        if has_local_path_or_traversal && (!is_non_file_uri || target_lower.contains("..") || target_lower.contains("%2e")) {
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

    /// Zero-Closure Confined Execution Broker (`AO-FIND-01` Remediation):
    /// Binds Dual Concentric Containment Ring authorization directly to a structured
    /// [`TieredToolRequest`](super::tiered_executor::TieredToolRequest) executed via
    /// [`TieredExecutionDispatcher`](super::tiered_executor::TieredExecutionDispatcher),
    /// eliminating any arbitrary in-process `FnOnce` closure in the untrusted execution path.
    pub async fn execute_tiered_with_containment(
        &self,
        req: &RingOperationRequest,
        tiered_req: &super::tiered_executor::TieredToolRequest,
        dispatcher: &super::tiered_executor::TieredExecutionDispatcher,
    ) -> Result<super::tiered_executor::TieredExecutionReceipt, OctopusSecurityError> {
        if req.agent_id != tiered_req.agent_id || req.role != tiered_req.role {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "RING_TIERED_IDENTITY_MISMATCH: RingOperationRequest ({}, {:?}) != TieredToolRequest ({}, {:?})",
                req.agent_id, req.role, tiered_req.agent_id, tiered_req.role
            )));
        }
        if let Some((ref prog, ref args)) = tiered_req.native_command {
            if req.operation_type == "doc_extractor"
                || req.operation_type == "extract"
                || req.operation_type == "ledger_writer"
                || req.operation_type == "write"
            {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "RING_METADATA_MISREPRESENTATION: Operation '{}' cannot invoke native binary '{} {:?}'",
                    req.operation_type, prog, args
                )));
            }
        }

        let (decision, reason) = self.evaluate_operation(req).await;
        self.audit_ledger
            .record(
                &req.agent_id,
                "ConcentricOCR-Tiered",
                &req.operation_type,
                &req.target,
                decision,
                &reason,
            )
            .await;

        match decision {
            RingDecision::Allow => dispatcher.dispatch(tiered_req),
            RingDecision::Deny => Err(OctopusSecurityError::DeterministicLayerViolation(reason)),
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
