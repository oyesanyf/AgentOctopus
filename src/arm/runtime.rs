use crate::containment_ring::{
    ContainmentRing, Operation, RingError, RingOperationRequest, RingRequest, TrustedArmHandle,
};
use crate::core::circuit_breaker::KillSwitch;
use crate::core::merkle::{MerkleLeaf, MerkleTree};
use crate::core::types::{
    ArmExecutionReport, ArmRole, OctopusSecurityError, StrategicDirective, TelemetryPacket,
};
use crate::deterministic::layer::DeterministicLayer;
use crate::enclave::doc_extractor::SafeDocumentExtractor;
use crate::enclave::http_gate::HttpEgressGate;
use crate::enclave::ledger_writer::SafeLedgerWriter;
use crate::enclave::tool::SafeTool;
use crate::security::CapabilityToken;
use crate::telemetry::detector::AnomalyDetector;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

pub struct ArmRuntime {
    arm_id: Option<usize>,
    custom_agent_id: Option<String>,
    role: ArmRole,
    directive_rx: mpsc::Receiver<(
        StrategicDirective,
        oneshot::Sender<Result<ArmExecutionReport, OctopusSecurityError>>,
    )>,
    telemetry_tx: mpsc::Sender<TelemetryPacket>,
    kill_switch: KillSwitch,
    cancel_token: Option<tokio_util::sync::CancellationToken>,
    deterministic_layer: DeterministicLayer,
    step_limit: usize,
    containment_ring: Arc<ContainmentRing>,
    trusted_handle: Option<TrustedArmHandle>,
    capability_token: Option<CapabilityToken>,
    pub arm_ring: Option<Arc<crate::containment_ring::ArmContainmentRing>>,
    pub generation: u64,
}

impl ArmRuntime {
    pub fn new(
        role: ArmRole,
        directive_rx: mpsc::Receiver<(
            StrategicDirective,
            oneshot::Sender<Result<ArmExecutionReport, OctopusSecurityError>>,
        )>,
        telemetry_tx: mpsc::Sender<TelemetryPacket>,
        kill_switch: KillSwitch,
    ) -> Self {
        let containment_ring = Arc::new(ContainmentRing::default());
        let default_name = format!("arm-{:?}-0", role);
        let capability_token = match role {
            ArmRole::AccountingLedgerWrite => Some(containment_ring.capability_gate.issue_capability(
                "supervisor",
                &default_name,
                ArmRole::AccountingLedgerWrite,
                "ledger_writer",
                "s3://accounting/",
            )),
            ArmRole::NetworkEgress => Some(containment_ring.capability_gate.issue_capability(
                "supervisor",
                &default_name,
                ArmRole::NetworkEgress,
                "http_egress",
                "https://www.google.com/",
            )),
            _ => None,
        };

        let master_seed = crate::containment_ring::ArmRingRegistry::generate_master_seed();
        let arm_ring = Some(Arc::new(crate::containment_ring::ArmContainmentRing::new(
            0,
            role.clone(),
            1,
            &master_seed,
        )));

        Self {
            arm_id: None,
            custom_agent_id: None,
            role,
            directive_rx,
            telemetry_tx,
            kill_switch,
            cancel_token: None,
            deterministic_layer: DeterministicLayer::new(),
            step_limit: 10,
            containment_ring,
            trusted_handle: None,
            capability_token,
            arm_ring,
            generation: 1,
        }
    }

    pub fn with_arm_id(mut self, arm_id: usize) -> Self {
        self.arm_id = Some(arm_id);
        let master_seed = self
            .arm_ring
            .as_ref()
            .map(|r| *r.master_seed())
            .unwrap_or_else(crate::containment_ring::ArmRingRegistry::generate_master_seed);
        let ring = Arc::new(crate::containment_ring::ArmContainmentRing::new(
            arm_id,
            self.role.clone(),
            self.generation,
            &master_seed,
        ));
        self.arm_ring = Some(ring);
        let name = self.arm_name();
        match self.role {
            ArmRole::AccountingLedgerWrite => {
                self.capability_token = Some(self.containment_ring.capability_gate.issue_capability(
                    "supervisor",
                    &name,
                    ArmRole::AccountingLedgerWrite,
                    "ledger_writer",
                    "s3://accounting/",
                ));
            }
            ArmRole::NetworkEgress => {
                self.capability_token = Some(self.containment_ring.capability_gate.issue_capability(
                    "supervisor",
                    &name,
                    ArmRole::NetworkEgress,
                    "http_egress",
                    "https://www.google.com/",
                ));
            }
            _ => {}
        }
        self
    }

    pub fn with_arm_ring(mut self, arm_ring: Arc<crate::containment_ring::ArmContainmentRing>) -> Self {
        self.generation = arm_ring.current_generation();
        self.arm_ring = Some(arm_ring);
        self
    }

    pub fn with_generation(mut self, gen: u64) -> Self {
        self.generation = gen;
        if let Some(ref ring) = self.arm_ring {
            ring.generation.store(gen, std::sync::atomic::Ordering::SeqCst);
        }
        self
    }

    pub fn with_custom_agent_id(mut self, id: String) -> Self {
        self.custom_agent_id = Some(id);
        let name = self.arm_name();
        match self.role {
            ArmRole::AccountingLedgerWrite => {
                self.capability_token = Some(self.containment_ring.capability_gate.issue_capability(
                    "supervisor",
                    &name,
                    ArmRole::AccountingLedgerWrite,
                    "ledger_writer",
                    "s3://accounting/",
                ));
            }
            ArmRole::NetworkEgress => {
                self.capability_token = Some(self.containment_ring.capability_gate.issue_capability(
                    "supervisor",
                    &name,
                    ArmRole::NetworkEgress,
                    "http_egress",
                    "https://www.google.com/",
                ));
            }
            _ => {}
        }
        self
    }

    pub fn with_cancellation_token(mut self, token: tokio_util::sync::CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    pub fn with_containment_ring(mut self, ring: Arc<ContainmentRing>) -> Self {
        self.containment_ring = ring;
        let name = self.arm_name();
        match self.role {
            ArmRole::AccountingLedgerWrite => {
                self.capability_token = Some(self.containment_ring.capability_gate.issue_capability(
                    "supervisor",
                    &name,
                    ArmRole::AccountingLedgerWrite,
                    "ledger_writer",
                    "s3://accounting/",
                ));
            }
            ArmRole::NetworkEgress => {
                self.capability_token = Some(self.containment_ring.capability_gate.issue_capability(
                    "supervisor",
                    &name,
                    ArmRole::NetworkEgress,
                    "http_egress",
                    "https://www.google.com/",
                ));
            }
            _ => {}
        }
        self
    }

    pub fn with_trusted_handle(mut self, handle: TrustedArmHandle) -> Self {
        self.trusted_handle = Some(handle);
        self
    }

    pub fn with_capability_token(mut self, token: CapabilityToken) -> Self {
        self.capability_token = Some(token);
        self
    }

    pub fn without_capability_token(mut self) -> Self {
        self.capability_token = None;
        self
    }

    #[doc(hidden)]
    pub fn without_arm_ring_for_test(mut self) -> Self {
        self.arm_ring = None;
        self
    }

    pub fn arm_name(&self) -> String {
        if let Some(ref id) = self.custom_agent_id {
            return id.clone();
        }
        match self.arm_id {
            Some(id) => format!("arm-{:?}-{}", self.role, id),
            None => format!("arm-{:?}-0", self.role),
        }
    }

    fn extract_amount_cents(&self, payload: &str) -> Option<u64> {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(payload) {
            if let Some(amt) = val.get("amount_cents").and_then(|v| v.as_u64()) {
                return Some(amt);
            }
        }
        if let Some(pos) = payload.find('$') {
            let slice = &payload[pos + 1..];
            let num_str: String = slice
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if let Ok(dollars) = num_str.parse::<f64>() {
                return Some((dollars * 100.0).round() as u64);
            }
        }
        None
    }

    fn is_cancelled_or_killed(&self) -> bool {
        self.kill_switch.is_tripped()
            || self.cancel_token.as_ref().map_or(false, |t| t.is_cancelled())
    }

    /// Primary execution loop running inside an asynchronous task
    pub async fn run(mut self) {
        let agent_name = self.arm_name();
        if self.generation > 1 {
            let target_arm_id = self.arm_id.unwrap_or(0);
            if let Some(reg_ring) = self.containment_ring.arm_registry.get_ring(target_arm_id).await {
                if reg_ring.current_generation() < self.generation {
                    reg_ring
                        .generation
                        .store(self.generation, std::sync::atomic::Ordering::SeqCst);
                }
            }
            if let Some(sec_ring) = self
                .containment_ring
                .arm_registry
                .get_security_ring(self.role.clone())
                .await
            {
                if sec_ring.current_generation() < self.generation {
                    sec_ring
                        .generation
                        .store(self.generation, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
        self.containment_ring
            .isolation_manager
            .register_kill_switch(&agent_name, self.kill_switch.clone())
            .await;
        self.containment_ring
            .identity_gate
            .enroll(&agent_name, self.role.clone(), agent_name.as_bytes())
            .await;

        while let Some((directive, response_tx)) = self.directive_rx.recv().await {
            // Level 1: Mandatory Arm Containment Ring check (fail closed if missing or severed)
            let ring = match self.arm_ring.clone() {
                Some(r) => r,
                None => {
                    self.kill_switch.trip();
                    let _ = response_tx.send(Err(OctopusSecurityError::IsolationViolation(
                        "Execution halted: Missing mandatory Level 1 ArmContainmentRing".to_string(),
                    )));
                    break;
                }
            };

            // Check hardware/atomic circuit breaker, cancellation, isolation manager status, and Level 1 ring severance
            if self.is_cancelled_or_killed()
                || !self.containment_ring.isolation_manager.is_arm_active(&agent_name).await
                || ring.is_severed()
            {
                self.kill_switch.trip();
                let _ = response_tx.send(Err(OctopusSecurityError::LimbKilled));
                break;
            }

            let result = self.execute_directive(directive).await;
            if let Err(ref e) = result {
                match e {
                    OctopusSecurityError::MerkleTamperDetected(_)
                    | OctopusSecurityError::BreakoutDetected(_)
                    | OctopusSecurityError::SsrfBlocked(_)
                    | OctopusSecurityError::IllegalStateTransition { .. }
                    | OctopusSecurityError::DeterministicLayerViolation(_)
                    | OctopusSecurityError::CapabilityDenied(_)
                    | OctopusSecurityError::DelegationScopeViolation(_)
                    | OctopusSecurityError::IdentitySpoofingDetected(_)
                    | OctopusSecurityError::IsolationViolation(_)
                    | OctopusSecurityError::ResourceQuotaExceeded(_)
                    | OctopusSecurityError::EnclaveViolation(_) => {
                        // Tamper or security boundary breach detected:
                        // Instantly trip the atomic kill switch, quarantine state, sever Level 1 ring, and halt execution!
                        self.kill_switch.trip();
                        self.deterministic_layer.quarantine();
                        ring.sever("Breach detected during directive execution").await;
                        let _ = self
                            .containment_ring
                            .isolation_manager
                            .terminate_arm(&agent_name, "Breach detected during directive execution")
                            .await;
                    }
                    _ => {}
                }
            }
            let _ = response_tx.send(result);
            if self.kill_switch.is_tripped()
                || !self.containment_ring.isolation_manager.is_arm_active(&agent_name).await
                || ring.is_severed()
            {
                break; // Stop arm execution loop immediately
            }
        }
    }

    async fn execute_directive(
        &mut self,
        directive: StrategicDirective,
    ) -> Result<ArmExecutionReport, OctopusSecurityError> {
        // Level 1: Mandatory Arm Containment Ring epoch check (fail closed if missing or severed)
        let ring = match self.arm_ring.as_ref() {
            Some(r) => r,
            None => {
                return Err(OctopusSecurityError::IsolationViolation(
                    "Execution halted: Missing mandatory Level 1 ArmContainmentRing".to_string(),
                ));
            }
        };
        if ring.is_severed() {
            return Err(OctopusSecurityError::LimbKilled);
        }
        ring.validate_epoch(self.generation).await?;

        self.deterministic_layer = DeterministicLayer::new();

        // Physical & OS Sandbox Confinement Check (max_child_processes = 0, no path traversal)
        let sandbox_policy = crate::security::SandboxConfinementPolicy::default();
        sandbox_policy.validate_process_confinement(&directive.instruction)?;
        sandbox_policy.validate_filesystem_confinement(&directive.source_uri)?;
        if let Some(ref payload) = directive.raw_payload {
            sandbox_policy.validate_process_confinement(payload)?;
        }

        // Gate 1: Enforce directive policy & FSM transition to DirectiveAccepted
        self.deterministic_layer.accept_directive(&directive)?;

        // Gate 2: Enclave digest intake & FSM transition to EnclaveDigesting
        self.deterministic_layer.enter_enclave_digest()?;

        let mut current_step = 0;
        let effective_limit = directive.max_step_budget.min(self.step_limit);

        let mut execution_leaves: Vec<MerkleLeaf> = Vec::new();

        // Step 1: Pre-execution intake and out-of-band telemetry emission
        current_step += 1;
        execution_leaves.push(MerkleLeaf::new(
            current_step,
            "doc_extractor",
            &directive.source_uri,
            "telemetry_emitted",
        ));
        let step1_root = MerkleTree::from_leaves(execution_leaves.clone()).root_hex();

        self.emit_telemetry(
            &directive.directive_id,
            "doc_extractor",
            &directive.source_uri,
            current_step,
            Some(step1_root),
        )
        .await?;

        // Check if supervisory loop or cancellation tripped autotomy
        if self.is_cancelled_or_killed() {
            self.kill_switch.trip();
            self.deterministic_layer.quarantine();
            return Err(OctopusSecurityError::LimbKilled);
        }

        // Get raw payload from directive or source uri
        let raw_payload = directive.raw_payload.as_deref().unwrap_or(directive.source_uri.as_str());

        // Step 2: Digest raw content in peripheral scratchpad
        current_step += 1;
        if current_step > effective_limit {
            return Err(OctopusSecurityError::EnclaveViolation(
                "Limb step budget exceeded".to_string(),
            ));
        }

        execution_leaves.push(MerkleLeaf::new(
            current_step,
            "peripheral_digest",
            "local_scratchpad",
            "enclave_processed",
        ));
        let step2_root = MerkleTree::from_leaves(execution_leaves.clone()).root_hex();

        self.emit_telemetry(
            &directive.directive_id,
            "peripheral_digest",
            "local_scratchpad",
            current_step,
            Some(step2_root),
        )
        .await?;

        if self.is_cancelled_or_killed() {
            self.kill_switch.trip();
            self.deterministic_layer.quarantine();
            return Err(OctopusSecurityError::LimbKilled);
        }

        let merkle_tree = MerkleTree::from_leaves(execution_leaves);
        let merkle_root = merkle_tree.root_hex();

        // Gate 3: Cryptographic Merkle Root Sealing
        self.deterministic_layer.seal_merkle_trace(&merkle_root)?;

        let agent_name = self.arm_name();
        let (operation_type, ring_op) = match self.role {
            ArmRole::UntrustedDocIngest => ("doc_extractor", Operation::DocumentRead),
            ArmRole::AccountingLedgerWrite => ("ledger_writer", Operation::LedgerWrite),
            ArmRole::NetworkEgress => ("http_egress", Operation::HttpEgress),
            ArmRole::OutboundNotification => ("notifier", Operation::MeshMessage),
            ArmRole::TarpitDecoyDefense => ("quarantine", Operation::MeshMessage),
            ArmRole::KernelLevelSentinel => ("kernel_sentinel", Operation::MeshMessage),
            ArmRole::CedarPolicyEvaluation => ("cedar_evaluator", Operation::MeshMessage),
            ArmRole::AtlasThreatIntelligence => ("atlas_sync", Operation::MeshMessage),
            ArmRole::AnomalyDetection => ("behavioral_sentinel", Operation::MeshMessage),
            ArmRole::VulnerabilityResearch => ("vulnerability_scanner", Operation::MeshMessage),
            ArmRole::ContinuousOssFuzz => ("fuzz_mutator", Operation::MeshMessage),
            ArmRole::ContinuousOsvScanner => ("osv_client", Operation::MeshMessage),
            ArmRole::DifferentialProtocolAnalyzer => ("protocol_analyzer", Operation::MeshMessage),
            ArmRole::AutonomousProtocolResearch => ("protocol_research", Operation::MeshMessage),
            ArmRole::PostQuantumAttestation => ("pqc_attestation", Operation::MeshMessage),
            ArmRole::EvolutionaryOptimizer => ("evolutionary_optimizer", Operation::MeshMessage),
            ArmRole::DreamRsiOptimizer => ("dream_rsi_optimizer", Operation::MeshMessage),
        };

        let amount_cents = self.extract_amount_cents(raw_payload);

        let ring_req = RingOperationRequest {
            agent_id: agent_name.clone(),
            role: self.role.clone(),
            operation_type: operation_type.to_string(),
            target: directive.source_uri.clone(),
            capability_token: self.capability_token.clone(),
            step_count: current_step,
            payload: Some(raw_payload.to_string()),
            amount_cents,
            generation: Some(self.generation),
        };

        // ALL tool execution MUST route through the Containment Ring!
        let ring = self.containment_ring.clone();
        let trusted_handle = self.trusted_handle.clone();
        let target_resource = directive.source_uri.clone();
        let raw_payload_bytes = raw_payload.as_bytes().to_vec();
        let raw_payload_str = raw_payload.to_string();
        let merkle_root_for_exec = merkle_root.clone();
        let role_for_exec = self.role.clone();

        let tool_result_bytes: Result<Vec<u8>, OctopusSecurityError> = ring
            .execute_with_containment(&ring_req, || async move {
                if let Some(ref handle) = trusted_handle {
                    let tc_req = RingRequest {
                        operation: ring_op,
                        resource: target_resource,
                        body: raw_payload_bytes,
                    };
                    handle.request(tc_req).await.map_err(|e| match e {
                        RingError::Denied => OctopusSecurityError::CapabilityDenied(
                            "Containment Ring denied tool invocation".to_string(),
                        ),
                        RingError::Revoked => OctopusSecurityError::DeterministicLayerViolation(
                            "Arm authorization revoked by Containment Ring".to_string(),
                        ),
                        RingError::Oversize => OctopusSecurityError::IsolationViolation(
                            "Request payload oversize".to_string(),
                        ),
                        RingError::Busy => OctopusSecurityError::ResourceQuotaExceeded(
                            "Containment Ring busy".to_string(),
                        ),
                        RingError::Deadline => OctopusSecurityError::ExecutionTimeout,
                        RingError::PolicyUnavailable => {
                            OctopusSecurityError::DeterministicLayerViolation(
                                "Policy engine unavailable".to_string(),
                            )
                        }
                        RingError::UnknownArm => OctopusSecurityError::IdentitySpoofingDetected(
                            "Unknown arm handle".to_string(),
                        ),
                        RingError::ToolFailed => OctopusSecurityError::EnclaveViolation(
                            "Tool execution failure inside broker".to_string(),
                        ),
                    })
                } else {
                    // Execute safe tool inside the trusted broker closure
                    match role_for_exec {
                        ArmRole::UntrustedDocIngest => {
                            let extractor = SafeDocumentExtractor::new();
                            let artifact = extractor
                                .extract_artifact(&raw_payload_str, merkle_root_for_exec, current_step)?;
                            serde_json::to_vec(&artifact).map_err(|e| {
                                OctopusSecurityError::DeterministicLayerViolation(format!(
                                    "Serialization error: {}",
                                    e
                                ))
                            })
                        }
                        ArmRole::AccountingLedgerWrite => {
                            let writer = SafeLedgerWriter::new();
                            let res = writer.execute(&raw_payload_str)?;
                            Ok(res.into_bytes())
                        }
                        ArmRole::NetworkEgress => {
                            let egress_gate = HttpEgressGate::default();
                            let res = egress_gate.execute(&raw_payload_str)?;
                            Ok(res.into_bytes())
                        }
                        _ => Ok(raw_payload_bytes),
                    }
                }
            })
            .await;

        let output_bytes = match tool_result_bytes {
            Ok(b) => b,
            Err(e) => {
                self.kill_switch.trip();
                self.deterministic_layer.quarantine();
                return Err(e);
            }
        };

        match self.role {
            ArmRole::UntrustedDocIngest => {
                let artifact: crate::core::types::VerifiedInvoiceArtifact =
                    if let Ok(art) = serde_json::from_slice(&output_bytes) {
                        art
                    } else {
                        let extractor = SafeDocumentExtractor::new();
                        extractor.extract_artifact(raw_payload, merkle_root.clone(), current_step)?
                    };

                // Gate 4: Final Schema Assertion & Spending Cap & FSM Completion
                self.deterministic_layer.finalize_artifact(&artifact)?;

                Ok(ArmExecutionReport {
                    directive_id: directive.directive_id,
                    arm_role: format!("{:?}", self.role),
                    success: true,
                    verified_data: Some(artifact),
                    merkle_root: Some(merkle_root),
                    steps_taken: current_step,
                    anomaly_flag: false,
                })
            }
            _ => {
                let _ = self
                    .deterministic_layer
                    .fsm
                    .transition_to(crate::deterministic::fsm::ArmState::Completed);
                Ok(ArmExecutionReport {
                    directive_id: directive.directive_id,
                    arm_role: format!("{:?}", self.role),
                    success: true,
                    verified_data: None,
                    merkle_root: Some(merkle_root),
                    steps_taken: current_step,
                    anomaly_flag: false,
                })
            }
        }
    }

    async fn emit_telemetry(
        &self,
        directive_id: &str,
        tool: &str,
        target: &str,
        step: usize,
        incremental_root: Option<String>,
    ) -> Result<(), OctopusSecurityError> {
        let entropy_bits = AnomalyDetector::compute_shannon_entropy(target.as_bytes());

        self.telemetry_tx
            .send(TelemetryPacket {
                arm_id: self.arm_id,
                arm_role: self.role.clone(),
                directive_id: directive_id.to_string(),
                tool_invoked: tool.to_string(),
                raw_target: target.to_string(),
                step_index: step,
                entropy_bits,
                incremental_merkle_root: incremental_root,
            })
            .await
            .map_err(|_| OctopusSecurityError::ChannelSevered)
    }
}
