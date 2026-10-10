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
use crate::telemetry::detector::AnomalyDetector;
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};

pub struct ArmRuntime {
    role: ArmRole,
    tools: HashMap<String, Box<dyn SafeTool>>,
    directive_rx: mpsc::Receiver<(
        StrategicDirective,
        oneshot::Sender<Result<ArmExecutionReport, OctopusSecurityError>>,
    )>,
    telemetry_tx: mpsc::Sender<TelemetryPacket>,
    kill_switch: KillSwitch,
    deterministic_layer: DeterministicLayer,
    step_limit: usize,
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
        let mut tools: HashMap<String, Box<dyn SafeTool>> = HashMap::new();
        match role {
            ArmRole::UntrustedDocIngest => {
                tools.insert("doc_extractor".into(), Box::new(SafeDocumentExtractor::new()));
            }
            ArmRole::AccountingLedgerWrite => {
                tools.insert("ledger_writer".into(), Box::new(SafeLedgerWriter::new()));
            }
            ArmRole::NetworkEgress => {
                tools.insert("http_egress".into(), Box::new(HttpEgressGate::default()));
            }
            ArmRole::OutboundNotification => {}
            ArmRole::TarpitDecoyDefense => {}
            ArmRole::KernelLevelSentinel => {}
        }

        Self {
            role,
            tools,
            directive_rx,
            telemetry_tx,
            kill_switch,
            deterministic_layer: DeterministicLayer::new(),
            step_limit: 10,
        }
    }

    /// Primary execution loop running inside an asynchronous task
    pub async fn run(mut self) {
        while let Some((directive, response_tx)) = self.directive_rx.recv().await {
            // Check hardware/atomic circuit breaker prior to processing
            if self.kill_switch.is_tripped() {
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
                        // Instantly trip the atomic kill switch, quarantine state, and halt execution!
                        self.kill_switch.trip();
                        self.deterministic_layer.quarantine();
                    }
                    _ => {}
                }
            }
            let _ = response_tx.send(result);
            if self.kill_switch.is_tripped() {
                break; // Stop arm execution loop immediately
            }
        }
    }

    async fn execute_directive(
        &mut self,
        directive: StrategicDirective,
    ) -> Result<ArmExecutionReport, OctopusSecurityError> {
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

        // Check if supervisory loop tripped autotomy
        if self.kill_switch.is_tripped() {
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

        if self.kill_switch.is_tripped() {
            self.deterministic_layer.quarantine();
            return Err(OctopusSecurityError::LimbKilled);
        }

        let merkle_tree = MerkleTree::from_leaves(execution_leaves);
        let merkle_root = merkle_tree.root_hex();

        // Gate 3: Cryptographic Merkle Root Sealing
        self.deterministic_layer.seal_merkle_trace(&merkle_root)?;

        match self.role {
            ArmRole::UntrustedDocIngest => {
                let extractor = SafeDocumentExtractor::new();
                let artifact = extractor.extract_artifact(raw_payload, merkle_root.clone(), current_step)?;

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
            ArmRole::AccountingLedgerWrite => {
                if let Some(tool) = self.tools.get("ledger_writer") {
                    let _ = tool.execute(raw_payload)?;
                }
                let _ = self.deterministic_layer.fsm.transition_to(crate::deterministic::fsm::ArmState::Completed);

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
            ArmRole::NetworkEgress => {
                if let Some(tool) = self.tools.get("http_egress") {
                    let _ = tool.execute(raw_payload)?;
                }
                let _ = self.deterministic_layer.fsm.transition_to(crate::deterministic::fsm::ArmState::Completed);

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
            ArmRole::OutboundNotification | ArmRole::TarpitDecoyDefense | ArmRole::KernelLevelSentinel => {
                let _ = self.deterministic_layer.fsm.transition_to(crate::deterministic::fsm::ArmState::Completed);
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
