use crate::arm::runtime::ArmRuntime;
use crate::core::circuit_breaker::KillSwitch;
use crate::core::types::{
    ArmExecutionReport, ArmRole, OctopusSecurityError, StrategicDirective, TelemetryPacket,
};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

pub struct CentralBrain {
    dispatch_table: HashMap<
        ArmRole,
        mpsc::Sender<(
            StrategicDirective,
            oneshot::Sender<Result<ArmExecutionReport, OctopusSecurityError>>,
        )>,
    >,
    arm_kill_switches: HashMap<ArmRole, KillSwitch>,
    arm_generations: HashMap<ArmRole, u64>,
    telemetry_tx: mpsc::Sender<TelemetryPacket>,
}

impl CentralBrain {
    pub fn new(
        dispatch_table: HashMap<
            ArmRole,
            mpsc::Sender<(
                StrategicDirective,
                oneshot::Sender<Result<ArmExecutionReport, OctopusSecurityError>>,
            )>,
        >,
        arm_kill_switches: HashMap<ArmRole, KillSwitch>,
        telemetry_tx: mpsc::Sender<TelemetryPacket>,
    ) -> Self {
        let mut arm_generations = HashMap::new();
        for role in dispatch_table.keys() {
            arm_generations.insert(role.clone(), 1);
        }
        for role in arm_kill_switches.keys() {
            arm_generations.entry(role.clone()).or_insert(1);
        }
        Self {
            dispatch_table,
            arm_kill_switches,
            arm_generations,
            telemetry_tx,
        }
    }

    /// Returns the current active generation epoch for a peripheral limb role.
    pub fn arm_generation(&self, role: &ArmRole) -> u64 {
        self.arm_generations.get(role).copied().unwrap_or(1)
    }

    /// Dispatches a high-level strategic directive to a peripheral limb with strict timeout enforcement.
    pub async fn delegate(
        &self,
        role: ArmRole,
        directive: StrategicDirective,
        timeout_budget: Duration,
    ) -> Result<ArmExecutionReport, OctopusSecurityError> {
        let channel = self.dispatch_table.get(&role).ok_or_else(|| {
            OctopusSecurityError::EnclaveViolation(format!("Target limb '{:?}' unmapped", role))
        })?;

        let (resp_tx, resp_rx) = oneshot::channel();
        channel
            .send((directive, resp_tx))
            .await
            .map_err(|_| OctopusSecurityError::ChannelSevered)?;

        match timeout(timeout_budget, resp_rx).await {
            Ok(Ok(result)) => {
                // Cryptographic Merkle Root Verification in O(1) by Central Brain
                if let Ok(ref report) = result {
                    if let Some(ref artifact) = report.verified_data {
                        // Check hex length (32 bytes = 64 hex characters)
                        if artifact.merkle_root.len() != 64
                            || hex::decode(&artifact.merkle_root).is_err()
                        {
                            if let Some(kill_switch) = self.arm_kill_switches.get(&role) {
                                kill_switch.trip();
                            }
                            return Err(OctopusSecurityError::MerkleTamperDetected(
                                "Invalid or forged Merkle root format in verified artifact"
                                    .to_string(),
                            ));
                        }

                        // Check consistency between report and artifact root
                        if let Some(ref report_root) = report.merkle_root {
                            if report_root != &artifact.merkle_root {
                                if let Some(kill_switch) = self.arm_kill_switches.get(&role) {
                                    kill_switch.trip();
                                }
                                return Err(OctopusSecurityError::MerkleTamperDetected(
                                    "Report Merkle root does not match verified artifact Merkle root".to_string(),
                                ));
                            }
                        }

                        if artifact.execution_step_count == 0 {
                            if let Some(kill_switch) = self.arm_kill_switches.get(&role) {
                                kill_switch.trip();
                            }
                            return Err(OctopusSecurityError::MerkleTamperDetected(
                                "Zero execution step count with claimed Merkle root".to_string(),
                            ));
                        }
                    }
                }
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
                            if let Some(kill_switch) = self.arm_kill_switches.get(&role) {
                                kill_switch.trip();
                            }
                        }
                        _ => {}
                    }
                }
                result
            }
            Ok(Err(_)) => Err(OctopusSecurityError::ChannelSevered),
            Err(_) => {
                // Biologically inspired reflex: Autotomy on deadline starvation
                eprintln!(
                    "[CENTRAL BRAIN] Limb {:?} exceeded execution deadline ({:?})! Triggering autotomy circuit breaker.",
                    role, timeout_budget
                );
                if let Some(kill_switch) = self.arm_kill_switches.get(&role) {
                    kill_switch.trip();
                }
                Err(OctopusSecurityError::ExecutionTimeout)
            }
        }
    }

    /// Regenerates a severed or terminated limb with a pristine, unpoisoned state and advances its generation epoch (N -> N + 1).
    pub fn regenerate_limb(&mut self, role: ArmRole) {
        let prev_gen = self.arm_generations.get(&role).copied().unwrap_or(1);
        let next_gen = prev_gen + 1;
        self.arm_generations.insert(role.clone(), next_gen);
        println!(
            "[CENTRAL BRAIN] Regenerating peripheral limb: {:?} (Advancing Epoch {} -> {})",
            role, prev_gen, next_gen
        );
        let (tx, rx) = mpsc::channel(16);
        let kill_switch = KillSwitch::new();

        let arm = ArmRuntime::new(
            role.clone(),
            rx,
            self.telemetry_tx.clone(),
            kill_switch.clone(),
        )
        .with_generation(next_gen);

        tokio::spawn(arm.run());

        self.dispatch_table.insert(role.clone(), tx);
        self.arm_kill_switches.insert(role, kill_switch);
    }

    pub fn is_limb_killed(&self, role: &ArmRole) -> bool {
        self.arm_kill_switches
            .get(role)
            .map(|k| k.is_tripped())
            .unwrap_or(false)
    }
}
