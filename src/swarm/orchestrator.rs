use crate::arm::runtime::ArmRuntime;
use crate::core::circuit_breaker::KillSwitch;
use crate::core::types::{
    ArmExecutionReport, ArmRole, OctopusSecurityError, StrategicDirective, TelemetryPacket,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::timeout;

/// Manages a high-concurrency swarm of 50 autonomous limbs bounded by deterministic layers.
pub struct SwarmManager {
    concurrency_size: usize,
    dispatch_table: HashMap<
        usize,
        mpsc::Sender<(
            StrategicDirective,
            oneshot::Sender<Result<ArmExecutionReport, OctopusSecurityError>>,
        )>,
    >,
    arm_kill_switches: HashMap<usize, KillSwitch>,
    telemetry_tx: mpsc::Sender<TelemetryPacket>,
    semaphore: Arc<Semaphore>,
}

impl SwarmManager {
    pub fn telemetry_sender(&self) -> &mpsc::Sender<TelemetryPacket> {
        &self.telemetry_tx
    }
}

#[derive(Debug, Clone)]
pub struct SwarmBatchSummary {
    pub total_dispatched: usize,
    pub successful_completions: usize,
    pub deterministic_violations_blocked: usize,
    pub autotomy_tripped_count: usize,
}

impl SwarmManager {
    /// Spawns a pool of `size` concurrent arms (default: 50).
    pub fn new(size: usize, telemetry_tx: mpsc::Sender<TelemetryPacket>) -> Self {
        let mut dispatch_table = HashMap::new();
        let mut arm_kill_switches = HashMap::new();

        for arm_id in 0..size {
            let (tx, rx) = mpsc::channel(16);
            let kill_switch = KillSwitch::new();

            // Alternate roles across the 50 agents for diverse enterprise workloads
            let role = match arm_id % 3 {
                0 => ArmRole::UntrustedDocIngest,
                1 => ArmRole::AccountingLedgerWrite,
                _ => ArmRole::NetworkEgress,
            };

            let arm = ArmRuntime::new(
                role,
                rx,
                telemetry_tx.clone(),
                kill_switch.clone(),
            );

            tokio::spawn(arm.run());

            dispatch_table.insert(arm_id, tx);
            arm_kill_switches.insert(arm_id, kill_switch);
        }

        Self {
            concurrency_size: size,
            dispatch_table,
            arm_kill_switches,
            telemetry_tx,
            semaphore: Arc::new(Semaphore::new(size)),
        }
    }

    pub fn size(&self) -> usize {
        self.concurrency_size
    }

    /// Dispatches a batch of 50 tasks across all 50 arms concurrently,
    /// enforcing deterministic layer boundaries on every single task.
    pub async fn dispatch_swarm_batch(
        &self,
        tasks: Vec<StrategicDirective>,
        timeout_per_task: Duration,
    ) -> (Vec<Result<ArmExecutionReport, OctopusSecurityError>>, SwarmBatchSummary) {
        let mut handles = Vec::new();

        for (idx, directive) in tasks.into_iter().enumerate() {
            let arm_id = idx % self.concurrency_size;
            let channel = self.dispatch_table.get(&arm_id).unwrap().clone();
            let kill_switch = self.arm_kill_switches.get(&arm_id).unwrap().clone();
            let sem = self.semaphore.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();

                let (resp_tx, resp_rx) = oneshot::channel();
                if channel.send((directive, resp_tx)).await.is_err() {
                    return Err(OctopusSecurityError::ChannelSevered);
                }

                match timeout(timeout_per_task, resp_rx).await {
                    Ok(Ok(report_res)) => report_res,
                    Ok(Err(_)) => Err(OctopusSecurityError::ChannelSevered),
                    Err(_) => {
                        kill_switch.trip();
                        Err(OctopusSecurityError::ExecutionTimeout)
                    }
                }
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        let mut successful_completions = 0;
        let mut deterministic_violations_blocked = 0;
        let mut autotomy_tripped_count = 0;

        for handle in handles {
            let res = handle.await.unwrap_or_else(|_| Err(OctopusSecurityError::ChannelSevered));
            match &res {
                Ok(report) if report.success => successful_completions += 1,
                Err(OctopusSecurityError::DeterministicLayerViolation(_))
                | Err(OctopusSecurityError::IllegalStateTransition { .. })
                | Err(OctopusSecurityError::EnclaveViolation(_)) => {
                    deterministic_violations_blocked += 1;
                }
                Err(OctopusSecurityError::BreakoutDetected(_))
                | Err(OctopusSecurityError::SsrfBlocked(_))
                | Err(OctopusSecurityError::LimbKilled)
                | Err(OctopusSecurityError::MerkleTamperDetected(_)) => {
                    autotomy_tripped_count += 1;
                }
                _ => {}
            }
            results.push(res);
        }

        let total_dispatched = results.len();
        let summary = SwarmBatchSummary {
            total_dispatched,
            successful_completions,
            deterministic_violations_blocked,
            autotomy_tripped_count,
        };

        (results, summary)
    }
}
