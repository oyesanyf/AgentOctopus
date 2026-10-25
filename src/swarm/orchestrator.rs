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
use tokio_util::sync::CancellationToken;

/// Manages a high-concurrency swarm of autonomous limbs bounded by deterministic layers.
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
    arm_cancel_tokens: HashMap<usize, CancellationToken>,
    arm_roles: HashMap<usize, ArmRole>,
    role_to_arms: HashMap<ArmRole, Vec<usize>>,
    telemetry_tx: mpsc::Sender<TelemetryPacket>,
    semaphore: Arc<Semaphore>,
    containment_ring: Arc<crate::containment_ring::ContainmentRing>,
}

impl SwarmManager {
    pub fn telemetry_sender(&self) -> &mpsc::Sender<TelemetryPacket> {
        &self.telemetry_tx
    }

    pub fn kill_switches(&self) -> HashMap<usize, KillSwitch> {
        self.arm_kill_switches.clone()
    }

    pub fn cancel_tokens(&self) -> HashMap<usize, CancellationToken> {
        self.arm_cancel_tokens.clone()
    }

    pub fn containment_ring(&self) -> &Arc<crate::containment_ring::ContainmentRing> {
        &self.containment_ring
    }

    pub async fn sever_arm(&self, arm_id: usize, reason: &str) -> Result<(), OctopusSecurityError> {
        if let Some(ks) = self.arm_kill_switches.get(&arm_id) {
            ks.trip();
        }
        if let Some(token) = self.arm_cancel_tokens.get(&arm_id) {
            token.cancel();
        }
        self.containment_ring.arm_registry.sever_arm(arm_id, reason).await
    }

    pub async fn regenerate_arm(&self, arm_id: usize) -> Result<u64, OctopusSecurityError> {
        self.containment_ring.arm_registry.sever_and_regenerate(arm_id).await
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
        let containment_ring = Arc::new(crate::containment_ring::ContainmentRing::default());
        let mut dispatch_table = HashMap::new();
        let mut arm_kill_switches = HashMap::new();
        let mut arm_cancel_tokens = HashMap::new();
        let mut arm_roles = HashMap::new();
        let mut role_to_arms: HashMap<ArmRole, Vec<usize>> = HashMap::new();

        if size > 0 {
            for arm_id in 0..size {
                let (tx, rx) = mpsc::channel(16);
                let kill_switch = KillSwitch::new();
                let cancel_token = CancellationToken::new();

                // Alternate roles across the agents for diverse enterprise workloads
                let role = match arm_id % 3 {
                    0 => ArmRole::UntrustedDocIngest,
                    1 => ArmRole::AccountingLedgerWrite,
                    _ => ArmRole::NetworkEgress,
                };

                let arm = ArmRuntime::new(
                    role.clone(),
                    rx,
                    telemetry_tx.clone(),
                    kill_switch.clone(),
                )
                .with_containment_ring(containment_ring.clone())
                .with_arm_id(arm_id)
                .with_cancellation_token(cancel_token.clone());

                tokio::spawn(arm.run());

                dispatch_table.insert(arm_id, tx);
                arm_kill_switches.insert(arm_id, kill_switch);
                arm_cancel_tokens.insert(arm_id, cancel_token);
                arm_roles.insert(arm_id, role.clone());
                role_to_arms.entry(role).or_default().push(arm_id);
            }
        }

        Self {
            concurrency_size: size,
            dispatch_table,
            arm_kill_switches,
            arm_cancel_tokens,
            arm_roles,
            role_to_arms,
            telemetry_tx,
            semaphore: Arc::new(Semaphore::new(size.max(1))),
            containment_ring,
        }
    }

    pub fn size(&self) -> usize {
        self.concurrency_size
    }

    /// Dispatches a batch of tasks across arms concurrently with role-based routing,
    /// full lifecycle timeout wrapping, and guaranteed cancellation/kill-switch enforcement.
    pub async fn dispatch_swarm_batch(
        &self,
        tasks: Vec<StrategicDirective>,
        timeout_per_task: Duration,
    ) -> (Vec<Result<ArmExecutionReport, OctopusSecurityError>>, SwarmBatchSummary) {
        // Zero-size swarm concurrency safety: prevent division-by-zero panics
        if self.concurrency_size == 0 || self.dispatch_table.is_empty() {
            let total = tasks.len();
            let results = tasks.into_iter().map(|_| Err(OctopusSecurityError::ZeroSwarmCapacity)).collect();
            let summary = SwarmBatchSummary {
                total_dispatched: total,
                successful_completions: 0,
                deterministic_violations_blocked: 0,
                autotomy_tripped_count: 0,
            };
            return (results, summary);
        }

        let mut handles = Vec::new();

        for (idx, directive) in tasks.into_iter().enumerate() {
            // Role-based task routing: dispatch tasks based on directive target role
            let target_role = directive.target_role();
            let arm_id = if let Some(candidate_arms) = self.role_to_arms.get(&target_role) {
                if !candidate_arms.is_empty() {
                    candidate_arms[idx % candidate_arms.len()]
                } else {
                    idx % self.concurrency_size
                }
            } else {
                idx % self.concurrency_size
            };

            let (Some(channel), Some(kill_switch), Some(cancel_token)) = (
                self.dispatch_table.get(&arm_id).cloned(),
                self.arm_kill_switches.get(&arm_id).cloned(),
                self.arm_cancel_tokens.get(&arm_id).cloned(),
            ) else {
                continue;
            };
            let sem = self.semaphore.clone();

            let handle = tokio::spawn(async move {
                // Full lifecycle deadline wrapping: wrap semaphore acquisition, channel send, and task execution inside timeout
                let lifecycle_future = async {
                    let permit = sem.acquire().await.map_err(|_| OctopusSecurityError::ChannelSevered)?;
                    let (resp_tx, resp_rx) = oneshot::channel();
                    if channel.send((directive, resp_tx)).await.is_err() {
                        return Err(OctopusSecurityError::ChannelSevered);
                    }
                    let report_res = resp_rx.await.map_err(|_| OctopusSecurityError::ChannelSevered)?;
                    drop(permit);
                    report_res
                };

                match timeout(timeout_per_task, lifecycle_future).await {
                    Ok(result) => result,
                    Err(_) => {
                        // Guaranteed execution termination on timeout: cancel token and trip kill switch
                        cancel_token.cancel();
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

    pub fn arm_roles(&self) -> &HashMap<usize, ArmRole> {
        &self.arm_roles
    }

    pub fn role_to_arms(&self) -> &HashMap<ArmRole, Vec<usize>> {
        &self.role_to_arms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_zero_size_swarm_concurrency_safety() {
        let (tx, _rx) = mpsc::channel(10);
        let zero_swarm = SwarmManager::new(0, tx);
        assert_eq!(zero_swarm.size(), 0);

        let tasks = vec![
            StrategicDirective {
                directive_id: "T-0".to_string(),
                source_uri: "s3://invoices/1.pdf".to_string(),
                instruction: "extract".to_string(),
                raw_payload: None,
                max_step_budget: 2,
            },
        ];

        let (results, summary) = zero_swarm.dispatch_swarm_batch(tasks, Duration::from_millis(100)).await;
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], Err(OctopusSecurityError::ZeroSwarmCapacity)));
        assert_eq!(summary.total_dispatched, 1);
        assert_eq!(summary.successful_completions, 0);
    }

    #[tokio::test]
    async fn test_role_based_task_routing() {
        let (tx, _rx) = mpsc::channel(100);
        let swarm = SwarmManager::new(6, tx);

        // Verify roles distribution
        let roles = swarm.arm_roles();
        assert_eq!(roles.len(), 6);
        assert_eq!(roles.get(&0), Some(&ArmRole::UntrustedDocIngest));
        assert_eq!(roles.get(&1), Some(&ArmRole::AccountingLedgerWrite));
        assert_eq!(roles.get(&2), Some(&ArmRole::NetworkEgress));

        let ledger_directive = StrategicDirective {
            directive_id: "T-LEDGER".to_string(),
            source_uri: "s3://accounting/ledger.json".to_string(),
            instruction: "ledger write".to_string(),
            raw_payload: Some("ACC-1234-USD".to_string()),
            max_step_budget: 3,
        };
        assert_eq!(ledger_directive.target_role(), ArmRole::AccountingLedgerWrite);

        let egress_directive = StrategicDirective {
            directive_id: "T-EGRESS".to_string(),
            source_uri: "https://www.google.com/search?q=test".to_string(),
            instruction: "network egress portal".to_string(),
            raw_payload: Some("https://www.google.com/search?q=test".to_string()),
            max_step_budget: 3,
        };
        assert_eq!(egress_directive.target_role(), ArmRole::NetworkEgress);
    }
}
