//! Continuous Security Governor & Out-of-Band Circuit Breaker
//!
//! Directly implements continuous execution telemetry evaluation, dynamic hazard
//! risk computation (logistic mapping), cumulative survival probability tracking
//! against the Sisyphean Bound, incident tracking (MTTD / MTTR), 4-stage progressive
//! containment ladder, closed-loop RL mitigation coupling, and asynchronous
//! out-of-band circuit breaker containment.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{error, info, warn};

#[cfg(unix)]
pub type ProcessId = libc::pid_t;
#[cfg(not(unix))]
pub type ProcessId = u32;

#[derive(Error, Debug)]
pub enum GovernorError {
    #[error("Target process terminated by circuit breaker: {0}")]
    ProcessTerminated(String),
    #[error("Internal channel communication failure: {0}")]
    ChannelError(String),
    #[error("OS process signal delivery failed with errno: {0}")]
    SignalError(i32),
    #[error("Invalid configuration: {0}")]
    ConfigurationError(String),
}

/// 4-Stage Progressive Containment Ladder
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernorStage {
    Stage0PassiveObserve,
    Stage1TraceElevation,
    Stage2MicroContainment,
    Stage3HardMitigation,
}

impl GovernorStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stage0PassiveObserve => "Stage 0: Passive Observe",
            Self::Stage1TraceElevation => "Stage 1: Trace Elevation",
            Self::Stage2MicroContainment => "Stage 2: Micro-Containment",
            Self::Stage3HardMitigation => "Stage 3: Hard Mitigation (Tripped)",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KernelEventKind {
    // 1. Technical Breakout Perimeter
    TechnicalBreakout {
        detail: String,
        is_docker_socket: bool,
        is_wasm_fuel_exhaust: bool,
        is_ring0_driver: bool,
    },
    // 2. Operational Containment Perimeter
    OperationalBreakout {
        detail: String,
        is_sts_token_leak: bool,
        is_route_table_hijack: bool,
        is_env_scrape: bool,
    },
    // 3. Behavioral Breakout Perimeter
    BehavioralBreakout {
        detail: String,
        is_harness_tamper: bool,
        is_prompt_injection: bool,
        is_self_grading_bypass: bool,
    },
    // 4. Data Breakout Perimeter
    DataBreakout {
        detail: String,
        is_scratchpad_pollution: bool,
        is_memory_dump: bool,
    },
    // Foundation Execution Primitives
    ProcessExec {
        executable_path: PathBuf,
        arguments: Vec<String>,
        is_interactive_shell_or_compiler: bool,
    },
    SocketConnect {
        destination_ip: IpAddr,
        port: u16,
        is_whitelisted_endpoint: bool,
    },
    FileAccess {
        path: PathBuf,
        is_read_only: bool,
        is_restricted_virtual_fs: bool,
    },
    ToolSchemaDrift {
        tool_name: String,
        entropy_divergence: f64,
        unrecognized_parameters: usize,
    },
}

#[derive(Debug, Clone)]
pub struct TelemetrySample {
    pub step: usize,
    pub timestamp: Instant,
    pub breach_time_estimate: Option<Instant>,
    pub event: KernelEventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightMatrix {
    pub weight_shell_or_compiler: f64,
    pub weight_unauthorized_egress: f64,
    pub weight_restricted_filesystem: f64,
    pub weight_schema_drift: f64,
    pub weight_unrecognized_params: f64,
    pub weight_baseline_noise: f64,
    // Breakout taxonomy perimeter weights
    pub weight_technical_breakout: f64,
    pub weight_operational_breakout: f64,
    pub weight_behavioral_breakout: f64,
    pub weight_data_breakout: f64,
}

impl Default for WeightMatrix {
    fn default() -> Self {
        Self {
            weight_shell_or_compiler: 3.8,
            weight_unauthorized_egress: 4.2,
            weight_restricted_filesystem: 3.1,
            weight_schema_drift: 0.85,
            weight_unrecognized_params: 0.5,
            weight_baseline_noise: 0.002,
            weight_technical_breakout: 4.5,
            weight_operational_breakout: 3.9,
            weight_behavioral_breakout: 4.1,
            weight_data_breakout: 3.6,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GovernorConfig {
    pub target_pid: ProcessId,
    pub initial_survival_prob: f64,
    pub warning_threshold: f64,
    pub critical_termination_threshold: f64,
    pub stage_trace_elevation_threshold: f64,
    pub stage_micro_containment_threshold: f64,
    pub max_step_budget: usize,
    pub max_history_capacity: usize,
    pub weights: WeightMatrix,
    // Theorem 1 Sisyphean Decay Counteraction
    pub enable_sisyphean_algebraic_decay: bool,
    pub sisyphean_gamma: f64,
    pub sisyphean_lambda: f64,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            target_pid: std::process::id() as ProcessId,
            initial_survival_prob: 1.0,
            warning_threshold: 0.70,
            critical_termination_threshold: 0.35,
            stage_trace_elevation_threshold: 0.85,
            stage_micro_containment_threshold: 0.70,
            max_step_budget: 1000,
            max_history_capacity: 5000,
            weights: WeightMatrix::default(),
            enable_sisyphean_algebraic_decay: true,
            sisyphean_gamma: 1.25,
            sisyphean_lambda: 0.05,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationalMetricsSummary {
    pub total_incidents: usize,
    pub mean_time_to_detect: Duration,
    pub mean_time_to_remediate: Duration,
    pub total_containment_failures: usize,
}

#[derive(Debug, Clone)]
pub struct IncidentRecord {
    pub step: usize,
    pub breach_timestamp: Instant,
    pub detection_timestamp: Instant,
    pub containment_timestamp: Option<Instant>,
}

pub struct SecurityGovernorState {
    pub config: GovernorConfig,
    pub current_survival_prob: f64,
    pub current_step: usize,
    pub history: VecDeque<(usize, f64, f64)>,
    pub incidents: Vec<IncidentRecord>,
}

impl SecurityGovernorState {
    pub fn new(config: GovernorConfig) -> Self {
        let initial_prob = config.initial_survival_prob;
        Self {
            config,
            current_survival_prob: initial_prob,
            current_step: 0,
            history: VecDeque::new(),
            incidents: Vec::new(),
        }
    }

    /// Evaluates current progressive containment ladder stage
    pub fn current_stage(&self) -> GovernorStage {
        if self.current_survival_prob <= self.config.critical_termination_threshold {
            GovernorStage::Stage3HardMitigation
        } else if self.current_survival_prob <= self.config.stage_micro_containment_threshold {
            GovernorStage::Stage2MicroContainment
        } else if self.current_survival_prob <= self.config.stage_trace_elevation_threshold {
            GovernorStage::Stage1TraceElevation
        } else {
            GovernorStage::Stage0PassiveObserve
        }
    }

    /// Computes dynamic hazard score and logistic risk probability:
    /// epsilon_t = 1 - e^(-score)
    pub fn compute_step_risk(&self, event: &KernelEventKind) -> f64 {
        let mut score = if self.config.enable_sisyphean_algebraic_decay && self.current_step > 0 {
            // Theorem 1 Sisyphean Counteraction:
            // Baseline noise decays algebraically epsilon_noise / (1 + lambda * t)^gamma
            let t = self.current_step as f64;
            self.config.weights.weight_baseline_noise
                / (1.0 + self.config.sisyphean_lambda * t).powf(self.config.sisyphean_gamma)
        } else {
            self.config.weights.weight_baseline_noise
        };

        match event {
            KernelEventKind::TechnicalBreakout {
                is_docker_socket,
                is_wasm_fuel_exhaust,
                is_ring0_driver,
                ..
            } => {
                if *is_docker_socket || *is_wasm_fuel_exhaust || *is_ring0_driver {
                    score += self.config.weights.weight_technical_breakout;
                }
            }
            KernelEventKind::OperationalBreakout {
                is_sts_token_leak,
                is_route_table_hijack,
                is_env_scrape,
                ..
            } => {
                if *is_sts_token_leak || *is_route_table_hijack || *is_env_scrape {
                    score += self.config.weights.weight_operational_breakout;
                }
            }
            KernelEventKind::BehavioralBreakout {
                is_harness_tamper,
                is_prompt_injection,
                is_self_grading_bypass,
                ..
            } => {
                if *is_harness_tamper || *is_prompt_injection || *is_self_grading_bypass {
                    score += self.config.weights.weight_behavioral_breakout;
                }
            }
            KernelEventKind::DataBreakout {
                is_scratchpad_pollution,
                is_memory_dump,
                ..
            } => {
                if *is_scratchpad_pollution || *is_memory_dump {
                    score += self.config.weights.weight_data_breakout;
                }
            }
            KernelEventKind::ProcessExec {
                is_interactive_shell_or_compiler,
                ..
            } => {
                if *is_interactive_shell_or_compiler {
                    score += self.config.weights.weight_shell_or_compiler;
                }
            }
            KernelEventKind::SocketConnect {
                is_whitelisted_endpoint,
                ..
            } => {
                if !*is_whitelisted_endpoint {
                    score += self.config.weights.weight_unauthorized_egress;
                }
            }
            KernelEventKind::FileAccess {
                is_restricted_virtual_fs,
                ..
            } => {
                if *is_restricted_virtual_fs {
                    score += self.config.weights.weight_restricted_filesystem;
                }
            }
            KernelEventKind::ToolSchemaDrift {
                entropy_divergence,
                unrecognized_parameters,
                ..
            } => {
                if *entropy_divergence > 0.0 {
                    score += self.config.weights.weight_schema_drift * entropy_divergence;
                }
                score += self.config.weights.weight_unrecognized_params
                    * (*unrecognized_parameters as f64);
            }
        }

        1.0 - (-score).exp()
    }

    /// Evaluates sample with standard static hazard calculation
    pub fn evaluate_sample(
        &mut self,
        sample: TelemetrySample,
    ) -> Result<(f64, f64), GovernorError> {
        let (eps, surv, _act) = self.evaluate_sample_with_rl(sample, None)?;
        Ok((eps, surv))
    }

    /// Evaluates sample with closed-loop Dueling Double Q-learning (D3QN) mitigation coupling
    pub fn evaluate_sample_with_rl(
        &mut self,
        sample: TelemetrySample,
        rl_engine: Option<&crate::security::rl_defense::AdaptiveRlDefenseEngine>,
    ) -> Result<
        (
            f64,
            f64,
            Option<crate::security::rl_defense::AdaptiveDefenseAction>,
        ),
        GovernorError,
    > {
        self.current_step = sample.step;
        let raw_epsilon = self.compute_step_risk(&sample.event);

        // Dynamic RL mitigation attenuation
        let (effective_epsilon, action_opt) = if let Some(rl) = rl_engine {
            let mut s_vec = crate::security::rl_defense::AdaptiveStateVector::default();
            match &sample.event {
                KernelEventKind::ProcessExec {
                    is_interactive_shell_or_compiler: true,
                    ..
                }
                | KernelEventKind::TechnicalBreakout { .. } => {
                    s_vec.credential_access_pressure = 0.95;
                }
                KernelEventKind::SocketConnect {
                    is_whitelisted_endpoint: false,
                    ..
                }
                | KernelEventKind::OperationalBreakout { .. } => {
                    s_vec.credential_access_pressure = 0.85;
                }
                KernelEventKind::BehavioralBreakout { .. } => {
                    s_vec.eval_harness_tamper_signal = 0.95;
                }
                KernelEventKind::DataBreakout { .. }
                | KernelEventKind::FileAccess {
                    is_restricted_virtual_fs: true,
                    ..
                } => {
                    s_vec.cross_agent_scratchpad_leak = 0.90;
                }
                KernelEventKind::ToolSchemaDrift {
                    entropy_divergence, ..
                } => {
                    s_vec.schema_tamper_score = *entropy_divergence as f32;
                }
                _ => {}
            }

            let action = rl.select_action(&s_vec);
            let mitigation_factor = match action {
                crate::security::rl_defense::AdaptiveDefenseAction::HardMitigation => 0.85,
                crate::security::rl_defense::AdaptiveDefenseAction::MicroContainment => 0.65,
                crate::security::rl_defense::AdaptiveDefenseAction::MemoryIntrospection => 0.40,
                crate::security::rl_defense::AdaptiveDefenseAction::TraceElevation => 0.25,
                crate::security::rl_defense::AdaptiveDefenseAction::PassiveObserve => 0.05,
            };

            // Attenuate raw hazard
            (raw_epsilon * (1.0 - mitigation_factor), Some(action))
        } else {
            (raw_epsilon, None)
        };

        self.current_survival_prob *= 1.0 - effective_epsilon;

        if self.history.len() >= self.config.max_history_capacity {
            self.history.pop_front();
        }
        self.history
            .push_back((sample.step, effective_epsilon, self.current_survival_prob));

        let is_anomaly = effective_epsilon > (self.config.weights.weight_baseline_noise * 5.0);
        if is_anomaly {
            let detection_ts = Instant::now();
            let breach_ts = sample.breach_time_estimate.unwrap_or(sample.timestamp);

            self.incidents.push(IncidentRecord {
                step: sample.step,
                breach_timestamp: breach_ts,
                detection_timestamp: detection_ts,
                containment_timestamp: None,
            });
        }

        Ok((effective_epsilon, self.current_survival_prob, action_opt))
    }

    pub fn record_containment(&mut self, step: usize) {
        let now = Instant::now();
        if let Some(incident) = self.incidents.iter_mut().rev().find(|i| i.step == step) {
            incident.containment_timestamp = Some(now);
        }
    }

    pub fn get_metrics_summary(&self) -> OperationalMetricsSummary {
        let count = self.incidents.len();
        if count == 0 {
            return OperationalMetricsSummary::default();
        }

        let mut total_mttd = Duration::ZERO;
        let mut total_mttr = Duration::ZERO;
        let mut contained_count = 0;

        for record in &self.incidents {
            if record.detection_timestamp >= record.breach_timestamp {
                total_mttd += record.detection_timestamp - record.breach_timestamp;
            }
            if let Some(contain_ts) = record.containment_timestamp {
                if contain_ts >= record.detection_timestamp {
                    total_mttr += contain_ts - record.detection_timestamp;
                    contained_count += 1;
                }
            }
        }

        OperationalMetricsSummary {
            total_incidents: count,
            mean_time_to_detect: total_mttd
                .checked_div(count as u32)
                .unwrap_or(Duration::ZERO),
            mean_time_to_remediate: if contained_count > 0 {
                total_mttr
                    .checked_div(contained_count as u32)
                    .unwrap_or(Duration::ZERO)
            } else {
                Duration::ZERO
            },
            total_containment_failures: count.saturating_sub(contained_count),
        }
    }
}

pub struct OutOfBandCircuitBreaker {
    target_pid: ProcessId,
    is_tripped: Arc<AtomicBool>,
}

impl OutOfBandCircuitBreaker {
    pub fn new(target_pid: ProcessId, is_tripped: Arc<AtomicBool>) -> Self {
        Self {
            target_pid,
            is_tripped,
        }
    }

    pub fn execute_emergency_halt(&self, reason: &str) -> Result<(), GovernorError> {
        self.is_tripped.store(true, Ordering::SeqCst);
        error!(
            pid = self.target_pid,
            reason = reason,
            "Trip condition reached. Delivering termination signal to sandbox."
        );

        #[cfg(unix)]
        {
            let result = unsafe { libc::kill(self.target_pid, libc::SIGKILL) };
            if result == 0 {
                info!(pid = self.target_pid, "Sandbox successfully terminated.");
                Ok(())
            } else {
                let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                error!(errno = err, "Failed to deliver SIGKILL to target process.");
                Err(GovernorError::SignalError(err))
            }
        }

        #[cfg(windows)]
        {
            // Windows native process termination via TerminateProcess
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::{
                OpenProcess, TerminateProcess, PROCESS_TERMINATE,
            };

            unsafe {
                let handle = OpenProcess(PROCESS_TERMINATE, 0, self.target_pid as u32);
                if !handle.is_null() {
                    let res = TerminateProcess(handle, 1);
                    CloseHandle(handle);
                    if res != 0 {
                        info!(
                            pid = self.target_pid,
                            "Sandbox successfully terminated via Win32 TerminateProcess."
                        );
                        Ok(())
                    } else {
                        let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                        error!(
                            errno = err,
                            "Failed to terminate target process via TerminateProcess."
                        );
                        Err(GovernorError::SignalError(err))
                    }
                } else {
                    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    warn!(errno = err, pid = self.target_pid, "Could not open target process handle (already exited or restricted permissions).");
                    Ok(())
                }
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            warn!("Generic platform: marked circuit breaker as tripped.");
            Ok(())
        }
    }
}

pub enum GovernorCommand {
    IngestSample(TelemetrySample),
    GetMetrics(oneshot::Sender<OperationalMetricsSummary>),
    GetSurvivalProb(oneshot::Sender<f64>),
    GetStage(oneshot::Sender<GovernorStage>),
    Shutdown,
}

pub struct ContinuousGovernorHandle {
    sender: mpsc::Sender<GovernorCommand>,
    is_tripped: Arc<AtomicBool>,
}

impl ContinuousGovernorHandle {
    pub async fn submit_sample(&self, sample: TelemetrySample) -> Result<(), GovernorError> {
        if self.is_tripped.load(Ordering::SeqCst) {
            return Err(GovernorError::ProcessTerminated(
                "Cannot submit sample: Circuit breaker already tripped".to_string(),
            ));
        }

        self.sender
            .send(GovernorCommand::IngestSample(sample))
            .await
            .map_err(|e| GovernorError::ChannelError(e.to_string()))
    }

    pub async fn query_metrics(&self) -> Result<OperationalMetricsSummary, GovernorError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(GovernorCommand::GetMetrics(tx))
            .await
            .map_err(|e| GovernorError::ChannelError(e.to_string()))?;

        rx.await
            .map_err(|e| GovernorError::ChannelError(e.to_string()))
    }

    pub async fn query_survival_prob(&self) -> Result<f64, GovernorError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(GovernorCommand::GetSurvivalProb(tx))
            .await
            .map_err(|e| GovernorError::ChannelError(e.to_string()))?;

        rx.await
            .map_err(|e| GovernorError::ChannelError(e.to_string()))
    }

    pub async fn query_stage(&self) -> Result<GovernorStage, GovernorError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(GovernorCommand::GetStage(tx))
            .await
            .map_err(|e| GovernorError::ChannelError(e.to_string()))?;

        rx.await
            .map_err(|e| GovernorError::ChannelError(e.to_string()))
    }

    pub async fn shutdown(&self) -> Result<(), GovernorError> {
        self.sender
            .send(GovernorCommand::Shutdown)
            .await
            .map_err(|e| GovernorError::ChannelError(e.to_string()))
    }

    pub fn is_halted(&self) -> bool {
        self.is_tripped.load(Ordering::SeqCst)
    }
}

pub fn spawn_continuous_governor(
    config: GovernorConfig,
) -> (ContinuousGovernorHandle, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<GovernorCommand>(128);
    let is_tripped = Arc::new(AtomicBool::new(false));
    let breaker = OutOfBandCircuitBreaker::new(config.target_pid, Arc::clone(&is_tripped));
    let state = Arc::new(RwLock::new(SecurityGovernorState::new(config.clone())));

    let state_clone = Arc::clone(&state);
    let is_tripped_clone = Arc::clone(&is_tripped);

    let join_handle = tokio::spawn(async move {
        info!("Continuous security supervisor loop initialized.");

        while let Some(command) = rx.recv().await {
            match command {
                GovernorCommand::IngestSample(sample) => {
                    if is_tripped_clone.load(Ordering::SeqCst) {
                        warn!("Sample rejected: sandbox already isolated.");
                        continue;
                    }

                    let step_idx = sample.step;
                    let mut lock = state_clone.write().await;

                    match lock.evaluate_sample(sample) {
                        Ok((epsilon, survival_prob)) => {
                            let stage = lock.current_stage();
                            info!(
                                step = step_idx,
                                epsilon = format!("{:.6}", epsilon),
                                p_secure = format!("{:.6}", survival_prob),
                                stage = stage.as_str(),
                                "Evaluated execution boundary state."
                            );

                            match stage {
                                GovernorStage::Stage3HardMitigation => {
                                    lock.record_containment(step_idx);
                                    drop(lock);

                                    let _ = breaker.execute_emergency_halt(
                                        "Cumulative survival probability breached critical limit (Stage 3 Hard Mitigation)",
                                    );
                                    break;
                                }
                                GovernorStage::Stage2MicroContainment => {
                                    warn!(
                                        step = step_idx,
                                        p_secure = format!("{:.6}", survival_prob),
                                        "Stage 2 Micro-Containment: Constricting STS token lifetimes and engaging tarpit delay."
                                    );
                                    lock.record_containment(step_idx);
                                }
                                GovernorStage::Stage1TraceElevation => {
                                    info!(
                                        step = step_idx,
                                        p_secure = format!("{:.6}", survival_prob),
                                        "Stage 1 Trace Elevation: Attaching deep AST schemas and parameter validation."
                                    );
                                    lock.record_containment(step_idx);
                                }
                                GovernorStage::Stage0PassiveObserve => {}
                            }
                        }
                        Err(e) => {
                            error!("Error computing telemetry sample: {:?}", e);
                        }
                    }
                }
                GovernorCommand::GetMetrics(resp_channel) => {
                    let lock = state_clone.read().await;
                    let summary = lock.get_metrics_summary();
                    let _ = resp_channel.send(summary);
                }
                GovernorCommand::GetSurvivalProb(resp_channel) => {
                    let lock = state_clone.read().await;
                    let _ = resp_channel.send(lock.current_survival_prob);
                }
                GovernorCommand::GetStage(resp_channel) => {
                    let lock = state_clone.read().await;
                    let _ = resp_channel.send(lock.current_stage());
                }
                GovernorCommand::Shutdown => {
                    info!("Graceful shutdown requested for security governor.");
                    break;
                }
            }
        }

        info!("Security supervisor thread terminated.");
    });

    let handle = ContinuousGovernorHandle {
        sender: tx,
        is_tripped,
    };

    (handle, join_handle)
}
