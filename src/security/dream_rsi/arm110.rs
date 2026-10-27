use super::policy_optimizer::DreamRsiPolicyOptimizer;
use super::types::{
    DreamRolloutReport, DreamRsiStatus, ResearchPolicy, RsiExperimentPlan, TrajectoryEvent,
};
use crate::containment_ring::arm_ring::{ArmContainmentRing, ArmRingRegistry};
use crate::core::types::OctopusSecurityError;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Arm 110: Open Dream-RSI Recursive Self-Improving Policy Optimizer.
/// Strictly operates in offline Ring 2 containment (zero socket egress).
pub struct DreamRsiOptimizerArm {
    ring: Option<Arc<ArmContainmentRing>>,
    optimizer: Arc<RwLock<DreamRsiPolicyOptimizer>>,
    workspace_root: PathBuf,
    total_rollouts: AtomicUsize,
    last_trained: AtomicU64,
    latest_plan: Arc<RwLock<Option<RsiExperimentPlan>>>,
}

impl DreamRsiOptimizerArm {
    pub fn new() -> Self {
        let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let arm = Self {
            ring: None,
            optimizer: Arc::new(RwLock::new(DreamRsiPolicyOptimizer::new())),
            workspace_root: root.clone(),
            total_rollouts: AtomicUsize::new(0),
            last_trained: AtomicU64::new(0),
            latest_plan: Arc::new(RwLock::new(None)),
        };

        // Attempt loading persisted checkpoint if exists
        arm.try_load_checkpoint(&root);
        arm.try_ingest_historical_traces(&root);

        // Generate initial baseline plan
        let plan = arm
            .optimizer
            .try_read()
            .map(|o| o.generate_experiment_plan())
            .ok();
        if let Some(p) = plan {
            *arm.latest_plan.try_write().unwrap() = Some(p);
        }

        arm
    }

    pub fn with_registry(registry: &ArmRingRegistry) -> Self {
        let mut arm = Self::new();
        if let Some(ring) = registry.get_ring_sync(110) {
            arm.ring = Some(ring);
        }
        arm
    }

    pub fn with_workspace(mut self, path: PathBuf) -> Self {
        self.workspace_root = path.clone();
        self.try_load_checkpoint(&path);
        self.try_ingest_historical_traces(&path);
        self
    }

    fn try_load_checkpoint(&self, root: &Path) {
        let checkpoint_dir = root.join("data").join("dream_rsi");
        let policy_file = checkpoint_dir.join("active_policy.json");
        if policy_file.exists() {
            if let Ok(content) = fs::read_to_string(&policy_file) {
                if let Ok(policy) = serde_json::from_str::<ResearchPolicy>(&content) {
                    if let Ok(mut opt) = self.optimizer.try_write() {
                        opt.set_policy(policy);
                        let plan = opt.generate_experiment_plan();
                        if let Ok(mut lp) = self.latest_plan.try_write() {
                            *lp = Some(plan);
                        }
                    }
                }
            }
        }
    }

    fn try_ingest_historical_traces(&self, root: &Path) {
        let history_file = root
            .join("data")
            .join("protocol_research")
            .join("evaluation_history.jsonl");
        if history_file.exists() {
            if let Ok(content) = fs::read_to_string(&history_file) {
                let mut events = Vec::new();
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Ok(ev) = serde_json::from_str::<TrajectoryEvent>(trimmed) {
                        events.push(ev);
                    }
                }
                if !events.is_empty() {
                    if let Ok(mut opt) = self.optimizer.try_write() {
                        opt.world_model_mut().ingest_trajectories(&events);
                    }
                }
            }
        }
    }

    pub async fn get_status(&self) -> DreamRsiStatus {
        let (is_contained, is_severed, generation) = if let Some(ref r) = self.ring {
            let status = r.to_status_dto().await;
            (true, status.is_severed, status.generation)
        } else {
            (true, false, 1)
        };

        let opt = self.optimizer.read().await;
        let latest_plan = self.latest_plan.read().await.clone();

        DreamRsiStatus {
            arm_id: 110,
            role: "DreamRsiOptimizer (Arm 110)".to_string(),
            status: if is_severed {
                "SEVERED_AUTOTOMY_CONTAINED".to_string()
            } else {
                "OFFLINE_REPLAY_ACTIVE".to_string()
            },
            is_contained,
            is_severed,
            active_generation: generation,
            total_historical_trajectories: opt.world_model().total_samples(),
            total_world_model_states: opt.world_model().total_states(),
            active_policy_id: opt.active_policy().policy_id.clone(),
            active_policy_fitness: opt.active_policy().fitness_score,
            total_simulated_rollouts: self.total_rollouts.load(Ordering::Relaxed),
            last_training_timestamp: self.last_trained.load(Ordering::Relaxed),
            latest_experiment_plan: latest_plan,
            offline_isolation_mode: "RING2_STRICT_NO_SOCKET_EGRESS".to_string(),
        }
    }

    /// Train research policy offline over N generations of simulated world-model rollouts.
    pub async fn train_offline(
        &self,
        iterations: usize,
        steps_per_candidate: usize,
    ) -> Result<DreamRsiStatus, OctopusSecurityError> {
        if let Some(ref r) = self.ring {
            if r.is_severed() {
                return Err(OctopusSecurityError::CapabilityDenied(
                    "Arm 110 is severed".to_string(),
                ));
            }
        }

        let mut opt = self.optimizer.write().await;
        let evolved_policy = opt.optimize_policy(iterations, steps_per_candidate);
        let plan = opt.generate_experiment_plan();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.last_trained.store(now, Ordering::Relaxed);
        self.total_rollouts.fetch_add(iterations, Ordering::Relaxed);
        *self.latest_plan.write().await = Some(plan);

        // Persist policy
        let checkpoint_dir = self.workspace_root.join("data").join("dream_rsi");
        let _ = fs::create_dir_all(&checkpoint_dir);
        let policy_path = checkpoint_dir.join("active_policy.json");
        if let Ok(serialized) = serde_json::to_string_pretty(&evolved_policy) {
            let _ = fs::write(policy_path, serialized);
        }

        drop(opt);
        Ok(self.get_status().await)
    }

    /// Execute a simulated policy rollout against the offline world model.
    pub async fn run_rollout(&self, steps: usize) -> DreamRolloutReport {
        let opt = self.optimizer.read().await;
        let report = opt
            .world_model()
            .simulate_rollout(opt.active_policy(), steps);
        self.total_rollouts.fetch_add(1, Ordering::Relaxed);
        report
    }

    /// Get current research experiment recommendations for Arm 107.
    pub async fn get_recommendations(&self) -> RsiExperimentPlan {
        let mut plan_guard = self.latest_plan.write().await;
        if let Some(ref plan) = *plan_guard {
            plan.clone()
        } else {
            let opt = self.optimizer.read().await;
            let plan = opt.generate_experiment_plan();
            *plan_guard = Some(plan.clone());
            plan
        }
    }

    /// Feed empirical trajectory events from live protocol experiments back into the offline World Model.
    pub async fn feed_trajectories(&self, events: Vec<TrajectoryEvent>) -> usize {
        let count = events.len();
        let mut opt = self.optimizer.write().await;
        opt.world_model_mut().ingest_trajectories(&events);

        // Append to evaluation_history.jsonl
        let history_file = self
            .workspace_root
            .join("data")
            .join("protocol_research")
            .join("evaluation_history.jsonl");
        if let Some(parent) = history_file.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(mut file) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&history_file)
        {
            use std::io::Write;
            for ev in &events {
                if let Ok(line) = serde_json::to_string(ev) {
                    let _ = writeln!(file, "{}", line);
                }
            }
        }

        count
    }
}
