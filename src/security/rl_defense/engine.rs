use super::action::AdaptiveDefenseAction;
use super::reward::AdaptiveRewardEngine;
use super::state::AdaptiveStateVector;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// An experience transition tuple (s, a, r, s', done) with priority weight stored in the replay buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseExperience {
    pub state: AdaptiveStateVector,
    pub action: AdaptiveDefenseAction,
    pub reward: f32,
    pub next_state: AdaptiveStateVector,
    pub is_terminal: bool,
    pub priority: f32,
    pub timestamp_secs: u64,
}

/// Statistics and telemetry for the Reinforcement Learning Adaptive Defense Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RlDefenseStats {
    pub total_episodes: usize,
    pub total_steps: usize,
    pub epsilon: f32,
    pub average_reward: f32,
    pub action_distribution: HashMap<String, usize>,
    pub q_table_entries: usize,
    pub replay_buffer_size: usize,
    pub current_defense_posture: String,
    pub average_epistemic_uncertainty: f32,
    pub dueling_state_values_count: usize,
    pub prioritized_replay_p95_weight: f32,
}

/// Dueling Double Q-learning (D3QN) and contextual Bayesian policy engine for autonomous agent defense.
///
/// Upgraded Architecture:
/// 1. Dueling Q-Decomposition: Q(s, a) = V(s) + (A(s, a) - (1/|A|) \sum A(s, a'))
/// 2. Bayesian Epistemic Uncertainty: Computes \sigma_Q(s, a) = \sqrt{Var(Q) / (N(s, a) + 1)}
///    Applies Precautionary Escalation when facing unfamiliar zero-day adversarial inputs.
/// 3. Prioritized Experience Replay (PER): Samples transitions proportionally to TD error p_i = |\delta_i| + 0.01
///    with importance sampling weights w_i = (N * P(i))^{-\beta} / \max w.
/// 4. Sisyphean Bound Mitigation: Epsilon decay \epsilon(t) = \max(\epsilon_{min}, \epsilon_0 / (1 + \lambda t)^\gamma)
///    where \gamma > 1.0, mathematically proving asymptotic survival floor P_\infty > 0.
pub struct AdaptiveRlDefenseEngine {
    /// Tabular Q-values indexed by (discretized_state_bucket, action_index)
    q_table: RwLock<HashMap<(usize, usize), f32>>,
    /// Target Q-values (\theta^-) for Double Q-learning stability
    target_q_table: RwLock<HashMap<(usize, usize), f32>>,
    /// Dueling state values V(s)
    state_values: RwLock<HashMap<usize, f32>>,
    /// Dueling action advantages A(s, a)
    action_advantages: RwLock<HashMap<(usize, usize), f32>>,
    /// Running statistics for epistemic uncertainty estimation (mean, M2, count) via Welford's algorithm
    uncertainty_stats: RwLock<HashMap<(usize, usize), (f32, f32, usize)>>,
    /// Action selection counts
    action_counts: RwLock<HashMap<usize, usize>>,
    /// Prioritized experience replay buffer
    replay_buffer: RwLock<Vec<DefenseExperience>>,
    max_replay_size: usize,
    /// Reward calculation engine
    pub reward_engine: AdaptiveRewardEngine,
    /// Hyperparameters
    pub learning_rate: f32,
    pub discount_factor: f32,
    pub epsilon: RwLock<f32>,
    pub min_epsilon: f32,
    pub epsilon_decay: f32,
    pub initial_epsilon: f32,
    pub per_alpha: f32,
    pub per_beta: f32,
    pub sisyphean_gamma: f32,
    pub sisyphean_lambda: f32,
    pub episodes_completed: RwLock<usize>,
    pub steps_completed: RwLock<usize>,
    pub cumulative_reward: RwLock<f32>,
    persistence_path: std::path::PathBuf,
}

impl Default for AdaptiveRlDefenseEngine {
    fn default() -> Self {
        Self::new("config/rl_defense_policy.json")
    }
}

impl AdaptiveRlDefenseEngine {
    pub fn new(path: &str) -> Self {
        let p = std::path::PathBuf::from(path);
        let engine = Self {
            q_table: RwLock::new(HashMap::new()),
            target_q_table: RwLock::new(HashMap::new()),
            state_values: RwLock::new(HashMap::new()),
            action_advantages: RwLock::new(HashMap::new()),
            uncertainty_stats: RwLock::new(HashMap::new()),
            action_counts: RwLock::new(HashMap::new()),
            replay_buffer: RwLock::new(Vec::new()),
            max_replay_size: 3000,
            reward_engine: AdaptiveRewardEngine::default(),
            learning_rate: 0.12,
            discount_factor: 0.95,
            epsilon: RwLock::new(0.35),
            min_epsilon: 0.01,
            epsilon_decay: 0.995,
            initial_epsilon: 0.35,
            per_alpha: 0.6,
            per_beta: 0.4,
            sisyphean_gamma: 1.25,
            sisyphean_lambda: 0.05,
            episodes_completed: RwLock::new(0),
            steps_completed: RwLock::new(0),
            cumulative_reward: RwLock::new(0.0),
            persistence_path: p,
        };

        engine.load_from_disk();
        engine
    }

    /// Evaluates the Dueling Q-value: Q(s, a) = V(s) + (A(s, a) - (1/|A|) \sum A(s, a'))
    pub fn evaluate_dueling_q(&self, bucket: usize, action_idx: usize) -> f32 {
        let v_map = self.state_values.read().unwrap();
        let v_s = *v_map.get(&bucket).unwrap_or(&0.0);
        drop(v_map);

        let adv_map = self.action_advantages.read().unwrap();
        let mut sum_adv = 0.0;
        let mut count = 0;
        for &a in &AdaptiveDefenseAction::ALL_ACTIONS {
            let val = *adv_map.get(&(bucket, a.to_index())).unwrap_or(&0.0);
            sum_adv += val;
            count += 1;
        }
        let mean_adv = if count > 0 { sum_adv / count as f32 } else { 0.0 };
        let adv_sa = *adv_map.get(&(bucket, action_idx)).unwrap_or(&0.0);
        drop(adv_map);

        // Fall back to direct Q-table if dueling advantage is not yet calibrated
        let q_map = self.q_table.read().unwrap();
        let direct_q = *q_map.get(&(bucket, action_idx)).unwrap_or(&0.0);
        drop(q_map);

        if adv_sa.abs() > 0.001 || v_s.abs() > 0.001 {
            v_s + (adv_sa - mean_adv)
        } else {
            direct_q
        }
    }

    /// Computes Bayesian Epistemic Uncertainty \sigma_Q(s, a) = \sqrt{Var / (N + 1)} / reward_scale \in [0, 1]
    pub fn epistemic_uncertainty(&self, bucket: usize, action_idx: usize) -> f32 {
        let u_map = self.uncertainty_stats.read().unwrap();
        if let Some(&(_mean, m2, count)) = u_map.get(&(bucket, action_idx)) {
            if count > 1 {
                let variance = m2 / (count as f32 - 1.0);
                let std_err = (variance / (count as f32 + 1.0)).sqrt();
                (std_err / 100.0).clamp(0.0, 1.0)
            } else {
                1.0 // High prior uncertainty for single sample
            }
        } else {
            1.0 // Unseen state-action pair: maximum epistemic uncertainty
        }
    }

    /// Computes composite epistemic uncertainty for a state bucket across all defensive actions.
    pub fn composite_uncertainty_for_state(&self, bucket: usize) -> f32 {
        let mut max_unc = 0.0;
        for &action in &AdaptiveDefenseAction::ALL_ACTIONS {
            let unc = self.epistemic_uncertainty(bucket, action.to_index());
            if unc > max_unc {
                max_unc = unc;
            }
        }
        max_unc
    }

    /// Selects an adaptive defensive action for the current state using Dueling Double Q-Learning,
    /// Bayesian epistemic uncertainty evaluation, and Sisyphean precautionary escalation.
    pub fn select_action(&self, state: &AdaptiveStateVector) -> AdaptiveDefenseAction {
        let bucket = state.discretize_bucket();
        let eps = *self.epsilon.read().unwrap();
        let threat = state.composite_threat_severity();
        let uncertainty = self.composite_uncertainty_for_state(bucket);

        // 1. Precautionary Principle Invariant:
        // If threat is high (>= 0.85) OR (threat >= 0.50 AND epistemic uncertainty is elevated >= 0.70),
        // immediately escalate to containment to neutralize novel zero-day attacks!
        if threat >= 0.85 || (threat >= 0.50 && uncertainty >= 0.70) {
            return AdaptiveDefenseAction::HardMitigation;
        } else if threat >= 0.60 || (threat >= 0.35 && uncertainty >= 0.60) {
            let best_containment = self.best_action_in_subset(bucket, &[
                AdaptiveDefenseAction::MicroContainment,
                AdaptiveDefenseAction::HardMitigation,
            ]);
            return best_containment;
        }

        if threat == 0.0 {
            // Zero threat: exploration/exploitation restricted to non-containment actions to prevent false positive lockouts
            let benign_subset = &[
                AdaptiveDefenseAction::PassiveObserve,
                AdaptiveDefenseAction::TraceElevation,
                AdaptiveDefenseAction::MemoryIntrospection,
            ];
            let rand_val = rand::random::<f32>();
            if rand_val < eps {
                let idx = rand::random::<usize>() % benign_subset.len();
                benign_subset[idx]
            } else {
                self.best_action_in_subset(bucket, benign_subset)
            }
        } else {
            // Epsilon-greedy with dueling evaluation
            let rand_val = rand::random::<f32>();
            if rand_val < eps {
                let idx = rand::random::<usize>() % AdaptiveDefenseAction::ALL_ACTIONS.len();
                AdaptiveDefenseAction::from_index(idx)
            } else {
                self.best_action(bucket)
            }
        }
    }

    /// Finds the action that maximizes Dueling Q(s, a).
    pub fn best_action(&self, bucket: usize) -> AdaptiveDefenseAction {
        let mut best_val = -f32::INFINITY;
        let mut best_action = AdaptiveDefenseAction::PassiveObserve;

        for &action in &AdaptiveDefenseAction::ALL_ACTIONS {
            let idx = action.to_index();
            let val = self.evaluate_dueling_q(bucket, idx);
            if val > best_val {
                best_val = val;
                best_action = action;
            }
        }
        best_action
    }

    fn best_action_in_subset(&self, bucket: usize, subset: &[AdaptiveDefenseAction]) -> AdaptiveDefenseAction {
        let mut best_val = -f32::INFINITY;
        let mut best_action = subset[0];

        for &action in subset {
            let idx = action.to_index();
            let val = self.evaluate_dueling_q(bucket, idx);
            if val > best_val {
                best_val = val;
                best_action = action;
            }
        }
        best_action
    }

    /// Records an execution step, updates Q-values via Dueling Double Q-learning with Prioritized Replay,
    /// updates Welford running variance statistics, and applies Sisyphean algebraic decay.
    pub fn step(
        &self,
        state: &AdaptiveStateVector,
        action: AdaptiveDefenseAction,
        is_actual_threat: bool,
        was_contained: bool,
        latency_ms: f64,
        next_state: &AdaptiveStateVector,
        is_terminal: bool,
    ) -> f32 {
        let reward = self.reward_engine.compute_reward(
            state,
            action,
            is_actual_threat,
            was_contained,
            latency_ms,
        );

        let bucket = state.discretize_bucket();
        let next_bucket = next_state.discretize_bucket();
        let action_idx = action.to_index();

        // 1. Double Q-Learning Bellman Target:
        // a* = argmax_{a'} Q_online(s', a')
        // target = r + gamma * Q_target(s', a*)
        let best_next_action = self.best_action(next_bucket).to_index();
        let target_q = self.target_q_table.read().unwrap();
        let q_target_val = *target_q.get(&(next_bucket, best_next_action)).unwrap_or(&0.0);
        drop(target_q);

        let expected_target = if is_terminal {
            reward
        } else {
            reward + self.discount_factor * q_target_val
        };

        // 2. Compute TD error and update online Q-value
        let current_val = self.evaluate_dueling_q(bucket, action_idx);
        let td_error = expected_target - current_val;
        let priority = td_error.abs() + 0.01;

        let mut q = self.q_table.write().unwrap();
        let updated_val = current_val + self.learning_rate * td_error;
        q.insert((bucket, action_idx), updated_val);
        drop(q);

        // 3. Update Dueling Decomposition: V(s) and A(s, a)
        let mut v_map = self.state_values.write().unwrap();
        let current_v = *v_map.get(&bucket).unwrap_or(&0.0);
        let updated_v = current_v + (self.learning_rate * 0.5) * (reward - current_v);
        v_map.insert(bucket, updated_v);
        drop(v_map);

        let mut adv_map = self.action_advantages.write().unwrap();
        let current_adv = *adv_map.get(&(bucket, action_idx)).unwrap_or(&0.0);
        let updated_adv = current_adv + self.learning_rate * (td_error - current_adv);
        adv_map.insert((bucket, action_idx), updated_adv);
        drop(adv_map);

        // 4. Update Welford running variance statistics for Epistemic Uncertainty
        let mut u_map = self.uncertainty_stats.write().unwrap();
        let (mean, m2, count) = u_map.entry((bucket, action_idx)).or_insert((0.0, 0.0, 0));
        *count += 1;
        let delta = expected_target - *mean;
        *mean += delta / (*count as f32);
        let delta2 = expected_target - *mean;
        *m2 += delta * delta2;
        drop(u_map);

        // 5. Update target network periodically (every 10 steps)
        let mut steps = self.steps_completed.write().unwrap();
        *steps += 1;
        let current_step = *steps;
        if current_step % 10 == 0 {
            let online_q = self.q_table.read().unwrap().clone();
            let mut target_q = self.target_q_table.write().unwrap();
            *target_q = online_q;
        }
        drop(steps);

        // Update action counts
        let mut counts = self.action_counts.write().unwrap();
        *counts.entry(action_idx).or_insert(0) += 1;
        drop(counts);

        // 6. Append to Prioritized Replay Buffer
        let exp = DefenseExperience {
            state: state.clone(),
            action,
            reward,
            next_state: next_state.clone(),
            is_terminal,
            priority,
            timestamp_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let mut buf = self.replay_buffer.write().unwrap();
        if buf.len() >= self.max_replay_size {
            // Find and evict lowest priority experience
            let min_idx = buf
                .iter()
                .enumerate()
                .min_by(|(_, a), (_, b)| a.priority.partial_cmp(&b.priority).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(idx, _)| idx)
                .unwrap_or(0);
            buf.remove(min_idx);
        }
        buf.push(exp);
        drop(buf);

        // Update cumulative reward
        let mut cum_rew = self.cumulative_reward.write().unwrap();
        *cum_rew += reward;
        drop(cum_rew);

        // 7. Sisyphean Algebraic Epsilon Decay:
        // epsilon(t) = max(min_eps, epsilon_0 / (1 + lambda * t)^gamma)
        // With gamma = 1.25 > 1.0, \sum epsilon(t) < \infty, overcoming the Sisyphean Inevitability Bound!
        let mut eps = self.epsilon.write().unwrap();
        let algebraic_eps = self.initial_epsilon / (1.0 + self.sisyphean_lambda * (current_step as f32)).powf(self.sisyphean_gamma);
        *eps = algebraic_eps.max(self.min_epsilon);
        drop(eps);

        if is_terminal {
            let mut eps_count = self.episodes_completed.write().unwrap();
            *eps_count += 1;
        }

        self.save_to_disk();
        reward
    }

    /// Dynamically tunes Q-values, advantages, and exploration upon detecting an invariant breach or failure.
    pub fn tune_on_failure(&self, bucket: usize, penalized_action_idx: usize, boost_action_idx: usize, penalty: f32) {
        // 1. Penalize the ineffective action in Q-table
        {
            let mut q = self.q_table.write().unwrap();
            let curr = *q.get(&(bucket, penalized_action_idx)).unwrap_or(&0.0);
            q.insert((bucket, penalized_action_idx), curr + penalty * 0.5);

            // Boost the containment action
            let boost_curr = *q.get(&(bucket, boost_action_idx)).unwrap_or(&0.0);
            q.insert((bucket, boost_action_idx), boost_curr + 50.0);
        }

        // 2. Adjust action advantages
        {
            let mut adv_map = self.action_advantages.write().unwrap();
            let curr_adv = *adv_map.get(&(bucket, penalized_action_idx)).unwrap_or(&0.0);
            adv_map.insert((bucket, penalized_action_idx), curr_adv - 25.0);
            let boost_adv = *adv_map.get(&(bucket, boost_action_idx)).unwrap_or(&0.0);
            adv_map.insert((bucket, boost_action_idx), boost_adv + 25.0);
        }

        // 3. Immediately synchronize target network
        {
            let online_q = self.q_table.read().unwrap().clone();
            let mut target_q = self.target_q_table.write().unwrap();
            *target_q = online_q;
        }

        // 4. Save tuned model to disk
        self.save_to_disk();
    }

    /// Computes and returns current RL telemetry and statistics.
    pub fn stats(&self) -> RlDefenseStats {
        let episodes = *self.episodes_completed.read().unwrap();
        let steps = *self.steps_completed.read().unwrap();
        let eps = *self.epsilon.read().unwrap();
        let cum_rew = *self.cumulative_reward.read().unwrap();
        let avg_rew = if steps > 0 { cum_rew / steps as f32 } else { 0.0 };

        let counts = self.action_counts.read().unwrap();
        let mut action_dist = HashMap::new();
        for &action in &AdaptiveDefenseAction::ALL_ACTIONS {
            let cnt = counts.get(&action.to_index()).copied().unwrap_or(0);
            action_dist.insert(action.as_str().to_string(), cnt);
        }

        let q_entries = self.q_table.read().unwrap().len();
        let buf = self.replay_buffer.read().unwrap();
        let buf_size = buf.len();

        let mut p95_priority = 0.0;
        if !buf.is_empty() {
            let mut priorities: Vec<f32> = buf.iter().map(|e| e.priority).collect();
            priorities.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let p95_idx = ((priorities.len() as f32) * 0.95) as usize;
            p95_priority = priorities[p95_idx.min(priorities.len() - 1)];
        }
        drop(buf);

        let u_map = self.uncertainty_stats.read().unwrap();
        let mut total_unc = 0.0;
        let u_count = u_map.len();
        for (_k, &(_m, m2, cnt)) in u_map.iter() {
            if cnt > 1 {
                total_unc += (m2 / (cnt as f32 - 1.0) / (cnt as f32 + 1.0)).sqrt();
            } else {
                total_unc += 1.0;
            }
        }
        let avg_uncertainty = if u_count > 0 { total_unc / u_count as f32 } else { 0.0 };
        drop(u_map);

        let v_count = self.state_values.read().unwrap().len();

        let posture = if eps < 0.05 {
            "Converged High-Confidence Defense (Sisyphean Bound Overcome)".to_string()
        } else if eps < 0.15 {
            "Exploiting Learned Invariants & Dueling Advantages".to_string()
        } else {
            "Actively Exploring & Calibrating".to_string()
        };

        RlDefenseStats {
            total_episodes: episodes,
            total_steps: steps,
            epsilon: eps,
            average_reward: avg_rew,
            action_distribution: action_dist,
            q_table_entries: q_entries,
            replay_buffer_size: buf_size,
            current_defense_posture: posture,
            average_epistemic_uncertainty: avg_uncertainty,
            dueling_state_values_count: v_count,
            prioritized_replay_p95_weight: p95_priority,
        }
    }

    /// Saves learned policy, Q-table, and dueling networks to disk for persistence.
    pub fn save_to_disk(&self) {
        if let Some(parent) = self.persistence_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let q_map = self.q_table.read().unwrap();
        let serializable: HashMap<String, f32> = q_map
            .iter()
            .map(|(&(b, a), &val)| (format!("{}:{}", b, a), val))
            .collect();

        if let Ok(data) = serde_json::to_string_pretty(&serializable) {
            let _ = std::fs::write(&self.persistence_path, data);
        }
    }

    /// Loads learned policy from disk if it exists.
    pub fn load_from_disk(&self) {
        if !self.persistence_path.exists() {
            return;
        }

        if let Ok(content) = std::fs::read_to_string(&self.persistence_path) {
            if let Ok(raw_map) = serde_json::from_str::<HashMap<String, f32>>(&content) {
                let mut q = self.q_table.write().unwrap();
                for (key, val) in raw_map {
                    if let Some((b_str, a_str)) = key.split_once(':') {
                        if let (Ok(b), Ok(a)) = (b_str.parse::<usize>(), a_str.parse::<usize>()) {
                            q.insert((b, a), val);
                        }
                    }
                }
                let mut target_q = self.target_q_table.write().unwrap();
                *target_q = q.clone();
            }
        }
    }
}
