use super::types::{DreamRolloutReport, ResearchPolicy, TrajectoryEvent, WorldModelTransition};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Deterministic offline protocol world model learned from historical experiment traces.
pub struct ProtocolWorldModel {
    transitions: HashMap<String, WorldModelTransition>,
    total_samples: usize,
}

impl ProtocolWorldModel {
    pub fn new() -> Self {
        let mut model = Self {
            transitions: HashMap::new(),
            total_samples: 0,
        };
        model.seed_priors();
        model
    }

    /// Key format: "rfc:mutation"
    fn state_key(rfc_number: u32, mutation_type: &str) -> String {
        format!("{}:{}", rfc_number, mutation_type.to_lowercase().trim())
    }

    /// Seed Bayesian priors based on known RFC normative framing complexity.
    fn seed_priors(&mut self) {
        let priors = vec![
            (9112, "abnf_delimiter", 4.0, 10.0),
            (9112, "header_smuggling", 6.0, 8.0),
            (9112, "crlf_injection", 5.0, 10.0),
            (9110, "abnf_delimiter", 2.0, 15.0),
            (9110, "case_mutation", 1.0, 20.0),
            (7230, "header_smuggling", 7.0, 7.0),
            (7540, "duplicate_header", 3.0, 12.0),
            (9113, "chunk_extension", 4.0, 10.0),
        ];

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (rfc, mut_type, a, b) in priors {
            let p = a / (a + b);
            let entropy = Self::calculate_entropy(p);
            let key = Self::state_key(rfc, mut_type);
            self.transitions.insert(
                key,
                WorldModelTransition {
                    rfc_number: rfc,
                    mutation_type: mut_type.to_string(),
                    sample_count: (a + b) as usize,
                    alpha_anomalies: a,
                    beta_clean: b,
                    predicted_divergence: p,
                    predicted_reproducibility: 0.90,
                    information_entropy: entropy,
                    last_updated: now,
                },
            );
        }
    }

    fn calculate_entropy(p: f64) -> f64 {
        if p <= 0.0 || p >= 1.0 {
            0.0
        } else {
            -p * p.log2() - (1.0 - p) * (1.0 - p).log2()
        }
    }

    /// Ingest a batch of historical trajectory events into the world model.
    pub fn ingest_trajectories(&mut self, events: &[TrajectoryEvent]) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for ev in events {
            let key = Self::state_key(ev.rfc_number, &ev.mutation_type);
            let trans = self.transitions.entry(key).or_insert_with(|| WorldModelTransition {
                rfc_number: ev.rfc_number,
                mutation_type: ev.mutation_type.clone(),
                sample_count: 0,
                alpha_anomalies: 1.0,
                beta_clean: 5.0,
                predicted_divergence: 0.16,
                predicted_reproducibility: 0.85,
                information_entropy: Self::calculate_entropy(0.16),
                last_updated: now,
            });

            trans.sample_count += 1;
            if ev.is_anomalous {
                trans.alpha_anomalies += 1.0;
            } else {
                trans.beta_clean += 1.0;
            }

            let p = trans.alpha_anomalies / (trans.alpha_anomalies + trans.beta_clean);
            trans.predicted_divergence = p;
            trans.predicted_reproducibility = if trans.predicted_reproducibility == 0.0 {
                ev.reproducibility_rate
            } else {
                (trans.predicted_reproducibility * 0.8) + (ev.reproducibility_rate * 0.2)
            };
            trans.information_entropy = Self::calculate_entropy(p);
            trans.last_updated = now;

            self.total_samples += 1;
        }
    }

    pub fn get_transition(&self, rfc_number: u32, mutation_type: &str) -> Option<&WorldModelTransition> {
        let key = Self::state_key(rfc_number, mutation_type);
        self.transitions.get(&key)
    }

    pub fn all_transitions(&self) -> Vec<WorldModelTransition> {
        self.transitions.values().cloned().collect()
    }

    pub fn total_states(&self) -> usize {
        self.transitions.len()
    }

    pub fn total_samples(&self) -> usize {
        self.total_samples
    }

    /// Execute an offline Dream Rollout: simulates policy execution against the world model.
    /// Completely offline, zero socket egress, evaluating thousands of candidate probe decisions.
    pub fn simulate_rollout(&self, policy: &ResearchPolicy, steps: usize) -> DreamRolloutReport {
        let start_time = SystemTime::now();
        let mut rng_seed: u64 = 0x9E3779B97F4A7C15 ^ (steps as u64);

        let mut anomalies_discovered = 0;
        let mut false_positives_filtered = 0;
        let mut cumulative_yield = 0.0;
        let mut initial_entropy = 0.0;
        let mut final_entropy = 0.0;

        let rfc_keys: Vec<u32> = policy.rfc_weights.keys().cloned().collect();
        let mut_keys: Vec<String> = policy.mutation_weights.keys().cloned().collect();

        if rfc_keys.is_empty() || mut_keys.is_empty() {
            return DreamRolloutReport {
                rollout_id: format!("rollout-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()),
                policy_id: policy.policy_id.clone(),
                simulated_steps: 0,
                projected_yield: 0.0,
                projected_entropy_reduction: 0.0,
                projected_reproducibility: 0.0,
                simulated_anomalies_discovered: 0,
                simulated_false_positives_filtered: 0,
                duration_ms: 0,
            };
        }

        // Fast PRNG for simulation rollout
        let mut next_rand = || -> f64 {
            rng_seed = rng_seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((rng_seed >> 32) as f64) / (u32::MAX as f64)
        };

        for _ in 0..steps {
            // Select RFC according to policy weights
            let rfc = {
                let total_weight: f64 = rfc_keys.iter().map(|k| policy.rfc_weights.get(k).unwrap_or(&1.0)).sum();
                let pick = next_rand() * total_weight;
                let mut acc = 0.0;
                let mut chosen = rfc_keys[0];
                for k in &rfc_keys {
                    acc += policy.rfc_weights.get(k).unwrap_or(&1.0);
                    if pick <= acc {
                        chosen = *k;
                        break;
                    }
                }
                chosen
            };

            // Select Mutation according to policy weights
            let mut_type = {
                let total_weight: f64 = mut_keys.iter().map(|k| policy.mutation_weights.get(k).unwrap_or(&1.0)).sum();
                let pick = next_rand() * total_weight;
                let mut acc = 0.0;
                let mut chosen = &mut_keys[0];
                for k in &mut_keys {
                    acc += policy.mutation_weights.get(k).unwrap_or(&1.0);
                    if pick <= acc {
                        chosen = k;
                        break;
                    }
                }
                chosen.clone()
            };

            let default_trans = WorldModelTransition {
                rfc_number: rfc,
                mutation_type: mut_type.clone(),
                sample_count: 5,
                alpha_anomalies: 1.0,
                beta_clean: 4.0,
                predicted_divergence: 0.20,
                predicted_reproducibility: 0.80,
                information_entropy: Self::calculate_entropy(0.20),
                last_updated: 0,
            };

            let trans = self.get_transition(rfc, &mut_type).unwrap_or(&default_trans);
            initial_entropy += trans.information_entropy;

            // Simulated probe rollout outcome
            let outcome_roll = next_rand();
            if outcome_roll < trans.predicted_divergence {
                // Potential anomaly identified in dream simulation
                // Multi-trial confirmation verification
                let trial_budget = policy.default_trial_budget;
                let mut confirmed = 0;
                for _ in 0..trial_budget {
                    if next_rand() < trans.predicted_reproducibility {
                        confirmed += 1;
                    }
                }

                if confirmed >= (trial_budget * 2 / 3) {
                    anomalies_discovered += 1;
                    cumulative_yield += trans.predicted_divergence * trans.predicted_reproducibility;
                } else {
                    false_positives_filtered += 1;
                }
            }

            // Post-simulation updated entropy
            let new_alpha = trans.alpha_anomalies + if outcome_roll < trans.predicted_divergence { 1.0 } else { 0.0 };
            let new_beta = trans.beta_clean + if outcome_roll >= trans.predicted_divergence { 1.0 } else { 0.0 };
            let new_p = new_alpha / (new_alpha + new_beta);
            final_entropy += Self::calculate_entropy(new_p);
        }

        let entropy_reduction = ((initial_entropy - final_entropy) / (steps as f64)).max(0.0);
        let projected_yield = (cumulative_yield / (steps as f64)) * 100.0;
        let avg_reproducibility = if anomalies_discovered + false_positives_filtered > 0 {
            (anomalies_discovered as f64) / ((anomalies_discovered + false_positives_filtered) as f64)
        } else {
            0.0
        };

        let duration_ms = start_time.elapsed().map(|d| d.as_millis() as u64).unwrap_or(1);

        DreamRolloutReport {
            rollout_id: format!("rollout-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()),
            policy_id: policy.policy_id.clone(),
            simulated_steps: steps,
            projected_yield,
            projected_entropy_reduction: entropy_reduction,
            projected_reproducibility: avg_reproducibility,
            simulated_anomalies_discovered: anomalies_discovered,
            simulated_false_positives_filtered: false_positives_filtered,
            duration_ms,
        }
    }
}
