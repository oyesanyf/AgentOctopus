use super::types::{MutationPriorityItem, ResearchPolicy, RfcPriorityItem, RsiExperimentPlan};
use super::world_model::ProtocolWorldModel;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Optimizes protocol research policies by evaluating candidate strategies in the offline World Model.
pub struct DreamRsiPolicyOptimizer {
    world_model: ProtocolWorldModel,
    active_policy: ResearchPolicy,
    policy_history: Vec<ResearchPolicy>,
}

impl DreamRsiPolicyOptimizer {
    pub fn new() -> Self {
        Self {
            world_model: ProtocolWorldModel::new(),
            active_policy: ResearchPolicy::default(),
            policy_history: Vec::new(),
        }
    }

    pub fn with_world_model(model: ProtocolWorldModel) -> Self {
        Self {
            world_model: model,
            active_policy: ResearchPolicy::default(),
            policy_history: Vec::new(),
        }
    }

    pub fn world_model(&self) -> &ProtocolWorldModel {
        &self.world_model
    }

    pub fn world_model_mut(&mut self) -> &mut ProtocolWorldModel {
        &mut self.world_model
    }

    pub fn active_policy(&self) -> &ResearchPolicy {
        &self.active_policy
    }

    pub fn set_policy(&mut self, policy: ResearchPolicy) {
        self.active_policy = policy;
    }

    /// Run offline Dream-RSI policy optimization iterations.
    /// Evaluates candidate policy mutations across simulated rollouts in the world model.
    pub fn optimize_policy(
        &mut self,
        iterations: usize,
        steps_per_candidate: usize,
    ) -> ResearchPolicy {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut best_policy = self.active_policy.clone();
        let baseline_report = self
            .world_model
            .simulate_rollout(&best_policy, steps_per_candidate);
        let mut best_fitness =
            Self::calculate_fitness(&baseline_report, best_policy.default_trial_budget);
        best_policy.fitness_score = best_fitness;

        let rfc_list: Vec<u32> = best_policy.rfc_weights.keys().cloned().collect();
        let mut_list: Vec<String> = best_policy.mutation_weights.keys().cloned().collect();

        let mut rng_seed: u64 = 0x5DEECE66D ^ (iterations as u64);
        let mut next_rand = || -> f64 {
            rng_seed = rng_seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((rng_seed >> 32) as f64) / (u32::MAX as f64)
        };

        for gen in 1..=iterations {
            let mut candidate = best_policy.clone();
            candidate.generation = best_policy.generation + gen;
            candidate.policy_id = format!("rsi-gen-{}-{}", candidate.generation, now);

            // Mutate RFC weights
            for rfc in &rfc_list {
                let current_w = *candidate.rfc_weights.get(rfc).unwrap_or(&1.0);
                let delta = (next_rand() - 0.5) * 0.4;
                let new_w = (current_w + delta).clamp(0.1, 5.0);
                candidate.rfc_weights.insert(*rfc, new_w);
            }

            // Mutate Mutation weights
            for m in &mut_list {
                let current_w = *candidate.mutation_weights.get(m).unwrap_or(&1.0);
                let delta = (next_rand() - 0.5) * 0.4;
                let new_w = (current_w + delta).clamp(0.1, 5.0);
                candidate.mutation_weights.insert(m.clone(), new_w);
            }

            // Temperature / Trial budget tuning
            if next_rand() < 0.3 {
                candidate.default_trial_budget = if next_rand() < 0.5 { 3 } else { 4 };
            }
            let temp_delta = (next_rand() - 0.5) * 0.1;
            candidate.exploration_temperature =
                (candidate.exploration_temperature + temp_delta).clamp(0.05, 0.60);

            // Evaluate in dream simulation
            let report = self
                .world_model
                .simulate_rollout(&candidate, steps_per_candidate);
            let candidate_fitness =
                Self::calculate_fitness(&report, candidate.default_trial_budget);
            candidate.fitness_score = candidate_fitness;

            if candidate_fitness > best_fitness {
                best_fitness = candidate_fitness;
                best_policy = candidate;
            }
        }

        self.policy_history.push(self.active_policy.clone());
        self.active_policy = best_policy.clone();
        best_policy
    }

    fn calculate_fitness(report: &super::types::DreamRolloutReport, trial_budget: u32) -> f64 {
        let yield_component = report.projected_yield * 1.5;
        let entropy_gain = report.projected_entropy_reduction * 25.0;
        let reproducibility_factor = report.projected_reproducibility * 10.0;
        let budget_penalty = (trial_budget as f64) * 0.5;

        (yield_component + entropy_gain + reproducibility_factor - budget_penalty).max(0.01)
    }

    /// Generate an actionable strategic experiment plan from the current active policy.
    pub fn generate_experiment_plan(&self) -> RsiExperimentPlan {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let titles: HashMap<u32, (&str, Vec<&str>)> = [
            (
                9112,
                (
                    "HTTP/1.1 Framing and Delimiting",
                    vec![
                        "3.2 Header Fields",
                        "6.1 Chunked Transfer Coding",
                        "9.3 Protocol Smuggling",
                    ],
                ),
            ),
            (
                9110,
                (
                    "HTTP Semantics & Field Parsing",
                    vec![
                        "5.6 Header Format",
                        "7.1 Request Modifiers",
                        "8.8 Caching Preconditions",
                    ],
                ),
            ),
            (
                7230,
                (
                    "Legacy HTTP/1.1 Message Syntax",
                    vec![
                        "3.3.3 Message Body Length",
                        "4.1 Chunked Extension",
                        "5.4 Host Header",
                    ],
                ),
            ),
            (
                7540,
                (
                    "Hypertext Transfer Protocol Version 2",
                    vec![
                        "4.1 Frame Format",
                        "8.1 HTTP Message Frames",
                        "10.3 Framing Abuse",
                    ],
                ),
            ),
            (
                9113,
                (
                    "HTTP/2 Protocol Specification",
                    vec![
                        "4.3 Header Compression",
                        "6.2 HEADERS Frames",
                        "10.5 Denial of Service",
                    ],
                ),
            ),
        ]
        .into_iter()
        .collect();

        let mut prioritized_rfcs: Vec<RfcPriorityItem> = self
            .active_policy
            .rfc_weights
            .iter()
            .map(|(rfc, w)| {
                let (title, sections) = titles
                    .get(rfc)
                    .cloned()
                    .unwrap_or(("HTTP Specification", vec!["General Normative Requirements"]));
                RfcPriorityItem {
                    rfc_number: *rfc,
                    title: title.to_string(),
                    priority_score: *w,
                    recommended_sections: sections.into_iter().map(|s| s.to_string()).collect(),
                }
            })
            .collect();
        prioritized_rfcs.sort_by(|a, b| {
            b.priority_score
                .partial_cmp(&a.priority_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut prioritized_mutations: Vec<MutationPriorityItem> = self
            .active_policy
            .mutation_weights
            .iter()
            .map(|(m, w)| {
                let trans_rate = self
                    .world_model
                    .get_transition(9112, m)
                    .map(|t| t.predicted_divergence)
                    .unwrap_or(0.20);
                MutationPriorityItem {
                    mutation_type: m.clone(),
                    weight: *w,
                    historical_divergence_rate: trans_rate,
                }
            })
            .collect();
        prioritized_mutations.sort_by(|a, b| {
            b.weight
                .partial_cmp(&a.weight)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let top_rfc = prioritized_rfcs
            .first()
            .map(|r| r.rfc_number)
            .unwrap_or(9112);
        let top_mut = prioritized_mutations
            .first()
            .map(|m| m.mutation_type.as_str())
            .unwrap_or("header_smuggling");

        let rationale = format!(
            "Dream-RSI Rollout Gen {} prioritized RFC-{} ({:.2}x) and mutation '{}' ({:.2}x) based on offline world-model yield and entropy optimization without live egress.",
            self.active_policy.generation,
            top_rfc,
            prioritized_rfcs.first().map(|r| r.priority_score).unwrap_or(1.0),
            top_mut,
            prioritized_mutations.first().map(|m| m.weight).unwrap_or(1.0),
        );

        RsiExperimentPlan {
            plan_id: format!("rsi-plan-{}", now),
            generated_at: now,
            policy_generation: self.active_policy.generation,
            prioritized_rfcs,
            prioritized_mutations,
            recommended_trial_budget: self.active_policy.default_trial_budget,
            estimated_discovery_yield: self.active_policy.fitness_score,
            rationale,
        }
    }
}
