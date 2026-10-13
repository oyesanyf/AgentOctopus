"""
Dream-RSI Policy Agent.
Runs simulated rollouts in the world model to optimize experiment selection.
"""

import random
import time
from typing import Dict, Any, List
from .world_model import WorldModel

class PolicyAgent:
    def __init__(self, world_model: WorldModel):
        self.world_model = world_model
        self.policy = {
            "policy_id": "policy-agent-default",
            "generation": 0,
            "rfc_weights": {9110: 1.0, 9112: 1.2, 7230: 0.9, 7540: 1.1, 9113: 1.1},
            "mutation_weights": {
                "abnf_delimiter": 1.0,
                "header_smuggling": 1.2,
                "case_mutation": 0.7,
                "crlf_injection": 1.3,
                "duplicate_header": 0.8,
                "null_byte": 0.9,
                "chunk_extension": 1.1,
            },
            "default_trial_budget": 3,
            "exploration_temperature": 0.25,
            "fitness_score": 0.5,
        }

    def simulate_rollout(self, policy: Dict[str, Any], steps: int = 1000) -> Dict[str, Any]:
        """Simulate probing actions strictly against the world model."""
        rfc_keys = list(policy["rfc_weights"].keys())
        rfc_weights = [policy["rfc_weights"][k] for k in rfc_keys]

        mut_keys = list(policy["mutation_weights"].keys())
        mut_weights = [policy["mutation_weights"][k] for k in mut_keys]

        anomalies_discovered = 0
        false_positives_filtered = 0
        cumulative_yield = 0.0

        for _ in range(steps):
            chosen_rfc = random.choices(rfc_keys, weights=rfc_weights, k=1)[0]
            chosen_mut = random.choices(mut_keys, weights=mut_weights, k=1)[0]

            prediction = self.world_model.predict(chosen_rfc, chosen_mut)
            p_div = prediction["predicted_divergence"]
            p_rep = prediction["predicted_reproducibility"]

            if random.random() < p_div:
                # Potential anomaly, verify through multi-trial budget
                budget = policy.get("default_trial_budget", 3)
                confirmed = sum(1 for _ in range(budget) if random.random() < p_rep)
                if confirmed >= (budget * 2 / 3):
                    anomalies_discovered += 1
                    cumulative_yield += (p_div * p_rep)
                else:
                    false_positives_filtered += 1

        projected_yield = (cumulative_yield / steps) * 100.0
        avg_reproducibility = (
            (anomalies_discovered / (anomalies_discovered + false_positives_filtered))
            if (anomalies_discovered + false_positives_filtered) > 0
            else 0.0
        )

        fitness = (projected_yield * 1.5) + (avg_reproducibility * 10.0) - (policy.get("default_trial_budget", 3) * 0.5)

        return {
            "simulated_steps": steps,
            "anomalies_discovered": anomalies_discovered,
            "false_positives_filtered": false_positives_filtered,
            "projected_yield": projected_yield,
            "avg_reproducibility": avg_reproducibility,
            "fitness": max(0.01, fitness),
        }

    def train_policy(self, generations: int = 10, steps_per_gen: int = 1000) -> Dict[str, Any]:
        best_policy = dict(self.policy)
        best_report = self.simulate_rollout(best_policy, steps_per_gen)
        best_fitness = best_report["fitness"]

        for g in range(1, generations + 1):
            cand = {
                "policy_id": f"policy-gen-{g}",
                "generation": g,
                "rfc_weights": dict(best_policy["rfc_weights"]),
                "mutation_weights": dict(best_policy["mutation_weights"]),
                "default_trial_budget": best_policy["default_trial_budget"],
                "exploration_temperature": best_policy["exploration_temperature"],
            }

            # Mutate RFC weights
            for k in cand["rfc_weights"]:
                cand["rfc_weights"][k] = max(0.1, min(5.0, cand["rfc_weights"][k] + random.uniform(-0.2, 0.2)))

            # Mutate mutation weights
            for k in cand["mutation_weights"]:
                cand["mutation_weights"][k] = max(0.1, min(5.0, cand["mutation_weights"][k] + random.uniform(-0.2, 0.2)))

            if random.random() < 0.3:
                cand["default_trial_budget"] = random.choice([3, 4])

            rep = self.simulate_rollout(cand, steps_per_gen)
            if rep["fitness"] > best_fitness:
                best_fitness = rep["fitness"]
                best_policy = cand
                best_policy["fitness_score"] = best_fitness

        self.policy = best_policy
        return self.policy

    def generate_plan(self) -> Dict[str, Any]:
        prioritized_rfcs = sorted(
            [{"rfc_number": k, "priority_score": v} for k, v in self.policy["rfc_weights"].items()],
            key=lambda x: x["priority_score"],
            reverse=True,
        )
        prioritized_mutations = sorted(
            [{"mutation_type": k, "weight": v} for k, v in self.policy["mutation_weights"].items()],
            key=lambda x: x["weight"],
            reverse=True,
        )
        return {
            "policy_generation": self.policy["generation"],
            "prioritized_rfcs": prioritized_rfcs,
            "prioritized_mutations": prioritized_mutations,
            "recommended_trial_budget": self.policy["default_trial_budget"],
            "fitness_score": self.policy.get("fitness_score", 0.5),
        }
