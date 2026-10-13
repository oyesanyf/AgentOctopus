"""
Module 14: Dream-RSI Off-Policy Optimizer (Recursive Self-Improvement).

Executes off-policy rollouts and evolutionary optimization across historical
world models. Synthesizes exploration policies that maximize high-yield anomaly
discovery while penalizing false positives and unnecessary compute.
"""

import copy
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from engine.dream_world_model import ProtocolWorldModel, SimulatedResponse


@dataclass
class DreamPolicy:
    generation: int
    mutator_weights: Dict[str, float] = field(default_factory=dict)
    normative_bias: float = 0.5  # 0.0 = exploratory/anti-anchored, 1.0 = strict MUST/SHOULD clauses
    delta_aggressiveness: float = 0.5  # early pruning threshold in DeltaDebugger
    fitness_score: float = 0.0
    rsi_gain: float = 0.0
    simulated_yield: float = 0.0
    false_positive_rate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generation": self.generation,
            "mutator_weights": self.mutator_weights,
            "normative_bias": round(self.normative_bias, 4),
            "delta_aggressiveness": round(self.delta_aggressiveness, 4),
            "fitness_score": round(self.fitness_score, 4),
            "rsi_gain": round(self.rsi_gain, 4),
            "simulated_yield": round(self.simulated_yield, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DreamPolicy":
        return cls(
            generation=data.get("generation", 0),
            mutator_weights=data.get("mutator_weights", {}),
            normative_bias=data.get("normative_bias", 0.5),
            delta_aggressiveness=data.get("delta_aggressiveness", 0.5),
            fitness_score=data.get("fitness_score", 0.0),
            rsi_gain=data.get("rsi_gain", 0.0),
            simulated_yield=data.get("simulated_yield", 0.0),
            false_positive_rate=data.get("false_positive_rate", 0.0),
        )


class DreamRSIOptimizer:
    """
    Off-policy Dreaming Engine. Evaluates thousands of candidate exploration
    trajectories in simulation to discover superior protocol fuzzing policies.
    """

    DEFAULT_ARMS = [
        "TE_CL_DUAL_HEADER",
        "PATH_NUL_EARLY_RESPONSE",
        "DANGLING_BYTE_STACKED_RESPONSE",
        "MULTIPART_BYTERANGES_SHARED_PARSER",
        "HEADER_TAB_SPACING",
        "CRLF_DELIMITER_SPLIT",
        "OBS_FOLD_LINE_JOIN",
        "OVERLONG_UTF8_NORMALIZATION",
    ]

    def __init__(self, world_model: ProtocolWorldModel):
        self.world_model = world_model
        self.current_generation = 0
        self.active_policy = self._create_baseline_policy()

    def _create_baseline_policy(self) -> DreamPolicy:
        """Constructs a uniform exploratory baseline policy (Generation 0)."""
        uniform_weights = {arm: 1.0 / len(self.DEFAULT_ARMS) for arm in self.DEFAULT_ARMS}
        return DreamPolicy(
            generation=0,
            mutator_weights=uniform_weights,
            normative_bias=0.5,
            delta_aggressiveness=0.5,
            fitness_score=1.0,
            rsi_gain=0.0,
        )

    def evaluate_policy_fitness(self, policy: DreamPolicy, rollouts: int = 200) -> float:
        """
        Runs simulated rollouts against the ProtocolWorldModel to compute policy fitness.
        Reward objective:
          F(pi) = +10.0 * Vulns + 3.0 * Anomalies - 8.0 * FalsePositives - 0.01 * Steps
        """
        true_vulns = 0
        true_anomalies = 0
        false_positives = 0

        # Sample arms according to policy weights
        arms = list(policy.mutator_weights.keys())
        weights = list(policy.mutator_weights.values())
        total_w = sum(weights) or 1.0
        norm_weights = [w / total_w for w in weights]

        for _ in range(rollouts):
            chosen_arm = random.choices(arms, weights=norm_weights, k=1)[0]
            # Synthesize representative probe for this arm
            probe = self._synthesize_simulated_probe_for_arm(chosen_arm)
            sim_resp = self.world_model.simulate_probe(probe)

            if sim_resp.is_vulnerability:
                true_vulns += 1
            elif sim_resp.is_anomaly:
                true_anomalies += 1
            elif "framing omission" in sim_resp.details.lower():
                false_positives += 1

        fitness = (10.0 * true_vulns) + (3.0 * true_anomalies) - (8.0 * false_positives) - (0.01 * rollouts)
        policy.fitness_score = fitness
        policy.simulated_yield = (true_vulns + true_anomalies) / max(1, rollouts)
        policy.false_positive_rate = false_positives / max(1, rollouts)
        return fitness

    def _synthesize_simulated_probe_for_arm(self, arm_name: str) -> bytes:
        """Synthesizes structural byte patterns corresponding to exploration arms."""
        if arm_name == "TE_CL_DUAL_HEADER":
            return b"POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        elif arm_name == "PATH_NUL_EARLY_RESPONSE":
            return b"POST /nul HTTP/1.1\r\nHost: target.local\r\nContent-Length: 0\r\n\r\n"
        elif arm_name == "DANGLING_BYTE_STACKED_RESPONSE":
            return b"POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 1\r\n\r\n"
        elif arm_name == "MULTIPART_BYTERANGES_SHARED_PARSER":
            return b"POST / HTTP/1.1\r\nHost: target.local\r\nContent-Type: multipart/byteranges; boundary=B\r\nContent-Length: 0\r\n\r\n"
        elif arm_name == "HEADER_TAB_SPACING":
            return b"GET / HTTP/1.1\r\nHost: target.local\r\nX-Foo:\tbar\r\n\r\n"
        elif arm_name == "OBS_FOLD_LINE_JOIN":
            return b"GET / HTTP/1.1\r\nHost: target.local\r\nX-Header: val\r\n continued\r\n\r\n"
        elif arm_name == "OVERLONG_UTF8_NORMALIZATION":
            return b"GET / HTTP/1.1\r\nHost: target.local\r\nHeader: \xc0\x8a\r\n\r\n"
        return b"GET / HTTP/1.1\r\nHost: target.local\r\n\r\n"

    def evolve_policy_generation(self, rollouts_per_candidate: int = 200, population_size: int = 6) -> DreamPolicy:
        """
        Executes one evolutionary generation of off-policy dreaming.
        Mutates parent weights, evaluates fitness across the population,
        and returns the dominant evolved policy.
        """
        self.current_generation += 1
        base_fitness = self.evaluate_policy_fitness(self.active_policy, rollouts=rollouts_per_candidate)

        candidates: List[DreamPolicy] = []
        for i in range(population_size):
            cand_weights = copy.deepcopy(self.active_policy.mutator_weights)
            # Apply Gaussian perturbation to weights
            for arm in cand_weights:
                perturbation = random.gauss(0.0, 0.2)
                cand_weights[arm] = max(0.05, cand_weights[arm] + perturbation)

            # Normalize weights
            sum_w = sum(cand_weights.values())
            for arm in cand_weights:
                cand_weights[arm] /= sum_w

            cand_policy = DreamPolicy(
                generation=self.current_generation,
                mutator_weights=cand_weights,
                normative_bias=max(0.1, min(0.9, self.active_policy.normative_bias + random.gauss(0.0, 0.1))),
                delta_aggressiveness=max(0.1, min(0.9, self.active_policy.delta_aggressiveness + random.gauss(0.0, 0.1))),
            )
            self.evaluate_policy_fitness(cand_policy, rollouts=rollouts_per_candidate)
            candidates.append(cand_policy)

        # Select highest-fitness candidate
        best_candidate = max(candidates, key=lambda p: p.fitness_score)

        if best_candidate.fitness_score > base_fitness:
            gain = (best_candidate.fitness_score - base_fitness) / max(1.0, abs(base_fitness))
            best_candidate.rsi_gain = gain
            self.active_policy = best_candidate
        else:
            self.active_policy = copy.deepcopy(self.active_policy)
            self.active_policy.generation = self.current_generation
            self.active_policy.rsi_gain = 0.0

        return self.active_policy
