"""
Module 2: Adaptive Bandit and Genetic Scheduler (P0).

Employs Multi-Armed Bandit (UCB1 / Epsilon-Greedy) and Genetic Algorithm heuristics
to dynamically prioritize mutation families that yield high parser divergence
and protocol desynchronization.
"""

import math
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class BanditArmStats:
    name: str
    pulls: int = 0
    total_reward: float = 0.0
    anomalies_found: int = 0
    vulnerabilities_confirmed: int = 0
    last_pulled_at: float = field(default_factory=time.time)

    @property
    def mean_reward(self) -> float:
        return self.total_reward / self.pulls if self.pulls > 0 else 0.0


@dataclass
class GeneticIndividual:
    payload: bytes
    mutation_family: str
    fitness_score: float = 0.0
    generation: int = 0


class AdaptiveBanditScheduler:
    """
    Manages active exploration vs exploitation across mutation families,
    and breeds high-fitness protocol mutations using genetic operations.
    """

    CORE_MUTATION_FAMILIES = [
        "ABNF_INVERSION",
        "CRLF_DELIMITER_SPLIT",
        "TE_CL_DUAL_HEADER",
        "CHUNK_EXTENSION_CORRUPTION",
        "OBS_FOLD_MUTATION",
        "HOP_BY_HOP_INVERSION",
        "SHARED_PARSER_REVERSAL",
        "UNICODE_BOM_INJECTION",
    ]

    def __init__(self, exploration_weight: float = 1.414, epsilon: float = 0.15):
        self.c = exploration_weight  # UCB1 exploration constant
        self.epsilon = epsilon
        self.total_pulls = 0
        self.arms: Dict[str, BanditArmStats] = {
            name: BanditArmStats(name=name) for name in self.CORE_MUTATION_FAMILIES
        }
        self.population: List[GeneticIndividual] = []
        self.max_population = 50

    def select_arm(self) -> str:
        """Selects the next mutation family using UCB1 with epsilon-greedy fallback."""
        self.total_pulls += 1

        # Phase 1: Try every arm at least once (Cold Start)
        for name, arm in self.arms.items():
            if arm.pulls == 0:
                return name

        # Phase 2: Epsilon exploration
        if random.random() < self.epsilon:
            return random.choice(list(self.arms.keys()))

        # Phase 3: UCB1 score calculation
        best_score = -1.0
        best_arm = list(self.arms.keys())[0]

        for name, arm in self.arms.items():
            bonus = self.c * math.sqrt(math.log(self.total_pulls) / arm.pulls)
            score = arm.mean_reward + bonus
            if score > best_score:
                best_score = score
                best_arm = name

        return best_arm

    def record_feedback(
        self,
        family: str,
        reward: float,
        is_anomaly: bool = False,
        is_vulnerability: bool = False,
        payload: Optional[bytes] = None,
    ) -> None:
        """Updates bandit arms and populates the genetic breeding pool."""
        if family not in self.arms:
            self.arms[family] = BanditArmStats(name=family)

        arm = self.arms[family]
        arm.pulls += 1
        arm.total_reward += reward
        arm.last_pulled_at = time.time()

        if is_anomaly:
            arm.anomalies_found += 1
        if is_vulnerability:
            arm.vulnerabilities_confirmed += 1

        # Register into genetic population if fitness is positive
        if payload and reward > 0.5:
            individual = GeneticIndividual(
                payload=payload,
                mutation_family=family,
                fitness_score=reward,
            )
            self.population.append(individual)
            self.population.sort(key=lambda ind: ind.fitness_score, reverse=True)
            if len(self.population) > self.max_population:
                self.population.pop()

    def breed_next_generation(self) -> Optional[bytes]:
        """
        Applies genetic crossover and mutation to breed a novel candidate probe
        from the highest-performing individuals in the population.
        """
        if len(self.population) < 2:
            return None

        # Tournament selection of parents
        parent1 = random.choice(self.population[:5])
        parent2 = random.choice(self.population[:10])

        # Crossover: split headers and combine
        p1_lines = parent1.payload.split(b"\r\n")
        p2_lines = parent2.payload.split(b"\r\n")

        split_idx1 = max(1, len(p1_lines) // 2)
        split_idx2 = max(1, len(p2_lines) // 2)

        child_lines = p1_lines[:split_idx1] + p2_lines[split_idx2:]
        child_payload = b"\r\n".join(child_lines)

        # Mutation: bit-flip or delimiter substitution
        child_payload = self._apply_genetic_mutation(child_payload)
        return child_payload

    def _apply_genetic_mutation(self, payload: bytes) -> bytes:
        """Applies point mutation to a byte sequence."""
        if not payload:
            return payload

        mutations = [
            lambda p: p.replace(b" ", b"\t", 1),
            lambda p: p.replace(b"\r\n", b"\n", 1),
            lambda p: p.replace(b"chunked", b"chunked ", 1),
            lambda p: p + b"\r\n0\r\n\r\n",
            lambda p: p.replace(b": ", b":\t", 1),
        ]
        choice = random.choice(mutations)
        try:
            return choice(payload)
        except Exception:
            return payload

    def get_summary(self) -> Dict[str, Any]:
        """Returns diagnostic metrics for arms."""
        return {
            name: {
                "pulls": arm.pulls,
                "mean_reward": round(arm.mean_reward, 4),
                "anomalies": arm.anomalies_found,
                "vulnerabilities": arm.vulnerabilities_confirmed,
            }
            for name, arm in self.arms.items()
        }
