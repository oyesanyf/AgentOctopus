"""
Module 15: Dream-RSI Policy Store and Versioning Registry.

Persists evolved exploration policies, tracks lineage across generations,
and exports telemetry on empirical self-improvement gains.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from engine.dream_rsi_optimizer import DreamPolicy


class DreamPolicyStore:
    """
    Registry for versioning, storing, and loading evolved Dream-RSI policies.
    """

    def __init__(self, storage_path: str = "data/dream_policies.json"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.policies: List[DreamPolicy] = []
        self._load()

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    self.policies = [DreamPolicy.from_dict(item) for item in data]
                elif isinstance(data, dict) and "policies" in data:
                    self.policies = [DreamPolicy.from_dict(item) for item in data["policies"]]
        except Exception:
            self.policies = []

    def save_policy(self, policy: DreamPolicy) -> None:
        """Appends a newly evolved policy and persists the registry to disk."""
        self.policies.append(policy)
        payload = {
            "total_generations": len(self.policies),
            "latest_generation": policy.generation,
            "policies": [p.to_dict() for p in self.policies],
        }
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    def get_latest_policy(self) -> Optional[DreamPolicy]:
        if not self.policies:
            return None
        return self.policies[-1]

    def export_summary(self) -> Dict[str, Any]:
        """Returns empirical self-improvement summary."""
        if not self.policies:
            return {"status": "No evolved policies recorded"}
        
        latest = self.policies[-1]
        baseline = self.policies[0]
        cumulative_gain = ((latest.fitness_score - baseline.fitness_score) / max(1.0, abs(baseline.fitness_score))) * 100

        return {
            "total_generations": len(self.policies),
            "latest_generation": latest.generation,
            "latest_fitness": latest.fitness_score,
            "cumulative_rsi_gain_pct": round(cumulative_gain, 2),
            "dominant_mutators": sorted(
                latest.mutator_weights.items(), key=lambda x: x[1], reverse=True
            )[:3],
            "simulated_yield": latest.simulated_yield,
            "false_positive_rate": latest.false_positive_rate,
        }
