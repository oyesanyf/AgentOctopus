"""
Offline Protocol World Model for Dream-RSI.
Models protocol divergence probabilities and information entropy without touching live sockets.
"""

import math
from typing import Dict, List, Any, Optional

class WorldModel:
    def __init__(self):
        self.transitions: Dict[str, Dict[str, Any]] = {}
        self._seed_priors()

    def _state_key(self, rfc_number: int, mutation_type: str) -> str:
        return f"{rfc_number}:{mutation_type.strip().lower()}"

    def _seed_priors(self):
        priors = [
            (9112, "abnf_delimiter", 4.0, 10.0),
            (9112, "header_smuggling", 6.0, 8.0),
            (9112, "crlf_injection", 5.0, 10.0),
            (9110, "abnf_delimiter", 2.0, 15.0),
            (9110, "case_mutation", 1.0, 20.0),
            (7230, "header_smuggling", 7.0, 7.0),
            (7540, "duplicate_header", 3.0, 12.0),
            (9113, "chunk_extension", 4.0, 10.0),
        ]
        for rfc, mtype, a, b in priors:
            p = a / (a + b)
            key = self._state_key(rfc, mtype)
            self.transitions[key] = {
                "rfc_number": rfc,
                "mutation_type": mtype,
                "alpha_anomalies": a,
                "beta_clean": b,
                "predicted_divergence": p,
                "predicted_reproducibility": 0.90,
                "information_entropy": self._entropy(p),
                "samples": int(a + b),
            }

    @staticmethod
    def _entropy(p: float) -> float:
        if p <= 0.0 or p >= 1.0:
            return 0.0
        return -p * math.log2(p) - (1.0 - p) * math.log2(1.0 - p)

    def train_from_events(self, events: List[Dict[str, Any]]) -> int:
        for ev in events:
            rfc = ev["rfc_number"]
            mtype = ev["mutation_type"]
            key = self._state_key(rfc, mtype)
            if key not in self.transitions:
                self.transitions[key] = {
                    "rfc_number": rfc,
                    "mutation_type": mtype,
                    "alpha_anomalies": 1.0,
                    "beta_clean": 5.0,
                    "predicted_divergence": 0.16,
                    "predicted_reproducibility": 0.85,
                    "information_entropy": self._entropy(0.16),
                    "samples": 0,
                }
            entry = self.transitions[key]
            entry["samples"] += 1
            if ev["is_anomalous"]:
                entry["alpha_anomalies"] += 1.0
            else:
                entry["beta_clean"] += 1.0
            p = entry["alpha_anomalies"] / (entry["alpha_anomalies"] + entry["beta_clean"])
            entry["predicted_divergence"] = p
            entry["predicted_reproducibility"] = (entry["predicted_reproducibility"] * 0.8) + (ev["reproducibility_rate"] * 0.2)
            entry["information_entropy"] = self._entropy(p)
        return len(events)

    def predict(self, rfc_number: int, mutation_type: str) -> Dict[str, Any]:
        key = self._state_key(rfc_number, mutation_type)
        if key in self.transitions:
            return self.transitions[key]
        return {
            "rfc_number": rfc_number,
            "mutation_type": mutation_type,
            "predicted_divergence": 0.20,
            "predicted_reproducibility": 0.80,
            "information_entropy": self._entropy(0.20),
            "samples": 0,
        }
