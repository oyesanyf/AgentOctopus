"""
Trajectory Buffer for Open Dream-RSI.
Parses, normalizes, and indexes historical protocol evaluation traces from Arm 107.
"""

import json
import os
from typing import List, Dict, Any, Optional

class TrajectoryBuffer:
    def __init__(self, buffer_file: Optional[str] = None):
        self.buffer_file = buffer_file
        self.events: List[Dict[str, Any]] = []

    def load_from_file(self, filepath: str) -> int:
        """Load JSON Lines formatted trajectory events."""
        if not os.path.exists(filepath):
            return 0
        loaded = 0
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    self.events.append(self._normalize_event(ev))
                    loaded += 1
                except Exception:
                    continue
        return loaded

    def add_event(self, ev: Dict[str, Any]) -> None:
        self.events.append(self._normalize_event(ev))

    def _normalize_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "event_id": str(raw.get("event_id", f"ev-{len(self.events)}")),
            "rfc_number": int(raw.get("rfc_number", 9112)),
            "section": str(raw.get("section", "3.2")),
            "mutation_type": str(raw.get("mutation_type", "abnf_delimiter")),
            "is_anomalous": bool(raw.get("is_anomalous", False)),
            "divergence_score": float(raw.get("divergence_score", 0.0)),
            "reproducibility_rate": float(raw.get("reproducibility_rate", 1.0)),
            "latency_ms": float(raw.get("latency_ms", 10.0)),
            "finding_status": str(raw.get("finding_status", "HEURISTIC_ANOMALY")),
            "timestamp": int(raw.get("timestamp", 0)),
        }

    def get_events(self) -> List[Dict[str, Any]]:
        return self.events

    def __len__(self) -> int:
        return len(self.events)
