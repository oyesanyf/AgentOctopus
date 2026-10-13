"""
Module 13: Protocol World Model (Dream-RSI Offline Replay Simulator).

Implements the in-memory environment simulator for Dream-RSI (Recursive Self-Improvement
through Evolving Worlds). Reconstructs target protocol behavior, state transitions,
framing characteristics, and anomaly triggers from accumulated research history
without making live network requests.
"""

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class SimulatedResponse:
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    raw_response: bytes = b""
    latency: float = 0.05
    is_connection_closed: bool = False
    framing_type: str = "content-length"
    is_anomaly: bool = False
    anomaly_category: Optional[str] = None
    is_vulnerability: bool = False
    confidence: float = 1.0
    details: str = "Simulated from world model"


@dataclass
class WorldModelTrajectory:
    trajectory_id: str
    target_host: str
    target_port: int
    probe_bytes: bytes
    response_status: int
    framing_type: str
    is_anomaly: bool
    anomaly_category: Optional[str]
    is_vulnerability: bool
    desync_vectors: List[str] = field(default_factory=list)
    timestamp: float = 0.0


class ProtocolWorldModel:
    """
    Stateful protocol replay simulator. Converts empirical execution history
    into an off-policy Markov Decision Process (MDP) for Dream-RSI exploration.
    """

    def __init__(self, target_host: str = "127.0.0.1", target_port: int = 5006):
        self.target_host = target_host
        self.target_port = target_port
        self.exact_cache: Dict[str, SimulatedResponse] = {}
        self.trajectories: List[WorldModelTrajectory] = []
        self.known_anomaly_patterns: Set[str] = set()
        self.known_mutator_rewards: Dict[str, List[float]] = {}
        self.server_signature: str = "generic"

    def _hash_probe(self, probe_bytes: bytes) -> str:
        return hashlib.sha256(probe_bytes).hexdigest()

    def record_step(
        self,
        probe_bytes: bytes,
        status_code: int,
        raw_response: bytes = b"",
        latency: float = 0.05,
        is_anomaly: bool = False,
        anomaly_category: Optional[str] = None,
        is_vulnerability: bool = False,
        details: str = "",
    ) -> None:
        """Records a live execution step into the world model memory."""
        p_hash = self._hash_probe(probe_bytes)
        sim = SimulatedResponse(
            status_code=status_code,
            raw_response=raw_response,
            latency=latency,
            is_connection_closed=(b"connection: close" in raw_response.lower() or status_code in (400, 431, 500)),
            framing_type="chunked" if b"transfer-encoding: chunked" in raw_response.lower() else "content-length",
            is_anomaly=is_anomaly,
            anomaly_category=anomaly_category,
            is_vulnerability=is_vulnerability,
            confidence=1.0,
            details=details or "Empirical observation recorded",
        )
        self.exact_cache[p_hash] = sim

        # Identify structural vectors
        p_lower = probe_bytes.lower()
        vectors = []
        if b"content-length" in p_lower and b"transfer-encoding" in p_lower:
            vectors.append("CL_TE")
        if b" :\t" in p_lower or b" :" in p_lower:
            vectors.append("COLON_WHITESPACE")
        if b"\r\n " in p_lower or b"\r\n\t" in p_lower:
            vectors.append("OBS_FOLD")
        if b"/nul" in p_lower:
            vectors.append("PATH_NUL")
        if b"multipart/byteranges" in p_lower:
            vectors.append("MULTIPART")

        traj = WorldModelTrajectory(
            trajectory_id=f"traj_{len(self.trajectories) + 1}",
            target_host=self.target_host,
            target_port=self.target_port,
            probe_bytes=probe_bytes,
            response_status=status_code,
            framing_type=sim.framing_type,
            is_anomaly=is_anomaly,
            anomaly_category=anomaly_category,
            is_vulnerability=is_vulnerability,
            desync_vectors=vectors,
        )
        self.trajectories.append(traj)

        if is_anomaly and anomaly_category:
            self.known_anomaly_patterns.add(anomaly_category)

    def ingest_history_from_db(self, db_path: str = "terminator.db") -> int:
        """
        Loads historical execution traces from SQLite into the world model.
        Returns the number of trajectories loaded.
        """
        p = Path(db_path)
        if not p.exists():
            return 0

        conn = sqlite3.connect(str(p))
        conn.row_factory = sqlite3.Row
        count = 0
        try:
            cursor = conn.cursor()
            # Ingest from probes and evaluations
            cursor.execute("""
                SELECT p.raw_request, e.is_vulnerable, e.desync_class, e.details
                FROM probes p
                LEFT JOIN evaluations e ON p.probe_id = e.probe_id
                WHERE p.raw_request IS NOT NULL
            """)
            for row in cursor.fetchall():
                raw_req = row["raw_request"]
                if isinstance(raw_req, str):
                    probe_b = raw_req.encode("latin-1", errors="replace")
                else:
                    probe_b = raw_req or b""
                if not probe_b:
                    continue

                is_vuln = bool(row["is_vulnerable"]) if row["is_vulnerable"] is not None else False
                desync = row["desync_class"]
                details = row["details"] or ""

                self.record_step(
                    probe_bytes=probe_b,
                    status_code=200 if not is_vuln else 400,
                    is_anomaly=is_vuln or bool(desync),
                    anomaly_category=desync,
                    is_vulnerability=is_vuln,
                    details=details,
                )
                count += 1
        except Exception:
            pass
        finally:
            conn.close()

        return count

    def simulate_probe(self, probe_bytes: bytes) -> SimulatedResponse:
        """
        Simulates target server response to a candidate probe.
        Uses exact replay if seen, or structural generalization if novel.
        """
        p_hash = self._hash_probe(probe_bytes)
        if p_hash in self.exact_cache:
            return self.exact_cache[p_hash]

        # Structural Generalized Simulation
        p_lower = probe_bytes.lower()

        # Check for un-framed client body
        has_cl = b"content-length:" in p_lower or b"content-length :" in p_lower
        has_te = b"transfer-encoding:" in p_lower or b"transfer-encoding :" in p_lower
        has_body = False
        if b"\r\n\r\n" in probe_bytes:
            _, body = probe_bytes.split(b"\r\n\r\n", 1)
            has_body = len(body.strip()) > 0

        # RFC 9112 Section 6.1 un-framed body
        if has_body and not has_cl and not has_te:
            return SimulatedResponse(
                status_code=400,
                latency=0.01,
                is_connection_closed=True,
                framing_type="content-length",
                is_anomaly=False,
                is_vulnerability=False,
                confidence=0.95,
                details="Simulated: Client framing omission (RFC 9112 §6.1); server rejects trailing socket data with 400.",
            )

        # Dual-CL conflict (Kettle breakthrough)
        if p_lower.count(b"content-length:") >= 2:
            return SimulatedResponse(
                status_code=400,
                latency=0.04,
                is_connection_closed=True,
                framing_type="content-length",
                is_anomaly=True,
                anomaly_category="DUAL_HEADER_CONFLICT",
                is_vulnerability=True,
                confidence=0.88,
                details="Simulated: Dual Content-Length detected; induces parser divergence across front/back-end.",
            )

        # CL.TE conflict
        if has_cl and has_te:
            return SimulatedResponse(
                status_code=200,
                latency=0.08,
                is_connection_closed=False,
                framing_type="chunked",
                is_anomaly=True,
                anomaly_category="CL_TE_DESYNCHRONIZATION",
                is_vulnerability=True,
                confidence=0.90,
                details="Simulated: CL.TE conflicting framing triggers stateful boundary desync.",
            )

        # Pre-colon whitespace
        if b" :" in probe_bytes or b"\t:" in probe_bytes:
            return SimulatedResponse(
                status_code=400,
                latency=0.02,
                is_connection_closed=True,
                framing_type="content-length",
                is_anomaly=False,
                is_vulnerability=False,
                confidence=0.95,
                details="Simulated: Pre-colon whitespace rejected under RFC 9112 §5.1 compliant parsing.",
            )

        # Baseline default simulation
        return SimulatedResponse(
            status_code=200,
            latency=0.05,
            is_connection_closed=False,
            framing_type="content-length",
            is_anomaly=False,
            is_vulnerability=False,
            confidence=0.75,
            details="Simulated: Standard conforming HTTP request.",
        )
