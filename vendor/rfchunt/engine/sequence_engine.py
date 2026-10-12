"""
Module 5: Stateful Protocol Sequence Engine (P0).

Evaluates multi-request and multi-connection state machine lifecycles to detect
queue desynchronization, response queue poisoning, and pipelined byte leakage
over persistent TCP connections.
"""

import random
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from engine.taxonomy import AnomalyCategory, ImplementationAnomaly


@dataclass
class SequenceStepResult:
    step_name: str
    sent_bytes: bytes
    received_bytes: bytes
    status_code: int
    latency: float
    socket_error: Optional[str] = None


@dataclass
class SequenceExecutionReport:
    sequence_type: str
    target: str
    steps: List[SequenceStepResult] = field(default_factory=list)
    has_desynchronization: bool = False
    has_pipeline_leak: bool = False
    details: str = ""


class StatefulProtocolSequenceEngine:
    """
    Executes choreographed multi-request sequences over persistent sockets
    to uncover stateful boundary contamination and pipeline desynchronization.
    """

    def __init__(self, default_timeout: float = 3.5):
        self.default_timeout = default_timeout

    def run_pipelined_canary_sequence(
        self, host: str, port: int, candidate_probe: bytes, rule_id: Optional[str] = None
    ) -> SequenceExecutionReport:
        """
        Executes a 3-step sequence on a SINGLE persistent TCP connection:
        1. Baseline request -> ensure connection is clean and open.
        2. Candidate probe -> ambiguous boundary or mutated rule.
        3. Canary request -> detects if probe residual bytes leaked into canary.
        """
        report = SequenceExecutionReport(
            sequence_type="PIPELINED_CANARY",
            target=f"{host}:{port}",
        )
        canary_token = f"CANARY_{random.randint(10000, 99999)}"
        canary_request = (
            f"GET /check_{canary_token} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Canary-ID: {canary_token}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode("latin-1")

        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=self.default_timeout)

            # Step 1: Baseline Request
            start_t = time.time()
            baseline_req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n".encode()
            sock.sendall(baseline_req)
            resp1 = self._read_socket_available(sock, timeout=2.0)
            status1 = self._extract_status_code(resp1)

            report.steps.append(
                SequenceStepResult(
                    step_name="Step 1: Baseline",
                    sent_bytes=baseline_req,
                    received_bytes=resp1,
                    status_code=status1,
                    latency=time.time() - start_t,
                )
            )

            # Step 2: Send Candidate Probe
            start_t = time.time()
            sock.sendall(candidate_probe)
            resp2 = self._read_socket_available(sock, timeout=2.0)
            status2 = self._extract_status_code(resp2)

            report.steps.append(
                SequenceStepResult(
                    step_name="Step 2: Candidate Probe",
                    sent_bytes=candidate_probe,
                    received_bytes=resp2,
                    status_code=status2,
                    latency=time.time() - start_t,
                )
            )

            # Step 3: Canary Request
            start_t = time.time()
            sock.sendall(canary_request)
            resp3 = self._read_socket_available(sock, timeout=2.5)
            status3 = self._extract_status_code(resp3)

            report.steps.append(
                SequenceStepResult(
                    step_name="Step 3: Canary Check",
                    sent_bytes=canary_request,
                    received_bytes=resp3,
                    status_code=status3,
                    latency=time.time() - start_t,
                )
            )

            # Analyze sequence anomalies
            canary_bytes_lower = resp3.lower()
            if canary_token.lower().encode() in canary_bytes_lower and b"404" in resp3:
                # Normal: server processed canary route cleanly
                report.has_desynchronization = False
                report.details = "Normal: Canary request routed cleanly without boundary leakage."
            elif b"400 bad request" in resp3.lower() and status1 == 200:
                # Possible prefix contamination: probe bytes broke canary syntax
                report.has_pipeline_leak = True
                report.has_desynchronization = True
                report.details = "Pipeline Leak: Residual probe bytes corrupted the subsequent canary request."
            elif resp3 == b"" and len(resp2) > 0:
                report.has_pipeline_leak = True
                report.details = "Connection Dropped: Candidate probe caused premature connection termination before canary."
            elif b"terminator_marker" in resp3.lower() or b"x-smuggle" in resp3.lower():
                report.has_desynchronization = True
                report.details = "Queue Desynchronization: Candidate probe response or body bled directly into canary stream."

        except socket.timeout:
            report.details = "Socket Timeout during pipelined sequence execution."
        except ConnectionResetError:
            report.details = "Connection Reset by peer during stateful transition."
        except Exception as e:
            report.details = f"Sequence execution error: {e}"
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return report

    def _read_socket_available(self, sock: socket.socket, timeout: float = 2.0) -> bytes:
        """Reads whatever data is currently ready on the socket."""
        sock.settimeout(timeout)
        buf = b""
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                buf += data
                if b"\r\n\r\n" in buf and len(buf) > 1024:
                    break
            except socket.timeout:
                break
            except Exception:
                break
        return buf

    def _extract_status_code(self, data: bytes) -> int:
        try:
            first_line = data.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
            parts = first_line.split(" ", 2)
            if len(parts) > 1 and parts[1].isdigit():
                return int(parts[1])
        except Exception:
            pass
        return 0
