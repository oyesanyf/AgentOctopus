"""
Module 4: Multi-Implementation Differential Oracle (P0).

Dispatches identical protocol wire probes to multiple real parsers/endpoints
and evaluates divergence across status codes, header parsing, body framing,
and socket connection states.
"""

import socket
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from engine.http_framing import HTTPFramingReader
from engine.taxonomy import AnomalyCategory, ImplementationAnomaly


@dataclass
class TargetEndpoint:
    name: str
    host: str
    port: int
    timeout: float = 3.0


@dataclass
class TargetResponse:
    target_name: str
    status_code: int
    headers: Dict[str, str]
    raw_response: bytes
    latency: float
    socket_state: str  # 'OK', 'TIMEOUT', 'CONNECTION_CLOSED', 'CONNECTION_REFUSED'


class MultiImplementationDifferentialOracle:
    """
    Executes differential probes across multiple server implementations to detect
    parser divergence without requiring a golden reference model.
    """

    def __init__(self, targets: Optional[List[TargetEndpoint]] = None):
        self.targets = targets or [
            TargetEndpoint(name="AgentOctopus", host="127.0.0.1", port=5006),
            TargetEndpoint(name="TestLabServer", host="127.0.0.1", port=8888),
        ]

    def add_target(self, target: TargetEndpoint) -> None:
        self.targets.append(target)

    def dispatch_single_target(self, target: TargetEndpoint, raw_probe: bytes) -> TargetResponse:
        """Sends raw bytes to a single target and records response telemetry."""
        start_time = time.time()
        sock = None
        try:
            sock = socket.create_connection((target.host, target.port), timeout=target.timeout)
            sock.sendall(raw_probe)

            framed = HTTPFramingReader.read_response(sock, timeout=target.timeout)
            response_data = framed.raw_response
            latency = time.time() - start_time
            if not response_data:
                return TargetResponse(
                    target_name=target.name,
                    status_code=0,
                    headers={},
                    raw_response=b"",
                    latency=latency,
                    socket_state="CONNECTION_CLOSED",
                )

            status_code = framed.status_code
            headers = framed.headers
            return TargetResponse(
                target_name=target.name,
                status_code=status_code,
                headers=headers,
                raw_response=response_data,
                latency=latency,
                socket_state="OK",
            )

        except socket.timeout:
            return TargetResponse(
                target_name=target.name,
                status_code=408,
                headers={},
                raw_response=b"",
                latency=time.time() - start_time,
                socket_state="TIMEOUT",
            )
        except ConnectionRefusedError:
            return TargetResponse(
                target_name=target.name,
                status_code=0,
                headers={},
                raw_response=b"",
                latency=time.time() - start_time,
                socket_state="CONNECTION_REFUSED",
            )
        except Exception as e:
            return TargetResponse(
                target_name=target.name,
                status_code=500,
                headers={},
                raw_response=str(e).encode(),
                latency=time.time() - start_time,
                socket_state="ERROR",
            )
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def evaluate_divergence(
        self, raw_probe: bytes, rule_id: Optional[str] = None
    ) -> Tuple[bool, Optional[ImplementationAnomaly], Dict[str, Any]]:
        """
        Sends the probe to all targets and determines if any two parsers diverge.
        Returns: (has_divergence, optional_anomaly_object, telemetry_matrix)
        """
        responses: Dict[str, TargetResponse] = {}
        for target in self.targets:
            responses[target.name] = self.dispatch_single_target(target, raw_probe)

        # Filter out targets that were unreachable/refused
        active_responses = {k: v for k, v in responses.items() if v.socket_state != "CONNECTION_REFUSED"}

        matrix = {
            name: {
                "status": resp.status_code,
                "socket_state": resp.socket_state,
                "latency": round(resp.latency, 4),
                "bytes_len": len(resp.raw_response),
            }
            for name, resp in responses.items()
        }

        if len(active_responses) < 2:
            return False, None, matrix

        # Assess divergence criteria:
        # 1. Distinct status codes (e.g. 200 OK vs 400 Bad Request)
        status_codes = {resp.status_code for resp in active_responses.values() if resp.status_code != 0}
        # 2. Distinct socket states (e.g. OK vs TIMEOUT)
        socket_states = {resp.socket_state for resp in active_responses.values()}

        is_divergent = len(status_codes) > 1 or len(socket_states) > 1

        if is_divergent:
            primary_name = list(active_responses.keys())[0]
            primary_resp = active_responses[primary_name]

            anomaly = ImplementationAnomaly(
                anomaly_id=f"ANOM-DIFF-{int(time.time() * 1000)}",
                target_engine=f"DifferentialMatrix({','.join(active_responses.keys())})",
                category=AnomalyCategory.PARSER_DIVERGENCE,
                observed_behavior=f"Divergence detected across parsers: {status_codes}, states: {socket_states}",
                expected_behavior="Consistently identical specification handling across all implementations.",
                raw_probe=raw_probe,
                raw_response=primary_resp.raw_response,
                triggering_rule_id=rule_id,
                divergence_matrix=matrix,
            )
            return True, anomaly, matrix

        return False, None, matrix

    def _parse_http_response(self, data: bytes) -> Tuple[int, Dict[str, str]]:
        """Extracts status code and headers from raw bytes."""
        try:
            head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
            lines = head.split("\r\n")
            if not lines:
                return 0, {}

            # Status line: HTTP/1.1 200 OK
            status_parts = lines[0].split(" ", 2)
            status_code = int(status_parts[1]) if len(status_parts) > 1 and status_parts[1].isdigit() else 200

            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            return status_code, headers
        except Exception:
            return 200, {}
