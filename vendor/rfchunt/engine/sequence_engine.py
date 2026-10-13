"""
Module 5: Stateful Protocol Sequence Engine (P0).

Evaluates multi-request and multi-connection state machine lifecycles to detect
queue desynchronization, response queue poisoning, and pipelined byte leakage
over persistent TCP connections.
"""

import random
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from engine.http_framing import HTTPFramingReader
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
        self, host: str, port: int, candidate_probe: bytes, rule_id: Optional[str] = None, use_tls: bool = False
    ) -> SequenceExecutionReport:
        """
        Executes a 3-step sequence on a SINGLE persistent TCP connection:
        1. Baseline request -> ensure connection is clean, open, and response body completely consumed.
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
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            # Step 1: Baseline Request
            start_t = time.time()
            baseline_req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n".encode()
            sock.sendall(baseline_req)
            framed1 = HTTPFramingReader.read_response(sock, timeout=self.default_timeout, request_method="GET")
            resp1 = framed1.raw_response
            status1 = framed1.status_code
            latency1 = time.time() - start_t

            report.steps.append(
                SequenceStepResult(
                    step_name="Step 1: Baseline",
                    sent_bytes=baseline_req,
                    received_bytes=resp1,
                    status_code=status1,
                    latency=latency1,
                    socket_error=framed1.error,
                )
            )

            # Invariant: Baseline response must be fully consumed and valid
            if not framed1.is_complete:
                report.has_desynchronization = False
                report.has_pipeline_leak = False
                report.details = f"Baseline response incomplete or timed out: {framed1.error or 'framing incomplete'}"
                return report

            if framed1.is_connection_closed:
                report.has_desynchronization = False
                report.has_pipeline_leak = False
                report.details = "Baseline response closed connection (Connection: close or EOF); persistent pipelining not supported."
                return report

            # Step 2: Send Candidate Probe
            start_t = time.time()
            sock.sendall(candidate_probe)
            framed2 = HTTPFramingReader.read_response(
                sock, timeout=self.default_timeout, initial_bytes=framed1.unconsumed_bytes
            )
            resp2 = framed2.raw_response
            status2 = framed2.status_code
            latency2 = time.time() - start_t

            report.steps.append(
                SequenceStepResult(
                    step_name="Step 2: Candidate Probe",
                    sent_bytes=candidate_probe,
                    received_bytes=resp2,
                    status_code=status2,
                    latency=latency2,
                    socket_error=framed2.error,
                )
            )

            # Check if Step 2 received leftover baseline HTML bytes (scanner artifact guard)
            if framed1.body and resp2 and (resp2 in framed1.body or framed1.body.startswith(resp2[:100])):
                report.has_desynchronization = False
                report.has_pipeline_leak = False
                report.details = "Scanner Artifact: Residual baseline response bytes detected on socket; not a pipeline leak."
                return report

            # Check if server closed connection following candidate probe (RFC 9112 Section 9.3 client error closure)
            server_closed_after_probe = framed2.is_connection_closed or status2 in (400, 431, 500, 501, 505)

            # Step 3: Canary Request
            if server_closed_after_probe:
                # Connection was cleanly closed by the server due to malformed probe rejection.
                # Do not treat standard error connection teardown as a pipeline leak!
                report.steps.append(
                    SequenceStepResult(
                        step_name="Step 3: Canary Check",
                        sent_bytes=canary_request,
                        received_bytes=b"",
                        status_code=0,
                        latency=0.0,
                        socket_error="Connection closed by server after candidate probe",
                    )
                )
                report.has_desynchronization = False
                report.has_pipeline_leak = False
                report.details = f"Connection closed by server after candidate probe ({status2} rejection); expected HTTP error behavior, not a pipeline leak."
                return report

            start_t = time.time()
            sock.sendall(canary_request)
            framed3 = HTTPFramingReader.read_response(
                sock, timeout=self.default_timeout, initial_bytes=framed2.unconsumed_bytes
            )
            resp3 = framed3.raw_response
            status3 = framed3.status_code
            latency3 = time.time() - start_t

            report.steps.append(
                SequenceStepResult(
                    step_name="Step 3: Canary Check",
                    sent_bytes=canary_request,
                    received_bytes=resp3,
                    status_code=status3,
                    latency=latency3,
                    socket_error=framed3.error,
                )
            )

            # Analyze sequence anomalies
            canary_bytes_lower = resp3.lower()
            if canary_token.lower().encode() in canary_bytes_lower and (b"404" in resp3 or status3 == 404):
                # Normal: server processed canary route cleanly
                report.has_desynchronization = False
                report.has_pipeline_leak = False
                report.details = "Normal: Canary request routed cleanly without boundary leakage."
            elif b"400 bad request" in resp3.lower() and status1 == 200:
                # Check if probe was an un-framed client body (RFC 9112 Section 6.1 framing omission)
                probe_lower = candidate_probe.lower()
                has_cl = b"content-length:" in probe_lower or b"content-length :" in probe_lower
                has_te = b"transfer-encoding:" in probe_lower or b"transfer-encoding :" in probe_lower
                has_body = False
                if b"\r\n\r\n" in candidate_probe:
                    _, body_part = candidate_probe.split(b"\r\n\r\n", 1)
                    has_body = len(body_part.strip()) > 0

                if has_body and not has_cl and not has_te:
                    # Client sent un-framed body without Content-Length or Transfer-Encoding.
                    # Under RFC 9112 Section 6.1, message body length is zero.
                    # Trailing bytes remained on socket; server 400 rejection is conforming behavior, not a vulnerability!
                    report.has_pipeline_leak = False
                    report.has_desynchronization = False
                    report.details = (
                        "Client Framing Omission: Candidate probe sent un-framed body without Content-Length "
                        "or Transfer-Encoding; server treated body length as 0 (RFC 9112 Section 6.1) and rejected "
                        "trailing socket bytes with 400 Bad Request. Conforming HTTP behavior, not a pipeline leak."
                    )
                else:
                    report.has_pipeline_leak = True
                    report.has_desynchronization = True
                    report.details = "Pipeline Leak: Residual probe bytes corrupted the subsequent canary request."
            elif b"terminator_marker" in resp3.lower() or b"x-smuggle" in resp3.lower():
                report.has_desynchronization = True
                report.details = "Queue Desynchronization: Candidate probe response or body bled directly into canary stream."
            elif resp3 == b"" and len(resp2) > 0:
                # Normal connection drop if status was an error
                if status2 in (400, 431, 500, 501, 505):
                    report.has_pipeline_leak = False
                    report.has_desynchronization = False
                    report.details = f"Connection closed by server after candidate probe ({status2}); expected HTTP error behavior."
                else:
                    report.has_pipeline_leak = False
                    report.details = "Connection Dropped: Candidate probe caused connection termination before canary."
            else:
                report.has_desynchronization = False
                report.has_pipeline_leak = False
                report.details = "Normal: No stateful boundary contamination observed."

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
        """Reads a fully framed HTTP response from the socket per RFC 9112."""
        framed = HTTPFramingReader.read_response(sock, timeout=timeout)
        return framed.raw_response

    def _extract_status_code(self, data: bytes) -> int:
        return HTTPFramingReader._parse_headers(data)[0]

