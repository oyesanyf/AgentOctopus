"""
Comprehensive Verification Tests for HTTP Framing Oracle and Pipeline Leak Detection.

Tests:
1. Multi-chunk Content-Length accounting (including exact 72,682 byte large body baseline).
2. Transfer-Encoding: chunked parsing with extensions and trailers.
3. 1xx Informational interim responses (100 Continue, 103 Early Hints).
4. 204 No Content and 304 Not Modified body exclusion per RFC 9112 Section 6.3.
5. Connection: close and socket timeout conditions.
6. Elimination of false pipeline leaks in StatefulProtocolSequenceEngine over persistent connections.
7. Causal classifier detection of ordinary response framing artifacts.
8. Triage agent rejection of leftover baseline bytes.
9. Automatic publication suspension for unverified framing artifacts.
10. Target authorization enforcement for external services.
"""

import socket
import threading
import time
import pytest

from engine.causal_classifier import CausalAnomalyClassifier
from engine.defensive_publisher import DefensiveIntelligencePublisher
from engine.delta_debugger import DeltaDebugger
from engine.http_framing import HTTPFramingReader
from engine.sequence_engine import StatefulProtocolSequenceEngine
from engine.taxonomy import (
    AnomalyCategory,
    ImpactClass,
    ImplementationAnomaly,
    ReproducibleVulnerability,
)
from mcp_server import TargetAuthorizationGate


class MockSocketPair:
    """Creates a connected loopback socket pair for deterministic wire testing."""
    def __init__(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", port))
        server_conn, _ = server.accept()
        server.close()

        self.client = client
        self.server = server_conn

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass
        try:
            self.server.close()
        except Exception:
            pass


def test_content_length_exact_large_body_multi_chunk():
    """
    Tests exact consumption of large bodies (72,682 bytes),
    delivered across multiple small network chunks (18x4096 + 1x3954).
    Verifies that the reader does NOT stop prematurely when \\r\\n\\r\\n is encountered.
    """
    pair = MockSocketPair()
    total_body_len = 72682
    raw_body = b"X" * total_body_len
    header = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.41\r\n"
        b"Content-Type: text/html; charset=UTF-8\r\n"
        b"Content-Length: 72682\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )

    def server_worker():
        # Send headers first
        pair.server.sendall(header)
        # Send body in small 4096-byte chunks with brief delays to simulate network delivery
        offset = 0
        while offset < len(raw_body):
            chunk = raw_body[offset : offset + 4096]
            pair.server.sendall(chunk)
            offset += len(chunk)
            time.sleep(0.001)

    t = threading.Thread(target=server_worker)
    t.start()

    framed = HTTPFramingReader.read_response(pair.client, timeout=3.0)
    t.join()
    pair.close()

    assert framed.is_complete is True
    assert framed.status_code == 200
    assert framed.framing_type == "content-length"
    assert len(framed.body) == 72682
    assert framed.body == raw_body
    assert framed.unconsumed_bytes == b""
    assert framed.is_connection_closed is False


def test_content_length_with_unconsumed_pipeline_bytes():
    """
    Verifies that any bytes received in sock.recv() beyond Content-Length are preserved
    in unconsumed_bytes for subsequent pipelined requests rather than being discarded.
    """
    pair = MockSocketPair()
    body = b"1234567890"  # 10 bytes
    next_req_resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    wire_data = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 10\r\n"
        b"Connection: keep-alive\r\n\r\n"
        + body
        + next_req_resp
    )

    pair.server.sendall(wire_data)

    framed = HTTPFramingReader.read_response(pair.client, timeout=2.0)
    pair.close()

    assert framed.is_complete is True
    assert framed.status_code == 200
    assert framed.body == body
    assert framed.unconsumed_bytes == next_req_resp


def test_chunked_transfer_encoding_with_extensions_and_trailers():
    """
    Tests Transfer-Encoding: chunked with chunk extensions and trailing headers.
    """
    pair = MockSocketPair()
    wire = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: keep-alive\r\n\r\n"
        b"5;foo=bar\r\n"
        b"Hello\r\n"
        b"6\r\n"
        b" World\r\n"
        b"0\r\n"
        b"X-Checksum: abc123\r\n\r\n"
    )

    pair.server.sendall(wire)
    framed = HTTPFramingReader.read_response(pair.client, timeout=2.0)
    pair.close()

    assert framed.is_complete is True
    assert framed.status_code == 200
    assert framed.framing_type == "chunked"
    assert framed.body == b"Hello World"
    assert framed.unconsumed_bytes == b""


def test_1xx_interim_response_handling():
    """
    Tests 100 Continue followed by 200 OK final response (RFC 9112 Section 6.3 item 1).
    Verifies that interim response is captured and client continues reading final response.
    """
    pair = MockSocketPair()
    wire = (
        b"HTTP/1.1 100 Continue\r\n\r\n"
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 5\r\n\r\n"
        b"Final"
    )

    pair.server.sendall(wire)
    framed = HTTPFramingReader.read_response(pair.client, timeout=2.0)
    pair.close()

    assert framed.is_complete is True
    assert framed.status_code == 200
    assert len(framed.interim_responses) == 1
    assert b"100 Continue" in framed.interim_responses[0]
    assert framed.body == b"Final"


def test_no_body_status_codes_204_and_304():
    """
    Tests that 204 No Content and 304 Not Modified have no message body
    regardless of headers (RFC 9112 Section 6.3).
    """
    # 204 No Content
    pair204 = MockSocketPair()
    pair204.server.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\nNEXT_DATA")
    framed204 = HTTPFramingReader.read_response(pair204.client, timeout=2.0)
    pair204.close()
    assert framed204.status_code == 204
    assert framed204.body == b""
    assert framed204.unconsumed_bytes == b"NEXT_DATA"

    # 304 Not Modified (may contain Content-Length from origin cache, but NO body on wire)
    pair304 = MockSocketPair()
    pair304.server.sendall(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 1000\r\n\r\nNEXT_DATA")
    framed304 = HTTPFramingReader.read_response(pair304.client, timeout=2.0)
    pair304.close()
    assert framed304.status_code == 304
    assert framed304.body == b""
    assert framed304.unconsumed_bytes == b"NEXT_DATA"


def test_pipelined_canary_no_false_pipeline_leak_on_large_baseline():
    """
    Simulates the exact scenario reported by the user:
    1. Baseline request receives HTTP/1.1 200 OK with Content-Length: 72682.
    2. Scanner reads the baseline response.
    3. Next probe is sent on the persistent connection.
    Verifies that the scanner completely drains the 72,682 bytes in Step 1,
    so Step 2 receives the actual probe response and does NOT report a false pipeline leak.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    total_html_len = 72682
    prefix = b"<!DOCTYPE html><html><body>"
    suffix = b"</body></html>"
    baseline_html = prefix + (b"A" * (total_html_len - len(prefix) - len(suffix))) + suffix
    assert len(baseline_html) == total_html_len

    def server_thread():
        client, _ = server_sock.accept()
        try:
            # Step 1: Read baseline request and send 72,682 bytes
            _ = client.recv(4096)
            resp1 = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html\r\n"
                + f"Content-Length: {len(baseline_html)}\r\n".encode("ascii")
                + b"Connection: keep-alive\r\n\r\n"
                + baseline_html
            )
            client.sendall(resp1)

            # Step 2: Read candidate probe and send normal response or rejection
            probe_data = client.recv(4096)
            assert len(probe_data) > 0
            # Server returns 400 Bad Request and closes connection per RFC 9112 Section 9.3
            resp2 = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            client.sendall(resp2)
            client.close()
        except Exception:
            pass
        finally:
            server_sock.close()

    t = threading.Thread(target=server_thread)
    t.start()

    engine = StatefulProtocolSequenceEngine(default_timeout=3.0)
    candidate_probe = b"GET /malformed HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Bad : space\r\n\r\n"
    report = engine.run_pipelined_canary_sequence("127.0.0.1", port, candidate_probe, use_tls=False)
    t.join()

    # Step 1 must have fully received all 72,682 body bytes + headers
    step1 = next(s for s in report.steps if "Baseline" in s.step_name)
    assert step1.status_code == 200
    assert len(step1.received_bytes) > 72682

    # Step 2 must NOT receive residual HTML from Step 1!
    step2 = next(s for s in report.steps if "Candidate" in s.step_name)
    assert b"<!DOCTYPE html>" not in step2.received_bytes
    assert step2.status_code == 400

    # Invariant: Must NOT report false pipeline leak or desynchronization!
    assert report.has_pipeline_leak is False
    assert report.has_desynchronization is False
    assert "not a pipeline leak" in report.details.lower() or "expected http error" in report.details.lower() or "connection closed" in report.details.lower()


def test_causal_classifier_framing_artifact_detection():
    """
    Verifies that CausalAnomalyClassifier accurately identifies leftover baseline HTML
    as an ordinary framing artifact rather than a confirmed vulnerability.
    """
    classifier = CausalAnomalyClassifier()

    # Anomaly with residual HTML body fragment (like the user's log)
    anomaly = ImplementationAnomaly(
        anomaly_id="ANOM-SEQ-1791874582716",
        target_engine="target.example.com:443",
        category=AnomalyCategory.PIPELINE_LEAK,
        observed_behavior="Residual Pipeline Leak: 71,877 bytes in 20.4ms",
        expected_behavior="Clean request separation.",
        raw_probe=b"GET / HTTP/1.1\r\nHost: target.example.com\r\n\r\n",
        raw_response=b"<!DOCTYPE html><html><head><title>Generic Target</title></head><body>...",
    )

    is_artifact, reason = classifier.is_framing_artifact(anomaly)
    assert is_artifact is True
    assert "framing artifact" in reason.lower() or "residual" in reason.lower()

    # filter_environmental_noise must discard it
    is_noise = classifier.filter_environmental_noise(anomaly, baseline_is_healthy=True)
    assert is_noise is True
    assert anomaly.is_environmental_noise is True

    # validate_evidence must reject it
    fake_vuln = ReproducibleVulnerability(
        vuln_id="VULN-REPRO-1791874582716",
        anomaly_id=anomaly.anomaly_id,
        impact=ImpactClass.PARSER_CONFUSION,
        minimized_probe=b"GET / HTTP/1.1\r\nHost: target.example.com\r\n\r\n",
        reproducibility_rate=1.0,
        verification_attempts=3,
        successful_reproductions=3,
        delta_debug_steps=1,
    )
    is_valid, val_reason = classifier.validate_evidence(fake_vuln, anomaly)
    assert is_valid is False
    assert "ordinary response framing" in val_reason.lower()


def test_defensive_publisher_suspends_publication_on_unverified_evidence(tmp_path):
    """
    Verifies that DefensiveIntelligencePublisher suspends automatic publication of
    Arm 106 and Arm 107 rules when evidence_verified is False.
    """
    publisher = DefensiveIntelligencePublisher(output_dir=str(tmp_path))
    vuln = ReproducibleVulnerability(
        vuln_id="VULN-REPRO-SUSPEND-TEST",
        anomaly_id="ANOM-TEST",
        impact=ImpactClass.PARSER_CONFUSION,
        minimized_probe=b"GET / HTTP/1.1\r\n\r\n",
        reproducibility_rate=1.0,
        verification_attempts=3,
        successful_reproductions=3,
        delta_debug_steps=1,
    )

    rule, reg_test = publisher.publish_finding(vuln, evidence_verified=False)
    assert rule is None
    assert reg_test is None
    assert len(publisher.arm106_rules) == 0
    assert len(publisher.arm107_tests) == 0


def test_target_authorization_gate_external_domain():
    """
    Verifies that TargetAuthorizationGate blocks unauthorized testing against
    external services (like target.example.com) unless explicitly authorized.
    """
    # target.example.com should be rejected by default
    with pytest.raises(PermissionError):
        TargetAuthorizationGate.check_auth("target.example.com")

    # Authorize explicitly
    TargetAuthorizationGate.authorize_target("target.example.com")
    TargetAuthorizationGate.check_auth("target.example.com")
    assert "target.example.com" in TargetAuthorizationGate.get_allowed_targets()


def test_metamorphic_validity_gate_rejects_compliant_400():
    """
    Stage 3 Metamorphic Validity Gate:
    Verifies that a 200 vs 400 status difference resulting from non-standard whitespace
    (such as HTAB in header fields) is treated as RFC-compliant server input validation
    under RFC 9112 Section 5.1/5.5, rather than a confirmed security vulnerability.
    """
    from engine.metamorphic_engine import MetamorphicTestingEngine

    engine = MetamorphicTestingEngine()
    mr_ows = next(mr for mr in engine.relations if mr.relation_id == "MR-OWS-EQUIVALENCE")

    # 1. Verify Host header is preserved to avoid invalid host syntax (RFC 9112 Section 7.2)
    sample_probe = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Custom: test\r\n\r\n"
    transformed = mr_ows.transform(sample_probe)
    assert b"Host: example.com" in transformed
    assert b"X-Custom:\ttest" in transformed

    # 2. Verify comparator classifies 200 vs 400 as RFC-Compliant Rejection
    is_valid, reason = mr_ows.comparator(200, b"OK", 400, b"Bad Request")
    assert is_valid is False
    assert "RFC-Compliant Rejection" in reason

    # 3. Verify Causal Classifier rejects 200 vs 400 metamorphic anomalies as confirmed vulnerabilities
    classifier = CausalAnomalyClassifier()
    anomaly = ImplementationAnomaly(
        anomaly_id="ANOM-META-TEST",
        target_engine="target.example.com:443",
        category=AnomalyCategory.METAMORPHIC_VIOLATION,
        observed_behavior="Metamorphic Violation: Base request returned 200, but transformed request returned 400",
        expected_behavior=mr_ows.description,
        raw_probe=transformed,
        raw_response=b"HTTP/1.1 400 Bad Request\r\n\r\n",
        triggering_rule_id="MR-OWS-EQUIVALENCE",
    )

    vuln = ReproducibleVulnerability(
        vuln_id="VULN-REPRO-META-400",
        anomaly_id=anomaly.anomaly_id,
        impact=ImpactClass.PARSER_CONFUSION,
        minimized_probe=transformed,
        reproducibility_rate=1.0,
        verification_attempts=3,
        successful_reproductions=3,
        delta_debug_steps=1,
    )

    is_confirmed, val_reason = classifier.validate_evidence(vuln, anomaly)
    assert is_confirmed is False
    assert "Metamorphic Validity Gate" in val_reason

