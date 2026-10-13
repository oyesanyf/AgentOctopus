"""
Unit and integration tests for Decoupled Authorization, Rate Limiting,
Supervisor Approvals, Address Sanitization, and Database Integrity.
"""

import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path
import pytest

from mcp_server import TargetAuthorizationGate, TerminatorMCPServer
from database import Database


def test_target_rejects_inaddr_any():
    """Verifies that 0.0.0.0 and :: are rejected as invalid scan destinations."""
    with pytest.raises(ValueError, match="invalid destination address"):
        TargetAuthorizationGate.check_target("0.0.0.0")

    with pytest.raises(ValueError, match="invalid destination address"):
        TargetAuthorizationGate.check_target("::")


def test_target_rejects_wildcard_bypass():
    """Verifies that wildcard strings cannot be authorized to bypass security checks."""
    with pytest.raises(ValueError, match="Wildcard authorization is disallowed"):
        TargetAuthorizationGate.authorize_target("*")

    with pytest.raises(ValueError, match="Wildcard authorization is disallowed"):
        TargetAuthorizationGate.authorize_target("all")


def test_target_enforces_whitelist():
    """Verifies that external targets not in the whitelist are rejected."""
    with pytest.raises(PermissionError, match="not in the authorized targets whitelist"):
        TargetAuthorizationGate.check_target("unauthorized-victim.example.com")


def test_payload_length_enforcement():
    """Verifies that payloads exceeding 64KB are rejected."""
    small_payload = 1024  # 1 KB
    TargetAuthorizationGate.check_payload(small_payload)  # Should not raise

    oversized_payload = 65 * 1024  # 65 KB (> 64 KB boundary)
    with pytest.raises(ValueError, match="exceeds maximum allowed boundary"):
        TargetAuthorizationGate.check_payload(oversized_payload)


def test_sliding_window_rate_limiter():
    """Verifies that exceeding the per-minute rate limit raises RuntimeError."""
    client_id = f"test_client_{time.time()}"
    # Fill up to limit
    for _ in range(TargetAuthorizationGate.RATE_LIMIT_PER_MINUTE):
        TargetAuthorizationGate.check_rate_limit(client_id)

    # Exceed limit
    with pytest.raises(RuntimeError, match="Rate limit exceeded"):
        TargetAuthorizationGate.check_rate_limit(client_id)


def test_supervisor_token_enforcement(monkeypatch):
    """Verifies that weaponization and heavy scans fail closed without supervisor token."""
    # When no token is configured in environment
    monkeypatch.delenv("RFCHUNT_SUPERVISOR_TOKEN", raising=False)
    with pytest.raises(PermissionError, match="RFCHUNT_SUPERVISOR_TOKEN is not configured"):
        TargetAuthorizationGate.check_supervisor_approval(None, "weaponization")

    # When token is configured, invalid token must be rejected
    monkeypatch.setenv("RFCHUNT_SUPERVISOR_TOKEN", "super-secret-token-12345")
    with pytest.raises(PermissionError, match="Invalid or missing supervisor approval token"):
        TargetAuthorizationGate.check_supervisor_approval("wrong-token", "weaponization")

    # Valid token succeeds
    TargetAuthorizationGate.check_supervisor_approval("super-secret-token-12345", "weaponization")


def test_mcp_error_sanitization(monkeypatch):
    """Verifies that MCP tools/call sanitizes internal errors and does not leak tracebacks."""
    server = TerminatorMCPServer(db_path=":memory:")

    # Call evaluate_probe with 0.0.0.0 -> expect sanitized ValueError code -32602
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "evaluate_probe",
            "arguments": {
                "raw_request": "GET / HTTP/1.1\r\nHost: 0.0.0.0\r\n\r\n",
                "target_host": "0.0.0.0",
            },
        },
    }
    resp = server.handle_request(req)
    assert "error" in resp
    assert resp["error"]["code"] == -32602
    assert "invalid destination address" in resp["error"]["message"].lower()

    # Call weaponization without supervisor token -> expect PermissionError code -32001
    monkeypatch.setenv("RFCHUNT_SUPERVISOR_TOKEN", "valid-token-xyz")
    weap_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "weaponize_dangling_byte",
            "arguments": {
                "base_trigger": "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\n\r\na",
                "target_host": "127.0.0.1",
                "supervisor_token": "invalid-token",
            },
        },
    }
    weap_resp = server.handle_request(weap_req)
    assert "error" in weap_resp
    assert weap_resp["error"]["code"] == -32001
    assert "supervisor approval token" in weap_resp["error"]["message"]


def test_database_defensive_intelligence_population():
    """Verifies that terminator.db contains populated defensive rules and regression tests."""
    db_path = Path(__file__).resolve().parent.parent / "terminator.db"
    assert db_path.exists(), f"Database not found at {db_path}"

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    rules_count = cur.execute("SELECT COUNT(*) FROM arm106_defensive_rules").fetchone()[0]
    tests_count = cur.execute("SELECT COUNT(*) FROM arm107_regression_tests").fetchone()[0]
    evals_count = cur.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0]
    vulns_count = cur.execute("SELECT COUNT(*) FROM reproducible_vulnerabilities").fetchone()[0]

    conn.close()

    assert vulns_count > 0, "Reproducible vulnerabilities must not be empty"
    assert rules_count == vulns_count, f"Arm 106 defensive rules ({rules_count}) must match vulns ({vulns_count})"
    assert tests_count == vulns_count, f"Arm 107 regression tests ({tests_count}) must match vulns ({vulns_count})"
    assert evals_count >= vulns_count, f"Evaluations ({evals_count}) must cover all vulns ({vulns_count})"
