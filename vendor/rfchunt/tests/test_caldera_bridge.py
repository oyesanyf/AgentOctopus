"""
Unit and integration tests for Caldera Bridge Engine and Terminator Runner Payload:
Verifies non-MITRE taxonomy generation, ability synthesis, adversary profiles,
plugin directory export, and socket runner wire execution.
"""

import os
import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest
import yaml

from engine.caldera_bridge import CalderaBridge
from engine.dream_world_model import ProtocolWorldModel
from engine.taxonomy import ImpactClass, ReproducibleVulnerability
from payloads.terminator_runner import WireSocketClient, run_kettle_ab_evaluation, run_single_replay


def test_caldera_ability_generation_non_mitre():
    """Verifies that Caldera abilities are generated with RFC taxonomy and NOT generic MITRE ATT&CK IDs."""
    bridge = CalderaBridge()
    finding = {
        "vuln_id": "VULN-REPRO-9112-TEST-01",
        "impact": "QUEUE_POISONING",
        "minimized_probe": (
            "POST / HTTP/1.1\r\n"
            "Host: target.local\r\n"
            "Content-Length: 6\r\n\r\n"
            "12345"
        ),
        "rationale": "RFC 9112 §6.1 dangling byte payload",
        "rfc_fragment": "RFC 9112 states that the server must wait for declared length.",
    }

    ability = bridge.generate_ability(finding)

    # 1. Non-MITRE tactic verification
    assert ability["tactic"] == "queue-poisoning"

    # 2. Non-MITRE technique verification
    assert ability["technique"]["attack_id"] == "RFC-9112-DESYNC"
    assert "T1190" not in ability["technique"]["attack_id"]
    assert "HTTP/1.1" in ability["technique"]["name"]

    # 3. Payload and command verification
    platforms = ability["platforms"]
    assert "linux" in platforms and "windows" in platforms and "darwin" in platforms
    assert "terminator_runner.py" in platforms["linux"]["sh"]["payloads"]
    assert "--payload-hex" in platforms["linux"]["sh"]["command"]
    assert "python terminator_runner.py" in platforms["windows"]["psh"]["command"]

    # 4. Probe hex fidelity
    expected_hex = finding["minimized_probe"].encode("latin-1").hex()
    assert expected_hex in platforms["linux"]["sh"]["command"]


def test_caldera_adversary_generation():
    """Verifies that Caldera Adversaries are synthesized with atomic ordering."""
    bridge = CalderaBridge()
    abilities = [
        {"id": "terminator-ab-1", "name": "Probe 1"},
        {"id": "terminator-ab-2", "name": "Probe 2"},
    ]
    adversary = bridge.generate_adversary(
        abilities=abilities,
        adversary_id="adv-test-rfc-audit",
        name="RFC 9112 Replay Profile",
    )

    assert adversary["id"] == "adv-test-rfc-audit"
    assert adversary["name"] == "RFC 9112 Replay Profile"
    assert adversary["atomic_ordering"] == ["terminator-ab-1", "terminator-ab-2"]
    assert "non-mitre" in adversary["tags"]


def test_caldera_plugin_export_filesystem():
    """Verifies complete Caldera plugin directory creation and YAML validity."""
    temp_dir = tempfile.mkdtemp(prefix="caldera_test_")
    try:
        bridge = CalderaBridge()
        test_findings = [
            {
                "vuln_id": "RFC-9112-POISON",
                "impact": "QUEUE_POISONING",
                "minimized_probe": "POST / HTTP/1.1\r\nHost: target.local\r\n\r\n",
                "rationale": "RFC 9112 queue test",
            },
            {
                "vuln_id": "RFC-9113-MULTIPLEX-BUG",
                "impact": "PARSER_DIVERGENCE",
                "minimized_probe": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n",
                "rationale": "RFC 9113 stream test",
            },
        ]

        result = bridge.export_plugin(output_dir=temp_dir, findings=test_findings)
        assert result["status"] == "SUCCESS"
        assert result["abilities_count"] == 2

        plugin_path = Path(result["plugin_path"])
        assert (plugin_path / "hook.py").exists()
        assert (plugin_path / "app" / "terminator_svc.py").exists()
        assert (plugin_path / "payloads" / "terminator_runner.py").exists()

        # Check abilities
        ability_files = list((plugin_path / "data" / "abilities").rglob("*.yml"))
        assert len(ability_files) == 2
        for af in ability_files:
            with open(af, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                assert isinstance(loaded, list)
                assert len(loaded) > 0
                assert "technique" in loaded[0]

        # Check adversary
        adv_files = list((plugin_path / "data" / "adversaries").glob("*.yml"))
        assert len(adv_files) == 1
        with open(adv_files[0], "r", encoding="utf-8") as f:
            adv_loaded = yaml.safe_load(f)
            assert "atomic_ordering" in adv_loaded
            assert len(adv_loaded["atomic_ordering"]) == 2

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_terminator_runner_wire_execution_real_socket():
    """
    Verifies that the standalone terminator_runner accurately communicates over
    a real TCP socket and correctly parses HTTP framing without false residuals.
    """
    # Start a real temporary HTTP socket server
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(5)
    host, port = server_sock.getsockname()

    running = True

    def handle_server():
        while running:
            try:
                server_sock.settimeout(0.5)
                conn, _ = server_sock.accept()
            except (socket.timeout, OSError):
                continue

            try:
                conn.settimeout(2.0)
                req_data = bytearray()
                while b"\r\n\r\n" not in req_data:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    req_data.extend(chunk)

                # Return a framed HTTP/1.1 200 OK response with exact Content-Length
                body = b"<html><body>OK</body></html>"
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/html\r\n"
                    b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
                conn.sendall(resp)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    srv_thread = threading.Thread(target=handle_server, daemon=True)
    srv_thread.start()

    try:
        # Run replay test
        probe = b"GET /test HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        res = run_single_replay(host=host, port=port, probe_bytes=probe, timeout=2.0)

        assert res["status"] == "SUCCESS"
        assert "200 OK" in str(res["response_status"])
        assert res["body_len"] == 28
        assert res["residual_leak"] == 0  # Crucial: NO false pipeline leak reported!
    finally:
        running = False
        server_sock.close()
        srv_thread.join(timeout=1.0)


def test_caldera_operation_ingestion_into_world_model():
    """Verifies that Caldera operation reports update the Dream-RSI World Model."""
    world_model = ProtocolWorldModel(target_host="10.0.0.5", target_port=8080)
    bridge = CalderaBridge()

    probe_bytes = b"POST / HTTP/1.1\r\nHost: 10.0.0.5\r\nContent-Length: 6\r\n\r\n12345"
    simulated_operation = {
        "id": "op-caldera-fleet-run-42",
        "chain": [
            {
                "ability_id": "terminator-rfc9112-test",
                "command": f"python terminator_runner.py --payload-hex {probe_bytes.hex()}",
                "status": 0,
                "output": (
                    '{"status": "CONFIRMED_VULNERABILITY", "desync_confirmed": true, '
                    '"baseline_status": "HTTP/1.1 200 OK", "canary_status": "HTTP/1.1 400 Bad Request", '
                    '"residual_leak": 0}'
                ),
            }
        ]
    }

    summary = bridge.ingest_caldera_operation(simulated_operation, world_model=world_model)

    assert summary["operation_id"] == "op-caldera-fleet-run-42"
    assert summary["vulnerabilities_confirmed"] == 1
    assert summary["facts_ingested"] == 1

    # Verify that the world model has ingested this probe
    probe_hash = world_model._hash_probe(probe_bytes)
    assert probe_hash in world_model.exact_cache
    recorded = world_model.exact_cache[probe_hash]
    assert recorded.is_vulnerability is True
    assert "Caldera Operation" in recorded.details
