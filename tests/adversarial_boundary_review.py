#!/usr/bin/env python3
"""
Adversarial Verification Suite for Agent Octopus Error Boundaries & Exception Robustness.
Tests:
  1. Automated Server Lifecycle Management (attaches or launches start.exe cleanly).
  2. Slowloris / Slow Header Dribbling Timeout (HTTP 408 REQUEST_TIMEOUT).
  3. Header Boundary Clamping (>64KB without delimiter -> HTTP 400 INVALID_REQUEST).
  4. Live HTTP 413 Payload Clamp (>10MB -> PAYLOAD_TOO_LARGE).
  5. Malformed JSON across all POST endpoints (HTTP 400 INVALID_JSON).
  6. Unhandled routes & API 404 structured payload format (HTTP 404 ENDPOINT_NOT_FOUND).
  7. Concurrent request bursts to test Mutex lock poisoning resilience.
  8. Down gateway / connection refusal resilience in Python harness.
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

# Ensure tests/ directory is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

BASE_URL = "http://127.0.0.1:5005"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5005


def check_structured_error(resp_body, expected_code=None):
    try:
        data = json.loads(resp_body)
    except Exception as e:
        return False, f"Response is not valid JSON: {resp_body} ({e})"
    if data.get("error") is not True:
        return False, f"Missing or false 'error' boolean in: {data}"
    if not data.get("code"):
        return False, f"Missing 'code' string in: {data}"
    if expected_code and data.get("code") != expected_code:
        return False, f"Expected code '{expected_code}', got '{data.get('code')}'"
    if not data.get("message"):
        return False, f"Missing 'message' in: {data}"
    if not data.get("timestamp"):
        return False, f"Missing 'timestamp' in: {data}"
    return True, f"Valid structured error: {data['code']} - {data['message']}"


def send_req(method, path, body=None, headers=None, timeout=5.0):
    import http.client
    import urllib.parse
    parsed = urllib.parse.urlsplit(f"{BASE_URL}{path}")
    req_headers = dict(headers) if headers else {}
    body_bytes = None
    if body is not None:
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
    try:
        conn = http.client.HTTPConnection(parsed.hostname or "127.0.0.1", parsed.port or 5005, timeout=timeout)
        target = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        conn.request(method, target, body=body_bytes, headers=req_headers)
        resp = conn.getresponse()
        status = resp.status
        resp_body = resp.read().decode("utf-8", errors="replace")
        conn.close()
        return status, resp_body
    except Exception as e:
        return None, str(e)


def ensure_server_running():
    """Verify backend start.exe is online; if not, launch it in background and wait for readiness."""
    global BASE_URL, SERVER_PORT
    root_dir = os.path.dirname(SCRIPT_DIR)
    active_port_file = os.path.join(root_dir, "logs", "active_port.txt")

    def _probe_active_port():
        global BASE_URL, SERVER_PORT
        candidates = []
        if os.path.exists(active_port_file):
            try:
                with open(active_port_file, "r", encoding="utf-8") as f:
                    p = f.read().strip()
                    if p.isdigit():
                        candidates.append(int(p))
            except Exception:
                pass
        for p in range(5005, 5026):
            if p not in candidates:
                candidates.append(p)
        for p in candidates:
            BASE_URL = f"http://127.0.0.1:{p}"
            SERVER_PORT = p
            status, _ = send_req("GET", "/api/status", timeout=0.6)
            if status == 200:
                return True
        BASE_URL = "http://127.0.0.1:5005"
        SERVER_PORT = 5005
        return False

    if _probe_active_port():
        print(f"[+] Detected existing live Agent Octopus server on {BASE_URL} (reusing)")
        return None

    start_exe = os.path.join(root_dir, "start.exe")
    if not os.path.exists(start_exe):
        candidate = os.path.join(root_dir, "target", "debug", "start.exe")
        if os.path.exists(candidate):
            start_exe = candidate
        else:
            candidate = os.path.join(root_dir, "target", "release", "start.exe")
            if os.path.exists(candidate):
                start_exe = candidate

    cmd = [start_exe] if os.path.exists(start_exe) else ["cargo", "run", "--bin", "start"]
    print(f"[*] Server not running. Spawning backend lifecycle: {cmd}...")
    env = os.environ.copy()
    env["OCTOPUS_NO_BROWSER"] = "1"
    env["HEADLESS"] = "1"

    proc = subprocess.Popen(
        cmd,
        cwd=root_dir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )

    deadline = time.time() + 15.0
    ready = False
    while time.time() < deadline:
        if proc.poll() is not None:
            out, err = proc.communicate(timeout=1.0)
            raise RuntimeError(
                f"Server process terminated unexpectedly with code {proc.returncode}.\n"
                f"STDOUT: {out.decode('utf-8', errors='replace')}\n"
                f"STDERR: {err.decode('utf-8', errors='replace')}"
            )
        if _probe_active_port():
            ready = True
            break
        time.sleep(0.3)

    if not ready:
        try:
            proc.terminate()
        except Exception:
            pass
        raise TimeoutError(f"Agent Octopus backend did not become healthy on {BASE_URL} within 15 seconds")

    print(f"[+] Agent Octopus backend initialized and healthy (PID: {proc.pid})")
    return proc


def probe_slowloris_timeout():
    """Verify that stalled header dribbling triggers HTTP 408 REQUEST_TIMEOUT structured response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8.0)
    try:
        s.connect((SERVER_HOST, SERVER_PORT))
        # Send partial headers without closing delimiter
        partial = b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Incomplete: true\r\n"
        s.sendall(partial)
        # Server header chunk timeout is 5.0 seconds. Wait 5.3s then read response.
        time.sleep(5.3)
        raw_resp = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw_resp += chunk
                if b"\r\n\r\n" in raw_resp and b"}" in raw_resp:
                    break
            except socket.timeout:
                break
        resp_text = raw_resp.decode("utf-8", errors="replace")
        if "408 Request Timeout" not in resp_text:
            return False, f"Expected HTTP 408 Request Timeout, got: {resp_text[:200]}"
        body = resp_text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp_text else ""
        return check_structured_error(body, "REQUEST_TIMEOUT")
    except Exception as e:
        return False, f"Slowloris probe socket error: {e}"
    finally:
        s.close()


def probe_oversized_headers():
    """Verify that unbounded headers exceeding 64KB trigger HTTP 400 INVALID_REQUEST."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect((SERVER_HOST, SERVER_PORT))
        # Send 65KB of header noise without \r\n\r\n
        junk = b"GET / HTTP/1.1\r\n" + (b"X-Junk: " + b"A" * 1024 + b"\r\n") * 65
        s.sendall(junk)
        try:
            s.shutdown(socket.SHUT_WR)
        except Exception:
            pass
        raw_resp = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw_resp += chunk
                if b"\r\n\r\n" in raw_resp:
                    break
            except socket.timeout:
                break
        resp_text = raw_resp.decode("utf-8", errors="replace")
        if "400 Bad Request" not in resp_text:
            return False, f"Expected HTTP 400 Bad Request on oversized headers, got: {resp_text[:200]}"
        body = resp_text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp_text else ""
        return check_structured_error(body, "INVALID_REQUEST")
    except Exception as e:
        return False, f"Oversized header socket error: {e}"
    finally:
        s.close()


def main():
    print("=" * 70)
    print("Agent Octopus Adversarial Boundary Deep Verification")
    print("=" * 70)
    failures = []
    server_proc = None

    try:
        # 1. Manage server lifecycle (reuse existing or auto-launch background process)
        server_proc = ensure_server_running()

        # 2. Check live server online
        status, body = send_req("GET", "/api/status")
        if status != 200:
            failures.append(f"/api/status returned {status}: {body}")
            print(f"[-] /api/status check FAILED: {status}")
        else:
            print("[+] Live server online: 200 OK")

        # 3. Slowloris / Slow Header Dribbling Timeout (HTTP 408 REQUEST_TIMEOUT)
        print("[*] Probing Slowloris / slow header dribbling timeout (5.0s boundary)...")
        ok, msg = probe_slowloris_timeout()
        if not ok:
            failures.append(f"Slowloris probe failed: {msg}")
            print(f"[-] Slowloris probe FAILED: {msg}")
        else:
            print(f"[+] Slowloris stalled headers safely handled: HTTP 408 ({msg})")

        # 4. Oversized Header Boundary Clamp (>64KB -> HTTP 400 INVALID_REQUEST)
        print("[*] Probing oversized header clamp (64KB boundary)...")
        ok, msg = probe_oversized_headers()
        if not ok:
            failures.append(f"Oversized header clamp failed: {msg}")
            print(f"[-] Oversized header clamp FAILED: {msg}")
        else:
            print(f"[+] Oversized header boundary clamped: HTTP 400 ({msg})")

        # 5. Oversized payload clamp (>10MB -> 413 PAYLOAD_TOO_LARGE)
        print("[*] Probing 10MB payload ceiling clamp...")
        oversized_body = b"A" * (10 * 1024 * 1024 + 1024)  # 10MB + 1KB
        status, body = send_req("POST", "/api/evaluate-cedar", body=oversized_body, headers={"Content-Type": "application/json"})
        if status != 413:
            failures.append(f"Oversized payload expected 413, got {status}: {body[:200]}")
            print(f"[-] 10MB clamp FAILED: got {status}")
        else:
            ok, msg = check_structured_error(body, "PAYLOAD_TOO_LARGE")
            if not ok:
                failures.append(f"413 payload structure invalid: {msg}")
                print(f"[-] 413 payload structure invalid: {msg}")
            else:
                print(f"[+] 10MB ceiling correctly clamped: HTTP 413 with {msg}")

        # 6. Malformed JSON across all POST endpoints
        endpoints_to_test = [
            "/api/evaluate-cedar",
            "/api/egress-domains",
            "/api/rl-defense/evaluate-action",
            "/api/math/validate-sisyphean",
            "/api/governor/inject-sample",
        ]
        for ep in endpoints_to_test:
            print(f"[*] Probing malformed JSON boundary on {ep}...")
            status, body = send_req("POST", ep, body="{malformed json", headers={"Content-Type": "application/json"})
            if status != 400:
                failures.append(f"{ep} malformed JSON expected 400, got {status}: {body}")
                print(f"[-] {ep} malformed JSON FAILED: {status}")
            else:
                ok, msg = check_structured_error(body, "INVALID_JSON")
                if not ok:
                    failures.append(f"{ep} error structure invalid: {msg}")
                    print(f"[-] {ep} error structure invalid: {msg}")
                else:
                    print(f"[+] {ep} safely intercepted: HTTP 400 ({msg})")

        # 7. Unknown endpoint 404 structured payload
        print("[*] Probing non-existent endpoint for structured 404...")
        status, body = send_req("GET", "/api/completely-bogus-route-404")
        if status != 404:
            failures.append(f"Bogus endpoint expected 404, got {status}: {body}")
            print(f"[-] Bogus endpoint FAILED: {status}")
        else:
            ok, msg = check_structured_error(body, "ENDPOINT_NOT_FOUND")
            if not ok:
                failures.append(f"404 error structure invalid: {msg}")
                print(f"[-] 404 error structure invalid: {msg}")
            else:
                print(f"[+] 404 correctly structured: HTTP 404 ({msg})")

        # 8. Concurrent requests to test Mutex lock poisoning resilience (50 threads)
        print("[*] Probing concurrency & lock poisoning resilience (50 threads)...")
        errors = []
        def worker():
            s, b = send_req("GET", "/api/audit-log")
            if s != 200:
                errors.append(f"/api/audit-log thread failed with status {s}")
            s2, b2 = send_req("GET", "/api/live-tests?since_id=0")
            if s2 != 200:
                errors.append(f"/api/live-tests thread failed with status {s2}")
            s3, b3 = send_req("GET", "/api/governor/status")
            if s3 != 200:
                errors.append(f"/api/governor/status thread failed with status {s3}")

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        if errors:
            failures.extend(errors[:5])
            print(f"[-] Concurrency audit failed with {len(errors)} thread errors")
        else:
            print(f"[+] 50 concurrent threads completed with 0 lock contentions or poisoned locks.")

        # 9. Down-gateway simulation via Python OctopusTargetClient
        print("[*] Testing Python OctopusTargetClient against closed port (http://127.0.0.1:9999)...")
        from exhaustive_adversarial_tester import OctopusTargetClient
        client = OctopusTargetClient(base_url="http://127.0.0.1:9999")
        h = client.check_health()
        if h.get("status") != "offline":
            failures.append(f"Expected client.check_health() to report 'offline', got: {h}")
            print(f"[-] Down-gateway test FAILED: {h}")
        else:
            print(f"[+] Client gracefully caught connection error, status: '{h.get('status')}', intercepted_errors: {client.intercepted_errors}")

        cedar_res, lat = client.evaluate_cedar("ledger_arm", "write", "corporate_ledger", {"amount_cents": 100})
        if cedar_res.get("is_allowed") is not False or cedar_res.get("verdict") != "Deny":
            failures.append(f"Expected client.evaluate_cedar() to report Deny on offline gateway, got: {cedar_res}")
            print(f"[-] Down-gateway evaluate_cedar FAILED: {cedar_res}")
        else:
            print(f"[+] Offline evaluate_cedar returned Deny without crash: {cedar_res['reason']}")

    finally:
        if server_proc is not None:
            print(f"[*] Terminating background test server (PID: {server_proc.pid})...")
            try:
                server_proc.terminate()
                server_proc.wait(timeout=3.0)
            except Exception:
                try:
                    server_proc.kill()
                except Exception:
                    pass
            print("[+] Test server terminated cleanly.")

    print("=" * 70)
    if failures:
        print(f"AUDIT FAILED with {len(failures)} issues:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("ALL ADVERSARIAL ERROR BOUNDARY CHECKS PASSED!")
        sys.exit(0)


if __name__ == "__main__":
    main()
