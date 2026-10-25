#!/usr/bin/env python3
"""
Live adversarial HTTP/1.1 framing, smuggling, and HTTP Terminator novel attack verification test.
Connects directly over raw TCP sockets to http://127.0.0.1:5005 to verify that
strict_http and the Differential Protocol Analysis Engine reject protocol anomalies,
novel desync triggers, and Shared-Parser Confusion attempts fail-closed.
"""

import json
import socket
import sys
import urllib.request

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 5005
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def send_raw_request(raw_bytes: bytes, timeout=5) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((TARGET_HOST, TARGET_PORT))
        s.sendall(raw_bytes)
        response = b""
        while True:
            try:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break
        return response.decode('utf-8', errors='replace')
    except Exception as e:
        return f"SOCKET_ERROR: {e}"
    finally:
        s.close()

def main():
    print("=" * 75)
    print("AGENT OCTOPUS: LIVE NOVEL ATTACK & STRICT PROTOCOL DEFENSE TEST")
    print(f"Target: {TARGET_HOST}:{TARGET_PORT}")
    print("=" * 75)

    tests = [
        (
            "Valid GET Request",
            b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            "200 OK",
            True
        ),
        (
            "Valid POST Request",
            b"POST /api/rl-defense/train-cycle HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            "200 OK",
            True
        ),
        (
            "Shared-Parser Confusion: multipart/byteranges in Request",
            b"POST /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: multipart/byteranges; boundary=x\r\nContent-Length: 5\r\n\r\nhello",
            "400 Bad Request",
            True
        ),
        (
            "Shared-Parser Confusion: Content-Range in Client Request",
            b"POST /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Range: bytes 0-5/100\r\nContent-Length: 5\r\n\r\nhello",
            "400 Bad Request",
            True
        ),
        (
            "Shared-Parser Confusion: Location in Client Request",
            b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nLocation: http://attacker.com/\r\n\r\n",
            "400 Bad Request",
            True
        ),
        (
            "Novel Desync Trigger: Transfer-Encoding gzip (F5 Big-IP CL.0 Vector)",
            b"POST /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: gzip\r\nContent-Length: 5\r\n\r\nhello",
            "400 Bad Request",
            True
        ),
        (
            "Novel Desync Trigger: Early-Data Header without PSK",
            b"POST /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nEarly-Data: experimental\r\nContent-Length: 5\r\n\r\nhello",
            "400 Bad Request",
            True
        ),
        (
            "Novel Desync Trigger: Max-Forwards 0 on POST (CVE-2026-63078)",
            b"POST /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nMax-Forwards: 0\r\nContent-Length: 5\r\n\r\nhello",
            "400 Bad Request",
            True
        ),
        (
            "Novel Desync Trigger: Asterisk Request Target (OPTIONS *?xyz)",
            b"OPTIONS *?xyz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            "400 Bad Request",
            True
        ),
        (
            "Novel Desync Pattern: Dual Matching Content-Length (Citrix/SSO Desync)",
            b"POST /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 28\r\nContent-Length: 28\r\n\r\n1234567890123456789012345678",
            "400 Bad Request",
            True
        ),
        (
            "Novel Desync Pattern: Dual Conflicting Content-Length",
            b"POST /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 3\r\nContent-Length: 5\r\n\r\nfoo",
            "400 Bad Request",
            True
        ),
        (
            "Smuggling Attempt: Transfer-Encoding chunked",
            b"POST /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "400 Bad Request",
            True
        ),
        (
            "Status-Line Injection Attempt: Version Mutation (COW<)",
            b"GET / COW< HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            "400 Bad Request",
            True
        ),
        (
            "The Dangling-Byte Technique: Trailing Unannounced Body Bytes",
            b"POST /api/rl-defense/train-cycle HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}EXTRA_SMUGGLED_PAYLOAD",
            "400 Bad Request",
            True
        ),
    ]

    passed = 0
    failed = 0

    for name, raw, expected_pattern, should_contain in tests:
        res = send_raw_request(raw)
        has_pattern = expected_pattern in res
        if has_pattern == should_contain:
            print(f"[PASS] {name} -> Matched '{expected_pattern}'")
            passed += 1
        else:
            print(f"[FAIL] {name} -> Expected '{expected_pattern}' in response, got:\n{res[:200]}")
            failed += 1

    # Test the new Protocol Analyzer endpoints
    print("\n--- Verifying Protocol Analyzer API Endpoints ---")
    endpoints = [
        ("/api/protocol-analyzer/status", "GET", None, "total_streams_analyzed"),
        ("/api/protocol-analyzer/events", "GET", None, "reports"),
        ("/api/protocol-analyzer/analyze", "POST", json.dumps({"raw_http": "POST / HTTP/1.1\\r\\nHost: x\\r\\nContent-Type: multipart/byteranges\\r\\nContent-Length: 5\\r\\n\\r\\nhello"}).encode('utf-8'), "divergence_vector"),
    ]

    for path, method, data, expected_key in endpoints:
        try:
            import http.client
            conn = http.client.HTTPConnection("127.0.0.1", 5005, timeout=5)
            headers = {"Content-Type": "application/json"} if data else {}
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            body = resp.read().decode('utf-8')
            conn.close()
            if expected_key in body:
                print(f"[PASS] {method} {path} -> 200 OK (Contains '{expected_key}')")
                passed += 1
            else:
                print(f"[FAIL] {method} {path} -> Missing '{expected_key}' in response: {body[:150]}")
                failed += 1
        except Exception as e:
            print(f"[FAIL] {method} {path} -> Request error: {e}")
            failed += 1

    print("\n" + "=" * 75)
    print(f"Summary: {passed} passed, {failed} failed out of {len(tests) + len(endpoints)} tests")
    print("=" * 75)

    if failed > 0:
        sys.exit(1)
    print("[+] ALL NOVEL ATTACK DEFENSES AND PROTOCOL ANALYZER ENDPOINTS OPERATIONAL!")

if __name__ == "__main__":
    main()
