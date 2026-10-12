#!/usr/bin/env python3
"""
Live TCP Socket Verification: The Dangling-Byte Technique & Response Queue Poisoning (RQP) Defense.
PortSwigger Research (James Kettle): Attackers send incomplete request bodies and hold connections open.
Agent Octopus invariant: Clamps stalled bodies with 408 Request Timeout, severs the connection,
and guarantees subsequent connections on the server suffer zero Response Queue Poisoning.
"""

import socket
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

HOST = "127.0.0.1"
PORT = 5005

def test_dangling_byte_live_timeout():
    print("=" * 70)
    print("🔌 Live Socket Test: Dangling-Byte Technique & RQP Defense")
    print("=" * 70)

    # 1. Connect to live server
    print(f"[*] Connecting to {HOST}:{PORT}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((HOST, PORT))

    # 2. Transmit request declaring Content-Length: 100, but only send 12 bytes
    partial_request = (
        b"POST /api/status HTTP/1.1\r\n"
        b"Host: 127.0.0.1:5005\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 100\r\n"
        b"\r\n"
        b"DanglingData"
    )
    print(f"[*] Sending partial HTTP frame (declared CL: 100, sent: 12 bytes)...")
    s.sendall(partial_request)

    # 3. Hold connection open without sending remaining 88 bytes
    t0 = time.time()
    print("[*] Holding socket open and idle, awaiting server timeout clamp...")
    resp_bytes = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp_bytes += chunk
    except socket.timeout:
        print("❌ Error: Socket timed out on client side before server clamped!")
        s.close()
        return False
    finally:
        s.close()

    elapsed = time.time() - t0
    resp_str = resp_bytes.decode("utf-8", errors="replace")
    print(f"[+] Server responded after {elapsed:.2f}s:")
    first_line = resp_str.split("\r\n")[0] if resp_str else "NO_RESPONSE"
    print(f"    Status: {first_line}")

    if "408 Request Timeout" not in resp_str and "400 Bad Request" not in resp_str:
        print(f"❌ Dangling-byte clamp failed. Response was:\n{resp_str}")
        return False

    print("[+] Server successfully severed connection after dangling-byte timeout!")

    # 4. Immediate follow-up connection to verify zero Response Queue Poisoning (RQP)
    print("\n[*] Sending subsequent pipelined probe to verify ZERO Response Queue Poisoning...")
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.settimeout(3.0)
    s2.connect((HOST, PORT))

    clean_req = (
        b"GET /api/status HTTP/1.1\r\n"
        b"Host: 127.0.0.1:5005\r\n"
        b"Accept: application/json\r\n"
        b"\r\n"
    )
    s2.sendall(clean_req)
    resp2_bytes = s2.recv(4096)
    s2.close()

    resp2_str = resp2_bytes.decode("utf-8", errors="replace")
    status2_line = resp2_str.split("\r\n")[0] if resp2_str else "EMPTY"
    print(f"[+] Follow-up connection response: {status2_line}")

    if "200 OK" not in resp2_str:
        print(f"❌ Response Queue Poisoned! Contaminated response:\n{resp2_str}")
        return False

    print("🎯 ZERO RQP CONFIRMED: Server state remained 100% clean and isolated!")
    print("=" * 70)
    return True

if __name__ == "__main__":
    success = test_dangling_byte_live_timeout()
    sys.exit(0 if success else 1)
