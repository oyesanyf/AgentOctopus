"""
Terminator Socket Runner (Caldera Agent Payload):
Self-contained, zero-dependency socket runner executed by Caldera agents
to evaluate non-MITRE RFC protocol vulnerabilities, desynchronization triggers,
and raw wire-framing anomalies against remote servers and proxies.
"""

import argparse
import json
import socket
import ssl
import sys
import time
from typing import Dict, List, Optional, Tuple


class WireSocketClient:
    """Zero-dependency raw TCP/TLS socket client with RFC framing consumption."""

    def __init__(self, host: str, port: int, use_tls: bool = False, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def connect(self) -> None:
        raw_s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(raw_s, server_hostname=self.host)
        else:
            self.sock = raw_s
        self.sock.settimeout(self.timeout)

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def send_all(self, data: bytes) -> None:
        if not self.sock:
            raise RuntimeError("Socket not connected")
        self.sock.sendall(data)

    def read_http_response(self) -> Tuple[bytes, Dict[str, str], bytes]:
        """
        Reads one complete HTTP response according to RFC framing rules.
        Returns: (status_line_and_headers_raw, parsed_headers, body_bytes)
        """
        if not self.sock:
            raise RuntimeError("Socket not connected")

        # 1. Read until end of headers (\r\n\r\n)
        header_buf = bytearray()
        while b"\r\n\r\n" not in header_buf and b"\n\n" not in header_buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            header_buf.extend(chunk)

        delimiter = b"\r\n\r\n" if b"\r\n\r\n" in header_buf else b"\n\n"
        parts = header_buf.split(delimiter, 1)
        raw_headers = bytes(parts[0])
        initial_body = bytes(parts[1]) if len(parts) > 1 else b""

        # Parse headers
        headers: Dict[str, str] = {}
        status_line = ""
        lines = raw_headers.decode("latin-1", errors="replace").splitlines()
        if lines:
            status_line = lines[0]
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

        # Check for 204, 304, or HEAD (no body allowed)
        is_empty_body = False
        if status_line.startswith("HTTP/"):
            tokens = status_line.split()
            if len(tokens) >= 2:
                try:
                    code = int(tokens[1])
                    if code in (204, 304) or (100 <= code < 200):
                        is_empty_body = True
                except ValueError:
                    pass

        body = bytearray(initial_body)

        if not is_empty_body:
            transfer_encoding = headers.get("transfer-encoding", "").lower()
            content_length = headers.get("content-length")

            if "chunked" in transfer_encoding:
                # Read until terminating chunk 0\r\n\r\n
                while True:
                    if b"0\r\n\r\n" in body or b"0\n\n" in body:
                        break
                    try:
                        chunk = self.sock.recv(4096)
                        if not chunk:
                            break
                        body.extend(chunk)
                    except (socket.timeout, TimeoutError):
                        break
            elif content_length is not None:
                try:
                    target_len = int(content_length.strip())
                    while len(body) < target_len:
                        needed = target_len - len(body)
                        chunk = self.sock.recv(min(needed, 8192))
                        if not chunk:
                            break
                        body.extend(chunk)
                except ValueError:
                    pass
            elif headers.get("connection", "").lower() == "close":
                # Read until EOF
                while True:
                    try:
                        chunk = self.sock.recv(4096)
                        if not chunk:
                            break
                        body.extend(chunk)
                    except (socket.timeout, TimeoutError):
                        break

        return raw_headers, headers, bytes(body)

    def check_residual_bytes(self, grace_period: float = 0.3) -> bytes:
        """Checks if un-delimited residual bytes are sitting in socket buffer."""
        if not self.sock:
            return b""
        self.sock.settimeout(grace_period)
        residual = bytearray()
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                residual.extend(chunk)
        except (socket.timeout, TimeoutError):
            pass
        except Exception:
            pass
        finally:
            if self.sock:
                self.sock.settimeout(self.timeout)
        return bytes(residual)


def run_kettle_ab_evaluation(
    host: str,
    port: int,
    probe_bytes: bytes,
    use_tls: bool = False,
    timeout: float = 5.0,
) -> Dict[str, object]:
    """
    Executes Kettle Connection A/B cross-contamination evaluation primitive:
    Conn A: Baseline
    Conn B: Trigger Probe
    Conn A: Canary Request
    """
    results: Dict[str, object] = {
        "status": "SAFE",
        "divergence": False,
        "desync_confirmed": False,
        "residual_leak": 0,
        "baseline_status": None,
        "canary_status": None,
        "facts": [],
    }

    client_a = WireSocketClient(host, port, use_tls=use_tls, timeout=timeout)
    client_b = WireSocketClient(host, port, use_tls=use_tls, timeout=timeout)

    try:
        # Step 1: Baseline on Conn A
        client_a.connect()
        baseline_req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Caldera-Terminator/1.0\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode("latin-1")
        client_a.send_all(baseline_req)
        raw_h_a1, h_a1, body_a1 = client_a.read_http_response()
        status_a1 = raw_h_a1.splitlines()[0].decode("latin-1", errors="replace") if raw_h_a1 else ""
        results["baseline_status"] = status_a1

        # Step 2: Trigger on Conn B
        client_b.connect()
        client_b.send_all(probe_bytes)
        raw_h_b, h_b, body_b = client_b.read_http_response()
        # Check if Conn B left residual unread bytes
        b_residual = client_b.check_residual_bytes(grace_period=0.2)
        if b_residual:
            results["residual_leak"] = len(b_residual)

        # Step 3: Canary on Conn A
        canary_id = f"canary_{int(time.time() * 1000)}"
        canary_req = (
            f"GET /?test={canary_id} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Caldera-Terminator/1.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin-1")
        client_a.send_all(canary_req)
        raw_h_a2, h_a2, body_a2 = client_a.read_http_response()
        status_a2 = raw_h_a2.splitlines()[0].decode("latin-1", errors="replace") if raw_h_a2 else ""
        results["canary_status"] = status_a2

        # Step 4: Evaluate Divergence
        # If Conn A second request received an unexpected status code shift, reflection, or pipeline contamination
        if status_a1 and status_a2 and (status_a1 != status_a2):
            results["divergence"] = True
            # Cross-connection queue poisoning
            results["status"] = "CONFIRMED_VULNERABILITY"
            results["desync_confirmed"] = True
            results["facts"] = [
                {"trait": "target.vulnerability_confirmed", "value": "TRUE"},
                {"trait": "target.desync_class", "value": "CROSS_CONNECTION_POISONING"},
                {"trait": "target.baseline_status", "value": status_a1},
                {"trait": "target.canary_status", "value": status_a2},
            ]
        elif results["residual_leak"] > 0 and not b_residual.startswith(b"HTTP/"):
            # Check if residual is un-delimited response
            results["facts"].append({"trait": "target.residual_bytes", "value": str(len(b_residual))})

    except Exception as e:
        results["error"] = str(e)
    finally:
        client_a.close()
        client_b.close()

    return results


def run_single_replay(
    host: str,
    port: int,
    probe_bytes: bytes,
    use_tls: bool = False,
    timeout: float = 5.0,
) -> Dict[str, object]:
    """Replays a single probe and captures response & residual diagnostics."""
    client = WireSocketClient(host, port, use_tls=use_tls, timeout=timeout)
    results: Dict[str, object] = {
        "status": "SUCCESS",
        "response_status": None,
        "headers": {},
        "body_len": 0,
        "residual_leak": 0,
        "facts": [],
    }
    try:
        client.connect()
        client.send_all(probe_bytes)
        raw_h, headers, body = client.read_http_response()
        status_line = raw_h.splitlines()[0].decode("latin-1", errors="replace") if raw_h else ""
        residual = client.check_residual_bytes(grace_period=0.2)

        results["response_status"] = status_line
        results["headers"] = headers
        results["body_len"] = len(body)
        results["residual_leak"] = len(residual)

        results["facts"].append({"trait": "target.response_status", "value": status_line})
        if residual:
            results["facts"].append({"trait": "target.residual_bytes", "value": str(len(residual))})

    except Exception as e:
        results["status"] = "ERROR"
        results["error"] = str(e)
    finally:
        client.close()

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Terminator Wire-Exact Caldera Agent Runner")
    parser.add_argument("--host", "--target", dest="host", required=True, help="Target host domain or IP")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--tls", action="store_true", help="Enable TLS/HTTPS")
    parser.add_argument("--mode", choices=["kettle_ab", "replay"], default="kettle_ab", help="Evaluation mode")
    parser.add_argument("--payload-hex", type=str, required=True, help="Hex-encoded raw HTTP bytes to send")
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout in seconds")
    parser.add_argument("--json", action="store_true", default=True, help="Output Caldera JSON facts to stdout")

    args = parser.parse_args()

    use_tls = bool(args.tls or (args.port == 443))
    try:
        probe_bytes = bytes.fromhex(args.payload_hex)
    except ValueError as e:
        sys.stderr.write(f"Invalid hex payload: {e}\n")
        sys.exit(1)

    if args.mode == "kettle_ab":
        res = run_kettle_ab_evaluation(
            host=args.host,
            port=args.port,
            probe_bytes=probe_bytes,
            use_tls=use_tls,
            timeout=args.timeout,
        )
    else:
        res = run_single_replay(
            host=args.host,
            port=args.port,
            probe_bytes=probe_bytes,
            use_tls=use_tls,
            timeout=args.timeout,
        )

    # Print output formatted for Caldera agent collection
    out_str = json.dumps(res, indent=2)
    sys.stdout.write(out_str + "\n")

    # If vulnerability confirmed, exit 0 with facts so Caldera marks operation success
    sys.exit(0)


if __name__ == "__main__":
    main()
