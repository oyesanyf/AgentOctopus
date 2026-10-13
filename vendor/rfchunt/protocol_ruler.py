"""
Protocol Ruler Engine:
Implements James Kettle's benchmark technique from 'Can AI do novel security research?':
Using backend header length limits as a high-precision ruler to measure front-end
byte transformations, character expansions, IP-rewriting, and Unicode mojibake without
requiring header reflection.

Methodology:
1. Baseline Calibration:
   Binary-searches the backend's exact maximum header length limit L_base down to single-byte precision:
   A: AAA...{L_base}   -> 200 OK
   A: AAA...{L_base+1} -> 400 Bad Request

2. Sequence Transformation Measurement:
   Replaces bytes of padding with a target candidate sequence (e.g. overlong UTF-8 '\\xc0\\x8a').
   Measures the new cliff L_mutated where the backend hits 400 Bad Request:
   A: \\xc0\\x8a A...{L_mutated}   -> 200 OK
   A: \\xc0\\x8a A...{L_mutated+1} -> 400 Bad Request

3. Analysis:
   Delta = L_base - L_mutated
   - Delta > 0: Front-end EXPANDED the sequence by Delta bytes (e.g. UTF-8 decoding, WAF escaping, IP injection)
   - Delta < 0: Front-end STRIPPED/CONTRACTED the sequence by |Delta| bytes (e.g. dropped header, whitespace collapse)
   - Delta == 0: Transmitted verbatim without modification
"""

import argparse
import re
import socket
import ssl
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from engine.http_framing import HTTPFramingReader


def format_kettle_ruler_bytes(raw_bytes: bytes, max_len: int = 120) -> str:
    """
    Formats raw HTTP request bytes with Kettle-style run-length compression:
    e.g. 'A: ' + 'A'*64040 -> 'A: AAA...{64040}'
    """
    if not raw_bytes:
        return ""
    text = raw_bytes.decode("latin-1", errors="replace")

    def _replacer(m):
        c = m.group(1)
        length = len(m.group(0))
        return f"{c*3}...{{{length}}}"

    text = re.sub(r'([^\r\n])\1{23,}', _replacer, text)
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text.rstrip()


class ProtocolRuler:
    """
    Measures front-end transformations and backend parser limits using
    James Kettle's Protocol Ruler technique.
    """

    # Default catalog of interesting byte transformations to probe
    DEFAULT_TEST_CATALOG: List[Tuple[str, bytes, str]] = [
        ("Kettle Overlong UTF-8 (c0 8a)", b"\xc0\x8a", "Overlong 2-byte UTF-8 newline check for expansion/normalization"),
        ("Overlong UTF-8 Slash (c0 af)", b"\xc0\xaf", "Overlong 2-byte slash for path-traversal / normalization check"),
        ("Overlong UTF-8 Slash 3-byte (e0 80 af)", b"\xe0\x80\xaf", "Overlong 3-byte slash for normalization expansion"),
        ("Overlong UTF-8 Slash 4-byte (f0 80 80 af)", b"\xf0\x80\x80\xaf", "Overlong 4-byte slash for gateway decoding"),
        ("Unicode Kelvin Sign (e2 84 aa)", b"\xe2\x84\xaa", "U+212A normalizes to ASCII 'K' (3 bytes -> 1 byte contraction)"),
        ("Unicode Ligature fi (ef ac 81)", b"\xef\xac\x81", "U+FB01 normalizes to 'fi' (3 bytes -> 2 bytes contraction/expansion)"),
        ("Unicode Non-Breaking Space (c2 a0)", b"\xc2\xa0", "U+00A0 NBSP may expand or normalize to standard space 0x20"),
        ("Unicode Fullwidth Solidus (ef bc 8f)", b"\xef\xbc\x8f", "U+FF0F fullwidth slash normalizes to ASCII '/'"),
        ("Line Folding Space (CRLF + space)", b"\r\n ", "RFC 7230 obsolete line folding: tests if proxy collapses to space"),
        ("Line Folding Tab (CRLF + tab)", b"\r\n\t", "RFC 7230 obsolete line folding with horizontal tab"),
        ("IP Spoofing Injection (X-Forwarded-For)", b"X-Forwarded-For: 127.0.0.1\r\n", "Tests if front-end strips or appends client IP"),
        ("IP Spoofing Injection (X-Real-IP)", b"X-Real-IP: 127.0.0.1\r\n", "Tests if front-end overrides or drops internal IP header"),
        ("Null Byte (0x00)", b"\x00", "Tests if front-end truncates header at C-string null terminator"),
        ("Vertical Tab (0x0B)", b"\x0b", "Tests whitespace normalization or sanitization stripping"),
        ("Escaped Quote (\\\")", b'\\"', "Tests quote escaping or backslash stripping in WAFs"),
    ]

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 80,
        use_tls: bool = False,
        timeout: float = 3.5,
        verbose: bool = False,
        debug: bool = False,
        on_trace: Optional[Callable[[str], None]] = None,
    ):
        if host in ("0.0.0.0", "::"):
            raise ValueError(f"Target host cannot be {host} (INADDR_ANY listening address). Use 127.0.0.1 or localhost.")
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.verbose = verbose
        self.debug = debug
        self.on_trace = on_trace

    def _log(self, msg: str) -> None:
        if self.on_trace:
            self.on_trace(msg)
        else:
            print(msg)

    def _open_socket(self) -> socket.socket:
        raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context.wrap_socket(raw_sock, server_hostname=self.host)
        return raw_sock

    def send_probe(self, request_bytes: bytes) -> Tuple[int, bytes, float]:
        """
        Sends raw bytes over a fresh connection and returns (status_code, response_bytes, latency_ms).
        Status code 0 indicates connection drop / reset / timeout.
        """
        t0 = time.time()
        status_code = 0
        response_bytes = b""
        try:
            sock = self._open_socket()
            sock.sendall(request_bytes)
            framed = HTTPFramingReader.read_response(sock, timeout=self.timeout)
            sock.close()
            status_code = framed.status_code
            response_bytes = framed.raw_response
            latency = (time.time() - t0) * 1000
            return status_code, response_bytes, latency
        except Exception:
            latency = (time.time() - t0) * 1000
            return 0, b"", latency

    def is_error_boundary(self, status_code: int) -> bool:
        """
        Returns True if the status code represents hitting the server's header buffer limit.
        Typically 400 Bad Request, 431 Request Header Fields Too Large, 414 URI Too Long,
        502 Bad Gateway (upstream proxy error), or 0 (connection reset/dropped by firewall).
        """
        return status_code in (400, 431, 414, 502, 504, 0)

    def calibrate_baseline_limit(
        self,
        min_size: int = 1024,
        max_size: int = 131072,
        header_name: str = "A",
    ) -> Optional[int]:
        """
        Pinpoints the backend's exact maximum header length limit down to the single byte.
        Returns the maximum padding length that still receives a successful/non-error response.
        """
        proto = "https" if self.use_tls else "http"
        self._log(f"\n[*] Calibrating Header Length Limit Ruler against {proto}://{self.host}:{self.port}...")
        self._log(f"[*] Scanning buffer bracket between {min_size:,} and {max_size:,} bytes...")

        def _build_request(padding_len: int) -> bytes:
            payload = b"A" * padding_len
            return (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"User-Agent: ProtocolRuler/1.0\r\n"
                f"{header_name}: "
            ).encode("latin-1") + payload + b"\r\nConnection: close\r\n\r\n"

        # Step 1: Coarse exponential / stepped bracket search
        brackets = [1024, 2048, 4096, 8192, 16384, 32768, 64000, 64040, 65536, 98304, 131072]
        brackets = [b for b in brackets if min_size <= b <= max_size]
        if max_size not in brackets:
            brackets.append(max_size)

        low = None
        high = None

        for b_size in brackets:
            req = _build_request(b_size)
            code, resp, lat = self.send_probe(req)
            if self.debug:
                summary = f"HTTP {code}" if code > 0 else "Connection Dropped"
                self._log(f"    [Bracket Probe] {b_size:,} bytes -> {summary} ({lat:.1f}ms)")

            if not self.is_error_boundary(code):
                low = b_size
            else:
                high = b_size
                break

        if low is None:
            self._log(f"[-] Target rejected even minimum size ({min_size} bytes). Server might be down or blocking requests.")
            return None

        if high is None:
            self._log(f"[-] Target accepted maximum test size ({max_size:,} bytes) without error. Header limit exceeds test boundary.")
            return None

        self._log(f"[+] Coarse limit bracketed: {low:,} (OK) <= LIMIT < {high:,} (ERROR)")
        self._log(f"[*] Executing binary search to pinpoint exact single-byte cliff...")

        # Step 2: Binary Search down to exact single byte
        left = low
        right = high
        last_ok = low

        while left <= right:
            mid = (left + right) // 2
            req = _build_request(mid)
            code, resp, lat = self.send_probe(req)

            if not self.is_error_boundary(code):
                last_ok = mid
                left = mid + 1
            else:
                right = mid - 1

        limit = last_ok

        # Step 3: Verification of the cliff in Kettle trace format
        req_ok = _build_request(limit)
        code_ok, _, lat_ok = self.send_probe(req_ok)
        req_err = _build_request(limit + 1)
        code_err, _, lat_err = self.send_probe(req_err)

        self._log(f"\n{'='*70}")
        self._log(f"[+] PROTOCOL RULER CALIBRATED: Header Length Limit = {limit:,} bytes")
        self._log(f"{'='*70}")
        self._log(f"GET / HTTP/1.1")
        self._log(f"Host: {self.host}")
        self._log(f"{header_name}: AAA...{{{limit}}} -> {code_ok} OK ({lat_ok:.1f}ms)")
        self._log(f"{header_name}: AAA...{{{limit + 1}}} -> {code_err if code_err else 'Connection Drop'} ({lat_err:.1f}ms)")
        self._log(f"{'='*70}\n")

        return limit

    def measure_sequence_transformation(
        self,
        name: str,
        sequence_bytes: bytes,
        baseline_limit: int,
        search_radius: int = 128,
        header_name: str = "A",
    ) -> Dict[str, Any]:
        """
        Measures front-end transformation of sequence_bytes using baseline_limit as the ruler.
        Replaces len(sequence_bytes) bytes of padding with sequence_bytes and binary searches
        the new error cliff around baseline_limit.
        """
        seq_len = len(sequence_bytes)

        def _build_mutated_request(padding_len: int) -> bytes:
            payload = sequence_bytes + (b"A" * max(0, padding_len - seq_len))
            return (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"User-Agent: ProtocolRuler/1.0\r\n"
                f"{header_name}: "
            ).encode("latin-1") + payload + b"\r\nConnection: close\r\n\r\n"

        low_bound = max(10, baseline_limit - search_radius)
        high_bound = baseline_limit + search_radius

        if self.debug:
            self._log(f"[*] Testing sequence: '{name}' ({seq_len} bytes: {sequence_bytes!r}) around limit {baseline_limit:,}...")

        # Binary search for the mutated cliff
        left = low_bound
        right = high_bound
        last_ok = low_bound

        while left <= right:
            mid = (left + right) // 2
            req = _build_mutated_request(mid)
            code, _, _ = self.send_probe(req)

            if not self.is_error_boundary(code):
                last_ok = mid
                left = mid + 1
            else:
                right = mid - 1

        mutated_limit = last_ok
        delta = baseline_limit - mutated_limit

        # Fetch verification responses
        req_ok = _build_mutated_request(mutated_limit)
        code_ok, _, _ = self.send_probe(req_ok)
        req_err = _build_mutated_request(mutated_limit + 1)
        code_err, _, _ = self.send_probe(req_err)

        fmt_seq = sequence_bytes.decode("latin-1", errors="replace").encode("unicode_escape").decode("ascii")

        # Interpret the delta
        if delta > 0:
            verdict = f"EXPANDED by {delta} bytes on front-end!"
            classification = "EXPANSION"
        elif delta < 0:
            verdict = f"CONTRACTED / STRIPPED by {abs(delta)} bytes on front-end!"
            classification = "CONTRACTION"
        else:
            verdict = "Transmitted verbatim (0 byte difference)."
            classification = "VERBATIM"

        self._log(f"--- [RULER MEASUREMENT] {name} ---")
        self._log(f"  Sequence         : {sequence_bytes!r} ({seq_len} bytes)")
        self._log(f"  Mutated Limit    : {mutated_limit:,} bytes (Baseline: {baseline_limit:,})")
        self._log(f"  Delta            : {delta:+d} bytes")
        self._log(f"  Behavior         : {verdict}")
        self._log(f"  Trace Cliff      :")
        self._log(f"    {header_name}: {fmt_seq} A...{{{mutated_limit}}} -> {code_ok} OK")
        self._log(f"    {header_name}: {fmt_seq} A...{{{mutated_limit + 1}}} -> {code_err if code_err else 'Connection Drop'}")
        self._log(f"-" * 55)

        return {
            "name": name,
            "sequence_hex": sequence_bytes.hex(),
            "sequence_repr": repr(sequence_bytes),
            "sequence_length": seq_len,
            "baseline_limit": baseline_limit,
            "mutated_limit": mutated_limit,
            "delta_bytes": delta,
            "classification": classification,
            "verdict": verdict,
            "code_ok": code_ok,
            "code_err": code_err,
        }

    def run_comprehensive_audit(
        self,
        custom_sequences: Optional[List[Tuple[str, bytes, str]]] = None,
        max_size: int = 131072,
    ) -> Dict[str, Any]:
        """
        Executes a full Protocol Ruler audit:
        1. Calibrates baseline header limit.
        2. Measures standard and custom transformation sequences.
        3. Returns full summary findings report.
        """
        t_start = time.time()
        baseline_limit = self.calibrate_baseline_limit(max_size=max_size)

        if baseline_limit is None:
            return {
                "success": False,
                "error": "Failed to calibrate baseline limit.",
                "findings": [],
            }

        catalog = list(self.DEFAULT_TEST_CATALOG)
        if custom_sequences:
            catalog.extend(custom_sequences)

        self._log(f"\n[*] Measuring {len(catalog)} byte-transformation candidate sequences against ruler...")
        findings = []

        for name, seq_bytes, desc in catalog:
            try:
                res = self.measure_sequence_transformation(name, seq_bytes, baseline_limit)
                res["description"] = desc
                findings.append(res)
            except Exception as e:
                self._log(f"[!] Error evaluating sequence '{name}': {e}")

        # Summary Analysis
        expansions = [f for f in findings if f["classification"] == "EXPANSION"]
        contractions = [f for f in findings if f["classification"] == "CONTRACTION"]

        self._log(f"\n{'='*75}")
        self._log(f"[*] PROTOCOL RULER AUDIT SUMMARY: {self.host}:{self.port}")
        self._log(f"{'='*75}")
        self._log(f"  Target                 : {'https' if self.use_tls else 'http'}://{self.host}:{self.port}")
        self._log(f"  Backend Header Limit   : {baseline_limit:,} bytes")
        self._log(f"  Sequences Tested       : {len(findings)}")
        self._log(f"  Expansions Detected    : {len(expansions)}")
        self._log(f"  Contractions Detected  : {len(contractions)}")
        self._log(f"  Total Duration         : {time.time() - t_start:.2f}s")

        if expansions:
            self._log(f"\n[!] HIGH-VALUE DETECTIONS (Input Expansion / Rewriting):")
            for exp in expansions:
                self._log(f"    - {exp['name']}: Expanded by {exp['delta_bytes']} bytes! ({exp['description']})")

        if contractions:
            self._log(f"\n[!] STRIPPED / CONTRACTED SEQUENCES:")
            for c in contractions:
                self._log(f"    - {c['name']}: Shrunk by {abs(c['delta_bytes'])} bytes! ({c['description']})")

        self._log(f"{'='*75}\n")

        return {
            "success": True,
            "target": f"{'https' if self.use_tls else 'http'}://{self.host}:{self.port}",
            "baseline_limit": baseline_limit,
            "findings": findings,
            "expansions": expansions,
            "contractions": contractions,
            "duration_sec": time.time() - t_start,
        }


def main():
    parser = argparse.ArgumentParser(
        description="Protocol Ruler: Measure front-end byte transformations using backend length limits (James Kettle technique)."
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Target port (default: 8080)")
    parser.add_argument("--tls", action="store_true", help="Enable TLS/HTTPS")
    parser.add_argument("--max-size", type=int, default=131072, help="Max header length to test in bytes (default: 131,072)")
    parser.add_argument("--timeout", type=float, default=3.5, help="Socket timeout in seconds (default: 3.5)")
    parser.add_argument("--debug", action="store_true", help="Enable deep bracket and binary search tracing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--sequence", type=str, default=None, help="Custom byte sequence to test (e.g. '\\xc0\\x8a' or hex 'c08a')")
    parser.add_argument("--name", type=str, default="Custom Probe", help="Name for custom sequence")
    args = parser.parse_args()

    use_tls = args.tls or (args.port == 443)

    ruler = ProtocolRuler(
        host=args.host,
        port=args.port,
        use_tls=use_tls,
        timeout=args.timeout,
        verbose=args.verbose,
        debug=args.debug,
    )

    custom = []
    if args.sequence:
        seq_str = args.sequence
        if seq_str.startswith("\\x"):
            # Decode escaped hex
            seq_bytes = bytes.fromhex(seq_str.replace("\\x", ""))
        else:
            try:
                seq_bytes = bytes.fromhex(seq_str)
            except ValueError:
                seq_bytes = seq_str.encode("latin-1")
        custom.append((args.name, seq_bytes, f"User-supplied test sequence: {seq_str}"))

    ruler.run_comprehensive_audit(custom_sequences=custom, max_size=args.max_size)


if __name__ == "__main__":
    main()
