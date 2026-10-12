"""
Test Lab Server:
A real local multi-threaded HTTP/1.1 socket server simulating backend desync behaviors,
dangling-byte queue poisoning, and anomaly signatures (memory leaks, double HTML, inline headers).
Used for safe, deterministic local evaluation and automated verification.
"""

import socket
import threading
import time
from typing import Optional


class TestLabServer:
    __test__ = False

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.server_sock: Optional[socket.socket] = None
        self.is_running = False
        self.thread: Optional[threading.Thread] = None

        # Shared backend state between connections to simulate proxy connection reuse
        self.poisoned_prefix: bytes = b""
        self.dangling_byte_pending = False
        self.stolen_victim_data: bytes = b""
        self.lock = threading.Lock()

    def start(self) -> None:
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(128)
        self.is_running = True
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()
        print(f"[+] Test Lab Server running on http://{self.host}:{self.port}")

    def stop(self) -> None:
        self.is_running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
        print("[-] Test Lab Server stopped.")

    def _accept_loop(self) -> None:
        while self.is_running:
            try:
                client_sock, _ = self.server_sock.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
                t.start()
            except Exception:
                break

    def _handle_client(self, client_sock: socket.socket) -> None:
        client_sock.settimeout(3.0)
        buffer = bytearray()

        try:
            while self.is_running:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                buffer.extend(chunk)

                with self.lock:
                    # If a dangling-byte condition was pending from a previous attacker probe,
                    # this incoming victim request's arrival completes the dangling byte!
                    if self.dangling_byte_pending:
                        self.dangling_byte_pending = False
                        self.stolen_victim_data = bytes(buffer)
                        # Victim gets diverted to the attacker's smuggled endpoint
                        resp = (
                            b"HTTP/1.1 404 Not Found\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"Connection: keep-alive\r\n"
                            b"Content-Length: 35\r\n\r\n"
                            b"Smuggled Endpoint Captured Request!\n"
                        )
                        client_sock.sendall(resp)
                        buffer = bytearray()
                        continue

                    # If attacker connection sends stealer request after poisoning, return victim stolen data
                    if self.stolen_victim_data:
                        captured = self.stolen_victim_data
                        self.stolen_victim_data = b""
                        body = b"Stolen Victim Stream: " + captured
                        resp = (
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"Connection: keep-alive\r\n"
                            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                            + body
                        )
                        client_sock.sendall(resp)
                        buffer = bytearray()
                        continue

                    # Prepend any poisoned leftover from previous desync
                    if self.poisoned_prefix:
                        buffer = bytearray(self.poisoned_prefix) + buffer
                        self.poisoned_prefix = b""

                # Check if we have complete headers
                if b"\r\n\r\n" in buffer:
                    header_bytes, rest = bytes(buffer).split(b"\r\n\r\n", 1)
                    request_line = header_bytes.split(b"\r\n")[0].decode("latin-1", errors="ignore")

                    # Handle Dangling-Byte simulation:
                    # If request is POST with Content-Length: 1 but 0 body bytes present
                    if b"Content-Length: 1" in header_bytes and len(rest) == 0:
                        with self.lock:
                            self.dangling_byte_pending = True
                        # Do not send response yet - wait for next request to complete the byte!
                        break

                    # Handle Memory Leak simulation
                    if "GET /leak" in request_line:
                        # Printable text followed by unprintable binary null stream
                        leak_body = b"<html><body>Normal text header</body></html>" + (b"\x00" * 40) + b"\x01\x02\xfe\xff" * 10
                        resp = (
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: text/html\r\n"
                            + f"Content-Length: {len(leak_body)}\r\n\r\n".encode("ascii")
                            + leak_body
                        )
                        client_sock.sendall(resp)
                        buffer = bytearray(rest)
                        continue

                    # Handle Double HTML simulation
                    if "GET /double_html" in request_line:
                        body = b"<!DOCTYPE html><html><body>Page 1</body></html><!DOCTYPE html><html><body>Page 2</body></html>"
                        resp = (
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: text/html\r\n"
                            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                            + body
                        )
                        client_sock.sendall(resp)
                        buffer = bytearray(rest)
                        continue

                    # Handle Leaked Inline Headers simulation (CVE-2026-63078)
                    if "GET /inline_headers" in request_line:
                        body = b"Normal response prefix\r\nServer: ATS\r\nX-Amzn-Trace-Id: Root=1-5f11\r\nHTTP/1.1 200 OK\r\n"
                        resp = (
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: text/plain\r\n"
                            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                            + body
                        )
                        client_sock.sendall(resp)
                        buffer = bytearray(rest)
                        continue

                    # Handle Desync Trigger:
                    # If multipart/byteranges or dual Content-Length or Transfer_Encoding is received,
                    # backend misinterprets body length and leaves the trailing $PAYLOAD on the connection queue!
                    is_desync_trigger = (
                        b"multipart/byteranges" in header_bytes
                        or b"Transfer_Encoding:" in header_bytes
                        or header_bytes.count(b"Content-Length:") >= 2
                    )

                    if is_desync_trigger:
                        if b"Content-Length: 1" in rest:
                            with self.lock:
                                self.dangling_byte_pending = True
                            resp = (
                                b"HTTP/1.1 200 OK\r\n"
                                b"Content-Type: text/plain\r\n"
                                b"Connection: keep-alive\r\n"
                                b"Content-Length: 18\r\n\r\n"
                                b"Trigger Accepted\r\n"
                            )
                            client_sock.sendall(resp)
                            buffer = bytearray()
                            continue
                        elif b"/terminator_marker" in rest:
                            with self.lock:
                                # Stash the marker in the shared connection pipeline
                                self.poisoned_prefix = rest
                            resp = (
                                b"HTTP/1.1 200 OK\r\n"
                                b"Content-Type: text/plain\r\n"
                                b"Content-Length: 15\r\n\r\n"
                                b"Trigger Accepted"
                            )
                            client_sock.sendall(resp)
                            break

                    # Handle reflected marker (desynchronized request execution)
                    if "terminator_marker" in request_line:
                        resp = (
                            b"HTTP/1.1 404 Not Found\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"Content-Length: 38\r\n\r\n"
                            b"terminator_marker reflected on queue!\n"
                        )
                        client_sock.sendall(resp)
                        buffer = bytearray(rest)
                        continue

                    # Default standard response
                    resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/plain\r\n"
                        b"Content-Length: 13\r\n"
                        b"Connection: keep-alive\r\n\r\n"
                        b"Hello, world!"
                    )
                    client_sock.sendall(resp)
                    buffer = bytearray(rest)

        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass


if __name__ == "__main__":
    server = TestLabServer()
    server.start()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        server.stop()
