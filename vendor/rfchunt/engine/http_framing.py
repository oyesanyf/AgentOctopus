"""
HTTP Framing Engine (RFC 9112 / RFC 7230 Compliance).

Implements strict HTTP/1.1 message framing rules (RFC 9112 Section 6):
1. Status-Line and Header parsing until CRLF CRLF.
2. Handling of 1xx (Informational) interim responses (no body; continues reading final response).
3. Handling of 204 (No Content), 304 (Not Modified), and HEAD request responses (strictly no body).
4. Transfer-Encoding: chunked parsing (chunk size hex, chunk extensions, chunk data, 0 chunk, trailers).
5. Content-Length: exact byte accounting across multiple chunks/socket recv calls.
6. Connection close / EOF framing (when neither Content-Length nor Transfer-Encoding is present).
7. Connection state tracking (Connection: close, keep-alive, socket timeout, premature EOF).
8. Buffer preservation for pipelined multi-request persistent connections.
"""

import re
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class HTTPResponseFraming:
    raw_response: bytes
    status_code: int
    headers: Dict[str, str]
    body: bytes
    framing_type: str  # "content-length", "chunked", "no-body", "close", "incomplete"
    is_complete: bool
    is_connection_closed: bool
    unconsumed_bytes: bytes = b""
    error: Optional[str] = None
    interim_responses: List[bytes] = field(default_factory=list)

    @property
    def is_success(self) -> bool:
        return self.is_complete and self.status_code > 0 and self.error is None


class HTTPFramingReader:
    """
    RFC 9112 compliant socket response reader and message framing engine.
    Ensures complete, exact response consumption on persistent TCP/TLS connections.
    """

    CHUNK_READ_SIZE = 65536

    @classmethod
    def read_response(
        cls,
        sock: socket.socket,
        timeout: float = 3.5,
        initial_bytes: bytes = b"",
        request_method: str = "GET",
    ) -> HTTPResponseFraming:
        """
        Reads a single framed HTTP/1.1 response from a socket.
        Consumes the exact response body per RFC framing rules.
        Any bytes received beyond the framed response are returned in `unconsumed_bytes`
        so they can be passed to subsequent pipelined reads.
        """
        sock.settimeout(timeout)
        buffer = bytearray(initial_bytes)
        interim_responses: List[bytes] = []

        while True:
            # 1. Read until headers complete (CRLF CRLF or LF LF)
            header_bytes, rest, err = cls._read_until_headers_complete(sock, buffer, timeout)
            if err:
                return HTTPResponseFraming(
                    raw_response=bytes(buffer),
                    status_code=0,
                    headers={},
                    body=b"",
                    framing_type="incomplete",
                    is_complete=False,
                    is_connection_closed=True,
                    unconsumed_bytes=b"",
                    error=err,
                    interim_responses=interim_responses,
                )

            status_code, headers = cls._parse_headers(header_bytes)

            # 2. Check for 1xx Interim Responses (RFC 9112 Section 6.3 item 1)
            # 1xx responses MUST NOT have a body. The client continues reading for the final response.
            if 100 <= status_code < 200 and status_code != 101:
                interim_responses.append(header_bytes)
                buffer = bytearray(rest)
                # Loop back to read the subsequent (final) response
                continue

            break

        # Check Connection header for close
        conn_header = headers.get("connection", "").lower()
        is_conn_close = "close" in conn_header

        # 3. Status codes that MUST NOT have a message body (RFC 9112 Section 6.3 item 1)
        # Any 1xx, 204 (No Content), 304 (Not Modified), and responses to HEAD
        if (
            status_code in (204, 304)
            or (100 <= status_code < 200)
            or request_method.upper() == "HEAD"
        ):
            return HTTPResponseFraming(
                raw_response=header_bytes,
                status_code=status_code,
                headers=headers,
                body=b"",
                framing_type="no-body",
                is_complete=True,
                is_connection_closed=is_conn_close,
                unconsumed_bytes=bytes(rest),
                error=None,
                interim_responses=interim_responses,
            )

        # 4. Transfer-Encoding: chunked (RFC 9112 Section 6.3 item 3)
        te_header = headers.get("transfer-encoding", "").lower()
        if "chunked" in te_header:
            return cls._read_chunked_body(
                sock,
                header_bytes,
                rest,
                status_code,
                headers,
                is_conn_close,
                timeout,
                interim_responses,
            )

        # 5. Content-Length (RFC 9112 Section 6.3 item 5)
        cl_header = headers.get("content-length")
        if cl_header is not None:
            content_length = cls._parse_content_length(cl_header)
            if content_length is not None:
                return cls._read_content_length_body(
                    sock,
                    header_bytes,
                    rest,
                    status_code,
                    headers,
                    content_length,
                    is_conn_close,
                    timeout,
                    interim_responses,
                )

        # 6. Connection close framing (RFC 9112 Section 6.3 item 8)
        # If neither Transfer-Encoding nor Content-Length is present, body is bounded by connection close.
        return cls._read_until_close_body(
            sock,
            header_bytes,
            rest,
            status_code,
            headers,
            timeout,
            interim_responses,
        )

    @classmethod
    def _read_until_headers_complete(
        cls,
        sock: socket.socket,
        buffer: bytearray,
        timeout: float,
    ) -> Tuple[bytes, bytes, Optional[str]]:
        """Reads from socket until header delimiter CRLF CRLF is found."""
        while True:
            idx = buffer.find(b"\r\n\r\n")
            if idx != -1:
                header_bytes = bytes(buffer[: idx + 4])
                rest = bytes(buffer[idx + 4 :])
                return header_bytes, rest, None

            # Fallback for bare \n\n
            idx_lf = buffer.find(b"\n\n")
            if idx_lf != -1:
                header_bytes = bytes(buffer[: idx_lf + 2])
                rest = bytes(buffer[idx_lf + 2 :])
                return header_bytes, rest, None

            try:
                chunk = sock.recv(4096)
                if not chunk:
                    if buffer:
                        return b"", b"", "Connection closed before complete HTTP headers received"
                    return b"", b"", "Connection closed with no data"
                buffer.extend(chunk)
            except socket.timeout:
                return b"", b"", "Socket timeout while awaiting HTTP response headers"
            except (ConnectionResetError, ConnectionAbortedError) as e:
                return b"", b"", f"Connection reset by peer: {e}"
            except Exception as e:
                return b"", b"", f"Socket error while reading headers: {e}"

    @classmethod
    def _parse_headers(cls, header_bytes: bytes) -> Tuple[int, Dict[str, str]]:
        """Extracts status code and normalized lower-case headers dict."""
        status_code = 0
        headers: Dict[str, str] = {}
        lines = header_bytes.split(b"\r\n")
        if len(lines) <= 1:
            lines = header_bytes.split(b"\n")

        if lines:
            status_line = lines[0].decode("latin-1", errors="replace").strip()
            parts = status_line.split(None, 2)
            if len(parts) >= 2 and parts[1].isdigit():
                status_code = int(parts[1])

        for line in lines[1:]:
            line_str = line.decode("latin-1", errors="replace").strip()
            if not line_str:
                continue
            if ":" in line_str:
                k, v = line_str.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        return status_code, headers

    @classmethod
    def _parse_content_length(cls, cl_header: str) -> Optional[int]:
        """Parses Content-Length, handling commas if duplicate identical values are present."""
        try:
            parts = [p.strip() for p in cl_header.split(",") if p.strip()]
            if parts and parts[0].isdigit():
                return int(parts[0])
        except Exception:
            pass
        return None

    @classmethod
    def _read_content_length_body(
        cls,
        sock: socket.socket,
        header_bytes: bytes,
        rest: bytes,
        status_code: int,
        headers: Dict[str, str],
        content_length: int,
        is_conn_close: bool,
        timeout: float,
        interim_responses: List[bytes],
    ) -> HTTPResponseFraming:
        """Reads exactly content_length bytes from rest + socket."""
        body_buf = bytearray(rest)

        while len(body_buf) < content_length:
            remaining = content_length - len(body_buf)
            read_size = min(cls.CHUNK_READ_SIZE, max(4096, remaining))
            try:
                chunk = sock.recv(read_size)
                if not chunk:
                    # Premature EOF before full content length
                    body = bytes(body_buf)
                    return HTTPResponseFraming(
                        raw_response=header_bytes + body,
                        status_code=status_code,
                        headers=headers,
                        body=body,
                        framing_type="content-length",
                        is_complete=False,
                        is_connection_closed=True,
                        unconsumed_bytes=b"",
                        error=f"Premature EOF: received {len(body_buf)} of {content_length} body bytes",
                        interim_responses=interim_responses,
                    )
                body_buf.extend(chunk)
            except socket.timeout:
                body = bytes(body_buf)
                return HTTPResponseFraming(
                    raw_response=header_bytes + body,
                    status_code=status_code,
                    headers=headers,
                    body=body,
                    framing_type="content-length",
                    is_complete=False,
                    is_connection_closed=True,
                    unconsumed_bytes=b"",
                    error=f"Socket timeout while reading Content-Length body: received {len(body_buf)} of {content_length} bytes",
                    interim_responses=interim_responses,
                )
            except (ConnectionResetError, ConnectionAbortedError) as e:
                body = bytes(body_buf)
                return HTTPResponseFraming(
                    raw_response=header_bytes + body,
                    status_code=status_code,
                    headers=headers,
                    body=body,
                    framing_type="content-length",
                    is_complete=False,
                    is_connection_closed=True,
                    unconsumed_bytes=b"",
                    error=f"Connection reset: {e}",
                    interim_responses=interim_responses,
                )
            except Exception as e:
                body = bytes(body_buf)
                return HTTPResponseFraming(
                    raw_response=header_bytes + body,
                    status_code=status_code,
                    headers=headers,
                    body=body,
                    framing_type="content-length",
                    is_complete=False,
                    is_connection_closed=True,
                    unconsumed_bytes=b"",
                    error=f"Socket error reading body: {e}",
                    interim_responses=interim_responses,
                )

        body = bytes(body_buf[:content_length])
        unconsumed = bytes(body_buf[content_length:])
        return HTTPResponseFraming(
            raw_response=header_bytes + body,
            status_code=status_code,
            headers=headers,
            body=body,
            framing_type="content-length",
            is_complete=True,
            is_connection_closed=is_conn_close,
            unconsumed_bytes=unconsumed,
            error=None,
            interim_responses=interim_responses,
        )

    @classmethod
    def _read_chunked_body(
        cls,
        sock: socket.socket,
        header_bytes: bytes,
        rest: bytes,
        status_code: int,
        headers: Dict[str, str],
        is_conn_close: bool,
        timeout: float,
        interim_responses: List[bytes],
    ) -> HTTPResponseFraming:
        """Reads and de-chunks Transfer-Encoding: chunked message body."""
        buf = bytearray(rest)
        body = bytearray()
        raw_body_stream = bytearray()

        while True:
            # Find chunk size line ending in CRLF
            line_idx = buf.find(b"\r\n")
            while line_idx == -1:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        return HTTPResponseFraming(
                            raw_response=header_bytes + bytes(raw_body_stream),
                            status_code=status_code,
                            headers=headers,
                            body=bytes(body),
                            framing_type="chunked",
                            is_complete=False,
                            is_connection_closed=True,
                            unconsumed_bytes=b"",
                            error="Premature EOF while reading chunk size line",
                            interim_responses=interim_responses,
                        )
                    buf.extend(chunk)
                    line_idx = buf.find(b"\r\n")
                except socket.timeout:
                    return HTTPResponseFraming(
                        raw_response=header_bytes + bytes(raw_body_stream),
                        status_code=status_code,
                        headers=headers,
                        body=bytes(body),
                        framing_type="chunked",
                        is_complete=False,
                        is_connection_closed=True,
                        unconsumed_bytes=b"",
                        error="Socket timeout while reading chunk size line",
                        interim_responses=interim_responses,
                    )
                except Exception as e:
                    return HTTPResponseFraming(
                        raw_response=header_bytes + bytes(raw_body_stream),
                        status_code=status_code,
                        headers=headers,
                        body=bytes(body),
                        framing_type="chunked",
                        is_complete=False,
                        is_connection_closed=True,
                        unconsumed_bytes=b"",
                        error=f"Socket error reading chunk size: {e}",
                        interim_responses=interim_responses,
                    )

            chunk_line = bytes(buf[:line_idx])
            raw_body_stream.extend(buf[: line_idx + 2])
            del buf[: line_idx + 2]

            # Parse chunk size hex (ignore chunk extensions after ';')
            size_hex = chunk_line.split(b";")[0].strip()
            try:
                chunk_len = int(size_hex, 16)
            except ValueError:
                return HTTPResponseFraming(
                    raw_response=header_bytes + bytes(raw_body_stream),
                    status_code=status_code,
                    headers=headers,
                    body=bytes(body),
                    framing_type="chunked",
                    is_complete=False,
                    is_connection_closed=True,
                    unconsumed_bytes=bytes(buf),
                    error=f"Invalid chunk size hex: {size_hex!r}",
                    interim_responses=interim_responses,
                )

            if chunk_len == 0:
                # Last chunk! Read trailers until CRLF CRLF or CRLF
                # Check if trailers are present
                while True:
                    if buf.startswith(b"\r\n"):
                        # Empty trailers (just CRLF)
                        raw_body_stream.extend(b"\r\n")
                        del buf[:2]
                        break
                    trailer_end = buf.find(b"\r\n\r\n")
                    if trailer_end != -1:
                        raw_body_stream.extend(buf[: trailer_end + 4])
                        del buf[: trailer_end + 4]
                        break
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        buf.extend(chunk)
                    except Exception:
                        break

                return HTTPResponseFraming(
                    raw_response=header_bytes + bytes(raw_body_stream),
                    status_code=status_code,
                    headers=headers,
                    body=bytes(body),
                    framing_type="chunked",
                    is_complete=True,
                    is_connection_closed=is_conn_close,
                    unconsumed_bytes=bytes(buf),
                    error=None,
                    interim_responses=interim_responses,
                )

            # Read chunk data + trailing CRLF
            needed = chunk_len + 2
            while len(buf) < needed:
                try:
                    chunk = sock.recv(min(cls.CHUNK_READ_SIZE, max(4096, needed - len(buf))))
                    if not chunk:
                        return HTTPResponseFraming(
                            raw_response=header_bytes + bytes(raw_body_stream),
                            status_code=status_code,
                            headers=headers,
                            body=bytes(body),
                            framing_type="chunked",
                            is_complete=False,
                            is_connection_closed=True,
                            unconsumed_bytes=b"",
                            error=f"Premature EOF: received {len(buf)} of {needed} chunk bytes",
                            interim_responses=interim_responses,
                        )
                    buf.extend(chunk)
                except socket.timeout:
                    return HTTPResponseFraming(
                        raw_response=header_bytes + bytes(raw_body_stream),
                        status_code=status_code,
                        headers=headers,
                        body=bytes(body),
                        framing_type="chunked",
                        is_complete=False,
                        is_connection_closed=True,
                        unconsumed_bytes=b"",
                        error=f"Socket timeout while reading chunk data of length {chunk_len}",
                        interim_responses=interim_responses,
                    )
                except Exception as e:
                    return HTTPResponseFraming(
                        raw_response=header_bytes + bytes(raw_body_stream),
                        status_code=status_code,
                        headers=headers,
                        body=bytes(body),
                        framing_type="chunked",
                        is_complete=False,
                        is_connection_closed=True,
                        unconsumed_bytes=b"",
                        error=f"Socket error reading chunk data: {e}",
                        interim_responses=interim_responses,
                    )

            body.extend(buf[:chunk_len])
            raw_body_stream.extend(buf[:needed])
            del buf[:needed]

    @classmethod
    def _read_until_close_body(
        cls,
        sock: socket.socket,
        header_bytes: bytes,
        rest: bytes,
        status_code: int,
        headers: Dict[str, str],
        timeout: float,
        interim_responses: List[bytes],
    ) -> HTTPResponseFraming:
        """Reads body until EOF (server closed connection)."""
        body_buf = bytearray(rest)
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                body_buf.extend(chunk)
            except socket.timeout:
                break
            except Exception:
                break

        body = bytes(body_buf)
        return HTTPResponseFraming(
            raw_response=header_bytes + body,
            status_code=status_code,
            headers=headers,
            body=body,
            framing_type="close",
            is_complete=True,
            is_connection_closed=True,
            unconsumed_bytes=b"",
            error=None,
            interim_responses=interim_responses,
        )
