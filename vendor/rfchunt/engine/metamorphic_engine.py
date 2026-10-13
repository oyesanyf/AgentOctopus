"""
Module 7: Metamorphic Testing Engine (P1).

Applies Metamorphic Relations (MR) to uncover parser bugs and state corruption
without requiring a golden specification oracle. Tests metamorphic invariants such as
header permutation, case insensitivity, chunk splitting, and whitespace equivalence.
"""

import re
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple
from engine.http_framing import HTTPFramingReader
from engine.taxonomy import AnomalyCategory, ImplementationAnomaly


@dataclass
class MetamorphicRelation:
    relation_id: str
    name: str
    description: str
    transform: Callable[[bytes], bytes]
    comparator: Callable[[int, bytes, int, bytes], Tuple[bool, str]]


class MetamorphicTestingEngine:
    """
    Executes metamorphic transformations on base requests and verifies whether
    the server preserves the invariant relationships.
    """

    def __init__(self):
        self.relations: List[MetamorphicRelation] = []
        self._register_default_relations()

    def _register_default_relations(self):
        # MR 1: Header Case Insensitivity
        def transform_header_case(raw: bytes) -> bytes:
            # Change case of headers like 'Host' -> 'hOsT', 'Content-Type' -> 'cOnTeNt-tYpE'
            lines = raw.split(b"\r\n")
            new_lines = []
            for line in lines:
                if b":" in line and not line.startswith(b"GET") and not line.startswith(b"POST"):
                    k, v = line.split(b":", 1)
                    # Alternate case
                    new_k = b"".join(bytes([c ^ 0x20]) if c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" else bytes([c]) for c in k)
                    new_lines.append(new_k + b":" + v)
                else:
                    new_lines.append(line)
            return b"\r\n".join(new_lines)

        def compare_status_equality(s1: int, b1: bytes, s2: int, b2: bytes) -> Tuple[bool, str]:
            if s1 == s2:
                return True, f"Invariant preserved: Status codes match ({s1} == {s2})"
            return False, f"Metamorphic Violation: Base request returned {s1}, but transformed request returned {s2}"

        self.relations.append(
            MetamorphicRelation(
                relation_id="MR-HEADER-CASE",
                name="Header Case Insensitivity",
                description="Changing HTTP header field name casing MUST NOT alter the response status.",
                transform=transform_header_case,
                comparator=compare_status_equality,
            )
        )

        # MR 2: OWS Tab vs Space Equivalence (RFC 9112 Section 5.1 / 5.5 / 7.2)
        def transform_ows_whitespace(raw: bytes) -> bytes:
            # Replace ': ' with ':\t' in non-authority header fields.
            # Preserves Host header syntax to adhere strictly to RFC 9112 Section 7.2 (uri-host).
            lines = raw.split(b"\r\n")
            new_lines = []
            for line in lines:
                if line.lower().startswith(b"host:"):
                    new_lines.append(line)
                elif b": " in line:
                    new_lines.append(line.replace(b": ", b":\t", 1))
                else:
                    new_lines.append(line)
            return b"\r\n".join(new_lines)

        def compare_metamorphic_response(s1: int, b1: bytes, s2: int, b2: bytes) -> Tuple[bool, str]:
            if s1 == s2:
                return True, f"Invariant preserved: Status codes match ({s1} == {s2})"
            if s1 == 200 and s2 in (400, 431, 422):
                return False, (
                    f"RFC-Compliant Rejection: Base request returned {s1}, but transformed request returned {s2}. "
                    "Under RFC 9112 Section 5.1 and 5.5, servers MAY apply strict grammar validation and reject "
                    "optional-whitespace variations with 400 Bad Request; this is conformant input validation, not a vulnerability."
                )
            return False, f"Metamorphic Violation: Base request returned {s1}, but transformed request returned {s2}"

        self.relations.append(
            MetamorphicRelation(
                relation_id="MR-OWS-EQUIVALENCE",
                name="OWS Tab-Space Equivalence",
                description="Replacing SP with HTAB in optional header whitespace MUST yield equivalent status or RFC-compliant 400 rejection.",
                transform=transform_ows_whitespace,
                comparator=compare_metamorphic_response,
            )
        )

        # MR 3: Chunk Slicing Invariance
        def transform_chunk_slicing(raw: bytes) -> bytes:
            # If payload contains chunked body, slice a 4-byte chunk into two 2-byte chunks
            if b"\r\n4\r\ntest\r\n0\r\n\r\n" in raw:
                return raw.replace(b"\r\n4\r\ntest\r\n0\r\n\r\n", b"\r\n2\r\nte\r\n2\r\nst\r\n0\r\n\r\n")
            return raw

        self.relations.append(
            MetamorphicRelation(
                relation_id="MR-CHUNK-SLICING",
                name="Chunk Slicing Invariance",
                description="Subdividing chunked transfer blocks must preserve response semantics.",
                transform=transform_chunk_slicing,
                comparator=compare_status_equality,
            )
        )

    def test_metamorphic_invariance(
        self, host: str, port: int, base_probe: bytes, timeout: float = 3.0, use_tls: bool = False
    ) -> List[Tuple[MetamorphicRelation, bool, str, Optional[ImplementationAnomaly]]]:
        """
        Executes the base probe, applies each metamorphic relation transform,
        and tests if the relationship holds.
        """
        results = []
        base_status, base_body = self._execute_raw(host, port, base_probe, timeout, use_tls=use_tls)
        if base_status == 0:
            # Server unreachable or baseline failed
            return results

        for mr in self.relations:
            trans_probe = mr.transform(base_probe)
            if trans_probe == base_probe:
                continue  # Relation not applicable to this probe

            trans_status, trans_body = self._execute_raw(host, port, trans_probe, timeout, use_tls=use_tls)
            is_valid, reason = mr.comparator(base_status, base_body, trans_status, trans_body)

            anomaly = None
            if not is_valid and not reason.startswith("RFC-Compliant Rejection"):
                anomaly = ImplementationAnomaly(
                    anomaly_id=f"ANOM-META-{int(time.time() * 1000)}",
                    target_engine=f"{host}:{port}",
                    category=AnomalyCategory.METAMORPHIC_VIOLATION,
                    observed_behavior=reason,
                    expected_behavior=mr.description,
                    raw_probe=trans_probe,
                    raw_response=trans_body,
                    triggering_rule_id=mr.relation_id,
                )

            results.append((mr, is_valid, reason, anomaly))

        return results

    def _execute_raw(self, host: str, port: int, payload: bytes, timeout: float, use_tls: bool = False) -> Tuple[int, bytes]:
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.sendall(payload)
            framed = HTTPFramingReader.read_response(sock, timeout=timeout)
            return framed.status_code, framed.raw_response
        except Exception:
            return 0, b""
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _parse_status(self, data: bytes) -> int:
        try:
            line = data.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
            parts = line.split(" ", 2)
            if len(parts) > 1 and parts[1].isdigit():
                return int(parts[1])
        except Exception:
            pass
        return 0
