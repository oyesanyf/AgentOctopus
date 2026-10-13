"""
Terminator RFC Selector: Purpose-built RFC specification selector for HTTP Terminators,
Reverse Proxies, Gateways, and Load Balancers.

Prioritizes the exact suite of IETF RFC specifications governing HTTP message syntax,
framing, line terminators (CRLF, bare LF, bare CR), Transfer-Encoding, Content-Length,
and intermediary gateway downgrades based on PortSwigger's HTTP Terminator research by James Kettle.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class TerminatorRFCSpec:
    num: int
    rfc_id: str
    title: str
    weight: float
    category: str
    key_sections: List[str]
    discrepancy_focus: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "num": self.num,
            "id": self.rfc_id,
            "title": self.title,
            "weight": self.weight,
            "category": self.category,
            "key_sections": self.key_sections,
            "discrepancy_focus": self.discrepancy_focus,
        }


# Curated specifications governing HTTP Terminators and Intermediaries
# Ranked in order of desync / discrepancy attack yield
TERMINATOR_CORE_RFCS: List[TerminatorRFCSpec] = [
    TerminatorRFCSpec(
        num=9112,
        rfc_id="RFC9112",
        title="HTTP/1.1 (Message Syntax and Framing)",
        weight=1.00,
        category="Core Message Syntax & Framing",
        key_sections=[
            "Section 2.2: Line Terminators (CRLF, bare LF, bare CR)",
            "Section 6.1: Transfer-Encoding vs Content-Length Precedence",
            "Section 6.3: Message Body Length Determination",
            "Section 7.1: Chunked Transfer Coding & Chunk Extensions",
            "Section 5.2: Obsolete Line Folding (obs-fold)",
        ],
        discrepancy_focus="Primary line and message boundary specification. Defines CRLF/LF leniency and chunked framing discrepancies.",
    ),
    TerminatorRFCSpec(
        num=9110,
        rfc_id="RFC9110",
        title="HTTP Semantics",
        weight=0.95,
        category="Intermediary Semantics & Gateways",
        key_sections=[
            "Section 6.3: Intermediaries (Gateways, Proxies, Terminators)",
            "Section 7.2: Host and Authority Identification",
            "Section 9: Method Definitions & Body Expectations",
            "Section 15: Status Codes & Protocol State Signaling",
        ],
        discrepancy_focus="Defines intermediary routing, connection-specific fields, and hop-by-hop header handling.",
    ),
    TerminatorRFCSpec(
        num=7230,
        rfc_id="RFC7230",
        title="HTTP/1.1 Message Syntax and Routing (Predecessor Standard)",
        weight=0.90,
        category="Predecessor Proxy Standard",
        key_sections=[
            "Section 3.3.3: Message Body Length",
            "Section 3.5: Message Parsing Robustness",
            "Section 4: Transfer Codings",
        ],
        discrepancy_focus="Predecessor standard implemented by many active terminators (ALB, Nginx, Envoy, Cloudflare). Discrepancies with RFC 9112 cause desync.",
    ),
    TerminatorRFCSpec(
        num=2616,
        rfc_id="RFC2616",
        title="Hypertext Transfer Protocol -- HTTP/1.1 (Historic Standard)",
        weight=0.85,
        category="Historic Discrepancy Baseline",
        key_sections=[
            "Section 19.2: Tolerant Applications & Parser Leniency",
            "Section 19.4.6: Introduction of Transfer-Encoding",
            "Section 4.4: Message Length determination",
        ],
        discrepancy_focus="Historic 1999 standard. Source of multipart/byteranges parser leniency and obsolete folding confusion.",
    ),
    TerminatorRFCSpec(
        num=9113,
        rfc_id="RFC9113",
        title="HTTP/2 (Extensible Prioritization Scheme & Gateway Translation)",
        weight=0.80,
        category="Intermediary Protocol Translation",
        key_sections=[
            "Section 8: HTTP/2 to HTTP/1.1 Gateway Translation",
            "Section 8.1.1: Malformed Requests and Streams",
            "Section 8.2: HTTP Header Fields and Pseudo-Headers",
        ],
        discrepancy_focus="Rules for translating HTTP/2 frames into HTTP/1.1 wire requests at front-end terminators (H2.CL / H2.TE).",
    ),
    TerminatorRFCSpec(
        num=7540,
        rfc_id="RFC7540",
        title="Hypertext Transfer Protocol Version 2 (HTTP/2)",
        weight=0.75,
        category="Legacy H2 Framing & Intermediary Downgrades",
        key_sections=[
            "Section 8.1.2: HTTP Header Fields",
            "Section 8.1.2.2: Connection-Specific Header Fields",
        ],
        discrepancy_focus="Legacy HTTP/2 framing rules and intermediary downgrade vulnerabilities.",
    ),
    TerminatorRFCSpec(
        num=9114,
        rfc_id="RFC9114",
        title="HTTP/3 (QUIC-based Gateway Termination)",
        weight=0.70,
        category="HTTP/3 Gateway Termination",
        key_sections=[
            "Section 4.1: HTTP/3 Frame Format",
            "Section 4.2: Bidirectional and Unidirectional Streams",
        ],
        discrepancy_focus="QUIC stream boundary and mapping discrepancies across HTTP/3 reverse proxies.",
    ),
    TerminatorRFCSpec(
        num=8446,
        rfc_id="RFC8446",
        title="The Transport Layer Security (TLS) Protocol Version 1.3",
        weight=0.65,
        category="TLS Terminator & Transport",
        key_sections=[
            "Section 4.2.11: Pre-Shared Key Exchange & 0-RTT Early Data",
            "Section 4.2.7: Supported Versions & ALPN Protocol Negotiation",
        ],
        discrepancy_focus="TLS terminator handshakes, ALPN negotiation, and 0-RTT early data request smuggling.",
    ),
    TerminatorRFCSpec(
        num=3986,
        rfc_id="RFC3986",
        title="Uniform Resource Identifier (URI): Generic Syntax",
        weight=0.60,
        category="URI Normalization & Path Truncation",
        key_sections=[
            "Section 3.3: Path Component",
            "Section 5.2.4: Remove Dot Segments",
        ],
        discrepancy_focus="Path normalization, dot-segment removal, and NUL-byte truncation discrepancies between terminator and origin.",
    ),
    TerminatorRFCSpec(
        num=6265,
        rfc_id="RFC6265",
        title="HTTP State Management Mechanism (Cookies)",
        weight=0.55,
        category="Header Parsing & Delimiters",
        key_sections=[
            "Section 4.2: Cookie Header",
            "Section 5.4: The Cookie Header Field",
        ],
        discrepancy_focus="Cookie semicolon vs comma separator handling between reverse proxy and origin application.",
    ),
    TerminatorRFCSpec(
        num=2046,
        rfc_id="RFC2046",
        title="Multipurpose Internet Mail Extensions (MIME) Part Two: Media Types",
        weight=0.50,
        category="Multipart Boundary Delimiters",
        key_sections=[
            "Section 5.1: Multipart Media Type",
            "Section 5.1.1: Common Syntax and Boundaries",
        ],
        discrepancy_focus="Multipart delimiter parsing, preamble interpretation, and boundary quote discrepancies.",
    ),
]

# Keywords specifically indicating operative terminator behavior or parsing ambiguities
TERMINATOR_OPERATIVE_KEYWORDS = [
    # Message Boundaries & Line Terminators
    "terminator", "line terminator", "crlf", "bare cr", "bare lf",
    "end of headers", "empty line", "delimiter", "delimit",
    # Framing & Chunking
    "transfer-encoding", "content-length", "chunked", "chunk extension",
    "chunk-size", "chunk-data", "trailer", "last-chunk", "message body length",
    # Intermediaries & Gateways
    "intermediary", "gateway", "reverse proxy", "proxy", "recipient",
    "sender", "inbound", "outbound", "forwarding", "downgrade",
    # Parsing Tolerances & Divergence
    "obs-fold", "folding", "line folding", "whitespace", "sp", "htab",
    "must reject", "must ignore", "must not", "should reject",
    "multipart/byteranges", "boundary", "tunnel", "upgrade"
]


class TerminatorRFCSelector:
    """
    Intelligent RFC Selector optimized for discovering implementation discrepancies
    in HTTP Terminators, Reverse Proxies, and Gateways.
    """

    @classmethod
    def get_terminator_specs(cls) -> List[TerminatorRFCSpec]:
        """Returns the full list of curated Terminator RFC specifications."""
        return list(TERMINATOR_CORE_RFCS)

    @classmethod
    def get_terminator_corpus(cls, max_rfcs: Optional[int] = None) -> List[int]:
        """
        Returns the ordered list of RFC numbers prioritized specifically for
        HTTP Terminators. RFC 9112 is guaranteed to be position 0.
        """
        nums = [spec.num for spec in TERMINATOR_CORE_RFCS]
        if max_rfcs and max_rfcs > 0:
            return nums[:max_rfcs]
        return nums

    @classmethod
    def get_spec_by_num(cls, rfc_num: int) -> Optional[TerminatorRFCSpec]:
        """Looks up a Terminator specification by its numeric identifier."""
        for spec in TERMINATOR_CORE_RFCS:
            if spec.num == rfc_num:
                return spec
        return None

    @classmethod
    def score_text_for_terminator(cls, text: str) -> Tuple[float, List[str]]:
        """
        Scores a text segment (RFC chunk or section) based on its density of
        terminator-specific discrepancy and framing keywords.
        Returns (score, matched_keywords).
        """
        if not text:
            return 0.0, []

        text_lower = text.lower()
        matched = []
        weight_sum = 0.0

        high_impact = {
            "line terminator": 3.0,
            "terminator": 2.5,
            "bare cr": 3.0,
            "bare lf": 3.0,
            "crlf": 2.5,
            "transfer-encoding": 3.0,
            "content-length": 3.0,
            "chunk extension": 3.0,
            "obs-fold": 3.0,
            "intermediary": 2.5,
            "gateway": 2.0,
            "reverse proxy": 2.5,
            "multipart/byteranges": 3.0,
            "must reject": 2.5,
            "must ignore": 2.5,
        }

        for kw in TERMINATOR_OPERATIVE_KEYWORDS:
            if kw in text_lower:
                matched.append(kw)
                weight_sum += high_impact.get(kw, 1.0)

        # Normalize score relative to text length
        word_count = max(1, len(text.split()))
        normalized_score = round((weight_sum / (word_count ** 0.5)) * 10.0, 3)

        return normalized_score, matched

    @classmethod
    def is_terminator_relevant(cls, rfc_num: int) -> bool:
        """Checks if a given RFC number is part of the core Terminator suite."""
        return any(spec.num == rfc_num for spec in TERMINATOR_CORE_RFCS)
