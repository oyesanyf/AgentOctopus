"""
Module 1: ABNF Grammar Extractor and Inversion Engine (P0).

Extracts specification-grounded Augmented Backus-Naur Form (ABNF) definitions
from RFC texts (RFC 5234 compliance) and synthesizes both conforming and
systematically boundary-inverting protocol mutations.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from engine.taxonomy import RFCRequirement, RequirementType


class ABNFGrammarEngine:
    """
    Parses ABNF grammar rules from RFCs and provides an inversion engine
    to generate boundary-violating test vectors directly tied to specification rules.
    """

    # RFC 5234 / RFC 9112 Core ABNF Patterns
    ABNF_RULE_REGEX = re.compile(
        r"^[ \t]*([a-zA-Z][a-zA-Z0-9_-]*)[ \t]*=[ \t]*(.+?)(?=;.*)?$",
        re.MULTILINE,
    )

    CORE_HTTP_RULES = {
        "OWS": '*( SP / HTAB )',
        "RWS": '1*( SP / HTAB )',
        "BWS": 'OWS',
        "obs-fold": 'CRLF 1*( SP / HTAB )',
        "chunk-ext": '*( ";" chunk-ext-name [ "=" chunk-ext-val ] )',
        "header-field": 'field-name ":" OWS field-value OWS',
        "request-line": 'method SP request-target SP HTTP-version CRLF',
        "tchar": '"!" / "#" / "$" / "%" / "&" / "\'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA',
        "transfer-coding": '"chunked" / "compress" / "deflate" / "gzip" / transfer-extension',
    }

    def __init__(self):
        self.extracted_rules: Dict[str, Dict[str, str]] = {}
        # Preload canonical specifications
        for rule_name, rule_def in self.CORE_HTTP_RULES.items():
            self.extracted_rules[rule_name] = {
                "rfc_id": "RFC9112",
                "definition": rule_def,
                "section": "Core",
            }

    def extract_from_rfc_text(self, rfc_id: str, text: str) -> List[RFCRequirement]:
        """Scans raw RFC text and extracts formal ABNF rules."""
        requirements: List[RFCRequirement] = []
        for match in self.ABNF_RULE_REGEX.finditer(text):
            rule_name = match.group(1).strip()
            rule_body = match.group(2).strip()

            # Filter out non-grammar lines that accidentally match
            if len(rule_body) < 2 or rule_body.startswith("//") or rule_body.startswith("/*"):
                continue

            self.extracted_rules[rule_name] = {
                "rfc_id": rfc_id,
                "definition": rule_body,
                "section": "ABNF-Extracted",
            }

            req = RFCRequirement(
                requirement_id=f"ABNF-{rfc_id}-{rule_name.upper()}",
                rfc_id=rfc_id,
                section="ABNF",
                req_type=RequirementType.SYNTACTIC_ABNF,
                raw_statement=f"{rule_name} = {rule_body}",
                formal_expression=f"{rule_name} = {rule_body}",
            )
            requirements.append(req)

        return requirements

    def generate_conforming(self, rule_name: str) -> bytes:
        """Generates standard, strictly conforming byte representation."""
        rule_lower = rule_name.lower()
        if rule_lower in ("ows", "bws"):
            return b" "
        elif rule_lower == "rws":
            return b" "
        elif rule_lower == "obs-fold":
            return b"\r\n "
        elif rule_lower == "chunk-ext":
            return b";k=v"
        elif rule_lower == "header-field":
            return b"X-Spec-Test: valid\r\n"
        elif rule_lower == "request-line":
            return b"GET / HTTP/1.1\r\n"
        return b""

    def generate_inversions(self, rule_name: str, base_context: Optional[bytes] = None) -> List[Tuple[str, bytes]]:
        """
        Synthesizes boundary-violating mutations by inverting the ABNF constraints.
        Returns a list of (mutation_strategy_name, inverted_bytes).
        """
        rule_lower = rule_name.lower()
        mutations: List[Tuple[str, bytes]] = []

        if rule_lower in ("ows", "bws"):
            # OWS is *( SP / HTAB ). Inversions test illegal whitespace, bare controls, and nulls.
            mutations.extend([
                ("OWS_BARE_VTAB", b"\x0b"),
                ("OWS_NULL_BYTE", b"\x00"),
                ("OWS_UNICODE_NBSP", b"\xc2\xa0"),
                ("OWS_CARRIAGE_RETURN_SOLO", b"\r"),
                ("OWS_LINE_FEED_SOLO", b"\n"),
            ])
        elif rule_lower == "header-field":
            # header-field = field-name ":" OWS field-value OWS
            # Inversions: space before colon (RFC 9112 Section 5.1 forbidden), obs-fold, control chars
            mutations.extend([
                ("PRE_COLON_SPACE", b"X-Custom-Header : invalid-space-before-colon\r\n"),
                ("PRE_COLON_TAB", b"X-Custom-Header\t: invalid-tab-before-colon\r\n"),
                ("OBS_FOLD_LF_SPACE", b"X-Custom-Header: fold\n continuing\r\n"),
                ("OBS_FOLD_CRLF_TAB", b"X-Custom-Header: fold\r\n\tcontinuing\r\n"),
                ("EMBEDDED_NULL_HEADER_NAME", b"X-Cust\x00om: null-in-name\r\n"),
                ("DUPLICATE_COLON", b"X-Custom-Header:: double-colon\r\n"),
            ])
        elif rule_lower == "chunk-ext":
            # chunk-ext = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
            # Inversions: missing name, unquoted illegal chars, runaway extensions, null in extension
            mutations.extend([
                ("CHUNK_EXT_EMPTY_SEMICOLON", b";\r\n"),
                ("CHUNK_EXT_SPECIAL_CHARS", b";name=\"unclosed_quote\r\n"),
                ("CHUNK_EXT_NULL_BYTE", b";ext\x00=value\r\n"),
                ("CHUNK_EXT_LONG_PADDING", b";" + (b"A" * 2048) + b"\r\n"),
                ("CHUNK_EXT_DOUBLE_SEMICOLON", b";;key=val\r\n"),
            ])
        elif rule_lower == "obs-fold":
            # obs-fold = CRLF 1*( SP / HTAB )
            # Modern servers MUST reject or sanitize obs-fold.
            mutations.extend([
                ("OBS_FOLD_STANDALONE", b"\r\n "),
                ("OBS_FOLD_MULTIPLE_TABS", b"\r\n\t\t\t"),
                ("OBS_FOLD_CR_ONLY_SPACE", b"\r "),
                ("OBS_FOLD_LF_ONLY_SPACE", b"\n "),
            ])
        elif rule_lower in ("transfer-coding", "transfer-encoding"):
            mutations.extend([
                ("TE_CHUNKS_MIXED_CASE", b"Transfer-Encoding: cHuNkEd\r\n"),
                ("TE_DOUBLE_SPACE_DELIM", b"Transfer-Encoding:  chunked\r\n"),
                ("TE_SPACE_AFTER_CHUNKED", b"Transfer-Encoding: chunked \r\n"),
                ("TE_COMMA_PREFIXED", b"Transfer-Encoding: ,chunked\r\n"),
                ("TE_IDENTITY_CHUNKED_DUAL", b"Transfer-Encoding: identity, chunked\r\n"),
                ("TE_CHUNKED_COW_INVALID", b"Transfer-Encoding: chunked, cow\r\n"),
            ])
        else:
            # Generic boundary inversion: inject high-order byte, null byte, and bare LF
            mutations.extend([
                ("GENERIC_NULL_BYTE_INJECTION", b"\x00"),
                ("GENERIC_BARE_LF", b"\n"),
                ("GENERIC_OVERFLOW_PADDING", b"X" * 1024),
            ])

        return mutations

    def list_known_rules(self) -> List[str]:
        return list(self.extracted_rules.keys())
