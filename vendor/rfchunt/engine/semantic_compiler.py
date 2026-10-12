"""
Module 3: RFC Semantic Constraint Compiler (P0).

Scans normative RFC specifications for RFC 2119 imperative keywords
(MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT) and compiles prose
into programmatic, testable specification assertions.
"""

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple
from engine.taxonomy import RFCRequirement, RequirementType


@dataclass
class SpecificationAssertion:
    assertion_id: str
    rfc_id: str
    section: str
    keyword: str
    statement: str
    probe_factory: Callable[[], bytes]
    evaluator: Callable[[int, bytes, float], Tuple[bool, str]]

    def evaluate(self, status_code: int, response_bytes: bytes, latency: float) -> Tuple[bool, str]:
        return self.evaluator(status_code, response_bytes, latency)


class SemanticConstraintCompiler:
    """
    Compiles natural language normative constraints from RFCs into executable
    wire-level assertions and probes.
    """

    NORMATIVE_REGEX = re.compile(
        r"([^.?!]*?\b(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|REQUIRED)\b[^.?!]*?[.?!])",
        re.IGNORECASE | re.MULTILINE,
    )

    def __init__(self):
        self.compiled_assertions: Dict[str, SpecificationAssertion] = {}
        self._load_core_compiled_rules()

    def _load_core_compiled_rules(self):
        """Pre-compiles foundational RFC 9112 / RFC 9110 normative assertions."""

        # Rule 1: RFC 9112 Section 5.1 - Pre-colon whitespace MUST be rejected with 4xx
        def probe_pre_colon_space() -> bytes:
            return b"GET / HTTP/1.1\r\nHost: target\r\nX-Foo : bar\r\n\r\n"

        def eval_pre_colon_space(status: int, body: bytes, latency: float) -> Tuple[bool, str]:
            if 400 <= status < 500:
                return True, "Compliant: Rejected pre-colon whitespace with 4xx"
            return False, f"Non-compliant: Server returned {status} instead of 4xx"

        self.register_assertion(
            SpecificationAssertion(
                assertion_id="ASSERT-RFC9112-PRE-COLON-WHITESPACE",
                rfc_id="RFC9112",
                section="5.1",
                keyword="MUST",
                statement="A server MUST reject with 4xx any request containing whitespace before the colon.",
                probe_factory=probe_pre_colon_space,
                evaluator=eval_pre_colon_space,
            )
        )

        # Rule 2: RFC 9112 Section 6.1 - Duplicate differing Content-Length MUST be rejected
        def probe_duplicate_conflicting_cl() -> bytes:
            return b"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello"

        def eval_duplicate_conflicting_cl(status: int, body: bytes, latency: float) -> Tuple[bool, str]:
            if 400 <= status < 500:
                return True, "Compliant: Server rejected conflicting Content-Length with 4xx"
            return False, f"Non-compliant: Server accepted or misparsed duplicate Content-Length (Status {status})"

        self.register_assertion(
            SpecificationAssertion(
                assertion_id="ASSERT-RFC9112-DUPLICATE-CL",
                rfc_id="RFC9112",
                section="6.1",
                keyword="MUST",
                statement="A server MUST reject any request containing multiple conflicting Content-Length headers.",
                probe_factory=probe_duplicate_conflicting_cl,
                evaluator=eval_duplicate_conflicting_cl,
            )
        )

        # Rule 3: RFC 9112 Section 6.3 - Transfer-Encoding precedence or rejection
        def probe_te_cl_coexistence() -> bytes:
            return (
                b"POST / HTTP/1.1\r\n"
                b"Host: target\r\n"
                b"Content-Length: 4\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n0\r\n\r\n"
            )

        def eval_te_cl_coexistence(status: int, body: bytes, latency: float) -> Tuple[bool, str]:
            # Compliant if either rejected with 4xx or chunked parsing is correctly honored without hanging
            if 400 <= status < 500 or status == 200:
                return True, "Compliant: Handled TE/CL coexistence safely"
            return False, f"Anomaly: Unexpected behavior on TE/CL coexistence ({status})"

        self.register_assertion(
            SpecificationAssertion(
                assertion_id="ASSERT-RFC9112-TE-CL-PRECEDENCE",
                rfc_id="RFC9112",
                section="6.3",
                keyword="MUST",
                statement="If both TE and CL exist, TE MUST override CL, or request MUST be rejected.",
                probe_factory=probe_te_cl_coexistence,
                evaluator=eval_te_cl_coexistence,
            )
        )

    def register_assertion(self, assertion: SpecificationAssertion) -> None:
        self.compiled_assertions[assertion.assertion_id] = assertion

    def extract_normative_clauses(self, rfc_id: str, text: str) -> List[RFCRequirement]:
        """Extracts normative sentences from raw RFC prose."""
        requirements: List[RFCRequirement] = []
        for idx, match in enumerate(self.NORMATIVE_REGEX.finditer(text)):
            sentence = " ".join(match.group(1).split())
            keyword = match.group(2).upper()

            req = RFCRequirement(
                requirement_id=f"NORM-{rfc_id}-{idx:04d}",
                rfc_id=rfc_id,
                section="Normative-Text",
                req_type=RequirementType.SEMANTIC_NORMATIVE,
                raw_statement=sentence,
                formal_expression=f"ASSERT_{keyword}({sentence[:64]}...)",
                normative_keyword=keyword,
            )
            requirements.append(req)

        return requirements

    def get_all_assertions(self) -> List[SpecificationAssertion]:
        return list(self.compiled_assertions.values())

    def get_assertion(self, assertion_id: str) -> Optional[SpecificationAssertion]:
        return self.compiled_assertions.get(assertion_id)
