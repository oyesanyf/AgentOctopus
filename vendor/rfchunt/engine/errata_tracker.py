"""
Module 6: RFC Evolution and Errata Tracker (P1).

Tracks specification changes across RFC revisions (e.g. RFC 2616 -> RFC 7230 -> RFC 9112)
and official IETF errata, identifying when implementation anomalies stem from legacy
specification adherence or cross-version ambiguity.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from engine.taxonomy import RFCRequirement, RequirementType


@dataclass
class SpecificationShift:
    shift_id: str
    feature_name: str
    legacy_rfc: str
    legacy_rule: str
    modern_rfc: str
    modern_rule: str
    rational: str
    security_risk: str


class RFCEvolutionTracker:
    """
    Maintains historical lineage and errata shifts across the HTTP & SMTP specification trees.
    """

    HISTORICAL_SHIFTS: List[SpecificationShift] = [
        SpecificationShift(
            shift_id="SHIFT-OBS-FOLD",
            feature_name="Obsolete Line Folding (obs-fold)",
            legacy_rfc="RFC2616",
            legacy_rule="Header fields can be extended over multiple lines if preceded by SP or HTAB.",
            modern_rfc="RFC9112",
            modern_rule="A server MUST reject with 400 any request with line folding (CRLF followed by SP/HTAB).",
            rational="Line folding enables header-smuggling discrepancies between intermediaries.",
            security_risk="Request smuggling / header boundary desynchronization.",
        ),
        SpecificationShift(
            shift_id="SHIFT-PRE-COLON-WHITESPACE",
            feature_name="Whitespace Before Colon",
            legacy_rfc="RFC2616",
            legacy_rule="Silent tolerance or ambiguous handling of SP before colon.",
            modern_rfc="RFC9112",
            modern_rule="A server MUST reject with 400 any request with whitespace between field-name and colon.",
            rational="Proxies strip pre-colon spaces while backends may treat the header as unrecognized.",
            security_risk="Header smuggling and filter bypass.",
        ),
        SpecificationShift(
            shift_id="SHIFT-TE-CL-CONFLICT",
            feature_name="Transfer-Encoding & Content-Length Coexistence",
            legacy_rfc="RFC2616",
            legacy_rule="If both exist, Transfer-Encoding overrides Content-Length.",
            modern_rfc="RFC9112",
            modern_rule="A server MUST reject or resolve ambiguity; intermediaries MUST NOT forward both.",
            rational="Proxies preferring CL and backends preferring TE lead directly to desync.",
            security_risk="Classic CL.TE / TE.CL Request Smuggling.",
        ),
        SpecificationShift(
            shift_id="SHIFT-DUPLICATE-CL",
            feature_name="Multiple Content-Length Headers",
            legacy_rfc="RFC2616",
            legacy_rule="Not explicitly forbidden if values match.",
            modern_rfc="RFC9112",
            modern_rule="Multiple Content-Length headers with differing values MUST be rejected with 400.",
            rational="Prevent conflicting framing evaluations.",
            security_risk="Queue poisoning and framing desync.",
        ),
        SpecificationShift(
            shift_id="SHIFT-CHUNK-EXT",
            feature_name="Chunk Extensions Handling",
            legacy_rfc="RFC2616",
            legacy_rule="Recipients MAY parse chunk extensions.",
            modern_rfc="RFC9112",
            modern_rule="Recipients MUST parse and ignore unrecognized chunk extensions; MUST reject invalid syntax.",
            rational="Unbounded chunk extensions caused memory exhaustion and delimiter confusion.",
            security_risk="Denial of service and parser boundary confusion.",
        ),
    ]

    def __init__(self):
        self.shifts_by_feature: Dict[str, SpecificationShift] = {
            s.feature_name.lower(): s for s in self.HISTORICAL_SHIFTS
        }

    def get_all_shifts(self) -> List[SpecificationShift]:
        return self.HISTORICAL_SHIFTS

    def find_relevant_shift(self, query: str) -> Optional[SpecificationShift]:
        """Searches for specification shifts relevant to a rule or anomaly query."""
        q = query.lower()
        for shift in self.HISTORICAL_SHIFTS:
            feat_lower = shift.feature_name.lower()
            shift_id_lower = shift.shift_id.lower()
            if (
                q in feat_lower
                or feat_lower in q
                or q in shift_id_lower
                or shift.legacy_rfc.lower() in q
                or shift.modern_rfc.lower() in q
                or any(w in feat_lower for w in q.split())
            ):
                return shift
        return None

    def explain_anomaly_lineage(self, anomaly_description: str) -> str:
        """Explains if an anomaly is caused by a known historical specification transition."""
        shift = self.find_relevant_shift(anomaly_description)
        if shift:
            return (
                f"Historical Context: Shift '{shift.feature_name}' ({shift.legacy_rfc} -> {shift.modern_rfc}). "
                f"Legacy behavior: {shift.legacy_rule}. Modern requirement: {shift.modern_rule}. "
                f"Security Implication: {shift.security_risk}"
            )
        return "No direct historical RFC shift identified for this behavior."
