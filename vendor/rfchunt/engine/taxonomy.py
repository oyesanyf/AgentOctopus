"""
Taxonomy and Data Contracts for Protocol Research Engine.

Implements the fundamental 4-tier protocol research taxonomy:
1. RFC Requirement: Formal normative or syntactic specification rule.
2. Implementation Anomaly: Observable behavioral discrepancy or divergence.
3. Reproducible Vulnerability: Minimized, deterministic security defect.
4. Novel Technique: Generalized structural or architectural vulnerability class.

Also defines the output contracts for Agent Octopus Arms 106 and 107.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class RequirementType(str, Enum):
    SYNTACTIC_ABNF = "SYNTACTIC_ABNF"
    SEMANTIC_NORMATIVE = "SEMANTIC_NORMATIVE"  # MUST, MUST NOT, SHOULD, etc.
    HISTORICAL_SHIFT = "HISTORICAL_SHIFT"      # RFC evolution shift


class AnomalyCategory(str, Enum):
    PARSER_DIVERGENCE = "PARSER_DIVERGENCE"
    METAMORPHIC_VIOLATION = "METAMORPHIC_VIOLATION"
    STATUS_MISMATCH = "STATUS_MISMATCH"
    PIPELINE_LEAK = "PIPELINE_LEAK"
    SOCKET_HANG = "SOCKET_HANG"
    UNHANDLED_EXCEPTION = "UNHANDLED_EXCEPTION"


class ImpactClass(str, Enum):
    DESYNCHRONIZATION = "DESYNCHRONIZATION"
    QUEUE_POISONING = "QUEUE_POISONING"
    REQUEST_SMUGGLING = "REQUEST_SMUGGLING"
    CACHE_POISONING = "CACHE_POISONING"
    PARSER_CONFUSION = "PARSER_CONFUSION"
    BOUNDARY_OVERFLOW = "BOUNDARY_OVERFLOW"


@dataclass
class RFCRequirement:
    """Tier 1: Specification Ground Truth."""
    requirement_id: str
    rfc_id: str
    section: str
    req_type: RequirementType
    raw_statement: str
    formal_expression: str  # ABNF rule or compiled assertion expression
    normative_keyword: Optional[str] = None  # MUST, MUST NOT, SHOULD, etc.
    is_obsolete: bool = False
    superseded_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "rfc_id": self.rfc_id,
            "section": self.section,
            "req_type": self.req_type.value,
            "raw_statement": self.raw_statement,
            "formal_expression": self.formal_expression,
            "normative_keyword": self.normative_keyword,
            "is_obsolete": self.is_obsolete,
            "superseded_by": self.superseded_by,
            "created_at": self.created_at,
        }


@dataclass
class ImplementationAnomaly:
    """Tier 2: Observed behavioral divergence or non-conformance."""
    anomaly_id: str
    target_engine: str
    category: AnomalyCategory
    observed_behavior: str
    expected_behavior: str
    raw_probe: bytes
    raw_response: bytes
    triggering_rule_id: Optional[str] = None
    divergence_matrix: Optional[Dict[str, Any]] = None
    is_environmental_noise: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "target_engine": self.target_engine,
            "category": self.category.value,
            "observed_behavior": self.observed_behavior,
            "expected_behavior": self.expected_behavior,
            "raw_probe": self.raw_probe.decode("latin-1", errors="replace"),
            "raw_response": self.raw_response.decode("latin-1", errors="replace"),
            "triggering_rule_id": self.triggering_rule_id,
            "divergence_matrix": self.divergence_matrix,
            "is_environmental_noise": self.is_environmental_noise,
            "created_at": self.created_at,
        }


@dataclass
class ReproducibleVulnerability:
    """Tier 3: Minimized, deterministic security defect."""
    vuln_id: str
    anomaly_id: str
    impact: ImpactClass
    minimized_probe: bytes
    reproducibility_rate: float  # 0.0 to 1.0 (1.0 = 100% deterministic over N runs)
    verification_attempts: int
    successful_reproductions: int
    delta_debug_steps: int
    provenance_chain: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "anomaly_id": self.anomaly_id,
            "impact": self.impact.value,
            "minimized_probe": self.minimized_probe.decode("latin-1", errors="replace"),
            "reproducibility_rate": self.reproducibility_rate,
            "verification_attempts": self.verification_attempts,
            "successful_reproductions": self.successful_reproductions,
            "delta_debug_steps": self.delta_debug_steps,
            "provenance_chain": self.provenance_chain,
            "created_at": self.created_at,
        }


@dataclass
class NovelTechnique:
    """Tier 4: Generalized structural vulnerability class."""
    technique_id: str
    title: str
    conceptual_model: str  # Root cause theory
    inversion_pattern: str
    affected_architectures: List[str]
    supporting_vulnerabilities: List[str]
    recommended_mitigation: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "title": self.title,
            "conceptual_model": self.conceptual_model,
            "inversion_pattern": self.inversion_pattern,
            "affected_architectures": self.affected_architectures,
            "supporting_vulnerabilities": self.supporting_vulnerabilities,
            "recommended_mitigation": self.recommended_mitigation,
            "created_at": self.created_at,
        }


@dataclass
class Arm106DefensiveRule:
    """Agent Octopus Arm 106: Defensive hardening / signature ingestion."""
    rule_id: str
    name: str
    rule_type: str  # 'REGEX', 'SURICATA', 'WAF_MODSEC', 'RUST_PARSER_GUARD'
    target_protocol: str
    specification_anchor: str
    rule_body: str
    severity: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Arm107RegressionTest:
    """Agent Octopus Arm 107: Continuous regression test suite."""
    test_id: str
    vuln_id: str
    protocol: str
    expected_status_rejection: List[int]
    probe_bytes: bytes
    validation_logic: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
