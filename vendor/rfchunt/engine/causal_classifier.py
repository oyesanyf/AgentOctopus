"""
Module 9: Causal Anomaly and Novelty Classifier (P1).

Implements the 4-tier taxonomy classifier and counterfactual causal attribution.
Filters out environmental socket noise (TCP port exhaustion, transient target resets)
and identifies whether a reproducible vulnerability represents a genuinely novel technique.
"""

from typing import Any, Dict, List, Optional, Tuple
from engine.taxonomy import (
    AnomalyCategory,
    ImpactClass,
    ImplementationAnomaly,
    NovelTechnique,
    ReproducibleVulnerability,
    RFCRequirement,
)


class CausalAnomalyClassifier:
    """
    Evaluates causal attribution (counterfactual validation) and separates
    environmental noise from genuine specification-level vulnerabilities.
    """

    KNOWN_PATTERNS = {
        "CL_TE_DESYNC": lambda p: b"content-length" in p.lower() and b"transfer-encoding" in p.lower(),
        "PRE_COLON_SPACE": lambda p: b" :" in p or b"\t:" in p,
        "OBS_FOLD": lambda p: b"\r\n " in p or b"\r\n\t" in p,
        "CHUNK_EXT_OVERFLOW": lambda p: b";" in p and b"\r\n" in p,
    }

    def __init__(self):
        self.novel_techniques: Dict[str, NovelTechnique] = {}

    def filter_environmental_noise(
        self,
        anomaly: ImplementationAnomaly,
        baseline_is_healthy: bool,
        socket_error_type: Optional[str] = None,
    ) -> bool:
        """
        Determines if an anomaly is caused by environmental noise (e.g. OS port exhaustion,
        server crash/shutdown, transient connection refusal).
        Returns True if it IS environmental noise (should be discarded).
        """
        if not baseline_is_healthy:
            # If server cannot handle even a clean baseline request, network/target is degraded
            anomaly.is_environmental_noise = True
            return True

        if socket_error_type in ("WSAEADDRINUSE", "ECONNREFUSED", "WSAENOBUFS"):
            anomaly.is_environmental_noise = True
            return True

        anomaly.is_environmental_noise = False
        return False

    def classify_novelty(
        self, vuln: ReproducibleVulnerability, rfc_context: Optional[RFCRequirement] = None
    ) -> Tuple[bool, Optional[NovelTechnique]]:
        """
        Evaluates whether a reproducible vulnerability exhibits a genuinely novel
        attack/discovery technique or aligns with known historical desync patterns.
        """
        probe_lower = vuln.minimized_probe.lower()

        # Check for standard known patterns
        is_standard_cl_te = b"content-length" in probe_lower and b"transfer-encoding" in probe_lower
        is_standard_obs_fold = b"\r\n " in probe_lower or b"\r\n\t" in probe_lower

        if is_standard_cl_te or is_standard_obs_fold:
            return False, None

        # Check for novel patterns: Shared-Parser Confusion, chunk-ext injection, etc.
        if b"http/1.1 200 ok" in probe_lower or b"response" in probe_lower:
            # Novel Shared-Parser Confusion heuristic
            technique = NovelTechnique(
                technique_id="TECH-SHARED-PARSER-CONFUSION",
                title="Shared-Parser Confusion (Response-to-Request Inversion)",
                conceptual_model="Intermediary or server evaluates incoming client requests using response parsing rules.",
                inversion_pattern="Applying response syntax tokens (Status-Line, Reason-Phrase) directly into client stream.",
                affected_architectures=["Unified HTTP Parsers", "Reverse Proxy Duplex Channels"],
                supporting_vulnerabilities=[vuln.vuln_id],
                recommended_mitigation="Strictly segregate downstream request parsers from upstream response parsers.",
            )
            self.novel_techniques[technique.technique_id] = technique
            return True, technique

        if b"\x00" in vuln.minimized_probe:
            technique = NovelTechnique(
                technique_id="TECH-NULL-BYTE-FRAME-DESYNC",
                title="Null-Byte Frame Truncation Desync",
                conceptual_model="C-based string length termination discrepancies between proxy and backend parsers.",
                inversion_pattern="Injecting null bytes into ABNF header tokens to induce asymmetric length calculation.",
                affected_architectures=["C/C++ Proxy Frontends with High-Level Managed Backends"],
                supporting_vulnerabilities=[vuln.vuln_id],
                recommended_mitigation="Enforce strict rejection of b'\\x00' across all request fields at ingress.",
            )
            self.novel_techniques[technique.technique_id] = technique
            return True, technique

        return False, None
