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

    def is_framing_artifact(
        self,
        anomaly: ImplementationAnomaly,
        baseline_resp: Optional[bytes] = None,
    ) -> Tuple[bool, str]:
        """
        Validates whether anomalous bytes or reported pipeline leaks can be explained
        by ordinary HTTP response framing (e.g. unconsumed baseline HTML body,
        standard RFC 9112 400 Bad Request connection closure, or socket buffer leftovers).
        Returns (is_artifact, reason).
        """
        obs_lower = anomaly.observed_behavior.lower()
        raw_resp = anomaly.raw_response or b""
        raw_lower = raw_resp.lower()

        # Check for explicit scanner artifact indicator
        if "scanner artifact" in obs_lower:
            return True, "Scanner artifact: residual baseline response bytes detected on socket."

        # Check for residual HTML body fragment from previous baseline request
        html_markers = [b"<!doctype html", b"<html", b"<head", b"<title", b"<script", b"<style", b"<div", b"<body"]
        is_html_fragment = any(marker in raw_lower for marker in html_markers)
        is_residual_mention = (
            "residual pipeline leak" in obs_lower
            or "residual html body fragment" in obs_lower
            or "residual data leak" in obs_lower
            or "unconsumed response body" in obs_lower
        )

        if is_residual_mention or (is_html_fragment and not raw_resp.startswith(b"HTTP/")):
            return True, "Residual baseline HTML/body bytes from incomplete socket consumption; ordinary framing artifact, not a pipeline leak."

        # Compare directly against baseline response if available
        if baseline_resp:
            baseline_lower = baseline_resp.lower()
            if b"\r\n\r\n" in baseline_resp:
                _, baseline_body = baseline_resp.split(b"\r\n\r\n", 1)
                if baseline_body and raw_resp in baseline_body:
                    return True, "Residual body bytes matching baseline response; ordinary framing artifact."
            if raw_resp and raw_resp in baseline_lower:
                return True, "Anomalous response matches baseline content; ordinary framing artifact."

        # Check for ordinary connection closure after client error (400 Bad Request)
        if anomaly.category == AnomalyCategory.PIPELINE_LEAK:
            if (
                "connection closed by server after candidate probe" in obs_lower
                or "premature connection termination before canary" in obs_lower
            ):
                return True, "Ordinary RFC 9112 Section 9.3 connection teardown on client error rejection; not a vulnerability."
            if "client framing omission" in obs_lower:
                return True, "Client sent un-framed body without Content-Length or Transfer-Encoding; trailing bytes are an RFC 9112 §6.1 framing omission, not a pipeline leak."

        # Check if probe sent un-framed body without Content-Length or Transfer-Encoding
        raw_probe = anomaly.raw_probe or b""
        if b"\r\n\r\n" in raw_probe:
            probe_lower = raw_probe.lower()
            _, body = raw_probe.split(b"\r\n\r\n", 1)
            if len(body.strip()) > 0 and b"content-length" not in probe_lower and b"transfer-encoding" not in probe_lower:
                return True, "Probe contains body without Content-Length or Transfer-Encoding; trailing bytes are un-framed per RFC 9112 Section 6.1, not a server vulnerability."

        return False, ""

    def validate_evidence(
        self,
        vuln: ReproducibleVulnerability,
        anomaly: ImplementationAnomaly,
        baseline_resp: Optional[bytes] = None,
    ) -> Tuple[bool, str]:
        """
        Evidence Validator: Confirms that anomalous bytes cannot be explained by
        ordinary response framing before allowing classification as a confirmed vulnerability
        or publication of defensive rules.
        """
        is_artifact, reason = self.is_framing_artifact(anomaly, baseline_resp)
        if is_artifact:
            return False, f"Anomalous bytes explained by ordinary response framing: {reason}"

        if vuln.reproducibility_rate < 0.66:
            return False, f"Low reproducibility rate ({vuln.reproducibility_rate:.1%}); network flake or non-deterministic behavior."

        # Stage 3: Metamorphic validity gate
        if anomaly.category == AnomalyCategory.METAMORPHIC_VIOLATION:
            obs_lower = anomaly.observed_behavior.lower()
            if (
                "200 vs 400" in obs_lower
                or "returned 400" in obs_lower
                or "rfc-compliant rejection" in obs_lower
            ):
                return False, (
                    "Stage 3 Metamorphic Validity Gate: Status difference (200 vs 400) reflects RFC-compliant "
                    "server rejection of modified syntax under RFC 9112 Section 5.1/5.5; not evidence of a vulnerability."
                )

        # For pipeline leaks / queue desync, verify that desynchronization was actually demonstrated
        if (
            vuln.impact in (ImpactClass.QUEUE_POISONING, ImpactClass.DESYNCHRONIZATION)
            or anomaly.category == AnomalyCategory.PIPELINE_LEAK
            or "pipeline leak" in anomaly.observed_behavior.lower()
        ):
            probe_lower = vuln.minimized_probe.lower()
            has_desync_vectors = (
                (b"transfer-encoding" in probe_lower and b"content-length" in probe_lower)
                or b"canary" in probe_lower
                or b"terminator_marker" in probe_lower
                or (b"transfer-encoding" in probe_lower and b"chunk" in probe_lower)
            )
            if not has_desync_vectors:
                return False, "Unvalidated pipeline leak: does not exhibit verified cross-request queue desynchronization or conflicting framing headers."

        return True, "Evidence verified: anomaly cannot be explained by ordinary response framing."

    def filter_environmental_noise(
        self,
        anomaly: ImplementationAnomaly,
        baseline_is_healthy: bool,
        socket_error_type: Optional[str] = None,
        baseline_resp: Optional[bytes] = None,
    ) -> bool:
        """
        Determines if an anomaly is caused by environmental noise (e.g. OS port exhaustion,
        server crash/shutdown, transient connection refusal, or leftover framing bytes).
        Returns True if it IS environmental noise / framing artifact (should be discarded).
        """
        if not baseline_is_healthy:
            # If server cannot handle even a clean baseline request, network/target is degraded
            anomaly.is_environmental_noise = True
            return True

        if socket_error_type in ("WSAEADDRINUSE", "ECONNREFUSED", "WSAENOBUFS"):
            anomaly.is_environmental_noise = True
            return True

        # Check for response framing artifacts
        is_artifact, reason = self.is_framing_artifact(anomaly, baseline_resp)
        if is_artifact:
            anomaly.is_environmental_noise = True
            anomaly.observed_behavior += f" [DISCARDED_AS_FRAMING_ARTIFACT: {reason}]"
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
