"""
Module 12: Continuous Regression and Defensive Intelligence Publisher (P0).

Transforms verified reproducible vulnerabilities into reusable defensive rules
and automated regression test suites, publishing them directly into
Agent Octopus Arm 106 (Defensive Hardening) and Arm 107 (Continuous Regression Testing).
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from engine.taxonomy import (
    Arm106DefensiveRule,
    Arm107RegressionTest,
    ImpactClass,
    ReproducibleVulnerability,
)


class DefensiveIntelligencePublisher:
    """
    Synthesizes and exports defensive validation signatures for Arm 106
    and regression verification tests for Arm 107.
    """

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir or "data")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.octopus_dir = Path("D:/harfile/AgentOctopus/data") if Path("D:/harfile/AgentOctopus/data").exists() else None
        self.arm106_rules: List[Arm106DefensiveRule] = []
        self.arm107_tests: List[Arm107RegressionTest] = []

    def publish_finding(
        self, vuln: ReproducibleVulnerability, rfc_anchor: str = "RFC9112", evidence_verified: bool = True
    ) -> Tuple[Optional[Arm106DefensiveRule], Optional[Arm107RegressionTest]]:
        """
        Processes a confirmed reproducible vulnerability and synthesizes both
        defensive hardening rules and continuous regression tests.
        Suspends automatic publication if evidence is not confirmed.
        """
        if not evidence_verified:
            print(f"[!] [SUSPENDED] Automatic publication suspended for {vuln.vuln_id}: unverified evidence or framing artifact.")
            return None, None

        # 1. Synthesize Arm 106 Defensive Hardening Rule
        arm106_rule = self._synthesize_arm106_rule(vuln, rfc_anchor)
        self.arm106_rules.append(arm106_rule)

        # 2. Synthesize Arm 107 Regression Test
        arm107_test = self._synthesize_arm107_test(vuln)
        self.arm107_tests.append(arm107_test)

        # 3. Export to filesystem
        self.export_all()

        return arm106_rule, arm107_test

    def _synthesize_arm106_rule(self, vuln: ReproducibleVulnerability, rfc_anchor: str) -> Arm106DefensiveRule:
        """Constructs an Arm 106 parser defense rule (e.g. Rust/Regex/Suricata)."""
        probe_lower = vuln.minimized_probe.lower()
        rule_id = f"OCTO-ARM106-{len(self.arm106_rules) + 1:04d}"

        if b" :" in probe_lower or b"\t:" in probe_lower:
            rule_type = "RUST_PARSER_GUARD"
            rule_body = (
                "// Arm 106 Defense: Pre-colon whitespace rejection\n"
                "if header_name.ends_with(' ') || header_name.ends_with('\\t') {\n"
                "    return Err(ProtocolError::IllegalHeaderWhitespace);\n"
                "}"
            )
            name = "Reject Pre-Colon Whitespace"
        elif b"transfer-encoding" in probe_lower and b"content-length" in probe_lower:
            rule_type = "RUST_PARSER_GUARD"
            rule_body = (
                "// Arm 106 Defense: TE/CL dual-header conflict resolution\n"
                "if headers.contains_key('transfer-encoding') && headers.contains_key('content-length') {\n"
                "    return Err(ProtocolError::ConflictingMessageFraming);\n"
                "}"
            )
            name = "Reject Dual TE/CL Framing"
        elif b"\x00" in vuln.minimized_probe:
            rule_type = "REGEX"
            rule_body = r"[\x00]"
            name = "Ingress Null Byte Stripping"
        else:
            rule_type = "WAF_MODSEC"
            rule_body = f'SecRule REQUEST_HEADERS_NAMES "@rx .*" "id:{rule_id[-4:]},phase:1,deny,status:400"'
            name = f"Hardening Rule for {vuln.impact.value}"

        return Arm106DefensiveRule(
            rule_id=rule_id,
            name=name,
            rule_type=rule_type,
            target_protocol="HTTP/1.1",
            specification_anchor=rfc_anchor,
            rule_body=rule_body,
            severity="CRITICAL" if vuln.impact in (ImpactClass.DESYNCHRONIZATION, ImpactClass.QUEUE_POISONING) else "HIGH",
        )

    def _synthesize_arm107_test(self, vuln: ReproducibleVulnerability) -> Arm107RegressionTest:
        """Constructs an Arm 107 continuous regression assertion."""
        test_id = f"OCTO-ARM107-TEST-{len(self.arm107_tests) + 1:04d}"

        validation_code = (
            f"# Arm 107 Regression Test for {vuln.vuln_id}\n"
            f"def test_{test_id.lower().replace('-', '_')}():\n"
            f"    res = client.send_raw(raw_probe)\n"
            f"    assert res.status_code in [400, 431], f'Expected rejection, got {{res.status_code}}'\n"
        )

        return Arm107RegressionTest(
            test_id=test_id,
            vuln_id=vuln.vuln_id,
            protocol="HTTP/1.1",
            expected_status_rejection=[400, 431],
            probe_bytes=vuln.minimized_probe,
            validation_logic=validation_code,
        )

    def export_all(self) -> Dict[str, str]:
        """Writes data files for Arms 106 and 107."""
        arm106_file = self.output_dir / "defensive_rules_arm106.json"
        arm107_file = self.output_dir / "regression_suite_arm107.json"

        # Serialize Arm 106
        arm106_data = [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "type": r.rule_type,
                "anchor": r.specification_anchor,
                "body": r.rule_body,
                "severity": r.severity,
            }
            for r in self.arm106_rules
        ]
        with open(arm106_file, "w", encoding="utf-8") as f:
            json.dump(arm106_data, f, indent=2)

        # Serialize Arm 107
        arm107_data = [
            {
                "test_id": t.test_id,
                "vuln_id": t.vuln_id,
                "protocol": t.protocol,
                "expected_status": t.expected_status_rejection,
                "raw_probe_hex": t.probe_bytes.hex(),
                "validation_logic": t.validation_logic,
            }
            for t in self.arm107_tests
        ]
        with open(arm107_file, "w", encoding="utf-8") as f:
            json.dump(arm107_data, f, indent=2)

        # Conditionally mirror to AgentOctopus if the directory exists
        if self.octopus_dir:
            try:
                with open(self.octopus_dir / "defensive_rules_arm106.json", "w", encoding="utf-8") as f:
                    json.dump(arm106_data, f, indent=2)
                with open(self.octopus_dir / "regression_suite_arm107.json", "w", encoding="utf-8") as f:
                    json.dump(arm107_data, f, indent=2)
            except Exception:
                pass

        return {
            "arm106_path": str(arm106_file),
            "arm107_path": str(arm107_file),
        }
