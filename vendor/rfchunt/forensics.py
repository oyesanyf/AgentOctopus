"""
Forensic Logging & Evidence Capture Engine:
Generates timestamped execution logs and comprehensive forensic evidence JSON
reports per run, including full raw socket requests, connection response diffs,
leaked victim credentials/tokens, and anomaly traces.
"""

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class ForensicLogger:
    """
    Manages dual-output console/file logging and structured JSON forensic reports.
    """

    def __init__(
        self,
        target_host: str,
        target_port: int,
        logs_dir: str = "logs",
        forensics_dir: str = "forensics",
    ):
        self.target_host = target_host
        self.target_port = target_port
        self.start_time = time.time()
        self.start_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.file_timestamp = time.strftime("%Y%m%d_%H%M%S")

        self.logs_path = Path(logs_dir)
        self.forensics_path = Path(forensics_dir)
        self.logs_path.mkdir(parents=True, exist_ok=True)
        self.forensics_path.mkdir(parents=True, exist_ok=True)

        safe_target = re.sub(r"[^a-zA-Z0-9_.-]", "_", f"{target_host}_{target_port}")
        self.log_file = self.logs_path / f"run_{safe_target}_{self.file_timestamp}.log"
        self.json_file = self.forensics_path / f"forensics_{safe_target}_{self.file_timestamp}.json"

        # Forensic ledger
        self.findings: List[Dict[str, Any]] = []
        self.evaluated_probes_count = 0
        self.scanned_rfcs: List[str] = []
        self.anomalies_count = 0

        # Initial log header
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write(f"=== HTTP TERMINATOR FORENSIC RUN LOG ===\n")
            f.write(f"Target: {self.target_host}:{self.target_port}\n")
            f.write(f"Started At: {self.start_timestamp}\n")
            f.write(f"Forensic Report Target: {self.json_file}\n")
            f.write(f"{'=' * 50}\n\n")

    def log(self, message: str) -> None:
        """Dual output: prints to stdout and appends with timestamp to the run log."""
        try:
            sys.stdout.write(message + "\n")
        except UnicodeEncodeError:
            encoding = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
            safe_msg = message.encode(encoding, errors="backslashreplace").decode(encoding)
            sys.stdout.write(safe_msg + "\n")
        sys.stdout.flush()

        # Strip ANSI colors if any
        clean_msg = re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", message)
        t_str = time.strftime("[%H:%M:%S] ")
        with open(self.log_file, "a", encoding="utf-8") as f:
            for line in clean_msg.splitlines():
                f.write(f"{t_str}{line}\n")

    def record_rfc_ingested(self, rfc_id: str, title: str) -> None:
        entry = f"{rfc_id}: {title}"
        if entry not in self.scanned_rfcs:
            self.scanned_rfcs.append(entry)

    def record_probe_trial(self) -> None:
        self.evaluated_probes_count += 1

    def record_finding(
        self,
        rfc_num: Any,
        rfc_fragment: str,
        rationale: str,
        raw_request: str,
        is_vuln: bool,
        desync_class: Optional[str],
        details: str,
        metadata: Dict[str, Any],
        weaponization: Optional[str] = None,
        cascade: Optional[Dict[str, Any]] = None,
        concept_analysis: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Records a comprehensive forensic artifact for a confirmed breakthrough flaw."""
        anomalies = metadata.get("anomalies", [])
        self.anomalies_count += len(anomalies)

        finding_entry = {
            "finding_id": len(self.findings) + 1,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": f"{self.target_host}:{self.target_port}",
            "rfc": f"RFC{rfc_num}",
            "rfc_micro_fragment": rfc_fragment,
            "model_rationale": rationale,
            "raw_probe_request": raw_request,
            "attack_classification": desync_class or "Unclassified",
            "vulnerability_concept_name": concept_analysis.get("concept_name", desync_class or "Unclassified") if concept_analysis else (desync_class or "Unclassified"),
            "architectural_explanation": concept_analysis.get("architectural_explanation", "") if concept_analysis else "",
            "kettle_analysis": concept_analysis,
            "verification_status": "CONFIRMED_VULNERABLE" if is_vuln else "ANOMALY",
            "verification_details": details,
            "forensic_evidence": {
                "baseline_response_snippet": metadata.get("baseline_resp", "")[:1000],
                "attacker_response_snippet": metadata.get("attacker_resp", "")[:1000],
                "polluted_response_snippet": metadata.get("polluted_resp", "")[:1000],
                "anomalies_detected": anomalies,
            },
            "autonomous_weaponization": weaponization,
            "discovery_cascade": cascade,
        }

        self.findings.append(finding_entry)
        self.save_forensic_report()

    def save_forensic_report(self) -> str:
        """Flushes the structured forensic JSON audit report to disk."""
        duration = round(time.time() - self.start_time, 2)
        report_data = {
            "metadata": {
                "engine": "HTTP Terminator (DEF CON 34 Research Factory)",
                "target_host": self.target_host,
                "target_port": self.port_number(),
                "start_time": self.start_timestamp,
                "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration_seconds": duration,
                "total_rfcs_ingested": len(self.scanned_rfcs),
                "total_probes_evaluated": self.evaluated_probes_count,
                "total_breakthrough_flaws": len(self.findings),
                "total_anomalies_detected": self.anomalies_count,
            },
            "ingested_rfc_standards": self.scanned_rfcs,
            "confirmed_breakthrough_findings": self.findings,
        }

        with open(self.json_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        return str(self.json_file)

    def port_number(self) -> int:
        return self.target_port
