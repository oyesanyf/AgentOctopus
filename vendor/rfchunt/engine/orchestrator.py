"""
Unified Protocol Research Engine Orchestrator.

Integrates all 12 modules into a continuous, specification-driven loop:
1. ABNF Grammar Inversion (Mod 1)
2. Adaptive Bandit & Genetic Scheduler (Mod 2)
3. Semantic Constraint Compiler (Mod 3)
4. Multi-Implementation Differential Oracle (Mod 4)
5. Stateful Protocol Sequence Engine (Mod 5)
6. RFC Evolution & Errata Tracker (Mod 6)
7. Metamorphic Testing Engine (Mod 7)
8. Automated Reproducer & Delta Debugger (Mod 8)
9. Causal Anomaly & Novelty Classifier (Mod 9)
10. Cross-Protocol Boundary Analyzer (Mod 10)
11. Coverage & Research Knowledge Graph (Mod 11)
12. Defensive Intelligence Publisher for Arms 106 & 107 (Mod 12)
"""

import time
from typing import Any, Dict, List, Optional, Tuple

from engine.abnf_engine import ABNFGrammarEngine
from engine.bandit_scheduler import AdaptiveBanditScheduler
from engine.boundary_analyzer import CrossProtocolBoundaryAnalyzer
from engine.causal_classifier import CausalAnomalyClassifier
from engine.defensive_publisher import DefensiveIntelligencePublisher
from engine.delta_debugger import DeltaDebugger
from engine.differential_oracle import MultiImplementationDifferentialOracle, TargetEndpoint
from engine.errata_tracker import RFCEvolutionTracker
from engine.knowledge_graph import ResearchKnowledgeGraph
from engine.metamorphic_engine import MetamorphicTestingEngine
from engine.semantic_compiler import SemanticConstraintCompiler
from engine.sequence_engine import StatefulProtocolSequenceEngine
from engine.taxonomy import (
    AnomalyCategory,
    Arm106DefensiveRule,
    Arm107RegressionTest,
    ImplementationAnomaly,
    NovelTechnique,
    ReproducibleVulnerability,
    RFCRequirement,
)


class ProtocolResearchOrchestrator:
    """
    Coordinates specification extraction, autonomous scheduling, multi-engine differential
    verification, stateful sequencing, minimization, and defensive arm publishing.
    """

    def __init__(self, primary_host: str = "127.0.0.1", primary_port: int = 5006):
        self.host = primary_host
        self.port = primary_port

        # Initialize the 12 Modules
        self.abnf = ABNFGrammarEngine()                                 # Mod 1
        self.bandit = AdaptiveBanditScheduler()                         # Mod 2
        self.compiler = SemanticConstraintCompiler()                   # Mod 3
        self.oracle = MultiImplementationDifferentialOracle(            # Mod 4
            targets=[TargetEndpoint(name="Primary", host=primary_host, port=primary_port)]
        )
        self.sequence_engine = StatefulProtocolSequenceEngine()         # Mod 5
        self.errata = RFCEvolutionTracker()                             # Mod 6
        self.metamorphic = MetamorphicTestingEngine()                   # Mod 7
        self.debugger = DeltaDebugger(primary_host, primary_port)       # Mod 8
        self.classifier = CausalAnomalyClassifier()                     # Mod 9
        self.boundary = CrossProtocolBoundaryAnalyzer()                 # Mod 10
        self.knowledge_graph = ResearchKnowledgeGraph()                 # Mod 11
        self.publisher = DefensiveIntelligencePublisher()               # Mod 12

    def ingest_rfc_specification(self, rfc_id: str, rfc_text: str) -> Dict[str, int]:
        """
        Parses RFC text to populate formal ABNF rules and normative constraints
        into the Knowledge Graph.
        """
        # Register RFC Node
        self.knowledge_graph.add_node(rfc_id, "RFC", f"Specification {rfc_id}")

        # Mod 1: Extract ABNF
        abnf_reqs = self.abnf.extract_from_rfc_text(rfc_id, rfc_text)
        for req in abnf_reqs:
            self.knowledge_graph.add_node(req.requirement_id, "REQUIREMENT", req.raw_statement[:40])
            self.knowledge_graph.add_edge(rfc_id, req.requirement_id, "DEFINES")

        # Mod 3: Extract Normative Clauses
        norm_reqs = self.compiler.extract_normative_clauses(rfc_id, rfc_text)
        for req in norm_reqs:
            self.knowledge_graph.add_node(req.requirement_id, "REQUIREMENT", req.raw_statement[:40])
            self.knowledge_graph.add_edge(rfc_id, req.requirement_id, "DEFINES")

        return {
            "abnf_rules_extracted": len(abnf_reqs),
            "normative_rules_extracted": len(norm_reqs),
            "total_requirements": len(abnf_reqs) + len(norm_reqs),
        }

    def execute_research_cycle(self) -> Dict[str, Any]:
        """
        Executes a single end-to-end iteration of the 12-module research lifecycle.
        """
        cycle_result: Dict[str, Any] = {
            "cycle_timestamp": time.time(),
            "arm_selected": "",
            "anomaly_detected": False,
            "vulnerability_confirmed": False,
            "novel_technique": None,
            "arm106_rule_published": None,
            "arm107_test_published": None,
        }

        # Step 1: Mod 2 selects mutation family via UCB1/Thompson
        family = self.bandit.select_arm()
        cycle_result["arm_selected"] = family

        # Step 2: Mod 1 / Mod 10 synthesizes candidate probe based on chosen family
        candidate_probe = self._generate_probe_for_family(family)
        if not candidate_probe:
            return cycle_result

        # Step 3: Mod 5 executes stateful pipelined sequence
        seq_report = self.sequence_engine.run_pipelined_canary_sequence(
            self.host, self.port, candidate_probe
        )

        reward = 0.1
        anomaly: Optional[ImplementationAnomaly] = None

        if seq_report.has_desynchronization or seq_report.has_pipeline_leak:
            reward = 0.8
            anomaly = ImplementationAnomaly(
                anomaly_id=f"ANOM-SEQ-{int(time.time() * 1000)}",
                target_engine=f"{self.host}:{self.port}",
                category=AnomalyCategory.PIPELINE_LEAK if seq_report.has_pipeline_leak else AnomalyCategory.PARSER_DIVERGENCE,
                observed_behavior=seq_report.details,
                expected_behavior="Clean request separation and boundary integrity.",
                raw_probe=candidate_probe,
                raw_response=seq_report.steps[-1].received_bytes if seq_report.steps else b"",
            )

        # Step 4: Mod 7 runs Metamorphic invariance check if no desync found yet
        if not anomaly:
            meta_results = self.metamorphic.test_metamorphic_invariance(self.host, self.port, candidate_probe)
            for mr, is_valid, reason, meta_anomaly in meta_results:
                if not is_valid and meta_anomaly:
                    anomaly = meta_anomaly
                    reward = 0.6
                    break

        # Step 5: Mod 9 Causal Anomaly & Noise Filtering
        if anomaly:
            cycle_result["anomaly_detected"] = True
            is_noise = self.classifier.filter_environmental_noise(anomaly, baseline_is_healthy=True)
            if is_noise:
                cycle_result["details"] = "Anomaly identified as environmental noise; discarded."
                return cycle_result

            # Step 6: Mod 8 Automated Delta Debugging and Reproducibility Verification
            vuln = self.debugger.minimize_and_reproduce(anomaly, max_verification_trials=3)
            if vuln.reproducibility_rate >= 0.66:
                cycle_result["vulnerability_confirmed"] = True
                reward = 1.0

                # Step 7: Mod 6 RFC Evolution & Errata analysis
                lineage = self.errata.explain_anomaly_lineage(anomaly.observed_behavior)

                # Step 8: Mod 9 Novelty classification (e.g. Shared-Parser Confusion)
                is_novel, novel_tech = self.classifier.classify_novelty(vuln)
                if is_novel and novel_tech:
                    cycle_result["novel_technique"] = novel_tech.title

                # Step 9: Mod 11 Knowledge Graph update
                self.knowledge_graph.add_node(vuln.vuln_id, "VULNERABILITY", f"{vuln.impact.value} ({vuln.vuln_id})")
                self.knowledge_graph.add_edge(anomaly.anomaly_id, vuln.vuln_id, "PROVES_VULN")

                # Step 10: Mod 12 Publish to Arms 106 and 107
                arm106_rule, arm107_test = self.publisher.publish_finding(vuln, rfc_anchor="RFC9112")
                cycle_result["arm106_rule_published"] = arm106_rule.rule_id
                cycle_result["arm107_test_published"] = arm107_test.test_id

        # Update bandit feedback loop
        self.bandit.record_feedback(
            family=family,
            reward=reward,
            is_anomaly=cycle_result["anomaly_detected"],
            is_vulnerability=cycle_result["vulnerability_confirmed"],
            payload=candidate_probe,
        )

        return cycle_result

    def _generate_probe_for_family(self, family: str) -> bytes:
        """Dispatches to the specialized generator for the chosen mutation family."""
        if family == "ABNF_INVERSION":
            inversions = self.abnf.generate_inversions("header-field")
            if inversions:
                _, mut = inversions[0]
                return b"GET / HTTP/1.1\r\nHost: " + self.host.encode() + b"\r\n" + mut + b"\r\n"
        elif family == "TE_CL_DUAL_HEADER":
            assertion = self.compiler.get_assertion("ASSERT-RFC9112-TE-CL-PRECEDENCE")
            if assertion:
                return assertion.probe_factory()
        elif family == "CHUNK_EXTENSION_CORRUPTION":
            inversions = self.abnf.generate_inversions("chunk-ext")
            if inversions:
                _, mut = inversions[0]
                return (
                    b"POST / HTTP/1.1\r\nHost: "
                    + self.host.encode()
                    + b"\r\nTransfer-Encoding: chunked\r\n\r\n4"
                    + mut
                    + b"test\r\n0\r\n\r\n"
                )
        elif family == "CRLF_DELIMITER_SPLIT":
            return b"GET / HTTP/1.1\nHost: " + self.host.encode() + b"\n\n"
        elif family == "SHARED_PARSER_REVERSAL":
            return (
                b"HTTP/1.1 200 OK\r\nHost: "
                + self.host.encode()
                + b"\r\nContent-Length: 5\r\n\r\nhello"
            )

        # Fallback to genetic breeding if available
        child = self.bandit.breed_next_generation()
        if child:
            return child

        return b"GET / HTTP/1.1\r\nHost: " + self.host.encode() + b"\r\n\r\n"
