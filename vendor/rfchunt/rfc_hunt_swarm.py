import argparse
import operator
import time
from typing import Annotated, Any, Dict, List, Optional, TypedDict

from langgraph.graph import END, StateGraph

# External/Core components from original continuous_scanner
from database import Database
from forensics import ForensicLogger
from permutator import VectorPermutator
from probe_generator import ProbeGenerator
from rfc_chunker import RFCChunker
from rfc_fetcher import RFCFetcher
from cascade import DiscoveryCascade

# 12 Engine Modules
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
    ImplementationAnomaly,
    NovelTechnique,
    ReproducibleVulnerability,
)

# 1. State Definition (Encompassing all original functionality)
class ResearchState(TypedDict):
    rfc_num: str
    rfc_text: str
    fragments: List[str]
    current_fragment: str
    generated_candidates: List[Dict[str, Any]]
    current_probe: bytes
    reward: float
    current_anomaly: Optional[ImplementationAnomaly]
    current_vuln: Optional[ReproducibleVulnerability]
    novel_technique_found: Optional[str]
    cascade_results: Optional[Dict[str, Any]]
    cycle_count: int
    max_cycles: int
    history: Annotated[List[str], operator.add]


class ProtocolResearchSwarm:
    def __init__(self, host: str, port: int, db_path: str = "terminator.db", sec_model: Optional[str] = None):
        self.host = host
        self.port = port
        
        # Original Scanner Core Components
        self.db = Database(db_path)
        self.fetcher = RFCFetcher(db=self.db)
        self.generator = ProbeGenerator(preferred_model="gemma2:2b", use_fusion=True, db=self.db, sec_model=sec_model)
        self.permutator = VectorPermutator(db=self.db)
        self.cascade_engine = DiscoveryCascade(preferred_model="gemma2:2b", use_fusion=True, db=self.db)
        self.forensics = ForensicLogger(target_host=host, target_port=port)
        
        # The 12 Protocol Research Modules
        self.abnf = ABNFGrammarEngine()
        self.bandit = AdaptiveBanditScheduler()
        self.compiler = SemanticConstraintCompiler()
        self.oracle = MultiImplementationDifferentialOracle(
            targets=[TargetEndpoint(name="Primary", host=host, port=port)]
        )
        self.sequence_engine = StatefulProtocolSequenceEngine()
        self.errata = RFCEvolutionTracker()
        self.metamorphic = MetamorphicTestingEngine()
        self.debugger = DeltaDebugger(host, port)
        self.classifier = CausalAnomalyClassifier()
        self.boundary = CrossProtocolBoundaryAnalyzer()
        self.knowledge_graph = ResearchKnowledgeGraph()
        self.publisher = DefensiveIntelligencePublisher()

    # Agent 1: Fetch and Chunk (Replaces manual string entry)
    def fetch_and_chunk_agent(self, state: ResearchState) -> dict:
        rfc_num = int(state.get("rfc_num", "9112").replace("RFC", ""))
        # Fetch actual text
        rfc_text = self.fetcher.fetch_rfc_by_number(rfc_num)
        
        # Mod 1 & 3: Extractor / Compiler
        self.knowledge_graph.add_node(f"RFC{rfc_num}", "RFC", f"Specification RFC{rfc_num}")
        abnf_reqs = self.abnf.extract_from_rfc_text(f"RFC{rfc_num}", rfc_text)
        for req in abnf_reqs:
            self.knowledge_graph.add_node(req.requirement_id, "REQUIREMENT", req.raw_statement[:40])
            self.knowledge_graph.add_edge(f"RFC{rfc_num}", req.requirement_id, "DEFINES")

        # Chunk for LLM Generator
        fragments = RFCChunker.chunk_document(rfc_text)
        self.db.save_fragments(f"RFC{rfc_num}", fragments)
        
        return {
            "rfc_text": rfc_text,
            "fragments": fragments,
            "history": [f"fetch_and_chunk: Fetched RFC{rfc_num}, Extracted {len(abnf_reqs)} ABNF rules, Chunked into {len(fragments)} fragments."]
        }

    # Agent 2: LLM Probe Generation (Original Generator)
    def llm_generator_agent(self, state: ResearchState) -> dict:
        fragments = state.get("fragments", [])
        if not fragments:
            return {"history": ["llm_generator: No fragments left to process."]}
        
        current_frag_tuple = fragments.pop(0)
        frag_text = current_frag_tuple[0] if isinstance(current_frag_tuple, tuple) else current_frag_tuple
        
        # Call Local LLM to generate probes based on this RFC fragment
        llm_probes = self.generator.generate_candidate_probes(frag_text)
        
        # Permutate them
        all_candidates = []
        for p in llm_probes:
            perms = self.permutator.permute_probe(p)
            all_candidates.extend(perms)
            
        return {
            "fragments": fragments,
            "current_fragment": frag_text,
            "generated_candidates": all_candidates,
            "history": [f"llm_generator: Fragment processed. LLM yielded {len(llm_probes)} base probes -> {len(all_candidates)} permuted candidates."]
        }

    # Route: Check if we have candidates to test
    def route_after_generation(self, state: ResearchState) -> str:
        cands = state.get("generated_candidates", [])
        if not cands:
            # If no candidates were generated, loop back if fragments remain, else end
            if not state.get("fragments"):
                return END
            return "llm_generator_agent"
        return "execution_oracle_agent"

    # Agent 3: Execution and Differential Oracle (Combines sequence and metamorphic)
    def execution_oracle_agent(self, state: ResearchState) -> dict:
        cands = state.get("generated_candidates", [])
        if not cands:
            return {"history": ["execution_oracle: No candidates to execute."]}
        
        # Pop one candidate to test
        candidate = cands.pop(0)
        probe_bytes = candidate.get("raw_request", b"")
        if isinstance(probe_bytes, str):
            probe_bytes = probe_bytes.encode('latin-1', errors='replace')
            
        # Run stateful pipeline engine (Mod 5)
        seq_report = self.sequence_engine.run_pipelined_canary_sequence(self.host, self.port, probe_bytes)
        
        anomaly = None
        if seq_report.has_desynchronization or seq_report.has_pipeline_leak:
            anomaly = ImplementationAnomaly(
                anomaly_id=f"ANOM-SEQ-{int(time.time() * 1000)}",
                target_engine=f"{self.host}:{self.port}",
                category=AnomalyCategory.PIPELINE_LEAK if seq_report.has_pipeline_leak else AnomalyCategory.PARSER_DIVERGENCE,
                observed_behavior=seq_report.details,
                expected_behavior="Clean request separation.",
                raw_probe=probe_bytes,
                raw_response=seq_report.steps[-1].received_bytes if seq_report.steps else b"",
            )
            
        # Fallback to Metamorphic Oracle (Mod 7/4) if no sequence anomaly
        if not anomaly:
            meta_results = self.metamorphic.test_metamorphic_invariance(self.host, self.port, probe_bytes)
            for mr, is_valid, reason, meta_anomaly in meta_results:
                if not is_valid and meta_anomaly:
                    anomaly = meta_anomaly
                    break
        
        if anomaly:
            # SAVE to Database exactly like the original code
            self.db.save_implementation_anomaly(
                anomaly_id=anomaly.anomaly_id,
                target_engine=anomaly.target_engine,
                category=anomaly.category.value,
                observed_behavior=anomaly.observed_behavior,
                expected_behavior=anomaly.expected_behavior,
                raw_probe=anomaly.raw_probe.decode("latin-1", errors="replace"),
                raw_response=anomaly.raw_response.decode("latin-1", errors="replace"),
            )
            return {
                "generated_candidates": cands,
                "current_probe": probe_bytes,
                "current_anomaly": anomaly,
                "history": [f"execution_oracle: Tested probe, ANOMALY DETECTED! Saved to DB ({anomaly.anomaly_id})."]
            }

        return {
            "generated_candidates": cands,
            "current_probe": probe_bytes,
            "current_anomaly": None,
            "history": ["execution_oracle: Tested probe, target is healthy/conformant."]
        }

    def route_after_execution(self, state: ResearchState) -> str:
        if state.get("current_anomaly"):
            return "triage_debugger_agent"
        # If no anomaly, keep looping through candidates
        if state.get("generated_candidates"):
            return "execution_oracle_agent"
        
        # Cycle count logic
        cc = state.get("cycle_count", 0) + 1
        if cc >= state.get("max_cycles", 3):
            return END
            
        # Get more from LLM
        return "llm_generator_agent"

    # Agent 4: Triage & Delta Debugger (Mods 8 & 9)
    def triage_debugger_agent(self, state: ResearchState) -> dict:
        anomaly = state["current_anomaly"]
        
        # Noise filter
        is_noise = self.classifier.filter_environmental_noise(anomaly, baseline_is_healthy=True)
        if is_noise:
            return {"current_anomaly": None, "history": ["triage_debugger: Discarded anomaly as environmental noise."]}
            
        # Minimize (Mod 8)
        vuln = self.debugger.minimize_and_reproduce(anomaly, max_verification_trials=3)
        if vuln.reproducibility_rate >= 0.66:
            # SAVE to Database
            self.db.save_reproducible_vulnerability(
                vuln_id=vuln.vuln_id,
                anomaly_id=anomaly.anomaly_id,
                impact=vuln.impact.value,
                minimized_probe=vuln.minimized_probe.decode("latin-1", errors="replace"),
                reproducibility_rate=vuln.reproducibility_rate,
                verification_attempts=vuln.verification_attempts,
                successful_reproductions=vuln.successful_reproductions,
                delta_debug_steps=vuln.delta_debug_steps,
                provenance_chain=vuln.provenance_chain,
            )
            
            # Novelty Classifier (Mod 9)
            is_novel, tech = self.classifier.classify_novelty(vuln)
            novel_name = None
            if is_novel and tech:
                self.db.save_novel_technique(
                    technique_id=tech.technique_id, title=tech.title,
                    conceptual_model=tech.conceptual_model, inversion_pattern=tech.inversion_pattern,
                    affected_architectures=tech.affected_architectures, supporting_vulnerabilities=tech.supporting_vulnerabilities,
                    recommended_mitigation=tech.recommended_mitigation
                )
                novel_name = tech.title
                
            return {
                "current_vuln": vuln, 
                "novel_technique_found": novel_name, 
                "history": [f"triage_debugger: Confirmed Vulnerability {vuln.vuln_id}! Saved to DB."]
            }
        
        return {"current_vuln": None, "history": ["triage_debugger: Failed reproducibility verification."]}

    def route_after_triage(self, state: ResearchState) -> str:
        if state.get("current_vuln"):
            return "cascade_and_publish_agent"
        # If discarded or failed to reproduce, keep testing
        if state.get("generated_candidates"):
            return "execution_oracle_agent"
        return "llm_generator_agent"

    # Agent 5: Discovery Cascade, Knowledge Graph, Publish, & Forensics
    def cascade_and_publish_agent(self, state: ResearchState) -> dict:
        vuln = state["current_vuln"]
        anomaly = state["current_anomaly"]
        frag_text = state.get("current_fragment", "")
        rfc_num = state.get("rfc_num", "9112").replace("RFC", "")
        
        # 1. Cascade (LLM extrapolation)
        cascade_res = self.cascade_engine.cascade_from_finding({
            "rationale": "Swarm detected vulnerability.",
            "rfc_fragment": frag_text,
            "details": anomaly.observed_behavior,
        })
        
        # 2. Update Knowledge Graph (Mod 11)
        self.knowledge_graph.add_node(vuln.vuln_id, "VULNERABILITY", f"{vuln.impact.value} ({vuln.vuln_id})")
        self.knowledge_graph.add_edge(anomaly.anomaly_id, vuln.vuln_id, "PROVES_VULN")
        
        # 3. Publish Arm 106 & 107 (Mod 12)
        arm106, arm107 = self.publisher.publish_finding(vuln, rfc_anchor=f"RFC{rfc_num}")
        
        # 4. Forensic Logging (Original functionality)
        self.forensics.record_finding(
            rfc_num=int(rfc_num) if rfc_num.isdigit() else 0,
            rfc_fragment=frag_text,
            rationale="Swarm node detection",
            raw_request=vuln.minimized_probe.decode('latin-1', errors='replace'),
            is_vuln=True,
            desync_class=vuln.impact.value,
            details=anomaly.observed_behavior,
            metadata={"arm106": arm106.rule_id, "arm107": arm107.test_id},
            weaponization=None,
            cascade=cascade_res,
            concept_analysis=None
        )
        self.forensics.save_forensic_report()

        cc = state.get("cycle_count", 0) + 1
        return {
            "cascade_results": cascade_res,
            "cycle_count": cc,
            "history": [f"cascade_publish: Ran Cascade, Published rules ({arm106.rule_id}), and saved Forensic trace!"]
        }

    def route_after_publish(self, state: ResearchState) -> str:
        # Check cycles or go back to testing candidates
        if state.get("cycle_count", 0) >= state.get("max_cycles", 3):
            return END
        if state.get("generated_candidates"):
            return "execution_oracle_agent"
        return "llm_generator_agent"


    def build_graph(self) -> StateGraph:
        builder = StateGraph(ResearchState)

        # Add Nodes
        builder.add_node("fetch_and_chunk_agent", self.fetch_and_chunk_agent)
        builder.add_node("llm_generator_agent", self.llm_generator_agent)
        builder.add_node("execution_oracle_agent", self.execution_oracle_agent)
        builder.add_node("triage_debugger_agent", self.triage_debugger_agent)
        builder.add_node("cascade_and_publish_agent", self.cascade_and_publish_agent)

        # Edges
        builder.set_entry_point("fetch_and_chunk_agent")
        builder.add_edge("fetch_and_chunk_agent", "llm_generator_agent")
        
        builder.add_conditional_edges("llm_generator_agent", self.route_after_generation)
        builder.add_conditional_edges("execution_oracle_agent", self.route_after_execution)
        builder.add_conditional_edges("triage_debugger_agent", self.route_after_triage)
        builder.add_conditional_edges("cascade_and_publish_agent", self.route_after_publish)

        return builder.compile()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
===============================================================================
RFC HUNT SWARM: Specification-Driven Autonomous Protocol Research Engine
===============================================================================
A LangGraph-orchestrated 12-agent research swarm that:
  1. Fetches and parses normative RFC specifications and ABNF grammars.
  2. Generates novel protocol edge-cases using ModelFusion (Gemma + Foundation-Sec).
  3. Executes stateful pipelined sequences and metamorphic differential oracles.
  4. Automatically delta-debugs, minimizes, and verifies reproducible vulnerabilities.
  5. Formulates novel architectural concepts and publishes Arm 106 & 107 defenses.
""",
        epilog="""
===============================================================================
USAGE EXAMPLES:
===============================================================================

1. Scan a single RFC against the local target:
   python -u rfc_hunt_swarm.py --mode single --rfc 9112

2. Scan the curated James Kettle Research Corpus (138 core HTTP/SMTP RFCs):
   python -u rfc_hunt_swarm.py --mode corpus

3. Scan ALL active IETF protocol specifications (HTTP, TLS, WebSockets, etc.):
   python -u rfc_hunt_swarm.py --mode all

4. Scan with an extended 15-minute timeout for large (16GB) security models:
   python -u rfc_hunt_swarm.py --mode corpus --timeout 900

5. Scan with UNLIMITED timeout (disables timeout aborts completely):
   python -u rfc_hunt_swarm.py --mode corpus --timeout 0

6. Use a faster 4.7GB secondary security specialist model:
   python -u rfc_hunt_swarm.py --mode corpus --sec-model qwen2.5:7b

7. Target a custom host and port:
   python -u rfc_hunt_swarm.py --mode single --rfc 7230 --host 127.0.0.1 --port 8080

8. Run an intensive deep-search with 10 mutation cycles per RFC:
   python -u rfc_hunt_swarm.py --mode corpus --cycles 10
===============================================================================
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--rfc", type=str, default="9112", help="Specific RFC ID to analyze (e.g. 9112)")
    parser.add_argument("--mode", type=str, choices=["single", "corpus", "all"], default="single", help="Scan mode: single RFC, Kettle corpus, or all protocol RFCs")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=5006, help="Target port")
    parser.add_argument("--cycles", type=int, default=3, help="Max mutation cycles to run per RFC")
    parser.add_argument("--timeout", type=float, default=900.0, help="Ollama LLM inference timeout in seconds (default: 900.0 = 15m; 0 for unlimited)")
    parser.add_argument("--sec-model", type=str, default=None, help="Secondary security specialist model (e.g. fenkohq/foundation-sec-8b:latest, qwen2.5:7b, strix-qwen:latest)")
    args = parser.parse_args()

    import os
    os.environ["OLLAMA_TIMEOUT"] = str(args.timeout)

    print(f"[*] Initializing Full LangGraph Swarm against {args.host}:{args.port} (LLM Timeout: {'Unlimited' if args.timeout <= 0 else f'{args.timeout}s'})")
    swarm = ProtocolResearchSwarm(host=args.host, port=args.port, db_path="terminator.db", sec_model=args.sec_model)
    graph = swarm.build_graph()
    
    # Determine which RFCs to scan based on the selected mode
    if args.mode == "single":
        rfcs_to_scan = [args.rfc.replace("RFC", "")]
    elif args.mode == "corpus":
        print("[*] Resolving James Kettle Research Corpus...")
        rfcs_to_scan = swarm.fetcher.get_kettle_corpus()
    elif args.mode == "all":
        print("[*] Discovering all active protocol RFCs from IETF registry...")
        rfcs_to_scan = swarm.fetcher.discover_active_protocol_rfcs(unrestricted=False)
        
    print(f"\n[*] Queue ready: {len(rfcs_to_scan)} RFC(s) scheduled for Swarm processing.\n" + "="*60)

    for rfc_item in rfcs_to_scan:
        rfc_num_str = str(rfc_item)
        print(f"\n[*] --- Initiating Swarm Cycle for RFC {rfc_num_str} ---")
        
        initial_state = {
            "rfc_num": rfc_num_str,
            "rfc_text": "",
            "fragments": [],
            "current_fragment": "",
            "generated_candidates": [],
            "current_probe": b"",
            "reward": 0.0,
            "current_anomaly": None,
            "current_vuln": None,
            "novel_technique_found": None,
            "cascade_results": None,
            "cycle_count": 0,
            "max_cycles": args.cycles,
            "history": []
        }

        try:
            for event in graph.stream(initial_state, {"recursion_limit": 5000}):
                for node_name, state_update in event.items():
                    last_hist = state_update.get('history', [])[-1] if state_update.get('history') else ''
                    print(f"[{node_name}] -> {last_hist}")
                    if "current_vuln" in state_update and state_update["current_vuln"]:
                        print(f"    !!! VULNERABILITY CONFIRMED: {state_update['current_vuln'].vuln_id}")
        except Exception as e:
            print(f"[!] Swarm encountered a critical fault on RFC {rfc_num_str}: {e}")
            continue
            
    print("\n[*] Swarm Execution Completed. All evidence saved to DB and Forensics Log.")
