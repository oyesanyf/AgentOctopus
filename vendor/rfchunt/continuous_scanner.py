"""
Continuous RFC Discovery Engine:
Keeps fetching canonical and newly published RFCs from the RFC Editor,
chunking them into micro-inspiration fragments, generating novel probes with local
Google Gemma / ModelFusion (at zero cost 24/7), permuting, and evaluating
until breakthrough desync flaws or protocol anomalies are discovered.
"""

import time
from typing import Any, Callable, Dict, List, Optional

from cascade import DiscoveryCascade
from database import Database
from deterministic_harness import DeterministicHarness
from forensics import ForensicLogger
from permutator import VectorPermutator
from probe_generator import ProbeGenerator
from rfc_chunker import RFCChunker
from rfc_fetcher import RFCFetcher
from weaponizer import RQPWeaponizer
from engine.orchestrator import ProtocolResearchOrchestrator
from engine.taxonomy import ImplementationAnomaly, AnomalyCategory


class ContinuousFlawHunter:
    """
    Autonomous engine that keeps fetching RFCs until flaws or anomalies are found.
    """

    def __init__(
        self,
        target_host: str = "127.0.0.1",
        target_port: int = 8080,
        use_tls: bool = False,
        preferred_model: str = "gemma2:2b",
        use_fusion: bool = True,
        db_path: str = "terminator.db",
        on_progress: Optional[Callable[[str], None]] = None,
        verbose: bool = True,
        sec_model: Optional[str] = None,
    ):
        self.target_host = target_host
        self.target_port = target_port
        self.use_tls = use_tls
        self.preferred_model = preferred_model
        self.use_fusion = use_fusion
        self.sec_model = sec_model
        self.verbose = verbose
        self.db = Database(db_path)

        # Initialize Forensic Logging Engine
        self.forensics = ForensicLogger(target_host=target_host, target_port=target_port)
        self.on_progress = on_progress or self.forensics.log

        self.fetcher = RFCFetcher(db=self.db)
        self.generator = ProbeGenerator(preferred_model=preferred_model, use_fusion=use_fusion, sec_model=sec_model, db=self.db)
        self.permutator = VectorPermutator(db=self.db)
        self.harness = DeterministicHarness(
            host=target_host,
            port=target_port,
            use_tls=use_tls,
            db=self.db,
            verbose=verbose,
            on_trace=self.on_progress,
        )
        self.weaponizer = RQPWeaponizer(
            host=target_host, port=target_port, use_tls=use_tls, db=self.db
        )
        self.cascade_engine = DiscoveryCascade(
            preferred_model=preferred_model, use_fusion=use_fusion, db=self.db
        )
        self.research_engine = ProtocolResearchOrchestrator(
            primary_host=target_host, primary_port=target_port
        )

        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def run_until_flaw(
        self,
        max_rfcs: Optional[int] = 15,
        fragments_per_rfc: int = 3,
        permutations_per_probe: int = 2,
        stop_on_first_flaw: bool = True,
        all_active: bool = False,
        unrestricted: bool = False,
        kettle: bool = True,
        keywords: Optional[List[str]] = None,
        resume: bool = True,
        target_rfc: Optional[str] = None,
        comb_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Continuously loops through RFCs until flaws are found.
        When comb_only=True, generates and stores candidate probes into database without testing hosts.
        """
        if comb_only:
            self.on_progress("[*] Mode: Offline RFC Ingestion & Probe Generation (No host packets will be sent).")
        else:
            self.on_progress(f"[*] Starting Autonomous RFC Flaw Hunt on {self.target_host}:{self.target_port}...")
        self.on_progress(f"[*] Using local zero-cost model: {self.preferred_model} (fusion={self.use_fusion})")

        if target_rfc:
            clean_ref = str(target_rfc).strip().upper()
            if clean_ref in ("0", "MCP", "RFC-MCP"):
                rfc_queue = [0]
            else:
                num_part = int(clean_ref.replace("RFC", ""))
                rfc_queue = [num_part]
            self.on_progress(f"[*] Single RFC target selected: RFC {rfc_queue[0]}")
        else:
            # The RFC Queue explicitly starts with RFC-MCP (num 0: Model Context Protocol Specification)
            rfc_queue = [0]

            if keywords:
                self.on_progress(f"[*] Querying RFC Editor index for active RFCs matching: {keywords}...")
                discovered = self.fetcher.get_all_active_rfcs(keywords=keywords, max_rfcs=max_rfcs, reverse=True)
                self.on_progress(f"[+] Discovered {len(discovered)} active RFCs matching keywords.")
            elif kettle and not all_active:
                self.on_progress("[*] Loading James Kettle Curated Corpus: 138 HTTP & SMTP Protocol Specifications...")
                discovered = self.fetcher.get_kettle_corpus(max_rfcs=max_rfcs or 138)
                self.on_progress(f"[+] Total Kettle Corpus RFCs queued: {len(discovered)}")
            else:
                self.on_progress("[*] Indexing active (non-obsoleted) protocol RFCs from RFC Editor repository...")
                discovered = self.fetcher.discover_active_protocol_rfcs(
                    include_tier2=True,
                    max_rfcs=max_rfcs,
                    unrestricted=unrestricted,
                )
                self.on_progress(f"[+] Total Active Protocol RFCs queued: {len(discovered)}")

            for c in discovered:
                if c not in rfc_queue:
                    rfc_queue.append(c)

        if resume:
            already_scanned = set(self.db.get_scanned_rfc_nums())
            unscanned_queue = [num for num in rfc_queue if num not in already_scanned]
            # Always ensure RFC-MCP is preserved if not yet scanned
            if 0 not in already_scanned and 0 not in unscanned_queue:
                unscanned_queue.insert(0, 0)
            self.on_progress(f"[*] Resume status: {len(already_scanned)} RFCs already in database; {len(unscanned_queue)} RFCs queued to evaluate.")
            rfc_queue = unscanned_queue

        confirmed_flaws: List[Dict[str, Any]] = []

        for rfc_num in rfc_queue:
            if self._stop_requested:
                self.on_progress("[!] Stop requested by user.")
                break

            self.on_progress(f"\n=======================================================")
            self.on_progress(f"[+] STEP 1: Ingesting RFC {rfc_num} from RFC Editor...")
            self.on_progress(f"=======================================================")
            rfc_text = self.fetcher.fetch_rfc_by_number(rfc_num)
            if not rfc_text:
                continue

            # 2. Micro-Inspiration Chunking
            fragments = RFCChunker.chunk_document(rfc_text, sentences_per_chunk=2)
            if not fragments:
                self.on_progress(f"[-] No operative fragments found in RFC {rfc_num}. Continuing...")
                continue

            self.on_progress(f"[+] RFC {rfc_num}: Extracted {len(fragments)} micro-inspiration fragments.")
            saved_count = self.db.save_fragments(f"RFC{rfc_num}", fragments)

            # Ingest into 12-Module Research Knowledge Graph (ABNF + Normative Constraints)
            ingest_stats = self.research_engine.ingest_rfc_specification(f"RFC{rfc_num}", rfc_text)
            self.on_progress(
                f"    [Research Knowledge Graph]: Indexed {ingest_stats['abnf_rules_extracted']} ABNF rules and "
                f"{ingest_stats['normative_rules_extracted']} normative assertions."
            )

            # Sample top operative fragments
            selected_fragments = fragments[:fragments_per_rfc]

            for frag_text, keywords in selected_fragments:
                if self._stop_requested:
                    break

                self.on_progress(f"\n[*] Micro-Inspiration [{keywords}]:\n    \"{frag_text[:100]}...\"")

                # 3. Generate Probes with Local Gemma
                try:
                    probes = self.generator.generate_candidate_probes(frag_text)
                except Exception as gen_err:
                    self.on_progress(f"    [!] Error generating probes for fragment: {gen_err}")
                    probes = []
                self.on_progress(f"    -> Generated {len(probes)} novel probes via {self.preferred_model}.")

                all_candidates: List[Dict[str, Any]] = list(probes)

                # 4. Apply Systematic Vector Permutations
                for base_p in probes:
                    variants = self.permutator.permute_probe(base_p, max_variants=permutations_per_probe)
                    all_candidates.extend(variants)

                self.on_progress(f"    -> Total candidate triggers (with permutations): {len(all_candidates)}")

                # In comb-only / offline mode, skip socket evaluation
                if comb_only:
                    self.on_progress(f"    [+] Saved {len(all_candidates)} generated probes into terminator.db (Offline discovery).")
                    continue

                # 5. Deterministic Evaluation against Target
                for candidate in all_candidates:
                    if self._stop_requested:
                        break

                    self.forensics.record_probe_trial()
                    p_rationale = candidate.get("rationale", "")
                    self.on_progress(f"    [*] Evaluating: {p_rationale[:65]}...")

                    try:
                        is_vuln, desync_class, details, meta = self.harness.run_evaluation(candidate)
                    except Exception as eval_err:
                        self.on_progress(f"    [!] Evaluation error for candidate probe: {eval_err}")
                        continue

                    anomalies = meta.get("anomalies", [])
                    has_anomaly = len(anomalies) > 0

                    if is_vuln or has_anomaly:
                        flaw_record = {
                            "rfc_num": rfc_num,
                            "rationale": p_rationale,
                            "raw_request": candidate.get("raw_request"),
                            "is_vulnerable": is_vuln,
                            "desync_class": desync_class,
                            "details": details,
                            "anomalies": anomalies,
                            "timestamp": time.time(),
                        }
                        confirmed_flaws.append(flaw_record)

                        self.on_progress("\n" + "!" * 65)
                        if is_vuln:
                            self.on_progress(f"[!] BREAKTHROUGH FLAW FOUND: {details}")
                            self.on_progress(f"[!] Attack Classification: {desync_class}")
                        if has_anomaly:
                            for a in anomalies:
                                self.on_progress(f"[~] ANOMALY DETECTED: {a['type']} - {a['description']}")
                        self.on_progress("!" * 65)

                        # 6. Autonomous Weaponization with Dangling-Byte
                        weaponization_msg = None
                        if is_vuln and "$PAYLOAD" in candidate.get("raw_request", ""):
                            self.on_progress("[+] Triggering Autonomous RQP Weaponizer (Dangling-Byte Technique)...")
                            is_stolen, w_reason, _ = self.weaponizer.test_dangling_byte_rqp(candidate["raw_request"])
                            self.on_progress(f"    [Weaponization Result]: {w_reason}")
                            weaponization_msg = w_reason
                            flaw_record["weaponization"] = w_reason

                        # 6.5 James Kettle Autonomous Vulnerability Concept Theorization
                        concept_res = None
                        if hasattr(self.generator, "arbiter") and self.generator.arbiter:
                            self.on_progress("[+] ModelFusion Reasoning Arbiter: Formulating Vulnerability Concept (James Kettle Methodology)...")
                            concept_res = self.generator.arbiter.explain_vulnerability_concept(
                                rfc_fragment=frag_text,
                                probe_request=candidate.get("raw_request", ""),
                                baseline_resp=meta.get("baseline_resp", ""),
                                probe_resp=meta.get("attacker_resp", ""),
                                retest_resp=meta.get("polluted_resp", ""),
                                anomalies=anomalies,
                                desync_class=desync_class,
                                details=details,
                            )
                            c_name = concept_res.get("concept_name", desync_class or "Novel Protocol Discrepancy")
                            c_exp = concept_res.get("architectural_explanation", "")
                            self.on_progress(f"    [Attack Concept Name]      : {c_name}")
                            self.on_progress(f"    [Architectural Explanation]: {c_exp[:130]}...")
                            flaw_record["concept_name"] = c_name
                            flaw_record["architectural_explanation"] = c_exp
                            flaw_record["concept_analysis"] = concept_res

                        # 7. Autonomous Discovery Cascade Extrapolation
                        self.on_progress("[+] Feeding finding into Discovery Cascade ('You are not thinking big enough')...")
                        cascade_res = self.cascade_engine.cascade_from_finding({
                            "rationale": p_rationale,
                            "rfc_fragment": frag_text,
                            "details": details,
                            "concept_name": flaw_record.get("concept_name", ""),
                            "architectural_explanation": flaw_record.get("architectural_explanation", ""),
                            "raw_evidence": str(meta),
                        })
                        if cascade_res:
                            self.on_progress(f"    [Cascade Category]: {cascade_res['category']}")
                            self.on_progress(f"    [Cascade Hypothesis]: {cascade_res['hypothesis']}")
                            self.on_progress(f"    [Second-Order Probes Queued]: {len(cascade_res['suggested_probes'])}")
                            flaw_record["cascade"] = cascade_res

                        # 7.5 Specification-Driven 4-Tier Taxonomy Triage & Arm 106/107 Publishing
                        anom_id = f"ANOM-RFC{rfc_num}-{int(time.time()*1000)}"
                        anom_obj = ImplementationAnomaly(
                            anomaly_id=anom_id,
                            target_engine=f"{self.target_host}:{self.target_port}",
                            category=AnomalyCategory.PARSER_DIVERGENCE,
                            observed_behavior=details,
                            expected_behavior="Strict specification conformance",
                            raw_probe=candidate.get("raw_request", "").encode("latin-1", errors="replace"),
                            raw_response=meta.get("attacker_resp", "").encode("latin-1", errors="replace"),
                        )
                        self.db.save_implementation_anomaly(
                            anomaly_id=anom_obj.anomaly_id,
                            target_engine=anom_obj.target_engine,
                            category=anom_obj.category.value,
                            observed_behavior=anom_obj.observed_behavior,
                            expected_behavior=anom_obj.expected_behavior,
                            raw_probe=anom_obj.raw_probe.decode("latin-1", errors="replace"),
                            raw_response=anom_obj.raw_response.decode("latin-1", errors="replace"),
                        )

                        # Delta Debugging Minimization (Mod 8)
                        repro_vuln = self.research_engine.debugger.minimize_and_reproduce(anom_obj, max_verification_trials=3)
                        self.db.save_reproducible_vulnerability(
                            vuln_id=repro_vuln.vuln_id,
                            anomaly_id=anom_obj.anomaly_id,
                            impact=repro_vuln.impact.value,
                            minimized_probe=repro_vuln.minimized_probe.decode("latin-1", errors="replace"),
                            reproducibility_rate=repro_vuln.reproducibility_rate,
                            verification_attempts=repro_vuln.verification_attempts,
                            successful_reproductions=repro_vuln.successful_reproductions,
                            delta_debug_steps=repro_vuln.delta_debug_steps,
                            provenance_chain=repro_vuln.provenance_chain,
                        )

                        # Novelty check (Mod 9)
                        is_novel, tech = self.research_engine.classifier.classify_novelty(repro_vuln)
                        if is_novel and tech:
                            self.db.save_novel_technique(
                                technique_id=tech.technique_id,
                                title=tech.title,
                                conceptual_model=tech.conceptual_model,
                                inversion_pattern=tech.inversion_pattern,
                                affected_architectures=tech.affected_architectures,
                                supporting_vulnerabilities=tech.supporting_vulnerabilities,
                                recommended_mitigation=tech.recommended_mitigation,
                            )
                            self.on_progress(f"    [4-Tier Taxonomy]: Surfaced Novel Technique: {tech.title}")

                        # Publish to Agent Octopus Arms 106 and 107 (Mod 12)
                        arm106_rule, arm107_test = self.research_engine.publisher.publish_finding(repro_vuln, rfc_anchor=f"RFC{rfc_num}")
                        self.on_progress(f"    [Arm 106 Defense Ingestion]: Published {arm106_rule.rule_id} ({arm106_rule.name})")
                        self.on_progress(f"    [Arm 107 Regression Suite]: Published {arm107_test.test_id} (Expected Status: {arm107_test.expected_status_rejection})")

                        # Record Forensic Evidence Artifact
                        self.forensics.record_finding(
                            rfc_num=rfc_num,
                            rfc_fragment=frag_text,
                            rationale=p_rationale,
                            raw_request=candidate.get("raw_request", ""),
                            is_vuln=is_vuln,
                            desync_class=desync_class,
                            details=details,
                            metadata=meta,
                            weaponization=weaponization_msg,
                            cascade=cascade_res,
                            concept_analysis=concept_res,
                        )

                        if stop_on_first_flaw:
                            self.on_progress("\n[+] Target flaw discovered and verified! Halting research cascade.")
                            report_file = self.forensics.save_forensic_report()
                            self.on_progress(f"[+] Forensic Evidence Report saved: {report_file}")
                            self.on_progress(f"[+] Full Run Log saved: {self.forensics.log_file}")
                            return confirmed_flaws

        self.on_progress(f"\n[*] Continuous RFC scan cycle finished. Total flaws surfaced: {len(confirmed_flaws)}")
        report_file = self.forensics.save_forensic_report()
        self.on_progress(f"[+] Forensic Evidence Report saved: {report_file}")
        self.on_progress(f"[+] Full Run Log saved: {self.forensics.log_file}")
        return confirmed_flaws
