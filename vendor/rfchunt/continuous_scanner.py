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

                        # 7. Autonomous Discovery Cascade Extrapolation
                        self.on_progress("[+] Feeding finding into Discovery Cascade ('You are not thinking big enough')...")
                        cascade_res = self.cascade_engine.cascade_from_finding({
                            "rationale": p_rationale,
                            "rfc_fragment": frag_text,
                            "details": details,
                            "raw_evidence": str(meta),
                        })
                        if cascade_res:
                            self.on_progress(f"    [Cascade Category]: {cascade_res['category']}")
                            self.on_progress(f"    [Cascade Hypothesis]: {cascade_res['hypothesis']}")
                            self.on_progress(f"    [Second-Order Probes Queued]: {len(cascade_res['suggested_probes'])}")
                            flaw_record["cascade"] = cascade_res

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
