"""
HTTP Terminator: Autonomous Protocol Security Research Factory.
Based on PortSwigger's DEF CON 34 / Black Hat USA 2026 research by James Kettle.

Automates:
1. Dynamic RFC Fetching & Ingestion (canonical + recent HTTP specs).
2. Micro-Inspiration Fragmentation & Anti-Anchoring.
3. Zero-Cost Local Inference with Google Gemma & ModelFusion via Ollama.
4. Systematic Vector Permutations (path nul, dual-matching CL, dangling bytes).
5. Deterministic Evaluation Harness (Connection A/B state contamination).
6. Anomaly Detection Cascade (Text/Binary Blend, Double HTML, Inline Headers, Clean Dual-Responses).
7. Autonomous RQP & Dangling-Byte Technique.
8. Discovery Cascade & Shared-Parser Confusion extrapolation.
"""

import argparse
import sys
import time
from typing import Optional

from anomaly_detector import AnomalyDetector
from cascade import DiscoveryCascade
from database import Database
from deterministic_harness import DeterministicHarness
from permutator import VectorPermutator
from probe_generator import ProbeGenerator
from rfc_chunker import RFCChunker
from rfc_fetcher import RFCFetcher
from test_lab_server import TestLabServer
from weaponizer import RQPWeaponizer


def cmd_fetch(args):
    db = Database(args.db)
    fetcher = RFCFetcher(cache_dir=args.cache_dir, db=db)

    print(f"[+] Fetching core RFC documents (limit={args.count})...")
    core_docs = fetcher.fetch_core_rfcs(limit=args.count)
    print(f"[*] Fetched {len(core_docs)} core RFCs.")

    if args.discover_recent:
        print("[+] Scanning RFC index for newly published protocol specifications...")
        recent_nums = fetcher.discover_recent_rfcs(max_discover=args.discover_recent)
        for num in recent_nums:
            fetcher.fetch_rfc_by_number(num)


def cmd_chunk(args):
    db = Database(args.db)
    cursor = db.conn.cursor()
    cursor.execute("SELECT rfc_id, doc_path FROM rfcs")
    rows = cursor.fetchall()

    if not rows:
        print("[-] No RFCs found in database. Run 'fetch' first.")
        return

    total_chunks = 0
    for row in rows:
        rfc_id = row["rfc_id"]
        doc_path = row["doc_path"]
        try:
            with open(doc_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            fragments = RFCChunker.chunk_document(text, sentences_per_chunk=args.sentences)
            saved = db.save_fragments(rfc_id, fragments)
            total_chunks += saved
            print(f"[+] {rfc_id}: Generated and saved {saved} micro-inspiration fragments.")
        except Exception as e:
            print(f"[!] Error chunking {rfc_id}: {e}")

    print(f"[*] Successfully saved {total_chunks} total micro-inspiration fragments.")


def cmd_generate(args):
    db = Database(args.db)
    unprocessed = db.get_unprocessed_fragments(limit=args.limit)

    if not unprocessed:
        print("[-] No unprocessed fragments. Run 'chunk' first.")
        return

    print(f"[+] Generating novel candidate probes from {len(unprocessed)} fragments using {args.model} (fusion={args.fusion})...")
    generator = ProbeGenerator(preferred_model=args.model, use_fusion=args.fusion, db=db)

    total_probes = 0
    for frag in unprocessed:
        frag_id = frag["fragment_id"]
        rfc_id = frag["rfc_id"]
        content = frag["content"]

        print(f"\n[*] Fragment [{rfc_id} #{frag_id}]: {content[:80]}...")
        probes = generator.generate_candidate_probes(content, fragment_id=frag_id)
        for p in probes:
            print(f"    -> [Probe #{p.get('probe_id')}] (Clean: {p['is_clean']}) {p['rationale']}")
            total_probes += 1

    print(f"\n[+] Generated and saved {total_probes} candidate probes.")


def cmd_permute(args):
    db = Database(args.db)
    cursor = db.conn.cursor()
    cursor.execute("SELECT probe_id, fragment_id, rationale, raw_request, is_clean FROM probes WHERE source_type = 'llm' LIMIT ?", (args.limit,))
    rows = [dict(r) for r in cursor.fetchall()]

    if not rows:
        print("[-] No base probes to permute. Run 'generate' first.")
        return

    permutator = VectorPermutator(db=db)
    total_permuted = 0
    for row in rows:
        variants = permutator.permute_probe(row, max_variants=args.variants)
        for v in variants:
            print(f"[+] Permutation #{v.get('probe_id')}: {v['rationale']}")
            total_permuted += 1

    print(f"[*] Generated {total_permuted} permuted probe variants.")


def cmd_evaluate(args):
    db = Database(args.db)
    pending = db.get_pending_probes(target_host=args.target, limit=args.limit)

    if not pending:
        print(f"[-] No pending probes for target {args.target}. Generate probes first or check test history.")
        return

    harness = DeterministicHarness(
        host=args.target,
        port=args.port,
        use_tls=args.tls,
        timeout=args.timeout,
        db=db,
    )

    print(f"[+] Starting deterministic evaluation of {len(pending)} probes against {args.target}:{args.port} (TLS={args.tls})...")

    vulnerable_count = 0
    for row in pending:
        probe_dict = dict(row)
        p_id = probe_dict["probe_id"]
        print(f"\n[*] Evaluating Probe #{p_id}: {probe_dict['rationale'][:70]}...")

        is_vuln, desync_class, details, meta = harness.run_evaluation(probe_dict)
        if is_vuln:
            print(f"    [!] BREAKTHROUGH FINDING: {details}")
            print(f"    [!] Attack Class: {desync_class}")
            vulnerable_count += 1
        else:
            print(f"    [-] Result: {details}")

        if meta.get("anomalies"):
            for anom in meta["anomalies"]:
                print(f"    [~] ANOMALY DETECTED: {anom['type']} - {anom['description']}")

    print(f"\n[*] Evaluation complete: {vulnerable_count} breakthroughs out of {len(pending)} evaluated.")


def cmd_weaponize(args):
    db = Database(args.db)
    weaponizer = RQPWeaponizer(
        host=args.target,
        port=args.port,
        use_tls=args.tls,
        db=db,
    )

    # Use specified raw trigger or search database for confirmed findings
    sample_trigger = (
        "POST / HTTP/1.1\r\n"
        "Host: target.local\r\n"
        "Content-Type: multipart/byteranges; boundary=BOUND\r\n"
        "Content-Length: 120\r\n\r\n"
        "$PAYLOAD"
    )

    print(f"[+] Launching Autonomous RQP with Dangling-Byte Technique on {args.target}:{args.port}...")
    is_stolen, reason, evidence = weaponizer.test_dangling_byte_rqp(sample_trigger)
    if is_stolen:
        print(f"\n[!] WEAPONIZATION SUCCESS: {reason}")
    else:
        print(f"\n[-] Weaponization outcome: {reason}")


def cmd_cascade(args):
    db = Database(args.db)
    confirmed = db.get_confirmed_findings()

    if not confirmed:
        print("[-] No confirmed vulnerable findings yet. Run 'evaluate' to surface discoveries first.")
        # Provide a synthetic finding demo to verify cascade logic if requested
        if args.demo:
            print("[*] Running Cascade Extrapolation demo on Kettle's RFC 2616 multipart/byteranges finding...")
            confirmed = [{
                "eval_id": 1,
                "rationale": "RFC 2616 §19.2 response rule applied in request",
                "rfc_fragment": "The one exception is the 'multipart/byteranges' type when it appears in a 206 response.",
                "details": "Status shift 200 -> 405. Marker reflected in victim stream.",
                "raw_evidence": "HTTP/1.1 200 OK\r\n\r\nTrigger Accepted\n--- POLLUTED ---\nHTTP/1.1 405 Method Not Allowed",
            }]
        else:
            return

    cascade_engine = DiscoveryCascade(preferred_model=args.model, use_fusion=args.fusion, db=db)
    for finding in confirmed:
        f_dict = dict(finding)
        print(f"\n[+] Extrapolating finding #{f_dict.get('eval_id')}: {f_dict.get('details')}")
        result = cascade_engine.cascade_from_finding(f_dict, eval_id=f_dict.get("eval_id"))
        if result:
            print(f"    [Cascade Category]: {result['category']}")
            print(f"    [Hypothesis]: {result['hypothesis']}")
            print(f"    [New Probes Synthesized]: {len(result['suggested_probes'])}")


def cmd_lab(args):
    server = TestLabServer(host=args.host, port=args.port)
    server.start()
    try:
        print("[*] Test Lab Server is active. Press Ctrl+C to stop.")
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        server.stop()


def cmd_auto(args):
    """Continuous research loop: Ingest -> Chunk -> Generate -> Permute -> Evaluate -> Cascade."""
    print("=" * 70)
    print("  HTTP TERMINATOR: AUTONOMOUS PROTOCOL RESEARCH CASCADE ENGINE")
    print("  Model: Google Gemma 2 / Local ModelFusion (Zero-Cost 24/7 Mode)")
    print("=" * 70)

    # 1. Fetch
    cmd_fetch(args)

    # 2. Chunk
    cmd_chunk(args)

    # 3. Generate
    cmd_generate(args)

    # 4. Permute
    cmd_permute(args)

    # 5. Start Lab Server in background if targeting local lab
    lab_server = None
    if args.target == "127.0.0.1" and args.port == 8080:
        lab_server = TestLabServer(host="127.0.0.1", port=8080)
        lab_server.start()
        time.sleep(0.5)

    try:
        # 6. Evaluate
        cmd_evaluate(args)

        # 7. Weaponize
        cmd_weaponize(args)

        # 8. Cascade
        cmd_cascade(args)

    finally:
        if lab_server:
            lab_server.stop()


def cmd_hunt(args):
    """Continuously fetches RFCs and evaluates until flaws are discovered."""
    hunter = ContinuousFlawHunter(
        target_host=args.target,
        target_port=args.port,
        use_tls=args.tls,
        preferred_model=args.model,
        use_fusion=args.fusion,
        db_path=args.db,
    )
    flaws = hunter.run_until_flaw(
        max_rfcs=args.max_rfcs,
        fragments_per_rfc=args.fragments,
        permutations_per_probe=args.variants,
        stop_on_first_flaw=not args.keep_going,
    )
    print(f"\n[*] Hunt complete. Total flaws/anomalies found: {len(flaws)}")


def cmd_mcp(args):
    """Runs the HTTP Terminator MCP Server over stdio."""
    from mcp_server import TerminatorMCPServer
    server = TerminatorMCPServer(db_path=args.db)
    server.run_stdio()


def main():
    parser = argparse.ArgumentParser(description="HTTP Terminator: Autonomous Security Research Engine")
    parser.add_argument("--db", default="terminator.db", help="SQLite database path")
    parser.add_argument("--model", default="gemma2:2b", help="Preferred base model (e.g. gemma2:2b, gemma2:9b, qwen2.5:7b)")
    parser.add_argument("--no-fusion", dest="fusion", action="store_false", help="Disable multi-model panel fusion")
    parser.set_defaults(fusion=True)

    subparsers = parser.add_subparsers(dest="command")

    # Hunt (Continuous until flaws found)
    p_hunt = subparsers.add_parser("hunt", help="Continuously fetch RFCs and hunt for flaws")
    p_hunt.add_argument("--target", default="127.0.0.1", help="Target host")
    p_hunt.add_argument("--port", type=int, default=8080, help="Target port")
    p_hunt.add_argument("--tls", action="store_true", help="Use TLS")
    p_hunt.add_argument("--max-rfcs", type=int, default=15, help="Maximum RFCs to cycle through")
    p_hunt.add_argument("--fragments", type=int, default=3, help="Fragments per RFC")
    p_hunt.add_argument("--variants", type=int, default=2, help="Permutations per probe")
    p_hunt.add_argument("--keep-going", action="store_true", help="Don't stop on first flaw; continue discovering")

    # MCP Server
    p_mcp = subparsers.add_parser("mcp", help="Run MCP Server over JSON-RPC stdio")

    # Fetch
    p_fetch = subparsers.add_parser("fetch", help="Fetch RFC documents")
    p_fetch.add_argument("--count", type=int, default=3, help="Number of core RFCs to fetch")
    p_fetch.add_argument("--cache-dir", default="rfcs", help="Local directory to store RFCs")
    p_fetch.add_argument("--discover-recent", type=int, default=0, help="Discover recent RFCs from index")

    # Chunk
    p_chunk = subparsers.add_parser("chunk", help="Chunk RFCs into micro-inspiration fragments")
    p_chunk.add_argument("--sentences", type=int, default=2, help="Sentences per chunk")

    # Generate
    p_gen = subparsers.add_parser("generate", help="Generate novel probes with LLM")
    p_gen.add_argument("--limit", type=int, default=5, help="Fragments to process")

    # Permute
    p_perm = subparsers.add_parser("permute", help="Apply vector permutations to base probes")
    p_perm.add_argument("--limit", type=int, default=10, help="Base probes to permute")
    p_perm.add_argument("--variants", type=int, default=3, help="Variants per probe")

    # Evaluate
    p_eval = subparsers.add_parser("evaluate", help="Run deterministic evaluation harness")
    p_eval.add_argument("--target", default="127.0.0.1", help="Target host")
    p_eval.add_argument("--port", type=int, default=8080, help="Target port")
    p_eval.add_argument("--tls", action="store_true", help="Use TLS")
    p_eval.add_argument("--timeout", type=float, default=3.0, help="Socket timeout")
    p_eval.add_argument("--limit", type=int, default=20, help="Probes to evaluate")

    # Weaponize
    p_weap = subparsers.add_parser("weaponize", help="Execute dangling-byte RQP")
    p_weap.add_argument("--target", default="127.0.0.1", help="Target host")
    p_weap.add_argument("--port", type=int, default=8080, help="Target port")
    p_weap.add_argument("--tls", action="store_true", help="Use TLS")

    # Cascade
    p_casc = subparsers.add_parser("cascade", help="Run discovery cascade on findings")
    p_casc.add_argument("--demo", action="store_true", help="Run with demonstration finding if none confirmed yet")

    # Lab
    p_lab = subparsers.add_parser("lab", help="Run local test lab server")
    p_lab.add_argument("--host", default="127.0.0.1", help="Host interface")
    p_lab.add_argument("--port", type=int, default=8080, help="Port")

    # Auto
    p_auto = subparsers.add_parser("auto", help="Run complete continuous autonomous loop")
    p_auto.add_argument("--count", type=int, default=3, help="Number of RFCs to fetch")
    p_auto.add_argument("--cache-dir", default="rfcs", help="Local directory to store RFCs")
    p_auto.add_argument("--discover-recent", type=int, default=0, help="Discover recent RFCs")
    p_auto.add_argument("--sentences", type=int, default=2, help="Sentences per chunk")
    p_auto.add_argument("--limit", type=int, default=3, help="Fragments to generate")
    p_auto.add_argument("--variants", type=int, default=2, help="Variants per probe")
    p_auto.add_argument("--target", default="127.0.0.1", help="Target host")
    p_auto.add_argument("--port", type=int, default=8080, help="Target port")
    p_auto.add_argument("--tls", action="store_true", help="Use TLS")
    p_auto.add_argument("--timeout", type=float, default=3.0, help="Socket timeout")
    p_auto.add_argument("--demo", action="store_true", help="Enable cascade demo if needed")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "hunt": cmd_hunt,
        "mcp": cmd_mcp,
        "fetch": cmd_fetch,
        "chunk": cmd_chunk,
        "generate": cmd_generate,
        "permute": cmd_permute,
        "evaluate": cmd_evaluate,
        "weaponize": cmd_weaponize,
        "cascade": cmd_cascade,
        "lab": cmd_lab,
        "auto": cmd_auto,
    }

    dispatch[args.command](args)


if __name__ == "__main__":
    main()
