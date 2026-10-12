"""
HTTP Terminator One-Click Launcher (start.py):
Spawns both:
1. The local Protocol Test Lab Server (127.0.0.1:8080) in the background.
2. The Autonomous Flaw Hunter with local Google Gemma ModelFusion (or the MCP Server if requested).

Starts with the canonical Model Context Protocol (MCP) RFC specification,
ingests fragments, evaluates cross-connection queue contamination,
and executes dangling-byte RQP weaponization.
"""

import argparse
import os
import signal
import sys
import time

from continuous_scanner import ContinuousFlawHunter
from mcp_server import TerminatorMCPServer
from test_lab_server import TestLabServer

# Ensure Windows terminal doesn't crash on UTF-8 RFC characters or BOMs
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="HTTP Terminator: One-Click Dual Launcher (Test Lab + Flaw Hunter / MCP)"
    )
    parser.add_argument("--port", type=int, default=8080, help="Test lab server port (default: 8080)")
    parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    parser.add_argument("--model", default="gemma2:2b", help="Base model (default: gemma2:2b)")
    parser.add_argument("--no-fusion", dest="fusion", action="store_false", help="Disable multi-model panel fusion")
    parser.set_defaults(fusion=True)
    parser.add_argument("--max-rfcs", type=int, default=None, help="Maximum RFCs to cycle through (default: all when --all-active, else 10)")
    parser.add_argument("--fragments", type=int, default=2, help="Fragments per RFC (default: 2)")
    parser.add_argument("--variants", type=int, default=2, help="Permutations per probe (default: 2)")
    parser.add_argument("--keep-going", action="store_true", help="Keep running continuously after finding flaws")
    parser.add_argument("--kettle", dest="kettle", action="store_true", default=True, help="Target James Kettle's curated 138 HTTP and SMTP RFC corpus (default: True)")
    parser.add_argument("--all-active", action="store_true", help="Comb through all 1,259 active RFCs instead of the 138 Kettle corpus")
    parser.add_argument("--unrestricted", action="store_true", help="Scan every active RFC without keyword filtering")
    parser.add_argument("--keywords", default=None, help="Comma-separated keywords to filter active RFCs")
    parser.add_argument("--rfc", default=None, help="Target a specific RFC only (e.g. --rfc 9112 or --rfc MCP)")
    parser.add_argument("--no-resume", dest="resume", action="store_false", help="Do not skip previously scanned RFCs")
    parser.set_defaults(resume=True)
    parser.add_argument("-v", "--verbose", action="store_true", default=True, help="Display live HTTP request/response host activity trace")
    parser.add_argument("--cisco", dest="cisco", action="store_true", default=True, help="Use Cisco Foundation-Sec-8B as the exploit boundary specialist (default: True)")
    parser.add_argument("--no-cisco", dest="cisco", action="store_false", help="Disable Cisco model and fallback to Qwen")
    parser.add_argument("--tls", action="store_true", help="Force TLS/HTTPS for target connections")
    parser.add_argument("--no-lab", action="store_true", help="Do not spawn the built-in mock lab server; target an existing server instead")
    parser.add_argument("--comb-only", "--offline", dest="comb_only", action="store_true", help="Comb through RFCs, chunk fragments, and generate probes into database without testing hosts")
    parser.add_argument("--mcp", action="store_true", help="Launch the MCP server instead of the continuous hunter")
    args = parser.parse_args()

    # Determine TLS requirement (automatic for port 443)
    use_tls = args.tls or (args.port == 443)
    is_local_target = args.host in ("127.0.0.1", "localhost", "0.0.0.0")

    print("=" * 70)
    print("  HTTP TERMINATOR: AUTONOMOUS RESEARCH FACTORY")
    print("  Architecture: PortSwigger DEF CON 34 / Black Hat USA 2026")
    print("  Engine: Google Gemma 2 + ModelFusion via Ollama (Zero Cost 24/7)")
    print("  Starting Spec: RFC-MCP (Model Context Protocol Architecture)")
    print("=" * 70)

    # 1. Start the Local Protocol Test Lab Server (Only when targeting default local port 8080 and not explicitly disabled)
    lab_server = None
    should_spawn_lab = is_local_target and (args.port == 8080) and not args.no_lab and not args.comb_only

    if args.comb_only:
        print("\n[+] Step 1: Mode: Offline RFC Ingestion & Discovery")
        print("    (Host evaluation bypassed - generating and banking probes into database only)")
    elif should_spawn_lab:
        print(f"\n[+] Step 1: Initializing local Protocol Test Lab on http://{args.host}:{args.port}...")
        lab_server = TestLabServer(host=args.host, port=args.port)
        try:
            lab_server.start()
            time.sleep(0.4)
        except Exception as e:
            print(f"[!] Failed to bind lab server: {e}")
            sys.exit(1)
    else:
        proto = "https" if use_tls else "http"
        print(f"\n[+] Step 1: Target Configured: {proto}://{args.host}:{args.port}")
        print("    (Local mock lab bypassed - evaluating existing target directly)")

    # Graceful shutdown handler
    def shutdown(sig=None, frame=None):
        print("\n\n[*] Shutting down HTTP Terminator...")
        if lab_server:
            lab_server.stop()
        print("[+] All services halted safely.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # 2. Launch Hunter or MCP Server
    try:
        if args.mcp:
            print(f"\n[+] Step 2: Launching Model Context Protocol (MCP) Server over stdio...")
            mcp_server = TerminatorMCPServer()
            mcp_server.run_stdio()
        else:
            print(f"\n[+] Step 2: Launching Continuous Flaw Hunter (Starting with RFC-MCP)...")
            sec_model = "fenkohq/foundation-sec-8b:latest" if args.cisco else None
            hunter = ContinuousFlawHunter(
                target_host=args.host,
                target_port=args.port,
                use_tls=use_tls,
                preferred_model=args.model,
                use_fusion=args.fusion,
                verbose=args.verbose,
                sec_model=sec_model,
            )
            keyword_list = [k.strip() for k in args.keywords.split(",")] if args.keywords else None
            max_limit = args.max_rfcs  # None means unlimited / all active RFCs

            flaws = hunter.run_until_flaw(
                max_rfcs=max_limit,
                fragments_per_rfc=args.fragments,
                permutations_per_probe=args.variants,
                stop_on_first_flaw=not args.keep_going,
                all_active=args.all_active,
                unrestricted=args.unrestricted,
                kettle=args.kettle,
                keywords=keyword_list,
                resume=args.resume,
                target_rfc=args.rfc,
                comb_only=args.comb_only,
            )
            if args.comb_only:
                print(f"\n[+] RFC Ingestion & Probe Bank Discovery complete. All candidate triggers saved to database.")
            else:
                print(f"\n[*] Flaw hunt cycle complete. Total discoveries: {len(flaws)}")

    except KeyboardInterrupt:
        shutdown()
    except Exception as e:
        import traceback
        print(f"\n[!] Runtime Error: {e}")
        traceback.print_exc()
        shutdown()


if __name__ == "__main__":
    main()
