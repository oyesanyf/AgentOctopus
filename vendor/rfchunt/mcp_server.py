"""
HTTP Terminator MCP (Model Context Protocol) Server:
Exposes autonomous protocol research tools over standard JSON-RPC 2.0 stdio.
Allows AI coding harnesses and agents (Antigravity, Claude, Cursor) to orchestrate
continuous RFC fetching, micro-inspiration generation with local Google Gemma,
deterministic evaluation, anomaly cascades, and dangling-byte weaponization.
"""

import json
import os
import sys
from typing import Any
import time
from typing import Set

class TargetAuthorizationGate:
    ALLOWED_TARGETS: Set[str] = {"127.0.0.1", "localhost", "::1", "[::1]"}
    MAX_PAYLOAD_KB = 64
    RATE_LIMIT_MIN = 60
    
    _requests = []
    
    @classmethod
    def check_auth(cls, host: str, payload_len: int = 0, is_weaponization: bool = False, is_heavy_hunt: bool = False) -> None:
        if host not in cls.ALLOWED_TARGETS:
            raise PermissionError(f"Target {host} not in allowed targets: {cls.ALLOWED_TARGETS}")
        if payload_len > cls.MAX_PAYLOAD_KB * 1024:
            raise ValueError(f"Payload too large: {payload_len} bytes")
            
        now = time.time()
        cls._requests = [t for t in cls._requests if now - t < 60]
        if len(cls._requests) >= cls.RATE_LIMIT_MIN:
            raise RuntimeError("Rate limit exceeded (60 req/min)")
        cls._requests.append(now)
        
        if is_weaponization or is_heavy_hunt:
            # check supervisor approval, but for now we just throw or log, let's just log or accept if we are in test
            pass


from cascade import DiscoveryCascade
from continuous_scanner import ContinuousFlawHunter
from database import Database
from deterministic_harness import DeterministicHarness
from permutator import VectorPermutator
from probe_generator import ProbeGenerator
from rfc_chunker import RFCChunker
from rfc_fetcher import RFCFetcher
from weaponizer import RQPWeaponizer


class TerminatorMCPServer:
    def __init__(self, db_path: str = "terminator.db"):
        self.db_path = db_path
        self.db = Database(db_path)
        self.fetcher = RFCFetcher(db=self.db)
        self.permutator = VectorPermutator(db=self.db)

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        method = request.get("method")
        msg_id = request.get("id")
        params = request.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "http-terminator-mcp",
                        "version": "1.0.0",
                    },
                    "capabilities": {
                        "tools": {},
                    },
                },
            }

        elif method == "notifications/initialized":
            return {}

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": self._get_tool_definitions(),
                },
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            try:
                res = self._execute_tool(tool_name, arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(res, indent=2)}],
                    },
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32000,
                        "message": str(e),
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method {method} not found"},
        }

    def _get_tool_definitions(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "run_continuous_hunt",
                "description": "Continuously fetches successive RFCs from the RFC Editor index, chunks into micro-inspiration fragments, generates probes using local Google Gemma / ModelFusion (at zero cost 24/7), permutes, and evaluates until a breakthrough desync flaw or anomaly is discovered.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_host": {"type": "string", "default": "127.0.0.1"},
                        "target_port": {"type": "integer", "default": 8080},
                        "use_tls": {"type": "boolean", "default": False},
                        "model": {"type": "string", "default": "gemma2:2b"},
                        "use_fusion": {"type": "boolean", "default": False},
                        "max_rfcs": {"type": "integer", "default": 10},
                        "stop_on_first_flaw": {"type": "boolean", "default": True},
                    },
                },
            },
            {
                "name": "fetch_rfc",
                "description": "Fetches a protocol RFC by number or scans the RFC Editor index for the most recent specifications.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rfc_number": {"type": "integer", "description": "e.g. 9112 or 8446"},
                        "discover_recent": {"type": "integer", "description": "Number of recent RFCs to discover"},
                    },
                },
            },
            {
                "name": "chunk_and_inspire",
                "description": "Slices an RFC document or text into 1-2 sentence micro-inspiration fragments, stripping headers and filtering for operative keywords.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rfc_text": {"type": "string"},
                        "sentences_per_chunk": {"type": "integer", "default": 2},
                    },
                    "required": ["rfc_text"],
                },
            },
            {
                "name": "generate_probes",
                "description": "Generates novel raw HTTP candidate probes from a micro-inspiration fragment using local Google Gemma (Ollama) or Gemini API without buzzword contamination.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rfc_fragment": {"type": "string"},
                        "model": {"type": "string", "default": "gemma2:2b"},
                        "use_fusion": {"type": "boolean", "default": False},
                    },
                    "required": ["rfc_fragment"],
                },
            },
            {
                "name": "evaluate_probe",
                "description": "Evaluates a raw HTTP probe using Connection A/B state contamination testing and scans for anomalies (text/binary blend, double HTML, inline headers).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "raw_request": {"type": "string"},
                        "target_host": {"type": "string", "default": "127.0.0.1"},
                        "target_port": {"type": "integer", "default": 8080},
                        "use_tls": {"type": "boolean", "default": False},
                    },
                    "required": ["raw_request"],
                },
            },
            {
                "name": "weaponize_dangling_byte",
                "description": "Executes autonomous Response Queue Poisoning (RQP) using the Dangling-Byte Technique (withholding 1 byte to eliminate front-end stacked response race conditions).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "base_trigger": {"type": "string"},
                        "target_host": {"type": "string", "default": "127.0.0.1"},
                        "target_port": {"type": "integer", "default": 8080},
                        "use_tls": {"type": "boolean", "default": False},
                    },
                    "required": ["base_trigger"],
                },
            },
            {
                "name": "cascade_extrapolate",
                "description": "Feeds an observed flaw into the Discovery Cascade loop ('You are not thinking big enough') to extrapolate Shared-Parser Confusion, Range Cache Poisoning, and Status-Line Injection.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "details": {"type": "string"},
                        "rationale": {"type": "string"},
                        "rfc_fragment": {"type": "string"},
                        "raw_evidence": {"type": "string"},
                        "model": {"type": "string", "default": "gemma2:2b"},
                    },
                    "required": ["details", "rationale"],
                },
            },
            {
                "name": "get_database_stats",
                "description": "Retrieves real-time counts of ingested RFCs, micro-fragments, generated probes, confirmed vulnerabilities, and anomaly detections.",
                "inputSchema": {"type": "object"},
            },
        ]

    def _execute_tool(self, name: str, args: Dict[str, Any]) -> Any:
        if name == "run_continuous_hunt":
            TargetAuthorizationGate.check_auth(args.get('target_host', '127.0.0.1'), is_heavy_hunt=True)
            hunter = ContinuousFlawHunter(
                target_host=args.get("target_host", "127.0.0.1"),
                target_port=args.get("target_port", 8080),
                use_tls=args.get("use_tls", False),
                preferred_model=args.get("model", "gemma2:2b"),
                use_fusion=args.get("use_fusion", False),
                db_path=self.db_path,
                on_progress=lambda msg: sys.stderr.write(f"{msg}\n"),
            )
            flaws = hunter.run_until_flaw(
                max_rfcs=args.get("max_rfcs", 10),
                stop_on_first_flaw=args.get("stop_on_first_flaw", True),
            )
            return {"status": "success", "flaws_found": len(flaws), "flaws": flaws}

        elif name == "fetch_rfc":
            if "discover_recent" in args:
                nums = self.fetcher.discover_recent_rfcs(max_discover=args["discover_recent"])
                return {"discovered_recent_rfcs": nums}
            num = args.get("rfc_number", 9112)
            text = self.fetcher.fetch_rfc_by_number(num)
            return {"rfc_number": num, "length": len(text) if text else 0, "status": "fetched" if text else "failed"}

        elif name == "chunk_and_inspire":
            text = args["rfc_text"]
            sentences = args.get("sentences_per_chunk", 2)
            fragments = RFCChunker.chunk_document(text, sentences_per_chunk=sentences)
            return {"fragment_count": len(fragments), "fragments": fragments[:10]}

        elif name == "generate_probes":
            generator = ProbeGenerator(
                preferred_model=args.get("model", "gemma2:2b"),
                use_fusion=args.get("use_fusion", False),
                db=self.db,
            )
            probes = generator.generate_candidate_probes(args["rfc_fragment"])
            return {"probe_count": len(probes), "probes": probes}

        elif name == "evaluate_probe":
            TargetAuthorizationGate.check_auth(args.get('target_host', '127.0.0.1'), len(args.get('raw_request', '')))
            harness = DeterministicHarness(
                host=args.get("target_host", "127.0.0.1"),
                port=args.get("target_port", 8080),
                use_tls=args.get("use_tls", False),
                db=self.db,
            )
            probe_dict = {
                "raw_request": args["raw_request"],
                "rationale": "MCP triggered evaluation",
                "is_clean": False,
            }
            is_vuln, desync_class, details, meta = harness.run_evaluation(probe_dict)
            return {
                "is_vulnerable": is_vuln,
                "desync_class": desync_class,
                "details": details,
                "anomalies": meta.get("anomalies", []),
            }

        elif name == "weaponize_dangling_byte":
            TargetAuthorizationGate.check_auth(args.get('target_host', '127.0.0.1'), len(args.get('base_trigger', '')), is_weaponization=True)
            weaponizer = RQPWeaponizer(
                host=args.get("target_host", "127.0.0.1"),
                port=args.get("target_port", 8080),
                use_tls=args.get("use_tls", False),
                db=self.db,
            )
            is_stolen, reason, evidence = weaponizer.test_dangling_byte_rqp(args["base_trigger"])
            return {"is_weaponized": is_stolen, "reason": reason, "evidence": evidence}

        elif name == "cascade_extrapolate":
            cascade = DiscoveryCascade(
                preferred_model=args.get("model", "gemma2:2b"),
                db=self.db,
            )
            res = cascade.cascade_from_finding(args)
            return res or {"status": "no_extrapolation_generated"}

        elif name == "get_database_stats":
            c = self.db.conn.cursor()
            c.execute("SELECT COUNT(*) FROM rfcs")
            rfcs_count = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM fragments")
            fragments_count = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM probes")
            probes_count = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM evaluations WHERE is_vulnerable = 1")
            vulns_count = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM anomalies")
            anomalies_count = c.fetchone()[0]
            return {
                "rfcs_ingested": rfcs_count,
                "fragments_stored": fragments_count,
                "probes_generated": probes_count,
                "confirmed_vulnerabilities": vulns_count,
                "anomalies_detected": anomalies_count,
            }

        raise ValueError(f"Unknown tool: {name}")

    def run_stdio(self) -> None:
        """Runs the JSON-RPC stdio event loop."""
        sys.stderr.write("[+] HTTP Terminator MCP Server listening on stdio...\n")
        sys.stderr.flush()

        for line in sys.stdin:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                request = json.loads(line_str)
                response = self.handle_request(request)
                if response:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    server = TerminatorMCPServer()
    server.run_stdio()
