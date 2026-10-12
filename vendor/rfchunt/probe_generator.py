"""
LLM Hypothesis & Probe Generator:
Prompts LLMs using micro-inspiration fragments. Strictly avoids buzzwords
('desync', 'request smuggling') to maximize vector novelty and prevent context-contamination.
Integrates with ModelFusionAdapter to run Google Gemma 2 (gemma2:9b, gemma2:2b) and
local security models via Ollama at zero cost 24/7, with Gemini cloud API fallback.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional

from database import Database
from model_adapter import ModelFusionAdapter


class ProbeGenerator:
    """
    Generates novel HTTP protocol probes from micro-inspiration fragments
    using the prompt discipline defined in PortSwigger's HTTP Terminator research.
    """

    SYSTEM_INSTRUCTION = """
You are an expert network protocol state-machine analyzer and specification fuzzing researcher (James Kettle DEF CON 34 methodology).
Your task is to analyze protocol specification snippets as CLUES to construct novel, edge-case raw HTTP requests.
Strict Rules:
1. The vulnerability is NOT written in the RFC. The RFC snippet supplies a clue; the attack concept comes from inverting protocol expectations.
2. Rule Inversion (Shared-Parser Confusion): If the RFC passage discusses HTTP RESPONSES (status lines, 304/204 body suppression, HEAD response length, trailers, response framing), INVERT the behavior into an incoming client REQUEST to test if a shared parser applies response parsing rules to requests.
3. Cross-Protocol Inversion: If the RFC discusses SMTP/MIME (BDAT chunks, dot-stuffing, header line-folding), adapt the delimiter syntax into an HTTP probe.
4. Produce 1 to 3 unique raw HTTP requests that test these edge cases against proxies, load balancers, and backends.
5. Every request must use '\\r\\n' line delimiters and target host 'target.local'.
6. Include '$PAYLOAD' as a placeholder where trailing body or secondary requests can be attached.
7. Tag each probe as is_clean=true if the request is technically valid according to RFC grammar, or is_clean=false if it deliberately violates grammar.
8. Output strict JSON matching: [{"rationale": "...", "raw_request": "...", "is_clean": true/false}].
"""

    def __init__(
        self,
        preferred_model: Optional[str] = None,
        use_fusion: bool = True,
        db: Optional[Database] = None,
        sec_model: Optional[str] = None,
    ):
        self.use_fusion = use_fusion
        self.sec_model = sec_model
        self.adapter = ModelFusionAdapter(preferred_model=preferred_model, use_fusion=use_fusion, sec_model=sec_model)
        self.db = db
        self.arbiter = None
        if self.use_fusion:
            try:
                from fusion_engine import FusionArbiter
                self.arbiter = FusionArbiter(db=self.db, sec_model=sec_model)
            except Exception as e:
                pass

    def generate_candidate_probes(self, rfc_fragment: str, fragment_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Generates edge-case candidate probes from a single micro-fragment.
        If use_fusion is True, executes the full multi-model consensus arbitration protocol.
        """
        if self.use_fusion and self.arbiter:
            arb_result = self.arbiter.run_fusion_pipeline(rfc_fragment, fragment_id)
            if arb_result.fused_probes:
                return arb_result.fused_probes

        user_prompt = f"""
Create HTTP requests that surface state-machine, connection, or buffer edge-cases in webservers and reverse proxies. Novel techniques only.
You must use this inspiration:
\"\"\"{rfc_fragment}\"\"\"

Generate 1 to 3 raw HTTP request templates.
Remember:
- Use host 'target.local'
- Use '$PAYLOAD' placeholder for trailing data or nested secondary request
- Use explicit '\\r\\n' escapes
"""

        try:
            probes_data = self.adapter.generate_json(self.SYSTEM_INSTRUCTION, user_prompt)
            validated_probes = []
            for item in probes_data:
                if not isinstance(item, dict):
                    continue
                raw_req = self._normalize_newlines(item.get("raw_request", ""))
                if not raw_req:
                    continue
                is_clean = bool(item.get("is_clean", False))
                rationale = str(item.get("rationale", "Generated probe"))
                fused_model = item.get("fused_model", self.adapter.active_model)

                probe_dict = {
                    "fragment_id": fragment_id,
                    "rationale": f"[{fused_model}] {rationale}",
                    "raw_request": raw_req,
                    "is_clean": is_clean,
                    "source_type": "llm",
                }

                if self.db:
                    probe_id = self.db.save_probe(
                        fragment_id=fragment_id,
                        rationale=probe_dict["rationale"],
                        raw_request=raw_req,
                        is_clean=is_clean,
                        source_type="llm",
                    )
                    probe_dict["probe_id"] = probe_id

                validated_probes.append(probe_dict)

            return validated_probes

        except Exception as e:
            print(f"[!] Error in LLM probe generation: {e}")
            return []

    def _normalize_newlines(self, text: Any) -> str:
        if not text:
            return ""
        if isinstance(text, dict):
            for key in ("request", "raw", "raw_request", "template", "payload", "data"):
                if key in text and isinstance(text[key], str):
                    text = text[key]
                    break
            else:
                method = text.get("method", "GET")
                path = text.get("path", text.get("uri", "/"))
                version = text.get("version", "HTTP/1.1")
                headers = text.get("headers", {})
                body = text.get("body", "")

                lines = [f"{method} {path} {version}"]
                if isinstance(headers, dict):
                    for k, v in headers.items():
                        lines.append(f"{k}: {v}")
                elif isinstance(headers, list):
                    for h in headers:
                        lines.append(str(h))
                lines.append("")
                if body:
                    lines.append(str(body))
                text = "\r\n".join(lines)
        elif not isinstance(text, str):
            text = str(text)

        if "\\r\\n" in text and "\r\n" not in text:
            try:
                text = text.encode("utf-8").decode("unicode_escape")
            except Exception:
                text = text.replace("\\r\\n", "\r\n")
        return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
