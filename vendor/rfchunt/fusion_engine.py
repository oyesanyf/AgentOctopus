"""
ModelFusion Consensus & Arbitration Engine:
Faithfully ported from ModelFusion's Rust CLI architecture (d:\\harfile\\ModelFusion\\crates\\cli\\src\\fusion_arbiter.rs).
Implements multi-model ensemble rollouts, specialist role delegation, and DeepSeek-R1 arbitration:

Specialists:
1. Protocol Specialist: Google Gemma (gemma2:2b / gemma2:9b) - analyzes RFC state machine and grammar.
2. Exploit Boundary Specialist: Foundation-Sec (fenkohq/foundation-sec-8b:latest) or Qwen (qwen2.5:7b).
3. Deep Reasoning Arbiter: DeepSeek-R1 (deepseek-r1:1.5b / strix-deepseek) - synthesizes consensus probes.
"""

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional
import httpx

from database import Database

logger = logging.getLogger("terminator.fusion")


class CandidateProposal:
    def __init__(
        self,
        candidate_id: str,
        model: str,
        specialist_type: str,
        rationale: str,
        raw_request: str,
        is_clean: bool = False,
    ):
        self.candidate_id = candidate_id
        self.model = model
        self.specialist_type = specialist_type
        self.rationale = rationale
        self.raw_request = raw_request
        self.is_clean = is_clean

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.candidate_id,
            "model": self.model,
            "specialist": self.specialist_type,
            "rationale": self.rationale,
            "raw_request": self.raw_request,
            "is_clean": self.is_clean,
        }


class FusionArbitrationResult:
    def __init__(
        self,
        consensus_type: str,
        fused_probes: List[Dict[str, Any]],
        reasoning: str,
        participating_models: List[str],
    ):
        self.consensus_type = consensus_type
        self.fused_probes = fused_probes
        self.reasoning = reasoning
        self.participating_models = participating_models

    def to_dict(self) -> Dict[str, Any]:
        return {
            "consensus_type": self.consensus_type,
            "fused_probes": self.fused_probes,
            "reasoning": self.reasoning,
            "participating_models": self.participating_models,
        }


class FusionArbiter:
    """
    Orchestrates multi-model ensemble generation and DeepSeek-R1 consensus arbitration,
    mirroring crates/cli/src/fusion_arbiter.rs from ModelFusion.
    """

    DEFAULT_OLLAMA_ENDPOINT = "http://127.0.0.1:11434"

    def __init__(
        self,
        endpoint: Optional[str] = None,
        db: Optional[Database] = None,
        sec_model: Optional[str] = None,
    ):
        self.endpoint = endpoint or os.environ.get("OLLAMA_ENDPOINT", self.DEFAULT_OLLAMA_ENDPOINT)
        self.db = db
        timeout_env = os.environ.get("OLLAMA_TIMEOUT", "900.0")
        self.timeout = float(timeout_env) if float(timeout_env) > 0 else None
        self.client = httpx.Client(timeout=httpx.Timeout(self.timeout, connect=60.0))
        self.available_tags = self._fetch_available_tags()

        # Dynamic Model Assignment matching ModelFusion Tiered Scaling
        self.gemma_model = self._resolve_model(["gemma2:2b", "gemma2:9b"], fallback="gemma2:2b")
        if sec_model:
            self.sec_model = sec_model
        else:
            self.sec_model = self._resolve_model(["fenkohq/foundation-sec-8b:latest", "qwen2.5:7b", "strix-qwen:latest", "qwen2.5:32b"], fallback="fenkohq/foundation-sec-8b:latest")
        self.arbiter_model = self._resolve_model(["deepseek-r1:1.5b", "strix-deepseek:latest", "deepseek-r1:32b"], fallback="deepseek-r1:1.5b")

        print(f"[ModelFusion] Panel Initialized:")
        print(f"  - Protocol Specialist : {self.gemma_model}")
        print(f"  - Boundary Specialist : {self.sec_model}")
        print(f"  - Reasoning Arbiter   : {self.arbiter_model}")

    def _fetch_available_tags(self) -> List[str]:
        try:
            resp = httpx.get(f"{self.endpoint}/api/tags", timeout=1.5)
            if resp.status_code == 200:
                data = resp.json()
                return [m["name"] for m in data.get("models", []) if "name" in m]
        except Exception:
            pass
        return []

    def _resolve_model(self, candidates: List[str], fallback: str) -> str:
        for cand in candidates:
            cand_base = cand.split(":")[0]
            for tag in self.available_tags:
                if cand == tag or cand_base == tag.split(":")[0]:
                    return tag
        return fallback

    def _query_model(self, model: str, prompt: str, system_prompt: str) -> str:
        payload = {
            "model": model,
            "prompt": f"### SYSTEM:\n{system_prompt}\n\n### INSTRUCTION:\n{prompt}",
            "stream": False,
            "keep_alive": "60m",
            "options": {"temperature": 0.7, "num_predict": 1024},
        }
        for attempt in range(2):
            try:
                resp = self.client.post(
                    f"{self.endpoint}/api/generate",
                    json=payload,
                    timeout=httpx.Timeout(self.timeout, connect=60.0),
                )
                if resp.status_code == 200:
                    return resp.json().get("response", "").strip()
            except Exception as e:
                if attempt == 0 and "timed out" in str(e).lower():
                    logger.warning(
                        "Ollama query timed out for %s on initial attempt (likely loading model into VRAM/RAM). Retrying with model now resident...",
                        model,
                    )
                    time.sleep(2.0)
                    continue
                logger.warning("Ollama query failed for %s: %s", model, e)
                # Resilient fallback: if secondary model failed/timed out, try fast Qwen fallback
                if model != "qwen2.5:7b" and "qwen2.5:7b" in self.available_tags:
                    try:
                        payload["model"] = "qwen2.5:7b"
                        resp = self.client.post(
                            f"{self.endpoint}/api/generate",
                            json=payload,
                            timeout=httpx.Timeout(self.timeout, connect=60.0),
                        )
                        if resp.status_code == 200:
                            return resp.json().get("response", "").strip()
                    except Exception:
                        pass
                break
        return ""

    def run_fusion_pipeline(self, rfc_fragment: str, fragment_id: Optional[int] = None) -> FusionArbitrationResult:
        """
        Executes the full 4-Gate ModelFusion arbitration protocol:
        1. Query Google Gemma for protocol edge-cases.
        2. Query Security Specialist for offensive boundary conditions.
        3. Evaluate Gate 1 (Single Bypass) & Gate 2 (Unanimous).
        4. Invoke Gate 4 (DeepSeek-R1 Synthesis) to merge insights into novel super-probes.
        """
        participating_models = []
        proposals: List[CandidateProposal] = []

        # ------------------------------------------------------------------
        # Phase 1: Protocol Specialist (Google Gemma)
        # ------------------------------------------------------------------
        gemma_sys = (
            "You are a network protocol specification researcher (James Kettle DEF CON 34 methodology). "
            "The RFC snippet is a source of CLUES, but vulnerabilities are NOT written in the RFC. "
            "Identify subtle state-machine rules, constraints, or delimiter parsing behaviors in the snippet. "
            "CORE DISCOVERY HEURISTIC (Rule Inversion): "
            "1. If the snippet specifies rules for HTTP RESPONSES (e.g. status lines, 304/204 body suppression, "
            "   HEAD response handling, chunked response termination, trailers), INVERT it into an inbound client REQUEST "
            "   to test if the server/proxy uses a shared parser that mistakenly applies response rules to requests (Shared-Parser Confusion). "
            "2. If the snippet specifies SMTP/MIME rules (BDAT chunks, dot-stuffing, line folding), adapt the delimiter into an HTTP probe. "
            "Construct raw HTTP/1.1 requests using explicit '\\r\\n' line delimiters, host 'target.local', and '$PAYLOAD' placeholder. "
            "Output JSON: [{\"rationale\": \"...\", \"raw_request\": \"...\", \"is_clean\": true/false}]"
        )
        gemma_prompt = f"RFC Snippet:\n\"\"\"{rfc_fragment}\"\"\"\nGenerate 1-2 raw HTTP protocol edge-case templates applying Rule Inversion."
        gemma_out = self._query_model(self.gemma_model, gemma_prompt, gemma_sys)
        participating_models.append(self.gemma_model)

        for item in self._parse_json(gemma_out):
            proposals.append(CandidateProposal(
                candidate_id=f"cand_gemma_{len(proposals)+1}",
                model=self.gemma_model,
                specialist_type="Protocol Specialist",
                rationale=item.get("rationale", "Gemma protocol edge-case"),
                raw_request=self._normalize_crlf(item.get("raw_request", "")),
                is_clean=bool(item.get("is_clean", True)),
            ))

        # ------------------------------------------------------------------
        # Phase 2: Exploit Boundary Specialist (Foundation-Sec / Qwen)
        # ------------------------------------------------------------------
        sec_sys = (
            "You are an offensive HTTP framing specialist (Cisco Foundation-Sec / PortSwigger methodology). "
            "The RFC provides clues to structural parser weaknesses. Construct boundary mismatch triggers, "
            "dual-header conflicts, and parser-confusion mutations. "
            "CORE EXPLOIT HEURISTIC: "
            "1. Response-to-Request Inversion: Test if front-end or back-end servers apply response parsing logic to incoming requests (Shared-Parser Confusion). "
            "2. SMTP/MIME Cross-Protocol Inversion: Test if gateways or reverse proxies confuse SMTP framing (BDAT, foldings, dot delimiters) with HTTP. "
            "3. Framing Discrepancies: Exploit dual Content-Length, Transfer-Encoding mutations, trailing whitespace, or null bytes. "
            "Produce raw HTTP requests with '\\r\\n', host 'target.local', and '$PAYLOAD'. "
            "Output JSON: [{\"rationale\": \"...\", \"raw_request\": \"...\", \"is_clean\": false}]"
        )
        sec_prompt = f"RFC Snippet:\n\"\"\"{rfc_fragment}\"\"\"\nGenerate 1-2 boundary confusion probes applying Cross-Context Inversion."
        sec_out = self._query_model(self.sec_model, sec_prompt, sec_sys)
        participating_models.append(self.sec_model)

        for item in self._parse_json(sec_out):
            proposals.append(CandidateProposal(
                candidate_id=f"cand_sec_{len(proposals)+1}",
                model=self.sec_model,
                specialist_type="Boundary Specialist",
                rationale=item.get("rationale", "Security boundary probe"),
                raw_request=self._normalize_crlf(item.get("raw_request", "")),
                is_clean=bool(item.get("is_clean", False)),
            ))

        # ------------------------------------------------------------------
        # Gate 1: Single Candidate Bypass
        # ------------------------------------------------------------------
        if len(proposals) <= 1:
            res_probes = [p.to_dict() for p in proposals]
            self._save_probes_to_db(res_probes, fragment_id, "SingleBypass")
            return FusionArbitrationResult(
                consensus_type="SingleBypass",
                fused_probes=res_probes,
                reasoning="Single candidate available; bypassed arbitration.",
                participating_models=participating_models,
            )

        # ------------------------------------------------------------------
        # Gate 2: Unanimous Identical Implementations Bypass
        # ------------------------------------------------------------------
        first_req = proposals[0].raw_request.strip()
        if all(p.raw_request.strip() == first_req for p in proposals):
            res_probes = [proposals[0].to_dict()]
            self._save_probes_to_db(res_probes, fragment_id, "Unanimous")
            return FusionArbitrationResult(
                consensus_type="Unanimous",
                fused_probes=res_probes,
                reasoning="All specialists produced identical request templates.",
                participating_models=participating_models,
            )

        # ------------------------------------------------------------------
        # Gate 4: Synthesis via DeepSeek-R1 Reasoning Arbiter
        # ------------------------------------------------------------------
        participating_models.append(self.arbiter_model)
        candidates_summary = "\n\n".join([
            f"Candidate [{p.candidate_id}] by {p.model} ({p.specialist_type}):\n"
            f"- Rationale: {p.rationale}\n"
            f"- Raw Request Template:\n{p.raw_request}"
            for p in proposals if p.raw_request
        ])

        arbiter_sys = (
            "You are the Fusion Arbiter for ModelFusion (James Kettle research architect). "
            "You are given competing HTTP probe proposals derived from an RFC clue. "
            "Remember: The vulnerability was NOT written in the RFC. The RFC supplies a clue; the attack concept comes from "
            "inverting protocol expectations—especially testing whether servers apply response parsing rules to incoming requests (Shared-Parser Confusion), "
            "or whether reverse proxies disagree with backends on framing. "
            "Perform rigorous reasoning inside <think> tags. Synthesize the most potent, novel unified probe combining nuance and boundary manipulation. "
            "Output JSON: [{\"rationale\": \"...\", \"raw_request\": \"...\", \"is_clean\": true/false}]"
        )

        arbiter_prompt = (
            f"RFC Snippet Under Investigation:\n\"\"\"{rfc_fragment}\"\"\"\n\n"
            f"Candidate Proposals Submitted to Fusion Arbiter:\n{candidates_summary}\n\n"
            f"Synthesize the optimal consensus probe."
        )

        arbiter_out = self._query_model(self.arbiter_model, arbiter_prompt, arbiter_sys)
        synthesized_probes = self._parse_json(arbiter_out)

        final_fused: List[Dict[str, Any]] = []

        if synthesized_probes:
            # Gate 4 Success: DeepSeek-R1 synthesized consensus
            for sp in synthesized_probes:
                if not isinstance(sp, dict):
                    continue
                raw = self._normalize_crlf(sp.get("raw_request", ""))
                if raw:
                    final_fused.append({
                        "id": f"fused_arbiter_{len(final_fused)+1}",
                        "model": f"{self.arbiter_model} [Fused: {self.gemma_model} + {self.sec_model}]",
                        "specialist": "Arbiter Consensus Synthesis",
                        "rationale": f"[ModelFusion Consensus] {sp.get('rationale', 'Synthesized consensus vector')}",
                        "raw_request": raw,
                        "is_clean": bool(sp.get("is_clean", False)),
                    })

            consensus_type = "ArbiterSynthesized"
            reasoning = f"DeepSeek-R1 successfully synthesized {len(final_fused)} unified probes from Gemma + Security candidates."
        else:
            # Fallback: Merge both specialists' candidates directly
            consensus_type = "DominantWinner"
            reasoning = "Arbiter timed out or unparseable; retained individual specialist candidates."
            for p in proposals:
                if p.raw_request:
                    final_fused.append(p.to_dict())

        self._save_probes_to_db(final_fused, fragment_id, consensus_type)

        return FusionArbitrationResult(
            consensus_type=consensus_type,
            fused_probes=final_fused,
            reasoning=reasoning,
            participating_models=participating_models,
        )

    def _save_probes_to_db(self, probes: List[Dict[str, Any]], fragment_id: Optional[int], consensus_type: str) -> None:
        if not self.db:
            return
        for p in probes:
            self.db.save_probe(
                fragment_id=fragment_id,
                rationale=f"[{consensus_type}] {p.get('rationale', '')}",
                raw_request=p.get("raw_request", ""),
                is_clean=p.get("is_clean", False),
                source_type="fusion",
            )

    def explain_vulnerability_concept(
        self,
        rfc_fragment: str,
        probe_request: str,
        baseline_resp: str = "",
        probe_resp: str = "",
        retest_resp: str = "",
        anomalies: Optional[List[Dict[str, Any]]] = None,
        desync_class: Optional[str] = None,
        details: str = "",
    ) -> Dict[str, Any]:
        """
        The James Kettle Discovery Synthesis:
        The RFC fragment supplied the clue; the candidate request triggered unexpected behavior;
        now the AI analyzes what happened on the live server and formulates the broader
        architectural explanation (e.g. Shared-Parser Confusion, Response-Rule Inversion,
        Differential Header Stripping) and proposes the formal attack concept name.
        """
        anom_summary = "\n".join([f"- {a.get('type')}: {a.get('description')}" for a in (anomalies or [])]) if anomalies else "None"

        b_stat = baseline_resp.splitlines()[0] if baseline_resp else "200 OK"
        p_stat = probe_resp.splitlines()[0] if probe_resp else "Unknown / Disconnected"
        r_stat = retest_resp.splitlines()[0] if retest_resp else "CONNECTION_CLOSED"

        sys_prompt = (
            "You are an elite protocol security researcher (in the caliber of James Kettle / DEF CON 34 / Black Hat). "
            "You are analyzing live test results produced by HTTP Terminator against a target server. "
            "The vulnerability was NOT written in the RFC. The RFC provided the clue, and the attack concept comes from testing and analyzing what happened. "
            "For example, in Shared-Parser Confusion, an RFC passage about responses inspired a request that exposed a flaw, "
            "and the researcher/AI deduced that servers were applying response parsing rules to requests. "
            "Formulate the broader architectural explanation and propose the formal attack concept name. "
            "Output strict JSON with keys: 'concept_name', 'architectural_explanation', 'rfc_clue_connection', 'generalization', 'validation_steps'."
        )

        user_prompt = f"""
RFC FRAGMENT (THE INSPIRATION CLUE):
\"\"\"{rfc_fragment}\"\"\"

PROBE REQUEST SENT (THE TRIGGER):
{probe_request}

OBSERVED LIVE ACTIVITY TRACE:
- Diagnostic Details: {details}
- Desync Classification: {desync_class or 'Unclassified / Anomaly'}
- Conn A (Baseline Response) Status: {b_stat}
- Conn B (Probe Response) Status: {p_stat}
- Conn A (Re-Test Response) Status: {r_stat}
- Detected Anomalies:
{anom_summary}

Full Probe Response Snippet (First 350 bytes):
{probe_resp[:350]}

Full Re-Test Response Snippet (First 350 bytes):
{retest_resp[:350]}

Analyze what happened. Did the server apply response parsing rules to requests (Shared-Parser Confusion)? Did the front-end proxy disagree on body length? Did cross-protocol parser reuse occur?
Output strict JSON matching:
{{
  "concept_name": "Descriptive Vulnerability Concept Name",
  "architectural_explanation": "Detailed explanation of what the server parser did internally",
  "rfc_clue_connection": "How the RFC snippet inspired this discovery",
  "generalization": "How this vulnerability applies to other servers/protocols",
  "validation_steps": ["step 1", "step 2"]
}}
"""
        try:
            raw_out = self._query_model(self.arbiter_model, user_prompt, sys_prompt)
            parsed = self._parse_json(raw_out)
            if parsed and isinstance(parsed, list) and isinstance(parsed[0], dict):
                return parsed[0]
            elif parsed and isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

        # Heuristic fallback if arbiter times out
        inferred_concept = desync_class or "Shared-Parser / Framing Discrepancy"
        frag_lower = rfc_fragment.lower()
        if any(w in frag_lower for w in ["response", "status", "304", "204", "head"]):
            inferred_concept = "Shared-Parser Confusion (Response-to-Request Inversion)"
            explanation = "The server appears to apply RFC response-handling rules to incoming client requests, causing differential body termination or socket confusion."
        elif any(w in frag_lower for w in ["smtp", "bdat", "dot-stuffing", "mail"]):
            inferred_concept = "Cross-Protocol Parser Reuse (SMTP/HTTP Demarcation Discrepancy)"
            explanation = "The front-end or gateway appears to reuse socket parsers across SMTP and HTTP, failing to isolate multi-line stream delimiters."
        else:
            explanation = f"Observed differential behavior on target host triggered by RFC fragment: {details}"

        return {
            "concept_name": inferred_concept,
            "architectural_explanation": explanation,
            "rfc_clue_connection": f"Inspired by normative requirement in RFC fragment: {rfc_fragment[:80]}...",
            "generalization": "Servers utilizing unified protocol parsers or multi-tier reverse proxy pipelines with differing delimiter assumptions.",
            "validation_steps": ["Verify whether Conn A socket state persists across pipelined requests", "Test differential Content-Length vs chunked boundaries"],
        }

    def _normalize_crlf(self, text: Any) -> str:
        if not text:
            return ""
        if isinstance(text, dict):
            # Check for direct string fields inside the dict
            for key in ("request", "raw", "raw_request", "template", "payload", "data"):
                if key in text and isinstance(text[key], str):
                    text = text[key]
                    break
            else:
                # Reconstruct standard HTTP request if dictionary specifies components
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

    def _parse_json(self, text: str) -> List[Dict[str, Any]]:
        if not text:
            return []
        # Strip <think> tags from DeepSeek-R1
        if "</think>" in text:
            text = text.split("</think>")[-1].strip()

        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()

        try:
            val = json.loads(text)
            if isinstance(val, list):
                out = []
                for v in val:
                    if isinstance(v, dict):
                        out.append(v)
                    elif isinstance(v, str):
                        out.append({"rationale": "Synthesized probe", "raw_request": v, "is_clean": False})
                return out
            elif isinstance(val, dict):
                return [val]
        except Exception:
            pass

        m = re.search(r"\[\s*\{.*\}\s*\]", text, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group(0))
                if isinstance(parsed, list):
                    return [p for p in parsed if isinstance(p, dict)]
            except Exception:
                pass
        return []
