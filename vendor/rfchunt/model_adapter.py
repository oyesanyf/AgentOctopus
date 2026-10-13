"""
Model Adapter & Local Fusion Engine:
Adapted from ModelFusion (d:\\harfile\\ModelFusion) and Ollama client adapters.
Enables 24/7 zero-cost local LLM inference using Google Gemma (gemma2:9b, gemma2:2b),
Qwen (qwen2.5), and Foundation-Sec, with multi-model panel fusion and fallback to Gemini API.
"""

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional
import httpx

try:
    from google import genai
    from google.genai import types
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

logger = logging.getLogger("terminator.models")


class ModelFusionAdapter:
    """
    Manages local model inference via Ollama and panel fusion across models.
    Supports Google Gemma, Qwen, Foundation-Sec, and Gemini cloud API.
    """

    DEFAULT_OLLAMA_ENDPOINT = "http://127.0.0.1:11434"

    def __init__(
        self,
        preferred_model: Optional[str] = None,
        ollama_endpoint: Optional[str] = None,
        use_fusion: bool = True,
        sec_model: Optional[str] = None,
    ):
        self.endpoint = ollama_endpoint or os.environ.get("OLLAMA_ENDPOINT", self.DEFAULT_OLLAMA_ENDPOINT)
        # Model Fusion is enabled by default to ensure multi-model consensus and diversity
        self.use_fusion = use_fusion if os.environ.get("USE_MODEL_FUSION") is None else (os.environ.get("USE_MODEL_FUSION") == "1")
        self.preferred_model = preferred_model or os.environ.get("LOCAL_MODEL", "gemma2:2b")
        self.sec_model = sec_model
        self.available_tags = self._fetch_available_tags()
        self.active_model = self._resolve_model(self.preferred_model)
        timeout_env = os.environ.get("OLLAMA_TIMEOUT", "900.0")
        self.timeout = float(timeout_env) if float(timeout_env) > 0 else None
        self.client = httpx.Client(timeout=httpx.Timeout(self.timeout, connect=60.0))

        # Gemini Cloud client fallback
        self.gemini_client = None
        if HAS_GENAI and os.environ.get("GEMINI_API_KEY"):
            try:
                self.gemini_client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
            except Exception as e:
                logger.debug("Failed to init Gemini client: %s", e)

    def _fetch_available_tags(self) -> List[str]:
        try:
            resp = httpx.get(f"{self.endpoint}/api/tags", timeout=1.5)
            if resp.status_code == 200:
                data = resp.json()
                return [m["name"] for m in data.get("models", []) if "name" in m]
        except Exception:
            pass
        return []

    def _resolve_model(self, preferred: str) -> str:
        """
        Dynamically resolves a valid model tag to avoid 404 aborts.
        Hierarchy: Preferred (e.g. gemma2:9b / gemma2:2b) -> qwen2.5 -> first available -> gemma2:2b
        """
        if not self.available_tags:
            return preferred

        # Exact match
        for tag in self.available_tags:
            if tag == preferred or tag.startswith(preferred + ":") or preferred.startswith(tag):
                return tag

        # Check clean names
        clean_pref = preferred.split(":")[0]
        for tag in self.available_tags:
            if clean_pref in tag:
                return tag

        # Preference hierarchy for zero-cost local research
        candidates = ["gemma2:9b", "gemma2:2b", "qwen2.5:7b", "fenkohq/foundation-sec-8b:latest", "qwen2.5:32b", "deepseek-r1:1.5b"]
        for cand in candidates:
            cand_base = cand.split(":")[0]
            for tag in self.available_tags:
                if cand_base in tag:
                    return tag

        return self.available_tags[0]

    def generate_json(self, system_instruction: str, user_prompt: str) -> List[Dict[str, Any]]:
        """
        Executes structured JSON generation using local Ollama model(s) or Gemini fallback.
        If use_fusion is enabled, runs panel fusion across Gemma and secondary models.
        """
        if self.use_fusion:
            return self._run_panel_fusion(system_instruction, user_prompt)

        # Primary: Local Ollama model
        if self.available_tags:
            result = self._query_ollama(self.active_model, system_instruction, user_prompt)
            if result:
                return result

        # Secondary: Gemini Cloud Fallback if available
        if self.gemini_client:
            return self._query_gemini(system_instruction, user_prompt)

        return []

    def _query_ollama(self, model: str, system_instruction: str, user_prompt: str) -> List[Dict[str, Any]]:
        full_prompt = (
            f"### SYSTEM INSTRUCTION:\n{system_instruction}\n\n"
            f"### TASK PROMPT:\n{user_prompt}\n\n"
            f"CRITICAL: Output ONLY a valid JSON array of objects with keys 'rationale', 'raw_request', 'is_clean'. "
            f"No conversational text outside the JSON array."
        )

        payload = {
            "model": model,
            "prompt": full_prompt,
            "stream": False,
            "format": "json",
            "keep_alive": "60m",
            "options": {
                "temperature": 0.7,
                "num_predict": 1024,
            },
        }

        for attempt in range(2):
            try:
                resp = self.client.post(
                    f"{self.endpoint}/api/generate",
                    json=payload,
                    timeout=httpx.Timeout(self.timeout, connect=60.0),
                )
                if resp.status_code == 200:
                    raw_text = resp.json().get("response", "").strip()
                    return self._parse_json_array(raw_text)
            except Exception as e:
                if attempt == 0 and "timed out" in str(e).lower():
                    logger.warning(
                        "Ollama query timed out on %s on initial attempt (likely loading model into VRAM/RAM). Retrying with model now resident...",
                        model,
                    )
                    time.sleep(2.0)
                    continue
                logger.warning("Ollama query failed on %s: %s", model, e)
                break
        return []

    def _run_panel_fusion(self, system_instruction: str, user_prompt: str) -> List[Dict[str, Any]]:
        """
        ModelFusion Panel: Queries a fusion of Google Gemma (protocol state machine specialist)
        AND a secondary security/code model (exploit boundary specialist), merging and
        cross-pollinating their candidate probes to maximize novelty at zero cost.
        """
        gemma_model = None
        for tag in ["gemma2:2b", "gemma2:9b"]:
            matched = [t for t in self.available_tags if tag in t]
            if matched:
                gemma_model = matched[0]
                break

        if hasattr(self, "sec_model") and self.sec_model:
            sec_model = self.sec_model
        else:
            sec_model = None
            for tag in ["qwen2.5:7b", "strix-qwen:latest", "fenkohq/foundation-sec-8b:latest", "deepseek-r1:1.5b", "qwen2.5:32b"]:
                matched = [t for t in self.available_tags if tag in t or tag.split(":")[0] in t]
                if matched:
                    sec_model = matched[0]
                    break

        fusion_panel = []
        if gemma_model:
            fusion_panel.append(gemma_model)
        if sec_model and sec_model not in fusion_panel:
            fusion_panel.append(sec_model)

        if not fusion_panel:
            fusion_panel = [self.active_model]

        logger.info("[ModelFusion] Executing panel fusion across: %s", " + ".join(fusion_panel))

        all_probes: List[Dict[str, Any]] = []
        seen_requests = set()

        for model in fusion_panel:
            probes = self._query_ollama(model, system_instruction, user_prompt)
            for p in probes:
                if not isinstance(p, dict):
                    continue
                raw_req = p.get("raw_request", "").strip()
                if raw_req and raw_req not in seen_requests:
                    seen_requests.add(raw_req)
                    p["fused_model"] = model
                    all_probes.append(p)

        return all_probes

    def _query_gemini(self, system_instruction: str, user_prompt: str) -> List[Dict[str, Any]]:
        try:
            response = self.gemini_client.models.generate_content(
                model=os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"),
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    response_mime_type="application/json",
                    response_schema={
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "rationale": {"type": "string"},
                                "raw_request": {"type": "string"},
                                "is_clean": {"type": "boolean"},
                            },
                            "required": ["rationale", "raw_request", "is_clean"],
                        },
                    },
                    temperature=0.8,
                ),
            )
            return json.loads(response.text)
        except Exception as e:
            logger.warning("Gemini query failed: %s", e)
            return []

    def _parse_json_array(self, text: str) -> List[Dict[str, Any]]:
        """Robust parser for JSON arrays in LLM completions."""
        if not text:
            return []

        # Strip markdown fences if present
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]

        text = text.strip()

        def _clean_list(raw_list: list) -> List[Dict[str, Any]]:
            res = []
            for item in raw_list:
                if isinstance(item, dict):
                    res.append(item)
                elif isinstance(item, str) and item.strip():
                    res.append({"rationale": item.strip(), "raw_request": "", "is_clean": False})
            return res

        # Try direct parse
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return _clean_list(parsed)
            elif isinstance(parsed, dict):
                # Wrapped inside a key like 'probes', 'suggested_probes', or 'items'
                for k in ["suggested_probes", "probes", "items", "candidates"]:
                    if k in parsed and isinstance(parsed[k], list):
                        return _clean_list(parsed[k])
                for k, v in parsed.items():
                    if isinstance(v, list):
                        return _clean_list(v)
                return [parsed]
        except json.JSONDecodeError:
            pass

        # Regex fallback: find array [ ... ]
        m = re.search(r"\[\s*\{.*\}\s*\]", text, re.DOTALL)
        if m:
            try:
                raw_parsed = json.loads(m.group(0))
                if isinstance(raw_parsed, list):
                    return _clean_list(raw_parsed)
            except Exception:
                pass

        return []
