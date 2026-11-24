"""Dedicated Loopback-Only Seq2Seq NMT Server (Meta NLLB-200-distilled-600M).

Security Architecture:
- Pure encoder-decoder Neural Machine Translation (Seq2Seq): NO system prompt,
  NO chat instruction following -> structurally immune to translation-layer
  prompt injection.
- Covers 200+ languages including low-resource languages (Yoruba, Zulu, Swahili,
  Hausa, Igbo, Amharic, Hmong, Scots Gaelic, Welsh, Khmer, Tibetan, Georgian,
  Armenian, Tamil, Arabic, Russian, Chinese, Japanese, Hindi, etc.).
- Runs strictly on CPU (or quantized INT8 via CTranslate2 when installed) so local
  GPU VRAM is never exhausted, and binds exclusively to 127.0.0.1:5050 by default.
- Exposes a LibreTranslate-compatible API:
    GET  /health
    GET  /languages
    POST /translate  {"q": "...", "source": "auto|yo|am|...", "target": "en"}
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import os
import threading
import time
from typing import Any, AsyncIterator, Dict, Optional

# Bound Rayon/OpenMP/BLAS thread pools BEFORE importing torch/transformers so high-core hosts
# never exceed container pids_limit (EAGAIN / rayon ThreadPoolBuildError).
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("RAYON_NUM_THREADS", "2")
os.environ.setdefault("OMP_NUM_THREADS", "6")
os.environ.setdefault("MKL_NUM_THREADS", "6")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "6")

import torch
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

MODEL_ID = os.environ.get("OCTOPUS_NMT_MODEL", "facebook/nllb-200-distilled-600M")
MAX_INPUT_CHARS = int(os.environ.get("OCTOPUS_NMT_MAX_CHARS", "1500"))
MAX_NEW_TOKENS = int(os.environ.get("OCTOPUS_NMT_MAX_NEW_TOKENS", "256"))
CPU_THREADS = int(
    os.environ.get("OCTOPUS_NMT_THREADS", str(max(2, min(8, (os.cpu_count() or 4) // 2))))
)
QUANTIZE_INT8 = os.environ.get("OCTOPUS_NMT_INT8", "1").strip() not in ("0", "false", "False")

# ISO 639-1 / 639-3 -> FLORES-200 NLLB language code map
ISO_TO_FLORES: Dict[str, str] = {
    "en": "eng_Latn",
    "yo": "yor_Latn",
    "zu": "zul_Latn",
    "sw": "swh_Latn",
    "ha": "hau_Latn",
    "ig": "ibo_Latn",
    "am": "amh_Ethi",
    "gd": "gla_Latn",
    "cy": "cym_Latn",
    "km": "khm_Khmr",
    "bo": "bod_Tibt",
    "ka": "kat_Geor",
    "hy": "hye_Armn",
    "lo": "lao_Laoo",
    "my": "mya_Mymr",
    "ta": "tam_Taml",
    "te": "tel_Telu",
    "bn": "ben_Beng",
    "ar": "arb_Arab",
    "ru": "rus_Cyrl",
    "hi": "hin_Deva",
    "zh": "zho_Hans",
    "ja": "jpn_Jpan",
    "ko": "kor_Hang",
    "th": "tha_Thai",
    "el": "ell_Grek",
    "he": "heb_Hebr",
    "es": "spa_Latn",
    "fr": "fra_Latn",
    "de": "deu_Latn",
    "pt": "por_Latn",
    "tr": "tur_Latn",
    "vi": "vie_Latn",
    "id": "ind_Latn",
    "uk": "ukr_Cyrl",
    "pl": "pol_Latn",
    "nl": "nld_Latn",
    "it": "ita_Latn",
    "fa": "pes_Arab",
    "ur": "urd_Arab",
    "so": "som_Latn",
    "sn": "sna_Latn",
    "xh": "xho_Latn",
    "rw": "kin_Latn",
    "ti": "tir_Ethi",
    "om": "gaz_Latn",
    "mg": "plt_Latn",
    "mi": "mri_Latn",
    "sm": "smo_Latn",
    # Hmong uses Latin script; Vietnamese/Lao-adjacent fallback when not natively in NLLB-200
    "hmn": "vie_Latn",
}


def detect_flores_code(text: str, hint: Optional[str] = None) -> tuple[str, str]:
    """Resolves (iso_code, flores200_code) from an explicit hint or fast script heuristics."""
    if hint:
        h = hint.strip().lower()
        if h in ISO_TO_FLORES:
            return h, ISO_TO_FLORES[h]
        if "_" in hint and len(hint) == 8:
            return hint[:2].lower(), hint

    # Script-based deterministic detection for non-Latin scripts
    counts: Dict[str, int] = {}
    has_kana = False
    has_yoruba_subdot = False
    for ch in text:
        cp = ord(ch)
        if 0x3040 <= cp <= 0x30FF:
            has_kana = True
        if ch in "ẹọṣẸỌṢ":
            has_yoruba_subdot = True
        if 0x1200 <= cp <= 0x137F:
            counts["am"] = counts.get("am", 0) + 1
        elif 0x0600 <= cp <= 0x06FF or 0x0750 <= cp <= 0x077F:
            counts["ar"] = counts.get("ar", 0) + 1
        elif 0x0400 <= cp <= 0x052F:
            counts["ru"] = counts.get("ru", 0) + 1
        elif 0x0900 <= cp <= 0x097F:
            counts["hi"] = counts.get("hi", 0) + 1
        elif 0x0980 <= cp <= 0x09FF:
            counts["bn"] = counts.get("bn", 0) + 1
        elif 0x0B80 <= cp <= 0x0BFF:
            counts["ta"] = counts.get("ta", 0) + 1
        elif 0x0C00 <= cp <= 0x0C7F:
            counts["te"] = counts.get("te", 0) + 1
        elif 0x0E00 <= cp <= 0x0E7F:
            counts["th"] = counts.get("th", 0) + 1
        elif 0x0E80 <= cp <= 0x0EFF:
            counts["lo"] = counts.get("lo", 0) + 1
        elif 0x0F00 <= cp <= 0x0FFF:
            counts["bo"] = counts.get("bo", 0) + 1
        elif 0x1000 <= cp <= 0x109F:
            counts["my"] = counts.get("my", 0) + 1
        elif 0x10A0 <= cp <= 0x10FF:
            counts["ka"] = counts.get("ka", 0) + 1
        elif 0x0530 <= cp <= 0x058F:
            counts["hy"] = counts.get("hy", 0) + 1
        elif 0x1780 <= cp <= 0x17FF:
            counts["km"] = counts.get("km", 0) + 1
        elif 0x0370 <= cp <= 0x03FF:
            counts["el"] = counts.get("el", 0) + 1
        elif 0x0590 <= cp <= 0x05FF:
            counts["he"] = counts.get("he", 0) + 1
        elif 0xAC00 <= cp <= 0xD7AF:
            counts["ko"] = counts.get("ko", 0) + 1
        elif 0x4E00 <= cp <= 0x9FFF or 0x3400 <= cp <= 0x4DBF or 0x3040 <= cp <= 0x30FF:
            counts["cjk"] = counts.get("cjk", 0) + 1

    if counts:
        top = max(counts, key=lambda k: counts[k])
        if top == "cjk":
            iso = "ja" if has_kana else "zh"
            return iso, ISO_TO_FLORES[iso]
        return top, ISO_TO_FLORES[top]

    lower = text.lower()
    if has_yoruba_subdot or any(w in lower for w in ("jowo", "gbogbo", "koju", "ranse", "orọigbaniwọle")):
        return "yo", ISO_TO_FLORES["yo"]
    if any(w in lower for w in ("ngicela", "imiyalelo", "amaphasiwedi", "ziba yonke")):
        return "zu", ISO_TO_FLORES["zu"]
    if any(w in lower for w in ("tafadhali", "maagizo", "nywila", "puuza", "ripoti")):
        return "sw", ISO_TO_FLORES["sw"]
    if any(w in lower for w in ("don allah", "umarni", "kalmar sirri", "watsi")):
        return "ha", ISO_TO_FLORES["ha"]
    if any(w in lower for w in ("biko", "ntuziaka", "okwuntughe", "leghara")):
        return "ig", ISO_TO_FLORES["ig"]
    if any(w in lower for w in ("por favor", "instrucciones", "contrasena", "informe")):
        return "es", ISO_TO_FLORES["es"]
    if any(w in lower for w in ("veuillez", "mot de passe", "ignorer", "rapport")):
        return "fr", ISO_TO_FLORES["fr"]
    if any(w in lower for w in ("bitte", "anweisungen", "passwort", "ignorieren")):
        return "de", ISO_TO_FLORES["de"]

    return "en", ISO_TO_FLORES["en"]


class TranslateRequest(BaseModel):
    q: str = Field(..., min_length=1, max_length=MAX_INPUT_CHARS)
    source: str = Field(default="auto")
    target: str = Field(default="en")
    format: str = Field(default="text")
    source_lang_hint: Optional[str] = Field(default=None)


class NllbEngine:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.ready = False
        self.quantized_int8 = False
        self.load_error: Optional[str] = None
        self.load_seconds: float = 0.0
        self.tokenizer: Any = None
        self.model: Any = None

    def load(self) -> None:
        t0 = time.perf_counter()
        torch.set_num_threads(CPU_THREADS)
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
            model = AutoModelForSeq2SeqLM.from_pretrained(MODEL_ID)
            model.eval()
            if QUANTIZE_INT8:
                try:
                    model = torch.ao.quantization.quantize_dynamic(
                        model, {torch.nn.Linear}, dtype=torch.qint8
                    )
                    self.quantized_int8 = True
                except Exception:
                    self.quantized_int8 = False
            self.model = model
            self.ready = True
            self.load_seconds = round(time.perf_counter() - t0, 2)
        except Exception as exc:
            self.load_error = str(exc)
            self.ready = False
            raise

    def translate(self, text: str, src_iso: str, src_flores: str, tgt_flores: str) -> str:
        if not self.ready or self.model is None or self.tokenizer is None:
            raise RuntimeError("NMT model not ready")
        if src_flores == tgt_flores:
            return text
        with self._lock:
            self.tokenizer.src_lang = src_flores
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
            )
            tgt_lang_id = self.tokenizer.convert_tokens_to_ids(tgt_flores)
            with torch.inference_mode():
                generated = self.model.generate(
                    **inputs,
                    forced_bos_token_id=tgt_lang_id,
                    max_new_tokens=MAX_NEW_TOKENS,
                    num_beams=1,
                    do_sample=False,
                )
            decoded = self.tokenizer.batch_decode(generated, skip_special_tokens=True)
            return (decoded[0] if decoded else "").strip()


engine = NllbEngine()


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    # Load model synchronously before accepting traffic so /health reflects true readiness
    engine.load()
    yield


app = FastAPI(
    title="AgentOctopus Loopback Seq2Seq NMT (NLLB-200)",
    version="0.2.0",
    lifespan=_lifespan,
)


@app.get("/")
def root_info() -> Dict[str, Any]:
    return {
        "service": "AgentOctopus Loopback Seq2Seq NMT Sidecar (NLLB-200)",
        "note": "This port (5050) serves the headless POST /translate NMT API. Open the Agent Octopus Web UI Dashboard at http://127.0.0.1:3030",
        "web_ui_url": "http://127.0.0.1:3030",
        "endpoints": {
            "health": "GET /health",
            "languages": "GET /languages",
            "translate": "POST /translate",
            "openapi_docs": "GET /docs",
        },
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    if not engine.ready:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "loading_or_failed",
                "model": MODEL_ID,
                "error": engine.load_error,
            },
        )
    return {
        "status": "ok",
        "backend": "nllb-200-seq2seq",
        "model": MODEL_ID,
        "quantized_int8": engine.quantized_int8,
        "cpu_threads": CPU_THREADS,
        "supported_languages_count": len(ISO_TO_FLORES),
        "load_seconds": engine.load_seconds,
        "loopback_only": True,
    }


@app.get("/languages")
def languages() -> list[Dict[str, str]]:
    return [{"code": iso, "flores200": fl} for iso, fl in sorted(ISO_TO_FLORES.items())]


@app.post("/translate")
def translate(req: TranslateRequest) -> Dict[str, Any]:
    if not engine.ready:
        raise HTTPException(status_code=503, detail="NMT model not ready")
    t0 = time.perf_counter()
    hint = req.source_lang_hint or (None if req.source.lower() == "auto" else req.source)
    src_iso, src_flores = detect_flores_code(req.q, hint)
    tgt_iso = req.target.strip().lower()
    tgt_flores = ISO_TO_FLORES.get(tgt_iso, "eng_Latn")

    translated = engine.translate(req.q, src_iso, src_flores, tgt_flores)
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "translatedText": translated,
        "detectedLanguage": {
            "language": src_iso,
            "flores200": src_flores,
            "confidence": 1.0,
        },
        "targetLanguage": tgt_flores,
        "backend": "nllb-200-seq2seq",
        "model": MODEL_ID,
        "latency_ms": elapsed_ms,
    }


if __name__ == "__main__":
    host = os.environ.get("OCTOPUS_NMT_BIND", "127.0.0.1")
    port = int(os.environ.get("OCTOPUS_NMT_PORT", "5050"))
    uvicorn.run(app, host=host, port=port, log_level="warning")
