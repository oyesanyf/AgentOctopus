# Hardened CPU-Only Seq2Seq NMT Container (Meta NLLB-200-distilled-600M)
# Pure encoder-decoder translation (immune to LLM prompt injection), non-root UID 10001,
# read-only rootfs compatible, and bound to host loopback 127.0.0.1:5050 via compose/scripts.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/cache/hf \
    TOKENIZERS_PARALLELISM=false \
    RAYON_NUM_THREADS=2 \
    OMP_NUM_THREADS=6 \
    MKL_NUM_THREADS=6 \
    OPENBLAS_NUM_THREADS=6 \
    OCTOPUS_NMT_MODEL=facebook/nllb-200-distilled-600M \
    OCTOPUS_NMT_INT8=1 \
    OCTOPUS_NMT_PORT=5050

RUN groupadd --gid 10001 nmt \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin nmt \
    && mkdir -p /app /cache/hf \
    && chown -R 10001:10001 /app /cache

WORKDIR /app

# Install patched CPU-only PyTorch & NMT stack so local GPU VRAM is never touched
RUN pip install --no-cache-dir \
        --index-url https://download.pytorch.org/whl/cpu \
        torch==2.15.0 \
    && pip install --no-cache-dir \
        transformers==5.24.0 \
        sentencepiece==0.2.3 \
        protobuf==7.36.2 \
        fastapi==0.165.0 \
        uvicorn==0.54.0 \
        pydantic==2.14.4

COPY --chown=10001:10001 nllb_server.py /app/nllb_server.py

USER 10001:10001
EXPOSE 5050

HEALTHCHECK --interval=15s --timeout=3s --start-period=90s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5050/health', timeout=2)" || exit 1

ENTRYPOINT ["python", "-m", "uvicorn", "nllb_server:app", "--host", "0.0.0.0", "--port", "5050", "--workers", "1", "--log-level", "warning"]
