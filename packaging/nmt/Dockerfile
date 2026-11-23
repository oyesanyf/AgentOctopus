# Hardened CPU-Only Seq2Seq NMT Container (Meta NLLB-200-distilled-600M)
# Pure encoder-decoder translation (immune to LLM prompt injection), non-root UID 10001,
# read-only rootfs compatible, and bound to host loopback 127.0.0.1:5050 via compose/scripts.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/cache/hf \
    OCTOPUS_NMT_MODEL=facebook/nllb-200-distilled-600M \
    OCTOPUS_NMT_INT8=1 \
    OCTOPUS_NMT_PORT=5050

RUN groupadd --gid 10001 nmt \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin nmt \
    && mkdir -p /app /cache/hf \
    && chown -R 10001:10001 /app /cache

WORKDIR /app

# Install CPU-only PyTorch first so local GPU VRAM is never touched
RUN pip install --no-cache-dir \
        --index-url https://download.pytorch.org/whl/cpu \
        torch==2.6.0 \
    && pip install --no-cache-dir \
        transformers==4.49.0 \
        sentencepiece==0.2.0 \
        protobuf==5.29.3 \
        fastapi==0.115.11 \
        uvicorn==0.34.0 \
        pydantic==2.10.6

COPY --chown=10001:10001 nllb_server.py /app/nllb_server.py

USER 10001:10001
EXPOSE 5050

HEALTHCHECK --interval=15s --timeout=3s --start-period=90s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5050/health', timeout=2)" || exit 1

ENTRYPOINT ["python", "-m", "uvicorn", "nllb_server:app", "--host", "0.0.0.0", "--port", "5050", "--workers", "1", "--log-level", "warning"]
