#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/packaging/nmt/docker-compose.nmt.yml"
ENV_FILE="${REPO_ROOT}/.env"
PORT="${OCTOPUS_NMT_PORT:-5050}"

if [[ "${1:-}" == "--stop" ]]; then
  echo "[NMT] Stopping AgentOctopus loopback Seq2Seq NMT container..."
  docker compose -f "${COMPOSE_FILE}" down
  exit 0
fi

if [[ "${1:-}" == "--offline" ]]; then
  export HF_HUB_OFFLINE=1
fi

export COMPOSE_BAKE=0
echo "[NMT] Building hardened CPU-only NLLB-200 image (agentoctopus-nmt:0.2.0)..."
docker build --progress=plain -t agentoctopus-nmt:0.2.0 "${REPO_ROOT}/packaging/nmt"
echo "[NMT] Starting loopback-only NLLB-200 Seq2Seq container on 127.0.0.1:${PORT}..."
docker compose -f "${COMPOSE_FILE}" up -d --no-build

HEALTH_URL="http://127.0.0.1:${PORT}/health"
TRANSLATE_URL="http://127.0.0.1:${PORT}/translate"

echo "[NMT] Waiting for ${HEALTH_URL}..."
READY=0
for i in $(seq 1 180); do
  if curl -fsS --max-time 2 "${HEALTH_URL}" >/dev/null 2>&1; then
    READY=1
    echo "[NMT] Healthy: $(curl -fsS --max-time 2 "${HEALTH_URL}")"
    break
  fi
  if (( i % 10 == 0 )); then
    echo "[NMT] Still loading model (${i}/180)..."
  fi
  sleep 2
done

if [[ "${READY}" -ne 1 ]]; then
  docker logs --tail 40 agentoctopus-nmt || true
  echo "[NMT] Timed out waiting for ${HEALTH_URL}" >&2
  exit 1
fi

touch "${ENV_FILE}"
grep -v '^OCTOPUS_TRANSLATE_URL=' "${ENV_FILE}" > "${ENV_FILE}.tmp" || true
echo "OCTOPUS_TRANSLATE_URL=${TRANSLATE_URL}" >> "${ENV_FILE}.tmp"
mv "${ENV_FILE}.tmp" "${ENV_FILE}"
echo "[NMT] Wrote OCTOPUS_TRANSLATE_URL=${TRANSLATE_URL} to workspace .env."
