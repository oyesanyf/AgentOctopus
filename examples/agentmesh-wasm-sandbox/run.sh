#!/usr/bin/env bash
# Cross-platform launcher for the AgentOctopus x google/agentmesh v0.2.0 Wasmtime E2E suite.
# Supports Linux (x86_64, arm64), macOS (arm64, x86_64), and Windows Git Bash (MINGW/MSYS).
# Downloads official SHA-256 verified google/agentmesh v0.2.0 binaries into .run/bin/ if not already present.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
AGENTMESH_VERSION="${AGENTMESH_VERSION:-v0.2.0}"
RUN_DIR="${SCRIPT_DIR}/.run"
BIN_DIR="${AGENTMESH_BIN_DIR:-${RUN_DIR}/bin}"

verify_sha256() {
  local file="$1"
  local expected="$2"
  local actual=""
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  else
    echo "ERROR: neither sha256sum nor shasum found to verify ${file}" >&2
    exit 1
  fi
  local actual_lc expected_lc
  actual_lc="$(printf '%s' "$actual" | tr '[:upper:]' '[:lower:]')"
  expected_lc="$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')"
  if [[ "$actual_lc" != "$expected_lc" ]]; then
    echo "ERROR: SHA-256 mismatch for ${file}: expected ${expected}, got ${actual}" >&2
    exit 1
  fi
}

resolve_release_asset() {
  local uname_s uname_m os_tag arch_tag ext sha
  uname_s="$(uname -s)"
  uname_m="$(uname -m)"

  case "$uname_s" in
    Linux*)  os_tag="Linux"; ext="tar.gz" ;;
    Darwin*) os_tag="Darwin"; ext="tar.gz" ;;
    MINGW*|MSYS*|CYGWIN*) os_tag="Windows"; ext="zip" ;;
    *)
      echo "ERROR: Unsupported OS '${uname_s}'" >&2
      exit 1
      ;;
  esac

  case "$uname_m" in
    x86_64|amd64) arch_tag="x86_64" ;;
    arm64|aarch64) arch_tag="arm64" ;;
    *)
      echo "ERROR: Unsupported architecture '${uname_m}'" >&2
      exit 1
      ;;
  esac

  local archive="agentmesh_${os_tag}_${arch_tag}.${ext}"
  case "${os_tag}_${arch_tag}" in
    Darwin_arm64)   sha="cad60616e6348d40ddd56f34fed5454981d68088ca21598140a93590ad3ed105" ;;
    Darwin_x86_64)  sha="a05faf19c69da32a3d7ed7086ca5ed1c31a7c096bd5d4f2cc14200df2271c7ce" ;;
    Linux_arm64)    sha="563ae09105de5b0b38c27452a5225d84bc73264708e6de054416a3af7a47a913" ;;
    Linux_x86_64)   sha="447b58a9257966f61ccc4957f0a28825dc8a30d48c81ac7acfe01228a68dd3d7" ;;
    Windows_arm64)  sha="39f939dab302afa16d92ad9464982a8dd0d61012c1818c587903c6bd3f1d9860" ;;
    Windows_x86_64) sha="5239a1179a55e3e974ba3899a72d59ec0f195115eead7d94ec92cecea1f2f659" ;;
    *)
      echo "ERROR: No pinned v0.2.0 digest for ${os_tag}_${arch_tag}" >&2
      exit 1
      ;;
  esac

  echo "${archive}|${sha}|${ext}"
}

EXE_SUFFIX=""
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) EXE_SUFFIX=".exe" ;;
esac

if [[ ! -f "${BIN_DIR}/agentmesh-one${EXE_SUFFIX}" || ! -f "${BIN_DIR}/agentmesh-node${EXE_SUFFIX}" ]]; then
  if [[ "${AGENTMESH_VERSION}" != "v0.2.0" ]]; then
    echo "ERROR: Pinned SHA-256 verification in run.sh targets v0.2.0; set AGENTMESH_BIN_DIR for custom builds." >&2
    exit 1
  fi
  mkdir -p "${BIN_DIR}"
  IFS='|' read -r ARCHIVE EXPECTED_SHA EXT <<<"$(resolve_release_asset)"
  URL="https://github.com/google/agentmesh/releases/download/${AGENTMESH_VERSION}/${ARCHIVE}"
  DEST="${RUN_DIR}/${ARCHIVE}"

  echo "[setup] Downloading ${URL} ..."
  curl -fsSL "$URL" -o "$DEST"
  echo "[setup] Verifying SHA-256 (${EXPECTED_SHA}) ..."
  verify_sha256 "$DEST" "$EXPECTED_SHA"

  if [[ "$EXT" == "tar.gz" ]]; then
    tar -xzf "$DEST" -C "$BIN_DIR"
    chmod +x "${BIN_DIR}/agentmesh-one" "${BIN_DIR}/agentmesh-node"
  else
    if command -v unzip >/dev/null 2>&1; then
      unzip -oq "$DEST" -d "$BIN_DIR"
    else
      tar -xf "$DEST" -C "$BIN_DIR"
    fi
  fi
fi

export AGENTMESH_BIN_DIR="${BIN_DIR}"
cd "${REPO_ROOT}"
exec cargo run --example agentmesh_live_v020_e2e
