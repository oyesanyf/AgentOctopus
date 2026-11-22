#!/usr/bin/env bash
set -euo pipefail

# AgentOctopus macOS Packaging Script (.pkg & .tar.gz)
# Supports Universal (arm64 + x86_64 via lipo) or single-architecture bundles. Zero-Touch PATH.

BIN_DIR="${1:-target/universal-release}"
VERSION="${2:-0.2.0}"
INPUT_ARCH="${3:-universal}"
DIST_DIR="${4:-deploy/macos}"
PACKAGE_NAME="agent-octopus"

VERSION="${VERSION#v}"

case "$INPUT_ARCH" in
    aarch64|arm64) MACOS_ARCH="arm64" ;;
    x86_64|amd64)  MACOS_ARCH="x86_64" ;;
    *)             MACOS_ARCH="universal" ;;
esac

BIN_DIR="$(cd "${BIN_DIR}" && pwd)"
mkdir -p "${DIST_DIR}"
DIST_DIR="$(cd "${DIST_DIR}" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BINS=(
    "agent_octopus"
    "octopus"
    "start"
    "octopus-sentinel"
    "octopus-supervisor"
    "octopus-worker"
)

for b in "${BINS[@]}"; do
    if [ ! -f "${BIN_DIR}/${b}" ]; then
        echo "[-] Missing required macOS binary: ${BIN_DIR}/${b}" >&2
        exit 1
    fi
done

echo "[*] Packaging AgentOctopus v${VERSION} for macOS (${MACOS_ARCH})"

# 1. Portable Tarball (.tar.gz)
TAR_TMP="$(mktemp -d)"
STAGE="${TAR_TMP}/${PACKAGE_NAME}-${VERSION}-macos-${MACOS_ARCH}"
mkdir -p "${STAGE}/bin" "${STAGE}/config"
for b in "${BINS[@]}"; do
    install -m 755 "${BIN_DIR}/${b}" "${STAGE}/bin/${b}"
done
install -m 644 "${ROOT_DIR}/config/egress_domains.json" "${STAGE}/config/egress_domains.json"
[ -f "${ROOT_DIR}/LICENSE-MIT" ] && install -m 644 "${ROOT_DIR}/LICENSE-MIT" "${STAGE}/LICENSE-MIT"
[ -f "${ROOT_DIR}/LICENSE-APACHE" ] && install -m 644 "${ROOT_DIR}/LICENSE-APACHE" "${STAGE}/LICENSE-APACHE"

TAR_OUT="${DIST_DIR}/${PACKAGE_NAME}-${VERSION}-macos-${MACOS_ARCH}.tar.gz"
tar -czf "${TAR_OUT}" -C "${TAR_TMP}" "$(basename "${STAGE}")"
rm -rf "${TAR_TMP}"
echo "[+] Created: ${TAR_OUT}"

# 2. Native macOS Installer (.pkg)
if command -v pkgbuild >/dev/null 2>&1; then
    PKG_ROOT="$(mktemp -d)"
    mkdir -p "${PKG_ROOT}/usr/local/bin" "${PKG_ROOT}/Library/Application Support/AgentOctopus/config"
    for b in "${BINS[@]}"; do
        install -m 755 "${BIN_DIR}/${b}" "${PKG_ROOT}/usr/local/bin/${b}"
    done
    install -m 644 "${ROOT_DIR}/config/egress_domains.json" \
        "${PKG_ROOT}/Library/Application Support/AgentOctopus/config/egress_domains.json"

    PKG_OUT="${DIST_DIR}/AgentOctopus-${VERSION}-macos-${MACOS_ARCH}.pkg"
    pkgbuild \
        --root "${PKG_ROOT}" \
        --identifier "dev.agentoctopus.runtime" \
        --version "${VERSION}" \
        --install-location "/" \
        "${PKG_OUT}"
    rm -rf "${PKG_ROOT}"
    echo "[+] Created: ${PKG_OUT}"
fi

(cd "${DIST_DIR}" && shasum -a 256 ./*.tar.gz ./*.pkg 2>/dev/null || true) > "${DIST_DIR}/SHA256SUMS-macos-${MACOS_ARCH}.txt"
echo "[+] macOS (${MACOS_ARCH}) packaging complete."
