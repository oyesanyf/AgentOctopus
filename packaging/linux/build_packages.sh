#!/usr/bin/env bash
set -euo pipefail

# AgentOctopus Linux Multi-Format Packaging Script (.deb, .rpm, .tar.gz)
# Strictly Zero-Touch PATH: installs binaries into /usr/bin without mutating user/system PATH.

BIN_DIR="${1:-target/release}"
VERSION="${2:-0.2.0}"
INPUT_ARCH="${3:-amd64}"
DIST_DIR="${4:-deploy/linux}"
PACKAGE_NAME="agent-octopus"

VERSION="${VERSION#v}"

case "$INPUT_ARCH" in
    x86_64|amd64)
        DEB_ARCH="amd64"
        RPM_ARCH="x86_64"
        ;;
    aarch64|arm64)
        DEB_ARCH="arm64"
        RPM_ARCH="aarch64"
        ;;
    *)
        DEB_ARCH="$INPUT_ARCH"
        RPM_ARCH="$INPUT_ARCH"
        ;;
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
        echo "[-] Missing required binary: ${BIN_DIR}/${b}" >&2
        exit 1
    fi
done

echo "[*] Packaging AgentOctopus v${VERSION} for Linux (${DEB_ARCH} / ${RPM_ARCH})"

# 1. Portable Tarball (.tar.gz)
TAR_TMP="$(mktemp -d)"
STAGE="${TAR_TMP}/${PACKAGE_NAME}-${VERSION}-linux-${RPM_ARCH}"
mkdir -p "${STAGE}/bin" "${STAGE}/config"
for b in "${BINS[@]}"; do
    install -m 755 "${BIN_DIR}/${b}" "${STAGE}/bin/${b}"
done
install -m 644 "${ROOT_DIR}/config/egress_domains.json" "${STAGE}/config/egress_domains.json"
[ -f "${ROOT_DIR}/LICENSE-MIT" ] && install -m 644 "${ROOT_DIR}/LICENSE-MIT" "${STAGE}/LICENSE-MIT"
[ -f "${ROOT_DIR}/LICENSE-APACHE" ] && install -m 644 "${ROOT_DIR}/LICENSE-APACHE" "${STAGE}/LICENSE-APACHE"

cat <<'EOF' > "${STAGE}/install.sh"
#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
    exec sudo "$0" "$@"
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p /usr/bin /etc/agent-octopus
for b in agent_octopus octopus start octopus-sentinel octopus-supervisor octopus-worker; do
    install -m 755 "${SCRIPT_DIR}/bin/${b}" "/usr/bin/${b}"
done
install -m 644 "${SCRIPT_DIR}/config/egress_domains.json" /etc/agent-octopus/egress_domains.json
echo "[+] Installed AgentOctopus binaries into /usr/bin (Zero-Touch PATH)."
EOF
chmod 755 "${STAGE}/install.sh"

TAR_OUT="${DIST_DIR}/${PACKAGE_NAME}-${VERSION}-linux-${RPM_ARCH}.tar.gz"
tar -czf "${TAR_OUT}" -C "${TAR_TMP}" "$(basename "${STAGE}")"
rm -rf "${TAR_TMP}"
echo "[+] Created: ${TAR_OUT}"

# 2. Debian Package (.deb)
if command -v dpkg-deb >/dev/null 2>&1; then
    DEB_TMP="$(mktemp -d)"
    mkdir -p "${DEB_TMP}/DEBIAN" "${DEB_TMP}/usr/bin" "${DEB_TMP}/etc/agent-octopus"
    for b in "${BINS[@]}"; do
        install -m 755 "${BIN_DIR}/${b}" "${DEB_TMP}/usr/bin/${b}"
    done
    install -m 644 "${ROOT_DIR}/config/egress_domains.json" "${DEB_TMP}/etc/agent-octopus/egress_domains.json"
    cat <<EOF > "${DEB_TMP}/DEBIAN/control"
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: Agent Octopus Security <oyesanyf@gmail.com>
Description: Agent Octopus Zero-Trust Wasm, Kernel Patcher, Kernel Firewall & AgentMesh Runtime
 Biologically-inspired decentralized autonomous swarm breakout defense, AWS Cedar v4.13
 zero-trust policy engine, dynamic kernel patching shield, and native kernel firewall.
EOF
    DEB_OUT="${DIST_DIR}/${PACKAGE_NAME}_${VERSION}_${DEB_ARCH}.deb"
    dpkg-deb --build --root-owner-group "${DEB_TMP}" "${DEB_OUT}"
    rm -rf "${DEB_TMP}"
    echo "[+] Created: ${DEB_OUT}"
fi

# 3. RPM Package (.rpm)
if command -v rpmbuild >/dev/null 2>&1; then
    RPM_TOP="$(mktemp -d)"
    mkdir -p "${RPM_TOP}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    SPEC_FILE="${RPM_TOP}/SPECS/${PACKAGE_NAME}.spec"
    cat <<EOF > "${SPEC_FILE}"
Name:           ${PACKAGE_NAME}
Version:        ${VERSION}
Release:        1
Summary:        Agent Octopus Zero-Trust Wasm, Kernel Patcher & AgentMesh Runtime
License:        MIT OR Apache-2.0
URL:            https://github.com/oyesanyf/AgentOctopus
AutoReqProv:    no

%description
Biologically-inspired decentralized autonomous swarm breakout defense, AWS Cedar v4.13
zero-trust policy engine, dynamic kernel patching shield, and native kernel firewall.

%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/etc/agent-octopus
install -m 755 "${BIN_DIR}/agent_octopus" %{buildroot}/usr/bin/agent_octopus
install -m 755 "${BIN_DIR}/octopus" %{buildroot}/usr/bin/octopus
install -m 755 "${BIN_DIR}/start" %{buildroot}/usr/bin/start
install -m 755 "${BIN_DIR}/octopus-sentinel" %{buildroot}/usr/bin/octopus-sentinel
install -m 755 "${BIN_DIR}/octopus-supervisor" %{buildroot}/usr/bin/octopus-supervisor
install -m 755 "${BIN_DIR}/octopus-worker" %{buildroot}/usr/bin/octopus-worker
install -m 644 "${ROOT_DIR}/config/egress_domains.json" %{buildroot}/etc/agent-octopus/egress_domains.json

%files
/usr/bin/agent_octopus
/usr/bin/octopus
/usr/bin/start
/usr/bin/octopus-sentinel
/usr/bin/octopus-supervisor
/usr/bin/octopus-worker
%config(noreplace) /etc/agent-octopus/egress_domains.json
EOF
    rpmbuild --define "_topdir ${RPM_TOP}" --target "${RPM_ARCH}" -bb "${SPEC_FILE}"
    RPM_BUILT="$(find "${RPM_TOP}/RPMS" -name '*.rpm' | head -n 1)"
    if [ -n "${RPM_BUILT}" ]; then
        RPM_OUT="${DIST_DIR}/${PACKAGE_NAME}-${VERSION}-1.${RPM_ARCH}.rpm"
        cp -f "${RPM_BUILT}" "${RPM_OUT}"
        echo "[+] Created: ${RPM_OUT}"
    fi
    rm -rf "${RPM_TOP}"
fi

(cd "${DIST_DIR}" && sha256sum ./*.tar.gz ./*.deb ./*.rpm 2>/dev/null || true) > "${DIST_DIR}/SHA256SUMS-linux-${RPM_ARCH}.txt"
echo "[+] Linux (${RPM_ARCH}) packaging complete."
