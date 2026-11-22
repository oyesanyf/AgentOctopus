# Kernel Patching and Zero-Breakout Shield

**Docs:** [Hub](README.md) | [Architecture & Security](ARCHITECTURE_AND_SECURITY_MODEL.md) | [Kernel Shield](KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md) | [CLI & Policy](CLI_AND_POLICY_REFERENCE.md) | [Operations & API](OPERATIONS_AND_API_GUIDE.md) | [AgentMesh + Wasm](AGENTMESH_WASM_INTEGRATION.md) | [Red Teaming](ADVERSARIAL_DEFENSE_AND_RED_TEAMING.md) | [Root README](../README.md)

> **Architectural Thesis (Requirement R6): "A kernel bug must NEVER allow break-out or break-in."**

AgentOctopus combines a **Universal Multi-OS Host Kernel CVE/KEV Scanner & Patch Orchestrator** with a **Zero-Reboot Dynamic Kernel-Boundary & Virtual-Patching Shield**. While waiting for a vendor patch—or between installing a kernel package on disk and rebooting the host—AgentOctopus deterministically seals both **break-out** (sandbox escape / local privilege escalation) and **break-in** (remote network / driver / protocol exploitation) paths at runtime.

---

## Why Unsafe Ring-0 Binary Splicing Is Intentionally Avoided

AgentOctopus **intentionally does not** write raw machine-code detours or inline hooks into `ntoskrnl.exe` or `vmlinux` memory:
- On Windows, modifying kernel text violates **PatchGuard (Kernel Patch Protection)**, **HVCI (Hypervisor-Protected Code Integrity)**, and **WDAC**.
- On Linux, unsigned live kernel text mutation violates **Linux Kernel Lockdown (`integrity` / `confidentiality`)** and module-signing policies.
- On macOS, kernel-space patching violates **System Integrity Protection (SIP)** and Signed System Volume (SSV) sealing.

Instead, AgentOctopus delegates actual kernel binary updates to **vendor-signed rebootless livepatch engines and native OS patchers**, while enforcing **zero-reboot virtual patching** through kernel-supported control planes (Wasmtime Tier-1, `seccomp-BPF`, Windows process mitigations + `\\.\OsoosiDriver`, Seatbelt, BSD `unveil`/`pledge`/Capsicum, WFP, `nftables`/Netlink/`SOCK_DESTROY`, `/sbin/pfctl`, and tighten-only AWS Cedar rules).

---

## Universal All-OS Host Kernel CVE/KEV Scanner and Patch Orchestrator

Sources: [`src/security/kernel_patcher/`](../src/security/kernel_patcher/), [`src/security/kernel_patcher/discovery/`](../src/security/kernel_patcher/discovery/), [`src/security/kernel_patcher/patcher.rs`](../src/security/kernel_patcher/patcher.rs), [`src/web/api.rs`](../src/web/api.rs).

Exposed via `octopus kernel-patch` (alias `patch-kernel`), `agent_octopus patch-kernel`, and `GET /api/kernel-patcher/status`:

1. **OS/Distro Fingerprinting & CPE 2.3 Mapping (`cpe.rs`, `discovery/*.rs`)**: Auto-detects running OS family, kernel release (`uname` / Win32 / Darwin / BSD), and `/etc/os-release` ID, mapping them to NIST CPE 2.3 identifiers (e.g., `cpe:2.3:o:freebsd:freebsd:...`, `cpe:2.3:o:openbsd:openbsd:...`, `cpe:2.3:o:netbsd:netbsd:...`).
2. **NIST NVD API 2.0 + CISA KEV Ranking**: Queries NIST NVD API 2.0 (using `NVD_API_KEY` from environment only; CLI `--api-key`/`--nvd-api-key` flags are rejected) and CISA's Known Exploited Vulnerabilities (KEV) catalog, ranking actively exploited KEVs first.
3. **Fail-Closed Privilege & Dry-Run Execution**: `--dry-run` inspects posture and prints the exact patch plan without privileges; `--apply` / `--execute` fails closed unless running as Administrator (Windows) or `root` (Unix).

### Supported 6 OS Families and 17 Linux Distributions

| OS Family / Distro Group | Rebootless Livepatch / Posture Check | Pinned Native Patch Binary & Plan |
|---|---|---|
| **Windows** (10/11, Server 2019/2022/2025) | Windows Hotpatch (`HKLM\...\Hotpatch\Enabled`), HVCI, VBS, `VulnerableDriverBlocklistEnable`, `CBS\RebootPending`, `RebootRequired`, `PendingFileRenameOperations` | `C:\Windows\System32\UsoClient.exe` (`StartScan`, `StartDownload`, `StartInstall`) |
| **Linux: Ubuntu / Debian / Kali** | `/usr/bin/canonical-livepatch` or `/snap/bin/canonical-livepatch` (`refresh`), `/usr/bin/pro` (`status --wait`), `/sys/kernel/livepatch/*/enabled` | `/usr/bin/apt-get upgrade -y <linux-image-generic\|linux-image-amd64\|linux-image-arm64>` (`DEBIAN_FRONTEND=noninteractive`) |
| **Linux: RHEL / Fedora / Rocky / Alma / CentOS / Amazon Linux** | `/usr/sbin/kpatch` or `/usr/bin/kpatch` (`load --all`), `/sys/kernel/livepatch` | `/usr/bin/dnf upgrade --security -y kernel` or `/usr/bin/yum update --security -y kernel` |
| **Linux: Oracle Linux** | `ksplice` (`/usr/bin/uptrack-upgrade` or `/usr/sbin/uptrack-upgrade -y`) | Followed by `dnf` / `yum` security kernel upgrade |
| **Linux: SUSE / SLES / openSUSE** | `/usr/sbin/klp`, `/usr/bin/klp`, `/usr/sbin/kgr`, `/usr/bin/kgr` (`status`) | `/usr/bin/zypper --non-interactive patch --category security` |
| **Linux: Arch Linux** | `/sys/kernel/livepatch` | `/usr/bin/pacman -Syu --noconfirm linux` |
| **Linux: Alpine Linux** | `/sys/kernel/livepatch` | `/sbin/apk` or `/usr/sbin/apk` (`upgrade --no-cache linux-lts`) |
| **Linux: NixOS / Gentoo / Flatcar** | `/sys/kernel/livepatch` | `/run/current-system/sw/bin/nixos-rebuild switch --upgrade` (NixOS symlink into `/nix/store/` explicitly validated), `/usr/bin/emerge --update --oneshot sys-kernel/gentoo-kernel`, `/usr/bin/update_engine_client -update` |
| **macOS** (Apple Silicon & Intel) | Rapid Security Response (RSR) detection + `/usr/bin/csrutil status` (SIP) | `/usr/sbin/softwareupdate --list` and `--install --recommended --agree-to-license` |
| **FreeBSD** | Native release/patch inspection | `/usr/sbin/freebsd-update --not-running-from-cron fetch install` |
| **OpenBSD** | Native binary patch inspection (`-c` in `--dry-run`) | `/usr/sbin/syspatch` |
| **NetBSD** | Native sysupgrade / binary pkg inspection | `/usr/sbin/sysupgrade auto` or `/usr/pkg/sbin/pkgin -y full-upgrade` |

---

## Zero-Reboot Virtual-Patching Shield: No Break-Out and No Break-In

Sources: [`src/security/virtual_patch_shield.rs`](../src/security/virtual_patch_shield.rs), [`src/security/kernel_patcher/shield_state.rs`](../src/security/kernel_patcher/shield_state.rs), [`src/arm/kernel_sentinel_arm.rs`](../src/arm/kernel_sentinel_arm.rs), [`src/security/host_network_isolation.rs`](../src/security/host_network_isolation.rs), [`src/research_ingest.rs`](../src/research_ingest.rs).

### 1. No Break-Out (Eliminating Local Kernel EoP and Sandbox Escape Surfaces)

- **Tier-1 Wasmtime Promotion (`--sandbox wasm-strict`, `--wasm-promote`, `virtual_patch_shield.promote_wasm_on_cve`)**: When active, untrusted workloads are restricted to `.wasm`/`.wat` modules (native binaries fail closed with exit code `2`), denying guests any direct host kernel syscalls.
- **Linux `seccomp-BPF` High-CVE & Escape Clamp (`src/security/linux_sandbox.rs`)**:
  - **Exotic Socket Families (`EXOTIC_BLOCKED_SOCKET_FAMILIES` -> `EAFNOSUPPORT`)**: `AF_PACKET` (`17`), `AF_RDS` (`21`), `AF_TIPC` (`30`), `AF_VSOCK` (`40`).
  - **12 High-CVE Kernel EoP Syscalls (`EPERM` on `x86_64` & `aarch64`)**: `ptrace`, `init_module`, `delete_module`, `kexec_load`, `add_key`, `request_key`, `keyctl`, `perf_event_open`, `finit_module`, `kexec_file_load`, `bpf`, `userfaultfd`.
  - **15 Sandbox-Escape Syscalls (`EPERM`) + `clone3` (`LINUX_SYS_CLONE3 = 435` returning `LINUX_ENOSYS = 38`)**: `pivot_root`, `mount`, `umount2`, `unshare`, `setns`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`.
- **Windows Kernel EoP & BYOVD Clamp (`windows_sandbox.rs` + `kernel_sentinel_arm.rs`)**:
  - `compute_windows_mitigation_policy_mask(disallow_win32k, shield_active)` enforces `EXTENSION_POINT_DISABLE`, `IMAGE_LOAD_NO_REMOTE`, `IMAGE_LOAD_NO_LOW_LABEL`, and `IMAGE_LOAD_PREFER_SYSTEM32` (plus `WIN32K_SYSTEM_CALL_DISABLE` when `disallow_win32k && shield_active`).
  - `KernelSentinelArm` connects to `\\.\OsoosiDriver` (`FILE_DEVICE_UNKNOWN 0x22`, `METHOD_BUFFERED`, `FILE_ANY_ACCESS`) using `DeviceIoControl` IOCTLs computed via `ctl_code(0x22, fn, 0, 0)` from `OSOOSI_IOCTL_BASE` function codes `0x800`..`0x805` (`IOCTL_OSOOSI_GET_STATUS` function `0x800`, `SET_MODE` `0x801`, `ADD_BLOCK_PATH` `0x802`, `ADD_BLOCK_HASH` `0x803`, `CLEAR_RULES` `0x804`—refused if `shield_locked_until_reboot`, `POLL_INTERCEPTIONS` `0x805`) to block `BYOVD_VULNERABLE_DRIVERS` (`RTCore64.sys`, `DBUtil_2_3.sys`, `iqvw64e.sys`, `gdrv.sys`).
- **macOS Seatbelt Kernel Clamp (`macos_sandbox.rs`)**: Denies `system-kext-load`, `iokit-open`, `system-fsctl`, `system-nfssvc`, `system-privilege`, `system-acct`, and `system-swap`.
- **BSD Process & Capability Clamps (`bsd_sandbox.rs`)**: OpenBSD `unveil()` + `pledge()` + `setrlimit`; FreeBSD `procctl(PROC_NO_NEW_PRIVS_CTL)` + Capsicum `cap_enter()`; NetBSD `setrlimit`.

### 2. No Break-In (Kernel Network Perimeter and Tighten-Only Cedar Hot-Reload)

- **Dynamic Inbound Perimeter Shield (`host_network_isolation.rs`)**: Blocks vulnerable kernel network/driver ports (`VIRTUAL_PATCH_INBOUND_PORTS = [80, 135, 137, 138, 139, 443, 445, 3389, 5353, 5355, 5985, 5986]`) and IPv6 RA/ICMPv6 attack vectors (covering SMBv3, HTTP.sys, `ksmbd`, WinRM, RDP, NetBIOS, mDNS/LLMNR, IPv6 RCE) in `<1ms` without rebooting:
  - **Windows**: Windows Filtering Platform (`FwpmFilterAdd0`).
  - **Linux**: Pinned `/usr/sbin/nft` (`table inet agent_octopus_vpatch`) + `AF_NETLINK` `RTN_BLACKHOLE` + `INET_DIAG` `SOCK_DESTROY` (code `21`).
  - **macOS / BSD**: `/sbin/pfctl -a agent_octopus_vpatch` and `/dev/pf` binary `ioctl` anchors.
- **Tighten-Only Cedar Hot-Reload (`research_ingest.rs`)**: `hotload_cve_forbid_policies_into_runtime` injects newly synthesized CVE `forbid(...)` policies directly into `WebState.gateway`, `ContainmentRing.cedar_gate`, and `ProxyState.cedar_engine` with zero restart.

---

## The 5 Foolproof Invariants

1. **`shield_locked_until_reboot` Latch (Closing the Patched-on-Disk / Vulnerable-in-RAM Gap)**:
   - Installing a kernel package via `apt-get`, `dnf`, `zypper`, `pacman`, `apk`, `UsoClient.exe`, `softwareupdate`, `freebsd-update`, or `syspatch` does not update the running in-memory kernel until reboot unless a livepatch engine confirms in-memory activation.
   - Whenever `reboot_required && !livepatch_mitigated`, `shield_locked_until_reboot` latches `true` in `logs/kernel_shield_posture.json` (overridable via `AGENT_OCTOPUS_SHIELD_POSTURE_PATH` for isolated tests) with a self-committed `posture_sha256`. `attempt_loosen_shield` and `IOCTL_OSOOSI_CLEAR_RULES` refuse to disarm until `confirm_rebooted_into_kernel` observes `!reboot_required` and a changed running kernel release.
2. **Zero Shell Injection, Zero PATH Hijack, Zero Env Poisoning (`validation.rs`)**:
   - Never uses `sh -c`, `cmd /c`, or `powershell -Command`; forbids `FORBIDDEN_SHELL_BASENAMES` (`sh`, `bash`, `cmd.exe`, `powershell.exe`).
   - Resolves patcher binaries strictly from pinned absolute system paths, calls `cmd.env_clear()` via `apply_scrubbed_env`, strips 16 `UNTRUSTED_ENV_VARS` (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, etc.), and strictly allowlist-validates `/etc/os-release` IDs, `uname` strings, package names, `CVE-YYYY-NNNN+` IDs, and CPE 2.3 strings.
3. **Fail-Closed Offline / Rate-Limited Telemetry (`telemetry_degraded_fail_closed`)**:
   - If NVD or CISA KEV feeds time out, return HTTP `429`/`5xx`, return malformed JSON, or the host is air-gapped, AgentOctopus **never fails open** (`"0 CVEs -> no shield"`). `KernelShieldPosture::default_fail_closed()` sets `telemetry_degraded_fail_closed = true` and keeps proactive No-Break-Out and No-Break-In shields engaged.
4. **Monotonic Tighten-Only Rules with Merkle Receipts & Read-Back Verification**:
   - Untrusted feeds and runtime events can only tighten rules; posture persistence rejects symlinks and performs post-write read-back SHA-256 verification; every virtual-patch update emits an RFC 6962 `VirtualPatchShieldReceipt`.
5. **Adversarial Regression Proof Suites**:
   - Covered by `tests/virtual_patch_shield_tests.rs`, `tests/kernel_sentinel_tests.rs`, `tests/octopus_cli_e2e_tests.rs`, and the `#[cfg(test)]` unit test suites in `src/security/kernel_patcher/mod.rs` and `src/security/kernel_patcher/validation.rs`, testing malicious `/etc/os-release` metacharacters (`;`, `|`, `$()`, backticks), `PATH` shim hijacking, offline/corrupt NVD/KEV feeds, `reboot_pending` in-RAM vulnerability windows, and cross-OS CPE/argv plans across Windows, all 17 Linux distros, macOS, and FreeBSD/OpenBSD/NetBSD.
