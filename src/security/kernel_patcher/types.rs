//! Core types for OS kernel discovery, vulnerability scanning, and patch orchestration.

use super::error::PatcherError;
use serde::{Deserialize, Serialize};

/// Operating system platform family detected on the host.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsFamily {
    Linux,
    Windows,
    MacOS,
    FreeBSD,
    OpenBSD,
    NetBSD,
    Unknown(String),
}

impl OsFamily {
    /// Returns `true` when the detected platform is Linux.
    #[inline]
    #[must_use]
    pub fn is_linux(&self) -> bool {
        matches!(self, Self::Linux)
    }

    /// Returns `true` when the detected platform is Windows.
    #[inline]
    #[must_use]
    pub fn is_windows(&self) -> bool {
        matches!(self, Self::Windows)
    }

    /// Returns `true` when the detected platform is macOS.
    #[inline]
    #[must_use]
    pub fn is_macos(&self) -> bool {
        matches!(self, Self::MacOS)
    }

    /// Returns `true` when the detected platform is FreeBSD, OpenBSD, or NetBSD.
    #[inline]
    #[must_use]
    pub fn is_bsd(&self) -> bool {
        matches!(self, Self::FreeBSD | Self::OpenBSD | Self::NetBSD)
    }
}

impl std::fmt::Display for OsFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Linux => write!(f, "Linux"),
            Self::Windows => write!(f, "Windows"),
            Self::MacOS => write!(f, "macOS"),
            Self::FreeBSD => write!(f, "FreeBSD"),
            Self::OpenBSD => write!(f, "OpenBSD"),
            Self::NetBSD => write!(f, "NetBSD"),
            Self::Unknown(name) => write!(f, "Unknown ({name})"),
        }
    }
}

/// Linux distribution family classified from `/etc/os-release` `ID` and `ID_LIKE`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxDistro {
    Ubuntu,
    Debian,
    Kali,
    Rhel,
    Fedora,
    Rocky,
    Alma,
    CentOS,
    AmazonLinux,
    OracleLinux,
    Sles,
    OpenSuse,
    Arch,
    Alpine,
    NixOS,
    Gentoo,
    Flatcar,
    Unknown(String),
}

impl std::fmt::Display for LinuxDistro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ubuntu => write!(f, "ubuntu"),
            Self::Debian => write!(f, "debian"),
            Self::Kali => write!(f, "kali"),
            Self::Rhel => write!(f, "rhel"),
            Self::Fedora => write!(f, "fedora"),
            Self::Rocky => write!(f, "rocky"),
            Self::Alma => write!(f, "almalinux"),
            Self::CentOS => write!(f, "centos"),
            Self::AmazonLinux => write!(f, "amzn"),
            Self::OracleLinux => write!(f, "ol"),
            Self::Sles => write!(f, "sles"),
            Self::OpenSuse => write!(f, "opensuse"),
            Self::Arch => write!(f, "arch"),
            Self::Alpine => write!(f, "alpine"),
            Self::NixOS => write!(f, "nixos"),
            Self::Gentoo => write!(f, "gentoo"),
            Self::Flatcar => write!(f, "flatcar"),
            Self::Unknown(id) => write!(f, "{id}"),
        }
    }
}

/// Rebootless livepatch engine detected on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LivepatchEngine {
    CanonicalLivepatch,
    UbuntuPro,
    Kpatch,
    KspliceUptrack,
    KlpKgraft,
    WindowsHotpatch,
    SysfsGeneric,
    None,
}

/// Live in-memory kernel livepatch status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivepatchStatus {
    pub engine: LivepatchEngine,
    pub active_in_ram: bool,
    #[serde(default)]
    pub sysfs_patches: Vec<String>,
    pub details: String,
}

impl Default for LivepatchStatus {
    fn default() -> Self {
        Self {
            engine: LivepatchEngine::None,
            active_in_ram: false,
            sysfs_patches: Vec::new(),
            details: "No active livepatch engine detected".to_string(),
        }
    }
}

/// Tracks the "Patched on Disk, Still Vulnerable in RAM" pre-reboot gap (Foolproof Invariant #1).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RebootPendingStatus {
    pub reboot_required: bool,
    pub running_kernel: String,
    pub newest_installed_kernel: Option<String>,
    #[serde(default)]
    pub reasons: Vec<String>,
    pub livepatch_mitigated: bool,
    pub shield_locked_until_reboot: bool,
}

/// Host kernel hardening posture metadata across Windows, Linux, macOS, and BSD.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OsSecurityPosture {
    pub hvci_enabled: Option<bool>,
    pub vbs_enabled: Option<bool>,
    pub vulnerable_driver_blocklist_enabled: Option<bool>,
    pub hotpatch_enrolled: Option<bool>,
    pub lockdown_mode: Option<String>,
    #[serde(default)]
    pub livepatch_sysfs_count: usize,
    pub sip_enabled: Option<bool>,
    pub rsr_version: Option<String>,
    pub kern_securelevel: Option<i32>,
}

/// One deterministic argv-only command step inside a `PatchPlan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchStep {
    pub command: String,
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    pub os_subsystem: String,
    pub phase: String,
}

/// Complete multi-OS / multi-distro kernel patch plan (livepatch-first -> distro-native upgrade).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchPlan {
    pub os_family: OsFamily,
    pub distro: Option<LinuxDistro>,
    pub primary_command: String,
    pub primary_args: Vec<String>,
    pub os_subsystem: String,
    pub steps: Vec<PatchStep>,
    pub rebootless_livepatch_preferred: bool,
    pub requires_elevation: bool,
}

/// Health status of NVD/KEV threat intelligence telemetry (Foolproof Invariant #3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryHealthStatus {
    Healthy,
    DegradedFailClosed {
        reason: String,
        http_status: Option<u16>,
    },
}

/// Deterministic virtual-patch enforcement surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VirtualPatchSurface {
    WasmTier1Promotion,
    LinuxSeccompHighCveSyscalls,
    WindowsWin32kAndImageLoadClamp,
    WindowsOsoosiByovdBlock,
    MacOsSeatbeltKernelClamp,
    KernelPerimeterInboundShield,
    CedarTightenOnlyForbid,
}

/// Snapshot of the active Zero-Reboot Virtual-Patching Shield state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualPatchShieldState {
    pub active: bool,
    pub shield_locked_until_reboot: bool,
    pub telemetry_degraded_fail_closed: bool,
    pub monotonic_revision: u64,
    #[serde(default)]
    pub active_surfaces: Vec<VirtualPatchSurface>,
    #[serde(default)]
    pub mitigated_cves: Vec<String>,
    pub read_back_verified: bool,
    pub merkle_root: String,
}

/// RFC 6962 Merkle audit receipt for kernel patch & shield state transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchAuditReceipt {
    pub sequence: u64,
    pub timestamp_utc: String,
    pub action: String,
    pub os_family: String,
    pub target_cpe: String,
    pub shield_locked_until_reboot: bool,
    pub telemetry_degraded_fail_closed: bool,
    pub monotonic_revision: u64,
    pub leaf_hash_hex: String,
    pub merkle_root_hex: String,
}

/// Combined host discovery, distro CPE, livepatch, reboot-pending, and security posture snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKernelPostureSnapshot {
    pub host_kernel: HostKernelInfo,
    pub distro: Option<LinuxDistro>,
    pub distro_cpe23: Option<String>,
    pub livepatch: LivepatchStatus,
    pub reboot_pending: RebootPendingStatus,
    pub security_posture: OsSecurityPosture,
}

/// Host operating system and kernel version discovery metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKernelInfo {
    /// Operating system platform family.
    pub os_family: OsFamily,
    /// Kernel release version (e.g. "6.8.0-45-generic", "10.0.22631.3880", "23.4.0").
    pub kernel_release: String,
    /// User-facing OS version (e.g. "24.04", "Windows 11 23H2", "14.4.1").
    pub os_version: String,
    /// NIST Common Platform Enumeration 2.3 formatted identifier.
    pub cpe23: String,
    /// Target hardware CPU architecture (e.g. "x86_64", "aarch64").
    pub architecture: String,
}

impl HostKernelInfo {
    /// Probes the host system and constructs verified `HostKernelInfo`.
    pub fn detect_host_kernel() -> Result<Self, PatcherError> {
        super::discovery::detect_host_kernel()
    }

    /// Returns the CPE 2.3 formatted string.
    #[inline]
    #[must_use]
    pub fn to_cpe23(&self) -> String {
        self.cpe23.clone()
    }
}

/// Kernel vulnerability record parsed from NVD API 2.0 / CISA KEV catalog.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KernelVulnerability {
    /// Common Vulnerabilities and Exposures (CVE) identifier (e.g. "CVE-2024-21338").
    pub cve_id: String,
    /// Primary vulnerability description.
    pub description: String,
    /// CVSS v3.1 base score if scored (0.0 - 10.0).
    pub cvss_v31_score: Option<f32>,
    /// CVSS v3.1 qualitative severity rating ("LOW", "MEDIUM", "HIGH", "CRITICAL").
    pub cvss_v31_severity: Option<String>,
    /// Whether this vulnerability is listed in the CISA Known Exploited Vulnerabilities catalog.
    pub is_cisa_kev: bool,
    /// Date added to the CISA KEV catalog (YYYY-MM-DD).
    pub cisa_exploit_add: Option<String>,
    /// Remediation due date mandated by CISA BOD 22-01.
    pub cisa_action_due: Option<String>,
    /// Required remediation action specified by CISA.
    pub cisa_required_action: Option<String>,
    /// Descriptive vulnerability name from CISA KEV.
    pub cisa_vulnerability_name: Option<String>,
}

/// Options configuring an NVD kernel vulnerability scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Target CPE 2.3 string (defaults to auto-detected host kernel CPE).
    pub cpe: Option<String>,
    /// Minimum CVSS score threshold for returned findings (inclusive).
    pub min_cvss_score: Option<f32>,
    /// If true, only return vulnerabilities confirmed in the CISA KEV catalog.
    pub kev_only: bool,
    /// Optional NVD API key (resolved from `std::env::var("NVD_API_KEY")`, never CLI arguments).
    pub api_key: Option<String>,
    /// HTTP request timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            cpe: None,
            min_cvss_score: None,
            kev_only: false,
            api_key: None,
            timeout_secs: 30,
        }
    }
}

/// Result of an OS-native kernel patch execution or dry-run evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchExecutionResult {
    /// True if executed in safe simulation mode with zero system modifications.
    pub dry_run: bool,
    /// Primary executable command that was or would be invoked.
    pub command: String,
    /// Command-line arguments.
    pub args: Vec<String>,
    /// Whether the process exited successfully (exit code 0).
    pub success: bool,
    /// Combined stdout and stderr output.
    pub output: String,
    /// Subsystem identifier (e.g. "canonical-livepatch", "apt-get", "dnf", "UsoClient", "softwareupdate").
    pub os_subsystem: String,
    #[serde(default)]
    pub steps: Vec<PatchStep>,
    #[serde(default)]
    pub step_outputs: Vec<String>,
    #[serde(default)]
    pub reboot_pending: Option<RebootPendingStatus>,
    #[serde(default)]
    pub shield_locked_until_reboot: bool,
    #[serde(default)]
    pub audit_receipt: Option<PatchAuditReceipt>,
}
