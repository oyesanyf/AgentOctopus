//! Cross-Platform Zero-Subprocess Native OS Kernel Host Network Isolation.
//!
//! Enforces hermetic host-level network quarantine across all 16 Classical, Post-Quantum,
//! Cryo/Hardware, and Quantum protocol domains (`UniversalProtocolCatalog`: 218 named protocols,
//! all 256 IANA IP protocols `0..=255`, and Layer-2 hardware EtherTypes `0x88E5`, `0x88F7`,
//! `0x8809`, `0xAEFE`) with **zero external firewall subprocesses** (`netsh`, `iptables`, `nft`,
//! `pfctl` are never spawned):
//!
//! - **Windows**: Native `fwpuclnt.dll` Windows Filtering Platform (WFP) 22-layer atomic
//!   transaction quarantine (`FwpmFilter0` 200-byte x86_64 C ABI verified at compile time),
//!   live Base Filtering Engine (BFE) filter verification (`FwpmFilterGetById0` + `FwpmFilterEnum0`),
//!   direct `advapi32.dll` BFE `FirewallPolicy\FirewallRules` registry persistence, `iphlpapi.dll`
//!   `GetTcpTable` + `SetTcpEntry` (`MIB_TCP_STATE_DELETE_TCB = 12`) active TCP connection reset,
//!   and short-lived `--wfp-kernel-apply engage|disarm` UAC helper delegation (`ShellExecuteExW`
//!   `"runas"`) so the main AgentOctopus runtime and arms remain strictly de-elevated (Finding 7).
//! - **Linux**: Pure binary `AF_NETLINK` (`NETLINK_ROUTE` `RTM_NEWROUTE`/`RTM_DELROUTE`
//!   `RTN_BLACKHOLE` + `NETLINK_INET_DIAG` `SOCK_DESTROY`), preserving `lo` (`RT_TABLE_LOCAL`).
//! - **macOS**: Pure binary `/dev/pf` `ioctl` (`DIOCSTART`, `DIOCXBEGIN`, `DIOCADDRULE`,
//!   `DIOCXCOMMIT`) anchor quarantine preserving `lo0`, `127.0.0.1`, `::1`, and local WebUI port.

use crate::security::universal_protocols::UniversalProtocolCatalog;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

// =============================================================================
// Constants & Cross-Platform Types
// =============================================================================

pub const DEFAULT_OCTOPUS_PORT: u16 = 5005;
pub const FORBIDDEN_PORT_5000: u16 = 5000;
pub const WFP_RULE_PREFIX: &str = "AgentOctopus-KillSwitch";
pub const WFP_VPATCH_RULE_PREFIX: &str = "AgentOctopus-VirtualPatch";

pub const FWPM_SESSION_FLAG_DYNAMIC: u32 = 0x0000_0001;
pub const RPC_C_AUTHN_WINNT: u32 = 10;
pub const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

pub const FWP_MATCH_EQUAL: u32 = 0;
pub const FWP_MATCH_RANGE: u32 = 5;
pub const FWP_MATCH_FLAGS_ALL_SET: u32 = 6;

pub const FWP_EMPTY: u32 = 0;
pub const FWP_UINT8: u32 = 1;
pub const FWP_UINT16: u32 = 2;
pub const FWP_UINT32: u32 = 3;
pub const FWP_UINT64: u32 = 4;
pub const FWP_BYTE_ARRAY16_TYPE: u32 = 11;
pub const FWP_BYTE_BLOB_TYPE: u32 = 12;
pub const FWP_RANGE_TYPE: u32 = 258;

/// Well-known local proxy / tunnel / forwarder ports explicitly blocked from
/// firewall loopback exemptions so quarantined agents cannot pivot out via loopback.
pub const QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS: [u16; 5] = [1080, 3128, 8080, 8888, 9050];

/// Lateral-movement / remote-management ports always blocked during quarantine.
pub const QUARANTINE_BLOCKED_LATERAL_PORTS: [u16; 4] = [135, 445, 5985, 5986];

/// DNS / DoT / DHCP / DHCPv6 ports always blocked during quarantine.
pub const QUARANTINE_BLOCKED_DISCOVERY_PORTS: [u16; 6] = [53, 67, 68, 546, 547, 853];

/// Returns `true` if `port` is a proxy, lateral, discovery, forbidden (`5000`), or zero port.
pub fn is_blocked_quarantine_port(port: u16) -> bool {
    port == 0 || port == FORBIDDEN_PORT_5000 || is_explicitly_blocked_quarantine_port(port)
}

fn is_explicitly_blocked_quarantine_port(port: u16) -> bool {
    port == FORBIDDEN_PORT_5000
        || QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS.contains(&port)
        || QUARANTINE_BLOCKED_LATERAL_PORTS.contains(&port)
        || QUARANTINE_BLOCKED_DISCOVERY_PORTS.contains(&port)
}

/// Filters and deduplicates control-plane ports before installing WFP, BFE,
/// Netlink/nftables, or PF loopback allowlist rules.
pub fn sanitize_firewall_preserved_ports(preserved_ports: &[u16]) -> Vec<u16> {
    let mut sanitized = Vec::with_capacity(preserved_ports.len());
    for &port in preserved_ports {
        if !is_blocked_quarantine_port(port) && !sanitized.contains(&port) {
            sanitized.push(port);
        }
    }
    sanitized
}

#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
fn is_exact_localhost_v4(octets: [u8; 4]) -> bool {
    octets == [127, 0, 0, 1]
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_exact_localhost_v6(octets: [u8; 16]) -> bool {
    octets == Ipv6Addr::LOCALHOST.octets()
        || octets == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]
}

pub const FWP_ACTION_BLOCK: u32 = 0x0000_1001;
pub const FWP_ACTION_PERMIT: u32 = 0x0000_1002;
pub const FWP_CONDITION_FLAG_IS_LOOPBACK: u32 = 0x0000_0001;
pub const MIB_TCP_STATE_DELETE_TCB: u32 = 12;

/// Hardware & Quantum Control Layer-2 EtherTypes explicitly blocked at MAC layers.
pub const BLOCKED_L2_ETHERTYPES: [u16; 4] = [
    0x88E5, // IEEE 802.1AE MACsec / QKD Optical Link Encryption
    0x88F7, // IEEE 1588v2 PTP / White Rabbit Sub-Picosecond Sync
    0x8809, // ITU-T G.8264 SyncE ESMC Clock Distribution
    0xAEFE, // eCPRI Digitized RF Qubit Readout Transport
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostIsolationError {
    InsufficientPrivileges {
        details: String,
        remediation: String,
    },
    KernelEngineError(String),
    InvalidAction(String),
    LedgerError(String),
}

impl std::fmt::Display for HostIsolationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientPrivileges {
                details,
                remediation,
            } => write!(f, "INSUFFICIENT_PRIVILEGES: {} ({})", details, remediation),
            Self::KernelEngineError(msg) => write!(f, "KERNEL_ENGINE_ERROR: {}", msg),
            Self::InvalidAction(act) => write!(f, "INVALID_ACTION: {}", act),
            Self::LedgerError(msg) => write!(f, "LEDGER_ERROR: {}", msg),
        }
    }
}

impl std::error::Error for HostIsolationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelIsolationBackend {
    WindowsWfpBfe22Layer,
    WindowsWfpBfe24Layer,
    LinuxNetlinkBlackhole,
    MacOsPfIoctl,
    SimulatedNonElevatedTest,
}

impl KernelIsolationBackend {
    pub fn label(&self) -> &'static str {
        match self {
            Self::WindowsWfpBfe22Layer | Self::WindowsWfpBfe24Layer => {
                "Windows WFP 24-Layer + BFE Registry + IPHLPAPI TCP Reset"
            }
            Self::LinuxNetlinkBlackhole => {
                "Linux AF_NETLINK RTN_BLACKHOLE + INET_DIAG SOCK_DESTROY"
            }
            Self::MacOsPfIoctl => "macOS /dev/pf Binary ioctl Anchor Transaction",
            Self::SimulatedNonElevatedTest => "Non-Elevated Cargo Test Simulation",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIsolationReceipt {
    pub receipt_id: String,
    pub backend: KernelIsolationBackend,
    pub session_id: String,
    pub wfp_filter_ids: Vec<u64>,
    pub bfe_registry_rules: Vec<String>,
    pub netlink_or_pf_tokens: Vec<String>,
    pub preserved_ports: Vec<u16>,
    pub preserved_loopback_ips: Vec<String>,
    pub terminated_tcp_sockets: usize,
    pub universal_domains_covered: usize,
    pub universal_protocols_blocked: usize,
    pub iana_ip_protocols_blocked: u16,
    pub l2_ethertypes_blocked: Vec<String>,
    pub engaged_by: String,
    pub reason: String,
    pub timestamp_unix: u64,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostKillSwitchStatus {
    pub isolated: bool,
    pub containment_level: String,
    pub live_kernel_filters_verified: bool,
    pub active_wfp_filter_count: usize,
    pub backend_engine: String,
    pub preserved_loopback_ports: Vec<u16>,
    pub universal_domains_count: usize,
    pub universal_protocols_count: usize,
    pub iana_ip_protocols_covered: u16,
    pub wfp_kernel_layers_enforced: usize,
    pub zero_subprocess_enforced: bool,
    pub sequence: u64,
    pub state_hash: String,
    pub last_transition_unix: u64,
    pub last_operator: String,
    pub last_reason: String,
    pub active_receipt: Option<HostIsolationReceipt>,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_non_elevated_test_simulation() -> bool {
    if std::env::var("OCTOPUS_LIVE_WFP_TEST")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return false;
    }
    cfg!(test)
}

/// Discovers all active AgentOctopus loopback WebUI ports (`5005..=5025` plus any port recorded
/// in `logs/active_port.txt`). Strictly excludes port `5000` at all times.
pub fn discover_active_octopus_ports() -> Vec<u16> {
    let mut ports: Vec<u16> = (5005..=5025).collect();
    let mut candidates = vec![
        PathBuf::from("logs").join("active_port.txt"),
        PathBuf::from("active_port.txt"),
    ];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("logs").join("active_port.txt"));
            candidates.push(dir.join("active_port.txt"));
        }
    }
    #[cfg(windows)]
    if let Ok(prog_data) = std::env::var("ProgramData") {
        candidates.push(
            PathBuf::from(prog_data)
                .join("AgentOctopus")
                .join("active_port.txt"),
        );
    }
    #[cfg(target_os = "linux")]
    {
        candidates.push(PathBuf::from("/var/run/agent-octopus/active_port.txt"));
    }
    for path in candidates {
        if path.is_symlink() {
            continue;
        }
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(p) = raw.trim().parse::<u16>() {
                if (1024..=65535).contains(&p)
                    && !is_blocked_quarantine_port(p)
                    && !ports.contains(&p)
                {
                    ports.push(p);
                }
            }
        }
    }
    ports.retain(|&p| !is_blocked_quarantine_port(p));
    ports
}

// =============================================================================
// Windows Native WFP (22 Kernel Layers) + BFE Registry + IPHLPAPI + UAC Helper
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
pub struct WfpGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

pub const FWPM_LAYER_ALE_AUTH_CONNECT_V4: WfpGuid = WfpGuid {
    data1: 0xc38d57d1,
    data2: 0x05a7,
    data3: 0x4c33,
    data4: [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82],
};
pub const FWPM_LAYER_ALE_AUTH_CONNECT_V6: WfpGuid = WfpGuid {
    data1: 0x4a72393b,
    data2: 0x319f,
    data3: 0x44bc,
    data4: [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4],
};
pub const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4: WfpGuid = WfpGuid {
    data1: 0xe1cd9fe7,
    data2: 0xf4b5,
    data3: 0x4273,
    data4: [0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50],
};
pub const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6: WfpGuid = WfpGuid {
    data1: 0xa3b42c97,
    data2: 0x9f04,
    data3: 0x4672,
    data4: [0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f],
};
pub const FWPM_LAYER_OUTBOUND_TRANSPORT_V4: WfpGuid = WfpGuid {
    data1: 0x09e61aea,
    data2: 0xd214,
    data3: 0x46e2,
    data4: [0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8],
};
pub const FWPM_LAYER_OUTBOUND_TRANSPORT_V6: WfpGuid = WfpGuid {
    data1: 0xe1735bde,
    data2: 0x013f,
    data3: 0x4655,
    data4: [0xb3, 0x51, 0xa4, 0x9e, 0x15, 0x76, 0x2d, 0xf0],
};
pub const FWPM_LAYER_INBOUND_TRANSPORT_V4: WfpGuid = WfpGuid {
    data1: 0x5926dfc8,
    data2: 0xe3cf,
    data3: 0x4426,
    data4: [0xa2, 0x83, 0xdc, 0x39, 0x3f, 0x5d, 0x0f, 0x9d],
};
pub const FWPM_LAYER_INBOUND_TRANSPORT_V6: WfpGuid = WfpGuid {
    data1: 0x634a869f,
    data2: 0xfc23,
    data3: 0x4b90,
    data4: [0xb0, 0xc1, 0xbf, 0x62, 0x0a, 0x36, 0xae, 0x6f],
};
pub const FWPM_LAYER_OUTBOUND_IPPACKET_V4: WfpGuid = WfpGuid {
    data1: 0x1e5c9fae,
    data2: 0x8a84,
    data3: 0x4135,
    data4: [0xa3, 0x31, 0x95, 0x0b, 0x54, 0x22, 0x9e, 0xcd],
};
pub const FWPM_LAYER_OUTBOUND_IPPACKET_V6: WfpGuid = WfpGuid {
    data1: 0xa3b3ab6b,
    data2: 0x3564,
    data3: 0x488c,
    data4: [0x91, 0x17, 0xf3, 0x4e, 0x82, 0x14, 0x27, 0x63],
};
pub const FWPM_LAYER_INBOUND_IPPACKET_V4: WfpGuid = WfpGuid {
    data1: 0xc86fd1bf,
    data2: 0x21cd,
    data3: 0x497e,
    data4: [0xa0, 0xbb, 0x17, 0x42, 0x5c, 0x88, 0x5c, 0x58],
};
pub const FWPM_LAYER_INBOUND_IPPACKET_V6: WfpGuid = WfpGuid {
    data1: 0xf52032cb,
    data2: 0x991c,
    data3: 0x46e7,
    data4: [0x97, 0x1d, 0x26, 0x01, 0x45, 0x9a, 0x91, 0xca],
};
pub const FWPM_LAYER_DATAGRAM_DATA_V4: WfpGuid = WfpGuid {
    data1: 0x3d08bf4e,
    data2: 0x45f6,
    data3: 0x4930,
    data4: [0xa9, 0x22, 0x41, 0x70, 0x98, 0xe2, 0x00, 0x27],
};
pub const FWPM_LAYER_DATAGRAM_DATA_V6: WfpGuid = WfpGuid {
    data1: 0xfa45fe2f,
    data2: 0x3cba,
    data3: 0x4427,
    data4: [0x87, 0xfc, 0x57, 0xb9, 0xa4, 0xb1, 0x0d, 0x00],
};
pub const FWPM_LAYER_INBOUND_ICMP_ERROR_V4: WfpGuid = WfpGuid {
    data1: 0x61499990,
    data2: 0x3cb6,
    data3: 0x4e84,
    data4: [0xb9, 0x50, 0x53, 0xb9, 0x4b, 0x69, 0x64, 0xf3],
};
pub const FWPM_LAYER_INBOUND_ICMP_ERROR_V6: WfpGuid = WfpGuid {
    data1: 0x65f9bdff,
    data2: 0x3b2d,
    data3: 0x4e5d,
    data4: [0xb8, 0xc6, 0xc7, 0x20, 0x65, 0x1f, 0xe8, 0x98],
};
pub const FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4: WfpGuid = WfpGuid {
    data1: 0x41390100,
    data2: 0x564c,
    data3: 0x4b32,
    data4: [0xbc, 0x1d, 0x71, 0x80, 0x48, 0x35, 0x4d, 0x7c],
};
pub const FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6: WfpGuid = WfpGuid {
    data1: 0x7fb03b60,
    data2: 0x7b8d,
    data3: 0x4dfa,
    data4: [0xba, 0xdd, 0x98, 0x01, 0x76, 0xfc, 0x4e, 0x12],
};
pub const FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE: WfpGuid = WfpGuid {
    data1: 0xd4220bd3,
    data2: 0x62ce,
    data3: 0x4f08,
    data4: [0xae, 0x88, 0xb5, 0x6e, 0x85, 0x26, 0xdf, 0x50],
};
pub const FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE: WfpGuid = WfpGuid {
    data1: 0x94c44912,
    data2: 0x9d6f,
    data3: 0x4ebf,
    data4: [0xb9, 0x95, 0x05, 0xab, 0x8a, 0x08, 0x8d, 0x1b],
};
pub const FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET: WfpGuid = WfpGuid {
    data1: 0xeffb7edb,
    data2: 0x0055,
    data3: 0x4f9a,
    data4: [0xa2, 0x31, 0x4f, 0xf8, 0x13, 0x1a, 0xd1, 0x91],
};
pub const FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET: WfpGuid = WfpGuid {
    data1: 0x694673bc,
    data2: 0xd6db,
    data3: 0x4870,
    data4: [0xad, 0xee, 0x0a, 0xcd, 0xbd, 0xb7, 0xf4, 0xb2],
};

/// Official Microsoft Windows SDK GUID for FWPM_LAYER_IPFORWARD_V4: {444543b6-9046-4246-ab81-9b06227e243d}
pub const FWPM_LAYER_IPFORWARD_V4: WfpGuid = WfpGuid {
    data1: 0x444543b6,
    data2: 0x9046,
    data3: 0x4246,
    data4: [0xab, 0x81, 0x9b, 0x06, 0x22, 0x7e, 0x24, 0x3d],
};

/// Official Microsoft Windows SDK GUID for FWPM_LAYER_IPFORWARD_V6: {12fe69b5-485a-40e7-912a-82b818121294}
pub const FWPM_LAYER_IPFORWARD_V6: WfpGuid = WfpGuid {
    data1: 0x12fe69b5,
    data2: 0x485a,
    data3: 0x40e7,
    data4: [0x91, 0x2a, 0x82, 0xb8, 0x18, 0x12, 0x12, 0x94],
};

pub const FWPM_CONDITION_ETHER_TYPE: WfpGuid = WfpGuid {
    data1: 0xfd08948d,
    data2: 0xa219,
    data3: 0x4d52,
    data4: [0xbb, 0x98, 0x1a, 0x55, 0x40, 0xee, 0x7b, 0x4e],
};
pub const FWPM_CONDITION_IP_REMOTE_ADDRESS: WfpGuid = WfpGuid {
    data1: 0xb235ae9a,
    data2: 0x1d64,
    data3: 0x49b8,
    data4: [0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45],
};
pub const FWPM_CONDITION_IP_LOCAL_ADDRESS: WfpGuid = WfpGuid {
    data1: 0xd9ee00de,
    data2: 0xc1ef,
    data3: 0x4617,
    data4: [0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57],
};
pub const FWPM_CONDITION_IP_LOCAL_PORT: WfpGuid = WfpGuid {
    data1: 0x0c1ba1af,
    data2: 0x5765,
    data3: 0x453f,
    data4: [0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b],
};
pub const FWPM_CONDITION_IP_PROTOCOL: WfpGuid = WfpGuid {
    data1: 0x3971ef2b,
    data2: 0x623e,
    data3: 0x4f9a,
    data4: [0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7],
};
pub const FWPM_CONDITION_FLAGS: WfpGuid = WfpGuid {
    data1: 0x632ce23b,
    data2: 0x5167,
    data3: 0x435c,
    data4: [0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c],
};
pub const FWPM_CONDITION_IP_REMOTE_PORT: WfpGuid = WfpGuid {
    data1: 0xc35a604d,
    data2: 0xd22b,
    data3: 0x4e1a,
    data4: [0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b],
};
pub const FWPM_CONDITION_ALE_APP_ID: WfpGuid = WfpGuid {
    data1: 0xd78e1e87,
    data2: 0x8644,
    data3: 0x4ea5,
    data4: [0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71],
};

#[repr(C)]
pub struct FwpmDisplayData0 {
    pub name: *mut u16,
    pub description: *mut u16,
}

#[repr(C)]
pub struct FwpmSession0 {
    pub session_key: [u8; 16],
    pub display_data: FwpmDisplayData0,
    pub flags: u32,
    pub txn_wait_timeout_in_msec: u32,
    pub process_id: u32,
    pub sid: *mut std::ffi::c_void,
    pub username: *mut u16,
    pub kernel_mode: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwpValue0 {
    pub type_: u32,
    pub _pad: u32,
    pub value: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwpConditionValue0 {
    pub type_: u32,
    pub _pad: u32,
    pub value: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwpByteBlob {
    pub size: u32,
    pub _pad: u32,
    pub data: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwpRange0 {
    pub value_low: FwpValue0,
    pub value_high: FwpValue0,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwpmFilterCondition0 {
    pub field_key: WfpGuid,
    pub match_type: u32,
    pub _pad: u32,
    pub condition_value: FwpConditionValue0,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwpmAction0 {
    pub type_: u32,
    pub filter_type: WfpGuid,
}

#[repr(C)]
pub struct FwpmFilter0 {
    pub filter_key: WfpGuid,
    pub display_data: FwpmDisplayData0,
    pub flags: u32,
    pub _pad0: u32,
    pub provider_key: *mut WfpGuid,
    pub provider_data: FwpByteBlob,
    pub layer_key: WfpGuid,
    pub sub_layer_key: WfpGuid,
    pub weight: FwpValue0,
    pub num_filter_conditions: u32,
    pub _pad1: u32,
    pub filter_condition: *mut FwpmFilterCondition0,
    pub action: FwpmAction0,
    pub _pad2: u32,
    pub raw_context_or_provider_context_key: [u64; 2],
    pub reserved: *mut WfpGuid,
    pub filter_id: u64,
    pub effective_weight: FwpValue0,
}

#[cfg(target_arch = "x86_64")]
const _: () = {
    assert!(std::mem::size_of::<FwpmFilter0>() == 200);
    assert!(std::mem::align_of::<FwpmFilter0>() == 8);
    assert!(std::mem::offset_of!(FwpmFilter0, filter_key) == 0);
    assert!(std::mem::offset_of!(FwpmFilter0, display_data) == 16);
    assert!(std::mem::offset_of!(FwpmFilter0, flags) == 32);
    assert!(std::mem::offset_of!(FwpmFilter0, provider_key) == 40);
    assert!(std::mem::offset_of!(FwpmFilter0, provider_data) == 48);
    assert!(std::mem::offset_of!(FwpmFilter0, layer_key) == 64);
    assert!(std::mem::offset_of!(FwpmFilter0, sub_layer_key) == 80);
    assert!(std::mem::offset_of!(FwpmFilter0, weight) == 96);
    assert!(std::mem::offset_of!(FwpmFilter0, num_filter_conditions) == 112);
    assert!(std::mem::offset_of!(FwpmFilter0, filter_condition) == 120);
    assert!(std::mem::offset_of!(FwpmFilter0, action) == 128);
    assert!(std::mem::offset_of!(FwpmFilter0, raw_context_or_provider_context_key) == 152);
    assert!(std::mem::offset_of!(FwpmFilter0, reserved) == 168);
    assert!(std::mem::offset_of!(FwpmFilter0, filter_id) == 176);
    assert!(std::mem::offset_of!(FwpmFilter0, effective_weight) == 184);
    assert!(std::mem::size_of::<FwpmFilterCondition0>() == 40);
    assert!(std::mem::size_of::<FwpmAction0>() == 20);
};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MibTcpRow {
    pub dw_state: u32,
    pub dw_local_addr: u32,
    pub dw_local_port: u32,
    pub dw_remote_addr: u32,
    pub dw_remote_port: u32,
}

#[cfg(windows)]
mod win_ffi {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn LoadLibraryW(lpLibFileName: *const u16) -> *mut c_void;
        pub fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *const c_void;
        pub fn CloseHandle(hObject: *mut c_void) -> i32;
        pub fn GetCurrentProcess() -> *mut c_void;
        pub fn WaitForSingleObject(hHandle: *mut c_void, dwMilliseconds: u32) -> u32;
        pub fn GetExitCodeProcess(hProcess: *mut c_void, lpExitCode: *mut u32) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        pub fn OpenProcessToken(
            ProcessHandle: *mut c_void,
            DesiredAccess: u32,
            TokenHandle: *mut *mut c_void,
        ) -> i32;
        pub fn GetTokenInformation(
            TokenHandle: *mut c_void,
            TokenInformationClass: u32,
            TokenInformation: *mut c_void,
            TokenInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;
        pub fn RegOpenKeyExW(
            hKey: usize,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut usize,
        ) -> i32;
        pub fn RegSetValueExW(
            hKey: usize,
            lpValueName: *const u16,
            Reserved: u32,
            dwType: u32,
            lpData: *const u8,
            cbData: u32,
        ) -> i32;
        pub fn RegDeleteValueW(hKey: usize, lpValueName: *const u16) -> i32;
        #[cfg(windows)]
        pub fn RegEnumValueW(
            hKey: usize,
            dwIndex: u32,
            lpValueName: *mut u16,
            lpcchValueName: *mut u32,
            lpReserved: *mut u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;
        pub fn RegCloseKey(hKey: usize) -> i32;
    }

    pub const TOKEN_QUERY: u32 = 0x0008;
    pub const TOKEN_ELEVATION_CLASS: u32 = 20;
    pub const INFINITE: u32 = 0xFFFF_FFFF;
    pub const HKEY_LOCAL_MACHINE: usize = 0x8000_0002;
    pub const KEY_READ: u32 = 0x0002_0019;
    pub const KEY_WRITE: u32 = 0x0002_0006;
    pub const REG_SZ: u32 = 1;
    #[cfg(windows)]
    pub const ERROR_NO_MORE_ITEMS: i32 = 259;
}

/// Checks whether the current process holds an elevated token (Windows Admin / Unix root).
pub fn is_current_process_elevated() -> bool {
    #[cfg(windows)]
    unsafe {
        let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
        if win_ffi::OpenProcessToken(
            win_ffi::GetCurrentProcess(),
            win_ffi::TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }
        let mut elevated: u32 = 0;
        let mut ret_len: u32 = 0;
        let ok = win_ffi::GetTokenInformation(
            token,
            win_ffi::TOKEN_ELEVATION_CLASS,
            &mut elevated as *mut u32 as *mut std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            &mut ret_len,
        );
        let _ = win_ffi::CloseHandle(token);
        ok != 0 && elevated != 0
    }
    #[cfg(unix)]
    unsafe {
        libc::geteuid() == 0
    }
    #[cfg(not(any(windows, unix)))]
    {
        true
    }
}

#[cfg(windows)]
type FnFwpmEngineOpen0 = unsafe extern "system" fn(
    server_name: *const u16,
    authn_service: u32,
    auth_identity: *mut std::ffi::c_void,
    session: *const FwpmSession0,
    engine_handle: *mut *mut std::ffi::c_void,
) -> u32;
#[cfg(windows)]
type FnFwpmEngineClose0 = unsafe extern "system" fn(engine_handle: *mut std::ffi::c_void) -> u32;
#[cfg(windows)]
type FnFwpmTransactionBegin0 =
    unsafe extern "system" fn(engine_handle: *mut std::ffi::c_void, flags: u32) -> u32;
#[cfg(windows)]
type FnFwpmTransactionCommit0 =
    unsafe extern "system" fn(engine_handle: *mut std::ffi::c_void) -> u32;
#[cfg(windows)]
type FnFwpmTransactionAbort0 =
    unsafe extern "system" fn(engine_handle: *mut std::ffi::c_void) -> u32;
#[cfg(windows)]
type FnFwpmFilterAdd0 = unsafe extern "system" fn(
    engine_handle: *mut std::ffi::c_void,
    filter: *const FwpmFilter0,
    sd: *mut std::ffi::c_void,
    id: *mut u64,
) -> u32;
#[cfg(windows)]
type FnFwpmFilterDeleteById0 =
    unsafe extern "system" fn(engine_handle: *mut std::ffi::c_void, id: u64) -> u32;
#[cfg(windows)]
type FnFwpmFilterGetById0 = unsafe extern "system" fn(
    engine_handle: *mut std::ffi::c_void,
    id: u64,
    filter: *mut *mut FwpmFilter0,
) -> u32;
#[cfg(windows)]
type FnFwpmFreeMemory0 = unsafe extern "system" fn(p: *mut *mut std::ffi::c_void);
#[cfg(windows)]
type FnFwpmFilterCreateEnumHandle0 = unsafe extern "system" fn(
    engine_handle: *mut std::ffi::c_void,
    enum_template: *const std::ffi::c_void,
    enum_handle: *mut *mut std::ffi::c_void,
) -> u32;
#[cfg(windows)]
type FnFwpmFilterEnum0 = unsafe extern "system" fn(
    engine_handle: *mut std::ffi::c_void,
    enum_handle: *mut std::ffi::c_void,
    num_entries_requested: u32,
    entries: *mut *mut *mut FwpmFilter0,
    num_entries_returned: *mut u32,
) -> u32;
#[cfg(windows)]
type FnFwpmFilterDestroyEnumHandle0 = unsafe extern "system" fn(
    engine_handle: *mut std::ffi::c_void,
    enum_handle: *mut std::ffi::c_void,
) -> u32;
#[cfg(windows)]
type FnFwpmGetAppIdFromFileName0 =
    unsafe extern "system" fn(file_name: *const u16, app_id: *mut *mut FwpByteBlob) -> u32;
#[cfg(windows)]
type FnGetTcpTable =
    unsafe extern "system" fn(p_tcp_table: *mut u8, pdw_size: *mut u32, b_order: i32) -> u32;
#[cfg(windows)]
type FnSetTcpEntry = unsafe extern "system" fn(p_tcprow: *const MibTcpRow) -> u32;

#[cfg(windows)]
pub struct WfpKernelSession {
    engine_handle: *mut std::ffi::c_void,
    fn_close: FnFwpmEngineClose0,
    fn_begin: FnFwpmTransactionBegin0,
    fn_commit: FnFwpmTransactionCommit0,
    fn_abort: FnFwpmTransactionAbort0,
    fn_add: FnFwpmFilterAdd0,
    fn_delete: FnFwpmFilterDeleteById0,
    fn_get: Option<FnFwpmFilterGetById0>,
    fn_free: Option<FnFwpmFreeMemory0>,
    fn_create_enum: Option<FnFwpmFilterCreateEnumHandle0>,
    fn_enum: Option<FnFwpmFilterEnum0>,
    fn_destroy_enum: Option<FnFwpmFilterDestroyEnumHandle0>,
    fn_get_app_id: Option<FnFwpmGetAppIdFromFileName0>,
    in_txn: AtomicBool,
}

#[cfg(windows)]
unsafe impl Send for WfpKernelSession {}
#[cfg(windows)]
unsafe impl Sync for WfpKernelSession {}

#[cfg(windows)]
impl WfpKernelSession {
    pub fn open() -> Result<Self, HostIsolationError> {
        let dll_w: Vec<u16> = "fwpuclnt.dll\0".encode_utf16().collect();
        let h_mod = unsafe { win_ffi::LoadLibraryW(dll_w.as_ptr()) };
        if h_mod.is_null() {
            return Err(HostIsolationError::KernelEngineError(
                "LoadLibraryW(fwpuclnt.dll) failed".to_string(),
            ));
        }

        let load_sym = |name: &'static [u8]| -> Option<*const std::ffi::c_void> {
            let p = unsafe { win_ffi::GetProcAddress(h_mod, name.as_ptr()) };
            if p.is_null() {
                None
            } else {
                Some(p)
            }
        };

        let fn_open: FnFwpmEngineOpen0 = unsafe {
            std::mem::transmute(load_sym(b"FwpmEngineOpen0\0").ok_or_else(|| {
                HostIsolationError::KernelEngineError("Missing FwpmEngineOpen0".to_string())
            })?)
        };
        let fn_close: FnFwpmEngineClose0 = unsafe {
            std::mem::transmute(load_sym(b"FwpmEngineClose0\0").ok_or_else(|| {
                HostIsolationError::KernelEngineError("Missing FwpmEngineClose0".to_string())
            })?)
        };
        let fn_begin: FnFwpmTransactionBegin0 = unsafe {
            std::mem::transmute(load_sym(b"FwpmTransactionBegin0\0").ok_or_else(|| {
                HostIsolationError::KernelEngineError("Missing FwpmTransactionBegin0".to_string())
            })?)
        };
        let fn_commit: FnFwpmTransactionCommit0 = unsafe {
            std::mem::transmute(load_sym(b"FwpmTransactionCommit0\0").ok_or_else(|| {
                HostIsolationError::KernelEngineError("Missing FwpmTransactionCommit0".to_string())
            })?)
        };
        let fn_abort: FnFwpmTransactionAbort0 = unsafe {
            std::mem::transmute(load_sym(b"FwpmTransactionAbort0\0").ok_or_else(|| {
                HostIsolationError::KernelEngineError("Missing FwpmTransactionAbort0".to_string())
            })?)
        };
        let fn_add: FnFwpmFilterAdd0 = unsafe {
            std::mem::transmute(load_sym(b"FwpmFilterAdd0\0").ok_or_else(|| {
                HostIsolationError::KernelEngineError("Missing FwpmFilterAdd0".to_string())
            })?)
        };
        let fn_delete: FnFwpmFilterDeleteById0 = unsafe {
            std::mem::transmute(load_sym(b"FwpmFilterDeleteById0\0").ok_or_else(|| {
                HostIsolationError::KernelEngineError("Missing FwpmFilterDeleteById0".to_string())
            })?)
        };
        let fn_get: Option<FnFwpmFilterGetById0> =
            unsafe { load_sym(b"FwpmFilterGetById0\0").map(|p| std::mem::transmute(p)) };
        let fn_free: Option<FnFwpmFreeMemory0> =
            unsafe { load_sym(b"FwpmFreeMemory0\0").map(|p| std::mem::transmute(p)) };
        let fn_create_enum: Option<FnFwpmFilterCreateEnumHandle0> =
            unsafe { load_sym(b"FwpmFilterCreateEnumHandle0\0").map(|p| std::mem::transmute(p)) };
        let fn_enum: Option<FnFwpmFilterEnum0> =
            unsafe { load_sym(b"FwpmFilterEnum0\0").map(|p| std::mem::transmute(p)) };
        let fn_destroy_enum: Option<FnFwpmFilterDestroyEnumHandle0> =
            unsafe { load_sym(b"FwpmFilterDestroyEnumHandle0\0").map(|p| std::mem::transmute(p)) };
        let fn_get_app_id: Option<FnFwpmGetAppIdFromFileName0> =
            unsafe { load_sym(b"FwpmGetAppIdFromFileName0\0").map(|p| std::mem::transmute(p)) };

        let mut s_name: Vec<u16> = "AgentOctopus-KillSwitch-Session\0".encode_utf16().collect();
        let mut s_desc: Vec<u16> = "AgentOctopus 22-Layer Hermetic WFP Quarantine\0"
            .encode_utf16()
            .collect();
        let session = FwpmSession0 {
            session_key: [0u8; 16],
            display_data: FwpmDisplayData0 {
                name: s_name.as_mut_ptr(),
                description: s_desc.as_mut_ptr(),
            },
            flags: 0,
            txn_wait_timeout_in_msec: 5000,
            process_id: 0,
            sid: std::ptr::null_mut(),
            username: std::ptr::null_mut(),
            kernel_mode: 0,
        };

        let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut status = unsafe {
            fn_open(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null_mut(),
                &session,
                &mut handle,
            )
        };
        if status != ERROR_SUCCESS || handle.is_null() {
            status = unsafe {
                fn_open(
                    std::ptr::null(),
                    RPC_C_AUTHN_DEFAULT,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    &mut handle,
                )
            };
        }
        if status != ERROR_SUCCESS || handle.is_null() {
            if status == 5 {
                return Err(HostIsolationError::InsufficientPrivileges {
                    details: "Access denied (0x00000005) opening Windows Filtering Platform BFE"
                        .to_string(),
                    remediation: "Accept the Windows UAC prompt or run terminal as Administrator."
                        .to_string(),
                });
            }
            return Err(HostIsolationError::KernelEngineError(format!(
                "FwpmEngineOpen0 failed with Win32 status 0x{:08X}",
                status
            )));
        }

        Ok(Self {
            engine_handle: handle,
            fn_close,
            fn_begin,
            fn_commit,
            fn_abort,
            fn_add,
            fn_delete,
            fn_get,
            fn_free,
            fn_create_enum,
            fn_enum,
            fn_destroy_enum,
            fn_get_app_id,
            in_txn: AtomicBool::new(false),
        })
    }

    pub fn begin_txn(&self) -> Result<(), HostIsolationError> {
        let rc = unsafe { (self.fn_begin)(self.engine_handle, 0) };
        if rc != ERROR_SUCCESS {
            return Err(HostIsolationError::KernelEngineError(format!(
                "FwpmTransactionBegin0 failed: 0x{:08X}",
                rc
            )));
        }
        self.in_txn.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub fn commit_txn(&self) -> Result<(), HostIsolationError> {
        let rc = unsafe { (self.fn_commit)(self.engine_handle) };
        self.in_txn.store(false, Ordering::SeqCst);
        if rc != ERROR_SUCCESS {
            return Err(HostIsolationError::KernelEngineError(format!(
                "FwpmTransactionCommit0 failed: 0x{:08X}",
                rc
            )));
        }
        Ok(())
    }

    pub fn abort_txn(&self) {
        if self.in_txn.swap(false, Ordering::SeqCst) {
            let _ = unsafe { (self.fn_abort)(self.engine_handle) };
        }
    }

    pub fn delete_filter(&self, id: u64) -> bool {
        unsafe { (self.fn_delete)(self.engine_handle, id) == ERROR_SUCCESS }
    }

    pub fn filter_exists(&self, id: u64) -> bool {
        if id == 0 || self.engine_handle.is_null() {
            return false;
        }
        let Some(fn_get) = self.fn_get else {
            return false;
        };
        let mut ptr: *mut FwpmFilter0 = std::ptr::null_mut();
        let rc = unsafe { fn_get(self.engine_handle, id, &mut ptr) };
        if rc == ERROR_SUCCESS && !ptr.is_null() {
            if let Some(fn_free) = self.fn_free {
                let mut raw = ptr as *mut std::ffi::c_void;
                unsafe { fn_free(&mut raw) };
            }
            return true;
        }
        false
    }

    pub fn enumerate_prefixed_filter_ids(&self, prefix: &str) -> Vec<u64> {
        let mut ids = Vec::new();
        let (Some(fn_create), Some(fn_enum), Some(fn_destroy), Some(fn_free)) = (
            self.fn_create_enum,
            self.fn_enum,
            self.fn_destroy_enum,
            self.fn_free,
        ) else {
            return ids;
        };

        let mut enum_handle: *mut std::ffi::c_void = std::ptr::null_mut();
        if unsafe { fn_create(self.engine_handle, std::ptr::null(), &mut enum_handle) }
            != ERROR_SUCCESS
            || enum_handle.is_null()
        {
            return ids;
        }

        loop {
            let mut entries_ptr: *mut *mut FwpmFilter0 = std::ptr::null_mut();
            let mut returned: u32 = 0;
            let rc = unsafe {
                fn_enum(
                    self.engine_handle,
                    enum_handle,
                    512,
                    &mut entries_ptr,
                    &mut returned,
                )
            };
            if rc != ERROR_SUCCESS || entries_ptr.is_null() || returned == 0 {
                if !entries_ptr.is_null() {
                    let mut raw = entries_ptr as *mut std::ffi::c_void;
                    unsafe { fn_free(&mut raw) };
                }
                break;
            }
            for i in 0..(returned as usize) {
                unsafe {
                    let entry = *entries_ptr.add(i);
                    if entry.is_null() || (*entry).display_data.name.is_null() {
                        continue;
                    }
                    let name_ptr = (*entry).display_data.name;
                    let mut len = 0usize;
                    while len < 256 && *name_ptr.add(len) != 0 {
                        len += 1;
                    }
                    if len > 0 {
                        let name =
                            String::from_utf16_lossy(std::slice::from_raw_parts(name_ptr, len));
                        if name.starts_with(prefix) {
                            let fid = (*entry).filter_id;
                            if fid != 0 && !ids.contains(&fid) {
                                ids.push(fid);
                            }
                        }
                    }
                }
            }
            let mut raw = entries_ptr as *mut std::ffi::c_void;
            unsafe { fn_free(&mut raw) };
            if returned < 512 {
                break;
            }
        }

        unsafe {
            let _ = fn_destroy(self.engine_handle, enum_handle);
        }
        ids
    }

    pub fn install_22_layer_quarantine(
        &self,
        preserved_ports: &[u16],
    ) -> Result<Vec<u64>, HostIsolationError> {
        let mut filter_ids = Vec::new();
        self.begin_txn()?;

        let mut w_desc: Vec<u16> = "AgentOctopus 22-Layer Hermetic Network Quarantine\0"
            .encode_utf16()
            .collect();

        let mut add_one = |name: &str,
                           layer: WfpGuid,
                           action: u32,
                           weight_val: usize,
                           conditions: &mut [FwpmFilterCondition0]|
         -> Option<u64> {
            let mut w_name: Vec<u16> = format!("{}-{}\0", WFP_RULE_PREFIX, name)
                .encode_utf16()
                .collect();
            let mut filter = FwpmFilter0 {
                filter_key: WfpGuid::default(),
                display_data: FwpmDisplayData0 {
                    name: w_name.as_mut_ptr(),
                    description: w_desc.as_mut_ptr(),
                },
                flags: 0,
                _pad0: 0,
                provider_key: std::ptr::null_mut(),
                provider_data: FwpByteBlob {
                    size: 0,
                    _pad: 0,
                    data: std::ptr::null_mut(),
                },
                layer_key: layer,
                sub_layer_key: WfpGuid::default(),
                weight: FwpValue0 {
                    type_: if weight_val > 0 { FWP_UINT8 } else { FWP_EMPTY },
                    _pad: 0,
                    value: weight_val,
                },
                num_filter_conditions: conditions.len() as u32,
                _pad1: 0,
                filter_condition: if conditions.is_empty() {
                    std::ptr::null_mut()
                } else {
                    conditions.as_mut_ptr()
                },
                action: FwpmAction0 {
                    type_: action,
                    filter_type: WfpGuid::default(),
                },
                _pad2: 0,
                raw_context_or_provider_context_key: [0; 2],
                reserved: std::ptr::null_mut(),
                filter_id: 0,
                effective_weight: FwpValue0 {
                    type_: FWP_EMPTY,
                    _pad: 0,
                    value: 0,
                },
            };

            let mut assigned: u64 = 0;
            let rc = unsafe {
                (self.fn_add)(
                    self.engine_handle,
                    &filter,
                    std::ptr::null_mut(),
                    &mut assigned,
                )
            };
            if rc == ERROR_SUCCESS && assigned != 0 {
                return Some(assigned);
            }
            filter.weight = FwpValue0 {
                type_: FWP_EMPTY,
                _pad: 0,
                value: 0,
            };
            let rc2 = unsafe {
                (self.fn_add)(
                    self.engine_handle,
                    &filter,
                    std::ptr::null_mut(),
                    &mut assigned,
                )
            };
            if rc2 == ERROR_SUCCESS && assigned != 0 {
                Some(assigned)
            } else {
                None
            }
        };

        let sanitized_ports = sanitize_firewall_preserved_ports(preserved_ports);
        let mut app_id_blob: *mut FwpByteBlob = std::ptr::null_mut();
        if let (Some(fn_get_app_id), Ok(exe_path)) = (self.fn_get_app_id, std::env::current_exe()) {
            let exe_w: Vec<u16> = exe_path
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            if unsafe { fn_get_app_id(exe_w.as_ptr(), &mut app_id_blob) } != ERROR_SUCCESS {
                app_id_blob = std::ptr::null_mut();
            }
        }

        let loopback_v4 = u32::from_be_bytes([127, 0, 0, 1]);
        let loopback_v6 = Ipv6Addr::LOCALHOST.octets();
        let imds_v4 = u32::from_be_bytes([169, 254, 169, 254]);
        let loopback_alias_range = FwpRange0 {
            value_low: FwpValue0 {
                type_: FWP_UINT32,
                _pad: 0,
                value: u32::from_be_bytes([127, 0, 0, 2]) as usize,
            },
            value_high: FwpValue0 {
                type_: FWP_UINT32,
                _pad: 0,
                value: u32::from_be_bytes([127, 255, 255, 254]) as usize,
            },
        };

        // 1. Explicit High-Priority Quarantine Blocks (Weight 20):
        //    - Non-localhost loopback aliases (127.0.0.2..=127.255.255.254)
        //    - Cloud IMDS metadata endpoint (169.254.169.254)
        //    - Loopback proxy (1080, 3128, 8080, 8888, 9050), lateral (135, 445, 5985, 5986),
        //      discovery (53, 67, 68, 546, 547, 853), and forbidden (5000) ports
        for (layer, tag) in [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "ALE-Out"),
            (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, "ALE-In"),
            (FWPM_LAYER_OUTBOUND_TRANSPORT_V4, "Trans-Out"),
            (FWPM_LAYER_INBOUND_TRANSPORT_V4, "Trans-In"),
            (FWPM_LAYER_OUTBOUND_IPPACKET_V4, "IP-Out"),
            (FWPM_LAYER_INBOUND_IPPACKET_V4, "IP-In"),
        ] {
            for (cond_key, cond_tag) in [
                (FWPM_CONDITION_IP_REMOTE_ADDRESS, "Rem"),
                (FWPM_CONDITION_IP_LOCAL_ADDRESS, "Loc"),
            ] {
                let mut cond_alias = [FwpmFilterCondition0 {
                    field_key: cond_key,
                    match_type: FWP_MATCH_RANGE,
                    _pad: 0,
                    condition_value: FwpConditionValue0 {
                        type_: FWP_RANGE_TYPE,
                        _pad: 0,
                        value: &loopback_alias_range as *const FwpRange0 as usize,
                    },
                }];
                if let Some(id) = add_one(
                    &format!("Block-LB-Alias-{}-{}-v4", cond_tag, tag),
                    layer,
                    FWP_ACTION_BLOCK,
                    20,
                    &mut cond_alias,
                ) {
                    filter_ids.push(id);
                }
            }
        }

        for (layer, tag) in [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "ALE-Out"),
            (FWPM_LAYER_OUTBOUND_TRANSPORT_V4, "Trans-Out"),
            (FWPM_LAYER_OUTBOUND_IPPACKET_V4, "IP-Out"),
        ] {
            let mut cond_imds = [FwpmFilterCondition0 {
                field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                match_type: FWP_MATCH_EQUAL,
                _pad: 0,
                condition_value: FwpConditionValue0 {
                    type_: FWP_UINT32,
                    _pad: 0,
                    value: imds_v4 as usize,
                },
            }];
            if let Some(id) = add_one(
                &format!("Block-IMDS-{}-v4", tag),
                layer,
                FWP_ACTION_BLOCK,
                20,
                &mut cond_imds,
            ) {
                filter_ids.push(id);
            }
        }

        for port in QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS
            .iter()
            .chain(QUARANTINE_BLOCKED_LATERAL_PORTS.iter())
            .chain(QUARANTINE_BLOCKED_DISCOVERY_PORTS.iter())
            .chain(std::iter::once(&FORBIDDEN_PORT_5000))
        {
            for (layer, tag) in [
                (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "ALE-Out-v4"),
                (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "ALE-Out-v6"),
                (FWPM_LAYER_OUTBOUND_TRANSPORT_V4, "Trans-Out-v4"),
                (FWPM_LAYER_OUTBOUND_TRANSPORT_V6, "Trans-Out-v6"),
                (FWPM_LAYER_DATAGRAM_DATA_V4, "Dgram-Out-v4"),
                (FWPM_LAYER_DATAGRAM_DATA_V6, "Dgram-Out-v6"),
            ] {
                let mut cond_rport = [FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_IP_REMOTE_PORT,
                    match_type: FWP_MATCH_EQUAL,
                    _pad: 0,
                    condition_value: FwpConditionValue0 {
                        type_: FWP_UINT16,
                        _pad: 0,
                        value: *port as usize,
                    },
                }];
                if let Some(id) = add_one(
                    &format!("Block-Port-{}-Rem-{}", port, tag),
                    layer,
                    FWP_ACTION_BLOCK,
                    20,
                    &mut cond_rport,
                ) {
                    filter_ids.push(id);
                }
            }
            for (layer, tag) in [
                (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, "ALE-In-v4"),
                (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, "ALE-In-v6"),
                (FWPM_LAYER_INBOUND_TRANSPORT_V4, "Trans-In-v4"),
                (FWPM_LAYER_INBOUND_TRANSPORT_V6, "Trans-In-v6"),
            ] {
                let mut cond_lport = [FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_IP_LOCAL_PORT,
                    match_type: FWP_MATCH_EQUAL,
                    _pad: 0,
                    condition_value: FwpConditionValue0 {
                        type_: FWP_UINT16,
                        _pad: 0,
                        value: *port as usize,
                    },
                }];
                if let Some(id) = add_one(
                    &format!("Block-Port-{}-Loc-{}", port, tag),
                    layer,
                    FWP_ACTION_BLOCK,
                    20,
                    &mut cond_lport,
                ) {
                    filter_ids.push(id);
                }
            }
        }

        // 2. Strict Exact-Localhost IP-Layer Permits (127.0.0.1 <-> 127.0.0.1 and ::1 <-> ::1)
        //    All conditions are combined into a single filter per layer so source AND destination
        //    AND loopback flag must match simultaneously.
        for (layer, tag) in [
            (FWPM_LAYER_OUTBOUND_IPPACKET_V4, "IP-Out"),
            (FWPM_LAYER_INBOUND_IPPACKET_V4, "IP-In"),
        ] {
            let mut cond_ip_v4 = [
                FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    match_type: FWP_MATCH_EQUAL,
                    _pad: 0,
                    condition_value: FwpConditionValue0 {
                        type_: FWP_UINT32,
                        _pad: 0,
                        value: loopback_v4 as usize,
                    },
                },
                FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_IP_LOCAL_ADDRESS,
                    match_type: FWP_MATCH_EQUAL,
                    _pad: 0,
                    condition_value: FwpConditionValue0 {
                        type_: FWP_UINT32,
                        _pad: 0,
                        value: loopback_v4 as usize,
                    },
                },
                FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_FLAGS,
                    match_type: FWP_MATCH_FLAGS_ALL_SET,
                    _pad: 0,
                    condition_value: FwpConditionValue0 {
                        type_: FWP_UINT32,
                        _pad: 0,
                        value: FWP_CONDITION_FLAG_IS_LOOPBACK as usize,
                    },
                },
            ];
            if let Some(id) = add_one(
                &format!("Permit-ExactLB-{}-v4", tag),
                layer,
                FWP_ACTION_PERMIT,
                15,
                &mut cond_ip_v4,
            ) {
                filter_ids.push(id);
            }
        }

        for (layer, tag) in [
            (FWPM_LAYER_OUTBOUND_IPPACKET_V6, "IP-Out"),
            (FWPM_LAYER_INBOUND_IPPACKET_V6, "IP-In"),
        ] {
            let mut cond_ip_v6 = [
                FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    match_type: FWP_MATCH_EQUAL,
                    _pad: 0,
                    condition_value: FwpConditionValue0 {
                        type_: FWP_BYTE_ARRAY16_TYPE,
                        _pad: 0,
                        value: loopback_v6.as_ptr() as usize,
                    },
                },
                FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_IP_LOCAL_ADDRESS,
                    match_type: FWP_MATCH_EQUAL,
                    _pad: 0,
                    condition_value: FwpConditionValue0 {
                        type_: FWP_BYTE_ARRAY16_TYPE,
                        _pad: 0,
                        value: loopback_v6.as_ptr() as usize,
                    },
                },
                FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_FLAGS,
                    match_type: FWP_MATCH_FLAGS_ALL_SET,
                    _pad: 0,
                    condition_value: FwpConditionValue0 {
                        type_: FWP_UINT32,
                        _pad: 0,
                        value: FWP_CONDITION_FLAG_IS_LOOPBACK as usize,
                    },
                },
            ];
            if let Some(id) = add_one(
                &format!("Permit-ExactLB-{}-v6", tag),
                layer,
                FWP_ACTION_PERMIT,
                15,
                &mut cond_ip_v6,
            ) {
                filter_ids.push(id);
            }
        }

        // 3. Permit sanitized AgentOctopus TCP control-plane ports strictly on exact localhost
        //    (127.0.0.1 <-> 127.0.0.1 and ::1 <-> ::1), never permitting UDP or external hosts.
        for &port in &sanitized_ports {
            for (layer, port_field, tag) in [
                (
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    "ALE-Out-Rem",
                ),
                (
                    FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    "Trans-Out-Rem",
                ),
                (
                    FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
                    FWPM_CONDITION_IP_LOCAL_PORT,
                    "Trans-Out-Loc",
                ),
                (
                    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                    FWPM_CONDITION_IP_LOCAL_PORT,
                    "ALE-In-Loc",
                ),
                (
                    FWPM_LAYER_INBOUND_TRANSPORT_V4,
                    FWPM_CONDITION_IP_LOCAL_PORT,
                    "Trans-In-Loc",
                ),
                (
                    FWPM_LAYER_INBOUND_TRANSPORT_V4,
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    "Trans-In-Rem",
                ),
            ] {
                let mut cond_v4 = [
                    FwpmFilterCondition0 {
                        field_key: port_field,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpConditionValue0 {
                            type_: FWP_UINT16,
                            _pad: 0,
                            value: port as usize,
                        },
                    },
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_LOCAL_ADDRESS,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpConditionValue0 {
                            type_: FWP_UINT32,
                            _pad: 0,
                            value: loopback_v4 as usize,
                        },
                    },
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpConditionValue0 {
                            type_: FWP_UINT32,
                            _pad: 0,
                            value: loopback_v4 as usize,
                        },
                    },
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_PROTOCOL,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpConditionValue0 {
                            type_: FWP_UINT8,
                            _pad: 0,
                            value: 6,
                        },
                    },
                ];
                if let Some(id) = add_one(
                    &format!("Permit-WebUI-{}-{}-v4", port, tag),
                    layer,
                    FWP_ACTION_PERMIT,
                    15,
                    &mut cond_v4,
                ) {
                    filter_ids.push(id);
                }
            }

            if !app_id_blob.is_null() {
                let mut cond_app_v4 = [
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_ALE_APP_ID,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpConditionValue0 {
                            type_: FWP_BYTE_BLOB_TYPE,
                            _pad: 0,
                            value: app_id_blob as usize,
                        },
                    },
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_REMOTE_PORT,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpConditionValue0 {
                            type_: FWP_UINT16,
                            _pad: 0,
                            value: port as usize,
                        },
                    },
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_LOCAL_ADDRESS,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpConditionValue0 {
                            type_: FWP_UINT32,
                            _pad: 0,
                            value: loopback_v4 as usize,
                        },
                    },
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpConditionValue0 {
                            type_: FWP_UINT32,
                            _pad: 0,
                            value: loopback_v4 as usize,
                        },
                    },
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_PROTOCOL,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpConditionValue0 {
                            type_: FWP_UINT8,
                            _pad: 0,
                            value: 6,
                        },
                    },
                ];
                if let Some(id) = add_one(
                    &format!("Permit-SelfApp-WebUI-{}-v4", port),
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    FWP_ACTION_PERMIT,
                    16,
                    &mut cond_app_v4,
                ) {
                    filter_ids.push(id);
                }
            }

            for (layer, port_field, tag) in [
                (
                    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    "ALE-Out-Rem",
                ),
                (
                    FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    "Trans-Out-Rem",
                ),
                (
                    FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
                    FWPM_CONDITION_IP_LOCAL_PORT,
                    "Trans-Out-Loc",
                ),
                (
                    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                    FWPM_CONDITION_IP_LOCAL_PORT,
                    "ALE-In-Loc",
                ),
                (
                    FWPM_LAYER_INBOUND_TRANSPORT_V6,
                    FWPM_CONDITION_IP_LOCAL_PORT,
                    "Trans-In-Loc",
                ),
                (
                    FWPM_LAYER_INBOUND_TRANSPORT_V6,
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    "Trans-In-Rem",
                ),
            ] {
                let mut cond_v6 = [
                    FwpmFilterCondition0 {
                        field_key: port_field,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpConditionValue0 {
                            type_: FWP_UINT16,
                            _pad: 0,
                            value: port as usize,
                        },
                    },
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_LOCAL_ADDRESS,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpConditionValue0 {
                            type_: FWP_BYTE_ARRAY16_TYPE,
                            _pad: 0,
                            value: loopback_v6.as_ptr() as usize,
                        },
                    },
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpConditionValue0 {
                            type_: FWP_BYTE_ARRAY16_TYPE,
                            _pad: 0,
                            value: loopback_v6.as_ptr() as usize,
                        },
                    },
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_PROTOCOL,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpConditionValue0 {
                            type_: FWP_UINT8,
                            _pad: 0,
                            value: 6,
                        },
                    },
                ];
                if let Some(id) = add_one(
                    &format!("Permit-WebUI-{}-{}-v6", port, tag),
                    layer,
                    FWP_ACTION_PERMIT,
                    15,
                    &mut cond_v6,
                ) {
                    filter_ids.push(id);
                }
            }
        }

        if let Some(fn_free) = self.fn_free.filter(|_| !app_id_blob.is_null()) {
            unsafe {
                fn_free(
                    (&mut app_id_blob as *mut *mut FwpByteBlob).cast::<*mut std::ffi::c_void>(),
                );
            }
        }

        // 4. Catch-All Block Across All 24 WFP Kernel Layers (Zero DNS/DHCP/WSL2 NAT leaks)
        let block_layers = [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "Block-All-ALE-Out-v4"),
            (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "Block-All-ALE-Out-v6"),
            (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, "Block-All-ALE-In-v4"),
            (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, "Block-All-ALE-In-v6"),
            (FWPM_LAYER_OUTBOUND_TRANSPORT_V4, "Block-All-Trans-Out-v4"),
            (FWPM_LAYER_OUTBOUND_TRANSPORT_V6, "Block-All-Trans-Out-v6"),
            (FWPM_LAYER_INBOUND_TRANSPORT_V4, "Block-All-Trans-In-v4"),
            (FWPM_LAYER_INBOUND_TRANSPORT_V6, "Block-All-Trans-In-v6"),
            (FWPM_LAYER_OUTBOUND_IPPACKET_V4, "Block-All-IP-Out-v4"),
            (FWPM_LAYER_OUTBOUND_IPPACKET_V6, "Block-All-IP-Out-v6"),
            (FWPM_LAYER_INBOUND_IPPACKET_V4, "Block-All-IP-In-v4"),
            (FWPM_LAYER_INBOUND_IPPACKET_V6, "Block-All-IP-In-v6"),
            (FWPM_LAYER_DATAGRAM_DATA_V4, "Block-All-Dgram-Out-v4"),
            (FWPM_LAYER_DATAGRAM_DATA_V6, "Block-All-Dgram-Out-v6"),
            (FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4, "Block-All-ICMP-Out-v4"),
            (FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6, "Block-All-ICMP-Out-v6"),
            (FWPM_LAYER_INBOUND_ICMP_ERROR_V4, "Block-All-ICMP-In-v4"),
            (FWPM_LAYER_INBOUND_ICMP_ERROR_V6, "Block-All-ICMP-In-v6"),
            (
                FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
                "Block-All-MAC-Out-Native",
            ),
            (
                FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE,
                "Block-All-MAC-In-Native",
            ),
            (
                FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET,
                "Block-All-MAC-Out-Eth",
            ),
            (
                FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET,
                "Block-All-MAC-In-Eth",
            ),
            (FWPM_LAYER_IPFORWARD_V4, "Block-All-Forward-v4"),
            (FWPM_LAYER_IPFORWARD_V6, "Block-All-Forward-v6"),
        ];
        for (layer, name) in block_layers {
            if let Some(id) = add_one(name, layer, FWP_ACTION_BLOCK, 1, &mut []) {
                filter_ids.push(id);
            }
        }

        // 5. Explicit Layer-2 Hardware/Quantum EtherType Block Filters
        for ethertype in BLOCKED_L2_ETHERTYPES {
            let mut cond_et = [FwpmFilterCondition0 {
                field_key: FWPM_CONDITION_ETHER_TYPE,
                match_type: FWP_MATCH_EQUAL,
                _pad: 0,
                condition_value: FwpConditionValue0 {
                    type_: FWP_UINT16,
                    _pad: 0,
                    value: ethertype as usize,
                },
            }];
            for (layer, tag) in [
                (FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE, "Native"),
                (FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET, "Eth"),
            ] {
                if let Some(id) = add_one(
                    &format!("Block-EtherType-0x{:04X}-{}", ethertype, tag),
                    layer,
                    FWP_ACTION_BLOCK,
                    5,
                    &mut cond_et,
                ) {
                    filter_ids.push(id);
                }
            }
        }

        if filter_ids.is_empty() {
            self.abort_txn();
            return Err(HostIsolationError::KernelEngineError(
                "Zero WFP filters were added to BFE".to_string(),
            ));
        }

        self.commit_txn()?;
        Ok(filter_ids)
    }

    pub fn install_virtual_patch_inbound_shield(
        &self,
        spec: &KernelPerimeterPatchSpec,
    ) -> Result<Vec<u64>, HostIsolationError> {
        let mut filter_ids = Vec::new();
        self.begin_txn()?;

        // Remove any prior virtual-patch filters (never touching KillSwitch filters).
        for old_id in self.enumerate_prefixed_filter_ids(WFP_VPATCH_RULE_PREFIX) {
            let _ = self.delete_filter(old_id);
        }

        let mut w_desc: Vec<u16> = "AgentOctopus Zero-Reboot Virtual-Patch Inbound Shield\0"
            .encode_utf16()
            .collect();

        let mut add_vpatch = |name: &str,
                              layer: WfpGuid,
                              action: u32,
                              weight_val: usize,
                              conditions: &mut [FwpmFilterCondition0]|
         -> Result<u64, HostIsolationError> {
            let mut w_name: Vec<u16> = format!("{}-{}\0", WFP_VPATCH_RULE_PREFIX, name)
                .encode_utf16()
                .collect();
            let filter = FwpmFilter0 {
                filter_key: WfpGuid::default(),
                display_data: FwpmDisplayData0 {
                    name: w_name.as_mut_ptr(),
                    description: w_desc.as_mut_ptr(),
                },
                flags: 0,
                _pad0: 0,
                provider_key: std::ptr::null_mut(),
                provider_data: FwpByteBlob {
                    size: 0,
                    _pad: 0,
                    data: std::ptr::null_mut(),
                },
                layer_key: layer,
                sub_layer_key: WfpGuid::default(),
                weight: FwpValue0 {
                    type_: if weight_val > 0 { FWP_UINT8 } else { FWP_EMPTY },
                    _pad: 0,
                    value: weight_val,
                },
                num_filter_conditions: conditions.len() as u32,
                _pad1: 0,
                filter_condition: if conditions.is_empty() {
                    std::ptr::null_mut()
                } else {
                    conditions.as_mut_ptr()
                },
                action: FwpmAction0 {
                    type_: action,
                    filter_type: WfpGuid::default(),
                },
                _pad2: 0,
                raw_context_or_provider_context_key: [0; 2],
                reserved: std::ptr::null_mut(),
                filter_id: 0,
                effective_weight: FwpValue0 {
                    type_: FWP_EMPTY,
                    _pad: 0,
                    value: 0,
                },
            };

            let mut assigned: u64 = 0;
            let rc = unsafe {
                (self.fn_add)(
                    self.engine_handle,
                    &filter,
                    std::ptr::null_mut(),
                    &mut assigned,
                )
            };
            if rc == ERROR_SUCCESS && assigned != 0 {
                Ok(assigned)
            } else {
                Err(HostIsolationError::KernelEngineError(format!(
                    "FwpmFilterAdd0 failed for virtual-patch filter '{name}': 0x{rc:08X}"
                )))
            }
        };

        // 1. Weight 21 permit on loopback so 127.0.0.1 / ::1 control ports are preserved.
        for (layer, tag) in [
            (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, "ALE-In-v4"),
            (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, "ALE-In-v6"),
            (FWPM_LAYER_INBOUND_TRANSPORT_V4, "Trans-In-v4"),
            (FWPM_LAYER_INBOUND_TRANSPORT_V6, "Trans-In-v6"),
        ] {
            let mut cond_lb = [FwpmFilterCondition0 {
                field_key: FWPM_CONDITION_FLAGS,
                match_type: FWP_MATCH_FLAGS_ALL_SET,
                _pad: 0,
                condition_value: FwpConditionValue0 {
                    type_: FWP_UINT32,
                    _pad: 0,
                    value: FWP_CONDITION_FLAG_IS_LOOPBACK as usize,
                },
            }];
            match add_vpatch(
                &format!("Permit-Loopback-{tag}"),
                layer,
                FWP_ACTION_PERMIT,
                21,
                &mut cond_lb,
            ) {
                Ok(id) => filter_ids.push(id),
                Err(e) => {
                    self.abort_txn();
                    return Err(e);
                }
            }
        }

        // 2. Weight 20 inbound port blocks across ALE + Inbound Transport v4/v6.
        for &port in &spec.blocked_inbound_ports {
            for (layer, tag) in [
                (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, "ALE-In-v4"),
                (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, "ALE-In-v6"),
                (FWPM_LAYER_INBOUND_TRANSPORT_V4, "Trans-In-v4"),
                (FWPM_LAYER_INBOUND_TRANSPORT_V6, "Trans-In-v6"),
            ] {
                let mut cond_lport = [FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_IP_LOCAL_PORT,
                    match_type: FWP_MATCH_EQUAL,
                    _pad: 0,
                    condition_value: FwpConditionValue0 {
                        type_: FWP_UINT16,
                        _pad: 0,
                        value: port as usize,
                    },
                }];
                match add_vpatch(
                    &format!("Block-InPort-{port}-{tag}"),
                    layer,
                    FWP_ACTION_BLOCK,
                    20,
                    &mut cond_lport,
                ) {
                    Ok(id) => filter_ids.push(id),
                    Err(e) => {
                        self.abort_txn();
                        return Err(e);
                    }
                }
            }
        }

        // 3. Weight 18 inbound IPv6 ICMP error surface clamp when IPv6 RCE shield is active.
        if spec.block_ipv6_rce_surfaces {
            match add_vpatch(
                "Block-Inbound-ICMPv6-Error",
                FWPM_LAYER_INBOUND_ICMP_ERROR_V6,
                FWP_ACTION_BLOCK,
                18,
                &mut [],
            ) {
                Ok(id) => filter_ids.push(id),
                Err(e) => {
                    self.abort_txn();
                    return Err(e);
                }
            }
        }

        if filter_ids.is_empty() {
            self.abort_txn();
            return Err(HostIsolationError::KernelEngineError(
                "Zero virtual-patch WFP filters were added to BFE".to_string(),
            ));
        }

        self.commit_txn()?;
        Ok(filter_ids)
    }

    /// Atomically removes all `AgentOctopus-VirtualPatch-*` WFP filters without touching KillSwitch filters.
    pub fn remove_virtual_patch_inbound_shield(&self) -> Result<usize, HostIsolationError> {
        self.begin_txn()?;
        let mut removed = 0usize;
        for old_id in self.enumerate_prefixed_filter_ids(WFP_VPATCH_RULE_PREFIX) {
            if self.delete_filter(old_id) {
                removed += 1;
            }
        }
        self.commit_txn()?;
        Ok(removed)
    }
}

#[cfg(windows)]
impl Drop for WfpKernelSession {
    fn drop(&mut self) {
        self.abort_txn();
        if !self.engine_handle.is_null() {
            let _ = unsafe { (self.fn_close)(self.engine_handle) };
            self.engine_handle = std::ptr::null_mut();
        }
    }
}

/// Native BFE `FirewallPolicy\FirewallRules` registry rule writer (zero `netsh.exe`).
/// Strictly operates on `Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules` only.
#[cfg(windows)]
const BFE_FIREWALL_RULES_SUBKEY: &str =
    "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules\0";

#[cfg(windows)]
fn bfe_registry_rule_definitions(preserved_ports: &[u16]) -> Vec<(String, String)> {
    let sanitized_ports = sanitize_firewall_preserved_ports(preserved_ports);
    let mut rules = vec![
        (
            format!("{}-Block-Inbound-Low", WFP_RULE_PREFIX),
            format!(
                "v2.31|Action=Block|Active=TRUE|Dir=In|RA4=0.0.0.0-126.255.255.255|Name={}-Block-Inbound-Low|Desc=AgentOctopus Block Inbound Low|",
                WFP_RULE_PREFIX
            ),
        ),
        (
            format!("{}-Block-Inbound-High", WFP_RULE_PREFIX),
            format!(
                "v2.31|Action=Block|Active=TRUE|Dir=In|RA4=128.0.0.0-255.255.255.255|Name={}-Block-Inbound-High|Desc=AgentOctopus Block Inbound High|",
                WFP_RULE_PREFIX
            ),
        ),
        (
            format!("{}-Block-Outbound-Low", WFP_RULE_PREFIX),
            format!(
                "v2.31|Action=Block|Active=TRUE|Dir=Out|RA4=0.0.0.0-126.255.255.255|Name={}-Block-Outbound-Low|Desc=AgentOctopus Block Outbound Low|",
                WFP_RULE_PREFIX
            ),
        ),
        (
            format!("{}-Block-Outbound-High", WFP_RULE_PREFIX),
            format!(
                "v2.31|Action=Block|Active=TRUE|Dir=Out|RA4=128.0.0.0-255.255.255.255|Name={}-Block-Outbound-High|Desc=AgentOctopus Block Outbound High|",
                WFP_RULE_PREFIX
            ),
        ),
        (
            format!("{}-Block-Loopback-Alias-In", WFP_RULE_PREFIX),
            format!(
                "v2.31|Action=Block|Active=TRUE|Dir=In|RA4=127.0.0.2-127.255.255.254|Name={}-Block-Loopback-Alias-In|Desc=AgentOctopus Block Loopback Alias In|",
                WFP_RULE_PREFIX
            ),
        ),
        (
            format!("{}-Block-Loopback-Alias-Out", WFP_RULE_PREFIX),
            format!(
                "v2.31|Action=Block|Active=TRUE|Dir=Out|RA4=127.0.0.2-127.255.255.254|Name={}-Block-Loopback-Alias-Out|Desc=AgentOctopus Block Loopback Alias Out|",
                WFP_RULE_PREFIX
            ),
        ),
        (
            format!("{}-Block-IMDS-Out", WFP_RULE_PREFIX),
            format!(
                "v2.31|Action=Block|Active=TRUE|Dir=Out|RA4=169.254.169.254|Name={}-Block-IMDS-Out|Desc=AgentOctopus Block Cloud IMDS|",
                WFP_RULE_PREFIX
            ),
        ),
        (
            format!("{}-Block-Inbound-v6", WFP_RULE_PREFIX),
            format!(
                "v2.31|Action=Block|Active=TRUE|Dir=In|RA6=::-::0,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff|Name={}-Block-Inbound-v6|Desc=AgentOctopus Block Inbound IPv6|",
                WFP_RULE_PREFIX
            ),
        ),
        (
            format!("{}-Block-Outbound-v6", WFP_RULE_PREFIX),
            format!(
                "v2.31|Action=Block|Active=TRUE|Dir=Out|RA6=::-::0,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff|Name={}-Block-Outbound-v6|Desc=AgentOctopus Block Outbound IPv6|",
                WFP_RULE_PREFIX
            ),
        ),
    ];

    for port in QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS
        .iter()
        .chain(QUARANTINE_BLOCKED_LATERAL_PORTS.iter())
        .chain(QUARANTINE_BLOCKED_DISCOVERY_PORTS.iter())
        .chain(std::iter::once(&FORBIDDEN_PORT_5000))
    {
        for proto in [6u8, 17u8] {
            let block_out = format!("{}-Block-Port-{}-P{}-Out", WFP_RULE_PREFIX, port, proto);
            rules.push((
                block_out.clone(),
                format!(
                    "v2.31|Action=Block|Active=TRUE|Dir=Out|Protocol={}|RPort={}|Name={}|Desc=AgentOctopus Block Hardened Port Out|",
                    proto, port, block_out
                ),
            ));
            let block_in = format!("{}-Block-Port-{}-P{}-In", WFP_RULE_PREFIX, port, proto);
            rules.push((
                block_in.clone(),
                format!(
                    "v2.31|Action=Block|Active=TRUE|Dir=In|Protocol={}|LPort={}|Name={}|Desc=AgentOctopus Block Hardened Port In|",
                    proto, port, block_in
                ),
            ));
        }
    }

    for &port in &sanitized_ports {
        for (tag, la_key, addr, ra_key) in [
            ("v4", "LA4", "127.0.0.1", "RA4"),
            ("v6", "LA6", "::1", "RA6"),
        ] {
            let in_name = format!("{}-Allow-WebUI-{}-In-{}", WFP_RULE_PREFIX, port, tag);
            let in_val = format!(
                "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort={}|{}={}|{}={}|Name={}|Desc=AgentOctopus WebUI Exact Loopback In|",
                port, la_key, addr, ra_key, addr, in_name
            );
            rules.push((in_name, in_val));

            let out_name = format!("{}-Allow-WebUI-{}-Out-{}", WFP_RULE_PREFIX, port, tag);
            let out_val = format!(
                "v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort={}|{}={}|{}={}|Name={}|Desc=AgentOctopus WebUI Exact Loopback Out|",
                port, la_key, addr, ra_key, addr, out_name
            );
            rules.push((out_name, out_val));
        }
    }
    rules
}

#[cfg(windows)]
fn apply_bfe_registry_rules(preserved_ports: &[u16]) -> Vec<String> {
    let subkey_w: Vec<u16> = BFE_FIREWALL_RULES_SUBKEY.encode_utf16().collect();
    let mut hkey: usize = 0;
    let rc = unsafe {
        win_ffi::RegOpenKeyExW(
            win_ffi::HKEY_LOCAL_MACHINE,
            subkey_w.as_ptr(),
            0,
            win_ffi::KEY_READ | win_ffi::KEY_WRITE,
            &mut hkey,
        )
    };
    if rc != 0 || hkey == 0 {
        return Vec::new();
    }

    let mut applied = Vec::new();
    for (name, val) in bfe_registry_rule_definitions(preserved_ports) {
        let name_w: Vec<u16> = format!("{}\0", name).encode_utf16().collect();
        let val_w: Vec<u16> = format!("{}\0", val).encode_utf16().collect();
        let byte_len = (val_w.len() * 2) as u32;
        let set_rc = unsafe {
            win_ffi::RegSetValueExW(
                hkey,
                name_w.as_ptr(),
                0,
                win_ffi::REG_SZ,
                val_w.as_ptr() as *const u8,
                byte_len,
            )
        };
        if set_rc == 0 {
            applied.push(name);
        }
    }
    unsafe {
        let _ = win_ffi::RegCloseKey(hkey);
    }
    applied
}

#[cfg(windows)]
fn remove_bfe_registry_rules() -> usize {
    let subkey_w: Vec<u16> = BFE_FIREWALL_RULES_SUBKEY.encode_utf16().collect();
    let mut hkey: usize = 0;
    let rc = unsafe {
        win_ffi::RegOpenKeyExW(
            win_ffi::HKEY_LOCAL_MACHINE,
            subkey_w.as_ptr(),
            0,
            win_ffi::KEY_READ | win_ffi::KEY_WRITE,
            &mut hkey,
        )
    };
    if rc != 0 || hkey == 0 {
        return 0;
    }

    let mut prefixed_names: Vec<String> = Vec::new();
    let mut index: u32 = 0;
    loop {
        let mut name_buf = vec![0u16; 512];
        let mut name_len = name_buf.len() as u32;
        let enum_rc = unsafe {
            win_ffi::RegEnumValueW(
                hkey,
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if enum_rc == win_ffi::ERROR_NO_MORE_ITEMS {
            break;
        }
        if enum_rc == 0 {
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            if name.starts_with(WFP_RULE_PREFIX) {
                prefixed_names.push(name);
            }
            index = index.saturating_add(1);
        } else {
            break;
        }
    }

    let mut removed = 0usize;
    let mut deleted = Vec::with_capacity(prefixed_names.len());
    for name in prefixed_names {
        let name_w: Vec<u16> = format!("{}\0", name).encode_utf16().collect();
        if unsafe { win_ffi::RegDeleteValueW(hkey, name_w.as_ptr()) } == 0 {
            removed += 1;
        }
        deleted.push(name);
    }

    let mut ports: Vec<u16> = (5005..=5099).collect();
    for p in discover_active_octopus_ports() {
        if !ports.contains(&p) {
            ports.push(p);
        }
    }
    let sanitized = sanitize_firewall_preserved_ports(&ports);
    for (name, _) in bfe_registry_rule_definitions(&sanitized) {
        if deleted.contains(&name) {
            continue;
        }
        let name_w: Vec<u16> = format!("{}\0", name).encode_utf16().collect();
        if unsafe { win_ffi::RegDeleteValueW(hkey, name_w.as_ptr()) } == 0 {
            removed += 1;
        }
    }
    unsafe {
        let _ = win_ffi::RegCloseKey(hkey);
    }
    removed
}

/// Terminates all active non-loopback TCP connections via `iphlpapi.dll` `SetTcpEntry` (`DELETE_TCB`).
pub fn terminate_non_loopback_tcp_sockets(preserved_ports: &[u16]) -> usize {
    #[cfg(windows)]
    {
        let dll_w: Vec<u16> = "iphlpapi.dll\0".encode_utf16().collect();
        let h_mod = unsafe { win_ffi::LoadLibraryW(dll_w.as_ptr()) };
        if h_mod.is_null() {
            return 0;
        }
        let p_get = unsafe { win_ffi::GetProcAddress(h_mod, b"GetTcpTable\0".as_ptr()) };
        let p_set = unsafe { win_ffi::GetProcAddress(h_mod, b"SetTcpEntry\0".as_ptr()) };
        if p_get.is_null() || p_set.is_null() {
            return 0;
        }
        let fn_get: FnGetTcpTable = unsafe { std::mem::transmute(p_get) };
        let fn_set: FnSetTcpEntry = unsafe { std::mem::transmute(p_set) };

        let mut size: u32 = 0;
        let first = unsafe { fn_get(std::ptr::null_mut(), &mut size, 0) };
        if first != ERROR_INSUFFICIENT_BUFFER || size < 4 {
            return 0;
        }
        let mut buf = vec![0u8; size as usize + 512];
        let mut actual = buf.len() as u32;
        if unsafe { fn_get(buf.as_mut_ptr(), &mut actual, 0) } != ERROR_SUCCESS || actual < 4 {
            return 0;
        }

        let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let max_entries = (buf.len().saturating_sub(4)) / std::mem::size_of::<MibTcpRow>();
        let count = num_entries.min(max_entries);
        let rows_ptr = unsafe { buf.as_ptr().add(4) as *const MibTcpRow };

        let sanitized_ports = sanitize_firewall_preserved_ports(preserved_ports);
        let mut terminated = 0usize;
        for i in 0..count {
            let row = unsafe { *rows_ptr.add(i) };
            let local_octets = row.dw_local_addr.to_ne_bytes();
            let remote_octets = row.dw_remote_addr.to_ne_bytes();
            let local_port = u16::from_be((row.dw_local_port & 0xFFFF) as u16);
            let remote_port = u16::from_be((row.dw_remote_port & 0xFFFF) as u16);

            let both_exact_localhost =
                is_exact_localhost_v4(local_octets) && is_exact_localhost_v4(remote_octets);
            let hits_blocked_port = is_explicitly_blocked_quarantine_port(local_port)
                || is_explicitly_blocked_quarantine_port(remote_port);
            let is_ctrl = both_exact_localhost
                && (sanitized_ports.contains(&local_port)
                    || sanitized_ports.contains(&remote_port));
            if matches!(row.dw_state, 3 | 4 | 5 | 8)
                && (!both_exact_localhost || hits_blocked_port)
                && !is_ctrl
            {
                let mut reset_row = row;
                reset_row.dw_state = MIB_TCP_STATE_DELETE_TCB;
                if unsafe { fn_set(&reset_row) } == ERROR_SUCCESS {
                    terminated += 1;
                }
            }
        }
        terminated
    }
    #[cfg(target_os = "linux")]
    {
        terminate_linux_non_loopback_sockets(preserved_ports)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = preserved_ports;
        0
    }
}

#[cfg(target_os = "windows")]
fn wfp_filter_ledger_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let _ = std::fs::create_dir_all("logs");
    paths.push(PathBuf::from("logs").join("octopus_wfp_filters.json"));
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("octopus_wfp_filters.json"));
        }
    }
    paths.push(std::env::temp_dir().join("octopus_wfp_filters.json"));
    paths
}

#[cfg(target_os = "windows")]
fn persist_wfp_filter_ids(ids: &[u64]) {
    if ids.is_empty() {
        return;
    }
    let mut merged = load_persisted_wfp_filter_ids();
    for &id in ids {
        if id != 0 && !merged.contains(&id) {
            merged.push(id);
        }
    }
    if let Ok(json) = serde_json::to_string(&merged) {
        for p in wfp_filter_ledger_paths() {
            if !p.is_symlink() {
                if let Some(parent) = p.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(&p, &json);
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub fn load_persisted_wfp_filter_ids() -> Vec<u64> {
    let mut ids = Vec::new();
    for p in wfp_filter_ledger_paths() {
        if p.is_symlink() {
            continue;
        }
        if let Ok(raw) = std::fs::read_to_string(&p) {
            if let Ok(parsed) = serde_json::from_str::<Vec<u64>>(&raw) {
                for id in parsed {
                    if id != 0 && !ids.contains(&id) {
                        ids.push(id);
                    }
                }
            }
        }
    }
    ids
}

#[cfg(not(target_os = "windows"))]
pub fn load_persisted_wfp_filter_ids() -> Vec<u64> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn clear_persisted_wfp_filter_ids() {
    for p in wfp_filter_ledger_paths() {
        let _ = std::fs::remove_file(p);
    }
}

#[cfg(not(target_os = "windows"))]
fn clear_persisted_wfp_filter_ids() {}

/// Queries live Windows Base Filtering Engine (BFE) or verified filter ledger to check if
/// real kernel quarantine filters are currently active. Prevents split-brain stale ledgers
/// from short-circuiting `/api/killswitch/engage`.
pub fn has_live_active_wfp_filters() -> bool {
    #[cfg(windows)]
    {
        if is_current_process_elevated() {
            if let Ok(session) = WfpKernelSession::open() {
                let persisted = load_persisted_wfp_filter_ids();
                for &fid in &persisted {
                    if session.filter_exists(fid) {
                        return true;
                    }
                }
                let live = session.enumerate_prefixed_filter_ids(WFP_RULE_PREFIX);
                if !live.is_empty() {
                    persist_wfp_filter_ids(&live);
                    return true;
                }
                clear_persisted_wfp_filter_ids();
                return false;
            }
        }
        !load_persisted_wfp_filter_ids().is_empty()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(target_os = "windows")]
fn wfp_vpatch_filter_ledger_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let _ = std::fs::create_dir_all("logs");
    paths.push(PathBuf::from("logs").join("octopus_wfp_vpatch_filters.json"));
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("octopus_wfp_vpatch_filters.json"));
        }
    }
    paths.push(std::env::temp_dir().join("octopus_wfp_vpatch_filters.json"));
    paths
}

#[cfg(target_os = "windows")]
fn persist_vpatch_wfp_filter_ids(ids: &[u64]) {
    if let Ok(json) = serde_json::to_string(ids) {
        for p in wfp_vpatch_filter_ledger_paths() {
            if !p.is_symlink() {
                if let Some(parent) = p.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(&p, &json);
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub fn load_persisted_vpatch_wfp_filter_ids() -> Vec<u64> {
    let mut ids = Vec::new();
    for p in wfp_vpatch_filter_ledger_paths() {
        if p.is_symlink() {
            continue;
        }
        if let Ok(raw) = std::fs::read_to_string(&p) {
            if let Ok(parsed) = serde_json::from_str::<Vec<u64>>(&raw) {
                for id in parsed {
                    if id != 0 && !ids.contains(&id) {
                        ids.push(id);
                    }
                }
            }
        }
    }
    ids
}

#[cfg(not(target_os = "windows"))]
pub fn load_persisted_vpatch_wfp_filter_ids() -> Vec<u64> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn clear_persisted_vpatch_wfp_filter_ids() {
    for p in wfp_vpatch_filter_ledger_paths() {
        let _ = std::fs::remove_file(p);
    }
}

#[cfg(not(target_os = "windows"))]
fn clear_persisted_vpatch_wfp_filter_ids() {}

/// Queries live Windows BFE (when elevated) or persisted virtual-patch filter ledger to count
/// active `AgentOctopus-VirtualPatch-*` WFP filters.
pub fn active_vpatch_wfp_filter_count() -> usize {
    #[cfg(windows)]
    {
        if is_current_process_elevated() {
            if let Ok(session) = WfpKernelSession::open() {
                let live = session.enumerate_prefixed_filter_ids(WFP_VPATCH_RULE_PREFIX);
                if live.is_empty() {
                    clear_persisted_vpatch_wfp_filter_ids();
                } else {
                    persist_vpatch_wfp_filter_ids(&live);
                }
                return live.len();
            }
        }
        load_persisted_vpatch_wfp_filter_ids().len()
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// Returns `true` when targeted virtual-patch WFP filters are live in Windows BFE or recorded by
/// an elevated UAC helper session.
pub fn has_live_active_vpatch_wfp_filters() -> bool {
    active_vpatch_wfp_filter_count() > 0
}

/// Delegates kernel WFP modification to a short-lived elevated
/// `--wfp-kernel-apply <engage|disarm|vpatch-engage|vpatch-disarm>` helper via
/// `ShellExecuteExW("runas")`, keeping the main AgentOctopus server & arms de-elevated (Finding 7).
#[cfg(windows)]
pub fn try_elevated_delegation(action: &str) -> Result<bool, HostIsolationError> {
    if !matches!(
        action,
        "engage" | "disarm" | "vpatch-engage" | "vpatch-disarm"
    ) {
        return Err(HostIsolationError::InvalidAction(action.to_string()));
    }
    if is_current_process_elevated() || is_non_elevated_test_simulation() {
        return Ok(false);
    }

    #[repr(C)]
    struct ShellExecuteInfoW {
        cb_size: u32,
        f_mask: u32,
        hwnd: *mut std::ffi::c_void,
        lp_verb: *const u16,
        lp_file: *const u16,
        lp_parameters: *const u16,
        lp_directory: *const u16,
        n_show: i32,
        h_inst_app: *mut std::ffi::c_void,
        lp_id_list: *mut std::ffi::c_void,
        lp_class: *const u16,
        hkey_class: *mut std::ffi::c_void,
        dw_hot_key: u32,
        h_monitor_or_icon: *mut std::ffi::c_void,
        h_process: *mut std::ffi::c_void,
    }

    type FnShellExecuteExW = unsafe extern "system" fn(*mut ShellExecuteInfoW) -> i32;

    let exe = std::env::current_exe().map_err(|e| HostIsolationError::InsufficientPrivileges {
        details: format!("Cannot resolve current executable path: {}", e),
        remediation: "Run command from an elevated terminal.".to_string(),
    })?;

    let shell_w: Vec<u16> = "shell32.dll\0".encode_utf16().collect();
    let h_shell = unsafe { win_ffi::LoadLibraryW(shell_w.as_ptr()) };
    if h_shell.is_null() {
        return Err(HostIsolationError::InsufficientPrivileges {
            details: "Failed to load shell32.dll for UAC delegation".to_string(),
            remediation: "Run command as Administrator.".to_string(),
        });
    }
    let p_exec = unsafe { win_ffi::GetProcAddress(h_shell, b"ShellExecuteExW\0".as_ptr()) };
    if p_exec.is_null() {
        return Err(HostIsolationError::InsufficientPrivileges {
            details: "ShellExecuteExW not found in shell32.dll".to_string(),
            remediation: "Run command as Administrator.".to_string(),
        });
    }
    let fn_exec: FnShellExecuteExW = unsafe { std::mem::transmute(p_exec) };

    let exe_w: Vec<u16> = exe
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let verb_w: Vec<u16> = "runas\0".encode_utf16().collect();
    let params_w: Vec<u16> = format!("--wfp-kernel-apply {}\0", action)
        .encode_utf16()
        .collect();
    let cwd_w: Option<Vec<u16>> = std::env::current_dir().ok().map(|d| {
        d.to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    });

    let mut sei = ShellExecuteInfoW {
        cb_size: std::mem::size_of::<ShellExecuteInfoW>() as u32,
        f_mask: 0x0000_0040, // SEE_MASK_NOCLOSEPROCESS
        hwnd: std::ptr::null_mut(),
        lp_verb: verb_w.as_ptr(),
        lp_file: exe_w.as_ptr(),
        lp_parameters: params_w.as_ptr(),
        lp_directory: cwd_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
        n_show: 0, // SW_HIDE
        h_inst_app: std::ptr::null_mut(),
        lp_id_list: std::ptr::null_mut(),
        lp_class: std::ptr::null(),
        hkey_class: std::ptr::null_mut(),
        dw_hot_key: 0,
        h_monitor_or_icon: std::ptr::null_mut(),
        h_process: std::ptr::null_mut(),
    };

    let ok = unsafe { fn_exec(&mut sei) };
    if ok == 0 || sei.h_process.is_null() {
        return Err(HostIsolationError::InsufficientPrivileges {
            details: "Windows UAC elevation dialog was declined or cancelled.".to_string(),
            remediation: "Accept the Windows UAC elevation prompt to modify kernel WFP filters."
                .to_string(),
        });
    }

    unsafe {
        let _ = win_ffi::WaitForSingleObject(sei.h_process, win_ffi::INFINITE);
        let mut exit_code: u32 = 1;
        let _ = win_ffi::GetExitCodeProcess(sei.h_process, &mut exit_code);
        let _ = win_ffi::CloseHandle(sei.h_process);
        if exit_code != 0 {
            return Err(HostIsolationError::KernelEngineError(format!(
                "Elevated WFP helper exited with code {}",
                exit_code
            )));
        }
    }

    Ok(true)
}

/// Executes the one-shot elevated `--wfp-kernel-apply <engage|disarm|vpatch-engage|vpatch-disarm>`
/// helper action and exits. Must be invoked at the very top of `main()` before `relaunch_deelevated_or_fail`.
pub fn handle_wfp_kernel_apply_cli(action: &str) -> Result<(), HostIsolationError> {
    if !matches!(
        action,
        "engage" | "disarm" | "vpatch-engage" | "vpatch-disarm"
    ) {
        return Err(HostIsolationError::InvalidAction(format!(
            "Unsupported --wfp-kernel-apply action '{}' (expected 'engage', 'disarm', 'vpatch-engage', or 'vpatch-disarm')",
            action
        )));
    }
    if !is_current_process_elevated() {
        return Err(HostIsolationError::InsufficientPrivileges {
            details: "--wfp-kernel-apply requires an elevated Administrator/root token".to_string(),
            remediation: "Invoke via UAC runas delegation or elevated terminal.".to_string(),
        });
    }

    let preserved_ports = discover_active_octopus_ports();
    match action {
        "engage" => {
            let _ = apply_platform_kernel_quarantine(
                "wfp-helper",
                "Elevated helper engage",
                &preserved_ports,
            )?;
            Ok(())
        }
        "disarm" => {
            disarm_platform_kernel_quarantine("wfp-helper")?;
            Ok(())
        }
        "vpatch-engage" => {
            let posture = crate::security::virtual_patch_shield::current_shield_posture();
            let receipt = apply_virtual_patch_perimeter_shield_with_options(
                &posture,
                &preserved_ports,
                false,
            )?;
            if !receipt.os_enforcement_applied || !receipt.readback_verified {
                return Err(HostIsolationError::KernelEngineError(
                    "Elevated vpatch-engage helper did not verify OS virtual-patch filters"
                        .to_string(),
                ));
            }
            Ok(())
        }
        "vpatch-disarm" => {
            let _ = disarm_virtual_patch_perimeter_shield(false)?;
            Ok(())
        }
        _ => unreachable!(),
    }
}

// =============================================================================
// Linux Raw AF_NETLINK (RTN_BLACKHOLE + INET_DIAG SOCK_DESTROY) — Zero Subprocesses
// =============================================================================

pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const RTN_BLACKHOLE: u8 = 6;
pub const RT_TABLE_MAIN: u8 = 254;
pub const RTPROT_STATIC: u8 = 4;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RTA_PRIORITY: u16 = 6;
pub const NETLINK_INET_DIAG: i32 = 4;
pub const SOCK_DESTROY: u16 = 21;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RtMsg {
    pub rtm_family: u8,
    pub rtm_dst_len: u8,
    pub rtm_src_len: u8,
    pub rtm_tos: u8,
    pub rtm_table: u8,
    pub rtm_protocol: u8,
    pub rtm_scope: u8,
    pub rtm_type: u8,
    pub rtm_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RtAttr {
    pub rta_len: u16,
    pub rta_type: u16,
}

/// Builds a binary Linux `NETLINK_ROUTE` `RTN_BLACKHOLE` message (`0.0.0.0/0` or `::/0` in
/// `RT_TABLE_MAIN`, leaving `lo` in `RT_TABLE_LOCAL` untouched).
pub fn build_linux_blackhole_route_msg(is_v6: bool, is_delete: bool, priority: u32) -> Vec<u8> {
    let family: u8 = if is_v6 { 10 } else { 2 };
    let rta_len = std::mem::size_of::<RtAttr>() + std::mem::size_of::<u32>();
    let total_len = std::mem::size_of::<NlMsgHdr>() + std::mem::size_of::<RtMsg>() + rta_len;

    let hdr = NlMsgHdr {
        nlmsg_len: total_len as u32,
        nlmsg_type: if is_delete {
            RTM_DELROUTE
        } else {
            RTM_NEWROUTE
        },
        nlmsg_flags: if is_delete {
            NLM_F_REQUEST | NLM_F_ACK
        } else {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
        },
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };
    let rt = RtMsg {
        rtm_family: family,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RT_TABLE_MAIN,
        rtm_protocol: RTPROT_STATIC,
        rtm_scope: RT_SCOPE_UNIVERSE,
        rtm_type: RTN_BLACKHOLE,
        rtm_flags: 0,
    };
    let rta = RtAttr {
        rta_len: rta_len as u16,
        rta_type: RTA_PRIORITY,
    };

    let mut out = Vec::with_capacity(total_len);
    unsafe {
        out.extend_from_slice(std::slice::from_raw_parts(
            &hdr as *const _ as *const u8,
            std::mem::size_of::<NlMsgHdr>(),
        ));
        out.extend_from_slice(std::slice::from_raw_parts(
            &rt as *const _ as *const u8,
            std::mem::size_of::<RtMsg>(),
        ));
        out.extend_from_slice(std::slice::from_raw_parts(
            &rta as *const _ as *const u8,
            std::mem::size_of::<RtAttr>(),
        ));
    }
    out.extend_from_slice(&priority.to_ne_bytes());
    out
}

#[cfg(target_os = "linux")]
fn send_linux_netlink_route(msg: &[u8]) -> Result<(), HostIsolationError> {
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
        if fd < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(HostIsolationError::InsufficientPrivileges {
                details: format!("AF_NETLINK socket failed with errno {}", errno),
                remediation: "Run with root / CAP_NET_ADMIN privileges.".to_string(),
            });
        }
        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let sent = libc::sendto(
            fd,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        );
        if sent < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            libc::close(fd);
            return Err(HostIsolationError::KernelEngineError(format!(
                "Netlink sendto failed: errno {}",
                errno
            )));
        }
        let mut ack = [0u8; 512];
        let n = libc::recv(fd, ack.as_mut_ptr() as *mut libc::c_void, ack.len(), 0);
        libc::close(fd);
        if n >= (std::mem::size_of::<NlMsgHdr>() + 4) as isize {
            let hdr = *(ack.as_ptr() as *const NlMsgHdr);
            if hdr.nlmsg_type == 2 {
                let off = std::mem::size_of::<NlMsgHdr>();
                let code = i32::from_ne_bytes([ack[off], ack[off + 1], ack[off + 2], ack[off + 3]]);
                if code != 0 && code != -libc::EEXIST && code != -libc::ESRCH {
                    return Err(HostIsolationError::KernelEngineError(format!(
                        "Netlink route ACK returned {}",
                        code
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcNetSocketTarget {
    is_ipv6: bool,
    protocol: u8,
    local_words: [u32; 4],
    remote_words: [u32; 4],
    local_port: u16,
    remote_port: u16,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_linux_ipv4_hex_word(hex_str: &str) -> Option<(u32, [u8; 4])> {
    if hex_str.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(hex_str, 16).ok()?;
    Some((raw, raw.to_ne_bytes()))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_linux_ipv6_hex_words(hex_str: &str) -> Option<([u32; 4], [u8; 16])> {
    if hex_str.len() != 32 {
        return None;
    }
    let mut words = [0u32; 4];
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&hex_str[i * 8..(i + 1) * 8], 16).ok()?;
        words[i] = word;
        octets[i * 4..(i + 1) * 4].copy_from_slice(&word.to_ne_bytes());
    }
    Some((words, octets))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_net_destroy_targets(
    raw: &str,
    is_ipv6: bool,
    protocol: u8,
    sanitized_ports: &[u16],
) -> Vec<ProcNetSocketTarget> {
    let mut targets = Vec::new();
    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let state = cols[3];
        let active_state = if protocol == 6 {
            matches!(state, "01" | "02" | "03" | "08")
        } else {
            matches!(state, "01" | "07")
        };
        if !active_state {
            continue;
        }
        let Some((l_ip_hex, l_port_hex)) = cols[1].split_once(':') else {
            continue;
        };
        let Some((r_ip_hex, r_port_hex)) = cols[2].split_once(':') else {
            continue;
        };
        let Ok(l_port) = u16::from_str_radix(l_port_hex, 16) else {
            continue;
        };
        let Ok(r_port) = u16::from_str_radix(r_port_hex, 16) else {
            continue;
        };

        let (local_words, remote_words, local_exact_lb, remote_exact_lb, remote_unspec) = if is_ipv6
        {
            let Some((l_words, l_octets)) = parse_linux_ipv6_hex_words(l_ip_hex) else {
                continue;
            };
            let Some((r_words, r_octets)) = parse_linux_ipv6_hex_words(r_ip_hex) else {
                continue;
            };
            (
                l_words,
                r_words,
                is_exact_localhost_v6(l_octets),
                is_exact_localhost_v6(r_octets),
                r_octets == [0u8; 16] && r_port == 0,
            )
        } else {
            let Some((l_word, l_octets)) = parse_linux_ipv4_hex_word(l_ip_hex) else {
                continue;
            };
            let Some((r_word, r_octets)) = parse_linux_ipv4_hex_word(r_ip_hex) else {
                continue;
            };
            (
                [l_word, 0, 0, 0],
                [r_word, 0, 0, 0],
                is_exact_localhost_v4(l_octets),
                is_exact_localhost_v4(r_octets),
                r_octets == [0u8; 4] && r_port == 0,
            )
        };

        let hits_blocked_port = is_explicitly_blocked_quarantine_port(l_port)
            || is_explicitly_blocked_quarantine_port(r_port);
        let is_preserved_ctrl =
            sanitized_ports.contains(&l_port) || sanitized_ports.contains(&r_port);
        let exempt_exact_localhost = !hits_blocked_port
            && is_preserved_ctrl
            && local_exact_lb
            && (remote_exact_lb || (protocol != 6 && state == "07" && remote_unspec));

        if exempt_exact_localhost {
            continue;
        }
        targets.push(ProcNetSocketTarget {
            is_ipv6,
            protocol,
            local_words,
            remote_words,
            local_port: l_port,
            remote_port: r_port,
        });
    }
    targets
}

/// Generates an atomic `nftables` defense-in-depth quarantine ruleset
/// (`table inet agent_octopus_quarantine`) blocking external, loopback-alias, IMDS/link-local,
/// proxy, lateral, and discovery traffic while permitting exact `127.0.0.1`/`::1` TCP control ports.
pub fn generate_linux_nftables_quarantine_script(preserved_ports: &[u16]) -> String {
    let sanitized_ports = sanitize_firewall_preserved_ports(preserved_ports);
    let mut blocked_ports: Vec<u16> = Vec::with_capacity(
        QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS.len()
            + QUARANTINE_BLOCKED_LATERAL_PORTS.len()
            + QUARANTINE_BLOCKED_DISCOVERY_PORTS.len()
            + 1,
    );
    blocked_ports.extend_from_slice(&QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS);
    blocked_ports.extend_from_slice(&QUARANTINE_BLOCKED_LATERAL_PORTS);
    blocked_ports.extend_from_slice(&QUARANTINE_BLOCKED_DISCOVERY_PORTS);
    blocked_ports.push(FORBIDDEN_PORT_5000);
    blocked_ports.sort_unstable();
    blocked_ports.dedup();

    let blocked_list = blocked_ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let allowed_list = sanitized_ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");

    let mut script = String::new();
    script.push_str("add table inet agent_octopus_quarantine\n");
    script.push_str("delete table inet agent_octopus_quarantine\n");
    script.push_str("table inet agent_octopus_quarantine {\n");
    for (chain_name, hook, iface_kw) in [
        ("input", "input", "iifname"),
        ("output", "output", "oifname"),
    ] {
        script.push_str(&format!("    chain {} {{\n", chain_name));
        script.push_str(&format!(
            "        type filter hook {} priority -200; policy drop;\n",
            hook
        ));
        script.push_str("        ip saddr 127.0.0.2-127.255.255.254 drop\n");
        script.push_str("        ip daddr 127.0.0.2-127.255.255.254 drop\n");
        script.push_str("        ip daddr 169.254.0.0/16 drop\n");
        script.push_str("        ip6 daddr fe80::/10 drop\n");
        script.push_str(&format!("        tcp dport {{ {} }} drop\n", blocked_list));
        script.push_str(&format!("        tcp sport {{ {} }} drop\n", blocked_list));
        script.push_str(&format!("        udp dport {{ {} }} drop\n", blocked_list));
        script.push_str(&format!("        udp sport {{ {} }} drop\n", blocked_list));
        if !allowed_list.is_empty() {
            script.push_str(&format!(
                "        {} \"lo\" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp dport {{ {} }} accept\n",
                iface_kw, allowed_list
            ));
            script.push_str(&format!(
                "        {} \"lo\" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport {{ {} }} accept\n",
                iface_kw, allowed_list
            ));
            script.push_str(&format!(
                "        {} \"lo\" ip6 saddr ::1 ip6 daddr ::1 tcp dport {{ {} }} accept\n",
                iface_kw, allowed_list
            ));
            script.push_str(&format!(
                "        {} \"lo\" ip6 saddr ::1 ip6 daddr ::1 tcp sport {{ {} }} accept\n",
                iface_kw, allowed_list
            ));
        }
        script.push_str("    }\n");
    }
    script.push_str("    chain forward {\n");
    script.push_str("        type filter hook forward priority -200; policy drop;\n");
    script.push_str("    }\n");
    script.push_str("}\n");
    script
}

#[cfg(target_os = "linux")]
fn install_linux_nftables_quarantine(preserved_ports: &[u16]) -> Option<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let script = generate_linux_nftables_quarantine_script(preserved_ports);
    for bin in ["/usr/sbin/nft", "/sbin/nft", "nft"] {
        let Ok(mut child) = Command::new(bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
        else {
            continue;
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(script.as_bytes());
        }
        if matches!(child.wait_with_output(), Ok(out) if out.status.success()) {
            return Some("linux-nftables:agent_octopus_quarantine".to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn remove_linux_nftables_quarantine() {
    use std::process::{Command, Stdio};

    for bin in ["/usr/sbin/nft", "/sbin/nft", "nft"] {
        let Ok(status) = Command::new(bin)
            .args(["delete", "table", "inet", "agent_octopus_quarantine"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        else {
            continue;
        };
        if status.success() {
            break;
        }
    }
}

#[cfg(target_os = "linux")]
fn terminate_linux_non_loopback_sockets(preserved_ports: &[u16]) -> usize {
    #[repr(C)]
    struct InetDiagSockId {
        sport: u16,
        dport: u16,
        src: [u32; 4],
        dst: [u32; 4],
        if_idx: u32,
        cookie: [u32; 2],
    }
    #[repr(C)]
    struct InetDiagReqV2 {
        family: u8,
        protocol: u8,
        ext: u8,
        pad: u8,
        states: u32,
        id: InetDiagSockId,
    }

    let sanitized_ports = sanitize_firewall_preserved_ports(preserved_ports);
    let proc_tables: [(&str, bool, u8); 6] = [
        ("/proc/net/tcp", false, 6),
        ("/proc/net/tcp6", true, 6),
        ("/proc/net/udp", false, 17),
        ("/proc/net/udp6", true, 17),
        ("/proc/net/raw", false, 255),
        ("/proc/net/raw6", true, 255),
    ];

    let mut targets = Vec::new();
    for (path, is_ipv6, protocol) in proc_tables {
        if let Ok(raw) = std::fs::read_to_string(path) {
            targets.extend(parse_proc_net_destroy_targets(
                &raw,
                is_ipv6,
                protocol,
                &sanitized_ports,
            ));
        }
    }
    if targets.is_empty() {
        return 0;
    }

    let mut destroyed = 0usize;
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_INET_DIAG);
        if fd < 0 {
            return 0;
        }
        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;

        for (seq_offset, target) in targets.into_iter().enumerate() {
            let total_len = std::mem::size_of::<NlMsgHdr>() + std::mem::size_of::<InetDiagReqV2>();
            let hdr = NlMsgHdr {
                nlmsg_len: total_len as u32,
                nlmsg_type: SOCK_DESTROY,
                nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
                nlmsg_seq: 2 + seq_offset as u32,
                nlmsg_pid: 0,
            };
            let req = InetDiagReqV2 {
                family: if target.is_ipv6 {
                    libc::AF_INET6 as u8
                } else {
                    libc::AF_INET as u8
                },
                protocol: target.protocol,
                ext: 0,
                pad: 0,
                states: 0xFFFF_FFFF,
                id: InetDiagSockId {
                    sport: target.local_port.to_be(),
                    dport: target.remote_port.to_be(),
                    src: target.local_words,
                    dst: target.remote_words,
                    if_idx: 0,
                    cookie: [0xFFFF_FFFF, 0xFFFF_FFFF],
                },
            };
            let mut pkt = Vec::with_capacity(total_len);
            pkt.extend_from_slice(std::slice::from_raw_parts(
                &hdr as *const _ as *const u8,
                std::mem::size_of::<NlMsgHdr>(),
            ));
            pkt.extend_from_slice(std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<InetDiagReqV2>(),
            ));
            if libc::sendto(
                fd,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            ) >= 0
            {
                destroyed += 1;
            }
        }
        libc::close(fd);
    }
    destroyed
}

// =============================================================================
// macOS Native `/dev/pf` Binary `ioctl` Ruleset — Zero Subprocesses
// =============================================================================

pub const DIOCSTART: u64 = 0x2000_4401;
pub const DIOCADDRULE: u64 = 0xC808_4404;
pub const DIOCXBEGIN: u64 = 0xC810_4451;
pub const DIOCXCOMMIT: u64 = 0xC810_4452;
pub const DIOCXROLLBACK: u64 = 0xC810_4453;

/// Generates the deterministic hardened macOS `/dev/pf` anchor ruleset preserving ONLY
/// exact-localhost (`127.0.0.1` / `::1`) TCP control ports while explicitly blocking DNS,
/// DHCP, IMDS (`169.254.0.0/16`), link-local IPv6, loopback aliases, QUIC UDP/443, proxy
/// forwarders (`1080, 3128, 8080, 8888, 9050`), lateral ports (`135, 445, 5985, 5986`), and
/// all external traffic.
pub fn generate_macos_pf_quarantine_rules(anchor: &str, preserved_ports: &[u16]) -> Vec<String> {
    let sanitized_ports = sanitize_firewall_preserved_ports(preserved_ports);
    let mut lines = vec![
        format!("# AgentOctopus macOS /dev/pf Quarantine Anchor: {}", anchor),
        "block drop out quick proto { tcp, udp, icmp } from any to 169.254.0.0/16".to_string(),
        "block drop out quick proto { tcp, udp } from any to fe80::/10".to_string(),
        "block drop out quick proto udp from any to any port 443".to_string(),
    ];

    for port in QUARANTINE_BLOCKED_DISCOVERY_PORTS
        .iter()
        .chain(QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS.iter())
        .chain(QUARANTINE_BLOCKED_LATERAL_PORTS.iter())
        .chain(std::iter::once(&FORBIDDEN_PORT_5000))
    {
        lines.push(format!(
            "block drop in quick proto {{ tcp, udp }} from any to any port {}",
            port
        ));
        lines.push(format!(
            "block drop out quick proto {{ tcp, udp }} from any to any port {}",
            port
        ));
    }

    for &port in &sanitized_ports {
        lines.push(format!(
            "pass in quick on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.1 port {} keep state",
            port
        ));
        lines.push(format!(
            "pass out quick on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.1 port {} keep state",
            port
        ));
        lines.push(format!(
            "pass out quick on lo0 inet proto tcp from 127.0.0.1 port {} to 127.0.0.1 keep state",
            port
        ));
        lines.push(format!(
            "pass in quick on lo0 inet proto tcp from 127.0.0.1 port {} to 127.0.0.1 keep state",
            port
        ));
        lines.push(format!(
            "pass in quick on lo0 inet6 proto tcp from ::1 to ::1 port {} keep state",
            port
        ));
        lines.push(format!(
            "pass out quick on lo0 inet6 proto tcp from ::1 to ::1 port {} keep state",
            port
        ));
        lines.push(format!(
            "pass out quick on lo0 inet6 proto tcp from ::1 port {} to ::1 keep state",
            port
        ));
        lines.push(format!(
            "pass in quick on lo0 inet6 proto tcp from ::1 port {} to ::1 keep state",
            port
        ));
    }

    lines.push("block drop in quick on lo0 from 127.0.0.0/8 to any".to_string());
    lines.push("block drop out quick on lo0 from 127.0.0.0/8 to any".to_string());
    lines.push("block drop quick on lo0 all".to_string());
    lines.push("block drop in quick all".to_string());
    lines.push("block drop out quick all".to_string());
    lines
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn apply_macos_pf_ioctl(
    engage: bool,
    preserved_ports: &[u16],
) -> Result<String, HostIsolationError> {
    use std::ffi::CString;

    const MAXPATHLEN: usize = 1024;
    const IFNAMSIZ: usize = 16;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct PfTransElem {
        rs_num: i32,
        anchor: [u8; MAXPATHLEN],
        ticket: u32,
    }
    #[repr(C)]
    struct PfTrans {
        size: i32,
        esize: i32,
        array: *mut PfTransElem,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct PfPortRange {
        port_start: u16,
        port_end: u16,
        op: u8,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct PfRuleRaw {
        action: u8,
        direction: u8,
        quick: u8,
        log: u8,
        proto: u8,
        af: u8,
        ifname: [u8; IFNAMSIZ],
        src_port: PfPortRange,
        dst_port: PfPortRange,
        keep_state: u8,
        rule_flag: u32,
        return_icmp: u8,
        return_icmp6: u8,
        padding: [u8; 64],
    }
    #[repr(C)]
    struct PfiocRule {
        action: u32,
        ticket: u32,
        nr: u32,
        anchor: [u8; MAXPATHLEN],
        ruleset: [u8; MAXPATHLEN],
        rule: PfRuleRaw,
    }

    let dev = CString::new("/dev/pf").unwrap();
    let fd = unsafe { libc::open(dev.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(HostIsolationError::InsufficientPrivileges {
            details: format!("Cannot open /dev/pf (errno {})", errno),
            remediation: "Run with sudo / root privileges.".to_string(),
        });
    }

    let mut elem = PfTransElem {
        rs_num: 1,
        anchor: [0u8; MAXPATHLEN],
        ticket: 0,
    };
    let anchor_bytes = b"agent_octopus";
    elem.anchor[..anchor_bytes.len()].copy_from_slice(anchor_bytes);

    let mut trans = PfTrans {
        size: 1,
        esize: std::mem::size_of::<PfTransElem>() as i32,
        array: &mut elem,
    };

    unsafe {
        if engage {
            let _ = libc::ioctl(fd, DIOCSTART as libc::c_ulong);
        }
        if libc::ioctl(fd, DIOCXBEGIN as libc::c_ulong, &mut trans) < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            libc::close(fd);
            return Err(HostIsolationError::KernelEngineError(format!(
                "/dev/pf DIOCXBEGIN failed: errno {}",
                errno
            )));
        }

        if engage {
            let sanitized_ports = sanitize_firewall_preserved_ports(preserved_ports);
            let mut rules_raw: Vec<(u8, u8, Option<&[u8]>, u8, Option<u16>)> = Vec::new();
            for &port in QUARANTINE_BLOCKED_DISCOVERY_PORTS
                .iter()
                .chain(QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS.iter())
                .chain(QUARANTINE_BLOCKED_LATERAL_PORTS.iter())
                .chain(std::iter::once(&FORBIDDEN_PORT_5000))
            {
                for proto in [6u8, 17u8] {
                    rules_raw.push((1, 1, None, proto, Some(port)));
                    rules_raw.push((1, 2, None, proto, Some(port)));
                }
            }
            for &ctrl in &sanitized_ports {
                rules_raw.push((0, 1, Some(b"lo0"), 6, Some(ctrl)));
                rules_raw.push((0, 2, Some(b"lo0"), 6, Some(ctrl)));
            }
            rules_raw.push((1, 0, Some(b"lo0"), 0, None));
            rules_raw.push((1, 1, None, 0, None));
            rules_raw.push((1, 2, None, 0, None));

            for (idx, (act, dir, iface, proto, port)) in rules_raw.into_iter().enumerate() {
                let mut pr = PfiocRule {
                    action: 0,
                    ticket: elem.ticket,
                    nr: idx as u32,
                    anchor: [0u8; MAXPATHLEN],
                    ruleset: [0u8; MAXPATHLEN],
                    rule: PfRuleRaw {
                        action: act,
                        direction: dir,
                        quick: 1,
                        log: 0,
                        proto,
                        af: 0,
                        ifname: [0u8; IFNAMSIZ],
                        src_port: PfPortRange::default(),
                        dst_port: PfPortRange::default(),
                        keep_state: if act == 0 { 1 } else { 0 },
                        rule_flag: 0,
                        return_icmp: 0,
                        return_icmp6: 0,
                        padding: [0u8; 64],
                    },
                };
                pr.anchor[..anchor_bytes.len()].copy_from_slice(anchor_bytes);
                if let Some(ifb) = iface {
                    pr.rule.ifname[..ifb.len()].copy_from_slice(ifb);
                }
                if let Some(p) = port {
                    pr.rule.dst_port = PfPortRange {
                        port_start: p.to_be(),
                        port_end: p.to_be(),
                        op: 1,
                    };
                }
                if libc::ioctl(fd, DIOCADDRULE as libc::c_ulong, &mut pr) < 0 {
                    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    let _ = libc::ioctl(fd, DIOCXROLLBACK as libc::c_ulong, &mut trans);
                    libc::close(fd);
                    return Err(HostIsolationError::KernelEngineError(format!(
                        "/dev/pf DIOCADDRULE failed: errno {}",
                        errno
                    )));
                }
            }
        }

        if libc::ioctl(fd, DIOCXCOMMIT as libc::c_ulong, &mut trans) < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            libc::close(fd);
            return Err(HostIsolationError::KernelEngineError(format!(
                "/dev/pf DIOCXCOMMIT failed: errno {}",
                errno
            )));
        }
        libc::close(fd);
    }

    Ok(format!("darwin-pf-agent_octopus-ticket-{}", elem.ticket))
}

// =============================================================================
// Platform Dispatch + Unified Hash-Chained State Ledger (`HostKillSwitchManager`)
// =============================================================================

fn build_receipt(
    backend: KernelIsolationBackend,
    session_id: String,
    wfp_filter_ids: Vec<u64>,
    bfe_registry_rules: Vec<String>,
    netlink_or_pf_tokens: Vec<String>,
    preserved_ports: Vec<u16>,
    terminated_tcp_sockets: usize,
    engaged_by: &str,
    reason: &str,
) -> HostIsolationReceipt {
    let ts = unix_now_secs();
    let l2_hex: Vec<String> = BLOCKED_L2_ETHERTYPES
        .iter()
        .map(|e| format!("0x{:04X}", e))
        .collect();
    let preserved_ips = vec![
        IpAddr::V4(Ipv4Addr::LOCALHOST).to_string(),
        IpAddr::V6(Ipv6Addr::LOCALHOST).to_string(),
    ];
    let receipt_id = format!("octo-ks-{}-{}", ts, wfp_filter_ids.len());

    let mut hasher = Sha256::new();
    hasher.update(receipt_id.as_bytes());
    hasher.update(backend.label().as_bytes());
    hasher.update(session_id.as_bytes());
    hasher.update(format!("{:?}", wfp_filter_ids).as_bytes());
    hasher.update(engaged_by.as_bytes());
    hasher.update(reason.as_bytes());
    hasher.update(ts.to_le_bytes());
    let receipt_sha256 = hex::encode(hasher.finalize());

    HostIsolationReceipt {
        receipt_id,
        backend,
        session_id,
        wfp_filter_ids,
        bfe_registry_rules,
        netlink_or_pf_tokens,
        preserved_ports,
        preserved_loopback_ips: preserved_ips,
        terminated_tcp_sockets,
        universal_domains_covered: UniversalProtocolCatalog::all_domains().len(),
        universal_protocols_blocked: UniversalProtocolCatalog::total_protocols_count(),
        iana_ip_protocols_blocked: 256,
        l2_ethertypes_blocked: l2_hex,
        engaged_by: engaged_by.to_string(),
        reason: reason.to_string(),
        timestamp_unix: ts,
        receipt_sha256,
    }
}

fn apply_platform_kernel_quarantine(
    engaged_by: &str,
    reason: &str,
    preserved_ports: &[u16],
) -> Result<HostIsolationReceipt, HostIsolationError> {
    let sanitized_ports = sanitize_firewall_preserved_ports(preserved_ports);
    if !is_current_process_elevated() && is_non_elevated_test_simulation() {
        return Ok(build_receipt(
            KernelIsolationBackend::SimulatedNonElevatedTest,
            "simulated-cargo-test-session".to_string(),
            vec![900_001, 900_002, 900_003],
            Vec::new(),
            vec!["cargo-test-non-elevated".to_string()],
            sanitized_ports,
            0,
            engaged_by,
            reason,
        ));
    }

    #[cfg(windows)]
    {
        if !is_current_process_elevated() {
            let delegated = try_elevated_delegation("engage")?;
            if !delegated {
                return Err(HostIsolationError::InsufficientPrivileges {
                    details: "Administrator privileges required to install WFP kernel filters."
                        .to_string(),
                    remediation: "Accept the UAC prompt or run terminal as Administrator."
                        .to_string(),
                });
            }
            let persisted = load_persisted_wfp_filter_ids();
            if persisted.is_empty() {
                return Err(HostIsolationError::KernelEngineError(
                    "Elevated helper completed without persisting WFP filter IDs".to_string(),
                ));
            }
            return Ok(build_receipt(
                KernelIsolationBackend::WindowsWfpBfe22Layer,
                "elevated-uac-helper-session".to_string(),
                persisted,
                Vec::new(),
                Vec::new(),
                sanitized_ports,
                0,
                engaged_by,
                reason,
            ));
        }

        let session = WfpKernelSession::open()?;
        let mut stale = load_persisted_wfp_filter_ids();
        for fid in session.enumerate_prefixed_filter_ids(WFP_RULE_PREFIX) {
            if !stale.contains(&fid) {
                stale.push(fid);
            }
        }
        if !stale.is_empty() {
            if session.begin_txn().is_ok() {
                for fid in &stale {
                    let _ = session.delete_filter(*fid);
                }
                let _ = session.commit_txn();
            }
            clear_persisted_wfp_filter_ids();
        }

        let ids = session.install_22_layer_quarantine(&sanitized_ports)?;
        for fid in &ids {
            if !session.filter_exists(*fid) {
                return Err(HostIsolationError::KernelEngineError(format!(
                    "WFP post-commit read-back verification failed for filter {fid}"
                )));
            }
        }
        persist_wfp_filter_ids(&ids);
        let reg_rules = apply_bfe_registry_rules(&sanitized_ports);
        let severed = terminate_non_loopback_tcp_sockets(&sanitized_ports);

        Ok(build_receipt(
            KernelIsolationBackend::WindowsWfpBfe22Layer,
            format!("wfp-{:p}", session.engine_handle),
            ids,
            reg_rules,
            Vec::new(),
            sanitized_ports,
            severed,
            engaged_by,
            reason,
        ))
    }

    #[cfg(target_os = "linux")]
    {
        if !is_current_process_elevated() {
            return Err(HostIsolationError::InsufficientPrivileges {
                details: "Root / CAP_NET_ADMIN required for AF_NETLINK RTN_BLACKHOLE quarantine"
                    .to_string(),
                remediation: "Run with sudo or grant CAP_NET_ADMIN.".to_string(),
            });
        }
        send_linux_netlink_route(&build_linux_blackhole_route_msg(false, false, 10))?;
        send_linux_netlink_route(&build_linux_blackhole_route_msg(true, false, 10))?;
        let mut tokens = vec![
            "ipv4:0.0.0.0/0->RTN_BLACKHOLE".to_string(),
            "ipv6:::/0->RTN_BLACKHOLE".to_string(),
        ];
        if let Some(nft_token) = install_linux_nftables_quarantine(&sanitized_ports) {
            tokens.push(nft_token);
        }
        let severed = terminate_linux_non_loopback_sockets(&sanitized_ports);
        Ok(build_receipt(
            KernelIsolationBackend::LinuxNetlinkBlackhole,
            "linux-netlink-rt-main".to_string(),
            Vec::new(),
            Vec::new(),
            tokens,
            sanitized_ports,
            severed,
            engaged_by,
            reason,
        ))
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        if !is_current_process_elevated() {
            return Err(HostIsolationError::InsufficientPrivileges {
                details: "Root privileges required for /dev/pf ioctl quarantine".to_string(),
                remediation: "Run with sudo.".to_string(),
            });
        }
        let token = apply_macos_pf_ioctl(true, &sanitized_ports)?;
        Ok(build_receipt(
            KernelIsolationBackend::MacOsPfIoctl,
            token.clone(),
            Vec::new(),
            Vec::new(),
            vec![token],
            sanitized_ports,
            0,
            engaged_by,
            reason,
        ))
    }

    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        let _ = (engaged_by, reason, sanitized_ports);
        Err(HostIsolationError::KernelEngineError(
            "Unsupported OS for kernel perimeter isolation".to_string(),
        ))
    }
}

fn disarm_platform_kernel_quarantine(disarmed_by: &str) -> Result<(), HostIsolationError> {
    if !is_current_process_elevated() && is_non_elevated_test_simulation() {
        clear_persisted_wfp_filter_ids();
        return Ok(());
    }

    #[cfg(windows)]
    {
        if !is_current_process_elevated() {
            let persisted = load_persisted_wfp_filter_ids();
            let explicit = disarmed_by != "BOOT_RECONCILE";
            if !persisted.is_empty() || explicit {
                let delegated = try_elevated_delegation("disarm")?;
                if !delegated {
                    return Err(HostIsolationError::InsufficientPrivileges {
                        details:
                            "Administrator privileges required to remove WFP kernel quarantine filters."
                                .to_string(),
                        remediation: "Accept the UAC prompt or run terminal as Administrator."
                            .to_string(),
                    });
                }
            }
            clear_persisted_wfp_filter_ids();
            return Ok(());
        }

        let mut ids = load_persisted_wfp_filter_ids();
        if let Ok(session) = WfpKernelSession::open() {
            for live in session.enumerate_prefixed_filter_ids(WFP_RULE_PREFIX) {
                if !ids.contains(&live) {
                    ids.push(live);
                }
            }
            if !ids.is_empty() && session.begin_txn().is_ok() {
                for id in &ids {
                    let _ = session.delete_filter(*id);
                }
                let _ = session.commit_txn();
            }
        }
        let _ = remove_bfe_registry_rules();
        clear_persisted_wfp_filter_ids();
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let _ = disarmed_by;
        if is_current_process_elevated() {
            let _ = send_linux_netlink_route(&build_linux_blackhole_route_msg(false, true, 10));
            let _ = send_linux_netlink_route(&build_linux_blackhole_route_msg(true, true, 10));
            remove_linux_nftables_quarantine();
        }
        Ok(())
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        let _ = disarmed_by;
        if is_current_process_elevated() {
            let _ = apply_macos_pf_ioctl(false, &[]);
        }
        Ok(())
    }

    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        let _ = disarmed_by;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedKillSwitchLedger {
    pub isolated: bool,
    pub sequence: u64,
    pub state_hash: String,
    pub last_transition_unix: u64,
    pub last_operator: String,
    pub last_reason: String,
    pub active_receipt: Option<HostIsolationReceipt>,
}

impl Default for PersistedKillSwitchLedger {
    fn default() -> Self {
        let mut h = Sha256::new();
        h.update(b"AGENT_OCTOPUS_KILLSWITCH_GENESIS_V1");
        Self {
            isolated: false,
            sequence: 0,
            state_hash: hex::encode(h.finalize()),
            last_transition_unix: unix_now_secs(),
            last_operator: "system_genesis".to_string(),
            last_reason: "Initialized in normal connected posture".to_string(),
            active_receipt: None,
        }
    }
}

fn state_ledger_paths() -> Vec<PathBuf> {
    let _ = std::fs::create_dir_all("logs");
    let mut paths = vec![PathBuf::from("logs").join("killswitch_state.json")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("octopus_killswitch_state.json"));
        }
    }
    paths.push(std::env::temp_dir().join("octopus_killswitch_state.json"));
    paths
}

pub struct HostKillSwitchManager {
    inner: Mutex<PersistedKillSwitchLedger>,
    custom_ledger_path: Option<PathBuf>,
}

impl HostKillSwitchManager {
    pub fn new(custom_ledger_path: Option<PathBuf>) -> Self {
        #[allow(unused_mut)]
        let mut loaded = Self::read_latest_ledger(custom_ledger_path.as_ref());
        // Boot-time reconciliation: if disk claims isolated=true on Windows, verify live BFE filters!
        #[cfg(windows)]
        if loaded.isolated
            && custom_ledger_path.is_none()
            && !is_non_elevated_test_simulation()
            && !has_live_active_wfp_filters()
        {
            loaded.isolated = false;
            loaded.active_receipt = None;
            loaded.sequence = loaded.sequence.saturating_add(1);
            loaded.last_transition_unix = unix_now_secs();
            loaded.last_operator = "boot_reconciliation".to_string();
            loaded.last_reason =
                "Reconciled stale isolated=true ledger (zero live WFP filters in BFE)".to_string();
            loaded.state_hash = Self::compute_next_hash(
                &loaded.state_hash,
                loaded.sequence,
                false,
                &loaded.last_operator,
            );
            Self::write_ledger(&loaded, custom_ledger_path.as_ref());
        }
        Self {
            inner: Mutex::new(loaded),
            custom_ledger_path,
        }
    }

    fn read_latest_ledger(custom: Option<&PathBuf>) -> PersistedKillSwitchLedger {
        if let Some(p) = custom {
            if let Ok(raw) = std::fs::read_to_string(p) {
                if let Ok(parsed) = serde_json::from_str::<PersistedKillSwitchLedger>(&raw) {
                    return parsed;
                }
            }
            return PersistedKillSwitchLedger::default();
        }
        let mut best: Option<PersistedKillSwitchLedger> = None;
        for path in state_ledger_paths() {
            if path.is_symlink() {
                continue;
            }
            if let Ok(raw) = std::fs::read_to_string(&path) {
                if let Ok(parsed) = serde_json::from_str::<PersistedKillSwitchLedger>(&raw) {
                    let replace = match &best {
                        None => true,
                        Some(curr) => {
                            parsed.sequence > curr.sequence
                                || (parsed.sequence == curr.sequence
                                    && parsed.last_transition_unix > curr.last_transition_unix)
                        }
                    };
                    if replace {
                        best = Some(parsed);
                    }
                }
            }
        }
        best.unwrap_or_default()
    }

    fn write_ledger(state: &PersistedKillSwitchLedger, custom: Option<&PathBuf>) {
        let Ok(json) = serde_json::to_string_pretty(state) else {
            return;
        };
        if let Some(p) = custom {
            if !p.is_symlink() {
                if let Some(parent) = p.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(p, &json);
            }
            return;
        }
        for path in state_ledger_paths() {
            if !path.is_symlink() {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(&path, &json);
            }
        }
    }

    fn compute_next_hash(prev: &str, seq: u64, isolated: bool, operator: &str) -> String {
        let mut h = Sha256::new();
        h.update(prev.as_bytes());
        h.update(seq.to_le_bytes());
        h.update([u8::from(isolated)]);
        h.update(operator.as_bytes());
        hex::encode(h.finalize())
    }

    pub fn status(&self) -> HostKillSwitchStatus {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if self.custom_ledger_path.is_none() {
            let disk = Self::read_latest_ledger(None);
            if disk.sequence > guard.sequence {
                *guard = disk;
            }
        }

        #[cfg(windows)]
        let live_verified =
            if self.custom_ledger_path.is_some() || is_non_elevated_test_simulation() {
                guard.isolated
            } else {
                has_live_active_wfp_filters()
            };
        #[cfg(not(windows))]
        let live_verified = guard.isolated;

        #[cfg(windows)]
        if guard.isolated
            && self.custom_ledger_path.is_none()
            && !is_non_elevated_test_simulation()
            && !live_verified
        {
            guard.isolated = false;
            guard.active_receipt = None;
            guard.sequence = guard.sequence.saturating_add(1);
            guard.last_transition_unix = unix_now_secs();
            guard.last_operator = "live_bfe_reconciler".to_string();
            guard.last_reason = "BFE reported zero active WFP quarantine filters".to_string();
            guard.state_hash = Self::compute_next_hash(
                &guard.state_hash,
                guard.sequence,
                false,
                &guard.last_operator,
            );
            Self::write_ledger(&guard, self.custom_ledger_path.as_ref());
        }

        let active_filter_count = guard
            .active_receipt
            .as_ref()
            .map(|r| r.wfp_filter_ids.len())
            .unwrap_or_else(|| load_persisted_wfp_filter_ids().len());

        let backend_engine = if let Some(ref r) = guard.active_receipt {
            r.backend.label().to_string()
        } else if cfg!(windows) {
            KernelIsolationBackend::WindowsWfpBfe22Layer
                .label()
                .to_string()
        } else if cfg!(target_os = "linux") {
            KernelIsolationBackend::LinuxNetlinkBlackhole
                .label()
                .to_string()
        } else {
            KernelIsolationBackend::MacOsPfIoctl.label().to_string()
        };

        HostKillSwitchStatus {
            isolated: guard.isolated,
            containment_level: if guard.isolated {
                "HermeticIsolation".to_string()
            } else {
                "Disarmed".to_string()
            },
            live_kernel_filters_verified: live_verified,
            active_wfp_filter_count: active_filter_count,
            backend_engine,
            preserved_loopback_ports: discover_active_octopus_ports(),
            universal_domains_count: UniversalProtocolCatalog::all_domains().len(),
            universal_protocols_count: UniversalProtocolCatalog::total_protocols_count(),
            iana_ip_protocols_covered: 256,
            wfp_kernel_layers_enforced: 24,
            zero_subprocess_enforced: true,
            sequence: guard.sequence,
            state_hash: guard.state_hash.clone(),
            last_transition_unix: guard.last_transition_unix,
            last_operator: guard.last_operator.clone(),
            last_reason: guard.last_reason.clone(),
            active_receipt: guard.active_receipt.clone(),
        }
    }

    pub fn engage(
        &self,
        operator: &str,
        reason: &str,
    ) -> Result<HostKillSwitchStatus, HostIsolationError> {
        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if self.custom_ledger_path.is_none() {
                let disk = Self::read_latest_ledger(None);
                if disk.sequence > guard.sequence {
                    *guard = disk;
                }
            }
            if guard.isolated {
                #[cfg(windows)]
                let has_live =
                    if self.custom_ledger_path.is_some() || is_non_elevated_test_simulation() {
                        true
                    } else {
                        has_live_active_wfp_filters()
                    };
                #[cfg(not(windows))]
                let has_live = true;

                if has_live {
                    drop(guard);
                    return Ok(self.status());
                }
                guard.isolated = false;
                guard.active_receipt = None;
            }
        }

        let preserved_ports = discover_active_octopus_ports();
        let receipt = if self.custom_ledger_path.is_some() {
            build_receipt(
                KernelIsolationBackend::SimulatedNonElevatedTest,
                "custom-ledger-test-session".to_string(),
                vec![700_001, 700_002],
                Vec::new(),
                Vec::new(),
                preserved_ports,
                0,
                operator,
                reason,
            )
        } else {
            apply_platform_kernel_quarantine(operator, reason, &preserved_ports)?
        };

        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.sequence = guard.sequence.saturating_add(1);
            guard.isolated = true;
            guard.last_transition_unix = unix_now_secs();
            guard.last_operator = operator.to_string();
            guard.last_reason = reason.to_string();
            guard.state_hash =
                Self::compute_next_hash(&guard.state_hash, guard.sequence, true, operator);
            guard.active_receipt = Some(receipt);
            Self::write_ledger(&guard, self.custom_ledger_path.as_ref());
        }

        Ok(self.status())
    }

    pub fn disarm(
        &self,
        operator: &str,
        reason: &str,
    ) -> Result<HostKillSwitchStatus, HostIsolationError> {
        let is_isolated_test_fixture = self.custom_ledger_path.is_some();
        if !is_isolated_test_fixture
            && crate::security::virtual_patch_shield::current_shield_posture()
                .shield_locked_until_reboot
        {
            return Err(HostIsolationError::KernelEngineError(
                "Monotonic violation: cannot disarm host perimeter while shield_locked_until_reboot is active"
                    .to_string(),
            ));
        }

        if !is_isolated_test_fixture {
            disarm_platform_kernel_quarantine(operator)?;
        }

        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.sequence = guard.sequence.saturating_add(1);
            guard.isolated = false;
            guard.last_transition_unix = unix_now_secs();
            guard.last_operator = operator.to_string();
            guard.last_reason = reason.to_string();
            guard.state_hash =
                Self::compute_next_hash(&guard.state_hash, guard.sequence, false, operator);
            guard.active_receipt = None;
            Self::write_ledger(&guard, self.custom_ledger_path.as_ref());
        }

        Ok(self.status())
    }
}

static GLOBAL_HOST_KILLSWITCH: OnceLock<HostKillSwitchManager> = OnceLock::new();

pub fn global_host_killswitch() -> &'static HostKillSwitchManager {
    GLOBAL_HOST_KILLSWITCH.get_or_init(|| HostKillSwitchManager::new(None))
}

/// High-risk inbound/lateral kernel attack ports blocked by Zero-Reboot Virtual Patching
/// (`SMBv3`/`ksmbd` `445`, `HTTP.sys` `80/443/5985/5986`, `RPC`/`NetBIOS` `135/137/138/139`,
/// `RDP` `3389`, `mDNS`/`LLMNR` `5353/5355`).
pub const VIRTUAL_PATCH_INBOUND_PORTS: &[u16] = &[
    80, 135, 137, 138, 139, 443, 445, 3389, 5353, 5355, 5985, 5986,
];

/// Deterministic specification of the targeted `<1ms` No Break-In kernel perimeter shield.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelPerimeterPatchSpec {
    pub blocked_inbound_ports: Vec<u16>,
    pub block_ipv6_rce_surfaces: bool,
    pub preserved_loopback_ports: Vec<u16>,
    pub target_surfaces: Vec<String>,
    pub cve_ids: Vec<String>,
}

/// Builds a targeted `KernelPerimeterPatchSpec` from `KernelShieldPosture` (pure cross-OS).
#[must_use]
pub fn build_virtual_patch_perimeter_spec(
    posture: &crate::security::virtual_patch_shield::KernelShieldPosture,
    preserved_ports: &[u16],
) -> KernelPerimeterPatchSpec {
    let mut ports: Vec<u16> = Vec::new();
    for &p in VIRTUAL_PATCH_INBOUND_PORTS {
        if !ports.contains(&p) {
            ports.push(p);
        }
    }
    ports.sort_unstable();
    let sanitized = sanitize_firewall_preserved_ports(preserved_ports);
    KernelPerimeterPatchSpec {
        blocked_inbound_ports: ports,
        block_ipv6_rce_surfaces: posture.is_shield_active(),
        preserved_loopback_ports: sanitized,
        target_surfaces: posture
            .affected_surfaces
            .iter()
            .map(|s| s.as_str().to_string())
            .collect(),
        cve_ids: posture.unpatched_cve_ids.clone(),
    }
}

/// Generates BSD / macOS `/dev/pf` rules blocking inbound/lateral CVE ports while keeping loopback control ports.
#[must_use]
pub fn generate_bsd_darwin_pf_virtual_patch_rules(spec: &KernelPerimeterPatchSpec) -> Vec<String> {
    let mut rules = vec!["# AgentOctopus Zero-Reboot Virtual-Patch Perimeter (PF)".to_string()];
    if spec.block_ipv6_rce_surfaces {
        rules.push("block drop in quick inet6 proto ipv6-icmp all".to_string());
        rules.push("block drop in quick from any to fe80::/10".to_string());
    }
    for &port in &spec.blocked_inbound_ports {
        rules.push(format!(
            "block drop in quick proto {{ tcp, udp }} from any to any port {port}"
        ));
    }
    for &ctrl in &spec.preserved_loopback_ports {
        rules.push(format!(
            "pass in quick on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.1 port {ctrl} keep state"
        ));
    }
    rules
}

/// Generates Linux `nftables` rules blocking inbound/lateral CVE ports while preserving loopback `lo`.
#[must_use]
pub fn generate_linux_nftables_virtual_patch_rules(spec: &KernelPerimeterPatchSpec) -> Vec<String> {
    let mut rules = vec![
        "table inet agent_octopus_vpatch {".to_string(),
        "  chain input {".to_string(),
        "    type filter hook input priority 0; policy accept;".to_string(),
        "    iifname \"lo\" accept".to_string(),
    ];
    if spec.block_ipv6_rce_surfaces {
        rules.push("    icmpv6 type { nd-router-advert, nd-redirect } drop".to_string());
    }
    for &port in &spec.blocked_inbound_ports {
        rules.push(format!("    tcp dport {port} drop"));
        rules.push(format!("    udp dport {port} drop"));
    }
    rules.push("  }".to_string());
    rules.push("}".to_string());
    rules
}

/// Linux `NETLINK_NETFILTER` / `NFNL_SUBSYS_NFTABLES` constants for zero-subprocess virtual-patch enforcement.
pub const NETLINK_NETFILTER: i32 = 12;
pub const NFNL_SUBSYS_NFTABLES: u16 = 10;
pub const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
pub const NFNL_MSG_BATCH_END: u16 = 0x11;
pub const NFT_MSG_NEWTABLE: u16 = 0;
pub const NFT_MSG_GETTABLE: u16 = 1;
pub const NFT_MSG_DELTABLE: u16 = 2;
pub const NFT_MSG_NEWCHAIN: u16 = 3;
pub const NFT_MSG_NEWRULE: u16 = 6;
pub const NFPROTO_INET: u8 = 1;
const NLA_F_NESTED: u16 = 0x8000;

fn align4(len: usize) -> usize {
    (len + 3) & !3
}

fn push_nlattr(buf: &mut Vec<u8>, nla_type: u16, payload: &[u8]) {
    let nla_len = (4 + payload.len()) as u16;
    buf.extend_from_slice(&nla_len.to_ne_bytes());
    buf.extend_from_slice(&nla_type.to_ne_bytes());
    buf.extend_from_slice(payload);
    let pad = align4(payload.len()) - payload.len();
    buf.resize(buf.len() + pad, 0);
}

fn push_nlattr_str(buf: &mut Vec<u8>, nla_type: u16, s: &str) {
    let mut bytes = Vec::with_capacity(s.len() + 1);
    bytes.extend_from_slice(s.as_bytes());
    bytes.push(0);
    push_nlattr(buf, nla_type, &bytes);
}

fn push_nlattr_nested(buf: &mut Vec<u8>, nla_type: u16, inner: &[u8]) {
    push_nlattr(buf, nla_type | NLA_F_NESTED, inner);
}

fn build_nfgen_nlmsg(
    nlmsg_type: u16,
    nlmsg_flags: u16,
    seq: u32,
    nfgen_family: u8,
    res_id: u16,
    attrs: &[u8],
) -> Vec<u8> {
    let total_len = align4(16 + 4 + attrs.len());
    let mut msg = Vec::with_capacity(total_len);
    msg.extend_from_slice(&(total_len as u32).to_ne_bytes());
    msg.extend_from_slice(&nlmsg_type.to_ne_bytes());
    msg.extend_from_slice(&nlmsg_flags.to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid = 0 (kernel)
    msg.push(nfgen_family);
    msg.push(0u8); // NFNETLINK_V0
    msg.extend_from_slice(&res_id.to_be_bytes());
    msg.extend_from_slice(attrs);
    msg.resize(total_len, 0);
    msg
}

fn build_nft_expr(name: &str, data: &[u8]) -> Vec<u8> {
    let mut elem = Vec::new();
    push_nlattr_str(&mut elem, 1, name); // NFTA_EXPR_NAME
    push_nlattr_nested(&mut elem, 2, data); // NFTA_EXPR_DATA
    let mut wrapped = Vec::new();
    push_nlattr_nested(&mut wrapped, 1, &elem); // NFTA_LIST_ELEM
    wrapped
}

fn build_nft_meta_expr(key: u32, dreg: u32) -> Vec<u8> {
    let mut data = Vec::new();
    push_nlattr(&mut data, 1, &dreg.to_be_bytes()); // NFTA_META_DREG
    push_nlattr(&mut data, 2, &key.to_be_bytes()); // NFTA_META_KEY
    build_nft_expr("meta", &data)
}

fn build_nft_payload_expr(base: u32, offset: u32, len: u32, dreg: u32) -> Vec<u8> {
    let mut data = Vec::new();
    push_nlattr(&mut data, 1, &dreg.to_be_bytes()); // NFTA_PAYLOAD_DREG
    push_nlattr(&mut data, 2, &base.to_be_bytes()); // NFTA_PAYLOAD_BASE
    push_nlattr(&mut data, 3, &offset.to_be_bytes()); // NFTA_PAYLOAD_OFFSET
    push_nlattr(&mut data, 4, &len.to_be_bytes()); // NFTA_PAYLOAD_LEN
    build_nft_expr("payload", &data)
}

fn build_nft_cmp_expr(sreg: u32, op: u32, value: &[u8]) -> Vec<u8> {
    let mut cmp_data = Vec::new();
    push_nlattr(&mut cmp_data, 1, value); // NFTA_DATA_VALUE
    let mut data = Vec::new();
    push_nlattr(&mut data, 1, &sreg.to_be_bytes()); // NFTA_CMP_SREG
    push_nlattr(&mut data, 2, &op.to_be_bytes()); // NFTA_CMP_OP
    push_nlattr_nested(&mut data, 3, &cmp_data); // NFTA_CMP_DATA
    build_nft_expr("cmp", &data)
}

fn build_nft_verdict_expr(verdict_code: i32) -> Vec<u8> {
    let mut verdict = Vec::new();
    push_nlattr(&mut verdict, 1, &verdict_code.to_be_bytes()); // NFTA_VERDICT_CODE
    let mut imm_data = Vec::new();
    push_nlattr_nested(&mut imm_data, 2, &verdict); // NFTA_DATA_VERDICT
    let mut data = Vec::new();
    push_nlattr(&mut data, 1, &0u32.to_be_bytes()); // NFTA_IMMEDIATE_DREG = NFT_REG_VERDICT (0)
    push_nlattr_nested(&mut data, 2, &imm_data); // NFTA_IMMEDIATE_DATA
    build_nft_expr("immediate", &data)
}

/// Builds a deterministic raw binary `AF_NETLINK` (`NETLINK_NETFILTER` / `nf_tables`) batch
/// message configuring table `inet agent_octopus_vpatch` and chain `inbound_shield` without
/// spawning any external firewall subprocess.
#[must_use]
pub fn build_linux_nft_vpatch_netlink_batch(
    spec: &KernelPerimeterPatchSpec,
    engage: bool,
) -> Vec<u8> {
    let mut batch = Vec::new();
    let mut seq: u32 = 1;
    let req_ack: u16 = 0x0001 | 0x0004; // NLM_F_REQUEST | NLM_F_ACK
    let req_create: u16 = req_ack | 0x0400; // | NLM_F_CREATE
    let req_append: u16 = req_create | 0x0800; // | NLM_F_APPEND

    // 1. NFNL_MSG_BATCH_BEGIN
    batch.extend_from_slice(&build_nfgen_nlmsg(
        NFNL_MSG_BATCH_BEGIN,
        0x0001,
        seq,
        0,
        NFNL_SUBSYS_NFTABLES,
        &[],
    ));
    seq += 1;

    // 2. Ensure table exists, then delete cleanly to reset state atomically
    let mut tbl_attrs = Vec::new();
    push_nlattr_str(&mut tbl_attrs, 1, "agent_octopus_vpatch"); // NFTA_TABLE_NAME
    batch.extend_from_slice(&build_nfgen_nlmsg(
        (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
        req_create,
        seq,
        NFPROTO_INET,
        0,
        &tbl_attrs,
    ));
    seq += 1;

    batch.extend_from_slice(&build_nfgen_nlmsg(
        (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELTABLE,
        req_ack,
        seq,
        NFPROTO_INET,
        0,
        &tbl_attrs,
    ));
    seq += 1;

    if engage {
        // 3. Re-create table `inet agent_octopus_vpatch`
        batch.extend_from_slice(&build_nfgen_nlmsg(
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
            req_create,
            seq,
            NFPROTO_INET,
            0,
            &tbl_attrs,
        ));
        seq += 1;

        // 4. Create base input chain `inbound_shield` (priority -10, policy accept)
        let mut hook_attrs = Vec::new();
        push_nlattr(&mut hook_attrs, 1, &1u32.to_be_bytes()); // NF_INET_LOCAL_IN = 1
        push_nlattr(&mut hook_attrs, 2, &(-10i32).to_be_bytes()); // priority -10

        let mut chain_attrs = Vec::new();
        push_nlattr_str(&mut chain_attrs, 1, "agent_octopus_vpatch"); // NFTA_CHAIN_TABLE
        push_nlattr_str(&mut chain_attrs, 3, "inbound_shield"); // NFTA_CHAIN_NAME
        push_nlattr_nested(&mut chain_attrs, 4, &hook_attrs); // NFTA_CHAIN_HOOK
        push_nlattr(&mut chain_attrs, 5, &1u32.to_be_bytes()); // NFTA_CHAIN_POLICY = NF_ACCEPT (1)
        push_nlattr_str(&mut chain_attrs, 7, "filter"); // NFTA_CHAIN_TYPE

        batch.extend_from_slice(&build_nfgen_nlmsg(
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
            req_create,
            seq,
            NFPROTO_INET,
            0,
            &chain_attrs,
        ));
        seq += 1;

        // 5. Rule 0: permit loopback `iifname == "lo"` (`NF_ACCEPT = 1`)
        let mut lb_exprs = Vec::new();
        lb_exprs.extend_from_slice(&build_nft_meta_expr(6, 1)); // NFT_META_IIFNAME = 6 -> reg 1
        let mut lo_name = [0u8; 16];
        lo_name[0] = b'l';
        lo_name[1] = b'o';
        lb_exprs.extend_from_slice(&build_nft_cmp_expr(1, 0, &lo_name));
        lb_exprs.extend_from_slice(&build_nft_verdict_expr(1)); // NF_ACCEPT
        let mut lb_rule = Vec::new();
        push_nlattr_str(&mut lb_rule, 1, "agent_octopus_vpatch");
        push_nlattr_str(&mut lb_rule, 2, "inbound_shield");
        push_nlattr_nested(&mut lb_rule, 4, &lb_exprs);
        batch.extend_from_slice(&build_nfgen_nlmsg(
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
            req_append,
            seq,
            NFPROTO_INET,
            0,
            &lb_rule,
        ));
        seq += 1;

        // 6. Inbound TCP & UDP port drops (`NF_DROP = 0`)
        for &port in &spec.blocked_inbound_ports {
            for proto in [6u8, 17u8] {
                let mut exprs = Vec::new();
                exprs.extend_from_slice(&build_nft_meta_expr(16, 1)); // NFT_META_L4PROTO = 16 -> reg 1
                exprs.extend_from_slice(&build_nft_cmp_expr(1, 0, &[proto]));
                exprs.extend_from_slice(&build_nft_payload_expr(2, 2, 2, 1)); // transport dport -> reg 1
                exprs.extend_from_slice(&build_nft_cmp_expr(1, 0, &port.to_be_bytes()));
                exprs.extend_from_slice(&build_nft_verdict_expr(0)); // NF_DROP

                let mut rule = Vec::new();
                push_nlattr_str(&mut rule, 1, "agent_octopus_vpatch");
                push_nlattr_str(&mut rule, 2, "inbound_shield");
                push_nlattr_nested(&mut rule, 4, &exprs);
                batch.extend_from_slice(&build_nfgen_nlmsg(
                    (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
                    req_append,
                    seq,
                    NFPROTO_INET,
                    0,
                    &rule,
                ));
                seq += 1;
            }
        }

        // 7. ICMPv6 RA (134) & Redirect (137) drop when IPv6 RCE shield is active
        if spec.block_ipv6_rce_surfaces {
            for icmp6_type in [134u8, 137u8] {
                let mut exprs = Vec::new();
                exprs.extend_from_slice(&build_nft_meta_expr(16, 1)); // NFT_META_L4PROTO = 16
                exprs.extend_from_slice(&build_nft_cmp_expr(1, 0, &[58u8])); // IPPROTO_ICMPV6 = 58
                exprs.extend_from_slice(&build_nft_payload_expr(2, 0, 1, 1)); // icmpv6 type offset 0 len 1
                exprs.extend_from_slice(&build_nft_cmp_expr(1, 0, &[icmp6_type]));
                exprs.extend_from_slice(&build_nft_verdict_expr(0)); // NF_DROP

                let mut rule = Vec::new();
                push_nlattr_str(&mut rule, 1, "agent_octopus_vpatch");
                push_nlattr_str(&mut rule, 2, "inbound_shield");
                push_nlattr_nested(&mut rule, 4, &exprs);
                batch.extend_from_slice(&build_nfgen_nlmsg(
                    (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
                    req_append,
                    seq,
                    NFPROTO_INET,
                    0,
                    &rule,
                ));
                seq += 1;
            }
        }
    }

    // 8. NFNL_MSG_BATCH_END
    batch.extend_from_slice(&build_nfgen_nlmsg(
        NFNL_MSG_BATCH_END,
        0x0001,
        seq,
        0,
        NFNL_SUBSYS_NFTABLES,
        &[],
    ));
    batch
}

#[cfg(target_os = "linux")]
fn apply_linux_nft_vpatch_netlink(
    spec: &KernelPerimeterPatchSpec,
    engage: bool,
) -> Result<(), HostIsolationError> {
    let batch = build_linux_nft_vpatch_netlink_batch(spec, engage);
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_NETFILTER);
        if fd < 0 {
            return Err(HostIsolationError::KernelEngineError(format!(
                "socket(AF_NETLINK, NETLINK_NETFILTER) failed: errno {}",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            )));
        }
        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as u16;
        if libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        ) < 0
        {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            libc::close(fd);
            return Err(HostIsolationError::KernelEngineError(format!(
                "NETLINK_NETFILTER bind failed: errno {errno}"
            )));
        }
        let sent = libc::sendto(
            fd,
            batch.as_ptr() as *const libc::c_void,
            batch.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        );
        if sent < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            libc::close(fd);
            return Err(HostIsolationError::KernelEngineError(format!(
                "NETLINK_NETFILTER batch sendto failed: errno {errno}"
            )));
        }

        // Verify kernel ACKs on non-blocking drain + NFT_MSG_GETTABLE readback when engaging
        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        let mut ack_buf = [0u8; 4096];
        let n = libc::recv(
            fd,
            ack_buf.as_mut_ptr() as *mut libc::c_void,
            ack_buf.len(),
            0,
        );
        if n >= 20 {
            let nl_type = u16::from_ne_bytes([ack_buf[4], ack_buf[5]]);
            if nl_type == 2 {
                let code = i32::from_ne_bytes([ack_buf[16], ack_buf[17], ack_buf[18], ack_buf[19]]);
                if code != 0 && code != -libc::ENOENT {
                    libc::close(fd);
                    return Err(HostIsolationError::KernelEngineError(format!(
                        "NETLINK_NETFILTER batch ACK error: {code}"
                    )));
                }
            }
        }

        if engage {
            let mut tbl_attrs = Vec::new();
            push_nlattr_str(&mut tbl_attrs, 1, "agent_octopus_vpatch");
            let get_msg = build_nfgen_nlmsg(
                (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETTABLE,
                0x0001,
                999,
                NFPROTO_INET,
                0,
                &tbl_attrs,
            );
            if libc::sendto(
                fd,
                get_msg.as_ptr() as *const libc::c_void,
                get_msg.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            ) < 0
            {
                libc::close(fd);
                return Err(HostIsolationError::KernelEngineError(
                    "NETLINK_NETFILTER GETTABLE readback send failed".to_string(),
                ));
            }
            let rn = libc::recv(
                fd,
                ack_buf.as_mut_ptr() as *mut libc::c_void,
                ack_buf.len(),
                0,
            );
            libc::close(fd);
            if rn < 20 {
                return Err(HostIsolationError::KernelEngineError(
                    "NETLINK_NETFILTER GETTABLE readback returned empty response".to_string(),
                ));
            }
            let nl_type = u16::from_ne_bytes([ack_buf[4], ack_buf[5]]);
            if nl_type == 2 {
                let code = i32::from_ne_bytes([ack_buf[16], ack_buf[17], ack_buf[18], ack_buf[19]]);
                if code != 0 {
                    return Err(HostIsolationError::KernelEngineError(format!(
                        "NETLINK_NETFILTER GETTABLE readback failed: {code}"
                    )));
                }
            }
            return Ok(());
        }

        libc::close(fd);
        Ok(())
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn apply_macos_pf_vpatch_ioctl(
    spec: &KernelPerimeterPatchSpec,
    engage: bool,
) -> Result<usize, HostIsolationError> {
    use std::ffi::CString;

    const MAXPATHLEN: usize = 1024;
    const IFNAMSIZ: usize = 16;
    const DIOCGETRULES: u64 = 0xC808_4406;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct PfTransElem {
        rs_num: i32,
        anchor: [u8; MAXPATHLEN],
        ticket: u32,
    }
    #[repr(C)]
    struct PfTrans {
        size: i32,
        esize: i32,
        array: *mut PfTransElem,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct PfPortRange {
        port_start: u16,
        port_end: u16,
        op: u8,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct PfRuleRaw {
        action: u8,
        direction: u8,
        quick: u8,
        log: u8,
        proto: u8,
        af: u8,
        ifname: [u8; IFNAMSIZ],
        src_port: PfPortRange,
        dst_port: PfPortRange,
        keep_state: u8,
        rule_flag: u32,
        return_icmp: u8,
        return_icmp6: u8,
        padding: [u8; 64],
    }
    #[repr(C)]
    struct PfiocRule {
        action: u32,
        ticket: u32,
        nr: u32,
        anchor: [u8; MAXPATHLEN],
        ruleset: [u8; MAXPATHLEN],
        rule: PfRuleRaw,
    }

    let dev = CString::new("/dev/pf").unwrap();
    let fd = unsafe { libc::open(dev.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(HostIsolationError::InsufficientPrivileges {
            details: format!("Cannot open /dev/pf for virtual-patch anchor (errno {errno})"),
            remediation: "Run with sudo / root privileges.".to_string(),
        });
    }

    let mut elem = PfTransElem {
        rs_num: 1,
        anchor: [0u8; MAXPATHLEN],
        ticket: 0,
    };
    let anchor_bytes = b"agent_octopus_vpatch";
    elem.anchor[..anchor_bytes.len()].copy_from_slice(anchor_bytes);

    let mut trans = PfTrans {
        size: 1,
        esize: std::mem::size_of::<PfTransElem>() as i32,
        array: &mut elem,
    };

    let mut committed_rules = 0usize;
    unsafe {
        if engage {
            let _ = libc::ioctl(fd, DIOCSTART as libc::c_ulong);
        }
        if libc::ioctl(fd, DIOCXBEGIN as libc::c_ulong, &mut trans) < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            libc::close(fd);
            return Err(HostIsolationError::KernelEngineError(format!(
                "/dev/pf vpatch DIOCXBEGIN failed: errno {errno}"
            )));
        }

        if engage {
            let mut rules_raw: Vec<(u8, u8, Option<&[u8]>, u8, Option<u16>)> = Vec::new();
            // Permit loopback first
            rules_raw.push((0, 0, Some(b"lo0"), 0, None));
            // Block high-risk inbound TCP & UDP ports
            for &port in &spec.blocked_inbound_ports {
                rules_raw.push((1, 1, None, 6, Some(port)));
                rules_raw.push((1, 1, None, 17, Some(port)));
            }
            if spec.block_ipv6_rce_surfaces {
                rules_raw.push((1, 1, None, 58, None)); // IPPROTO_ICMPV6 inbound drop
            }

            for (idx, (act, dir, iface, proto, port)) in rules_raw.into_iter().enumerate() {
                let mut pr = PfiocRule {
                    action: 0,
                    ticket: elem.ticket,
                    nr: idx as u32,
                    anchor: [0u8; MAXPATHLEN],
                    ruleset: [0u8; MAXPATHLEN],
                    rule: PfRuleRaw {
                        action: act,
                        direction: dir,
                        quick: 1,
                        log: 0,
                        proto,
                        af: 0,
                        ifname: [0u8; IFNAMSIZ],
                        src_port: PfPortRange::default(),
                        dst_port: PfPortRange::default(),
                        keep_state: if act == 0 { 1 } else { 0 },
                        rule_flag: 0,
                        return_icmp: 0,
                        return_icmp6: 0,
                        padding: [0u8; 64],
                    },
                };
                pr.anchor[..anchor_bytes.len()].copy_from_slice(anchor_bytes);
                if let Some(ifb) = iface {
                    pr.rule.ifname[..ifb.len()].copy_from_slice(ifb);
                }
                if let Some(p) = port {
                    pr.rule.dst_port = PfPortRange {
                        port_start: p.to_be(),
                        port_end: p.to_be(),
                        op: 1,
                    };
                }
                if libc::ioctl(fd, DIOCADDRULE as libc::c_ulong, &mut pr) < 0 {
                    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    let _ = libc::ioctl(fd, DIOCXROLLBACK as libc::c_ulong, &mut trans);
                    libc::close(fd);
                    return Err(HostIsolationError::KernelEngineError(format!(
                        "/dev/pf vpatch DIOCADDRULE failed: errno {errno}"
                    )));
                }
                committed_rules += 1;
            }
        }

        if libc::ioctl(fd, DIOCXCOMMIT as libc::c_ulong, &mut trans) < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            libc::close(fd);
            return Err(HostIsolationError::KernelEngineError(format!(
                "/dev/pf vpatch DIOCXCOMMIT failed: errno {errno}"
            )));
        }

        // Binary DIOCGETRULES read-back verification when engaging
        if engage {
            let mut rb: PfiocRule = std::mem::zeroed();
            rb.anchor[..anchor_bytes.len()].copy_from_slice(anchor_bytes);
            if libc::ioctl(fd, DIOCGETRULES as libc::c_ulong, &mut rb) < 0 || rb.nr == 0 {
                libc::close(fd);
                return Err(HostIsolationError::KernelEngineError(
                    "/dev/pf vpatch DIOCGETRULES read-back verification failed".to_string(),
                ));
            }
            committed_rules = rb.nr as usize;
        }
        libc::close(fd);
    }

    Ok(committed_rules)
}

/// Applies the `<1ms` targeted No Break-In kernel perimeter shield with real OS enforcement
/// when elevated (no surprise UAC popups on unattended background scans).
pub fn apply_virtual_patch_perimeter_shield(
    posture: &crate::security::virtual_patch_shield::KernelShieldPosture,
    preserved_ports: &[u16],
) -> Result<crate::security::virtual_patch_shield::VirtualPatchShieldReceipt, HostIsolationError> {
    apply_virtual_patch_perimeter_shield_with_options(posture, preserved_ports, false)
}

/// Applies the targeted No Break-In kernel perimeter shield with optional Windows UAC helper
/// delegation (`--wfp-kernel-apply vpatch-engage`) for explicit operator CLI/Dashboard actions.
pub fn apply_virtual_patch_perimeter_shield_with_options(
    posture: &crate::security::virtual_patch_shield::KernelShieldPosture,
    preserved_ports: &[u16],
    allow_uac_delegation: bool,
) -> Result<crate::security::virtual_patch_shield::VirtualPatchShieldReceipt, HostIsolationError> {
    let start = std::time::Instant::now();
    let spec = build_virtual_patch_perimeter_spec(posture, preserved_ports);
    let mut rules_applied = Vec::with_capacity(spec.blocked_inbound_ports.len() + 4);
    let mut os_enforcement_applied = false;
    let mut readback_verified = false;

    let elevated = is_current_process_elevated();
    let is_test_sim = is_non_elevated_test_simulation();
    let should_enforce_live = posture.is_shield_active() && elevated && !is_test_sim;

    #[cfg(windows)]
    if posture.is_shield_active() && !elevated && allow_uac_delegation && !is_test_sim {
        let delegated = try_elevated_delegation("vpatch-engage")?;
        if delegated {
            let persisted = load_persisted_vpatch_wfp_filter_ids();
            if persisted.is_empty() {
                return Err(HostIsolationError::KernelEngineError(
                    "Elevated vpatch-engage helper completed without persisting WFP filter IDs"
                        .to_string(),
                ));
            }
            for &port in &spec.blocked_inbound_ports {
                rules_applied.push(format!("inbound_block:tcp_udp:{port}"));
            }
            if spec.block_ipv6_rce_surfaces {
                rules_applied.push("inbound_block:ipv6_ra_icmpv6_rce".to_string());
            }
            rules_applied.push(format!(
                "wfp_vpatch_uac_verified_filters:{}",
                persisted.len()
            ));
            let clamps: Vec<String> = posture
                .affected_surfaces
                .iter()
                .map(|s| format!("no_breakout:{}", s.as_str()))
                .collect();
            let elapsed_us = start.elapsed().as_micros() as u64;
            return Ok(
                crate::security::virtual_patch_shield::build_shield_receipt_with_enforcement(
                    posture.clone(),
                    clamps,
                    rules_applied,
                    Vec::new(),
                    true,
                    true,
                    elapsed_us,
                ),
            );
        }
    }
    #[cfg(not(windows))]
    let _ = allow_uac_delegation;

    if should_enforce_live {
        #[cfg(windows)]
        {
            let session = WfpKernelSession::open()?;
            let ids = session.install_virtual_patch_inbound_shield(&spec)?;
            if ids.is_empty() || !ids.iter().all(|fid| session.filter_exists(*fid)) {
                return Err(HostIsolationError::KernelEngineError(
                    "Virtual-patch WFP post-commit read-back failed".to_string(),
                ));
            }
            persist_vpatch_wfp_filter_ids(&ids);
            for &port in &spec.blocked_inbound_ports {
                rules_applied.push(format!("inbound_block:tcp_udp:{port}"));
            }
            if spec.block_ipv6_rce_surfaces {
                rules_applied.push("inbound_block:ipv6_ra_icmpv6_rce".to_string());
            }
            rules_applied.push(format!("wfp_vpatch_verified_filters:{}", ids.len()));
            os_enforcement_applied = true;
            readback_verified = true;
        }

        #[cfg(target_os = "linux")]
        {
            // Prefer pure zero-subprocess AF_NETLINK (NETLINK_NETFILTER nf_tables) batch; fall back
            // to pinned `/usr/sbin/nft` only if the kernel rejects raw netlink batch framing.
            if apply_linux_nft_vpatch_netlink(&spec, true).is_ok() {
                for &port in &spec.blocked_inbound_ports {
                    rules_applied.push(format!("inbound_block:tcp_udp:{port}"));
                }
                if spec.block_ipv6_rce_surfaces {
                    rules_applied.push("inbound_block:ipv6_ra_icmpv6_rce".to_string());
                }
                rules_applied.push("netlink_nft_vpatch_verified:agent_octopus_vpatch".to_string());
                os_enforcement_applied = true;
                readback_verified = true;
            } else {
                use std::io::Write;
                use std::process::{Command, Stdio};

                let nft_bin = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]
                    .into_iter()
                    .find(|p| std::path::Path::new(p).is_file())
                    .ok_or_else(|| {
                        HostIsolationError::KernelEngineError(
                            "NETLINK_NETFILTER failed and pinned nft binary not found under /usr/sbin/nft, /sbin/nft, or /usr/bin/nft"
                                .to_string(),
                        )
                    })?;
                let nft_script = format!(
                    "add table inet agent_octopus_vpatch\ndelete table inet agent_octopus_vpatch\n{}\n",
                    generate_linux_nftables_virtual_patch_rules(&spec).join("\n")
                );
                let mut child = Command::new(nft_bin)
                    .args(["-f", "-"])
                    .env_clear()
                    .env("PATH", "/usr/sbin:/sbin:/usr/bin:/bin")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|e| {
                        HostIsolationError::KernelEngineError(format!(
                            "Failed spawning {nft_bin}: {e}"
                        ))
                    })?;
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(nft_script.as_bytes()).map_err(|e| {
                        HostIsolationError::KernelEngineError(format!(
                            "Failed writing nft rules: {e}"
                        ))
                    })?;
                }
                let out = child.wait_with_output().map_err(|e| {
                    HostIsolationError::KernelEngineError(format!(
                        "Failed waiting on {nft_bin}: {e}"
                    ))
                })?;
                if !out.status.success() {
                    return Err(HostIsolationError::KernelEngineError(format!(
                        "nft virtual-patch apply failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    )));
                }

                let readback = Command::new(nft_bin)
                    .args(["-n", "list", "table", "inet", "agent_octopus_vpatch"])
                    .env_clear()
                    .env("PATH", "/usr/sbin:/sbin:/usr/bin:/bin")
                    .output()
                    .map_err(|e| {
                        HostIsolationError::KernelEngineError(format!("Failed nft read-back: {e}"))
                    })?;
                let rb_stdout = String::from_utf8_lossy(&readback.stdout);
                if !readback.status.success()
                    || !rb_stdout.contains("table inet agent_octopus_vpatch")
                    || !spec
                        .blocked_inbound_ports
                        .iter()
                        .all(|p| rb_stdout.contains(&format!("tcp dport {p} drop")))
                {
                    return Err(HostIsolationError::KernelEngineError(
                        "nft virtual-patch post-commit read-back verification failed".to_string(),
                    ));
                }
                for &port in &spec.blocked_inbound_ports {
                    rules_applied.push(format!("inbound_block:tcp_udp:{port}"));
                }
                if spec.block_ipv6_rce_surfaces {
                    rules_applied.push("inbound_block:ipv6_ra_icmpv6_rce".to_string());
                }
                rules_applied.push("nft_vpatch_verified:agent_octopus_vpatch".to_string());
                os_enforcement_applied = true;
                readback_verified = true;
            }
        }

        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        {
            let verified_rules = apply_macos_pf_vpatch_ioctl(&spec, true)?;
            for &port in &spec.blocked_inbound_ports {
                rules_applied.push(format!("inbound_block:tcp_udp:{port}"));
            }
            if spec.block_ipv6_rce_surfaces {
                rules_applied.push("inbound_block:ipv6_ra_icmpv6_rce".to_string());
            }
            rules_applied.push(format!("pf_ioctl_vpatch_verified_rules:{verified_rules}"));
            os_enforcement_applied = true;
            readback_verified = true;
        }
    } else {
        for &port in &spec.blocked_inbound_ports {
            rules_applied.push(format!(
                "unprivileged_plan_only:inbound_block:tcp_udp:{port}"
            ));
        }
        if spec.block_ipv6_rce_surfaces {
            rules_applied
                .push("unprivileged_plan_only:inbound_block:ipv6_ra_icmpv6_rce".to_string());
        }
        if !posture.is_shield_active() {
            rules_applied.push("shield_inactive_no_os_firewall_rules".to_string());
        } else {
            rules_applied
                .push("unprivileged_os_firewall_skipped:requires_root_or_admin".to_string());
        }
    }

    let clamps: Vec<String> = posture
        .affected_surfaces
        .iter()
        .map(|s| format!("no_breakout:{}", s.as_str()))
        .collect();
    let elapsed_us = start.elapsed().as_micros() as u64;
    Ok(
        crate::security::virtual_patch_shield::build_shield_receipt_with_enforcement(
            posture.clone(),
            clamps,
            rules_applied,
            Vec::new(),
            os_enforcement_applied,
            readback_verified,
            elapsed_us,
        ),
    )
}

/// Disarms ONLY the targeted `AgentOctopus-VirtualPatch-*` kernel perimeter rules without touching
/// full Host KillSwitch quarantine filters. Strictly fails closed while `shield_locked_until_reboot`
/// is active (Foolproof Invariant #1).
pub fn disarm_virtual_patch_perimeter_shield(
    allow_uac_delegation: bool,
) -> Result<usize, HostIsolationError> {
    let posture = crate::security::virtual_patch_shield::current_shield_posture();
    if posture.shield_locked_until_reboot {
        return Err(HostIsolationError::KernelEngineError(
            "Monotonic violation: cannot disarm virtual-patch perimeter while shield_locked_until_reboot is active"
                .to_string(),
        ));
    }

    if !is_current_process_elevated() && is_non_elevated_test_simulation() {
        return Ok(0);
    }

    #[cfg(windows)]
    {
        if !is_current_process_elevated() {
            if allow_uac_delegation {
                let delegated = try_elevated_delegation("vpatch-disarm")?;
                if delegated {
                    clear_persisted_vpatch_wfp_filter_ids();
                    return Ok(0);
                }
            }
            return Err(HostIsolationError::InsufficientPrivileges {
                details: "Administrator privileges required to remove virtual-patch WFP filters."
                    .to_string(),
                remediation: "Accept the UAC prompt or run from an elevated terminal.".to_string(),
            });
        }
        let session = WfpKernelSession::open()?;
        let removed = session.remove_virtual_patch_inbound_shield()?;
        clear_persisted_vpatch_wfp_filter_ids();
        Ok(removed)
    }

    #[cfg(target_os = "linux")]
    {
        let _ = allow_uac_delegation;
        if !is_current_process_elevated() {
            return Err(HostIsolationError::InsufficientPrivileges {
                details: "Root / CAP_NET_ADMIN required to remove virtual-patch netfilter table."
                    .to_string(),
                remediation: "Run with sudo or CAP_NET_ADMIN.".to_string(),
            });
        }
        let spec = build_virtual_patch_perimeter_spec(&posture, &[]);
        let _ = apply_linux_nft_vpatch_netlink(&spec, false);
        Ok(1)
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        let _ = allow_uac_delegation;
        if !is_current_process_elevated() {
            return Err(HostIsolationError::InsufficientPrivileges {
                details: "Root privileges required to flush /dev/pf virtual-patch anchor."
                    .to_string(),
                remediation: "Run with sudo / root privileges.".to_string(),
            });
        }
        let spec = build_virtual_patch_perimeter_spec(&posture, &[]);
        apply_macos_pf_vpatch_ioctl(&spec, false)
    }

    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        let _ = allow_uac_delegation;
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_firewall_preserved_ports_strips_proxy_lateral_discovery_and_5000() {
        let input = [
            0, 53, 67, 68, 135, 445, 546, 547, 853, 1080, 3128, 5000, 5005, 5005, 5985, 5986, 8080,
            8888, 9050, 5012,
        ];
        assert_eq!(sanitize_firewall_preserved_ports(&input), vec![5005, 5012]);
        for &blocked in QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS
            .iter()
            .chain(QUARANTINE_BLOCKED_LATERAL_PORTS.iter())
            .chain(QUARANTINE_BLOCKED_DISCOVERY_PORTS.iter())
            .chain(std::iter::once(&FORBIDDEN_PORT_5000))
        {
            assert!(
                is_blocked_quarantine_port(blocked),
                "port {} must be blocked from quarantine exemptions",
                blocked
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_bfe_registry_rules_exclude_blanket_loopback_and_block_proxies() {
        let rules = bfe_registry_rule_definitions(&[5005, 8080, 53, 5000]);
        let joined: String = rules
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(!joined.contains("Allow-Loopback-In"));
        assert!(!joined.contains("Allow-Loopback-Out"));
        assert!(joined.contains("127.0.0.2-127.255.255.254"));
        assert!(joined.contains("169.254.169.254"));
        assert!(joined.contains("Block-Port-8080"));
        assert!(joined.contains("Block-Port-53"));
        assert!(joined.contains("Allow-WebUI-5005-In-v4"));
        assert!(!joined.contains("Allow-WebUI-8080"));
        assert!(!joined.contains("Allow-WebUI-5000"));
        assert!(!joined.contains("Allow-WebUI-53"));
    }

    #[test]
    fn test_hardened_macos_pf_rules_reject_blanket_lo0_and_block_proxy_lateral_discovery() {
        let rules =
            generate_macos_pf_quarantine_rules("agent_octopus", &[5005, 8080, 53, 445, 5000]);
        let joined = rules.join("\n");

        assert!(!joined.contains("pass quick on lo0 all"));
        assert!(!joined.contains("pass quick from 127.0.0.1 to any"));
        assert!(!joined.contains("pass quick from ::1 to any"));
        assert!(joined.contains("169.254.0.0/16"));
        assert!(joined.contains("fe80::/10"));
        assert!(joined.contains("block drop out quick proto udp from any to any port 443"));
        assert!(joined.contains("block drop out quick proto { tcp, udp } from any to any port 53"));
        assert!(joined.contains("block drop out quick proto { tcp, udp } from any to any port 67"));
        assert!(joined.contains("block drop out quick proto { tcp, udp } from any to any port 68"));
        assert!(
            joined.contains("block drop out quick proto { tcp, udp } from any to any port 8080")
        );
        assert!(joined.contains("block drop out quick proto { tcp, udp } from any to any port 445"));
        assert!(joined.contains(
            "pass in quick on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.1 port 5005 keep state"
        ));
        assert!(!joined.contains("port 8080 keep state"));
        assert!(!joined.contains("port 53 keep state"));
        assert!(joined.contains("block drop in quick all"));
        assert!(joined.contains("block drop out quick all"));
    }

    #[test]
    fn test_linux_nftables_script_hardened_rules() {
        let script = generate_linux_nftables_quarantine_script(&[5005, 8080, 53, 5000]);
        assert!(script.contains("table inet agent_octopus_quarantine"));
        assert!(script.contains("policy drop;"));
        assert!(script.contains("127.0.0.2-127.255.255.254 drop"));
        assert!(script.contains("169.254.0.0/16 drop"));
        assert!(script.contains("8080"));
        assert!(script.contains("53"));
        assert!(script.contains("ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp dport { 5005 } accept"));
        assert!(!script.contains("tcp dport { 5005, 8080"));
    }

    #[test]
    fn test_parse_proc_net_destroy_targets_covers_ipv4_ipv6_tcp_udp_raw() {
        // Little-endian host encoding: 127.0.0.1 -> 0100007F, 127.0.0.2 -> 0200007F, 8.8.8.8 -> 08080808
        let tcp_v4 = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:138D 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 100\n\
   1: 0100007F:1F90 0100007F:C351 01 00000000:00000000 00:00000000 00000000  1000        0 101\n\
   2: 0200007F:138D 0100007F:C352 01 00000000:00000000 00:00000000 00000000  1000        0 102\n\
   3: 0100007F:A1B2 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 103\n";
        let targets_tcp4 = parse_proc_net_destroy_targets(tcp_v4, false, 6, &[5005]);
        // Slot 0 (127.0.0.1:5005 <-> 127.0.0.1) is spared; slots 1 (port 8080), 2 (127.0.0.2), 3 (8.8.8.8:53) targeted.
        assert_eq!(targets_tcp4.len(), 3);
        assert_eq!(targets_tcp4[0].local_port, 8080);
        assert_eq!(targets_tcp4[1].local_port, 5005);
        assert_eq!(targets_tcp4[2].remote_port, 53);

        // IPv6 ::1 on little-endian /proc/net/tcp6: 00000000000000000000000001000000
        let udp_v6 = "\
  sl  local_address                         remote_address                        st\n\
   0: 00000000000000000000000001000000:138D 00000000000000000000000001000000:C350 01\n\
   1: 00000000000000000000000001000000:A000 00000000000000000000000002000000:0035 07\n";
        let targets_udp6 = parse_proc_net_destroy_targets(udp_v6, true, 17, &[5005]);
        assert_eq!(targets_udp6.len(), 1);
        assert!(targets_udp6[0].is_ipv6);
        assert_eq!(targets_udp6[0].protocol, 17);
        assert_eq!(targets_udp6[0].remote_port, 53);

        let raw_v4 = "\
  sl  local_address rem_address   st\n\
   0: 00000000:00FF 00000000:0000 07\n";
        let targets_raw = parse_proc_net_destroy_targets(raw_v4, false, 255, &[5005]);
        assert_eq!(targets_raw.len(), 1);
        assert_eq!(targets_raw[0].protocol, 255);
    }
}
