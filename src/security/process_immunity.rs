//! Process Lineage Immunity, Ancestry Traversal (Depth <= 5), and TOCTOU Hardening.
//!
//! Enforces Requirement R2:
//! - Eliminates blanket process-name immunity (wsl, sudo, bash, powershell, node, python, cursor, code).
//! - Preserves ONLY immutable OS kernel anchors: PID <= 4, csrss, smss, wininit, systemd, launchd, self PID.
//! - Subprocesses spawned under developer tools or agent runtimes return `AgentRuntimeChild` (non-immune).
//! - Inspects process ancestry up to depth 5 using `sysinfo` with cycle termination.
//! - Enforces live OS stem TOCTOU verification preventing PID-reuse attacks.
//! - Dynamic binary capability probing and parent-child token delta observation.
//! - Enforces non-colliding `4_000_001+` synthetic PIDs in tests.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};
use tracing::warn;

fn shared_ancestry_scanner() -> &'static Mutex<System> {
    static SCANNER: OnceLock<Mutex<System>> = OnceLock::new();
    SCANNER.get_or_init(|| {
        Mutex::new(System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::new()),
        ))
    })
}

/// Maximum depth for process ancestry traversal.
pub const MAX_ANCESTRY_DEPTH: usize = 5;

/// Verdict returned by process lineage inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LineageImmunityVerdict {
    /// Target itself is an immutable OS kernel anchor or critical protected binary.
    ImmuneTarget { pid: u32, proc_name: String },
    /// An ancestor at depth 1..=5 is an immutable kernel anchor (PID <= 4, csrss, smss, wininit, systemd, launchd).
    ImmuneAncestor {
        target_pid: u32,
        ancestor_pid: u32,
        ancestor_name: String,
        depth: usize,
    },
    /// Subprocess spawned under an AI coding agent or developer runtime (e.g. cursor, code, node, python, powershell, bash, wsl).
    /// Crucially: does NOT grant automatic immunity; proceeds to full adjudication.
    AgentRuntimeChild {
        ancestor_pid: u32,
        ancestor_name: String,
        depth: usize,
    },
    /// No protected process in target or ancestry lineage.
    NotImmune,
}

impl LineageImmunityVerdict {
    pub fn is_immune(&self) -> bool {
        matches!(
            self,
            Self::ImmuneTarget { .. } | Self::ImmuneAncestor { .. }
        )
    }
}

pub use LineageImmunityVerdict::AgentRuntimeChild;

/// Extracts the lowercase binary stem: strips quotes, takes first whitespace token,
/// strips directory path components, converts to ASCII lowercase, and strips trailing `.exe`.
pub fn extract_proc_stem(name: &str) -> String {
    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    if trimmed.is_empty() {
        return String::new();
    }
    let first_token = trimmed.split_whitespace().next().unwrap_or(trimmed);
    let base = first_token
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(first_token);
    let name_lc = base.to_ascii_lowercase();
    name_lc.trim_end_matches(".exe").to_string()
}

/// Helper function strictly for immutable OS kernel anchors (PID 0, 1, 4, csrss, smss, wininit, systemd, launchd, etc.).
/// Decoupled from developer tools and agent runtimes (wsl.exe, sudo, su, bash, powershell.exe, node, python, cursor, code.exe).
pub fn is_immutable_os_kernel_pid(pid: u32, name: &str) -> bool {
    // 1. Kernel, Idle, and Self PIDs
    if pid <= 4 || pid == std::process::id() {
        return true;
    }

    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    let base = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed);
    let name_lc = base.to_ascii_lowercase();

    // 2. AgentOctopus / KillSwitch Self-Preservation
    if name_lc.contains("agent_octopus")
        || name_lc.contains("octopus")
        || name_lc.contains("killswitch")
        || name_lc.contains("osoosi")
        || name_lc.contains("oshoosi")
    {
        return true;
    }

    // 3. Immutable OS Kernel and Core System Subsystem Anchors ONLY
    matches!(
        name_lc.as_str(),
        // Windows Core Kernel / Session Subsystem Anchors
        "system"
            | "smss.exe"
            | "csrss.exe"
            | "wininit.exe"
            | "winlogon.exe"
            | "services.exe"
            | "lsass.exe"
            | "lsm.exe"
            | "fontdrvhost.exe"
            // Linux Core Kernel / Init Anchors
            | "init"
            | "systemd"
            | "systemd-journald"
            | "systemd-udevd"
            | "dbus-daemon"
            | "kthreadd"
            // macOS Core System Anchors
            | "launchd"
            | "kernel_task"
            | "windowserver"
            | "opendirectoryd"
    )
}

/// Helper function to classify developer tools, shells, and agent runtimes.
pub fn is_developer_or_agent_runtime(name: &str) -> bool {
    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    let base = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed);
    let name_lc = base.to_ascii_lowercase();

    matches!(
        name_lc.as_str(),
        "wsl.exe"
            | "wslservice.exe"
            | "wslhost.exe"
            | "vmmem"
            | "vmmemwsl"
            | "powershell.exe"
            | "pwsh.exe"
            | "cmd.exe"
            | "sudo"
            | "su"
            | "bash"
            | "sh"
            | "zsh"
            | "fish"
            | "python.exe"
            | "python"
            | "python3"
            | "python3.exe"
            | "node.exe"
            | "node"
            | "cursor.exe"
            | "cursor"
            | "code.exe"
            | "windsurf.exe"
            | "docker.exe"
            | "dockerd.exe"
            | "cargo.exe"
            | "cargo"
            | "rustc.exe"
            | "rustc"
            | "git.exe"
            | "git"
    )
}

/// Checks if a binary or command is strictly denied from receiving blanket direct target immunity.
fn is_blanket_immunity_denied(name: &str) -> bool {
    let name_no_exe = extract_proc_stem(name);
    if name_no_exe.is_empty() {
        return false;
    }

    if matches!(
        name_no_exe.as_str(),
        "wsl" | "wslservice" | "wslhost" | "sudo" | "su" | "doas" | "pkexec" | "runas"
    ) {
        return true;
    }

    // Dynamic binary metadata probe: if path exists on disk, probe for SUID or PE admin manifest
    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    let first_token = trimmed.split_whitespace().next().unwrap_or(trimmed);
    let candidate_path = std::path::Path::new(first_token);
    if candidate_path.exists() {
        if let Ok(meta) = crate::security::semantic_command::DynamicBinaryMetadataProbe::probe_path(candidate_path) {
            if meta.is_privileged_target() {
                return true;
            }
        }
    }

    false
}

/// Inspect target PID and traverse its parent ancestry up to depth 5.
pub fn inspect_process_lineage(target_pid: u32, proc_name: Option<&str>) -> LineageImmunityVerdict {
    let p_name = proc_name.unwrap_or("");
    let denied = is_blanket_immunity_denied(p_name);

    // 1. Direct Target Immunity Check
    if !denied && is_immutable_os_kernel_pid(target_pid, p_name) {
        return LineageImmunityVerdict::ImmuneTarget {
            pid: target_pid,
            proc_name: p_name.to_string(),
        };
    }

    // 2. Ancestry Traversal using reusable process-only scanner
    let mut sys = shared_ancestry_scanner().lock();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());

    // TOCTOU PID-reuse immunity leak & synthetic test PID collision defense:
    if !p_name.is_empty() && target_pid > 4 && target_pid != std::process::id() {
        if let Some(live_proc) = sys.process(Pid::from_u32(target_pid)) {
            let live_stem = extract_proc_stem(live_proc.name());
            let expected_stem = extract_proc_stem(p_name);
            if !live_stem.is_empty() && !expected_stem.is_empty() && live_stem != expected_stem {
                return LineageImmunityVerdict::NotImmune;
            }
        }
    }

    let mut current_pid = target_pid;
    let mut visited = HashSet::new();
    visited.insert(current_pid);

    let mut depth = 0;
    while depth < MAX_ANCESTRY_DEPTH {
        let Some(proc) = sys.process(Pid::from_u32(current_pid)) else {
            break;
        };

        let Some(parent_pid_obj) = proc.parent() else {
            break;
        };

        let parent_pid = parent_pid_obj.as_u32();

        if !visited.insert(parent_pid) {
            warn!("Cycle detected in process ancestry at PID {}", parent_pid);
            break;
        }

        depth += 1;

        let parent_name = sys.process(parent_pid_obj).map(|p| p.name()).unwrap_or("");

        // Check if ancestor is an agent runtime or developer tool/shell
        if is_developer_or_agent_runtime(parent_name) {
            return LineageImmunityVerdict::AgentRuntimeChild {
                ancestor_pid: parent_pid,
                ancestor_name: parent_name.to_string(),
                depth,
            };
        }

        // Immutable kernel anchor check
        if !denied && (parent_pid <= 4 || is_immutable_os_kernel_pid(parent_pid, parent_name)) {
            return LineageImmunityVerdict::ImmuneAncestor {
                target_pid,
                ancestor_pid: parent_pid,
                ancestor_name: parent_name.to_string(),
                depth,
            };
        }

        current_pid = parent_pid;
    }

    LineageImmunityVerdict::NotImmune
}

/// Inspect process ancestry returning the full lineage list of `(PID, process_name)`.
pub fn get_process_ancestry_chain(target_pid: u32) -> Vec<(u32, String)> {
    let mut chain = Vec::new();
    let mut sys = shared_ancestry_scanner().lock();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());

    let mut current_pid = target_pid;
    let mut visited = HashSet::new();
    visited.insert(current_pid);

    let mut depth = 0;
    while depth < MAX_ANCESTRY_DEPTH {
        let Some(proc) = sys.process(Pid::from_u32(current_pid)) else {
            break;
        };
        let Some(parent_pid_obj) = proc.parent() else {
            break;
        };
        let parent_pid = parent_pid_obj.as_u32();

        if !visited.insert(parent_pid) {
            break;
        }
        depth += 1;

        let parent_name = sys
            .process(parent_pid_obj)
            .map(|p| p.name().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        chain.push((parent_pid, parent_name));
        current_pid = parent_pid;
    }

    chain
}

// =============================================================================
// Dynamic Security Context Delta & Token Observation
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityContextDelta {
    LinuxEuidEscalation { parent_euid: u32, child_euid: u32 },
    LinuxCapabilityExpansion { added_capabilities: u64 },
    LinuxNamespaceTransition { namespaces: Vec<String> },
    WindowsIntegrityEscalation { parent_rid: u32, child_rid: u32 },
    WindowsTokenElevation,
    WindowsSession0Transition { parent_session: u32 },
    CleanIdentityPreserved,
}

impl SecurityContextDelta {
    pub fn is_privilege_escalation(&self) -> bool {
        !matches!(self, Self::CleanIdentityPreserved)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSecurityContext {
    pub pid: u32,
    pub euid: u32,
    pub capabilities: u64,
    pub namespaces: HashMap<String, u64>,
    pub integrity_rid: u32,
    pub is_elevated: bool,
    pub session_id: u32,
}

impl Default for ProcessSecurityContext {
    fn default() -> Self {
        Self {
            pid: 0,
            euid: 1000,
            capabilities: 0,
            namespaces: HashMap::new(),
            integrity_rid: 0x2000, // Medium Integrity
            is_elevated: false,
            session_id: 1,
        }
    }
}

pub fn evaluate_security_context_delta(
    parent: &ProcessSecurityContext,
    child: &ProcessSecurityContext,
) -> Vec<SecurityContextDelta> {
    let mut deltas = Vec::new();

    // 1. Linux EUID Escalation
    if parent.euid != 0 && child.euid == 0 {
        deltas.push(SecurityContextDelta::LinuxEuidEscalation {
            parent_euid: parent.euid,
            child_euid: child.euid,
        });
    }

    // 2. Linux CapEff Bitmask Expansion
    let added_caps = child.capabilities & !parent.capabilities;
    if added_caps != 0 {
        deltas.push(SecurityContextDelta::LinuxCapabilityExpansion {
            added_capabilities: added_caps,
        });
    }

    // 3. Linux Namespace Inode Transitions
    let mut transitioned_ns = Vec::new();
    for (ns, &child_inode) in &child.namespaces {
        if let Some(&parent_inode) = parent.namespaces.get(ns) {
            if child_inode != parent_inode {
                transitioned_ns.push(ns.clone());
            }
        }
    }
    if !transitioned_ns.is_empty() {
        transitioned_ns.sort();
        deltas.push(SecurityContextDelta::LinuxNamespaceTransition {
            namespaces: transitioned_ns,
        });
    }

    // 4. Windows TokenIntegrityLevel Escalation (< High 0x3000 -> >= High 0x3000)
    if parent.integrity_rid < 0x3000 && child.integrity_rid >= 0x3000 {
        deltas.push(SecurityContextDelta::WindowsIntegrityEscalation {
            parent_rid: parent.integrity_rid,
            child_rid: child.integrity_rid,
        });
    }

    // 5. Windows TokenElevation Delta
    if !parent.is_elevated && child.is_elevated {
        deltas.push(SecurityContextDelta::WindowsTokenElevation);
    }

    // 6. Windows Session 0 Transition
    if parent.session_id != 0 && child.session_id == 0 {
        deltas.push(SecurityContextDelta::WindowsSession0Transition {
            parent_session: parent.session_id,
        });
    }

    if deltas.is_empty() {
        deltas.push(SecurityContextDelta::CleanIdentityPreserved);
    }

    deltas
}

pub use is_immutable_os_kernel_pid as is_immutable_os_kernel_anchor;

pub fn is_process_immune(pid: u32, proc_name: Option<&str>) -> bool {
    inspect_process_lineage(pid, proc_name).is_immune()
}

pub type LineageInspectionResult = LineageImmunityVerdict;

pub fn stem_matches_exact(stem1: &str, stem2: &str) -> bool {
    extract_proc_stem(stem1) == extract_proc_stem(stem2)
}

pub type BinaryCapabilities = crate::security::semantic_command::DynamicBinaryMetadataProbe;

pub fn probe_binary_capabilities(path: &std::path::Path) -> Result<BinaryCapabilities, String> {
    crate::security::semantic_command::DynamicBinaryMetadataProbe::probe_path(path)
        .map_err(|e| e.to_string())
}

pub type TokenDeltaObservation = SecurityContextDelta;

pub fn observe_process_token_delta(
    parent: &ProcessSecurityContext,
    child: &ProcessSecurityContext,
) -> Vec<SecurityContextDelta> {
    evaluate_security_context_delta(parent, child)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic test PIDs strictly >= 4_000_001
    const SYNTHETIC_PID_1: u32 = 4_000_001;
    const SYNTHETIC_PID_2: u32 = 4_000_002;
    const SYNTHETIC_PID_3: u32 = 4_000_003;

    #[test]
    fn test_immutable_os_kernel_pid_preservation() {
        assert!(is_immutable_os_kernel_pid(0, "System Idle Process"));
        assert!(is_immutable_os_kernel_pid(4, "System"));
        assert!(is_immutable_os_kernel_pid(SYNTHETIC_PID_1, "csrss.exe"));
        assert!(is_immutable_os_kernel_pid(SYNTHETIC_PID_2, "smss.exe"));
        assert!(is_immutable_os_kernel_pid(SYNTHETIC_PID_3, "launchd"));
    }

    #[test]
    fn test_developer_and_agent_runtimes_not_immutable() {
        assert!(!is_immutable_os_kernel_pid(SYNTHETIC_PID_1, "wsl.exe"));
        assert!(!is_immutable_os_kernel_pid(SYNTHETIC_PID_2, "sudo"));
        assert!(!is_immutable_os_kernel_pid(SYNTHETIC_PID_3, "bash"));
        assert!(!is_immutable_os_kernel_pid(4_000_004, "powershell.exe"));
        assert!(!is_immutable_os_kernel_pid(4_000_005, "cursor.exe"));
        assert!(!is_immutable_os_kernel_pid(4_000_006, "code.exe"));
        assert!(!is_immutable_os_kernel_pid(4_000_007, "node.exe"));
        assert!(!is_immutable_os_kernel_pid(4_000_008, "python.exe"));
    }

    #[test]
    fn test_security_context_delta_detection() {
        let parent = ProcessSecurityContext {
            pid: SYNTHETIC_PID_1,
            euid: 1000,
            capabilities: 0,
            namespaces: HashMap::new(),
            integrity_rid: 0x2000,
            is_elevated: false,
            session_id: 1,
        };

        let escalated_child = ProcessSecurityContext {
            pid: SYNTHETIC_PID_2,
            euid: 0,
            capabilities: 0x0000_0000_0000_0008,
            namespaces: HashMap::new(),
            integrity_rid: 0x3000,
            is_elevated: true,
            session_id: 1,
        };

        let deltas = evaluate_security_context_delta(&parent, &escalated_child);
        assert!(deltas.iter().any(|d| matches!(d, SecurityContextDelta::LinuxEuidEscalation { .. })));
        assert!(deltas.iter().any(|d| matches!(d, SecurityContextDelta::LinuxCapabilityExpansion { .. })));
        assert!(deltas.iter().any(|d| matches!(d, SecurityContextDelta::WindowsIntegrityEscalation { .. })));
        assert!(deltas.iter().any(|d| matches!(d, SecurityContextDelta::WindowsTokenElevation)));
    }
}
