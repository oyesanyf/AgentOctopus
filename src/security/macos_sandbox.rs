//! macOS Tier 2 Kernel Confinement Subsystem (`src/security/macos_sandbox.rs`)
//!
//! Provides macOS Seatbelt SBPL (`sandbox-exec`) containment and native `libproc`
//! (`proc_listchildpids`) process-subtree tracking / fixed-point `SIGSTOP` freezing:
//! 1. **Fail-Closed SBPL Profile (`(version 1) (deny default)`)**: Denies filesystem writes,
//!    credential stores, and outbound networking by default while scoping read-only/read-write
//!    paths (handling macOS `/var` -> `/private/var` and `/tmp` -> `/private/tmp` symlinks)
//!    and sanitizing any permitted loopback control ports via `sanitize_firewall_preserved_ports`.
//! 2. **Descendant Process Tree Freezing (`proc_listchildpids`)**: Native `libSystem` FFI
//!    fixed-point child enumeration and atomic `SIGSTOP` / `SIGCONT` / `SIGKILL` enforcement so
//!    forked grandchildren cannot race past containment.
//! 3. **Cross-Architecture CI Compatibility**: All OS FFI and `sandbox-exec` process spawning are
//!    strictly gated under `#[cfg(target_os = "macos")]` while pure SBPL generation and port
//!    sanitization compile and test cleanly on Windows and Linux (`x86_64` / `aarch64`).

use crate::security::host_network_isolation::sanitize_firewall_preserved_ports;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use crate::core::types::OctopusSecurityError;
#[cfg(target_os = "macos")]
use std::collections::{HashSet, VecDeque};
#[cfg(target_os = "macos")]
use std::process::{Child, Command, ExitStatus, Stdio};

/// Configuration for spawning a macOS Seatbelt-confined process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxedMacosConfig {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub read_only_dirs: Vec<PathBuf>,
    pub read_write_dirs: Vec<PathBuf>,
    pub working_dir: Option<PathBuf>,
    pub allow_loopback: bool,
    pub control_ports: Vec<u16>,
}

/// Handle representing a spawned macOS Seatbelt-confined child process tree.
#[derive(Debug)]
pub struct SandboxedMacosProcess {
    pub root_pid: u32,
    pub backend: String,
    pub sbpl_profile: String,
    pub control_ports: Vec<u16>,
    #[cfg(target_os = "macos")]
    child: Option<Child>,
}

/// Escapes backslashes and double quotes for safe embedding inside SBPL string literals.
pub fn escape_sbpl_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let mut escaped = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Pushes a path and (if resolvable) its canonicalized symlink target without duplicates.
///
/// macOS maps `/tmp` -> `/private/tmp` and `/var` -> `/private/var`, so Seatbelt profiles
/// must permit both forms for declared read-only/scratchpad directories.
pub fn push_sbpl_path_variants(out: &mut Vec<PathBuf>, path: &Path) {
    let candidate = path.to_path_buf();
    if !out.contains(&candidate) {
        out.push(candidate);
    }
    if let Ok(canon) = std::fs::canonicalize(path) {
        if !out.contains(&canon) {
            out.push(canon);
        }
    }
}

/// Resolves a macOS executable path using explicit paths or `PATH` lookup when non-qualified.
pub fn resolve_macos_program_path(program: &Path) -> PathBuf {
    if program.is_absolute() || program.components().count() > 1 {
        return std::fs::canonicalize(program).unwrap_or_else(|_| program.to_path_buf());
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(program);
            if candidate.is_file() {
                return std::fs::canonicalize(&candidate).unwrap_or(candidate);
            }
        }
    }
    program.to_path_buf()
}

/// Generates a deterministic, fail-closed macOS Seatbelt SBPL profile for `config`.
///
/// - Enforces `(version 1)` and `(deny default)`.
/// - Blocks all outbound/inbound networking with `(deny network*)`, optionally re-enabling ONLY
///   sanitized `localhost:<port>` rules when `config.allow_loopback` is true (never permitting
///   blocked proxy, lateral, discovery, `0`, or `5000` ports).
/// - Grants access strictly to minimal OS shared libraries, `/dev/{null,zero,random,urandom}`,
///   and declared `read_only_dirs` / `read_write_dirs` / `working_dir`.
pub fn generate_macos_seatbelt_profile(config: &SandboxedMacosConfig) -> String {
    let mut profile = String::with_capacity(1024);
    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n");
    profile.push_str("(allow process-fork)\n");
    profile.push_str("(allow process-info* (target self))\n");
    profile.push_str("(allow signal (target self))\n");
    profile.push_str("(allow sysctl-read)\n");
    profile.push_str("(allow file-read-metadata)\n");
    profile.push_str(
        "(allow file-read*\n    (subpath \"/usr/lib\")\n    (subpath \"/usr/share\")\n    (subpath \"/System/Library\")\n    (subpath \"/Library/Apple\")\n    (literal \"/dev/null\")\n    (literal \"/dev/zero\")\n    (literal \"/dev/random\")\n    (literal \"/dev/urandom\")\n    (literal \"/private/var/run/syslog\"))\n",
    );
    profile.push_str(
        "(allow file-write*\n    (literal \"/dev/null\")\n    (literal \"/dev/zero\"))\n",
    );

    let mut exec_paths = Vec::new();
    let resolved_prog = resolve_macos_program_path(&config.program);
    push_sbpl_path_variants(&mut exec_paths, &config.program);
    push_sbpl_path_variants(&mut exec_paths, &resolved_prog);
    for exec_path in &exec_paths {
        let escaped = escape_sbpl_path(exec_path);
        profile.push_str(&format!("(allow process-exec (literal \"{}\"))\n", escaped));
        profile.push_str(&format!("(allow file-read* (literal \"{}\"))\n", escaped));
    }

    let mut ro_paths = Vec::new();
    for dir in &config.read_only_dirs {
        push_sbpl_path_variants(&mut ro_paths, dir);
    }
    for dir in &ro_paths {
        let escaped = escape_sbpl_path(dir);
        profile.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", escaped));
    }

    let mut rw_paths = Vec::new();
    for dir in &config.read_write_dirs {
        push_sbpl_path_variants(&mut rw_paths, dir);
    }
    if let Some(ref wd) = config.working_dir {
        push_sbpl_path_variants(&mut rw_paths, wd);
    }
    for dir in &rw_paths {
        let escaped = escape_sbpl_path(dir);
        profile.push_str(&format!(
            "(allow file-read* file-write* (subpath \"{}\"))\n",
            escaped
        ));
    }

    profile.push_str("(deny network*)\n");
    if config.allow_loopback {
        let sanitized_ports = sanitize_firewall_preserved_ports(&config.control_ports);
        for port in sanitized_ports {
            profile.push_str(&format!(
                "(allow network-outbound (remote tcp \"localhost:{}\"))\n",
                port
            ));
            profile.push_str(&format!(
                "(allow network-inbound (local tcp \"localhost:{}\"))\n",
                port
            ));
        }
    }

    profile
}

#[cfg(target_os = "macos")]
mod libproc_ffi {
    extern "C" {
        pub fn proc_listchildpids(
            ppid: libc::pid_t,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
    }
}

/// Enumerates direct child PIDs of `ppid` using macOS `proc_listchildpids` (`libSystem`).
#[cfg(target_os = "macos")]
pub fn native_direct_children_macos(ppid: u32) -> Vec<u32> {
    if ppid == 0 {
        return Vec::new();
    }
    let mut capacity: usize = 128;
    for _ in 0..6 {
        let mut buf: Vec<libc::pid_t> = vec![0; capacity];
        let buf_bytes = (capacity * std::mem::size_of::<libc::pid_t>()) as libc::c_int;
        let ret = unsafe {
            libproc_ffi::proc_listchildpids(
                ppid as libc::pid_t,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf_bytes,
            )
        };
        if ret <= 0 {
            return Vec::new();
        }
        let count = (ret as usize).min(capacity);
        if count == capacity {
            capacity *= 2;
            continue;
        }
        let mut children = Vec::with_capacity(count);
        for &pid in &buf[..count] {
            if pid > 1 && (pid as u32) != ppid && !children.contains(&(pid as u32)) {
                children.push(pid as u32);
            }
        }
        return children;
    }
    Vec::new()
}

/// Performs bounded BFS over macOS `proc_listchildpids` to collect `root_pid` and all descendants.
#[cfg(target_os = "macos")]
pub fn enumerate_macos_process_subtree(root_pid: u32) -> Vec<u32> {
    if root_pid <= 1 {
        return Vec::new();
    }
    let mut seen = HashSet::new();
    let mut order = Vec::new();
    let mut queue = VecDeque::new();
    seen.insert(root_pid);
    order.push(root_pid);
    queue.push_back(root_pid);

    while let Some(pid) = queue.pop_front() {
        for child in native_direct_children_macos(pid) {
            if seen.insert(child) {
                order.push(child);
                queue.push_back(child);
                if order.len() >= 4096 {
                    return order;
                }
            }
        }
    }
    order
}

/// Atomically suspends (`SIGSTOP`) `root_pid` and all descendants to a fixed point so racing
/// child forks cannot escape quarantine.
#[cfg(target_os = "macos")]
pub fn freeze_macos_process_subtree(root_pid: u32) -> Result<Vec<u32>, OctopusSecurityError> {
    if root_pid <= 1 {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "Refusing to freeze protected macOS PID {}",
            root_pid
        )));
    }
    let self_pid = std::process::id();
    let mut frozen = HashSet::new();

    for _pass in 0..5 {
        let mut newly_frozen = false;
        for pid in enumerate_macos_process_subtree(root_pid) {
            if pid <= 1 || pid == self_pid {
                continue;
            }
            if frozen.insert(pid) {
                let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) };
                if rc == 0 {
                    newly_frozen = true;
                } else if pid == root_pid {
                    let err = std::io::Error::last_os_error();
                    return Err(OctopusSecurityError::IsolationViolation(format!(
                        "SIGSTOP failed for macOS PID {}: {}",
                        pid, err
                    )));
                }
            }
        }
        if !newly_frozen {
            break;
        }
    }

    let mut result: Vec<u32> = frozen.into_iter().collect();
    result.sort_unstable();
    Ok(result)
}

/// Resumes (`SIGCONT`) a previously suspended macOS process subtree.
#[cfg(target_os = "macos")]
pub fn resume_macos_process_subtree(root_pid: u32) -> Result<Vec<u32>, OctopusSecurityError> {
    if root_pid <= 1 {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "Refusing to resume protected macOS PID {}",
            root_pid
        )));
    }
    let self_pid = std::process::id();
    let mut resumed = Vec::new();
    for pid in enumerate_macos_process_subtree(root_pid) {
        if pid <= 1 || pid == self_pid {
            continue;
        }
        if unsafe { libc::kill(pid as libc::pid_t, libc::SIGCONT) } == 0 {
            resumed.push(pid);
        }
    }
    Ok(resumed)
}

/// Freezes (`SIGSTOP`) then terminates (`SIGKILL`) all descendants and root process bottom-up.
#[cfg(target_os = "macos")]
pub fn kill_macos_process_subtree(root_pid: u32) -> Result<usize, OctopusSecurityError> {
    if root_pid <= 1 {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "Refusing to kill protected macOS PID {}",
            root_pid
        )));
    }
    let self_pid = std::process::id();
    let _ = freeze_macos_process_subtree(root_pid);
    let pids = enumerate_macos_process_subtree(root_pid);
    let mut killed = 0usize;
    for &pid in pids.iter().rev() {
        if pid <= 1 || pid == self_pid {
            continue;
        }
        if unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) } == 0 {
            killed += 1;
        }
    }
    Ok(killed)
}

/// Spawns a process strictly confined under `/usr/bin/sandbox-exec` with a fail-closed SBPL
/// profile. Returns an error immediately if `/usr/bin/sandbox-exec` is unavailable or fails.
#[cfg(target_os = "macos")]
pub fn spawn_macos_seatbelt_process(
    config: &SandboxedMacosConfig,
) -> Result<SandboxedMacosProcess, OctopusSecurityError> {
    const SANDBOX_EXEC_BIN: &str = "/usr/bin/sandbox-exec";
    if !Path::new(SANDBOX_EXEC_BIN).is_file() {
        return Err(OctopusSecurityError::IsolationViolation(
            "/usr/bin/sandbox-exec is missing; refusing uncontained macOS spawn".to_string(),
        ));
    }

    let sbpl_profile = generate_macos_seatbelt_profile(config);
    let resolved_program = resolve_macos_program_path(&config.program);
    let sanitized_ports = if config.allow_loopback {
        sanitize_firewall_preserved_ports(&config.control_ports)
    } else {
        Vec::new()
    };

    let mut cmd = Command::new(SANDBOX_EXEC_BIN);
    cmd.arg("-p")
        .arg(&sbpl_profile)
        .arg(&resolved_program)
        .args(&config.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(ref wd) = config.working_dir {
        cmd.current_dir(wd);
    }

    let child = cmd.spawn().map_err(|e| {
        OctopusSecurityError::IsolationViolation(format!(
            "Failed to spawn macOS sandbox-exec child: {}",
            e
        ))
    })?;
    let root_pid = child.id();

    Ok(SandboxedMacosProcess {
        root_pid,
        backend: "macos-seatbelt-sbpl".to_string(),
        sbpl_profile,
        control_ports: sanitized_ports,
        child: Some(child),
    })
}

#[cfg(target_os = "macos")]
impl SandboxedMacosProcess {
    /// Suspends the entire macOS process subtree via `proc_listchildpids` + `SIGSTOP`.
    pub fn freeze(&self) -> Result<Vec<u32>, OctopusSecurityError> {
        freeze_macos_process_subtree(self.root_pid)
    }

    /// Resumes the macOS process subtree via `SIGCONT`.
    pub fn resume(&self) -> Result<Vec<u32>, OctopusSecurityError> {
        resume_macos_process_subtree(self.root_pid)
    }

    /// Freezes and terminates the entire process subtree bottom-up, reaping the child handle.
    pub fn terminate(&mut self) -> Result<usize, OctopusSecurityError> {
        let killed = kill_macos_process_subtree(self.root_pid)?;
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
        Ok(killed)
    }

    /// Waits for the confined child process to exit and returns its exit status.
    pub fn wait(&mut self) -> Result<ExitStatus, OctopusSecurityError> {
        let mut child = self.child.take().ok_or_else(|| {
            OctopusSecurityError::IsolationViolation(
                "SandboxedMacosProcess child handle already consumed".to_string(),
            )
        })?;
        child.wait().map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!(
                "Failed waiting on macOS sandbox-exec child: {}",
                e
            ))
        })
    }

    /// Takes ownership of the underlying `std::process::Child` if still active.
    pub fn take_child(&mut self) -> Option<Child> {
        self.child.take()
    }
}

#[cfg(target_os = "macos")]
impl Drop for SandboxedMacosProcess {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if let Ok(None) = child.try_wait() {
            let _ = kill_macos_process_subtree(self.root_pid);
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_sbpl_path_handles_quotes_and_backslashes() {
        let p = Path::new("/tmp/agent\"dir\\sub");
        assert_eq!(escape_sbpl_path(p), "/tmp/agent\\\"dir\\\\sub");
    }

    #[test]
    fn test_generate_macos_seatbelt_profile_enforces_deny_default_and_port_sanitization() {
        let cfg = SandboxedMacosConfig {
            program: PathBuf::from("/usr/bin/true"),
            args: vec![],
            read_only_dirs: vec![PathBuf::from("/opt/agent_ro")],
            read_write_dirs: vec![PathBuf::from("/tmp/agent_rw")],
            working_dir: Some(PathBuf::from("/tmp/agent_work")),
            allow_loopback: true,
            control_ports: vec![0, 53, 67, 68, 135, 445, 1080, 3128, 5000, 5005, 8080, 8888, 9050],
        };

        let sbpl = generate_macos_seatbelt_profile(&cfg);
        assert!(sbpl.contains("(version 1)"));
        assert!(sbpl.contains("(deny default)"));
        assert!(sbpl.contains("(deny network*)"));
        assert!(sbpl.contains("(allow file-read* (subpath \"/opt/agent_ro\"))"));
        assert!(sbpl.contains("(allow file-read* file-write* (subpath \"/tmp/agent_rw\"))"));
        assert!(sbpl.contains("(allow file-read* file-write* (subpath \"/tmp/agent_work\"))"));
        assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:5005\"))"));
        assert!(sbpl.contains("(allow network-inbound (local tcp \"localhost:5005\"))"));

        for blocked in [0u16, 53, 67, 68, 135, 445, 1080, 3128, 5000, 8080, 8888, 9050] {
            assert!(
                !sbpl.contains(&format!("localhost:{}\"", blocked)),
                "SBPL must never allow blocked port {}",
                blocked
            );
        }
    }

    #[test]
    fn test_generate_macos_seatbelt_profile_denies_all_network_when_loopback_disabled() {
        let cfg = SandboxedMacosConfig {
            program: PathBuf::from("/usr/bin/env"),
            args: vec![],
            read_only_dirs: vec![],
            read_write_dirs: vec![],
            working_dir: None,
            allow_loopback: false,
            control_ports: vec![5005],
        };

        let sbpl = generate_macos_seatbelt_profile(&cfg);
        assert!(sbpl.contains("(deny network*)"));
        assert!(!sbpl.contains("network-outbound"));
        assert!(!sbpl.contains("network-inbound"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_sandboxed_agent_enforces_seatbelt_isolation() {
        let tmp = std::env::temp_dir().join(format!("octo_sbpl_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let cfg = SandboxedMacosConfig {
            program: PathBuf::from("/bin/sh"),
            args: vec![
                "-c".to_string(),
                "ls /Users >/dev/null 2>&1 && exit 42 || exit 0".to_string(),
            ],
            read_only_dirs: vec![PathBuf::from("/bin")],
            read_write_dirs: vec![tmp.clone()],
            working_dir: Some(tmp.clone()),
            allow_loopback: false,
            control_ports: vec![],
        };
        let mut proc_handle = spawn_macos_seatbelt_process(&cfg).expect("spawn sandbox-exec");
        let status = proc_handle.wait().expect("wait sandbox-exec");
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(status.success(), "Seatbelt must deny /Users read: {:?}", status);
    }
}
