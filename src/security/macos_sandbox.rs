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
use std::process::{Child, Command, ExitStatus, Output, Stdio};

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
    let mut profile = String::with_capacity(2048);
    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n");
    profile.push_str("(import \"system.sb\")\n");
    profile.push_str("(allow process-exec* process-fork sysctl-read)\n");
    profile.push_str("(allow process-info* (target self))\n");
    profile.push_str("(allow signal (target same-sandbox))\n");
    profile.push_str("(allow file-read-metadata)\n");
    profile.push_str("(allow mach-lookup\n");
    profile.push_str("    (global-name \"com.apple.system.logger\")\n");
    profile.push_str("    (global-name \"com.apple.system.opendirectoryd.libinfo\"))\n");
    profile.push_str("(allow file-read* file-write*\n");
    profile.push_str("    (literal \"/dev/null\")\n");
    profile.push_str("    (literal \"/dev/zero\")\n");
    profile.push_str("    (literal \"/dev/dtracehelper\"))\n");
    profile.push_str("(allow file-ioctl\n");
    profile.push_str("    (literal \"/dev/null\")\n");
    profile.push_str("    (literal \"/dev/tty\")\n");
    profile.push_str("    (literal \"/dev/dtracehelper\"))\n");
    profile.push_str("(deny system-kext-load)\n");
    profile.push_str("(deny iokit-open)\n");
    profile.push_str("(deny system-fsctl)\n");
    profile.push_str("(deny system-nfssvc)\n");
    profile.push_str("(deny system-privilege)\n");
    profile.push_str("(deny system-acct)\n");
    profile.push_str("(deny system-swap)\n");
    profile.push_str("(allow file-read* file-map-executable\n");
    for base_path in [
        "/usr",
        "/bin",
        "/sbin",
        "/System",
        "/Library",
        "/opt",
        "/Applications",
        "/private/preboot",
        "/private/var/db/dyld",
        "/private/var/db/xcode_select_link",
        "/private/var/select",
        "/private/etc",
        "/etc",
    ] {
        profile.push_str(&format!("    (subpath \"{}\")\n", base_path));
    }
    profile.push_str(")\n");

    let mut exec_paths = Vec::new();
    let resolved_prog = resolve_macos_program_path(&config.program);
    push_sbpl_path_variants(&mut exec_paths, &config.program);
    push_sbpl_path_variants(&mut exec_paths, &resolved_prog);
    for exec_path in &exec_paths {
        let escaped = escape_sbpl_path(exec_path);
        profile.push_str(&format!("(allow process-exec (literal \"{}\"))\n", escaped));
        profile.push_str(&format!(
            "(allow file-read* file-map-executable (literal \"{}\"))\n",
            escaped
        ));
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
/// profile, passing sanitized `env_pairs` and inherited or piped stdio.
#[cfg(target_os = "macos")]
pub fn spawn_macos_seatbelt_process_with_stdio(
    config: &SandboxedMacosConfig,
    env_pairs: &[(String, String)],
    pipe_stdio: bool,
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
        .env_clear()
        .envs(env_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));

    if pipe_stdio {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    } else {
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    }
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

    /// Waits for the confined child process to exit and captures stdout/stderr output.
    pub fn wait_with_output(&mut self) -> Result<Output, OctopusSecurityError> {
        let child = self.child.take().ok_or_else(|| {
            OctopusSecurityError::IsolationViolation(
                "SandboxedMacosProcess child handle already consumed".to_string(),
            )
        })?;
        child.wait_with_output().map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!(
                "Failed capturing output from macOS sandbox-exec child: {}",
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
            control_ports: vec![
                0, 53, 67, 68, 135, 445, 1080, 3128, 5000, 5005, 8080, 8888, 9050,
            ],
        };

        let sbpl = generate_macos_seatbelt_profile(&cfg);
        assert!(sbpl.contains("(version 1)"));
        assert!(sbpl.contains("(deny default)"));
        assert!(sbpl.contains("(import \"system.sb\")"));
        assert!(sbpl.contains("(allow file-read* file-map-executable"));
        assert!(sbpl.contains("(deny network*)"));
        assert!(sbpl.contains("(allow file-read* (subpath \"/opt/agent_ro\"))"));
        assert!(sbpl.contains("(allow file-read* file-write* (subpath \"/tmp/agent_rw\"))"));
        assert!(sbpl.contains("(allow file-read* file-write* (subpath \"/tmp/agent_work\"))"));
        assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:5005\"))"));
        assert!(sbpl.contains("(allow network-inbound (local tcp \"localhost:5005\"))"));

        for blocked in [
            0u16, 53, 67, 68, 135, 445, 1080, 3128, 5000, 8080, 8888, 9050,
        ] {
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
        let pid = std::process::id();
        let base = std::env::temp_dir().join(format!("octo_sbpl_test_{}", pid));
        let allowed_dir = base.join("allowed");
        let forbidden_dir = base.join("forbidden");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&allowed_dir).expect("create allowed_dir");
        std::fs::create_dir_all(&forbidden_dir).expect("create forbidden_dir");

        let allowed_file = allowed_dir.join("ok.txt");
        let allow_cmd = format!("printf confined > '{}'", allowed_file.display());
        let allow_cfg = SandboxedMacosConfig {
            program: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_string(), allow_cmd],
            read_only_dirs: vec![PathBuf::from("/bin")],
            read_write_dirs: vec![allowed_dir.clone()],
            working_dir: Some(allowed_dir.clone()),
            allow_loopback: false,
            control_ports: vec![],
        };
        let mut allow_proc = spawn_macos_seatbelt_process(&allow_cfg).expect("spawn allowed");
        let allow_out = allow_proc.wait_with_output().expect("wait allowed");
        assert!(
            allow_out.status.success(),
            "Seatbelt allowed write failed: {:?} stdout={} stderr={}",
            allow_out.status,
            String::from_utf8_lossy(&allow_out.stdout),
            String::from_utf8_lossy(&allow_out.stderr)
        );
        let actual = std::fs::read_to_string(&allowed_file).expect("read allowed_file");
        assert_eq!(actual, "confined");

        let escape_file = forbidden_dir.join("escape.txt");
        let esc = escape_file.display();
        let deny_cmd = format!("ls /Users >/dev/null 2>&1 || touch '{esc}' 2>/dev/null");
        let deny_cfg = SandboxedMacosConfig {
            program: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_string(), deny_cmd],
            read_only_dirs: vec![PathBuf::from("/bin")],
            read_write_dirs: vec![allowed_dir.clone()],
            working_dir: Some(allowed_dir),
            allow_loopback: false,
            control_ports: vec![],
        };
        let mut deny_proc = spawn_macos_seatbelt_process(&deny_cfg).expect("spawn deny");
        let deny_out = deny_proc.wait_with_output().expect("wait deny");
        let escape_exists = escape_file.exists();
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            !deny_out.status.success() && deny_out.status.code().is_some(),
            "Seatbelt must deny escape cleanly: {:?} stdout={} stderr={}",
            deny_out.status,
            String::from_utf8_lossy(&deny_out.stdout),
            String::from_utf8_lossy(&deny_out.stderr)
        );
        assert!(
            !escape_exists,
            "Seatbelt must prevent creating escape file outside read_write_dirs"
        );
    }
}
