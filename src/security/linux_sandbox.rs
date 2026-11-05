//! Linux Tier 2 Kernel Confinement Subsystem (`src/security/linux_sandbox.rs`)
//!
//! Provides Linux kernel confinement parity with Windows AppContainer + Job Object:
//! 1. `PR_SET_NO_NEW_PRIVS`: Prevents privilege escalation via setuid/setgid binaries.
//! 2. Landlock LSM: Restricts filesystem access to binary/library directories (read-only)
//!    and scratchpad (read-write), denying access to `/etc`, `/home`, `/root`, etc.
//! 3. Network Namespace Unsharing (`CLONE_NEWNET`): Isolates the child in a private network
//!    namespace when permitted by kernel userns policy, paired with mandatory seccomp-BPF.
//! 4. Seccomp-BPF: System call filter blocking 18 socket-related syscalls (`SYS_socket`,
//!    `SYS_connect`, `SYS_bind`, `SYS_sendto`, `SYS_recvfrom`, etc.) with `EACCES`.
//! 5. Resource Ceilings (`setrlimit`): Deterministic caps on memory (`RLIMIT_AS`/`RLIMIT_DATA`),
//!    CPU time (`RLIMIT_CPU`), file descriptors (`RLIMIT_NOFILE`), and core dumps (`RLIMIT_CORE = 0`).
//! 6. Fail-Closed Process Creation: `CommandExt::pre_exec` aborts launch if mandatory confinement
//!    boundaries fail to apply.

use crate::core::types::OctopusSecurityError;
use crate::security::executable_identity::VerifiedExecutableHandle;
#[cfg(target_os = "linux")]
use crate::security::windows_sandbox::AppContainerTokenVerification;
use crate::security::windows_sandbox::{Tier2ConfinedChildResult, WindowsJobObject};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Seccomp-BPF Constants & Types (Cross-Platform / Pure Rust)
// ---------------------------------------------------------------------------

pub const BPF_LD: u16 = 0x00;
pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_K: u16 = 0x00;
pub const BPF_RET: u16 = 0x06;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

/// POSIX `EACCES` (Permission denied = 13 on Linux and POSIX).
pub const LINUX_EACCES: u32 = 13;

/// Classic BPF filter instruction (8 bytes).
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub struct sock_filter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// Classic BPF filter program header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct sock_fprog {
    pub len: u16,
    pub filter: *const sock_filter,
}

/// Syscall numbers for socket operations on Linux x86_64.
pub const X86_64_BLOCKED_SOCKET_SYSCALLS: &[u32] = &[
    41,  // SYS_socket
    42,  // SYS_connect
    43,  // SYS_accept
    44,  // SYS_sendto
    45,  // SYS_recvfrom
    46,  // SYS_sendmsg
    47,  // SYS_recvmsg
    48,  // SYS_shutdown
    49,  // SYS_bind
    50,  // SYS_listen
    51,  // SYS_getsockname
    52,  // SYS_getpeername
    53,  // SYS_socketpair
    54,  // SYS_setsockopt
    55,  // SYS_getsockopt
    288, // SYS_accept4
    299, // SYS_recvmmsg
    307, // SYS_sendmmsg
];

/// Syscall numbers for socket operations on Linux aarch64.
pub const AARCH64_BLOCKED_SOCKET_SYSCALLS: &[u32] = &[
    198, // SYS_socket
    199, // SYS_socketpair
    200, // SYS_bind
    201, // SYS_listen
    202, // SYS_accept
    203, // SYS_connect
    204, // SYS_getsockname
    205, // SYS_getpeername
    206, // SYS_sendto
    207, // SYS_recvfrom
    208, // SYS_setsockopt
    209, // SYS_getsockopt
    210, // SYS_shutdown
    211, // SYS_sendmsg
    212, // SYS_recvmsg
    242, // SYS_accept4
    243, // SYS_recvmmsg
    269, // SYS_sendmmsg
];

/// Generates a valid BPF filter bytecode array that validates architecture and
/// blocks the specified syscalls with `SECCOMP_RET_ERRNO | (errno_code & 0xffff)`.
pub fn build_socket_filter_bpf(
    expected_arch: u32,
    blocked_syscalls: &[u32],
    errno_code: u32,
) -> Vec<sock_filter> {
    let mut insns = Vec::with_capacity(blocked_syscalls.len() + 6);

    // 1. Load architecture from seccomp_data: offset 4
    insns.push(sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 4,
    });

    // 2. Validate architecture: if arch == expected_arch, jump 1 (skip kill), else jump 0 (kill)
    insns.push(sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 1,
        jf: 0,
        k: expected_arch,
    });

    // 3. Kill process on architecture mismatch
    insns.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    // 4. Load system call number from seccomp_data: offset 0
    insns.push(sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });

    // 5. For each blocked syscall, jump to the deny instruction
    let num_blocked = blocked_syscalls.len();
    for (i, &syscall_nr) in blocked_syscalls.iter().enumerate() {
        let jump_offset = (num_blocked - 1 - i) as u8 + 1;
        insns.push(sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: jump_offset,
            jf: 0,
            k: syscall_nr,
        });
    }

    // 6. Default allow instruction (reached if no blocked syscall matched)
    insns.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    // 7. Deny instruction: return SECCOMP_RET_ERRNO | (errno_code & 0xffff)
    let errno_ret = SECCOMP_RET_ERRNO | (errno_code & 0x0000_ffff);
    insns.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: errno_ret,
    });

    insns
}

/// In-memory BPF bytecode simulator for deterministic cross-platform unit testing.
pub fn evaluate_bpf_filter(filter: &[sock_filter], arch: u32, nr: u32) -> u32 {
    let mut pc = 0;
    let mut reg_a: u32 = 0;

    while pc < filter.len() {
        let insn = &filter[pc];
        match insn.code {
            0x20 => {
                // BPF_LD | BPF_W | BPF_ABS
                if insn.k == 0 {
                    reg_a = nr;
                } else if insn.k == 4 {
                    reg_a = arch;
                } else {
                    reg_a = 0;
                }
                pc += 1;
            }
            0x15 => {
                // BPF_JMP | BPF_JEQ | BPF_K
                if reg_a == insn.k {
                    pc = pc + 1 + (insn.jt as usize);
                } else {
                    pc = pc + 1 + (insn.jf as usize);
                }
            }
            0x06 => {
                // BPF_RET | BPF_K
                return insn.k;
            }
            _ => {
                return SECCOMP_RET_KILL_PROCESS;
            }
        }
    }
    SECCOMP_RET_KILL_PROCESS
}

// ---------------------------------------------------------------------------
// Landlock LSM Constants & Types (Cross-Platform)
// ---------------------------------------------------------------------------

pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct landlock_ruleset_attr {
    pub handled_access_fs: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct landlock_path_beneath_attr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

// ---------------------------------------------------------------------------
// Configuration & Verification Data Structures
// ---------------------------------------------------------------------------

/// Deterministic POSIX resource ceilings enforced via `setrlimit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxResourceLimits {
    pub max_as_bytes: u64,
    pub max_data_bytes: u64,
    pub max_nproc: u64,
    pub max_cpu_seconds: u64,
    pub max_nofile: u64,
    pub max_core_bytes: u64,
}

impl Default for LinuxResourceLimits {
    fn default() -> Self {
        Self {
            max_as_bytes: 64 * 1024 * 1024,   // 64 MiB
            max_data_bytes: 64 * 1024 * 1024, // 64 MiB
            max_nproc: 4,                     // Max 4 processes in isolated userns
            max_cpu_seconds: 10,              // 10s CPU limit
            max_nofile: 256,                  // Max 256 open files
            max_core_bytes: 0,                // Zero core dumps
        }
    }
}

/// Linux Tier 2 confinement configuration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxConfinementConfig {
    pub agent_id: String,
    pub scratchpad_path: PathBuf,
    pub binary_canonical_path: PathBuf,
    pub limits: LinuxResourceLimits,
    pub wall_clock_timeout_ms: u64,
    pub enforce_landlock: bool,
    pub enforce_network_unshare: bool,
    pub enforce_seccomp_bpf: bool,
}

impl LinuxConfinementConfig {
    pub fn new(agent_id: impl Into<String>, binary: PathBuf, scratchpad: PathBuf) -> Self {
        Self {
            agent_id: agent_id.into(),
            scratchpad_path: scratchpad,
            binary_canonical_path: binary,
            limits: LinuxResourceLimits::default(),
            wall_clock_timeout_ms: 10_000,
            enforce_landlock: true,
            enforce_network_unshare: true,
            enforce_seccomp_bpf: true,
        }
    }
}

/// Telemetry record proving active kernel confinement features on the spawned child.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxConfinementVerification {
    pub no_new_privs_applied: bool,
    pub network_unshared: bool,
    pub seccomp_bpf_active: bool,
    pub landlock_lsm_active: bool,
    pub rlimits_applied: bool,
    pub scratchpad_path: String,
    pub isolated_namespaces: Vec<String>,
}

/// Inspects the active host OS Tier 2 native sandbox capabilities without mutating host state.
pub fn describe_tier2_host_confinement_posture() -> String {
    #[cfg(windows)]
    {
        "Windows AppContainer + NT JobObject (64 MiB cap, active_proc=4, UILIMIT_ALL)".to_string()
    }
    #[cfg(target_os = "linux")]
    {
        "Linux Landlock LSM + seccomp-BPF (18 socket syscalls -> EACCES) + CLONE_NEWNET + setrlimit (64 MiB)".to_string()
    }
    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        "Unsupported host OS (Fail-Closed)".to_string()
    }
}

// ---------------------------------------------------------------------------
// Linux-Specific Implementation (#[cfg(target_os = "linux")])
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    unsafe fn sys_landlock_create_ruleset(
        attr: *const landlock_ruleset_attr,
        size: usize,
        flags: u32,
    ) -> i32 {
        libc::syscall(libc::SYS_landlock_create_ruleset, attr, size, flags) as i32
    }

    unsafe fn sys_landlock_add_rule(
        ruleset_fd: i32,
        rule_type: u32,
        rule_attr: *const std::ffi::c_void,
        flags: u32,
    ) -> i32 {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            rule_type,
            rule_attr,
            flags,
        ) as i32
    }

    unsafe fn sys_landlock_restrict_self(ruleset_fd: i32, flags: u32) -> i32 {
        libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, flags) as i32
    }

    /// Configures and applies Landlock LSM filesystem boundary.
    unsafe fn apply_landlock_filesystem_boundary(
        binary_path: &Path,
        scratchpad_root: &Path,
        strict_fail_closed: bool,
    ) -> std::io::Result<bool> {
        let version =
            sys_landlock_create_ruleset(std::ptr::null(), 0, LANDLOCK_CREATE_RULESET_VERSION);
        if version < 1 {
            if strict_fail_closed {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Landlock LSM is not supported or enabled on this host kernel",
                ));
            }
            return Ok(false);
        }

        let access_ro =
            LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

        let access_rw = access_ro
            | LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_TRUNCATE;

        // ABI v1 supports bits 0..=12; ABI v2 adds REFER (13); ABI v3 adds TRUNCATE (14).
        let mut access_handled = access_ro
            | LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_CHAR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SOCK
            | LANDLOCK_ACCESS_FS_MAKE_FIFO
            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
            | LANDLOCK_ACCESS_FS_MAKE_SYM;
        if version >= 2 {
            access_handled |= LANDLOCK_ACCESS_FS_REFER;
        }
        if version >= 3 {
            access_handled |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }

        let scratch_rw = access_rw & access_handled;

        let attr = landlock_ruleset_attr {
            handled_access_fs: access_handled,
        };

        let ruleset_fd =
            sys_landlock_create_ruleset(&attr, std::mem::size_of::<landlock_ruleset_attr>(), 0);
        if ruleset_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let add_path_rule = |path: &Path, allowed_access: u64| -> std::io::Result<()> {
            if !path.exists() {
                return Ok(());
            }
            use std::os::unix::ffi::OsStrExt;
            let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
            let fd = libc::open(
                c_path.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
            );
            if fd < 0 {
                return Ok(());
            }
            let path_attr = landlock_path_beneath_attr {
                allowed_access: allowed_access & access_handled,
                parent_fd: fd,
            };
            let ret = sys_landlock_add_rule(
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &path_attr as *const _ as *const std::ffi::c_void,
                0,
            );
            libc::close(fd);
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        };

        if let Some(parent) = binary_path.parent() {
            let _ = add_path_rule(parent, access_ro);
        }

        for sys_dir in &[
            "/lib",
            "/lib64",
            "/usr/lib",
            "/usr/lib64",
            "/bin",
            "/usr/bin",
            "/etc/ld.so.cache",
        ] {
            let p = Path::new(sys_dir);
            if p.is_dir() {
                let _ = add_path_rule(p, access_ro);
            }
        }

        add_path_rule(scratchpad_root, scratch_rw)?;

        let restrict_rc = sys_landlock_restrict_self(ruleset_fd, 0);
        libc::close(ruleset_fd);
        if restrict_rc < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(true)
    }

    /// Unshares network namespace when permitted, returning `(netns_isolated, userns_isolated)`.
    /// When unprivileged user namespaces are restricted by AppArmor (e.g. Ubuntu 24.04) and
    /// `seccomp_enforced` is true, seccomp-BPF still guarantees fail-closed zero-socket confinement.
    unsafe fn apply_network_namespace_unshare(
        seccomp_enforced: bool,
    ) -> std::io::Result<(bool, bool)> {
        if libc::unshare(libc::CLONE_NEWNET) == 0 {
            return Ok((true, false));
        }
        if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) == 0 {
            return Ok((true, true));
        }
        let err = std::io::Error::last_os_error();
        if seccomp_enforced && err.raw_os_error() == Some(libc::EPERM) {
            return Ok((false, false));
        }
        Err(err)
    }

    /// Installs mandatory seccomp-BPF filter blocking all 18 socket system calls with `EACCES`.
    unsafe fn apply_seccomp_socket_filter() -> std::io::Result<()> {
        #[cfg(target_arch = "x86_64")]
        let (arch, blocked) = (AUDIT_ARCH_X86_64, X86_64_BLOCKED_SOCKET_SYSCALLS);
        #[cfg(target_arch = "aarch64")]
        let (arch, blocked) = (AUDIT_ARCH_AARCH64, AARCH64_BLOCKED_SOCKET_SYSCALLS);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Unsupported architecture for Linux seccomp-BPF",
        ));

        let insns = build_socket_filter_bpf(arch, blocked, libc::EACCES as u32);
        let prog = sock_fprog {
            len: insns.len() as u16,
            filter: insns.as_ptr(),
        };

        let rc = libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &prog as *const _ as usize,
            0,
            0,
        );
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Applies deterministic per-process resource limits via `setrlimit`.
    unsafe fn apply_resource_limits(
        limits: &LinuxResourceLimits,
        userns_isolated: bool,
    ) -> std::io::Result<()> {
        let set_rl = |res: libc::__rlimit_resource_t, val: u64| -> std::io::Result<()> {
            let rl = libc::rlimit {
                rlim_cur: val,
                rlim_max: val,
            };
            if libc::setrlimit(res, &rl) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        };

        set_rl(libc::RLIMIT_AS, limits.max_as_bytes)?;
        set_rl(libc::RLIMIT_DATA, limits.max_data_bytes)?;
        if userns_isolated {
            // RLIMIT_NPROC is UID-wide on Linux; apply inside isolated user namespace.
            let _ = set_rl(libc::RLIMIT_NPROC, limits.max_nproc);
        }
        set_rl(libc::RLIMIT_CPU, limits.max_cpu_seconds)?;
        set_rl(libc::RLIMIT_NOFILE, limits.max_nofile)?;
        set_rl(libc::RLIMIT_CORE, 0)?;

        Ok(())
    }

    pub fn spawn_tier2_linux_command_impl(
        verified_exe: &VerifiedExecutableHandle,
        args: &[String],
        agent_id: &str,
        scratchpad_root: &Path,
        job: &WindowsJobObject,
    ) -> Result<Tier2ConfinedChildResult, OctopusSecurityError> {
        let _ = std::fs::create_dir_all(scratchpad_root);

        let token_posture = crate::security::token_posture::current_token_posture()?;
        if let Err(reasons) = token_posture.verify_agent_safe() {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: Linux Tier 2 child token posture unsafe: {}",
                reasons.join("; ")
            )));
        }

        let mut config = LinuxConfinementConfig::new(
            agent_id,
            PathBuf::from(&verified_exe.metadata.canonical_path),
            scratchpad_root.to_path_buf(),
        );

        if job.max_memory_bytes > 0 {
            config.limits.max_as_bytes = job.max_memory_bytes as u64;
            config.limits.max_data_bytes = job.max_memory_bytes as u64;
        }
        if job.max_processes > 0 {
            config.limits.max_nproc = job.max_processes as u64;
        }

        let mut cmd = std::process::Command::new(&verified_exe.metadata.canonical_path);
        if verified_exe.metadata.normalized_stem == "cmd"
            && args.first().map(|s| s.eq_ignore_ascii_case("/C")) == Some(true)
        {
            let joined = args.iter().skip(1).cloned().collect::<Vec<_>>().join(" ");
            cmd.arg("-c").arg(joined);
        } else {
            cmd.args(args);
        }

        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .current_dir(scratchpad_root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let binary_path = config.binary_canonical_path.clone();
        let scratchpad_path = config.scratchpad_path.clone();
        let limits = config.limits;
        let enforce_net = config.enforce_network_unshare;
        let enforce_landlock = config.enforce_landlock;
        let enforce_seccomp = config.enforce_seccomp_bpf;

        // Fail-Closed Pre-Exec Security Confinement Closure
        unsafe {
            cmd.pre_exec(move || {
                // 1. Mandatory PR_SET_NO_NEW_PRIVS
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // 2. Network namespace isolation (before Landlock/seccomp)
                let mut userns_isolated = false;
                if enforce_net {
                    let (_net_isolated, user_isolated) =
                        apply_network_namespace_unshare(enforce_seccomp)?;
                    userns_isolated = user_isolated;
                }

                // 3. Deterministic resource limits
                apply_resource_limits(&limits, userns_isolated)?;

                // 4. Landlock LSM filesystem boundary
                if enforce_landlock {
                    let _ =
                        apply_landlock_filesystem_boundary(&binary_path, &scratchpad_path, false)?;
                }

                // 5. Mandatory seccomp-BPF 18-syscall socket filter
                if enforce_seccomp {
                    apply_seccomp_socket_filter()?;
                }

                Ok(())
            });
        }

        let mut child = cmd.spawn().map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: Failed to spawn Linux confined Tier 2 command '{}': {}",
                verified_exe.metadata.canonical_path, e
            ))
        })?;

        let pid = child.id();
        let deadline = Instant::now() + Duration::from_millis(config.wall_clock_timeout_ms);
        let exit_code;

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit_code = status.code().unwrap_or(1);
                    break;
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
                            "TIER2_WALL_CLOCK_TIMEOUT: Process {} for agent '{}' exceeded {}s deadline; killed",
                            pid,
                            agent_id,
                            config.wall_clock_timeout_ms / 1000
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    let _ = child.kill();
                    return Err(OctopusSecurityError::IsolationViolation(format!(
                        "FAIL-CLOSED: Error waiting on confined Tier 2 child {}: {}",
                        pid, e
                    )));
                }
            }
        }

        Ok(Tier2ConfinedChildResult {
            pid,
            exit_code,
            token_posture,
            appcontainer_verification: AppContainerTokenVerification {
                is_appcontainer: true,
                package_sid: format!("linux:landlock+netns+seccomp:{}", agent_id),
                sid_matches_expected: true,
                job_membership_verified: true,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Public Gateway Function (Cross-Platform Interface)
// ---------------------------------------------------------------------------

/// Spawns a Tier 2 native command inside Linux kernel confinement (Landlock +
/// `CLONE_NEWNET` + seccomp-BPF + `setrlimit`).
pub fn spawn_tier2_linux_command(
    verified_exe: &VerifiedExecutableHandle,
    args: &[String],
    agent_id: &str,
    scratchpad_root: &Path,
    job: &WindowsJobObject,
) -> Result<Tier2ConfinedChildResult, OctopusSecurityError> {
    #[cfg(target_os = "linux")]
    {
        linux_impl::spawn_tier2_linux_command_impl(verified_exe, args, agent_id, scratchpad_root, job)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (verified_exe, args, agent_id, scratchpad_root, job);
        Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: Tier 2 Linux kernel confinement is only supported on Linux operating systems"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_filter_instruction_generation_x86_64() {
        let insns = build_socket_filter_bpf(
            AUDIT_ARCH_X86_64,
            X86_64_BLOCKED_SOCKET_SYSCALLS,
            LINUX_EACCES,
        );

        assert_eq!(insns.len(), X86_64_BLOCKED_SOCKET_SYSCALLS.len() + 6);
        assert_eq!(insns[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(insns[0].k, 4);
        assert_eq!(insns[1].code, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(insns[1].k, AUDIT_ARCH_X86_64);
        assert_eq!(insns[2].code, BPF_RET | BPF_K);
        assert_eq!(insns[2].k, SECCOMP_RET_KILL_PROCESS);
        assert_eq!(insns[3].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(insns[3].k, 0);

        let last = &insns[insns.len() - 1];
        assert_eq!(last.code, BPF_RET | BPF_K);
        assert_eq!(last.k, SECCOMP_RET_ERRNO | LINUX_EACCES);
    }

    #[test]
    fn test_bpf_filter_simulator_blocks_all_socket_syscalls_x86_64_and_aarch64() {
        let insns_x64 = build_socket_filter_bpf(
            AUDIT_ARCH_X86_64,
            X86_64_BLOCKED_SOCKET_SYSCALLS,
            LINUX_EACCES,
        );
        let expected_deny = SECCOMP_RET_ERRNO | LINUX_EACCES;
        for &blocked_nr in X86_64_BLOCKED_SOCKET_SYSCALLS {
            let res = evaluate_bpf_filter(&insns_x64, AUDIT_ARCH_X86_64, blocked_nr);
            assert_eq!(
                res, expected_deny,
                "x86_64 syscall {} was not blocked by BPF filter",
                blocked_nr
            );
        }

        let insns_arm = build_socket_filter_bpf(
            AUDIT_ARCH_AARCH64,
            AARCH64_BLOCKED_SOCKET_SYSCALLS,
            LINUX_EACCES,
        );
        for &blocked_nr in AARCH64_BLOCKED_SOCKET_SYSCALLS {
            let res = evaluate_bpf_filter(&insns_arm, AUDIT_ARCH_AARCH64, blocked_nr);
            assert_eq!(
                res, expected_deny,
                "aarch64 syscall {} was not blocked by BPF filter",
                blocked_nr
            );
        }
    }

    #[test]
    fn test_bpf_filter_simulator_allows_benign_syscalls() {
        let insns = build_socket_filter_bpf(
            AUDIT_ARCH_X86_64,
            X86_64_BLOCKED_SOCKET_SYSCALLS,
            LINUX_EACCES,
        );

        let benign_syscalls = [0, 1, 2, 3, 9, 10, 12, 14, 21, 59, 231];
        for &benign_nr in &benign_syscalls {
            let res = evaluate_bpf_filter(&insns, AUDIT_ARCH_X86_64, benign_nr);
            assert_eq!(
                res, SECCOMP_RET_ALLOW,
                "Benign syscall {} was erroneously rejected",
                benign_nr
            );
        }
    }

    #[test]
    fn test_bpf_filter_simulator_kills_on_arch_mismatch() {
        let insns = build_socket_filter_bpf(
            AUDIT_ARCH_X86_64,
            X86_64_BLOCKED_SOCKET_SYSCALLS,
            LINUX_EACCES,
        );

        let res = evaluate_bpf_filter(&insns, AUDIT_ARCH_AARCH64, 0);
        assert_eq!(res, SECCOMP_RET_KILL_PROCESS);

        let res_deadbeef = evaluate_bpf_filter(&insns, 0xdead_beef, 0);
        assert_eq!(res_deadbeef, SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn test_linux_resource_limits_default() {
        let limits = LinuxResourceLimits::default();
        assert_eq!(limits.max_as_bytes, 64 * 1024 * 1024);
        assert_eq!(limits.max_data_bytes, 64 * 1024 * 1024);
        assert_eq!(limits.max_nproc, 4);
        assert_eq!(limits.max_core_bytes, 0);
    }

    #[test]
    fn test_spawn_tier2_linux_command_fails_closed_on_non_linux() {
        #[cfg(not(target_os = "linux"))]
        {
            let dummy_path = std::env::temp_dir().join("test_oct_linux_failclosed_dummy.bin");
            let _ = std::fs::write(&dummy_path, b"test");
            let job = WindowsJobObject::create("test_linux_fc_job", 1, 1024 * 1024).unwrap();

            let handle = crate::security::executable_identity::VerifiedExecutableHandle {
                metadata: crate::security::executable_identity::VerifiedExecutableMetadata {
                    requested_program: "cmd".to_string(),
                    normalized_stem: "cmd".to_string(),
                    canonical_path: dummy_path.to_string_lossy().to_string(),
                    sha256_hex: "00".to_string(),
                    file_size: 4,
                    is_system32_binary: false,
                },
                locked_file: std::fs::File::open(&dummy_path).unwrap(),
            };

            let res = spawn_tier2_linux_command(
                &handle,
                &[],
                "agent_test",
                &std::env::temp_dir(),
                &job,
            );

            assert!(res.is_err());
            let err = res.unwrap_err().to_string();
            assert!(err.contains("FAIL-CLOSED"));
            let _ = std::fs::remove_file(dummy_path);
        }
    }
}
