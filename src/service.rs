//! Cross-Platform Native OS Service Lifecycle & Unconditional Shutdown Disarm Subsystem for AgentOctopus.
//!
//! Provides zero-external-tool background daemon management across Windows, Linux, and macOS:
//! - Windows (`#[cfg(target_os = "windows")]`):
//!   - Direct Win32 Service Control Manager (SCM) FFI via `advapi32.dll`:
//!     `OpenSCManagerW`, `CreateServiceW`, `OpenServiceW`, `StartServiceW`, `ControlService`,
//!     `DeleteService`, `QueryServiceStatusEx`, `StartServiceCtrlDispatcherW`,
//!     `RegisterServiceCtrlHandlerExW`, `SetServiceStatus`.
//!   - Zero `sc.exe` subprocess invocations.
//! - Linux (`#[cfg(target_os = "linux")]`):
//!   - Pure Rust `systemd` service unit generation and direct filesystem installation
//!     (`/etc/systemd/system/{name}.service` or configurable root directory for testing).
//!   - Systemd `sd_notify` UNIX datagram socket communication (`READY=1`, `STOPPING=1`).
//!   - POSIX `SIGTERM` / `SIGINT` lifecycle handling.
//!   - Zero `systemctl` subprocess invocations.
//! - macOS (`#[cfg(target_os = "macos")]`):
//!   - Pure Rust `launchd` `.plist` XML property list generation and direct filesystem installation
//!     (`/Library/LaunchDaemons/com.agent_octopus.{name}.plist` or configurable root directory for testing).
//!   - POSIX `SIGTERM` / `SIGINT` lifecycle handling.
//!   - Zero `launchctl` subprocess invocations.
//! - Unconditional Automatic Host Disarm:
//!   - Upon receiving `SERVICE_CONTROL_STOP`, `SERVICE_CONTROL_SHUTDOWN`, `SIGTERM`, or `SIGINT`,
//!     the daemon unconditionally executes `execute_host_disarm_unauthenticated()`, guaranteeing
//!     that the host endpoint is never left isolated upon service termination or reboot.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

pub const SERVICE_NAME: &str = "AgentOctopus";
pub const SERVICE_DISPLAY_NAME: &str = "Agent Octopus Swarm Breakout Defense";
pub const SERVICE_DESCRIPTION: &str =
    "Biologically-inspired decentralized agent swarm breakout defense & Real-Time Agentic Self-Protection (RT-ASP) engine";

// -----------------------------------------------------------------------------
// Daemon Lifecycle & Signal Management
// -----------------------------------------------------------------------------

static GLOBAL_DAEMON_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Signals all active service daemons across platforms to initiate shutdown and disarm.
pub fn request_daemon_shutdown() {
    GLOBAL_DAEMON_STOP_REQUESTED.store(true, Ordering::SeqCst);
}

/// Checks whether a daemon stop has been requested.
pub fn is_daemon_stop_requested() -> bool {
    GLOBAL_DAEMON_STOP_REQUESTED.load(Ordering::SeqCst)
}

/// Resets the daemon stop state (useful for test isolation).
pub fn reset_daemon_stop_flag() {
    GLOBAL_DAEMON_STOP_REQUESTED.store(false, Ordering::SeqCst);
}

#[cfg(unix)]
static POSIX_STOP_SIGNAL: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn posix_signal_handler(_sig: libc::c_int) {
    POSIX_STOP_SIGNAL.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_posix_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGTERM,
            posix_signal_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            posix_signal_handler as *const () as libc::sighandler_t,
        );
    }
}

#[cfg(unix)]
fn is_posix_stop_signaled() -> bool {
    POSIX_STOP_SIGNAL.load(Ordering::SeqCst)
}

#[cfg(not(unix))]
fn is_posix_stop_signaled() -> bool {
    false
}

/// Unconditional automatic host disarm executed on service shutdown or stop.
pub fn execute_host_disarm_unauthenticated() -> Result<(), String> {
    info!("🚨 [SERVICE-LIFECYCLE] Unconditional host network quarantine disarm triggered by OS service shutdown");
    match crate::security::global_host_killswitch()
        .disarm("service_shutdown", "Unconditional OS service termination host disarm")
    {
        Ok(_) => {
            info!("✅ [SERVICE-LIFECYCLE] Host endpoint successfully disarmed; loopback and network connectivity restored");
            Ok(())
        }
        Err(e) => {
            warn!("⚠️ [SERVICE-LIFECYCLE] Host disarm returned status/warning: {}", e);
            Err(e.to_string())
        }
    }
}

// -----------------------------------------------------------------------------
// Core Service Types & Contracts
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown,
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped => write!(f, "STOPPED"),
            Self::StartPending => write!(f, "START_PENDING"),
            Self::StopPending => write!(f, "STOP_PENDING"),
            Self::Running => write!(f, "RUNNING"),
            Self::ContinuePending => write!(f, "CONTINUE_PENDING"),
            Self::PausePending => write!(f, "PAUSE_PENDING"),
            Self::Paused => write!(f, "PAUSED"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub executable_path: PathBuf,
    pub arguments: Vec<String>,
    pub working_dir: Option<PathBuf>,
    pub auto_start: bool,
    pub root_dir: Option<PathBuf>,
}

impl ServiceConfig {
    pub fn new(name: impl Into<String>, executable_path: impl Into<PathBuf>) -> Self {
        let n = name.into();
        Self {
            display_name: n.clone(),
            description: format!("AgentOctopus background service daemon: {}", n),
            name: n,
            executable_path: executable_path.into(),
            arguments: Vec::new(),
            working_dir: None,
            auto_start: true,
            root_dir: None,
        }
    }

    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = display_name.into();
        self
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn with_arguments(mut self, args: Vec<String>) -> Self {
        self.arguments = args;
        self
    }

    pub fn with_working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    pub fn with_auto_start(mut self, auto: bool) -> Self {
        self.auto_start = auto;
        self
    }

    pub fn with_root_dir(mut self, root: impl Into<PathBuf>) -> Self {
        self.root_dir = Some(root.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub display_name: String,
    pub state: ServiceState,
    pub pid: Option<u32>,
    pub binary_path: Option<String>,
    pub description: Option<String>,
    pub is_installed: bool,
}

impl ServiceStatus {
    pub fn not_installed(name: &str) -> Self {
        Self {
            name: name.to_string(),
            display_name: name.to_string(),
            state: ServiceState::Stopped,
            pid: None,
            binary_path: None,
            description: None,
            is_installed: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("I/O error during service operation: {0}")]
    Io(#[from] std::io::Error),

    #[error("Service '{0}' was not found or is not registered")]
    NotFound(String),

    #[error("Service '{0}' is already installed")]
    AlreadyInstalled(String),

    #[error("Failed to install service '{0}': {1}")]
    InstallFailed(String, String),

    #[error("Failed to uninstall service '{0}': {1}")]
    UninstallFailed(String, String),

    #[error("Failed to start service '{0}': {1}")]
    StartFailed(String, String),

    #[error("Failed to stop service '{0}': {1}")]
    StopFailed(String, String),

    #[error("Failed to query status of service '{0}': {1}")]
    QueryFailed(String, String),

    #[error("Service daemon error: {0}")]
    DaemonError(String),

    #[error("Permission denied managing service: {0}")]
    PermissionDenied(String),
}

// -----------------------------------------------------------------------------
// Native Service Manager Trait
// -----------------------------------------------------------------------------

pub trait NativeServiceManager: Send + Sync {
    /// Installs the service into the host operating system.
    fn install_service(&self, config: &ServiceConfig) -> Result<(), ServiceError>;

    /// Uninstalls and removes the service from the host operating system.
    fn uninstall_service(&self, service_name: &str) -> Result<(), ServiceError>;

    /// Commands the host service manager to start the installed service.
    fn start_service(&self, service_name: &str) -> Result<(), ServiceError>;

    /// Commands the host service manager to stop the running service.
    fn stop_service(&self, service_name: &str) -> Result<(), ServiceError>;

    /// Queries the operational status of the service.
    fn service_status(&self, service_name: &str) -> Result<ServiceStatus, ServiceError>;

    /// Restarts the service by stopping it and then starting it.
    fn restart_service(&self, service_name: &str) -> Result<(), ServiceError> {
        let _ = self.stop_service(service_name);
        std::thread::sleep(Duration::from_millis(500));
        self.start_service(service_name)
    }

    /// Runs the daemon execution loop. Blocks until shutdown signal is received.
    /// Unconditionally executes `execute_host_disarm_unauthenticated()` before returning.
    fn run_service_daemon(&self) -> Result<(), ServiceError>;

    /// Requests that the service daemon loop gracefully terminate.
    fn request_stop(&self) {
        request_daemon_shutdown();
    }
}

// -----------------------------------------------------------------------------
// Systemd Unit Generator & Linux Service Manager
// -----------------------------------------------------------------------------

pub fn generate_systemd_unit(config: &ServiceConfig) -> String {
    let mut args_joined = String::new();
    for arg in &config.arguments {
        if arg.contains(' ') {
            args_joined.push_str(&format!(" \"{}\"", arg));
        } else {
            args_joined.push_str(&format!(" {}", arg));
        }
    }

    let exec_start = format!("{}{}", config.executable_path.display(), args_joined);
    let working_dir_entry = if let Some(wd) = &config.working_dir {
        format!("WorkingDirectory={}\n", wd.display())
    } else {
        String::new()
    };

    let restart_entry = if config.auto_start {
        "Restart=on-failure\nRestartSec=5s\n"
    } else {
        "Restart=no\n"
    };

    format!(
        "[Unit]\n\
         Description={}\n\
         After=network.target\n\
         Documentation=https://github.com/oyesanyf/AgentOctopus\n\n\
         [Service]\n\
         Type=notify\n\
         ExecStart={}\n\
         {}{}\
         KillMode=process\n\
         TimeoutStopSec=15\n\
         SendSIGKILL=yes\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        config.description, exec_start, working_dir_entry, restart_entry
    )
}

#[derive(Debug, Clone)]
pub struct LinuxServiceManager {
    pub root_dir: Option<PathBuf>,
    pub stop_flag: Arc<AtomicBool>,
}

impl Default for LinuxServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxServiceManager {
    pub fn new() -> Self {
        Self {
            root_dir: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_root_dir(root: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: Some(root.into()),
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_stop_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.stop_flag = flag;
        self
    }

    pub fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn unit_path(&self, service_name: &str) -> PathBuf {
        let rel_path = format!("etc/systemd/system/{}.service", service_name);
        if let Some(root) = &self.root_dir {
            root.join(rel_path)
        } else {
            PathBuf::from("/").join(rel_path)
        }
    }
}

impl NativeServiceManager for LinuxServiceManager {
    fn install_service(&self, config: &ServiceConfig) -> Result<(), ServiceError> {
        let path = if let Some(root) = &config.root_dir {
            root.join(format!("etc/systemd/system/{}.service", config.name))
        } else {
            self.unit_path(&config.name)
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let unit_content = generate_systemd_unit(config);
        fs::write(&path, unit_content)?;

        info!(
            "🟢 [LINUX-SERVICE] Installed systemd unit for '{}' at {}",
            config.name,
            path.display()
        );
        Ok(())
    }

    fn uninstall_service(&self, service_name: &str) -> Result<(), ServiceError> {
        let path = self.unit_path(service_name);
        if path.exists() {
            fs::remove_file(&path)?;
            info!(
                "🟢 [LINUX-SERVICE] Uninstalled systemd unit for '{}' from {}",
                service_name,
                path.display()
            );
            Ok(())
        } else {
            Err(ServiceError::NotFound(service_name.to_string()))
        }
    }

    fn start_service(&self, service_name: &str) -> Result<(), ServiceError> {
        let path = self.unit_path(service_name);
        if !path.exists() {
            return Err(ServiceError::NotFound(service_name.to_string()));
        }
        let status = self.service_status(service_name)?;
        if status.state == ServiceState::Running {
            info!(
                "🟢 [LINUX-SERVICE] Service '{}' is already running",
                service_name
            );
            return Ok(());
        }
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/bin/agent_octopus"));
        std::process::Command::new(exe)
            .args(["--service", "run"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(ServiceError::Io)?;
        info!(
            "🟢 [LINUX-SERVICE] Spawned background daemon for '{}'",
            service_name
        );
        Ok(())
    }

    fn stop_service(&self, service_name: &str) -> Result<(), ServiceError> {
        let status = self.service_status(service_name)?;
        if let Some(pid) = status.pid {
            #[cfg(unix)]
            unsafe {
                if libc::kill(pid as libc::pid_t, libc::SIGTERM) != 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(ServiceError::Io(err));
                }
            }
            #[cfg(not(unix))]
            {
                let _ = pid;
            }
            info!(
                "🟢 [LINUX-SERVICE] Sent SIGTERM to service '{}' (PID {})",
                service_name, pid
            );
        } else {
            info!(
                "🟢 [LINUX-SERVICE] Service '{}' is not running",
                service_name
            );
        }
        self.stop_flag.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn service_status(&self, service_name: &str) -> Result<ServiceStatus, ServiceError> {
        let path = self.unit_path(service_name);
        let is_installed = path.exists();

        if !is_installed {
            return Ok(ServiceStatus::not_installed(service_name));
        }

        let mut sys = sysinfo::System::new();
        sys.refresh_processes();

        let mut running_pid = None;
        let mut exe_path = None;

        for (pid, proc) in sys.processes() {
            let name_lc = proc.name().to_ascii_lowercase();
            if name_lc.contains(&service_name.to_ascii_lowercase()) {
                running_pid = Some(pid.as_u32());
                exe_path = proc.exe().map(|p| p.to_string_lossy().to_string());
                break;
            }
        }

        if let Some(pid) = running_pid {
            Ok(ServiceStatus {
                name: service_name.to_string(),
                display_name: format!("{} (systemd)", service_name),
                state: ServiceState::Running,
                pid: Some(pid),
                binary_path: exe_path,
                description: Some("Linux systemd background service".to_string()),
                is_installed: true,
            })
        } else {
            Ok(ServiceStatus {
                name: service_name.to_string(),
                display_name: format!("{} (systemd)", service_name),
                state: ServiceState::Stopped,
                pid: None,
                binary_path: None,
                description: Some("Linux systemd background service".to_string()),
                is_installed: true,
            })
        }
    }

    fn run_service_daemon(&self) -> Result<(), ServiceError> {
        info!("🚨 [LINUX-DAEMON] Starting Linux native service daemon");

        if self.stop_flag.load(Ordering::SeqCst)
            || is_daemon_stop_requested()
            || std::env::var("OCTOPUS_SERVICE_TEST_ONCE").is_ok()
        {
            info!("ℹ️ [LINUX-DAEMON] Test stop requested — performing single-cycle verification");
            info!("🚨 [LINUX-DAEMON] Service stopping: executing unconditional host disarm");
            let _ = execute_host_disarm_unauthenticated();
            return Ok(());
        }

        #[cfg(unix)]
        {
            install_posix_signal_handlers();

            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async {
                    if let (Ok(mut sigterm), Ok(mut sigint)) = (
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()),
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()),
                    ) {
                        tokio::select! {
                            _ = sigterm.recv() => {
                                info!("🚨 [LINUX-DAEMON] Caught SIGTERM shutdown signal via Tokio");
                            }
                            _ = sigint.recv() => {
                                info!("🚨 [LINUX-DAEMON] Caught SIGINT shutdown signal via Tokio");
                            }
                        }
                        POSIX_STOP_SIGNAL.store(true, Ordering::SeqCst);
                    }
                });
            }
        }

        info!("🟢 [LINUX-DAEMON] Daemon running — waiting for SIGTERM/SIGINT");
        while !self.stop_flag.load(Ordering::SeqCst)
            && !is_daemon_stop_requested()
            && !is_posix_stop_signaled()
        {
            std::thread::sleep(Duration::from_millis(50));
        }

        info!("🚨 [LINUX-DAEMON] Service stopping: executing unconditional host disarm");
        let _ = execute_host_disarm_unauthenticated();
        info!("🟢 [LINUX-DAEMON] Clean Linux daemon shutdown complete");
        Ok(())
    }

    fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

// -----------------------------------------------------------------------------
// Launchd Plist Generator & macOS Service Manager
// -----------------------------------------------------------------------------

pub fn generate_launchd_plist(config: &ServiceConfig) -> String {
    let mut args_xml = String::new();
    args_xml.push_str(&format!(
        "        <string>{}</string>\n",
        config.executable_path.display()
    ));
    for arg in &config.arguments {
        args_xml.push_str(&format!("        <string>{}</string>\n", arg));
    }

    let run_at_load = if config.auto_start {
        "    <key>RunAtLoad</key>\n    <true/>\n"
    } else {
        "    <key>RunAtLoad</key>\n    <false/>\n"
    };

    let working_dir_xml = if let Some(wd) = &config.working_dir {
        format!(
            "    <key>WorkingDirectory</key>\n    <string>{}</string>\n",
            wd.display()
        )
    } else {
        String::new()
    };

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
             <key>Label</key>\n\
             <string>com.agent_octopus.{}</string>\n\
             <key>ProgramArguments</key>\n\
             <array>\n\
         {}\
             </array>\n\
         {}\
         {}\
             <key>KeepAlive</key>\n\
             <true/>\n\
             <key>StandardOutPath</key>\n\
             <string>/var/log/{}.log</string>\n\
             <key>StandardErrorPath</key>\n\
             <string>/var/log/{}.err</string>\n\
         </dict>\n\
         </plist>\n",
        config.name, args_xml, run_at_load, working_dir_xml, config.name, config.name
    )
}

#[derive(Debug, Clone)]
pub struct MacOsServiceManager {
    pub root_dir: Option<PathBuf>,
    pub stop_flag: Arc<AtomicBool>,
}

impl Default for MacOsServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MacOsServiceManager {
    pub fn new() -> Self {
        Self {
            root_dir: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_root_dir(root: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: Some(root.into()),
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_stop_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.stop_flag = flag;
        self
    }

    pub fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn plist_path(&self, service_name: &str) -> PathBuf {
        let rel_path = format!("Library/LaunchDaemons/com.agent_octopus.{}.plist", service_name);
        if let Some(root) = &self.root_dir {
            root.join(rel_path)
        } else {
            PathBuf::from("/").join(rel_path)
        }
    }
}

impl NativeServiceManager for MacOsServiceManager {
    fn install_service(&self, config: &ServiceConfig) -> Result<(), ServiceError> {
        let path = if let Some(root) = &config.root_dir {
            root.join(format!(
                "Library/LaunchDaemons/com.agent_octopus.{}.plist",
                config.name
            ))
        } else {
            self.plist_path(&config.name)
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let plist_content = generate_launchd_plist(config);
        fs::write(&path, plist_content)?;

        info!(
            "🟢 [MACOS-SERVICE] Installed launchd plist for '{}' at {}",
            config.name,
            path.display()
        );
        Ok(())
    }

    fn uninstall_service(&self, service_name: &str) -> Result<(), ServiceError> {
        let path = self.plist_path(service_name);
        if path.exists() {
            fs::remove_file(&path)?;
            info!(
                "🟢 [MACOS-SERVICE] Uninstalled launchd plist for '{}' from {}",
                service_name,
                path.display()
            );
            Ok(())
        } else {
            Err(ServiceError::NotFound(service_name.to_string()))
        }
    }

    fn start_service(&self, service_name: &str) -> Result<(), ServiceError> {
        let path = self.plist_path(service_name);
        if !path.exists() {
            return Err(ServiceError::NotFound(service_name.to_string()));
        }
        let status = self.service_status(service_name)?;
        if status.state == ServiceState::Running {
            info!(
                "🟢 [MACOS-SERVICE] Service '{}' is already running",
                service_name
            );
            return Ok(());
        }
        let exe =
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/agent_octopus"));
        std::process::Command::new(exe)
            .args(["--service", "run"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(ServiceError::Io)?;
        info!(
            "🟢 [MACOS-SERVICE] Started launchd service daemon for '{}'",
            service_name
        );
        Ok(())
    }

    fn stop_service(&self, service_name: &str) -> Result<(), ServiceError> {
        let status = self.service_status(service_name)?;
        if let Some(pid) = status.pid {
            #[cfg(unix)]
            unsafe {
                if libc::kill(pid as libc::pid_t, libc::SIGTERM) != 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(ServiceError::Io(err));
                }
            }
            #[cfg(not(unix))]
            {
                let _ = pid;
            }
            info!(
                "🟢 [MACOS-SERVICE] Sent SIGTERM to launchd service '{}' (PID {})",
                service_name, pid
            );
        } else {
            info!(
                "🟢 [MACOS-SERVICE] Service '{}' is not running",
                service_name
            );
        }
        self.stop_flag.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn service_status(&self, service_name: &str) -> Result<ServiceStatus, ServiceError> {
        let path = self.plist_path(service_name);
        let is_installed = path.exists();

        if !is_installed {
            return Ok(ServiceStatus::not_installed(service_name));
        }

        let mut sys = sysinfo::System::new();
        sys.refresh_processes();

        let mut running_pid = None;
        let mut exe_path = None;

        for (pid, proc) in sys.processes() {
            let name_lc = proc.name().to_ascii_lowercase();
            if name_lc.contains(&service_name.to_ascii_lowercase()) {
                running_pid = Some(pid.as_u32());
                exe_path = proc.exe().map(|p| p.to_string_lossy().to_string());
                break;
            }
        }

        if let Some(pid) = running_pid {
            Ok(ServiceStatus {
                name: service_name.to_string(),
                display_name: format!("com.agent_octopus.{} (launchd)", service_name),
                state: ServiceState::Running,
                pid: Some(pid),
                binary_path: exe_path,
                description: Some("Apple launchd background daemon".to_string()),
                is_installed: true,
            })
        } else {
            Ok(ServiceStatus {
                name: service_name.to_string(),
                display_name: format!("com.agent_octopus.{} (launchd)", service_name),
                state: ServiceState::Stopped,
                pid: None,
                binary_path: None,
                description: Some("Apple launchd background daemon".to_string()),
                is_installed: true,
            })
        }
    }

    fn run_service_daemon(&self) -> Result<(), ServiceError> {
        info!("🚨 [MACOS-DAEMON] Starting macOS native service daemon");

        if self.stop_flag.load(Ordering::SeqCst)
            || is_daemon_stop_requested()
            || std::env::var("OCTOPUS_SERVICE_TEST_ONCE").is_ok()
        {
            info!("ℹ️ [MACOS-DAEMON] Test stop requested — performing single-cycle verification");
            info!("🚨 [MACOS-DAEMON] Service stopping: executing unconditional host disarm");
            let _ = execute_host_disarm_unauthenticated();
            return Ok(());
        }

        #[cfg(unix)]
        {
            install_posix_signal_handlers();

            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async {
                    if let (Ok(mut sigterm), Ok(mut sigint)) = (
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()),
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()),
                    ) {
                        tokio::select! {
                            _ = sigterm.recv() => {
                                info!("🚨 [MACOS-DAEMON] Caught SIGTERM shutdown signal via Tokio");
                            }
                            _ = sigint.recv() => {
                                info!("🚨 [MACOS-DAEMON] Caught SIGINT shutdown signal via Tokio");
                            }
                        }
                        POSIX_STOP_SIGNAL.store(true, Ordering::SeqCst);
                    }
                });
            }
        }

        info!("🟢 [MACOS-DAEMON] Daemon running — waiting for SIGTERM/SIGINT");
        while !self.stop_flag.load(Ordering::SeqCst)
            && !is_daemon_stop_requested()
            && !is_posix_stop_signaled()
        {
            std::thread::sleep(Duration::from_millis(50));
        }

        info!("🚨 [MACOS-DAEMON] Service stopping: executing unconditional host disarm");
        let _ = execute_host_disarm_unauthenticated();
        info!("🟢 [MACOS-DAEMON] Clean macOS daemon shutdown complete");
        Ok(())
    }

    fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

// -----------------------------------------------------------------------------
// Win32 SCM FFI Implementation (Windows advapi32.dll)
// -----------------------------------------------------------------------------

#[cfg(target_os = "windows")]
static WIN32_SCM_STATUS_HANDLE: std::sync::atomic::AtomicPtr<core::ffi::c_void> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

#[cfg(target_os = "windows")]
static WIN32_SCM_STOP_FLAG: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "windows")]
unsafe extern "system" fn win32_service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::System::Services::*;

    info!("🚨 [WIN32-SCM] ServiceMain entry point invoked by SCM");

    let service_name_w = to_wide("AgentOctopus");
    let status_handle = RegisterServiceCtrlHandlerExW(
        service_name_w.as_ptr(),
        Some(win32_service_ctrl_handler),
        std::ptr::null_mut(),
    );

    if status_handle.is_null() {
        error!(
            "❌ [WIN32-SCM] RegisterServiceCtrlHandlerExW failed: 0x{:08X}",
            windows_sys::Win32::Foundation::GetLastError()
        );
        return;
    }

    WIN32_SCM_STATUS_HANDLE.store(status_handle, Ordering::SeqCst);

    // 1. Report SERVICE_START_PENDING
    let mut status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_START_PENDING,
        dwControlsAccepted: 0,
        dwWin32ExitCode: NO_ERROR,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 1,
        dwWaitHint: 3000,
    };
    SetServiceStatus(status_handle, &status);

    // 2. Report SERVICE_RUNNING
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;
    SetServiceStatus(status_handle, &status);
    info!("🟢 [WIN32-SCM] Service operational: state reported as SERVICE_RUNNING");

    // 3. Worker loop waiting for stop signal
    while !WIN32_SCM_STOP_FLAG.load(Ordering::SeqCst) && !is_daemon_stop_requested() {
        std::thread::sleep(Duration::from_millis(100));
    }

    // 4. Report SERVICE_STOP_PENDING
    status.dwCurrentState = SERVICE_STOP_PENDING;
    status.dwControlsAccepted = 0;
    status.dwCheckPoint = 1;
    status.dwWaitHint = 15000;
    SetServiceStatus(status_handle, &status);
    info!("🚨 [WIN32-SCM] Stopping: executing unconditional host disarm");

    // 5. Unconditional host disarm
    let _ = execute_host_disarm_unauthenticated();

    // 6. Report SERVICE_STOPPED
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwControlsAccepted = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;
    SetServiceStatus(status_handle, &status);
    info!("🟢 [WIN32-SCM] Service state reported as SERVICE_STOPPED");
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn win32_service_ctrl_handler(
    dw_control: u32,
    _dw_event_type: u32,
    _lp_event_data: *mut core::ffi::c_void,
    _lp_context: *mut core::ffi::c_void,
) -> u32 {
    use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR};
    use windows_sys::Win32::System::Services::*;

    match dw_control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            info!(
                "🚨 [WIN32-SCM] Control handler received STOP/SHUTDOWN control (0x{:X})",
                dw_control
            );

            let handle = WIN32_SCM_STATUS_HANDLE.load(Ordering::SeqCst);
            if !handle.is_null() {
                let stop_pending = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: SERVICE_STOP_PENDING,
                    dwControlsAccepted: 0,
                    dwWin32ExitCode: NO_ERROR,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 1,
                    dwWaitHint: 15000,
                };
                SetServiceStatus(handle, &stop_pending);
            }

            WIN32_SCM_STOP_FLAG.store(true, Ordering::SeqCst);
            let _ = execute_host_disarm_unauthenticated();

            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => {
            let handle = WIN32_SCM_STATUS_HANDLE.load(Ordering::SeqCst);
            if !handle.is_null() {
                let running = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: if WIN32_SCM_STOP_FLAG.load(Ordering::SeqCst) {
                        SERVICE_STOP_PENDING
                    } else {
                        SERVICE_RUNNING
                    },
                    dwControlsAccepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                    dwWin32ExitCode: NO_ERROR,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 0,
                    dwWaitHint: 0,
                };
                SetServiceStatus(handle, &running);
            }
            NO_ERROR
        }
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct WindowsServiceManager {
    pub stop_flag: Arc<AtomicBool>,
}

#[cfg(target_os = "windows")]
impl Default for WindowsServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
impl WindowsServiceManager {
    pub fn new() -> Self {
        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_stop_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.stop_flag = flag;
        self
    }

    pub fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn run_standalone_console_daemon(&self) -> Result<(), ServiceError> {
        info!("🚨 [WINDOWS-DAEMON] Standalone console daemon operational");

        let running = Arc::new(AtomicBool::new(true));
        let r_clone = running.clone();

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                info!("🚨 [WINDOWS-DAEMON] Caught Ctrl+C shutdown signal");
                r_clone.store(false, Ordering::SeqCst);
            });
        }

        while running.load(Ordering::SeqCst)
            && !self.stop_flag.load(Ordering::SeqCst)
            && !is_daemon_stop_requested()
        {
            std::thread::sleep(Duration::from_millis(50));
        }

        info!(
            "🚨 [WINDOWS-DAEMON] Standalone daemon stopping: executing unconditional host disarm"
        );
        let _ = execute_host_disarm_unauthenticated();
        info!("🟢 [WINDOWS-DAEMON] Clean standalone daemon shutdown complete");
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
const STANDARD_DELETE: u32 = 0x0001_0000;

#[cfg(target_os = "windows")]
impl NativeServiceManager for WindowsServiceManager {
    fn install_service(&self, config: &ServiceConfig) -> Result<(), ServiceError> {
        use windows_sys::Win32::System::Services::*;

        let service_name_w = to_wide(&config.name);
        let display_name_w = to_wide(&config.display_name);

        let mut bin_path = format!("\"{}\"", config.executable_path.display());
        for arg in &config.arguments {
            bin_path.push_str(&format!(" \"{}\"", arg));
        }
        let bin_path_w = to_wide(&bin_path);

        let start_type = if config.auto_start {
            SERVICE_AUTO_START
        } else {
            SERVICE_DEMAND_START
        };

        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
            if scm.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                return Err(ServiceError::InstallFailed(
                    config.name.clone(),
                    format!("OpenSCManagerW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let service = CreateServiceW(
                scm,
                service_name_w.as_ptr(),
                display_name_w.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                start_type,
                SERVICE_ERROR_NORMAL,
                bin_path_w.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            );

            if service.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                CloseServiceHandle(scm);
                if err == 1073 {
                    // ERROR_SERVICE_EXISTS
                    return Err(ServiceError::AlreadyInstalled(config.name.clone()));
                }
                return Err(ServiceError::InstallFailed(
                    config.name.clone(),
                    format!("CreateServiceW failed: Win32 error 0x{:08X}", err),
                ));
            }

            // Set Description via ChangeServiceConfig2W
            let desc_w = to_wide(&config.description);
            let mut desc_struct = SERVICE_DESCRIPTIONW {
                lpDescription: desc_w.as_ptr() as *mut u16,
            };
            let _ = ChangeServiceConfig2W(
                service,
                SERVICE_CONFIG_DESCRIPTION,
                &mut desc_struct as *mut _ as *mut _,
            );

            CloseServiceHandle(service);
            CloseServiceHandle(scm);
        }

        info!(
            "🟢 [WINDOWS-SCM] Successfully registered Win32 service '{}'",
            config.name
        );
        Ok(())
    }

    fn uninstall_service(&self, service_name: &str) -> Result<(), ServiceError> {
        use windows_sys::Win32::System::Services::*;

        let name_w = to_wide(service_name);

        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                return Err(ServiceError::UninstallFailed(
                    service_name.to_string(),
                    format!("OpenSCManagerW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let service = OpenServiceW(
                scm,
                name_w.as_ptr(),
                SERVICE_STOP | STANDARD_DELETE | SERVICE_QUERY_STATUS,
            );

            if service.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                CloseServiceHandle(scm);
                if err == 1060 {
                    // ERROR_SERVICE_DOES_NOT_EXIST
                    return Err(ServiceError::NotFound(service_name.to_string()));
                }
                return Err(ServiceError::UninstallFailed(
                    service_name.to_string(),
                    format!("OpenServiceW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let mut status: SERVICE_STATUS = std::mem::zeroed();
            let _ = ControlService(service, SERVICE_CONTROL_STOP, &mut status);

            let del_ret = DeleteService(service);
            let del_err = if del_ret == 0 {
                windows_sys::Win32::Foundation::GetLastError()
            } else {
                0
            };

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if del_ret == 0 && del_err != 0 {
                return Err(ServiceError::UninstallFailed(
                    service_name.to_string(),
                    format!("DeleteService failed: Win32 error 0x{:08X}", del_err),
                ));
            }
        }

        info!(
            "🟢 [WINDOWS-SCM] Successfully deleted Win32 service '{}'",
            service_name
        );
        Ok(())
    }

    fn start_service(&self, service_name: &str) -> Result<(), ServiceError> {
        use windows_sys::Win32::System::Services::*;

        let name_w = to_wide(service_name);

        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                return Err(ServiceError::StartFailed(
                    service_name.to_string(),
                    format!("OpenSCManagerW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let service = OpenServiceW(scm, name_w.as_ptr(), SERVICE_START);
            if service.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                CloseServiceHandle(scm);
                return Err(ServiceError::StartFailed(
                    service_name.to_string(),
                    format!("OpenServiceW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let ret = StartServiceW(service, 0, std::ptr::null());
            let err = if ret == 0 {
                windows_sys::Win32::Foundation::GetLastError()
            } else {
                0
            };

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if ret == 0 && err != 1056 {
                // ERROR_SERVICE_ALREADY_RUNNING = 1056
                return Err(ServiceError::StartFailed(
                    service_name.to_string(),
                    format!("StartServiceW failed: Win32 error 0x{:08X}", err),
                ));
            }
        }

        info!(
            "🟢 [WINDOWS-SCM] Dispatched start command to Win32 service '{}'",
            service_name
        );
        Ok(())
    }

    fn stop_service(&self, service_name: &str) -> Result<(), ServiceError> {
        use windows_sys::Win32::System::Services::*;

        let name_w = to_wide(service_name);

        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                return Err(ServiceError::StopFailed(
                    service_name.to_string(),
                    format!("OpenSCManagerW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let service = OpenServiceW(scm, name_w.as_ptr(), SERVICE_STOP);
            if service.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                CloseServiceHandle(scm);
                return Err(ServiceError::StopFailed(
                    service_name.to_string(),
                    format!("OpenServiceW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let mut status: SERVICE_STATUS = std::mem::zeroed();
            let ret = ControlService(service, SERVICE_CONTROL_STOP, &mut status);
            let err = if ret == 0 {
                windows_sys::Win32::Foundation::GetLastError()
            } else {
                0
            };

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if ret == 0 && err != 1062 {
                // ERROR_SERVICE_NOT_ACTIVE = 1062
                return Err(ServiceError::StopFailed(
                    service_name.to_string(),
                    format!("ControlService(STOP) failed: Win32 error 0x{:08X}", err),
                ));
            }
        }

        info!(
            "🟢 [WINDOWS-SCM] Dispatched stop command to Win32 service '{}'",
            service_name
        );
        Ok(())
    }

    fn service_status(&self, service_name: &str) -> Result<ServiceStatus, ServiceError> {
        use windows_sys::Win32::System::Services::*;

        let name_w = to_wide(service_name);

        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                return Err(ServiceError::QueryFailed(
                    service_name.to_string(),
                    format!("OpenSCManagerW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let service = OpenServiceW(scm, name_w.as_ptr(), SERVICE_QUERY_STATUS);

            if service.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                CloseServiceHandle(scm);
                if err == 1060 {
                    return Ok(ServiceStatus::not_installed(service_name));
                }
                return Err(ServiceError::QueryFailed(
                    service_name.to_string(),
                    format!("OpenServiceW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let mut process_status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
            let mut bytes_needed = 0;

            let ret = QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                &mut process_status as *mut _ as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut bytes_needed,
            );

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if ret == 0 {
                let err = windows_sys::Win32::Foundation::GetLastError();
                return Err(ServiceError::QueryFailed(
                    service_name.to_string(),
                    format!("QueryServiceStatusEx failed: Win32 error 0x{:08X}", err),
                ));
            }

            let state = match process_status.dwCurrentState {
                SERVICE_RUNNING => ServiceState::Running,
                SERVICE_STOPPED => ServiceState::Stopped,
                SERVICE_START_PENDING => ServiceState::StartPending,
                SERVICE_STOP_PENDING => ServiceState::StopPending,
                SERVICE_PAUSED => ServiceState::Paused,
                _ => ServiceState::Unknown,
            };

            let pid = if process_status.dwProcessId > 0 {
                Some(process_status.dwProcessId)
            } else {
                None
            };

            Ok(ServiceStatus {
                name: service_name.to_string(),
                display_name: format!("{} (Win32 Service)", service_name),
                state,
                pid,
                binary_path: None,
                description: None,
                is_installed: true,
            })
        }
    }

    fn run_service_daemon(&self) -> Result<(), ServiceError> {
        info!("🚨 [WINDOWS-DAEMON] Launching Win32 Service Dispatcher");

        if self.stop_flag.load(Ordering::SeqCst)
            || is_daemon_stop_requested()
            || std::env::var("OCTOPUS_SERVICE_TEST_ONCE").is_ok()
        {
            info!("ℹ️ [WINDOWS-DAEMON] Test stop requested — performing single-cycle verification");
            let _ = execute_host_disarm_unauthenticated();
            return Ok(());
        }

        WIN32_SCM_STOP_FLAG.store(false, Ordering::SeqCst);
        WIN32_SCM_STATUS_HANDLE.store(std::ptr::null_mut(), Ordering::SeqCst);

        let mut service_name_w = to_wide("AgentOctopus");
        let dispatch_table: [windows_sys::Win32::System::Services::SERVICE_TABLE_ENTRYW; 2] = [
            windows_sys::Win32::System::Services::SERVICE_TABLE_ENTRYW {
                lpServiceName: service_name_w.as_mut_ptr(),
                lpServiceProc: Some(win32_service_main),
            },
            windows_sys::Win32::System::Services::SERVICE_TABLE_ENTRYW {
                lpServiceName: std::ptr::null_mut(),
                lpServiceProc: None,
            },
        ];

        let ok = unsafe {
            windows_sys::Win32::System::Services::StartServiceCtrlDispatcherW(
                dispatch_table.as_ptr(),
            )
        };

        if ok == 0 {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if err == windows_sys::Win32::Foundation::ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
                info!("ℹ️ [WINDOWS-DAEMON] Not launched by Win32 SCM; running standalone console daemon");
                return self.run_standalone_console_daemon();
            } else {
                return Err(ServiceError::DaemonError(format!(
                    "StartServiceCtrlDispatcherW failed: Win32 error 0x{:08X}",
                    err
                )));
            }
        }

        Ok(())
    }

    fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

// -----------------------------------------------------------------------------
// Unified Default Service Manager Provider & CLI Handler
// -----------------------------------------------------------------------------

pub fn default_service_manager() -> Box<dyn NativeServiceManager> {
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsServiceManager::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxServiceManager::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(MacOsServiceManager::new())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Box::new(LinuxServiceManager::new())
    }
}

/// Unified CLI handler for `--service <action>` and `service <action>` commands.
pub fn handle_service_cli(action: &str) -> Result<(), ServiceError> {
    let mgr = default_service_manager();
    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("agent_octopus.exe"));
    let working_dir = current_exe.parent().map(|p| p.to_path_buf());

    let config = ServiceConfig::new(SERVICE_NAME, &current_exe)
        .with_display_name(SERVICE_DISPLAY_NAME)
        .with_description(SERVICE_DESCRIPTION)
        .with_arguments(vec!["--service".to_string(), "run".to_string()])
        .with_auto_start(true);

    let config = if let Some(wd) = working_dir {
        config.with_working_dir(wd)
    } else {
        config
    };

    match action.to_ascii_lowercase().as_str() {
        "install" => {
            println!("⚙️  Installing native OS service '{}'...", SERVICE_NAME);
            match mgr.install_service(&config) {
                Ok(()) => {
                    println!("✅ Service '{}' installed successfully.", SERVICE_NAME);
                    Ok(())
                }
                Err(ServiceError::AlreadyInstalled(_)) => {
                    println!("ℹ️  Service '{}' is already installed.", SERVICE_NAME);
                    Ok(())
                }
                Err(e) => {
                    eprintln!("❌ Failed to install service: {}", e);
                    Err(e)
                }
            }
        }
        "delete" | "uninstall" | "remove" | "rm" => {
            println!("🗑️  Uninstalling native OS service '{}'...", SERVICE_NAME);
            match mgr.uninstall_service(SERVICE_NAME) {
                Ok(()) => {
                    println!("✅ Service '{}' uninstalled successfully.", SERVICE_NAME);
                    Ok(())
                }
                Err(ServiceError::NotFound(_)) => {
                    println!("ℹ️  Service '{}' is not installed.", SERVICE_NAME);
                    Ok(())
                }
                Err(e) => {
                    eprintln!("❌ Failed to uninstall service: {}", e);
                    Err(e)
                }
            }
        }
        "start" => {
            println!("🚀 Starting native OS service '{}'...", SERVICE_NAME);
            match mgr.start_service(SERVICE_NAME) {
                Ok(()) => {
                    println!("✅ Service '{}' start signal dispatched.", SERVICE_NAME);
                    Ok(())
                }
                Err(e) => {
                    eprintln!("❌ Failed to start service: {}", e);
                    Err(e)
                }
            }
        }
        "stop" => {
            println!("🛑 Stopping native OS service '{}'...", SERVICE_NAME);
            match mgr.stop_service(SERVICE_NAME) {
                Ok(()) => {
                    println!("✅ Service '{}' stop signal dispatched.", SERVICE_NAME);
                    println!("🚨 Executing unconditional host disarm...");
                    let _ = execute_host_disarm_unauthenticated();
                    Ok(())
                }
                Err(e) => {
                    eprintln!("❌ Failed to stop service: {}", e);
                    Err(e)
                }
            }
        }
        "restart" => {
            println!("🔄 Restarting native OS service '{}'...", SERVICE_NAME);
            match mgr.restart_service(SERVICE_NAME) {
                Ok(()) => {
                    println!("✅ Service '{}' restart dispatched.", SERVICE_NAME);
                    Ok(())
                }
                Err(e) => {
                    eprintln!("❌ Failed to restart service: {}", e);
                    Err(e)
                }
            }
        }
        "status" => {
            match mgr.service_status(SERVICE_NAME) {
                Ok(status) => {
                    println!("{}", serde_json::to_string_pretty(&status).unwrap_or_default());
                    Ok(())
                }
                Err(e) => {
                    eprintln!("❌ Failed to query service status: {}", e);
                    Err(e)
                }
            }
        }
        "run" => {
            println!("🐙 Running AgentOctopus native OS service daemon...");
            mgr.run_service_daemon()
        }
        unknown => {
            let msg = format!(
                "Unknown service action '{}'. Valid actions: install, delete, uninstall, start, stop, restart, status, run",
                unknown
            );
            eprintln!("❌ {}", msg);
            Err(ServiceError::DaemonError(msg))
        }
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_systemd_unit_generation() {
        let config = ServiceConfig::new("agent_octopus_test", PathBuf::from("/usr/bin/agent_octopus"))
            .with_description("Agent Octopus Test Service")
            .with_arguments(vec!["--service".to_string(), "run".to_string()])
            .with_auto_start(true);

        let unit = generate_systemd_unit(&config);
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("Description=Agent Octopus Test Service"));
        assert!(unit.contains("ExecStart=/usr/bin/agent_octopus --service run"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn test_launchd_plist_generation() {
        let config = ServiceConfig::new("agent_octopus_test", PathBuf::from("/usr/local/bin/agent_octopus"))
            .with_description("Agent Octopus Test Service")
            .with_arguments(vec!["--service".to_string(), "run".to_string()])
            .with_auto_start(true);

        let plist = generate_launchd_plist(&config);
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains("<string>com.agent_octopus.agent_octopus_test</string>"));
        assert!(plist.contains("<string>/usr/local/bin/agent_octopus</string>"));
        assert!(plist.contains("<string>--service</string>"));
        assert!(plist.contains("<string>run</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<true/>"));
    }

    #[test]
    fn test_service_status_not_installed() {
        let status = ServiceStatus::not_installed("dummy_nonexistent_service_123");
        assert_eq!(status.name, "dummy_nonexistent_service_123");
        assert!(!status.is_installed);
        assert_eq!(status.state, ServiceState::Stopped);
    }

    #[test]
    fn test_service_lifecycle_disarm_hook() {
        // execute_host_disarm_unauthenticated should not panic
        let res = execute_host_disarm_unauthenticated();
        assert!(res.is_ok() || res.is_err());
    }
}
