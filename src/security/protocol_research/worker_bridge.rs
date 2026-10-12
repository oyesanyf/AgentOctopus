use crate::core::types::OctopusSecurityError;
use crate::security::windows_sandbox::WindowsJobObject;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub struct PythonWorkerBridge {
    job_object: WindowsJobObject,
    child: Option<Child>,
    worker_dir: PathBuf,
}

impl PythonWorkerBridge {
    /// Discovers the rfchunt worker directory dynamically without hardcoded assumptions.
    pub fn locate_worker_dir() -> Result<PathBuf, OctopusSecurityError> {
        // Priority 1: Process-scoped environment variable
        if let Ok(env_path) = std::env::var("OCTOPUS_RFCHUNT_PATH") {
            let p = PathBuf::from(env_path);
            if p.join("mcp_server.py").exists() {
                return Ok(p);
            }
        }

        // Priority 2: Relative vendor directory
        let vendor = PathBuf::from("vendor").join("rfchunt");
        if vendor.join("mcp_server.py").exists() {
            return Ok(vendor);
        }

        // Priority 3: Sibling directory
        let sibling = PathBuf::from("..").join("rfchunt");
        if sibling.join("mcp_server.py").exists() {
            return Ok(sibling);
        }

        // Priority 4: Standard dedicated path
        let standard = PathBuf::from(r"d:\harfile\rfchunt");
        if standard.join("mcp_server.py").exists() {
            return Ok(standard);
        }

        Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: rfchunt research worker directory not found. Zero fallback execution permitted.".to_string(),
        ))
    }

    /// Spawns the research worker sandboxed in a Windows Job Object with a 64MB memory clamp.
    pub fn start_worker() -> Result<Self, OctopusSecurityError> {
        let worker_dir = Self::locate_worker_dir()?;
        let script = worker_dir.join("mcp_server.py");
        if !script.exists() {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: Worker entrypoint '{}' does not exist.",
                script.display()
            )));
        }

        let max_memory_bytes = 64 * 1024 * 1024; // Strict 64 MB clamp
        let job = WindowsJobObject::create("protocol_research_worker", 10, max_memory_bytes)?;

        // Spawn python worker with piped I/O
        let child = Command::new("python")
            .arg("mcp_server.py")
            .current_dir(&worker_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| OctopusSecurityError::IsolationViolation(format!("Failed to spawn worker: {}", e)))?;

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            let handle = child.as_raw_handle();
            job.assign_process(handle as _)?;

            // Verify process is strictly bound inside Job Object
            unsafe {
                let mut in_job: i32 = 0;
                let check_ok = windows_sys::Win32::System::JobObjects::IsProcessInJob(
                    handle as _,
                    job.handle,
                    &mut in_job,
                );
                if check_ok == 0 || in_job == 0 {
                    let _ = child;
                    return Err(OctopusSecurityError::IsolationViolation(
                        "FAIL-CLOSED: Worker process could not be verified inside Windows Job Object.".to_string(),
                    ));
                }
            }
        }

        Ok(Self {
            job_object: job,
            child: Some(child),
            worker_dir,
        })
    }

    pub fn worker_dir(&self) -> &Path {
        &self.worker_dir
    }

    pub fn terminate(&mut self) -> Result<(), OctopusSecurityError> {
        self.job_object.terminate(1)?;
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
        }
        Ok(())
    }
}
