use crate::core::types::OctopusSecurityError;
use crate::security::windows_sandbox::WindowsJobObject;
use std::os::windows::io::AsRawHandle;
use std::process::{Command, Stdio};


pub struct PythonWorkerBridge {
    job_object: WindowsJobObject,
}

impl PythonWorkerBridge {
    pub fn start_worker() -> Result<Self, OctopusSecurityError> {
        let max_memory_bytes = 64 * 1024 * 1024; // 64 MB
        let job = WindowsJobObject::create("protocol_research_worker", 10, max_memory_bytes)?;

        // Spawn python worker
        let child = Command::new("python")
            .arg("mcp_server.py")
            .current_dir("d:\\harfile\\rfchunt")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        #[cfg(windows)]
        {
            let handle = child.as_raw_handle();
            job.assign_process(handle as _)?;
        }

        Ok(Self {
            job_object: job,
        })
    }
}
