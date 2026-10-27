use crate::core::types::OctopusSecurityError;

/// Operating System and Process Sandbox Confinement Policy.
/// Enforces physical and execution boundaries beyond logical language-level enclaves.
#[derive(Debug, Clone)]
pub struct SandboxConfinementPolicy {
    pub max_child_processes: usize,
    pub allow_host_filesystem: bool,
    pub allow_raw_sockets: bool,
    pub allowed_file_prefixes: Vec<String>,
}

impl Default for SandboxConfinementPolicy {
    fn default() -> Self {
        Self {
            max_child_processes: 0,
            allow_host_filesystem: false,
            allow_raw_sockets: false,
            allowed_file_prefixes: vec![
                "s3://invoices/".to_string(),
                "s3://accounting/".to_string(),
                "sandbox://".to_string(),
            ],
        }
    }
}

impl SandboxConfinementPolicy {
    /// Validates that an agent is not attempting to spawn child processes, shell commands, or escape to the OS.
    pub fn validate_process_confinement(&self, command: &str) -> Result<(), OctopusSecurityError> {
        let lower = command.to_lowercase();
        let forbidden_commands = [
            "cmd.exe",
            "cmd ",
            "powershell",
            "pwsh",
            "bash",
            "sh ",
            "/bin/sh",
            "sh.exe",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
            "conhost",
            "taskkill",
            "net user",
            "reg add",
            "reg delete",
            "system(",
            "popen(",
            "fork(",
            "exec(",
            "spawn(",
            "process::",
            "std::process",
        ];

        for &forbidden in &forbidden_commands {
            if lower.contains(forbidden) {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "Process isolation boundary breach: attempt to spawn/invoke child process '{}' blocked (max_child_processes = 0)",
                    forbidden
                )));
            }
        }

        Ok(())
    }

    /// Validates that an agent cannot read or write to host filesystems, escape via path traversal, or touch system files.
    pub fn validate_filesystem_confinement(
        &self,
        target_path: &str,
    ) -> Result<(), OctopusSecurityError> {
        let lower = target_path.to_lowercase();

        // 1. Path traversal attacks (including single-dot or mixed percent-encoded traversal `%2e.` / `.%2e` and `%00`)
        if lower.contains("..")
            || lower.contains("%2e")
            || lower.contains("%00")
            || lower.contains("%2f")
            || lower.contains("%5c")
            || lower.contains("..\\")
            || lower.contains("../")
        {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "Directory traversal escape attempt '{}' blocked by filesystem sandbox",
                target_path
            )));
        }

        // 2. Sensitive OS paths and credentials
        let forbidden_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "c:\\windows",
            "c:\\users",
            "id_rsa",
            ".ssh",
            ".aws",
            ".env",
            "config\\sam",
            "config/sam",
            "system32",
            "\\pipe\\",
            "\\\\.\\",
            "/dev/",
            "/proc/",
            "/sys/",
        ];

        for &forbidden in &forbidden_paths {
            if lower.contains(forbidden) {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "Host filesystem access denied: target '{}' violates sandbox boundary",
                    target_path
                )));
            }
        }

        // 3. Prefix allowlist check
        if !self.allow_host_filesystem {
            let is_allowed = self
                .allowed_file_prefixes
                .iter()
                .any(|prefix| lower.starts_with(prefix));

            if !is_allowed
                && (lower.starts_with("file://") || lower.contains(":\\") || lower.starts_with("/"))
            {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "Unconfined filesystem path '{}' is outside authorized sandbox prefixes",
                    target_path
                )));
            }
        }

        Ok(())
    }
}
