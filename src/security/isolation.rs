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

        // 2. Sensitive OS paths and credential stores (system + developer/cloud/profile stores)
        if let Some(store_kind) =
            crate::security::sensitive_paths::classify_sensitive_system_path(target_path)
        {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "Host credential store access denied ({}): target '{}' violates sandbox boundary",
                store_kind.description(),
                target_path
            )));
        }

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

    /// Validates write/create/modify access against mandatory auto-protected workspace files
    /// (`.git/hooks`, `.git/config`, `.bashrc`, `.mcp.json`, `.vscode`, `.claude/commands`),
    /// which remain protected even inside writable working directories.
    pub fn validate_filesystem_write_confinement(
        &self,
        target_path: &str,
    ) -> Result<(), OctopusSecurityError> {
        self.validate_filesystem_confinement(target_path)?;
        if let Some(kind) =
            crate::security::sensitive_paths::classify_mandatory_write_deny_path(target_path)
        {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "{}: write to '{}' blocked by mandatory auto-protection",
                kind.description(),
                target_path
            )));
        }
        Ok(())
    }

    /// Validates directory rename/delete mutations, enforcing pinned-parent / `FILE_DELETE_CHILD`
    /// protection so attackers cannot move `.git`, `.vscode`, `.idea`, or `.claude` aside.
    pub fn validate_directory_mutation_confinement(
        &self,
        dir_path: &str,
    ) -> Result<(), OctopusSecurityError> {
        self.validate_filesystem_confinement(dir_path)?;
        if let Some(kind) =
            crate::security::sensitive_paths::classify_pinned_parent_for_write_deny(dir_path)
        {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "{}: mutation/unlink of pinned ancestor directory '{}' blocked",
                kind.description(),
                dir_path
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_and_pinned_parent_confinement_blocks_auto_protected_paths() {
        let mut policy = SandboxConfinementPolicy::default();
        policy.allow_host_filesystem = true;

        assert!(policy
            .validate_filesystem_write_confinement("src/lib.rs")
            .is_ok());
        assert!(policy
            .validate_filesystem_write_confinement(".git/hooks/pre-commit")
            .is_err());
        assert!(policy
            .validate_filesystem_write_confinement(".mcp.json")
            .is_err());
        assert!(policy
            .validate_filesystem_write_confinement("~/.zshrc")
            .is_err());
        assert!(policy
            .validate_filesystem_write_confinement(".vscode/settings.json")
            .is_err());
        assert!(policy
            .validate_directory_mutation_confinement(".git")
            .is_err());
        assert!(policy
            .validate_directory_mutation_confinement(".claude")
            .is_err());
    }
}
