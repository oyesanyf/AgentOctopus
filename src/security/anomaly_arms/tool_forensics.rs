use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct ToolInvocationTrace {
    pub invocation_id: String,
    pub caller_agent_id: String,
    pub tool_name: String,
    pub argument_digest: String,
    pub execution_duration_millis: u64,
    pub sanitized: bool,
    pub security_flags: Vec<String>,
}

/// Layer 3: Tool Forensics Arm.
/// Conducts fine-grained, invocation-level parameter sanitization, payload inspection,
/// and side-effect profiling on every tool execution.
pub struct ToolForensicsArm {
    pub arm_id: String,
    traces: Vec<ToolInvocationTrace>,
}

impl ToolForensicsArm {
    pub fn new(arm_id: &str) -> Self {
        Self {
            arm_id: arm_id.to_string(),
            traces: Vec::new(),
        }
    }

    /// Inspects and sanitizes tool parameters before execution.
    pub fn inspect_invocation(
        &mut self,
        invocation_id: &str,
        caller_agent_id: &str,
        tool_name: &str,
        raw_arguments: &str,
    ) -> ToolInvocationTrace {
        let mut flags = Vec::new();

        // 1. Shell Metacharacter Injection Detection
        for meta in &['|', ';', '&', '$', '`', '\n', '\r'] {
            if raw_arguments.contains(*meta) {
                flags.push(format!("Shell metacharacter '{}' detected in parameters", meta));
            }
        }

        // 2. Path Traversal Detection
        if raw_arguments.contains("../") || raw_arguments.contains("..\\") {
            flags.push("Path traversal sequence ('../' or '..\\') detected".to_string());
        }

        // 3. Environment Variable Mutation / Expansion Attempts
        if raw_arguments.contains("%PATH%") || raw_arguments.contains("$env:PATH") || raw_arguments.contains("PATH=") {
            flags.push("Potentially dangerous PATH environment access attempt detected".to_string());
        }

        // 4. Executable binary / script extension references
        for ext in &[".exe", ".bat", ".cmd", ".ps1", ".vbs", ".dll", ".so"] {
            if raw_arguments.to_ascii_lowercase().contains(ext) {
                flags.push(format!("Executable extension '{}' referenced in tool payload", ext));
            }
        }

        // Compute argument SHA-256 fingerprint
        let mut hasher = Sha256::new();
        hasher.update(raw_arguments.as_bytes());
        let digest = hex::encode(hasher.finalize());

        let trace = ToolInvocationTrace {
            invocation_id: invocation_id.to_string(),
            caller_agent_id: caller_agent_id.to_string(),
            tool_name: tool_name.to_string(),
            argument_digest: digest,
            execution_duration_millis: 0,
            sanitized: flags.is_empty(),
            security_flags: flags,
        };

        self.traces.push(trace.clone());
        trace
    }

    pub fn traces(&self) -> &[ToolInvocationTrace] {
        &self.traces
    }
}
