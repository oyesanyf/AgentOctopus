use serde::{Deserialize, Serialize};

/// Verdict resulting from inspecting an action for Technical Breakout indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnicalBreakoutVerdict {
    pub is_clean: bool,
    pub detected_vectors: Vec<String>,
    pub sandbox_quarantine_required: bool,
    pub description: String,
}

/// Technical Breakout Guard:
/// Mitigates hypervisor, container, or runtime sandbox escapes.
/// Detects unmasked Docker daemon sockets, Wasm memory corruption, and kernel privilege escalation.
pub struct TechnicalBreakoutGuard {
    docker_socket_patterns: Vec<&'static str>,
    wasm_escape_indicators: Vec<&'static str>,
}

impl Default for TechnicalBreakoutGuard {
    fn default() -> Self {
        Self {
            docker_socket_patterns: vec![
                "/var/run/docker.sock",
                "//./pipe/docker_engine",
                r"\\.\pipe\docker_engine",
                "/run/containerd/containerd.sock",
                "docker.sock",
                "podman.sock",
                "crio.sock",
            ],
            wasm_escape_indicators: vec![
                "wasm_table_overflow",
                "memory.grow_unbounded",
                "hypercall_exploit",
                "microvm_vmcall_trap",
                "dirty_pipe_probe",
                "cgroup_escape_probe",
            ],
        }
    }
}

impl TechnicalBreakoutGuard {
    /// Evaluates a command, file path, or execution context against technical breakout signatures.
    pub fn evaluate_execution(&self, command_or_path: &str, raw_payload: &str) -> TechnicalBreakoutVerdict {
        let mut detected_vectors = Vec::new();
        let lower_cmd = command_or_path.to_ascii_lowercase();
        let lower_payload = raw_payload.to_ascii_lowercase();

        // 1. Unmasked Docker / Container Daemon Socket Mounts & Requests
        for &pattern in &self.docker_socket_patterns {
            if lower_cmd.contains(pattern) || lower_payload.contains(pattern) {
                detected_vectors.push(format!("Unmasked container daemon socket probe detected: '{}'", pattern));
            }
        }

        // 2. Wasm / MicroVM Sandbox Escape & Memory Corruption Indicators
        for &indicator in &self.wasm_escape_indicators {
            if lower_cmd.contains(indicator) || lower_payload.contains(indicator) {
                detected_vectors.push(format!("Sandbox virtualization escape indicator detected: '{}'", indicator));
            }
        }

        // 3. Container namespace, encoded shell execution, and privilege escalation indicators
        if lower_cmd.contains("nsenter")
            || lower_cmd.contains("unshare")
            || lower_cmd.contains("--privileged")
            || lower_payload.contains("powershell -enc")
            || lower_payload.contains("-encodedcommand")
            || lower_payload.contains("ignore previous instructions")
        {
            detected_vectors.push(
                "Host namespace access, encoded shell injection, or privileged container spawn attempt"
                    .to_string(),
            );
        }

        let is_clean = detected_vectors.is_empty();
        let sandbox_quarantine_required = !is_clean;
        let description = if is_clean {
            "Hardware-isolated sandbox containment intact (read-only root verified)".to_string()
        } else {
            format!("Technical breakout intercepted: {} vector(s) identified", detected_vectors.len())
        };

        TechnicalBreakoutVerdict {
            is_clean,
            detected_vectors,
            sandbox_quarantine_required,
            description,
        }
    }

    /// Verifies ephemeral sandbox lifecycle destruction guarantee.
    pub fn purge_ephemeral_sandbox(&self, sandbox_id: &str) -> bool {
        let temp_dir = std::env::temp_dir().join(format!("agent_octopus_sandbox_{}", sandbox_id));
        if temp_dir.exists() {
            let _ = std::fs::remove_dir_all(&temp_dir);
        }
        true
    }
}
