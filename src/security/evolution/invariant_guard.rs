use super::types::SecurityAuditResult;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SecurityInvariantGuard;

impl SecurityInvariantGuard {
    const FORBIDDEN_CALLS: &'static [&'static str] = &[
        "os.system", "system(", "popen(", "os.popen", "spawn(", "os.spawn", "fork(", "os.fork",
        "exec(", "eval(", "__import__(", "compile(", "ctypes", "winreg", "_winapi", "pty.", "commands.",
    ];

    const FORBIDDEN_MODULES: &'static [&'static str] = &[
        "subprocess", "shutil", "ctypes", "winreg", "_winapi", "socket.bind",
    ];

    const FORBIDDEN_ENV_MUTATIONS: &'static [&'static str] = &[
        "os.environ", "environ[", "environ.get", "set_var", "SetEnvironmentVariable",
    ];

    /// Performs static token and structural safety audit on candidate Python code.
    pub fn audit_code(code: &str) -> SecurityAuditResult {
        let mut violations = Vec::new();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Check line-by-line excluding comments
        for line in code.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            let code_part = if let Some(idx) = line.find('#') {
                line[..idx].trim()
            } else {
                trimmed
            };

            // Check imports
            if code_part.starts_with("import ") || code_part.starts_with("from ") {
                for &forbidden in Self::FORBIDDEN_MODULES {
                    if code_part.contains(forbidden) {
                        violations.push(format!("Forbidden import statement: '{}'", trimmed));
                    }
                }
            }

            // Check calls
            for &call in Self::FORBIDDEN_CALLS {
                if code_part.contains(call) {
                    violations.push(format!("Forbidden primitive or execution call: '{}'", call));
                }
            }

            // Check env mutations
            for &env_mut in Self::FORBIDDEN_ENV_MUTATIONS {
                if code_part.contains(env_mut) {
                    violations.push(format!("Forbidden environment access or mutation: '{}'", env_mut));
                }
            }
        }

        let passed = violations.is_empty();
        let tokens_count = code.split_whitespace().count();

        SecurityAuditResult {
            passed,
            violations,
            audited_tokens: tokens_count,
            audit_timestamp: timestamp,
        }
    }

    /// Verifies if a given module path is within the strictly whitelisted research scope.
    pub fn is_module_whitelisted(module_path: &str) -> bool {
        let normalized = module_path.replace('\\', "/");
        normalized.starts_with("vendor/rfchunt/permutator.py")
            || normalized.starts_with("vendor/rfchunt/anomaly_detector.py")
            || normalized.starts_with("vendor/rfchunt/engine/abnf_engine.py")
            || normalized.starts_with("data/evolution_staging/auto_remediation_patches.py")
            || normalized == "permutator"
            || normalized == "anomaly_detector"
            || normalized == "abnf_engine"
            || normalized == "auto_remediation"
            || normalized == "enclave_fallback_patch"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invariant_guard_rejects_subprocesses() {
        let code = r#"
import subprocess
def mutate(req):
    subprocess.Popen(["calc.exe"])
    return req
"#;
        let res = SecurityInvariantGuard::audit_code(code);
        assert!(!res.passed);
        assert!(res.violations.iter().any(|v| v.contains("subprocess")));
    }

    #[test]
    fn test_invariant_guard_rejects_environ_mutations() {
        let code = r#"
import os
def mutate(req):
    os.environ['PATH'] = 'hack'
    return req
"#;
        let res = SecurityInvariantGuard::audit_code(code);
        assert!(!res.passed);
        assert!(res.violations.iter().any(|v| v.contains("os.environ")));
    }

    #[test]
    fn test_invariant_guard_passes_safe_code() {
        let code = r#"
def generate_permutations(req):
    # Safe string mutation
    return [req.replace("Transfer-Encoding:", "Transfer-Encoding: gzip\r\nTransfer-Encoding:")]
"#;
        let res = SecurityInvariantGuard::audit_code(code);
        assert!(res.passed);
        assert!(res.violations.is_empty());
    }

    #[test]
    fn test_whitelist_validation() {
        assert!(SecurityInvariantGuard::is_module_whitelisted("vendor/rfchunt/permutator.py"));
        assert!(SecurityInvariantGuard::is_module_whitelisted("anomaly_detector"));
        assert!(!SecurityInvariantGuard::is_module_whitelisted("src/main.rs"));
        assert!(!SecurityInvariantGuard::is_module_whitelisted("src/security/cedar_arm/mod.rs"));
    }
}
