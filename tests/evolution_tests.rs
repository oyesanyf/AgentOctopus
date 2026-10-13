use agent_octopus::containment_ring::ArmRingRegistry;
use agent_octopus::core::types::{ArmRole, OctopusSecurityError};
use agent_octopus::security::evolution::arm109::EvolutionaryOptimizerArm;
use agent_octopus::security::evolution::invariant_guard::SecurityInvariantGuard;
use agent_octopus::security::evolution::types::PromotionState;
use std::fs;
use std::sync::Arc;

#[test]
fn test_invariant_guard_ast_audit_safe_code() {
    let safe_code = r#"
def permute_rfc_boundary(headers, payload):
    """Mutate RFC headers safely without system side-effects."""
    mutated = dict(headers)
    if 'Transfer-Encoding' in mutated:
        mutated['Transfer-Encoding'] = mutated['Transfer-Encoding'] + ', chunked'
    return mutated, payload
"#;

    let audit = SecurityInvariantGuard::audit_code(safe_code);
    assert!(audit.passed, "Safe code must pass AST invariant audit");
    assert!(
        audit.violations.is_empty(),
        "No violations should be detected in safe code"
    );
    assert!(audit.audited_tokens > 0);
}

#[test]
fn test_invariant_guard_rejects_subprocess_command_injection() {
    let malicious_code = r#"
import subprocess

def exploit_boundary():
    """Attempt shell injection."""
    subprocess.run(["cmd.exe", "/c", "dir"])
"#;

    let audit = SecurityInvariantGuard::audit_code(malicious_code);
    assert!(!audit.passed, "Subprocess call must fail invariant audit");
    assert!(
        audit.violations.iter().any(|v| v.contains("subprocess")),
        "Violations must contain 'subprocess'"
    );
}

#[test]
fn test_invariant_guard_rejects_os_environ_mutation() {
    let malicious_code = r#"
import os

def tamper_environment():
    """Attempt to overwrite user/system PATH variable."""
    os.environ['PATH'] = 'C:\\temp'
"#;

    let audit = SecurityInvariantGuard::audit_code(malicious_code);
    assert!(!audit.passed, "os.environ access must fail invariant audit");
    assert!(
        audit.violations.iter().any(|v| v.contains("os.environ")),
        "Violations must detect os.environ"
    );
}

#[test]
fn test_invariant_guard_rejects_eval_and_exec() {
    let malicious_code = r#"
def arbitrary_exec(payload):
    eval("1 + 1")
    exec("import os")
"#;

    let audit = SecurityInvariantGuard::audit_code(malicious_code);
    assert!(!audit.passed, "eval and exec must fail invariant audit");
    assert!(
        audit.violations.iter().any(|v| v.contains("eval(") || v.contains("exec(")),
        "Violations must detect eval/exec"
    );
}

#[test]
fn test_invariant_guard_whitelisted_module_paths() {
    assert!(SecurityInvariantGuard::is_module_whitelisted("vendor/rfchunt/permutator.py"));
    assert!(SecurityInvariantGuard::is_module_whitelisted("vendor/rfchunt/anomaly_detector.py"));
    assert!(SecurityInvariantGuard::is_module_whitelisted("vendor/rfchunt/engine/abnf_engine.py"));
    assert!(SecurityInvariantGuard::is_module_whitelisted("permutator"));
    assert!(SecurityInvariantGuard::is_module_whitelisted("anomaly_detector"));
    assert!(SecurityInvariantGuard::is_module_whitelisted("abnf_engine"));

    // Forbidden paths: Rust core, Cedar policies, Cargo.toml
    assert!(!SecurityInvariantGuard::is_module_whitelisted("src/core/types.rs"));
    assert!(!SecurityInvariantGuard::is_module_whitelisted("config/cedar_policy.cedar"));
    assert!(!SecurityInvariantGuard::is_module_whitelisted("Cargo.toml"));
    assert!(!SecurityInvariantGuard::is_module_whitelisted("vendor/rfchunt/arbitrary_file.py"));
}

#[tokio::test]
async fn test_evolutionary_arm_staging_and_status() {
    let registry = Arc::new(ArmRingRegistry::new(50, b"test_seed_evolution_12345678901234567890"));
    let arm = EvolutionaryOptimizerArm::with_registry(&registry);

    let status = arm.get_status().await;
    assert_eq!(status.arm_id, 109);
    assert_eq!(status.role, "EvolutionaryOptimizer (Arm 109)");
    assert_eq!(status.is_severed, false);
    assert_eq!(status.is_contained, true);
    assert!(status.whitelisted_modules.contains(&"permutator".to_string()));
}

#[tokio::test]
async fn test_evolutionary_arm_evaluates_and_rejects_malicious_candidate() {
    let registry = Arc::new(ArmRingRegistry::new(50, b"test_seed_evolution_12345678901234567890"));
    let arm = EvolutionaryOptimizerArm::with_registry(&registry);

    let evil_code = "import subprocess\nsubprocess.Popen('calc.exe')\n";
    let res = arm.evaluate_code_snippet(evil_code, "permutator").await;

    // Must be vetoed with EvolutionaryVeto
    assert!(res.is_err(), "Evaluating malicious code must return error");
    match res.unwrap_err() {
        OctopusSecurityError::EvolutionaryVeto(msg) => {
            assert!(msg.contains("subprocess"));
        }
        other => panic!("Expected EvolutionaryVeto error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_human_in_the_loop_mandatory_gate_and_promotion_rollback() {
    let temp_dir = std::env::temp_dir().join(format!("octopus_evo_test_{}", std::process::id()));
    let _ = fs::create_dir_all(temp_dir.join("vendor").join("rfchunt"));
    let target_file = temp_dir.join("vendor").join("rfchunt").join("permutator.py");
    fs::write(&target_file, "# Original permutator baseline\ndef baseline(): pass\n").unwrap();

    let registry = Arc::new(ArmRingRegistry::new(50, b"test_seed_evolution_12345678901234567890"));
    let arm = EvolutionaryOptimizerArm::with_registry(&registry).with_workspace(temp_dir.clone());

    // 1. Evaluate safe candidate
    let safe_code = "# Evolved safe permutator\ndef evolved_boundary(): return True\n";
    let candidate = arm.evaluate_code_snippet(safe_code, "permutator").await
        .expect("Safe code evaluation must succeed");

    assert!(candidate.security_audit.passed);
    assert_eq!(candidate.promotion_state, PromotionState::QuarantinedPendingHitl);

    // 2. Approve & Promote candidate
    let promoted = arm.approve_promotion(&candidate.candidate_id).await
        .expect("HITL Promotion must succeed");

    assert_eq!(promoted.promotion_state, PromotionState::ApprovedActive);

    // Verify file content was atomically updated
    let current_content = fs::read_to_string(&target_file).unwrap();
    assert!(current_content.contains("def evolved_boundary"));

    // Verify backup (.bak) was created
    let backup_file = temp_dir.join("vendor").join("rfchunt").join("permutator.py.openevolve.bak");
    assert!(backup_file.exists(), "Backup file (.openevolve.bak) must exist after promotion");
    let backup_content = fs::read_to_string(&backup_file).unwrap();
    assert!(backup_content.contains("def baseline"));

    // 3. Rollback to backup
    let rollback_msg = arm.rollback("permutator").await
        .expect("Rollback must succeed");
    assert!(rollback_msg.contains("restored") || rollback_msg.contains("rolled back"));

    // Verify original content was restored
    let restored_content = fs::read_to_string(&target_file).unwrap();
    assert!(restored_content.contains("def baseline"));

    // Clean up temp test directory
    let _ = fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_arm109_containment_ring_autotomy_and_severance() {
    let registry = Arc::new(ArmRingRegistry::new(50, b"test_seed_evolution_12345678901234567890"));
    let arm_ring = registry.get_ring_sync(109).expect("Arm 109 ring must be registered");

    assert_eq!(arm_ring.role, ArmRole::EvolutionaryOptimizer);
    assert_eq!(arm_ring.arm_id, 109);
    assert!(!arm_ring.is_severed());

    // Trip autotomy circuit breaker
    arm_ring.sever("test autotomy").await;
    assert!(arm_ring.is_severed(), "Arm 109 ring must report severed after autotomy");
}
