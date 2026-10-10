use agent_octopus::arm::{KernelSentinelArm, KernelSentinelConfig};
use agent_octopus::core::types::ArmRole;
use agent_octopus::security::cedar_arm::CedarPolicyEngine;
use serde_json::json;

#[test]
fn test_kernel_sentinel_tier1_initialization() {
    let config = KernelSentinelConfig {
        job_name: "AgentOctopus.TestKernelJob".to_string(),
        max_active_processes: 1,
        max_memory_bytes: 64 * 1024 * 1024,
        enable_ring0_driver_bridge: false,
        driver_device_name: r"\\.\OsoosiDriver".to_string(),
        default_autonomy_mode: "Active".to_string(),
        assign_current_process: false,
    };

    let sentinel = KernelSentinelArm::new(config);
    assert_eq!(sentinel.role, ArmRole::KernelLevelSentinel);

    let stats = sentinel.stats();
    assert!(stats.tier1_active);
    assert_eq!(stats.job_name, "AgentOctopus.TestKernelJob");
    assert_eq!(stats.max_processes, 1);
    assert_eq!(stats.max_memory_bytes, 64 * 1024 * 1024);
    assert_eq!(stats.process_creation_vetos, 0);
    assert_eq!(stats.memory_limit_intercepts, 0);
    assert_eq!(stats.autotomy_hardware_kills, 0);
    assert!(stats.cedar_enforced);
    assert!(!stats.tier2_connected);
}

#[test]
fn test_kernel_sentinel_process_veto_and_memory_intercept() {
    let mut config = KernelSentinelConfig::default();
    config.assign_current_process = false;
    let sentinel = KernelSentinelArm::new(config);

    // Veto a simulated rogue PID
    let res = sentinel.veto_process_creation(999999, "Unauthorized child process spawn");
    assert!(res.is_ok());

    sentinel.record_memory_limit_intercept();
    sentinel.record_memory_limit_intercept();

    let stats = sentinel.stats();
    assert_eq!(stats.process_creation_vetos, 1);
    assert_eq!(stats.memory_limit_intercepts, 2);
}

#[test]
fn test_kernel_sentinel_autotomy_hardware_termination() {
    let mut config = KernelSentinelConfig::default();
    config.assign_current_process = false;
    let sentinel = KernelSentinelArm::new(config);
    let res = sentinel.trigger_hardware_autotomy();
    assert!(res.is_ok());

    let stats = sentinel.stats();
    assert_eq!(stats.autotomy_hardware_kills, 1);
}

#[test]
fn test_kernel_sentinel_cedar_policy_evaluation() {
    let engine = CedarPolicyEngine::new().expect("Failed to initialize CedarPolicyEngine");

    // 1. Authorized action: kernel_sentinel_arm performing kernel_enforce on KernelSubstrate
    let verdict = engine.evaluate(
        "kernel_sentinel_arm",
        "kernel_enforce",
        "hardware_clamps",
        "KernelSubstrate",
        json!({
            "enforcement_tier": "Ring0",
            "target_pid": 1234
        }),
    ).expect("Cedar evaluation failed");

    assert!(verdict.is_allowed, "kernel_sentinel_arm must be permitted to kernel_enforce");
    assert!(
        verdict.determining_policies.iter().any(|p| p.contains("policy5") || p.contains("6")),
        "Determining policies should include kernel sentinel policy: {:?}",
        verdict.determining_policies
    );

    // 2. Hostile/Unauthorized agent attempting kernel_enforce must be DENIED (default-deny)
    let hostile_verdict = engine.evaluate(
        "untrusted_doc_arm",
        "kernel_enforce",
        "hardware_clamps",
        "KernelSubstrate",
        json!({
            "enforcement_tier": "Ring0",
            "target_pid": 1234
        }),
    ).expect("Cedar evaluation failed");

    assert!(!hostile_verdict.is_allowed, "Hostile untrusted agent must be DENIED kernel_enforce");
}

#[test]
fn test_kernel_sentinel_driver_bridge_resilience() {
    // Probing driver when device is absent must NOT panic or error
    let mut config = KernelSentinelConfig::default();
    config.assign_current_process = false;
    let sentinel = KernelSentinelArm::new(config);
    let connected = sentinel.probe_ring0_driver();
    let stats = sentinel.stats();

    if connected {
        assert!(stats.tier2_connected);
        assert_eq!(stats.driver_status_label, "Active Ring-0 Driver Attached (Hardware ObRegisterCallbacks Pre-Op Enforcing)");
    } else {
        assert!(!stats.tier2_connected);
        assert_eq!(stats.driver_status_label, "Standby Native Job Substrate (Tier 1 Windows NT Job Object Enforcing)");
    }
}
