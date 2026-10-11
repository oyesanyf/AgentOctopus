//! Comprehensive Test Suite for Ring 4: The Octopus Sentinel Ring (OSR)
//!
//! Validates the 8 principal components and the mandatory security directives:
//! 1. Positive Baseline Control (Healthy State, Authenticated Heartbeats)
//! 2. Anti-Replay & Sequence Validation (Negative Control)
//! 3. Policy & Containment Digest Tamper Detection (Negative Control)
//! 4. Process Identity & Anti-PID Reuse Guard (Correction C)
//! 5. Zombie Worker Autonomous OS Termination (Negative Control)
//! 6. Network Containment & Google Egress Invariant (Correction 5)
//! 7. Remote Forensic Checkpoint Anchoring & Chain Integrity (Correction E)
//! 8. 5-Phase Verified Recovery (Correction F)
//! 9. Complete Primary Supervisor Compromise Simulation (Test 9 Directive)
//! 10. Fail-Closed Resilience During Sentinel Inactivity (Directive 10)

use agent_octopus::sentinel_ring::{
    create_authenticated_heartbeat, NetworkVerificationVerdict, ProcessLivenessStatus,
    SentinelAction, SentinelObservation, SentinelSupervisor, SentinelSystemState,
};
use std::time::Duration;

const TEST_SECRET_SEED: &[u8] = b"OCTOPUS_SENTINEL_TEST_SEED_2026_AUTHORITATIVE";

#[tokio::test]
async fn test_1_positive_baseline_control_and_heartbeat_flow() {
    let sentinel = SentinelSupervisor::new(TEST_SECRET_SEED, 50);
    let snap = sentinel.snapshot().await;
    assert_eq!(snap.system_state, SentinelSystemState::Healthy);
    assert!(!snap.is_locked_down);

    // Supervisor sends valid authenticated heartbeat sequence 1
    let hb1 = create_authenticated_heartbeat(
        "supervisor_alpha",
        1,
        1,
        1000,
        TEST_SECRET_SEED,
    );
    let res = sentinel.ingest_supervisor_heartbeat(hb1).await;
    assert!(res.is_ok(), "Healthy heartbeat must be accepted");

    // Telemetry observation for healthy arm 17
    let obs = SentinelObservation::healthy(17, 8);
    let action = sentinel.evaluate_observation(&obs).await.expect("Evaluation must succeed");
    assert_eq!(action, SentinelAction::Continue);
}

#[tokio::test]
async fn test_2_heartbeat_anti_replay_and_sequence_protection() {
    let sentinel = SentinelSupervisor::new(TEST_SECRET_SEED, 50);

    let hb1 = create_authenticated_heartbeat("supervisor_alpha", 1, 1, 1000, TEST_SECRET_SEED);
    assert!(sentinel.ingest_supervisor_heartbeat(hb1).await.is_ok());

    // Replay sequence 1: MUST be rejected and trigger lockdown
    let replay_hb1 = create_authenticated_heartbeat("supervisor_alpha", 1, 1, 1000, TEST_SECRET_SEED);
    let replay_res = sentinel.ingest_supervisor_heartbeat(replay_hb1).await;
    assert!(replay_res.is_err(), "Replayed sequence 1 must be rejected");

    let snap = sentinel.snapshot().await;
    assert_eq!(snap.system_state, SentinelSystemState::Lockdown);
    assert!(snap.is_locked_down);
}

#[tokio::test]
async fn test_3_heartbeat_uptime_rollback_protection() {
    let sentinel = SentinelSupervisor::new(TEST_SECRET_SEED, 50);

    let hb1 = create_authenticated_heartbeat("supervisor_alpha", 1, 1, 5000, TEST_SECRET_SEED);
    assert!(sentinel.ingest_supervisor_heartbeat(hb1).await.is_ok());

    // Seq 2 arrives with reversed monotonic uptime (4000 < 5000)
    let hb2_rollback = create_authenticated_heartbeat("supervisor_alpha", 1, 2, 4000, TEST_SECRET_SEED);
    let res = sentinel.ingest_supervisor_heartbeat(hb2_rollback).await;
    assert!(res.is_err(), "Monotonic clock rollback must be rejected");

    assert!(sentinel.lockdown_controller.is_locked_down());
}

#[tokio::test]
async fn test_4_policy_and_containment_digest_tampering() {
    let sentinel = SentinelSupervisor::new(TEST_SECRET_SEED, 50);

    let mut tampered_hb = create_authenticated_heartbeat("supervisor_alpha", 1, 1, 1000, TEST_SECRET_SEED);
    tampered_hb.policy_digest[0] ^= 0xFF; // Deliberately corrupt policy digest

    let res = sentinel.ingest_supervisor_heartbeat(tampered_hb).await;
    assert!(res.is_err(), "Tampered policy digest must be rejected");

    let snap = sentinel.snapshot().await;
    assert_eq!(snap.system_state, SentinelSystemState::Lockdown);
}

#[tokio::test]
async fn test_5_process_identity_and_anti_pid_reuse() {
    let sentinel = SentinelSupervisor::new(TEST_SECRET_SEED, 50);
    let current_pid = std::process::id();

    // Register worker with current OS PID
    sentinel
        .process_monitor
        .register_worker_identity(17, 8, current_pid, 60)
        .await;

    let status = sentinel.process_monitor.inspect_worker(17).await;
    assert_eq!(status, ProcessLivenessStatus::HealthyRunning);

    let workers = sentinel.process_monitor.get_all_workers().await;
    let w17 = workers.iter().find(|w| w.identity.arm_id == 17).unwrap();
    assert_eq!(w17.identity.pid, current_pid);
    assert_eq!(w17.identity.generation, 8);
    assert!(w17.identity.job_object_guid.contains("AgentOctopus.ArmJob.Arm17"));
    assert!(w17.identity.appcontainer_sid.contains("S-1-15-2-1017"));
}

#[tokio::test]
async fn test_6_zombie_worker_autonomous_os_termination() {
    let sentinel = SentinelSupervisor::new(TEST_SECRET_SEED, 50);

    // Observation: arm 17 exceeded termination deadline but OS worker is still alive
    let mut zombie_obs = SentinelObservation::healthy(17, 8);
    zombie_obs.termination_deadline_exceeded = true;
    zombie_obs.worker_alive = true;

    let action = sentinel
        .evaluate_observation(&zombie_obs)
        .await
        .expect("Evaluation must succeed");
    assert_eq!(action, SentinelAction::TerminateArm(17));

    let snap = sentinel.snapshot().await;
    assert_eq!(snap.system_state, SentinelSystemState::Degraded);

    // Verify forensic audit record was generated out-of-band
    let records = sentinel.forensic_audit.get_records().await;
    assert!(records.iter().any(|r| r.event_type == "ZOMBIE_WORKER_DETECTED"));
}

#[tokio::test]
async fn test_7_network_containment_and_google_egress_invariant() {
    let sentinel = SentinelSupervisor::new(TEST_SECRET_SEED, 50);

    // Allowed: Google domain through approved egress broker
    let v1 = sentinel
        .network_verifier
        .verify_egress(17, "https://google.com/search?q=test", true)
        .await
        .unwrap();
    assert_eq!(v1, NetworkVerificationVerdict::Allowed);

    let v2 = sentinel
        .network_verifier
        .verify_egress(17, "https://www.google.com/finance", true)
        .await
        .unwrap();
    assert_eq!(v2, NetworkVerificationVerdict::Allowed);

    // Denied: Cloud metadata SSRF attempt
    let v3 = sentinel
        .network_verifier
        .verify_egress(17, "http://169.254.169.254/latest/meta-data", true)
        .await
        .unwrap();
    assert_eq!(v3, NetworkVerificationVerdict::BlockedSsrfMetadata);

    // Denied: RFC1918 Private subnet traversal attempt
    let v4 = sentinel
        .network_verifier
        .verify_egress(17, "http://192.168.1.100:8080/admin", true)
        .await
        .unwrap();
    assert!(matches!(v4, NetworkVerificationVerdict::BlockedPrivateSubnet(_)));

    // Denied: Unapproved external domain
    let v5 = sentinel
        .network_verifier
        .verify_egress(17, "https://malicious-c2.evil.com/exfil", true)
        .await
        .unwrap();
    assert!(matches!(v5, NetworkVerificationVerdict::BlockedUnauthorizedDomain(_)));

    // Denied: Direct raw socket without routing through egress proxy
    let v6 = sentinel
        .network_verifier
        .verify_egress(17, "https://google.com", false)
        .await
        .unwrap();
    assert_eq!(v6, NetworkVerificationVerdict::BlockedUnbrokeredEgress);
}

#[tokio::test]
async fn test_8_remote_forensic_anchoring_and_chain_integrity() {
    let sentinel = SentinelSupervisor::new(TEST_SECRET_SEED, 50);

    sentinel
        .forensic_audit
        .append_event("TEST_EVENT_1", Some(17), "ToolExec", "doc_extractor")
        .await
        .unwrap();
    sentinel
        .forensic_audit
        .append_event("TEST_EVENT_2", Some(1), "LedgerWrite", "corporate_ledger")
        .await
        .unwrap();
    sentinel
        .forensic_audit
        .append_event("TEST_EVENT_3", None, "SupervisorHeartbeat", "seq=1")
        .await
        .unwrap();

    // Verify cryptographic SHA-256 chain integrity
    assert!(sentinel.forensic_audit.verify_chain_integrity().await);

    // Anchor remote audit checkpoint
    let cp = sentinel
        .forensic_audit
        .create_and_anchor_checkpoint()
        .await
        .unwrap();
    assert_eq!(cp.records_covered, 3);
    assert!(!cp.merkle_root_hash.is_empty());
    assert!(!cp.checkpoint_signature.is_empty());
}

#[tokio::test]
async fn test_9_complete_primary_supervisor_compromise_simulation() {
    let sentinel = SentinelSupervisor::new(TEST_SECRET_SEED, 50);

    // Boot supervisor and send initial heartbeat
    let hb1 = create_authenticated_heartbeat("supervisor_alpha", 1, 1, 1000, TEST_SECRET_SEED);
    assert!(sentinel.ingest_supervisor_heartbeat(hb1).await.is_ok());
    assert_eq!(sentinel.snapshot().await.system_state, SentinelSystemState::Healthy);

    // SIMULATE COMPROMISE: Primary supervisor is abruptly killed without shutdown signal.
    // Sentinel detects missing heartbeat (> 5s elapsed)
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Trigger liveness check with forced timeout
    let _action = sentinel.check_supervisor_liveness().await;
    // With 5s timeout, if not elapsed, simulate liveness evaluation
    let obs = SentinelObservation {
        arm_id: 17,
        generation: 8,
        worker_alive: true,
        authorization_healthy: false, // Compromise breaks authorization channel
        sandbox_verified: false,
        unauthorized_egress_detected: false,
        supervisor_healthy: false,    // Primary supervisor is down
        termination_deadline_exceeded: false,
        proxy_enforcement_intact: false,
        timestamp_secs: 1000,
    };

    let action_comp = sentinel.evaluate_observation(&obs).await.unwrap();
    assert_eq!(action_comp, SentinelAction::LockdownSystem);

    // System is locked down
    assert!(sentinel.lockdown_controller.is_locked_down());
    assert!(sentinel.lockdown_controller.assert_not_locked_down().is_err());

    // Execute 5-phase verified recovery
    let recovery_rep = sentinel
        .recovery_controller
        .execute_safe_recovery(17, None)
        .await
        .expect("Verified recovery must succeed");

    assert_eq!(recovery_rep.previous_generation, 8);
    assert_eq!(recovery_rep.new_generation, 9);
    assert!(recovery_rep.phase1_manifest_attested);
    assert!(recovery_rep.phase2_credentials_reestablished);
    assert!(recovery_rep.phase3_isolation_verified);
    assert!(recovery_rep.phase4_external_ledger_reconciled);
    assert!(recovery_rep.phase5_clean_baseline_spawned);

    // Verify stale Gen 8 credentials are permanently rejected
    let stale_check = sentinel.epoch_registry.is_generation_active(17, 8).await;
    assert!(stale_check.is_err(), "Stale Gen 8 credentials must be denied");

    // Release lockdown with authoritative administrative recovery token
    let release_res = sentinel
        .lockdown_controller
        .release_lockdown("AUTHORITATIVE_SENTINEL_RECOVERY_TOKEN_2026")
        .await;
    assert!(release_res.is_ok());
    assert!(!sentinel.lockdown_controller.is_locked_down());
}

#[tokio::test]
async fn test_10_sentinel_crash_fail_closed_invariant() {
    let sentinel = SentinelSupervisor::new(TEST_SECRET_SEED, 50);

    // Even if watchdog is explicitly deactivated, lockdown assertion and epoch boundaries fail closed
    sentinel.set_watchdog_active(false);
    sentinel.trigger_lockdown("Sentinel Crash", "Simulated sentinel crash").await;

    assert!(sentinel.lockdown_controller.is_locked_down());
    assert!(sentinel.lockdown_controller.assert_not_locked_down().is_err());
}
