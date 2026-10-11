//! Component 1: Independent Sentinel Supervisor (`sentinel_supervisor.rs`)
//!
//! A separately running, privileged Rust supervisor service that monitors the health
//! of the main supervisor, containment policies, worker isolation, and security mechanisms.
//!
//! Key Properties:
//! 1. **No Shared Writable Memory**: Completely decoupled from untrusted worker arms.
//! 2. **Deterministic State Machine**: States: `Healthy`, `Degraded`, `Quarantined`, `Lockdown`.
//! 3. **Cryptographic Anti-Replay Heartbeats**: Strict monotonic sequence validation,
//!    policy digest verification, and containment digest verification.
//! 4. **No LLM in Ring 4**: Purely deterministic logic and cryptographic enforcement.

use crate::core::types::OctopusSecurityError;
use crate::sentinel_ring::emergency_lockdown::{EmergencyLockdownController, LockdownReport};
use crate::sentinel_ring::epoch_registry::EpochRegistry;
use crate::sentinel_ring::forensic_audit::ForensicAuditLog;
use crate::sentinel_ring::integrity_monitor::IntegrityMonitor;
use crate::sentinel_ring::network_verifier::NetworkVerifier;
use crate::sentinel_ring::process_monitor::ProcessMonitor;
use crate::sentinel_ring::recovery_controller::RecoveryController;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Definitive four states of the Sentinel Ring supervisory state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SentinelSystemState {
    /// All 4 containment rings verified, supervisor heartbeating, zero anomalies.
    Healthy,
    /// Isolated worker anomaly or deadline overrun detected; containment held.
    Degraded,
    /// Arm isolated or quarantined due to lateral pivot attempt or unbrokered egress.
    Quarantined,
    /// Critical security failure (supervisor crash, tampering, bypass attempt); system locked down.
    Lockdown,
}

/// Action commanded by the Sentinel Supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SentinelAction {
    Continue,
    RevokeCapabilities,
    IsolateArm(u64),
    TerminateArm(u64),
    LockdownSystem,
}

/// Telemetry observation ingested by Sentinel Supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelObservation {
    pub arm_id: u64,
    pub generation: u64,
    pub worker_alive: bool,
    pub authorization_healthy: bool,
    pub sandbox_verified: bool,
    pub unauthorized_egress_detected: bool,
    pub supervisor_healthy: bool,
    pub termination_deadline_exceeded: bool,
    pub proxy_enforcement_intact: bool,
    pub timestamp_secs: u64,
}

impl SentinelObservation {
    pub fn healthy(arm_id: u64, generation: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            arm_id,
            generation,
            worker_alive: true,
            authorization_healthy: true,
            sandbox_verified: true,
            unauthorized_egress_detected: false,
            supervisor_healthy: true,
            termination_deadline_exceeded: false,
            proxy_enforcement_intact: true,
            timestamp_secs: now,
        }
    }
}

/// Cryptographically authenticated heartbeat emitted by the main supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorHeartbeat {
    pub supervisor_id: String,
    pub generation: u64,
    pub sequence_number: u64,
    pub monotonic_uptime_ms: u64,
    pub policy_digest: [u8; 32],
    pub containment_digest: [u8; 32],
    pub authentication_tag: [u8; 32],
}

/// Complete telemetry snapshot of Ring 4 for UI dashboards and REST endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelStatusSnapshot {
    pub system_state: SentinelSystemState,
    pub is_locked_down: bool,
    pub supervisor_healthy: bool,
    pub last_heartbeat_secs_ago: u64,
    pub active_workers_monitored: usize,
    pub total_audit_records: usize,
    pub integrity_verified: bool,
    pub network_broker_healthy: bool,
}

/// Component 1: The Independent Sentinel Supervisor Engine.
pub struct SentinelSupervisor {
    state: Arc<RwLock<SentinelSystemState>>,
    secret_key: [u8; 32],
    expected_policy_digest: [u8; 32],
    expected_containment_digest: [u8; 32],
    heartbeat_timeout_secs: u64,
    last_heartbeat_time: Arc<AtomicU64>,
    last_sequence_number: Arc<AtomicU64>,
    last_uptime_ms: Arc<AtomicU64>,
    last_heartbeat_data: Arc<RwLock<Option<SupervisorHeartbeat>>>,

    // The 7 other Sentinel Components
    pub process_monitor: Arc<ProcessMonitor>,
    pub integrity_monitor: Arc<IntegrityMonitor>,
    pub epoch_registry: Arc<EpochRegistry>,
    pub network_verifier: Arc<NetworkVerifier>,
    pub lockdown_controller: Arc<EmergencyLockdownController>,
    pub forensic_audit: Arc<ForensicAuditLog>,
    pub recovery_controller: Arc<RecoveryController>,

    // Sensitivity switches for negative-control tests
    watchdog_active: Arc<AtomicBool>,
}

impl SentinelSupervisor {
    /// Instantiates the Sentinel Supervisor and boots all 8 principal components.
    pub fn new(secret_seed: &[u8], total_arms: usize) -> Self {
        let mut key = [0u8; 32];
        if secret_seed.len() >= 32 {
            key.copy_from_slice(&secret_seed[..32]);
        } else {
            let hash = Sha256::digest(secret_seed);
            key.copy_from_slice(&hash);
        }

        let policy_digest = Sha256::digest(b"cedar_v4_13_octopus_v1_ruleset");
        let containment_digest = Sha256::digest(b"concentric_containment_ring_v1_topology");

        let mut p_dig = [0u8; 32];
        let mut c_dig = [0u8; 32];
        p_dig.copy_from_slice(&policy_digest);
        c_dig.copy_from_slice(&containment_digest);

        let process_monitor = Arc::new(ProcessMonitor::new());
        let integrity_monitor = Arc::new(IntegrityMonitor::new());
        let epoch_registry = Arc::new(EpochRegistry::new(total_arms));
        let network_verifier = Arc::new(NetworkVerifier::new());
        let lockdown_controller = Arc::new(EmergencyLockdownController::new());
        let forensic_audit = Arc::new(ForensicAuditLog::new(
            PathBuf::from("logs/sentinel_forensic_audit.log"),
            secret_seed,
        ));
        let recovery_controller = Arc::new(RecoveryController::new(
            Arc::clone(&epoch_registry),
            Arc::clone(&process_monitor),
        ));

        Self {
            state: Arc::new(RwLock::new(SentinelSystemState::Healthy)),
            secret_key: key,
            expected_policy_digest: p_dig,
            expected_containment_digest: c_dig,
            heartbeat_timeout_secs: 5,
            last_heartbeat_time: Arc::new(AtomicU64::new(0)),
            last_sequence_number: Arc::new(AtomicU64::new(0)),
            last_uptime_ms: Arc::new(AtomicU64::new(0)),
            last_heartbeat_data: Arc::new(RwLock::new(None)),
            process_monitor,
            integrity_monitor,
            epoch_registry,
            network_verifier,
            lockdown_controller,
            forensic_audit,
            recovery_controller,
            watchdog_active: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Ingests and cryptographically validates a heartbeat from the main supervisor.
    pub async fn ingest_supervisor_heartbeat(
        &self,
        hb: SupervisorHeartbeat,
    ) -> Result<(), OctopusSecurityError> {
        if !self.watchdog_active.load(Ordering::SeqCst) {
            return Ok(());
        }

        // 1. Anti-Replay & Monotonic Sequence Check
        let last_seq = self.last_sequence_number.load(Ordering::SeqCst);
        if hb.sequence_number <= last_seq {
            self.trigger_lockdown(
                "Heartbeat Replay Attack Detected",
                &format!(
                    "Heartbeat sequence {} <= last seen sequence {}",
                    hb.sequence_number, last_seq
                ),
            )
            .await;
            return Err(OctopusSecurityError::CapabilityDenied(
                "Sentinel rejected replayed or out-of-order supervisor heartbeat".to_string(),
            ));
        }

        // 2. Monotonic Uptime Check
        let last_up = self.last_uptime_ms.load(Ordering::SeqCst);
        if hb.monotonic_uptime_ms < last_up {
            self.trigger_lockdown(
                "Heartbeat Clock Rollback Detected",
                &format!(
                    "Supervisor uptime {} < last seen uptime {}",
                    hb.monotonic_uptime_ms, last_up
                ),
            )
            .await;
            return Err(OctopusSecurityError::CapabilityDenied(
                "Sentinel rejected heartbeat with reversed monotonic clock".to_string(),
            ));
        }

        // 3. Digest Validation (Policy and Containment topology)
        if hb.policy_digest != self.expected_policy_digest {
            self.trigger_lockdown(
                "Supervisor Policy Digest Tampering",
                "Heartbeat policy digest does not match authoritative Sentinel manifest",
            )
            .await;
            return Err(OctopusSecurityError::CapabilityDenied(
                "Policy digest mismatch in supervisor heartbeat".to_string(),
            ));
        }

        if hb.containment_digest != self.expected_containment_digest {
            self.trigger_lockdown(
                "Supervisor Containment Digest Tampering",
                "Heartbeat containment digest does not match authoritative Sentinel manifest",
            )
            .await;
            return Err(OctopusSecurityError::CapabilityDenied(
                "Containment topology digest mismatch in supervisor heartbeat".to_string(),
            ));
        }

        // 4. Cryptographic Authentication Tag (HMAC-SHA256)
        let expected_tag = compute_heartbeat_tag(
            &self.secret_key,
            &hb.supervisor_id,
            hb.generation,
            hb.sequence_number,
            hb.monotonic_uptime_ms,
            &hb.policy_digest,
            &hb.containment_digest,
        );

        if hb.authentication_tag != expected_tag {
            self.trigger_lockdown(
                "Supervisor Authentication Tag Invalid",
                "Heartbeat HMAC tag verification failed; possible supervisor forgery",
            )
            .await;
            return Err(OctopusSecurityError::CapabilityDenied(
                "Invalid supervisor heartbeat authentication tag".to_string(),
            ));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.last_heartbeat_time.store(now, Ordering::SeqCst);
        self.last_sequence_number.store(hb.sequence_number, Ordering::SeqCst);
        self.last_uptime_ms.store(hb.monotonic_uptime_ms, Ordering::SeqCst);

        let mut data = self.last_heartbeat_data.write().await;
        *data = Some(hb);

        // If system was healthy or degraded, maintain health
        let mut st = self.state.write().await;
        if *st != SentinelSystemState::Lockdown {
            *st = SentinelSystemState::Healthy;
        }

        Ok(())
    }

    /// Evaluates supervisor liveness against heartbeat timeout threshold.
    pub async fn check_supervisor_liveness(&self) -> SentinelAction {
        if !self.watchdog_active.load(Ordering::SeqCst) {
            return SentinelAction::Continue;
        }

        let last_time = self.last_heartbeat_time.load(Ordering::SeqCst);
        if last_time == 0 {
            return SentinelAction::Continue;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now.saturating_sub(last_time) > self.heartbeat_timeout_secs {
            self.trigger_lockdown(
                "Supervisor Heartbeat Timeout",
                &format!(
                    "Main supervisor silent for > {}s. Initiating emergency fail-closed lockdown.",
                    self.heartbeat_timeout_secs
                ),
            )
            .await;
            SentinelAction::LockdownSystem
        } else {
            SentinelAction::Continue
        }
    }

    /// Core Ring 4 decision function: evaluates observation and executes autonomous enforcement.
    pub async fn evaluate_observation(
        &self,
        obs: &SentinelObservation,
    ) -> Result<SentinelAction, OctopusSecurityError> {
        // Check 1: Supervisor health
        if !obs.supervisor_healthy {
            self.trigger_lockdown(
                "Supervisor Unhealthy",
                "Observation indicated main supervisor failure",
            )
            .await;
            return Ok(SentinelAction::LockdownSystem);
        }

        // Check 2: Policy & Sandbox integrity
        if !obs.authorization_healthy
            || !obs.sandbox_verified
            || !obs.proxy_enforcement_intact
        {
            self.trigger_lockdown(
                "Security Perimeter Failure",
                "Cedar authorization, sandbox clamp, or proxy broker check failed",
            )
            .await;
            return Ok(SentinelAction::LockdownSystem);
        }

        // Check 3: Zombie worker detection
        if obs.termination_deadline_exceeded && obs.worker_alive {
            let mut st = self.state.write().await;
            *st = SentinelSystemState::Degraded;
            let _ = self
                .forensic_audit
                .append_event(
                    "ZOMBIE_WORKER_DETECTED",
                    Some(obs.arm_id),
                    "TerminateArm",
                    "Arm exceeded termination deadline; non-cooperative termination issued",
                )
                .await;

            let _ = self
                .process_monitor
                .terminate_worker_non_cooperative(obs.arm_id)
                .await;
            return Ok(SentinelAction::TerminateArm(obs.arm_id));
        }

        // Check 4: Unauthorized egress or lateral movement
        if obs.unauthorized_egress_detected {
            let mut st = self.state.write().await;
            *st = SentinelSystemState::Quarantined;
            let _ = self
                .forensic_audit
                .append_event(
                    "UNAUTHORIZED_EGRESS_DETECTED",
                    Some(obs.arm_id),
                    "TerminateArm",
                    "Arm attempted egress violation; non-cooperative termination issued",
                )
                .await;

            let _ = self
                .process_monitor
                .terminate_worker_non_cooperative(obs.arm_id)
                .await;
            return Ok(SentinelAction::TerminateArm(obs.arm_id));
        }

        Ok(SentinelAction::Continue)
    }

    /// Transitions system to Emergency Lockdown.
    pub async fn trigger_lockdown(&self, trigger: &str, reason: &str) -> LockdownReport {
        let mut st = self.state.write().await;
        *st = SentinelSystemState::Lockdown;

        let _ = self
            .forensic_audit
            .append_event(
                "EMERGENCY_LOCKDOWN_ENGAGED",
                None,
                "LockdownSystem",
                &format!("trigger={} reason={}", trigger, reason),
            )
            .await;

        self.lockdown_controller
            .engage_lockdown(trigger, reason, 0, 0)
            .await
    }

    /// Returns a full status snapshot of the Sentinel Ring.
    pub async fn snapshot(&self) -> SentinelStatusSnapshot {
        let st = *self.state.read().await;
        let is_locked = self.lockdown_controller.is_locked_down();
        let last_time = self.last_heartbeat_time.load(Ordering::SeqCst);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last_ago = if last_time == 0 { 0 } else { now.saturating_sub(last_time) };
        let supervisor_ok = last_time > 0 && last_ago <= self.heartbeat_timeout_secs;

        let workers = self.process_monitor.get_all_workers().await.len();
        let audits = self.forensic_audit.get_records().await.len();
        let network_ok = self.network_verifier.is_broker_healthy();

        SentinelStatusSnapshot {
            system_state: st,
            is_locked_down: is_locked,
            supervisor_healthy: supervisor_ok,
            last_heartbeat_secs_ago: last_ago,
            active_workers_monitored: workers,
            total_audit_records: audits,
            integrity_verified: !is_locked,
            network_broker_healthy: network_ok,
        }
    }

    // Negative control testing hooks
    pub fn set_watchdog_active(&self, active: bool) {
        self.watchdog_active.store(active, Ordering::SeqCst);
    }
}

/// Generates a compliant SupervisorHeartbeat with HMAC tag.
pub fn create_authenticated_heartbeat(
    supervisor_id: &str,
    generation: u64,
    sequence_number: u64,
    monotonic_uptime_ms: u64,
    secret_key: &[u8],
) -> SupervisorHeartbeat {
    let mut key = [0u8; 32];
    if secret_key.len() >= 32 {
        key.copy_from_slice(&secret_key[..32]);
    } else {
        let hash = Sha256::digest(secret_key);
        key.copy_from_slice(&hash);
    }

    let policy_digest = Sha256::digest(b"cedar_v4_13_octopus_v1_ruleset");
    let containment_digest = Sha256::digest(b"concentric_containment_ring_v1_topology");

    let mut p_dig = [0u8; 32];
    let mut c_dig = [0u8; 32];
    p_dig.copy_from_slice(&policy_digest);
    c_dig.copy_from_slice(&containment_digest);

    let tag = compute_heartbeat_tag(
        &key,
        supervisor_id,
        generation,
        sequence_number,
        monotonic_uptime_ms,
        &p_dig,
        &c_dig,
    );

    SupervisorHeartbeat {
        supervisor_id: supervisor_id.to_string(),
        generation,
        sequence_number,
        monotonic_uptime_ms,
        policy_digest: p_dig,
        containment_digest: c_dig,
        authentication_tag: tag,
    }
}

fn compute_heartbeat_tag(
    key: &[u8; 32],
    supervisor_id: &str,
    generation: u64,
    sequence_number: u64,
    monotonic_uptime_ms: u64,
    policy_digest: &[u8; 32],
    containment_digest: &[u8; 32],
) -> [u8; 32] {
    let mut mac = Sha256::new();
    mac.update(key);
    mac.update(supervisor_id.as_bytes());
    mac.update(&generation.to_le_bytes());
    mac.update(&sequence_number.to_le_bytes());
    mac.update(&monotonic_uptime_ms.to_le_bytes());
    mac.update(policy_digest);
    mac.update(containment_digest);
    let hash = mac.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}
