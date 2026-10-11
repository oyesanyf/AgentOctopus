//! Ring 4: The Octopus Sentinel Ring (OSR)
//!
//! An out-of-band, invisible containment ring that verifies the integrity and operation
//! of Ring 1 (Arm Containment Rings), Ring 2 (Neural Mesh), Ring 3 (Global Containment),
//! and the central supervisor.
//!
//! Eight Principal Components:
//! 1. `sentinel_supervisor`: Independent Sentinel Supervisor (4-state machine: Healthy, Degraded, Quarantined, Lockdown)
//! 2. `process_monitor`: Out-of-Band Process Lifecycle Monitoring (zombie detection, OS handles)
//! 3. `integrity_monitor`: Runtime Integrity and Attestation (golden manifest, SHA-256 hashes)
//! 4. `epoch_registry`: Independent Revocation Authority (authoritative generations, revoked epochs)
//! 5. `network_verifier`: Network Containment Verification (Google egress invariant, SSRF block)
//! 6. `emergency_lockdown`: Emergency Global Lockdown (fail-closed, denial of privileged ops)
//! 7. `forensic_audit`: Protected Forensic Audit (SHA-256 hash chained, HMAC-signed out-of-band log)
//! 8. `recovery_controller`: Safe Recovery Controller (clean baseline bootstrapping, no dirty memory)

pub mod emergency_lockdown;
pub mod epoch_registry;
pub mod forensic_audit;
pub mod integrity_monitor;
pub mod network_verifier;
pub mod process_monitor;
pub mod recovery_controller;
pub mod sentinel_supervisor;

pub use emergency_lockdown::{EmergencyLockdownController, LockdownReport};
pub use epoch_registry::{ArmEpochState, EpochRegistry};
pub use forensic_audit::{ForensicAuditLog, ForensicAuditRecord};
pub use integrity_monitor::{IntegrityMonitor, IntegrityReport, SignedSecurityManifest};
pub use network_verifier::{NetworkVerificationVerdict, NetworkVerifier};
pub use process_monitor::{ProcessLivenessStatus, ProcessMonitor, WorkerProcessTelemetry};
pub use recovery_controller::{RecoveryController, RecoveryReport};
pub use sentinel_supervisor::{
    create_authenticated_heartbeat, SentinelAction, SentinelObservation, SentinelStatusSnapshot,
    SentinelSupervisor, SentinelSystemState, SupervisorHeartbeat,
};
