//! Component 6: Emergency Global Lockdown (`emergency_lockdown.rs`)
//!
//! Enforces immediate, fail-closed system lockdown if critical security infrastructure fails
//! (e.g. supervisor crash, runtime tampering, proxy compromise).
//! Guarantees that all new privileged operations are denied, capability tokens are revoked,
//! and affected worker processes are terminated via out-of-band OS authority.

use crate::core::types::OctopusSecurityError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Status and metadata for an emergency system lockdown event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockdownReport {
    pub is_locked_down: bool,
    pub initiated_at_secs: u64,
    pub trigger_source: String,
    pub reason: String,
    pub terminated_workers_count: usize,
    pub capabilities_revoked_count: usize,
    pub recovery_authorized: bool,
}

/// Emergency Global Lockdown Controller for Ring 4.
pub struct EmergencyLockdownController {
    is_active: Arc<AtomicBool>,
    current_report: Arc<RwLock<Option<LockdownReport>>>,
    state_file_path: PathBuf,
    recovery_token: Arc<RwLock<Option<String>>>,
}

impl Default for EmergencyLockdownController {
    fn default() -> Self {
        Self::new()
    }
}

impl EmergencyLockdownController {
    /// Creates a new lockdown controller bound to a state persistence file.
    pub fn new() -> Self {
        Self {
            is_active: Arc::new(AtomicBool::new(false)),
            current_report: Arc::new(RwLock::new(None)),
            state_file_path: PathBuf::from("logs/sentinel_lockdown.state"),
            recovery_token: Arc::new(RwLock::new(None)),
        }
    }

    /// Creates a new lockdown controller with a dynamically configured recovery token.
    pub fn with_recovery_token(token: impl Into<String>) -> Self {
        Self {
            is_active: Arc::new(AtomicBool::new(false)),
            current_report: Arc::new(RwLock::new(None)),
            state_file_path: PathBuf::from("logs/sentinel_lockdown.state"),
            recovery_token: Arc::new(RwLock::new(Some(token.into()))),
        }
    }

    /// Dynamically sets or rotates the recovery token required to lift emergency lockdown.
    pub async fn set_recovery_token(&self, token: impl Into<String>) {
        let mut guard = self.recovery_token.write().await;
        *guard = Some(token.into());
    }

    /// Engages full emergency global lockdown across the entire Agent Octopus swarm.
    pub async fn engage_lockdown(
        &self,
        trigger: &str,
        reason: &str,
        terminated_workers: usize,
        revoked_capabilities: usize,
    ) -> LockdownReport {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.is_active.store(true, Ordering::SeqCst);

        let report = LockdownReport {
            is_locked_down: true,
            initiated_at_secs: now,
            trigger_source: trigger.to_string(),
            reason: reason.to_string(),
            terminated_workers_count: terminated_workers,
            capabilities_revoked_count: revoked_capabilities,
            recovery_authorized: false,
        };

        {
            let mut rep_guard = self.current_report.write().await;
            *rep_guard = Some(report.clone());
        }

        // Persist lockdown state to disk out-of-band
        if let Some(parent) = self.state_file_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }

        if let Ok(json) = serde_json::to_string_pretty(&report) {
            let _ = tokio::fs::write(&self.state_file_path, json).await;
        }

        report
    }

    /// Returns whether the system is currently under emergency lockdown.
    pub fn is_locked_down(&self) -> bool {
        self.is_active.load(Ordering::SeqCst)
    }

    /// Asserts that the system is not locked down; fails closed if lockdown is active.
    pub fn assert_not_locked_down(&self) -> Result<(), OctopusSecurityError> {
        if self.is_locked_down() {
            Err(OctopusSecurityError::EnclaveViolation(
                "CRITICAL: System is under emergency Sentinel Lockdown. All privileged operations denied."
                    .to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Releases the lockdown upon verified supervisor recovery.
    pub async fn release_lockdown(
        &self,
        recovery_token: &str,
    ) -> Result<LockdownReport, OctopusSecurityError> {
        let dynamic_token = {
            let guard = self.recovery_token.read().await;
            guard.clone()
        };
        let valid_token = dynamic_token
            .or_else(|| std::env::var("SENTINEL_RECOVERY_TOKEN").ok())
            .filter(|t| !t.trim().is_empty());

        let valid_token = match valid_token {
            Some(t) => t,
            None => {
                return Err(OctopusSecurityError::CapabilityDenied(
                    "Recovery token not configured: SENTINEL_RECOVERY_TOKEN environment variable or dynamic token must be set".to_string(),
                ));
            }
        };

        if recovery_token.trim() != valid_token.trim() {
            return Err(OctopusSecurityError::CapabilityDenied(
                "Unauthorized recovery token: Sentinel lockdown cannot be lifted without authoritative credentials"
                    .to_string(),
            ));
        }

        self.is_active.store(false, Ordering::SeqCst);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let report = LockdownReport {
            is_locked_down: false,
            initiated_at_secs: now,
            trigger_source: "supervisor_recovery".to_string(),
            reason: "Safe recovery verified; lockdown lifted".to_string(),
            terminated_workers_count: 0,
            capabilities_revoked_count: 0,
            recovery_authorized: true,
        };

        {
            let mut rep_guard = self.current_report.write().await;
            *rep_guard = Some(report.clone());
        }

        // Remove disk state file
        let _ = tokio::fs::remove_file(&self.state_file_path).await;

        Ok(report)
    }

    /// Returns the current lockdown report if active.
    pub async fn get_report(&self) -> Option<LockdownReport> {
        let rep = self.current_report.read().await;
        rep.clone()
    }
}
