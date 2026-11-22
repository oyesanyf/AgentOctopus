//! Monotonic Tighten-Only Kernel Shield Coordinator + RFC 6962 Merkle Audit Receipts
//! (Foolproof Invariants #1, #3, #4).

use super::error::PatcherError;
use super::types::{
    HostKernelPostureSnapshot, KernelVulnerability, OsFamily, PatchAuditReceipt,
    RebootPendingStatus, TelemetryHealthStatus, VirtualPatchShieldState, VirtualPatchSurface,
};
use crate::core::merkle::{MerkleLeaf, MerkleTree};
use crate::security::virtual_patch_shield::{
    apply_shield_posture, current_shield_posture, KernelAttackSurface, KernelShieldPosture,
};
use sha2::{Digest, Sha256};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Baseline proactive virtual-patch surfaces kept active on degraded telemetry or unpatched exposure.
#[must_use]
pub fn baseline_virtual_patch_surfaces(os_family: &OsFamily) -> Vec<VirtualPatchSurface> {
    let mut surfaces = vec![
        VirtualPatchSurface::WasmTier1Promotion,
        VirtualPatchSurface::KernelPerimeterInboundShield,
        VirtualPatchSurface::CedarTightenOnlyForbid,
    ];
    match os_family {
        OsFamily::Linux => surfaces.push(VirtualPatchSurface::LinuxSeccompHighCveSyscalls),
        OsFamily::Windows => {
            surfaces.push(VirtualPatchSurface::WindowsWin32kAndImageLoadClamp);
            surfaces.push(VirtualPatchSurface::WindowsOsoosiByovdBlock);
        }
        OsFamily::MacOS => surfaces.push(VirtualPatchSurface::MacOsSeatbeltKernelClamp),
        OsFamily::FreeBSD | OsFamily::OpenBSD | OsFamily::NetBSD | OsFamily::Unknown(_) => {}
    }
    surfaces
}

#[derive(Debug)]
struct InnerShieldState {
    shield: VirtualPatchShieldState,
    health: TelemetryHealthStatus,
    leaves: Vec<MerkleLeaf>,
    locked_running_kernel: Option<String>,
    locked_target_kernel: Option<String>,
}

/// Coordinates monotonic tighten-only virtual-patch shield state, reboot-pending latching,
/// fail-closed degraded telemetry, post-write read-back verification, and Merkle receipts.
#[derive(Debug)]
pub struct KernelShieldCoordinator {
    inner: Mutex<InnerShieldState>,
    sync_to_global_posture: bool,
}

impl Default for KernelShieldCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelShieldCoordinator {
    /// Creates an isolated coordinator (defaults fail-closed with `telemetry_degraded_fail_closed = true`).
    #[must_use]
    pub fn new() -> Self {
        Self::with_global_bridge(false)
    }

    fn with_global_bridge(sync_to_global_posture: bool) -> Self {
        let initial_surfaces = vec![
            VirtualPatchSurface::WasmTier1Promotion,
            VirtualPatchSurface::LinuxSeccompHighCveSyscalls,
            VirtualPatchSurface::WindowsWin32kAndImageLoadClamp,
            VirtualPatchSurface::WindowsOsoosiByovdBlock,
            VirtualPatchSurface::MacOsSeatbeltKernelClamp,
            VirtualPatchSurface::KernelPerimeterInboundShield,
            VirtualPatchSurface::CedarTightenOnlyForbid,
        ];
        let shield = VirtualPatchShieldState {
            active: true,
            shield_locked_until_reboot: false,
            telemetry_degraded_fail_closed: true,
            monotonic_revision: 1,
            active_surfaces: initial_surfaces,
            mitigated_cves: Vec::new(),
            read_back_verified: true,
            merkle_root: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        };
        Self {
            inner: Mutex::new(InnerShieldState {
                shield,
                health: TelemetryHealthStatus::DegradedFailClosed {
                    reason: "Initial fail-closed posture before first verified scan".to_string(),
                    http_status: None,
                },
                leaves: Vec::new(),
                locked_running_kernel: None,
                locked_target_kernel: None,
            }),
            sync_to_global_posture,
        }
    }

    /// Returns a snapshot of the current virtual-patch shield state.
    #[must_use]
    pub fn state(&self) -> VirtualPatchShieldState {
        self.inner
            .lock()
            .map(|g| g.shield.clone())
            .unwrap_or_else(|e| e.into_inner().shield.clone())
    }

    /// Returns the current telemetry health status.
    #[must_use]
    pub fn telemetry_health(&self) -> TelemetryHealthStatus {
        self.inner
            .lock()
            .map(|g| g.health.clone())
            .unwrap_or_else(|e| e.into_inner().health.clone())
    }

    /// Records degraded NVD/KEV telemetry (429/5xx/offline/malformed JSON) and fails closed,
    /// keeping all baseline Zero-Breakout & Zero-Breakin virtual-patch surfaces active.
    pub fn record_degraded_telemetry(
        &self,
        os_family: &OsFamily,
        target_cpe: &str,
        reason: &str,
        http_status: Option<u16>,
    ) -> Result<PatchAuditReceipt, PatcherError> {
        self.record_degraded_telemetry_with_reboot(os_family, target_cpe, reason, http_status, None)
    }

    /// Records degraded NVD/KEV telemetry while preserving any active `reboot_pending` latch.
    pub fn record_degraded_telemetry_with_reboot(
        &self,
        os_family: &OsFamily,
        target_cpe: &str,
        reason: &str,
        http_status: Option<u16>,
        reboot_pending: Option<&RebootPendingStatus>,
    ) -> Result<PatchAuditReceipt, PatcherError> {
        let baseline = baseline_virtual_patch_surfaces(os_family);
        let lock_reboot = reboot_pending.is_some_and(|r| {
            r.shield_locked_until_reboot || (r.reboot_required && !r.livepatch_mitigated)
        });
        let receipt = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.health = TelemetryHealthStatus::DegradedFailClosed {
                reason: reason.to_string(),
                http_status,
            };
            guard.shield.telemetry_degraded_fail_closed = true;
            guard.shield.active = true;
            if lock_reboot {
                guard.shield.shield_locked_until_reboot = true;
                if let Some(rp) = reboot_pending {
                    let rk = rp.running_kernel.trim();
                    if !rk.is_empty() {
                        guard.locked_running_kernel = Some(rk.to_string());
                    }
                    if let Some(ref tk) = rp.newest_installed_kernel {
                        let tk = tk.trim();
                        if !tk.is_empty() {
                            guard.locked_target_kernel = Some(tk.to_string());
                        }
                    }
                }
            }
            for s in &baseline {
                if !guard.shield.active_surfaces.contains(s) {
                    guard.shield.active_surfaces.push(*s);
                }
            }
            guard.shield.monotonic_revision = guard.shield.monotonic_revision.saturating_add(1);
            let receipt = Self::append_merkle_receipt(
                &mut guard,
                "telemetry_degraded_fail_closed",
                os_family,
                target_cpe,
            );
            Self::verify_read_back(
                &guard.shield,
                &baseline,
                &[],
                guard.shield.shield_locked_until_reboot,
            )?;
            guard.shield.read_back_verified = true;
            receipt
        };

        if self.sync_to_global_posture {
            let mut posture = current_shield_posture();
            posture.os_family = os_family.to_string();
            if !target_cpe.is_empty() {
                posture.cpe23 = target_cpe.to_string();
            }
            posture.telemetry_degraded_fail_closed = true;
            if let Some(rp) = reboot_pending {
                posture.reboot_pending = rp.reboot_required;
                posture.livepatch_active = rp.livepatch_mitigated;
                let rk = rp.running_kernel.trim();
                if !rk.is_empty() {
                    posture.running_kernel = rk.to_string();
                }
                if lock_reboot {
                    posture.shield_locked_until_reboot = true;
                }
            }
            apply_shield_posture(posture).map_err(PatcherError::ReadBackVerificationFailed)?;
        }

        Ok(receipt)
    }

    /// Applies verified NVD/KEV findings and reboot-pending status monotonically.
    pub fn apply_scan_findings(
        &self,
        os_family: &OsFamily,
        target_cpe: &str,
        vulns: &[KernelVulnerability],
        reboot_pending: &RebootPendingStatus,
    ) -> Result<PatchAuditReceipt, PatcherError> {
        let mut expected_surfaces = baseline_virtual_patch_surfaces(os_family);
        let lock_reboot = reboot_pending.shield_locked_until_reboot
            || (reboot_pending.reboot_required && !reboot_pending.livepatch_mitigated);
        if vulns.is_empty() && !lock_reboot {
            expected_surfaces.clear();
        }
        let cve_ids: Vec<String> = vulns.iter().map(|v| v.cve_id.clone()).collect();

        let receipt = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.health = TelemetryHealthStatus::Healthy;
            guard.shield.telemetry_degraded_fail_closed = false;

            if lock_reboot {
                guard.shield.shield_locked_until_reboot = true;
                let rk = reboot_pending.running_kernel.trim();
                if !rk.is_empty() {
                    guard.locked_running_kernel = Some(rk.to_string());
                }
                if let Some(ref tk) = reboot_pending.newest_installed_kernel {
                    let tk = tk.trim();
                    if !tk.is_empty() {
                        guard.locked_target_kernel = Some(tk.to_string());
                    }
                }
            }

            // Monotonic union when locked or findings exist
            for cve in &cve_ids {
                if !guard.shield.mitigated_cves.contains(cve) {
                    guard.shield.mitigated_cves.push(cve.clone());
                }
            }
            for s in &expected_surfaces {
                if !guard.shield.active_surfaces.contains(s) {
                    guard.shield.active_surfaces.push(*s);
                }
            }

            guard.shield.active = guard.shield.shield_locked_until_reboot
                || !guard.shield.mitigated_cves.is_empty()
                || !guard.shield.active_surfaces.is_empty();
            guard.shield.monotonic_revision = guard.shield.monotonic_revision.saturating_add(1);
            let receipt = Self::append_merkle_receipt(
                &mut guard,
                "apply_scan_findings",
                os_family,
                target_cpe,
            );
            Self::verify_read_back(&guard.shield, &expected_surfaces, &cve_ids, lock_reboot)?;
            guard.shield.read_back_verified = true;
            receipt
        };

        if self.sync_to_global_posture {
            let mut posture = KernelShieldPosture::default_fail_closed();
            posture.os_family = os_family.to_string();
            posture.cpe23 = target_cpe.to_string();
            let rk = reboot_pending.running_kernel.trim();
            if !rk.is_empty() {
                posture.running_kernel = rk.to_string();
            }
            posture.telemetry_degraded_fail_closed = false;
            posture.reboot_pending = reboot_pending.reboot_required;
            posture.livepatch_active = reboot_pending.livepatch_mitigated;
            posture.shield_locked_until_reboot =
                current_shield_posture().shield_locked_until_reboot || lock_reboot;
            posture.unpatched_cve_ids = cve_ids;
            posture.cisa_kev_ids = vulns
                .iter()
                .filter(|v| v.is_cisa_kev)
                .map(|v| v.cve_id.clone())
                .collect();
            let mut surfaces = Vec::new();
            for v in vulns {
                for s in KernelAttackSurface::classify_cve(
                    &v.cve_id,
                    &v.description,
                    v.cisa_vulnerability_name.as_deref(),
                ) {
                    if !surfaces.contains(&s) {
                        surfaces.push(s);
                    }
                }
            }
            if surfaces.is_empty() && posture.is_shield_active() {
                surfaces = KernelAttackSurface::baseline_proactive_surfaces();
            }
            posture.affected_surfaces = surfaces;
            apply_shield_posture(posture).map_err(PatcherError::ReadBackVerificationFailed)?;
        }

        Ok(receipt)
    }

    /// Updates coordinator state after OS-native patch execution, latching
    /// `shield_locked_until_reboot = true` if a reboot is still required without in-RAM livepatch.
    pub fn apply_post_patch_status(
        &self,
        os_family: &OsFamily,
        target_cpe: &str,
        reboot_pending: &RebootPendingStatus,
    ) -> Result<PatchAuditReceipt, PatcherError> {
        let expected_surfaces = baseline_virtual_patch_surfaces(os_family);
        let lock_reboot = reboot_pending.shield_locked_until_reboot
            || (reboot_pending.reboot_required && !reboot_pending.livepatch_mitigated);
        let receipt = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if lock_reboot {
                guard.shield.shield_locked_until_reboot = true;
                guard.shield.active = true;
                let rk = reboot_pending.running_kernel.trim();
                if !rk.is_empty() {
                    guard.locked_running_kernel = Some(rk.to_string());
                }
                if let Some(ref tk) = reboot_pending.newest_installed_kernel {
                    let tk = tk.trim();
                    if !tk.is_empty() {
                        guard.locked_target_kernel = Some(tk.to_string());
                    }
                }
                for s in &expected_surfaces {
                    if !guard.shield.active_surfaces.contains(s) {
                        guard.shield.active_surfaces.push(*s);
                    }
                }
            }
            guard.shield.monotonic_revision = guard.shield.monotonic_revision.saturating_add(1);
            let receipt = Self::append_merkle_receipt(
                &mut guard,
                "post_patch_reboot_check",
                os_family,
                target_cpe,
            );
            Self::verify_read_back(
                &guard.shield,
                if lock_reboot { &expected_surfaces } else { &[] },
                &[],
                lock_reboot,
            )?;
            guard.shield.read_back_verified = true;
            receipt
        };

        if self.sync_to_global_posture && lock_reboot {
            let mut posture = current_shield_posture();
            posture.os_family = os_family.to_string();
            if !target_cpe.is_empty() {
                posture.cpe23 = target_cpe.to_string();
            }
            let rk = reboot_pending.running_kernel.trim();
            if !rk.is_empty() {
                posture.running_kernel = rk.to_string();
            }
            posture.reboot_pending = reboot_pending.reboot_required;
            posture.livepatch_active = reboot_pending.livepatch_mitigated;
            posture.shield_locked_until_reboot = true;
            apply_shield_posture(posture).map_err(PatcherError::ReadBackVerificationFailed)?;
        }

        Ok(receipt)
    }

    /// Convenience wrapper applying a `HostKernelPostureSnapshot` to `apply_post_patch_status`.
    pub fn apply_snapshot(
        &self,
        os_family: &OsFamily,
        target_cpe: &str,
        snapshot: &HostKernelPostureSnapshot,
    ) -> Result<PatchAuditReceipt, PatcherError> {
        self.apply_post_patch_status(os_family, target_cpe, &snapshot.reboot_pending)
    }

    /// Explicitly rejects any attempt to loosen/remove active virtual-patch surfaces or clear
    /// `shield_locked_until_reboot` without a verified host reboot (Foolproof Invariant #4).
    pub fn attempt_loosen_shield(
        &self,
        clear_reboot_lock: bool,
        remove_surfaces: &[VirtualPatchSurface],
    ) -> Result<(), PatcherError> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if clear_reboot_lock && guard.shield.shield_locked_until_reboot {
            return Err(PatcherError::MonotonicViolation(
                "Cannot clear shield_locked_until_reboot without confirmed host reboot".to_string(),
            ));
        }
        for s in remove_surfaces {
            if guard.shield.active_surfaces.contains(s) {
                return Err(PatcherError::MonotonicViolation(format!(
                    "Cannot remove active virtual-patch surface {:?} monotonically",
                    s
                )));
            }
        }
        Ok(())
    }

    /// Clears `shield_locked_until_reboot` ONLY when `!reboot_required` and the running kernel
    /// has transitioned cleanly away from the locked kernel release.
    pub fn confirm_rebooted_into_kernel(
        &self,
        os_family: &OsFamily,
        target_cpe: &str,
        new_reboot_pending: &RebootPendingStatus,
    ) -> Result<PatchAuditReceipt, PatcherError> {
        let new_kernel = new_reboot_pending.running_kernel.trim();
        let still_pending =
            new_reboot_pending.reboot_required && !new_reboot_pending.livepatch_mitigated;
        if still_pending || new_reboot_pending.shield_locked_until_reboot {
            return Err(PatcherError::MonotonicViolation(format!(
                "Host kernel '{}' still reports reboot_required; refusing to unlock shield",
                new_kernel
            )));
        }
        if new_kernel.is_empty() {
            return Err(PatcherError::MonotonicViolation(
                "Empty running_kernel cannot confirm reboot".to_string(),
            ));
        }
        if let Some(ref newest) = new_reboot_pending.newest_installed_kernel {
            let newest_trimmed = newest.trim();
            if !newest_trimmed.is_empty() && newest_trimmed != new_kernel {
                return Err(PatcherError::MonotonicViolation(format!(
                    "Running kernel '{}' does not match newest installed kernel '{}'; refusing to unlock shield",
                    new_kernel, newest_trimmed
                )));
            }
        }

        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if guard.shield.shield_locked_until_reboot
            && guard.locked_running_kernel.as_deref() == Some(new_kernel)
        {
            return Err(PatcherError::MonotonicViolation(format!(
                "Running kernel '{}' is unchanged since reboot lock was armed; refusing to unlock shield",
                new_kernel
            )));
        }
        if guard.shield.shield_locked_until_reboot {
            if let Some(ref target_k) = guard.locked_target_kernel {
                if !target_k.is_empty() && target_k != new_kernel {
                    return Err(PatcherError::MonotonicViolation(format!(
                        "Running kernel '{}' does not match locked target kernel '{}'; refusing to unlock shield",
                        new_kernel, target_k
                    )));
                }
            }
        }

        if self.sync_to_global_posture {
            crate::security::virtual_patch_shield::global_shield_store()
                .confirm_reboot_cleared(new_kernel, false)
                .map_err(PatcherError::MonotonicViolation)?;
        }

        guard.shield.shield_locked_until_reboot = false;
        guard.locked_running_kernel = None;
        guard.locked_target_kernel = None;
        guard.shield.monotonic_revision = guard.shield.monotonic_revision.saturating_add(1);
        let receipt = Self::append_merkle_receipt(
            &mut guard,
            "confirm_rebooted_into_kernel",
            os_family,
            target_cpe,
        );

        Ok(receipt)
    }

    /// Generates an RFC 6962 `MerkleTree` over all shield transitions recorded by this coordinator.
    #[must_use]
    pub fn merkle_tree(&self) -> MerkleTree {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        MerkleTree::from_leaves(guard.leaves.clone())
    }

    fn verify_read_back(
        shield: &VirtualPatchShieldState,
        expected_surfaces: &[VirtualPatchSurface],
        expected_cves: &[String],
        expected_reboot_lock: bool,
    ) -> Result<(), PatcherError> {
        if expected_reboot_lock && !shield.shield_locked_until_reboot {
            return Err(PatcherError::ReadBackVerificationFailed(
                "shield_locked_until_reboot failed post-write read-back".to_string(),
            ));
        }
        for s in expected_surfaces {
            if !shield.active_surfaces.contains(s) {
                return Err(PatcherError::ReadBackVerificationFailed(format!(
                    "expected surface {:?} missing on read-back",
                    s
                )));
            }
        }
        for cve in expected_cves {
            if !shield.mitigated_cves.contains(cve) {
                return Err(PatcherError::ReadBackVerificationFailed(format!(
                    "expected CVE '{}' missing on read-back",
                    cve
                )));
            }
        }
        Ok(())
    }

    fn append_merkle_receipt(
        guard: &mut InnerShieldState,
        action: &str,
        os_family: &OsFamily,
        target_cpe: &str,
    ) -> PatchAuditReceipt {
        let step_idx = guard.leaves.len();
        let mut input_hasher = Sha256::new();
        input_hasher.update(action.as_bytes());
        input_hasher.update(b"|");
        input_hasher.update(os_family.to_string().as_bytes());
        input_hasher.update(b"|");
        input_hasher.update(target_cpe.as_bytes());
        let input_digest = hex::encode(input_hasher.finalize());

        let mut out_hasher = Sha256::new();
        out_hasher.update(guard.shield.monotonic_revision.to_le_bytes());
        out_hasher.update([
            u8::from(guard.shield.active),
            u8::from(guard.shield.shield_locked_until_reboot),
            u8::from(guard.shield.telemetry_degraded_fail_closed),
        ]);
        for cve in &guard.shield.mitigated_cves {
            out_hasher.update(cve.as_bytes());
            out_hasher.update(b",");
        }
        let output_digest = hex::encode(out_hasher.finalize());

        let leaf = MerkleLeaf::new(step_idx, action, input_digest, output_digest);
        let leaf_hash_hex = leaf.hash_hex();
        guard.leaves.push(leaf);

        let tree = MerkleTree::from_leaves(guard.leaves.clone());
        let merkle_root_hex = tree.root_hex();
        guard.shield.merkle_root = merkle_root_hex.clone();

        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let timestamp_utc = chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| secs.to_string());

        PatchAuditReceipt {
            sequence: (step_idx as u64) + 1,
            timestamp_utc,
            action: action.to_string(),
            os_family: os_family.to_string(),
            target_cpe: target_cpe.to_string(),
            shield_locked_until_reboot: guard.shield.shield_locked_until_reboot,
            telemetry_degraded_fail_closed: guard.shield.telemetry_degraded_fail_closed,
            monotonic_revision: guard.shield.monotonic_revision,
            leaf_hash_hex,
            merkle_root_hex,
        }
    }
}

static GLOBAL_KERNEL_SHIELD: OnceLock<KernelShieldCoordinator> = OnceLock::new();

/// Returns the process-wide `KernelShieldCoordinator`.
pub fn global_kernel_shield() -> &'static KernelShieldCoordinator {
    GLOBAL_KERNEL_SHIELD.get_or_init(|| {
        let persist = std::env::var(crate::security::virtual_patch_shield::ENV_SHIELD_POSTURE_PATH)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
            || !crate::security::virtual_patch_shield::is_shield_test_isolation_context();
        KernelShieldCoordinator::with_global_bridge(persist)
    })
}
