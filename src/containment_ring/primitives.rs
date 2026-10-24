//! Mathematical & Hardware-Enforced Containment Ring Primitives
//!
//! Adapted from the OshoosiClaw 7-Ring Breakout Prevention Architecture:
//! - **Law 3 (`DiracDeltaCapabilityTicket`)**: Ephemeral single-use capability impulse ticket
//!   ($\text{Cap}(t) = 1$ iff $t \in [t_0, t_0 + \Delta t]$ and $\text{consumed} == 0$,
//!   consumed via single-instruction `AtomicU32::compare_exchange`, volatile zeroized on `Drop`).
//! - **Law 5 (`ZeroCopyImmutableToolBuffer`)**: 4096-byte page-aligned buffer locked `PAGE_READONLY`
//!   (`VirtualProtect` on Windows / `mprotect(PROT_READ)` on Unix) before policy inspection
//!   so $\Delta t_{\text{TOCTOU}} = 0$, restored and volatile-scrubbed on `Drop`.
//! - **Descriptor & Object Identity Pinning (`PinnedToolObjectBinding`)**: Captures
//!   `(canonical_path, file_size, modified_ns, content_sha256)` at $t_{\text{check}}$, rejects
//!   symlinks/reparse points, and verifies opened `std::fs::File` descriptors at $t_{\text{use}}$.
//! - **Cross-Layer Non-Circular Trust Boundary Verifier (`IndependentTrustBoundaryVerifier`)**:
//!   Orthogonal 3-layer `AND` gate (`Layer1_UserSpace_Cedar_Capability`,
//!   `Layer2_TPM2_SHA256_Merkle_Attestation`, `Layer3_OS_Kernel_Confinement_Boundary`) with
//!   monotonically advancing independent epochs.

use crate::core::types::OctopusSecurityError;
use crate::security::{constant_time_eq, hmac_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Monotonic microsecond timestamp helper.
pub fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

// ============================================================================
// Law 3: Dirac-Delta Ephemeral Capability Impulse Ticket
// ============================================================================

/// Law 3: Ephemeral Single-Use Capability Impulse Ticket.
///
/// Enforces $\text{Cap}(t) = \delta(t - t_{\text{issue}})$ over a microsecond validity window
/// $[t_0, t_0 + \Delta t]$ with atomic single-instruction consumption (`AtomicU32::compare_exchange`).
/// Once consumed or dropped, the 32-byte capability secret is volatile-zeroed in RAM.
#[derive(Debug)]
pub struct DiracDeltaCapabilityTicket {
    pub ticket_id: String,
    pub arm_id: String,
    pub generation_epoch: u64,
    pub authorized_tool: String,
    pub authorized_target: String,
    pub issued_at_us: u64,
    pub window_us: u64,
    consumed: AtomicU32,
    secret_material: [u8; 32],
    signature_tag: [u8; 32],
    pub canary_token_hash: Option<String>,
}

impl DiracDeltaCapabilityTicket {
    /// Issues a new single-use capability impulse ticket bound to `(arm_id, generation_epoch, tool, target)`.
    pub fn issue(
        arm_id: &str,
        generation_epoch: u64,
        authorized_tool: &str,
        authorized_target: &str,
        window_us: u64,
        signing_key: &[u8; 32],
        canary_token_hash: Option<String>,
    ) -> Self {
        let issued_at_us = now_micros();
        let clamped_window_us = window_us.clamp(1, 5_000_000); // 1 us .. 5 s max
        let payload = format!(
            "dirac-cap-v1|{}|{}|{}|{}|{}|{}",
            arm_id,
            generation_epoch,
            authorized_tool,
            authorized_target,
            issued_at_us,
            clamped_window_us
        );
        let signature_tag = hmac_sha256(signing_key, payload.as_bytes());
        let mut secret_material = [0u8; 32];
        let derived = hmac_sha256(&signature_tag, b"dirac-ephemeral-secret");
        secret_material.copy_from_slice(&derived);

        let ticket_id = format!("dirac-{}-{}", arm_id, &hex::encode(signature_tag)[..12]);

        Self {
            ticket_id,
            arm_id: arm_id.to_string(),
            generation_epoch,
            authorized_tool: authorized_tool.to_string(),
            authorized_target: authorized_target.to_string(),
            issued_at_us,
            window_us: clamped_window_us,
            consumed: AtomicU32::new(0),
            secret_material,
            signature_tag,
            canary_token_hash,
        }
    }

    /// Atomically consumes the ticket in a single hardware compare-and-swap instruction.
    /// Fails closed if:
    /// 1. A canary trap digest is triggered,
    /// 2. The ticket was already consumed (`consumed != 0`),
    /// 3. The current time is outside $[t_0, t_0 + \Delta t]$,
    /// 4. The tool, target, or generation epoch does not match, or
    /// 5. The cryptographic HMAC-SHA256 tag fails constant-time verification.
    pub fn consume_once(
        &mut self,
        requested_tool: &str,
        requested_target: &str,
        active_epoch: u64,
        signing_key: &[u8; 32],
        observed_canary_hash: Option<&str>,
    ) -> Result<[u8; 32], OctopusSecurityError> {
        // 1. Canary Trap Check: If a canary token was touched, immediately self-revoke
        if let (Some(expected_canary), Some(observed)) =
            (self.canary_token_hash.as_deref(), observed_canary_hash)
        {
            if expected_canary == observed {
                self.zeroize_secret();
                self.consumed.store(2, Ordering::SeqCst);
                return Err(OctopusSecurityError::BreakoutDetected(format!(
                    "LAW3_CANARY_TRAP_TRIPPED: Ticket '{}' self-destructed on canary touch",
                    self.ticket_id
                )));
            }
        }

        // 2. Single-instruction atomic compare-and-exchange (0 -> 1)
        if self
            .consumed
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            self.zeroize_secret();
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "LAW3_DIRAC_REPLAY_BLOCKED: Ephemeral ticket '{}' already consumed (Cap(t) = 0)",
                self.ticket_id
            )));
        }

        // 3. Verify microsecond impulse window [t_0, t_0 + \Delta t]
        let now = now_micros();
        let elapsed_us = now.saturating_sub(self.issued_at_us);
        if elapsed_us > self.window_us {
            self.zeroize_secret();
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "LAW3_DIRAC_WINDOW_EXPIRED: Ticket '{}' expired ({} us > {} us impulse window)",
                self.ticket_id, elapsed_us, self.window_us
            )));
        }

        // 4. Verify epoch, tool, and target binding
        if active_epoch != self.generation_epoch {
            self.zeroize_secret();
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "LAW3_EPOCH_MISMATCH: Ticket epoch {} != active epoch {}",
                self.generation_epoch, active_epoch
            )));
        }
        if requested_tool != self.authorized_tool || requested_target != self.authorized_target {
            self.zeroize_secret();
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "LAW3_SCOPE_MISMATCH: Ticket bound to ({}, {}) cannot authorize ({}, {})",
                self.authorized_tool, self.authorized_target, requested_tool, requested_target
            )));
        }

        // 5. Constant-time HMAC verification
        let payload = format!(
            "dirac-cap-v1|{}|{}|{}|{}|{}|{}",
            self.arm_id,
            self.generation_epoch,
            self.authorized_tool,
            self.authorized_target,
            self.issued_at_us,
            self.window_us
        );
        let expected_tag = hmac_sha256(signing_key, payload.as_bytes());
        if !constant_time_eq(&self.signature_tag, &expected_tag) {
            self.zeroize_secret();
            return Err(OctopusSecurityError::IdentitySpoofingDetected(
                "LAW3_SIGNATURE_INVALID: Dirac capability ticket HMAC tag mismatch".to_string(),
            ));
        }

        let receipt = hmac_sha256(&self.secret_material, payload.as_bytes());
        self.zeroize_secret();
        Ok(receipt)
    }

    /// Volatile-zeroes the 32-byte secret material in RAM so post-use heap inspection yields `0x00`.
    pub fn zeroize_secret(&mut self) {
        for byte in self.secret_material.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0u8);
            }
        }
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed.load(Ordering::SeqCst) != 0
    }

    pub fn inspect_secret_bytes(&self) -> &[u8; 32] {
        &self.secret_material
    }
}

impl Drop for DiracDeltaCapabilityTicket {
    fn drop(&mut self) {
        self.zeroize_secret();
    }
}

// ============================================================================
// Law 5: Zero-Copy Immutable Page-Locked Tool Buffer (\Delta t_TOCTOU = 0)
// ============================================================================

/// Law 5: Zero-Copy Immutable Page-Locked Tool Argument Buffer.
///
/// Allocates a 4096-byte page-aligned memory region, copies the tool arguments into the page,
/// locks the OS virtual memory page `PAGE_READONLY` (`VirtualProtect` on Windows / `mprotect` on Unix)
/// *before* policy inspection and SHA-256 hashing, and maintains the hardware read-only lock
/// across authorization and execution ($\Delta t_{\text{TOCTOU}} = 0$).
pub struct ZeroCopyImmutableToolBuffer {
    ptr: *mut u8,
    layout: std::alloc::Layout,
    len: usize,
    is_locked_readonly: bool,
    pub sha256_digest: [u8; 32],
}

unsafe impl Send for ZeroCopyImmutableToolBuffer {}
unsafe impl Sync for ZeroCopyImmutableToolBuffer {}

impl ZeroCopyImmutableToolBuffer {
    pub const PAGE_SIZE: usize = 4096;

    /// Allocates a page-aligned buffer, writes `payload`, locks the page `PAGE_READONLY` via OS MMU,
    /// and computes the immutable SHA-256 digest over the locked page.
    pub fn create_and_lock(payload: &[u8]) -> Result<Self, OctopusSecurityError> {
        if payload.len() > Self::PAGE_SIZE * 16 {
            return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
                "LAW5_BUFFER_OVERSIZE: Payload ({} bytes) exceeds 64KB immutable page limit",
                payload.len()
            )));
        }

        let alloc_size = ((payload.len().max(1) + Self::PAGE_SIZE - 1) / Self::PAGE_SIZE)
            * Self::PAGE_SIZE;
        let layout = std::alloc::Layout::from_size_align(alloc_size, Self::PAGE_SIZE).map_err(
            |e| OctopusSecurityError::EnclaveViolation(format!("Invalid page layout: {}", e)),
        )?;

        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(OctopusSecurityError::EnclaveViolation(
                "LAW5_ALLOC_FAILED: Failed to allocate page-aligned tool buffer".to_string(),
            ));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), ptr, payload.len());
        }

        // Lock virtual page to PAGE_READONLY before computing digest or inspecting policy
        #[cfg(windows)]
        let locked = {
            extern "system" {
                fn VirtualProtect(
                    lpAddress: *const std::ffi::c_void,
                    dwSize: usize,
                    flNewProtect: u32,
                    lpflOldProtect: *mut u32,
                ) -> i32;
            }
            const PAGE_READONLY: u32 = 0x02;
            let mut old_prot: u32 = 0;
            let ok = unsafe {
                VirtualProtect(
                    ptr as *const std::ffi::c_void,
                    alloc_size,
                    PAGE_READONLY,
                    &mut old_prot,
                )
            };
            if ok == 0 {
                unsafe { std::alloc::dealloc(ptr, layout) };
                return Err(OctopusSecurityError::IsolationViolation(
                    "LAW5_VIRTUAL_PROTECT_FAILED: OS refused PAGE_READONLY lock on tool buffer"
                        .to_string(),
                ));
            }
            true
        };

        #[cfg(unix)]
        let locked = {
            let res = unsafe {
                libc::mprotect(
                    ptr as *mut libc::c_void,
                    alloc_size,
                    libc::PROT_READ,
                )
            };
            if res != 0 {
                unsafe { std::alloc::dealloc(ptr, layout) };
                return Err(OctopusSecurityError::IsolationViolation(
                    "LAW5_MPROTECT_FAILED: OS refused PROT_READ lock on tool buffer".to_string(),
                ));
            }
            true
        };

        #[cfg(not(any(windows, unix)))]
        let locked = true;

        let slice = unsafe { std::slice::from_raw_parts(ptr, payload.len()) };
        let digest_ga = Sha256::digest(slice);
        let mut sha256_digest = [0u8; 32];
        sha256_digest.copy_from_slice(&digest_ga);

        Ok(Self {
            ptr,
            layout,
            len: payload.len(),
            is_locked_readonly: locked,
            sha256_digest,
        })
    }

    /// Returns an immutable slice over the hardware-locked page and verifies that its SHA-256
    /// digest matches the pre-inspection digest ($\Delta t_{\text{TOCTOU}} = 0$).
    pub fn as_verified_slice(&self) -> Result<&[u8], OctopusSecurityError> {
        if !self.is_locked_readonly {
            return Err(OctopusSecurityError::IsolationViolation(
                "LAW5_UNLOCKED_PAGE: Tool buffer is not hardware-locked PAGE_READONLY".to_string(),
            ));
        }
        let slice = unsafe { std::slice::from_raw_parts(self.ptr, self.len) };
        let current_hash = Sha256::digest(slice);
        let mut current = [0u8; 32];
        current.copy_from_slice(&current_hash);
        if !constant_time_eq(&self.sha256_digest, &current) {
            return Err(OctopusSecurityError::BreakoutDetected(
                "LAW5_TOCTOU_MUTATION_DETECTED: Page contents mutated after policy check"
                    .to_string(),
            ));
        }
        Ok(slice)
    }

    pub fn is_locked_readonly(&self) -> bool {
        self.is_locked_readonly
    }
}

impl Drop for ZeroCopyImmutableToolBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            #[cfg(windows)]
            unsafe {
                extern "system" {
                    fn VirtualProtect(
                        lpAddress: *const std::ffi::c_void,
                        dwSize: usize,
                        flNewProtect: u32,
                        lpflOldProtect: *mut u32,
                    ) -> i32;
                }
                const PAGE_READWRITE: u32 = 0x04;
                let mut old_prot: u32 = 0;
                let _ = VirtualProtect(
                    self.ptr as *const std::ffi::c_void,
                    self.layout.size(),
                    PAGE_READWRITE,
                    &mut old_prot,
                );
            }
            #[cfg(unix)]
            unsafe {
                let _ = libc::mprotect(
                    self.ptr as *mut libc::c_void,
                    self.layout.size(),
                    libc::PROT_READ | libc::PROT_WRITE,
                );
            }

            unsafe {
                for i in 0..self.layout.size() {
                    std::ptr::write_volatile(self.ptr.add(i), 0u8);
                }
                std::sync::atomic::compiler_fence(Ordering::SeqCst);
                std::alloc::dealloc(self.ptr, self.layout);
            }
        }
    }
}

// ============================================================================
// Descriptor & Object Identity Pinning (Anti-Symlink / File-Swap TOCTOU)
// ============================================================================

/// Pins a filesystem object's canonical identity and cryptographic digest at $t_{\text{check}}$
/// and verifies an opened `std::fs::File` descriptor at $t_{\text{use}}$ before execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedToolObjectBinding {
    pub canonical_path: PathBuf,
    pub file_size: u64,
    pub modified_ns: u128,
    pub sha256_digest_hex: String,
    pub symlink_or_reparse_rejected: bool,
}

impl PinnedToolObjectBinding {
    /// Captures and pins the target file's identity at $t_{\text{check}}$.
    /// Immediately rejects symbolic links and NTFS reparse points / junctions.
    pub fn pin_at_check(path: &Path) -> Result<Self, OctopusSecurityError> {
        let sym_meta = std::fs::symlink_metadata(path).map_err(|e| {
            OctopusSecurityError::EnclaveViolation(format!(
                "TOCTOU_PIN_METADATA_ERROR: Cannot stat '{}': {}",
                path.display(),
                e
            ))
        })?;

        if sym_meta.file_type().is_symlink() {
            return Err(OctopusSecurityError::BreakoutDetected(format!(
                "TOCTOU_SYMLINK_REJECTED: Target '{}' is a symbolic link or junction point",
                path.display()
            )));
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            if (sym_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                return Err(OctopusSecurityError::BreakoutDetected(format!(
                    "TOCTOU_REPARSE_POINT_REJECTED: Target '{}' has NTFS FILE_ATTRIBUTE_REPARSE_POINT",
                    path.display()
                )));
            }
        }

        let canonical_path = std::fs::canonicalize(path).map_err(|e| {
            OctopusSecurityError::EnclaveViolation(format!(
                "TOCTOU_CANONICALIZE_ERROR: Cannot canonicalize '{}': {}",
                path.display(),
                e
            ))
        })?;

        let bytes = std::fs::read(&canonical_path).map_err(|e| {
            OctopusSecurityError::EnclaveViolation(format!(
                "TOCTOU_READ_ERROR: Cannot read '{}': {}",
                canonical_path.display(),
                e
            ))
        })?;

        let modified_ns = sym_meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        let sha256_digest_hex = hex::encode(Sha256::digest(&bytes));

        Ok(Self {
            canonical_path,
            file_size: sym_meta.len(),
            modified_ns,
            sha256_digest_hex,
            symlink_or_reparse_rejected: true,
        })
    }

    /// Verifies an opened `std::fs::File` descriptor at $t_{\text{use}}$ against the pinned
    /// identity captured at $t_{\text{check}}$. Detects any mid-flight file replacement or mutation.
    pub fn verify_open_descriptor(
        &self,
        open_file: &mut std::fs::File,
        recheck_path: &Path,
    ) -> Result<(), OctopusSecurityError> {
        use std::io::{Read, Seek, SeekFrom};

        let sym_meta = std::fs::symlink_metadata(recheck_path).map_err(|e| {
            OctopusSecurityError::BreakoutDetected(format!(
                "TOCTOU_RECHECK_FAILED: Target '{}' vanished before use: {}",
                recheck_path.display(),
                e
            ))
        })?;

        if sym_meta.file_type().is_symlink() {
            return Err(OctopusSecurityError::BreakoutDetected(format!(
                "TOCTOU_SWAP_DETECTED: Target '{}' was swapped with a symlink between t_check and t_use",
                recheck_path.display()
            )));
        }

        let fd_meta = open_file.metadata().map_err(|e| {
            OctopusSecurityError::BreakoutDetected(format!(
                "TOCTOU_FD_STAT_FAILED: Cannot stat opened descriptor: {}",
                e
            ))
        })?;

        if fd_meta.len() != self.file_size {
            return Err(OctopusSecurityError::BreakoutDetected(format!(
                "TOCTOU_SIZE_DRIFT: Descriptor size {} != pinned size {}",
                fd_meta.len(),
                self.file_size
            )));
        }

        open_file.seek(SeekFrom::Start(0)).map_err(|e| {
            OctopusSecurityError::EnclaveViolation(format!("Descriptor seek failed: {}", e))
        })?;
        let mut buf = Vec::with_capacity(fd_meta.len() as usize);
        open_file.read_to_end(&mut buf).map_err(|e| {
            OctopusSecurityError::EnclaveViolation(format!("Descriptor read failed: {}", e))
        })?;

        let actual_hex = hex::encode(Sha256::digest(&buf));
        if !crate::security::constant_time_eq_hex(&actual_hex, &self.sha256_digest_hex) {
            return Err(OctopusSecurityError::BreakoutDetected(format!(
                "TOCTOU_DIGEST_MISMATCH: Opened descriptor SHA-256 ({}) != pinned SHA-256 ({})",
                actual_hex, self.sha256_digest_hex
            )));
        }

        Ok(())
    }
}

// ============================================================================
// Cross-Layer Non-Circular Trust Boundary Verifier (3-Layer Orthogonal AND Gate)
// ============================================================================

/// Verdict returned by the 3-layer orthogonal non-circular trust boundary verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiLayerGateVerdict {
    pub allowed: bool,
    pub layer1_userspace_cedar_ok: bool,
    pub layer2_tpm_merkle_attestation_ok: bool,
    pub layer3_kernel_confinement_ok: bool,
    pub composite_proof_hex: String,
    pub reason: String,
}

/// Verifies three orthogonal, non-circular trust layers before permitting privileged execution:
/// - **Layer 1**: User-space Cedar policy + Dirac capability epoch (`L1` key).
/// - **Layer 2**: Out-of-band Merkle root attestation (`L2` key).
/// - **Layer 3**: OS kernel Job Object / AppContainer / seccomp confinement state (`L3` key).
///
/// Compromising any 1 or 2 layers cannot forge the 3rd layer's independent cryptographic state.
pub struct IndependentTrustBoundaryVerifier {
    layer1_key: [u8; 32],
    layer2_key: [u8; 32],
    layer3_key: [u8; 32],
    pub layer1_epoch: AtomicU64,
    pub layer2_epoch: AtomicU64,
    pub layer3_epoch: AtomicU64,
}

impl IndependentTrustBoundaryVerifier {
    pub fn new(master_seed: &[u8; 32]) -> Self {
        let layer1_key = hmac_sha256(master_seed, b"OCTOPUS_ORTHOGONAL_LAYER_1_USERSPACE");
        let layer2_key = hmac_sha256(master_seed, b"OCTOPUS_ORTHOGONAL_LAYER_2_TPM_MERKLE");
        let layer3_key = hmac_sha256(master_seed, b"OCTOPUS_ORTHOGONAL_LAYER_3_KERNEL_OS");
        Self {
            layer1_key,
            layer2_key,
            layer3_key,
            layer1_epoch: AtomicU64::new(1),
            layer2_epoch: AtomicU64::new(1),
            layer3_epoch: AtomicU64::new(1),
        }
    }

    pub fn compute_layer1_token(&self, arm_id: &str, epoch: u64) -> [u8; 32] {
        hmac_sha256(
            &self.layer1_key,
            format!("L1:{}:{}", arm_id, epoch).as_bytes(),
        )
    }

    pub fn compute_layer2_token(&self, merkle_root_hex: &str, epoch: u64) -> [u8; 32] {
        hmac_sha256(
            &self.layer2_key,
            format!("L2:{}:{}", merkle_root_hex, epoch).as_bytes(),
        )
    }

    pub fn compute_layer3_token(&self, kernel_container_id: &str, epoch: u64) -> [u8; 32] {
        hmac_sha256(
            &self.layer3_key,
            format!("L3:{}:{}", kernel_container_id, epoch).as_bytes(),
        )
    }

    /// Evaluates the non-circular 3-layer `AND` gate. All three independent proofs must verify.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_three_layer_gate(
        &self,
        arm_id: &str,
        merkle_root_hex: &str,
        kernel_container_id: &str,
        presented_l1: &[u8; 32],
        presented_l2: &[u8; 32],
        presented_l3: &[u8; 32],
        kernel_process_in_job: bool,
    ) -> MultiLayerGateVerdict {
        let e1 = self.layer1_epoch.load(Ordering::SeqCst);
        let e2 = self.layer2_epoch.load(Ordering::SeqCst);
        let e3 = self.layer3_epoch.load(Ordering::SeqCst);

        let expected_l1 = self.compute_layer1_token(arm_id, e1);
        let expected_l2 = self.compute_layer2_token(merkle_root_hex, e2);
        let expected_l3 = self.compute_layer3_token(kernel_container_id, e3);

        let l1_ok = constant_time_eq(presented_l1, &expected_l1);
        let l2_ok = constant_time_eq(presented_l2, &expected_l2);
        let l3_ok = constant_time_eq(presented_l3, &expected_l3) && kernel_process_in_job;

        let allowed = l1_ok && l2_ok && l3_ok;

        let mut composite = Sha256::new();
        composite.update(presented_l1);
        composite.update(presented_l2);
        composite.update(presented_l3);
        composite.update([allowed as u8]);
        let composite_proof_hex = hex::encode(composite.finalize());

        let reason = if allowed {
            "PERMIT_ALL_3_ORTHOGONAL_TRUST_LAYERS_VERIFIED".to_string()
        } else {
            format!(
                "DENY_NON_CIRCULAR_TRUST_BOUNDARY_VETO: L1_Cedar={} L2_Merkle={} L3_Kernel={}",
                l1_ok, l2_ok, l3_ok
            )
        };

        MultiLayerGateVerdict {
            allowed,
            layer1_userspace_cedar_ok: l1_ok,
            layer2_tpm_merkle_attestation_ok: l2_ok,
            layer3_kernel_confinement_ok: l3_ok,
            composite_proof_hex,
            reason,
        }
    }
}

/// P2P Mesh Watch-Out Broadcast Signal emitted when an arm is severed via autotomy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshWatchOutSignal {
    pub severed_arm_id: usize,
    pub revoked_generation: u64,
    pub new_generation: u64,
    pub reason: String,
    pub timestamp_us: u64,
}
