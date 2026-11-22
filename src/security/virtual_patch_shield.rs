//! Cross-Module Zero-Reboot Virtual-Patching Shield ("No Break-Out / No Break-In").
//!
//! Bridges `kernel_patcher` CVE/KEV discovery, `reboot_pending` state, and degraded NVD/KEV
//! telemetry into deterministic containment enforcement across:
//! - Tier-1 Wasmtime isolation promotion (`wasm_tier1.rs`, `tiered_executor.rs`, `cli/run.rs`)
//! - Tier-2 OS kernel clamps (`linux_sandbox.rs`, `windows_sandbox.rs`, `token_posture.rs`,
//!   `kernel_sentinel_arm.rs`, `macos_sandbox.rs`, `bsd_sandbox.rs`)
//! - Kernel perimeter & strict AWS Cedar `forbid(...)` synthesis (`host_network_isolation.rs`,
//!   `cedar_arm/`, `research_ingest.rs`)
//!
//! # Foolproof Invariants
//! 1. **Fail-Closed Default**: Starts with `telemetry_degraded_fail_closed = true` until a verified
//!    NVD/KEV scan succeeds.
//! 2. **Reboot-Pending Latch**: Whenever `reboot_pending && !livepatch_active`,
//!    `shield_locked_until_reboot` latches `true` and cannot be loosened until reboot is confirmed.
//! 3. **Monotonic Tighten-Only + Read-Back + RFC 6962 Merkle Receipts**: Updates can only expand
//!    mitigated surfaces/CVEs while locked, verify post-commit read-back, and emit verifiable
//!    `MerkleTree` inclusion proofs.
//! 4. **Zero D3QN/RL**: 100% deterministic; zero ML/RL in any shield verdict.

use crate::core::merkle::{MerkleLeaf, MerkleProof, MerkleTree};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Override environment variable for shield posture JSON persistence (primarily for isolated tests).
pub const ENV_SHIELD_POSTURE_PATH: &str = "AGENT_OCTOPUS_SHIELD_POSTURE_PATH";
const DEFAULT_SHIELD_POSTURE_PATH: &str = "logs/kernel_shield_posture.json";
const MAX_SHIELD_POSTURE_BYTES: u64 = 1024 * 1024;

/// Kernel attack surfaces targeted by Zero-Reboot Virtual Patching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelAttackSurface {
    SmbV3AndKsmbd,
    HttpSys,
    Ipv6Rce,
    NetfilterNfTables,
    IoUringEop,
    EbpfAndUserfaultfd,
    Win32kAndByovd,
    DarwinIokitKext,
    GenericKernelCve,
}

impl KernelAttackSurface {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SmbV3AndKsmbd => "smb_v3_and_ksmbd",
            Self::HttpSys => "http_sys",
            Self::Ipv6Rce => "ipv6_rce",
            Self::NetfilterNfTables => "netfilter_nf_tables",
            Self::IoUringEop => "io_uring_eop",
            Self::EbpfAndUserfaultfd => "ebpf_and_userfaultfd",
            Self::Win32kAndByovd => "win32k_and_byovd",
            Self::DarwinIokitKext => "darwin_iokit_kext",
            Self::GenericKernelCve => "generic_kernel_cve",
        }
    }

    /// Returns baseline proactive virtual-patch surfaces applied fail-closed on every host.
    #[must_use]
    pub fn baseline_proactive_surfaces() -> Vec<Self> {
        vec![
            Self::SmbV3AndKsmbd,
            Self::HttpSys,
            Self::Ipv6Rce,
            Self::NetfilterNfTables,
            Self::IoUringEop,
            Self::EbpfAndUserfaultfd,
            Self::Win32kAndByovd,
            Self::DarwinIokitKext,
        ]
    }

    /// Maps a CVE description / KEV title to impacted kernel attack surfaces deterministically.
    #[must_use]
    pub fn classify_cve(cve_id: &str, description: &str, cisa_name: Option<&str>) -> Vec<Self> {
        let mut combined = String::with_capacity(
            cve_id.len() + description.len() + cisa_name.map_or(0, str::len) + 2,
        );
        combined.push_str(cve_id);
        combined.push(' ');
        combined.push_str(description);
        if let Some(name) = cisa_name {
            combined.push(' ');
            combined.push_str(name);
        }
        let lower = combined.to_ascii_lowercase();

        let mut surfaces = Vec::new();
        if lower.contains("smb") || lower.contains("ksmbd") || lower.contains("445") {
            surfaces.push(Self::SmbV3AndKsmbd);
        }
        if lower.contains("http.sys") || lower.contains("http2") || lower.contains("http/3") {
            surfaces.push(Self::HttpSys);
        }
        if lower.contains("ipv6") || lower.contains("icmpv6") || lower.contains("tcp/ip") {
            surfaces.push(Self::Ipv6Rce);
        }
        if lower.contains("netfilter") || lower.contains("nf_tables") || lower.contains("nftables")
        {
            surfaces.push(Self::NetfilterNfTables);
        }
        if lower.contains("io_uring") {
            surfaces.push(Self::IoUringEop);
        }
        if lower.contains("ebpf")
            || lower.contains("bpf")
            || lower.contains("userfaultfd")
            || lower.contains("keyctl")
        {
            surfaces.push(Self::EbpfAndUserfaultfd);
        }
        if lower.contains("win32k")
            || lower.contains("byovd")
            || lower.contains("driver")
            || lower.contains("clfs")
            || lower.contains("afd.sys")
        {
            surfaces.push(Self::Win32kAndByovd);
        }
        if lower.contains("iokit")
            || lower.contains("kext")
            || lower.contains("darwin")
            || lower.contains("xnu")
        {
            surfaces.push(Self::DarwinIokitKext);
        }
        if surfaces.is_empty() {
            surfaces.push(Self::GenericKernelCve);
        }
        surfaces
    }
}

/// Deterministic, monotonic snapshot of the host's Virtual-Patching Shield posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelShieldPosture {
    pub schema_version: u32,
    pub os_family: String,
    pub cpe23: String,
    #[serde(default)]
    pub running_kernel: String,
    pub unpatched_cve_ids: Vec<String>,
    pub cisa_kev_ids: Vec<String>,
    pub affected_surfaces: Vec<KernelAttackSurface>,
    pub reboot_pending: bool,
    pub livepatch_active: bool,
    pub shield_locked_until_reboot: bool,
    pub telemetry_degraded_fail_closed: bool,
    #[serde(default)]
    pub integrity_tampered: bool,
    #[serde(default)]
    pub monotonic_revision: u64,
    pub posture_sha256: String,
    pub updated_at_unix: u64,
}

impl Default for KernelShieldPosture {
    fn default() -> Self {
        Self::default_fail_closed()
    }
}

impl KernelShieldPosture {
    /// Fail-closed initial posture: keeps proactive baseline virtual-patch clamps active
    /// until a verified NVD/KEV scan completes cleanly with zero pending reboot.
    #[must_use]
    pub fn default_fail_closed() -> Self {
        let mut posture = Self {
            schema_version: 1,
            os_family: std::env::consts::OS.to_string(),
            cpe23: String::new(),
            running_kernel: String::new(),
            unpatched_cve_ids: Vec::new(),
            cisa_kev_ids: Vec::new(),
            affected_surfaces: KernelAttackSurface::baseline_proactive_surfaces(),
            reboot_pending: false,
            livepatch_active: false,
            shield_locked_until_reboot: false,
            telemetry_degraded_fail_closed: true,
            integrity_tampered: false,
            monotonic_revision: 1,
            posture_sha256: String::new(),
            updated_at_unix: unix_now_secs(),
        };
        posture.posture_sha256 = posture.compute_sha256();
        posture
    }

    /// Fail-closed tampered posture: locks `shield_locked_until_reboot = true` and
    /// `integrity_tampered = true` when an existing posture file is corrupt, truncated,
    /// oversized, non-regular, symlinked/reparse-pointed, or fails SHA-256 verification.
    #[must_use]
    pub fn tampered_fail_closed() -> Self {
        let mut posture = Self::default_fail_closed();
        posture.shield_locked_until_reboot = true;
        posture.integrity_tampered = true;
        posture.posture_sha256 = posture.compute_sha256();
        posture
    }

    /// Returns `true` whenever any kernel exposure, reboot window, or (when enabled) degraded
    /// telemetry condition requires deterministic Zero-Breakout & Zero-Breakin virtual patching.
    #[must_use]
    pub fn is_shield_active_with_degraded_policy(&self, fail_closed_on_degraded: bool) -> bool {
        !self.unpatched_cve_ids.is_empty()
            || !self.cisa_kev_ids.is_empty()
            || (self.reboot_pending && !self.livepatch_active)
            || self.shield_locked_until_reboot
            || self.integrity_tampered
            || (fail_closed_on_degraded && self.telemetry_degraded_fail_closed)
    }

    /// Returns `true` whenever any kernel exposure, reboot window, or degraded telemetry condition
    /// requires deterministic Zero-Breakout & Zero-Breakin virtual patching.
    #[must_use]
    pub fn is_shield_active(&self) -> bool {
        self.is_shield_active_with_degraded_policy(true)
    }

    /// Deterministic SHA-256 commitment over all posture security fields.
    #[must_use]
    pub fn compute_sha256(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.schema_version.to_le_bytes());
        hasher.update(self.os_family.as_bytes());
        hasher.update(b"|");
        hasher.update(self.cpe23.as_bytes());
        if !self.running_kernel.is_empty() {
            hasher.update(b"|");
            hasher.update(self.running_kernel.as_bytes());
        }
        hasher.update(b"|");
        for cve in &self.unpatched_cve_ids {
            hasher.update(cve.as_bytes());
            hasher.update(b",");
        }
        hasher.update(b"|");
        for kev in &self.cisa_kev_ids {
            hasher.update(kev.as_bytes());
            hasher.update(b",");
        }
        hasher.update(b"|");
        for surface in &self.affected_surfaces {
            hasher.update(surface.as_str().as_bytes());
            hasher.update(b",");
        }
        hasher.update([
            u8::from(self.reboot_pending),
            u8::from(self.livepatch_active),
            u8::from(self.shield_locked_until_reboot),
            u8::from(self.telemetry_degraded_fail_closed),
        ]);
        hasher.update(self.monotonic_revision.to_le_bytes());
        if self.integrity_tampered {
            hasher.update(b"|integrity_tampered");
        }
        hex::encode(hasher.finalize())
    }

    /// Recomputes and updates `posture_sha256` after canonicalizing sorted deduplicated vectors.
    pub fn finalize(&mut self) {
        let cves: BTreeSet<String> = self.unpatched_cve_ids.drain(..).collect();
        self.unpatched_cve_ids = cves.into_iter().collect();

        let kevs: BTreeSet<String> = self.cisa_kev_ids.drain(..).collect();
        self.cisa_kev_ids = kevs.into_iter().collect();

        let surfaces: BTreeSet<KernelAttackSurface> = self.affected_surfaces.drain(..).collect();
        self.affected_surfaces = surfaces.into_iter().collect();

        if (self.reboot_pending && !self.livepatch_active) || self.integrity_tampered {
            self.shield_locked_until_reboot = true;
        }
        self.updated_at_unix = unix_now_secs();
        self.posture_sha256 = self.compute_sha256();
    }
}

/// Cryptographic receipt covering every No Break-Out and No Break-In enforcement step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualPatchShieldReceipt {
    pub posture: KernelShieldPosture,
    pub no_breakout_clamps: Vec<String>,
    pub no_breakin_rules: Vec<String>,
    pub cedar_forbid_policy_ids: Vec<String>,
    #[serde(default)]
    pub os_enforcement_applied: bool,
    pub readback_verified: bool,
    pub merkle_root_hex: String,
    pub merkle_leaves: Vec<MerkleLeaf>,
    pub merkle_proofs: Vec<MerkleProof>,
    pub applied_latency_us: u64,
}

impl VirtualPatchShieldReceipt {
    /// Verifies that every leaf proof resolves cleanly to `merkle_root_hex`.
    #[must_use]
    pub fn verify_merkle_proofs(&self) -> bool {
        if self.merkle_leaves.len() != self.merkle_proofs.len() {
            return false;
        }
        let Ok(root_bytes) = hex::decode(&self.merkle_root_hex) else {
            return false;
        };
        let Ok(root_arr): Result<[u8; 32], _> = root_bytes.try_into() else {
            return false;
        };
        if self.merkle_leaves.is_empty() {
            return root_arr == [0u8; 32];
        }
        self.merkle_leaves
            .iter()
            .zip(self.merkle_proofs.iter())
            .all(|(leaf, proof)| leaf.hash() == proof.leaf_hash && proof.verify(&root_arr))
    }
}

/// Builds a `VirtualPatchShieldReceipt` with RFC 6962 `MerkleTree` leaves and inclusion proofs.
#[must_use]
pub fn build_shield_receipt(
    posture: KernelShieldPosture,
    no_breakout_clamps: Vec<String>,
    no_breakin_rules: Vec<String>,
    cedar_forbid_policy_ids: Vec<String>,
    readback_verified: bool,
    applied_latency_us: u64,
) -> VirtualPatchShieldReceipt {
    build_shield_receipt_with_enforcement(
        posture,
        no_breakout_clamps,
        no_breakin_rules,
        cedar_forbid_policy_ids,
        readback_verified,
        readback_verified,
        applied_latency_us,
    )
}

/// Builds a `VirtualPatchShieldReceipt` with explicit `os_enforcement_applied` and `readback_verified` flags.
#[must_use]
pub fn build_shield_receipt_with_enforcement(
    posture: KernelShieldPosture,
    no_breakout_clamps: Vec<String>,
    no_breakin_rules: Vec<String>,
    cedar_forbid_policy_ids: Vec<String>,
    os_enforcement_applied: bool,
    readback_verified: bool,
    applied_latency_us: u64,
) -> VirtualPatchShieldReceipt {
    let posture_digest = posture.posture_sha256.clone();
    let mut leaves = Vec::new();
    let mut idx = 0usize;

    for clamp in &no_breakout_clamps {
        leaves.push(MerkleLeaf::new(
            idx,
            "no_breakout_clamp",
            &posture_digest,
            sha256_hex(clamp.as_bytes()),
        ));
        idx += 1;
    }
    for rule in &no_breakin_rules {
        leaves.push(MerkleLeaf::new(
            idx,
            "no_breakin_rule",
            &posture_digest,
            sha256_hex(rule.as_bytes()),
        ));
        idx += 1;
    }
    for pid in &cedar_forbid_policy_ids {
        leaves.push(MerkleLeaf::new(
            idx,
            "cedar_forbid_policy",
            &posture_digest,
            sha256_hex(pid.as_bytes()),
        ));
        idx += 1;
    }
    if leaves.is_empty() {
        leaves.push(MerkleLeaf::new(
            0,
            "shield_posture_baseline",
            &posture_digest,
            sha256_hex(if posture.is_shield_active() {
                b"active"
            } else {
                b"standby"
            }),
        ));
    }

    let tree = MerkleTree::from_leaves(leaves.clone());
    let merkle_root_hex = tree.root_hex();
    let merkle_proofs = (0..leaves.len())
        .filter_map(|i| tree.generate_proof(i))
        .collect();

    VirtualPatchShieldReceipt {
        posture,
        no_breakout_clamps,
        no_breakin_rules,
        cedar_forbid_policy_ids,
        os_enforcement_applied,
        readback_verified,
        merkle_root_hex,
        merkle_leaves: leaves,
        merkle_proofs,
        applied_latency_us,
    }
}

/// Isolated store managing monotonic shield posture and optional symlink-checked persistence.
#[derive(Debug)]
pub struct VirtualPatchShieldStore {
    inner: RwLock<KernelShieldPosture>,
    persistence_path: Option<PathBuf>,
}

impl VirtualPatchShieldStore {
    /// Creates a new fail-closed store without automatic disk writes unless `path` is provided.
    ///
    /// Clean missing files (`ErrorKind::NotFound`) initialize `default_fail_closed()` (`shield_locked_until_reboot = false`).
    /// Any existing corrupt, truncated, oversized, non-regular, symlinked/reparse-pointed, or
    /// SHA-256-mismatched posture file initializes `tampered_fail_closed()` (`shield_locked_until_reboot = true`,
    /// `integrity_tampered = true`).
    #[must_use]
    pub fn new(persistence_path: Option<PathBuf>) -> Self {
        let initial = match persistence_path.as_deref().map(Self::load_from_disk) {
            None | Some(Ok(None)) => KernelShieldPosture::default_fail_closed(),
            Some(Ok(Some(posture))) => posture,
            Some(Err(_)) => KernelShieldPosture::tampered_fail_closed(),
        };
        Self {
            inner: RwLock::new(initial),
            persistence_path,
        }
    }

    /// Reads the current posture snapshot in-memory (`<50 us`, zero network I/O).
    #[must_use]
    pub fn current(&self) -> KernelShieldPosture {
        self.inner
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone())
    }

    /// Applies an updated posture monotonically:
    /// - Rejects clearing `shield_locked_until_reboot` while still latched.
    /// - While latched (`shield_locked_until_reboot == true`), unions CVEs, KEVs, and surfaces.
    /// - Verifies post-write read-back integrity.
    pub fn apply_posture(
        &self,
        mut next: KernelShieldPosture,
    ) -> Result<KernelShieldPosture, String> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());

        if guard.shield_locked_until_reboot && !next.shield_locked_until_reboot {
            return Err(
                "Monotonic violation: cannot clear shield_locked_until_reboot without confirmed host reboot"
                    .to_string(),
            );
        }

        if guard.shield_locked_until_reboot {
            next.shield_locked_until_reboot = true;
            if guard.integrity_tampered {
                next.integrity_tampered = true;
            }
            if next.running_kernel.is_empty() && !guard.running_kernel.is_empty() {
                next.running_kernel = guard.running_kernel.clone();
            }
            for cve in &guard.unpatched_cve_ids {
                if !next.unpatched_cve_ids.contains(cve) {
                    next.unpatched_cve_ids.push(cve.clone());
                }
            }
            for kev in &guard.cisa_kev_ids {
                if !next.cisa_kev_ids.contains(kev) {
                    next.cisa_kev_ids.push(kev.clone());
                }
            }
            for s in &guard.affected_surfaces {
                if !next.affected_surfaces.contains(s) {
                    next.affected_surfaces.push(*s);
                }
            }
        }

        // Always keep proactive baseline surfaces when shield is active.
        if next.is_shield_active() {
            for base in KernelAttackSurface::baseline_proactive_surfaces() {
                if !next.affected_surfaces.contains(&base) {
                    next.affected_surfaces.push(base);
                }
            }
        }

        next.monotonic_revision = guard.monotonic_revision.saturating_add(1);
        next.finalize();
        let expected_sha = next.posture_sha256.clone();

        *guard = next.clone();
        if let Some(ref path) = self.persistence_path {
            Self::write_to_disk(path, &next)?;
        }

        // Immediate post-write read-back verification.
        if guard.posture_sha256 != expected_sha || guard.compute_sha256() != expected_sha {
            return Err(
                "Read-back verification failed: stored shield posture hash mismatch".to_string(),
            );
        }
        if let Some(ref path) = self.persistence_path {
            let disk = Self::read_from_disk(path).ok_or_else(|| {
                "Read-back verification failed: persisted shield posture unreadable".to_string()
            })?;
            if disk.posture_sha256 != expected_sha {
                return Err(
                    "Read-back verification failed: persisted shield posture hash mismatch"
                        .to_string(),
                );
            }
        }

        Ok(guard.clone())
    }

    /// Marks telemetry as degraded fail-closed while preserving all locked surfaces/CVEs.
    pub fn mark_telemetry_degraded(&self) -> KernelShieldPosture {
        let mut posture = self.current();
        posture.telemetry_degraded_fail_closed = true;
        for base in KernelAttackSurface::baseline_proactive_surfaces() {
            if !posture.affected_surfaces.contains(&base) {
                posture.affected_surfaces.push(base);
            }
        }
        self.apply_posture(posture).unwrap_or_else(|_| {
            let mut fallback = self.current();
            fallback.telemetry_degraded_fail_closed = true;
            fallback.finalize();
            fallback
        })
    }

    /// Clears `shield_locked_until_reboot` ONLY after verifying `!reboot_still_pending`
    /// and a valid kernel release transition (plus post-write read-back).
    pub fn confirm_reboot_cleared(
        &self,
        new_kernel_release: &str,
        reboot_still_pending: bool,
    ) -> Result<KernelShieldPosture, String> {
        let new_rel = new_kernel_release.trim();
        if reboot_still_pending {
            return Err(format!(
                "Monotonic violation: host still reports reboot_pending on kernel '{}'",
                new_rel
            ));
        }
        if new_rel.is_empty() {
            return Err(
                "Monotonic violation: empty kernel release cannot confirm reboot".to_string(),
            );
        }
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if guard.shield_locked_until_reboot
            && !guard.running_kernel.is_empty()
            && guard.running_kernel == new_rel
        {
            return Err(format!(
                "Monotonic violation: running kernel '{}' has not changed since reboot lock was armed",
                new_rel
            ));
        }
        let mut updated = guard.clone();
        updated.reboot_pending = false;
        updated.shield_locked_until_reboot = false;
        updated.integrity_tampered = false;
        updated.running_kernel = new_rel.to_string();
        updated.monotonic_revision = updated.monotonic_revision.saturating_add(1);
        updated.finalize();
        let expected_sha = updated.posture_sha256.clone();

        if let Some(ref path) = self.persistence_path {
            Self::write_to_disk(path, &updated)?;
            let disk = Self::read_from_disk(path).ok_or_else(|| {
                "Read-back verification failed: persisted shield posture unreadable after reboot confirmation".to_string()
            })?;
            if disk.posture_sha256 != expected_sha {
                return Err(
                    "Read-back verification failed: persisted shield posture hash mismatch after reboot confirmation".to_string(),
                );
            }
        }
        *guard = updated;
        Ok(guard.clone())
    }

    fn is_symlink_or_reparse(meta: &std::fs::Metadata) -> bool {
        if meta.file_type().is_symlink() {
            return true;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                return true;
            }
        }
        false
    }

    fn open_regular_no_follow(path: &Path) -> Result<std::fs::File, String> {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let file = opts
            .open(path)
            .map_err(|e| format!("Failed opening shield posture '{}': {e}", path.display()))?;
        let fmeta = file.metadata().map_err(|e| {
            format!(
                "Failed inspecting open shield posture '{}': {e}",
                path.display()
            )
        })?;
        if Self::is_symlink_or_reparse(&fmeta) || !fmeta.is_file() {
            return Err(format!(
                "Shield posture '{}' is not a regular non-reparse file",
                path.display()
            ));
        }
        Ok(file)
    }

    fn load_from_disk(path: &Path) -> Result<Option<KernelShieldPosture>, String> {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(format!(
                    "Cannot inspect shield posture '{}': {e}",
                    path.display()
                ));
            }
        };
        if Self::is_symlink_or_reparse(&meta) || !meta.is_file() {
            return Err(format!(
                "Shield posture '{}' is a symlink, reparse point, or non-regular file",
                path.display()
            ));
        }
        if meta.len() == 0 || meta.len() > MAX_SHIELD_POSTURE_BYTES {
            return Err(format!(
                "Shield posture '{}' size {} bytes outside valid range (1..={})",
                path.display(),
                meta.len(),
                MAX_SHIELD_POSTURE_BYTES
            ));
        }

        use std::io::Read;
        let file = Self::open_regular_no_follow(path)?;
        let mut buf = Vec::with_capacity(meta.len() as usize);
        file.take(MAX_SHIELD_POSTURE_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("Failed reading shield posture '{}': {e}", path.display()))?;
        if buf.is_empty() || buf.len() as u64 > MAX_SHIELD_POSTURE_BYTES {
            return Err(format!(
                "Shield posture '{}' read {} bytes outside valid range (1..={})",
                path.display(),
                buf.len(),
                MAX_SHIELD_POSTURE_BYTES
            ));
        }

        let raw = std::str::from_utf8(&buf).map_err(|e| {
            format!(
                "Shield posture '{}' contains invalid UTF-8: {e}",
                path.display()
            )
        })?;
        let parsed: KernelShieldPosture = serde_json::from_str(raw).map_err(|e| {
            format!(
                "Shield posture '{}' contains malformed JSON: {e}",
                path.display()
            )
        })?;
        if parsed.schema_version != 1 {
            return Err(format!(
                "Shield posture '{}' has unsupported schema_version {}",
                path.display(),
                parsed.schema_version
            ));
        }
        if parsed.posture_sha256.is_empty() || parsed.compute_sha256() != parsed.posture_sha256 {
            return Err(format!(
                "Shield posture '{}' failed SHA-256 integrity verification",
                path.display()
            ));
        }
        if parsed.integrity_tampered && !parsed.shield_locked_until_reboot {
            return Err(format!(
                "Shield posture '{}' has inconsistent integrity_tampered without reboot lock",
                path.display()
            ));
        }
        Ok(Some(parsed))
    }

    fn read_from_disk(path: &Path) -> Option<KernelShieldPosture> {
        Self::load_from_disk(path).ok().flatten()
    }

    fn write_to_disk(path: &Path, posture: &KernelShieldPosture) -> Result<(), String> {
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if Self::is_symlink_or_reparse(&meta) {
                return Err(format!(
                    "Refusing to write shield posture to symlink or reparse point '{}'",
                    path.display()
                ));
            }
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed creating shield posture dir: {e}"))?;
            }
        }
        let json = serde_json::to_string_pretty(posture)
            .map_err(|e| format!("Failed serializing shield posture: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("Failed writing shield posture: {e}"))?;
        Ok(())
    }
}

static GLOBAL_SHIELD_STORE: OnceLock<VirtualPatchShieldStore> = OnceLock::new();

/// Detects unit test isolation (`cfg!(test)`). Never trusts mutable environment variables
/// or executable directory names (`deps`) in `!cfg!(test)` binaries.
pub(crate) fn is_shield_test_isolation_context() -> bool {
    cfg!(test)
}

fn resolve_global_posture_path() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var(ENV_SHIELD_POSTURE_PATH) {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }
    if is_shield_test_isolation_context() {
        None
    } else {
        Some(PathBuf::from(DEFAULT_SHIELD_POSTURE_PATH))
    }
}

/// Returns the process-wide `VirtualPatchShieldStore`.
pub fn global_shield_store() -> &'static VirtualPatchShieldStore {
    GLOBAL_SHIELD_STORE.get_or_init(|| VirtualPatchShieldStore::new(resolve_global_posture_path()))
}

/// Reads the active `KernelShieldPosture` from `ENV_SHIELD_POSTURE_PATH` (if set) or global store.
#[must_use]
pub fn current_shield_posture() -> KernelShieldPosture {
    if let Ok(custom) = std::env::var(ENV_SHIELD_POSTURE_PATH) {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return match VirtualPatchShieldStore::load_from_disk(Path::new(trimmed)) {
                Ok(Some(disk)) => disk,
                Ok(None) => KernelShieldPosture::default_fail_closed(),
                Err(_) => KernelShieldPosture::tampered_fail_closed(),
            };
        }
    }
    global_shield_store().current()
}

/// Applies an updated `KernelShieldPosture` monotonically to the global store.
pub fn apply_shield_posture(next: KernelShieldPosture) -> Result<KernelShieldPosture, String> {
    if let Ok(custom) = std::env::var(ENV_SHIELD_POSTURE_PATH) {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            let store = VirtualPatchShieldStore::new(Some(PathBuf::from(trimmed)));
            return store.apply_posture(next);
        }
    }
    global_shield_store().apply_posture(next)
}

/// Marks NVD/KEV telemetry as degraded fail-closed in the active shield posture.
#[must_use]
pub fn mark_shield_telemetry_degraded() -> KernelShieldPosture {
    if let Ok(custom) = std::env::var(ENV_SHIELD_POSTURE_PATH) {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            let store = VirtualPatchShieldStore::new(Some(PathBuf::from(trimmed)));
            return store.mark_telemetry_degraded();
        }
    }
    global_shield_store().mark_telemetry_degraded()
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_shield_posture_is_fail_closed() {
        let posture = KernelShieldPosture::default_fail_closed();
        assert!(posture.telemetry_degraded_fail_closed);
        assert!(posture.is_shield_active());
        assert!(!posture.affected_surfaces.is_empty());
        assert_eq!(posture.posture_sha256, posture.compute_sha256());
    }

    #[test]
    fn test_monotonic_store_enforces_reboot_latch_and_merkle_proofs() {
        let store = VirtualPatchShieldStore::new(None);
        let mut locked = KernelShieldPosture::default_fail_closed();
        locked.telemetry_degraded_fail_closed = false;
        locked.reboot_pending = true;
        locked.livepatch_active = false;
        locked.shield_locked_until_reboot = true;
        locked.unpatched_cve_ids = vec!["CVE-2024-1086".to_string()];
        let applied = store.apply_posture(locked).expect("latch applies");
        assert!(applied.shield_locked_until_reboot);
        assert!(applied.is_shield_active());

        // Attempt to clear shield_locked_until_reboot without reboot must fail closed.
        let mut loosen = applied.clone();
        loosen.reboot_pending = false;
        loosen.shield_locked_until_reboot = false;
        let err = store
            .apply_posture(loosen)
            .expect_err("monotonic violation must reject clearing reboot latch");
        assert!(err.contains("Monotonic violation"));

        // Confirm reboot clears latch when reboot_still_pending == false.
        let cleared = store
            .confirm_reboot_cleared("6.8.0-50-generic", false)
            .expect("reboot confirmation clears latch");
        assert!(!cleared.shield_locked_until_reboot);

        let receipt = build_shield_receipt(
            cleared,
            vec!["seccomp_high_cve".to_string()],
            vec!["wfp_smb_445_block".to_string()],
            vec!["vp_cve_2024_1086".to_string()],
            true,
            120,
        );
        assert!(receipt.verify_merkle_proofs());
    }

    #[test]
    fn test_load_from_disk_distinguishes_not_found_vs_tampered_corrupt_oversized_and_dir() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "ao_m7_vps_tamper_unit_{}_{}",
            std::process::id(),
            unix_now_secs()
        ));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).expect("create temp test dir");

        // 1. Clean NotFound -> default_fail_closed (shield_locked_until_reboot=false, integrity_tampered=false)
        let missing_path = tmp_dir.join("missing_posture.json");
        let missing_store = VirtualPatchShieldStore::new(Some(missing_path));
        let missing_cur = missing_store.current();
        assert!(!missing_cur.shield_locked_until_reboot);
        assert!(!missing_cur.integrity_tampered);
        assert!(missing_cur.telemetry_degraded_fail_closed);

        let assert_tampered_locked = |path: PathBuf, label: &str| {
            let store = VirtualPatchShieldStore::new(Some(path));
            let cur = store.current();
            assert!(
                cur.shield_locked_until_reboot,
                "{label}: shield_locked_until_reboot must be true"
            );
            assert!(
                cur.integrity_tampered,
                "{label}: integrity_tampered must be true"
            );
            assert!(
                cur.is_shield_active_with_degraded_policy(false),
                "{label}: shield must remain active even when degraded policy is false"
            );

            let mut unlocked = KernelShieldPosture::default_fail_closed();
            unlocked.telemetry_degraded_fail_closed = false;
            unlocked.shield_locked_until_reboot = false;
            let err = store
                .apply_posture(unlocked)
                .expect_err("tampered posture must reject unlocked apply_posture");
            assert!(
                err.contains("Monotonic violation"),
                "{label}: expected Monotonic violation, got: {err}"
            );

            let degraded = store.mark_telemetry_degraded();
            assert!(
                degraded.shield_locked_until_reboot && degraded.integrity_tampered,
                "{label}: mark_telemetry_degraded must preserve lock & tamper flags"
            );
        };

        // 2. Malformed JSON
        let bad_json_path = tmp_dir.join("malformed.json");
        std::fs::write(&bad_json_path, "{bad_json").expect("write malformed json");
        assert_tampered_locked(bad_json_path, "malformed_json");

        // 3. Empty 0-byte truncated file
        let empty_path = tmp_dir.join("empty.json");
        std::fs::write(&empty_path, b"").expect("write empty file");
        assert_tampered_locked(empty_path, "empty_0_byte");

        // 4. Invalid UTF-8 bytes
        let bad_utf8_path = tmp_dir.join("invalid_utf8.json");
        std::fs::write(&bad_utf8_path, [0xFF, 0xFE, 0xFD, 0x80]).expect("write invalid utf8");
        assert_tampered_locked(bad_utf8_path, "invalid_utf8");

        // 5. Directory at posture path
        let dir_path = tmp_dir.join("dir_posture.json");
        std::fs::create_dir_all(&dir_path).expect("create dir at posture path");
        assert_tampered_locked(dir_path, "directory");

        // 6. Oversized > 1 MiB file
        let oversized_path = tmp_dir.join("oversized.json");
        let oversized_buf = vec![b' '; (MAX_SHIELD_POSTURE_BYTES as usize) + 64];
        std::fs::write(&oversized_path, oversized_buf).expect("write oversized file");
        assert_tampered_locked(oversized_path, "oversized");

        // 7. Valid JSON with flipped shield_locked_until_reboot=false & stale posture_sha256
        let mut valid_locked = KernelShieldPosture::default_fail_closed();
        valid_locked.shield_locked_until_reboot = true;
        valid_locked.finalize();
        let mut tampered_val =
            serde_json::to_value(&valid_locked).expect("serialize locked posture");
        tampered_val["shield_locked_until_reboot"] = serde_json::Value::Bool(false);
        let tampered_sha_path = tmp_dir.join("tampered_sha.json");
        std::fs::write(
            &tampered_sha_path,
            serde_json::to_string_pretty(&tampered_val).expect("serialize tampered json"),
        )
        .expect("write tampered sha file");
        assert_tampered_locked(tampered_sha_path, "tampered_sha256");

        // 8. Symlink at posture path
        let target_path = tmp_dir.join("real_target.json");
        std::fs::write(
            &target_path,
            serde_json::to_string_pretty(&KernelShieldPosture::default_fail_closed())
                .expect("serialize target"),
        )
        .expect("write symlink target");
        let symlink_path = tmp_dir.join("symlink_posture.json");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target_path, &symlink_path)
                .expect("create unix symlink posture");
            assert_tampered_locked(symlink_path, "unix_symlink");
        }
        #[cfg(windows)]
        {
            if std::os::windows::fs::symlink_file(&target_path, &symlink_path).is_ok() {
                assert_tampered_locked(symlink_path, "windows_symlink");
            }
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
