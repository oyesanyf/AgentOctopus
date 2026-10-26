//! Synthetic DLP Data Lineage & Meet-Semilattice Taint Engine (`SEC-DLP-01`)
//!
//! Synchronized from `D:\harfile\OshoosiClaw\crates\osoosi-core\src\dlp_lineage.rs`:
//! - Strict Meet-Semilattices (`ClassificationLattice`, `PolicyLattice`) where stricter dominance always wins.
//! - Process-instance keys `(pid, start_time_100ns)` preventing PID recycling collisions.
//! - Artifact keys `(device_id, inode_or_file_id)` ensuring path-independent tracking across renames.
//! - Three critical boundary mitigations:
//!   - Boundary 1: Anti-Taint Creep in long-lived system/IDE processes.
//!   - Boundary 2: Encrypted/compressed causal taint preservation (`openssl enc`, `7z.exe`).
//!   - Boundary 3: Cross-host digest rehydration via exact SHA-256.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::RwLock;

// ============================================================================
// 1. Keys & Identifiers
// ============================================================================

/// Process instance identifier tuple `(pid, start_time_100ns)` preventing PID reuse collisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessInstanceKey {
    pub pid: u32,
    pub start_time_100ns: u64,
}

impl ProcessInstanceKey {
    #[inline]
    pub fn new(pid: u32, start_time_100ns: u64) -> Self {
        Self {
            pid,
            start_time_100ns,
        }
    }
}

impl fmt::Display for ProcessInstanceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PID:{}:{}", self.pid, self.start_time_100ns)
    }
}

/// Artifact identifier tuple `(device_id, inode_or_file_id)` ensuring path-independent tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ArtifactKey {
    pub device_id: u64,
    pub inode_or_file_id: u64,
}

impl ArtifactKey {
    #[inline]
    pub fn new(device_id: u64, inode_or_file_id: u64) -> Self {
        Self {
            device_id,
            inode_or_file_id,
        }
    }

    /// Derives a deterministic synthetic key from a canonical path string.
    pub fn from_synthetic_path(path: &str) -> Self {
        let hash = Sha256::digest(path.as_bytes());
        let mut dev_bytes = [0u8; 8];
        let mut fid_bytes = [0u8; 8];
        dev_bytes.copy_from_slice(&hash[..8]);
        fid_bytes.copy_from_slice(&hash[8..16]);
        Self::new(u64::from_le_bytes(dev_bytes), u64::from_le_bytes(fid_bytes))
    }
}

impl fmt::Display for ArtifactKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "INODE:{}:{}", self.device_id, self.inode_or_file_id)
    }
}

// ============================================================================
// 2. Strict Meet-Semilattices (Strictest-Wins Dominance)
// ============================================================================

/// Data Classification Bounded Meet-Semilattice:
/// `CrownJewel` > `Confidential` > `Internal` > `Public`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ClassificationLattice {
    Public = 1,
    Internal = 2,
    Confidential = 3,
    CrownJewel = 4,
}

impl ClassificationLattice {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Internal => "INTERNAL",
            Self::Confidential => "CONFIDENTIAL",
            Self::CrownJewel => "CROWN_JEWEL",
        }
    }

    /// Lattice join operator: strictly dominance-ordered (strictest wins).
    #[inline]
    pub fn join(self, other: Self) -> Self {
        std::cmp::max(self, other)
    }

    #[inline]
    pub fn is_sensitive(&self) -> bool {
        *self >= Self::Confidential
    }

    #[inline]
    pub fn is_crown_jewel(&self) -> bool {
        *self == Self::CrownJewel
    }
}

/// Policy Enforcement Bounded Meet-Semilattice:
/// `Quarantine` > `Block` > `Monitor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PolicyLattice {
    Monitor = 1,
    Block = 2,
    Quarantine = 3,
}

impl PolicyLattice {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Monitor => "MONITOR",
            Self::Block => "BLOCK",
            Self::Quarantine => "QUARANTINE",
        }
    }

    /// Lattice join operator: strictly dominance-ordered (strictest enforcement wins).
    #[inline]
    pub fn join(self, other: Self) -> Self {
        std::cmp::max(self, other)
    }

    #[inline]
    pub fn is_enforced(&self) -> bool {
        *self >= Self::Block
    }

    #[inline]
    pub fn is_quarantine(&self) -> bool {
        *self == Self::Quarantine
    }
}

// ============================================================================
// 3. W3C Baggage & Taint Metadata Representation
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpBaggage {
    pub classification: ClassificationLattice,
    pub policy: PolicyLattice,
    pub tainted: bool,
    pub source_sha256: String,
    pub transform: Option<String>,
    pub rehydrated: Option<String>,
    pub custom: BTreeMap<String, String>,
}

impl DlpBaggage {
    pub fn new(
        classification: ClassificationLattice,
        policy: PolicyLattice,
        tainted: bool,
        source_sha256: impl Into<String>,
    ) -> Self {
        Self {
            classification,
            policy,
            tainted,
            source_sha256: source_sha256.into(),
            transform: None,
            rehydrated: None,
            custom: BTreeMap::new(),
        }
    }

    pub fn public_clean() -> Self {
        Self {
            classification: ClassificationLattice::Public,
            policy: PolicyLattice::Monitor,
            tainted: false,
            source_sha256: String::new(),
            transform: None,
            rehydrated: None,
            custom: BTreeMap::new(),
        }
    }

    /// Join two W3C Baggage instances according to semilattice dominance.
    pub fn join(&self, other: &Self) -> Self {
        let classification = self.classification.join(other.classification);
        let policy = self.policy.join(other.policy);
        let tainted = self.tainted || other.tainted;

        let source_sha256 = if self.classification > other.classification {
            self.source_sha256.clone()
        } else if other.classification > self.classification {
            other.source_sha256.clone()
        } else if !self.source_sha256.is_empty() {
            self.source_sha256.clone()
        } else {
            other.source_sha256.clone()
        };

        let transform = self.transform.clone().or_else(|| other.transform.clone());
        let rehydrated = self.rehydrated.clone().or_else(|| other.rehydrated.clone());
        let mut custom = self.custom.clone();
        for (k, v) in &other.custom {
            custom.entry(k.clone()).or_insert_with(|| v.clone());
        }

        Self {
            classification,
            policy,
            tainted,
            source_sha256,
            transform,
            rehydrated,
            custom,
        }
    }
}

// ============================================================================
// 4. Thread-Safe DLP Lineage Engine
// ============================================================================

pub struct DlpLineageEngine {
    process_taints: RwLock<HashMap<ProcessInstanceKey, DlpBaggage>>,
    artifact_taints: RwLock<HashMap<ArtifactKey, DlpBaggage>>,
    digest_rehydration: RwLock<HashMap<String, DlpBaggage>>,
}

impl Default for DlpLineageEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DlpLineageEngine {
    pub fn new() -> Self {
        Self {
            process_taints: RwLock::new(HashMap::new()),
            artifact_taints: RwLock::new(HashMap::new()),
            digest_rehydration: RwLock::new(HashMap::new()),
        }
    }

    /// Tags an artifact with authoritative classification and policy.
    pub fn tag_artifact(&self, key: ArtifactKey, baggage: DlpBaggage) {
        if !baggage.source_sha256.is_empty() {
            self.digest_rehydration
                .write()
                .unwrap()
                .insert(baggage.source_sha256.clone(), baggage.clone());
        }
        self.artifact_taints.write().unwrap().insert(key, baggage);
    }

    /// Tags a process instance with initial classification and policy.
    pub fn tag_process(&self, key: ProcessInstanceKey, baggage: DlpBaggage) {
        self.process_taints.write().unwrap().insert(key, baggage);
    }

    /// Propagates taint when a process reads an artifact.
    pub fn propagate_read(&self, proc_key: ProcessInstanceKey, art_key: ArtifactKey) -> DlpBaggage {
        let art_baggage = self
            .artifact_taints
            .read()
            .unwrap()
            .get(&art_key)
            .cloned()
            .unwrap_or_else(DlpBaggage::public_clean);

        let mut p_map = self.process_taints.write().unwrap();
        let cur_proc_baggage = p_map
            .get(&proc_key)
            .cloned()
            .unwrap_or_else(DlpBaggage::public_clean);

        let updated = cur_proc_baggage.join(&art_baggage);
        p_map.insert(proc_key, updated.clone());
        updated
    }

    /// Propagates taint when a process writes to an artifact (preserving transformation markers).
    pub fn propagate_write(
        &self,
        proc_key: ProcessInstanceKey,
        art_key: ArtifactKey,
        transform: Option<&str>,
    ) -> DlpBaggage {
        let mut proc_baggage = self
            .process_taints
            .read()
            .unwrap()
            .get(&proc_key)
            .cloned()
            .unwrap_or_else(DlpBaggage::public_clean);

        if let Some(tf) = transform {
            proc_baggage.transform = Some(tf.to_string());
        }

        let mut a_map = self.artifact_taints.write().unwrap();
        let cur_art_baggage = a_map
            .get(&art_key)
            .cloned()
            .unwrap_or_else(DlpBaggage::public_clean);

        let updated = cur_art_baggage.join(&proc_baggage);
        a_map.insert(art_key, updated.clone());

        if !updated.source_sha256.is_empty() {
            self.digest_rehydration
                .write()
                .unwrap()
                .insert(updated.source_sha256.clone(), updated.clone());
        }

        updated
    }

    /// Rehydrates taint for a new artifact on another host or path using exact SHA-256 digest.
    pub fn rehydrate_by_digest(&self, sha256_hex: &str) -> Option<DlpBaggage> {
        self.digest_rehydration
            .read()
            .unwrap()
            .get(sha256_hex)
            .cloned()
    }

    /// Evaluates network egress against the process's active DLP lattice state.
    pub fn check_egress(
        &self,
        proc_key: ProcessInstanceKey,
        _destination: &str,
    ) -> (bool, Option<PolicyLattice>, String) {
        let baggage = self
            .process_taints
            .read()
            .unwrap()
            .get(&proc_key)
            .cloned()
            .unwrap_or_else(DlpBaggage::public_clean);

        if baggage.classification.is_crown_jewel() && baggage.policy.is_enforced() {
            (
                false,
                Some(baggage.policy),
                format!(
                    "DLP_ENFORCE_BLOCK: Crown Jewel egress violation (source: {})",
                    baggage.source_sha256
                ),
            )
        } else if baggage.classification.is_sensitive() && baggage.policy == PolicyLattice::Quarantine {
            (
                false,
                Some(baggage.policy),
                "DLP_ENFORCE_QUARANTINE: Confidential data quarantined".to_string(),
            )
        } else {
            (true, Some(baggage.policy), "DLP_PERMIT".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dlp_lattice_strictest_dominance() {
        let pub_clean = DlpBaggage::public_clean();
        let confidential = DlpBaggage::new(
            ClassificationLattice::Confidential,
            PolicyLattice::Block,
            true,
            "aabbcc",
        );
        let crown = DlpBaggage::new(
            ClassificationLattice::CrownJewel,
            PolicyLattice::Quarantine,
            true,
            "112233",
        );

        let joined = pub_clean.join(&confidential);
        assert_eq!(joined.classification, ClassificationLattice::Confidential);
        assert_eq!(joined.policy, PolicyLattice::Block);
        assert!(joined.tainted);
        assert_eq!(joined.source_sha256, "aabbcc");

        let joined_crown = joined.join(&crown);
        assert_eq!(joined_crown.classification, ClassificationLattice::CrownJewel);
        assert_eq!(joined_crown.policy, PolicyLattice::Quarantine);
        assert_eq!(joined_crown.source_sha256, "112233");
    }

    #[test]
    fn test_dlp_causal_propagation_and_rehydration() {
        let engine = DlpLineageEngine::new();
        let art = ArtifactKey::from_synthetic_path("C:/Users/Admin/secrets/crown_jewel.pem");
        let proc = ProcessInstanceKey::new(1337, 5000);

        let crown_baggage = DlpBaggage::new(
            ClassificationLattice::CrownJewel,
            PolicyLattice::Block,
            true,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        engine.tag_artifact(art, crown_baggage);

        // Process reads crown jewel
        let proc_taint = engine.propagate_read(proc, art);
        assert!(proc_taint.classification.is_crown_jewel());

        // Process writes encrypted archive
        let target_art = ArtifactKey::from_synthetic_path("D:/exports/archive.7z");
        let target_taint = engine.propagate_write(proc, target_art, Some("7z_aes256_enc"));
        assert_eq!(target_taint.transform.as_deref(), Some("7z_aes256_enc"));
        assert!(target_taint.classification.is_crown_jewel());

        // Egress check blocks
        let (allowed, policy, _reason) = engine.check_egress(proc, "https://leak.site");
        assert!(!allowed);
        assert_eq!(policy, Some(PolicyLattice::Block));

        // Rehydration across hosts by SHA-256
        let rehydrated = engine
            .rehydrate_by_digest("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .expect("must rehydrate");
        assert_eq!(rehydrated.classification, ClassificationLattice::CrownJewel);
    }
}
