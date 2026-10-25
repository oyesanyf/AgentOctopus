//! Bounded Input-File Lineage & Canary Trap Tracker (`SEC-LIN-01`)
//!
//! Adapted from `D:\harfile\OshoosiClaw\crates\osoosi-agent-anomaly\src\file_lineage.rs`:
//! - Tracks up to `MAX_LINEAGE_RECORDS` (16,384) file ingestion events with FIFO eviction.
//! - Enforces **Hard Repository & Developer Toolchain Immunity** (`is_path_immune`) checked
//!   *before* `poisoned_digests` so project source files (`Cargo.toml`, `src/`, `crates/`,
//!   `scripts/`, `tests/`) and standard developer toolchains (`git.exe`, `cargo.exe`, `rustc.exe`,
//!   `py312.exe`, `node.exe`) can NEVER be falsely poisoned or deadlocked.
//! - Detects canary trap touches and indirect prompt-injection poison propagation across files.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_LINEAGE_RECORDS: usize = 16_384;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLineageRecord {
    pub normalized_path: String,
    pub sha256_digest: String,
    pub ingested_by_agent: String,
    pub origin_source: String,
    pub is_tainted_external: bool,
    pub is_canary_trap: bool,
    pub timestamp_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageCheckVerdict {
    pub allowed: bool,
    pub path: String,
    pub is_immune_repository_or_toolchain: bool,
    pub is_canary_tripped: bool,
    pub is_poisoned_lineage: bool,
    pub reason: String,
}

pub struct FileLineageTracker {
    max_capacity: usize,
    fifo_order: RwLock<VecDeque<String>>,
    records: RwLock<HashMap<String, FileLineageRecord>>,
    poisoned_digests: RwLock<HashSet<String>>,
    canary_digests: RwLock<HashSet<String>>,
    canary_paths: RwLock<HashSet<String>>,
}

impl Default for FileLineageTracker {
    fn default() -> Self {
        Self::new(MAX_LINEAGE_RECORDS)
    }
}

impl FileLineageTracker {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            max_capacity: max_capacity.max(16),
            fifo_order: RwLock::new(VecDeque::new()),
            records: RwLock::new(HashMap::new()),
            poisoned_digests: RwLock::new(HashSet::new()),
            canary_digests: RwLock::new(HashSet::new()),
            canary_paths: RwLock::new(HashSet::new()),
        }
    }

    pub fn normalize_path(path: &str) -> String {
        path.trim().replace('\\', "/").to_ascii_lowercase()
    }

    pub fn compute_digest(content: &[u8]) -> String {
        hex::encode(Sha256::digest(content))
    }

    /// Hard Repository & Developer Toolchain Immunity Invariant:
    /// Always evaluated BEFORE `poisoned_digests` so legitimate developer/build files
    /// cannot be DoS-locked by hash collisions or adversarial taint injection.
    pub fn is_path_immune(path: &str) -> bool {
        let norm = Self::normalize_path(path);
        // Never grant immunity to agent scratchpads or temporary directories even if a subdirectory
        // is named `src/` or `cargo.toml`.
        if norm.contains("scratchpad")
            || norm.contains("/temp/")
            || norm.contains("\\temp\\")
            || norm.contains("/tmp/")
            || norm.starts_with("tmp/")
            || norm.starts_with("temp/")
        {
            return false;
        }
        let exact_or_suffix = [
            "cargo.toml",
            "cargo.lock",
            "pyproject.toml",
            "package.json",
            "/src/",
            "/crates/",
            "/tests/",
            "/scripts/",
            "/git.exe",
            "/cargo.exe",
            "/rustc.exe",
            "/rustfmt.exe",
            "/clippy-driver.exe",
            "/py312.exe",
            "/python.exe",
            "/node.exe",
            "/powershell.exe",
            "/pwsh.exe",
        ];
        norm.starts_with("src/")
            || norm.starts_with("crates/")
            || norm.starts_with("tests/")
            || norm.starts_with("scripts/")
            || exact_or_suffix
                .iter()
                .any(|m| norm == m.trim_start_matches('/') || norm.ends_with(m) || (m.ends_with('/') && norm.contains(m)))
    }

    /// Registers a synthetic canary honeyfile path and its content digest.
    pub fn register_canary_trap(&self, path: &str, content: &[u8]) -> String {
        let norm = Self::normalize_path(path);
        let digest = Self::compute_digest(content);
        self.canary_paths.write().unwrap().insert(norm);
        self.canary_digests.write().unwrap().insert(digest.clone());
        digest
    }

    /// Records a file ingestion event into the bounded FIFO lineage map.
    pub fn record_file_ingest(
        &self,
        path: &str,
        content: &[u8],
        ingested_by_agent: &str,
        origin_source: &str,
        is_tainted_external: bool,
    ) -> FileLineageRecord {
        let norm = Self::normalize_path(path);
        let digest = Self::compute_digest(content);
        let is_canary = self.canary_paths.read().unwrap().contains(&norm)
            || self.canary_digests.read().unwrap().contains(&digest);

        if is_tainted_external && !Self::is_path_immune(&norm) {
            self.poisoned_digests.write().unwrap().insert(digest.clone());
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let rec = FileLineageRecord {
            normalized_path: norm.clone(),
            sha256_digest: digest,
            ingested_by_agent: ingested_by_agent.to_string(),
            origin_source: origin_source.to_string(),
            is_tainted_external,
            is_canary_trap: is_canary,
            timestamp_secs: now_secs,
        };

        let mut records = self.records.write().unwrap();
        let mut fifo = self.fifo_order.write().unwrap();
        if !records.contains_key(&norm) {
            while fifo.len() >= self.max_capacity {
                if let Some(evicted_key) = fifo.pop_front() {
                    records.remove(&evicted_key);
                }
            }
            fifo.push_back(norm.clone());
        }
        records.insert(norm, rec.clone());
        rec
    }

    /// Evaluates a file access or tool input against canary traps, hard immunity, and poisoned lineage.
    pub fn evaluate_lineage(&self, path: &str, content: Option<&[u8]>) -> LineageCheckVerdict {
        let norm = Self::normalize_path(path);
        let content_digest = content.map(Self::compute_digest);

        // 1. Check Canary Trap FIRST (touching a honeyfile always triggers immediate autotomy)
        let canary_path_hit = self.canary_paths.read().unwrap().contains(&norm);
        let canary_digest_hit = content_digest
            .as_ref()
            .map(|d| self.canary_digests.read().unwrap().contains(d))
            .unwrap_or(false);

        if canary_path_hit || canary_digest_hit {
            return LineageCheckVerdict {
                allowed: false,
                path: path.to_string(),
                is_immune_repository_or_toolchain: false,
                is_canary_tripped: true,
                is_poisoned_lineage: true,
                reason: format!(
                    "LINEAGE_CANARY_TRAP_TRIPPED: Agent accessed decoy canary trap '{}'",
                    path
                ),
            };
        }

        // 2. Hard Repository & Developer Toolchain Immunity BEFORE poisoned_digests
        if Self::is_path_immune(&norm) {
            return LineageCheckVerdict {
                allowed: true,
                path: path.to_string(),
                is_immune_repository_or_toolchain: true,
                is_canary_tripped: false,
                is_poisoned_lineage: false,
                reason: "LINEAGE_IMMUNE_PATH_PERMIT: Verified repository/toolchain path is immune from taint lockout".to_string(),
            };
        }

        // 3. Check Poisoned Digest & Tainted Lineage
        let digest_poisoned = content_digest
            .as_ref()
            .map(|d| self.poisoned_digests.read().unwrap().contains(d))
            .unwrap_or(false);

        let record_tainted = self
            .records
            .read()
            .unwrap()
            .get(&norm)
            .map(|r| r.is_tainted_external)
            .unwrap_or(false);

        if digest_poisoned || record_tainted {
            return LineageCheckVerdict {
                allowed: false,
                path: path.to_string(),
                is_immune_repository_or_toolchain: false,
                is_canary_tripped: false,
                is_poisoned_lineage: true,
                reason: format!(
                    "LINEAGE_POISON_BLOCKED: File '{}' carries untrusted external taint lineage",
                    path
                ),
            };
        }

        LineageCheckVerdict {
            allowed: true,
            path: path.to_string(),
            is_immune_repository_or_toolchain: false,
            is_canary_tripped: false,
            is_poisoned_lineage: false,
            reason: "LINEAGE_CLEAN_PERMIT".to_string(),
        }
    }

    pub fn len(&self) -> usize {
        self.records.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
