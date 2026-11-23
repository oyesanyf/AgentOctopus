//! Red-Team Upgrade #4: Cryptographic Instruction & Memory File Provenance
//! + Live `notify` Filesystem Tamper Watcher.
//!
//! Defends against **Delayed Break-In / Persistent Memory Poisoning** where an attacker
//! plants instructions in `.cursorrules`, `CLAUDE.md`, `AGENTS.md`, `MEMORY.md`, or
//! `SKILL.md` (or delivers a Mark-of-the-Web downloaded file).
//!
//! Only cryptographically human-attested instruction files matching their signed SHA-256
//! digest and free of MotW/injection markers may enter the privileged **Control Plane**.
//! Unattested, modified, or MotW files are strictly quarantined into the **Inert Data Plane**
//! so they can NEVER alter agent instructions.

use crate::security::artemis_dfir::{inspect_mark_of_the_web, unix_now_secs};
use crate::security::identity::hmac_sha256;
use crate::security::log_sanitizer::LogSanitizer;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Execution privilege plane assigned to a workspace instruction or memory file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryPlane {
    /// Verified human-attested instruction file allowed in system prompt / control plane.
    ControlPlaneTrusted,
    /// Unattested, modified, or MotW file quarantined as passive inert data only.
    InertDataPlane,
}

/// Cryptographic provenance attestation for a human-approved instruction/memory file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAttestationRecord {
    pub normalized_path: String,
    pub content_sha256: String,
    pub attested_by: String,
    pub attested_epoch: u64,
    pub attested_at_unix: u64,
    pub hmac_hex: String,
}

/// Evaluation verdict for loading a workspace instruction/memory file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProvenanceVerdict {
    pub plane: MemoryPlane,
    pub allowed_in_control_plane: bool,
    pub tampered_or_unattested: bool,
    pub has_mark_of_the_web: bool,
    pub has_injection_or_unicode_smuggling: bool,
    pub observed_sha256: String,
    pub reason: String,
}

/// Handle keeping a live `notify` background watcher alive for workspace instruction files.
pub struct MemoryWatcherHandle {
    _watcher: RecommendedWatcher,
}

/// Registry enforcing cryptographic provenance on agent instruction & persistent memory files.
pub struct MemoryProvenanceGuard {
    signing_key: Zeroizing<[u8; 32]>,
    attestations: RwLock<HashMap<String, MemoryAttestationRecord>>,
    tamper_events: RwLock<Vec<String>>,
}

impl Default for MemoryProvenanceGuard {
    fn default() -> Self {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        Self::new(key)
    }
}

impl MemoryProvenanceGuard {
    #[must_use]
    pub fn new(signing_key: [u8; 32]) -> Self {
        Self {
            signing_key: Zeroizing::new(signing_key),
            attestations: RwLock::new(HashMap::new()),
            tamper_events: RwLock::new(Vec::new()),
        }
    }

    fn normalize(path: &str) -> String {
        path.trim().replace('\\', "/").to_ascii_lowercase()
    }

    fn compute_attestation_mac(
        &self,
        norm_path: &str,
        sha256: &str,
        attested_by: &str,
        epoch: u64,
    ) -> [u8; 32] {
        let payload = format!(
            "OCTOPUS_MEM_PROVENANCE_V1|{norm_path}|{sha256}|{}|{epoch}",
            attested_by.trim().to_ascii_lowercase()
        );
        hmac_sha256(&self.signing_key[..], payload.as_bytes())
    }

    /// Cryptographically attests a clean human-reviewed instruction/memory file.
    pub fn attest_content(
        &self,
        path: &str,
        content: &str,
        attested_by: &str,
        epoch: u64,
    ) -> MemoryAttestationRecord {
        let norm = Self::normalize(path);
        let sha256 = hex::encode(Sha256::digest(content.as_bytes()));
        let mac = self.compute_attestation_mac(&norm, &sha256, attested_by, epoch);
        let rec = MemoryAttestationRecord {
            normalized_path: norm.clone(),
            content_sha256: sha256,
            attested_by: attested_by.to_string(),
            attested_epoch: epoch,
            attested_at_unix: unix_now_secs(),
            hmac_hex: hex::encode(mac),
        };
        self.attestations.write().insert(norm, rec.clone());
        rec
    }

    /// Attests an on-disk file safely (rejecting symlinks and files > 512 KiB).
    pub fn attest_file(
        &self,
        path: &Path,
        attested_by: &str,
        epoch: u64,
    ) -> Result<MemoryAttestationRecord, String> {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| format!("Failed inspecting file metadata: {e}"))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err("Refusing to attest symlink or non-regular file".to_string());
        }
        if meta.len() > 512 * 1024 {
            return Err("Instruction file exceeds 512 KiB attestation cap".to_string());
        }
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("UTF-8 read error: {e}"))?;
        Ok(self.attest_content(&path.to_string_lossy(), &content, attested_by, epoch))
    }

    /// Evaluates whether an instruction/memory file may enter the Control Plane or must
    /// be downgraded to the Inert Data Plane.
    #[must_use]
    pub fn evaluate_content(
        &self,
        path: &str,
        content: &str,
        has_mark_of_the_web: bool,
    ) -> MemoryProvenanceVerdict {
        let norm = Self::normalize(path);
        let observed_sha256 = hex::encode(Sha256::digest(content.as_bytes()));

        let stripped = LogSanitizer::strip_dangerous_unicode(content);
        let lower = stripped.to_ascii_lowercase();
        let has_injection = stripped.len() != content.len()
            || lower.contains("ignore previous instructions")
            || lower.contains("ignore all prior")
            || lower.contains("override system policy")
            || lower.contains("<|im_start|>")
            || lower.contains("<|system|>")
            || lower.contains("exfiltrate");

        if has_mark_of_the_web {
            return MemoryProvenanceVerdict {
                plane: MemoryPlane::InertDataPlane,
                allowed_in_control_plane: false,
                tampered_or_unattested: true,
                has_mark_of_the_web: true,
                has_injection_or_unicode_smuggling: has_injection,
                observed_sha256,
                reason: format!(
                    "MEMORY_MOTW_QUARANTINE: '{path}' carries Mark-of-the-Web; locked to Inert Data Plane"
                ),
            };
        }

        if has_injection {
            return MemoryProvenanceVerdict {
                plane: MemoryPlane::InertDataPlane,
                allowed_in_control_plane: false,
                tampered_or_unattested: true,
                has_mark_of_the_web: false,
                has_injection_or_unicode_smuggling: true,
                observed_sha256,
                reason: format!(
                    "MEMORY_INJECTION_QUARANTINE: '{path}' contains prompt-injection or invisible Unicode smuggling; locked to Inert Data Plane"
                ),
            };
        }

        let Some(rec) = self.attestations.read().get(&norm).cloned() else {
            return MemoryProvenanceVerdict {
                plane: MemoryPlane::InertDataPlane,
                allowed_in_control_plane: false,
                tampered_or_unattested: true,
                has_mark_of_the_web: false,
                has_injection_or_unicode_smuggling: false,
                observed_sha256,
                reason: format!(
                    "MEMORY_UNATTESTED_QUARANTINE: '{path}' lacks cryptographic human provenance; downgraded to Inert Data Plane"
                ),
            };
        };

        // Constant-time HMAC verification of stored attestation + SHA-256 content integrity check
        let expected_mac = self.compute_attestation_mac(
            &rec.normalized_path,
            &rec.content_sha256,
            &rec.attested_by,
            rec.attested_epoch,
        );
        let mac_ok = hex::decode(rec.hmac_hex.trim())
            .map(|b| b.len() == expected_mac.len() && bool::from(b.as_slice().ct_eq(&expected_mac)))
            .unwrap_or(false);

        if !mac_ok || rec.content_sha256 != observed_sha256 {
            return MemoryProvenanceVerdict {
                plane: MemoryPlane::InertDataPlane,
                allowed_in_control_plane: false,
                tampered_or_unattested: true,
                has_mark_of_the_web: false,
                has_injection_or_unicode_smuggling: false,
                observed_sha256,
                reason: format!(
                    "MEMORY_TAMPER_DETECTED: '{path}' digest changed after human attestation; locked to Inert Data Plane"
                ),
            };
        }

        MemoryProvenanceVerdict {
            plane: MemoryPlane::ControlPlaneTrusted,
            allowed_in_control_plane: true,
            tampered_or_unattested: false,
            has_mark_of_the_web: false,
            has_injection_or_unicode_smuggling: false,
            observed_sha256,
            reason: format!(
                "MEMORY_PROVENANCE_VERIFIED: '{path}' matches human attestation by '{}'",
                rec.attested_by
            ),
        }
    }

    /// Evaluates an on-disk file including live Windows `Zone.Identifier` MotW inspection.
    pub fn evaluate_file(&self, path: &Path) -> Result<MemoryProvenanceVerdict, String> {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| format!("Failed inspecting file metadata: {e}"))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err("Refusing to load symlink or non-regular instruction file".to_string());
        }
        if meta.len() > 512 * 1024 {
            return Err("Instruction file exceeds 512 KiB limit".to_string());
        }
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("UTF-8 read error: {e}"))?;
        let has_motw = inspect_mark_of_the_web(path).is_some();
        Ok(self.evaluate_content(&path.to_string_lossy(), &content, has_motw))
    }

    /// Starts a live `notify` filesystem watcher over `workspace_root` that automatically
    /// detects out-of-band tampering of `.cursorrules`, `CLAUDE.md`, `AGENTS.md`, `MEMORY.md`,
    /// or `SKILL.md` and revokes their Control Plane attestation immediately.
    pub fn start_live_memory_watcher(
        self: &Arc<Self>,
        workspace_root: PathBuf,
    ) -> Result<MemoryWatcherHandle, String> {
        let guard_ref = Arc::clone(self);
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                for path in event.paths {
                    let fname = path
                        .file_name()
                        .map(|f| f.to_string_lossy().to_ascii_lowercase())
                        .unwrap_or_default();
                    if matches!(
                        fname.as_str(),
                        ".cursorrules"
                            | "claude.md"
                            | "agents.md"
                            | "memory.md"
                            | "skill.md"
                            | "copilot-instructions.md"
                            | ".windsurfrules"
                    ) {
                        let norm = Self::normalize(&path.to_string_lossy());
                        guard_ref.attestations.write().remove(&norm);
                        let mut evs = guard_ref.tamper_events.write();
                        if evs.len() >= 256 {
                            evs.remove(0);
                        }
                        evs.push(format!("live_fs_modification_revoked_attestation:{norm}"));
                    }
                }
            }
        })
        .map_err(|e| format!("Failed creating notify watcher: {e}"))?;

        watcher
            .watch(&workspace_root, RecursiveMode::NonRecursive)
            .map_err(|e| format!("Failed watching workspace root: {e}"))?;

        Ok(MemoryWatcherHandle { _watcher: watcher })
    }

    #[must_use]
    pub fn recent_tamper_events(&self) -> Vec<String> {
        self.tamper_events.read().clone()
    }

    #[must_use]
    pub fn attestation_count(&self) -> usize {
        self.attestations.read().len()
    }
}
