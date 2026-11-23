//! Red-Team Upgrade #2: MCP Tool-Schema Cryptographic Rug-Pull Pinning.
//!
//! Defends against MCP Tool Poisoning ("Rug-Pull") attacks where a remote MCP server
//! serves a benign tool manifest during initial approval (`tools/list`), then silently
//! mutates the tool `description` or `inputSchema` later to inject hidden exfiltration
//! instructions into the agent's context window.
//!
//! Pins `SHA-256(canonical_tool_manifest)` upon first human-approved registration; any
//! subsequent digest drift fails closed until an operator explicitly re-approves the pin.

use crate::security::artemis_dfir::unix_now_secs;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Normalized MCP tool definition pinned by AgentOctopus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolManifest {
    pub server_name: String,
    pub tool_name: String,
    pub description: String,
    pub input_schema_json: String,
}

/// Stored cryptographic pin record for a tool manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedToolSchemaRecord {
    pub key: String,
    pub server_name: String,
    pub tool_name: String,
    pub pinned_sha256: String,
    pub approved_by: String,
    pub pinned_at_unix: u64,
}

/// Verdict returned when verifying an MCP tool manifest against its cryptographic pin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaPinVerdict {
    pub allowed: bool,
    pub rug_pull_detected: bool,
    pub observed_sha256: String,
    pub pinned_sha256: Option<String>,
    pub reason: String,
}

/// Computes canonical SHA-256 hash over an MCP tool's server name, tool name, description, and schema.
#[must_use]
pub fn compute_tool_manifest_sha256(manifest: &McpToolManifest) -> String {
    // Normalize JSON schema canonically when valid JSON so harmless whitespace changes don't false-positive
    let normalized_schema = serde_json::from_str::<serde_json::Value>(&manifest.input_schema_json)
        .and_then(|v| serde_json::to_string(&v))
        .unwrap_or_else(|_| manifest.input_schema_json.trim().to_string());

    let mut hasher = Sha256::new();
    hasher.update(b"OCTOPUS_MCP_TOOL_PIN_V1|");
    hasher.update(manifest.server_name.trim().to_ascii_lowercase().as_bytes());
    hasher.update(b"|");
    hasher.update(manifest.tool_name.trim().to_ascii_lowercase().as_bytes());
    hasher.update(b"|");
    hasher.update(manifest.description.trim().as_bytes());
    hasher.update(b"|");
    hasher.update(normalized_schema.as_bytes());
    hex::encode(hasher.finalize())
}

/// Registry enforcing cryptographic SHA-256 tool-manifest pinning against rug-pull mutations.
#[derive(Default)]
pub struct McpToolSchemaPinRegistry {
    pins: RwLock<HashMap<String, PinnedToolSchemaRecord>>,
}

impl McpToolSchemaPinRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn key(server_name: &str, tool_name: &str) -> String {
        format!(
            "{}::{}",
            server_name.trim().to_ascii_lowercase(),
            tool_name.trim().to_ascii_lowercase()
        )
    }

    /// Explicitly pins or re-approves a tool manifest after human review.
    pub fn pin_manifest(
        &self,
        manifest: &McpToolManifest,
        approved_by: &str,
    ) -> PinnedToolSchemaRecord {
        let k = Self::key(&manifest.server_name, &manifest.tool_name);
        let digest = compute_tool_manifest_sha256(manifest);
        let rec = PinnedToolSchemaRecord {
            key: k.clone(),
            server_name: manifest.server_name.clone(),
            tool_name: manifest.tool_name.clone(),
            pinned_sha256: digest,
            approved_by: approved_by.to_string(),
            pinned_at_unix: unix_now_secs(),
        };
        self.pins.write().insert(k, rec.clone());
        rec
    }

    /// Verifies an observed MCP tool manifest against its stored pin.
    /// If `trust_on_first_use` is `false`, unpinned tools fail closed until explicitly approved.
    #[must_use]
    pub fn verify_manifest(
        &self,
        manifest: &McpToolManifest,
        trust_on_first_use: bool,
    ) -> SchemaPinVerdict {
        let k = Self::key(&manifest.server_name, &manifest.tool_name);
        let observed = compute_tool_manifest_sha256(manifest);

        if let Some(existing) = self.pins.read().get(&k).cloned() {
            if existing.pinned_sha256 == observed {
                return SchemaPinVerdict {
                    allowed: true,
                    rug_pull_detected: false,
                    observed_sha256: observed,
                    pinned_sha256: Some(existing.pinned_sha256),
                    reason: format!(
                        "SCHEMA_PIN_VERIFIED: '{}' matches pinned SHA-256",
                        manifest.tool_name
                    ),
                };
            }
            return SchemaPinVerdict {
                allowed: false,
                rug_pull_detected: true,
                observed_sha256: observed,
                pinned_sha256: Some(existing.pinned_sha256),
                reason: format!(
                    "MCP_SCHEMA_RUG_PULL_DENY: Tool '{}' on '{}' mutated its description/schema after pinning; blocked fail-closed",
                    manifest.tool_name, manifest.server_name
                ),
            };
        }

        if trust_on_first_use {
            let rec = self.pin_manifest(manifest, "tofu_initial_pin");
            return SchemaPinVerdict {
                allowed: true,
                rug_pull_detected: false,
                observed_sha256: observed,
                pinned_sha256: Some(rec.pinned_sha256),
                reason: format!(
                    "SCHEMA_PIN_TOFU_LOCKED: Pinned initial manifest for '{}'",
                    manifest.tool_name
                ),
            };
        }

        SchemaPinVerdict {
            allowed: false,
            rug_pull_detected: false,
            observed_sha256: observed,
            pinned_sha256: None,
            reason: format!(
                "MCP_SCHEMA_UNPINNED_DENY: Tool '{}' on '{}' has no approved schema pin",
                manifest.tool_name, manifest.server_name
            ),
        }
    }

    #[must_use]
    pub fn list_pins(&self) -> Vec<PinnedToolSchemaRecord> {
        self.pins.read().values().cloned().collect()
    }
}
