//! Dual-Mode Artemis DFIR & Forensics Engine (`puffyCid/artemis` v0.21 + Native Cross-OS Collectors).
//!
//! Bridges digital forensics directly into deterministic ABIBO (Agent Break In & Break Out)
//! containment controls:
//! 1. **Native Mode (Zero External Dependency)**: Parallel cross-OS Workstation Liveness /
//!    Event-Horizon sensor, Windows `Zone.Identifier` MotW & `*.pf` Prefetch binary header
//!    parser, Windows RunKeys/Startup, Linux systemd/cron, macOS LaunchAgents, agent
//!    instruction/memory poisoning scanner, and local MCP connector inventory.
//! 2. **Artemis CLI Bridge Mode**: Generates valid `puffyCid/artemis` v0.21 TOML recipes,
//!    optionally invokes a local `artemis` binary safely (argv-only, zero shell), and ingests
//!    Artemis JSONL / Timesketch forensic timelines correlated against workstation sleep windows.
//! 3. **Closed-Loop Control Compiler**: Compiles High/Critical forensic findings directly into
//!    schema-validated AWS Cedar `forbid` policies, `FileLineageTracker` taint entries, and
//!    RFC 6962 Merkle audit receipts, while exposing all telemetry to `SiqueryEngine` SQL tables.

pub mod artemis_bridge;
pub mod control_compiler;
pub mod liveness;
pub mod native_collectors;
pub mod types;

pub use artemis_bridge::{
    detect_local_artemis_binary, generate_abibo_artemis_toml, ingest_artemis_file,
    ingest_artemis_jsonl_str, run_local_artemis_collection,
};
pub use control_compiler::ForensicControlCompiler;
pub use liveness::{
    probe_os_workstation_liveness, unix_now_secs, OsLivenessReading, WorkstationLivenessTracker,
};
pub use native_collectors::{
    audit_agent_instruction_and_memory_files, collect_local_mcp_connectors,
    collect_native_persistence_artifacts, inspect_mark_of_the_web, parse_mcp_config_json,
    parse_windows_prefetch_header,
};
pub use types::{
    AbiboDirection, ArtemisCollectionReport, ArtemisForensicEvent, ControlSynthesisKind,
    ForensicArtifactKind, ForensicSeverity, LivenessEventRecord, McpConnectorAuditEntry,
    PersistenceArtifactFinding, SleepLockWindow, SynthesizedControlAction, WindowsPrefetchHeader,
    WorkstationLivenessSnapshot,
};

use crate::core::merkle::{MerkleLeaf, MerkleTree};
use crate::security::cedar_arm::CedarPolicyEngine;
use crate::security::file_lineage::FileLineageTracker;
use chrono::Utc;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

const MAX_TIMELINE_RING: usize = 2048;
const MAX_PERSISTENCE_RING: usize = 512;
const MAX_MCP_RING: usize = 256;
const MAX_LIVENESS_RING: usize = 512;

/// Global bounded ring buffer of normalized Artemis DFIR timeline events (exposed to Siquery SQL).
pub static ARTEMIS_FORENSIC_TIMELINE: LazyLock<RwLock<VecDeque<ArtemisForensicEvent>>> =
    LazyLock::new(|| RwLock::new(VecDeque::with_capacity(256)));

/// Global bounded cache of discovered OS persistence artifacts (exposed to Siquery SQL).
pub static ARTEMIS_PERSISTENCE_CACHE: LazyLock<RwLock<VecDeque<PersistenceArtifactFinding>>> =
    LazyLock::new(|| RwLock::new(VecDeque::with_capacity(128)));

/// Global bounded cache of discovered local MCP connectors (exposed to Siquery SQL).
pub static ARTEMIS_MCP_CONNECTORS_CACHE: LazyLock<RwLock<VecDeque<McpConnectorAuditEntry>>> =
    LazyLock::new(|| RwLock::new(VecDeque::with_capacity(64)));

/// Global bounded ring buffer of workstation liveness / Event-Horizon transitions (exposed to Siquery SQL).
pub static ARTEMIS_LIVENESS_EVENTS: LazyLock<RwLock<VecDeque<LivenessEventRecord>>> =
    LazyLock::new(|| RwLock::new(VecDeque::with_capacity(128)));

pub fn record_forensic_events(events: &[ArtemisForensicEvent]) {
    let mut ring = ARTEMIS_FORENSIC_TIMELINE.write();
    for ev in events {
        if ring.len() >= MAX_TIMELINE_RING {
            ring.pop_front();
        }
        ring.push_back(ev.clone());
    }
}

pub fn record_persistence_findings(items: &[PersistenceArtifactFinding]) {
    let mut ring = ARTEMIS_PERSISTENCE_CACHE.write();
    ring.clear();
    for item in items.iter().take(MAX_PERSISTENCE_RING) {
        ring.push_back(item.clone());
    }
}

pub fn record_mcp_connectors(items: &[McpConnectorAuditEntry]) {
    let mut ring = ARTEMIS_MCP_CONNECTORS_CACHE.write();
    ring.clear();
    for item in items.iter().take(MAX_MCP_RING) {
        ring.push_back(item.clone());
    }
}

pub fn record_liveness_events(records: &[LivenessEventRecord]) {
    let mut ring = ARTEMIS_LIVENESS_EVENTS.write();
    ring.clear();
    for rec in records.iter().take(MAX_LIVENESS_RING) {
        ring.push_back(rec.clone());
    }
}

#[must_use]
pub fn snapshot_artemis_forensic_timeline() -> Vec<ArtemisForensicEvent> {
    ARTEMIS_FORENSIC_TIMELINE.read().iter().cloned().collect()
}

#[must_use]
pub fn snapshot_artemis_persistence_findings() -> Vec<PersistenceArtifactFinding> {
    ARTEMIS_PERSISTENCE_CACHE.read().iter().cloned().collect()
}

#[must_use]
pub fn snapshot_artemis_mcp_connectors() -> Vec<McpConnectorAuditEntry> {
    ARTEMIS_MCP_CONNECTORS_CACHE
        .read()
        .iter()
        .cloned()
        .collect()
}

#[must_use]
pub fn snapshot_artemis_liveness_events() -> Vec<LivenessEventRecord> {
    ARTEMIS_LIVENESS_EVENTS.read().iter().cloned().collect()
}

/// Primary coordinator for Dual-Mode Artemis DFIR forensic collection, ingestion, and
/// closed-loop Cedar + FileLineage control compilation.
pub struct ArtemisDfirEngine {
    workspace_root: PathBuf,
    liveness: Arc<WorkstationLivenessTracker>,
    cedar_engine: Arc<CedarPolicyEngine>,
    lineage_tracker: Arc<FileLineageTracker>,
}

impl ArtemisDfirEngine {
    #[must_use]
    pub fn new(
        workspace_root: PathBuf,
        liveness: Arc<WorkstationLivenessTracker>,
        cedar_engine: Arc<CedarPolicyEngine>,
        lineage_tracker: Arc<FileLineageTracker>,
    ) -> Self {
        record_liveness_events(&liveness.history_records());
        Self {
            workspace_root,
            liveness,
            cedar_engine,
            lineage_tracker,
        }
    }

    #[must_use]
    pub fn liveness(&self) -> &Arc<WorkstationLivenessTracker> {
        &self.liveness
    }

    #[must_use]
    pub fn cedar_engine(&self) -> &Arc<CedarPolicyEngine> {
        &self.cedar_engine
    }

    #[must_use]
    pub fn lineage_tracker(&self) -> &Arc<FileLineageTracker> {
        &self.lineage_tracker
    }

    /// Generates an Artemis v0.21 TOML collection recipe for the current host OS.
    #[must_use]
    pub fn export_artemis_toml(&self, output_dir: &str) -> String {
        let host = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "agentoctopus-host".to_string());
        generate_abibo_artemis_toml(std::env::consts::OS, output_dir, &host)
    }

    /// Executes a native zero-dependency parallel DFIR forensic sweep across workstation
    /// liveness, agent instruction/memory files, OS persistence surfaces, and MCP connectors,
    /// then compiles deterministic controls and seals an RFC 6962 Merkle root.
    #[must_use]
    pub fn run_native_collection(&self) -> ArtemisCollectionReport {
        let liveness_snap = self.liveness.snapshot();
        record_liveness_events(&self.liveness.history_records());

        let (events_mem, (persistence_findings, mcp_connectors)) = rayon::join(
            || audit_agent_instruction_and_memory_files(&self.workspace_root),
            || {
                rayon::join(collect_native_persistence_artifacts, || {
                    collect_local_mcp_connectors(&self.workspace_root)
                })
            },
        );

        let mut events = events_mem;

        // Promote suspicious persistence & risky MCP connectors into unified timeline events
        let now_utc = Utc::now().to_rfc3339();
        let now_unix = unix_now_secs();
        for p in persistence_findings.iter().filter(|p| p.suspicious) {
            events.push(ArtemisForensicEvent {
                timestamp_utc: now_utc.clone(),
                timestamp_unix: now_unix,
                artifact: ForensicArtifactKind::RegistryRunKey,
                direction: AbiboDirection::BreakIn,
                severity: ForensicSeverity::High,
                principal: p.name.clone(),
                path_or_uri: p.command_or_path.clone(),
                summary: format!("[{}] {}: {}", p.os_family, p.category, p.reason),
                sha256: p.sha256.clone(),
                indicators: vec![format!("suspicious_persistence:{}", p.category)],
                raw_source: "native_persistence_collector".to_string(),
            });
        }

        for conn in mcp_connectors
            .iter()
            .filter(|c| c.write_capable && c.has_inline_secret)
        {
            events.push(ArtemisForensicEvent {
                timestamp_utc: now_utc.clone(),
                timestamp_unix: now_unix,
                artifact: ForensicArtifactKind::McpConfig,
                direction: AbiboDirection::BidirectionalCoupling,
                severity: ForensicSeverity::High,
                principal: conn.server_name.clone(),
                path_or_uri: conn.config_source.clone(),
                summary: format!(
                    "Write-capable MCP connector '{}' exposes inline standing credentials ({})",
                    conn.server_name, conn.risk_notes
                ),
                sha256: None,
                indicators: vec!["standing_mcp_credential_risk".to_string()],
                raw_source: "native_mcp_auditor".to_string(),
            });
        }

        let synthesized_controls = ForensicControlCompiler::compile_controls(
            &events,
            &persistence_findings,
            &mcp_connectors,
            Some(&self.cedar_engine),
            Some(&self.lineage_tracker),
        );

        // If sleep-window activity triggered EpochRevocation, advance workstation epoch
        if synthesized_controls
            .iter()
            .any(|c| c.control_kind == ControlSynthesisKind::EpochRevocation)
        {
            self.liveness
                .trigger_event_horizon("artemis_dfir_unconsented_sleep_activity");
        }

        record_forensic_events(&events);
        record_persistence_findings(&persistence_findings);
        record_mcp_connectors(&mcp_connectors);
        record_liveness_events(&self.liveness.history_records());

        let merkle_root_hex = seal_report_merkle_root(&events, &synthesized_controls);
        let artemis_cli = detect_local_artemis_binary();

        ArtemisCollectionReport {
            collected_at_utc: now_utc,
            os_family: std::env::consts::OS.to_string(),
            mode: if artemis_cli.is_some() {
                "dual_native_plus_artemis_cli_ready".to_string()
            } else {
                "native_zero_dependency_dfir".to_string()
            },
            liveness: liveness_snap,
            events,
            persistence_findings,
            mcp_connectors,
            synthesized_controls,
            artemis_cli_available: artemis_cli.is_some(),
            artemis_cli_path: artemis_cli.map(|p| p.to_string_lossy().to_string()),
            merkle_root_hex,
        }
    }

    /// Ingests an external Artemis v0.21 JSONL / JSON / Timesketch payload, correlates it
    /// against recorded workstation sleep windows (plus any caller-supplied windows),
    /// compiles deterministic Cedar/Lineage containment controls, and seals a Merkle root.
    #[must_use]
    pub fn ingest_external_artemis_jsonl(
        &self,
        jsonl: &str,
        extra_sleep_windows: &[SleepLockWindow],
    ) -> ArtemisCollectionReport {
        let mut windows = self.liveness.sleep_windows();
        windows.extend_from_slice(extra_sleep_windows);

        let events = ingest_artemis_jsonl_str(jsonl, &windows);
        let synthesized_controls = ForensicControlCompiler::compile_controls(
            &events,
            &[],
            &[],
            Some(&self.cedar_engine),
            Some(&self.lineage_tracker),
        );

        if synthesized_controls
            .iter()
            .any(|c| c.control_kind == ControlSynthesisKind::EpochRevocation)
        {
            self.liveness
                .trigger_event_horizon("artemis_jsonl_unconsented_sleep_activity");
        }

        record_forensic_events(&events);
        record_liveness_events(&self.liveness.history_records());

        let merkle_root_hex = seal_report_merkle_root(&events, &synthesized_controls);
        let artemis_cli = detect_local_artemis_binary();

        ArtemisCollectionReport {
            collected_at_utc: Utc::now().to_rfc3339(),
            os_family: std::env::consts::OS.to_string(),
            mode: "artemis_v021_jsonl_ingest".to_string(),
            liveness: self.liveness.snapshot(),
            events,
            persistence_findings: Vec::new(),
            mcp_connectors: Vec::new(),
            synthesized_controls,
            artemis_cli_available: artemis_cli.is_some(),
            artemis_cli_path: artemis_cli.map(|p| p.to_string_lossy().to_string()),
            merkle_root_hex,
        }
    }

    /// Ingests an Artemis v0.21 JSONL/JSON file from disk safely.
    pub fn ingest_external_artemis_file(
        &self,
        path: &Path,
        extra_sleep_windows: &[SleepLockWindow],
    ) -> Result<ArtemisCollectionReport, String> {
        let mut windows = self.liveness.sleep_windows();
        windows.extend_from_slice(extra_sleep_windows);
        let events = ingest_artemis_file(path, &windows)?;
        let synthesized_controls = ForensicControlCompiler::compile_controls(
            &events,
            &[],
            &[],
            Some(&self.cedar_engine),
            Some(&self.lineage_tracker),
        );
        record_forensic_events(&events);
        record_liveness_events(&self.liveness.history_records());
        let merkle_root_hex = seal_report_merkle_root(&events, &synthesized_controls);
        let artemis_cli = detect_local_artemis_binary();

        Ok(ArtemisCollectionReport {
            collected_at_utc: Utc::now().to_rfc3339(),
            os_family: std::env::consts::OS.to_string(),
            mode: "artemis_v021_file_ingest".to_string(),
            liveness: self.liveness.snapshot(),
            events,
            persistence_findings: Vec::new(),
            mcp_connectors: Vec::new(),
            synthesized_controls,
            artemis_cli_available: artemis_cli.is_some(),
            artemis_cli_path: artemis_cli.map(|p| p.to_string_lossy().to_string()),
            merkle_root_hex,
        })
    }
}

fn seal_report_merkle_root(
    events: &[ArtemisForensicEvent],
    controls: &[SynthesizedControlAction],
) -> String {
    let mut leaves = Vec::with_capacity(events.len() + controls.len() + 1);
    for (idx, ev) in events.iter().enumerate() {
        let in_digest = hex::encode(Sha256::digest(
            format!("{}|{}|{}", ev.timestamp_unix, ev.principal, ev.path_or_uri).as_bytes(),
        ));
        let out_digest = hex::encode(Sha256::digest(
            format!(
                "{}|{}|{}",
                ev.direction.as_str(),
                ev.severity.as_str(),
                ev.summary
            )
            .as_bytes(),
        ));
        leaves.push(MerkleLeaf::new(
            idx,
            format!("artemis:{}", ev.artifact.as_str()),
            in_digest,
            out_digest,
        ));
    }
    let base = leaves.len();
    for (i, ctl) in controls.iter().enumerate() {
        let in_digest = hex::encode(Sha256::digest(ctl.target.as_bytes()));
        let out_digest = hex::encode(Sha256::digest(
            format!("{}|{}", ctl.detail, ctl.applied).as_bytes(),
        ));
        leaves.push(MerkleLeaf::new(
            base + i,
            format!("control:{:?}", ctl.control_kind),
            in_digest,
            out_digest,
        ));
    }
    if leaves.is_empty() {
        leaves.push(MerkleLeaf::new(
            0,
            "artemis:clean_sweep",
            "0000000000000000",
            "clean",
        ));
    }
    MerkleTree::from_leaves(leaves).root_hex()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_artemis_toml_for_all_os_families() {
        for os in ["windows", "linux", "macos"] {
            let toml = generate_abibo_artemis_toml(os, "./artemis_out", "host-01");
            assert!(toml.contains("[output]"));
            assert!(toml.contains("format = \"jsonl\""));
            assert!(toml.contains("[[artifacts]]"));
            assert!(toml.contains("artifact_name = \"processes\""));
        }
        let win = generate_abibo_artemis_toml("windows", "./out", "w1");
        assert!(win.contains("artifact_name = \"prefetch\""));
        assert!(win.contains("artifact_name = \"eventlogs\""));
        let mac = generate_abibo_artemis_toml("macos", "./out", "m1");
        assert!(mac.contains("artifact_name = \"launchd\""));
    }

    #[test]
    fn parses_windows_scca_and_mam_prefetch_headers() {
        // Test MAM compressed magic
        let mam = b"MAM\x04\x00\x00\x00\x00\x01\x02";
        let hdr = parse_windows_prefetch_header(mam).expect("MAM header should parse");
        assert!(hdr.compressed_mam);

        // Test uncompressed SCCA v30 header
        let mut buf = vec![0u8; 256];
        buf[0..4].copy_from_slice(&30u32.to_le_bytes());
        buf[4..8].copy_from_slice(b"SCCA");
        let name_utf16: Vec<u16> = "POWERSHELL.EXE".encode_utf16().collect();
        for (i, ch) in name_utf16.iter().enumerate() {
            let b = ch.to_le_bytes();
            buf[16 + i * 2] = b[0];
            buf[16 + i * 2 + 1] = b[1];
        }
        buf[208..212].copy_from_slice(&7u32.to_le_bytes());
        let parsed = parse_windows_prefetch_header(&buf).expect("SCCA v30 should parse");
        assert!(!parsed.compressed_mam);
        assert_eq!(parsed.format_version, 30);
        assert_eq!(parsed.executable_name, "POWERSHELL.EXE");
        assert_eq!(parsed.run_count, Some(7));
    }

    #[test]
    fn artemis_jsonl_sleep_window_compiles_live_cedar_forbid_policies() {
        let cedar = Arc::new(CedarPolicyEngine::new().expect("default Cedar engine"));
        let liveness = Arc::new(WorkstationLivenessTracker::new(300));
        let lineage = Arc::new(FileLineageTracker::default());
        let engine = ArtemisDfirEngine::new(std::env::temp_dir(), liveness, cedar.clone(), lineage);

        let sleep_window = SleepLockWindow {
            start_unix: 1_794_600_000,
            end_unix: 1_794_628_800,
        };
        let jsonl = concat!(
            r#"{"timestamp": 1794610000, "artifact": "network", "principal": "grok_bot", "domain": "api.evil-c2.example", "message": "Overnight unconsented MCP polling"}"#,
            "\n",
            r#"{"timestamp": 1794610500, "artifact": "tasks", "principal": "SYSTEM", "command_line": "rogue_dropper.exe -enc AAAA", "event_id": 4698}"#
        );

        let report = engine.ingest_external_artemis_jsonl(jsonl, &[sleep_window]);
        assert_eq!(report.events.len(), 2);
        assert_eq!(report.events[0].severity, ForensicSeverity::Critical);
        assert!(report
            .synthesized_controls
            .iter()
            .any(|c| c.control_kind == ControlSynthesisKind::CedarForbidPolicy && c.applied));
        assert!(report
            .synthesized_controls
            .iter()
            .any(|c| c.control_kind == ControlSynthesisKind::EpochRevocation));
        assert_eq!(report.merkle_root_hex.len(), 64);

        // Verify the synthesized Cedar egress forbid rule is live and denies egress to api.evil-c2.example
        let verdict = cedar
            .evaluate(
                "network_arm",
                "egress",
                "target_1",
                "NetworkTarget",
                serde_json::json!({ "destination_domain": "api.evil-c2.example" }),
            )
            .expect("Cedar evaluation");
        assert!(!verdict.is_allowed);
    }
}
