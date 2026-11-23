//! Data structures for Dual-Mode Artemis DFIR & Forensics integration in AgentOctopus.

use serde::{Deserialize, Serialize};

/// Directional classification in the ABIBO (Agent Break In and Break Out) threat taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbiboDirection {
    /// Inbound untrusted instruction, poisoned memory/MotW file, or unconsented control-plane activation.
    BreakIn,
    /// Outbound host/sandbox escape, credential theft, or lateral SaaS write/egress mutation.
    BreakOut,
    /// Lethal Trifecta / asymmetric coupling combining Break-In ingestion with Break-Out mutation.
    BidirectionalCoupling,
    /// Neutral baseline forensic observation.
    Telemetry,
}

impl AbiboDirection {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BreakIn => "break_in",
            Self::BreakOut => "break_out",
            Self::BidirectionalCoupling => "bidirectional_coupling",
            Self::Telemetry => "telemetry",
        }
    }
}

/// Canonical forensic artifact categories supported natively and via Artemis v0.21 JSONL ingestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForensicArtifactKind {
    EventLog,
    ScheduledTask,
    RegistryRunKey,
    Service,
    Prefetch,
    MarkOfTheWeb,
    LaunchAgent,
    SystemdTimer,
    CronJob,
    McpConfig,
    AgentMemoryFile,
    Process,
    NetworkConnection,
    WorkstationLiveness,
    Srum,
    Amcache,
    Shimcache,
    UsnJrnl,
    UnifiedLogs,
    FsEvents,
    Journal,
    ArtemisExternal,
}

impl ForensicArtifactKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EventLog => "eventlogs",
            Self::ScheduledTask => "tasks",
            Self::RegistryRunKey => "registry",
            Self::Service => "services",
            Self::Prefetch => "prefetch",
            Self::MarkOfTheWeb => "mark_of_the_web",
            Self::LaunchAgent => "launchd",
            Self::SystemdTimer => "systemd_timer",
            Self::CronJob => "cron",
            Self::McpConfig => "mcp_config",
            Self::AgentMemoryFile => "agent_memory",
            Self::Process => "processes",
            Self::NetworkConnection => "connections",
            Self::WorkstationLiveness => "workstation_liveness",
            Self::Srum => "srum",
            Self::Amcache => "amcache",
            Self::Shimcache => "shimcache",
            Self::UsnJrnl => "usnjrnl",
            Self::UnifiedLogs => "unifiedlogs",
            Self::FsEvents => "fsevents",
            Self::Journal => "journal",
            Self::ArtemisExternal => "artemis_external",
        }
    }
}

/// Severity rating for normalized forensic observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForensicSeverity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl ForensicSeverity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// A single normalized DFIR forensic event from either native collectors or Artemis v0.21 JSONL exports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtemisForensicEvent {
    pub timestamp_utc: String,
    pub timestamp_unix: u64,
    pub artifact: ForensicArtifactKind,
    pub direction: AbiboDirection,
    pub severity: ForensicSeverity,
    pub principal: String,
    pub path_or_uri: String,
    pub summary: String,
    pub sha256: Option<String>,
    #[serde(default)]
    pub indicators: Vec<String>,
    pub raw_source: String,
}

/// Snapshot of host workstation human presence and Spacetime Event-Horizon epoch state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkstationLivenessSnapshot {
    pub epoch: u64,
    pub human_live: bool,
    pub workstation_locked: bool,
    pub idle_secs: u64,
    pub max_idle_secs: u64,
    pub last_heartbeat_unix: u64,
    pub event_horizon_count: u64,
    pub last_horizon_reason: Option<String>,
    pub os_probe_method: String,
}

/// A recorded workstation lock/sleep/unlock/heartbeat transition exposed to Siquery SQL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessEventRecord {
    pub epoch: u64,
    pub state: String,
    pub idle_secs: u64,
    pub event_horizon_reason: String,
    pub timestamp_utc: String,
    pub timestamp_unix: u64,
}

/// A time window `[start_unix, end_unix]` during which the workstation was asleep or locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SleepLockWindow {
    pub start_unix: u64,
    pub end_unix: u64,
}

impl SleepLockWindow {
    #[must_use]
    pub fn contains(self, ts_unix: u64) -> bool {
        ts_unix >= self.start_unix && ts_unix <= self.end_unix
    }
}

/// Native persistence artifact entry (Windows RunKeys/Tasks/Startup/Prefetch, Linux systemd/cron, macOS LaunchAgents).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceArtifactFinding {
    pub os_family: String,
    pub category: String,
    pub name: String,
    pub command_or_path: String,
    pub suspicious: bool,
    pub reason: String,
    pub sha256: Option<String>,
}

/// Discovered local MCP connector definition audited for write scope and inline secret exposure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConnectorAuditEntry {
    pub config_source: String,
    pub server_name: String,
    pub command_or_url: String,
    pub write_capable: bool,
    pub has_inline_secret: bool,
    pub risk_notes: String,
}

/// Parsed Windows Prefetch (`*.pf`) header metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsPrefetchHeader {
    pub format_version: u32,
    pub compressed_mam: bool,
    pub executable_name: String,
    pub run_count: Option<u32>,
}

/// Category of deterministic control synthesized automatically from Artemis forensic findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlSynthesisKind {
    CedarForbidPolicy,
    FileLineageTaint,
    EpochRevocation,
    ThermodynamicTaintBoost,
    QuantumZenoAccelerate,
    MerkleReceipt,
}

/// A deterministic containment control compiled by `ForensicControlCompiler`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesizedControlAction {
    pub control_kind: ControlSynthesisKind,
    pub target: String,
    pub detail: String,
    pub policy_text: Option<String>,
    pub applied: bool,
}

/// Complete report returned by a native or Artemis-bridge DFIR collection & control synthesis sweep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtemisCollectionReport {
    pub collected_at_utc: String,
    pub os_family: String,
    pub mode: String,
    pub liveness: WorkstationLivenessSnapshot,
    pub events: Vec<ArtemisForensicEvent>,
    pub persistence_findings: Vec<PersistenceArtifactFinding>,
    pub mcp_connectors: Vec<McpConnectorAuditEntry>,
    pub synthesized_controls: Vec<SynthesizedControlAction>,
    pub artemis_cli_available: bool,
    pub artemis_cli_path: Option<String>,
    pub merkle_root_hex: String,
}
