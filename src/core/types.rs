use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OctopusSecurityError {
    #[error("Breakout attempt detected: {0}")]
    BreakoutDetected(String),

    #[error("Input payload violated strict enclave boundaries: {0}")]
    EnclaveViolation(String),

    #[error("Limb execution deadline exceeded (timeout)")]
    ExecutionTimeout,

    #[error("Arm communication channel severed")]
    ChannelSevered,

    #[error("Limb terminated by supervisory autotomy circuit breaker")]
    LimbKilled,

    #[error("High entropy payload anomaly detected: {entropy:.2} bits/byte exceeds threshold")]
    HighEntropyDetected { entropy: u32 }, // stored as scaled integer (entropy * 100) for Eq

    #[error("Prohibited outbound target (SSRF/Pivot blocked): {0}")]
    SsrfBlocked(String),

    #[error("Cryptographic Merkle tamper detected: {0}")]
    MerkleTamperDetected(String),

    #[error("Deterministic layer violation: {0}")]
    DeterministicLayerViolation(String),

    #[error("Illegal FSM state transition: cannot transition from '{from}' to '{to}'")]
    IllegalStateTransition { from: String, to: String },

    #[error("Zero-trust capability authorization failure: {0}")]
    CapabilityDenied(String),

    #[error("Delegation authority violation: delegation chain exceeds permitted scope: {0}")]
    DelegationScopeViolation(String),

    #[error("Cryptographic agent identity spoofing detected: {0}")]
    IdentitySpoofingDetected(String),

    #[error("Operating system / process sandbox confinement violation: {0}")]
    IsolationViolation(String),

    #[error("Resource quota exceeded or exhaustion attempt blocked: {0}")]
    ResourceQuotaExceeded(String),

    #[error("Zero-capacity swarm: cannot dispatch tasks to an empty swarm")]
    ZeroSwarmCapacity,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArmRole {
    UntrustedDocIngest,
    AccountingLedgerWrite,
    OutboundNotification,
    NetworkEgress,
    TarpitDecoyDefense,
    KernelLevelSentinel,
    CedarPolicyEvaluation,
    AtlasThreatIntelligence,
    AnomalyDetection,
    VulnerabilityResearch,
    ContinuousOssFuzz,
    ContinuousOsvScanner,
    DifferentialProtocolAnalyzer,
    AutonomousProtocolResearch,
}

/// High-level strategic intent sent downward from Central Brain to Arm.
/// Contains no raw agent prompts or unparsed scripts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategicDirective {
    pub directive_id: String,
    pub source_uri: String,
    pub instruction: String,
    pub raw_payload: Option<String>,
    pub max_step_budget: usize,
}

impl StrategicDirective {
    /// Resolves the required operational security role for this directive.
    pub fn target_role(&self) -> ArmRole {
        let uri_lower = self.source_uri.to_lowercase();
        let inst_lower = self.instruction.to_lowercase();

        if uri_lower.starts_with("http")
            || uri_lower.contains("api.")
            || uri_lower.contains("evil-c2.com")
            || inst_lower.contains("network")
            || inst_lower.contains("egress")
            || inst_lower.contains("portal")
            || inst_lower.contains("google")
            || inst_lower.contains("exfiltrat")
        {
            ArmRole::NetworkEgress
        } else if uri_lower.contains("ledger")
            || uri_lower.contains("accounting")
            || inst_lower.contains("ledger")
            || inst_lower.contains("accounting")
        {
            ArmRole::AccountingLedgerWrite
        } else {
            ArmRole::UntrustedDocIngest
        }
    }
}

/// Strongly typed structured artifact sent upward to Central Brain.
/// Raw document text, untrusted tokens, and system prompts are excluded
/// by design to guarantee zero context poisoning of the Brain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedInvoiceArtifact {
    pub invoice_id: String,
    pub vendor_name: String,
    pub amount_cents: u64,
    pub currency: String,
    pub line_item_count: usize,
    pub sanitization_digest: String,
    pub merkle_root: String,
    pub execution_step_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArmExecutionReport {
    pub directive_id: String,
    pub arm_role: String,
    pub success: bool,
    pub verified_data: Option<VerifiedInvoiceArtifact>,
    pub merkle_root: Option<String>,
    pub steps_taken: usize,
    pub anomaly_flag: bool,
}

/// Telemetry packet emitted out-of-band to the supervisory watchdog loop.
#[derive(Debug, Clone)]
pub struct TelemetryPacket {
    pub arm_id: Option<usize>,
    pub arm_role: ArmRole,
    pub directive_id: String,
    pub tool_invoked: String,
    pub raw_target: String,
    pub step_index: usize,
    pub entropy_bits: f64,
    pub incremental_merkle_root: Option<String>,
}

