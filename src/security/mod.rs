pub mod agentjacking_guard;
pub mod anomaly_arms;
pub mod atlas_arm;
pub mod audit;
pub mod breakouts;
pub mod capabilities;
pub mod cedar_arm;
pub mod continuous_eval;
pub mod delegation;
pub mod differential_protocol;
pub mod governor;
pub mod guard_arms;
pub mod identity;
pub mod isolation;
pub mod log_sanitizer;
pub mod math_validator;
pub mod openshell;
pub mod oss_fuzz_arm;
pub mod osv_scanner_arm;
pub mod rasp;
pub mod research_arms;
pub mod rl_defense;
pub mod windows_sandbox;

pub use agentjacking_guard::{AgentjackingGuard, AgentjackingPhase, AgentjackingVerdict, SessionTaintState};
pub use log_sanitizer::LogSanitizer;
pub use oss_fuzz_arm::{ContinuousOssFuzzArm, OssFuzzCycleReport, TargetTelemetry};
pub use osv_scanner_arm::{ContinuousOsvScannerArm, OsvScanReport};

pub use audit::{AuditRecord, SecurityAuditLog};
pub use breakouts::{
    AgentTrustTier, BehavioralBreakoutGuard, BreakoutDefenseCoordinator, DataBreakoutGuard,
    OperationalContainmentGuard, TechnicalBreakoutGuard, UnifiedBreakoutEvaluation,
};
pub use capabilities::{CapabilityToken, ExternalAuthorizationEngine};
pub use cedar_arm::{CedarAuthorizationGateway, CedarPolicyEngine, CedarSchema};
pub use continuous_eval::{ContinuousCycleReport, ContinuousEvaluationEngine, ContinuousProbeResult};
pub use delegation::DelegationScopeGuard;
pub use differential_protocol::{
    DifferentialAction, DifferentialAnalysisReport, DifferentialEngineStats,
    DifferentialProtocolEngine, DivergenceVector,
};
pub use governor::{
    spawn_continuous_governor, ContinuousGovernorHandle, GovernorCommand, GovernorConfig,
    GovernorError, GovernorStage, IncidentRecord, KernelEventKind, OperationalMetricsSummary,
    OutOfBandCircuitBreaker, SecurityGovernorState, TelemetrySample, WeightMatrix,
};
pub use identity::{constant_time_eq, constant_time_eq_hex, hmac_sha256, AgentIdentity, SignedAgentMessage};
pub use isolation::SandboxConfinementPolicy;
pub use math_validator::{
    MonteCarloSimulationResult, ResilienceBreachEvent, SisypheanValidationReport,
    VassilevMathValidator,
};
pub use openshell::{OpenShellConfig, OpenShellMode, WasmArmSandbox};
pub use rasp::{
    AdaptiveMitigationTier, AgentRaspEngine, AgentSecuritySubject, LateralA2AInterceptor,
    MemoryScratchpadInterceptor, PromptInvocationInterceptor, RaspAgentTrustTier, RaspDecision,
    RaspInterceptionEvent, RaspInterceptor, RaspPolicyConfig, RaspPolicyEngine,
    RaspTelemetryMetrics, RaspTelemetryRegistry, RaspThreatCategory, SubstrateClampInterceptor,
    TaintLevel, ToolActuatorInterceptor,
};
pub use rl_defense::{
    AdaptiveDefenseAction, AdaptiveRewardEngine, AdaptiveRlDefenseEngine, AdaptiveStateVector,
    DefenseExperience, RlDefenseStats,
};
pub use windows_sandbox::{
    WindowsAppContainerProfile, WindowsJobObject, WindowsNamedPipeSecurity,
    WindowsRestrictedTokenPolicy,
};

pub mod protocol_research;
pub mod pqc_arm;
pub use pqc_arm::{CbomScanner, PostQuantumArm, PqcAlgorithm, PqcArmStatus, PqcDsaEngine, PqcKemEngine};
pub mod evolution;
pub use evolution::{EvolutionArmStatus, EvolutionCandidate, EvolutionMetrics, EvolutionaryOptimizerArm, PromotionState, SecurityInvariantGuard};
pub mod dream_rsi;
pub use dream_rsi::{DreamRsiOptimizerArm, DreamRsiPolicyOptimizer, DreamRsiStatus, DreamRolloutReport, ResearchPolicy, RsiExperimentPlan, TrajectoryEvent, WorldModelTransition};
pub mod harness2;
pub use harness2::{
    Harness2ArmStatus, HarnessBudgetLedger, HarnessComponentKind, HarnessExperienceEntry,
    HarnessRunReport, HarnessStageResult, HarnessSurfaceSpec, HarnessTreeValidationReport,
    HarnessTreeValidator, RecursiveHarnessOptimizerArm,
};


pub mod agent_classifier;
pub mod alignment_scanner;
pub mod console_defense;
pub mod file_lineage;
pub mod mercury_guard;
pub mod spider_physics;

pub use agent_classifier::{
    AgentClassificationVerdict, DynamicAgentClassifier, ProcessBehavioralTelemetry,
};
pub use alignment_scanner::{
    AlignmentScanVerdict, RuntimeAlignmentScanner, SessionIntentContract, ToolCallTraceStep,
};
pub use breakouts::{
    open_confined, validate_agent_filesystem_access, validate_sandbox_relative_path,
    ZeroMiProjectionResult, ZeroMutualInformationProjector,
};
pub use console_defense::{
    compute_hardened_console_mode, harden_windows_console, is_console_mode_hardened,
    CommandConsoleExt, CREATE_NO_WINDOW, ENABLE_EXTENDED_FLAGS, ENABLE_INSERT_MODE,
    ENABLE_MOUSE_INPUT, ENABLE_QUICK_EDIT_MODE,
};
pub use file_lineage::{
    FileLineageRecord, FileLineageTracker, LineageCheckVerdict, MAX_LINEAGE_RECORDS,
};
pub use mercury_guard::{
    HostActuationPore, MercuryContainmentEngine, MercuryEvaluationResult, CRITICAL_WEBER_NUMBER,
    MERCURY_ABS_COS_THETA, MERCURY_DENSITY_KG_M3, MERCURY_SURFACE_TENSION_N_PER_M,
};
pub use rl_defense::{
    ConfidenceInterval95, CyberBattleBenchmarkReport, PolicyBenchmarkMetrics, PolicyBenchmarkReport,
};
pub use spider_physics::{OrbWebContainmentEngine, OrbWebEvaluationResult, SilkRegime};
pub use windows_sandbox::{
    evaluate_pre_resume_confinement_gate, verify_windows_confinement_invariants,
    WindowsConfinementPolicy,
};

pub mod token_posture;
pub use token_posture::{
    current_token_posture, relaunch_deelevated_or_fail, TokenPosture, DANGEROUS_PRIVILEGES,
    DEELEVATED_ENV_MARKER, INTEGRITY_HIGH, INTEGRITY_MEDIUM,
};
#[cfg(windows)]
pub use token_posture::{create_deelevated_token, spawn_deelevated, DeelevatedChild, OwnedToken};

pub mod hidden_process_ledger;
pub use hidden_process_ledger::{
    list_hidden_spawns, output_hidden, record_hidden_spawn, spawn_hidden, spawn_hidden_tokio,
    status_hidden, HiddenSpawnRecord,
};

pub mod command_line;
pub use command_line::{
    analyze_command_line, decode_base64_strict, decode_encoded_command, encode_utf16le_base64,
    normalize_executable_stem, parse_powershell_args, strip_cmd_carets_outside_quotes,
    tokenize_windows_argv, EncodedCommandState, ParsedInvocation, PsParameter, MAX_UNWRAP_DEPTH,
};
