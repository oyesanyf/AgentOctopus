pub mod agentjacking_guard;
pub mod anomaly_arms;
pub mod atlas_arm;
pub mod audit;
pub mod breakouts;
pub mod capabilities;
pub mod cedar_arm;
pub mod continuous_eval;
pub mod delegation;
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
pub use governor::{
    spawn_continuous_governor, ContinuousGovernorHandle, GovernorCommand, GovernorConfig,
    GovernorError, GovernorStage, IncidentRecord, KernelEventKind, OperationalMetricsSummary,
    OutOfBandCircuitBreaker, SecurityGovernorState, TelemetrySample, WeightMatrix,
};
pub use identity::{hmac_sha256, AgentIdentity, SignedAgentMessage};
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
