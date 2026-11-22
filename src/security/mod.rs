pub mod agentjacking_guard;
pub mod agentmesh;
pub mod anomaly_arms;
pub mod atlas_arm;
pub mod audit;
pub mod breakouts;
pub mod bsd_sandbox;
pub mod cage_governance;
pub mod capabilities;

pub use agentmesh::{
    validate_mesh_uri, AgentMeshBindingDef, AgentMeshConfig, AgentMeshEngine,
    AgentMeshPolicyConfig, AgentMeshPolicyRoot, AgentMeshReferenceNode, AgentMeshRoleDef,
    AgentMeshServingNode, AgentMeshStatus, AsyncHttpWireClient, AttenuatedMandate, CachedMeshToken,
    ConformanceNodeStats, DelegationLink, EcJwk, ExchangedTokenMetadata, InboundMeshCallReport,
    JwksDocument, JwsHeader, MandateError, MeshCallError, MeshCallReceipt, OctopusOidcActorIssuer,
    OidcError, OpenIdConfiguration, PepBridgeConfig, PepVaultTelemetry, SandboxMeshCallReport,
    ServingNodeStats, SyncHttpWireClient, WorkloadClaims, ALLOWED_SCHEMES, MAX_DELEGATION_DEPTH,
};

pub use cage_governance::{
    ActionReversibility, BfsModelResult, BfsPhase, BfsState, BfsViolation, CageApiError,
    CageGovernanceEngine, CageRoutingSeal, CbfSafetyEngine, CbfViolation, CommitReceipt,
    CompiledCagePolicy, ConsumeSealResponse, DebitLedger, FormalBfsModel, FtraVerdict,
    GovernanceEvaluationResult, GovernanceRequest, GovernanceVerdict, IngestPolicyResponse,
    Phase2Mode, PlanGraphAnalyzer, PlanStep, PolicyFormat, PolicyIngestError,
    PolicyVersionConflict, Profile, ProofStatusResponse, RoutingSealSigner, SealRejection,
    StageOutcome, StpaValidator, StreamConformanceStatus, StreamFinding, StreamVerificationReport,
    SubstrateTranslator, TheoremProofResult, UnsafeControlAction,
};

pub mod atif_scan;
pub mod cedar_arm;
pub mod continuous_eval;
pub mod cpu_pool;
pub mod delegation;
pub mod differential_protocol;
pub mod governor;
pub mod guard_arms;
pub mod identity;
pub mod isolation;
pub mod journal_watcher;
pub mod kernel_patcher;
pub mod linux_sandbox;
pub mod log_sanitizer;
pub mod macos_sandbox;
pub mod math_validator;
pub mod openshell;
pub mod oss_fuzz_arm;
pub mod osv_scanner_arm;
pub mod rasp;
pub mod research_arms;
pub mod rl_defense;
pub mod safeagents_client;
pub mod windows_sandbox;

pub use atif_scan::{
    extract_hosts_from_text, AtifScanner, AtifSeverity, AtifSignal, SafeAgentsHarnessEvaluator,
    ToolInvocationContext, ToolVerdict,
};
pub use cpu_pool::{global_cpu_pool, init_global_cpu_pool, spawn_cpu, CpuPoolError, CpuThreadPool};
pub use journal_watcher::{
    AtifSignal as JournalSignal, JournalEntry, JournalWatcherConfig, SafeAgentsJournalWatcher,
    SafeAgentsJournalWatcherHandle,
};
pub use safeagents_client::{
    host_port_pattern_matches, is_denied_resolved_ip, is_denied_resolved_ip_with_local,
    local_host_interface_ips, parse_and_validate_dynamic_policy, resolve_and_pin_allowed_host,
    validate_http_request_target, CredentialSentinelMasker, DynamicNetworkPolicy, IpCidr,
    SafeAgentsClient, SafeAgentsClientConfig, SafeAgentsClientError, ToolCallEvaluator,
    ToolEvaluationVerdict,
};

pub use linux_sandbox::{
    build_hardened_sandbox_bpf, build_socket_filter_bpf, build_syscall_policy_bpf,
    build_virtual_patch_socket_family_bpf, describe_tier2_host_confinement_posture,
    evaluate_bpf_filter, evaluate_bpf_filter_with_args, spawn_tier2_linux_command,
    LinuxConfinementConfig, LinuxConfinementVerification, LinuxResourceLimits,
    AARCH64_BLOCKED_SANDBOX_ESCAPE_SYSCALLS, AARCH64_BLOCKED_SOCKET_SYSCALLS,
    AARCH64_VIRTUAL_PATCH_CVE_SYSCALLS, AUDIT_ARCH_AARCH64, AUDIT_ARCH_X86_64,
    EXOTIC_BLOCKED_SOCKET_FAMILIES, LINUX_EACCES, LINUX_EAFNOSUPPORT, LINUX_ENOSYS, LINUX_EPERM,
    LINUX_SYS_CLONE3, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
    X86_64_BLOCKED_SANDBOX_ESCAPE_SYSCALLS, X86_64_BLOCKED_SOCKET_SYSCALLS,
    X86_64_VIRTUAL_PATCH_CVE_SYSCALLS,
};

pub use agentjacking_guard::{
    AgentjackingGuard, AgentjackingPhase, AgentjackingVerdict, SessionTaintState,
};
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
pub use continuous_eval::{
    ContinuousCycleReport, ContinuousEvaluationEngine, ContinuousProbeResult,
};
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
pub use identity::{
    constant_time_eq, constant_time_eq_hex, hmac_sha256, AgentIdentity, SignedAgentMessage,
};
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

pub mod pqc_arm;
pub mod protocol_research;
pub use pqc_arm::{
    CbomScanner, PostQuantumArm, PqcAlgorithm, PqcArmStatus, PqcDsaEngine, PqcKemEngine,
};
pub mod evolution;
pub use evolution::{
    EvolutionArmStatus, EvolutionCandidate, EvolutionMetrics, EvolutionaryOptimizerArm,
    PromotionState, SecurityInvariantGuard,
};
pub mod dream_rsi;
pub use dream_rsi::{
    DreamRolloutReport, DreamRsiOptimizerArm, DreamRsiPolicyOptimizer, DreamRsiStatus,
    ResearchPolicy, RsiExperimentPlan, TrajectoryEvent, WorldModelTransition,
};
pub mod harness2;
pub use harness2::{
    Harness2ArmStatus, HarnessBudgetLedger, HarnessComponentKind, HarnessExperienceEntry,
    HarnessRunReport, HarnessStageResult, HarnessSurfaceSpec, HarnessTreeValidationReport,
    HarnessTreeValidator, RecursiveHarnessOptimizerArm,
};

pub mod agent_classifier;
pub mod alignment_scanner;
pub mod console_defense;
pub mod dlp_lineage;
pub mod file_lineage;
pub mod glm_fusion_calibration;
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
pub use dlp_lineage::{
    ArtifactKey, ClassificationLattice, DlpBaggage, DlpLineageEngine, PolicyLattice,
    ProcessInstanceKey,
};
pub use file_lineage::{
    FileLineageRecord, FileLineageTracker, LineageCheckVerdict, MAX_LINEAGE_RECORDS,
};
pub use glm_fusion_calibration::{
    calibrate_glm_for_hardware, probe_ollama_installed_tags_fast, GlmFusionCalibrationReport,
    GlmHardwareSpec, GlmModelTier,
};
pub use mercury_guard::{
    HostActuationPore, MercuryContainmentEngine, MercuryEvaluationResult, CRITICAL_WEBER_NUMBER,
    MERCURY_ABS_COS_THETA, MERCURY_DENSITY_KG_M3, MERCURY_SURFACE_TENSION_N_PER_M,
};
pub use rl_defense::{
    ConfidenceInterval95, CyberBattleBenchmarkReport, PolicyBenchmarkMetrics, PolicyBenchmarkReport,
};
pub use spider_physics::{OrbWebContainmentEngine, OrbWebEvaluationResult, SilkRegime};
#[cfg(windows)]
pub use windows_sandbox::verify_process_appcontainer_token;
pub use windows_sandbox::{
    compute_windows_mitigation_policy_mask, evaluate_pre_resume_confinement_gate,
    spawn_tier2_appcontainer_command, verify_windows_confinement_invariants,
    AppContainerTokenVerification, Tier2ConfinedChildResult, WindowsConfinementPolicy,
    PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON,
    PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON,
    PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON,
    PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON,
    PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON,
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
};

pub mod executable_identity;
pub use executable_identity::{
    detect_renamed_interpreter_marker, open_and_lock_executable_for_cli,
    ExecutableIdentityVerifier, VerifiedExecutableHandle, VerifiedExecutableMetadata,
    ALLOWED_TIER2_EXECUTABLE_STEMS, FORBIDDEN_TIER2_EXECUTABLE_STEMS,
};
pub mod rea_binary_gate;
pub use rea_binary_gate::{
    inspect_binary_bytes, inspect_locked_file, BinaryFormat, BinaryIntegrityVerdict, ByteCursor,
};

pub mod token_posture;
#[cfg(windows)]
pub use token_posture::{
    create_deelevated_token, spawn_deelevated, spawn_deelevated_in_job, DeelevatedChild, OwnedToken,
};
pub use token_posture::{
    current_token_posture, relaunch_deelevated_or_fail, TokenPosture, DANGEROUS_PRIVILEGES,
    DEELEVATED_ENV_MARKER, INTEGRITY_HIGH, INTEGRITY_MEDIUM,
};

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

pub mod wasm_tier1;
pub use wasm_tier1::{
    WasmExecutionReceipt, WasmFsPolicy, WasmHostState, WasmSandboxLimits, WasmTier1Executor,
    WASI_ERR_ACCESS_DENIED, WASI_ERR_FAULT, WASI_ERR_IO, WASM_DOC_EXTRACTOR_WAT,
    WASM_LEDGER_VALIDATOR_WAT,
};

pub mod rate_limit_backoff;
pub use rate_limit_backoff::{
    global_rate_limit_ensemble, global_rete_engine, BackoffEvaluationReport,
    CorrelatedEvidenceBundle, DeterministicPhysicsVoter, EdrAction, GenerativeLlmVoter,
    GoogleApiBackoffAnalyzer, HarEntrySample, HarFlowFact, NetworkProtocol, OpenJevDecisionVoter,
    OsqueryProcessFact, PreSpawnReaPolicy, PreSpawnReaVerdict, RateLimitAllowlist,
    RateLimitAllowlistStore, RateLimitReleaseEntry, RateLimitVoterEnsemble, ReaBinaryFact,
    ReteEngine, VoterConsensus, VoterVerdict,
};

pub mod cage_substrate;
pub mod host_network_isolation;
pub mod latent_shield;
pub mod universal_protocols;

pub use cage_substrate::{
    base64url_decode_no_pad, base64url_encode_no_pad, canonicalize_jcs, canonicalize_jcs_string,
    freeze_process_by_pid, resolve_loopback_peer_pid, resume_process_by_pid,
    CageAttestationResponse, CageConformalBaselineResponse, CageConformalValidateRequest,
    CageConformalValidateResponse, CageKeyManifestResolver, CageQuarantineReceiptResponse,
    CageQuarantineReleaseReceiptResponse, CageQuarantineReleaseRequest, CageQuarantineRequest,
    CageSubstrateState, Cumulative24hTracker, JcsError, JournalData, JournalRecord, JwkKeyDto,
    JwksResponse, KeyedCumulative24hTracker, NonceReplayCache, QuarantineJournal, QuarantineLease,
    SealedJournalEnvelope,
};
pub use host_network_isolation::{
    apply_virtual_patch_perimeter_shield, build_linux_blackhole_route_msg,
    build_virtual_patch_perimeter_spec, discover_active_octopus_ports,
    generate_bsd_darwin_pf_virtual_patch_rules, generate_linux_nftables_virtual_patch_rules,
    generate_macos_pf_quarantine_rules, global_host_killswitch, handle_wfp_kernel_apply_cli,
    has_live_active_wfp_filters, is_current_process_elevated, load_persisted_wfp_filter_ids,
    terminate_non_loopback_tcp_sockets, FwpmFilter0, HostIsolationError, HostIsolationReceipt,
    HostKillSwitchManager, HostKillSwitchStatus, KernelIsolationBackend, KernelPerimeterPatchSpec,
    BLOCKED_L2_ETHERTYPES, DEFAULT_OCTOPUS_PORT, FORBIDDEN_PORT_5000, VIRTUAL_PATCH_INBOUND_PORTS,
    WFP_RULE_PREFIX,
};
pub use universal_protocols::{
    OsiLayer, ProtocolDefinition, ProtocolDomain, ProtocolVectorType, UniversalProtocolCatalog,
    CATALOG_ENTRIES,
};

pub mod active_sockets;
pub mod agent_hooks;
pub mod circumvention;
pub mod exec_sensor;
pub mod process_immunity;
pub mod semantic_command;
pub mod semantic_dlp;
pub mod sensitive_paths;
pub mod siquery;
pub mod virtual_patch_shield;

pub use bsd_sandbox::{build_bsd_confinement_posture, BsdConfinementPosture};
pub use virtual_patch_shield::{
    apply_shield_posture, build_shield_receipt, build_shield_receipt_with_enforcement,
    current_shield_posture, global_shield_store, mark_shield_telemetry_degraded,
    KernelAttackSurface, KernelShieldPosture, VirtualPatchShieldReceipt, VirtualPatchShieldStore,
    ENV_SHIELD_POSTURE_PATH,
};

pub use active_sockets::{query_live_os_process_sockets, OsQueryProcessSocketRow};
pub use agent_hooks::{
    evaluate_hook_synchronously, format_claude_response, format_copilot_response,
    format_cursor_response, format_mcp_error_response, format_opencode_response,
    install_agent_hooks, parse_claude_request, parse_copilot_request, parse_cursor_request,
    parse_mcp_request, parse_opencode_request, snapshot_interceptions, AgentInterceptionRecord,
    HookEvaluationDecision, HookEventType, NormalizedHookRequest, SupportedAgentKind,
};
pub use circumvention::{
    evaluate_denial_outcome, is_cross_boundary_invocation, observe_denial, CircumventionAlert,
    DenialPatternKind, DynamicDenialSignal, TemporalCircumventionCorrelator,
    TemporalCircumventionEngine,
};
pub use exec_sensor::{
    ExecEvent, ExecEventSubscriber, ExecSensorBuffer, EXEC_SENSOR_BUFFER,
    EXEC_SENSOR_DEFAULT_CAPACITY,
};
pub use latent_shield::{
    extract_sbom_features, load_cyclonedx_sbom_file, parse_cyclonedx_sbom_bounded,
    validate_sbom_bounds, AgentRuntimeGuard, ComponentProperty, CycloneDxSbom, GuardVerdict,
    LatentShieldError, LatentWorldModel, LicenseChoice, LicenseDetail, LiveRuntimeMonitor,
    RuntimeEventKind, RuntimeGuardVerdictSummary, RuntimeTelemetry, SbomComponent, SbomDependency,
    SbomIntent, SbomSupplyChainGuard, UnifiedSecurityShield, DEFAULT_EMBEDDED_WEIGHTS_JSON,
    DEFAULT_LATENT_DIM, MAX_MODEL_DIM, MAX_SBOM_COMPONENTS, MAX_SBOM_DEPENDENCIES, MAX_SBOM_EDGES,
    MAX_SBOM_JSON_BYTES, MAX_SBOM_LICENSES_PER_COMPONENT, MAX_SBOM_PROPERTIES_PER_COMPONENT,
    MAX_SBOM_STRING_LEN, MAX_WEIGHTS_JSON_BYTES, RUNTIME_ACTION_DIM, RUNTIME_OBS_DIM,
    SBOM_ACTION_DIM, SBOM_OBS_DIM,
};
pub use process_immunity::{
    inspect_process_lineage, is_immutable_os_kernel_anchor, is_process_immune,
    observe_process_token_delta, probe_binary_capabilities, stem_matches_exact, AgentRuntimeChild,
    BinaryCapabilities, LineageInspectionResult, TokenDeltaObservation,
};
pub use semantic_command::{
    classify_action_class, parse_semantic_command, tokenize_command, unwrap_env_invocation,
    unwrap_shell_and_env_nesting, unwrap_shell_invocation, DynamicBinaryMetadataProbe,
    PrivilegeEquivalenceClass, SemanticCommand,
};
pub use semantic_dlp::{
    is_dlp_deal_delimiter, is_dlp_structural_delimiter, luhn_check, query_recent_semantic_events,
    record_semantic_dlp_event, safe_utf8_slice, snapshot_semantic_dlp_events,
    tokenize_dlp_deal_payload, tokenize_dlp_payload, GlinerSpanMatch, GlinerSpanNerEngine,
    PresidioGlinerPiiZeroGuard, RedactXStructuredValidator, SemanticDlpEngine, SemanticDlpEntity,
    SemanticDlpRecord, SemanticDlpVerdict, SemanticEntityKind, ZeroLeakageProof,
};
pub use sensitive_paths::{
    classify_mandatory_write_deny_path, classify_pinned_parent_for_write_deny,
    classify_sensitive_system_path, is_mandatory_write_deny_path, is_sensitive_credential_store,
    scan_for_sensitive_system_path, scan_json_for_sensitive_path, MandatoryWriteDenyKind,
    SensitiveCredentialStoreKind, SensitiveSystemPathGuard, SensitiveSystemStoreKind,
};
pub use siquery::{
    register_lineage_file_events_hook, register_lineage_open_files_hook, FileEventRecord,
    SiqueryEngine, SiqueryRow, LIVE_FILE_EVENTS, SIQUERY_LAST_TELEMETRY,
};
