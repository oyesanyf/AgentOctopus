pub mod adversary;
pub mod arm;
pub mod brain;
pub mod conformal_jailbreak;
pub mod containment_ring;
pub mod core;
pub mod deterministic;
pub mod edr_bench;
pub mod enclave;
pub mod fprime_flight;
pub mod ledger;
pub mod neural_mesh;
pub mod quantum;
pub mod research_ingest;
pub mod security;
pub mod sentinel_ring;
pub mod swarm;
pub mod telemetry;
pub mod web;

pub use adversary::{
    AdversarialAttack, AttackCategory, AttackEvaluation, CampaignSummary, PromptInjectionEngine,
};
pub use arm::ArmRuntime;
pub use brain::CentralBrain;
pub use containment_ring::{
    ArmContainmentRing, ArmExecutionError, ArmRingConfig, ArmRingMeshMessage, ArmRingRegistry,
    AuditEvent, Authorizer, BoxFuture, BudgetQuota, CapabilityGate, CedarAuthorizer, CedarGate,
    ContainmentRing, EgressProxy, EgressRequest, EgressResponse, EgressSecurityLevel,
    EnclaveToolExecutor, IdentityGate, IsolationManager, MeshGuard, Operation,
    PolicyAttestationRecord, ResourceGuard, RingAttestation, RingAuditEntry, RingAuditLedger,
    RingConfig, RingController, RingDecision, RingError, RingOperationRequest, RingRequest,
    SandboxConstraints, ToolExecutor, TrustedArmHandle,
};
pub use core::circuit_breaker::KillSwitch;
pub use core::merkle::{
    hash_leaf, hash_nodes, verify_execution_step, DatasetMerkleTree, Direction,
    ExecutionMerkleTree, Hash32, MerkleLeaf, MerkleProof, MerkleTree, PolicyMerkleTree,
};
pub use core::types::*;
pub use deterministic::{
    ArmState, DeterministicLayer, FsmTransitionGuard, PolicyGuard, SchemaGuard,
};
pub use edr_bench::{
    resolve_fixture_path, BenchmarkReport, BenignBaselineAssertion, EdrBenchHarness, EdrBenchTask,
    ExpectedVerdict, HarnessBounds, ParsedYaraRule, StringPattern, TargetArch, TelemetryContext,
    ThreatAssertion,
};
pub use enclave::{HttpEgressGate, SafeDocumentExtractor, SafeLedgerWriter, SafeTool};
pub use fprime_flight::{
    create_port_pair, ArenaBinKind, ArenaSlotHandle, BftMeshConsensusComponent,
    BftQuorumPromotionProof, ComponentHealthVerdict, ContainmentDirective,
    EbpfPmuTelemetryComponent, FPrimeComponent, FPrimeError, FPrimeFlightRuntime,
    FPrimeOperatingMode, FPrimeTelemetrySnapshot, FPrimeTopology, InputPort, IsolationAck,
    OutputPort, PingToken, PongToken, PortConnectionDescriptor, PortEnvelope, PortQosLane,
    ReaInspectionVerdict, ReaMagikaInspectorComponent, RecoilAssessment,
    RecoilLikelihoodScorerComponent, SafeModeExecutionReport, SafeModePlaybook, SequencerOp,
    StaticArenaPool, SvcCmdSequencer, SvcHealthMonitor, TelemetryFrame, WatchdogStrokeReceipt,
    WfpNetworkIsolatorComponent,
};
pub use ledger::{
    InclusionProof, LedgerError, LogCheckpoint, PolicyAttestation, PolicyProposal,
    PostQuantumAttestation, PqcAlgorithm, PqcKeypair, ProofDirection, ProofSibling,
    QuorumPolicyGuard, SignedExecutionReceipt, TransparencyLog,
};
pub use neural_mesh::{ArmEndpoint, MeshError, MessageKind, NeuralMesh, NeuralMessage};
pub use quantum::{
    AgentNode, AttackEdge, AttackGraph, ChannelType, Complex, ExperimentComparisonReport,
    QuantumAnnealerConfig, QuantumCircuit, QuantumGate, QuantumWalkSimulator, QuboModel,
    QuboResult, SimulatedQuantumAnnealer, WalkComparison,
};
pub use research_ingest::{
    approve_ingested_research_rule, approve_pending_research_item, auto_correct_research_rule,
    canonical_research_rule_id, check_paper_to_code_semantic_domain_alignment,
    clear_all_ingested_research_rules, clear_or_restore_research_rules,
    compute_pending_item_priority, default_seeded_research_defense_rules,
    detect_verified_code_repo, evaluate_research_ingest, evaluate_research_novelty_check,
    execute_langgraph_research_swarm, get_pending_research_queue, get_research_schedule,
    get_research_status, is_canonical_m12_research_arxiv_id, is_current_research_arxiv_id,
    is_research_rule_operator_approved, is_research_rule_pinned, is_valid_technical_indicator,
    is_valid_verified_repo_url, list_ingested_research_rules, normalize_base_arxiv_id,
    parse_arxiv_year_month, pin_ingested_research_rule, register_ingested_research_rule,
    reject_pending_research_item, remove_ingested_research_rule, reset_research_defense_registry,
    restore_default_research_rules, run_live_regression_probe, run_paper2agent_accuracy_suite,
    safe_arxiv_abs_url, safe_arxiv_pdf_url, search_research_papers, synthesize_rust_guard_snippet,
    trim_pending_research_queue, update_research_schedule, validate_pending_research_item,
    validate_research_rule_acceptance, verify_generated_guard_code_accuracy,
    verify_rule_against_canary_benign_corpus, AgenticToolInvocation, GlmMultiModelFusionEvaluator,
    GroundedBreakoutExtraction, IngestedResearchDefenseRule, LangGraphEdge,
    LangGraphEdgeTransition, LangGraphNodeExecution, LangGraphSwarmRequest, LangGraphSwarmResponse,
    LiveRegressionProbeReport, LiveRegressionProbeResult, LlmFusionArmReport, LlmFusionConsensus,
    Paper2AgentAccuracySuiteResult, Paper2AgentCompiler, PaperNoveltyEvaluation,
    PendingResearchItem, ResearchAcceptanceVerdict, ResearchApprovalRequest,
    ResearchApprovalResponse, ResearchClearRequest, ResearchClearResponse, ResearchCoverageReport,
    ResearchExtractionItem, ResearchIngestRequest, ResearchIngestResponse,
    ResearchNoveltyCheckRequest, ResearchNoveltyCheckResponse, ResearchScheduleConfig,
    ResearchScheduleResponse, ResearchScheduleUpdateRequest, ResearchSearchRequest,
    ResearchSearchResponse, ResearchStatusResponse, ResearchValidationResponse, RingProbeVerdict,
    RuleAccuracyReport, VectorCoverageVerdict, ALREADY_IMPLEMENTED_ARXIV_IDS,
    CANARY_BENIGN_TELEMETRY_CORPUS, CODE_REPO_PRIORITY_BOOST, MIN_CURRENT_RESEARCH_ARXIV_YY,
};
pub use security::{
    hmac_sha256, AdaptiveMitigationTier, AgentIdentity, AgentRaspEngine, AgentSecuritySubject,
    AuditRecord, CapabilityToken, CedarAuthorizationGateway, CedarPolicyEngine, CedarSchema,
    DelegationScopeGuard, ExternalAuthorizationEngine, OpenShellConfig, OpenShellMode,
    RaspDecision, RaspThreatCategory, SandboxConfinementPolicy, SecurityAuditLog,
    SignedAgentMessage, WasmArmSandbox,
};
pub use swarm::{SwarmBatchSummary, SwarmManager};
pub use telemetry::{AnomalyDetector, WatchdogSupervisor};
pub use web::{start_web_server, static_files::INDEX_HTML};

pub use containment_ring::{
    is_restricted_rebinding_ip, now_micros, validate_agent_egress_url, AlgebraicTraceProof,
    DiracDeltaCapabilityTicket, HomologicalAuditReport, HomologicalBoundaryAuditor,
    IndependentTrustBoundaryVerifier, MeshWatchOutSignal, MultiLayerGateVerdict,
    PinnedToolObjectBinding, VanishingPolynomialTraceVerifier, ZeroCopyImmutableToolBuffer,
    MERSENNE_PRIME_127,
};
pub use security::{
    calibrate_glm_for_hardware, compute_hardened_console_mode,
    evaluate_pre_resume_confinement_gate, harden_windows_console, is_console_mode_hardened,
    probe_ollama_installed_tags_fast, validate_agent_filesystem_access,
    validate_sandbox_relative_path, verify_windows_confinement_invariants,
    AgentClassificationVerdict, AlignmentScanVerdict, ArtifactKey, ClassificationLattice,
    CommandConsoleExt, ConfidenceInterval95, CyberBattleBenchmarkReport, DlpBaggage,
    DlpLineageEngine, DynamicAgentClassifier, FileLineageRecord, FileLineageTracker,
    GlmFusionCalibrationReport, GlmHardwareSpec, GlmModelTier, HostActuationPore,
    LineageCheckVerdict, MercuryContainmentEngine, MercuryEvaluationResult,
    OrbWebContainmentEngine, OrbWebEvaluationResult, PolicyBenchmarkMetrics, PolicyLattice,
    ProcessBehavioralTelemetry, ProcessInstanceKey, RuntimeAlignmentScanner, SessionIntentContract,
    SilkRegime, ToolCallTraceStep, WindowsConfinementPolicy, ZeroMiProjectionResult,
    ZeroMutualInformationProjector,
};

pub use security::{
    CageGovernanceEngine, CageRoutingSeal, CbfSafetyEngine, CbfViolation, CommitReceipt,
    CompiledCagePolicy, DebitLedger, FormalBfsModel, FtraVerdict, GovernanceEvaluationResult,
    GovernanceRequest, GovernanceVerdict, PlanGraphAnalyzer, PlanStep, PolicyFormat,
    RoutingSealSigner, SealRejection, StreamVerificationReport, SubstrateTranslator,
    TheoremProofResult,
};

pub use security::{
    build_linux_blackhole_route_msg, discover_active_octopus_ports,
    generate_macos_pf_quarantine_rules, global_host_killswitch, handle_wfp_kernel_apply_cli,
    has_live_active_wfp_filters, HostIsolationError, HostIsolationReceipt, HostKillSwitchManager,
    HostKillSwitchStatus, KernelIsolationBackend, OsiLayer, ProtocolDefinition, ProtocolDomain,
    ProtocolVectorType, UniversalProtocolCatalog,
};
