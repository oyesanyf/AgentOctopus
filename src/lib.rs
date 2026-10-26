pub mod adversary;
pub mod arm;
pub mod brain;
pub mod containment_ring;
pub mod core;
pub mod deterministic;
pub mod enclave;
pub mod fprime_flight;
pub mod ledger;
pub mod neural_mesh;
pub mod quantum;
pub mod security;
pub mod swarm;
pub mod telemetry;
pub mod sentinel_ring;
pub mod web;

pub use adversary::{
    AdversarialAttack, AttackCategory, AttackEvaluation, CampaignSummary, PromptInjectionEngine,
};
pub use arm::ArmRuntime;
pub use brain::CentralBrain;
pub use containment_ring::{
    ArmContainmentRing, ArmRingConfig, ArmRingMeshMessage, ArmRingRegistry, AuditEvent, Authorizer,
    BoxFuture, BudgetQuota, CapabilityGate, CedarAuthorizer, CedarGate, ContainmentRing,
    EgressProxy, EgressRequest, EgressResponse, EgressSecurityLevel, EnclaveToolExecutor,
    IdentityGate, IsolationManager, MeshGuard, Operation, PolicyAttestationRecord, ResourceGuard,
    RingAttestation, RingAuditEntry, RingAuditLedger, RingConfig, RingController, RingDecision,
    RingError, RingOperationRequest, RingRequest, SandboxConstraints, ToolExecutor,
    TrustedArmHandle,
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
pub use neural_mesh::{ArmEndpoint, MessageKind, MeshError, NeuralMesh, NeuralMessage};
pub use quantum::{
    AgentNode, AttackEdge, AttackGraph, ChannelType, Complex, ExperimentComparisonReport,
    QuantumAnnealerConfig, QuantumCircuit, QuantumGate, QuantumWalkSimulator, QuboModel,
    QuboResult, SimulatedQuantumAnnealer, WalkComparison,
};
pub use security::{
    hmac_sha256, AdaptiveMitigationTier, AgentIdentity, AgentRaspEngine, AgentSecuritySubject,
    AuditRecord, CapabilityToken, CedarAuthorizationGateway, CedarPolicyEngine, CedarSchema,
    DelegationScopeGuard, ExternalAuthorizationEngine, OpenShellConfig, OpenShellMode,
    RaspDecision, RaspThreatCategory, SandboxConfinementPolicy, SecurityAuditLog, SignedAgentMessage,
    WasmArmSandbox,
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
    compute_hardened_console_mode, evaluate_pre_resume_confinement_gate, harden_windows_console,
    is_console_mode_hardened, validate_agent_filesystem_access, validate_sandbox_relative_path,
    verify_windows_confinement_invariants, AgentClassificationVerdict, AlignmentScanVerdict,
    ArtifactKey, ClassificationLattice, CommandConsoleExt, ConfidenceInterval95,
    CyberBattleBenchmarkReport, DlpBaggage, DlpLineageEngine, DynamicAgentClassifier,
    FileLineageRecord, FileLineageTracker, HostActuationPore, LineageCheckVerdict,
    MercuryContainmentEngine, MercuryEvaluationResult, OrbWebContainmentEngine,
    OrbWebEvaluationResult, PolicyBenchmarkMetrics, PolicyLattice, ProcessBehavioralTelemetry,
    ProcessInstanceKey, RuntimeAlignmentScanner, SessionIntentContract, SilkRegime,
    ToolCallTraceStep, WindowsConfinementPolicy, ZeroMiProjectionResult,
    ZeroMutualInformationProjector,
};
