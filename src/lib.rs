pub mod adversary;
pub mod arm;
pub mod brain;
pub mod core;
pub mod deterministic;
pub mod enclave;
pub mod ledger;
pub mod neural_mesh;
pub mod quantum;
pub mod security;
pub mod swarm;
pub mod telemetry;
pub mod web;

pub use adversary::{
    AdversarialAttack, AttackCategory, AttackEvaluation, CampaignSummary, PromptInjectionEngine,
};
pub use arm::ArmRuntime;
pub use brain::CentralBrain;
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
