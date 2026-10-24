//! Octopus Containment Ring (OCR)
//!
//! An independently enforced, concentric security boundary surrounding the entire
//! Agent Octopus swarm, Central Brain, and host environment.
//!
//! Architecture:
//! - **Inner Ring (Inter-Agent Trust Boundary)**: Governs every transition between
//!   the Central Brain, Neural Mesh, and individual Arms (`IdentityGate`, `MeshGuard`, `CapabilityGate`).
//!   Guarantees zero privilege inheritance through messaging and eliminates agent collusion.
//! - **Outer Ring (Host & External Containment Boundary)**: Governs all interactions crossing
//!   into the host OS and external networks (`EgressProxy`, `IsolationManager`, `ResourceGuard`).
//!   Operates out-of-band and cannot be disabled, bypassed, or modified by compromised agents.

pub mod arm_ring;
pub mod attestation;
pub mod audit;
pub mod auditor;
pub mod capability_gate;
pub mod cedar_gate;
pub mod egress_proxy;
pub mod identity_gate;
pub mod isolation_manager;
pub mod mesh_guard;
pub mod primitives;
pub mod resource_guard;
pub mod ring_controller;
pub mod sentinel;
pub mod trusted_controller;

pub use arm_ring::{
    ArmContainmentRing, ArmRingConfig, ArmRingMeshMessage, ArmRingRegistry, ArmRingStatusDto,
    ProvenanceHop,
};
pub use primitives::{
    now_micros, DiracDeltaCapabilityTicket, IndependentTrustBoundaryVerifier, MeshWatchOutSignal,
    MultiLayerGateVerdict, PinnedToolObjectBinding, ZeroCopyImmutableToolBuffer,
};
pub use sentinel::{
    evaluate as evaluate_sentinel, create_supervisor_heartbeat, OctopusSentinelRing,
    SentinelAction, SentinelAuditEntry, SentinelConfig, SentinelObservation, SupervisorHeartbeat,
};
pub use attestation::{PolicyAttestationRecord, RingAttestation};
pub use audit::{RingAuditEntry, RingAuditLedger};
pub use auditor::{ContainmentAuditor, DefenseAuditReport};
pub use capability_gate::CapabilityGate;
pub use cedar_gate::{
    AlgebraicTraceProof, CedarAuditControlToken, CedarGate, NegativeControlToken,
    VanishingPolynomialTraceVerifier, MERSENNE_PRIME_127,
};
pub use egress_proxy::{
    is_restricted_rebinding_ip, pinned_curl_command, resolve_and_pin, validate_agent_egress_url,
    EgressProxy, EgressRequest, EgressResponse, EgressSecurityLevel, PinnedEgress,
};
pub use identity_gate::IdentityGate;
pub use isolation_manager::{IsolationManager, SandboxConstraints};
pub use mesh_guard::{
    role_trust_tier, HomologicalAuditReport, HomologicalBoundaryAuditor, MeshGuard, TrustTier,
    VerifiedMeshMessage, MAX_RELAY_HOPS,
};
pub use resource_guard::{BudgetQuota, ResourceGuard};
pub use ring_controller::{ContainmentAuditHarness, ContainmentRing, RingOperationRequest};
pub use trusted_controller::{
    AuditEvent, Authorizer, BoxFuture, CedarAuthorizer, EnclaveToolExecutor, Operation,
    RingConfig, RingController, RingError, RingRequest, ToolExecutor, TrustedArmHandle,
};

use serde::{Deserialize, Serialize};

/// The definitive verdict returned by the Octopus Containment Ring for any operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RingDecision {
    /// Operation is cryptographically verified, within policy, and authorized for execution.
    Allow,
    /// Operation violates policy or perimeter bounds; safely rejected with no external side effects.
    Deny,
    /// Suspicious behavioral anomaly or lateral pivot detected; arm suspended and quarantined.
    Quarantine,
    /// Severe security breach or tamper detected; arm terminated immediately via autotomy circuit breaker.
    Terminate,
}
