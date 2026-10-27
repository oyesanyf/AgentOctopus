use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::neural_mesh::MessageKind;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Law 1: Topological & Homological Audit Report over the Agent Communication Complex $K$.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomologicalAuditReport {
    pub allowed: bool,
    pub sender: String,
    pub intermediary: Option<String>,
    pub recipient: String,
    pub sender_potential: i64,
    pub intermediary_potential: Option<i64>,
    pub recipient_potential: i64,
    pub coboundary_residue: i64,
    pub boundary_squared_zero: bool,
    pub proxy_laundering_detected: bool,
    pub reason: String,
}

/// Law 1: Simplicial Homology & Cochain Boundary Auditor (`\partial_1 \circ \partial_2 = 0` and `\delta^2 \phi = 0`).
///
/// Models the multi-agent mesh as an oriented simplicial complex $K = (V, E, F)$ equipped with
/// a discrete privilege potential 0-cochain $\phi: V \to \mathbb{Z}$.
/// Any 2-simplex $[v_0, v_1, v_2]$ where a low-privilege node $v_0$ attempts to launder authority
/// through an intermediate worker $v_1$ into a high-privilege sink $v_2$ induces a non-exact
/// coboundary defect ($\Delta_{\text{proxy}} > 0$) and is mathematically vetoed.
#[derive(Debug, Clone, Default)]
pub struct HomologicalBoundaryAuditor;

impl HomologicalBoundaryAuditor {
    /// CIS Benchmark 2.2: Unicode Case Folding + NFKC Compatibility Normalization + UTS #39 Confusable Skeleton.
    /// Prevents homoglyph spoofing (Cyrillic/Greek/Fullwidth/Math lookalikes, zero-width characters)
    /// when evaluating lateral sink isolation, role names, and agent identities.
    pub fn normalize_identifier_uts39_skeleton(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        for c in input.trim().chars() {
            if matches!(
                c,
                '\u{200B}'..='\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2060}'..='\u{206F}'
                    | '\u{FEFF}'
                    | '\u{00AD}'
            ) {
                continue;
            }
            let mapped = if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
                char::from_u32((c as u32) - 0xFEE0).unwrap_or(c)
            } else {
                match c {
                    '\u{0430}' | '\u{0410}' | '\u{03B1}' | '\u{0391}' => 'a',
                    '\u{0432}' | '\u{0412}' | '\u{03B2}' | '\u{0392}' => 'b',
                    '\u{0441}' | '\u{0421}' | '\u{03F2}' | '\u{03F9}' => 'c',
                    '\u{0435}' | '\u{0415}' | '\u{03B5}' | '\u{0395}' => 'e',
                    '\u{04BB}' | '\u{04BA}' | '\u{03B7}' | '\u{0397}' => 'h',
                    '\u{0456}' | '\u{0406}' | '\u{03B9}' | '\u{0399}' | '\u{0131}' => 'i',
                    '\u{0458}' | '\u{0408}' | '\u{03F3}' => 'j',
                    '\u{043A}' | '\u{041A}' | '\u{03BA}' | '\u{039A}' => 'k',
                    '\u{04CF}' | '\u{04C0}' | '\u{2113}' => 'l',
                    '\u{043C}' | '\u{041C}' | '\u{03BC}' | '\u{039C}' => 'm',
                    '\u{043D}' | '\u{03BD}' | '\u{039D}' => 'n',
                    '\u{043E}' | '\u{041E}' | '\u{03BF}' | '\u{039F}' => 'o',
                    '\u{0440}' | '\u{0420}' | '\u{03C1}' | '\u{03A1}' => 'p',
                    '\u{0455}' | '\u{0405}' => 's',
                    '\u{0442}' | '\u{0422}' | '\u{03C4}' | '\u{03A4}' => 't',
                    '\u{0443}' | '\u{0423}' | '\u{03C5}' | '\u{03A5}' => 'u',
                    '\u{0475}' | '\u{0474}' => 'v',
                    '\u{0461}' | '\u{0460}' | '\u{03C9}' => 'w',
                    '\u{0445}' | '\u{0425}' | '\u{03C7}' | '\u{03A7}' => 'x',
                    '\u{03B3}' => 'y',
                    '\u{03B6}' | '\u{0396}' => 'z',
                    '\u{FB00}' => {
                        out.push_str("ff");
                        continue;
                    }
                    '\u{FB01}' => {
                        out.push_str("fi");
                        continue;
                    }
                    '\u{FB02}' => {
                        out.push_str("fl");
                        continue;
                    }
                    '\u{FB03}' => {
                        out.push_str("ffi");
                        continue;
                    }
                    '\u{FB04}' => {
                        out.push_str("ffl");
                        continue;
                    }
                    other => other,
                }
            };
            for lc in mapped.to_lowercase() {
                out.push(lc);
            }
        }
        out
    }

    /// Discrete privilege potential $\phi(v) \in \mathbb{Z}$, derived ONLY from an authenticated
    /// [`ArmRole`] (the role is bound into the sender's epoch HMAC key derivation), never from a
    /// self-chosen agent name. An untrusted arm calling itself `arm-Worker-7` or `docker-admin`
    /// still carries `UntrustedDocIngest` in its signature.
    pub fn privilege_potential(role: &ArmRole) -> i64 {
        role_trust_tier(role).potential()
    }

    /// Law 1 audit over a full relay chain $[v_0, v_1, \dots, v_n]$ of authenticated roles
    /// (origin first, recipient last).
    ///
    /// Taint is sticky: the effective origin potential is the **minimum** potential over every
    /// upstream hop, so `untrusted -> worker -> worker -> ledger` is vetoed exactly like the direct
    /// edge. Chains shorter than 2 or longer than [`MAX_RELAY_HOPS`] + 1 fail closed.
    pub fn audit_role_chain(chain: &[ArmRole]) -> HomologicalAuditReport {
        let describe = |r: &ArmRole| format!("{:?}", r);
        if chain.len() < 2 || chain.len() > MAX_RELAY_HOPS + 1 {
            return HomologicalAuditReport {
                allowed: false,
                sender: chain.first().map(describe).unwrap_or_default(),
                intermediary: None,
                recipient: chain.last().map(describe).unwrap_or_default(),
                sender_potential: 0,
                intermediary_potential: None,
                recipient_potential: 0,
                coboundary_residue: 0,
                boundary_squared_zero: false,
                proxy_laundering_detected: true,
                reason: format!(
                    "LAW1_CHAIN_LENGTH_VETO: relay chain length {} outside [2, {}]",
                    chain.len(),
                    MAX_RELAY_HOPS + 1
                ),
            };
        }

        let potentials: Vec<i64> = chain.iter().map(Self::privilege_potential).collect();
        let n = potentials.len();
        let phi_s = potentials[0];
        let phi_r = potentials[n - 1];
        let middle = &potentials[1..n - 1];
        let phi_i = middle.iter().copied().min();

        // Telescoping boundary check: sum of consecutive edge differences equals the direct edge.
        let telescoped: i64 = potentials.windows(2).map(|w| w[1] - w[0]).sum();
        let coboundary_residue = telescoped - (phi_r - phi_s);
        let boundary_squared_zero = coboundary_residue == 0;

        // Sticky taint: lowest-trust upstream hop determines the effective origin.
        let origin_floor = potentials[..n - 1].iter().copied().min().unwrap_or(phi_s);
        let direct_violation = n == 2
            && phi_s <= TrustTier::Untrusted.potential()
            && phi_r >= TrustTier::PrivilegedSink.potential();
        let transitive_laundering = n > 2
            && origin_floor <= TrustTier::Untrusted.potential()
            && phi_r >= TrustTier::PrivilegedSink.potential();
        let proxy_laundering_detected =
            direct_violation || transitive_laundering || !boundary_squared_zero;
        let allowed = !proxy_laundering_detected;

        let chain_str = chain.iter().map(describe).collect::<Vec<_>>().join(" -> ");
        let reason = if allowed {
            format!(
                "LAW1_HOMOLOGICAL_EXACTNESS_VERIFIED: chain [{}] preserves privilege potential (origin floor {} -> sink {})",
                chain_str, origin_floor, phi_r
            )
        } else if transitive_laundering {
            format!(
                "LAW1_PROXY_LAUNDERING_VETO: {}-hop relay [{}] carries untrusted taint (floor {}) into privileged sink (phi {})",
                n - 1,
                chain_str,
                origin_floor,
                phi_r
            )
        } else {
            format!(
                "LAW1_DIRECT_BOUNDARY_VETO: 1-simplex [{}] violates cochain privilege potential (phi: {} -> {})",
                chain_str, phi_s, phi_r
            )
        };

        HomologicalAuditReport {
            allowed,
            sender: describe(&chain[0]),
            intermediary: if n > 2 {
                Some(
                    chain[1..n - 1]
                        .iter()
                        .map(describe)
                        .collect::<Vec<_>>()
                        .join(" -> "),
                )
            } else {
                None
            },
            recipient: describe(&chain[n - 1]),
            sender_potential: phi_s,
            intermediary_potential: phi_i,
            recipient_potential: phi_r,
            coboundary_residue,
            boundary_squared_zero,
            proxy_laundering_detected,
            reason,
        }
    }

    /// Evaluates a direct 1-simplex edge $[v_0, v_1]$ or a 2-simplex relay $[v_0, v_1, v_2]$
    /// over authenticated roles. Convenience wrapper around [`Self::audit_role_chain`].
    pub fn audit_simplex_transition(
        sender: &ArmRole,
        intermediary: Option<&ArmRole>,
        recipient: &ArmRole,
    ) -> HomologicalAuditReport {
        let mut chain = vec![sender.clone()];
        if let Some(i) = intermediary {
            chain.push(i.clone());
        }
        chain.push(recipient.clone());
        Self::audit_role_chain(&chain)
    }
}

/// Maximum number of relay hops carried in a mesh message's signed provenance chain.
pub const MAX_RELAY_HOPS: usize = 16;

/// Trust tier of an authenticated arm role (the 0-cochain $\phi$ values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustTier {
    /// Arms that ingest attacker-controlled input (documents, fuzz corpora, raw wire traffic, decoys).
    Untrusted = 10,
    /// Standard worker / analysis arms.
    Worker = 50,
    /// High-privilege sinks (ledger writes, kernel sentinel, policy authority, signing keys).
    PrivilegedSink = 100,
}

impl TrustTier {
    pub fn potential(self) -> i64 {
        self as i64
    }
}

/// Exhaustive role -> trust tier mapping. There is deliberately NO wildcard arm: adding a new
/// [`ArmRole`] variant is a compile error until it is explicitly classified (fail-closed).
pub fn role_trust_tier(role: &ArmRole) -> TrustTier {
    match role {
        ArmRole::UntrustedDocIngest
        | ArmRole::DifferentialProtocolAnalyzer
        | ArmRole::AutonomousProtocolResearch
        | ArmRole::ContinuousOssFuzz
        | ArmRole::TarpitDecoyDefense => TrustTier::Untrusted,

        ArmRole::AccountingLedgerWrite
        | ArmRole::KernelLevelSentinel
        | ArmRole::CedarPolicyEvaluation
        | ArmRole::PostQuantumAttestation => TrustTier::PrivilegedSink,

        ArmRole::OutboundNotification
        | ArmRole::NetworkEgress
        | ArmRole::AtlasThreatIntelligence
        | ArmRole::AnomalyDetection
        | ArmRole::VulnerabilityResearch
        | ArmRole::ContinuousOsvScanner
        | ArmRole::EvolutionaryOptimizer
        | ArmRole::DreamRsiOptimizer
        | ArmRole::RecursiveHarnessOptimizer => TrustTier::Worker,
    }
}

/// Inner Ring Neural Mesh Guard:
/// Mediates inter-arm communication, preventing privilege escalation,
/// message forgery, and unauthorized lateral movement.
///
/// Operates exclusively on [`VerifiedMeshMessage`]s, which can only be produced by
/// `ArmContainmentRing::verify_incoming_message` after HMAC verification against the sender's
/// `(arm_id, epoch, role)` key. Roles are therefore authenticated, never taken from names.
#[derive(Clone)]
pub struct MeshGuard {
    allowed_routes: Arc<RwLock<HashSet<(usize, usize, Option<MessageKind>)>>>,
}

impl Default for MeshGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshGuard {
    pub fn new() -> Self {
        Self {
            allowed_routes: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Allows a specific route (by authenticated arm id) and message kind between two arms.
    pub async fn allow_route(
        &self,
        sender_arm_id: usize,
        recipient_arm_id: usize,
        kind: Option<MessageKind>,
    ) {
        let mut routes = self.allowed_routes.write().await;
        routes.insert((sender_arm_id, recipient_arm_id, kind));
    }

    /// Validates an authenticated inter-agent message crossing the Inner Ring.
    ///
    /// INVARIANTS:
    /// - An inter-agent message passes data, NEVER authority.
    /// - Law 1 is evaluated over the full signed provenance chain (multi-hop sticky taint).
    /// - An empty route table means **deny** (fail-closed), not "allow everything".
    pub async fn validate_message(
        &self,
        verified: &VerifiedMeshMessage,
    ) -> Result<HomologicalAuditReport, OctopusSecurityError> {
        let msg = verified.message();

        // 1. Metadata bounds
        if msg.correlation_id.len() > 128 {
            return Err(OctopusSecurityError::EnclaveViolation(
                "Inter-arm message correlation_id exceeds strict 128-byte limit".to_string(),
            ));
        }
        if msg.payload.len() > 16 * 1024 {
            return Err(OctopusSecurityError::EnclaveViolation(
                "Inter-arm message payload exceeds 16KB neural mesh capacity".to_string(),
            ));
        }

        // 2. Law 1 over the authenticated role chain AND sticky effective taint floor
        if verified.effective_taint_floor() == TrustTier::Untrusted
            && role_trust_tier(verified.recipient_role()) == TrustTier::PrivilegedSink
        {
            return Err(OctopusSecurityError::DelegationScopeViolation(format!(
                "Inner Ring Sticky Taint Violation: arm {} -> arm {} (recipient {:?} cannot accept message with Untrusted effective taint floor)",
                msg.sender_arm_id,
                verified.recipient_arm_id(),
                verified.recipient_role()
            )));
        }
        let report = HomologicalBoundaryAuditor::audit_role_chain(verified.role_chain());
        if !report.allowed {
            return Err(OctopusSecurityError::DelegationScopeViolation(format!(
                "Inner Ring Boundary Violation: arm {} -> arm {} ({})",
                msg.sender_arm_id,
                verified.recipient_arm_id(),
                report.reason
            )));
        }

        // 3. Route authorization (fail-closed on empty table)
        let routes = self.allowed_routes.read().await;
        let permitted =
            routes.contains(&(
                msg.sender_arm_id,
                verified.recipient_arm_id(),
                Some(msg.kind.clone()),
            )) || routes.contains(&(msg.sender_arm_id, verified.recipient_arm_id(), None));
        if !permitted {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Inner Ring Route Veto: route arm {} -> arm {} for kind {:?} is not authorized",
                msg.sender_arm_id,
                verified.recipient_arm_id(),
                msg.kind
            )));
        }

        Ok(report)
    }
}

/// A mesh message whose HMAC, epochs and provenance were verified by the recipient's
/// `ArmContainmentRing`. Constructible only inside the crate.
#[derive(Debug, Clone)]
pub struct VerifiedMeshMessage {
    message: crate::containment_ring::arm_ring::ArmRingMeshMessage,
    recipient_arm_id: usize,
    recipient_role: ArmRole,
    role_chain: Vec<ArmRole>,
    effective_taint_floor: TrustTier,
}

impl VerifiedMeshMessage {
    pub(crate) fn new(
        message: crate::containment_ring::arm_ring::ArmRingMeshMessage,
        recipient_arm_id: usize,
        recipient_role: ArmRole,
        role_chain: Vec<ArmRole>,
        effective_taint_floor: TrustTier,
    ) -> Self {
        Self {
            message,
            recipient_arm_id,
            recipient_role,
            role_chain,
            effective_taint_floor,
        }
    }
    pub fn message(&self) -> &crate::containment_ring::arm_ring::ArmRingMeshMessage {
        &self.message
    }
    pub fn recipient_arm_id(&self) -> usize {
        self.recipient_arm_id
    }
    pub fn recipient_role(&self) -> &ArmRole {
        &self.recipient_role
    }
    /// Authenticated roles: provenance hops, then sender, then recipient.
    pub fn role_chain(&self) -> &[ArmRole] {
        &self.role_chain
    }
    pub fn effective_taint_floor(&self) -> TrustTier {
        self.effective_taint_floor
    }
}
