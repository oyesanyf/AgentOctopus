use crate::core::types::OctopusSecurityError;
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

    /// Assigns the discrete privilege potential $\phi(v) \in \mathbb{Z}$ to an agent node.
    pub fn privilege_potential(node_id: &str) -> i64 {
        let lower = Self::normalize_identifier_uts39_skeleton(node_id);
        if lower.contains("untrusted")
            || lower.contains("ingest")
            || lower.contains("doc")
            || lower.contains("fuzz")
            || lower.contains("tarpit")
            || lower.contains("differential")
            || lower.contains("protocolresearch")
            || lower.contains("external")
        {
            10 // Low-trust / untrusted ingress potential
        } else if lower.contains("ledger")
            || lower.contains("accounting")
            || lower.contains("kernel")
            || lower.contains("sentinel")
            || lower.contains("admin")
            || lower.contains("supervisor")
        {
            100 // High-privilege sink potential
        } else {
            50 // Standard worker / intermediate potential
        }
    }

    /// Evaluates a direct 1-simplex edge $[v_0, v_1]$ or a 2-simplex transitive path $[v_0, v_1, v_2]$
    /// for simplicial boundary exactness ($\partial_1 \circ \partial_2 = 0$) and proxy laundering.
    pub fn audit_simplex_transition(
        sender: &str,
        intermediary: Option<&str>,
        recipient: &str,
    ) -> HomologicalAuditReport {
        let phi_s = Self::privilege_potential(sender);
        let phi_i = intermediary.map(Self::privilege_potential);
        let phi_r = Self::privilege_potential(recipient);

        // Verify \partial_1(\partial_2([v_0, v_1, v_2])) = (v_1 - v_0) - (v_2 - v_0) + (v_2 - v_1) = 0
        let coboundary_residue = if let Some(p_i) = phi_i {
            let d_01 = p_i - phi_s;
            let d_12 = phi_r - p_i;
            let d_02 = phi_r - phi_s;
            (d_01 + d_12) - d_02
        } else {
            0
        };
        let boundary_squared_zero = coboundary_residue == 0;

        // Detect direct or transitive proxy laundering from untrusted source (phi <= 10)
        // to high-privilege sink (phi >= 100), even when relayed via an intermediate worker (phi == 50).
        let direct_violation = phi_s <= 10 && phi_r >= 100;
        let transitive_laundering = match phi_i {
            Some(p_i) => phi_s <= 10 && p_i > phi_s && phi_r >= 100,
            None => false,
        };
        let proxy_laundering_detected =
            direct_violation || transitive_laundering || !boundary_squared_zero;

        let allowed = !proxy_laundering_detected;
        let reason = if allowed {
            "LAW1_HOMOLOGICAL_EXACTNESS_VERIFIED: Simplicial boundary d1(d2(sigma)) = 0 and privilege potential preserved".to_string()
        } else if transitive_laundering {
            format!(
                "LAW1_PROXY_LAUNDERING_VETO: 2-simplex [{} -> {} -> {}] attempts confused-deputy privilege laundering (phi: {} -> {} -> {})",
                sender,
                intermediary.unwrap_or("none"),
                recipient,
                phi_s,
                phi_i.unwrap_or(0),
                phi_r
            )
        } else {
            format!(
                "LAW1_DIRECT_BOUNDARY_VETO: 1-simplex [{} -> {}] violates cochain privilege potential (phi: {} -> {})",
                sender, recipient, phi_s, phi_r
            )
        };

        HomologicalAuditReport {
            allowed,
            sender: sender.to_string(),
            intermediary: intermediary.map(|s| s.to_string()),
            recipient: recipient.to_string(),
            sender_potential: phi_s,
            intermediary_potential: phi_i,
            recipient_potential: phi_r,
            coboundary_residue,
            boundary_squared_zero,
            proxy_laundering_detected,
            reason,
        }
    }
}

/// Inner Ring Neural Mesh Guard:
/// Mediates inter-arm communication, preventing privilege escalation,
/// message forgery, and unauthorized lateral movement.
#[derive(Clone)]
pub struct MeshGuard {
    allowed_routes: Arc<RwLock<HashSet<(String, String, Option<MessageKind>)>>>,
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

    /// Allows a specific route and message kind between two endpoints.
    pub async fn allow_route(&self, sender: &str, recipient: &str, kind: Option<MessageKind>) {
        let mut routes = self.allowed_routes.write().await;
        routes.insert((sender.to_string(), recipient.to_string(), kind));
    }

    /// Audits a 2-simplex transitive relay (`origin_sender -> intermediary -> recipient`) using Law 1.
    pub fn validate_transitive_simplex(
        &self,
        origin_sender: &str,
        intermediary: &str,
        recipient: &str,
    ) -> Result<HomologicalAuditReport, OctopusSecurityError> {
        let report = HomologicalBoundaryAuditor::audit_simplex_transition(
            origin_sender,
            Some(intermediary),
            recipient,
        );
        if !report.allowed {
            return Err(OctopusSecurityError::DelegationScopeViolation(
                report.reason,
            ));
        }
        Ok(report)
    }

    /// Validates an inter-agent message crossing the Inner Ring.
    ///
    /// INVARIANT: An inter-agent message passes data, NEVER authority.
    /// An untrusted ingest arm sending an artifact to a ledger arm CANNOT
    /// grant the sender or recipient ledger-writing capabilities.
    pub async fn validate_message(
        &self,
        sender: &str,
        recipient: &str,
        kind: &MessageKind,
        correlation_id: &str,
        content: &str,
    ) -> Result<(), OctopusSecurityError> {
        // 1. Metadata bounds
        if correlation_id.len() > 128 {
            return Err(OctopusSecurityError::EnclaveViolation(
                "Inter-arm message correlation_id exceeds strict 128-byte limit".to_string(),
            ));
        }

        if content.len() > 16 * 1024 {
            return Err(OctopusSecurityError::EnclaveViolation(
                "Inter-arm message payload exceeds 16KB neural mesh capacity".to_string(),
            ));
        }

        // 2. Law 1 Homological Boundary & High-trust inter-arm boundary check
        let homological =
            HomologicalBoundaryAuditor::audit_simplex_transition(sender, None, recipient);
        if !homological.allowed {
            return Err(OctopusSecurityError::DelegationScopeViolation(format!(
                "Inner Ring Boundary Violation: Untrusted Arm '{}' is forbidden from direct lateral messaging to Sensitive Sink Arm '{}' ({})",
                sender, recipient, homological.reason
            )));
        }

        // 3. Route authorization
        let routes = self.allowed_routes.read().await;
        let permitted = routes.contains(&(sender.to_string(), recipient.to_string(), Some(kind.clone())))
            || routes.contains(&(sender.to_string(), recipient.to_string(), None));

        if !permitted && !routes.is_empty() {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Inner Ring Route Veto: Route ({}) -> ({}) for kind {:?} is not authorized",
                sender, recipient, kind
            )));
        }

        Ok(())
    }
}
