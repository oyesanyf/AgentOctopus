use crate::core::types::{ArmRole, OctopusSecurityError};
use std::collections::HashSet;

/// Tracks and validates cross-agent delegation chains to prevent "confused deputy" attacks
/// and privilege laundering within the agent swarm.
#[derive(Debug, Clone)]
pub struct DelegationScopeGuard {
    max_delegation_depth: usize,
}

impl Default for DelegationScopeGuard {
    fn default() -> Self {
        Self::new(2)
    }
}

impl DelegationScopeGuard {
    pub fn new(max_delegation_depth: usize) -> Self {
        Self {
            max_delegation_depth,
        }
    }

    /// Computes the static capability set for an arm role.
    pub fn permitted_tools_for_role(role: &ArmRole) -> HashSet<&'static str> {
        let mut tools = HashSet::new();
        match role {
            ArmRole::UntrustedDocIngest => {
                tools.insert("doc_extractor");
            }
            ArmRole::AccountingLedgerWrite => {
                tools.insert("ledger_writer");
            }
            ArmRole::NetworkEgress => {
                tools.insert("http_egress");
            }
            ArmRole::OutboundNotification => {
                tools.insert("notifier");
            }
            ArmRole::TarpitDecoyDefense => {
                tools.insert("quarantine");
            }
            ArmRole::KernelLevelSentinel => {
                tools.insert("kernel_sentinel");
                tools.insert("hardware_clamp");
                tools.insert("autotomy_kill");
            }
            ArmRole::CedarPolicyEvaluation => {
                tools.insert("cedar_evaluator");
                tools.insert("policy_compiler");
            }
            ArmRole::AtlasThreatIntelligence => {
                tools.insert("atlas_sync");
                tools.insert("stix_parser");
            }
            ArmRole::AnomalyDetection => {
                tools.insert("behavioral_sentinel");
                tools.insert("entropy_calc");
            }
            ArmRole::VulnerabilityResearch => {
                tools.insert("vulnerability_scanner");
                tools.insert("attack_chain");
            }
            ArmRole::ContinuousOssFuzz => {
                tools.insert("fuzz_mutator");
                tools.insert("corpus_manager");
            }
            ArmRole::ContinuousOsvScanner => {
                tools.insert("osv_client");
                tools.insert("dep_advisor");
            }
            ArmRole::AutonomousProtocolResearch => {
                // no delegation
            }
            ArmRole::DifferentialProtocolAnalyzer => {
                tools.insert("protocol_analyzer");
                tools.insert("fuzz_divergence");
            }
            ArmRole::PostQuantumAttestation => {
                tools.insert("pqc_kem_encapsulate");
                tools.insert("pqc_kem_decapsulate");
                tools.insert("pqc_dsa_sign");
                tools.insert("pqc_dsa_verify");
                tools.insert("pqc_cbom_scanner");
            }
            ArmRole::EvolutionaryOptimizer => {
                tools.insert("evolution_evaluate");
                tools.insert("evolution_stage");
            }
            ArmRole::DreamRsiOptimizer => {
                tools.insert("dream_rsi_replay");
                tools.insert("dream_rsi_rollout");
                tools.insert("dream_rsi_prioritize");
            }
            ArmRole::RecursiveHarnessOptimizer => {
                tools.insert("harness2_propose_probe_compose");
                tools.insert("harness2_validate_tree");
                tools.insert("harness2_experience_library");
            }
        }
        tools
    }

    /// Evaluates an inter-agent delegation chain:
    /// Invariant: Authority must strictly be the INTERSECTION of all participants in the chain.
    /// A compromised agent cannot acquire permissions by delegating to a more privileged peer.
    pub fn validate_delegation(
        &self,
        originator_role: &ArmRole,
        delegation_chain: &[ArmRole],
        target_role: &ArmRole,
        requested_tool: &str,
    ) -> Result<(), OctopusSecurityError> {
        // 1. Check delegation chain depth
        if delegation_chain.len() > self.max_delegation_depth {
            return Err(OctopusSecurityError::DelegationScopeViolation(format!(
                "Delegation chain length {} exceeds maximum allowable depth {}",
                delegation_chain.len(),
                self.max_delegation_depth
            )));
        }

        // 2. Check Originator Authority
        // Invariant: If the originator doesn't have the permission, it can NEVER delegate it!
        let originator_tools = Self::permitted_tools_for_role(originator_role);
        if !originator_tools.contains(requested_tool) {
            return Err(OctopusSecurityError::DelegationScopeViolation(format!(
                "Privilege laundering attempt detected! Originating agent ({:?}) lacks authority for tool '{}'. \
                 Cannot launder privilege via delegate agent ({:?})!",
                originator_role, requested_tool, target_role
            )));
        }

        // 3. Check every intermediate delegator in the chain
        for (hop, delegator) in delegation_chain.iter().enumerate() {
            let delegator_tools = Self::permitted_tools_for_role(delegator);
            if !delegator_tools.contains(requested_tool) {
                return Err(OctopusSecurityError::DelegationScopeViolation(format!(
                    "Delegation broken at hop {} ({:?}): delegator lacks authority for tool '{}'",
                    hop, delegator, requested_tool
                )));
            }
        }

        // 4. Check Target Agent Authority
        let target_tools = Self::permitted_tools_for_role(target_role);
        if !target_tools.contains(requested_tool) {
            return Err(OctopusSecurityError::DelegationScopeViolation(format!(
                "Target agent ({:?}) cannot execute tool '{}'",
                target_role, requested_tool
            )));
        }

        Ok(())
    }
}
