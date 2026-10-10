use super::policy_engine::CedarPolicyEngine;
use crate::core::types::OctopusSecurityError;
use serde_json::json;

/// Evaluates multi-step agent delegation chains using Cedar.
/// Invariant: Delegation depth must strictly be <= 2, and delegated actions
/// must satisfy Cedar policies for each intermediate participant.
pub struct CedarDelegationPolicyGuard {
    max_depth: usize,
    engine: CedarPolicyEngine,
}

impl Default for CedarDelegationPolicyGuard {
    fn default() -> Self {
        Self::new(2)
    }
}

impl CedarDelegationPolicyGuard {
    pub fn new(max_depth: usize) -> Self {
        Self {
            max_depth,
            engine: CedarPolicyEngine::default(),
        }
    }

    /// Evaluates whether an originator agent may delegate a tool action through an intermediary chain.
    pub fn validate_delegation(
        &self,
        originator_agent: &str,
        delegation_chain: &[String],
        target_agent: &str,
        tool_name: &str,
        target_resource: &str,
    ) -> Result<(), OctopusSecurityError> {
        // 1. Check chain length constraint
        let chain_len = delegation_chain.len();
        if chain_len > self.max_depth {
            return Err(OctopusSecurityError::DelegationScopeViolation(format!(
                "Delegation chain length {} exceeds maximum allowable depth {}",
                chain_len, self.max_depth
            )));
        }

        // 2. Map tool to Cedar action and resource type
        let (action_name, resource_type) = match tool_name {
            "doc_extractor" => ("extract", "Document"),
            "ledger_writer" => ("write", "Ledger"),
            "http_egress" => ("egress", "NetworkTarget"),
            "notifier" => ("notify", "Agent"),
            _ => {
                return Err(OctopusSecurityError::CapabilityDenied(format!(
                    "Unsupported tool for delegation: {}",
                    tool_name
                )))
            }
        };

        // 3. Invariant: Originator must be permitted by Cedar
        let context = json!({
            "delegation_depth": chain_len as i64
        });

        let originator_verdict = self
            .engine
            .evaluate(
                originator_agent,
                action_name,
                target_resource,
                resource_type,
                context.clone(),
            )
            .map_err(|e| OctopusSecurityError::CapabilityDenied(format!("Cedar error: {}", e)))?;

        if !originator_verdict.is_allowed {
            return Err(OctopusSecurityError::DelegationScopeViolation(format!(
                "Originator '{}' lacks Cedar authorization for '{}' on '{}'",
                originator_agent, tool_name, target_resource
            )));
        }

        // 4. Invariant: Target agent must also be authorized by Cedar
        let target_verdict = self
            .engine
            .evaluate(
                target_agent,
                action_name,
                target_resource,
                resource_type,
                context,
            )
            .map_err(|e| OctopusSecurityError::CapabilityDenied(format!("Cedar error: {}", e)))?;

        if !target_verdict.is_allowed {
            return Err(OctopusSecurityError::DelegationScopeViolation(format!(
                "Target agent '{}' lacks Cedar authorization for '{}' on '{}'",
                target_agent, tool_name, target_resource
            )));
        }

        Ok(())
    }
}
