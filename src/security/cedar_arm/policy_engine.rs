use super::policy_schema::CedarSchema;
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, Policy,
    PolicySet, Request, Response,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CedarEngineError {
    #[error("Failed to parse policy text: {0}")]
    PolicyParseError(String),
    #[error("Failed to construct Cedar context: {0}")]
    ContextError(String),
    #[error("Failed to parse EntityUid: {0}")]
    EntityUidError(String),
    #[error("Cedar evaluation panic caught: {0}")]
    EvaluationPanic(String),
}

/// Baseline policy set for Agent Octopus.
pub const DEFAULT_OCTOPUS_POLICIES: &str = r#"
// 1. Document Extraction Policy
permit (
    principal == Octopus::Agent::"document_arm",
    action == Octopus::Action::"extract",
    resource is Octopus::Document
);

// 2. Ledger Writing Policy with Spending Limit and Supervisor Approval
permit (
    principal == Octopus::Agent::"ledger_arm",
    action == Octopus::Action::"write",
    resource is Octopus::Ledger
) when {
    context.amount_cents <= 10000000 && context.approved == true
};

// 3. Network Egress Policy: Only approved Google domains
permit (
    principal == Octopus::Agent::"network_arm",
    action == Octopus::Action::"egress",
    resource is Octopus::NetworkTarget
) when {
    context.destination_domain == "google.com" || context.destination_domain == "www.google.com"
};

// 4. Global Security Policy Guard: Forbid unauthorized policy mutation unless approved by 2-of-3 Quorum
forbid (
    principal,
    action == Octopus::Action::"change_security_policy",
    resource is Octopus::SystemPolicy
) unless {
    context has quorum_authorized && context.quorum_authorized == true
};

// 5. Tarpit Decoy Defense Policy: Allow tarpit arm to quarantine and exhaust adversaries
permit (
    principal == Octopus::Agent::"tarpit_arm",
    action == Octopus::Action::"quarantine",
    resource is Octopus::DecoyTrap
);

// 6. Kernel Sentinel Protection Policy: Allow kernel sentinel arm to enforce hardware/kernel clamps
permit (
    principal == Octopus::Agent::"kernel_sentinel_arm",
    action == Octopus::Action::"kernel_enforce",
    resource is Octopus::KernelSubstrate
);

// 7. ALL Unified Dynamic Defense Policy: Master policy bounding swarm operations against rogue breakout
@id("ALL")
forbid (
    principal,
    action,
    resource
) when {
    principal == Octopus::Agent::"rogue_adversary"
};

// 8. Protocol Research Isolation Gate
permit (
    principal == Octopus::Agent::"protocol_research_arm",
    action == Octopus::Action::"evaluate",
    resource is Octopus::NetworkTarget
) when {
    context.destination_host == "127.0.0.1" || context.destination_host == "localhost" || context.destination_host == "::1" || context.destination_host == "[::1]"
};
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarEvaluationVerdict {
    pub is_allowed: bool,
    pub determining_policies: Vec<String>,
    pub diagnostic_errors: Vec<String>,
}

/// CedarPolicyEngine: Isolated deterministic policy evaluation service.
/// Evaluates every tool execution and inter-agent action using the AWS Cedar language.
pub struct CedarPolicyEngine {
    authorizer: Authorizer,
    policy_set: Arc<RwLock<PolicySet>>,
    entities: Arc<RwLock<Entities>>,
    schema: CedarSchema,
}

impl Default for CedarPolicyEngine {
    fn default() -> Self {
        Self::new().expect("Failed to initialize default CedarPolicyEngine")
    }
}

impl CedarPolicyEngine {
    pub fn new() -> Result<Self, CedarEngineError> {
        let policy_set = PolicySet::from_str(DEFAULT_OCTOPUS_POLICIES)
            .map_err(|e| CedarEngineError::PolicyParseError(e.to_string()))?;
        let entities = Entities::empty();
        let schema = CedarSchema::default();

        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set: Arc::new(RwLock::new(policy_set)),
            entities: Arc::new(RwLock::new(entities)),
            schema,
        })
    }

    /// Creates an empty `CedarPolicyEngine` (for forbid-only runtime virtual-patch hot-load).
    pub fn from_empty() -> Result<Self, CedarEngineError> {
        let policy_set = PolicySet::new();
        let entities = Entities::empty();
        let schema = CedarSchema::default();
        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set: Arc::new(RwLock::new(policy_set)),
            entities: Arc::new(RwLock::new(entities)),
            schema,
        })
    }

    /// Creates a CedarPolicyEngine configured with custom policy rules (for testing / negative controls).
    pub fn from_custom_policy_set(policies: &str) -> Result<Self, CedarEngineError> {
        let policy_set = PolicySet::from_str(policies)
            .map_err(|e| CedarEngineError::PolicyParseError(e.to_string()))?;
        let entities = Entities::empty();
        let schema = CedarSchema::default();

        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set: Arc::new(RwLock::new(policy_set)),
            entities: Arc::new(RwLock::new(entities)),
            schema,
        })
    }

    /// Creates a CedarPolicyEngine configured with custom policy rules validated in `ValidationMode::Strict`
    /// against the authoritative `OCTOPUS_CEDAR_SCHEMA_JSON`.
    pub fn from_validated_policy_set(policies: &str) -> Result<Self, CedarEngineError> {
        let policies = policies.trim_start_matches('\u{feff}');
        if policies.trim().is_empty() {
            return Err(CedarEngineError::PolicyParseError(
                "Cedar policy text is empty".to_string(),
            ));
        }
        let policy_set = PolicySet::from_str(policies)
            .map_err(|e| CedarEngineError::PolicyParseError(e.to_string()))?;
        if policy_set.is_empty() {
            return Err(CedarEngineError::PolicyParseError(
                "Cedar policy set contains zero policies".to_string(),
            ));
        }
        let report = super::policy_validator::CedarPolicyValidator::default()
            .validate_policy_set(&policy_set);
        if !report.is_valid {
            return Err(CedarEngineError::PolicyParseError(format!(
                "Cedar strict schema validation failed: {}",
                report.validation_errors.join("; ")
            )));
        }
        let entities = Entities::empty();
        let schema = CedarSchema::default();

        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set: Arc::new(RwLock::new(policy_set)),
            entities: Arc::new(RwLock::new(entities)),
            schema,
        })
    }

    /// Evaluates a PARC (Principal, Action, Resource, Context) authorization query.
    pub fn evaluate(
        &self,
        principal_id: &str,
        action_name: &str,
        resource_id: &str,
        resource_type: &str,
        context_json: serde_json::Value,
    ) -> Result<CedarEvaluationVerdict, CedarEngineError> {
        let unwind_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let principal_type = EntityTypeName::from_str("Octopus::Agent")
                .map_err(|e| CedarEngineError::EntityUidError(format!("{:?}", e)))?;
            let principal =
                EntityUid::from_type_name_and_id(principal_type, EntityId::new(principal_id));

            let action_type = EntityTypeName::from_str("Octopus::Action")
                .map_err(|e| CedarEngineError::EntityUidError(format!("{:?}", e)))?;
            let action = EntityUid::from_type_name_and_id(action_type, EntityId::new(action_name));

            let resource_type_name =
                EntityTypeName::from_str(&format!("Octopus::{}", resource_type))
                    .map_err(|e| CedarEngineError::EntityUidError(format!("{:?}", e)))?;
            let resource =
                EntityUid::from_type_name_and_id(resource_type_name, EntityId::new(resource_id));

            let context =
                Context::from_json_value(context_json, Some((self.schema.inner(), &action)))
                    .map_err(|e| CedarEngineError::ContextError(e.to_string()))?;

            let request = Request::new(
                principal,
                action,
                resource,
                context,
                Some(self.schema.inner()),
            )
            .map_err(|e| CedarEngineError::ContextError(e.to_string()))?;

            let policies = self
                .policy_set
                .read()
                .map_err(|e| CedarEngineError::ContextError(format!("Lock poisoned: {}", e)))?;
            let entities = self
                .entities
                .read()
                .map_err(|e| CedarEngineError::ContextError(format!("Lock poisoned: {}", e)))?;

            let response: Response = self
                .authorizer
                .is_authorized(&request, &policies, &entities);

            let is_allowed = matches!(response.decision(), Decision::Allow);
            let determining_policies = response
                .diagnostics()
                .reason()
                .map(|p| p.to_string())
                .collect();
            let diagnostic_errors = response
                .diagnostics()
                .errors()
                .map(|e| e.to_string())
                .collect();

            Ok(CedarEvaluationVerdict {
                is_allowed,
                determining_policies,
                diagnostic_errors,
            })
        }));

        match unwind_res {
            Ok(inner_res) => inner_res,
            Err(panic_payload) => {
                let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown Cedar evaluation panic".to_string()
                };
                Err(CedarEngineError::EvaluationPanic(panic_msg))
            }
        }
    }

    /// Adds a policy to the active policy set (e.g. after quorum approval).
    pub fn add_policy(
        &self,
        policy_id: Option<&str>,
        policy_text: &str,
    ) -> Result<String, CedarEngineError> {
        let mut policies = self.policy_set.write().map_err(|_| {
            CedarEngineError::EvaluationPanic("Cedar policy_set write lock poisoned".to_string())
        })?;
        let id_str = match policy_id {
            Some(id) => id.to_string(),
            None => format!("dynamic_policy_{}", policies.policies().count() + 1),
        };
        let pid = cedar_policy::PolicyId::new(&id_str);
        let policy = Policy::parse(Some(pid), policy_text)
            .map_err(|e| CedarEngineError::PolicyParseError(e.to_string()))?;
        policies
            .add(policy)
            .map_err(|e| CedarEngineError::PolicyParseError(e.to_string()))?;
        Ok(id_str)
    }

    /// Monotonic tighten-only policy insertion: accepts ONLY `forbid` policies and validates
    /// them in `ValidationMode::Strict` against `OCTOPUS_CEDAR_SCHEMA_JSON` before activating.
    /// Rejects any `permit` policy or schema violation (Foolproof Invariant #4).
    pub fn add_tighten_only_forbid_policy(
        &self,
        policy_id: Option<&str>,
        policy_text: &str,
    ) -> Result<String, CedarEngineError> {
        let mut policies = self.policy_set.write().map_err(|_| {
            CedarEngineError::EvaluationPanic("Cedar policy_set write lock poisoned".to_string())
        })?;
        let id_str = match policy_id {
            Some(id) => id.to_string(),
            None => {
                let mut seq = policies.policies().count() + 1;
                loop {
                    let cand = format!("virtual_patch_forbid_{seq}");
                    if !policies.policies().any(|p| p.id().to_string() == cand) {
                        break cand;
                    }
                    seq += 1;
                }
            }
        };
        let pid = cedar_policy::PolicyId::new(&id_str);
        let policy = Policy::parse(Some(pid), policy_text)
            .map_err(|e| CedarEngineError::PolicyParseError(e.to_string()))?;

        if !matches!(policy.effect(), cedar_policy::Effect::Forbid) {
            return Err(CedarEngineError::PolicyParseError(
                "Monotonic tighten-only violation: only Effect::Forbid policies are allowed"
                    .to_string(),
            ));
        }

        let mut validation_set = PolicySet::new();
        validation_set
            .add(policy.clone())
            .map_err(|e| CedarEngineError::PolicyParseError(e.to_string()))?;
        let report = super::policy_validator::CedarPolicyValidator::default()
            .validate_policy_set(&validation_set);
        if !report.is_valid {
            return Err(CedarEngineError::PolicyParseError(format!(
                "Cedar strict schema validation failed for virtual-patch forbid policy: {}",
                report.validation_errors.join("; ")
            )));
        }

        if let Some(existing) = policies.policies().find(|p| p.id().to_string() == id_str) {
            if matches!(existing.effect(), cedar_policy::Effect::Forbid)
                && existing.to_string() == policy.to_string()
            {
                return Ok(id_str);
            }
            return Err(CedarEngineError::PolicyParseError(format!(
                "Policy ID collision: '{}' already exists as a non-identical or permit policy",
                id_str
            )));
        }

        policies
            .add(policy)
            .map_err(|e| CedarEngineError::PolicyParseError(e.to_string()))?;
        Ok(id_str)
    }

    /// Returns the count of active policies in the engine.
    pub fn policy_count(&self) -> usize {
        self.policy_set
            .read()
            .map(|g| g.policies().count())
            .unwrap_or(0)
    }

    /// Returns `true` if any policy in the compiled PolicySet targets `action_name`
    /// (including `ActionConstraint::Any` when compatible with the action's resource types).
    pub fn has_action_policy(&self, action_name: &str) -> bool {
        let Ok(guard) = self.policy_set.read() else {
            return false;
        };
        let matched = guard
            .policies()
            .any(|policy| policy_matches_action(policy, action_name));
        matched
    }

    /// Returns `true` if any `permit` policy in the compiled PolicySet targets `action_name`
    /// (including `ActionConstraint::Any` when compatible with the action's resource types).
    pub fn has_permit_action_policy(&self, action_name: &str) -> bool {
        let Ok(guard) = self.policy_set.read() else {
            return false;
        };
        let matched = guard.policies().any(|policy| {
            matches!(policy.effect(), cedar_policy::Effect::Permit)
                && policy_matches_action(policy, action_name)
        });
        matched
    }

    /// Returns `true` if any `forbid` policy in the compiled PolicySet targets `action_name`
    /// (including `ActionConstraint::Any` when compatible with the action's resource types).
    pub fn has_forbid_action_policy(&self, action_name: &str) -> bool {
        let Ok(guard) = self.policy_set.read() else {
            return false;
        };
        let matched = guard.policies().any(|policy| {
            matches!(policy.effect(), cedar_policy::Effect::Forbid)
                && policy_matches_action(policy, action_name)
        });
        matched
    }

    /// Dynamically updates the authorized network egress domains in Cedar Policy #3.
    /// Recompiles the authoritative Cedar policy set and atomically swaps it in memory.
    pub fn update_egress_domains(&self, domains: &[String]) -> Result<(), CedarEngineError> {
        let domain_expr = if domains.is_empty() {
            "false".to_string()
        } else {
            domains
                .iter()
                .map(|d| format!("context.destination_domain == \"{}\"", d))
                .collect::<Vec<_>>()
                .join(" || ")
        };

        let policies_text = format!(
            r#"
// 1. Document Extraction Policy
permit (
    principal == Octopus::Agent::"document_arm",
    action == Octopus::Action::"extract",
    resource is Octopus::Document
);

// 2. Ledger Writing Policy with Spending Limit and Supervisor Approval
permit (
    principal == Octopus::Agent::"ledger_arm",
    action == Octopus::Action::"write",
    resource is Octopus::Ledger
) when {{
    context.amount_cents <= 10000000 && context.approved == true
}};

// 3. Network Egress Policy: Configurable approved domains
permit (
    principal == Octopus::Agent::"network_arm",
    action == Octopus::Action::"egress",
    resource is Octopus::NetworkTarget
) when {{
    {}
}};

// 4. Global Security Policy Guard: Forbid unauthorized policy mutation unless approved by 2-of-3 Quorum
forbid (
    principal,
    action == Octopus::Action::"change_security_policy",
    resource is Octopus::SystemPolicy
) unless {{
    context has quorum_authorized && context.quorum_authorized == true
}};

// 5. Tarpit Decoy Defense Policy: Allow tarpit arm to quarantine and exhaust adversaries
permit (
    principal == Octopus::Agent::"tarpit_arm",
    action == Octopus::Action::"quarantine",
    resource is Octopus::DecoyTrap
);

// 6. Kernel Sentinel Protection Policy: Allow kernel sentinel arm to enforce hardware/kernel clamps
permit (
    principal == Octopus::Agent::"kernel_sentinel_arm",
    action == Octopus::Action::"kernel_enforce",
    resource is Octopus::KernelSubstrate
);

// 8. Protocol Research Isolation Gate
permit (
    principal == Octopus::Agent::"protocol_research_arm",
    action == Octopus::Action::"evaluate",
    resource is Octopus::NetworkTarget
) when {{
    context.destination_host == "127.0.0.1" || context.destination_host == "localhost" || context.destination_host == "::1" || context.destination_host == "[::1]"
}};
"#,
            domain_expr
        );

        let new_set = PolicySet::from_str(&policies_text)
            .map_err(|e| CedarEngineError::PolicyParseError(e.to_string()))?;
        let mut guard = self.policy_set.write().map_err(|_| {
            CedarEngineError::EvaluationPanic("Cedar policy_set write lock poisoned".to_string())
        })?;
        *guard = new_set;
        Ok(())
    }
}

fn action_compatible_resource_types(action_name: &str) -> &'static [&'static str] {
    match action_name {
        "exec" => &["Octopus::Command"],
        "fs_read" => &["Octopus::FilePath", "Octopus::Document"],
        "fs_write" => &["Octopus::FilePath", "Octopus::Ledger"],
        "egress" => &["Octopus::NetworkTarget", "Octopus::Host"],
        "tool_call" => &["Octopus::Tool"],
        _ => &[],
    }
}

fn resource_constraint_compatible(policy: &Policy, action_name: &str) -> bool {
    let allowed_types = action_compatible_resource_types(action_name);
    if allowed_types.is_empty() {
        return true;
    }
    match policy.resource_constraint() {
        cedar_policy::ResourceConstraint::Any => true,
        cedar_policy::ResourceConstraint::Eq(uid) | cedar_policy::ResourceConstraint::In(uid) => {
            allowed_types.contains(&uid.type_name().to_string().as_str())
        }
        cedar_policy::ResourceConstraint::Is(et)
        | cedar_policy::ResourceConstraint::IsIn(et, _) => {
            allowed_types.contains(&et.to_string().as_str())
        }
    }
}

fn policy_matches_action(policy: &Policy, action_name: &str) -> bool {
    let target = format!("Octopus::Action::\"{}\"", action_name);
    match policy.action_constraint() {
        cedar_policy::ActionConstraint::Eq(uid) => uid.to_string() == target,
        cedar_policy::ActionConstraint::In(uids) => {
            uids.iter().any(|uid| uid.to_string() == target)
        }
        cedar_policy::ActionConstraint::Any => resource_constraint_compatible(policy, action_name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_action_and_permit_action_policy_semantics() {
        let forbid_only = CedarPolicyEngine::from_validated_policy_set(
            r#"
            forbid (principal, action == Octopus::Action::"fs_write", resource is Octopus::FilePath)
              when { context has path && context.path like "*secret*" };
            "#,
        )
        .expect("valid forbid-only policy");
        assert!(forbid_only.has_action_policy("fs_write"));
        assert!(forbid_only.has_forbid_action_policy("fs_write"));
        assert!(!forbid_only.has_permit_action_policy("fs_write"));
        assert!(!forbid_only.has_action_policy("fs_read"));
        assert!(!forbid_only.has_forbid_action_policy("fs_read"));

        let any_action_cmd = CedarPolicyEngine::from_validated_policy_set(
            r#"
            permit (principal, action, resource is Octopus::Command);
            "#,
        )
        .expect("valid any-action command policy");
        assert!(any_action_cmd.has_action_policy("exec"));
        assert!(any_action_cmd.has_permit_action_policy("exec"));
        assert!(!any_action_cmd.has_forbid_action_policy("exec"));
        assert!(!any_action_cmd.has_action_policy("fs_write"));
        assert!(!any_action_cmd.has_permit_action_policy("fs_write"));
        assert!(!any_action_cmd.has_forbid_action_policy("fs_write"));
    }
}
