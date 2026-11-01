//! # Oso AI Agent Authorization & AWS Agent Containment-Response Engine
//!
//! Combines two complementary agent security architectures into Agent Octopus:
//! 1. **Oso (`osohq`) Context-Aware AI Agent Authorization**:
//!    - 3-Way Delegated Identity Intersection (`Perm(User) ∩ Cap(AgentRole) ∩ Scope(Task)`)
//!    - Pre-Retrieval RAG Document Authorization Filter (ReBAC Owner/Shared ACL + Classification Clearance)
//!    - MCP Tool-Call Parameter & Row-Ownership Policy Gate (`Valid JSON Syntax != Valid Authority`)
//!    - Out-of-Band Cryptographic HMAC-SHA256 HITL Step-Up Ticket Verification (constant-time comparison)
//! 2. **AWS (`aws-samples/sample-agent-containment-response`) 5-Layer Detect & Respond (R1-R5)**:
//!    - R1: Trust Separation & DNS Firewall (`*.amazonaws.com` / `localhost` allowlist, `NXDOMAIN` block)
//!    - R3: 4-Invariant Independent Containment Watchdog (`check_security_group`, `check_route_tables`,
//!      `check_iam_policies` with Policy Swap Attack set verification, `check_dns_firewall`)
//!    - R4: Adversarial Audit Isolation (Explicit Deny on `iam:*`, `cloudtrail:*`, `cloudwatch:*`, `guardduty:*`, `osoosi:watchdog:*`)
//!    - R5: Capability Envelope `AccessDenied` Velocity Alarm (`>= 3` denied calls in `60s` -> KillSwitch)
//!    - KillSwitch Service Scale-Down (`desired_count = 0`, `auto_respawn_disabled = true`) + Task Termination + Epoch Bump

use crate::containment_ring::mesh_guard::{role_trust_tier, TrustTier};
use crate::core::types::ArmRole;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default R5 capability envelope threshold: 3 denied calls within 60 seconds triggers KillSwitch.
pub const AWS_R5_DEFAULT_DENIED_THRESHOLD: usize = 3;
/// Default R5 sliding window in seconds (60s).
pub const AWS_R5_DEFAULT_WINDOW_SECS: i64 = 60;

pub fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Pure RFC 2104 HMAC-SHA256 computation.
pub fn compute_hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hash = Sha256::digest(key);
        k[..32].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    hex::encode(outer.finalize())
}

/// Constant-time byte comparison to prevent timing side-channels.
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatingUserContext {
    pub user_id: String,
    pub permissions: BTreeSet<String>,
    pub allowed_resources: BTreeSet<String>,
    pub max_clearance_tier: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskScopeEnvelope {
    pub task_id: String,
    pub workspace_id: String,
    pub allowed_actions: BTreeSet<String>,
    pub allowed_resource_prefixes: Vec<String>,
    pub max_query_limit: u64,
    pub allow_production_mutation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RagDocumentChunk {
    pub doc_id: String,
    pub workspace_id: String,
    pub owner_id: String,
    pub shared_with_users: BTreeSet<String>,
    pub classification_tier: u8,
    pub content_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RagFilterResult {
    pub total_candidates: usize,
    pub authorized_doc_ids: Vec<String>,
    pub filtered_out_doc_ids: Vec<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitlStepUpTicket {
    pub approver_id: String,
    pub user_id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub canonical_args_sha256: String,
    pub expires_at_unix: i64,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsoAuthzDecision {
    Allow {
        effective_intersection_action: String,
        rationale: String,
    },
    Deny {
        code: String,
        reason: String,
        kill_switch_triggered: bool,
    },
}

pub fn role_capability_actions(role: &ArmRole) -> BTreeSet<String> {
    let mut caps = BTreeSet::new();
    match role {
        ArmRole::UntrustedDocIngest => {
            caps.insert("read:docs".to_string());
            caps.insert("extract:text".to_string());
        }
        ArmRole::AccountingLedgerWrite => {
            caps.insert("read:ledger".to_string());
            caps.insert("write:ledger".to_string());
            caps.insert("transfer:funds".to_string());
        }
        ArmRole::NetworkEgress => {
            caps.insert("net:egress".to_string());
            caps.insert("http:get".to_string());
            caps.insert("http:post".to_string());
        }
        ArmRole::CedarPolicyEvaluation => {
            caps.insert("policy:evaluate".to_string());
            caps.insert("read:docs".to_string());
        }
        ArmRole::AtlasThreatIntelligence | ArmRole::AnomalyDetection => {
            caps.insert("read:telemetry".to_string());
            caps.insert("query:siquery".to_string());
            caps.insert("read:docs".to_string());
        }
        ArmRole::KernelLevelSentinel => {
            caps.insert("read:telemetry".to_string());
            caps.insert("sentinel:verify".to_string());
            caps.insert("containment:isolate".to_string());
        }
        _ => {
            caps.insert("read:docs".to_string());
            caps.insert("read:telemetry".to_string());
        }
    }
    caps
}

pub fn role_max_clearance_tier(role: &ArmRole) -> u8 {
    match role_trust_tier(role) {
        TrustTier::Untrusted => 1,
        TrustTier::Worker => 2,
        TrustTier::PrivilegedSink => 3,
    }
}

pub fn canonical_json_sha256(val: &Value) -> String {
    let canonical = serde_json::to_string(val).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn issue_hitl_step_up_ticket(
    secret_key: &[u8],
    approver_id: &str,
    user_id: &str,
    agent_id: &str,
    tool_name: &str,
    arguments: &Value,
    expires_at_unix: i64,
) -> HitlStepUpTicket {
    let canonical_args_sha256 = canonical_json_sha256(arguments);
    let payload = format!(
        "{}:{}:{}:{}:{}:{}",
        approver_id, user_id, agent_id, tool_name, canonical_args_sha256, expires_at_unix
    );
    let signature_hex = compute_hmac_sha256_hex(secret_key, payload.as_bytes());

    HitlStepUpTicket {
        approver_id: approver_id.to_string(),
        user_id: user_id.to_string(),
        agent_id: agent_id.to_string(),
        tool_name: tool_name.to_string(),
        canonical_args_sha256,
        expires_at_unix,
        signature_hex,
    }
}

pub fn verify_hitl_step_up_ticket(
    secret_key: &[u8],
    ticket: &HitlStepUpTicket,
    expected_user_id: &str,
    expected_agent_id: &str,
    expected_tool_name: &str,
    arguments: &Value,
    now_unix: i64,
) -> Result<(), String> {
    if ticket.approver_id.trim().is_empty() {
        return Err("HITL_APPROVER_EMPTY".to_string());
    }
    if ticket.user_id != expected_user_id {
        return Err(format!(
            "HITL_USER_MISMATCH: ticket user '{}' != '{}'",
            ticket.user_id, expected_user_id
        ));
    }
    if ticket.agent_id != expected_agent_id {
        return Err(format!(
            "HITL_AGENT_MISMATCH: ticket agent '{}' != '{}'",
            ticket.agent_id, expected_agent_id
        ));
    }
    if ticket.tool_name != expected_tool_name {
        return Err(format!(
            "HITL_TOOL_MISMATCH: ticket tool '{}' != '{}'",
            ticket.tool_name, expected_tool_name
        ));
    }
    if now_unix > ticket.expires_at_unix {
        return Err(format!(
            "HITL_TICKET_EXPIRED: now {} > expires_at {}",
            now_unix, ticket.expires_at_unix
        ));
    }
    let actual_args_sha256 = canonical_json_sha256(arguments);
    if ticket.canonical_args_sha256 != actual_args_sha256 {
        return Err("HITL_ARGS_TAMPERED: tool arguments do not match approved digest".to_string());
    }

    let payload = format!(
        "{}:{}:{}:{}:{}:{}",
        ticket.approver_id,
        ticket.user_id,
        ticket.agent_id,
        ticket.tool_name,
        ticket.canonical_args_sha256,
        ticket.expires_at_unix
    );
    let expected_sig = compute_hmac_sha256_hex(secret_key, payload.as_bytes());
    if !constant_time_eq_str(&expected_sig, &ticket.signature_hex) {
        return Err("HITL_SIGNATURE_INVALID: HMAC-SHA256 verification failed".to_string());
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxEgressRule {
    pub rule_id: String,
    pub protocol: String,
    pub cidr_ipv4: Option<String>,
    pub cidr_ipv6: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRouteEntry {
    pub route_table_id: String,
    pub destination_cidr: String,
    pub gateway_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFirewallAssociation {
    pub association_id: String,
    pub vpc_id: String,
    pub status: String,
    pub allowed_domain_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentEnvironmentSnapshot {
    pub security_group_id: String,
    pub vpc_id: String,
    pub task_role_name: String,
    pub egress_rules: Vec<SandboxEgressRule>,
    pub route_entries: Vec<SandboxRouteEntry>,
    pub expected_attached_policy_arns: BTreeSet<String>,
    pub actual_attached_policy_arns: BTreeSet<String>,
    pub expected_inline_policy_names: BTreeSet<String>,
    pub actual_inline_policy_names: BTreeSet<String>,
    pub dns_firewall_associations: Vec<DnsFirewallAssociation>,
}

impl Default for ContainmentEnvironmentSnapshot {
    fn default() -> Self {
        let mut attached = BTreeSet::new();
        attached.insert("arn:osoosi:iam::policy/AgentScopedBedrockAndS3Policy".to_string());
        let mut inline = BTreeSet::new();
        inline.insert("AdversarialAuditIsolationExplicitDeny".to_string());

        Self {
            security_group_id: "sg-osoosi-agent-sandbox".to_string(),
            vpc_id: "vpc-osoosi-isolated".to_string(),
            task_role_name: "OsoosiAgentTaskRole".to_string(),
            egress_rules: vec![SandboxEgressRule {
                rule_id: "sgr-vpce-only".to_string(),
                protocol: "tcp".to_string(),
                cidr_ipv4: Some("10.254.0.0/16".to_string()),
                cidr_ipv6: None,
                description: "Scoped VPC Endpoint egress only".to_string(),
            }],
            route_entries: vec![SandboxRouteEntry {
                route_table_id: "rtb-osoosi-isolated".to_string(),
                destination_cidr: "10.254.0.0/16".to_string(),
                gateway_id: "local".to_string(),
            }],
            expected_attached_policy_arns: attached.clone(),
            actual_attached_policy_arns: attached,
            expected_inline_policy_names: inline.clone(),
            actual_inline_policy_names: inline,
            dns_firewall_associations: vec![DnsFirewallAssociation {
                association_id: "rslvr-frgassoc-osoosi01".to_string(),
                vpc_id: "vpc-osoosi-isolated".to_string(),
                status: "COMPLETE".to_string(),
                allowed_domain_patterns: vec![
                    "*.amazonaws.com".to_string(),
                    "localhost".to_string(),
                    "127.0.0.1".to_string(),
                ],
            }],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchdogAssessmentReport {
    pub status: String,
    pub checked_at_unix: i64,
    pub security_group_violations: Vec<String>,
    pub route_table_violations: Vec<String>,
    pub iam_policy_violations: Vec<String>,
    pub dns_firewall_violations: Vec<String>,
    pub all_violations: Vec<String>,
    pub kill_switch_report: Option<KillSwitchTerminationReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchTerminationReport {
    pub triggered_at_unix: i64,
    pub cluster_id: String,
    pub services_scaled_down_to_zero: Vec<String>,
    pub auto_respawn_disabled: bool,
    pub tasks_terminated_count: usize,
    pub terminated_task_ids: Vec<String>,
    pub new_generation_epoch: u64,
    pub violation_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentClusterServiceState {
    pub cluster_id: String,
    pub service_name: String,
    pub desired_count: usize,
    pub auto_respawn_disabled: bool,
    pub running_task_ids: Vec<String>,
    pub generation_epoch: u64,
}

pub struct OsoAwsContainmentEngine {
    hitl_secret_key: Vec<u8>,
    denied_call_windows: Mutex<HashMap<String, VecDeque<i64>>>,
    cluster_services: Mutex<HashMap<String, AgentClusterServiceState>>,
    kill_switch_history: Mutex<HashMap<String, Vec<KillSwitchTerminationReport>>>,
    pub r5_denied_threshold: usize,
    pub r5_window_secs: i64,
}

impl Default for OsoAwsContainmentEngine {
    fn default() -> Self {
        Self::new(b"osoosi-oso-aws-containment-hitl-default-key-2026")
    }
}

impl OsoAwsContainmentEngine {
    pub fn new(hitl_secret_key: &[u8]) -> Self {
        let engine = Self {
            hitl_secret_key: hitl_secret_key.to_vec(),
            denied_call_windows: Mutex::new(HashMap::new()),
            cluster_services: Mutex::new(HashMap::new()),
            kill_switch_history: Mutex::new(HashMap::new()),
            r5_denied_threshold: AWS_R5_DEFAULT_DENIED_THRESHOLD,
            r5_window_secs: AWS_R5_DEFAULT_WINDOW_SECS,
        };
        engine.register_agent_service(
            "octopus-agent-cluster",
            "octopus-worker-service",
            2,
            vec![
                "task-arm-01-doc-ingest".to_string(),
                "task-arm-02-network-egress".to_string(),
            ],
        );
        engine
    }

    pub fn register_agent_service(
        &self,
        cluster_id: &str,
        service_name: &str,
        desired_count: usize,
        running_task_ids: Vec<String>,
    ) {
        if let Ok(mut map) = self.cluster_services.lock() {
            map.insert(
                cluster_id.to_string(),
                AgentClusterServiceState {
                    cluster_id: cluster_id.to_string(),
                    service_name: service_name.to_string(),
                    desired_count,
                    auto_respawn_disabled: false,
                    running_task_ids,
                    generation_epoch: 1,
                },
            );
        }
    }

    pub fn get_cluster_state(&self, cluster_id: &str) -> Option<AgentClusterServiceState> {
        self.cluster_services
            .lock()
            .ok()
            .and_then(|m| m.get(cluster_id).cloned())
    }

    pub fn is_adversarial_audit_or_control_plane_probe(action: &str, resource: &str) -> bool {
        let lower_act = action.to_ascii_lowercase();
        let lower_res = resource.to_ascii_lowercase();

        const FORBIDDEN_ACTION_PREFIXES: &[&str] = &[
            "iam:",
            "cloudtrail:",
            "cloudwatch:",
            "guardduty:",
            "ec2:describe",
            "ec2:authorizesecuritygroup",
            "ec2:createroute",
            "route53resolver:",
            "s3:bypassgovernanceretention",
            "osoosi:watchdog:",
            "osoosi:audit:",
            "osoosi:killswitch:",
            "sentinel:disable",
            "watchdog:tamper",
        ];

        const FORBIDDEN_RESOURCE_PATTERNS: &[&str] = &[
            "/var/lib/osoosi/audit",
            "watchdog_stack",
            "audit_stack",
            "kill_switch",
            "containment_verifier_role",
        ];

        FORBIDDEN_ACTION_PREFIXES
            .iter()
            .any(|p| lower_act.starts_with(p))
            || FORBIDDEN_RESOURCE_PATTERNS
                .iter()
                .any(|p| lower_res.contains(p))
    }

    pub fn record_access_denied_and_check_alarm(
        &self,
        agent_id: &str,
        cluster_id: &str,
        denial_reason: &str,
        now_unix: i64,
    ) -> Option<KillSwitchTerminationReport> {
        let cutoff = now_unix - self.r5_window_secs;
        let count = if let Ok(mut map) = self.denied_call_windows.lock() {
            let entry = map.entry(agent_id.to_string()).or_default();
            while let Some(&front) = entry.front() {
                if front < cutoff {
                    entry.pop_front();
                } else {
                    break;
                }
            }
            entry.push_back(now_unix);
            entry.len()
        } else {
            1
        };

        if count >= self.r5_denied_threshold {
            let violation = format!(
                "R5_CAPABILITY_ENVELOPE_ALARM: Agent '{}' triggered {} AccessDenied events within {}s (threshold: {}). Latest denial: {}",
                agent_id, count, self.r5_window_secs, self.r5_denied_threshold, denial_reason
            );
            Some(self.execute_kill_switch(cluster_id, &[violation], now_unix))
        } else {
            None
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_intersection_authority(
        &self,
        agent_id: &str,
        cluster_id: &str,
        agent_role: &ArmRole,
        user: &DelegatingUserContext,
        task_scope: &TaskScopeEnvelope,
        action: &str,
        resource: &str,
        now_unix: i64,
    ) -> OsoAuthzDecision {
        if Self::is_adversarial_audit_or_control_plane_probe(action, resource) {
            let reason = format!(
                "AWS_R4_ADVERSARIAL_AUDIT_ISOLATION_DENY: Agent '{}' attempted forbidden control-plane/monitoring action '{}' on '{}'",
                agent_id, action, resource
            );
            let ks = self.record_access_denied_and_check_alarm(
                agent_id,
                cluster_id,
                &reason,
                now_unix,
            );
            return OsoAuthzDecision::Deny {
                code: "AWS_R4_EXPLICIT_DENY".to_string(),
                reason,
                kill_switch_triggered: ks.is_some(),
            };
        }

        if !user.permissions.contains(action) {
            let reason = format!(
                "OSO_INTERSECTION_USER_DENIED: Delegating user '{}' lacks permission '{}' for resource '{}'",
                user.user_id, action, resource
            );
            let ks = self.record_access_denied_and_check_alarm(
                agent_id,
                cluster_id,
                &reason,
                now_unix,
            );
            return OsoAuthzDecision::Deny {
                code: "OSO_USER_PERMISSION_MISSING".to_string(),
                reason,
                kill_switch_triggered: ks.is_some(),
            };
        }

        let user_owns_resource = user
            .allowed_resources
            .iter()
            .any(|prefix| resource == prefix || resource.starts_with(prefix));
        if !user_owns_resource {
            let reason = format!(
                "OSO_INTERSECTION_USER_RESOURCE_DENIED: Delegating user '{}' has no ownership/ACL grant over resource '{}'",
                user.user_id, resource
            );
            let ks = self.record_access_denied_and_check_alarm(
                agent_id,
                cluster_id,
                &reason,
                now_unix,
            );
            return OsoAuthzDecision::Deny {
                code: "OSO_USER_RESOURCE_UNAUTHORIZED".to_string(),
                reason,
                kill_switch_triggered: ks.is_some(),
            };
        }

        let role_caps = role_capability_actions(agent_role);
        if !role_caps.contains(action) {
            let reason = format!(
                "OSO_INTERSECTION_ROLE_DENIED: Agent '{}' with role {:?} lacks capability '{}' (even though user '{}' possesses it)",
                agent_id, agent_role, action, user.user_id
            );
            let ks = self.record_access_denied_and_check_alarm(
                agent_id,
                cluster_id,
                &reason,
                now_unix,
            );
            return OsoAuthzDecision::Deny {
                code: "OSO_AGENT_ROLE_CAPABILITY_MISSING".to_string(),
                reason,
                kill_switch_triggered: ks.is_some(),
            };
        }

        if !task_scope.allowed_actions.contains(action) {
            let reason = format!(
                "OSO_INTERSECTION_TASK_SCOPE_DENIED: Task '{}' does not scope action '{}'",
                task_scope.task_id, action
            );
            let ks = self.record_access_denied_and_check_alarm(
                agent_id,
                cluster_id,
                &reason,
                now_unix,
            );
            return OsoAuthzDecision::Deny {
                code: "OSO_TASK_SCOPE_ACTION_DENIED".to_string(),
                reason,
                kill_switch_triggered: ks.is_some(),
            };
        }

        let in_task_resource_scope = task_scope
            .allowed_resource_prefixes
            .iter()
            .any(|prefix| resource.starts_with(prefix));
        if !in_task_resource_scope {
            let reason = format!(
                "OSO_INTERSECTION_TASK_RESOURCE_OUT_OF_SCOPE: Resource '{}' is outside task '{}' prefixes {:?}",
                resource, task_scope.task_id, task_scope.allowed_resource_prefixes
            );
            let ks = self.record_access_denied_and_check_alarm(
                agent_id,
                cluster_id,
                &reason,
                now_unix,
            );
            return OsoAuthzDecision::Deny {
                code: "OSO_TASK_RESOURCE_OUT_OF_SCOPE".to_string(),
                reason,
                kill_switch_triggered: ks.is_some(),
            };
        }

        OsoAuthzDecision::Allow {
            effective_intersection_action: action.to_string(),
            rationale: format!(
                "Authorized via 3-way Oso intersection: User('{}') ∩ Role({:?}) ∩ Task('{}') on '{}'",
                user.user_id, agent_role, task_scope.task_id, resource
            ),
        }
    }

    pub fn filter_rag_documents_pre_retrieval(
        &self,
        user: &DelegatingUserContext,
        agent_role: &ArmRole,
        task_scope: &TaskScopeEnvelope,
        candidates: &[RagDocumentChunk],
    ) -> RagFilterResult {
        let max_role_tier = role_max_clearance_tier(agent_role);
        let effective_max_tier = user.max_clearance_tier.min(max_role_tier);

        let mut authorized_doc_ids = Vec::new();
        let mut filtered_out_doc_ids = Vec::new();
        let mut reasons = Vec::new();

        for doc in candidates {
            if doc.workspace_id != task_scope.workspace_id {
                filtered_out_doc_ids.push(doc.doc_id.clone());
                reasons.push(format!(
                    "Doc '{}' excluded: workspace '{}' != task workspace '{}'",
                    doc.doc_id, doc.workspace_id, task_scope.workspace_id
                ));
                continue;
            }

            let has_rebac_access =
                doc.owner_id == user.user_id || doc.shared_with_users.contains(&user.user_id);
            if !has_rebac_access {
                filtered_out_doc_ids.push(doc.doc_id.clone());
                reasons.push(format!(
                    "Doc '{}' excluded: user '{}' is neither owner ('{}') nor in shared ACL",
                    doc.doc_id, user.user_id, doc.owner_id
                ));
                continue;
            }

            if doc.classification_tier > effective_max_tier {
                filtered_out_doc_ids.push(doc.doc_id.clone());
                reasons.push(format!(
                    "Doc '{}' excluded: classification tier {} exceeds effective intersection clearance {}",
                    doc.doc_id, doc.classification_tier, effective_max_tier
                ));
                continue;
            }

            authorized_doc_ids.push(doc.doc_id.clone());
        }

        RagFilterResult {
            total_candidates: candidates.len(),
            authorized_doc_ids,
            filtered_out_doc_ids,
            reasons,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_mcp_tool_call(
        &self,
        agent_id: &str,
        cluster_id: &str,
        agent_role: &ArmRole,
        user: &DelegatingUserContext,
        task_scope: &TaskScopeEnvelope,
        tool_name: &str,
        mapped_action: &str,
        target_resource: &str,
        arguments: &Value,
        hitl_ticket: Option<&HitlStepUpTicket>,
        now_unix: i64,
    ) -> OsoAuthzDecision {
        let base_decision = self.evaluate_intersection_authority(
            agent_id,
            cluster_id,
            agent_role,
            user,
            task_scope,
            mapped_action,
            target_resource,
            now_unix,
        );
        if matches!(base_decision, OsoAuthzDecision::Deny { .. }) {
            return base_decision;
        }

        if let Some(limit) = arguments.get("limit").and_then(|v| v.as_u64()) {
            if limit > task_scope.max_query_limit {
                let reason = format!(
                    "OSO_MCP_PARAM_LIMIT_EXCEEDED: Tool '{}' requested limit={} exceeding task max_query_limit={}",
                    tool_name, limit, task_scope.max_query_limit
                );
                let ks = self.record_access_denied_and_check_alarm(
                    agent_id,
                    cluster_id,
                    &reason,
                    now_unix,
                );
                return OsoAuthzDecision::Deny {
                    code: "OSO_MCP_PARAM_LIMIT_EXCEEDED".to_string(),
                    reason,
                    kill_switch_triggered: ks.is_some(),
                };
            }
        }

        if let Some(row_owner) = arguments.get("owner_id").and_then(|v| v.as_str()) {
            if row_owner != user.user_id {
                let reason = format!(
                    "OSO_MCP_ROW_OWNERSHIP_VIOLATION: Tool '{}' targeted row owner '{}' != delegating user '{}'",
                    tool_name, row_owner, user.user_id
                );
                let ks = self.record_access_denied_and_check_alarm(
                    agent_id,
                    cluster_id,
                    &reason,
                    now_unix,
                );
                return OsoAuthzDecision::Deny {
                    code: "OSO_MCP_ROW_OWNERSHIP_VIOLATION".to_string(),
                    reason,
                    kill_switch_triggered: ks.is_some(),
                };
            }
        }

        let lower_tool = tool_name.to_ascii_lowercase();
        let is_destructive_tool = lower_tool.starts_with("delete_")
            || lower_tool.starts_with("drop_")
            || lower_tool.starts_with("truncate_")
            || lower_tool == "transfer_funds"
            || lower_tool == "modify_security_policy"
            || mapped_action.starts_with("delete:")
            || mapped_action == "transfer:funds";

        if is_destructive_tool {
            match hitl_ticket {
                None => {
                    let reason = format!(
                        "OSO_HITL_STEP_UP_REQUIRED: Destructive tool '{}' requires an out-of-band HMAC-SHA256 HitlStepUpTicket",
                        tool_name
                    );
                    let ks = self.record_access_denied_and_check_alarm(
                        agent_id,
                        cluster_id,
                        &reason,
                        now_unix,
                    );
                    return OsoAuthzDecision::Deny {
                        code: "OSO_HITL_STEP_UP_REQUIRED".to_string(),
                        reason,
                        kill_switch_triggered: ks.is_some(),
                    };
                }
                Some(ticket) => {
                    if let Err(err) = verify_hitl_step_up_ticket(
                        &self.hitl_secret_key,
                        ticket,
                        &user.user_id,
                        agent_id,
                        tool_name,
                        arguments,
                        now_unix,
                    ) {
                        let reason = format!(
                            "OSO_HITL_STEP_UP_INVALID: Destructive tool '{}' rejected: {}",
                            tool_name, err
                        );
                        let ks = self.record_access_denied_and_check_alarm(
                            agent_id,
                            cluster_id,
                            &reason,
                            now_unix,
                        );
                        return OsoAuthzDecision::Deny {
                            code: "OSO_HITL_STEP_UP_INVALID".to_string(),
                            reason,
                            kill_switch_triggered: ks.is_some(),
                        };
                    }
                }
            }
        }

        OsoAuthzDecision::Allow {
            effective_intersection_action: mapped_action.to_string(),
            rationale: format!(
                "MCP tool '{}' authorized via Oso parameter & intersection policy for user '{}'",
                tool_name, user.user_id
            ),
        }
    }

    pub fn check_security_group_invariants(snapshot: &ContainmentEnvironmentSnapshot) -> Vec<String> {
        let mut violations = Vec::new();
        for rule in &snapshot.egress_rules {
            if let Some(ref cidr) = rule.cidr_ipv4 {
                if cidr.trim() == "0.0.0.0/0" {
                    violations.push(format!(
                        "Security group {} has egress rule {} allowing 0.0.0.0/0 (protocol: {})",
                        snapshot.security_group_id, rule.rule_id, rule.protocol
                    ));
                }
            }
            if let Some(ref cidr6) = rule.cidr_ipv6 {
                if cidr6.trim() == "::/0" {
                    violations.push(format!(
                        "Security group {} has egress rule {} allowing ::/0 (protocol: {})",
                        snapshot.security_group_id, rule.rule_id, rule.protocol
                    ));
                }
            }
        }
        violations
    }

    pub fn check_route_table_invariants(snapshot: &ContainmentEnvironmentSnapshot) -> Vec<String> {
        let mut violations = Vec::new();
        for route in &snapshot.route_entries {
            if route.gateway_id.starts_with("igw-")
                || route.gateway_id.starts_with("unproxied-raw-")
            {
                violations.push(format!(
                    "Route table {} has route to internet gateway {} (destination: {})",
                    route.route_table_id, route.gateway_id, route.destination_cidr
                ));
            }
        }
        violations
    }

    pub fn check_iam_policy_invariants(snapshot: &ContainmentEnvironmentSnapshot) -> Vec<String> {
        let mut violations = Vec::new();
        let expected_attached_count = snapshot.expected_attached_policy_arns.len();
        let actual_attached_count = snapshot.actual_attached_policy_arns.len();
        if actual_attached_count != expected_attached_count {
            violations.push(format!(
                "Role {} has {} attached policies, expected {}",
                snapshot.task_role_name, actual_attached_count, expected_attached_count
            ));
        }

        let unexpected_arns: Vec<String> = snapshot
            .actual_attached_policy_arns
            .difference(&snapshot.expected_attached_policy_arns)
            .cloned()
            .collect();
        let missing_arns: Vec<String> = snapshot
            .expected_attached_policy_arns
            .difference(&snapshot.actual_attached_policy_arns)
            .cloned()
            .collect();

        if !unexpected_arns.is_empty() {
            violations.push(format!(
                "Role {} has unexpected attached policies: {}",
                snapshot.task_role_name,
                unexpected_arns.join(", ")
            ));
        }
        if !missing_arns.is_empty() {
            violations.push(format!(
                "Role {} is missing expected attached policies: {}",
                snapshot.task_role_name,
                missing_arns.join(", ")
            ));
        }

        let expected_inline_count = snapshot.expected_inline_policy_names.len();
        let actual_inline_count = snapshot.actual_inline_policy_names.len();
        if actual_inline_count != expected_inline_count {
            violations.push(format!(
                "Role {} has {} inline policies, expected {}",
                snapshot.task_role_name, actual_inline_count, expected_inline_count
            ));
        }

        let unexpected_inline: Vec<String> = snapshot
            .actual_inline_policy_names
            .difference(&snapshot.expected_inline_policy_names)
            .cloned()
            .collect();
        let missing_inline: Vec<String> = snapshot
            .expected_inline_policy_names
            .difference(&snapshot.actual_inline_policy_names)
            .cloned()
            .collect();

        if !unexpected_inline.is_empty() {
            violations.push(format!(
                "Role {} has unexpected inline policies: {}",
                snapshot.task_role_name,
                unexpected_inline.join(", ")
            ));
        }
        if !missing_inline.is_empty() {
            violations.push(format!(
                "Role {} is missing expected inline policies: {}",
                snapshot.task_role_name,
                missing_inline.join(", ")
            ));
        }

        violations
    }

    pub fn check_dns_firewall_invariants(snapshot: &ContainmentEnvironmentSnapshot) -> Vec<String> {
        let active_complete = snapshot
            .dns_firewall_associations
            .iter()
            .filter(|a| a.vpc_id == snapshot.vpc_id && a.status == "COMPLETE")
            .count();

        if active_complete == 0 {
            vec![format!(
                "No active DNS Firewall rule group associated with VPC {}.",
                snapshot.vpc_id
            )]
        } else {
            Vec::new()
        }
    }

    pub fn verify_four_containment_invariants(
        &self,
        cluster_id: &str,
        snapshot: &ContainmentEnvironmentSnapshot,
        now_unix: i64,
    ) -> WatchdogAssessmentReport {
        let security_group_violations = Self::check_security_group_invariants(snapshot);
        let route_table_violations = Self::check_route_table_invariants(snapshot);
        let iam_policy_violations = Self::check_iam_policy_invariants(snapshot);
        let dns_firewall_violations = Self::check_dns_firewall_invariants(snapshot);

        let mut all_violations = Vec::new();
        all_violations.extend(security_group_violations.clone());
        all_violations.extend(route_table_violations.clone());
        all_violations.extend(iam_policy_violations.clone());
        all_violations.extend(dns_firewall_violations.clone());

        if !all_violations.is_empty() {
            let ks_report = self.execute_kill_switch(cluster_id, &all_violations, now_unix);
            return WatchdogAssessmentReport {
                status: "killed".to_string(),
                checked_at_unix: now_unix,
                security_group_violations,
                route_table_violations,
                iam_policy_violations,
                dns_firewall_violations,
                all_violations,
                kill_switch_report: Some(ks_report),
            };
        }

        WatchdogAssessmentReport {
            status: "healthy".to_string(),
            checked_at_unix: now_unix,
            security_group_violations,
            route_table_violations,
            iam_policy_violations,
            dns_firewall_violations,
            all_violations,
            kill_switch_report: None,
        }
    }

    pub fn execute_kill_switch(
        &self,
        cluster_id: &str,
        violations: &[String],
        now_unix: i64,
    ) -> KillSwitchTerminationReport {
        let violation_summary = if violations.is_empty() {
            "Unknown containment violation".to_string()
        } else {
            violations.join("; ")
        };

        let (scaled_services, terminated_task_ids, new_generation_epoch) =
            if let Ok(mut map) = self.cluster_services.lock() {
                let state = map
                    .entry(cluster_id.to_string())
                    .or_insert_with(|| AgentClusterServiceState {
                        cluster_id: cluster_id.to_string(),
                        service_name: "default-agent-service".to_string(),
                        desired_count: 1,
                        auto_respawn_disabled: false,
                        running_task_ids: vec!["task-default-0".to_string()],
                        generation_epoch: 1,
                    });
                state.desired_count = 0;
                state.auto_respawn_disabled = true;
                let scaled = vec![state.service_name.clone()];
                let tasks: Vec<String> = state.running_task_ids.drain(..).collect();
                state.generation_epoch = state.generation_epoch.saturating_add(1);
                (scaled, tasks, state.generation_epoch)
            } else {
                (Vec::new(), Vec::new(), 2)
            };

        let report = KillSwitchTerminationReport {
            triggered_at_unix: now_unix,
            cluster_id: cluster_id.to_string(),
            services_scaled_down_to_zero: scaled_services,
            auto_respawn_disabled: true,
            tasks_terminated_count: terminated_task_ids.len(),
            terminated_task_ids,
            new_generation_epoch,
            violation_summary,
        };

        if let Ok(mut hist) = self.kill_switch_history.lock() {
            hist.entry(cluster_id.to_string())
                .or_default()
                .push(report.clone());
        }

        report
    }
}

pub static GLOBAL_OSO_AWS_CONTAINMENT: LazyLock<Arc<OsoAwsContainmentEngine>> =
    LazyLock::new(|| Arc::new(OsoAwsContainmentEngine::default()));

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_user_and_task() -> (DelegatingUserContext, TaskScopeEnvelope) {
        let mut perms = BTreeSet::new();
        perms.insert("read:docs".to_string());
        perms.insert("write:ledger".to_string());
        perms.insert("transfer:funds".to_string());

        let mut resources = BTreeSet::new();
        resources.insert("doc://workspace-alpha/".to_string());
        resources.insert("ledger://workspace-alpha/".to_string());

        let user = DelegatingUserContext {
            user_id: "alice@enterprise.internal".to_string(),
            permissions: perms,
            allowed_resources: resources,
            max_clearance_tier: 2,
        };

        let mut task_actions = BTreeSet::new();
        task_actions.insert("read:docs".to_string());
        task_actions.insert("write:ledger".to_string());
        task_actions.insert("transfer:funds".to_string());

        let task = TaskScopeEnvelope {
            task_id: "task-q3-reconcile".to_string(),
            workspace_id: "workspace-alpha".to_string(),
            allowed_actions: task_actions,
            allowed_resource_prefixes: vec![
                "doc://workspace-alpha/".to_string(),
                "ledger://workspace-alpha/".to_string(),
            ],
            max_query_limit: 50,
            allow_production_mutation: false,
        };

        (user, task)
    }

    #[test]
    fn test_oso_three_way_delegated_intersection_authority() {
        let engine = OsoAwsContainmentEngine::new(b"test-secret-key-32-bytes-long!!!");
        let (user, task) = sample_user_and_task();
        let now = 1_793_470_000;

        let denied_by_role = engine.evaluate_intersection_authority(
            "arm-doc-1",
            "cluster-1",
            &ArmRole::UntrustedDocIngest,
            &user,
            &task,
            "write:ledger",
            "ledger://workspace-alpha/q3",
            now,
        );
        assert!(matches!(
            denied_by_role,
            OsoAuthzDecision::Deny {
                ref code,
                kill_switch_triggered: false,
                ..
            } if code == "OSO_AGENT_ROLE_CAPABILITY_MISSING"
        ));

        let allowed = engine.evaluate_intersection_authority(
            "arm-ledger-1",
            "cluster-1",
            &ArmRole::AccountingLedgerWrite,
            &user,
            &task,
            "write:ledger",
            "ledger://workspace-alpha/q3",
            now,
        );
        assert!(matches!(allowed, OsoAuthzDecision::Allow { .. }));
    }

    #[test]
    fn test_oso_pre_retrieval_rag_filtering() {
        let engine = OsoAwsContainmentEngine::default();
        let (user, task) = sample_user_and_task();

        let chunks = vec![
            RagDocumentChunk {
                doc_id: "doc-1-allowed".to_string(),
                workspace_id: "workspace-alpha".to_string(),
                owner_id: "alice@enterprise.internal".to_string(),
                shared_with_users: BTreeSet::new(),
                classification_tier: 1,
                content_preview: "Q3 benign invoice summary".to_string(),
            },
            RagDocumentChunk {
                doc_id: "doc-2-too-secret-for-role".to_string(),
                workspace_id: "workspace-alpha".to_string(),
                owner_id: "alice@enterprise.internal".to_string(),
                shared_with_users: BTreeSet::new(),
                classification_tier: 2,
                content_preview: "Confidential M&A board deck".to_string(),
            },
        ];

        let filtered = engine.filter_rag_documents_pre_retrieval(
            &user,
            &ArmRole::UntrustedDocIngest,
            &task,
            &chunks,
        );
        assert_eq!(filtered.authorized_doc_ids, vec!["doc-1-allowed"]);
        assert_eq!(filtered.filtered_out_doc_ids, vec!["doc-2-too-secret-for-role"]);
    }

    #[test]
    fn test_oso_mcp_tool_call_and_hitl_step_up_ticket() {
        let secret = b"super-secret-hitl-hmac-key-2026";
        let engine = OsoAwsContainmentEngine::new(secret);
        let (user, task) = sample_user_and_task();
        let now = 1_793_470_000;
        let args = json!({
            "owner_id": "alice@enterprise.internal",
            "amount_usd": 2500
        });

        let without_ticket = engine.authorize_mcp_tool_call(
            "arm-ledger-1",
            "cluster-hitl",
            &ArmRole::AccountingLedgerWrite,
            &user,
            &task,
            "transfer_funds",
            "transfer:funds",
            "ledger://workspace-alpha/transfers",
            &args,
            None,
            now,
        );
        assert!(matches!(without_ticket, OsoAuthzDecision::Deny { .. }));

        let valid_ticket = issue_hitl_step_up_ticket(
            secret,
            "secops-lead@enterprise.internal",
            &user.user_id,
            "arm-ledger-1",
            "transfer_funds",
            &args,
            now + 300,
        );

        let with_valid_ticket = engine.authorize_mcp_tool_call(
            "arm-ledger-1",
            "cluster-hitl",
            &ArmRole::AccountingLedgerWrite,
            &user,
            &task,
            "transfer_funds",
            "transfer:funds",
            "ledger://workspace-alpha/transfers",
            &args,
            Some(&valid_ticket),
            now,
        );
        assert!(matches!(with_valid_ticket, OsoAuthzDecision::Allow { .. }));
    }

    #[test]
    fn test_aws_r3_four_invariants_and_policy_swap_detection() {
        let engine = OsoAwsContainmentEngine::default();
        let now = 1_793_470_000;

        let mut breached_snap = ContainmentEnvironmentSnapshot::default();
        breached_snap.actual_attached_policy_arns.clear();
        breached_snap
            .actual_attached_policy_arns
            .insert("arn:aws:iam::aws:policy/AdministratorAccess".to_string());

        let breach_report = engine.verify_four_containment_invariants(
            "octopus-agent-cluster",
            &breached_snap,
            now,
        );
        assert_eq!(breach_report.status, "killed");
        assert_eq!(breach_report.iam_policy_violations.len(), 2);
    }

    #[test]
    fn test_aws_r4_audit_isolation_and_r5_velocity_alarm_kill_switch() {
        let engine = OsoAwsContainmentEngine::default();
        engine.register_agent_service(
            "cluster-r5",
            "agent-worker-svc",
            1,
            vec!["task-rogue-99".to_string()],
        );
        let (user, task) = sample_user_and_task();
        let now = 1_793_470_000;

        let _ = engine.evaluate_intersection_authority(
            "agent-rogue-99",
            "cluster-r5",
            &ArmRole::UntrustedDocIngest,
            &user,
            &task,
            "cloudtrail:StopLogging",
            "arn:aws:cloudtrail:us-east-1:222222222222:trail/org-trail",
            now,
        );
        let _ = engine.evaluate_intersection_authority(
            "agent-rogue-99",
            "cluster-r5",
            &ArmRole::UntrustedDocIngest,
            &user,
            &task,
            "iam:AttachRolePolicy",
            "arn:aws:iam::111111111111:role/AgentTaskRole",
            now + 10,
        );
        let d3 = engine.evaluate_intersection_authority(
            "agent-rogue-99",
            "cluster-r5",
            &ArmRole::UntrustedDocIngest,
            &user,
            &task,
            "osoosi:watchdog:Disable",
            "/var/lib/osoosi/audit",
            now + 25,
        );
        assert!(matches!(
            d3,
            OsoAuthzDecision::Deny {
                kill_switch_triggered: true,
                ..
            }
        ));
    }
}
