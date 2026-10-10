use super::vulnerability_arm::DiscoveredVulnerability;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttackStepType {
    PromptInjection,
    CapabilityTheft,
    LateralMovement,
    PrivilegeEscalation,
    EgressExfiltration,
    PersistenceAttempt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub step_number: usize,
    pub step_type: AttackStepType,
    pub actor_agent: String,
    pub target_component: String,
    pub payload_vector: String,
    pub associated_vuln_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateAttackChain {
    pub chain_id: String,
    pub name: String,
    pub target_asset: String,
    pub steps: Vec<AttackStep>,
    pub estimated_blast_radius: String,
}

/// Attack Chain Arm: Synthesizes multi-step adversarial attack graphs
/// to test whether isolated weaknesses can be combined to achieve compromise.
pub struct AttackChainArm {
    pub arm_id: String,
}

impl AttackChainArm {
    pub fn new(arm_id: &str) -> Self {
        Self {
            arm_id: arm_id.to_string(),
        }
    }

    /// Synthesizes candidate attack chains based on discovered vulnerabilities.
    pub fn synthesize_attack_chains(
        &self,
        vulnerabilities: &[DiscoveredVulnerability],
    ) -> Vec<CandidateAttackChain> {
        let mut chains = Vec::new();

        // Check if egress allowlist or delegation depth vulnerabilities exist
        let has_egress_vuln = vulnerabilities.iter().any(|v| v.vuln_id == "OCT-VULN-004");
        let has_delegation_vuln = vulnerabilities.iter().any(|v| v.vuln_id == "OCT-VULN-002");

        if has_egress_vuln {
            chains.push(CandidateAttackChain {
                chain_id: "CHAIN-EXFIL-001".to_string(),
                name: "Lateral Delegation to Unauthorized Egress Exfiltration".to_string(),
                target_asset: "Proprietary Swarm Invoices & Credentials".to_string(),
                steps: vec![
                    AttackStep {
                        step_number: 1,
                        step_type: AttackStepType::PromptInjection,
                        actor_agent: "agent_doc_ingest".to_string(),
                        target_component: "doc_extractor".to_string(),
                        payload_vector: "Indirect prompt injection via PDF invoice text".to_string(),
                        associated_vuln_id: None,
                    },
                    AttackStep {
                        step_number: 2,
                        step_type: AttackStepType::LateralMovement,
                        actor_agent: "agent_doc_ingest".to_string(),
                        target_component: "agent_network_egress".to_string(),
                        payload_vector: "Cross-arm message delegation request".to_string(),
                        associated_vuln_id: if has_delegation_vuln {
                            Some("OCT-VULN-002".to_string())
                        } else {
                            None
                        },
                    },
                    AttackStep {
                        step_number: 3,
                        step_type: AttackStepType::EgressExfiltration,
                        actor_agent: "agent_network_egress".to_string(),
                        target_component: "http_egress".to_string(),
                        payload_vector: "HTTPS POST to non-Google attacker C2 endpoint".to_string(),
                        associated_vuln_id: Some("OCT-VULN-004".to_string()),
                    },
                ],
                estimated_blast_radius: "High: Exfiltration of confidential accounting documents".to_string(),
            });
        }

        // Standard test chain for privilege escalation
        chains.push(CandidateAttackChain {
            chain_id: "CHAIN-ESC-001".to_string(),
            name: "Capability Token Forgery & Accounting Ledger Tampering".to_string(),
            target_asset: "Immutable Accounting Ledger State".to_string(),
            steps: vec![
                AttackStep {
                    step_number: 1,
                    step_type: AttackStepType::CapabilityTheft,
                    actor_agent: "untrusted_worker".to_string(),
                    target_component: "capabilities::CapabilityToken".to_string(),
                    payload_vector: "Attempt to forge HMAC signature or modify permitted_role".to_string(),
                    associated_vuln_id: Some("OCT-VULN-003".to_string()),
                },
                AttackStep {
                    step_number: 2,
                    step_type: AttackStepType::PrivilegeEscalation,
                    actor_agent: "untrusted_worker".to_string(),
                    target_component: "enclave::ledger_writer".to_string(),
                    payload_vector: "Direct tool invocation with modified capability token".to_string(),
                    associated_vuln_id: None,
                },
            ],
            estimated_blast_radius: "Critical: Corruption of financial audit records".to_string(),
        });

        chains
    }
}
