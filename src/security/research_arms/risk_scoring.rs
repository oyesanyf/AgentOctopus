use super::attack_chain_arm::CandidateAttackChain;
use super::chain_validator::ChainValidationReport;
use super::vulnerability_arm::{DiscoveredVulnerability, VulnerabilitySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmRiskScore {
    pub exploitability_score: f64, // 0.0 to 10.0
    pub impact_score: f64,         // 0.0 to 10.0
    pub composite_score: f64,      // 0.0 to 10.0
    pub risk_tier: String,         // Critical, High, Medium, Low
    pub defense_mitigation_rate: f64, // 0.0 to 1.0 (100% neutralized)
}

/// Risk Scoring Engine: Computes quantitative AI agent vulnerability and attack chain risk scores.
pub struct RiskScoringEngine;

impl RiskScoringEngine {
    /// Computes risk score for an individual vulnerability.
    pub fn score_vulnerability(vuln: &DiscoveredVulnerability) -> f64 {
        match vuln.severity {
            VulnerabilitySeverity::Critical => 9.5,
            VulnerabilitySeverity::High => 7.8,
            VulnerabilitySeverity::Medium => 5.2,
            VulnerabilitySeverity::Low => 2.5,
            VulnerabilitySeverity::Informational => 0.5,
        }
    }

    /// Evaluates aggregate swarm risk given discovered vulnerabilities and attack chain validation outcomes.
    pub fn evaluate_swarm_risk(
        vulnerabilities: &[DiscoveredVulnerability],
        _chains: &[CandidateAttackChain],
        validation_reports: &[ChainValidationReport],
    ) -> SwarmRiskScore {
        if vulnerabilities.is_empty() && validation_reports.is_empty() {
            return SwarmRiskScore {
                exploitability_score: 0.0,
                impact_score: 0.0,
                composite_score: 0.0,
                risk_tier: "Negligible".to_string(),
                defense_mitigation_rate: 1.0,
            };
        }

        // Base exploitability from vulnerabilities
        let max_vuln_score = vulnerabilities
            .iter()
            .map(Self::score_vulnerability)
            .fold(0.0_f64, f64::max);

        // Mitigation rate from validation reports
        let total_chains = validation_reports.len();
        let neutralized_chains = validation_reports
            .iter()
            .filter(|r| r.fully_neutralized)
            .count();

        let mitigation_rate = if total_chains == 0 {
            1.0
        } else {
            neutralized_chains as f64 / total_chains as f64
        };

        // Residual risk: unmitigated portion scales the composite score
        let residual_factor = 1.0 - (mitigation_rate * 0.85); // 85% reduction when all chains are blocked
        let composite = (max_vuln_score * residual_factor).clamp(0.0, 10.0);

        let risk_tier = if composite >= 8.5 {
            "Critical".to_string()
        } else if composite >= 6.5 {
            "High".to_string()
        } else if composite >= 4.0 {
            "Medium".to_string()
        } else {
            "Low".to_string()
        };

        SwarmRiskScore {
            exploitability_score: max_vuln_score,
            impact_score: 8.0,
            composite_score: composite,
            risk_tier,
            defense_mitigation_rate: mitigation_rate,
        }
    }
}
