pub mod behavioral;
pub mod data;
pub mod operational;
pub mod technical;

pub use behavioral::{BehavioralBreakoutGuard, BehavioralBreakoutVerdict};
pub use data::{AgentTrustTier, DataBreakoutGuard, DataBreakoutVerdict};
pub use operational::{OperationalContainmentGuard, OperationalContainmentVerdict};
pub use technical::{TechnicalBreakoutGuard, TechnicalBreakoutVerdict};

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Comprehensive evaluation verdict across the 4-Category Taxonomy from the paper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedBreakoutEvaluation {
    pub is_clean: bool,
    pub technical: TechnicalBreakoutVerdict,
    pub operational: OperationalContainmentVerdict,
    pub behavioral: BehavioralBreakoutVerdict,
    pub data: DataBreakoutVerdict,
    pub composite_verdict: String,
    pub recommended_action_tier: String,
}

/// Unified Breakout Defense Coordinator orchestrating the 4 guards from "Beyond One and Done: Agent Breakouts".
pub struct BreakoutDefenseCoordinator {
    pub technical: Arc<TechnicalBreakoutGuard>,
    pub operational: Arc<OperationalContainmentGuard>,
    pub behavioral: Arc<BehavioralBreakoutGuard>,
    pub data: Arc<DataBreakoutGuard>,
}

impl Default for BreakoutDefenseCoordinator {
    fn default() -> Self {
        Self {
            technical: Arc::new(TechnicalBreakoutGuard::default()),
            operational: Arc::new(OperationalContainmentGuard::default()),
            behavioral: Arc::new(BehavioralBreakoutGuard::default()),
            data: Arc::new(DataBreakoutGuard::default()),
        }
    }
}

impl BreakoutDefenseCoordinator {
    /// Comprehensive audit of an agent action across all 4 taxonomy categories.
    pub fn evaluate_action(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        payload: &str,
    ) -> UnifiedBreakoutEvaluation {
        let tech_res = self.technical.evaluate_execution(resource, payload);
        let oper_res = self.operational.evaluate_context_leakage(payload);
        let behav_res = self.behavioral.evaluate_action(action, resource, payload);
        let data_res = self.data.evaluate_data_access(principal, resource, payload);

        let is_clean = tech_res.is_clean && oper_res.is_clean && behav_res.is_clean && data_res.is_clean;

        let composite_verdict = if is_clean {
            "PERMIT_ALL_CATEGORIES_INTACT".to_string()
        } else {
            let mut reasons = Vec::new();
            if !tech_res.is_clean { reasons.push("TECHNICAL_BREAKOUT"); }
            if !oper_res.is_clean { reasons.push("OPERATIONAL_FAILURE"); }
            if !behav_res.is_clean { reasons.push("BEHAVIORAL_BREAKOUT"); }
            if !data_res.is_clean { reasons.push("DATA_BREAKOUT"); }
            format!("VETO_{}", reasons.join("_AND_"))
        };

        let recommended_action_tier = if !tech_res.is_clean || !data_res.is_clean {
            "HardMitigation"
        } else if !behav_res.is_clean || !oper_res.is_clean {
            "MicroContainment"
        } else {
            "PassiveObserve"
        };

        UnifiedBreakoutEvaluation {
            is_clean,
            technical: tech_res,
            operational: oper_res,
            behavioral: behav_res,
            data: data_res,
            composite_verdict,
            recommended_action_tier: recommended_action_tier.to_string(),
        }
    }
}
