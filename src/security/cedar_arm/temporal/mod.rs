pub mod evaluator;
pub mod event_trace;
pub mod parser;
pub mod types;

pub use evaluator::{DecisionContext, DogwoodEvaluator};
pub use event_trace::TemporalEventTrace;
pub use parser::{DogwoodParser, ParsedTemporalClause};
pub use types::*;

use std::sync::Arc;

/// Integrated Dogwood Temporal Policy Engine for Agent Octopus
pub struct DogwoodTemporalEngine {
    trace: Arc<TemporalEventTrace>,
}

impl DogwoodTemporalEngine {
    pub fn new(trace: Arc<TemporalEventTrace>) -> Self {
        Self { trace }
    }

    /// Evaluates a Dogwood temporal policy clause against historical event trace
    pub fn evaluate_policy(
        &self,
        temporal_clause: &str,
        decision_ctx: &DecisionContext,
    ) -> Result<bool, String> {
        let parsed = DogwoodParser::parse(temporal_clause)?;
        let history = self.trace.get_history_up_to(None);
        let evaluator = DogwoodEvaluator::new(&history, decision_ctx);
        let holds = evaluator.evaluate(&parsed.expr);

        // when temporal { phi }: holds => permit/allow
        // unless temporal { phi }: holds => forbid/block (so !holds => allow)
        if parsed.is_unless {
            Ok(!holds)
        } else {
            Ok(holds)
        }
    }

    /// Records an event to the trace
    pub fn record_event(
        &self,
        timestamp_secs: u64,
        action: &str,
        kind: EventKind,
        caller_principal: &str,
        caller_resource: &str,
        fields: std::collections::HashMap<String, serde_json::Value>,
    ) -> u64 {
        self.trace.record_event(
            timestamp_secs,
            action,
            kind,
            caller_principal,
            caller_resource,
            fields,
        )
    }

    /// Returns reference to trace
    pub fn trace(&self) -> &Arc<TemporalEventTrace> {
        &self.trace
    }
}
