pub mod evaluator;
pub mod event_trace;
pub mod parser;
pub mod types;

pub use evaluator::{DecisionContext, DogwoodEvaluator};
pub use event_trace::TemporalEventTrace;
pub use parser::{DogwoodParser, ParsedTemporalClause};
pub use types::*;

use std::path::Path;
use std::sync::Arc;
use crate::security::audit::SecurityAuditLog;

/// Integrated Dogwood Temporal Policy Engine for Agent Octopus.
/// Supports joint evaluation of AWS Cedar static policies and Dogwood temporal logic (MFOTL).
pub struct DogwoodTemporalEngine {
    trace: Arc<TemporalEventTrace>,
}

impl Default for DogwoodTemporalEngine {
    fn default() -> Self {
        Self::new_simulation()
    }
}

impl DogwoodTemporalEngine {
    pub fn new(trace: Arc<TemporalEventTrace>) -> Self {
        Self { trace }
    }

    /// Creates a production temporal engine anchored to SecurityAuditLog and durable storage.
    pub fn new_production<P: AsRef<Path>>(audit_log: Arc<SecurityAuditLog>, durable_path: P) -> Self {
        Self {
            trace: Arc::new(TemporalEventTrace::new_production(audit_log, durable_path)),
        }
    }

    /// Creates an isolated simulation temporal engine for sandbox experimentation.
    pub fn new_simulation() -> Self {
        Self {
            trace: Arc::new(TemporalEventTrace::new_simulation()),
        }
    }

    /// Evaluates a Dogwood temporal policy clause against historical event trace.
    /// Fails closed if the clause cannot be parsed or evaluated.
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

    /// Records an authenticated security event using system monotonic time.
    /// Strictly prevents caller from supplying fabricated timestamps.
    pub fn record_event(
        &self,
        action: &str,
        kind: EventKind,
        caller_principal: &str,
        caller_resource: &str,
        fields: std::collections::HashMap<String, serde_json::Value>,
    ) -> u64 {
        self.trace.record_event(
            action,
            kind,
            caller_principal,
            caller_resource,
            fields,
        )
    }

    /// Records a simulated event with a specified timestamp (only allowed in simulation engine).
    pub fn record_simulated_event(
        &self,
        timestamp_secs: u64,
        action: &str,
        kind: EventKind,
        caller_principal: &str,
        caller_resource: &str,
        fields: std::collections::HashMap<String, serde_json::Value>,
    ) -> u64 {
        self.trace.record_simulated_event(
            timestamp_secs,
            action,
            kind,
            caller_principal,
            caller_resource,
            fields,
        )
    }

    /// Checks if this engine is running in isolated simulation mode.
    pub fn is_simulation(&self) -> bool {
        self.trace.is_simulation()
    }

    /// Returns reference to trace
    pub fn trace(&self) -> &Arc<TemporalEventTrace> {
        &self.trace
    }
}
