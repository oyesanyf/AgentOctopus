use super::types::{EventKind, TemporalEvent};
use std::collections::HashMap;
use std::sync::RwLock;

/// In-memory sliding window event store for historical temporal evaluation.
pub struct TemporalEventTrace {
    events: RwLock<Vec<TemporalEvent>>,
    max_retention_secs: u64,
}

impl Default for TemporalEventTrace {
    fn default() -> Self {
        Self::new(86400 * 7) // 7 days default retention
    }
}

impl TemporalEventTrace {
    pub fn new(max_retention_secs: u64) -> Self {
        Self {
            events: RwLock::new(Vec::new()),
            max_retention_secs,
        }
    }

    /// Records an event to the trace with auto-incremented index.
    pub fn record_event(
        &self,
        timestamp_secs: u64,
        action: &str,
        kind: EventKind,
        caller_principal: &str,
        caller_resource: &str,
        fields: HashMap<String, serde_json::Value>,
    ) -> u64 {
        let mut trace = self.events.write().unwrap();
        let id = trace.len() as u64;
        let event = TemporalEvent {
            id,
            timestamp_secs,
            action: action.to_string(),
            kind,
            caller_principal: caller_principal.to_string(),
            caller_resource: caller_resource.to_string(),
            fields,
        };
        trace.push(event);

        // Prune events older than max_retention_secs
        if trace.len() > 1000 {
            if let Some(cutoff) = timestamp_secs.checked_sub(self.max_retention_secs) {
                trace.retain(|e| e.timestamp_secs >= cutoff);
            }
        }
        id
    }

    /// Returns a copy of the full trace up to timepoint index i (inclusive).
    pub fn get_history_up_to(&self, max_id: Option<u64>) -> Vec<TemporalEvent> {
        let trace = self.events.read().unwrap();
        match max_id {
            Some(max) => trace.iter().filter(|e| e.id <= max).cloned().collect(),
            None => trace.clone(),
        }
    }

    /// Slices history by principal (key-local semantics) up to max_id.
    pub fn slice_by_principal(&self, principal: &str, max_id: Option<u64>) -> Vec<TemporalEvent> {
        let trace = self.events.read().unwrap();
        trace
            .iter()
            .filter(|e| e.caller_principal == principal && max_id.map(|m| e.id <= m).unwrap_or(true))
            .cloned()
            .collect()
    }

    /// Returns total count of recorded events.
    pub fn len(&self) -> usize {
        self.events.read().unwrap().len()
    }

    /// Clears the trace.
    pub fn clear(&self) {
        self.events.write().unwrap().clear();
    }
}
