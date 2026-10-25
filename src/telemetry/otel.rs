use crate::security::LogSanitizer;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// W3C TraceContext compliant trace identifier (128-bit hex string, 32 lowercase hex chars).
pub fn generate_trace_id() -> String {
    let mut bytes = [0u8; 16];
    for b in &mut bytes {
        *b = rand::random::<u8>();
    }
    hex::encode(bytes)
}

/// W3C TraceContext compliant span identifier (64-bit hex string, 16 lowercase hex chars).
pub fn generate_span_id() -> String {
    let mut bytes = [0u8; 8];
    for b in &mut bytes {
        *b = rand::random::<u8>();
    }
    hex::encode(bytes)
}

/// OpenTelemetry Span Kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtelSpanKind {
    Internal,
    Server,
    Client,
    Producer,
    Consumer,
}

/// OpenTelemetry Span Status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtelStatusCode {
    Unset,
    Ok,
    Error,
}

/// OpenTelemetry Span Event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelSpanEvent {
    pub name: String,
    pub timestamp_unix_nano: u64,
    pub attributes: HashMap<String, String>,
}

/// Comprehensive OpenTelemetry Span capturing Agentic Session Telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelSpan {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub kind: OtelSpanKind,
    pub start_time_unix_nano: u64,
    pub end_time_unix_nano: u64,
    pub duration_ms: f64,
    pub status: OtelStatusCode,
    pub status_message: Option<String>,
    pub attributes: HashMap<String, String>,
    pub events: Vec<OtelSpanEvent>,
}

/// Summary of an active or completed Agentic Session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSessionTelemetry {
    pub session_id: String,
    pub trace_id: String,
    pub agent_principal: String,
    pub start_time_secs: u64,
    pub last_active_secs: u64,
    pub total_turns: usize,
    pub total_tool_calls: usize,
    pub security_violations_detected: usize,
    pub rl_action_tier: String,
    pub mttd_ms: f64,
    pub mttr_ms: f64,
    pub survival_probability: f64,
    pub is_active: bool,
}

/// Operational Resilience Metrics derived from the continuous security paper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResilienceMetrics {
    /// MTTD: Mean Time to Detection (ms) across all boundary violations.
    pub mttd_ms: f64,
    /// MTTR: Mean Time to Remediation / Containment (ms).
    pub mttr_ms: f64,
    /// Total boundary events detected.
    pub total_breach_events: usize,
    /// Vassilev Sisyphean Survival Probability: P_secure(N) <= (1 - epsilon_min)^N.
    pub cumulative_survival_prob: f64,
    /// Current step count N.
    pub current_step_count: usize,
    /// Assumed epsilon_min per-step error lower bound (default 0.01 = 1%).
    pub epsilon_min: f64,
    /// Active RL defense action tier.
    pub active_rl_action_tier: String,
}

/// OpenTelemetry Session Telemetry Engine:
/// Collects and aggregates session traces, spans, and metrics.
pub struct OtelSessionTelemetry {
    active_sessions: RwLock<HashMap<String, AgentSessionTelemetry>>,
    spans: Mutex<Vec<OtelSpan>>,
    max_spans: usize,
    disk_log_path: std::path::PathBuf,
    detection_latencies_ms: Mutex<Vec<f64>>,
    remediation_latencies_ms: Mutex<Vec<f64>>,
    step_counter: Mutex<usize>,
}

impl Default for OtelSessionTelemetry {
    fn default() -> Self {
        Self::new("logs/otel_sessions.jsonl", 1000)
    }
}

impl OtelSessionTelemetry {
    pub fn new(path: &str, max_spans: usize) -> Self {
        let p = std::path::PathBuf::from(path);
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(meta) = std::fs::metadata(&p) {
            if meta.len() > 5 * 1024 * 1024 {
                let _ = std::fs::File::create(&p);
            }
        }

        Self {
            active_sessions: RwLock::new(HashMap::new()),
            spans: Mutex::new(Vec::with_capacity(max_spans)),
            max_spans,
            disk_log_path: p,
            detection_latencies_ms: Mutex::new(Vec::new()),
            remediation_latencies_ms: Mutex::new(Vec::new()),
            step_counter: Mutex::new(0),
        }
    }

    /// Starts or retrieves an active session for an agent principal.
    pub fn get_or_start_session(&self, session_id: &str, principal: &str) -> (String, String) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut sessions = self.active_sessions.write().unwrap_or_else(|e| e.into_inner());
        if let Some(sess) = sessions.get_mut(session_id) {
            sess.last_active_secs = now;
            sess.total_turns += 1;
            return (session_id.to_string(), sess.trace_id.clone());
        }
        if sessions.len() >= 1024 {
            if let Some(oldest_key) = sessions.keys().next().cloned() {
                sessions.remove(&oldest_key);
            }
        }

        let trace_id = generate_trace_id();
        let new_sess = AgentSessionTelemetry {
            session_id: session_id.to_string(),
            trace_id: trace_id.clone(),
            agent_principal: principal.to_string(),
            start_time_secs: now,
            last_active_secs: now,
            total_turns: 1,
            total_tool_calls: 0,
            security_violations_detected: 0,
            rl_action_tier: "PassiveObserve".to_string(),
            mttd_ms: 0.0,
            mttr_ms: 0.0,
            survival_probability: 1.0,
            is_active: true,
        };

        sessions.insert(session_id.to_string(), new_sess);
        (session_id.to_string(), trace_id)
    }

    /// Records an OpenTelemetry span for an agent turn, tool execution, or security evaluation.
    pub fn record_span(
        &self,
        trace_id: &str,
        parent_span_id: Option<String>,
        name: &str,
        kind: OtelSpanKind,
        start_nano: u64,
        end_nano: u64,
        status: OtelStatusCode,
        status_message: Option<String>,
        attributes: HashMap<String, String>,
        events: Vec<OtelSpanEvent>,
    ) -> OtelSpan {
        let span_id = generate_span_id();
        let duration_ms = (end_nano.saturating_sub(start_nano)) as f64 / 1_000_000.0;

        let sanitized_name = LogSanitizer::sanitize_text(name);
        let sanitized_status_message = status_message.map(|msg| LogSanitizer::sanitize_text(&msg));
        let mut sanitized_attributes = attributes;
        LogSanitizer::sanitize_map(&mut sanitized_attributes);

        let sanitized_events = events
            .into_iter()
            .map(|mut ev| {
                ev.name = LogSanitizer::sanitize_text(&ev.name);
                LogSanitizer::sanitize_map(&mut ev.attributes);
                ev
            })
            .collect();

        let span = OtelSpan {
            trace_id: trace_id.to_string(),
            span_id,
            parent_span_id,
            name: sanitized_name,
            kind,
            start_time_unix_nano: start_nano,
            end_time_unix_nano: end_nano,
            duration_ms,
            status,
            status_message: sanitized_status_message,
            attributes: sanitized_attributes,
            events: sanitized_events,
        };

        // Increment step count
        let mut steps = self.step_counter.lock().unwrap();
        *steps += 1;
        let current_steps = *steps;
        drop(steps);

        // Store in memory ring buffer
        let mut spans = self.spans.lock().unwrap();
        if spans.len() >= self.max_spans {
            spans.remove(0);
        }
        spans.push(span.clone());
        drop(spans);

        // Append to disk log (bounded sampling during high-frequency bursts to prevent I/O starvation)
        if current_steps <= 50 || current_steps % 20 == 0 {
            if let Ok(line) = serde_json::to_string(&span) {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.disk_log_path)
                {
                    let _ = writeln!(f, "{}", line);
                }
            }
        }

        span
    }

    /// Records an observed boundary event with detection and remediation latencies.
    pub fn record_resilience_event(&self, mttd_ms: f64, mttr_ms: f64, session_id: Option<&str>) {
        if mttd_ms > 0.0 {
            let mut det = self.detection_latencies_ms.lock().unwrap_or_else(|e| e.into_inner());
            if det.len() >= 1024 {
                det.remove(0);
            }
            det.push(mttd_ms);
        }
        if mttr_ms > 0.0 {
            let mut rem = self.remediation_latencies_ms.lock().unwrap_or_else(|e| e.into_inner());
            if rem.len() >= 1024 {
                rem.remove(0);
            }
            rem.push(mttr_ms);
        }

        if let Some(sid) = session_id {
            let mut sessions = self.active_sessions.write().unwrap_or_else(|e| e.into_inner());
            if let Some(sess) = sessions.get_mut(sid) {
                sess.security_violations_detected += 1;
                sess.mttd_ms = mttd_ms;
                sess.mttr_ms = mttr_ms;
            }
        }
    }

    /// Updates the RL action tier associated with a session.
    pub fn update_session_rl_tier(&self, session_id: &str, tier: &str) {
        let mut sessions = self.active_sessions.write().unwrap();
        if let Some(sess) = sessions.get_mut(session_id) {
            sess.rl_action_tier = tier.to_string();
        }
    }

    /// Calculates live Operational Resilience Metrics.
    pub fn get_resilience_metrics(&self) -> ResilienceMetrics {
        let det = self.detection_latencies_ms.lock().unwrap();
        let rem = self.remediation_latencies_ms.lock().unwrap();
        let steps = *self.step_counter.lock().unwrap();

        let mttd_ms = if det.is_empty() {
            0.0
        } else {
            det.iter().sum::<f64>() / det.len() as f64
        };

        let mttr_ms = if rem.is_empty() {
            0.0
        } else {
            rem.iter().sum::<f64>() / rem.len() as f64
        };

        let total_breach_events = det.len().max(rem.len());

        // Vassilev Sisyphean Bound: P_secure(N) <= (1 - epsilon_min)^N
        let epsilon_min = 0.01f64; // Conservative 1% lower bound error per interaction step
        let survival_prob = (1.0f64 - epsilon_min).powf(steps as f64);

        ResilienceMetrics {
            mttd_ms,
            mttr_ms,
            total_breach_events,
            cumulative_survival_prob: survival_prob,
            current_step_count: steps,
            epsilon_min,
            active_rl_action_tier: "PassiveObserve".to_string(),
        }
    }

    /// Returns all active sessions.
    pub fn list_sessions(&self) -> Vec<AgentSessionTelemetry> {
        self.active_sessions.read().unwrap().values().cloned().collect()
    }

    /// Returns recent spans from the in-memory ring buffer.
    pub fn get_recent_spans(&self, limit: usize) -> Vec<OtelSpan> {
        let spans = self.spans.lock().unwrap();
        spans.iter().rev().take(limit).cloned().collect()
    }
}
