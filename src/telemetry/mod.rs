pub mod detector;
pub mod otel;
pub mod supervisor;

pub use detector::AnomalyDetector;
pub use otel::{
    AgentSessionTelemetry, OtelSessionTelemetry, OtelSpan, OtelSpanEvent, OtelSpanKind,
    OtelStatusCode, ResilienceMetrics,
};
pub use supervisor::WatchdogSupervisor;
