//! Differential Protocol Analysis Engine module.
//! Provides multi-model HTTP/1.1 and HTTP/2 framing discrepancy detection,
//! request-response desynchronization correlation, and automated Ring 1 quarantine.

pub mod desync_correlator;
pub mod engine;
pub mod parser_profiles;

pub use desync_correlator::{DesyncCorrelator, DesyncEvent};
pub use engine::{
    DifferentialAction, DifferentialAnalysisReport, DifferentialEngineStats,
    DifferentialProtocolEngine, DivergenceVector,
};
pub use parser_profiles::{
    AsyncMicroserviceParser, CdnProxyParser, ParsedProfileInterpretation, PermissiveLegacyParser,
    StrictRfc7230Parser,
};
