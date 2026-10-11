//! Differential Protocol Analysis Engine for Novel HTTP Attack & Desync Detection.
//! Simultaneously evaluates raw ingress streams against multiple disparate HTTP parser profiles,
//! computing a quantitative Divergence Vector and Novelty Risk Score.

use super::desync_correlator::DesyncCorrelator;
use super::parser_profiles::{
    AsyncMicroserviceParser, CdnProxyParser, ParsedProfileInterpretation, PermissiveLegacyParser,
    StrictRfc7230Parser,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Enforcement action dictated by the differential engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DifferentialAction {
    /// Parsers agree or discrepancies are below sensitivity threshold. Normal dispatch.
    Allow,
    /// Low-to-moderate parser divergence observed; logged to active defense.
    Observe,
    /// High-confidence novel attack or desync vector; stream must be severed and quarantined.
    QuarantineAndSever,
}

/// Quantitative divergence vector calculated across parser profiles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DivergenceVector {
    pub max_content_length_delta: usize,
    pub framing_conflict: bool,
    pub path_normalization_divergence: bool,
    pub header_precedence_disparity: bool,
    pub line_termination_divergence: bool,
    pub shared_parser_confusion: bool,
    pub novel_trigger_detected: bool,
    pub anomaly_token_count: usize,
    pub novelty_score: f64,
}

/// Comprehensive report of a differential analysis evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialAnalysisReport {
    pub report_id: String,
    pub timestamp_epoch_secs: u64,
    pub raw_stream_length: usize,
    pub divergence_vector: DivergenceVector,
    pub action: DifferentialAction,
    pub primary_verdict: String,
    pub parser_interpretations: Vec<ParsedProfileInterpretation>,
    pub quarantined_in_arm: Option<usize>,
}

/// Global statistics for the Differential Protocol Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialEngineStats {
    pub total_streams_analyzed: u64,
    pub total_divergence_events: u64,
    pub total_quarantined_streams: u64,
    pub active_profiles_count: usize,
    pub desync_anomalies_detected: u64,
    pub engine_status: String,
}

/// The Differential Protocol Analysis Engine.
pub struct DifferentialProtocolEngine {
    correlator: Arc<DesyncCorrelator>,
    recent_reports: Arc<RwLock<Vec<DifferentialAnalysisReport>>>,
    total_streams: Arc<AtomicU64>,
    total_divergences: Arc<AtomicU64>,
    total_quarantines: Arc<AtomicU64>,
}

impl Default for DifferentialProtocolEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DifferentialProtocolEngine {
    pub fn new() -> Self {
        Self {
            correlator: Arc::new(DesyncCorrelator::new()),
            recent_reports: Arc::new(RwLock::new(Vec::with_capacity(100))),
            total_streams: Arc::new(AtomicU64::new(0)),
            total_divergences: Arc::new(AtomicU64::new(0)),
            total_quarantines: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn correlator(&self) -> Arc<DesyncCorrelator> {
        Arc::clone(&self.correlator)
    }

    /// Evaluates a raw HTTP request byte stream across all 4 parser profiles.
    pub async fn evaluate_raw_stream(&self, raw: &[u8]) -> DifferentialAnalysisReport {
        let stream_id = self.total_streams.fetch_add(1, Ordering::SeqCst) + 1;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Parse across disparate profiles in parallel
        let p_strict = StrictRfc7230Parser::parse(raw);
        let p_legacy = PermissiveLegacyParser::parse(raw);
        let p_cdn = CdnProxyParser::parse(raw);
        let p_micro = AsyncMicroserviceParser::parse(raw);

        // 2. Compute Divergence Metrics
        let mut framing_conflict = false;
        let mut path_divergence = false;
        let mut header_disparity = false;
        let mut line_term_divergence = false;
        let mut anomaly_count = 0;

        let cl_strict = p_strict.content_length.unwrap_or(0);
        let cl_legacy = p_legacy.content_length.unwrap_or(0);
        let cl_cdn = p_cdn.content_length.unwrap_or(0);
        let cl_micro = p_micro.content_length.unwrap_or(0);

        let cls = [cl_strict, cl_legacy, cl_cdn, cl_micro];
        let min_cl = *cls.iter().min().unwrap_or(&0);
        let max_cl = *cls.iter().max().unwrap_or(&0);
        let max_cl_delta = max_cl.saturating_sub(min_cl);

        // Framing conflict: one parser thinks chunked, another thinks Content-Length or differing lengths
        let chunked_flags = [p_strict.is_chunked, p_legacy.is_chunked, p_cdn.is_chunked, p_micro.is_chunked];
        let any_chunked = chunked_flags.iter().any(|&c| c);
        let all_chunked = chunked_flags.iter().all(|&c| c);
        if any_chunked != all_chunked || p_strict.has_ambiguous_framing || max_cl_delta > 0 {
            framing_conflict = true;
        }

        // Path normalization divergence (e.g. traversal tricks %2e%2e, double slashes, semicolon bypasses)
        if !p_strict.normalized_path.is_empty() {
            if p_strict.normalized_path != p_legacy.normalized_path
                || p_strict.normalized_path != p_cdn.normalized_path
            {
                path_divergence = true;
            }
        }

        // Header precedence disparity: check if host or authorization differs
        for key in ["host", "authorization", "x-forwarded-for"] {
            let h_strict = p_strict.headers.get(key);
            let h_legacy = p_legacy.headers.get(key);
            let h_cdn = p_cdn.headers.get(key);
            if h_strict != h_legacy || h_strict != h_cdn {
                header_disparity = true;
                break;
            }
        }

        // Line termination divergence: bare LF or NUL anomalies
        if p_strict.detected_anomalies.iter().any(|a| a.contains("BARE_LF") || a.contains("NUL")) {
            line_term_divergence = true;
        }

        let shared_parser_confusion = p_strict.detected_anomalies.iter().any(|a| a.starts_with("SHARED_PARSER_CONFUSION"));
        let novel_trigger_detected = p_strict.detected_anomalies.iter().any(|a| a.starts_with("NOVEL_DESYNC_TRIGGER"));

        for p in [&p_strict, &p_legacy, &p_cdn, &p_micro] {
            anomaly_count += p.detected_anomalies.len();
        }

        // 3. Compute Composite Novelty Score S in [0.0, 1.0]
        let mut score = 0.0f64;
        if framing_conflict {
            score += 0.55;
        }
        if shared_parser_confusion {
            score += 0.60;
        }
        if novel_trigger_detected {
            score += 0.50;
        }
        if max_cl_delta > 0 {
            score += 0.30;
        }
        if path_divergence {
            score += 0.25;
        }
        if header_disparity {
            score += 0.20;
        }
        if line_term_divergence {
            score += 0.30;
        }
        if anomaly_count > 0 {
            score += (anomaly_count as f64 * 0.05).min(0.25);
        }
        let novelty_score = score.min(1.0);

        // 4. Select Action
        let (action, verdict, quarantined_arm) = if novelty_score >= 0.70 {
            self.total_divergences.fetch_add(1, Ordering::Relaxed);
            self.total_quarantines.fetch_add(1, Ordering::Relaxed);
            (
                DifferentialAction::QuarantineAndSever,
                "HIGH_DIVERGENCE_NOVEL_ATTACK_QUARANTINED",
                Some(106), // Dispatched to Arm ID 106 (DifferentialProtocolAnalyzer)
            )
        } else if novelty_score >= 0.35 {
            self.total_divergences.fetch_add(1, Ordering::Relaxed);
            (
                DifferentialAction::Observe,
                "MODERATE_PARSER_DIVERGENCE_OBSERVED",
                None,
            )
        } else {
            (
                DifferentialAction::Allow,
                "CONCORDANT_STREAM_PERMITTED",
                None,
            )
        };

        let divergence_vector = DivergenceVector {
            max_content_length_delta: max_cl_delta,
            framing_conflict,
            path_normalization_divergence: path_divergence,
            header_precedence_disparity: header_disparity,
            line_termination_divergence: line_term_divergence,
            shared_parser_confusion,
            novel_trigger_detected,
            anomaly_token_count: anomaly_count,
            novelty_score,
        };

        let report = DifferentialAnalysisReport {
            report_id: format!("diff-{}", stream_id),
            timestamp_epoch_secs: now,
            raw_stream_length: raw.len(),
            divergence_vector,
            action,
            primary_verdict: verdict.to_string(),
            parser_interpretations: vec![p_strict, p_legacy, p_cdn, p_micro],
            quarantined_in_arm: quarantined_arm,
        };

        let mut reports = self.recent_reports.write().await;
        if reports.len() >= 100 {
            reports.remove(0);
        }
        reports.push(report.clone());

        report
    }

    /// Returns high-level engine telemetry.
    pub fn get_stats(&self) -> DifferentialEngineStats {
        DifferentialEngineStats {
            total_streams_analyzed: self.total_streams.load(Ordering::Relaxed),
            total_divergence_events: self.total_divergences.load(Ordering::Relaxed),
            total_quarantined_streams: self.total_quarantines.load(Ordering::Relaxed),
            active_profiles_count: 4,
            desync_anomalies_detected: self.correlator.total_desync_count(),
            engine_status: "OPERATIONAL_ACTIVE_CONTAINMENT".to_string(),
        }
    }

    /// Returns recent differential analysis reports.
    pub async fn get_recent_reports(&self) -> Vec<DifferentialAnalysisReport> {
        self.recent_reports.read().await.clone()
    }
}
