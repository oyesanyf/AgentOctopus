//! Differential Protocol Analysis Engine for Novel HTTP Attack & Desync Detection.
//! Simultaneously evaluates raw ingress streams against multiple disparate HTTP parser profiles,
//! computing a quantitative Divergence Vector and Novelty Risk Score.

use super::desync_correlator::DesyncCorrelator;
use super::parser_profiles::{
    AsyncMicroserviceParser, CdnProxyParser, ParsedProfileInterpretation, PermissiveLegacyParser,
    StrictRfc7230Parser,
};
use crate::containment_ring::arm_ring::ArmRingRegistry;
use crate::security::audit::SecurityAuditLog;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    pub containment_proof_hmac: Option<String>,
    pub quarantined_generation: Option<u64>,
    pub audit_record_hash: Option<String>,
    pub isolation_details: Option<String>,
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
    arm_registry: Option<Arc<ArmRingRegistry>>,
    audit_log: Option<Arc<SecurityAuditLog>>,
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
            arm_registry: None,
            audit_log: None,
        }
    }

    pub fn with_containment(
        arm_registry: Arc<ArmRingRegistry>,
        audit_log: Arc<SecurityAuditLog>,
    ) -> Self {
        Self {
            correlator: Arc::new(DesyncCorrelator::new()),
            recent_reports: Arc::new(RwLock::new(Vec::with_capacity(100))),
            total_streams: Arc::new(AtomicU64::new(0)),
            total_divergences: Arc::new(AtomicU64::new(0)),
            total_quarantines: Arc::new(AtomicU64::new(0)),
            arm_registry: Some(arm_registry),
            audit_log: Some(audit_log),
        }
    }

    pub fn set_containment(
        &mut self,
        arm_registry: Arc<ArmRingRegistry>,
        audit_log: Arc<SecurityAuditLog>,
    ) {
        self.arm_registry = Some(arm_registry);
        self.audit_log = Some(audit_log);
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

        // Framing conflict: chunked vs CL disagreement, ambiguous CL, differing CLs, or header boundary desync
        let chunked_flags = [p_strict.is_chunked, p_legacy.is_chunked, p_cdn.is_chunked, p_micro.is_chunked];
        let any_chunked = chunked_flags.iter().any(|&c| c);
        let all_chunked = chunked_flags.iter().all(|&c| c);
        let boundary_mismatch = (p_strict.header_end_offset > 0 && p_legacy.header_end_offset > 0 && p_strict.header_end_offset != p_legacy.header_end_offset)
            || (p_strict.header_end_offset == 0 && p_legacy.header_end_offset > 0);
        if any_chunked != all_chunked || p_strict.has_ambiguous_framing || max_cl_delta > 0 || boundary_mismatch {
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
        if p_strict.detected_anomalies.iter().any(|a| a.contains("BARE_LF") || a.contains("NUL"))
            || raw.contains(&0)
        {
            line_term_divergence = true;
        }

        let shared_parser_confusion = p_strict.detected_anomalies.iter().any(|a| a.starts_with("SHARED_PARSER_CONFUSION"));
        let novel_trigger_detected = p_strict.detected_anomalies.iter().any(|a| a.starts_with("NOVEL_DESYNC_TRIGGER") || a.contains("NUL"));

        for p in [&p_strict, &p_legacy, &p_cdn, &p_micro] {
            anomaly_count += p.detected_anomalies.len();
        }

        // 3. Compute Composite Novelty Score S in [0.0, 1.0]
        let mut score = 0.0f64;
        if framing_conflict {
            score += 0.65;
        }
        if shared_parser_confusion {
            score += 0.65;
        }
        if novel_trigger_detected {
            score += 0.65;
        }
        if max_cl_delta > 0 {
            score += 0.30;
        }
        if path_divergence {
            score += 0.35;
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

        // 4. Select Action with Calibrated Thresholds & Arm 106 Ring 1 Quarantine
        let report_id = format!("diff-{}", stream_id);
        let mut containment_proof_hmac = None;
        let mut quarantined_generation = None;
        let mut audit_record_hash = None;
        let mut isolation_details = None;

        let (action, verdict, quarantined_arm) = if novelty_score >= 0.65 {
            self.total_divergences.fetch_add(1, Ordering::Relaxed);
            self.total_quarantines.fetch_add(1, Ordering::Relaxed);

            let arm_id = 106; // Dispatched to Arm ID 106 (DifferentialProtocolAnalyzer)
            let mut quarantined_verdict = "HIGH_DIVERGENCE_NOVEL_ATTACK_QUARANTINED";

            // Execute authoritative Ring 1 containment isolation if registry is configured
            if let Some(ref registry) = self.arm_registry {
                let payload_sha256 = hex::encode(Sha256::digest(raw));
                match registry.get_ring_or_fail(arm_id).await {
                    Ok(ring) => {
                        let active_gen = ring.current_generation();
                        match ring.execute_quarantine_containment(
                            &report_id,
                            &payload_sha256,
                            raw.len(),
                            novelty_score,
                        ).await {
                            Ok((hmac_proof, job_name, ac_sid, mem_limit, pid)) => {
                                containment_proof_hmac = Some(hmac_proof.clone());
                                quarantined_generation = Some(active_gen);
                                let iso_details = format!("Windows NT Job Object (64MB) + AppContainer [{}] PID: {}", ac_sid, pid);
                                isolation_details = Some(iso_details.clone());

                                if let Some(ref audit) = self.audit_log {
                                    // Phase 1: AUTHORIZATION_COMPLETED
                                    audit.record_event(
                                        "DIFFERENTIAL_PROTOCOL_ARM106_QUARANTINE",
                                        "arm-DifferentialProtocolAnalyzer-106",
                                        &serde_json::json!({"report_id": report_id, "phase": "AUTHORIZATION_COMPLETED", "epoch": active_gen, "tool": "protocol_analyzer"}).to_string(),
                                        "AUTHORIZATION_COMPLETED"
                                    );

                                    // Phase 2: REQUEST_BLOCKED
                                    audit.record_event(
                                        "DIFFERENTIAL_PROTOCOL_ARM106_QUARANTINE",
                                        "arm-DifferentialProtocolAnalyzer-106",
                                        &serde_json::json!({"report_id": report_id, "phase": "REQUEST_BLOCKED", "connection": "severed"}).to_string(),
                                        "REQUEST_BLOCKED"
                                    );

                                    // Phase 3: PROCESS_ISOLATED
                                    audit.record_event(
                                        "DIFFERENTIAL_PROTOCOL_ARM106_QUARANTINE",
                                        "arm-DifferentialProtocolAnalyzer-106",
                                        &serde_json::json!({
                                            "report_id": report_id,
                                            "phase": "PROCESS_ISOLATED",
                                            "job_object": job_name,
                                            "app_container_sid": ac_sid,
                                            "memory_limit": mem_limit,
                                            "pid": pid,
                                            "containment_proof_hmac": hmac_proof
                                        }).to_string(),
                                        "PROCESS_ISOLATED"
                                    );

                                    let details = serde_json::json!({
                                        "report_id": report_id,
                                        "raw_stream_length": raw.len(),
                                        "payload_sha256": payload_sha256,
                                        "novelty_score": novelty_score,
                                        "quarantined_in_arm": arm_id,
                                        "generation": active_gen,
                                        "containment_proof_hmac": hmac_proof,
                                        "isolation": iso_details,
                                        "framing_conflict": framing_conflict,
                                        "shared_parser_confusion": shared_parser_confusion,
                                        "novel_trigger_detected": novel_trigger_detected,
                                    }).to_string();

                                    let entry_hash = audit.record_event(
                                        "DIFFERENTIAL_PROTOCOL_ARM106_QUARANTINE",
                                        "arm-DifferentialProtocolAnalyzer-106",
                                        &details,
                                        "QUARANTINE_AND_SEVER",
                                    );
                                    audit_record_hash = Some(entry_hash);
                                }
                            }
                            Err(e) => {
                                eprintln!("[CONTAINMENT-FAIL-CLOSED] Arm {} quarantine execution error: {:?}", arm_id, e);
                                quarantined_verdict = "HIGH_DIVERGENCE_QUARANTINE_FAIL_CLOSED";
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[CONTAINMENT-FAIL-CLOSED] Missing mandatory Arm {} ring: {:?}", arm_id, e);
                        quarantined_verdict = "HIGH_DIVERGENCE_MISSING_RING_FAIL_CLOSED";
                    }
                }
            }

            (
                DifferentialAction::QuarantineAndSever,
                quarantined_verdict,
                Some(arm_id),
            )
        } else if novelty_score >= 0.30 {
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
            report_id,
            timestamp_epoch_secs: now,
            raw_stream_length: raw.len(),
            divergence_vector,
            action,
            primary_verdict: verdict.to_string(),
            parser_interpretations: vec![p_strict, p_legacy, p_cdn, p_micro],
            quarantined_in_arm: quarantined_arm,
            containment_proof_hmac,
            quarantined_generation,
            audit_record_hash,
            isolation_details,
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
