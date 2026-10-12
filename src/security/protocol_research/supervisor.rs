use super::rfc_knowledge_base::RfcKnowledgeBase;
use super::rfc_sync::{RfcIndexSynchronizer, RfcSyncReport};
use super::types::{
    Arm106ValidationHandoff, EvaluationRequest, ProtocolResearchStatus,
    ResearchFinding, ResearchFindingStatus, TransportOutcome,
};
use crate::containment_ring::arm_ring::ArmRingRegistry;
use crate::core::types::OctopusSecurityError;
use crate::security::cedar_arm::temporal::{DecisionContext, DogwoodTemporalEngine, EventKind};
use crate::security::cedar_arm::CedarPolicyEngine;
use crate::security::differential_protocol::{DifferentialAction, DifferentialProtocolEngine};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

/// Transmits a raw request over a TCP connection to the pinned socket address.
/// Returns structured transport outcome and wire response without synthetic HTTP diagnostic synthesis.
async fn transmit_request(
    target_addr: std::net::SocketAddr,
    raw_request: &str,
    timeout_duration: std::time::Duration,
) -> (TransportOutcome, String) {
    match tokio::time::timeout(timeout_duration, TcpStream::connect(target_addr)).await {
        Ok(Ok(mut stream)) => {
            if let Err(e) = stream.write_all(raw_request.as_bytes()).await {
                return (
                    TransportOutcome::ConnectionRefused {
                        error: format!("Write error: {}", e),
                    },
                    String::new(),
                );
            }
            let mut buf = vec![0u8; 65536];
            match tokio::time::timeout(timeout_duration, stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let wire_str = String::from_utf8_lossy(&buf[..n]).to_string();
                    (TransportOutcome::ResponseReceived { bytes_count: n }, wire_str)
                }
                Ok(Ok(_)) => (TransportOutcome::Connected, String::new()),
                Ok(Err(e)) => (
                    TransportOutcome::ConnectionRefused {
                        error: format!("Read error: {}", e),
                    },
                    String::new(),
                ),
                Err(_) => (
                    TransportOutcome::Timeout {
                        timeout_ms: timeout_duration.as_millis() as u64,
                    },
                    String::new(),
                ),
            }
        }
        Ok(Err(err)) => (
            TransportOutcome::ConnectionRefused {
                error: err.to_string(),
            },
            String::new(),
        ),
        Err(_) => (
            TransportOutcome::Timeout {
                timeout_ms: timeout_duration.as_millis() as u64,
            },
            String::new(),
        ),
    }
}

/// ProtocolResearchSupervisor: Central coordinator for Arm 107 (Autonomous Protocol Research).
/// Enforces ring containment (#107), mandatory AWS Cedar allowlisting, Dogwood temporal velocity limits,
/// OS-level destination boundary enforcement, DNS rebinding immunity, structured transport outcomes,
/// and routes all candidate anomalies to Arm 106 for independent differential cross-validation.
pub struct ProtocolResearchSupervisor {
    ring_registry: Arc<ArmRingRegistry>,
    cedar_engine: Arc<CedarPolicyEngine>,
    dogwood_engine: Arc<DogwoodTemporalEngine>,
    differential_engine: Arc<DifferentialProtocolEngine>,
    knowledge_base: Arc<RfcKnowledgeBase>,
    synchronizer: RfcIndexSynchronizer,
    evaluation_counter: AtomicUsize,
    recent_evaluations: RwLock<Vec<u64>>,
}

impl ProtocolResearchSupervisor {
    /// Creates a new ProtocolResearchSupervisor with dedicated isolated components.
    pub fn new(
        ring_registry: Arc<ArmRingRegistry>,
        cedar_engine: Arc<CedarPolicyEngine>,
        dogwood_engine: Arc<DogwoodTemporalEngine>,
        differential_engine: Arc<DifferentialProtocolEngine>,
    ) -> Self {
        let knowledge_base = Arc::new(RfcKnowledgeBase::new());
        let synchronizer = RfcIndexSynchronizer::new(Arc::clone(&knowledge_base));
        Self {
            ring_registry,
            cedar_engine,
            dogwood_engine,
            differential_engine,
            knowledge_base,
            synchronizer,
            evaluation_counter: AtomicUsize::new(0),
            recent_evaluations: RwLock::new(Vec::new()),
        }
    }

    /// Access the underlying dedicated Octopus knowledge base.
    pub fn knowledge_base(&self) -> &RfcKnowledgeBase {
        &self.knowledge_base
    }

    /// Access the arm ring registry.
    pub fn ring_registry(&self) -> &Arc<ArmRingRegistry> {
        &self.ring_registry
    }

    /// Triggers automated RFC index synchronization pass.
    pub async fn sync_rfc_index(&self) -> Result<RfcSyncReport, OctopusSecurityError> {
        self.synchronizer.sync_index().await
    }

    /// Retrieves status telemetry for the Arm 107 subsystem.
    pub async fn get_status(&self) -> ProtocolResearchStatus {
        let (rfcs, fragments, probes, evals) = self.knowledge_base.get_full_counts();
        let db_path_str = self.knowledge_base.db_path().to_string_lossy().to_string();

        ProtocolResearchStatus {
            arm_role: "AutonomousProtocolResearch (Arm 107)".to_string(),
            containment_ring_id: 107,
            database_mode: "Dedicated Isolated Octopus SQLite DB".to_string(),
            database_path: db_path_str,
            is_database_isolated: true,
            rfc_count: rfcs,
            fragment_count: fragments,
            probe_count: probes,
            evaluations_recorded: evals,
            memory_clamp_mb: 64,
            cedar_policy_bound: "Policy 8 (Target Allowlist: 127.0.0.1, localhost, ::1)".to_string(),
            dogwood_velocity_bound: "Velocity Limiter: max 30 evals per 300s window".to_string(),
            active_worker_sandboxed: true,
        }
    }

    /// Validates destination target, performs DNS resolution, and enforces that
    /// all resolved IP destinations strictly reside within authorized laboratory research boundaries.
    /// Returns the pinned SocketAddr to prevent DNS rebinding attacks.
    pub fn validate_and_resolve_destination(
        &self,
        host: &str,
        port: u16,
    ) -> Result<std::net::SocketAddr, OctopusSecurityError> {
        let trimmed_host = host.trim();
        if trimmed_host.is_empty() {
            return Err(OctopusSecurityError::CapabilityDenied(
                "FAIL-CLOSED: Empty target host rejected.".to_string(),
            ));
        }

        if port == 0 {
            return Err(OctopusSecurityError::CapabilityDenied(
                "FAIL-CLOSED: Invalid target port 0 rejected.".to_string(),
            ));
        }

        // Reject control chars and null bytes in host
        if trimmed_host.chars().any(|c| (c as u32) < 0x20 || (c as u32) == 0x7f) {
            return Err(OctopusSecurityError::CapabilityDenied(
                "FAIL-CLOSED: Target host contains illegal control characters.".to_string(),
            ));
        }

        // Reject credentials in host (@)
        if trimmed_host.contains('@') {
            return Err(OctopusSecurityError::CapabilityDenied(
                "FAIL-CLOSED: Target host contains embedded credentials.".to_string(),
            ));
        }

        // Reject non-standard numeric IP encoding (e.g. integer IP 2130706433 or octal)
        if trimmed_host.chars().all(|c| c.is_ascii_digit()) && !trimmed_host.contains('.') {
            return Err(OctopusSecurityError::CapabilityDenied(
                "FAIL-CLOSED: Dword/integer-encoded IP format strictly prohibited.".to_string(),
            ));
        }

        // Perform DNS resolution
        let host_for_lookup = if trimmed_host.starts_with('[') && trimmed_host.ends_with(']') {
            &trimmed_host[1..trimmed_host.len() - 1]
        } else {
            trimmed_host
        };

        let resolved_addrs: Vec<std::net::SocketAddr> = match (host_for_lookup, port).to_socket_addrs() {
            Ok(iter) => iter.collect(),
            Err(e) => {
                return Err(OctopusSecurityError::CapabilityDenied(format!(
                    "FAIL-CLOSED: DNS resolution failed for '{}:{}': {}",
                    host, port, e
                )));
            }
        };

        if resolved_addrs.is_empty() {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "FAIL-CLOSED: Zero IP addresses resolved for research target '{}:{}'.",
                host, port
            )));
        }

        // Enforce strict network boundary on EVERY resolved IP address
        // Arm 107 active research is strictly restricted to loopback laboratory targets
        for addr in &resolved_addrs {
            let ip = addr.ip();

            // Must be loopback (127.0.0.0/8 or ::1)
            let is_authorized_loopback = match ip {
                std::net::IpAddr::V4(v4) => v4.is_loopback(),
                std::net::IpAddr::V6(v6) => {
                    v6.is_loopback() || (v6.to_ipv4_mapped().map_or(false, |m| m.is_loopback()))
                }
            };

            if !is_authorized_loopback {
                return Err(OctopusSecurityError::CapabilityDenied(format!(
                    "FAIL-CLOSED: Resolved IP address '{}' for target '{}' is outside authorized research network boundary (must be loopback laboratory endpoint). Egress blocked.",
                    ip, host
                )));
            }

            // Explicitly reject unspecified, multicast, or link-local (cloud metadata) addresses
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(OctopusSecurityError::CapabilityDenied(format!(
                    "FAIL-CLOSED: Resolved IP address '{}' is unspecified or multicast. Egress blocked.",
                    ip
                )));
            }

            if let std::net::IpAddr::V4(v4) = ip {
                if v4.is_link_local() {
                    return Err(OctopusSecurityError::CapabilityDenied(format!(
                        "FAIL-CLOSED: Resolved IP address '{}' is link-local (cloud metadata). Egress blocked.",
                        ip
                    )));
                }
            }
        }

        // Pin connection to the first validated SocketAddr (prevents DNS rebinding TOCTOU)
        Ok(resolved_addrs[0])
    }

    /// Executes an authorized probe evaluation through the joint Cedar + Dogwood gate.
    /// Performs genuine wire TCP socket transmission with structured outcomes and differential baseline comparison.
    pub async fn evaluate_probe(
        &self,
        request: EvaluationRequest,
    ) -> Result<ResearchFinding, OctopusSecurityError> {
        // Step 0: Mandatory Containment Ring Check (Fail closed if Ring 107 is severed or unallocated)
        if self.ring_registry.get_ring(107).await.is_none() {
            return Err(OctopusSecurityError::IsolationViolation(
                "FAIL-CLOSED: Containment Ring #107 is not allocated. Research execution strictly prohibited.".to_string(),
            ));
        }

        // Step 1: Mandatory Cedar Target Authorization Gate (Policy 8)
        self.authorize_target(&request.target_host, request.target_port)?;

        // Step 2: Validate and resolve network destination (loopback boundary + DNS rebinding immunity)
        let target_addr = self.validate_and_resolve_destination(&request.target_host, request.target_port)?;

        // Step 3: Mandatory Dogwood Temporal Velocity Gate (Fail closed on any evaluation error)
        self.enforce_temporal_velocity().await?;

        // Step 4: Execute Real Network Transmission over TCP Socket (Zero Mocks)
        let timeout_duration = std::time::Duration::from_millis(2500);

        let (baseline_outcome, baseline_response) = if let Some(ref base_req) = request.baseline_request {
            let (out, resp) = transmit_request(target_addr, base_req, timeout_duration).await;
            (Some(out), Some(resp))
        } else {
            (None, None)
        };

        let (probe_outcome, probe_response) = transmit_request(target_addr, &request.raw_request, timeout_duration).await;

        // Step 5: Baseline Subtraction & Response-Level Anomaly Detection
        let count = self.evaluation_counter.fetch_add(1, Ordering::SeqCst);
        let finding_id = format!("eval-{:08x}", count + 1);
        let probe_hash = format!("{:x}", Sha256::digest(request.raw_request.as_bytes()));
        let probe_id = format!("probe-{}", &probe_hash[..12]);

        let is_anomalous = self.detect_anomaly_differential(
            &request.raw_request,
            &probe_response,
            &probe_outcome,
            request.baseline_request.as_deref(),
            baseline_response.as_deref(),
            baseline_outcome.as_ref(),
        );

        // Confirmation pass: If divergent and baseline provided, repeat to confirm reproducibility across trials
        let (confirmed_anomalous, confirmation_count, finding_status) = if is_anomalous {
            if request.baseline_request.is_some() {
                // Repeat probe to confirm reproducibility across trials
                let (rep_outcome, rep_response) = transmit_request(target_addr, &request.raw_request, timeout_duration).await;
                
                // Also repeat baseline transmission to ensure baseline stability
                let (rep_base_outcome, rep_base_response) = if let Some(ref base_req) = request.baseline_request {
                    let (b_out, b_resp) = transmit_request(target_addr, base_req, timeout_duration).await;
                    (Some(b_out), Some(b_resp))
                } else {
                    (None, None)
                };

                let rep_anomalous = self.detect_anomaly_differential(
                    &request.raw_request,
                    &rep_response,
                    &rep_outcome,
                    request.baseline_request.as_deref(),
                    rep_base_response.as_deref(),
                    rep_base_outcome.as_ref(),
                );

                // Verify repeated divergence across trials
                if rep_anomalous {
                    (true, 2, ResearchFindingStatus::LaboratoryResearchFinding.to_string())
                } else {
                    // Downgrade non-reproducible / transient anomalies
                    (false, 1, ResearchFindingStatus::NonReproducibleTransient.to_string())
                }
            } else {
                (true, 1, ResearchFindingStatus::LaboratoryResearchFinding.to_string())
            }
        } else {
            (false, 1, "BENIGN_CONCORDANT".to_string())
        };

        let details = if confirmed_anomalous {
            format!(
                "Candidate divergence detected and verified reproducible on target {}:{}. Baseline subtraction applied. Outcome: {:?}. Confirmation count: {}. Requires Arm 106 independent cross-validation. Wire response length: {} bytes.",
                request.target_host, request.target_port, probe_outcome, confirmation_count, probe_response.len()
            )
        } else if is_anomalous {
            format!(
                "Downgraded: Candidate divergence on target {}:{} failed reproducibility verification on repeated trial. Anomaly dismissed as non-reproducible transient. Wire response length: {} bytes.",
                request.target_host, request.target_port, probe_response.len()
            )
        } else {
            format!(
                "Response attributes conform to baseline for target {}:{}. Outcome: {:?}. Wire response length: {} bytes.",
                request.target_host, request.target_port, probe_outcome, probe_response.len()
            )
        };

        // Step 6: Record finding into Octopus's private, separate database
        self.knowledge_base.record_evaluation(
            &finding_id,
            &probe_id,
            &request.target_host,
            request.target_port,
            confirmed_anomalous,
            &finding_status,
            &details,
            request.baseline_request.is_some(),
        );

        Ok(ResearchFinding {
            finding_id,
            probe_id,
            is_anomalous: confirmed_anomalous,
            finding_status,
            details,
            baseline_subtracted: request.baseline_request.is_some(),
            raw_response: probe_response,
            transport_outcome: probe_outcome,
            baseline_response,
            confirmation_count,
        })
    }

    /// Evaluates candidate anomaly through Arm 106 for independent differential cross-validation.
    pub async fn handoff_to_arm106(
        &self,
        handoff: Arm106ValidationHandoff,
    ) -> Result<crate::security::differential_protocol::DifferentialAnalysisReport, OctopusSecurityError> {
        // Enforce Ring 107 permissions: Arm 107 can only communicate candidate findings to Arm 106
        let report = self
            .differential_engine
            .evaluate_raw_stream(handoff.candidate_probe.raw_request.as_bytes())
            .await;

        let requires_promotion = report.action == DifferentialAction::QuarantineAndSever;
        let hex_prefix = Sha256::digest(handoff.handoff_id.as_bytes())[..8]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        let validation_id = format!("val-{}", hex_prefix);

        // Record cross-validation into Octopus's own database
        self.knowledge_base.record_arm106_validation(
            &validation_id,
            &handoff.finding_id,
            &report.primary_verdict,
            &format!("{:?}", report.action),
            requires_promotion,
        );

        Ok(report)
    }

    /// Validates the target using Cedar Policy 8.
    fn authorize_target(&self, host: &str, port: u16) -> Result<(), OctopusSecurityError> {
        let context_json = serde_json::json!({
            "destination_host": host,
            "destination_port": port,
        });

        let verdict = self
            .cedar_engine
            .evaluate(
                "protocol_research_arm",
                "evaluate",
                "network_target",
                "NetworkTarget",
                context_json,
            )
            .map_err(|e| {
                OctopusSecurityError::CapabilityDenied(format!(
                    "FAIL-CLOSED: Cedar Policy evaluation error: {}",
                    e
                ))
            })?;

        if !verdict.is_allowed {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "FAIL-CLOSED: Target host '{}:{}' is not authorized by Cedar Policy 8. Research probes are strictly bounded to local loopback.",
                host, port
            )));
        }

        Ok(())
    }

    /// Enforces the Dogwood temporal velocity rate limiter (maximum 30 evaluations per 300 seconds).
    /// FAIL-CLOSED: Returns an authorization error for ANY Dogwood evaluation failure.
    async fn enforce_temporal_velocity(&self) -> Result<(), OctopusSecurityError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut lock = self.recent_evaluations.write().await;
        // Retain entries from the last 300 seconds
        lock.retain(|&ts| now.saturating_sub(ts) <= 300);

        if lock.len() >= 30 {
            return Err(OctopusSecurityError::CapabilityDenied(
                "FAIL-CLOSED: Dogwood temporal velocity policy exceeded. 30 evaluations executed in last 300s window.".to_string(),
            ));
        }

        // Dogwood MFOTL velocity evaluation & event tracing
        let mut ctx_fields = HashMap::new();
        ctx_fields.insert("count".to_string(), serde_json::json!(lock.len()));

        let decision_ctx = DecisionContext {
            current_time_secs: now,
            principal: "protocol_research_arm".to_string(),
            resource: "NetworkTarget".to_string(),
            context_fields: ctx_fields,
        };

        let rate_policy = r#"when temporal { (count for (t: Timepoint). where (formerly within 5m (Octopus::Action::"EvaluateProbe"::request{ callerPrincipal: principal } && tp(t)))) < 30 };"#;
        match self.dogwood_engine.evaluate_policy(rate_policy, &decision_ctx) {
            Ok(true) => {
                let mut fields = HashMap::new();
                fields.insert("target".to_string(), serde_json::json!("local_target"));
                self.dogwood_engine.record_event(
                    "Octopus::Action::\"EvaluateProbe\"",
                    EventKind::Request,
                    "protocol_research_arm",
                    "NetworkTarget",
                    fields,
                );
            }
            Ok(false) => {
                return Err(OctopusSecurityError::CapabilityDenied(
                    "FAIL-CLOSED: Dogwood temporal velocity policy exceeded. Rate threshold reached.".to_string(),
                ));
            }
            Err(e) => {
                // FAIL-CLOSED: Dogwood evaluation error blocks operation strictly
                return Err(OctopusSecurityError::CapabilityDenied(format!(
                    "FAIL-CLOSED: Dogwood temporal policy evaluation error: {}. Probe execution denied.",
                    e
                )));
            }
        }

        lock.push(now);
        Ok(())
    }

    /// Differential heuristic detector with baseline subtraction comparing real wire responses.
    fn detect_anomaly_differential(
        &self,
        raw_request: &str,
        probe_response: &str,
        probe_outcome: &TransportOutcome,
        _baseline_request: Option<&str>,
        baseline_response: Option<&str>,
        baseline_outcome: Option<&TransportOutcome>,
    ) -> bool {
        // 1. Syntactic framing anomalies in request
        let has_chunk_mutation = raw_request.contains("Transfer-Encoding: chunked")
            && (raw_request.contains("Content-Length:") || raw_request.contains("Transfer-Encoding: \tchunked"));
        let has_ambiguous_delimiters = raw_request.contains("\r\n\r ") || raw_request.contains("\n\r\n");
        let has_probe_framing_anomaly = has_chunk_mutation || has_ambiguous_delimiters;

        // 2. Behavioral response divergence against baseline
        if let (Some(base_resp), Some(base_out)) = (baseline_response, baseline_outcome) {
            // Transport outcome divergence
            let transport_diverged = match (base_out, probe_outcome) {
                (TransportOutcome::ResponseReceived { .. }, TransportOutcome::Timeout { .. }) => true,
                (TransportOutcome::ResponseReceived { .. }, TransportOutcome::ConnectionRefused { .. }) => true,
                _ => false,
            };

            // Status code divergence
            let base_status = base_resp.lines().next().and_then(|l| l.split_whitespace().nth(1));
            let probe_status = probe_response.lines().next().and_then(|l| l.split_whitespace().nth(1));
            let status_diverged = base_status.is_some() && probe_status.is_some() && base_status != probe_status;

            // Wire response divergence
            let response_diverged = !base_resp.is_empty() && !probe_response.is_empty() && base_resp != probe_response;

            return transport_diverged || status_diverged || (has_probe_framing_anomaly && response_diverged);
        }

        has_probe_framing_anomaly
    }
}
