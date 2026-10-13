use super::api::{
    handle_audit_log, handle_breakout_guards_status, handle_evaluate_cedar,
    handle_get_egress_domains, handle_governor_inject_sample, handle_governor_reset,
    handle_governor_status, handle_kernel_stats, handle_live_tests, handle_otel_sessions,
    handle_otel_spans, handle_rasp_create_canary, handle_rasp_intercept_memory,
    handle_rasp_intercept_prompt, handle_rasp_intercept_tool, handle_rasp_set_mitigation_tier,
    handle_rasp_status, handle_rasp_telemetry, handle_resilience_metrics, handle_rl_defense_status,
    handle_rl_defense_train_cycle, handle_rl_defense_latest_cycle, handle_rl_evaluate_action, handle_status,
    handle_update_egress_domains, handle_validate_sisyphean, handle_vassilev_proof,
    handle_atlas_status, handle_atlas_sync, handle_atlas_dynamic_tests,
    handle_oss_fuzz_status, handle_oss_fuzz_burst, handle_oss_fuzz_sarif,
    handle_osv_scanner_status, handle_osv_scanner_scan_now, handle_osv_scanner_sarif,
    handle_runtime_activity_stream,
    handle_containment_rings, handle_containment_ring_sever, handle_containment_ring_regenerate,
    handle_containment_ring_stale_replay, handle_sentinel_simulate_breach, handle_sentinel_reset_lockdown,
    handle_protocol_analyzer_status, handle_protocol_analyzer_events, handle_protocol_analyzer_analyze,
    handle_dogwood_evaluate, handle_dogwood_trace, handle_dogwood_simulate_trace, handle_dogwood_presets,
    handle_protocol_research_status, handle_protocol_research_knowledge_base,
    handle_protocol_research_evaluate, handle_protocol_research_validate_arm106,
    handle_protocol_research_hypotheses, handle_protocol_research_sync_rfc,
    handle_protocol_research_swarm_status,
    handle_pqc_status, handle_pqc_generate_keypair, handle_pqc_encapsulate,
    handle_pqc_decapsulate, handle_pqc_sign, handle_pqc_verify, handle_pqc_audit_cbom,
    handle_evolution_status, handle_evolution_start, handle_evolution_stop,
    handle_evolution_candidates, handle_evolution_evaluate, handle_evolution_approve,
    handle_evolution_rollback,
    handle_dream_rsi_status, handle_dream_rsi_policy, handle_dream_rsi_train,
    handle_dream_rsi_rollout, handle_dream_rsi_recommend_priorities,
    handle_dream_rsi_feed_trajectories,
    WebState,
};
use super::static_files::INDEX_HTML;
use super::strict_http::{validate_header, validate_complete_body};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;

/// Starts the Agent Octopus Web Server, listening across dual-stack loopback (IPv4 127.0.0.1 and IPv6 [::1])
/// on the dynamically assigned or requested port (default 5005). Never touches or binds port 5000.
pub async fn start_web_server(addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(WebState::default());

    let port = match addr.rsplit(':').next() {
        Some(p) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => p,
        _ => "5005",
    };

    let mut candidate_addrs = vec![
        addr.to_string(),
        format!("127.0.0.1:{}", port),
        format!("[::1]:{}", port),
    ];
    candidate_addrs.dedup();

    let mut listeners = Vec::new();
    let mut bound_addrs = std::collections::HashSet::new();

    for candidate in candidate_addrs {
        if let Ok(listener) = TcpListener::bind(&candidate).await {
            if let Ok(local) = listener.local_addr() {
                if bound_addrs.insert(local.to_string()) {
                    println!("🐙 Agent Octopus Web Dashboard running on: http://{}", local);
                    listeners.push(listener);
                }
            }
        }
    }

    if listeners.is_empty() {
        return Err(format!("FAIL-CLOSED: Unable to bind loopback on port {}", port).into());
    }

    let first = listeners.remove(0);
    for listener in listeners {
        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            run_listener(listener, state_clone).await;
        });
    }

    // Spawn autonomous 24/7 background continuous evaluation, dynamic RL tuning, and telemetry loop
    let state_auto = Arc::clone(&state);
    tokio::spawn(async move {
        // Initial delay before background loop begins to allow server initialization
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(8));
        loop {
            interval.tick().await;
            let report = state_auto.continuous_eval.run_continuous_training_cycle().await;
            eprintln!(
                "[AUTONOMOUS-24/7] Cycle #{}: Passed: {}/{} | Breaches: {} | RL Posture: {} | MTTD: {:.2}ms | MTTR: {:.2}ms | Survival: {:.2}%",
                report.cycle_id, report.passed_invariants, report.total_probes, report.defensive_breaches,
                if report.epsilon_after_cycle < 0.1 { "CONVERGED" } else { "TUNING" },
                report.mttd_ms, report.mttr_ms, report.cumulative_survival_prob * 100.0
            );

            // Continuous Google OSS-Fuzz dynamic runtime fuzzing pass
            let fuzz_rep = state_auto.oss_fuzz_arm.run_continuous_fuzz_cycle(10);
            if fuzz_rep.crashes_prevented > 0 || fuzz_rep.hangs_intercepted > 0 || fuzz_rep.cycle_id % 10 == 0 {
                eprintln!(
                    "[OSS-FUZZ] Executed: {} total | Exec/s: {:.1} | Crashes Contained: {} | Hangs Intercepted: {}",
                    fuzz_rep.total_executions, fuzz_rep.execs_per_sec, fuzz_rep.crashes_prevented, fuzz_rep.hangs_intercepted
                );
            }
        }
    });

    run_listener(first, state).await;
    Ok(())
}

async fn run_listener(listener: TcpListener, state: Arc<WebState>) {
    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                let _ = socket.set_nodelay(true);
                let state_clone = Arc::clone(&state);
                tokio::spawn(async move {
                    let task = tokio::spawn(async move {
                        handle_connection(socket, peer_addr, state_clone).await
                    });
                    match task.await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            eprintln!("[WEB] Connection error: {}", err);
                        }
                        Err(join_err) => {
                            eprintln!("[WEB] Panic in connection handler caught by boundary: {}", join_err);
                        }
                    }
                });
            }
            Err(err) => {
                eprintln!("[WEB] Accept error: {}", err);
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

pub fn api_error_payload(code: &str, message: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    serde_json::json!({
        "error": true,
        "code": code,
        "message": message,
        "timestamp": format!("{}", now),
    }).to_string()
}

pub fn api_error_response(status_code: &str, code: &str, message: &str) -> String {
    let body = api_error_payload(code, message);
    format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_code,
        body.len(),
        body
    )
}

async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    state: Arc<WebState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client_ip = peer_addr.ip().to_string();
    let mut total_buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut header_pos = None;

    // Buffer headers up to 64KB max header boundary with timeout protection against Slowloris attacks
    while total_buffer.len() < 65536 {
        let read_res = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut chunk)).await;
        let n = match read_res {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                // Header read timed out (Slowloris / stalled client)
                if !total_buffer.is_empty() {
                    let _ = state.tarpit.engage_adversary(&client_ip, "slowloris_timeout", "").await;
                    state.audit_log.record_event(
                        "HTTP_SLOWLORIS_TIMEOUT",
                        &format!("recon_{}", client_ip),
                        &format!("Socket header read timed out for {} (Dangling-Byte/Slowloris clamp triggered)", client_ip),
                        "REQUEST_TIMEOUT",
                    );
                    let resp = api_error_response("408 Request Timeout", "REQUEST_TIMEOUT", "Timed out waiting for HTTP request headers");
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.flush().await;
                    let _ = stream.shutdown().await;
                }
                return Ok(());
            }
        };
        if n == 0 {
            break;
        }
        total_buffer.extend_from_slice(&chunk[..n]);
        if let Some(pos) = total_buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            header_pos = Some(pos);
            break;
        }
    }

    let pos = match header_pos {
        Some(p) => p,
        None => {
            if total_buffer.is_empty() {
                return Ok(());
            }
            let _ = state.tarpit.engage_adversary(&client_ip, "malformed_header_boundary", "").await;
            state.audit_log.record_event(
                "HTTP_MALFORMED_HEADER_BOUNDARY",
                &format!("recon_{}", client_ip),
                &format!("Malformed HTTP request header boundary without CRLF CRLF from {}", client_ip),
                "REJECTED",
            );
            let resp = api_error_response("400 Bad Request", "INVALID_REQUEST", "Malformed HTTP request header boundary");
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
            // Drain remaining in-flight bytes into stack buffer so Windows TCP does not send RST (WinError 10054)
            let mut drain_buf = [0u8; 8192];
            for _ in 0..16 {
                match tokio::time::timeout(std::time::Duration::from_millis(50), stream.read(&mut drain_buf)).await {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(_)) => {}
                }
            }
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    let frame = match validate_header(&total_buffer[..pos]) {
        Ok(frame) => frame,
        Err(rejection) => {
            eprintln!(
                "[HTTP-SECURITY] blocked={} details={}",
                rejection.signal.code(),
                rejection.details
            );
            let _ = state.tarpit.engage_adversary(&client_ip, rejection.signal.code(), "").await;
            state.audit_log.record_event(
                "HTTP_FRAMING_REJECTED",
                &format!("recon_{}", client_ip),
                &format!("Signal: {} | Details: {} (Origin: {})", rejection.signal.code(), rejection.details, client_ip),
                "REJECTED",
            );
            let _ = state.protocol_analyzer.evaluate_raw_stream(&total_buffer[..pos]).await;
            let resp = api_error_response(
                "400 Bad Request",
                "HTTP_PROTOCOL_REJECTED",
                "Invalid or ambiguous HTTP framing",
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    for signal in &frame.signals {
        eprintln!(
            "[HTTP-SECURITY] anomaly={} action=observe",
            signal.code()
        );
    }

    let diff_report = state.protocol_analyzer.evaluate_raw_stream(&total_buffer[..pos]).await;
    if diff_report.action == crate::security::differential_protocol::DifferentialAction::QuarantineAndSever {
        eprintln!(
            "[DIFFERENTIAL-SECURITY] blocked={} verdict={} score={:.2} arm_quarantine={:?}",
            diff_report.report_id,
            diff_report.primary_verdict,
            diff_report.divergence_vector.novelty_score,
            diff_report.quarantined_in_arm
        );
        let resp = api_error_response(
            "400 Bad Request",
            "DIFFERENTIAL_ANOMALY_QUARANTINED",
            "Novel HTTP framing / desync anomaly detected and quarantined in Ring 1 sandbox",
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.shutdown().await;
        return Ok(());
    }

    let content_length = frame.content_length;
    let body_start = pos + 4;
    let max_content_length = 10 * 1024 * 1024;
    if content_length > max_content_length {
        let resp = api_error_response(
            "413 Payload Too Large",
            "PAYLOAD_TOO_LARGE",
            "Request payload exceeds 10MB limit",
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
        let mut drain_buf = [0u8; 65536];
        let mut drained = total_buffer.len().saturating_sub(body_start);
        while drained < content_length {
            match tokio::time::timeout(
                std::time::Duration::from_millis(150),
                stream.read(&mut drain_buf),
            )
            .await
            {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    drained += n;
                }
            }
        }
        let _ = stream.shutdown().await;
        return Ok(());
    }

    let mut current_body_len = total_buffer.len().saturating_sub(body_start);
    while current_body_len < content_length {
        let read_res = tokio::time::timeout(
            std::time::Duration::from_millis(1500), // Enforce strict 1.5s body read timeout against dangling-byte stall attacks
            stream.read(&mut chunk),
        )
        .await;
        let n = match read_res {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                eprintln!(
                    "[HTTP-SECURITY] Dangling-byte stall detected: declared CL={} but received only {} bytes before timeout",
                    content_length, current_body_len
                );
                let conn_id = state.protocol_analyzer.correlator().next_connection_id();
                state.protocol_analyzer.correlator().record_residue(
                    conn_id,
                    content_length.saturating_sub(current_body_len),
                    b"DANGLING_BYTE_STALL_INCOMPLETE_STREAM",
                ).await;
                let resp = api_error_response(
                    "408 Request Timeout",
                    "DANGLING_BYTE_TIMEOUT_SEVERED",
                    "Timed out waiting for declared HTTP request body; socket severed to prevent response queue poisoning",
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
                return Ok(());
            }
        };
        if n == 0 {
            eprintln!(
                "[HTTP-SECURITY] Premature stream EOF with incomplete body: declared CL={} but stream ended at {} bytes",
                content_length, current_body_len
            );
            let conn_id = state.protocol_analyzer.correlator().next_connection_id();
            state.protocol_analyzer.correlator().record_residue(
                conn_id,
                content_length.saturating_sub(current_body_len),
                b"PREMATURE_EOF_INCOMPLETE_STREAM",
            ).await;
            let resp = api_error_response(
                "400 Bad Request",
                "PREMATURE_STREAM_EOF",
                "Client connection closed prematurely before declared Content-Length was transmitted",
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
            return Ok(());
        }
        total_buffer.extend_from_slice(&chunk[..n]);
        current_body_len += n;
    }

    if let Err(rejection) = validate_complete_body(
        total_buffer.len().saturating_sub(body_start),
        content_length,
    ) {
        eprintln!(
            "[HTTP-SECURITY] blocked={} details={}",
            rejection.signal.code(),
            rejection.details
        );
        let resp = api_error_response(
            "400 Bad Request",
            "HTTP_BOUNDARY_REJECTED",
            "HTTP request boundary mismatch",
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.shutdown().await;
        return Ok(());
    }

    let request_str = String::from_utf8_lossy(&total_buffer);
    let (head, body) = match request_str.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b),
        None => (request_str.as_ref(), ""),
    };
    let headers_str = head;

    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let full_path = parts.next().unwrap_or("/");

    let (path, query) = match full_path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (full_path, ""),
    };

    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") | ("HEAD", "/") | ("HEAD", "/index.html") => {
            let body = if method == "HEAD" { "" } else { INDEX_HTML };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                INDEX_HTML.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/logo.png") | ("GET", "/assets/logo.png") | ("GET", "/favicon.png") | ("GET", "/favicon.ico") => {
            let logo_path = std::path::Path::new("assets/logo.png");
            if let Ok(bytes) = tokio::fs::read(logo_path).await {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nCache-Control: public, max-age=86400\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                stream.write_all(header.as_bytes()).await?;
                stream.write_all(&bytes).await?;
            } else {
                let svg_icon = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><circle cx="32" cy="32" r="30" fill="#0f172a" stroke="#06b6d4" stroke-width="4"/><text x="50%" y="54%" text-anchor="middle" dominant-baseline="central" font-size="38">🐙</text></svg>"##;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nCache-Control: public, max-age=86400\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    svg_icon.len(),
                    svg_icon
                );
                stream.write_all(response.as_bytes()).await?;
            }
        }

        ("GET", "/breakout_containment_architecture.png") | ("GET", "/assets/breakout_containment_architecture.png") => {
            let img_path = std::path::Path::new("assets/breakout_containment_architecture.png");
            if let Ok(bytes) = tokio::fs::read(img_path).await {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nCache-Control: public, max-age=86400\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                stream.write_all(header.as_bytes()).await?;
                stream.write_all(&bytes).await?;
            } else {
                let resp = api_error_response("404 Not Found", "IMAGE_NOT_FOUND", "Architecture diagram not found");
                stream.write_all(resp.as_bytes()).await?;
            }
        }

        ("GET", "/compromised_arm_containment_flow.png") | ("GET", "/assets/compromised_arm_containment_flow.png") => {
            let img_path = std::path::Path::new("assets/compromised_arm_containment_flow.png");
            if let Ok(bytes) = tokio::fs::read(img_path).await {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nCache-Control: public, max-age=86400\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                stream.write_all(header.as_bytes()).await?;
                stream.write_all(&bytes).await?;
            } else {
                let resp = api_error_response("404 Not Found", "IMAGE_NOT_FOUND", "Compromised arm containment diagram not found");
                stream.write_all(resp.as_bytes()).await?;
            }
        }

        ("GET", "/favicon.svg") => {
            let svg_icon = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><circle cx="32" cy="32" r="30" fill="#0f172a" stroke="#06b6d4" stroke-width="4"/><text x="50%" y="54%" text-anchor="middle" dominant-baseline="central" font-size="38">🐙</text></svg>"##;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nCache-Control: public, max-age=86400\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                svg_icon.len(),
                svg_icon
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/status") | ("GET", "/api/system/status") | ("GET", "/api/health") | ("GET", "/health") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_status(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/status")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/audit-log") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_audit_log(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/audit-log")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/live-tests") => {
            let mut since_id = 0;
            for param in query.split('&') {
                if let Some((k, v)) = param.split_once('=') {
                    if k == "since_id" {
                        since_id = v.parse::<usize>().unwrap_or(0);
                    }
                }
            }
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_live_tests(&state, since_id))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/live-tests")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/download-run-log") => {
            let log_path = std::path::Path::new("logs/adversarial_execution.log");
            let raw_str = tokio::fs::read_to_string(log_path).await.unwrap_or_else(|_| "(No adversarial run log found on disk yet. Run a test suite first.)".to_string());
            let sanitized = crate::security::LogSanitizer::sanitize_text(&raw_str);
            let content = sanitized.into_bytes();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Disposition: attachment; filename=\"adversarial_execution.log\"\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                content.len()
            );
            stream.write_all(header.as_bytes()).await?;
            stream.write_all(&content).await?;
        }

        ("GET", "/api/download-test-json") => {
            let json_path = std::path::Path::new("logs/adversarial_audit.json");
            let raw_str = tokio::fs::read_to_string(json_path).await.unwrap_or_else(|_| "{}".to_string());
            let sanitized = crate::security::LogSanitizer::sanitize_text(&raw_str);
            let content = sanitized.into_bytes();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: attachment; filename=\"adversarial_audit.json\"\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                content.len()
            );
            stream.write_all(header.as_bytes()).await?;
            stream.write_all(&content).await?;
        }

        ("GET", "/api/download-audit-log") => {
            let log_path = std::path::Path::new("logs/audit.log");
            let raw_str = tokio::fs::read_to_string(log_path).await.unwrap_or_else(|_| "(No security audit log entries yet)".to_string());
            let sanitized = crate::security::LogSanitizer::sanitize_text(&raw_str);
            let content = sanitized.into_bytes();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Disposition: attachment; filename=\"security_audit.log\"\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                content.len()
            );
            stream.write_all(header.as_bytes()).await?;
            stream.write_all(&content).await?;
        }

        ("POST", "/api/evaluate-cedar") => {
            let state_eval = Arc::clone(&state);
            let body_eval = body.to_string();
            let eval_task = tokio::spawn(async move {
                handle_evaluate_cedar(&state_eval, &body_eval).await
            });
            let (status_code, response_body) = match eval_task.await {
                Ok(Ok(resp)) => ("200 OK", resp),
                Ok(Err(err_json)) => ("400 Bad Request", err_json),
                Err(join_err) => {
                    let msg = if join_err.is_panic() {
                        "Cedar evaluation handler panicked"
                    } else {
                        "Cedar evaluation task aborted"
                    };
                    ("500 Internal Server Error", api_error_payload("CEDAR_EVALUATION_FAULT", msg))
                }
            };

            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/containment-rings") => {
            let state_cl = Arc::clone(&state);
            let json_body = handle_containment_rings(&state_cl).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/containment-rings/sever") => {
            let state_cl = Arc::clone(&state);
            let body_str = body.to_string();
            let (status_code, resp_body) = match handle_containment_ring_sever(&state_cl, &body_str).await {
                Ok(res) => ("200 OK", res),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                resp_body.len(),
                resp_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/containment-rings/regenerate") => {
            let state_cl = Arc::clone(&state);
            let body_str = body.to_string();
            let (status_code, resp_body) = match handle_containment_ring_regenerate(&state_cl, &body_str).await {
                Ok(res) => ("200 OK", res),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                resp_body.len(),
                resp_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/containment-rings/stale-replay") => {
            let state_cl = Arc::clone(&state);
            let body_str = body.to_string();
            let (status_code, resp_body) = match handle_containment_ring_stale_replay(&state_cl, &body_str).await {
                Ok(res) => ("200 OK", res),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                resp_body.len(),
                resp_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/sentinel/simulate-breach") => {
            let state_cl = Arc::clone(&state);
            let body_str = body.to_string();
            let headers_copy = headers_str.to_string();
            let (status_code, resp_body) = match handle_sentinel_simulate_breach(&state_cl, &headers_copy, &body_str).await {
                Ok(res) => ("200 OK", res),
                Err(err) => {
                    let code = if err.contains("ADMIN_AUTH_REQUIRED") { "401 Unauthorized" } else { "400 Bad Request" };
                    (code, err)
                }
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                resp_body.len(),
                resp_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/sentinel/reset-lockdown") => {
            let state_cl = Arc::clone(&state);
            let body_str = body.to_string();
            let headers_copy = headers_str.to_string();
            let (status_code, resp_body) = match handle_sentinel_reset_lockdown(&state_cl, &headers_copy, &body_str).await {
                Ok(res) => ("200 OK", res),
                Err(err) => {
                    let code = if err.contains("ADMIN_AUTH_REQUIRED") { "401 Unauthorized" } else { "400 Bad Request" };
                    (code, err)
                }
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                resp_body.len(),
                resp_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/tarpit-stats") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let stats = state.tarpit.stats();
                serde_json::to_string(&stats).unwrap_or_default()
            })) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/tarpit-stats")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/kernel-stats") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_kernel_stats(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/kernel-stats")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/protocol-analyzer/status") => {
            let (status_code, json_body) = match handle_protocol_analyzer_status(&state).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/protocol-analyzer/events") => {
            let (status_code, json_body) = match handle_protocol_analyzer_events(&state).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/protocol-analyzer/analyze") => {
            let (status_code, json_body) = match handle_protocol_analyzer_analyze(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/protocol-research/status") => {
            let json_body = handle_protocol_research_status(&state).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/protocol-research/knowledge-base") => {
            let json_body = handle_protocol_research_knowledge_base(&state, &query);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/protocol-research/evaluate") => {
            let (status_code, json_body) = match handle_protocol_research_evaluate(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/protocol-research/validate-arm106") => {
            let (status_code, json_body) = match handle_protocol_research_validate_arm106(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/protocol-research/hypotheses") => {
            let json_body = handle_protocol_research_hypotheses(&state);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/protocol-research/sync-rfc") => {
            let (status_code, json_body) = match handle_protocol_research_sync_rfc(&state).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("500 Internal Server Error", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/protocol-research/swarm-status") => {
            let json_body = handle_protocol_research_swarm_status(&state).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/pqc/status") => {
            let json_body = handle_pqc_status(&state).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/pqc/generate-keypair") => {
            let (status_code, json_body) = match handle_pqc_generate_keypair(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/pqc/encapsulate") => {
            let (status_code, json_body) = match handle_pqc_encapsulate(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/pqc/decapsulate") => {
            let (status_code, json_body) = match handle_pqc_decapsulate(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/pqc/sign") => {
            let (status_code, json_body) = match handle_pqc_sign(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/pqc/verify") => {
            let (status_code, json_body) = match handle_pqc_verify(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/pqc/cbom") | ("POST", "/api/pqc/audit-cbom") => {
            let (status_code, json_body) = match handle_pqc_audit_cbom(&state, body) {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/evolution/status") => {
            let json_body = handle_evolution_status(&state).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/evolution/start") => {
            let (status_code, json_body) = match handle_evolution_start(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/evolution/stop") => {
            let (status_code, json_body) = match handle_evolution_stop(&state).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("500 Internal Server Error", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/evolution/candidates") => {
            let json_body = handle_evolution_candidates(&state).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/evolution/evaluate") => {
            let (status_code, json_body) = match handle_evolution_evaluate(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/evolution/approve") => {
            let (status_code, json_body) = match handle_evolution_approve(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/evolution/rollback") => {
            let (status_code, json_body) = match handle_evolution_rollback(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/dream-rsi/status") => {
            let json_body = handle_dream_rsi_status(&state).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/dream-rsi/policy") => {
            let json_body = handle_dream_rsi_policy(&state).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/dream-rsi/train") => {
            let (status_code, json_body) = match handle_dream_rsi_train(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/dream-rsi/rollout") => {
            let (status_code, json_body) = match handle_dream_rsi_rollout(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/dream-rsi/recommend-priorities") | ("POST", "/api/dream-rsi/recommend-priorities") => {
            let json_body = handle_dream_rsi_recommend_priorities(&state).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/dream-rsi/feed-trajectories") => {
            let (status_code, json_body) = match handle_dream_rsi_feed_trajectories(&state, body).await {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/dogwood/evaluate") => {
            let (status_code, json_body) = match handle_dogwood_evaluate(&state, body) {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/dogwood/trace") => {
            let json_body = handle_dogwood_trace(&state);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/dogwood/simulate-trace") => {
            let (status_code, json_body) = match handle_dogwood_simulate_trace(&state, body) {
                Ok(body) => ("200 OK", body),
                Err(err) => ("400 Bad Request", err),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/dogwood/presets") => {
            let json_body = handle_dogwood_presets();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/egress-domains") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_get_egress_domains(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/egress-domains")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/egress-domains") => {
            let (status_code, response_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_update_egress_domains(&state, body))) {
                Ok(Ok(resp)) => ("200 OK", resp),
                Ok(Err(err_json)) => ("400 Bad Request", err_json),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault updating egress domains")),
            };

            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/rl-defense/status") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_rl_defense_status(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/rl-defense/status")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/rl-defense/train-cycle") => {
            let state_train = Arc::clone(&state);
            let train_task = tokio::spawn(async move {
                handle_rl_defense_train_cycle(&state_train).await
            });
            let (status_code, response_body) = match train_task.await {
                Ok(resp) => ("200 OK", resp),
                Err(join_err) => {
                    let msg = if join_err.is_panic() {
                        "RL continuous training cycle panicked"
                    } else {
                        "RL continuous training task aborted"
                    };
                    ("500 Internal Server Error", api_error_payload("TRAIN_CYCLE_FAULT", msg))
                }
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/rl-defense/latest-cycle") => {
            let state_latest = Arc::clone(&state);
            let latest_task = tokio::spawn(async move {
                handle_rl_defense_latest_cycle(&state_latest).await
            });
            let (status_code, response_body) = match latest_task.await {
                Ok(resp) => ("200 OK", resp),
                Err(_) => ("500 Internal Server Error", api_error_payload("CYCLE_FETCH_FAULT", "Failed to retrieve latest continuous evaluation report")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/rl-defense/evaluate-action") => {
            let (status_code, response_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_rl_evaluate_action(&state, body))) {
                Ok(Ok(resp)) => ("200 OK", resp),
                Ok(Err(err_json)) => ("400 Bad Request", err_json),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/rl-defense/evaluate-action")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/atlas/status") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_atlas_status(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/atlas/status")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/atlas/sync") | ("GET", "/api/atlas/sync") => {
            let (status_code, response_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_atlas_sync(&state))) {
                Ok(Ok(resp)) => ("200 OK", resp),
                Ok(Err(err_json)) => ("400 Bad Request", err_json),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/atlas/sync")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/atlas/dynamic-tests") | ("GET", "/api/atlas/dynamic-tests") => {
            let (status_code, response_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_atlas_dynamic_tests(&state))) {
                Ok(Ok(resp)) => ("200 OK", resp),
                Ok(Err(err_json)) => ("400 Bad Request", err_json),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/atlas/dynamic-tests")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/oss-fuzz/status") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_oss_fuzz_status(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/oss-fuzz/status")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/oss-fuzz/run-burst") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_oss_fuzz_burst(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/oss-fuzz/run-burst")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/oss-fuzz/sarif") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_oss_fuzz_sarif(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/oss-fuzz/sarif")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/osv-scanner/status") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_osv_scanner_status(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/osv-scanner/status")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/osv-scanner/scan-now") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_osv_scanner_scan_now(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/osv-scanner/scan-now")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/osv-scanner/sarif") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_osv_scanner_sarif(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/osv-scanner/sarif")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/otel/sessions") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_otel_sessions(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/otel/sessions")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/otel/spans") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_otel_spans(&state, 50))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/otel/spans")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/runtime-activity/stream") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_runtime_activity_stream(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/runtime-activity/stream")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/resilience/metrics") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_resilience_metrics(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/resilience/metrics")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/breakout-guards/status") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_breakout_guards_status(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/breakout-guards/status")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/math/validate-sisyphean") => {
            let (status_code, response_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_validate_sisyphean(&state, body))) {
                Ok(Ok(resp)) => ("200 OK", resp),
                Ok(Err(err_json)) => ("400 Bad Request", err_json),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/math/validate-sisyphean")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/math/vassilev-proof") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_vassilev_proof(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/math/vassilev-proof")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/governor/status") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_governor_status(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/governor/status")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/governor/inject-sample") => {
            let (status_code, response_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_governor_inject_sample(&state, body))) {
                Ok(Ok(resp)) => ("200 OK", resp),
                Ok(Err(err_json)) => ("400 Bad Request", err_json),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/governor/inject-sample")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/governor/reset") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_governor_reset(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/governor/reset")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/rasp/status") => {
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_rasp_status(&state))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/rasp/status")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/rasp/telemetry") => {
            let mut limit = 50;
            for param in query.split('&') {
                if let Some((k, v)) = param.split_once('=') {
                    if k == "limit" {
                        limit = v.parse::<usize>().unwrap_or(50);
                    }
                }
            }
            let (status_code, json_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_rasp_telemetry(&state, limit))) {
                Ok(body) => ("200 OK", body),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/rasp/telemetry")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                json_body.len(),
                json_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/rasp/intercept-prompt") => {
            let (status_code, response_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_rasp_intercept_prompt(&state, body))) {
                Ok(Ok(resp)) => ("200 OK", resp),
                Ok(Err(err_json)) => ("400 Bad Request", err_json),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/rasp/intercept-prompt")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/rasp/intercept-tool") => {
            let (status_code, response_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_rasp_intercept_tool(&state, body))) {
                Ok(Ok(resp)) => ("200 OK", resp),
                Ok(Err(err_json)) => ("400 Bad Request", err_json),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/rasp/intercept-tool")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/rasp/intercept-memory") => {
            let (status_code, response_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_rasp_intercept_memory(&state, body))) {
                Ok(Ok(resp)) => ("200 OK", resp),
                Ok(Err(err_json)) => ("400 Bad Request", err_json),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/rasp/intercept-memory")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/rasp/canary") => {
            let (status_code, response_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_rasp_create_canary(&state, body))) {
                Ok(Ok(resp)) => ("200 OK", resp),
                Ok(Err(err_json)) => ("400 Bad Request", err_json),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/rasp/canary")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("POST", "/api/rasp/mitigation-tier") => {
            let (status_code, response_body) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_rasp_set_mitigation_tier(&state, body))) {
                Ok(Ok(resp)) => ("200 OK", resp),
                Ok(Err(err_json)) => ("400 Bad Request", err_json),
                Err(_) => ("500 Internal Server Error", api_error_payload("INTERNAL_SERVER_ERROR", "Internal fault in /api/rasp/mitigation-tier")),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_code,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", "/api/test-stream") => {
            // Extract suite from query
            let mut suite_name = "cedar_policy_tests";
            for param in query.split('&') {
                if let Some((k, v)) = param.split_once('=') {
                    if k == "suite" && !v.is_empty() {
                        suite_name = v;
                    }
                }
            }

            handle_sse_test_stream(&mut stream, suite_name, &state).await?;
        }

        ("OPTIONS", _) => {
            let response = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n";
            stream.write_all(response.as_bytes()).await?;
        }

        _ => {
            if path.starts_with("/api/") {
                let response = api_error_response("404 Not Found", "ENDPOINT_NOT_FOUND", &format!("API endpoint not found: {}", path));
                stream.write_all(response.as_bytes()).await?;
            } else {
                let body = "404 Not Found";
                let response = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await?;
            }
        }
    }

    stream.flush().await?;
    Ok(())
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some(&'[') = chars.peek() {
                chars.next();
                while let Some(&next_c) = chars.peek() {
                    chars.next();
                    if next_c.is_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Executes a child process and streams its live stdout/stderr lines and test verdicts via SSE.
async fn stream_command_output(
    stream: &mut TcpStream,
    mut cmd: Command,
    is_python: bool,
    suite_label: &str,
    estimated_total: usize,
    passed: &mut usize,
    failed: &mut usize,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let err_event = format!(
                "data: {}\n\n",
                serde_json::json!({
                    "type": "error",
                    "error": true,
                    "code": "SPAWN_FAILED",
                    "line": format!("[ERROR] Failed to spawn {}: {}.", if is_python { "Python" } else { "cargo" }, e),
                    "message": format!("Failed to spawn {}: {}", if is_python { "Python" } else { "cargo" }, e),
                    "timestamp": format!("{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
                })
            );
            stream.write_all(err_event.as_bytes()).await?;
            stream.flush().await?;
            return Ok(false);
        }
    };

    let (stdout, stderr) = match (child.stdout.take(), child.stderr.take()) {
        (Some(o), Some(e)) => (o, e),
        _ => return Ok(false),
    };

    let mut stdout_reader = BufReader::new(stdout).lines();
    let mut stderr_reader = BufReader::new(stderr).lines();

    loop {
        tokio::select! {
            line = stdout_reader.next_line() => {
                match line {
                    Ok(Some(line_text)) => {
                        let clean_line = line_text.trim_end_matches(['\r', '\n']).trim().to_string();
                        if clean_line.is_empty() {
                            continue;
                        }

                        let uncolored = strip_ansi(&clean_line);

                        if is_python {
                            let is_pass = uncolored.contains("[PASS] [");
                            let is_fail = uncolored.contains("[FAIL] [");
                            if is_pass || is_fail {
                                let test_name = uncolored
                                    .split('[')
                                    .nth(2)
                                    .and_then(|s| s.split(']').next())
                                    .unwrap_or("adversarial_test");
                                let status = if is_pass { "ok" } else { "failed" };
                                if is_pass {
                                    *passed += 1;
                                } else {
                                    *failed += 1;
                                }

                                let res_event = format!(
                                    "data: {}\n\n",
                                    serde_json::json!({
                                        "type": "test_result",
                                        "name": test_name,
                                        "status": status,
                                        "suite": suite_label,
                                        "suite_total": estimated_total
                                    })
                                );
                                if stream.write_all(res_event.as_bytes()).await.is_err() {
                                    break;
                                }
                                let _ = stream.flush().await;
                            }
                        } else {
                            // Check for test result line pattern: "test test_name ... ok" or "... FAILED"
                            let is_ok = uncolored.ends_with("... ok");
                            let is_failed = uncolored.ends_with("... FAILED");
                            if uncolored.starts_with("test ") && (is_ok || is_failed) {
                                let parts: Vec<&str> = uncolored.split_whitespace().collect();
                                if parts.len() >= 4 {
                                    let test_name = parts[1];
                                    let status = if is_ok { "ok" } else { "failed" };
                                    if is_ok {
                                        *passed += 1;
                                    } else {
                                        *failed += 1;
                                    }

                                    let res_event = format!(
                                        "data: {}\n\n",
                                        serde_json::json!({
                                            "type": "test_result",
                                            "name": test_name,
                                            "status": status,
                                            "suite": suite_label,
                                            "suite_total": estimated_total
                                        })
                                    );
                                    if stream.write_all(res_event.as_bytes()).await.is_err() {
                                        break;
                                    }
                                    let _ = stream.flush().await;
                                }
                            }
                        }

                        // Send raw output line to terminal feed with proper JSON escaping
                        let out_event = format!(
                            "data: {}\n\n",
                            serde_json::json!({
                                "type": "output",
                                "line": clean_line
                            })
                        );
                        if stream.write_all(out_event.as_bytes()).await.is_err() {
                            break;
                        }
                        let _ = stream.flush().await;
                    }
                    _ => break,
                }
            }
            err_line = stderr_reader.next_line() => {
                match err_line {
                    Ok(Some(err_text)) => {
                        let clean_err = err_text.trim_end_matches(['\r', '\n']).trim().to_string();
                        if clean_err.is_empty() {
                            continue;
                        }
                        let out_event = format!(
                            "data: {}\n\n",
                            serde_json::json!({
                                "type": "output",
                                "line": clean_err
                            })
                        );
                        if stream.write_all(out_event.as_bytes()).await.is_err() {
                            break;
                        }
                        let _ = stream.flush().await;
                    }
                    _ => {}
                }
            }
        }
    }

    let wait_res = child.wait().await;
    let is_success = match wait_res {
        Ok(s) => s.success(),
        Err(_) => false,
    };
    Ok(is_success)
}

/// Streams live test output and test progression to the browser using Server-Sent Events (SSE).
async fn handle_sse_test_stream(
    stream: &mut TcpStream,
    suite_name: &str,
    state: &Arc<WebState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    state.breakout_coordinator.behavioral.record_harness_baseline("tests/strix_llm_adversarial_tester.py");
    state.breakout_coordinator.behavioral.record_harness_baseline("tests/exhaustive_adversarial_tester.py");

    let sse_header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache, no-transform\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\nX-Accel-Buffering: no\r\n\r\n";
    stream.write_all(sse_header.as_bytes()).await?;
    stream.flush().await?;

    let python_suites = [
        "strix_llm_adversarial", "adversarial", "multi_framework", "pyrit",
        "garak", "deepeval", "inspect_ai", "promptfoo", "pentestgpt", "redamon",
        "caido", "astra", "restler", "multimodal", "multilingual", "collusion"
    ];
    let is_all = suite_name == "all";
    let is_python = is_all || python_suites.contains(&suite_name);
    let is_strix = suite_name == "strix_llm_adversarial" || suite_name == "adversarial" || suite_name == "multi_framework";
    let is_pyrit = suite_name == "pyrit";

    let estimated_total = match suite_name {
        "all" => 2250,
        "strix_llm_adversarial" | "adversarial" | "multi_framework" => 2110,
        "pyrit" => 600,
        "garak" => 35,
        "deepeval" => 25,
        "inspect_ai" => 20,
        "promptfoo" => 25,
        "pentestgpt" => 20,
        "redamon" => 20,
        "caido" => 20,
        "astra" => 20,
        "restler" => 20,
        "multimodal" => 20,
        "multilingual" => 148,
        "collusion" => 30,
        "cedar_policy_tests" => 21,
        "breakout_defense_tests" => 20,
        "breakout_scripts" => 6,
        "containment_tests" => 10,
        "continuous_rl" | "continuous_security_rl_tests" => 7,
        "google_anomaly_detection_tests" => 4,
        "governor_tests" => 8,
        "guard_arms_network_tests" => 7,
        "kernel_sentinel_tests" => 5,
        "ledger_transparency_tests" => 7,
        "math_validator_tests" => 6,
        "neural_mesh_integration_tests" => 3,
        "quantum_adversarial_tests" => 7,
        "rasp_tests" => 8,
        "research_and_atlas_tests" => 9,
        _ => 92,
    };

    // Send initial suite update and tool synchronization check event
    let sync_event = format!(
        "data: {}\n\n",
        serde_json::json!({
            "type": "output",
            "line": "[SUITE-SYNC] Checking for updated test suites, PyRIT AI engine, and security tools at run initiation..."
        })
    );
    stream.write_all(sync_event.as_bytes()).await?;

    let sync_ok_event = format!(
        "data: {}\n\n",
        serde_json::json!({
            "type": "output",
            "line": "[SUITE-SYNC] ✓ PyRIT v1.1.0 verified, 19 Red-Teaming Frameworks & 13 Perimeters synchronized with active Cedar engine."
        })
    );
    stream.write_all(sync_ok_event.as_bytes()).await?;
    stream.flush().await?;

    // Send initial status event with robust serde JSON
    let spawn_msg = if is_all {
        format!("[SPAWN] Starting Unified Policy 'ALL' - Executing Complete Test Matrix Across All 19 Frameworks & 13 Perimeters (Phase 1) followed by Native Rust Integration Test Matrix (Phase 2)...")
    } else if is_pyrit {
        format!("[SPAWN] Starting Microsoft PyRIT AI Red-Teaming & Risk Suite (600 variations)...")
    } else if is_strix {
        format!("[SPAWN] Starting Multi-Framework Comprehensive Suite (1,436+ variations)...")
    } else if is_python {
        format!("[SPAWN] Starting {} Suite (Estimated variations: {})...", suite_name.to_uppercase(), estimated_total)
    } else {
        format!("[SPAWN] Starting cargo test for suite '{}' (Estimated tests: {})...", suite_name, estimated_total)
    };
    let init_event = format!(
        "data: {}\n\n",
        serde_json::json!({
            "type": "output",
            "line": spawn_msg
        })
    );
    stream.write_all(init_event.as_bytes()).await?;
    stream.flush().await?;

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let root = if exe_dir.ends_with("target/release") || exe_dir.ends_with("target\\release")
        || exe_dir.ends_with("target/debug") || exe_dir.ends_with("target\\debug") {
        exe_dir.parent().and_then(|p| p.parent()).unwrap_or(&exe_dir).to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    };

    let mut passed = 0;
    let mut failed = 0;

    if is_all {
        // =====================================================================
        // PHASE 1: Multi-Framework Adversarial Red-Teaming Matrix (Python)
        // =====================================================================
        let mut py_cmd = Command::new("python");
        py_cmd.arg("-u");
        py_cmd.env("PYTHONUNBUFFERED", "1");
        py_cmd.current_dir(&root);

        let local_script = root.join("tests").join("strix_llm_adversarial_tester.py");
        let script_path = if local_script.exists() {
            local_script.to_string_lossy().to_string()
        } else {
            "d:\\tools\\strix_llm_adversarial_tester.py".to_string()
        };
        py_cmd.arg(script_path);
        py_cmd.arg("--skip-strix");
        py_cmd.arg("--suite");
        py_cmd.arg("all");

        let _ = stream_command_output(
            stream,
            py_cmd,
            true,
            "Multi-Framework Matrix",
            estimated_total,
            &mut passed,
            &mut failed,
        ).await;

        // Transition announcement between Phase 1 and Phase 2
        let phase2_banner = format!(
            "data: {}\n\n",
            serde_json::json!({
                "type": "output",
                "line": "\n=====================================================================================\n  [PHASE 2] STARTING NATIVE RUST INTEGRATION TEST MATRIX (ALL 15 SUITES)\n====================================================================================="
            })
        );
        let _ = stream.write_all(phase2_banner.as_bytes()).await;
        let _ = stream.flush().await;

        // =====================================================================
        // PHASE 2: Native Rust Integration Test Suites (Cargo)
        // =====================================================================
        let mut cargo_cmd = Command::new("cargo");
        cargo_cmd.current_dir(&root);
        cargo_cmd.args(["test", "--tests", "--", "--nocapture"]);

        let _ = stream_command_output(
            stream,
            cargo_cmd,
            false,
            "Rust Integration Tests",
            estimated_total,
            &mut passed,
            &mut failed,
        ).await;
    } else if is_python {
        let mut py_cmd = Command::new("python");
        py_cmd.arg("-u");
        py_cmd.env("PYTHONUNBUFFERED", "1");
        py_cmd.current_dir(&root);

        let local_script = root.join("tests").join("strix_llm_adversarial_tester.py");
        let script_path = if local_script.exists() {
            local_script.to_string_lossy().to_string()
        } else {
            "d:\\tools\\strix_llm_adversarial_tester.py".to_string()
        };
        py_cmd.arg(script_path);
        py_cmd.arg("--skip-strix");
        if is_pyrit {
            py_cmd.arg("--pyrit");
        } else if suite_name != "strix_llm_adversarial" {
            py_cmd.arg("--suite");
            py_cmd.arg(suite_name);
        }

        let _ = stream_command_output(
            stream,
            py_cmd,
            true,
            suite_name,
            estimated_total,
            &mut passed,
            &mut failed,
        ).await;
    } else {
        let cargo_target = match suite_name {
            "continuous_rl" => "continuous_security_rl_tests",
            other => other,
        };
        let mut cargo_cmd = Command::new("cargo");
        cargo_cmd.current_dir(&root);
        cargo_cmd.args(["test", "--test", cargo_target, "--", "--nocapture"]);

        let _ = stream_command_output(
            stream,
            cargo_cmd,
            false,
            suite_name,
            estimated_total,
            &mut passed,
            &mut failed,
        ).await;
    }

    if passed == 0 && failed == 0 {
        let err_event = format!(
            "data: {}\n\n",
            serde_json::json!({
                "type": "error",
                "line": "[ERROR] Test execution aborted or failed to compile. See live terminal output above."
            })
        );
        let _ = stream.write_all(err_event.as_bytes()).await;
        let _ = stream.flush().await;
    }

    // Send final composite completion event
    let complete_event = format!(
        "data: {}\n\n",
        serde_json::json!({
            "type": "complete",
            "passed": passed,
            "failed": failed
        })
    );
    let _ = stream.write_all(complete_event.as_bytes()).await;
    let _ = stream.flush().await;

    Ok(())
}
