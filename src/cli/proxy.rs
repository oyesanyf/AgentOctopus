use crate::cli::policy::{is_bare_or_port_wildcard, LoadedOctopusPolicy};
use crate::containment_ring::egress_proxy::{
    is_non_standard_ip_host_encoding, is_restricted_rebinding_ip,
};
use crate::security::cedar_arm::CedarPolicyEngine;
use crate::security::host_network_isolation::is_blocked_quarantine_port;
use crate::security::safeagents_client::{
    host_port_pattern_matches, is_denied_resolved_ip_with_local, local_host_interface_ips,
    resolve_and_pin_allowed_host, validate_http_request_target, CredentialSentinelMasker, IpCidr,
};
use crate::security::semantic_dlp::SemanticDlpEngine;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressEventRecord {
    pub decision: String,
    pub method: String,
    pub target: String,
    pub status: u16,
    pub reason: String,
}

#[derive(Clone)]
struct RegisteredSecretTracker {
    env_name: String,
    sentinel: String,
    real_secret: Zeroizing<String>,
    inject_hosts: Vec<String>,
    allow_plaintext_inject: bool,
}

struct ProxyState {
    proxy_port: u16,
    cedar_ipc_port: Option<u16>,
    is_standalone_cedar: bool,
    allowed_domains: Vec<String>,
    denied_domains: Vec<String>,
    denied_cidrs: Vec<IpCidr>,
    cedar_engine: Option<CedarPolicyEngine>,
    masker: CredentialSentinelMasker,
    secrets: Vec<RegisteredSecretTracker>,
    local_ips: Vec<IpAddr>,
    events: Mutex<Vec<EgressEventRecord>>,
    quiet_stderr: bool,
}

pub struct LoopbackProxyHandle {
    pub port: u16,
    pub child_env: Vec<(String, String)>,
    state: Arc<ProxyState>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl LoopbackProxyHandle {
    pub fn events_snapshot(&self) -> Vec<EgressEventRecord> {
        self.state
            .events
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(jh) = self.join_handle.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), jh).await;
        }
    }
}

pub async fn start_loopback_proxy(
    policy: &LoadedOctopusPolicy,
    quiet_stderr: bool,
    cedar_ipc_port: Option<u16>,
) -> Result<LoopbackProxyHandle, String> {
    let mut kept_listeners = Vec::new();
    let mut chosen_listener = None;
    for _ in 0..32 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("failed to bind loopback proxy on 127.0.0.1:0: {}", e))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("failed to inspect loopback proxy addr: {}", e))?
            .port();
        if !is_blocked_quarantine_port(port) {
            chosen_listener = Some((listener, port));
            break;
        }
        kept_listeners.push(listener);
    }
    drop(kept_listeners);

    let (listener, proxy_port) = chosen_listener.ok_or_else(|| {
        "failed to allocate non-quarantined ephemeral port for loopback proxy".to_string()
    })?;

    let masker = CredentialSentinelMasker::new();
    let mut secrets = Vec::new();
    let inject_hosts = policy.json_policy.credentials.inject_hosts.clone();
    let allow_plaintext = policy.json_policy.credentials.allow_plaintext_inject;

    for env_name in &policy.json_policy.credentials.mask_env {
        let trimmed = env_name.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(real_secret) = std::env::var(trimmed) {
            if !real_secret.is_empty() {
                let reg_hosts = if inject_hosts.is_empty() {
                    vec!["__octopus_never_inject__.invalid".to_string()]
                } else {
                    inject_hosts.clone()
                };
                let sentinel = masker
                    .register_masked_credential(trimmed, &real_secret, reg_hosts, allow_plaintext)
                    .map_err(|e| format!("failed to mask credential '{}': {}", trimmed, e))?;
                secrets.push(RegisteredSecretTracker {
                    env_name: trimmed.to_string(),
                    sentinel,
                    real_secret: Zeroizing::new(real_secret),
                    inject_hosts: inject_hosts.clone(),
                    allow_plaintext_inject: allow_plaintext,
                });
            }
        }
    }

    let parent_env: Vec<(String, String)> = std::env::vars().collect();
    let mut child_env = masker.sanitized_child_env(&parent_env);
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);

    child_env.retain(|(k, _)| {
        !matches!(
            k.to_ascii_uppercase().as_str(),
            "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY"
        )
    });
    child_env.push(("HTTP_PROXY".to_string(), proxy_url.clone()));
    child_env.push(("HTTPS_PROXY".to_string(), proxy_url.clone()));
    child_env.push(("ALL_PROXY".to_string(), proxy_url.clone()));
    child_env.push(("http_proxy".to_string(), proxy_url.clone()));
    child_env.push(("https_proxy".to_string(), proxy_url));
    child_env.push(("NO_PROXY".to_string(), String::new()));
    child_env.push(("no_proxy".to_string(), String::new()));

    let cedar_engine =
        if policy.cedar_engine.is_some() {
            if policy.is_standalone_cedar {
                let txt = std::fs::read_to_string(&policy.policy_path)
                    .map_err(|e| format!("failed to reload Cedar policy: {}", e))?;
                Some(
                    CedarPolicyEngine::from_validated_policy_set(&txt)
                        .map_err(|e| format!("failed to compile Cedar policy: {}", e))?,
                )
            } else {
                let mut chunks = Vec::new();
                if let Some(ref cf) = policy.json_policy.cedar_file {
                    let p = if std::path::Path::new(cf).is_absolute() {
                        std::path::PathBuf::from(cf)
                    } else {
                        policy
                            .policy_path
                            .parent()
                            .map(|par| par.join(cf))
                            .unwrap_or_else(|| std::path::PathBuf::from(cf))
                    };
                    chunks.push(std::fs::read_to_string(&p).map_err(|e| {
                        format!("failed to read cedar_file '{}': {}", p.display(), e)
                    })?);
                }
                if let Some(ref inline) = policy.json_policy.cedar_policy {
                    chunks.push(inline.clone());
                }
                if chunks.is_empty() {
                    None
                } else {
                    Some(
                        CedarPolicyEngine::from_validated_policy_set(&chunks.join("\n"))
                            .map_err(|e| format!("failed to compile Cedar policy: {}", e))?,
                    )
                }
            }
        } else {
            None
        };

    let state = Arc::new(ProxyState {
        proxy_port,
        cedar_ipc_port,
        is_standalone_cedar: policy.is_standalone_cedar,
        allowed_domains: policy.json_policy.allowed_domains.clone(),
        denied_domains: policy.json_policy.denied_domains.clone(),
        denied_cidrs: policy.denied_cidrs.clone(),
        cedar_engine,
        masker,
        secrets,
        local_ips: local_host_interface_ips(),
        events: Mutex::new(Vec::new()),
        quiet_stderr,
    });

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let state_loop = state.clone();
    let join_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, _peer)) => {
                            let st = state_loop.clone();
                            tokio::spawn(async move {
                                handle_proxy_connection(stream, st).await;
                            });
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    Ok(LoopbackProxyHandle {
        port: proxy_port,
        child_env,
        state,
        shutdown_tx: Some(shutdown_tx),
        join_handle: Some(join_handle),
    })
}

fn record_event(
    state: &ProxyState,
    decision: &str,
    method: &str,
    target: &str,
    status: u16,
    reason: &str,
) {
    if let Ok(mut g) = state.events.lock() {
        g.push(EgressEventRecord {
            decision: decision.to_string(),
            method: method.to_string(),
            target: target.to_string(),
            status,
            reason: reason.to_string(),
        });
    }
    if decision == "DENY" && !state.quiet_stderr {
        eprintln!(
            "[octopus] DENY egress {} {} -> HTTP {} ({})",
            method, target, status, reason
        );
    }
}

async fn send_blocked_json(
    stream: &mut TcpStream,
    state: &ProxyState,
    method: &str,
    target: &str,
    status: u16,
    reason: &str,
) {
    record_event(state, "DENY", method, target, status, reason);
    let status_text = match status {
        400 => "Bad Request",
        405 => "Method Not Allowed",
        421 => "Misdirected Request",
        502 => "Bad Gateway",
        _ => "Forbidden",
    };
    let body = serde_json::json!({
        "error": "blocked_by_octopus_policy",
        "layer": "AgentOctopus+EgressGuard",
        "status": status,
        "target": target,
        "reason": reason,
    })
    .to_string();
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        status_text,
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn is_cloud_metadata_literal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (o[0] == 169 && o[1] == 254)
                || o == [100, 100, 100, 200]
                || o == [168, 63, 129, 16]
                || o == [192, 0, 0, 192]
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] == 0xfd00 && s[1] == 0x0ec2)
                || s == [0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254]
                || s == [0xfd00, 0x00c1, 0, 0, 0, 0, 0xa9fe, 0xa9fe]
                || s == [0xfd00, 0x0042, 0, 0, 0, 0, 0, 0x0042]
                || (s[0] & 0xffc0) == 0xfe80
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_cloud_metadata_literal(IpAddr::V4(v4)))
        }
    }
}

fn has_explicit_loopback_port_allowlist(allowed_domains: &[String], host: &str, port: u16) -> bool {
    let norm_host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    for pat in allowed_domains {
        if is_bare_or_port_wildcard(pat) {
            continue;
        }
        let trimmed = pat.trim();
        let (pat_host, pat_port_opt) = if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some((ip_part, tail)) = rest.split_once(']') {
                let p = tail.strip_prefix(':').and_then(|s| s.parse::<u16>().ok());
                (ip_part, p)
            } else {
                continue;
            }
        } else if trimmed.matches(':').count() == 1 {
            if let Some((h, p_str)) = trimmed.split_once(':') {
                (h, p_str.parse::<u16>().ok())
            } else {
                continue;
            }
        } else {
            continue;
        };
        let Some(req_port) = pat_port_opt else {
            continue;
        };
        if req_port != port {
            continue;
        }
        let norm_pat_host = pat_host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let matches = matches!(
            (norm_host.as_str(), norm_pat_host.as_str()),
            ("127.0.0.1", "127.0.0.1") | ("::1", "::1") | ("localhost", "localhost")
        );
        if matches {
            return true;
        }
    }
    false
}
fn extract_raw_authority_host(authority: &str) -> String {
    let after_userinfo = authority.rsplit('@').next().unwrap_or(authority).trim();
    let raw = if let Some(rest) = after_userinfo.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        after_userinfo.split(':').next().unwrap_or(after_userinfo)
    };
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

async fn connect_pinned_addrs(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last_err = None;
    for (idx, &addr) in addrs.iter().enumerate() {
        let has_more = idx + 1 < addrs.len();
        if has_more && addr.ip().is_loopback() {
            match tokio::time::timeout(
                std::time::Duration::from_millis(300),
                TcpStream::connect(addr),
            )
            .await
            {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => {
                    last_err = Some(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("loopback connect timeout for {}", addr),
                    ));
                }
            }
        } else {
            match TcpStream::connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no resolved upstream address",
        )
    }))
}

fn authorize_egress(
    state: &ProxyState,
    scheme: &str,
    raw_host: &str,
    port: u16,
    method: &str,
    path: &str,
) -> Result<(String, Vec<SocketAddr>), (u16, String)> {
    let trimmed_raw = raw_host.trim();
    if trimmed_raw.is_empty() {
        return Err((400, "empty_target_host".to_string()));
    }
    if trimmed_raw.contains('@') {
        return Err((400, "userinfo_in_authority_rejected".to_string()));
    }
    if port == 0 {
        return Err((400, "invalid_port_zero".to_string()));
    }

    let unbracketed = trimmed_raw
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if unbracketed.is_empty() {
        return Err((400, "empty_target_host".to_string()));
    }

    if is_non_standard_ip_host_encoding(&unbracketed) {
        return Err((
            403,
            format!("non_standard_ip_encoding_blocked: '{}'", raw_host),
        ));
    }

    for pat in &state.denied_domains {
        if !is_bare_or_port_wildcard(pat) && host_port_pattern_matches(&unbracketed, port, pat) {
            return Err((
                403,
                format!(
                    "target '{}:{}' matched denied_domains rule '{}'",
                    unbracketed, port, pat
                ),
            ));
        }
    }

    let pinned_addrs: Vec<SocketAddr> = if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        if is_cloud_metadata_literal(ip) {
            return Err((403, format!("cloud_metadata_ip_blocked: '{}'", ip)));
        }
        if ip.is_unspecified() {
            return Err((403, format!("unspecified_ip_blocked: '{}'", ip)));
        }
        if state.denied_cidrs.iter().any(|c| c.contains(ip)) {
            return Err((
                403,
                format!("denied_resolved_addresses_cidr_blocked: '{}'", ip),
            ));
        }
        if ip.is_loopback() {
            if port == state.proxy_port {
                return Err((403, "proxy_self_loop_blocked".to_string()));
            }
            if state.cedar_ipc_port == Some(port) {
                return Err((403, "cedar_control_port_blocked".to_string()));
            }
            if !state.is_standalone_cedar
                && !has_explicit_loopback_port_allowlist(&state.allowed_domains, &unbracketed, port)
            {
                return Err((
                    403,
                    format!(
                        "loopback target '{}:{}' requires explicit host:port entry in allowed_domains",
                        unbracketed, port
                    ),
                ));
            }
            vec![SocketAddr::new(ip, port)]
        } else {
            if is_restricted_rebinding_ip(&ip) {
                return Err((403, format!("restricted_ip_blocked: '{}'", ip)));
            }
            if !state.is_standalone_cedar {
                let safe_allowed: Vec<String> = state
                    .allowed_domains
                    .iter()
                    .filter(|p| !is_bare_or_port_wildcard(p))
                    .cloned()
                    .collect();
                if !safe_allowed
                    .iter()
                    .any(|pat| host_port_pattern_matches(&unbracketed, port, pat))
                {
                    return Err((
                        403,
                        format!("target '{}:{}' not in allowed_domains", unbracketed, port),
                    ));
                }
            }
            vec![SocketAddr::new(ip, port)]
        }
    } else if unbracketed == "localhost" || unbracketed.ends_with(".localhost") {
        if port == state.proxy_port {
            return Err((403, "proxy_self_loop_blocked".to_string()));
        }
        if state.cedar_ipc_port == Some(port) {
            return Err((403, "cedar_control_port_blocked".to_string()));
        }
        if !state.is_standalone_cedar
            && !has_explicit_loopback_port_allowlist(&state.allowed_domains, &unbracketed, port)
        {
            return Err((
                403,
                format!(
                    "loopback hostname '{}:{}' requires explicit host:port entry in allowed_domains",
                    unbracketed, port
                ),
            ));
        }
        let mut resolved: Vec<SocketAddr> = (unbracketed.as_str(), port)
            .to_socket_addrs()
            .map(|iter| iter.filter(|sa| sa.ip().is_loopback()).collect())
            .unwrap_or_default();
        if unbracketed == "localhost" {
            let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
            if !resolved.contains(&v4) {
                resolved.push(v4);
            }
            if !resolved.contains(&v6) {
                resolved.push(v6);
            }
        } else if resolved.is_empty() {
            resolved.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        }
        resolved
    } else if !state.is_standalone_cedar {
        let safe_allowed: Vec<String> = state
            .allowed_domains
            .iter()
            .filter(|p| !is_bare_or_port_wildcard(p))
            .cloned()
            .collect();
        resolve_and_pin_allowed_host(
            &unbracketed,
            port,
            &safe_allowed,
            &state.denied_domains,
            &state.denied_cidrs,
            None,
        )
        .map_err(|e| (403, e.to_string()))?
    } else {
        // Standalone .cedar mode: evaluate Cedar first, then resolve & validate SSRF invariants.
        if let Some(ref cedar) = state.cedar_engine {
            let verdict = cedar
                .evaluate(
                    "cli_runner",
                    "egress",
                    &unbracketed,
                    "NetworkTarget",
                    serde_json::json!({
                        "destination_domain": unbracketed,
                        "destination_host": unbracketed,
                        "destination_port": port as i64,
                        "scheme": scheme,
                        "method": method,
                        "path": path,
                    }),
                )
                .map_err(|e| (403, format!("cedar_egress_error: {}", e)))?;
            if !verdict.is_allowed {
                return Err((
                    403,
                    format!(
                        "cedar_egress_denied: target '{}:{}' not permitted by Cedar policy",
                        unbracketed, port
                    ),
                ));
            }
        }
        let addrs: Vec<SocketAddr> = (unbracketed.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| {
                (
                    403,
                    format!(
                        "DNS resolution failed for '{}:{}': {}",
                        unbracketed, port, e
                    ),
                )
            })?
            .collect();
        if addrs.is_empty() {
            return Err((
                403,
                format!(
                    "DNS resolution returned zero addresses for '{}:{}'",
                    unbracketed, port
                ),
            ));
        }
        for sa in &addrs {
            if let Some(reason) =
                is_denied_resolved_ip_with_local(sa.ip(), &state.denied_cidrs, &state.local_ips)
            {
                return Err((
                    403,
                    format!(
                        "resolved IP '{}' for '{}:{}' blocked by SSRF guard ({})",
                        sa.ip(),
                        unbracketed,
                        port,
                        reason
                    ),
                ));
            }
        }
        return Ok((unbracketed, addrs));
    };

    if let Some(ref cedar) = state.cedar_engine {
        let verdict = cedar
            .evaluate(
                "cli_runner",
                "egress",
                &unbracketed,
                "NetworkTarget",
                serde_json::json!({
                    "destination_domain": unbracketed,
                    "destination_host": unbracketed,
                    "destination_port": port as i64,
                    "scheme": scheme,
                    "method": method,
                    "path": path,
                }),
            )
            .map_err(|e| (403, format!("cedar_egress_error: {}", e)))?;
        let enforce_cedar_default_deny =
            state.is_standalone_cedar || cedar.has_permit_action_policy("egress");
        if !verdict.is_allowed
            && (enforce_cedar_default_deny || !verdict.determining_policies.is_empty())
        {
            return Err((
                403,
                format!(
                    "cedar_egress_denied: target '{}:{}' not permitted by Cedar policy",
                    unbracketed, port
                ),
            ));
        }
    }

    Ok((unbracketed, pinned_addrs))
}

fn parse_connect_authority(target: &str) -> Result<(String, u16), String> {
    let trimmed = target.trim();
    if trimmed.is_empty()
        || trimmed.bytes().any(|b| b <= 0x20 || b == 0x7f)
        || trimmed.contains('@')
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains('%')
    {
        return Err("malformed CONNECT authority target".to_string());
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let Some((ip, tail)) = rest.split_once(']') else {
            return Err("unclosed IPv6 bracket in CONNECT target".to_string());
        };
        let port = if let Some(p_str) = tail.strip_prefix(':') {
            p_str
                .parse::<u16>()
                .map_err(|_| "invalid port in CONNECT target".to_string())?
        } else if tail.is_empty() {
            443
        } else {
            return Err("invalid suffix after IPv6 bracket in CONNECT target".to_string());
        };
        return Ok((format!("[{}]", ip), port));
    }
    if let Some((host, p_str)) = trimmed.split_once(':') {
        if host.is_empty() || p_str.contains(':') {
            return Err("invalid host:port in CONNECT target".to_string());
        }
        let port = p_str
            .parse::<u16>()
            .map_err(|_| "invalid port in CONNECT target".to_string())?;
        return Ok((host.to_string(), port));
    }
    Ok((trimmed.to_string(), 443))
}

async fn read_http_request(
    stream: &mut TcpStream,
) -> Result<Option<(String, String, String, Vec<(String, String)>, Vec<u8>)>, (u16, String)> {
    const MAX_HEADER_BYTES: usize = 64 * 1024;
    const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];
    let header_end;

    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos;
            break;
        }
        if buf.len() >= MAX_HEADER_BYTES {
            return Err((400, "http_header_too_large".to_string()));
        }
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| (400, format!("socket_read_error: {}", e)))?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err((400, "incomplete_http_request".to_string()));
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    let head_str = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| (400, "non_utf8_http_headers".to_string()))?;
    let mut lines = head_str.split("\r\n");
    let req_line = lines
        .next()
        .ok_or_else(|| (400, "missing_request_line".to_string()))?;
    let mut parts = req_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| (400, "missing_http_method".to_string()))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| (400, "missing_http_target".to_string()))?
        .to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    let mut headers = Vec::new();
    let mut content_length: usize = 0;
    let mut seen_content_length = false;
    let mut seen_transfer_encoding = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                if seen_content_length {
                    return Err((400, "duplicate_content_length_rejected".to_string()));
                }
                seen_content_length = true;
                content_length = val
                    .parse::<usize>()
                    .map_err(|_| (400, "invalid_content_length".to_string()))?;
                if content_length > MAX_BODY_BYTES {
                    return Err((400, "http_body_too_large".to_string()));
                }
            } else if key.eq_ignore_ascii_case("transfer-encoding") {
                seen_transfer_encoding = true;
            }
            headers.push((key, val));
        }
    }
    if seen_transfer_encoding && seen_content_length {
        return Err((
            400,
            "conflicting_transfer_encoding_and_content_length".to_string(),
        ));
    }

    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| (400, format!("socket_body_read_error: {}", e)))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
        if body.len() > MAX_BODY_BYTES {
            return Err((400, "http_body_too_large".to_string()));
        }
    }
    body.truncate(content_length);

    Ok(Some((method, target, version, headers, body)))
}

async fn handle_proxy_connection(mut client: TcpStream, state: Arc<ProxyState>) {
    let parsed = match read_http_request(&mut client).await {
        Ok(Some(v)) => v,
        Ok(None) => return,
        Err((code, reason)) => {
            send_blocked_json(&mut client, &state, "RAW", "<malformed>", code, &reason).await;
            return;
        }
    };

    let (method, target, version, headers, body) = parsed;
    let upper_method = method.trim().to_ascii_uppercase();

    let host_headers: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str())
        .collect();
    if host_headers.len() > 1 {
        send_blocked_json(
            &mut client,
            &state,
            &method,
            &target,
            400,
            "duplicate_host_header_rejected",
        )
        .await;
        return;
    }
    let host_hdr = host_headers.first().copied();

    if upper_method == "CONNECT" {
        let (raw_host, port) = match parse_connect_authority(&target) {
            Ok(v) => v,
            Err(reason) => {
                send_blocked_json(&mut client, &state, &method, &target, 400, &reason).await;
                return;
            }
        };
        let (_clean_host, pinned_addrs) =
            match authorize_egress(&state, "https", &raw_host, port, "CONNECT", "/") {
                Ok(v) => v,
                Err((code, reason)) => {
                    send_blocked_json(&mut client, &state, &method, &target, code, &reason).await;
                    return;
                }
            };
        match connect_pinned_addrs(&pinned_addrs).await {
            Ok(mut upstream) => {
                record_event(
                    &state,
                    "ALLOW",
                    "CONNECT",
                    &target,
                    200,
                    "tunnel_established",
                );
                if client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            }
            Err(e) => {
                send_blocked_json(
                    &mut client,
                    &state,
                    &method,
                    &target,
                    502,
                    &format!("upstream_connect_failed: {}", e),
                )
                .await;
            }
        }
        return;
    }

    if let Err((code, reason)) =
        validate_http_request_target(&method, &target, host_hdr, None, None)
    {
        send_blocked_json(&mut client, &state, &method, &target, code, reason).await;
        return;
    }

    let full_url_str = if target.starts_with("http://") || target.starts_with("https://") {
        target.clone()
    } else if let Some(h) = host_hdr {
        format!("http://{}{}", h, target)
    } else {
        send_blocked_json(
            &mut client,
            &state,
            &method,
            &target,
            400,
            "missing_host_or_absolute_url",
        )
        .await;
        return;
    };

    if let Some(after_scheme) = full_url_str.split("://").nth(1) {
        let raw_authority = after_scheme
            .split(&['/', '?', '#'][..])
            .next()
            .unwrap_or("");
        let raw_host = extract_raw_authority_host(raw_authority);
        if is_non_standard_ip_host_encoding(&raw_host) {
            send_blocked_json(
                &mut client,
                &state,
                &method,
                &target,
                403,
                &format!("non_standard_ip_encoding_blocked: '{}'", raw_host),
            )
            .await;
            return;
        }
    }
    if let Some(h) = host_hdr {
        let raw_hdr_host = extract_raw_authority_host(h);
        if is_non_standard_ip_host_encoding(&raw_hdr_host) {
            send_blocked_json(
                &mut client,
                &state,
                &method,
                &target,
                403,
                &format!("non_standard_ip_encoding_blocked: '{}'", raw_hdr_host),
            )
            .await;
            return;
        }
    }

    let parsed_url = match url::Url::parse(&full_url_str) {
        Ok(u) => u,
        Err(e) => {
            send_blocked_json(
                &mut client,
                &state,
                &method,
                &target,
                400,
                &format!("invalid_url: {}", e),
            )
            .await;
            return;
        }
    };

    let scheme = parsed_url.scheme();
    if scheme != "http" && scheme != "https" {
        send_blocked_json(
            &mut client,
            &state,
            &method,
            &target,
            403,
            "unsupported_url_scheme",
        )
        .await;
        return;
    }

    let Some(host_str) = parsed_url.host_str() else {
        send_blocked_json(
            &mut client,
            &state,
            &method,
            &target,
            400,
            "url_missing_host",
        )
        .await;
        return;
    };
    let port = parsed_url.port_or_known_default().unwrap_or(80);
    let mut origin_target = parsed_url.path().to_string();
    if origin_target.is_empty() {
        origin_target = "/".to_string();
    }
    if let Some(q) = parsed_url.query() {
        origin_target.push('?');
        origin_target.push_str(q);
    }

    let (clean_host, pinned_addrs) = match authorize_egress(
        &state,
        scheme,
        host_str,
        port,
        &upper_method,
        &origin_target,
    ) {
        Ok(v) => v,
        Err((code, reason)) => {
            send_blocked_json(&mut client, &state, &method, &target, code, &reason).await;
            return;
        }
    };

    let body_lossy = String::from_utf8_lossy(&body).to_string();
    let mut inspection_payload = format!("{} {}\n", method, target);
    for (k, v) in &headers {
        inspection_payload.push_str(k);
        inspection_payload.push_str(": ");
        inspection_payload.push_str(v);
        inspection_payload.push('\n');
    }
    inspection_payload.push_str(&body_lossy);

    for sec in &state.secrets {
        if inspection_payload.contains(sec.real_secret.as_str()) {
            let transport_ok = scheme.eq_ignore_ascii_case("https") || sec.allow_plaintext_inject;
            let host_ok = sec
                .inject_hosts
                .iter()
                .any(|pat| host_port_pattern_matches(&clean_host, port, pat));
            if !transport_ok || !host_ok {
                send_blocked_json(
                    &mut client,
                    &state,
                    &method,
                    &target,
                    403,
                    &format!("raw_credential_leak_blocked ({})", sec.env_name),
                )
                .await;
                return;
            }
        }
    }

    let mut dlp_payload = inspection_payload;
    for sec in &state.secrets {
        if !sec.sentinel.is_empty() && dlp_payload.contains(&sec.sentinel) {
            dlp_payload = dlp_payload.replace(&sec.sentinel, "<OCTOPUS_SENTINEL>");
        }
    }
    let dlp_verdict = SemanticDlpEngine::default().evaluate_verdict(&dlp_payload);
    if !dlp_verdict.is_allow() {
        send_blocked_json(
            &mut client,
            &state,
            &method,
            &target,
            403,
            "semantic_dlp_blocked",
        )
        .await;
        return;
    }

    let (unmasked_headers, unmasked_body) =
        match state
            .masker
            .inject_on_egress(scheme, &clean_host, port, &headers, &body_lossy)
        {
            Ok(res) => res,
            Err(e) => {
                send_blocked_json(
                    &mut client,
                    &state,
                    &method,
                    &target,
                    403,
                    &format!("credential_sentinel_blocked: {}", e),
                )
                .await;
                return;
            }
        };

    let out_body_bytes = if unmasked_body == body_lossy {
        body
    } else {
        unmasked_body.into_bytes()
    };

    let mut upstream = match connect_pinned_addrs(&pinned_addrs).await {
        Ok(u) => u,
        Err(e) => {
            send_blocked_json(
                &mut client,
                &state,
                &method,
                &target,
                502,
                &format!("upstream_connect_failed: {}", e),
            )
            .await;
            return;
        }
    };

    let mut req_buf = Vec::with_capacity(1024 + out_body_bytes.len());
    req_buf.extend_from_slice(format!("{} {} {}\r\n", method, origin_target, version).as_bytes());
    let mut has_host = false;
    for (k, v) in &unmasked_headers {
        let lower = k.to_ascii_lowercase();
        if lower == "proxy-connection"
            || lower == "connection"
            || lower == "content-length"
            || lower == "transfer-encoding"
            || lower == "proxy-authorization"
        {
            continue;
        }
        if lower == "host" {
            has_host = true;
        }
        req_buf.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
    }
    if !has_host {
        let host_val = if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
            clean_host.clone()
        } else {
            format!("{}:{}", clean_host, port)
        };
        req_buf.extend_from_slice(format!("Host: {}\r\n", host_val).as_bytes());
    }
    if !out_body_bytes.is_empty()
        || upper_method == "POST"
        || upper_method == "PUT"
        || upper_method == "PATCH"
    {
        req_buf
            .extend_from_slice(format!("Content-Length: {}\r\n", out_body_bytes.len()).as_bytes());
    }
    req_buf.extend_from_slice(b"Connection: close\r\n\r\n");
    req_buf.extend_from_slice(&out_body_bytes);

    if upstream.write_all(&req_buf).await.is_err() {
        send_blocked_json(
            &mut client,
            &state,
            &method,
            &target,
            502,
            "upstream_write_failed",
        )
        .await;
        return;
    }

    record_event(&state, "ALLOW", &method, &target, 200, "allowed_by_policy");
    let _ = tokio::io::copy(&mut upstream, &mut client).await;
    let _ = client.shutdown().await;
}
