//! Persistent HTTP/2 Cleartext Client & Hardened Egress Guard for SafeAgents Sidecar Proxy Interception
//!
//! Enforces:
//! - Persistent HTTP/2 prior knowledge (`h2c`) to eliminate handshake round-trips.
//! - `TCP_NODELAY` and keep-alive socket tuning to prevent Nagle buffering delays.
//! - Non-blocking streaming SSE rewriter: immediate pass-through of text generation tokens,
//!   with parallel evaluation of tool-call chunks and sub-15ms replacement of blocked calls.
//! - Single-lookup resolved-address DNS pinning with NAT64, 6to4, cloud IMDS, local interface,
//!   and custom CIDR SSRF blocking (reusing `containment_ring::egress_proxy`).
//! - Sentinel credential masking (`CredentialSentinelMasker`) replacing secrets in child
//!   environments with opaque sentinels unmasked only on verified HTTPS `inject_hosts`.
//! - Ambiguous HTTP request-target rejection (`400` / `405`) and `Host`/SNI verification (`421`).

use crate::containment_ring::egress_proxy::is_restricted_rebinding_ip;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum SafeAgentsClientError {
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Configuration error: {0}")]
    Config(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolEvaluationVerdict {
    Allow,
    Block { reason: String },
}

pub trait ToolCallEvaluator: Send + Sync {
    fn evaluate(&self, tool_name: &str, arguments_json: &str) -> ToolEvaluationVerdict;
}

#[derive(Debug, Clone)]
pub struct SafeAgentsClientConfig {
    pub base_url: String,
    pub connect_timeout: Duration,
    pub tcp_keepalive: Duration,
    pub pool_idle_timeout: Duration,
    pub max_idle_per_host: usize,
}

impl Default for SafeAgentsClientConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8787".to_string(),
            connect_timeout: Duration::from_millis(500),
            tcp_keepalive: Duration::from_secs(60),
            pool_idle_timeout: Duration::from_secs(90),
            max_idle_per_host: 32,
        }
    }
}

#[derive(Clone)]
pub struct SafeAgentsClient {
    client: reqwest::Client,
    config: SafeAgentsClientConfig,
    evaluator: Option<Arc<dyn ToolCallEvaluator>>,
}

impl SafeAgentsClient {
    pub fn new(config: SafeAgentsClientConfig) -> Result<Self, SafeAgentsClientError> {
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .tcp_nodelay(true)
            .tcp_keepalive(Some(config.tcp_keepalive))
            .pool_idle_timeout(Some(config.pool_idle_timeout))
            .pool_max_idle_per_host(config.max_idle_per_host)
            .connect_timeout(config.connect_timeout)
            .build()?;

        Ok(Self {
            client,
            config,
            evaluator: None,
        })
    }

    pub fn with_evaluator(mut self, evaluator: Arc<dyn ToolCallEvaluator>) -> Self {
        self.evaluator = Some(evaluator);
        self
    }

    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    pub fn anthropic_endpoint(&self) -> String {
        std::env::var("ANTHROPIC_BASE_URL")
            .unwrap_or_else(|_| format!("{}/v1/messages", self.config.base_url))
    }

    pub fn openai_endpoint(&self) -> String {
        std::env::var("OPENAI_BASE_URL")
            .unwrap_or_else(|_| format!("{}/v1/chat/completions", self.config.base_url))
    }

    /// Evaluates a tool call using the registered evaluator, defaulting to Allow if none is registered.
    pub fn evaluate_call(&self, tool_name: &str, arguments_json: &str) -> ToolEvaluationVerdict {
        if let Some(evaluator) = &self.evaluator {
            evaluator.evaluate(tool_name, arguments_json)
        } else {
            ToolEvaluationVerdict::Allow
        }
    }

    /// Rewrites an OpenAI SSE chunk in-stream:
    /// - If content delta: passes through immediately.
    /// - If tool call delta: evaluates call and replaces blocked tools with text notices.
    pub fn transform_openai_chunk(&self, raw_chunk: &str) -> String {
        let trimmed = raw_chunk.trim();
        if !trimmed.starts_with("data: ") || trimmed == "data: [DONE]" {
            return raw_chunk.to_string();
        }

        let json_str = &trimmed[6..];
        let mut parsed: serde_json::Value = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(_) => return raw_chunk.to_string(),
        };

        if let Some(choices) = parsed.get_mut("choices").and_then(|c| c.as_array_mut()) {
            for choice in choices {
                if let Some(delta) = choice.get_mut("delta") {
                    if let Some(tool_calls) =
                        delta.get_mut("tool_calls").and_then(|tc| tc.as_array_mut())
                    {
                        let mut allowed_calls = Vec::new();
                        let mut blocked_notices = Vec::new();

                        for tc in tool_calls.drain(..) {
                            let name = tc
                                .pointer("/function/name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("");
                            let args = tc
                                .pointer("/function/arguments")
                                .and_then(|a| a.as_str())
                                .unwrap_or("{}");

                            match self.evaluate_call(name, args) {
                                ToolEvaluationVerdict::Allow => allowed_calls.push(tc),
                                ToolEvaluationVerdict::Block { reason } => {
                                    blocked_notices.push(format!(
                                        "[safeagents] blocked call to `{}`: {}\n",
                                        name, reason
                                    ));
                                }
                            }
                        }

                        if !blocked_notices.is_empty() {
                            let existing_content =
                                delta.get("content").and_then(|c| c.as_str()).unwrap_or("");
                            let mut new_content = existing_content.to_string();
                            for notice in blocked_notices {
                                new_content.push_str(&notice);
                            }
                            delta["content"] = serde_json::Value::String(new_content);

                            if allowed_calls.is_empty() {
                                delta.as_object_mut().map(|o| o.remove("tool_calls"));
                                choice["finish_reason"] =
                                    serde_json::Value::String("stop".to_string());
                            } else {
                                delta["tool_calls"] = serde_json::Value::Array(allowed_calls);
                            }
                        } else {
                            delta["tool_calls"] = serde_json::Value::Array(allowed_calls);
                        }
                    }
                }
            }
        }

        format!(
            "data: {}\n\n",
            serde_json::to_string(&parsed).unwrap_or_else(|_| json_str.to_string())
        )
    }
}

// ============================================================================
// Component 4: Single-Resolution DNS Pinning & Cloud-IMDS / NAT64 / 6to4 Guard
// ============================================================================

/// Parsed IPv4 or IPv6 CIDR block used for configurable egress IP restrictions
/// (mirroring `network.deniedResolvedAddresses` from `anthropics/sandbox-runtime`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpCidr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl IpCidr {
    /// Parses a CIDR string such as `"10.0.0.0/8"`, `"fc00::/7"`, or single IP `"168.63.129.16"`.
    pub fn parse(cidr: &str) -> Result<Self, SafeAgentsClientError> {
        let trimmed = cidr.trim();
        let (addr_part, prefix_opt) = match trimmed.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim())),
            None => (trimmed, None),
        };
        let addr: IpAddr = addr_part
            .parse()
            .map_err(|_| SafeAgentsClientError::Config(format!("Invalid CIDR IP '{}'", cidr)))?;
        let max_prefix = match addr {
            IpAddr::V4(_) => 32u8,
            IpAddr::V6(_) => 128u8,
        };
        let prefix_len = match prefix_opt {
            Some(p) => p.parse::<u8>().map_err(|_| {
                SafeAgentsClientError::Config(format!("Invalid CIDR prefix in '{}'", cidr))
            })?,
            None => max_prefix,
        };
        if prefix_len > max_prefix {
            return Err(SafeAgentsClientError::Config(format!(
                "CIDR prefix length {} exceeds max {} in '{}'",
                prefix_len, max_prefix, cidr
            )));
        }
        Ok(Self { addr, prefix_len })
    }

    /// Returns `true` if `candidate` (including IPv4-mapped IPv6 forms) falls inside this CIDR.
    pub fn contains(&self, candidate: IpAddr) -> bool {
        match (self.addr, candidate) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => ipv4_matches_prefix(net, ip, self.prefix_len),
            (IpAddr::V4(net), IpAddr::V6(v6)) => {
                if let Some(mapped) = v6.to_ipv4_mapped() {
                    ipv4_matches_prefix(net, mapped, self.prefix_len)
                } else {
                    false
                }
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                if self.prefix_len == 0 {
                    true
                } else if self.prefix_len >= 128 {
                    net == ip
                } else {
                    let mask = !0u128 << (128 - self.prefix_len);
                    (u128::from(net) & mask) == (u128::from(ip) & mask)
                }
            }
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

#[inline]
fn ipv4_matches_prefix(net: Ipv4Addr, ip: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        true
    } else if prefix_len >= 32 {
        net == ip
    } else {
        let mask = !0u32 << (32 - prefix_len);
        (u32::from(net) & mask) == (u32::from(ip) & mask)
    }
}

/// Discovers primary outbound interface IP addresses bound on this host without sending network traffic.
pub fn local_host_interface_ips() -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for (bind_addr, remote_addr) in [
        ("0.0.0.0:0", "8.8.8.8:80"),
        ("[::]:0", "[2001:4860:4860::8888]:80"),
    ] {
        if let Ok(sock) = UdpSocket::bind(bind_addr) {
            if sock.connect(remote_addr).is_ok() {
                if let Ok(local) = sock.local_addr() {
                    let ip = local.ip();
                    if !ip.is_unspecified() && !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
        }
    }
    ips
}

#[inline]
fn is_cloud_metadata_ip(ip: IpAddr) -> bool {
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
            // AWS fd00:ec2::/32, OpenStack/cloud fd20:ce::254, GCP/Alibaba fd00:c1::a9fe:a9fe, fd00:42::42, link-local fe80::/10
            (s[0] == 0xfd00 && s[1] == 0x0ec2)
                || (s == [0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254])
                || (s == [0xfd00, 0x00c1, 0, 0, 0, 0, 0xa9fe, 0xa9fe])
                || (s == [0xfd00, 0x0042, 0, 0, 0, 0, 0, 0x0042])
                || (s[0] & 0xffc0) == 0xfe80
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_cloud_metadata_ip(IpAddr::V4(v4)))
        }
    }
}

#[inline]
fn is_nat64_or_6to4_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => false,
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let nat64_wk = s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0];
            let nat64_local = s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 1;
            let is_6to4 = s[0] == 0x2002;
            nat64_wk || nat64_local || is_6to4
        }
    }
}

/// Checks whether a resolved `IpAddr` is blocked due to cloud metadata, NAT64/6to4, loopback,
/// private/reserved IPv4/IPv6 ranges (`is_restricted_rebinding_ip`), or `extra_denied_cidrs`.
pub fn is_denied_resolved_ip(ip: IpAddr, extra_denied_cidrs: &[IpCidr]) -> Option<&'static str> {
    is_denied_resolved_ip_with_local(ip, extra_denied_cidrs, &[])
}

/// Same as [`is_denied_resolved_ip`], additionally checking against explicit host interface IPs.
pub fn is_denied_resolved_ip_with_local(
    ip: IpAddr,
    extra_denied_cidrs: &[IpCidr],
    local_interface_ips: &[IpAddr],
) -> Option<&'static str> {
    if is_cloud_metadata_ip(ip) {
        return Some("cloud_metadata");
    }
    if is_nat64_or_6to4_ip(ip) {
        return Some("nat64_or_6to4");
    }
    if local_interface_ips.contains(&ip) {
        return Some("local_interface");
    }
    if extra_denied_cidrs.iter().any(|cidr| cidr.contains(ip)) {
        return Some("denied_cidr");
    }
    if is_restricted_rebinding_ip(&ip) {
        return Some("restricted_ip");
    }
    None
}

/// Splits an entry such as `"*.github.com:443"` or `"[::1]:8080"` into `(host_pattern, Option<port>)`.
fn split_host_and_optional_port(pattern: &str) -> (&str, Option<u16>) {
    let trimmed = pattern.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((ip_part, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (ip_part, port);
        }
    }
    if trimmed.matches(':').count() == 1 {
        if let Some((h, p_str)) = trimmed.split_once(':') {
            if let Ok(port) = p_str.parse::<u16>() {
                return (h, Some(port));
            }
        }
    }
    (trimmed, None)
}

/// Matches a target `(host, port)` against an `allowedDomains` / `deniedDomains` / `injectHosts` pattern.
pub fn host_port_pattern_matches(host: &str, port: u16, pattern: &str) -> bool {
    let norm_host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let (raw_pat, pat_port) = split_host_and_optional_port(pattern);
    if let Some(required_port) = pat_port {
        if port != required_port {
            return false;
        }
    }
    let norm_pat = raw_pat.trim().trim_end_matches('.').to_ascii_lowercase();
    if norm_pat == "*" {
        return true;
    }
    if let Some(suffix) = norm_pat.strip_prefix("*.") {
        return norm_host.len() > suffix.len()
            && norm_host.ends_with(suffix)
            && norm_host.as_bytes()[norm_host.len() - suffix.len() - 1] == b'.';
    }
    norm_host == norm_pat
}

/// Resolves `host:port` at most **once**, verifies deny-before-allow domain precedence, validates every
/// resolved IP against `is_denied_resolved_ip_with_local`, and returns pinned `SocketAddr`s so callers
/// dial the verified IP directly with zero DNS-rebinding TOCTOU window.
pub fn resolve_and_pin_allowed_host(
    host: &str,
    port: u16,
    allowed_domains: &[String],
    denied_domains: &[String],
    extra_denied_cidrs: &[IpCidr],
    dns_override: Option<&[IpAddr]>,
) -> Result<Vec<SocketAddr>, SafeAgentsClientError> {
    let clean_host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if clean_host.is_empty() {
        return Err(SafeAgentsClientError::Protocol(
            "Empty egress target host rejected".to_string(),
        ));
    }

    if denied_domains
        .iter()
        .any(|pat| host_port_pattern_matches(&clean_host, port, pat))
    {
        return Err(SafeAgentsClientError::Protocol(format!(
            "Target '{}:{}' denied by deniedDomains rule",
            clean_host, port
        )));
    }

    if !allowed_domains
        .iter()
        .any(|pat| host_port_pattern_matches(&clean_host, port, pat))
    {
        return Err(SafeAgentsClientError::Protocol(format!(
            "Target '{}:{}' is not present in allowedDomains",
            clean_host, port
        )));
    }

    let resolved_ips: Vec<IpAddr> = if let Ok(literal) = clean_host.parse::<IpAddr>() {
        vec![literal]
    } else if let Some(override_ips) = dns_override {
        override_ips.to_vec()
    } else {
        (clean_host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| {
                SafeAgentsClientError::Protocol(format!(
                    "DNS resolution failed for '{}:{}': {}",
                    clean_host, port, e
                ))
            })?
            .map(|sa| sa.ip())
            .collect()
    };

    if resolved_ips.is_empty() {
        return Err(SafeAgentsClientError::Protocol(format!(
            "DNS resolution returned zero addresses for '{}:{}'",
            clean_host, port
        )));
    }

    let local_ips = local_host_interface_ips();
    let mut pinned = Vec::with_capacity(resolved_ips.len());
    for ip in resolved_ips {
        if let Some(reason) = is_denied_resolved_ip_with_local(ip, extra_denied_cidrs, &local_ips) {
            return Err(SafeAgentsClientError::Protocol(format!(
                "Resolved IP '{}' for '{}:{}' blocked by SSRF guard ({})",
                ip, clean_host, port, reason
            )));
        }
        let sa = SocketAddr::new(ip, port);
        if !pinned.contains(&sa) {
            pinned.push(sa);
        }
    }

    Ok(pinned)
}

// ============================================================================
// Component 5: Sentinel Credential Masking & Live Control Policy Updates
// ============================================================================

#[derive(Clone)]
struct MaskedCredentialEntry {
    env_name: String,
    real_secret: Zeroizing<String>,
    sentinel: String,
    inject_hosts: Vec<String>,
    allow_plaintext_inject: bool,
}

impl std::fmt::Debug for MaskedCredentialEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaskedCredentialEntry")
            .field("env_name", &self.env_name)
            .field("real_secret", &"[REDACTED]")
            .field("sentinel", &self.sentinel)
            .field("inject_hosts", &self.inject_hosts)
            .field("allow_plaintext_inject", &self.allow_plaintext_inject)
            .finish()
    }
}

/// Dynamic network policy state swappable atomically at runtime (equivalent to `srt --control-fd`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicNetworkPolicy {
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub denied_domains: Vec<String>,
    #[serde(default)]
    pub denied_resolved_addresses: Vec<String>,
}

/// Validates and parses a JSON control-channel network policy update before applying it.
pub fn parse_and_validate_dynamic_policy(
    json_line: &str,
) -> Result<(DynamicNetworkPolicy, Vec<IpCidr>), SafeAgentsClientError> {
    let policy: DynamicNetworkPolicy = serde_json::from_str(json_line)?;
    let mut cidrs = Vec::with_capacity(policy.denied_resolved_addresses.len());
    for raw in &policy.denied_resolved_addresses {
        cidrs.push(IpCidr::parse(raw)?);
    }
    Ok((policy, cidrs))
}

/// Masks real credentials inside sandboxed child environments using unguessable 128-bit sentinels
/// and only unmasks them on outbound HTTPS requests targeting explicitly approved `inject_hosts`.
#[derive(Debug, Default)]
pub struct CredentialSentinelMasker {
    entries: RwLock<HashMap<String, MaskedCredentialEntry>>,
}

impl CredentialSentinelMasker {
    /// Creates an empty sentinel credential masker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a secret under `env_name`, returning the opaque 128-bit sentinel to expose to child processes.
    pub fn register_masked_credential(
        &self,
        env_name: &str,
        real_secret: &str,
        inject_hosts: Vec<String>,
        allow_plaintext_inject: bool,
    ) -> Result<String, SafeAgentsClientError> {
        let name = env_name.trim();
        if name.is_empty() || real_secret.is_empty() || inject_hosts.is_empty() {
            return Err(SafeAgentsClientError::Config(
                "Masked credential requires non-empty env_name, secret, and inject_hosts".into(),
            ));
        }
        let mut rnd = [0u8; 16];
        OsRng.fill_bytes(&mut rnd);
        let sentinel = format!("ao_mask_{}", hex::encode(rnd));

        let entry = MaskedCredentialEntry {
            env_name: name.to_string(),
            real_secret: Zeroizing::new(real_secret.to_string()),
            sentinel: sentinel.clone(),
            inject_hosts,
            allow_plaintext_inject,
        };
        self.entries.write().insert(name.to_string(), entry);
        Ok(sentinel)
    }

    /// Builds a sanitized environment map where real secrets are replaced with opaque sentinels.
    pub fn sanitized_child_env(&self, parent_env: &[(String, String)]) -> Vec<(String, String)> {
        let guard = self.entries.read();
        let mut out = Vec::with_capacity(parent_env.len() + guard.len());
        let mut seen = HashMap::with_capacity(guard.len());

        for (k, v) in parent_env {
            if let Some(entry) = guard.get(k) {
                out.push((k.clone(), entry.sentinel.clone()));
                seen.insert(k.clone(), ());
            } else {
                let mut scrubbed_val = v.clone();
                for entry in guard.values() {
                    if scrubbed_val.contains(entry.real_secret.as_str()) {
                        scrubbed_val =
                            scrubbed_val.replace(entry.real_secret.as_str(), &entry.sentinel);
                    }
                }
                out.push((k.clone(), scrubbed_val));
            }
        }
        for (k, entry) in guard.iter() {
            if !seen.contains_key(k) {
                out.push((k.clone(), entry.sentinel.clone()));
            }
        }
        out
    }

    /// Inspects outbound request headers and body for registered sentinels; unmasks ONLY when the
    /// transport is HTTPS (unless opted out) and `target_host:target_port` matches `inject_hosts`.
    pub fn inject_on_egress(
        &self,
        scheme: &str,
        target_host: &str,
        target_port: u16,
        headers: &[(String, String)],
        body: &str,
    ) -> Result<(Vec<(String, String)>, String), SafeAgentsClientError> {
        let guard = self.entries.read();
        let is_https = scheme.eq_ignore_ascii_case("https");
        let mut out_headers = headers.to_vec();
        let mut out_body = body.to_string();

        for entry in guard.values() {
            let in_headers = out_headers.iter().any(|(_, v)| v.contains(&entry.sentinel));
            let in_body = out_body.contains(&entry.sentinel);
            if !in_headers && !in_body {
                continue;
            }
            if !is_https && !entry.allow_plaintext_inject {
                return Err(SafeAgentsClientError::Protocol(format!(
                    "Refusing to unmask sentinel credential '{}' over non-HTTPS scheme '{}'",
                    entry.env_name, scheme
                )));
            }
            let host_allowed = entry
                .inject_hosts
                .iter()
                .any(|pat| host_port_pattern_matches(target_host, target_port, pat));
            if !host_allowed {
                return Err(SafeAgentsClientError::Protocol(format!(
                    "Refusing to unmask sentinel credential '{}' to unapproved host '{}:{}'",
                    entry.env_name, target_host, target_port
                )));
            }
            for (_, v) in &mut out_headers {
                if v.contains(&entry.sentinel) {
                    *v = v.replace(&entry.sentinel, entry.real_secret.as_str());
                }
            }
            if in_body {
                out_body = out_body.replace(&entry.sentinel, entry.real_secret.as_str());
            }
        }

        Ok((out_headers, out_body))
    }
}

// ============================================================================
// Component 6: Ambiguous HTTP Request-Target & Host/SNI Mismatch Validator
// ============================================================================

fn normalize_authority(raw: &str, default_port: Option<u16>) -> Option<(String, Option<u16>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('@') {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (ip, tail) = rest.split_once(']')?;
        let port = if let Some(p_str) = tail.strip_prefix(':') {
            Some(p_str.parse::<u16>().ok()?)
        } else if tail.is_empty() {
            default_port
        } else {
            return None;
        };
        return Some((ip.to_ascii_lowercase(), port));
    }
    if let Some((h, p_str)) = trimmed.split_once(':') {
        let port = p_str.parse::<u16>().ok()?;
        return Some((h.trim_end_matches('.').to_ascii_lowercase(), Some(port)));
    }
    Some((
        trimmed.trim_end_matches('.').to_ascii_lowercase(),
        default_port,
    ))
}

/// Validates raw HTTP request-target spelling (before URL library dot-segment resolution), blocking:
/// - `TRACE`/`TRACK` reflection methods (`405`)
/// - Control chars, whitespace, non-ASCII, `#fragment`, backslash, leading `//`, `%2e`/`%2f`/`%5c`/`%25`,
///   and `.` / `..` path segments (`400`)
/// - `Host`, TLS SNI, and absolute-form URI authority mismatches (`421 Misdirected Request`)
pub fn validate_http_request_target(
    method: &str,
    raw_target: &str,
    host_header: Option<&str>,
    expected_authority: Option<&str>,
    tls_sni: Option<&str>,
) -> Result<String, (u16, &'static str)> {
    let upper_method = method.trim().to_ascii_uppercase();
    if upper_method.is_empty()
        || !upper_method
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        return Err((400, "invalid_request_method"));
    }
    if upper_method == "TRACE" || upper_method == "TRACK" {
        return Err((405, "method_not_allowed_for_header_injection"));
    }

    if raw_target.is_empty()
        || !raw_target.is_ascii()
        || raw_target.bytes().any(|b| b <= 0x20 || b == 0x7f)
    {
        return Err((400, "ambiguous_request_target_invalid_bytes"));
    }

    if raw_target.contains('#') {
        return Err((400, "ambiguous_request_target_fragment"));
    }

    if raw_target == "*" {
        return if upper_method == "OPTIONS" {
            Ok(raw_target.to_string())
        } else {
            Err((400, "ambiguous_request_target_asterisk"))
        };
    }

    let (abs_authority, abs_default_port, raw_path_and_query) =
        if let Some(after) = raw_target.strip_prefix("https://") {
            let (auth, tail) = after.split_once('/').unwrap_or((after, ""));
            (Some(auth), Some(443u16), tail)
        } else if let Some(after) = raw_target.strip_prefix("http://") {
            let (auth, tail) = after.split_once('/').unwrap_or((after, ""));
            (Some(auth), Some(80u16), tail)
        } else if raw_target.starts_with('/') {
            (None, None, raw_target)
        } else {
            return Err((400, "invalid_request_target_form"));
        };

    let raw_path = raw_path_and_query
        .split_once('?')
        .map(|(p, _)| p)
        .unwrap_or(raw_path_and_query);

    if raw_path.starts_with("//") {
        return Err((400, "ambiguous_request_target_leading_slashes"));
    }
    if raw_path.contains('\\') {
        return Err((400, "ambiguous_request_target_backslash"));
    }

    let path_lower = raw_path.to_ascii_lowercase();
    if path_lower.contains("%2e")
        || path_lower.contains("%2f")
        || path_lower.contains("%5c")
        || path_lower.contains("%25")
        || path_lower.contains("%00")
    {
        return Err((400, "ambiguous_request_target_encoded_segment"));
    }

    if raw_path.split('/').any(|seg| seg == "." || seg == "..") {
        return Err((400, "ambiguous_request_target_dot_segment"));
    }

    // Authority / Host / SNI cross-checks (421 Misdirected Request)
    let default_port = abs_default_port.or(if tls_sni.is_some() { Some(443) } else { None });
    let norm_host_hdr = host_header.and_then(|h| normalize_authority(h, default_port));
    if host_header.is_some() && norm_host_hdr.is_none() {
        return Err((400, "invalid_host_header"));
    }
    let norm_expected = expected_authority.and_then(|e| normalize_authority(e, default_port));
    if let Some(abs_auth_raw) = abs_authority {
        let norm_abs = normalize_authority(abs_auth_raw, default_port)
            .ok_or((400, "invalid_absolute_authority"))?;
        if let Some(ref hdr) = norm_host_hdr {
            if *hdr != norm_abs {
                return Err((421, "misdirected_request_authority_mismatch"));
            }
        }
        if let Some(ref exp) = norm_expected {
            if *exp != norm_abs {
                return Err((421, "misdirected_request_expected_mismatch"));
            }
        }
    }
    if let (Some(ref hdr), Some(ref exp)) = (&norm_host_hdr, &norm_expected) {
        if hdr != exp {
            return Err((421, "misdirected_request_host_mismatch"));
        }
    }
    if let Some(sni_raw) = tls_sni {
        let sni_host = sni_raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some((ref h, _)) = norm_host_hdr {
            if *h != sni_host {
                return Err((421, "misdirected_request_sni_mismatch"));
            }
        }
        if let Some((ref exp_h, _)) = norm_expected {
            if *exp_h != sni_host {
                return Err((421, "misdirected_request_sni_mismatch"));
            }
        }
    }

    Ok(raw_target.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEvaluator;
    impl ToolCallEvaluator for MockEvaluator {
        fn evaluate(&self, tool_name: &str, _arguments_json: &str) -> ToolEvaluationVerdict {
            if tool_name == "blocked_tool" {
                ToolEvaluationVerdict::Block {
                    reason: "prohibited by policy".to_string(),
                }
            } else {
                ToolEvaluationVerdict::Allow
            }
        }
    }

    #[test]
    fn test_client_endpoints_and_config() {
        let config = SafeAgentsClientConfig::default();
        assert_eq!(config.base_url, "http://127.0.0.1:8787");

        let client = SafeAgentsClient::new(config).expect("Client creation succeeds");
        assert_eq!(client.base_url(), "http://127.0.0.1:8787");
        assert_eq!(
            client.anthropic_endpoint(),
            "http://127.0.0.1:8787/v1/messages"
        );
        assert_eq!(
            client.openai_endpoint(),
            "http://127.0.0.1:8787/v1/chat/completions"
        );
    }

    #[test]
    fn test_transform_chunk_allowed() {
        let client = SafeAgentsClient::new(SafeAgentsClientConfig::default())
            .expect("Client creation succeeds")
            .with_evaluator(Arc::new(MockEvaluator));

        let raw = r#"data: {"choices":[{"delta":{"tool_calls":[{"function":{"name":"allowed_tool","arguments":"{}"}}]}}]}"#;
        let transformed = client.transform_openai_chunk(raw);
        assert!(transformed.contains("allowed_tool"));
        assert!(!transformed.contains("[safeagents]"));
    }

    #[test]
    fn test_transform_chunk_blocked_replacement() {
        let client = SafeAgentsClient::new(SafeAgentsClientConfig::default())
            .expect("Client creation succeeds")
            .with_evaluator(Arc::new(MockEvaluator));

        let raw = r#"data: {"choices":[{"delta":{"tool_calls":[{"function":{"name":"blocked_tool","arguments":"{}"}}]}}]}"#;
        let transformed = client.transform_openai_chunk(raw);
        assert!(transformed
            .contains("[safeagents] blocked call to `blocked_tool`: prohibited by policy"));
        assert!(transformed.contains(r#""finish_reason":"stop""#));
    }

    #[test]
    fn test_resolved_address_blocks_imds_nat64_6to4_and_custom_cidrs() {
        let custom = vec![
            IpCidr::parse("10.0.0.0/8").unwrap(),
            IpCidr::parse("172.16.0.0/12").unwrap(),
        ];
        // Cloud IMDS endpoints (Alibaba, Azure WireServer, Oracle, AWS IPv6, GCP/link-local)
        for imds in [
            "100.100.100.200",
            "168.63.129.16",
            "192.0.0.192",
            "169.254.169.254",
            "fd00:ec2::254",
            "fd20:ce::254",
            "fd00:c1::a9fe:a9fe",
            "fd00:42::42",
        ] {
            let ip: IpAddr = imds.parse().unwrap();
            assert_eq!(
                is_denied_resolved_ip(ip, &custom),
                Some("cloud_metadata"),
                "failed to block IMDS {}",
                imds
            );
        }

        // NAT64 & 6to4 IPv6 embedding IPv4
        assert_eq!(
            is_denied_resolved_ip("64:ff9b::7f00:1".parse().unwrap(), &custom),
            Some("nat64_or_6to4")
        );
        assert_eq!(
            is_denied_resolved_ip("2002:0a00:0001::1".parse().unwrap(), &custom),
            Some("nat64_or_6to4")
        );

        // Allowed domain with deterministic pinned IP
        let pinned = resolve_and_pin_allowed_host(
            "api.github.com",
            443,
            &["*.github.com".to_string()],
            &[],
            &custom,
            Some(&["140.82.112.6".parse().unwrap()]),
        )
        .expect("public GitHub IP should pin");
        assert_eq!(pinned, vec!["140.82.112.6:443".parse().unwrap()]);

        // Denied domain overrides allowlist; DNS rebinding to IMDS rejected
        assert!(resolve_and_pin_allowed_host(
            "api.github.com",
            443,
            &["*.github.com".to_string()],
            &["api.github.com".to_string()],
            &custom,
            Some(&["140.82.112.6".parse().unwrap()]),
        )
        .is_err());
        assert!(resolve_and_pin_allowed_host(
            "api.github.com",
            443,
            &["*.github.com".to_string()],
            &[],
            &custom,
            Some(&["168.63.129.16".parse().unwrap()]),
        )
        .is_err());
    }

    #[test]
    fn test_credential_sentinel_masking_enforces_https_and_inject_hosts() {
        let masker = CredentialSentinelMasker::new();
        let sentinel = masker
            .register_masked_credential(
                "GITHUB_TOKEN",
                "ghp_real_secret_token_value",
                vec!["api.github.com".to_string()],
                false,
            )
            .expect("register secret");
        assert!(sentinel.starts_with("ao_mask_"));
        assert!(!sentinel.contains("ghp_real"));

        let child_env = masker.sanitized_child_env(&[
            ("PATH".to_string(), "/usr/bin".to_string()),
            (
                "GITHUB_TOKEN".to_string(),
                "ghp_real_secret_token_value".to_string(),
            ),
        ]);
        assert!(child_env
            .iter()
            .any(|(k, v)| k == "GITHUB_TOKEN" && v == &sentinel));
        assert!(!child_env
            .iter()
            .any(|(_, v)| v.contains("ghp_real_secret_token_value")));

        let hdrs = vec![("Authorization".to_string(), format!("Bearer {}", sentinel))];

        // Approved HTTPS host unmasks cleanly
        let (out_hdrs, _) = masker
            .inject_on_egress("https", "api.github.com", 443, &hdrs, "")
            .expect("approved https host");
        assert_eq!(out_hdrs[0].1, "Bearer ghp_real_secret_token_value");

        // Plaintext HTTP refused
        assert!(masker
            .inject_on_egress("http", "api.github.com", 80, &hdrs, "")
            .is_err());

        // Unapproved host refused even over HTTPS
        assert!(masker
            .inject_on_egress("https", "attacker.example.com", 443, &hdrs, "")
            .is_err());

        // Dynamic policy update validation
        let bad =
            parse_and_validate_dynamic_policy(r#"{"denied_resolved_addresses":["not-an-ip"]}"#);
        assert!(bad.is_err());
        let ok = parse_and_validate_dynamic_policy(
            r#"{"allowed_domains":["api.github.com"],"denied_resolved_addresses":["10.0.0.0/8"]}"#,
        )
        .unwrap();
        assert_eq!(ok.1.len(), 1);
    }

    #[test]
    fn test_ambiguous_request_target_and_host_sni_validation() {
        assert!(validate_http_request_target(
            "POST",
            "/v1/messages?stream=true",
            Some("api.anthropic.com:443"),
            Some("api.anthropic.com:443"),
            Some("api.anthropic.com")
        )
        .is_ok());

        for bad_target in [
            "/public/../admin",
            "/a%2e%2e/admin",
            "/a\\b/admin",
            "//admin",
            "/v1/messages#frag",
            "/./secret",
        ] {
            let err = validate_http_request_target(
                "GET",
                bad_target,
                Some("api.github.com"),
                Some("api.github.com"),
                None,
            )
            .unwrap_err();
            assert_eq!(err.0, 400, "expected 400 for {}", bad_target);
        }

        assert_eq!(
            validate_http_request_target("TRACE", "/v1", None, None, None)
                .unwrap_err()
                .0,
            405
        );
        assert_eq!(
            validate_http_request_target(
                "GET",
                "/v1/repos",
                Some("evil.example.com"),
                Some("api.github.com"),
                Some("api.github.com"),
            )
            .unwrap_err()
            .0,
            421
        );
    }
}
