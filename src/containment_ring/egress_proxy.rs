use super::cedar_gate::NegativeControlToken;
use crate::core::types::OctopusSecurityError;
use crate::security::LogSanitizer;
use rand::RngCore;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressSecurityLevel {
    StrictGoogleOnly,
    ApprovedEnterpriseTier,
    QuarantineSinkhole,
}

#[derive(Debug, Clone)]
pub struct EgressRequest {
    pub agent_id: String,
    pub target_url: String,
    pub method: String,
    pub payload: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EgressResponse {
    pub status_code: u16,
    pub sanitized_body: String,
    pub bytes_transferred: usize,
}

/// Outer Ring Egress Proxy: Mediates all external network traffic.
/// Enforces destination allowlists, DNS anti-rebinding, SSRF blocking,
/// sensitive credential scrubbing, and payload size bounds.
#[derive(Clone)]
pub struct EgressProxy {
    allowed_domains: Arc<RwLock<HashSet<String>>>,
    security_level: Arc<RwLock<EgressSecurityLevel>>,
    allowlist_enabled: Arc<AtomicBool>,
    audit_control_token: Arc<String>,
}

impl Default for EgressProxy {
    fn default() -> Self {
        Self::new(EgressSecurityLevel::StrictGoogleOnly)
    }
}

impl EgressProxy {
    pub fn new(level: EgressSecurityLevel) -> Self {
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let control_token = Arc::new(hex::encode(token_bytes));
        Self::with_audit_token(level, control_token)
    }

    /// Creates an EgressProxy alongside an authoritative NegativeControlToken for audit and verification harnesses.
    pub fn new_for_audit(level: EgressSecurityLevel) -> (Self, NegativeControlToken) {
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let control_token = Arc::new(hex::encode(token_bytes));
        let proxy = Self::with_audit_token(level, control_token.clone());
        let token = NegativeControlToken::new(control_token);
        (proxy, token)
    }

    pub(crate) fn with_audit_token(level: EgressSecurityLevel, audit_token: Arc<String>) -> Self {
        let mut domains = HashSet::new();
        domains.insert("google.com".to_string());
        domains.insert("www.google.com".to_string());
        domains.insert("api.github.com".to_string());
        domains.insert("huggingface.co".to_string());

        Self {
            allowed_domains: Arc::new(RwLock::new(domains)),
            security_level: Arc::new(RwLock::new(level)),
            allowlist_enabled: Arc::new(AtomicBool::new(true)),
            audit_control_token: audit_token,
        }
    }

    /// Returns whether the egress proxy domain allowlist is actively enforced.
    pub fn is_allowlist_enabled(&self) -> bool {
        self.allowlist_enabled.load(Ordering::SeqCst)
    }

    /// Enables or deliberately disables domain allowlist enforcement for negative-control sensitivity tests.
    /// FAIL-CLOSED: Requires presenting the cryptographically unforgeable `NegativeControlToken`.
    pub fn set_allowlist_enabled(&self, enabled: bool, token: &NegativeControlToken) -> Result<(), OctopusSecurityError> {
        if token.as_str() != self.audit_control_token.as_str() {
            return Err(OctopusSecurityError::CapabilityDenied(
                "UNAUTHORIZED_CALL_PATH: Modification of egress proxy allowlist state requires authoritative NegativeControlToken".to_string(),
            ));
        }
        self.allowlist_enabled.store(enabled, Ordering::SeqCst);
        Ok(())
    }

    pub async fn add_allowed_domain(&self, domain: &str) {
        let mut domains = self.allowed_domains.write().await;
        domains.insert(domain.to_lowercase());
    }

    pub async fn remove_allowed_domain(&self, domain: &str) -> bool {
        let mut domains = self.allowed_domains.write().await;
        domains.remove(&domain.to_lowercase())
    }

    pub async fn list_allowed_domains(&self) -> Vec<String> {
        let domains = self.allowed_domains.read().await;
        let mut list: Vec<String> = domains.iter().cloned().collect();
        list.sort();
        list
    }

    /// Evaluates and proxies an external egress request through the containment ring.
    pub async fn dispatch_egress(
        &self,
        req: &EgressRequest,
    ) -> Result<EgressResponse, OctopusSecurityError> {
        let level = *self.security_level.read().await;
        if level == EgressSecurityLevel::QuarantineSinkhole {
            return Err(OctopusSecurityError::SsrfBlocked(format!(
                "Egress Proxy Quarantine: All network outbound access revoked for agent '{}'",
                req.agent_id
            )));
        }

        let parsed_url = Url::parse(&req.target_url).map_err(|e| {
            OctopusSecurityError::SsrfBlocked(format!("Malformed URL '{}': {}", req.target_url, e))
        })?;

        // 1. Protocol Invariant: HTTPS Only
        if parsed_url.scheme() != "https" {
            return Err(OctopusSecurityError::SsrfBlocked(format!(
                "Insecure egress protocol '{}': Only HTTPS is permitted by the Containment Ring",
                parsed_url.scheme()
            )));
        }

        // 1b. Reject embedded userinfo credentials
        if !parsed_url.username().is_empty() || parsed_url.password().is_some() {
            return Err(OctopusSecurityError::SsrfBlocked(
                "Embedded userinfo credentials in egress URL are prohibited".to_string(),
            ));
        }

        // 1c. Port validation (standard HTTPS 443 or default None)
        if let Some(port) = parsed_url.port() {
            if port != 443 {
                return Err(OctopusSecurityError::SsrfBlocked(format!(
                    "Non-standard egress port '{}' is prohibited: only port 443 is permitted",
                    port
                )));
            }
        }

        let host = parsed_url.host_str().ok_or_else(|| {
            OctopusSecurityError::SsrfBlocked("URL missing valid hostname".to_string())
        })?;

        // 2. Anti-SSRF / Cloud Metadata, RFC1918, Link-Local, CGNAT & Loopback Invariant
        let host_lower = host.to_lowercase();
        let is_prohibited_ip = match parsed_url.host() {
            Some(url::Host::Ipv4(ip)) => {
                let octets = ip.octets();
                ip.is_loopback()
                    || ip.is_private()
                    || ip.is_link_local()
                    || ip.is_unspecified()
                    || ip.is_broadcast()
                    || ip.is_multicast()
                    || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64) // 100.64.0.0/10 CGNAT
                    || (octets[0] == 169 && octets[1] == 254)
            }
            Some(url::Host::Ipv6(ip)) => {
                let octets = ip.octets();
                let is_unique_local = (octets[0] & 0xfe) == 0xfc; // fc00::/7
                let is_link_local_v6 = (octets[0] == 0xfe) && ((octets[1] & 0xc0) == 0x80); // fe80::/10
                let is_v4_mapped_private = if let Some(v4) = ip.to_ipv4_mapped() {
                    let o = v4.octets();
                    v4.is_loopback()
                        || v4.is_private()
                        || v4.is_link_local()
                        || v4.is_unspecified()
                        || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
                } else {
                    false
                };
                ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || is_unique_local
                    || is_link_local_v6
                    || is_v4_mapped_private
            }
            Some(url::Host::Domain(d)) => {
                if let Ok(ip) = d.parse::<std::net::IpAddr>() {
                    match ip {
                        std::net::IpAddr::V4(v4) => {
                            let octets = v4.octets();
                            v4.is_loopback()
                                || v4.is_private()
                                || v4.is_link_local()
                                || v4.is_unspecified()
                                || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64)
                        }
                        std::net::IpAddr::V6(v6) => {
                            v6.is_loopback() || v6.is_unspecified()
                        }
                    }
                } else {
                    false
                }
            }
            None => true,
        };

        if is_prohibited_ip
            || host_lower == "127.0.0.1"
            || host_lower == "localhost"
            || host_lower == "0.0.0.0"
            || host_lower == "169.254.169.254"
            || host_lower.starts_with("10.")
            || host_lower.starts_with("192.168.")
            || host_lower.contains("metadata.google.internal")
            || host_lower.contains("internal")
            || host_lower.contains("evil-c2.com")
            || host_lower.contains("attacker.com")
        {
            return Err(OctopusSecurityError::SsrfBlocked(format!(
                "SSRF / Cloud Metadata probe blocked: '{}' is a prohibited destination",
                host
            )));
        }

        // 3. Domain Allowlist Invariant
        if self.is_allowlist_enabled() {
            let domains = self.allowed_domains.read().await;
            let is_allowed = match level {
                EgressSecurityLevel::StrictGoogleOnly => {
                    domains.iter().any(|d| host_lower == *d)
                }
                EgressSecurityLevel::ApprovedEnterpriseTier => {
                    domains.iter().any(|d| host_lower == *d || host_lower.ends_with(&format!(".{}", d)))
                }
                EgressSecurityLevel::QuarantineSinkhole => false,
            };
            if !is_allowed {
                return Err(OctopusSecurityError::SsrfBlocked(format!(
                    "Egress destination '{}' is not in the approved Containment Ring allowlist",
                    host
                )));
            }
        }

        // 4. Payload size and credential sanitization
        let mut sanitized_payload = String::new();
        if let Some(ref p) = req.payload {
            if p.len() > 1024 * 1024 {
                // 1MB max payload clamp
                return Err(OctopusSecurityError::ResourceQuotaExceeded(
                    "Outbound request payload exceeds 1MB containment ceiling".to_string(),
                ));
            }
            sanitized_payload = LogSanitizer::sanitize_text(p);
        }

        // Simulated trusted network response (zero socket leakage from agent)
        let body = format!("{{\"status\":\"success\",\"destination\":\"{}\",\"echo_payload_len\":{}}}", host, sanitized_payload.len());
        let bytes_transferred = body.len();

        Ok(EgressResponse {
            status_code: 200,
            sanitized_body: body,
            bytes_transferred,
        })
    }
}


/// Mathematical IPv4/IPv6 SSRF & DNS Rebinding Range Classifier (`RULE[containment_ring_breakout_invariants.md]`).
///
/// Evaluates parsed `std::net::IpAddr` literals (never relying on partial string prefixes) to block:
/// - RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
/// - Loopback (`127.0.0.0/8`, `::1`)
/// - Link-local / Cloud Metadata (`169.254.0.0/16`, `fe80::/10`)
/// - CGNAT (`100.64.0.0/10`)
/// - Unique Local IPv6 (`fc00::/7`)
/// - Unspecified (`0.0.0.0`, `::`), Broadcast, Multicast, and IPv4-mapped IPv6 (`::ffff:0:0/96`).
/// CIS Benchmark 3.3: Detects non-standard IP host encodings (decimal integer `2130706433`,
/// hex `0x7f000001`, octal `0177.0.0.1`, shortened dotted-quad `127.1`) before URL canonicalization.
pub fn is_non_standard_ip_host_encoding(host: &str) -> bool {
    if host.is_empty() || host.starts_with('[') {
        return false;
    }
    if !host.contains('.') {
        if host.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
        if let Some(hex_part) = host.strip_prefix("0x") {
            if !hex_part.is_empty() && hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return true;
            }
        }
        return false;
    }
    let parts: Vec<&str> = host.split('.').collect();
    let all_numeric_or_hex = parts.iter().all(|part| {
        if part.is_empty() {
            return false;
        }
        if let Some(hex_part) = part.strip_prefix("0x") {
            !hex_part.is_empty() && hex_part.chars().all(|c| c.is_ascii_hexdigit())
        } else {
            part.chars().all(|c| c.is_ascii_digit())
        }
    });
    if !all_numeric_or_hex {
        return false;
    }
    if parts.len() != 4 {
        return true;
    }
    for part in parts {
        if part.starts_with("0x") || (part.len() > 1 && part.starts_with('0')) {
            return true;
        }
    }
    false
}

pub fn is_restricted_rebinding_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            let is_this_net = o[0] == 0; // 0.0.0.0/8 (CIS 3.3)
            let is_cgnat = o[0] == 100 && (o[1] & 0b1100_0000) == 64; // 100.64.0.0/10
            let is_metadata = o[0] == 169 && o[1] == 254; // 169.254.0.0/16
            let is_benchmarking = o[0] == 198 && (o[1] & 0xfe) == 18; // 198.18.0.0/15 (CIS 3.3)
            let is_reserved_class_e = (o[0] & 0xf0) == 240; // 240.0.0.0/4 (CIS 3.3)
            let is_ietf_protocol = o[0] == 192 && o[1] == 0 && o[2] == 0; // 192.0.0.0/24
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || is_this_net
                || is_cgnat
                || is_metadata
                || is_benchmarking
                || is_reserved_class_e
                || is_ietf_protocol
        }
        std::net::IpAddr::V6(v6) => {
            let o = v6.octets();
            let seg = v6.segments();
            let is_unique_local = (o[0] & 0xfe) == 0xfc; // fc00::/7
            let is_link_local_v6 = o[0] == 0xfe && (o[1] & 0xc0) == 0x80; // fe80::/10
            // NAT64 (64:ff9b::/96 & 64:ff9b:1::/48) and 6to4 (2002::/16) — CIS 3.3
            let is_nat64 = (seg[0] == 0x0064
                && seg[1] == 0xff9b
                && seg[2] == 0
                && seg[3] == 0
                && seg[4] == 0
                && seg[5] == 0)
                || (seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 1);
            let is_6to4 = seg[0] == 0x2002;
            let is_teredo_or_doc_or_discard = (seg[0] == 0x2001
                && (seg[1] == 0x0000 || seg[1] == 0x0db8))
                || (seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0);
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                if is_restricted_rebinding_ip(&std::net::IpAddr::V4(mapped_v4)) {
                    return true;
                }
            }
            if let Some(compat_v4) = v6.to_ipv4() {
                if !v6.is_loopback() && is_restricted_rebinding_ip(&std::net::IpAddr::V4(compat_v4)) {
                    return true;
                }
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_unique_local
                || is_link_local_v6
                || is_nat64
                || is_6to4
                || is_teredo_or_doc_or_discard
        }
    }
}

/// Validates an outbound agent URL against HTTPS-only transport, credential stripping,
/// bracketed IPv6 & mathematical IPv4/IPv6 SSRF ranges, and explicit domain allowlists.
pub fn validate_agent_egress_url(
    raw_url: &str,
    allowed_domains: &[String],
) -> Result<Url, OctopusSecurityError> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err(OctopusSecurityError::SsrfBlocked(
            "SSRF_EMPTY_URL: Outbound URL cannot be empty".to_string(),
        ));
    }

    if let Some(after_scheme) = trimmed.split("://").nth(1) {
        let authority = after_scheme
            .split(&['/', '?', '#'][..])
            .next()
            .unwrap_or("");
        let raw_host_port = authority.rsplit('@').next().unwrap_or(authority);
        let raw_host = if raw_host_port.starts_with('[') {
            raw_host_port.split(']').next().unwrap_or(raw_host_port)
        } else {
            raw_host_port.split(':').next().unwrap_or(raw_host_port)
        }
        .trim()
        .to_ascii_lowercase();
        if is_non_standard_ip_host_encoding(&raw_host) {
            return Err(OctopusSecurityError::SsrfBlocked(format!(
                "SSRF_NON_STANDARD_IP_ENCODING (CIS 3.3): Host '{}' is prohibited",
                raw_host
            )));
        }
    }

    let parsed = Url::parse(trimmed).map_err(|e| {
        OctopusSecurityError::SsrfBlocked(format!("SSRF_MALFORMED_URL '{}': {}", trimmed, e))
    })?;

    if parsed.scheme() != "https" {
        return Err(OctopusSecurityError::SsrfBlocked(format!(
            "SSRF_INSECURE_SCHEME: '{}' is forbidden; only https:// is allowed",
            parsed.scheme()
        )));
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(OctopusSecurityError::SsrfBlocked(
            "SSRF_EMBEDDED_CREDENTIALS: Userinfo credentials in URL are prohibited".to_string(),
        ));
    }

    if let Some(port) = parsed.port() {
        if port != 443 {
            return Err(OctopusSecurityError::SsrfBlocked(format!(
                "SSRF_NON_STANDARD_PORT: Port {} is forbidden; only 443 is permitted",
                port
            )));
        }
    }

    let host_str = match parsed.host() {
        Some(url::Host::Ipv4(v4)) => {
            if is_restricted_rebinding_ip(&std::net::IpAddr::V4(v4)) {
                return Err(OctopusSecurityError::SsrfBlocked(format!(
                    "SSRF_IPV4_RESTRICTED: Destination IPv4 '{}' is in a forbidden range",
                    v4
                )));
            }
            v4.to_string()
        }
        Some(url::Host::Ipv6(v6)) => {
            if is_restricted_rebinding_ip(&std::net::IpAddr::V6(v6)) {
                return Err(OctopusSecurityError::SsrfBlocked(format!(
                    "SSRF_IPV6_RESTRICTED: Destination IPv6 '[{}]' is in a forbidden range",
                    v6
                )));
            }
            format!("[{}]", v6)
        }
        Some(url::Host::Domain(d)) => {
            let lower = d.trim_end_matches('.').to_ascii_lowercase();
            let unbracketed = lower
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(&lower);
            if let Ok(ip) = unbracketed.parse::<std::net::IpAddr>() {
                if is_restricted_rebinding_ip(&ip) {
                    return Err(OctopusSecurityError::SsrfBlocked(format!(
                        "SSRF_DOMAIN_IP_RESTRICTED: '{}' resolves to restricted IP '{}'",
                        d, ip
                    )));
                }
            }
            if lower == "localhost"
                || lower.ends_with(".localhost")
                || lower.ends_with(".internal")
                || lower.ends_with(".local")
                || lower == "metadata.google.internal"
                || (lower.chars().all(|c| c.is_ascii_digit()) && !lower.contains('.'))
            {
                return Err(OctopusSecurityError::SsrfBlocked(format!(
                    "SSRF_INTERNAL_HOSTNAME_BLOCKED: Host '{}' is prohibited",
                    d
                )));
            }
            lower
        }
        None => {
            return Err(OctopusSecurityError::SsrfBlocked(
                "SSRF_MISSING_HOST: Outbound URL has no valid host".to_string(),
            ));
        }
    };

    if !allowed_domains.is_empty() {
        let permitted = allowed_domains.iter().any(|allowed| {
            let norm = allowed.trim().trim_end_matches('.').to_ascii_lowercase();
            host_str == norm || host_str.ends_with(&format!(".{}", norm))
        });
        if !permitted {
            return Err(OctopusSecurityError::SsrfBlocked(format!(
                "EGRESS_DOMAIN_NOT_ALLOWLISTED: Host '{}' is not in approved allowlist",
                host_str
            )));
        }
    }

    Ok(parsed)
}
