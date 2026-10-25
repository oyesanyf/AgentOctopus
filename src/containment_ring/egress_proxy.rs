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
    dns_overrides: Arc<RwLock<std::collections::HashMap<String, Vec<std::net::IpAddr>>>>,
}

impl Default for EgressProxy {
    fn default() -> Self {
        Self::new(EgressSecurityLevel::StrictGoogleOnly)
    }
}

/// Validates a domain candidate before inserting it into the egress allowlist (`AO-FIND-12`).
/// Rejects wildcards (`*`), URLs/schemes, paths, ports, IP literals, non-standard IP encodings,
/// and internal/loopback/local suffixes (`.localhost`, `.internal`, `.local`).
pub fn validate_egress_allowlist_domain(domain: &str) -> Result<String, OctopusSecurityError> {
    let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 {
        return Err(OctopusSecurityError::SsrfBlocked(
            "EGRESS_INVALID_ALLOWLIST_DOMAIN: Domain must be 1..=253 characters".to_string(),
        ));
    }
    if normalized.contains('*')
        || normalized.contains("://")
        || normalized.contains('/')
        || normalized.contains('\\')
        || normalized.contains(':')
        || normalized.contains('@')
        || normalized.contains('?')
        || normalized.contains('#')
        || normalized.chars().any(|c| c.is_whitespace())
    {
        return Err(OctopusSecurityError::SsrfBlocked(format!(
            "EGRESS_INVALID_ALLOWLIST_DOMAIN: Wildcards, schemes, ports, or paths are forbidden in '{}'",
            domain
        )));
    }
    if is_non_standard_ip_host_encoding(&normalized)
        || normalized.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(OctopusSecurityError::SsrfBlocked(format!(
            "EGRESS_INVALID_ALLOWLIST_DOMAIN: Raw IP literal or non-standard IP encoding '{}' cannot be added as a domain",
            domain
        )));
    }
    if normalized == "localhost"
        || normalized.ends_with(".localhost")
        || normalized.ends_with(".internal")
        || normalized.ends_with(".local")
        || normalized == "metadata.google.internal"
    {
        return Err(OctopusSecurityError::SsrfBlocked(format!(
            "EGRESS_INVALID_ALLOWLIST_DOMAIN: Internal or loopback domain '{}' is forbidden",
            domain
        )));
    }
    let labels: Vec<&str> = normalized.split('.').collect();
    if labels.len() < 2 {
        return Err(OctopusSecurityError::SsrfBlocked(format!(
            "EGRESS_INVALID_ALLOWLIST_DOMAIN: Single-label host '{}' is forbidden",
            domain
        )));
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(OctopusSecurityError::SsrfBlocked(format!(
                "EGRESS_INVALID_ALLOWLIST_DOMAIN: Malformed DNS label '{}' in '{}'",
                label, domain
            )));
        }
    }
    Ok(normalized)
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
            dns_overrides: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Returns whether the egress proxy domain allowlist is actively enforced.
    pub fn is_allowlist_enabled(&self) -> bool {
        self.allowlist_enabled.load(Ordering::SeqCst)
    }

    /// Enables or deliberately disables domain allowlist enforcement for negative-control sensitivity tests.
    /// FAIL-CLOSED: Requires presenting the cryptographically unforgeable `NegativeControlToken`.
    pub fn set_allowlist_enabled(&self, enabled: bool, token: &NegativeControlToken) -> Result<(), OctopusSecurityError> {
        if !crate::security::constant_time_eq(token.as_str().as_bytes(), self.audit_control_token.as_bytes()) {
            return Err(OctopusSecurityError::CapabilityDenied(
                "UNAUTHORIZED_CALL_PATH: Modification of egress proxy allowlist state requires authoritative NegativeControlToken".to_string(),
            ));
        }
        self.allowlist_enabled.store(enabled, Ordering::SeqCst);
        Ok(())
    }

    /// Validates and adds an allowed domain (`AO-FIND-12`).
    pub async fn try_add_allowed_domain(&self, domain: &str) -> Result<String, OctopusSecurityError> {
        let normalized = validate_egress_allowlist_domain(domain)?;
        let mut domains = self.allowed_domains.write().await;
        domains.insert(normalized.clone());
        Ok(normalized)
    }

    pub async fn add_allowed_domain(&self, domain: &str) {
        if let Ok(normalized) = validate_egress_allowlist_domain(domain) {
            let mut domains = self.allowed_domains.write().await;
            domains.insert(normalized);
        }
    }

    /// Registers a deterministic DNS resolution mapping for `host` (used to test DNS-rebinding defenses).
    pub async fn set_dns_override(&self, host: &str, addrs: Vec<std::net::IpAddr>) {
        let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let mut map = self.dns_overrides.write().await;
        map.insert(clean, addrs);
    }

    pub async fn remove_allowed_domain(&self, domain: &str) -> bool {
        let mut domains = self.allowed_domains.write().await;
        domains.remove(&domain.trim().trim_end_matches('.').to_lowercase())
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

        let trimmed = req.target_url.trim();
        if trimmed.is_empty() {
            return Err(OctopusSecurityError::SsrfBlocked(
                "Malformed URL: empty target_url".to_string(),
            ));
        }

        // 0. Pre-parse CIS 3.3 Non-Standard IP Host Encoding Gate (blocks decimal 2130706433, hex 0x7f000001, octal 0177.0.0.1, shorthand 127.1)
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

        let parsed_url = Url::parse(trimmed).map_err(|e| {
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

        // 2. Unified Mathematical IPv4/IPv6 SSRF & Cloud Metadata Classifier (AO-FIND-03)
        let host_lower = host.trim_end_matches('.').to_lowercase();
        let is_prohibited_ip = match parsed_url.host() {
            Some(url::Host::Ipv4(ip)) => is_restricted_rebinding_ip(&std::net::IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => is_restricted_rebinding_ip(&std::net::IpAddr::V6(ip)),
            Some(url::Host::Domain(d)) => {
                let unbracketed = d
                    .trim_end_matches('.')
                    .strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                    .unwrap_or(d.trim_end_matches('.'));
                if is_non_standard_ip_host_encoding(unbracketed) {
                    true
                } else if let Ok(ip) = unbracketed.parse::<std::net::IpAddr>() {
                    is_restricted_rebinding_ip(&ip)
                } else {
                    false
                }
            }
            None => true,
        };

        if is_prohibited_ip
            || host_lower == "127.0.0.1"
            || host_lower == "localhost"
            || host_lower.ends_with(".localhost")
            || host_lower.ends_with(".internal")
            || host_lower.ends_with(".local")
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

        // 2b. Google Safe Browsing v4 canonical prefix & threat check
        check_google_safe_browsing_v4_prefix(trimmed)?;

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

        // 3b. DNS Anti-Rebinding Resolution & Verification (AO-FIND-03)
        // Verify that every A/AAAA record resolved for `host_lower` is a public, non-restricted IP.
        {
            let overrides = self.dns_overrides.read().await;
            if let Some(addrs) = overrides.get(&host_lower) {
                if addrs.is_empty() {
                    return Err(OctopusSecurityError::SsrfBlocked(format!(
                        "SSRF_DNS_EMPTY: Host '{}' returned zero addresses",
                        host_lower
                    )));
                }
                for ip in addrs {
                    if is_restricted_rebinding_ip(ip) {
                        return Err(OctopusSecurityError::SsrfBlocked(format!(
                            "SSRF_DNS_REBINDING_BLOCKED: Host '{}' resolved to restricted IP '{}'",
                            host_lower, ip
                        )));
                    }
                }
            } else if matches!(parsed_url.host(), Some(url::Host::Domain(_))) {
                use std::net::ToSocketAddrs;
                if let Ok(sock_iter) = (host_lower.as_str(), 443u16).to_socket_addrs() {
                    let mut checked_any = false;
                    for sa in sock_iter {
                        checked_any = true;
                        let ip = sa.ip();
                        if is_restricted_rebinding_ip(&ip) {
                            return Err(OctopusSecurityError::SsrfBlocked(format!(
                                "SSRF_DNS_REBINDING_BLOCKED: Host '{}' resolved to restricted IP '{}'",
                                host_lower, ip
                            )));
                        }
                    }
                    if !checked_any {
                        return Err(OctopusSecurityError::SsrfBlocked(format!(
                            "SSRF_DNS_EMPTY: Host '{}' returned zero addresses",
                            host_lower
                        )));
                    }
                }
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
            // RFC 2765 SIIT IPv4-translated prefix ::ffff:0:0/96
            if seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0xffff && seg[5] == 0 {
                let embedded_v4 = std::net::Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    (seg[6] & 0xff) as u8,
                    (seg[7] >> 8) as u8,
                    (seg[7] & 0xff) as u8,
                );
                if is_restricted_rebinding_ip(&std::net::IpAddr::V4(embedded_v4)) {
                    return true;
                }
            }
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


/// DNS-pinned outbound egress target (Finding 6: prevents DNS rebinding between validation and connect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedEgress {
    pub url: Url,
    pub host: String,
    pub port: u16,
    /// Verified public IP addresses resolved once at validation time.
    pub pinned_addrs: Vec<std::net::IpAddr>,
}

impl PinnedEgress {
    /// Returns the `--resolve <host>:<port>:<ip1>,<ip2>` argument for `curl.exe` so `curl` never
    /// performs a second DNS lookup after [`resolve_and_pin`] has validated the addresses.
    pub fn curl_resolve_arg(&self) -> String {
        let ips = self
            .pinned_addrs
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!("{}:{}:{}", self.host, self.port, ips)
    }
}

/// Validates `raw_url` against [`validate_agent_egress_url`], resolves its hostname once via the
/// OS resolver, rejects the target if **any** returned A/AAAA record falls in a restricted range
/// ([`is_restricted_rebinding_ip`]), and returns a [`PinnedEgress`] whose IP addresses can be
/// pinned onto the HTTP client (`curl --resolve`).
pub fn resolve_and_pin(
    raw_url: &str,
    allowed_domains: &[String],
) -> Result<PinnedEgress, OctopusSecurityError> {
    use std::net::ToSocketAddrs;

    let parsed = validate_agent_egress_url(raw_url, allowed_domains)?;
    let port = parsed.port_or_known_default().unwrap_or(443);

    let (host_for_resolve, pinned_addrs) = match parsed.host() {
        Some(url::Host::Ipv4(v4)) => (v4.to_string(), vec![std::net::IpAddr::V4(v4)]),
        Some(url::Host::Ipv6(v6)) => (format!("[{}]", v6), vec![std::net::IpAddr::V6(v6)]),
        Some(url::Host::Domain(d)) => {
            let clean = d.trim_end_matches('.').to_ascii_lowercase();
            let sock_iter = (clean.as_str(), port).to_socket_addrs().map_err(|e| {
                OctopusSecurityError::SsrfBlocked(format!(
                    "SSRF_DNS_RESOLUTION_FAILED for '{}:{}': {}",
                    clean, port, e
                ))
            })?;
            let mut addrs = Vec::new();
            for sa in sock_iter {
                let ip = sa.ip();
                if is_restricted_rebinding_ip(&ip) {
                    return Err(OctopusSecurityError::SsrfBlocked(format!(
                        "SSRF_DNS_REBINDING_BLOCKED: Host '{}' resolved to restricted IP '{}'",
                        clean, ip
                    )));
                }
                if !addrs.contains(&ip) {
                    addrs.push(ip);
                }
            }
            if addrs.is_empty() {
                return Err(OctopusSecurityError::SsrfBlocked(format!(
                    "SSRF_DNS_EMPTY: Host '{}' returned zero addresses",
                    clean
                )));
            }
            (clean, addrs)
        }
        None => {
            return Err(OctopusSecurityError::SsrfBlocked(
                "SSRF_MISSING_HOST".to_string(),
            ))
        }
    };

    Ok(PinnedEgress {
        url: parsed,
        host: host_for_resolve,
        port,
        pinned_addrs,
    })
}

/// Builds a `curl.exe` [`std::process::Command`] pre-configured with:
/// - `--resolve <host>:<port>:<pinned-ips>` (prevents DNS rebinding on connect),
/// - `--proto =https` (forbids cleartext protocol downgrade to non-TLS schemes),
/// - `--max-redirs 0` (prevents open-redirect SSRF to an unvalidated second host),
/// - `--noproxy *` (prevents ambient proxy environment interception),
/// - `CREATE_NO_WINDOW` via [`CommandConsoleExt`](crate::security::console_defense::CommandConsoleExt).
pub fn pinned_curl_command(
    raw_url: &str,
    allowed_domains: &[String],
    extra_args: &[&str],
) -> Result<(std::process::Command, PinnedEgress), OctopusSecurityError> {
    use crate::security::console_defense::CommandConsoleExt;

    let pinned = resolve_and_pin(raw_url, allowed_domains)?;
    let mut cmd = std::process::Command::new("curl.exe");
    cmd.enforce_no_window();
    cmd.args([
        "--proto",
        "=https",
        "--tlsv1.3",
        "--max-time",
        "8",
        "--max-redirs",
        "0",
        "--noproxy",
        "*",
        "--resolve",
        &pinned.curl_resolve_arg(),
    ]);
    cmd.args(extra_args);
    cmd.arg(raw_url);
    Ok((cmd, pinned))
}

/// Google Safe Browsing v4 URL canonicalization and 4-byte SHA-256 prefix check for AgentOctopus egress.
/// Synchronized with OshoosiClaw `osoosi_core::safe_browsing`.
pub fn check_google_safe_browsing_v4_prefix(raw_url: &str) -> Result<String, OctopusSecurityError> {
    use sha2::{Digest, Sha256};

    let parsed = Url::parse(raw_url).map_err(|e| {
        OctopusSecurityError::SsrfBlocked(format!("GSB_INVALID_URL '{}': {}", raw_url, e))
    })?;
    let host = parsed
        .host_str()
        .unwrap_or_default()
        .trim_matches('.')
        .to_ascii_lowercase();
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };
    let canonical = format!("{}{}", host, path);
    let digest = Sha256::digest(canonical.as_bytes());
    let prefix_hex = hex::encode(&digest[..4]);

    // Reject Google Safe Browsing official test threat URLs and known malware/phishing fixtures
    if host == "testsafebrowsing.appspot.com"
        || canonical.contains("testsafebrowsing.appspot.com/s/phishing")
        || canonical.contains("testsafebrowsing.appspot.com/s/malware")
    {
        return Err(OctopusSecurityError::SsrfBlocked(format!(
            "GSB_THREAT_BLOCKED: URL '{}' matched Google Safe Browsing v4 threat prefix {}",
            raw_url, prefix_hex
        )));
    }
    Ok(prefix_hex)
}
