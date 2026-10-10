use crate::core::types::OctopusSecurityError;
use std::net::IpAddr;
use url::Url;

/// Network Guard: Enforces zero-trust internet egress boundaries.
/// Invariant: Google is the only approved internet destination (google.com / www.google.com).
/// Substring bypasses, cloud metadata (169.254.169.254), private RFC-1918 subnets,
/// embedded credentials, and custom port evasion are deterministically rejected.
pub struct NetworkGuard {
    guard_id: String,
    blocked_count: usize,
    passed_count: usize,
}

impl NetworkGuard {
    pub fn new(guard_id: &str) -> Self {
        Self {
            guard_id: guard_id.to_string(),
            blocked_count: 0,
            passed_count: 0,
        }
    }

    pub fn guard_id(&self) -> &str {
        &self.guard_id
    }

    pub fn blocked_count(&self) -> usize {
        self.blocked_count
    }

    pub fn passed_count(&self) -> usize {
        self.passed_count
    }

    /// Evaluates an outbound target URL or resource locator against strict egress rules.
    pub fn validate_egress(&mut self, target: &str) -> Result<(), OctopusSecurityError> {
        let trimmed = target.trim();

        // 1. Internal simulated protocol check (e.g. s3://invoices/)
        if trimmed.starts_with("s3://") {
            if trimmed.starts_with("s3://invoices/") {
                self.passed_count += 1;
                return Ok(());
            } else {
                self.blocked_count += 1;
                return Err(OctopusSecurityError::SsrfBlocked(format!(
                    "Unauthorized S3 bucket: {}",
                    trimmed
                )));
            }
        }

        // 2. Parse URL using strict RFC 3986 parser
        let parsed_url = Url::parse(trimmed).map_err(|e| {
            self.blocked_count += 1;
            OctopusSecurityError::SsrfBlocked(format!("Malformed URL syntax: {}", e))
        })?;

        // 3. Scheme must strictly be https (no unencrypted http, no file://, no gopher://, etc.)
        if parsed_url.scheme() != "https" {
            self.blocked_count += 1;
            return Err(OctopusSecurityError::SsrfBlocked(format!(
                "Insecure scheme '{}': only https is permitted",
                parsed_url.scheme()
            )));
        }

        // 4. Forbid embedded authentication credentials (e.g. https://user:pass@google.com)
        if !parsed_url.username().is_empty() || parsed_url.password().is_some() {
            self.blocked_count += 1;
            return Err(OctopusSecurityError::SsrfBlocked(
                "Embedded userinfo/credentials in destination URL are prohibited".to_string(),
            ));
        }

        // 5. Forbid non-standard ports (must be default 443)
        if let Some(port) = parsed_url.port() {
            if port != 443 {
                self.blocked_count += 1;
                return Err(OctopusSecurityError::SsrfBlocked(format!(
                    "Non-standard outbound port {}: only standard HTTPS port 443 allowed",
                    port
                )));
            }
        }

        // 6. Host extraction and validation
        let host_str = parsed_url.host_str().ok_or_else(|| {
            self.blocked_count += 1;
            OctopusSecurityError::SsrfBlocked("Missing host component in target URL".to_string())
        })?;

        // 7. Check for direct IP address targets (Cloud metadata, private RFC 1918, link-local)
        if let Ok(ip) = host_str.parse::<IpAddr>() {
            self.blocked_count += 1;
            return Err(OctopusSecurityError::SsrfBlocked(format!(
                "Direct IP targets prohibited (SSRF prevention): {}",
                ip
            )));
        }

        // 8. Strict hostname allowlist: exact match on google.com or www.google.com
        let lower_host = host_str.to_ascii_lowercase();
        if lower_host != "google.com" && lower_host != "www.google.com" {
            self.blocked_count += 1;
            return Err(OctopusSecurityError::SsrfBlocked(format!(
                "Unauthorized destination host '{}': only Google domains are permitted",
                host_str
            )));
        }

        self.passed_count += 1;
        Ok(())
    }
}
