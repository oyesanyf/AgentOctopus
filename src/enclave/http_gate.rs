use crate::core::types::OctopusSecurityError;
use crate::enclave::tool::SafeTool;
use url::Url;

pub struct HttpEgressGate {
    pub allowed_domains: Vec<String>,
}

impl Default for HttpEgressGate {
    fn default() -> Self {
        Self::new(vec![
            "https://www.google.com".to_string(),
            "https://google.com".to_string(),
            "s3://invoices/".to_string(),
        ])
    }
}

impl HttpEgressGate {
    pub fn new(allowed_domains: Vec<String>) -> Self {
        Self { allowed_domains }
    }

    pub fn validate_target(&self, target_url: &str) -> Result<(), OctopusSecurityError> {
        let lower = target_url.trim().to_lowercase();

        // 1. SSRF and Cloud Metadata tripwires
        if lower.contains("169.254.169.254")
            || lower.contains("metadata.google.internal")
            || lower.contains("127.0.0.1")
            || lower.contains("localhost")
            || lower.contains("0.0.0.0")
            || lower.contains("::1")
            || lower.starts_with("http://10.")
            || lower.starts_with("http://192.168.")
            || lower.starts_with("http://172.16.")
            || lower.contains("internal.net")
            || lower.starts_with("file://")
            || lower.starts_with("gopher://")
        {
            return Err(OctopusSecurityError::SsrfBlocked(format!(
                "SSRF/Metadata access violation: target '{}' blocked by egress gate",
                target_url
            )));
        }

        // 2. Allow specific trusted cloud object storage prefixes
        if lower.starts_with("s3://") {
            if lower.starts_with("s3://invoices/") || lower.starts_with("s3://accounting/") {
                return Ok(());
            }
            return Err(OctopusSecurityError::EnclaveViolation(format!(
                "Outbound target '{}' blocked: unauthorized S3 bucket prefix",
                target_url
            )));
        }

        // 3. Strict Internet Site Policy with URL Parsing (Zero Substring Bypass)
        let parsed = Url::parse(target_url).map_err(|e| {
            OctopusSecurityError::EnclaveViolation(format!(
                "Malformed URL '{}': {} - outbound targets must be valid URLs",
                target_url, e
            ))
        })?;

        // Scheme enforcement (strictly https or http)
        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            return Err(OctopusSecurityError::EnclaveViolation(format!(
                "Outbound target '{}' blocked: scheme '{}' is prohibited",
                target_url,
                parsed.scheme()
            )));
        }

        // Mathematical IPv4 / IPv6 SSRF & Private Range Check
        match parsed.host() {
            Some(url::Host::Ipv4(v4)) => {
                let o = v4.octets();
                if v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
                    || (o[0] == 169 && o[1] == 254)
                {
                    return Err(OctopusSecurityError::SsrfBlocked(format!(
                        "SSRF/Metadata access violation: private/loopback IPv4 '{}' blocked by egress gate",
                        v4
                    )));
                }
            }
            Some(url::Host::Ipv6(v6)) => {
                let o = v6.octets();
                let is_unique_local = (o[0] & 0xfe) == 0xfc;
                let is_link_local_v6 = (o[0] == 0xfe) && ((o[1] & 0xc0) == 0x80);
                if v6.is_loopback() || v6.is_unspecified() || is_unique_local || is_link_local_v6 {
                    return Err(OctopusSecurityError::SsrfBlocked(format!(
                        "SSRF/Metadata access violation: private/loopback IPv6 '{}' blocked by egress gate",
                        v6
                    )));
                }
            }
            _ => {}
        }

        // Hostname verification against exact allowlist (prevents google.com.attacker.example)
        let host = parsed.host_str().unwrap_or("").to_lowercase();
        let is_authorized_google = host == "google.com" || host == "www.google.com";

        if !is_authorized_google {
            return Err(OctopusSecurityError::EnclaveViolation(format!(
                "Outbound target '{}' blocked: destination host '{}' is unauthorized (the only approved internet site is Google)",
                target_url, host
            )));
        }

        // Port enforcement (standard ports 80/443 only)
        if let Some(port) = parsed.port() {
            if port != 80 && port != 443 {
                return Err(OctopusSecurityError::EnclaveViolation(format!(
                    "Outbound target '{}' blocked: unauthorized port {}",
                    target_url, port
                )));
            }
        }

        // Embedded credential enforcement
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(OctopusSecurityError::EnclaveViolation(format!(
                "Outbound target '{}' blocked: embedded credentials are prohibited",
                target_url
            )));
        }

        Ok(())
    }
}

impl SafeTool for HttpEgressGate {
    fn name(&self) -> &'static str {
        "http_egress_gate"
    }

    fn execute(&self, raw_input: &str) -> Result<String, OctopusSecurityError> {
        self.validate_target(raw_input)?;
        Ok(format!(
            "Validated target '{}' within authorized perimeter",
            raw_input
        ))
    }
}
