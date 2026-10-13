//! Component 5: Network Containment Verification (`network_verifier.rs`)
//!
//! Independently verifies that restricted workers cannot establish unauthorized
//! network connections outside the approved egress broker.
//! Enforces the Google Egress Invariant (google.com, www.google.com only) and
//! guarantees that raw socket, SSRF, or private subnet escape attempts are detected and denied.

use crate::core::types::OctopusSecurityError;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Network egress evaluation verdict from the Sentinel verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkVerificationVerdict {
    /// Destination is approved under the strict egress broker whitelist.
    Allowed,
    /// Destination violates the whitelist (blocked external host).
    BlockedUnauthorizedDomain(String),
    /// Destination matches cloud metadata SSRF (169.254.169.254).
    BlockedSsrfMetadata,
    /// Destination attempts private RFC1918 subnet traversal.
    BlockedPrivateSubnet(String),
    /// Worker attempted direct socket bypass without routing through egress proxy.
    BlockedUnbrokeredEgress,
}

/// Network Containment Verification Engine for Ring 4.
pub struct NetworkVerifier {
    approved_domains: Arc<RwLock<HashSet<String>>>,
    proxy_broker_healthy: Arc<AtomicBool>,
}

impl NetworkVerifier {
    /// Creates a new NetworkVerifier enforcing the Google Egress Invariant.
    pub fn new() -> Self {
        let mut domains = HashSet::new();
        domains.insert("google.com".to_string());
        domains.insert("www.google.com".to_string());

        Self {
            approved_domains: Arc::new(RwLock::new(domains)),
            proxy_broker_healthy: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Verifies whether an outbound destination is permitted.
    pub async fn verify_egress(
        &self,
        _arm_id: u64,
        destination: &str,
        routed_through_proxy: bool,
    ) -> Result<NetworkVerificationVerdict, OctopusSecurityError> {
        if !self.proxy_broker_healthy.load(Ordering::SeqCst) {
            return Ok(NetworkVerificationVerdict::BlockedUnbrokeredEgress);
        }

        // Direct socket bypass attempt
        if !routed_through_proxy {
            return Ok(NetworkVerificationVerdict::BlockedUnbrokeredEgress);
        }

        let clean_dest = destination.trim().to_ascii_lowercase();

        // 1. SSRF metadata detection
        if clean_dest.contains("169.254.169.254") || clean_dest.contains("metadata.google.internal") {
            return Ok(NetworkVerificationVerdict::BlockedSsrfMetadata);
        }

        // 2. Extract host and check IP ranges (RFC 1918, Loopback, Link-Local, CGNAT, Unspecified)
        let host = if let Ok(parsed_url) = url::Url::parse(&clean_dest) {
            match parsed_url.host() {
                Some(url::Host::Ipv4(v4)) => {
                    let o = v4.octets();
                    if v4.is_link_local() || (o[0] == 169 && o[1] == 254) {
                        return Ok(NetworkVerificationVerdict::BlockedSsrfMetadata);
                    }
                    if v4.is_loopback()
                        || v4.is_private()
                        || v4.is_unspecified()
                        || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
                    {
                        return Ok(NetworkVerificationVerdict::BlockedPrivateSubnet(clean_dest));
                    }
                    v4.to_string()
                }
                Some(url::Host::Ipv6(v6)) => {
                    let o = v6.octets();
                    let is_unique_local = (o[0] & 0xfe) == 0xfc;
                    let is_link_local_v6 = (o[0] == 0xfe) && ((o[1] & 0xc0) == 0x80);
                    if v6.is_loopback() || v6.is_unspecified() || is_unique_local || is_link_local_v6 {
                        return Ok(NetworkVerificationVerdict::BlockedPrivateSubnet(clean_dest));
                    }
                    format!("[{}]", v6)
                }
                Some(url::Host::Domain(d)) => d.to_string(),
                None => String::new(),
            }
        } else {
            clean_dest.clone()
        };

        if let Ok(ip) = host.trim_matches(|c| c == '[' || c == ']').parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    let o = v4.octets();
                    if v4.is_link_local() || (o[0] == 169 && o[1] == 254) {
                        return Ok(NetworkVerificationVerdict::BlockedSsrfMetadata);
                    }
                    if v4.is_loopback()
                        || v4.is_private()
                        || v4.is_unspecified()
                        || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
                    {
                        return Ok(NetworkVerificationVerdict::BlockedPrivateSubnet(clean_dest));
                    }
                }
                std::net::IpAddr::V6(v6) => {
                    let o = v6.octets();
                    let is_unique_local = (o[0] & 0xfe) == 0xfc;
                    let is_link_local_v6 = (o[0] == 0xfe) && ((o[1] & 0xc0) == 0x80);
                    if v6.is_loopback() || v6.is_unspecified() || is_unique_local || is_link_local_v6 {
                        return Ok(NetworkVerificationVerdict::BlockedPrivateSubnet(clean_dest));
                    }
                }
            }
        }

        if clean_dest.contains("127.0.0.1")
            || clean_dest.contains("localhost")
            || clean_dest.contains("0.0.0.0")
            || clean_dest.contains("10.")
            || clean_dest.contains("192.168.")
            || clean_dest.contains("172.16.")
        {
            return Ok(NetworkVerificationVerdict::BlockedPrivateSubnet(clean_dest));
        }

        // 4. Check domain whitelist
        let approved = self.approved_domains.read().await;
        if approved.contains(&host) {
            Ok(NetworkVerificationVerdict::Allowed)
        } else {
            Ok(NetworkVerificationVerdict::BlockedUnauthorizedDomain(host))
        }
    }

    /// Checks if the proxy broker itself is operational.
    pub fn is_broker_healthy(&self) -> bool {
        self.proxy_broker_healthy.load(Ordering::SeqCst)
    }

    /// Simulates broker failure for negative-control testing.
    pub fn set_broker_healthy(&self, healthy: bool) {
        self.proxy_broker_healthy.store(healthy, Ordering::SeqCst);
    }

    /// Adds an approved egress domain.
    pub async fn add_approved_domain(&self, domain: &str) {
        let mut set = self.approved_domains.write().await;
        set.insert(domain.to_ascii_lowercase());
    }

    /// Returns list of currently approved egress domains.
    pub async fn get_approved_domains(&self) -> Vec<String> {
        let set = self.approved_domains.read().await;
        set.iter().cloned().collect()
    }
}
