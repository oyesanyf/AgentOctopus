//! Host-side Policy Enforcement Point (PEP) Bridge, Secret Vault, and Sub-Millisecond Eviction.
//!
//! Google AgentMesh (#734) x AgentOctopus Tier 1 Wasm Integration.
//!
//! Enforces:
//! 1. Zero secrets in Wasm linear memory: all mesh credentials remain in host vault memory.
//! 2. Token vault caching indexed by `(arm_id, generation_epoch)`.
//! 3. Bounded token vault capacity (no memory leaks).
//! 4. Proactive token refresh when < 15 seconds remain before expiry.
//! 5. Strict header hygiene: strips `Authorization`, `Cookie`, `X-Mesh-*`; injects `X-Mesh-Authentication`.
//! 6. Sub-millisecond KillSwitch eviction (< 1,000 microseconds) closing the #734 window.
//! 7. Zero-Mutual-Information output projection on all upstream response payloads.
//! 8. Strict URI scheme filtering (`mcp://`, `a2a://`, `inference://`, `egress://`).

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::core::circuit_breaker::KillSwitch;
use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::security::breakouts::ZeroMutualInformationProjector;
use super::oidc_actor_issuer::OctopusOidcActorIssuer;

/// Tolerance window in seconds: if remaining lifetime is <= this buffer, refresh token proactively.
pub const TOKEN_REFRESH_BUFFER_SECS: u64 = 15;

/// Sub-millisecond eviction SLA: 1,000 microseconds (1 millisecond).
pub const KILLSWITCH_EVICTION_SLA_MICROS: u128 = 1_000;

/// Default connect timeout for loopback HTTP transport.
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 1_500;

/// Default read/write timeout for loopback HTTP transport.
pub const DEFAULT_IO_TIMEOUT_MS: u64 = 3_000;

/// Maximum number of cached tokens in vault
pub const MAX_CACHED_TOKENS_CAPACITY: usize = 1_024;

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum MeshCallError {
    #[error("KillSwitch is tripped for arm '{0}'")]
    KillSwitchTripped(String),

    #[error("Prohibited mesh URI '{0}': scheme must be 'mcp://', 'a2a://', 'inference://', or 'egress://'")]
    InvalidUri(String),

    #[error("Workload JWT minting failed: {0}")]
    TokenMintError(String),

    #[error("RFC 8693 token exchange failed (HTTP {status}): {message}")]
    TokenExchangeFailed { status: u16, message: String },

    #[error("Upstream mesh call failed (HTTP {status}): {message}")]
    UpstreamCallFailed { status: u16, message: String },

    #[error("Access denied by mesh policy (HTTP 403 / WASI_ERR_ACCESS_DENIED): {0}")]
    AccessDenied(String),

    #[error("Network transport error during mesh communication: {0}")]
    NetworkError(String),

    #[error("Token expired or missing for arm '{0}', epoch {1}")]
    TokenExpired(String, u64),

    #[error("Internal PEP bridge synchronization error: {0}")]
    Internal(String),
}

impl From<MeshCallError> for OctopusSecurityError {
    fn from(err: MeshCallError) -> Self {
        match err {
            MeshCallError::KillSwitchTripped(_) => OctopusSecurityError::LimbKilled,
            MeshCallError::AccessDenied(msg) => OctopusSecurityError::CapabilityDenied(msg),
            MeshCallError::InvalidUri(uri) => OctopusSecurityError::SsrfBlocked(uri),
            other => OctopusSecurityError::IsolationViolation(other.to_string()),
        }
    }
}

// ============================================================================
// Token Vault Data Structures & RFC 8693 Schemas
// ============================================================================

/// Cached exchanged mesh credential, stored strictly in host memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedMeshToken {
    pub arm_id: String,
    pub epoch: u64,
    pub role: ArmRole,
    pub access_token: String,
    pub token_type: String,
    pub issued_token_type: String,
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
}

impl CachedMeshToken {
    /// Returns true if the token has expired or is within the proactive refresh buffer.
    pub fn is_expired_or_near(&self, now_secs: u64, buffer_secs: u64) -> bool {
        now_secs.saturating_add(buffer_secs) >= self.expires_at_unix_secs
    }
}

/// Bounded Token Vault Store
#[derive(Default)]
pub struct BoundedTokenVault {
    tokens: HashMap<(String, u64), CachedMeshToken>,
    insertion_order: VecDeque<(String, u64)>,
    capacity: usize,
}

impl BoundedTokenVault {
    pub fn new(capacity: usize) -> Self {
        Self {
            tokens: HashMap::with_capacity(capacity),
            insertion_order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn insert(&mut self, key: (String, u64), token: CachedMeshToken) {
        if !self.tokens.contains_key(&key) {
            if self.tokens.len() >= self.capacity {
                if let Some(oldest) = self.insertion_order.pop_front() {
                    self.tokens.remove(&oldest);
                }
            }
            self.insertion_order.push_back(key.clone());
        }
        self.tokens.insert(key, token);
    }

    pub fn get(&self, key: &(String, u64)) -> Option<&CachedMeshToken> {
        self.tokens.get(key)
    }

    pub fn remove(&mut self, key: &(String, u64)) -> Option<CachedMeshToken> {
        self.tokens.remove(key)
    }

    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&(String, u64), &mut CachedMeshToken) -> bool,
    {
        self.tokens.retain(|k, v| f(k, v));
        self.insertion_order.retain(|k| self.tokens.contains_key(k));
    }

    pub fn clear(&mut self) {
        self.tokens.clear();
        self.insertion_order.clear();
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

/// RFC 8693 OAuth 2.0 Token Exchange Request (JSON representation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rfc8693TokenRequest {
    pub grant_type: String,
    pub subject_token: String,
    pub subject_token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// RFC 8693 OAuth 2.0 Token Exchange Successful Response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rfc8693TokenResponse {
    pub access_token: String,
    pub issued_token_type: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// RFC 6749 / RFC 8693 Standard Error Response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rfc8693ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// Receipt returned after executing a mesh call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshCallReceipt {
    pub uri: String,
    pub caller_arm_id: String,
    pub epoch: u64,
    pub response_bytes: Vec<u8>,
    pub execution_duration_us: u64,
}

/// Configuration for PEP bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PepBridgeConfig {
    pub mesh_node_base_url: String,
    pub token_exchange_timeout_ms: u64,
}

impl Default for PepBridgeConfig {
    fn default() -> Self {
        Self {
            mesh_node_base_url: "http://127.0.0.1:0".to_string(),
            token_exchange_timeout_ms: 2000,
        }
    }
}

/// Telemetry structure exposed to WebUI dashboard (Tab 17) and audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PepVaultTelemetry {
    pub cached_tokens_count: usize,
    pub active_killswitches_count: usize,
    pub total_token_exchanges: u64,
    pub total_cache_hits: u64,
    pub total_killswitch_evictions: u64,
    pub last_eviction_duration_us: u64,
    pub mesh_node_url: String,
}

// ============================================================================
// Pure-Rust Synchronous & Asynchronous Wire Transports
// ============================================================================

/// Minimal synchronous HTTP/1.1 transport using `std::net::TcpStream`.
/// Operates without an async runtime for host imports called inside `wasmtime`.
pub struct SyncHttpWireClient {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
}

impl Default for SyncHttpWireClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncHttpWireClient {
    pub fn new() -> Self {
        Self {
            connect_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            read_timeout: Duration::from_millis(DEFAULT_IO_TIMEOUT_MS),
            write_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
        }
    }

    /// Dispatches an HTTP POST request over a raw TCP connection.
    pub fn post(
        &self,
        target_url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), MeshCallError> {
        let parsed = Url::parse(target_url)
            .map_err(|e| MeshCallError::NetworkError(format!("Malformed URL '{}': {}", target_url, e)))?;

        let host = parsed.host_str().unwrap_or("127.0.0.1");
        let port = parsed.port_or_known_default().unwrap_or(80);
        let path = if parsed.path().is_empty() { "/" } else { parsed.path() };
        let query = parsed.query().map(|q| format!("?{}", q)).unwrap_or_default();
        let request_target = format!("{}{}", path, query);

        let addrs: Vec<SocketAddr> = format!("{}:{}", host, port)
            .to_socket_addrs()
            .map_err(|e| MeshCallError::NetworkError(format!("DNS resolution failed for {}:{}: {}", host, port, e)))?
            .collect();

        if addrs.is_empty() {
            return Err(MeshCallError::NetworkError(format!("No resolved addresses for {}:{}", host, port)));
        }

        let mut stream = TcpStream::connect_timeout(&addrs[0], self.connect_timeout)
            .map_err(|e| MeshCallError::NetworkError(format!("TCP connect to {} failed: {}", addrs[0], e)))?;

        stream
            .set_read_timeout(Some(self.read_timeout))
            .map_err(|e| MeshCallError::NetworkError(format!("Set read timeout failed: {}", e)))?;
        stream
            .set_write_timeout(Some(self.write_timeout))
            .map_err(|e| MeshCallError::NetworkError(format!("Set write timeout failed: {}", e)))?;

        let mut wire_req = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Length: {}\r\nConnection: close\r\n",
            request_target, host, port, body.len()
        );

        for (k, v) in headers {
            wire_req.push_str(&format!("{}: {}\r\n", k, v));
        }
        wire_req.push_str("\r\n");

        stream
            .write_all(wire_req.as_bytes())
            .map_err(|e| MeshCallError::NetworkError(format!("TCP write header error: {}", e)))?;
        if !body.is_empty() {
            stream
                .write_all(body)
                .map_err(|e| MeshCallError::NetworkError(format!("TCP write body error: {}", e)))?;
        }
        stream
            .flush()
            .map_err(|e| MeshCallError::NetworkError(format!("TCP flush error: {}", e)))?;

        let mut raw_response = Vec::new();
        stream
            .read_to_end(&mut raw_response)
            .map_err(|e| MeshCallError::NetworkError(format!("TCP read error: {}", e)))?;

        Self::parse_http_response(&raw_response)
    }

    /// Parses a raw HTTP/1.1 response buffer into status code, headers, and body.
    pub fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<(String, String)>, Vec<u8>), MeshCallError> {
        let header_end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| MeshCallError::NetworkError("Malformed HTTP response: missing header terminator".into()))?;

        let header_bytes = &raw[..header_end];
        let body_bytes = &raw[header_end + 4..];

        let header_str = std::str::from_utf8(header_bytes)
            .map_err(|e| MeshCallError::NetworkError(format!("Non-UTF8 HTTP headers: {}", e)))?;

        let mut lines = header_str.lines();
        let status_line = lines
            .next()
            .ok_or_else(|| MeshCallError::NetworkError("Empty HTTP response status line".into()))?;

        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(MeshCallError::NetworkError(format!("Invalid HTTP status line: '{}'", status_line)));
        }

        let status_code: u16 = parts[1]
            .parse()
            .map_err(|e| MeshCallError::NetworkError(format!("Failed to parse HTTP status '{}': {}", parts[1], e)))?;

        let mut headers = Vec::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }

        Ok((status_code, headers, body_bytes.to_vec()))
    }
}

/// Asynchronous wire transport using `tokio::net::TcpStream` for server tasks.
pub struct AsyncHttpWireClient;

impl AsyncHttpWireClient {
    pub async fn post(
        target_url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), MeshCallError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let parsed = Url::parse(target_url)
            .map_err(|e| MeshCallError::NetworkError(format!("Malformed URL '{}': {}", target_url, e)))?;

        let host = parsed.host_str().unwrap_or("127.0.0.1");
        let port = parsed.port_or_known_default().unwrap_or(80);
        let path = if parsed.path().is_empty() { "/" } else { parsed.path() };
        let query = parsed.query().map(|q| format!("?{}", q)).unwrap_or_default();
        let request_target = format!("{}{}", path, query);

        let mut stream = tokio::time::timeout(
            Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            tokio::net::TcpStream::connect(format!("{}:{}", host, port)),
        )
        .await
        .map_err(|_| MeshCallError::NetworkError(format!("Async connect timeout to {}:{}", host, port)))?
        .map_err(|e| MeshCallError::NetworkError(format!("Async connect failed: {}", e)))?;

        let mut wire_req = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Length: {}\r\nConnection: close\r\n",
            request_target, host, port, body.len()
        );

        for (k, v) in headers {
            wire_req.push_str(&format!("{}: {}\r\n", k, v));
        }
        wire_req.push_str("\r\n");

        stream
            .write_all(wire_req.as_bytes())
            .await
            .map_err(|e| MeshCallError::NetworkError(format!("Async write headers error: {}", e)))?;
        if !body.is_empty() {
            stream
                .write_all(body)
                .await
                .map_err(|e| MeshCallError::NetworkError(format!("Async write body error: {}", e)))?;
        }
        stream
            .flush()
            .await
            .map_err(|e| MeshCallError::NetworkError(format!("Async flush error: {}", e)))?;

        let mut raw_response = Vec::new();
        stream
            .read_to_end(&mut raw_response)
            .await
            .map_err(|e| MeshCallError::NetworkError(format!("Async read error: {}", e)))?;

        SyncHttpWireClient::parse_http_response(&raw_response)
    }
}

// ============================================================================
// Core Policy Enforcement Point (PEP) Bridge
// ============================================================================

/// Out-of-sandbox policy enforcement point, host-only secret vault, and sub-ms autotomy controller.
#[derive(Clone)]
pub struct AgentMeshPepBridge {
    issuer: Arc<OctopusOidcActorIssuer>,
    token_vault: Arc<RwLock<BoundedTokenVault>>,
    killswitch_registry: Arc<RwLock<HashMap<String, KillSwitch>>>,
    global_killswitch: Arc<RwLock<Option<Arc<KillSwitch>>>>,
    mesh_node_url: Arc<RwLock<String>>,
    wire_client: Arc<SyncHttpWireClient>,

    // Telemetry counters
    total_token_exchanges: Arc<AtomicU64>,
    total_cache_hits: Arc<AtomicU64>,
    total_killswitch_evictions: Arc<AtomicU64>,
    last_eviction_duration_us: Arc<AtomicU64>,
}

impl AgentMeshPepBridge {
    /// Creates a new PEP bridge bound to the given workload actor issuer.
    pub fn new(issuer: Arc<OctopusOidcActorIssuer>, default_mesh_node_url: String) -> Self {
        Self {
            issuer,
            token_vault: Arc::new(RwLock::new(BoundedTokenVault::new(MAX_CACHED_TOKENS_CAPACITY))),
            killswitch_registry: Arc::new(RwLock::new(HashMap::new())),
            global_killswitch: Arc::new(RwLock::new(None)),
            mesh_node_url: Arc::new(RwLock::new(default_mesh_node_url)),
            wire_client: Arc::new(SyncHttpWireClient::new()),
            total_token_exchanges: Arc::new(AtomicU64::new(0)),
            total_cache_hits: Arc::new(AtomicU64::new(0)),
            total_killswitch_evictions: Arc::new(AtomicU64::new(0)),
            last_eviction_duration_us: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Creates a new PEP bridge with PepBridgeConfig and global KillSwitch
    pub fn new_with_config(
        config: PepBridgeConfig,
        issuer: Arc<OctopusOidcActorIssuer>,
        killswitch: Arc<KillSwitch>,
    ) -> Self {
        let bridge = Self::new(issuer, config.mesh_node_base_url);
        if let Ok(mut gks) = bridge.global_killswitch.write() {
            *gks = Some(killswitch);
        }
        bridge
    }

    /// Sets or updates the target mesh node URL (e.g. after loopback reference node startup).
    pub fn set_mesh_node_url(&self, url: String) {
        if let Ok(mut lock) = self.mesh_node_url.write() {
            *lock = url;
        }
    }

    /// Update URL method (alias for consistency across modules)
    pub fn update_mesh_node_url(&self, url: &str) {
        self.set_mesh_node_url(url.to_string());
    }

    /// Returns the currently configured mesh node URL.
    pub fn get_mesh_node_url(&self) -> String {
        self.mesh_node_url
            .read()
            .map(|u| u.clone())
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string())
    }

    /// Number of active cached tokens
    pub fn cached_token_count(&self) -> usize {
        self.token_vault.read().map(|v| v.len()).unwrap_or(0)
    }

    // ------------------------------------------------------------------------
    // Circuit Breaker Registration & Sub-Millisecond Eviction
    // ------------------------------------------------------------------------

    /// Registers a limb's circuit breaker to be governed by the PEP bridge.
    pub fn register_arm_killswitch(&self, arm_id: &str, killswitch: KillSwitch) {
        if let Ok(mut reg) = self.killswitch_registry.write() {
            reg.insert(arm_id.to_string(), killswitch);
        }
    }

    /// Checks whether an arm's registered KillSwitch (or global KillSwitch) has been tripped.
    pub fn is_arm_tripped(&self, arm_id: &str) -> bool {
        // Check global killswitch first
        if let Ok(gks_lock) = self.global_killswitch.read() {
            if let Some(ref ks) = *gks_lock {
                if ks.is_tripped() {
                    return true;
                }
            }
        }

        // Check per-arm registry
        if let Ok(reg) = self.killswitch_registry.read() {
            if let Some(ks) = reg.get(arm_id) {
                return ks.is_tripped();
            }
        }
        false
    }

    /// Sub-Millisecond KillSwitch Eviction:
    /// 1. Immediately evicts all token cache entries matching `arm_id`.
    /// 2. Trips the registered KillSwitch atomically (`SeqCst`).
    /// 3. Asserts total elapsed duration < 1,000 microseconds (< 1ms SLA).
    /// 4. Returns the measured elapsed duration.
    pub fn trip_arm_killswitch(&self, arm_id: &str) -> Duration {
        let t0 = Instant::now();

        // 1. Evict matching credentials from token vault
        if let Ok(mut vault) = self.token_vault.write() {
            vault.retain(|(cached_arm, _epoch), _token| cached_arm != arm_id);
        }

        // 2. Trip registered circuit breaker
        if let Ok(reg) = self.killswitch_registry.read() {
            if let Some(ks) = reg.get(arm_id) {
                ks.trip();
            }
        }
        if let Ok(gks_lock) = self.global_killswitch.read() {
            if let Some(ref ks) = *gks_lock {
                ks.trip();
            }
        }

        let elapsed = t0.elapsed();

        // Update telemetry
        self.total_killswitch_evictions.fetch_add(1, Ordering::Relaxed);
        self.last_eviction_duration_us
            .store(elapsed.as_micros() as u64, Ordering::Relaxed);

        // Verification of sub-millisecond SLA
        assert!(
            elapsed.as_micros() < KILLSWITCH_EVICTION_SLA_MICROS,
            "CRITICAL: KillSwitch eviction latency SLA breached (took {:?}, expected < 1ms)",
            elapsed
        );

        elapsed
    }

    /// Evicts a specific generation epoch token for an arm without tripping the circuit breaker.
    pub fn evict_arm_epoch(&self, arm_id: &str, epoch: u64) {
        if let Ok(mut vault) = self.token_vault.write() {
            vault.remove(&(arm_id.to_string(), epoch));
        }
    }

    /// Purges all cached tokens across all arms and epochs.
    pub fn purge_all_tokens(&self) {
        if let Ok(mut vault) = self.token_vault.write() {
            vault.clear();
        }
    }

    // ------------------------------------------------------------------------
    // Header Hygiene & Injection
    // ------------------------------------------------------------------------

    /// Sanitizes caller headers and injects verified `X-Mesh-Authentication`.
    /// Strips: `Authorization`, `Cookie`, `X-Mesh-*` (case-insensitive).
    /// Injects: `X-Mesh-Authentication: Bearer <mesh_token>`.
    pub fn sanitize_and_inject_headers(
        raw_headers: &[(String, String)],
        mesh_token: &str,
    ) -> Vec<(String, String)> {
        let mut sanitized = Vec::with_capacity(raw_headers.len() + 2);
        let mut has_user_agent = false;
        let mut has_content_type = false;

        for (name, val) in raw_headers {
            let name_lower = name.to_ascii_lowercase();

            // Strip sensitive caller headers that could shadow identity or bypass mesh controls
            if name_lower == "authorization"
                || name_lower == "cookie"
                || name_lower.starts_with("x-mesh-")
            {
                continue;
            }

            if name_lower == "user-agent" {
                has_user_agent = true;
            }
            if name_lower == "content-type" {
                has_content_type = true;
            }

            sanitized.push((name.clone(), val.clone()));
        }

        // Inject authoritative host-held mesh bearer credential
        sanitized.push((
            "X-Mesh-Authentication".to_string(),
            format!("Bearer {}", mesh_token),
        ));

        if !has_user_agent {
            sanitized.push(("User-Agent".to_string(), "AgentOctopus-HostPep/1.0".to_string()));
        }
        if !has_content_type {
            sanitized.push(("Content-Type".to_string(), "application/json".to_string()));
        }

        sanitized
    }

    // ------------------------------------------------------------------------
    // Logical URI Resolution & Scheme Validation
    // ------------------------------------------------------------------------

    /// Resolves logical mesh URIs into the target HTTP endpoint on the mesh node.
    /// Strictly allows: `mcp://`, `a2a://`, `inference://`, `egress://`.
    /// Strictly rejects: `http://`, `https://`, `file://`, IP literals, TCP sockets.
    pub fn resolve_mesh_endpoint(node_url: &str, logical_uri: &str) -> Result<String, MeshCallError> {
        let trimmed_base = node_url.trim_end_matches('/');

        if let Some(rest) = logical_uri.strip_prefix("mcp://") {
            Ok(format!("{}/mesh/mcp/{}", trimmed_base, rest))
        } else if let Some(rest) = logical_uri.strip_prefix("a2a://") {
            Ok(format!("{}/mesh/a2a/{}", trimmed_base, rest))
        } else if let Some(rest) = logical_uri.strip_prefix("inference://") {
            Ok(format!("{}/mesh/inference/{}", trimmed_base, rest))
        } else if let Some(rest) = logical_uri.strip_prefix("egress://") {
            Ok(format!("{}/mesh/egress/{}", trimmed_base, rest))
        } else {
            Err(MeshCallError::InvalidUri(logical_uri.to_string()))
        }
    }

    // ------------------------------------------------------------------------
    // RFC 8693 Token Exchange Workflow
    // ------------------------------------------------------------------------

    /// Obtains a cached token or performs RFC 8693 token exchange if missing or near expiry.
    pub fn get_or_exchange_token_sync(
        &self,
        arm_id: &str,
        epoch: u64,
        role: &ArmRole,
        target_resource: &str,
    ) -> Result<String, MeshCallError> {
        // 1. Fail closed if KillSwitch is tripped
        if self.is_arm_tripped(arm_id) {
            return Err(MeshCallError::KillSwitchTripped(arm_id.to_string()));
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let cache_key = (arm_id.to_string(), epoch);

        // 2. Fast-path: Check cached token in host vault
        if let Ok(vault) = self.token_vault.read() {
            if let Some(cached) = vault.get(&cache_key) {
                if !cached.is_expired_or_near(now_secs, TOKEN_REFRESH_BUFFER_SECS) {
                    self.total_cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(cached.access_token.clone());
                }
            }
        }

        // 3. Slow-path: Mint workload JWT via OIDC actor issuer
        let workload_jwt = self
            .issuer
            .mint_arm_token(arm_id, epoch, role)
            .map_err(|e| MeshCallError::TokenMintError(e.to_string()))?;

        // 4. Construct RFC 8693 Token Exchange request
        let token_req = Rfc8693TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            subject_token: workload_jwt,
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            requested_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            audience: Some("agentmesh.local".to_string()),
            resource: Some(target_resource.to_string()),
        };

        let req_body = serde_json::to_vec(&token_req)
            .map_err(|e| MeshCallError::Internal(format!("Failed to serialize RFC 8693 request: {}", e)))?;

        let token_endpoint = format!("{}/oauth/token", self.get_mesh_node_url().trim_end_matches('/'));
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];

        // 5. Transmit token exchange request to STS endpoint
        let (status, _resp_headers, resp_bytes) = self.wire_client.post(&token_endpoint, &headers, &req_body)?;

        if status == 200 {
            let token_resp: Rfc8693TokenResponse = serde_json::from_slice(&resp_bytes)
                .map_err(|e| MeshCallError::TokenExchangeFailed {
                    status,
                    message: format!("Malformed RFC 8693 token response: {}", e),
                })?;

            let cached = CachedMeshToken {
                arm_id: arm_id.to_string(),
                epoch,
                role: role.clone(),
                access_token: token_resp.access_token.clone(),
                token_type: token_resp.token_type,
                issued_token_type: token_resp.issued_token_type,
                issued_at_unix_secs: now_secs,
                expires_at_unix_secs: now_secs.saturating_add(token_resp.expires_in),
            };

            // Store in vault
            if let Ok(mut vault) = self.token_vault.write() {
                vault.insert(cache_key, cached);
            }

            self.total_token_exchanges.fetch_add(1, Ordering::Relaxed);
            Ok(token_resp.access_token)
        } else if status == 403 {
            let err_msg = String::from_utf8_lossy(&resp_bytes).to_string();
            Err(MeshCallError::AccessDenied(err_msg))
        } else {
            let err_desc = serde_json::from_slice::<Rfc8693ErrorResponse>(&resp_bytes)
                .map(|e| e.error_description.unwrap_or(e.error))
                .unwrap_or_else(|_| String::from_utf8_lossy(&resp_bytes).to_string());

            Err(MeshCallError::TokenExchangeFailed {
                status,
                message: err_desc,
            })
        }
    }

    /// Asynchronous counterpart for RFC 8693 token exchange.
    pub async fn get_or_exchange_token_async(
        &self,
        arm_id: &str,
        epoch: u64,
        role: &ArmRole,
        target_resource: &str,
    ) -> Result<String, MeshCallError> {
        if self.is_arm_tripped(arm_id) {
            return Err(MeshCallError::KillSwitchTripped(arm_id.to_string()));
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let cache_key = (arm_id.to_string(), epoch);

        if let Ok(vault) = self.token_vault.read() {
            if let Some(cached) = vault.get(&cache_key) {
                if !cached.is_expired_or_near(now_secs, TOKEN_REFRESH_BUFFER_SECS) {
                    self.total_cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(cached.access_token.clone());
                }
            }
        }

        let workload_jwt = self
            .issuer
            .mint_arm_token(arm_id, epoch, role)
            .map_err(|e| MeshCallError::TokenMintError(e.to_string()))?;

        let token_req = Rfc8693TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            subject_token: workload_jwt,
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            requested_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            audience: Some("agentmesh.local".to_string()),
            resource: Some(target_resource.to_string()),
        };

        let req_body = serde_json::to_vec(&token_req)
            .map_err(|e| MeshCallError::Internal(format!("Failed to serialize RFC 8693 request: {}", e)))?;

        let token_endpoint = format!("{}/oauth/token", self.get_mesh_node_url().trim_end_matches('/'));
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];

        let (status, _resp_headers, resp_bytes) = AsyncHttpWireClient::post(&token_endpoint, &headers, &req_body).await?;

        if status == 200 {
            let token_resp: Rfc8693TokenResponse = serde_json::from_slice(&resp_bytes)
                .map_err(|e| MeshCallError::TokenExchangeFailed {
                    status,
                    message: format!("Malformed RFC 8693 token response: {}", e),
                })?;

            let cached = CachedMeshToken {
                arm_id: arm_id.to_string(),
                epoch,
                role: role.clone(),
                access_token: token_resp.access_token.clone(),
                token_type: token_resp.token_type,
                issued_token_type: token_resp.issued_token_type,
                issued_at_unix_secs: now_secs,
                expires_at_unix_secs: now_secs.saturating_add(token_resp.expires_in),
            };

            if let Ok(mut vault) = self.token_vault.write() {
                vault.insert(cache_key, cached);
            }

            self.total_token_exchanges.fetch_add(1, Ordering::Relaxed);
            Ok(token_resp.access_token)
        } else if status == 403 {
            let err_msg = String::from_utf8_lossy(&resp_bytes).to_string();
            Err(MeshCallError::AccessDenied(err_msg))
        } else {
            let err_desc = serde_json::from_slice::<Rfc8693ErrorResponse>(&resp_bytes)
                .map(|e| e.error_description.unwrap_or(e.error))
                .unwrap_or_else(|_| String::from_utf8_lossy(&resp_bytes).to_string());

            Err(MeshCallError::TokenExchangeFailed {
                status,
                message: err_desc,
            })
        }
    }

    // ------------------------------------------------------------------------
    // Response Sanitization: Zero-Mutual-Information Projector
    // ------------------------------------------------------------------------

    /// Projects upstream raw bytes through `ZeroMutualInformationProjector`.
    /// Strips zero-width stego chars, redacts secrets with `<ZK_MI_REDACTED>`,
    /// sorts JSON keys, and quantizes release time.
    pub fn sanitize_upstream_payload(raw_bytes: &[u8]) -> Vec<u8> {
        let raw_str = String::from_utf8_lossy(raw_bytes);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let projected = ZeroMutualInformationProjector::project_output(&raw_str, now_ms, 100);
        projected.canonical_output.into_bytes()
    }

    // ------------------------------------------------------------------------
    // Public Dispatch Interface for Wasm & Containment
    // ------------------------------------------------------------------------

    /// Synchronous dispatch for `octopus_wasi::mesh_call` inside Tier 1 Wasm host import.
    pub fn dispatch_mesh_call_sync(
        &self,
        arm_id: &str,
        epoch: u64,
        role: &ArmRole,
        uri: &str,
        req_bytes: &[u8],
    ) -> Result<Vec<u8>, MeshCallError> {
        // 1. Check KillSwitch
        if self.is_arm_tripped(arm_id) {
            return Err(MeshCallError::KillSwitchTripped(arm_id.to_string()));
        }

        // 2. Validate and resolve URI
        let endpoint_url = Self::resolve_mesh_endpoint(&self.get_mesh_node_url(), uri)?;

        // 3. Obtain exchanged token from vault or STS
        let token = self.get_or_exchange_token_sync(arm_id, epoch, role, uri)?;

        // 4. Sanitize headers and inject X-Mesh-Authentication
        let default_headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let sanitized_headers = Self::sanitize_and_inject_headers(&default_headers, &token);

        // 5. Transmit request to mesh service
        let (status, _resp_headers, resp_bytes) = self.wire_client.post(&endpoint_url, &sanitized_headers, req_bytes)?;

        // 6. Handle response status & project payload
        if status == 200 {
            Ok(Self::sanitize_upstream_payload(&resp_bytes))
        } else if status == 403 {
            Err(MeshCallError::AccessDenied(String::from_utf8_lossy(&resp_bytes).to_string()))
        } else {
            Err(MeshCallError::UpstreamCallFailed {
                status,
                message: String::from_utf8_lossy(&resp_bytes).to_string(),
            })
        }
    }

    /// Asynchronous dispatch for Tokio tasks and Web API endpoints.
    pub async fn dispatch_mesh_call_async(
        &self,
        arm_id: &str,
        epoch: u64,
        role: &ArmRole,
        uri: &str,
        req_bytes: &[u8],
    ) -> Result<Vec<u8>, MeshCallError> {
        if self.is_arm_tripped(arm_id) {
            return Err(MeshCallError::KillSwitchTripped(arm_id.to_string()));
        }

        let endpoint_url = Self::resolve_mesh_endpoint(&self.get_mesh_node_url(), uri)?;
        let token = self.get_or_exchange_token_async(arm_id, epoch, role, uri).await?;

        let default_headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let sanitized_headers = Self::sanitize_and_inject_headers(&default_headers, &token);

        let (status, _resp_headers, resp_bytes) = AsyncHttpWireClient::post(&endpoint_url, &sanitized_headers, req_bytes).await?;

        if status == 200 {
            Ok(Self::sanitize_upstream_payload(&resp_bytes))
        } else if status == 403 {
            Err(MeshCallError::AccessDenied(String::from_utf8_lossy(&resp_bytes).to_string()))
        } else {
            Err(MeshCallError::UpstreamCallFailed {
                status,
                message: String::from_utf8_lossy(&resp_bytes).to_string(),
            })
        }
    }

    // ------------------------------------------------------------------------
    // Telemetry & Monitoring
    // ------------------------------------------------------------------------

    /// Returns active PEP vault telemetry for WebUI dashboard (Tab 17) and audit.
    pub fn telemetry(&self) -> PepVaultTelemetry {
        let cached_count = self.token_vault.read().map(|v| v.len()).unwrap_or(0);
        let killswitch_count = self.killswitch_registry.read().map(|k| k.len()).unwrap_or(0);

        PepVaultTelemetry {
            cached_tokens_count: cached_count,
            active_killswitches_count: killswitch_count,
            total_token_exchanges: self.total_token_exchanges.load(Ordering::Relaxed),
            total_cache_hits: self.total_cache_hits.load(Ordering::Relaxed),
            total_killswitch_evictions: self.total_killswitch_evictions.load(Ordering::Relaxed),
            last_eviction_duration_us: self.last_eviction_duration_us.load(Ordering::Relaxed),
            mesh_node_url: self.get_mesh_node_url(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn test_header_hygiene_stripping_and_injection() {
        let dirty_headers = vec![
            ("Authorization".to_string(), "Bearer stolen_token_12345".to_string()),
            ("authorization".to_string(), "Bearer lower_case_attempt".to_string()),
            ("Cookie".to_string(), "session_id=abcd1234secret".to_string()),
            ("cookie".to_string(), "tracked_cookie=xyz".to_string()),
            ("X-Mesh-Custom-Actor".to_string(), "spoofed_admin".to_string()),
            ("x-mesh-forwarded-for".to_string(), "10.0.0.1".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Custom-Tracing".to_string(), "trace_99".to_string()),
        ];

        let sanitized = AgentMeshPepBridge::sanitize_and_inject_headers(&dirty_headers, "valid_mesh_token_xyz");

        // 1. Verify Authorization, Cookie, and X-Mesh-* are completely removed
        assert!(!sanitized.iter().any(|(k, _)| k.eq_ignore_ascii_case("authorization")));
        assert!(!sanitized.iter().any(|(k, _)| k.eq_ignore_ascii_case("cookie")));
        assert!(!sanitized.iter().any(|(k, _)| k.to_ascii_lowercase().starts_with("x-mesh-") && k != "X-Mesh-Authentication"));

        // 2. Verify X-Mesh-Authentication is injected
        let auth_hdr = sanitized.iter().find(|(k, _)| k == "X-Mesh-Authentication");
        assert!(auth_hdr.is_some());
        assert_eq!(auth_hdr.unwrap().1, "Bearer valid_mesh_token_xyz");

        // 3. Verify non-sensitive headers are preserved
        assert!(sanitized.iter().any(|(k, v)| k == "Content-Type" && v == "application/json"));
        assert!(sanitized.iter().any(|(k, v)| k == "X-Custom-Tracing" && v == "trace_99"));
    }

    #[test]
    fn test_strict_uri_scheme_filtering() {
        let base_url = "http://127.0.0.1:8080";

        // Allowed schemes
        assert_eq!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "mcp://calc").unwrap(),
            "http://127.0.0.1:8080/mesh/mcp/calc"
        );
        assert_eq!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "a2a://worker").unwrap(),
            "http://127.0.0.1:8080/mesh/a2a/worker"
        );
        assert_eq!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "inference://qwen").unwrap(),
            "http://127.0.0.1:8080/mesh/inference/qwen"
        );
        assert_eq!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "egress://api.service.com").unwrap(),
            "http://127.0.0.1:8080/mesh/egress/api.service.com"
        );

        // Prohibited schemes (must fail closed)
        assert!(matches!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "http://127.0.0.1:8080/evil"),
            Err(MeshCallError::InvalidUri(_))
        ));
        assert!(matches!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "https://google.com"),
            Err(MeshCallError::InvalidUri(_))
        ));
        assert!(matches!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "file:///etc/passwd"),
            Err(MeshCallError::InvalidUri(_))
        ));
        assert!(matches!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "tcp://192.168.1.1:5000"),
            Err(MeshCallError::InvalidUri(_))
        ));
    }

    #[test]
    fn test_sub_millisecond_killswitch_eviction_benchmark() {
        let issuer = Arc::new(OctopusOidcActorIssuer::new_ephemeral("https://agentoctopus.local"));
        let bridge = AgentMeshPepBridge::new(issuer, "http://127.0.0.1:8080".to_string());

        let arm_calc = "arm_calc";
        let arm_rogue = "arm_rogue";

        let ks_calc = KillSwitch::new();
        let ks_rogue = KillSwitch::new();

        bridge.register_arm_killswitch(arm_calc, ks_calc.clone());
        bridge.register_arm_killswitch(arm_rogue, ks_rogue.clone());

        // Pre-populate cache with multiple epochs
        {
            let mut vault = bridge.token_vault.write().unwrap();
            vault.insert(
                (arm_calc.to_string(), 1),
                CachedMeshToken {
                    arm_id: arm_calc.to_string(),
                    epoch: 1,
                    role: ArmRole::UntrustedDocIngest,
                    access_token: "token_calc_ep1".to_string(),
                    token_type: "Bearer".to_string(),
                    issued_token_type: "access_token".to_string(),
                    issued_at_unix_secs: 1000,
                    expires_at_unix_secs: 2000,
                },
            );
            vault.insert(
                (arm_calc.to_string(), 2),
                CachedMeshToken {
                    arm_id: arm_calc.to_string(),
                    epoch: 2,
                    role: ArmRole::UntrustedDocIngest,
                    access_token: "token_calc_ep2".to_string(),
                    token_type: "Bearer".to_string(),
                    issued_token_type: "access_token".to_string(),
                    issued_at_unix_secs: 1000,
                    expires_at_unix_secs: 2000,
                },
            );
            vault.insert(
                (arm_rogue.to_string(), 1),
                CachedMeshToken {
                    arm_id: arm_rogue.to_string(),
                    epoch: 1,
                    role: ArmRole::AccountingLedgerWrite,
                    access_token: "token_rogue_ep1".to_string(),
                    token_type: "Bearer".to_string(),
                    issued_token_type: "access_token".to_string(),
                    issued_at_unix_secs: 1000,
                    expires_at_unix_secs: 2000,
                },
            );
        }

        assert_eq!(bridge.token_vault.read().unwrap().len(), 3);
        assert!(!ks_calc.is_tripped());
        assert!(!ks_rogue.is_tripped());

        // Trip KillSwitch for arm_calc and benchmark eviction latency
        let elapsed = bridge.trip_arm_killswitch(arm_calc);

        // Sub-millisecond SLA assertion (< 1,000 microseconds)
        assert!(
            elapsed.as_micros() < 1_000,
            "Eviction took {} us, exceeding 1,000 us SLA",
            elapsed.as_micros()
        );

        // Verify arm_calc is evicted from vault and circuit breaker tripped
        assert!(ks_calc.is_tripped());
        assert!(!ks_rogue.is_tripped());

        let vault = bridge.token_vault.read().unwrap();
        assert!(vault.get(&(arm_calc.to_string(), 1)).is_none());
        assert!(vault.get(&(arm_calc.to_string(), 2)).is_none());
        assert!(vault.get(&(arm_rogue.to_string(), 1)).is_some()); // Sibling untouched
        assert_eq!(vault.len(), 1);

        // Subsequent call for arm_calc fails closed immediately
        let res = bridge.dispatch_mesh_call_sync(arm_calc, 2, &ArmRole::UntrustedDocIngest, "mcp://calc", b"{}");
        assert!(matches!(res, Err(MeshCallError::KillSwitchTripped(_))));
    }

    #[test]
    fn test_zero_mutual_information_sanitization() {
        let dirty_payload = "{\"zebra\": 1, \"alpha\": 2, \"key\": \"ghp_99887766554433221100aabbccddeeff\u{200B}\u{FEFF}\"}";

        let sanitized_bytes = AgentMeshPepBridge::sanitize_upstream_payload(dirty_payload.as_bytes());
        let sanitized_str = String::from_utf8(sanitized_bytes).unwrap();

        // Zero-width characters must be completely stripped
        assert!(!sanitized_str.contains('\u{200B}'));
        assert!(!sanitized_str.contains('\u{FEFF}'));

        // High entropy secret must be redacted
        assert!(sanitized_str.contains("<ZK_MI_REDACTED>"));
        assert!(!sanitized_str.contains("ghp_99887766554433221100aabbccddeeff"));
    }

    #[test]
    fn test_cached_token_proactive_refresh_window() {
        let token = CachedMeshToken {
            arm_id: "arm_calc".to_string(),
            epoch: 1,
            role: ArmRole::UntrustedDocIngest,
            access_token: "token_abc".to_string(),
            token_type: "Bearer".to_string(),
            issued_token_type: "access_token".to_string(),
            issued_at_unix_secs: 100,
            expires_at_unix_secs: 200,
        };

        // At t=150 (50s remaining): not expired
        assert!(!token.is_expired_or_near(150, 15));

        // At t=186 (14s remaining): within 15s refresh buffer -> must refresh
        assert!(token.is_expired_or_near(186, 15));

        // At t=205: past expiry -> must refresh
        assert!(token.is_expired_or_near(205, 15));
    }

    #[test]
    fn test_e2e_token_exchange_mock_node() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mock_url = format!("http://127.0.0.1:{}", port);

        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut full_req = Vec::new();
                let mut buf = [0u8; 1024];
                while !String::from_utf8_lossy(&full_req).contains("grant_type") {
                    let n = stream.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    full_req.extend_from_slice(&buf[..n]);
                }
                let req_str = String::from_utf8_lossy(&full_req);

                assert!(req_str.contains("POST /oauth/token HTTP/1.1"));
                assert!(req_str.contains("grant_type"));

                let resp_body = "{\"access_token\":\"mock_mesh_token_777\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",\"token_type\":\"Bearer\",\"expires_in\":300}";
                let resp_wire = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                stream.write_all(resp_wire.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });

        let issuer = Arc::new(OctopusOidcActorIssuer::new_ephemeral("https://agentoctopus.local"));
        let bridge = AgentMeshPepBridge::new(issuer, mock_url);

        let token = bridge
            .get_or_exchange_token_sync("arm_calc", 1, &ArmRole::UntrustedDocIngest, "mcp://calc")
            .unwrap();

        assert_eq!(token, "mock_mesh_token_777");

        let vault = bridge.token_vault.read().unwrap();
        let cached = vault.get(&("arm_calc".to_string(), 1)).unwrap();
        assert_eq!(cached.access_token, "mock_mesh_token_777");

        handle.join().unwrap();
    }
}
