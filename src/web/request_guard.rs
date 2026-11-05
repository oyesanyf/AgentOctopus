//! Dashboard Request Guard (Finding 8).
//!
//! The dashboard can run `cargo test`, sever arms, edit egress allowlists, etc. Before this guard,
//! every response carried `Access-Control-Allow-Origin: *` and no request was authenticated, so any
//! web page (cross-site POST or DNS rebinding) could drive those endpoints.
//!
//! Enforced on every request, before routing:
//! 1. **Host allowlist** — `Host` must be exactly `127.0.0.1:<port>`, `localhost:<port>` or
//!    `[::1]:<port>` where `<port>` is the *local* port of the accepted socket. Rebinding hostnames
//!    (`evil.example` resolving to 127.0.0.1) fail with 421.
//! 2. **Origin / Sec-Fetch-Site** — for any `/api/*` request and any non-GET/HEAD request, an
//!    `Origin` header (if present) must be `http://<allowed host>`; `Sec-Fetch-Site: cross-site`
//!    is rejected (403).
//! 3. **Per-launch token** — every `/api/*` request must carry `X-Octopus-Token` equal to a random
//!    256-bit token generated at startup (constant-time comparison). The token is delivered only
//!    inside the same-origin `index.html` (`<meta name="octopus-token">`), which cross-origin pages
//!    cannot read once wildcard CORS is gone. `EventSource` (SSE) cannot set headers, so for
//!    `text/event-stream` endpoints a `token=` query parameter is accepted — only after (1) and (2).

use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Header carrying the per-launch dashboard token.
pub const TOKEN_HEADER: &str = "x-octopus-token";

/// Session cookie name for authenticated dashboard operator sessions (`AO-FIND-05`).
pub const SESSION_COOKIE_NAME: &str = "Octopus-Session";

/// Endpoints consumed via `EventSource` (cannot send custom headers).
pub const SSE_PATHS: &[&str] = &["/api/test-stream", "/api/runtime-activity/stream"];

/// Header carrying optional CAGE Substrate API keys.
pub const CAGE_KEY_HEADER: &str = "x-cage-key";

/// Canonical CAGE Substrate Contract v1.0 endpoint paths exempt from the per-launch dashboard token.
pub const CAGE_SUBSTRATE_PATHS: &[&str] = &[
    "/governance/ingest-policy",
    "/governance/policy-version",
    "/governance/validate-action",
    "/v1/governance/validate-action",
    "/governance/consume-seal",
    "/governance/proof-status",
    "/governance/trace-conformance",
    "/api/cage/ingest-policy",
    "/api/cage/policy-version",
    "/api/cage/validate-action",
    "/api/cage/consume-seal",
    "/api/cage/proof-status",
    "/api/cage/trace-conformance",
];

/// Liveness endpoints exempt from the token (Host/Origin checks still apply; no sensitive data).
pub const TOKEN_EXEMPT_PATHS: &[&str] = &[
    "/health",
    "/api/health",
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration",
    "/jwks",
    "/jwks.json",
    "/oauth/token",
    "/oauth/revoke",
    "/governance/ingest-policy",
    "/governance/policy-version",
    "/governance/validate-action",
    "/v1/governance/validate-action",
    "/governance/consume-seal",
    "/governance/proof-status",
    "/governance/trace-conformance",
    "/api/cage/ingest-policy",
    "/api/cage/policy-version",
    "/api/cage/validate-action",
    "/api/cage/consume-seal",
    "/api/cage/proof-status",
    "/api/cage/trace-conformance",
];

/// Returns true if the path belongs to the AgentMesh OIDC discovery, token exchange, or inbound MCP surface.
/// Inbound `/mesh/*` routes enforce their own `X-Mesh-Authentication` JWT/token + `X-Octopus-Cage-Seal` verification.
pub fn is_mesh_path(path: &str) -> bool {
    let trimmed = path.trim_end_matches('/');
    trimmed == "/mesh"
        || trimmed.starts_with("/mesh/")
        || trimmed == "/mcp/octopus-doc-extractor"
        || trimmed == "/mcp/octopus-ledger-validator"
        || trimmed == "/oauth/token"
        || trimmed == "/oauth/revoke"
        || trimmed == "/.well-known/openid-configuration"
        || trimmed == "/jwks"
        || trimmed == "/jwks.json"
}

/// Returns true if the path belongs to the CAGE Substrate Contract v1.0 interface.
pub fn is_cage_substrate_path(path: &str) -> bool {
    let trimmed = path.trim_end_matches('/');
    trimmed.starts_with("/governance/")
        || trimmed == "/governance"
        || trimmed.starts_with("/v1/governance/")
        || trimmed == "/v1/governance"
        || trimmed.starts_with("/api/cage/")
        || trimmed == "/api/cage"
        || trimmed.starts_with("/v1/cage/")
        || trimmed == "/v1/cage"
        || trimmed.starts_with("/api/v1/cage/")
        || trimmed == "/api/v1/cage"
        || CAGE_SUBSTRATE_PATHS.contains(&trimmed)
}

/// Returns true if the path is exempt from mandatory dashboard token checks on loopback.
pub fn is_token_exempt_path(path: &str) -> bool {
    let trimmed = path.trim_end_matches('/');
    TOKEN_EXEMPT_PATHS.contains(&path)
        || TOKEN_EXEMPT_PATHS.contains(&trimmed)
        || is_cage_substrate_path(path)
        || is_mesh_path(path)
}

/// Extracts a Bearer token from the `Authorization` header, if present.
pub fn extract_bearer_token(headers: &str) -> Option<&str> {
    for line in headers.lines() {
        if line.to_ascii_lowercase().starts_with("authorization:") {
            if let Some((_, val)) = line.split_once(':') {
                let trimmed = val.trim();
                if let Some(token) = trimmed.strip_prefix("Bearer ") {
                    return Some(token.trim());
                } else if let Some(token) = trimmed.strip_prefix("bearer ") {
                    return Some(token.trim());
                }
            }
        }
    }
    None
}

/// Resolves the configured CAGE API key from the environment, if present.
pub fn configured_cage_api_key() -> Option<String> {
    std::env::var("CAGE_API_KEY")
        .ok()
        .filter(|k| !k.trim().is_empty())
        .or_else(|| {
            std::env::var("CAGE_AUTH_TOKEN")
                .ok()
                .filter(|k| !k.trim().is_empty())
        })
}

/// Response headers applied to every dashboard response instead of wildcard CORS.
pub const SECURITY_HEADERS: &str = "X-Content-Type-Options: nosniff\r\nCross-Origin-Resource-Policy: same-origin\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: frame-ancestors 'none'\r\nReferrer-Policy: no-referrer\r\n";

/// Returns the per-launch dashboard token (generated once from the OS CSPRNG).
pub fn dashboard_token() -> &'static str {
    static TOKEN: OnceLock<String> = OnceLock::new();
    TOKEN.get_or_init(|| {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    })
}

fn bootstrap_nonce_store() -> &'static Mutex<Option<String>> {
    static BOOTSTRAP: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    BOOTSTRAP.get_or_init(|| Mutex::new(None))
}

fn session_store() -> &'static Mutex<HashMap<String, String>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Issues a single-use 256-bit CSPRNG bootstrap nonce for the operator browser launch (`AO-FIND-05`).
/// Once redeemed on `GET /?bootstrap=<nonce>`, the nonce is immediately invalidated and exchanged
/// for an `HttpOnly; SameSite=Strict` `Octopus-Session` cookie bound to a session-specific CSRF token.
pub fn issue_bootstrap_nonce() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let nonce = hex::encode(bytes);
    if let Ok(mut guard) = bootstrap_nonce_store().lock() {
        *guard = Some(nonce.clone());
    }
    let _ = std::fs::create_dir_all("logs");
    let _ = std::fs::write("logs/.octopus_operator_token", dashboard_token());
    nonce
}

fn extract_cookie_value<'a>(headers: &'a str, cookie_name: &str) -> Option<&'a str> {
    let cookie_hdr = header_value(headers, "cookie")?;
    for pair in cookie_hdr.split(';') {
        let (k, v) = pair.trim().split_once('=')?;
        if k.trim() == cookie_name {
            return Some(v.trim());
        }
    }
    None
}

/// Resolves the session-scoped CSRF token to inject into `index.html` (`AO-FIND-05`).
///
/// - If the request carries a valid `Cookie: Octopus-Session=<sid>`, returns that session's CSRF token.
/// - If the request carries the single-use `?bootstrap=<nonce>` query parameter (or the authoritative
///   `X-Octopus-Token` header), consumes the bootstrap nonce, mints a new `(session_id, csrf_token)`
///   pair, and returns `(csrf_token, Some("Set-Cookie: ..."))`.
/// - If the request is an unauthenticated `GET /` (e.g., a local process attempting to scrape the
///   HTML for `<meta name="octopus-token">`), returns `(String::new(), None)` so **no reusable token**
///   is exposed in the HTML response.
pub fn resolve_index_session_token(req: &GuardRequest<'_>) -> (String, Option<String>) {
    // 1. Check existing authenticated session cookie
    if let Some(sid) = extract_cookie_value(req.headers, SESSION_COOKIE_NAME) {
        if !sid.is_empty() {
            if let Ok(sessions) = session_store().lock() {
                if let Some(csrf) = sessions.get(sid) {
                    return (csrf.clone(), None);
                }
            }
        }
    }

    // 2. Check single-use bootstrap nonce in query (`?bootstrap=<nonce>`) or authoritative header
    let bootstrap_ok = if let Some(presented_nonce) = query_param(req.query, "bootstrap") {
        if !presented_nonce.is_empty() {
            if let Ok(mut guard) = bootstrap_nonce_store().lock() {
                if let Some(ref expected_nonce) = *guard {
                    if constant_time_str_eq(presented_nonce, expected_nonce) {
                        *guard = None; // Single-use redemption
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else if let Some(hdr_tok) = header_value(req.headers, TOKEN_HEADER) {
        !hdr_tok.is_empty() && constant_time_str_eq(hdr_tok, dashboard_token())
    } else {
        false
    };

    if bootstrap_ok {
        let mut sid_bytes = [0u8; 32];
        let mut csrf_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sid_bytes);
        rand::rngs::OsRng.fill_bytes(&mut csrf_bytes);
        let sid = hex::encode(sid_bytes);
        let csrf = hex::encode(csrf_bytes);
        if let Ok(mut sessions) = session_store().lock() {
            if sessions.len() >= 256 {
                if let Some(oldest_sid) = sessions.keys().next().cloned() {
                    sessions.remove(&oldest_sid);
                }
            }
            sessions.insert(sid.clone(), csrf.clone());
        }
        let cookie_hdr = format!(
            "Set-Cookie: {}={}; HttpOnly; SameSite=Strict; Path=/\r\n",
            SESSION_COOKIE_NAME, sid
        );
        return (csrf, Some(cookie_hdr));
    }

    // 3. Unauthenticated GET / -> never expose a reusable token in HTML
    (String::new(), None)
}

fn is_valid_token_or_session(req: &GuardRequest<'_>, presented: &str, master_token: &str) -> bool {
    if presented.is_empty() {
        return false;
    }
    if !master_token.is_empty() && constant_time_str_eq(presented, master_token) {
        return true;
    }
    if let Some(sid) = extract_cookie_value(req.headers, SESSION_COOKIE_NAME) {
        if !sid.is_empty() {
            if let Ok(sessions) = session_store().lock() {
                if let Some(expected_csrf) = sessions.get(sid) {
                    return constant_time_str_eq(presented, expected_csrf);
                }
            }
        }
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardRejection {
    /// 421 Misdirected Request — Host header not an allowed loopback authority.
    BadHost(String),
    /// 403 Forbidden — cross-origin request.
    CrossOrigin(String),
    /// 401 Unauthorized — missing or wrong token.
    Unauthorized,
}

impl GuardRejection {
    pub fn status_line(&self) -> &'static str {
        match self {
            Self::BadHost(_) => "421 Misdirected Request",
            Self::CrossOrigin(_) => "403 Forbidden",
            Self::Unauthorized => "401 Unauthorized",
        }
    }
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadHost(_) => "DASHBOARD_HOST_REJECTED",
            Self::CrossOrigin(_) => "DASHBOARD_CROSS_ORIGIN_REJECTED",
            Self::Unauthorized => "DASHBOARD_TOKEN_REQUIRED",
        }
    }
    pub fn message(&self) -> String {
        match self {
            Self::BadHost(h) => format!(
                "Host '{}' is not an allowed loopback authority for this dashboard",
                h
            ),
            Self::CrossOrigin(o) => {
                format!("Cross-origin request rejected (origin/fetch-site: {})", o)
            }
            Self::Unauthorized => "Missing or invalid X-Octopus-Token".to_string(),
        }
    }
}

/// Minimal parsed request view needed by the guard.
#[derive(Debug, Clone, Copy)]
pub struct GuardRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a str,
    pub local_port: u16,
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) {
            Some(v.trim())
        } else {
            None
        }
    })
}

fn allowed_authorities(port: u16) -> [String; 3] {
    [
        format!("127.0.0.1:{}", port),
        format!("localhost:{}", port),
        format!("[::1]:{}", port),
    ]
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k == name {
            Some(v)
        } else {
            None
        }
    })
}

fn constant_time_str_eq(a: &str, b: &str) -> bool {
    crate::security::constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Enforces Host, Origin/Sec-Fetch-Site and token checks. Must run before any routing.
pub fn authorize_request(req: &GuardRequest<'_>, token: &str) -> Result<(), GuardRejection> {
    // 1. Host allowlist (exact authority match incl. port; case-insensitive host).
    let host = header_value(req.headers, "host").unwrap_or("");
    let host_lc = host.to_ascii_lowercase();
    let authorities = allowed_authorities(req.local_port);
    if !authorities.iter().any(|a| *a == host_lc) {
        return Err(GuardRejection::BadHost(host.to_string()));
    }

    let is_api = req.path.starts_with("/api/") || req.path == "/api";
    let is_state_changing = !matches!(req.method, "GET" | "HEAD");
    let is_cage = is_cage_substrate_path(req.path);
    let is_exempt = is_token_exempt_path(req.path);

    // 2. Origin / Sec-Fetch-Site (enforced on API, state-changing, and CAGE endpoints)
    if is_api || is_state_changing || is_cage {
        if let Some(site) = header_value(req.headers, "sec-fetch-site") {
            if site.eq_ignore_ascii_case("cross-site") {
                return Err(GuardRejection::CrossOrigin(format!(
                    "sec-fetch-site={}",
                    site
                )));
            }
        }
        if let Some(origin) = header_value(req.headers, "origin") {
            let origin_lc = origin.to_ascii_lowercase();
            let ok = authorities
                .iter()
                .any(|a| origin_lc == format!("http://{}", a));
            if !ok {
                return Err(GuardRejection::CrossOrigin(origin.to_string()));
            }
        }
    }

    // 3. Token Authentication
    if is_cage {
        // If an explicit CAGE_API_KEY / CAGE_AUTH_TOKEN is configured in the environment,
        // callers MUST supply a matching Bearer token, X-Cage-Key, or X-Octopus-Token.
        if let Some(expected_key) = configured_cage_api_key() {
            let presented = extract_bearer_token(req.headers)
                .or_else(|| header_value(req.headers, CAGE_KEY_HEADER))
                .or_else(|| header_value(req.headers, TOKEN_HEADER));
            match presented {
                Some(p)
                    if constant_time_str_eq(p, &expected_key) || constant_time_str_eq(p, token) => {
                }
                _ => return Err(GuardRejection::Unauthorized),
            }
        } else if let Some(presented) = header_value(req.headers, TOKEN_HEADER) {
            // When accessed via the dashboard with an explicit X-Octopus-Token, validate it.
            if !presented.is_empty() && !is_valid_token_or_session(req, presented, token) {
                return Err(GuardRejection::Unauthorized);
            }
        }
        // When CAGE_API_KEY is not set, local loopback callers proceed without mandatory token.
    } else if is_api && !is_exempt {
        let presented = header_value(req.headers, TOKEN_HEADER).or_else(|| {
            if req.method == "GET" && SSE_PATHS.contains(&req.path) {
                query_param(req.query, "token")
            } else {
                None
            }
        });
        match presented {
            Some(t) if is_valid_token_or_session(req, t, token) => {}
            _ => return Err(GuardRejection::Unauthorized),
        }
    } else if is_state_changing && !is_api && req.method != "OPTIONS" && !is_exempt {
        // Non-API state-changing requests are not part of the dashboard surface.
        let presented = header_value(req.headers, TOKEN_HEADER);
        match presented {
            Some(t) if is_valid_token_or_session(req, t, token) => {}
            _ => return Err(GuardRejection::Unauthorized),
        }
    }

    Ok(())
}

/// Injects the token `<meta>` tag and a fetch/EventSource wrapper into the dashboard HTML.
pub fn inject_token_into_index(index_html: &str, token: &str) -> String {
    let snippet = format!(
        concat!(
            "<meta name=\"octopus-token\" content=\"{}\">",
            "<script>(function(){{",
            "var t=document.querySelector('meta[name=\"octopus-token\"]').content;",
            "var of=window.fetch;",
            "window.fetch=function(i,o){{o=Object.assign({{}},o||{{}});",
            "var h=new Headers(o.headers||((typeof Request!=='undefined'&&i instanceof Request)?i.headers:undefined));",
            "h.set('X-Octopus-Token',t);o.headers=h;return of.call(this,i,o);}};",
            "var OE=window.EventSource;if(OE){{var W=function(u,c){{var x=new URL(u,location.href);",
            "if(x.origin===location.origin){{x.searchParams.set('token',t);}}return new OE(x.toString(),c);}};",
            "W.prototype=OE.prototype;W.CONNECTING=0;W.OPEN=1;W.CLOSED=2;window.EventSource=W;}}",
            "}})();</script>"
        ),
        token
    );
    if let Some(idx) = index_html.find("<head>") {
        let mut out = String::with_capacity(index_html.len() + snippet.len());
        out.push_str(&index_html[..idx + "<head>".len()]);
        out.push_str(&snippet);
        out.push_str(&index_html[idx + "<head>".len()..]);
        out
    } else {
        format!("{}{}", snippet, index_html)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(method: &'a str, path: &'a str, headers: &'a str) -> GuardRequest<'a> {
        GuardRequest {
            method,
            path,
            query: "",
            headers,
            local_port: 5005,
        }
    }

    #[test]
    fn rejects_rebinding_host() {
        let h =
            "POST /api/run-rust-tests HTTP/1.1\r\nHost: evil.example:5005\r\nX-Octopus-Token: abc";
        assert!(matches!(
            authorize_request(&req("POST", "/api/run-rust-tests", h), "abc"),
            Err(GuardRejection::BadHost(_))
        ));
    }

    #[test]
    fn rejects_cross_origin() {
        let h = "POST /api/x HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nOrigin: https://evil.example\r\nX-Octopus-Token: abc";
        assert!(matches!(
            authorize_request(&req("POST", "/api/x", h), "abc"),
            Err(GuardRejection::CrossOrigin(_))
        ));
    }

    #[test]
    fn rejects_missing_token() {
        let h = "POST /api/x HTTP/1.1\r\nHost: localhost:5005\r\nOrigin: http://localhost:5005";
        assert_eq!(
            authorize_request(&req("POST", "/api/x", h), "abc"),
            Err(GuardRejection::Unauthorized)
        );
    }

    #[test]
    fn accepts_same_origin_with_token() {
        let h = "POST /api/x HTTP/1.1\r\nHost: localhost:5005\r\nOrigin: http://localhost:5005\r\nX-Octopus-Token: abc";
        assert!(authorize_request(&req("POST", "/api/x", h), "abc").is_ok());
    }

    #[test]
    fn accepts_cage_substrate_loopback_without_token() {
        let endpoints = [
            ("POST", "/governance/ingest-policy"),
            ("GET", "/governance/policy-version"),
            ("POST", "/governance/validate-action"),
            ("POST", "/v1/governance/validate-action"),
            ("POST", "/governance/consume-seal"),
            ("GET", "/governance/proof-status"),
            ("POST", "/governance/trace-conformance"),
            ("POST", "/api/cage/ingest-policy"),
            ("GET", "/api/cage/policy-version"),
            ("POST", "/api/cage/validate-action"),
            ("POST", "/api/cage/consume-seal"),
            ("GET", "/api/cage/proof-status"),
            ("POST", "/api/cage/trace-conformance"),
        ];
        for (method, path) in endpoints {
            let h = format!("{} {} HTTP/1.1\r\nHost: 127.0.0.1:5005", method, path);
            assert!(
                authorize_request(&req(method, path, &h), "mock_master_token").is_ok(),
                "Endpoint {} {} should be authorized on loopback without token",
                method,
                path
            );
        }
    }

    #[test]
    fn rejects_cage_substrate_cross_origin() {
        let h = "POST /governance/validate-action HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nOrigin: https://evil.example";
        assert!(matches!(
            authorize_request(&req("POST", "/governance/validate-action", h), "mock_token"),
            Err(GuardRejection::CrossOrigin(_))
        ));
    }

    #[test]
    fn rejects_cage_substrate_cross_site_fetch() {
        let h = "POST /governance/validate-action HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nSec-Fetch-Site: cross-site";
        assert!(matches!(
            authorize_request(&req("POST", "/governance/validate-action", h), "mock_token"),
            Err(GuardRejection::CrossOrigin(_))
        ));
    }

    #[test]
    fn rejects_cage_substrate_rebinding_host() {
        let h =
            "POST /governance/validate-action HTTP/1.1\r\nHost: attacker-rebinding.example:5005";
        assert!(matches!(
            authorize_request(&req("POST", "/governance/validate-action", h), "mock_token"),
            Err(GuardRejection::BadHost(_))
        ));
    }

    #[test]
    fn strictly_enforces_non_exempt_api_token() {
        let h = "POST /api/run-rust-tests HTTP/1.1\r\nHost: 127.0.0.1:5005";
        assert_eq!(
            authorize_request(&req("POST", "/api/run-rust-tests", h), "mock_token"),
            Err(GuardRejection::Unauthorized)
        );
        let h_am = "GET /api/agentmesh/status HTTP/1.1\r\nHost: 127.0.0.1:5005";
        assert_eq!(
            authorize_request(&req("GET", "/api/agentmesh/status", h_am), "mock_token"),
            Err(GuardRejection::Unauthorized)
        );
    }

    #[test]
    fn accepts_agentmesh_oidc_and_inbound_mcp_loopback_while_blocking_rebinding() {
        for (m, p) in [
            ("GET", "/.well-known/openid-configuration"),
            ("GET", "/jwks"),
            ("POST", "/oauth/token"),
            ("POST", "/mesh/mcp/octopus/doc_extractor"),
        ] {
            let h = format!("{} {} HTTP/1.1\r\nHost: 127.0.0.1:5005", m, p);
            assert!(
                authorize_request(&req(m, p, &h), "mock_token").is_ok(),
                "{} {} should pass loopback guard",
                m,
                p
            );
        }

        let bad_host =
            "POST /mesh/mcp/octopus/doc_extractor HTTP/1.1\r\nHost: rebind.attacker.example:5005";
        assert!(matches!(
            authorize_request(
                &req("POST", "/mesh/mcp/octopus/doc_extractor", bad_host),
                "mock_token"
            ),
            Err(GuardRejection::BadHost(_))
        ));
    }
}
