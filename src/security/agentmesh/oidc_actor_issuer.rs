//! OIDC Workload Identity Actor Issuer & RFC 7517 EC JWKS Provider
//!
//! Conforms to:
//! - RFC 7515: JSON Web Signature (JWS) Compact Serialization
//! - RFC 7517: JSON Web Key (JWK) and JWKS
//! - RFC 7518 §3.4: ES256 (ECDSA P-256 with SHA-256, IEEE P1363 64-byte raw signature)
//! - RFC 7518 §6.2: Elliptic Curve Key JWK representation (crv: P-256, x, y base64url unpadded)
//! - OpenID Connect Discovery 1.0 §3 (/.well-known/openid-configuration)
//! - SPIFFE Workload Identity: spiffe://agentoctopus.local/arm/{arm_id}/epoch/{epoch}
//! - Google AgentMesh (#734) Invariant: strict <= 5s clock drift tolerance and bounded replay cache.

use std::collections::{HashSet, VecDeque};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::types::ArmRole;
use crate::security::cage_substrate::{JwkKeyDto, JwksResponse};

pub const DEFAULT_TOKEN_TTL_SECS: u64 = 300; // 5 minutes
pub const DEFAULT_ROTATION_GRACE_SECS: u64 = 300; // 5 minutes
pub const MAX_CLOCK_DRIFT_SECS: u64 = 5; // Strict <= 5s drift tolerance (fixing #734 60s gap)
pub const SPIFFE_ISSUER_DEFAULT: &str = "spiffe://agentoctopus.local";
pub const AUDIENCE_DEFAULT: &str = "agentmesh.local";
pub const MAX_JTI_CACHE_ENTRIES: usize = 10_000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OidcError {
    #[error("Cryptographic signing/verification failure: {0}")]
    CryptoError(String),

    #[error("Token expired: exp={exp}, now={now} (drift exceeded {max_drift}s)")]
    TokenExpired {
        exp: u64,
        now: u64,
        max_drift: u64,
    },

    #[error("Token not yet valid: nbf={nbf}, now={now} (drift exceeded {max_drift}s)")]
    TokenNotYetValid {
        nbf: u64,
        now: u64,
        max_drift: u64,
    },

    #[error("Token issued in future: iat={iat}, now={now} (drift exceeded {max_drift}s)")]
    TokenIssuedInFuture {
        iat: u64,
        now: u64,
        max_drift: u64,
    },

    #[error("Key not found in JWKS: kid='{kid}'")]
    KeyNotFound { kid: String },

    #[error("Key has been retired and grace period expired: kid='{kid}', retired_at={retired_at}, grace={grace_secs}s")]
    KeyRetiredExpired {
        kid: String,
        retired_at: u64,
        grace_secs: u64,
    },

    #[error("Unsupported JWS algorithm: '{0}' (only 'ES256' permitted)")]
    UnsupportedAlgorithm(String),

    #[error("Invalid token format: {0}")]
    InvalidTokenFormat(String),

    #[error("Invalid signature format: raw IEEE P1363 must be exactly 64 bytes (got {0} bytes)")]
    InvalidSignatureLength(usize),

    #[error("ASN.1 DER signature rejected: RFC 7515 §3.4 mandates IEEE P1363 raw (R || S) format")]
    DerSignatureForbidden,

    #[error("Token replay detected: jti '{0}' already consumed")]
    ReplayDetected(String),

    #[error("JSON serialization/deserialization error: {0}")]
    JsonError(String),

    #[error("Audience mismatch: expected '{expected}', found '{actual}'")]
    AudienceMismatch { expected: String, actual: String },

    #[error("Issuer mismatch: expected '{expected}', found '{actual}'")]
    IssuerMismatch { expected: String, actual: String },
}

/// RFC 7515 JWS Protected Header
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JwsHeader {
    pub alg: String, // MUST be "ES256"
    pub typ: String, // MUST be "JWT"
    pub kid: String, // Key Identifier
}

/// Workload Identity JWT Claims
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub arm_id: String,
    pub epoch: u64,
    pub role: String,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub jti: String,
}

/// RFC 7517 / RFC 7518 §6.2 Elliptic Curve Public Key in JWK Format
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcJwk {
    pub kty: String, // "EC"
    pub crv: String, // "P-256"
    pub x: String,   // 32-byte big-endian X coordinate, base64url unpadded
    pub y: String,   // 32-byte big-endian Y coordinate, base64url unpadded
    #[serde(rename = "use")]
    pub key_use: String, // "sig"
    pub alg: String, // "ES256"
    pub kid: String, // Key ID
}

/// RFC 7517 JWKS Document
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JwksDocument {
    pub keys: Vec<EcJwk>,
}

/// OpenID Connect Discovery 1.0 Metadata Document
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenIdConfiguration {
    pub issuer: String,
    pub jwks_uri: String,
    pub token_endpoint: String,
    pub response_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
}

/// Internal Key Representation
#[derive(Clone)]
pub struct KeyEntry {
    pub kid: String,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub created_at: u64,
}

/// Historical Retired Key with Grace Period
#[derive(Clone)]
pub struct RetiredKeyEntry {
    pub key: KeyEntry,
    pub retired_at: u64,
    pub grace_period_secs: u64,
}

/// Extracts uncompressed (X, Y) coordinates from a P-256 VerifyingKey.
/// Returns (x_base64url, y_base64url) unpadded strings.
pub fn verifying_key_to_jwk_coords(vk: &VerifyingKey) -> (String, String) {
    let point = vk.to_encoded_point(false);
    let raw = point.as_bytes();
    assert_eq!(raw[0], 0x04, "Uncompressed EC point must begin with 0x04");
    assert_eq!(raw.len(), 65, "P-256 uncompressed point must be 65 bytes");

    let x_bytes = &raw[1..33];
    let y_bytes = &raw[33..65];

    let x_b64 = URL_SAFE_NO_PAD.encode(x_bytes);
    let y_b64 = URL_SAFE_NO_PAD.encode(y_bytes);
    (x_b64, y_b64)
}

/// Constructs an EcJwk from a KeyEntry.
pub fn key_entry_to_jwk(entry: &KeyEntry) -> EcJwk {
    let (x, y) = verifying_key_to_jwk_coords(&entry.verifying_key);
    EcJwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x,
        y,
        key_use: "sig".to_string(),
        alg: "ES256".to_string(),
        kid: entry.kid.clone(),
    }
}

/// Converts a 64-byte raw IEEE P1363 signature into a p256::ecdsa::Signature.
/// Fails closed if ASN.1 DER is detected (starts with 0x30).
pub fn parse_ieee_p1363_signature(raw_sig: &[u8]) -> Result<Signature, OidcError> {
    if raw_sig.is_empty() {
        return Err(OidcError::InvalidSignatureLength(0));
    }
    // Check for ASN.1 DER signature tag (0x30 = SEQUENCE)
    if raw_sig[0] == 0x30 {
        return Err(OidcError::DerSignatureForbidden);
    }
    if raw_sig.len() != 64 {
        return Err(OidcError::InvalidSignatureLength(raw_sig.len()));
    }
    Signature::from_bytes(raw_sig.into())
        .map_err(|e| OidcError::CryptoError(format!("Malformed IEEE P1363 scalar: {e}")))
}

/// Bounded JTI Replay Prevention Cache
struct BoundedJtiCache {
    seen: HashSet<String>,
    order: VecDeque<String>,
    max_capacity: usize,
}

impl BoundedJtiCache {
    fn new(max_capacity: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(max_capacity),
            order: VecDeque::with_capacity(max_capacity),
            max_capacity,
        }
    }

    fn check_and_insert(&mut self, jti: &str) -> bool {
        if self.seen.contains(jti) {
            return false;
        }
        if self.order.len() >= self.max_capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(jti.to_string());
        self.order.push_back(jti.to_string());
        true
    }
}

pub struct OctopusOidcActorIssuer {
    issuer_url: String,
    audience: String,
    token_ttl_secs: u64,
    rotation_grace_secs: u64,
    max_clock_drift_secs: u64,
    current_key: RwLock<KeyEntry>,
    retired_key: RwLock<Option<RetiredKeyEntry>>,
    jti_cache: RwLock<BoundedJtiCache>,
}

impl OctopusOidcActorIssuer {
    /// Initializes a new issuer with an ephemeral OS-generated P-256 key pair.
    pub fn new(issuer_url: &str, audience: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        let kid = format!("key-{}-01", now);

        let initial_key = KeyEntry {
            kid,
            signing_key,
            verifying_key,
            created_at: now,
        };

        Self {
            issuer_url: issuer_url.to_string(),
            audience: audience.to_string(),
            token_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
            rotation_grace_secs: DEFAULT_ROTATION_GRACE_SECS,
            max_clock_drift_secs: MAX_CLOCK_DRIFT_SECS,
            current_key: RwLock::new(initial_key),
            retired_key: RwLock::new(None),
            jti_cache: RwLock::new(BoundedJtiCache::new(MAX_JTI_CACHE_ENTRIES)),
        }
    }

    /// Convenience constructor with defaults
    pub fn new_ephemeral(issuer_url: &str) -> Self {
        Self::new(issuer_url, AUDIENCE_DEFAULT)
    }

    /// Returns active key identifier
    pub fn active_key_id(&self) -> String {
        self.current_key
            .read()
            .map(|k| k.kid.clone())
            .unwrap_or_else(|_| "poisoned".to_string())
    }

    /// Performs key rotation: promotes current key to retired key and generates a new current key.
    pub fn rotate_key(&self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.rotate_key_with_time(now)
    }

    /// Performs key rotation with deterministic timestamp.
    pub fn rotate_key_with_time(&self, now: u64) -> String {
        let mut curr_guard = self.current_key.write().expect("current_key write lock poisoned");
        let mut ret_guard = self.retired_key.write().expect("retired_key write lock poisoned");

        let old_key = curr_guard.clone();
        *ret_guard = Some(RetiredKeyEntry {
            key: old_key,
            retired_at: now,
            grace_period_secs: self.rotation_grace_secs,
        });

        let new_signing_key = SigningKey::random(&mut OsRng);
        let new_verifying_key = *new_signing_key.verifying_key();
        let new_kid = format!("key-{}-{:04x}", now, rand::random::<u16>());

        *curr_guard = KeyEntry {
            kid: new_kid.clone(),
            signing_key: new_signing_key,
            verifying_key: new_verifying_key,
            created_at: now,
        };

        new_kid
    }

    /// Exports RFC 7517 EC JWKS containing active current key and unexpired retired key.
    pub fn get_jwks(&self, now: u64) -> JwksDocument {
        let mut keys = Vec::with_capacity(2);

        let curr_guard = self.current_key.read().expect("current_key read lock poisoned");
        keys.push(key_entry_to_jwk(&curr_guard));

        let ret_guard = self.retired_key.read().expect("retired_key read lock poisoned");
        if let Some(ref retired) = *ret_guard {
            if now.saturating_sub(retired.retired_at) <= retired.grace_period_secs {
                keys.push(key_entry_to_jwk(&retired.key));
            }
        }

        JwksDocument { keys }
    }

    /// Exports JwksResponse compatible with cage_substrate.
    pub fn jwks_response(&self) -> JwksResponse {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let jwks_doc = self.get_jwks(now);
        let dto_array: Vec<JwkKeyDto> = jwks_doc
            .keys
            .into_iter()
            .map(|k| JwkKeyDto {
                kty: k.kty,
                crv: k.crv,
                x: k.x,
                kid: k.kid,
                r#use: k.key_use,
                alg: k.alg,
            })
            .collect();
        JwksResponse { keys: dto_array }
    }

    /// Generates OpenID Connect Discovery 1.0 metadata.
    pub fn get_openid_configuration(&self, host_base_url: &str) -> OpenIdConfiguration {
        let base = host_base_url.trim_end_matches('/');
        OpenIdConfiguration {
            issuer: self.issuer_url.clone(),
            jwks_uri: format!("{base}/.well-known/jwks.json"),
            token_endpoint: format!("{base}/oauth/token"),
            response_types_supported: vec!["token".to_string()],
            id_token_signing_alg_values_supported: vec!["ES256".to_string()],
            grant_types_supported: vec!["urn:ietf:params:oauth:grant-type:token-exchange".to_string()],
            subject_types_supported: vec!["public".to_string()],
        }
    }

    /// Standard discovery document using issuer base URL
    pub fn openid_configuration(&self) -> OpenIdConfiguration {
        self.get_openid_configuration(&self.issuer_url)
    }

    /// Mints a workload JWT token for an arm under RFC 7515 Compact Serialization.
    /// Signature is strictly 64-byte IEEE P1363 encoded in Base64url without padding.
    pub fn mint_arm_token(&self, arm_id: &str, epoch: u64, role: &ArmRole) -> Result<String, OidcError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.mint_arm_token_with_time(arm_id, epoch, role, now)
    }

    /// Mints token with explicit timestamp (useful for determinism and edge tests).
    pub fn mint_arm_token_with_time(
        &self,
        arm_id: &str,
        epoch: u64,
        role: &ArmRole,
        now: u64,
    ) -> Result<String, OidcError> {
        let curr_guard = self.current_key.read().expect("current_key read lock poisoned");

        let header = JwsHeader {
            alg: "ES256".to_string(),
            typ: "JWT".to_string(),
            kid: curr_guard.kid.clone(),
        };

        let sub = format!("{}/arm/{}/epoch/{}", self.issuer_url.trim_end_matches('/'), arm_id, epoch);
        let jti = format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>());

        let claims = WorkloadClaims {
            iss: self.issuer_url.clone(),
            sub,
            aud: self.audience.clone(),
            arm_id: arm_id.to_string(),
            epoch,
            role: format!("{role:?}"),
            iat: now,
            nbf: now,
            exp: now + self.token_ttl_secs,
            jti,
        };

        let header_json = serde_json::to_vec(&header).map_err(|e| OidcError::JsonError(e.to_string()))?;
        let payload_json = serde_json::to_vec(&claims).map_err(|e| OidcError::JsonError(e.to_string()))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

        let signing_input = format!("{header_b64}.{payload_b64}");

        // Sign using P-256 ECDSA
        let signature: Signature = curr_guard.signing_key.sign(signing_input.as_bytes());
        let raw_sig = signature.to_bytes(); // Exactly 64 bytes (R || S IEEE P1363)
        assert_eq!(raw_sig.len(), 64, "ECDSA P-256 signature must be 64 bytes");

        let sig_b64 = URL_SAFE_NO_PAD.encode(&raw_sig);

        Ok(format!("{signing_input}.{sig_b64}"))
    }

    /// Verifies a JWS token against current key or retired key within grace period.
    /// Strictly verifies <= 5s clock drift tolerance and bounded JTI replay cache.
    pub fn verify_arm_token(&self, token: &str, now: u64) -> Result<WorkloadClaims, OidcError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(OidcError::InvalidTokenFormat(
                "Token must have exactly 3 parts separated by dots".to_string(),
            ));
        }

        let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| OidcError::InvalidTokenFormat(format!("Header base64 decode failed: {e}")))?;
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| OidcError::InvalidTokenFormat(format!("Payload base64 decode failed: {e}")))?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| OidcError::InvalidTokenFormat(format!("Signature base64 decode failed: {e}")))?;

        let header: JwsHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| OidcError::JsonError(format!("Malformed header JSON: {e}")))?;

        if header.alg != "ES256" {
            return Err(OidcError::UnsupportedAlgorithm(header.alg));
        }

        let signature = parse_ieee_p1363_signature(&sig_bytes)?;
        let signing_input = format!("{header_b64}.{payload_b64}");

        // Locate verifying key
        let verifying_key = self.resolve_verifying_key(&header.kid, now)?;

        // Cryptographic verification
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|e| OidcError::CryptoError(format!("Signature mismatch: {e}")))?;

        // Claims deserialization and validation
        let claims: WorkloadClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| OidcError::JsonError(format!("Malformed claims JSON: {e}")))?;

        // Validate issuer and audience
        if claims.iss != self.issuer_url {
            return Err(OidcError::IssuerMismatch {
                expected: self.issuer_url.clone(),
                actual: claims.iss,
            });
        }
        if claims.aud != self.audience {
            return Err(OidcError::AudienceMismatch {
                expected: self.audience.clone(),
                actual: claims.aud,
            });
        }

        // Validate timestamps with strict <= 5s drift tolerance
        let max_drift = self.max_clock_drift_secs;
        if now.saturating_add(max_drift) < claims.nbf {
            return Err(OidcError::TokenNotYetValid {
                nbf: claims.nbf,
                now,
                max_drift,
            });
        }
        if now > claims.exp.saturating_add(max_drift) {
            return Err(OidcError::TokenExpired {
                exp: claims.exp,
                now,
                max_drift,
            });
        }
        if now.saturating_add(max_drift) < claims.iat {
            return Err(OidcError::TokenIssuedInFuture {
                iat: claims.iat,
                now,
                max_drift,
            });
        }

        // Validate JTI replay
        if let Ok(mut jti_guard) = self.jti_cache.write() {
            if !jti_guard.check_and_insert(&claims.jti) {
                return Err(OidcError::ReplayDetected(claims.jti));
            }
        }

        Ok(claims)
    }

    fn resolve_verifying_key(&self, kid: &str, now: u64) -> Result<VerifyingKey, OidcError> {
        let curr_guard = self.current_key.read().expect("current_key read lock poisoned");
        if curr_guard.kid == kid {
            return Ok(curr_guard.verifying_key);
        }

        let ret_guard = self.retired_key.read().expect("retired_key read lock poisoned");
        if let Some(ref retired) = *ret_guard {
            if retired.key.kid == kid {
                let elapsed = now.saturating_sub(retired.retired_at);
                if elapsed <= retired.grace_period_secs {
                    return Ok(retired.key.verifying_key);
                } else {
                    return Err(OidcError::KeyRetiredExpired {
                        kid: kid.to_string(),
                        retired_at: retired.retired_at,
                        grace_secs: retired.grace_period_secs,
                    });
                }
            }
        }

        Err(OidcError::KeyNotFound {
            kid: kid.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mint_and_verify_token_roundtrip() {
        let issuer = OctopusOidcActorIssuer::new("https://agentoctopus.local", "agentmesh.local");
        let now = 10_000;
        let token = issuer
            .mint_arm_token_with_time("arm_calc", 1, &ArmRole::UntrustedDocIngest, now)
            .expect("Minting failed");

        let claims = issuer
            .verify_arm_token(&token, now)
            .expect("Verification failed");

        assert_eq!(claims.arm_id, "arm_calc");
        assert_eq!(claims.epoch, 1);
        assert_eq!(claims.role, "UntrustedDocIngest");
        assert_eq!(claims.iss, "https://agentoctopus.local");
        assert_eq!(claims.aud, "agentmesh.local");
        assert_eq!(claims.sub, "https://agentoctopus.local/arm/arm_calc/epoch/1");
    }

    #[test]
    fn test_ieee_p1363_signature_length() {
        let issuer = OctopusOidcActorIssuer::new_ephemeral("https://agentoctopus.local");
        let token = issuer
            .mint_arm_token("arm_calc", 0, &ArmRole::CedarPolicyEvaluation)
            .unwrap();

        let sig_part = token.split('.').nth(2).unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(sig_part).unwrap();
        assert_eq!(decoded.len(), 64, "Raw signature must be exactly 64 bytes");
    }

    #[test]
    fn test_der_signature_rejected() {
        // Construct synthetic DER header: 0x30 ...
        let mut fake_der = vec![0x30, 0x44, 0x02, 0x20];
        fake_der.extend(vec![0xAA; 32]);
        fake_der.extend(vec![0x02, 0x20]);
        fake_der.extend(vec![0xBB; 32]);

        let res = parse_ieee_p1363_signature(&fake_der);
        assert_eq!(res, Err(OidcError::DerSignatureForbidden));
    }

    #[test]
    fn test_key_rotation_grace_period() {
        let issuer = OctopusOidcActorIssuer::new("https://agentoctopus.local", "agentmesh.local");
        let t0 = 10_000;
        let token_old = issuer
            .mint_arm_token_with_time("arm_calc", 1, &ArmRole::UntrustedDocIngest, t0)
            .unwrap();

        // Rotate key at t0
        let new_kid = issuer.rotate_key_with_time(t0);
        assert_ne!(new_kid, issuer.retired_key.read().unwrap().as_ref().unwrap().key.kid);

        // Verification within grace period (t0 + 100 <= t0 + 300) succeeds
        let claims = issuer.verify_arm_token(&token_old, t0 + 100);
        assert!(claims.is_ok());

        // Verification after grace period (t0 + 350 > t0 + 300) fails
        let res = issuer.verify_arm_token(&token_old, t0 + 350);
        assert!(matches!(res, Err(OidcError::KeyRetiredExpired { .. })));
    }

    #[test]
    fn test_clock_drift_enforcement() {
        let issuer = OctopusOidcActorIssuer::new("https://agentoctopus.local", "agentmesh.local");
        let t0 = 10_000;
        let token = issuer
            .mint_arm_token_with_time("arm_calc", 1, &ArmRole::UntrustedDocIngest, t0)
            .unwrap();
        // exp = 10_300

        // 10_304 is 4s expired: within 5s drift tolerance -> Ok
        assert!(issuer.verify_arm_token(&token, 10_304).is_ok());

        // 10_306 is 6s expired: exceeds 5s drift tolerance -> TokenExpired
        let exp_res = issuer.verify_arm_token(&token, 10_306);
        assert!(matches!(exp_res, Err(OidcError::TokenExpired { .. })));

        // 9_994 is 6s before nbf (10_000): exceeds 5s drift -> TokenNotYetValid
        let nbf_res = issuer.verify_arm_token(&token, 9_994);
        assert!(matches!(nbf_res, Err(OidcError::TokenNotYetValid { .. })));
    }

    #[test]
    fn test_jwks_serialization() {
        let issuer = OctopusOidcActorIssuer::new("https://agentoctopus.local", "agentmesh.local");
        let doc = issuer.get_jwks(1000);
        assert_eq!(doc.keys.len(), 1);
        let k = &doc.keys[0];
        assert_eq!(k.kty, "EC");
        assert_eq!(k.crv, "P-256");
        assert_eq!(k.key_use, "sig");
        assert_eq!(k.alg, "ES256");
        assert!(!k.x.is_empty());
        assert!(!k.y.is_empty());
    }

    #[test]
    fn test_openid_discovery_metadata() {
        let issuer = OctopusOidcActorIssuer::new("https://agentoctopus.local", "agentmesh.local");
        let meta = issuer.get_openid_configuration("http://127.0.0.1:8080");
        assert_eq!(meta.issuer, "https://agentoctopus.local");
        assert_eq!(meta.jwks_uri, "http://127.0.0.1:8080/.well-known/jwks.json");
        assert_eq!(meta.token_endpoint, "http://127.0.0.1:8080/oauth/token");
        assert!(meta.id_token_signing_alg_values_supported.contains(&"ES256".to_string()));
    }

    #[test]
    fn test_replay_detection() {
        let issuer = OctopusOidcActorIssuer::new("https://agentoctopus.local", "agentmesh.local");
        let now = 10_000;
        let token = issuer
            .mint_arm_token_with_time("arm_calc", 1, &ArmRole::UntrustedDocIngest, now)
            .unwrap();

        // First verification succeeds
        assert!(issuer.verify_arm_token(&token, now).is_ok());

        // Second verification of identical token (same jti) fails with ReplayDetected
        let res2 = issuer.verify_arm_token(&token, now);
        assert!(matches!(res2, Err(OidcError::ReplayDetected(_))));
    }
}
