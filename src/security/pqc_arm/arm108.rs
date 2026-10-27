use crate::containment_ring::{ArmContainmentRing, ArmRingRegistry};
use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::security::pqc_arm::cbom::CbomScanner;
use crate::security::pqc_arm::dsa::PqcDsaEngine;
use crate::security::pqc_arm::kem::PqcKemEngine;
use crate::security::pqc_arm::types::{
    CbomReport, PqcAlgorithm, PqcArmStatus, PqcDecapsulationResult, PqcEncapsulationResult,
    PqcKeypairInfo, PqcSignatureResult,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Arm #108: Post-Quantum Cryptography & Attestation Arm.
/// Enforces NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) across the autonomous swarm.
pub struct PostQuantumArm {
    pub arm_id: usize,
    pub role: ArmRole,
    arm_ring: Option<Arc<ArmContainmentRing>>,
    arm_registry: Option<Arc<ArmRingRegistry>>,
    // Private decapsulation keys stored in memory (key_id -> (PqcAlgorithm, secret_key_seed_hex))
    decapsulation_keys: Arc<RwLock<HashMap<String, (PqcAlgorithm, String)>>>,
    // Active signing keys (key_id -> (PqcAlgorithm, secret_key_seed_hex))
    signing_keys: Arc<RwLock<HashMap<String, (PqcAlgorithm, String)>>>,
    // Public key info cache
    public_key_registry: Arc<RwLock<HashMap<String, PqcKeypairInfo>>>,
    // Active default keypair ID for audit sealing
    active_signing_key_id: Arc<RwLock<Option<String>>>,
    // Metrics
    total_keypairs: AtomicUsize,
    total_encaps: AtomicUsize,
    total_decaps: AtomicUsize,
    total_sigs: AtomicUsize,
}

impl PostQuantumArm {
    /// Creates a new Arm #108 instance bound to an authoritative containment ring.
    pub fn new(arm_ring: Arc<ArmContainmentRing>) -> Self {
        Self {
            arm_id: 108,
            role: ArmRole::PostQuantumAttestation,
            arm_ring: Some(arm_ring),
            arm_registry: None,
            decapsulation_keys: Arc::new(RwLock::new(HashMap::new())),
            signing_keys: Arc::new(RwLock::new(HashMap::new())),
            public_key_registry: Arc::new(RwLock::new(HashMap::new())),
            active_signing_key_id: Arc::new(RwLock::new(None)),
            total_keypairs: AtomicUsize::new(0),
            total_encaps: AtomicUsize::new(0),
            total_decaps: AtomicUsize::new(0),
            total_sigs: AtomicUsize::new(0),
        }
    }

    /// Creates a new Arm #108 instance bound to the fleet containment ring registry.
    pub fn with_registry(arm_registry: Arc<ArmRingRegistry>) -> Self {
        Self {
            arm_id: 108,
            role: ArmRole::PostQuantumAttestation,
            arm_ring: None,
            arm_registry: Some(arm_registry),
            decapsulation_keys: Arc::new(RwLock::new(HashMap::new())),
            signing_keys: Arc::new(RwLock::new(HashMap::new())),
            public_key_registry: Arc::new(RwLock::new(HashMap::new())),
            active_signing_key_id: Arc::new(RwLock::new(None)),
            total_keypairs: AtomicUsize::new(0),
            total_encaps: AtomicUsize::new(0),
            total_decaps: AtomicUsize::new(0),
            total_sigs: AtomicUsize::new(0),
        }
    }

    /// Resolves the active containment ring for Arm #108.
    pub fn get_ring(&self) -> Result<Arc<ArmContainmentRing>, OctopusSecurityError> {
        if let Some(r) = &self.arm_ring {
            return Ok(Arc::clone(r));
        }
        if let Some(reg) = &self.arm_registry {
            if let Some(r) = reg.get_ring_sync(self.arm_id) {
                return Ok(r);
            }
        }
        Err(OctopusSecurityError::LimbKilled)
    }

    /// Initializes default post-quantum signing and KEM keypairs on startup.
    pub async fn initialize_default_keys(&self) -> Result<(), OctopusSecurityError> {
        self.check_containment()?;

        // 1. Generate default ML-KEM-768 keypair for swarm IPC
        let kem_info = self.generate_keypair(PqcAlgorithm::MlKem768).await?;
        eprintln!(
            "[PQC-ARM] Initialized default swarm ML-KEM-768 keypair: {}",
            kem_info.key_id
        );

        // 2. Generate default ML-DSA-65 keypair for audit trail sealing
        let dsa_info = self.generate_keypair(PqcAlgorithm::MlDsa65).await?;
        {
            let mut active = self.active_signing_key_id.write().await;
            *active = Some(dsa_info.key_id.clone());
        }
        eprintln!(
            "[PQC-ARM] Initialized default swarm ML-DSA-65 signing keypair: {}",
            dsa_info.key_id
        );

        Ok(())
    }

    /// Fail-closed check: Ensures the arm's containment ring is active and uncompromised.
    pub fn check_containment(&self) -> Result<(), OctopusSecurityError> {
        let ring = self.get_ring()?;
        if ring.is_severed() {
            return Err(OctopusSecurityError::LimbKilled);
        }
        Ok(())
    }

    /// Generates a new Post-Quantum keypair (ML-KEM or ML-DSA).
    pub async fn generate_keypair(
        &self,
        algorithm: PqcAlgorithm,
    ) -> Result<PqcKeypairInfo, OctopusSecurityError> {
        self.check_containment()?;

        let (sk_hex, pk_hex) = if algorithm.is_kem() {
            PqcKemEngine::generate_keypair(algorithm)
                .map_err(|e| OctopusSecurityError::DeterministicLayerViolation(e))?
        } else {
            PqcDsaEngine::generate_keypair(algorithm)
                .map_err(|e| OctopusSecurityError::DeterministicLayerViolation(e))?
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let epoch = self
            .get_ring()
            .map(|r| r.generation.load(Ordering::SeqCst))
            .unwrap_or(1);
        let key_id = format!(
            "pqc-{}-{}",
            algorithm.name().to_lowercase().replace(' ', "-"),
            &pk_hex[..16]
        );

        let pk_bytes_len = pk_hex.len() / 2;
        let info = PqcKeypairInfo {
            key_id: key_id.clone(),
            algorithm,
            public_key_hex: pk_hex,
            public_key_bytes_len: pk_bytes_len,
            created_at_secs: now,
            epoch_generation: epoch,
        };

        if algorithm.is_kem() {
            let mut dks = self.decapsulation_keys.write().await;
            dks.insert(key_id.clone(), (algorithm, sk_hex));
        } else {
            let mut sks = self.signing_keys.write().await;
            sks.insert(key_id.clone(), (algorithm, sk_hex));
            let mut active = self.active_signing_key_id.write().await;
            *active = Some(key_id.clone());
        }

        {
            let mut registry = self.public_key_registry.write().await;
            registry.insert(key_id.clone(), info.clone());
        }

        self.total_keypairs.fetch_add(1, Ordering::SeqCst);
        Ok(info)
    }

    /// Encapsulates a shared secret using a target public key.
    pub async fn encapsulate(
        &self,
        algorithm: PqcAlgorithm,
        public_key_hex: &str,
    ) -> Result<PqcEncapsulationResult, OctopusSecurityError> {
        self.check_containment()?;

        let (ct_hex, ss_hex, elapsed) = PqcKemEngine::encapsulate(algorithm, public_key_hex)
            .map_err(|e| OctopusSecurityError::DeterministicLayerViolation(e))?;

        let ct_bytes_len = ct_hex.len() / 2;
        let ss_bytes_len = ss_hex.len() / 2;
        let key_id = format!(
            "encap-{}",
            &public_key_hex[..std::cmp::min(16, public_key_hex.len())]
        );

        self.total_encaps.fetch_add(1, Ordering::SeqCst);
        Ok(PqcEncapsulationResult {
            key_id,
            algorithm,
            ciphertext_hex: ct_hex,
            ciphertext_bytes_len: ct_bytes_len,
            shared_secret_hex: ss_hex,
            shared_secret_bytes_len: ss_bytes_len,
            execution_micros: elapsed,
        })
    }

    /// Decapsulates a shared secret using a stored secret key by `key_id`.
    pub async fn decapsulate(
        &self,
        key_id: &str,
        ciphertext_hex: &str,
    ) -> Result<PqcDecapsulationResult, OctopusSecurityError> {
        self.check_containment()?;

        let (algo, sk_hex) = {
            let dks = self.decapsulation_keys.read().await;
            dks.get(key_id).cloned().ok_or_else(|| {
                OctopusSecurityError::CapabilityDenied(format!(
                    "Key ID '{}' not found in Arm 108 decapsulation cache",
                    key_id
                ))
            })?
        };

        let (ss_hex, elapsed) = PqcKemEngine::decapsulate(algo, &sk_hex, ciphertext_hex)
            .map_err(|e| OctopusSecurityError::DeterministicLayerViolation(e))?;

        self.total_decaps.fetch_add(1, Ordering::SeqCst);
        Ok(PqcDecapsulationResult {
            key_id: key_id.to_string(),
            shared_secret_hex: ss_hex,
            success: true,
            execution_micros: elapsed,
        })
    }

    /// Signs an audit block or critical swarm payload with the active ML-DSA-65 signing key.
    pub async fn sign_audit_block(
        &self,
        message: &[u8],
    ) -> Result<PqcSignatureResult, OctopusSecurityError> {
        self.sign_audit_block_with_key(None, message).await
    }

    /// Signs an audit block or critical swarm payload with a specific or active ML-DSA signing key.
    pub async fn sign_audit_block_with_key(
        &self,
        target_key_id: Option<&str>,
        message: &[u8],
    ) -> Result<PqcSignatureResult, OctopusSecurityError> {
        self.check_containment()?;

        let (key_id, algo, sk_hex) = {
            let active_guard = self.active_signing_key_id.read().await;
            let resolved_id = target_key_id
                .or_else(|| active_guard.as_deref())
                .ok_or_else(|| {
                    OctopusSecurityError::CapabilityDenied(
                        "No active ML-DSA signing key configured".to_string(),
                    )
                })?;
            let sks = self.signing_keys.read().await;
            let (algo, sk) = sks.get(resolved_id).cloned().ok_or_else(|| {
                OctopusSecurityError::CapabilityDenied(format!(
                    "Signing key '{}' missing from cache",
                    resolved_id
                ))
            })?;
            (resolved_id.to_string(), algo, sk)
        };

        let (sig_hex, elapsed) = PqcDsaEngine::sign(algo, &sk_hex, message)
            .map_err(|e| OctopusSecurityError::DeterministicLayerViolation(e))?;

        let mut hasher = Sha256::new();
        hasher.update(message);
        let digest_hex = hex::encode(hasher.finalize());
        let sig_len = sig_hex.len() / 2;

        self.total_sigs.fetch_add(1, Ordering::SeqCst);
        Ok(PqcSignatureResult {
            key_id,
            algorithm: algo,
            message_digest_sha256: digest_hex,
            signature_hex: sig_hex,
            signature_bytes_len: sig_len,
            verified: true,
            execution_micros: elapsed,
        })
    }

    /// Verifies an ML-DSA post-quantum signature against a public key.
    pub fn verify_signature(
        &self,
        algorithm: PqcAlgorithm,
        public_verifying_key_hex: &str,
        message: &[u8],
        signature_hex: &str,
    ) -> Result<bool, OctopusSecurityError> {
        self.check_containment()?;
        let (valid, _) =
            PqcDsaEngine::verify(algorithm, public_verifying_key_hex, message, signature_hex)
                .map_err(|e| OctopusSecurityError::DeterministicLayerViolation(e))?;
        Ok(valid)
    }

    /// Scans the swarm for quantum cryptographic posture and returns a CBOM report.
    pub fn run_cbom_audit(&self) -> CbomReport {
        CbomScanner::scan_swarm_cryptography()
    }

    /// Queries the live status and metrics of Arm #108.
    pub async fn get_status(&self) -> PqcArmStatus {
        let is_severed = self.get_ring().map(|r| r.is_severed()).unwrap_or(false);
        let epoch = self
            .get_ring()
            .map(|r| r.generation.load(Ordering::SeqCst))
            .unwrap_or(1);
        let active_keys = {
            let reg = self.public_key_registry.read().await;
            reg.values().cloned().collect::<Vec<_>>()
        };
        let cbom = self.run_cbom_audit();

        PqcArmStatus {
            arm_id: self.arm_id,
            role: "PostQuantumAttestation".to_string(),
            status: if is_severed {
                "SEVERED_CONTAINED".to_string()
            } else {
                "OPERATIONAL_QUANTUM_RESISTANT".to_string()
            },
            is_contained: true,
            is_severed,
            active_generation: epoch,
            active_algorithm: "NIST FIPS 203 (ML-KEM-768) + FIPS 204 (ML-DSA-65)".to_string(),
            total_keypairs_generated: self.total_keypairs.load(Ordering::SeqCst),
            total_encapsulations: self.total_encaps.load(Ordering::SeqCst),
            total_decapsulations: self.total_decaps.load(Ordering::SeqCst),
            total_signatures_verified: self.total_sigs.load(Ordering::SeqCst),
            quantum_readiness_score: cbom.quantum_readiness_score,
            active_keypairs: active_keys,
            latest_cbom_summary: Some(cbom),
        }
    }
}
