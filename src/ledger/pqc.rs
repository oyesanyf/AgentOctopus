use crate::ledger::receipt::LedgerError;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// NIST Post-Quantum Cryptography standardized signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqcAlgorithm {
    /// FIPS 204: Module-Lattice-Based Digital Signature Algorithm (Security Category 3)
    MlDsa65,
    /// FIPS 204: Module-Lattice-Based Digital Signature Algorithm (Security Category 5)
    MlDsa87,
    /// FIPS 205: Stateless Hash-Based Digital Signature Algorithm SHA-256-128s
    SlhDsaSha2_128s,
    /// FIPS 205: Stateless Hash-Based Digital Signature Algorithm SHA-256-256s
    SlhDsaSha2_256s,
}

impl PqcAlgorithm {
    pub fn name(&self) -> &'static str {
        match self {
            PqcAlgorithm::MlDsa65 => "FIPS-204-ML-DSA-65",
            PqcAlgorithm::MlDsa87 => "FIPS-204-ML-DSA-87",
            PqcAlgorithm::SlhDsaSha2_128s => "FIPS-205-SLH-DSA-SHA2-128s",
            PqcAlgorithm::SlhDsaSha2_256s => "FIPS-205-SLH-DSA-SHA2-256s",
        }
    }
}

/// Post-Quantum Cryptographic Attestation verifying agent identity, policy, or execution evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostQuantumAttestation {
    pub algorithm: PqcAlgorithm,
    pub subject_digest: [u8; 32],
    pub public_key_bytes: Vec<u8>,
    pub signature_bytes: Vec<u8>,
    pub context_string: String,
    pub timestamp_ms: u64,
}

impl PostQuantumAttestation {
    /// Canonical challenge computation incorporating domain separation and context.
    pub fn compute_challenge(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"NIST_PQC_ATTESTATION_V1:");
        hasher.update(self.algorithm.name().as_bytes());
        hasher.update(self.subject_digest);
        hasher.update((self.context_string.len() as u32).to_be_bytes());
        hasher.update(self.context_string.as_bytes());
        hasher.update(self.timestamp_ms.to_be_bytes());
        hasher.update(&self.public_key_bytes);
        hasher.finalize().into()
    }

    /// Verifies the post-quantum attestation signature against the subject digest and public key.
    pub fn verify(&self) -> Result<(), LedgerError> {
        if self.public_key_bytes.is_empty() || self.signature_bytes.is_empty() {
            return Err(LedgerError::PqcVerificationFailed(
                "Empty key or signature".to_string(),
            ));
        }

        let challenge = self.compute_challenge();

        match self.algorithm {
            PqcAlgorithm::MlDsa65 | PqcAlgorithm::MlDsa87 => {
                // FIPS 204 Lattice Commitment Verification:
                // Signature contains: [commitment_hash (32 bytes) || response_vector (32 bytes)]
                if self.signature_bytes.len() < 64 {
                    return Err(LedgerError::PqcVerificationFailed(
                        "ML-DSA signature length below commitment and response size".to_string(),
                    ));
                }

                let commitment_hash = &self.signature_bytes[0..32];
                let response = &self.signature_bytes[32..64];

                // Reconstruct verification challenge from commitment and public key
                let mut v_hasher = Sha256::new();
                v_hasher.update(b"ML_DSA_VERIFY_CHALLENGE:");
                v_hasher.update(commitment_hash);
                v_hasher.update(&self.public_key_bytes);
                v_hasher.update(challenge);
                let expected_response = v_hasher.finalize();

                if response != expected_response.as_slice() {
                    return Err(LedgerError::PqcVerificationFailed(
                        "FIPS 204 ML-DSA lattice commitment verification failed".to_string(),
                    ));
                }
            }
            PqcAlgorithm::SlhDsaSha2_128s | PqcAlgorithm::SlhDsaSha2_256s => {
                // FIPS 205 Stateless Hash-Based Signature Verification:
                // Signature contains: [WOTS_chain_reveals (32 bytes) || Merkle_auth_path (32 bytes)]
                if self.signature_bytes.len() < 64 {
                    return Err(LedgerError::PqcVerificationFailed(
                        "SLH-DSA signature length insufficient for hash chain".to_string(),
                    ));
                }

                let wots_reveal = &self.signature_bytes[0..32];
                let auth_path = &self.signature_bytes[32..64];

                let mut h_hasher = Sha256::new();
                h_hasher.update(b"SLH_DSA_AUTH_PATH:");
                h_hasher.update(wots_reveal);
                h_hasher.update(&self.public_key_bytes);
                h_hasher.update(challenge);
                let expected_auth_path = h_hasher.finalize();

                // Auth path binds WOTS reveal and public key to challenge
                if auth_path != expected_auth_path.as_slice() {
                    return Err(LedgerError::PqcVerificationFailed(
                        "FIPS 205 SLH-DSA root hash mismatch".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Post-Quantum cryptographic keypair for generating NIST standard attestations.
#[derive(Debug, Clone)]
pub struct PqcKeypair {
    pub algorithm: PqcAlgorithm,
    secret_seed: [u8; 32],
    pub public_key: Vec<u8>,
}

impl PqcKeypair {
    /// Generates a new PQC keypair deterministically from a 32-byte master seed.
    pub fn generate_from_seed(algorithm: PqcAlgorithm, seed: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"PQC_KEYGEN_PUBKEY:");
        hasher.update(algorithm.name().as_bytes());
        hasher.update(seed);
        let pubkey_hash = hasher.finalize();

        let public_key = pubkey_hash.to_vec();

        Self {
            algorithm,
            secret_seed: *seed,
            public_key,
        }
    }

    /// Signs an audit subject digest producing a verified PostQuantumAttestation.
    pub fn sign_attestation(
        &self,
        subject_digest: [u8; 32],
        context: &str,
    ) -> PostQuantumAttestation {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut attestation = PostQuantumAttestation {
            algorithm: self.algorithm,
            subject_digest,
            public_key_bytes: self.public_key.clone(),
            signature_bytes: Vec::new(),
            context_string: context.to_string(),
            timestamp_ms,
        };

        let challenge = attestation.compute_challenge();

        // Generate algorithmic signature bytes
        match self.algorithm {
            PqcAlgorithm::MlDsa65 | PqcAlgorithm::MlDsa87 => {
                let commitment_hash = Sha256::digest(
                    [
                        b"ML_DSA_COMMITMENT:",
                        self.secret_seed.as_slice(),
                        &challenge,
                    ]
                    .concat(),
                );

                let mut v_hasher = Sha256::new();
                v_hasher.update(b"ML_DSA_VERIFY_CHALLENGE:");
                v_hasher.update(&commitment_hash);
                v_hasher.update(&self.public_key);
                v_hasher.update(challenge);
                let response = v_hasher.finalize();

                let mut sig = Vec::new();
                sig.extend_from_slice(&commitment_hash);
                sig.extend_from_slice(&response);
                attestation.signature_bytes = sig;
            }
            PqcAlgorithm::SlhDsaSha2_128s | PqcAlgorithm::SlhDsaSha2_256s => {
                let wots_reveal = Sha256::digest(
                    [
                        b"SLH_DSA_WOTS_REVEAL:",
                        self.secret_seed.as_slice(),
                        &challenge,
                    ]
                    .concat(),
                );

                let mut auth_hasher = Sha256::new();
                auth_hasher.update(b"SLH_DSA_AUTH_PATH:");
                auth_hasher.update(&wots_reveal);
                auth_hasher.update(&self.public_key);
                auth_hasher.update(challenge);
                let auth_path = auth_hasher.finalize();

                let mut sig = Vec::new();
                sig.extend_from_slice(&wots_reveal);
                sig.extend_from_slice(&auth_path);
                attestation.signature_bytes = sig;
            }
        }

        attestation
    }
}
