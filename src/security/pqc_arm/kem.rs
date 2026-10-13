use crate::security::pqc_arm::types::PqcAlgorithm;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, Kem, MlKem1024, MlKem512, MlKem768};
use sha2::{Digest, Sha256};
use std::time::Instant;

pub struct PqcKemEngine;

impl PqcKemEngine {
    /// Generates a post-quantum keypair for the specified KEM algorithm.
    /// Returns (secret_key_seed_hex, public_key_hex).
    pub fn generate_keypair(algorithm: PqcAlgorithm) -> Result<(String, String), String> {
        match algorithm {
            PqcAlgorithm::MlKem512 => {
                let (dk, ek) = MlKem512::generate_keypair();
                Ok((hex::encode(dk.to_bytes().as_slice()), hex::encode(ek.to_bytes().as_slice())))
            }
            PqcAlgorithm::MlKem768 | PqcAlgorithm::HybridX25519MlKem768 => {
                let (dk, ek) = MlKem768::generate_keypair();
                Ok((hex::encode(dk.to_bytes().as_slice()), hex::encode(ek.to_bytes().as_slice())))
            }
            PqcAlgorithm::MlKem1024 => {
                let (dk, ek) = MlKem1024::generate_keypair();
                Ok((hex::encode(dk.to_bytes().as_slice()), hex::encode(ek.to_bytes().as_slice())))
            }
            _ => Err(format!("Algorithm {:?} is not a Key Encapsulation Mechanism", algorithm)),
        }
    }

    /// Encapsulates a shared secret using the recipient's public encapsulation key.
    /// Returns (ciphertext_hex, shared_secret_hex, duration_micros).
    pub fn encapsulate(
        algorithm: PqcAlgorithm,
        public_key_hex: &str,
    ) -> Result<(String, String, u128), String> {
        let start = Instant::now();
        let pk_bytes = hex::decode(public_key_hex.trim())
            .map_err(|e| format!("Invalid public key hex: {}", e))?;

        let (ct_hex, ss_hex) = match algorithm {
            PqcAlgorithm::MlKem512 => {
                if pk_bytes.len() != 800 {
                    return Err(format!("Invalid ML-KEM-512 public key length: expected 800 bytes, got {}", pk_bytes.len()));
                }
                let key_array = Array::try_from(pk_bytes.as_slice())
                    .map_err(|_| "Failed to convert ML-KEM-512 public key to Array")?;
                let ek = EncapsulationKey::<MlKem512>::new(&key_array)
                    .map_err(|_| "Failed to decode ML-KEM-512 public key")?;
                let (ct, ss) = ek.encapsulate();
                (hex::encode(ct.as_slice()), hex::encode(ss.as_slice()))
            }
            PqcAlgorithm::MlKem768 | PqcAlgorithm::HybridX25519MlKem768 => {
                if pk_bytes.len() != 1184 {
                    return Err(format!("Invalid ML-KEM-768 public key length: expected 1184 bytes, got {}", pk_bytes.len()));
                }
                let key_array = Array::try_from(pk_bytes.as_slice())
                    .map_err(|_| "Failed to convert ML-KEM-768 public key to Array")?;
                let ek = EncapsulationKey::<MlKem768>::new(&key_array)
                    .map_err(|_| "Failed to decode ML-KEM-768 public key")?;
                let (ct, ss) = ek.encapsulate();
                (hex::encode(ct.as_slice()), hex::encode(ss.as_slice()))
            }
            PqcAlgorithm::MlKem1024 => {
                if pk_bytes.len() != 1568 {
                    return Err(format!("Invalid ML-KEM-1024 public key length: expected 1568 bytes, got {}", pk_bytes.len()));
                }
                let key_array = Array::try_from(pk_bytes.as_slice())
                    .map_err(|_| "Failed to convert ML-KEM-1024 public key to Array")?;
                let ek = EncapsulationKey::<MlKem1024>::new(&key_array)
                    .map_err(|_| "Failed to decode ML-KEM-1024 public key")?;
                let (ct, ss) = ek.encapsulate();
                (hex::encode(ct.as_slice()), hex::encode(ss.as_slice()))
            }
            _ => return Err(format!("Algorithm {:?} is not a KEM", algorithm)),
        };

        let elapsed = start.elapsed().as_micros();
        Ok((ct_hex, ss_hex, elapsed))
    }

    /// Decapsulates a shared secret using the recipient's secret decapsulation key.
    /// Returns (shared_secret_hex, duration_micros).
    pub fn decapsulate(
        algorithm: PqcAlgorithm,
        secret_key_hex: &str,
        ciphertext_hex: &str,
    ) -> Result<(String, u128), String> {
        let start = Instant::now();
        let sk_bytes = hex::decode(secret_key_hex.trim())
            .map_err(|e| format!("Invalid secret key hex: {}", e))?;
        let ct_bytes = hex::decode(ciphertext_hex.trim())
            .map_err(|e| format!("Invalid ciphertext hex: {}", e))?;

        if sk_bytes.len() != 64 {
            return Err(format!("Invalid ML-KEM secret seed length: expected 64 bytes, got {}", sk_bytes.len()));
        }
        let seed = Array::try_from(sk_bytes.as_slice())
            .map_err(|_| "Failed to convert ML-KEM secret seed to Array")?;

        let ss_hex = match algorithm {
            PqcAlgorithm::MlKem512 => {
                if ct_bytes.len() != 768 {
                    return Err(format!("Invalid ML-KEM-512 ciphertext length: expected 768 bytes, got {}", ct_bytes.len()));
                }
                let dk = DecapsulationKey::<MlKem512>::from_seed(seed);
                let ct = Array::try_from(ct_bytes.as_slice())
                    .map_err(|_| "Failed to convert ML-KEM-512 ciphertext to Array")?;
                let ss = dk.decapsulate(&ct);
                hex::encode(ss.as_slice())
            }
            PqcAlgorithm::MlKem768 | PqcAlgorithm::HybridX25519MlKem768 => {
                if ct_bytes.len() != 1088 {
                    return Err(format!("Invalid ML-KEM-768 ciphertext length: expected 1088 bytes, got {}", ct_bytes.len()));
                }
                let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
                let ct = Array::try_from(ct_bytes.as_slice())
                    .map_err(|_| "Failed to convert ML-KEM-768 ciphertext to Array")?;
                let ss = dk.decapsulate(&ct);
                hex::encode(ss.as_slice())
            }
            PqcAlgorithm::MlKem1024 => {
                if ct_bytes.len() != 1568 {
                    return Err(format!("Invalid ML-KEM-1024 ciphertext length: expected 1568 bytes, got {}", ct_bytes.len()));
                }
                let dk = DecapsulationKey::<MlKem1024>::from_seed(seed);
                let ct = Array::try_from(ct_bytes.as_slice())
                    .map_err(|_| "Failed to convert ML-KEM-1024 ciphertext to Array")?;
                let ss = dk.decapsulate(&ct);
                hex::encode(ss.as_slice())
            }
            _ => return Err(format!("Algorithm {:?} is not a KEM", algorithm)),
        };

        let elapsed = start.elapsed().as_micros();
        Ok((ss_hex, elapsed))
    }

    /// Hybrid Key Derivation: Combines classical shared secret (e.g. X25519 or ECDH)
    /// with Post-Quantum ML-KEM shared secret via SHA-256 HKDF-Extract/Expand (RFC 9180 §4.1).
    pub fn combine_hybrid_secrets(classical_secret: &[u8], pqc_secret: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"OCTOPUS-HYBRID-PQC-V1-DUAL-EXTRACT");
        hasher.update(classical_secret);
        hasher.update(pqc_secret);
        let prk = hasher.finalize();

        let mut expander = Sha256::new();
        expander.update(&prk);
        expander.update(b"OCTOPUS-HYBRID-PQC-EXPAND-SHARED-KEY");
        expander.update(&[1u8]);
        let okm: [u8; 32] = expander.finalize().into();
        okm
    }
}
