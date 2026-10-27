use crate::security::pqc_arm::types::PqcAlgorithm;
use ml_dsa::signature::{SignatureEncoding, Signer, Verifier};
use ml_dsa::{
    Generate, KeyExport, Keypair, MlDsa44, MlDsa65, MlDsa87, Signature, SigningKey, VerifyingKey,
};
use std::time::Instant;

pub struct PqcDsaEngine;

impl PqcDsaEngine {
    /// Generates a post-quantum digital signature keypair for the specified DSA algorithm.
    /// Returns (secret_key_seed_hex, public_verifying_key_hex).
    pub fn generate_keypair(algorithm: PqcAlgorithm) -> Result<(String, String), String> {
        match algorithm {
            PqcAlgorithm::MlDsa44 => {
                let sk = SigningKey::<MlDsa44>::generate();
                let vk = sk.verifying_key();
                Ok((
                    hex::encode(sk.to_seed().as_slice()),
                    hex::encode(vk.to_bytes().as_slice()),
                ))
            }
            PqcAlgorithm::MlDsa65 => {
                let sk = SigningKey::<MlDsa65>::generate();
                let vk = sk.verifying_key();
                Ok((
                    hex::encode(sk.to_seed().as_slice()),
                    hex::encode(vk.to_bytes().as_slice()),
                ))
            }
            PqcAlgorithm::MlDsa87 => {
                let sk = SigningKey::<MlDsa87>::generate();
                let vk = sk.verifying_key();
                Ok((
                    hex::encode(sk.to_seed().as_slice()),
                    hex::encode(vk.to_bytes().as_slice()),
                ))
            }
            _ => Err(format!(
                "Algorithm {:?} is not a Digital Signature Algorithm",
                algorithm
            )),
        }
    }

    /// Signs a message using a post-quantum signing key.
    /// Returns (signature_hex, duration_micros).
    pub fn sign(
        algorithm: PqcAlgorithm,
        secret_key_seed_hex: &str,
        message: &[u8],
    ) -> Result<(String, u128), String> {
        let start = Instant::now();
        let seed_bytes = hex::decode(secret_key_seed_hex.trim())
            .map_err(|e| format!("Invalid secret key seed hex: {}", e))?;

        let sig_hex = match algorithm {
            PqcAlgorithm::MlDsa44 => {
                let seed = (&seed_bytes[..])
                    .try_into()
                    .map_err(|_| "Invalid ML-DSA-44 seed length (expected 32 bytes)")?;
                let sk = SigningKey::<MlDsa44>::from_seed(seed);
                let sig = sk.sign(message);
                hex::encode(sig.to_bytes().as_slice())
            }
            PqcAlgorithm::MlDsa65 => {
                let seed = (&seed_bytes[..])
                    .try_into()
                    .map_err(|_| "Invalid ML-DSA-65 seed length (expected 32 bytes)")?;
                let sk = SigningKey::<MlDsa65>::from_seed(seed);
                let sig = sk.sign(message);
                hex::encode(sig.to_bytes().as_slice())
            }
            PqcAlgorithm::MlDsa87 => {
                let seed = (&seed_bytes[..])
                    .try_into()
                    .map_err(|_| "Invalid ML-DSA-87 seed length (expected 32 bytes)")?;
                let sk = SigningKey::<MlDsa87>::from_seed(seed);
                let sig = sk.sign(message);
                hex::encode(sig.to_bytes().as_slice())
            }
            _ => return Err(format!("Algorithm {:?} is not a DSA", algorithm)),
        };

        let elapsed = start.elapsed().as_micros();
        Ok((sig_hex, elapsed))
    }

    /// Verifies a post-quantum signature against a message and public verifying key.
    /// Returns (is_valid, duration_micros).
    pub fn verify(
        algorithm: PqcAlgorithm,
        public_verifying_key_hex: &str,
        message: &[u8],
        signature_hex: &str,
    ) -> Result<(bool, u128), String> {
        let start = Instant::now();
        let vk_bytes = hex::decode(public_verifying_key_hex.trim())
            .map_err(|e| format!("Invalid public verifying key hex: {}", e))?;
        let sig_bytes = hex::decode(signature_hex.trim())
            .map_err(|e| format!("Invalid signature hex: {}", e))?;

        let is_valid =
            match algorithm {
                PqcAlgorithm::MlDsa44 => {
                    let vk = VerifyingKey::<MlDsa44>::decode(
                        (&vk_bytes[..])
                            .try_into()
                            .map_err(|_| "Invalid ML-DSA-44 public key length")?,
                    );
                    let sig = Signature::<MlDsa44>::decode(
                        (&sig_bytes[..])
                            .try_into()
                            .map_err(|_| "Invalid ML-DSA-44 signature length")?,
                    )
                    .ok_or_else(|| "Failed to decode ML-DSA-44 signature".to_string())?;
                    vk.verify(message, &sig).is_ok()
                }
                PqcAlgorithm::MlDsa65 => {
                    let vk = VerifyingKey::<MlDsa65>::decode((&vk_bytes[..]).try_into().map_err(
                        |_| "Invalid ML-DSA-65 public key length (expected 1952 bytes)",
                    )?);
                    let sig =
                        Signature::<MlDsa65>::decode((&sig_bytes[..]).try_into().map_err(
                            |_| "Invalid ML-DSA-65 signature length (expected 3309 bytes)",
                        )?)
                        .ok_or_else(|| "Failed to decode ML-DSA-65 signature".to_string())?;
                    vk.verify(message, &sig).is_ok()
                }
                PqcAlgorithm::MlDsa87 => {
                    let vk = VerifyingKey::<MlDsa87>::decode(
                        (&vk_bytes[..])
                            .try_into()
                            .map_err(|_| "Invalid ML-DSA-87 public key length")?,
                    );
                    let sig = Signature::<MlDsa87>::decode(
                        (&sig_bytes[..])
                            .try_into()
                            .map_err(|_| "Invalid ML-DSA-87 signature length")?,
                    )
                    .ok_or_else(|| "Failed to decode ML-DSA-87 signature".to_string())?;
                    vk.verify(message, &sig).is_ok()
                }
                _ => return Err(format!("Algorithm {:?} is not a DSA", algorithm)),
            };

        let elapsed = start.elapsed().as_micros();
        Ok((is_valid, elapsed))
    }
}
