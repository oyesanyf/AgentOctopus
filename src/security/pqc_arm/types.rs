use serde::{Deserialize, Serialize};

/// Supported Post-Quantum and Hybrid Cryptographic Algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PqcAlgorithm {
    /// NIST FIPS 203: ML-KEM-512 (Security Category 1, ~AES-128 equivalent)
    MlKem512,
    /// NIST FIPS 203: ML-KEM-768 (Security Category 3, ~AES-192 equivalent, Recommended standard)
    MlKem768,
    /// NIST FIPS 203: ML-KEM-1024 (Security Category 5, ~AES-256 equivalent)
    MlKem1024,
    /// NIST FIPS 204: ML-DSA-44 (Security Category 2)
    MlDsa44,
    /// NIST FIPS 204: ML-DSA-65 (Security Category 3, Recommended standard)
    MlDsa65,
    /// NIST FIPS 204: ML-DSA-87 (Security Category 5)
    MlDsa87,
    /// Hybrid X25519 + ML-KEM-768 dual key exchange (RFC 9180 dual defense)
    HybridX25519MlKem768,
}

impl PqcAlgorithm {
    pub fn name(&self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512 (FIPS 203)",
            Self::MlKem768 => "ML-KEM-768 (FIPS 203)",
            Self::MlKem1024 => "ML-KEM-1024 (FIPS 203)",
            Self::MlDsa44 => "ML-DSA-44 (FIPS 204)",
            Self::MlDsa65 => "ML-DSA-65 (FIPS 204)",
            Self::MlDsa87 => "ML-DSA-87 (FIPS 204)",
            Self::HybridX25519MlKem768 => "Hybrid X25519 + ML-KEM-768",
        }
    }

    pub fn security_category(&self) -> u8 {
        match self {
            Self::MlKem512 => 1,
            Self::MlDsa44 => 2,
            Self::MlKem768 | Self::MlDsa65 | Self::HybridX25519MlKem768 => 3,
            Self::MlKem1024 | Self::MlDsa87 => 5,
        }
    }

    pub fn is_kem(&self) -> bool {
        matches!(
            self,
            Self::MlKem512 | Self::MlKem768 | Self::MlKem1024 | Self::HybridX25519MlKem768
        )
    }

    pub fn is_dsa(&self) -> bool {
        matches!(self, Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87)
    }
}

/// Cryptographic Post-Quantum Keypair metadata and serialized public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcKeypairInfo {
    pub key_id: String,
    pub algorithm: PqcAlgorithm,
    pub public_key_hex: String,
    pub public_key_bytes_len: usize,
    pub created_at_secs: u64,
    pub epoch_generation: u64,
}

/// Result of an encapsulation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcEncapsulationResult {
    pub key_id: String,
    pub algorithm: PqcAlgorithm,
    pub ciphertext_hex: String,
    pub ciphertext_bytes_len: usize,
    pub shared_secret_hex: String,
    pub shared_secret_bytes_len: usize,
    pub execution_micros: u128,
}

/// Result of a decapsulation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcDecapsulationResult {
    pub key_id: String,
    pub shared_secret_hex: String,
    pub success: bool,
    pub execution_micros: u128,
}

/// Digital signature created by a post-quantum signing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcSignatureResult {
    pub key_id: String,
    pub algorithm: PqcAlgorithm,
    pub message_digest_sha256: String,
    pub signature_hex: String,
    pub signature_bytes_len: usize,
    pub verified: bool,
    pub execution_micros: u128,
}

/// Quantum Vulnerability Level for inspected cryptographic assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuantumVulnerabilityLevel {
    /// Completely vulnerable to Shor's algorithm polynomial-time discrete log / factoring (RSA, ECC, DH)
    CriticalVulnerable,
    /// Vulnerable to Grover's algorithm search reduction (e.g. AES-128 halved to 64-bit security)
    ModerateRisk,
    /// Quantum-resistant lattice / hash-based primitive (FIPS 203 ML-KEM, FIPS 204 ML-DSA, AES-256)
    QuantumSafe,
}

/// Cryptographic Bill of Materials (CBOM) entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomEntry {
    pub component_name: String,
    pub algorithm: String,
    pub key_size_bits: usize,
    pub primitive_type: String, // "KEM", "Signature", "Symmetric", "Hash"
    pub vulnerability_level: QuantumVulnerabilityLevel,
    pub shor_vulnerable: bool,
    pub grover_affected: bool,
    pub recommendation: String,
}

/// Complete Cryptographic Bill of Materials (CBOM) & Quantum Readiness Report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomReport {
    pub timestamp_secs: u64,
    pub total_primitives_scanned: usize,
    pub quantum_safe_count: usize,
    pub quantum_vulnerable_count: usize,
    pub quantum_readiness_score: f64, // 0.0 to 100.0%
    pub entries: Vec<CbomEntry>,
    pub migration_advisories: Vec<String>,
}

/// Overall status of Arm 108: Post-Quantum Cryptography & Attestation Arm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcArmStatus {
    pub arm_id: usize,
    pub role: String,
    pub status: String,
    pub is_contained: bool,
    pub is_severed: bool,
    pub active_generation: u64,
    pub active_algorithm: String,
    pub total_keypairs_generated: usize,
    pub total_encapsulations: usize,
    pub total_decapsulations: usize,
    pub total_signatures_verified: usize,
    pub quantum_readiness_score: f64,
    pub active_keypairs: Vec<PqcKeypairInfo>,
    pub latest_cbom_summary: Option<CbomReport>,
}
