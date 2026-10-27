use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LedgerError {
    #[error("Cryptographic signature verification failed: {0}")]
    InvalidSignature(String),
    #[error("Invalid sequence number: expected {expected}, got {got}")]
    InvalidSequence { expected: u64, got: u64 },
    #[error("Merkle inclusion proof failed: leaf hash not bound to root")]
    InvalidInclusionProof,
    #[error("Quorum threshold not met: required {required}, valid signatures {valid}")]
    QuorumNotMet { required: usize, valid: usize },
    #[error("Duplicate authority signature from '{0}'")]
    DuplicateAuthority(String),
    #[error("Unknown or unauthorized authority ID '{0}'")]
    UnauthorizedAuthority(String),
    #[error("Post-quantum attestation verification failed: {0}")]
    PqcVerificationFailed(String),
    #[error("Ledger storage error: {0}")]
    StorageError(String),
}

/// Cryptographically signed execution receipt produced for every agent execution step.
/// Signed using Ed25519 by the supervisor authority to guarantee non-repudiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedExecutionReceipt {
    pub sequence_number: u64,
    pub agent_id: String,
    pub action_type: String,
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub timestamp_ms: u64,
    pub payload_digest: [u8; 32],
    pub supervisor_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

impl SignedExecutionReceipt {
    /// Computes the canonical SHA-256 digest of the receipt payload prior to signing.
    pub fn payload_digest_bytes(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"AGENT_OCTOPUS_RECEIPT_V1:");
        hasher.update(self.sequence_number.to_be_bytes());
        hasher.update((self.agent_id.len() as u32).to_be_bytes());
        hasher.update(self.agent_id.as_bytes());
        hasher.update((self.action_type.len() as u32).to_be_bytes());
        hasher.update(self.action_type.as_bytes());
        hasher.update(self.pre_state_root);
        hasher.update(self.post_state_root);
        hasher.update(self.timestamp_ms.to_be_bytes());
        hasher.update(self.payload_digest);
        hasher.finalize().into()
    }

    /// Computes the unique Merkle leaf hash for this signed receipt.
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"RECEIPT_LEAF:");
        hasher.update(self.payload_digest_bytes());
        hasher.update(&self.supervisor_pubkey);
        hasher.update(&self.signature);
        hasher.finalize().into()
    }

    /// Signs an execution receipt using the supervisor's Ed25519 signing key.
    pub fn create_and_sign(
        sequence_number: u64,
        agent_id: &str,
        action_type: &str,
        pre_state_root: [u8; 32],
        post_state_root: [u8; 32],
        payload_digest: [u8; 32],
        signing_key: &SigningKey,
    ) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_bytes();

        let mut receipt = Self {
            sequence_number,
            agent_id: agent_id.to_string(),
            action_type: action_type.to_string(),
            pre_state_root,
            post_state_root,
            timestamp_ms,
            payload_digest,
            supervisor_pubkey: pubkey_bytes,
            signature: Vec::new(),
        };

        let digest = receipt.payload_digest_bytes();
        let signature = signing_key.sign(&digest);
        receipt.signature = signature.to_vec();

        receipt
    }

    /// Verifies the Ed25519 supervisor signature against the receipt contents.
    pub fn verify(&self) -> Result<(), LedgerError> {
        let verifying_key = VerifyingKey::from_bytes(&self.supervisor_pubkey)
            .map_err(|e| LedgerError::InvalidSignature(format!("Malformed public key: {}", e)))?;

        let sig_bytes: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            LedgerError::InvalidSignature("Signature length is not 64 bytes".to_string())
        })?;

        let signature = Signature::from_bytes(&sig_bytes);
        let digest = self.payload_digest_bytes();

        verifying_key.verify(&digest, &signature).map_err(|e| {
            LedgerError::InvalidSignature(format!("Ed25519 signature mismatch: {}", e))
        })
    }
}
