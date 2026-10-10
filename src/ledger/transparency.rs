use crate::ledger::receipt::{LedgerError, SignedExecutionReceipt};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Direction of the sibling in the Merkle audit path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofDirection {
    Left,
    Right,
}

/// Sibling node in the cryptographic inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofSibling {
    pub direction: ProofDirection,
    pub hash: [u8; 32],
}

/// Verifiable Merkle inclusion proof for a receipt in the Transparency Log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub total_leaves: u64,
    pub audit_path: Vec<ProofSibling>,
}

/// Signed root checkpoint for the transparency log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogCheckpoint {
    pub sequence: u64,
    pub root_hash: [u8; 32],
    pub leaf_count: u64,
    pub timestamp_ms: u64,
    pub supervisor_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

impl LogCheckpoint {
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"TRANSPARENCY_CHECKPOINT_V1:");
        hasher.update(self.sequence.to_be_bytes());
        hasher.update(self.root_hash);
        hasher.update(self.leaf_count.to_be_bytes());
        hasher.update(self.timestamp_ms.to_be_bytes());
        hasher.finalize().into()
    }

    pub fn verify(&self) -> Result<(), LedgerError> {
        let verifying_key = VerifyingKey::from_bytes(&self.supervisor_pubkey)
            .map_err(|e| LedgerError::InvalidSignature(format!("Malformed checkpoint pubkey: {}", e)))?;

        let sig_bytes: [u8; 64] = self.signature.as_slice().try_into()
            .map_err(|_| LedgerError::InvalidSignature("Checkpoint signature length is not 64 bytes".to_string()))?;

        let signature = Signature::from_bytes(&sig_bytes);
        let digest = self.digest();

        verifying_key
            .verify(&digest, &signature)
            .map_err(|e| LedgerError::InvalidSignature(format!("Checkpoint signature mismatch: {}", e)))
    }
}

/// Append-only Merkle transparency log providing tamper-evident audit evidence.
#[derive(Debug, Clone)]
pub struct TransparencyLog {
    receipts: Vec<SignedExecutionReceipt>,
    leaf_hashes: Vec<[u8; 32]>,
    checkpoints: Vec<LogCheckpoint>,
}

impl TransparencyLog {
    pub fn new() -> Self {
        Self {
            receipts: Vec::new(),
            leaf_hashes: Vec::new(),
            checkpoints: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn get_receipt(&self, index: usize) -> Option<&SignedExecutionReceipt> {
        self.receipts.get(index)
    }

    /// Appends a cryptographically verified receipt to the log.
    /// Strictly verifies sequence numbering and signature before appending.
    pub fn append(&mut self, receipt: SignedExecutionReceipt) -> Result<u64, LedgerError> {
        // 1. Verify Ed25519 signature
        receipt.verify()?;

        // 2. Verify strict sequential ordering
        let expected_seq = self.receipts.len() as u64;
        if receipt.sequence_number != expected_seq {
            return Err(LedgerError::InvalidSequence {
                expected: expected_seq,
                got: receipt.sequence_number,
            });
        }

        let leaf_hash = receipt.leaf_hash();
        self.receipts.push(receipt);
        self.leaf_hashes.push(leaf_hash);

        Ok(expected_seq)
    }

    /// Computes the current root hash of the transparency log Merkle tree.
    pub fn root_hash(&self) -> [u8; 32] {
        if self.leaf_hashes.is_empty() {
            return [0u8; 32];
        }

        let mut current_level = self.leaf_hashes.clone();

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);

            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(hash_children(&chunk[0], &chunk[1]));
                } else {
                    // Odd element: promote or hash with itself
                    next_level.push(hash_children(&chunk[0], &chunk[0]));
                }
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Generates a signed checkpoint representing the current committed log state.
    pub fn create_checkpoint(&mut self, signing_key: &SigningKey) -> LogCheckpoint {
        let sequence = self.checkpoints.len() as u64;
        let root = self.root_hash();
        let leaf_count = self.leaf_hashes.len() as u64;
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let pubkey_bytes = signing_key.verifying_key().to_bytes();

        let mut cp = LogCheckpoint {
            sequence,
            root_hash: root,
            leaf_count,
            timestamp_ms,
            supervisor_pubkey: pubkey_bytes,
            signature: Vec::new(),
        };

        let digest = cp.digest();
        cp.signature = signing_key.sign(&digest).to_vec();
        self.checkpoints.push(cp.clone());

        cp
    }

    /// Generates a verifiable Merkle inclusion proof for a receipt at `leaf_index`.
    pub fn generate_inclusion_proof(&self, leaf_index: u64) -> Result<InclusionProof, LedgerError> {
        let total = self.leaf_hashes.len() as u64;
        if leaf_index >= total {
            return Err(LedgerError::StorageError(format!(
                "Leaf index {} out of bounds (total {})",
                leaf_index, total
            )));
        }

        let mut audit_path = Vec::new();
        let mut idx = leaf_index as usize;
        let mut current_level = self.leaf_hashes.clone();

        while current_level.len() > 1 {
            let is_right_child = idx % 2 == 1;
            let sibling_idx = if is_right_child { idx - 1 } else { idx + 1 };

            let sibling_hash = if sibling_idx < current_level.len() {
                current_level[sibling_idx]
            } else {
                // Odd last node paired with itself
                current_level[idx]
            };

            audit_path.push(ProofSibling {
                direction: if is_right_child {
                    ProofDirection::Left
                } else {
                    ProofDirection::Right
                },
                hash: sibling_hash,
            });

            // Build next level
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(hash_children(&chunk[0], &chunk[1]));
                } else {
                    next_level.push(hash_children(&chunk[0], &chunk[0]));
                }
            }

            idx /= 2;
            current_level = next_level;
        }

        Ok(InclusionProof {
            leaf_index,
            total_leaves: total,
            audit_path,
        })
    }

    /// Verifies a Merkle inclusion proof independently against an expected root hash.
    pub fn verify_inclusion(
        leaf_hash: [u8; 32],
        proof: &InclusionProof,
        expected_root: [u8; 32],
    ) -> bool {
        let mut current = leaf_hash;

        for sibling in &proof.audit_path {
            current = match sibling.direction {
                ProofDirection::Left => hash_children(&sibling.hash, &current),
                ProofDirection::Right => hash_children(&current, &sibling.hash),
            };
        }

        current == expected_root
    }
}

fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"TRANSPARENCY_INTERNAL_NODE:");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}
