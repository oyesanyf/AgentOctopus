use crate::core::merkle::{MerkleLeaf, MerkleTree};
use crate::core::types::OctopusSecurityError;
use crate::ledger::receipt::SignedExecutionReceipt;
use crate::security::audit::SecurityAuditLog;

/// Integrity Guard: Verifies Merkle audit integrity, prevents historical tampering,
/// and independently validates signed execution receipts from arms.
pub struct IntegrityGuard {
    guard_id: String,
}

impl IntegrityGuard {
    pub fn new(guard_id: &str) -> Self {
        Self {
            guard_id: guard_id.to_string(),
        }
    }

    pub fn guard_id(&self) -> &str {
        &self.guard_id
    }

    /// Verifies the cryptographic integrity of an append-only audit trail.
    pub fn verify_audit_trail_integrity(
        &self,
        audit_log: &SecurityAuditLog,
    ) -> Result<usize, OctopusSecurityError> {
        if !audit_log.verify_integrity() {
            return Err(OctopusSecurityError::MerkleTamperDetected(
                "Audit trail hash chain integrity verification failed (tampered records detected)".to_string(),
            ));
        }

        Ok(audit_log.total_records())
    }

    /// Verifies Merkle root computation over an ordered sequence of Merkle leaves.
    pub fn verify_merkle_provenance(
        &self,
        leaves: Vec<MerkleLeaf>,
        claimed_root: &str,
    ) -> Result<(), OctopusSecurityError> {
        let tree = MerkleTree::from_leaves(leaves);
        if tree.root_hex() != claimed_root {
            return Err(OctopusSecurityError::MerkleTamperDetected(format!(
                "Merkle root mismatch: computed {}, claimed {}",
                tree.root_hex(),
                claimed_root
            )));
        }
        Ok(())
    }

    /// Validates an Ed25519-signed execution receipt from an executing arm.
    pub fn verify_execution_receipt(
        &self,
        receipt: &SignedExecutionReceipt,
    ) -> Result<(), OctopusSecurityError> {
        receipt.verify().map_err(|e| {
            OctopusSecurityError::MerkleTamperDetected(format!("Invalid execution receipt: {}", e))
        })
    }
}
