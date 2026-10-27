use crate::core::merkle::MerkleProof;
use crate::core::types::OctopusSecurityError;
use crate::ledger::receipt::SignedExecutionReceipt;
use crate::security::audit::SecurityAuditLog;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceValidationVerdict {
    pub technique_id: String,
    pub is_empirically_verified: bool,
    pub evidence_type: String,
    pub cryptographic_fingerprint: String,
    pub notes: String,
}

/// EvidenceValidator: Validates that defensive containment claims are backed by
/// genuine cryptographic artifacts (Merkle proofs, Ed25519 receipts, audit log chains).
pub struct EvidenceValidator;

impl EvidenceValidator {
    /// Validates an Ed25519-signed execution receipt as proof of authorized execution.
    pub fn validate_execution_receipt(
        technique_id: &str,
        receipt: &SignedExecutionReceipt,
    ) -> Result<EvidenceValidationVerdict, OctopusSecurityError> {
        receipt.verify().map_err(|e| {
            OctopusSecurityError::MerkleTamperDetected(format!(
                "Receipt verification failed: {}",
                e
            ))
        })?;

        Ok(EvidenceValidationVerdict {
            technique_id: technique_id.to_string(),
            is_empirically_verified: true,
            evidence_type: "Ed25519 Signed Execution Receipt".to_string(),
            cryptographic_fingerprint: hex::encode(&receipt.signature),
            notes: format!(
                "Verified sequence {} from agent {}",
                receipt.sequence_number, receipt.agent_id
            ),
        })
    }

    /// Validates a Merkle inclusion proof as evidence of tamper-evident step recording.
    pub fn validate_merkle_inclusion_proof(
        technique_id: &str,
        proof: &MerkleProof,
        claimed_root: &[u8; 32],
    ) -> Result<EvidenceValidationVerdict, OctopusSecurityError> {
        if !proof.verify(claimed_root) {
            return Err(OctopusSecurityError::MerkleTamperDetected(
                "Merkle inclusion proof verification failed".to_string(),
            ));
        }

        Ok(EvidenceValidationVerdict {
            technique_id: technique_id.to_string(),
            is_empirically_verified: true,
            evidence_type: "Cryptographic Merkle Inclusion Proof".to_string(),
            cryptographic_fingerprint: hex::encode(proof.leaf_hash),
            notes: format!(
                "Verified inclusion across {} audit path siblings",
                proof.audit_path.len()
            ),
        })
    }

    /// Validates append-only security audit log chain integrity as evidence of containment.
    pub fn validate_audit_chain(
        technique_id: &str,
        audit_log: &SecurityAuditLog,
    ) -> Result<EvidenceValidationVerdict, OctopusSecurityError> {
        if !audit_log.verify_integrity() {
            return Err(OctopusSecurityError::MerkleTamperDetected(
                "Audit log integrity check failed: hash chain broken".to_string(),
            ));
        }

        Ok(EvidenceValidationVerdict {
            technique_id: technique_id.to_string(),
            is_empirically_verified: true,
            evidence_type: "SHA-256 Append-Only Audit Log Hash Chain".to_string(),
            cryptographic_fingerprint: format!("records:{}", audit_log.total_records()),
            notes: format!(
                "Verified complete chain of {} audit records",
                audit_log.total_records()
            ),
        })
    }
}
