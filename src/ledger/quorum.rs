use crate::ledger::receipt::LedgerError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Policy or egress update proposal requiring multi-party quorum approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyProposal {
    pub proposal_id: String,
    pub proposed_policy_hash: [u8; 32],
    pub new_egress_domains: Vec<String>,
    pub timestamp_ms: u64,
}

impl PolicyProposal {
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"POLICY_PROPOSAL_V1:");
        hasher.update((self.proposal_id.len() as u32).to_be_bytes());
        hasher.update(self.proposal_id.as_bytes());
        hasher.update(self.proposed_policy_hash);
        for domain in &self.new_egress_domains {
            hasher.update((domain.len() as u32).to_be_bytes());
            hasher.update(domain.as_bytes());
        }
        hasher.update(self.timestamp_ms.to_be_bytes());
        hasher.finalize().into()
    }
}

/// Cryptographic attestation from a trusted authority endorsing a policy proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAttestation {
    pub proposal_id: String,
    pub authority_id: String,
    pub authority_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

impl PolicyAttestation {
    pub fn create_and_sign(
        proposal: &PolicyProposal,
        authority_id: &str,
        signing_key: &SigningKey,
    ) -> Self {
        let digest = proposal.digest();
        let sig = signing_key.sign(&digest);
        let pubkey_bytes = signing_key.verifying_key().to_bytes();

        Self {
            proposal_id: proposal.proposal_id.clone(),
            authority_id: authority_id.to_string(),
            authority_pubkey: pubkey_bytes,
            signature: sig.to_vec(),
        }
    }
}

/// Multi-party quorum policy guard requiring M-of-N (e.g. 2-of-3) independent
/// trusted authorities to approve any policy or network egress modifications.
#[derive(Debug, Clone)]
pub struct QuorumPolicyGuard {
    pub quorum_threshold: usize,
    authorities: HashMap<String, VerifyingKey>,
    pub active_policy_hash: [u8; 32],
    pub active_egress_domains: Vec<String>,
    pub committed_history: Vec<PolicyProposal>,
}

impl QuorumPolicyGuard {
    pub fn new(quorum_threshold: usize, initial_policy_hash: [u8; 32]) -> Self {
        Self {
            quorum_threshold,
            authorities: HashMap::new(),
            active_policy_hash: initial_policy_hash,
            active_egress_domains: Vec::new(),
            committed_history: Vec::new(),
        }
    }

    /// Registers a trusted authority public key.
    pub fn register_authority(
        &mut self,
        authority_id: impl Into<String>,
        verifying_key: VerifyingKey,
    ) {
        self.authorities.insert(authority_id.into(), verifying_key);
    }

    pub fn authority_count(&self) -> usize {
        self.authorities.len()
    }

    /// Evaluates and commits a proposal if it satisfies the M-of-N quorum threshold.
    /// Strictly verifies:
    /// 1. Each attestation targets the correct proposal ID.
    /// 2. Each signature is verified against that authority's registered public key.
    /// 3. Signers are unique (anti-sybil / double-voting prevention).
    /// 4. Total valid independent signatures >= quorum_threshold.
    pub fn submit_and_commit_proposal(
        &mut self,
        proposal: &PolicyProposal,
        attestations: &[PolicyAttestation],
    ) -> Result<(), LedgerError> {
        let proposal_digest = proposal.digest();
        let mut verified_authorities = HashSet::new();

        for attestation in attestations {
            // Check proposal ID matching
            if attestation.proposal_id != proposal.proposal_id {
                return Err(LedgerError::InvalidSignature(format!(
                    "Attestation proposal mismatch: expected '{}', got '{}'",
                    proposal.proposal_id, attestation.proposal_id
                )));
            }

            // Check authority registration
            let trusted_key = self
                .authorities
                .get(&attestation.authority_id)
                .ok_or_else(|| {
                    LedgerError::UnauthorizedAuthority(attestation.authority_id.clone())
                })?;

            // Check public key bytes match registered key
            if trusted_key.to_bytes() != attestation.authority_pubkey {
                return Err(LedgerError::InvalidSignature(format!(
                    "Authority pubkey mismatch for '{}'",
                    attestation.authority_id
                )));
            }

            // Anti-sybil: Check for duplicate authority voting
            if !verified_authorities.insert(attestation.authority_id.clone()) {
                return Err(LedgerError::DuplicateAuthority(
                    attestation.authority_id.clone(),
                ));
            }

            // Cryptographic Ed25519 signature verification
            let sig_bytes: [u8; 64] =
                attestation.signature.as_slice().try_into().map_err(|_| {
                    LedgerError::InvalidSignature("Signature length must be 64 bytes".to_string())
                })?;

            let signature = Signature::from_bytes(&sig_bytes);
            trusted_key
                .verify(&proposal_digest, &signature)
                .map_err(|e| {
                    LedgerError::InvalidSignature(format!(
                        "Authority '{}' signature invalid: {}",
                        attestation.authority_id, e
                    ))
                })?;
        }

        if verified_authorities.len() < self.quorum_threshold {
            return Err(LedgerError::QuorumNotMet {
                required: self.quorum_threshold,
                valid: verified_authorities.len(),
            });
        }

        // Commit state update
        self.active_policy_hash = proposal.proposed_policy_hash;
        self.active_egress_domains = proposal.new_egress_domains.clone();
        self.committed_history.push(proposal.clone());

        Ok(())
    }
}
