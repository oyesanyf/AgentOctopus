use agent_octopus::ledger::{
    LedgerError, PolicyAttestation, PolicyProposal, PqcAlgorithm, PqcKeypair, QuorumPolicyGuard,
    SignedExecutionReceipt, TransparencyLog,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[test]
fn test_signed_execution_receipt_creation_and_tamper_detection() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    let pre_state = [1u8; 32];
    let post_state = [2u8; 32];
    let payload_digest = [3u8; 32];

    let receipt = SignedExecutionReceipt::create_and_sign(
        0,
        "arm-worker-01",
        "doc_extract",
        pre_state,
        post_state,
        payload_digest,
        &signing_key,
    );

    // 1. Genuine receipt verifies successfully
    assert!(receipt.verify().is_ok());

    // 2. Tampering sequence number triggers verification error
    let mut tampered_seq = receipt.clone();
    tampered_seq.sequence_number = 1;
    assert!(tampered_seq.verify().is_err());

    // 3. Tampering agent ID triggers verification error
    let mut tampered_agent = receipt.clone();
    tampered_agent.agent_id = "arm-rogue-99".to_string();
    assert!(tampered_agent.verify().is_err());

    // 4. Tampering post_state_root triggers verification error
    let mut tampered_state = receipt.clone();
    tampered_state.post_state_root = [99u8; 32];
    assert!(tampered_state.verify().is_err());

    // 5. Tampering signature bytes triggers verification error
    let mut tampered_sig = receipt.clone();
    tampered_sig.signature[0] ^= 0xFF;
    assert!(tampered_sig.verify().is_err());
}

#[test]
fn test_transparency_log_sequential_append_and_ordering() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let mut log = TransparencyLog::new();

    // Append sequence 0
    let r0 = SignedExecutionReceipt::create_and_sign(
        0,
        "arm-worker-01",
        "action_0",
        [0u8; 32],
        [1u8; 32],
        [10u8; 32],
        &signing_key,
    );
    assert_eq!(log.append(r0).unwrap(), 0);

    // Append sequence 1
    let r1 = SignedExecutionReceipt::create_and_sign(
        1,
        "arm-worker-02",
        "action_1",
        [1u8; 32],
        [2u8; 32],
        [20u8; 32],
        &signing_key,
    );
    assert_eq!(log.append(r1).unwrap(), 1);

    // Out-of-order append (sequence 5 instead of 2) -> rejected
    let r_bad_seq = SignedExecutionReceipt::create_and_sign(
        5,
        "arm-worker-03",
        "action_5",
        [2u8; 32],
        [3u8; 32],
        [50u8; 32],
        &signing_key,
    );
    let err = log.append(r_bad_seq).unwrap_err();
    match err {
        LedgerError::InvalidSequence { expected, got } => {
            assert_eq!(expected, 2);
            assert_eq!(got, 5);
        }
        other => panic!("Expected InvalidSequence, got {:?}", other),
    }

    assert_eq!(log.len(), 2);
}

#[test]
fn test_merkle_transparency_inclusion_proof_and_verification() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let mut log = TransparencyLog::new();

    let count = 8;
    let mut leaf_hashes = Vec::new();

    for i in 0..count {
        let r = SignedExecutionReceipt::create_and_sign(
            i,
            &format!("arm-{:02}", i),
            "step",
            [i as u8; 32],
            [(i + 1) as u8; 32],
            [(i + 10) as u8; 32],
            &signing_key,
        );
        leaf_hashes.push(r.leaf_hash());
        log.append(r).unwrap();
    }

    let root = log.root_hash();
    assert_ne!(root, [0u8; 32]);

    // Verify inclusion proof for every leaf in the log
    for (idx, &leaf_hash) in leaf_hashes.iter().enumerate() {
        let proof = log.generate_inclusion_proof(idx as u64).unwrap();
        assert_eq!(proof.leaf_index, idx as u64);
        assert_eq!(proof.total_leaves, count);

        // Verification must succeed
        assert!(TransparencyLog::verify_inclusion(leaf_hash, &proof, root));

        // Tampered leaf hash must fail verification
        let mut bad_leaf = leaf_hash;
        bad_leaf[0] ^= 0xAA;
        assert!(!TransparencyLog::verify_inclusion(bad_leaf, &proof, root));

        // Wrong root must fail verification
        let bad_root = [99u8; 32];
        assert!(!TransparencyLog::verify_inclusion(
            leaf_hash, &proof, bad_root
        ));
    }
}

#[test]
fn test_transparency_log_checkpoint_signing_and_tamper_detection() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let mut log = TransparencyLog::new();

    let r0 = SignedExecutionReceipt::create_and_sign(
        0,
        "arm-worker-01",
        "action_0",
        [0u8; 32],
        [1u8; 32],
        [10u8; 32],
        &signing_key,
    );
    log.append(r0).unwrap();

    let checkpoint = log.create_checkpoint(&signing_key);
    assert_eq!(checkpoint.sequence, 0);
    assert_eq!(checkpoint.leaf_count, 1);
    assert_eq!(checkpoint.root_hash, log.root_hash());

    // Checkpoint signature verification passes
    assert!(checkpoint.verify().is_ok());

    // Tampered checkpoint root fails
    let mut tampered_cp = checkpoint.clone();
    tampered_cp.root_hash[0] ^= 0x01;
    assert!(tampered_cp.verify().is_err());
}

#[test]
fn test_quorum_policy_guard_multi_party_approval_success() {
    let mut csprng = OsRng;
    let key_auth1 = SigningKey::generate(&mut csprng);
    let key_auth2 = SigningKey::generate(&mut csprng);
    let key_auth3 = SigningKey::generate(&mut csprng);

    let initial_policy = [0xAA; 32];
    let mut guard = QuorumPolicyGuard::new(2, initial_policy);

    guard.register_authority("authority-alpha", key_auth1.verifying_key());
    guard.register_authority("authority-beta", key_auth2.verifying_key());
    guard.register_authority("authority-gamma", key_auth3.verifying_key());

    assert_eq!(guard.authority_count(), 3);

    // Create policy update proposal
    let new_policy = [0xBB; 32];
    let proposal = PolicyProposal {
        proposal_id: "PROP-2026-001".to_string(),
        proposed_policy_hash: new_policy,
        new_egress_domains: vec![
            "https://google.com".to_string(),
            "https://www.google.com".to_string(),
        ],
        timestamp_ms: 1775700000000,
    };

    // Authorities Alpha and Beta sign the proposal (2-of-3 quorum met)
    let attestation_alpha =
        PolicyAttestation::create_and_sign(&proposal, "authority-alpha", &key_auth1);
    let attestation_beta =
        PolicyAttestation::create_and_sign(&proposal, "authority-beta", &key_auth2);

    let res = guard.submit_and_commit_proposal(&proposal, &[attestation_alpha, attestation_beta]);
    assert!(res.is_ok(), "2-of-3 quorum approval must succeed");

    // Guard state is committed
    assert_eq!(guard.active_policy_hash, new_policy);
    assert_eq!(guard.active_egress_domains.len(), 2);
    assert!(guard
        .active_egress_domains
        .contains(&"https://google.com".to_string()));
}

#[test]
fn test_quorum_policy_guard_insufficient_signatures_and_sybil_prevention() {
    let mut csprng = OsRng;
    let key_auth1 = SigningKey::generate(&mut csprng);
    let key_auth2 = SigningKey::generate(&mut csprng);
    let key_rogue = SigningKey::generate(&mut csprng);

    let initial_policy = [0xAA; 32];
    let mut guard = QuorumPolicyGuard::new(2, initial_policy);

    guard.register_authority("authority-alpha", key_auth1.verifying_key());
    guard.register_authority("authority-beta", key_auth2.verifying_key());

    let proposal = PolicyProposal {
        proposal_id: "PROP-2026-002".to_string(),
        proposed_policy_hash: [0xCC; 32],
        new_egress_domains: vec!["https://malicious-egress.org".to_string()],
        timestamp_ms: 1775700000000,
    };

    // 1. Only 1 signature provided when threshold = 2 -> rejected
    let attestation_alpha =
        PolicyAttestation::create_and_sign(&proposal, "authority-alpha", &key_auth1);
    let res_insufficient =
        guard.submit_and_commit_proposal(&proposal, &[attestation_alpha.clone()]);
    assert!(res_insufficient.is_err());
    match res_insufficient.unwrap_err() {
        LedgerError::QuorumNotMet { required, valid } => {
            assert_eq!(required, 2);
            assert_eq!(valid, 1);
        }
        other => panic!("Expected QuorumNotMet, got {:?}", other),
    }

    // 2. Sybil / Double-voting attempt: Authority Alpha signs twice -> rejected
    let res_double = guard.submit_and_commit_proposal(
        &proposal,
        &[attestation_alpha.clone(), attestation_alpha.clone()],
    );
    assert!(res_double.is_err());
    match res_double.unwrap_err() {
        LedgerError::DuplicateAuthority(id) => {
            assert_eq!(id, "authority-alpha");
        }
        other => panic!("Expected DuplicateAuthority, got {:?}", other),
    }

    // 3. Rogue unregistered authority signature -> rejected
    let attestation_rogue =
        PolicyAttestation::create_and_sign(&proposal, "authority-rogue", &key_rogue);
    let res_rogue = guard
        .submit_and_commit_proposal(&proposal, &[attestation_alpha.clone(), attestation_rogue]);
    assert!(res_rogue.is_err());
    match res_rogue.unwrap_err() {
        LedgerError::UnauthorizedAuthority(id) => {
            assert_eq!(id, "authority-rogue");
        }
        other => panic!("Expected UnauthorizedAuthority, got {:?}", other),
    }
}

#[test]
fn test_post_quantum_attestations_fips_204_and_205() {
    let seed = [42u8; 32];
    let subject_digest = [77u8; 32];
    let context = "AGENT_AUDIT_ATTESTATION_2026";

    // 1. FIPS 204: ML-DSA-65 (Module-Lattice signature)
    let keypair_mldsa65 = PqcKeypair::generate_from_seed(PqcAlgorithm::MlDsa65, &seed);
    let attestation_mldsa65 = keypair_mldsa65.sign_attestation(subject_digest, context);
    assert_eq!(attestation_mldsa65.algorithm, PqcAlgorithm::MlDsa65);
    assert!(attestation_mldsa65.verify().is_ok());

    // Tampered subject digest fails ML-DSA
    let mut tampered_ml = attestation_mldsa65.clone();
    tampered_ml.subject_digest[0] ^= 0x01;
    assert!(tampered_ml.verify().is_err());

    // 2. FIPS 204: ML-DSA-87 (Security Category 5)
    let keypair_mldsa87 = PqcKeypair::generate_from_seed(PqcAlgorithm::MlDsa87, &seed);
    let attestation_mldsa87 = keypair_mldsa87.sign_attestation(subject_digest, context);
    assert!(attestation_mldsa87.verify().is_ok());

    // 3. FIPS 205: SLH-DSA-SHA2-128s (Stateless Hash-based signature)
    let keypair_slhdsa = PqcKeypair::generate_from_seed(PqcAlgorithm::SlhDsaSha2_128s, &seed);
    let attestation_slh = keypair_slhdsa.sign_attestation(subject_digest, context);
    assert_eq!(attestation_slh.algorithm, PqcAlgorithm::SlhDsaSha2_128s);
    assert!(attestation_slh.verify().is_ok());

    // Tampered context string fails SLH-DSA
    let mut tampered_slh = attestation_slh.clone();
    tampered_slh.context_string = "FORGED_CONTEXT".to_string();
    assert!(tampered_slh.verify().is_err());

    // 4. FIPS 205: SLH-DSA-SHA2-256s
    let keypair_slhdsa256 = PqcKeypair::generate_from_seed(PqcAlgorithm::SlhDsaSha2_256s, &seed);
    let attestation_slh256 = keypair_slhdsa256.sign_attestation(subject_digest, context);
    assert!(attestation_slh256.verify().is_ok());
}
