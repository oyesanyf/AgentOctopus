use agent_octopus::containment_ring::ArmContainmentRing;
use agent_octopus::core::types::{ArmRole, OctopusSecurityError};
use agent_octopus::security::pqc_arm::cbom::CbomScanner;
use agent_octopus::security::pqc_arm::dsa::PqcDsaEngine;
use agent_octopus::security::pqc_arm::kem::PqcKemEngine;
use agent_octopus::security::pqc_arm::types::{PqcAlgorithm, QuantumVulnerabilityLevel};
use agent_octopus::security::pqc_arm::PostQuantumArm;
use agent_octopus::web::api::*;
use std::sync::Arc;

#[test]
fn test_ml_kem_768_keygen_encap_decap_roundtrip() {
    // 1. Key generation for ML-KEM-768 (Swarm Standard NIST Level 3)
    let (sk_hex, pk_hex) = PqcKemEngine::generate_keypair(PqcAlgorithm::MlKem768)
        .expect("ML-KEM-768 key generation must succeed");
    assert!(!sk_hex.is_empty(), "Secret key seed must not be empty");
    assert_eq!(pk_hex.len(), 1184 * 2, "ML-KEM-768 public key must be 1184 bytes (2368 hex characters)");

    // 2. Encapsulation: Sender uses public key to encapsulate a shared secret
    let (ct_hex, sender_ss_hex, encap_micros) = PqcKemEngine::encapsulate(PqcAlgorithm::MlKem768, &pk_hex)
        .expect("ML-KEM-768 encapsulation must succeed");
    assert_eq!(ct_hex.len(), 1088 * 2, "ML-KEM-768 ciphertext must be 1088 bytes (2176 hex characters)");
    assert_eq!(sender_ss_hex.len(), 32 * 2, "Shared secret must be 32 bytes (64 hex characters)");
    assert!(encap_micros < 500_000, "Encapsulation should execute efficiently in microseconds");

    // 3. Decapsulation: Recipient uses secret key seed to decapsulate the shared secret
    let (recipient_ss_hex, decap_micros) = PqcKemEngine::decapsulate(PqcAlgorithm::MlKem768, &sk_hex, &ct_hex)
        .expect("ML-KEM-768 decapsulation must succeed");
    assert!(decap_micros < 500_000, "Decapsulation should execute efficiently in microseconds");

    // 4. Exact equality of shared secret
    assert_eq!(sender_ss_hex, recipient_ss_hex, "Shared secrets must match identically across sender and recipient");
}

#[test]
fn test_ml_kem_512_and_1024_roundtrip() {
    // Test ML-KEM-512 (NIST Level 1)
    let (sk512, pk512) = PqcKemEngine::generate_keypair(PqcAlgorithm::MlKem512)
        .expect("ML-KEM-512 keygen must succeed");
    assert_eq!(pk512.len(), 800 * 2);
    let (ct512, ss512_send, _) = PqcKemEngine::encapsulate(PqcAlgorithm::MlKem512, &pk512)
        .expect("ML-KEM-512 encap must succeed");
    assert_eq!(ct512.len(), 768 * 2);
    let (ss512_recv, _) = PqcKemEngine::decapsulate(PqcAlgorithm::MlKem512, &sk512, &ct512)
        .expect("ML-KEM-512 decap must succeed");
    assert_eq!(ss512_send, ss512_recv);

    // Test ML-KEM-1024 (NIST Level 5)
    let (sk1024, pk1024) = PqcKemEngine::generate_keypair(PqcAlgorithm::MlKem1024)
        .expect("ML-KEM-1024 keygen must succeed");
    assert_eq!(pk1024.len(), 1568 * 2);
    let (ct1024, ss1024_send, _) = PqcKemEngine::encapsulate(PqcAlgorithm::MlKem1024, &pk1024)
        .expect("ML-KEM-1024 encap must succeed");
    assert_eq!(ct1024.len(), 1568 * 2);
    let (ss1024_recv, _) = PqcKemEngine::decapsulate(PqcAlgorithm::MlKem1024, &sk1024, &ct1024)
        .expect("ML-KEM-1024 decap must succeed");
    assert_eq!(ss1024_send, ss1024_recv);
}

#[test]
fn test_hybrid_x25519_ml_kem_768_derivation() {
    let (sk_hex, pk_hex) = PqcKemEngine::generate_keypair(PqcAlgorithm::HybridX25519MlKem768)
        .expect("Hybrid keygen must succeed");
    let (ct_hex, ss_send, _) = PqcKemEngine::encapsulate(PqcAlgorithm::HybridX25519MlKem768, &pk_hex)
        .expect("Hybrid encap must succeed");
    let (ss_recv, _) = PqcKemEngine::decapsulate(PqcAlgorithm::HybridX25519MlKem768, &sk_hex, &ct_hex)
        .expect("Hybrid decap must succeed");
    assert_eq!(ss_send, ss_recv);

    let x25519_secret = [0x42u8; 32];
    let derived1 = PqcKemEngine::combine_hybrid_secrets(&x25519_secret, &hex::decode(&ss_send).unwrap());
    let derived2 = PqcKemEngine::combine_hybrid_secrets(&x25519_secret, &hex::decode(&ss_recv).unwrap());
    assert_eq!(derived1, derived2, "Derived hybrid key must match across parties");
}

#[test]
fn test_ml_dsa_65_sign_verify_and_tamper_rejection() {
    // 1. Generate ML-DSA-65 keypair
    let (sk_hex, vk_hex) = PqcDsaEngine::generate_keypair(PqcAlgorithm::MlDsa65)
        .expect("ML-DSA-65 key generation must succeed");
    assert_eq!(sk_hex.len(), 32 * 2, "ML-DSA-65 seed must be 32 bytes");
    assert_eq!(vk_hex.len(), 1952 * 2, "ML-DSA-65 public key must be 1952 bytes (3904 hex chars)");

    let message = b"Agent Octopus Ledger Attestation Block #108 - Immutable Swarm Event";

    // 2. Sign message
    let (sig_hex, sign_micros) = PqcDsaEngine::sign(PqcAlgorithm::MlDsa65, &sk_hex, message)
        .expect("Signing must succeed");
    assert_eq!(sig_hex.len(), 3309 * 2, "ML-DSA-65 signature must be 3309 bytes (6618 hex chars)");
    assert!(sign_micros < 500_000);

    // 3. Verify valid signature
    let (is_valid, verify_micros) = PqcDsaEngine::verify(PqcAlgorithm::MlDsa65, &vk_hex, message, &sig_hex)
        .expect("Verification must succeed");
    assert!(is_valid, "Valid ML-DSA-65 signature must be accepted");
    assert!(verify_micros < 500_000);

    // 4. Reject tampered message
    let tampered_message = b"Agent Octopus Ledger Attestation Block #108 - Tampered Payload";
    let (is_valid_tampered, _) = PqcDsaEngine::verify(PqcAlgorithm::MlDsa65, &vk_hex, tampered_message, &sig_hex)
        .expect("Verification must complete without panic");
    assert!(!is_valid_tampered, "Tampered message must be rejected");

    // 5. Reject corrupted signature
    let mut corrupted_sig_bytes = hex::decode(&sig_hex).unwrap();
    corrupted_sig_bytes[10] ^= 0xff; // Flip bits
    let corrupted_sig_hex = hex::encode(corrupted_sig_bytes);
    let (is_valid_corrupt, _) = PqcDsaEngine::verify(PqcAlgorithm::MlDsa65, &vk_hex, message, &corrupted_sig_hex)
        .expect("Verification must complete without panic");
    assert!(!is_valid_corrupt, "Corrupted signature must be rejected");
}

#[test]
fn test_ml_dsa_44_and_87_sign_verify() {
    let msg = b"Swarm Zero-Trust Attestation";

    // ML-DSA-44 (NIST Level 2)
    let (sk44, vk44) = PqcDsaEngine::generate_keypair(PqcAlgorithm::MlDsa44).unwrap();
    let (sig44, _) = PqcDsaEngine::sign(PqcAlgorithm::MlDsa44, &sk44, msg).unwrap();
    let (v44, _) = PqcDsaEngine::verify(PqcAlgorithm::MlDsa44, &vk44, msg, &sig44).unwrap();
    assert!(v44);

    // ML-DSA-87 (NIST Level 5)
    let (sk87, vk87) = PqcDsaEngine::generate_keypair(PqcAlgorithm::MlDsa87).unwrap();
    let (sig87, _) = PqcDsaEngine::sign(PqcAlgorithm::MlDsa87, &sk87, msg).unwrap();
    let (v87, _) = PqcDsaEngine::verify(PqcAlgorithm::MlDsa87, &vk87, msg, &sig87).unwrap();
    assert!(v87);
}

#[test]
fn test_cbom_scanner_audit() {
    let report = CbomScanner::scan_swarm_cryptography();
    assert!(!report.entries.is_empty(), "CBOM report must include scanned components");
    assert!(report.total_primitives_scanned >= 7, "CBOM must inspect all classical and quantum components");
    assert!(report.quantum_readiness_score > 0.0, "Quantum readiness score must be computed");

    // Verify Shor's vulnerability identification
    let rsa_comp = report.entries.iter().find(|c| c.algorithm.contains("RSA")).expect("RSA must be in CBOM");
    assert!(rsa_comp.shor_vulnerable, "RSA must be identified as vulnerable to Shor's algorithm");
    assert_ne!(rsa_comp.vulnerability_level, QuantumVulnerabilityLevel::QuantumSafe, "RSA is not quantum resistant");

    let ecc_comp = report.entries.iter().find(|c| c.algorithm.contains("Ed25519") || c.algorithm.contains("ECDHE")).expect("ECC must be in CBOM");
    assert!(ecc_comp.shor_vulnerable, "Classical ECC must be identified as vulnerable to Shor's algorithm");

    // Verify PQC components
    let kem_comp = report.entries.iter().find(|c| c.algorithm.contains("ML-KEM")).expect("ML-KEM must be in CBOM");
    assert!(!kem_comp.shor_vulnerable, "ML-KEM is not vulnerable to Shor's algorithm");
    assert_eq!(kem_comp.vulnerability_level, QuantumVulnerabilityLevel::QuantumSafe, "ML-KEM is quantum resistant");

    let dsa_comp = report.entries.iter().find(|c| c.algorithm.contains("ML-DSA")).expect("ML-DSA must be in CBOM");
    assert!(!dsa_comp.shor_vulnerable, "ML-DSA is not vulnerable to Shor's algorithm");
    assert_eq!(dsa_comp.vulnerability_level, QuantumVulnerabilityLevel::QuantumSafe, "ML-DSA is quantum resistant");
}

#[tokio::test]
async fn test_arm108_containment_ring_binding_and_autotomy() {
    let seed = [0x55u8; 32];
    let ring = Arc::new(ArmContainmentRing::new(108, ArmRole::PostQuantumAttestation, 1, &seed));
    let arm = PostQuantumArm::new(Arc::clone(&ring));

    // 1. Arm operates normally when containment ring is active
    let keypair = arm.generate_keypair(PqcAlgorithm::MlKem768).await
        .expect("Keygen must succeed when ring is active");
    assert_eq!(keypair.epoch_generation, 1);

    let encap = arm.encapsulate(PqcAlgorithm::MlKem768, &keypair.public_key_hex).await
        .expect("Encapsulation must succeed when ring is active");

    let decap = arm.decapsulate(&keypair.key_id, &encap.ciphertext_hex).await
        .expect("Decapsulation must succeed when ring is active");
    assert!(decap.success);
    assert_eq!(encap.shared_secret_hex, decap.shared_secret_hex);

    // 2. Autotomy event: Supervisor severs Arm 108 due to containment breach
    ring.sever("Simulated compromise of cryptographic boundary").await;
    assert!(ring.is_severed());

    // 3. Fail-closed behavior: Any cryptographic invocation must fail immediately with LimbKilled
    let severed_keygen = arm.generate_keypair(PqcAlgorithm::MlKem768).await;
    assert!(matches!(severed_keygen, Err(OctopusSecurityError::LimbKilled)), "Severed arm must reject keygen");

    let severed_encap = arm.encapsulate(PqcAlgorithm::MlKem768, &keypair.public_key_hex).await;
    assert!(matches!(severed_encap, Err(OctopusSecurityError::LimbKilled)), "Severed arm must reject encapsulation");

    let severed_decap = arm.decapsulate(&keypair.key_id, &encap.ciphertext_hex).await;
    assert!(matches!(severed_decap, Err(OctopusSecurityError::LimbKilled)), "Severed arm must reject decapsulation");

    let status = arm.get_status().await;
    assert!(status.is_severed, "Status must report arm is severed");
    assert_eq!(status.status, "SEVERED_CONTAINED");
}

#[tokio::test]
async fn test_pqc_rest_api_roundtrip() {
    let state = WebState::default();

    // 1. GET /api/pqc/status
    let status_json = handle_pqc_status(&state).await;
    let status: serde_json::Value = serde_json::from_str(&status_json).expect("Status JSON must parse");
    assert_eq!(status["arm_id"], 108);
    assert_eq!(status["role"], "PostQuantumAttestation");
    assert!(status["quantum_readiness_score"].as_f64().unwrap() > 0.0);

    // 2. POST /api/pqc/generate-keypair (ML-KEM-768)
    let keygen_res = handle_pqc_generate_keypair(&state, r#"{"algorithm":"MlKem768"}"#).await
        .expect("Keygen API call must succeed");
    let key_info: serde_json::Value = serde_json::from_str(&keygen_res).expect("Keypair JSON must parse");
    let key_id = key_info["key_id"].as_str().unwrap().to_string();
    let pk_hex = key_info["public_key_hex"].as_str().unwrap().to_string();
    assert_eq!(key_info["algorithm"], "MlKem768");
    assert_eq!(key_info["public_key_bytes_len"], 1184);

    // 3. POST /api/pqc/encapsulate
    let encap_body = serde_json::json!({
        "algorithm": "MlKem768",
        "public_key_hex": pk_hex
    }).to_string();
    let encap_res = handle_pqc_encapsulate(&state, &encap_body).await
        .expect("Encapsulate API call must succeed");
    let encap_info: serde_json::Value = serde_json::from_str(&encap_res).expect("Encap JSON must parse");
    let ciphertext_hex = encap_info["ciphertext_hex"].as_str().unwrap().to_string();
    let shared_secret_sender = encap_info["shared_secret_hex"].as_str().unwrap().to_string();

    // 4. POST /api/pqc/decapsulate
    let decap_body = serde_json::json!({
        "key_id": key_id,
        "ciphertext_hex": ciphertext_hex
    }).to_string();
    let decap_res = handle_pqc_decapsulate(&state, &decap_body).await
        .expect("Decapsulate API call must succeed");
    let decap_info: serde_json::Value = serde_json::from_str(&decap_res).expect("Decap JSON must parse");
    let shared_secret_recipient = decap_info["shared_secret_hex"].as_str().unwrap().to_string();
    assert_eq!(shared_secret_sender, shared_secret_recipient, "API shared secrets must match exactly");

    // 5. POST /api/pqc/generate-keypair (ML-DSA-65) & Sign/Verify
    let dsa_key_res = handle_pqc_generate_keypair(&state, r#"{"algorithm":"MlDsa65"}"#).await
        .expect("DSA keygen must succeed");
    let dsa_info: serde_json::Value = serde_json::from_str(&dsa_key_res).expect("DSA JSON must parse");
    let dsa_pk_hex = dsa_info["public_key_hex"].as_str().unwrap().to_string();

    // Sign message
    let test_message = "Agent Octopus Swarm Attestation Block #108 - Cryptographic Verification";
    let sign_body = serde_json::json!({
        "message": test_message,
        "encoding": "utf8"
    }).to_string();
    let sign_res = handle_pqc_sign(&state, &sign_body).await
        .expect("Sign API call must succeed");
    let sig_info: serde_json::Value = serde_json::from_str(&sign_res).expect("Signature JSON must parse");
    let sig_hex = sig_info["signature_hex"].as_str().unwrap().to_string();
    assert_eq!(sig_info["signature_bytes_len"], 3309);

    // Verify signature
    let verify_body = serde_json::json!({
        "algorithm": "MlDsa65",
        "public_key_hex": dsa_pk_hex,
        "message": test_message,
        "signature_hex": sig_hex
    }).to_string();
    let verify_res = handle_pqc_verify(&state, &verify_body).await
        .expect("Verify API call must succeed");
    let verify_info: serde_json::Value = serde_json::from_str(&verify_res).expect("Verify JSON must parse");
    assert_eq!(verify_info["verified"], true);
    assert_eq!(verify_info["status"], "SIGNATURE_VALID");

    // 6. POST /api/pqc/audit-cbom
    let cbom_res = handle_pqc_audit_cbom(&state, "{}").expect("CBOM audit must succeed");
    let cbom: serde_json::Value = serde_json::from_str(&cbom_res).expect("CBOM JSON must parse");
    assert!(cbom["total_primitives_scanned"].as_u64().unwrap() >= 7);
    assert!(cbom["quantum_readiness_score"].as_f64().unwrap() > 0.0);
}
