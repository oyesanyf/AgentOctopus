//! End-to-end integration tests for the CAGE Host-Kernel Containment Substrate (`actuator_04`),
//! RFC 8785 ECMAScript JCS (`2^63` float precision), loopback peer-PID anti-spoofing, and
//! Ed25519-sealed `QuarantineJournal`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use agent_octopus::security::breakouts::BreakoutDefenseCoordinator;
use agent_octopus::web::api::{handle_killswitch_disarm_with_peer, WebState};
use agent_octopus::web::request_guard::{is_cage_substrate_path, is_token_exempt_path};
use agent_octopus::{
    base64url_decode_no_pad, base64url_encode_no_pad, canonicalize_jcs, canonicalize_jcs_string,
    resolve_loopback_peer_pid, CageAttestationResponse, CageConformalBaselineResponse,
    CageConformalValidateResponse, CageQuarantineReceiptResponse,
    CageQuarantineReleaseReceiptResponse, CageSubstrateState, Cumulative24hTracker, JwksResponse,
    KeyedCumulative24hTracker, QuarantineJournal,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn parse_verifying_key_from_jwks(jwks_body: &str, expected_kid: &str) -> VerifyingKey {
    let jwks: JwksResponse = serde_json::from_str(jwks_body).expect("valid JWKS JSON");
    assert!(!jwks.keys.is_empty());
    let key = jwks
        .keys
        .iter()
        .find(|k| k.kid == expected_kid)
        .expect("matching kid in JWKS");
    assert_eq!(key.kty, "OKP");
    assert_eq!(key.crv, "Ed25519");
    assert_eq!(key.alg, "EdDSA");
    assert_eq!(key.r#use, "sig");
    assert_eq!(key.kid.len(), 64);

    let pub_bytes = base64url_decode_no_pad(&key.x).expect("valid base64url x");
    assert_eq!(pub_bytes.len(), 32);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pub_bytes);
    VerifyingKey::from_bytes(&arr).expect("valid Ed25519 VerifyingKey")
}

fn verify_domain_separated_envelope(
    vk: &VerifyingKey,
    domain_prefix: &[u8],
    unsigned_value: &Value,
    sig_b64: &str,
) {
    let canonical = canonicalize_jcs(unsigned_value).expect("JCS canonicalize");
    let mut preimage = domain_prefix.to_vec();
    preimage.extend_from_slice(&canonical);

    let sig_bytes = base64url_decode_no_pad(sig_b64).expect("base64url signature");
    assert_eq!(sig_bytes.len(), 64);
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&arr);
    vk.verify(&preimage, &sig)
        .expect("Ed25519 signature must verify over domain-separated JCS preimage");
}

#[test]
fn test_all_six_cage_substrate_endpoints_and_journal_chain() {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let state_dir = std::env::temp_dir().join(format!("octopus_cage_it_{}", ts));
    let _ = std::fs::remove_dir_all(&state_dir);

    let substrate = CageSubstrateState::with_state_dir(state_dir.clone());
    let coordinator = BreakoutDefenseCoordinator::default();

    // 1. GET /.well-known/jwks.json
    let (status_jwks, body_jwks) = substrate.handle_jwks();
    assert_eq!(status_jwks, "200 OK");
    let substrate_vk = parse_verifying_key_from_jwks(&body_jwks, &substrate.ed25519_kid);

    // 2. GET /v1/cage/normative-baseline/{region}
    let (status_base, body_base) = substrate.handle_conformal_baseline("us-central1");
    assert_eq!(status_base, "200 OK");
    let base_resp: CageConformalBaselineResponse = serde_json::from_str(&body_base).unwrap();
    assert_eq!(base_resp.region, "us-central1");
    assert_eq!(base_resp.calibration_size, 500);
    verify_domain_separated_envelope(
        &substrate_vk,
        b"CAGE_CONFORMAL_BASELINE_V1:",
        &json!({
            "region": base_resp.region,
            "alpha": base_resp.alpha,
            "calibration_size": base_resp.calibration_size,
            "nonconformity_threshold": base_resp.nonconformity_threshold,
            "timestamp_utc": base_resp.timestamp_utc,
            "kid": base_resp.kid,
        }),
        &base_resp.signature,
    );

    // 3. GET /v1/cage/attest
    let (status_att, body_att) = substrate.handle_attest();
    assert_eq!(status_att, "200 OK");
    let att_resp: CageAttestationResponse = serde_json::from_str(&body_att).unwrap();
    assert_eq!(att_resp.attestation_type, "HOST_TPM_PCR");
    assert!(att_resp.pcr_values.contains_key("0"));
    assert!(att_resp.pcr_values.contains_key("7"));
    verify_domain_separated_envelope(
        &substrate_vk,
        b"CAGE_ATTESTATION_RECEIPT_V1:",
        &json!({
            "attestation_type": att_resp.attestation_type,
            "ring0_posture": att_resp.ring0_posture,
            "tpm_pcr_quote": att_resp.tpm_pcr_quote,
            "pcr_values": att_resp.pcr_values,
            "timestamp_utc": att_resp.timestamp_utc,
            "kid": att_resp.kid,
        }),
        &att_resp.signature,
    );

    // 4. POST /v1/cage/conformal/validate (empty -> 400, conforming -> ALLOW, replay -> 409, outlier -> DENY)
    let (st_empty, _) =
        substrate.handle_conformal_validate(br#"{"scores":[],"nonce":"n_empty"}"#, &coordinator);
    assert_eq!(st_empty, "400 Bad Request");

    let valid_payload = json!({
        "scores": [0.5],
        "alpha": 0.05,
        "action": "read_telemetry",
        "nonce": "nonce_conf_ok_1"
    });
    let valid_bytes = serde_json::to_vec(&valid_payload).unwrap();
    let (st_ok, body_ok) = substrate.handle_conformal_validate(&valid_bytes, &coordinator);
    assert_eq!(st_ok, "200 OK");
    let conf_ok: CageConformalValidateResponse = serde_json::from_str(&body_ok).unwrap();
    assert!(conf_ok.admitted);
    assert_eq!(conf_ok.voter_consensus, "CONSENSUS_ALLOW");
    let expected_digest = hex::encode(Sha256::digest(canonicalize_jcs(&valid_payload).unwrap()));
    assert_eq!(
        conf_ok.envelope_digest.as_deref(),
        Some(expected_digest.as_str())
    );
    verify_domain_separated_envelope(
        &substrate_vk,
        b"CAGE_CONFORMAL_VALIDATION_V1:",
        &json!({
            "admitted": conf_ok.admitted,
            "p_value": conf_ok.p_value,
            "alpha": conf_ok.alpha,
            "voter_consensus": conf_ok.voter_consensus,
            "timestamp_utc": conf_ok.timestamp_utc,
            "envelope_digest": conf_ok.envelope_digest,
            "kid": conf_ok.kid,
        }),
        &conf_ok.signature,
    );

    // Replay nonce -> 409 Conflict
    let (st_replay, body_replay) = substrate.handle_conformal_validate(&valid_bytes, &coordinator);
    assert_eq!(st_replay, "409 Conflict");
    assert!(body_replay.contains("REPLAY_DETECTED"));

    // Outlier -> CONSENSUS_DENY
    let outlier_bytes = serde_json::to_vec(&json!({
        "scores": [20.0],
        "alpha": 0.05,
        "action": "read_telemetry",
        "nonce": "nonce_conf_outlier_2"
    }))
    .unwrap();
    let (st_deny, body_deny) = substrate.handle_conformal_validate(&outlier_bytes, &coordinator);
    assert_eq!(st_deny, "200 OK");
    let conf_deny: CageConformalValidateResponse = serde_json::from_str(&body_deny).unwrap();
    assert!(!conf_deny.admitted);
    assert_eq!(conf_deny.voter_consensus, "CONSENSUS_DENY");

    // 5. POST /v1/cage/quarantine
    let gov_sk = SigningKey::generate(&mut OsRng);
    let gov_vk = gov_sk.verifying_key();
    let gov_kid = hex::encode(Sha256::digest(gov_vk.to_bytes()));
    substrate.cage_key_manifest.register_key(&gov_kid, gov_vk);

    let q_payload = json!({
        "workload_id": "spiffe://cage.local/ns/prod/sa/arm-04",
        "target_pid": 42424,
        "trigger_reason": "CBF_SAFETY_BARRIER_BREACH",
        "rule_id": "RULE-SC-7-CBF-LETHAL",
        "nonce": "nonce_quar_001"
    });
    let q_bytes = serde_json::to_vec(&q_payload).unwrap();
    let q_jcs = canonicalize_jcs(&q_payload).unwrap();
    let mut q_preimage = b"CAGE_QUARANTINE_ASSERTION_V1:".to_vec();
    q_preimage.extend_from_slice(&q_jcs);
    let q_sig_b64 = base64url_encode_no_pad(&gov_sk.sign(&q_preimage).to_bytes());

    // Unknown kid -> 403
    let (st_unk, _) = substrate.handle_quarantine(Some(&q_sig_b64), Some("deadbeef"), &q_bytes);
    assert_eq!(st_unk, "403 Forbidden");

    // Bad signature -> 401
    let bad_sig = base64url_encode_no_pad(&[0u8; 64]);
    let (st_bad_sig, _) = substrate.handle_quarantine(Some(&bad_sig), Some(&gov_kid), &q_bytes);
    assert_eq!(st_bad_sig, "401 Unauthorized");

    // Valid quarantine -> 200 OK
    let (st_q, body_q) = substrate.handle_quarantine(Some(&q_sig_b64), Some(&gov_kid), &q_bytes);
    assert_eq!(st_q, "200 OK");
    let q_resp: CageQuarantineReceiptResponse = serde_json::from_str(&body_q).unwrap();
    assert!(q_resp.quarantined);
    assert_eq!(q_resp.status, "QUARANTINED");
    assert_eq!(q_resp.enforcement_plane, "HOST_OS_KERNEL");
    assert_eq!(q_resp.target_pid, Some(42424));
    assert_eq!(substrate.journal.unexpired_leases().len(), 1);

    verify_domain_separated_envelope(
        &substrate_vk,
        b"CAGE_QUARANTINE_RECEIPT_V1:",
        &json!({
            "status": q_resp.status,
            "quarantined": q_resp.quarantined,
            "enforcement_plane": q_resp.enforcement_plane,
            "rule_id": q_resp.rule_id,
            "quarantined_at": q_resp.quarantined_at,
            "target_pid": q_resp.target_pid,
            "envelope_digest": q_resp.envelope_digest,
            "kid": q_resp.kid,
        }),
        &q_resp.signature,
    );

    // Replay quarantine nonce -> 409 Conflict
    let (st_q_rep, _) = substrate.handle_quarantine(Some(&q_sig_b64), Some(&gov_kid), &q_bytes);
    assert_eq!(st_q_rep, "409 Conflict");

    // 6. POST /v1/cage/release (quorum < 2 -> 400, valid quorum >= 2 -> epoch 1 -> 2 & disarm)
    let low_quorum = json!({
        "workload_id": "spiffe://cage.local/ns/prod/sa/arm-04",
        "quorum_approval_digest": "a".repeat(64),
        "quorum_count": 1,
        "nonce": "nonce_rel_low"
    });
    let low_bytes = serde_json::to_vec(&low_quorum).unwrap();
    let mut low_pre = b"CAGE_QUARANTINE_RELEASE_V1:".to_vec();
    low_pre.extend_from_slice(&canonicalize_jcs(&low_quorum).unwrap());
    let low_sig = base64url_encode_no_pad(&gov_sk.sign(&low_pre).to_bytes());
    let (st_low, _) = substrate.handle_release(Some(&low_sig), Some(&gov_kid), &low_bytes);
    assert_eq!(st_low, "400 Bad Request");

    let rel_payload = json!({
        "workload_id": "spiffe://cage.local/ns/prod/sa/arm-04",
        "quorum_approval_digest": "b".repeat(64),
        "quorum_count": 2,
        "nonce": "nonce_rel_valid_1"
    });
    let rel_bytes = serde_json::to_vec(&rel_payload).unwrap();
    let mut rel_pre = b"CAGE_QUARANTINE_RELEASE_V1:".to_vec();
    rel_pre.extend_from_slice(&canonicalize_jcs(&rel_payload).unwrap());
    let rel_sig = base64url_encode_no_pad(&gov_sk.sign(&rel_pre).to_bytes());

    let (st_rel, body_rel) = substrate.handle_release(Some(&rel_sig), Some(&gov_kid), &rel_bytes);
    assert_eq!(st_rel, "200 OK");
    let rel_resp: CageQuarantineReleaseReceiptResponse = serde_json::from_str(&body_rel).unwrap();
    assert!(rel_resp.released);
    assert_eq!(rel_resp.epoch_before, 1);
    assert_eq!(rel_resp.epoch_after, 2);
    assert_eq!(rel_resp.outcome, "RELEASED");
    assert!(substrate.journal.unexpired_leases().is_empty());

    verify_domain_separated_envelope(
        &substrate_vk,
        b"CAGE_QUARANTINE_RELEASE_RECEIPT_V1:",
        &json!({
            "released": rel_resp.released,
            "enforcement_plane": rel_resp.enforcement_plane,
            "epoch_before": rel_resp.epoch_before,
            "epoch_after": rel_resp.epoch_after,
            "outcome": rel_resp.outcome,
            "released_at": rel_resp.released_at,
            "envelope_digest": rel_resp.envelope_digest,
            "kid": rel_resp.kid,
        }),
        &rel_resp.signature,
    );

    // Verify sealed journal reload & cryptographic hash-chain integrity
    let reloaded = QuarantineJournal::new(
        state_dir.clone(),
        Arc::clone(&substrate.signing_key),
        substrate.ed25519_kid.clone(),
    );
    assert!(reloaded.verify_hash_chain().unwrap());
    assert_eq!(reloaded.current_seq(), 3); // QUARANTINE + ADVANCE_EPOCH + RELEASE
    assert_eq!(
        reloaded.get_generation_epoch("spiffe://cage.local/ns/prod/sa/arm-04"),
        2
    );

    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn test_jcs_2_pow_63_trackers_request_guard_and_peer_pid_anti_spoofing() {
    // 1. JCS 2^63 precision & RFC 8785 compliance
    assert_eq!(
        canonicalize_jcs_string(&json!(9223372036854775808.0)).unwrap(),
        "9223372036854775808"
    );
    assert_eq!(
        canonicalize_jcs_string(&json!(-9223372036854775808.0)).unwrap(),
        "-9223372036854775808"
    );
    assert_eq!(canonicalize_jcs_string(&json!(-0.0)).unwrap(), "0");
    assert_eq!(canonicalize_jcs_string(&json!(1e21)).unwrap(), "1e+21");

    // 2. 24h sliding window accumulators
    let tracker = Cumulative24hTracker::new();
    tracker.record(1_000, 12.5);
    tracker.record(86_400_500, 7.5);
    assert!((tracker.get_cumulative_24h(86_401_500) - 7.5).abs() < 1e-9);

    let keyed = KeyedCumulative24hTracker::new();
    keyed.record("agent-a", 10_000, 40.0);
    keyed.record("agent-b", 10_000, 15.0);
    assert!((keyed.get_cumulative_24h("agent-a", 20_000) - 40.0).abs() < 1e-9);
    assert!((keyed.get_cumulative_24h("agent-b", 20_000) - 15.0).abs() < 1e-9);

    // 3. Request guard path classification
    assert!(is_token_exempt_path("/.well-known/jwks.json"));
    assert!(is_cage_substrate_path("/v1/cage/attest"));
    assert!(is_cage_substrate_path(
        "/v1/cage/normative-baseline/us-east1"
    ));
    assert!(is_cage_substrate_path("/v1/cage/conformal/validate"));
    assert!(is_cage_substrate_path("/v1/cage/quarantine"));
    assert!(is_cage_substrate_path("/v1/cage/release"));
    assert!(is_cage_substrate_path("/api/v1/cage/quarantine"));

    // 4. Live kernel TCP socket table peer-PID resolution & disarm anti-spoofing
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bound_port = listener.local_addr().unwrap().port();
    let client = std::net::TcpStream::connect(("127.0.0.1", bound_port)).unwrap();
    let peer_addr = client.local_addr().unwrap();
    let (_accepted, _) = listener.accept().unwrap();

    let resolved_pid = resolve_loopback_peer_pid(peer_addr, bound_port).unwrap();
    assert_eq!(resolved_pid, std::process::id());

    let state = WebState::default();
    let spoofed_body = json!({
        "operator": "spoofing_actor",
        "reason": "attempting unauthorized disarm",
        "caller_pid": resolved_pid.wrapping_add(99999)
    })
    .to_string();
    let (st_spoof, body_spoof) =
        handle_killswitch_disarm_with_peer(&state, &spoofed_body, Some(peer_addr), bound_port);
    assert_eq!(st_spoof, "403 Forbidden");
    assert!(body_spoof.contains("CALLER_PID_SPOOF_DETECTED"));

    let authentic_body = json!({
        "operator": "verified_local_cli",
        "reason": "authenticated local disarm",
        "caller_pid": resolved_pid
    })
    .to_string();
    let (st_auth, _) =
        handle_killswitch_disarm_with_peer(&state, &authentic_body, Some(peer_addr), bound_port);
    assert_eq!(st_auth, "200 OK");
}
