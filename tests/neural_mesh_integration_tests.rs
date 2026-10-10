use agent_octopus::neural_mesh::{MessageKind, MeshError, NeuralMesh};
use agent_octopus::core::types::{ArmRole, OctopusSecurityError};
use agent_octopus::security::capabilities::ExternalAuthorizationEngine;

#[tokio::test]
async fn test_tri_path_neural_communication_flow() {
    // Communication routes covering all three paths:
    // 1. Brain to Arm: ("brain", "vulnerability")
    // 2. Arm to Arm: ("vulnerability", "atlas"), ("atlas", "attack_chain")
    // 3. Arm to Supervisor: ("attack_chain", "supervisor")
    let mesh = NeuralMesh::new([
        ("brain".to_string(), "vulnerability".to_string()),
        ("vulnerability".to_string(), "atlas".to_string()),
        ("atlas".to_string(), "attack_chain".to_string()),
        ("attack_chain".to_string(), "supervisor".to_string()),
    ]);

    let (brain_ep, _) = mesh.enroll("brain", 16).await.unwrap();
    let (vuln_ep, mut vuln_rx) = mesh.enroll("vulnerability", 16).await.unwrap();
    let (atlas_ep, mut atlas_rx) = mesh.enroll("atlas", 16).await.unwrap();
    let (chain_ep, mut chain_rx) = mesh.enroll("attack_chain", 16).await.unwrap();
    let (_, mut supervisor_rx) = mesh.enroll("supervisor", 16).await.unwrap();

    // --- Path 1: Brain to Arm ---
    brain_ep.send(
        "vulnerability",
        MessageKind::Finding, // Using available MessageKind variant
        "task-directive-001",
        "Scan system configurations and delegation policies",
    ).await.unwrap();

    let brain_msg = vuln_rx.recv().await.unwrap();
    assert_eq!(brain_msg.sender, "brain");
    assert_eq!(brain_msg.content, "Scan system configurations and delegation policies");

    // --- Path 2: Arm to Arm (Vulnerability -> ATLAS -> Attack Chain) ---
    vuln_ep.send(
        "atlas",
        MessageKind::Finding,
        "vuln-finding-001",
        "Discovered overly permissive network allowlist: evil.com",
    ).await.unwrap();

    let atlas_msg = atlas_rx.recv().await.unwrap();
    assert_eq!(atlas_msg.sender, "vulnerability");
    assert_eq!(atlas_msg.correlation_id, "vuln-finding-001");

    // ATLAS maps to AML.T0031 (Command and Control) and forwards to Attack Chain Arm
    atlas_ep.send(
        "attack_chain",
        MessageKind::ThreatMapping,
        "threat-atlas-aml-t0031",
        "Mapped to MITRE ATLAS technique AML.T0031 Command and Control",
    ).await.unwrap();

    let chain_msg = chain_rx.recv().await.unwrap();
    assert_eq!(chain_msg.sender, "atlas");
    assert_eq!(chain_msg.kind, MessageKind::ThreatMapping);

    // --- Path 3: Arm to Security Supervisor (Independent Alert) ---
    chain_ep.send(
        "supervisor",
        MessageKind::Alert,
        "alert-attack-chain-001",
        "High-confidence attack chain synthesized: isolate egress arm immediately",
    ).await.unwrap();

    let supervisor_msg = supervisor_rx.recv().await.unwrap();
    assert_eq!(supervisor_msg.sender, "attack_chain");
    assert_eq!(supervisor_msg.kind, MessageKind::Alert);
    assert!(supervisor_msg.content.contains("isolate egress arm immediately"));
}

#[tokio::test]
async fn test_neural_mesh_information_exchange_without_permission_exchange() {
    let mesh = NeuralMesh::new([
        ("vulnerability".to_string(), "atlas".to_string()),
    ]);

    let (vuln_ep, _) = mesh.enroll("vulnerability", 8).await.unwrap();
    let (_, mut atlas_rx) = mesh.enroll("atlas", 8).await.unwrap();

    // Vulnerability Arm sends finding to ATLAS Arm
    vuln_ep.send(
        "atlas",
        MessageKind::Finding,
        "finding-ledger-access",
        "Attempted access to AccountingLedgerWrite tool",
    ).await.unwrap();

    let msg = atlas_rx.recv().await.unwrap();
    assert_eq!(msg.content, "Attempted access to AccountingLedgerWrite tool");

    // Invariant: The receiving arm holds the structured information,
    // but CANNOT invoke the tool because it holds no capability token.
    let auth_engine = ExternalAuthorizationEngine::new(b"auth_secret", 300, "policy_v1");
    let atlas_token = auth_engine.issue_capability(
        "brain",
        "atlas_arm",
        ArmRole::UntrustedDocIngest,
        "doc_extractor",
        "s3://invoices/",
    );

    // Attempting to invoke ledger_writer fails authorization regardless of neural mesh message
    let auth_result = auth_engine.verify_capability(
        &atlas_token,
        "atlas_arm",
        "ledger_writer",
        "s3://invoices/",
    );
    assert!(matches!(auth_result, Err(OctopusSecurityError::CapabilityDenied(_))));
}

#[tokio::test]
async fn test_neural_mesh_unauthorized_routes_and_oversize_protection() {
    let mesh = NeuralMesh::new([
        ("arm_a".to_string(), "arm_b".to_string()),
    ]);

    let (a_ep, _) = mesh.enroll("arm_a", 4).await.unwrap();
    let (b_ep, _) = mesh.enroll("arm_b", 4).await.unwrap();
    let (_, _) = mesh.enroll("arm_c", 4).await.unwrap();

    // 1. Arm B attempting to send to Arm A (reverse route not in allowlist)
    let rev_err = b_ep.send("arm_a", MessageKind::Finding, "id-1", "hello").await;
    assert_eq!(rev_err, Err(MeshError::ForbiddenRoute));

    // 2. Arm A attempting to send to Arm C (unpermitted destination)
    let unperm_err = a_ep.send("arm_c", MessageKind::Finding, "id-2", "hello").await;
    assert_eq!(unperm_err, Err(MeshError::ForbiddenRoute));

    // 3. Sending to an un-enrolled node
    let unk_err = a_ep.send("ghost_node", MessageKind::Finding, "id-3", "hello").await;
    assert_eq!(unk_err, Err(MeshError::ForbiddenRoute));

    // 4. Oversize payload rejection (> 16 KB)
    let huge_content = "X".repeat(17 * 1024);
    let oversize_err = a_ep.send("arm_b", MessageKind::Finding, "id-4", &huge_content).await;
    assert_eq!(oversize_err, Err(MeshError::Oversize));
}
