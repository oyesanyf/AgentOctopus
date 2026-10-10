use agent_octopus::core::merkle::{MerkleLeaf, MerkleTree};
use agent_octopus::ledger::receipt::SignedExecutionReceipt;
use agent_octopus::security::atlas_arm::{
    AtlasCoverageMatrix, AtlasParser, AtlasSyncManager, AtlasTestGenerator, EvidenceValidator,
    MitigationStatus, MitreAtlasMatrix, TechniqueMapper, ThreatCorrelator, ThreatFeasibility,
};
use agent_octopus::security::audit::SecurityAuditLog;
use agent_octopus::security::guard_arms::GuardCoordinator;
use agent_octopus::security::research_arms::{
    AttackChainArm, ChainValidator, RiskScoringEngine, TrustedTestController, VulnerabilityArm,
    VulnerabilitySeverity,
};

#[test]
fn test_vulnerability_arm_system_audit() {
    let mut vuln_arm = VulnerabilityArm::new("vuln_research_01");

    let vulns = vuln_arm.audit_system_configuration(
        0,
        5,
        1200,
        &["google.com".to_string(), "evil.com".to_string()],
        256 * 1024 * 1024,
    );

    assert_eq!(vulns.len(), 5);
    assert!(vulns.iter().any(|v| v.vuln_id == "OCT-VULN-001" && v.severity == VulnerabilitySeverity::Critical));
    assert!(vulns.iter().any(|v| v.vuln_id == "OCT-VULN-002" && v.severity == VulnerabilitySeverity::High));
    assert!(vulns.iter().any(|v| v.vuln_id == "OCT-VULN-003" && v.severity == VulnerabilitySeverity::Medium));
    assert!(vulns.iter().any(|v| v.vuln_id == "OCT-VULN-004" && v.severity == VulnerabilitySeverity::Critical));
    assert!(vulns.iter().any(|v| v.vuln_id == "OCT-VULN-005" && v.severity == VulnerabilitySeverity::High));
}

#[test]
fn test_attack_chain_synthesis_and_validation() {
    let mut vuln_arm = VulnerabilityArm::new("vuln_research_01");
    let vulns = vuln_arm.audit_system_configuration(
        500_000,
        4,
        300,
        &["google.com".to_string(), "evil.com".to_string()],
        64 * 1024 * 1024,
    );

    let chain_arm = AttackChainArm::new("chain_arm_01");
    let chains = chain_arm.synthesize_attack_chains(&vulns);
    assert!(!chains.is_empty());

    let mut coordinator = GuardCoordinator::new(b"seed_123", "policy_v1");

    for chain in &chains {
        let report = ChainValidator::validate_chain(chain, &mut coordinator);
        assert!(
            report.fully_neutralized,
            "Attack chain {} was not neutralized!",
            chain.chain_id
        );
        assert!(report.severed_at_step.is_some());
    }
}

#[test]
fn test_risk_scoring_engine() {
    let mut vuln_arm = VulnerabilityArm::new("vuln_research_01");
    let vulns = vuln_arm.audit_system_configuration(
        500_000,
        2,
        300,
        &["google.com".to_string()],
        64 * 1024 * 1024,
    );

    let chain_arm = AttackChainArm::new("chain_arm_01");
    let chains = chain_arm.synthesize_attack_chains(&vulns);

    let mut coordinator = GuardCoordinator::new(b"seed_123", "policy_v1");
    let validation_reports: Vec<_> = chains
        .iter()
        .map(|c| ChainValidator::validate_chain(c, &mut coordinator))
        .collect();

    let score = RiskScoringEngine::evaluate_swarm_risk(&vulns, &chains, &validation_reports);
    assert_eq!(score.defense_mitigation_rate, 1.0);
    assert!(score.composite_score < 2.0);
}

#[test]
fn test_trusted_test_controller_enforces_sandbox() {
    let mut controller = TrustedTestController::new();
    assert!(controller.is_active());

    assert!(controller.authorize_test_action("test://invoice/sample.pdf").is_ok());
    assert!(controller.authorize_test_action("s3://invoices/test_batch/").is_ok());

    assert!(controller.authorize_test_action("prod://database/live_keys").is_err());
    assert!(controller.authorize_test_action(".octopus_security_audit.log").is_err());
}

#[test]
fn test_atlas_sync_manager_and_parser() {
    let sync_mgr = AtlasSyncManager::default();

    // 1. Ingest valid payload from trusted source
    let sample_payload = b"version: 2026.02\ntactics: 16\ntechniques: 208\nmitigations: 40\ncase_studies: 73\n";
    let meta = sync_mgr.verify_and_ingest(
        "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/atlas.yaml",
        "2026.02",
        sample_payload,
        None,
    ).unwrap();

    assert_eq!(meta.dataset_version, "2026.02");
    assert_eq!(meta.total_tactics, 16);
    assert_eq!(meta.total_techniques, 208);
    assert_eq!(meta.total_mitigations, 40);
    assert_eq!(meta.total_case_studies, 73);

    // 2. Untrusted publication source rejected
    let untrusted_res = sync_mgr.verify_and_ingest(
        "https://attacker.evil.com/fake_atlas.yaml",
        "2026.02",
        sample_payload,
        None,
    );
    assert!(untrusted_res.is_err());

    // 3. Parse authoritative bundle into knowledge base
    let matrix = MitreAtlasMatrix::new();
    let parsed_kb = AtlasParser::parse_authoritative_bundle(&matrix);
    assert_eq!(parsed_kb.tactics.len(), 16);
    assert!(parsed_kb.mitigations.contains_key("AML.M1004"));
    assert!(parsed_kb.case_studies.contains_key("AML.CS001"));
}

#[test]
fn test_technique_mapper_and_threat_correlator() {
    let mapper = TechniqueMapper::new();

    // Map configuration finding to ATLAS technique
    let mapped = mapper.map_finding(
        "OCT-VULN-002",
        "delegation::DelegationScopeGuard",
        ThreatFeasibility::Demonstrated,
        "Excessive delegation depth permits lateral capability expansion",
    ).unwrap();

    assert_eq!(mapped.atlas_technique_id, "AML.T0016"); // Obtain Capabilities
    assert_eq!(mapped.feasibility, ThreatFeasibility::Demonstrated);

    // Dynamic prompt injection mapping
    let mapped_injection = mapper.map_finding(
        "PROMPT_INJECTION_PDF",
        "doc_extractor",
        ThreatFeasibility::Realized,
        "Adversary attempted instruction override",
    ).unwrap();
    assert_eq!(mapped_injection.atlas_technique_id, "AML.T0051");

    // Correlate multi-step attack chain using ATLAS relationships
    let correlator = ThreatCorrelator::new();
    let records = vec![mapped, mapped_injection];
    let synthesized_chains = correlator.correlate_chains(&records);

    assert!(!synthesized_chains.is_empty());
    let chain = &synthesized_chains[0];
    assert_eq!(chain.chain_id, "CHAIN-ATLAS-CORRELATED-01");
    assert!(chain.steps.len() >= 3);
}

#[test]
fn test_coverage_matrix_prevention_vs_detection() {
    let matrix = MitreAtlasMatrix::new();
    let coverage = AtlasCoverageMatrix::build(&matrix);

    // Invariant: Escape to Host (AML.T0000) must be PreventedAtBoundary by Windows Job Object / AppContainer
    let escape_cov = coverage.get_coverage("AML.T0000").unwrap();
    assert_eq!(escape_cov.status, MitigationStatus::PreventedAtBoundary);
    assert!(escape_cov.primary_enforcement_boundary.contains("Windows Job Object"));
    assert!(!escape_cov.empirical_evidence_reference.is_empty());

    // Prompt injection (AML.T0051) must be PreventedAtBoundary by Schema Lexer
    let injection_cov = coverage.get_coverage("AML.T0051").unwrap();
    assert_eq!(injection_cov.status, MitigationStatus::PreventedAtBoundary);

    // Resource hijacking (AML.T0042) is DetectedPostExecution by Anomaly Watchdog
    let dos_cov = coverage.get_coverage("AML.T0042").unwrap();
    assert_eq!(dos_cov.status, MitigationStatus::DetectedPostExecution);

    // Summary statistics
    let summary = coverage.summary();
    assert!(summary.prevented_at_boundary_count >= 10);
    assert!(summary.detected_post_execution_count >= 1);
    assert!(summary.verified_prevention_rate > 80.0);
    assert!(summary.total_coverage_percentage > 90.0);
}

#[test]
fn test_evidence_validator_with_cryptographic_artifacts() {
    // 1. Validate Ed25519 execution receipt
    let mut csprng = rand::rngs::OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
    let receipt = SignedExecutionReceipt::create_and_sign(
        1,
        "arm_doc",
        "doc_extract",
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
        &signing_key,
    );
    let verdict_receipt = EvidenceValidator::validate_execution_receipt("AML.T0001", &receipt).unwrap();
    assert!(verdict_receipt.is_empirically_verified);
    assert_eq!(verdict_receipt.evidence_type, "Ed25519 Signed Execution Receipt");

    // 2. Validate Merkle inclusion proof
    let leaf1 = MerkleLeaf::new(0, "doc_extractor", "arg1", "out1");
    let leaf2 = MerkleLeaf::new(1, "ledger_writer", "arg2", "out2");
    let tree = MerkleTree::from_leaves(vec![leaf1, leaf2]);
    let proof = tree.generate_proof(0).unwrap();
    let verdict_merkle = EvidenceValidator::validate_merkle_inclusion_proof("AML.T0043", &proof, &tree.root()).unwrap();
    assert!(verdict_merkle.is_empirically_verified);

    // 3. Validate audit log hash chain
    let audit_log = SecurityAuditLog::new();
    audit_log.record_event("ISOLATION", "supervisor", "AppContainer profile active", "ENFORCE");
    audit_log.record_event("TASK", "arm_doc", "Extracted invoice", "ALLOW");
    let verdict_audit = EvidenceValidator::validate_audit_chain("AML.T0000", &audit_log).unwrap();
    assert!(verdict_audit.is_empirically_verified);
}

#[test]
fn test_atlas_test_generator_with_test_controller() {
    let mut controller = TrustedTestController::new();
    let suite = AtlasTestGenerator::generate_test_suite();

    assert_eq!(suite.len(), 6);
    for tc in suite {
        // Authorize test in sandbox envelope
        assert!(controller.authorize_test_action(&format!("test://atlas/{}", tc.technique_id)).is_ok());
        assert!(tc.expected_blocked);
        assert!(!tc.target_component.is_empty());
    }
}

#[test]
fn test_dynamic_atlas_stix_ingestion_and_test_synthesis() {
    let sync_mgr = AtlasSyncManager::default();
    let cache_path = "data/atlas_stix/stix-atlas.json";
    let (meta, kb) = sync_mgr.sync_or_load_stix(cache_path).expect("Failed to sync or load STIX bundle");

    assert_eq!(meta.total_tactics, 16);
    assert_eq!(meta.total_techniques, 208);
    assert_eq!(meta.total_mitigations, 40);
    assert_eq!(meta.total_case_studies, 73);

    // Generate dynamic tests for all 208 techniques
    let dynamic_suite = AtlasTestGenerator::generate_dynamic_test_suite(&kb);
    assert_eq!(dynamic_suite.len(), 208);

    // Verify key techniques are mapped correctly
    assert!(dynamic_suite.iter().any(|t| t.technique_id == "AML.T0000" && t.target_component == "cedar_arm::CedarAuthorizationGateway"));
    assert!(dynamic_suite.iter().any(|t| t.technique_id == "AML.T0051" && t.target_component == "doc_extractor"));
    assert!(dynamic_suite.iter().any(|t| t.technique_id == "AML.T0054" && t.target_component == "doc_extractor"));
    assert!(dynamic_suite.iter().any(|t| t.technique_id == "AML.T0016" && t.target_component == "guard_arms::capability_guard"));
    assert!(dynamic_suite.iter().any(|t| t.technique_id == "AML.T0025" && t.target_component == "guard_arms::network_guard"));
    assert!(dynamic_suite.iter().any(|t| t.technique_id == "AML.T0031" && t.target_component == "governor::OutOfBandCircuitBreaker"));
}

#[test]
fn test_continuous_oss_fuzz_arm() {
    use agent_octopus::security::oss_fuzz_arm::ContinuousOssFuzzArm;

    let arm = ContinuousOssFuzzArm::new();

    // Run 50 continuous fuzzing mutations across all 5 targets
    let report = arm.run_continuous_fuzz_cycle(50);
    assert_eq!(report.targets.len(), 5);
    assert!(report.total_executions >= 50);
    assert_eq!(report.crashes_prevented, 0);

    // Verify CIFuzz SARIF export
    let sarif = arm.generate_cifuzz_sarif_report();
    let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("SARIF must be valid JSON");
    assert_eq!(parsed["version"], "2.1.0");
    assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "Google OSS-Fuzz Continuous Runtime Arm (Agent Octopus)");
}

#[test]
fn test_continuous_osv_scanner_arm() {
    use agent_octopus::security::osv_scanner_arm::ContinuousOsvScannerArm;

    let arm = ContinuousOsvScannerArm::default();
    let report = arm.run_continuous_scan();

    // Verify real Cargo.lock dependencies were parsed and scanned against Google OSV
    assert!(report.total_dependencies_scanned >= 300);
    assert!(report.health_score_pct >= 80.0);
    assert!(!report.supply_chain_security_posture.is_empty());

    // Verify OSV SARIF export
    let sarif = arm.generate_osv_sarif_report();
    let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("OSV SARIF must be valid JSON");
    assert_eq!(parsed["version"], "2.1.0");
    assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "Google OSV-Scanner Continuous Arm (Agent Octopus)");
}

