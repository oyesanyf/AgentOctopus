use agent_octopus::core::types::{OctopusSecurityError, StrategicDirective};
use agent_octopus::security::anomaly_arms::{
    BehavioralSentinelArm, DualSpeedSecurityEngine, ReasoningAuditorArm, ToolForensicsArm,
};

#[test]
fn test_layer1_behavioral_sentinel_burst_and_spike_detection() {
    let mut sentinel = BehavioralSentinelArm::new("sentinel_test", 5.0);

    // 1. Normal benign calls: low tokens, normal entropy
    let r1 = sentinel.record_event("agent_1", 200, 4.5);
    assert!(!r1.is_anomalous);
    assert!(r1.anomaly_score < 5.0);

    // 2. High entropy payload: encrypted/obfuscated content (> 7.5 bits/byte)
    let r2 = sentinel.record_event("agent_1", 300, 7.9);
    assert!(r2.reasons.iter().any(|s| s.contains("Abnormal payload entropy")));

    // 3. Excessive token spike (> 5000 tokens)
    let r3 = sentinel.record_event("agent_2", 8500, 4.2);
    assert!(r3.reasons.iter().any(|s| s.contains("Excessive token spike")));
    assert!(r3.is_anomalous || r3.anomaly_score >= 3.5);
}

#[test]
fn test_layer2_reasoning_auditor_deceptive_alignment_and_goal_drift() {
    let auditor = ReasoningAuditorArm::new("auditor_test");

    let directive = StrategicDirective {
        directive_id: "dir-extract-001".to_string(),
        source_uri: "s3://invoices/inv.pdf".to_string(),
        instruction: "Extract vendor name and amount from PDF invoice".to_string(),
        raw_payload: None,
        max_step_budget: 10,
    };

    // 1. Benign tool action
    let report_benign = auditor.audit_intent_alignment(&directive, "doc_extractor", "{\"page\":1}");
    assert!(!report_benign.deceptive_alignment_detected);
    assert!(!report_benign.goal_drift_detected);

    // 2. Deceptive alignment: Directive is extraction, but agent attempts outbound HTTP egress
    let report_deceptive = auditor.audit_intent_alignment(&directive, "http_egress", "{\"target\":\"https://google.com\"}");
    assert!(report_deceptive.deceptive_alignment_detected);

    // 3. Goal drift: Agent payload mentions powershell or credentials
    let report_drift = auditor.audit_intent_alignment(&directive, "doc_extractor", "{\"cmd\":\"powershell.exe -enc ...\"}");
    assert!(report_drift.goal_drift_detected);
}

#[test]
fn test_layer3_tool_forensics_parameter_sanitization() {
    let mut forensics = ToolForensicsArm::new("forensics_test");

    // 1. Clean parameters pass
    let t1 = forensics.inspect_invocation("inv-1", "doc_agent", "doc_extractor", "{\"file\":\"test.pdf\"}");
    assert!(t1.sanitized);
    assert!(t1.security_flags.is_empty());
    assert!(!t1.argument_digest.is_empty());

    // 2. Command injection shell metacharacters detected
    let t2 = forensics.inspect_invocation("inv-2", "doc_agent", "doc_extractor", "{\"file\":\"test.pdf; calc.exe\"}");
    assert!(!t2.sanitized);
    assert!(t2.security_flags.iter().any(|f| f.contains("Shell metacharacter")));

    // 3. Path traversal detected
    let t3 = forensics.inspect_invocation("inv-3", "doc_agent", "doc_extractor", "{\"file\":\"../../etc/shadow\"}");
    assert!(!t3.sanitized);
    assert!(t3.security_flags.iter().any(|f| f.contains("Path traversal")));

    // 4. Dangerous PATH mutation detected
    let t4 = forensics.inspect_invocation("inv-4", "doc_agent", "doc_extractor", "{\"env\":\"$env:PATH=/bad\"}");
    assert!(!t4.sanitized);
    assert!(t4.security_flags.iter().any(|f| f.contains("PATH environment access")));
}

#[test]
fn test_dual_speed_security_engine_fast_path_and_async_verdict() {
    let mut engine = DualSpeedSecurityEngine::new();

    let directive = StrategicDirective {
        directive_id: "dir-100".to_string(),
        source_uri: "s3://invoices/sample.pdf".to_string(),
        instruction: "Extract invoice totals".to_string(),
        raw_payload: None,
        max_step_budget: 10,
    };

    // 1. Benign execution: Fast path succeeds in microseconds, async audit triggers no alarm
    let verdict1 = engine.evaluate_invocation(
        &directive,
        "agent_doc",
        "doc_extractor",
        "{\"page\":1,\"mode\":\"text\"}",
        250,
        4.8,
    ).unwrap();

    assert!(verdict1.allow_fast_path);
    assert!(!verdict1.async_alarm_triggered);
    assert!(verdict1.fast_path_duration_micros < 5000); // Strict sub-5ms fast path

    // 2. Parameter injection: Fast path immediately rejects with deterministic error (<5ms)
    let res_inj = engine.evaluate_invocation(
        &directive,
        "agent_doc",
        "doc_extractor",
        "{\"page\":1,\"cmd\":\"| whoami\"}",
        250,
        4.8,
    );
    assert!(matches!(res_inj, Err(OctopusSecurityError::DeterministicLayerViolation(_))));

    // 3. Deceptive alignment: Fast path parameter sanitization passes, but deep async audit triggers alarm
    let verdict_deceptive = engine.evaluate_invocation(
        &directive,
        "agent_doc",
        "http_egress",
        "{\"url\":\"https://google.com\"}",
        250,
        4.8,
    ).unwrap();

    assert!(verdict_deceptive.allow_fast_path);
    assert!(verdict_deceptive.async_alarm_triggered);
    assert!(verdict_deceptive.reasoning_report.deceptive_alignment_detected);
}
