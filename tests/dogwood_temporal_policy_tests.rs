use agent_octopus::security::audit::SecurityAuditLog;
use agent_octopus::security::cedar_arm::temporal::*;
use agent_octopus::security::CedarAuthorizationGateway;
use std::collections::HashMap;
use std::sync::Arc;

#[test]
fn test_dogwood_write_after_read_success() {
    let trace = Arc::new(TemporalEventTrace::default());
    let engine = DogwoodTemporalEngine::new(trace);

    let mut fields = HashMap::new();
    fields.insert("input.user".to_string(), serde_json::json!("alice"));
    fields.insert("input.document".to_string(), serde_json::json!("doc_42"));
    fields.insert("output.result".to_string(), serde_json::json!(true));

    // 1. Record past Read response at t = 1000
    engine.record_simulated_event(
        1000,
        "Drupe::Action::\"Read\"",
        EventKind::Response,
        "user_alice",
        "doc_42",
        fields,
    );

    // 2. Decision at t = 1500 (within 1h = 3600s)
    let mut ctx_fields = HashMap::new();
    ctx_fields.insert("input.user".to_string(), serde_json::json!("alice"));
    ctx_fields.insert("input.document".to_string(), serde_json::json!("doc_42"));

    let decision_ctx = DecisionContext {
        current_time_secs: 1500,
        principal: "user_alice".to_string(),
        resource: "doc_42".to_string(),
        context_fields: ctx_fields,
    };

    let policy = r#"when temporal { formerly within 1h Drupe::Action::"Read"::response{ input.user: context.input.user, input.document: context.input.document } };"#;
    let verdict = engine
        .evaluate_policy(policy, &decision_ctx)
        .expect("Should evaluate");
    assert!(
        verdict,
        "Write should be permitted because read occurred 500s ago (within 1h)"
    );
}

#[test]
fn test_dogwood_write_without_read_fails() {
    let trace = Arc::new(TemporalEventTrace::default());
    let engine = DogwoodTemporalEngine::new(trace);

    // Trace is empty! No Read occurred.
    let mut ctx_fields = HashMap::new();
    ctx_fields.insert("input.user".to_string(), serde_json::json!("alice"));
    ctx_fields.insert("input.document".to_string(), serde_json::json!("doc_42"));

    let decision_ctx = DecisionContext {
        current_time_secs: 1500,
        principal: "user_alice".to_string(),
        resource: "doc_42".to_string(),
        context_fields: ctx_fields,
    };

    let policy = r#"when temporal { formerly within 1h Drupe::Action::"Read"::response{ input.user: context.input.user, input.document: context.input.document } };"#;
    let verdict = engine
        .evaluate_policy(policy, &decision_ctx)
        .expect("Should evaluate");
    assert!(!verdict, "Write must be denied because no read occurred");
}

#[test]
fn test_dogwood_velocity_burst_rate_limiter() {
    let trace = Arc::new(TemporalEventTrace::default());
    let engine = DogwoodTemporalEngine::new(trace);

    // Record 4 rapid queries in last 5 minutes
    for i in 0..4 {
        let mut fields = HashMap::new();
        fields.insert("query_id".to_string(), serde_json::json!(i));
        engine.record_simulated_event(
            1000 + i * 20,
            "Octopus::Action::\"QueryTool\"",
            EventKind::Request,
            "agent_alpha",
            "db_tool",
            fields,
        );
    }

    let decision_ctx = DecisionContext {
        current_time_secs: 1100,
        principal: "agent_alpha".to_string(),
        resource: "db_tool".to_string(),
        context_fields: HashMap::new(),
    };

    // Forbid rule if count > 3
    let policy = r#"when temporal { (count for (t: Timepoint). where (formerly within 10m (Octopus::Action::"QueryTool"::request{ callerPrincipal: principal } && tp(t)))) > 3 };"#;
    let verdict = engine
        .evaluate_policy(policy, &decision_ctx)
        .expect("Should evaluate");
    assert!(
        verdict,
        "Rate limit condition should trigger (count is 4, > 3)"
    );
}

#[test]
fn test_dogwood_open_session_since_revocation() {
    let trace = Arc::new(TemporalEventTrace::default());
    let engine = DogwoodTemporalEngine::new(trace);

    let mut fields = HashMap::new();
    fields.insert("user".to_string(), serde_json::json!("bob"));

    // 1. Grant event at t = 2000
    engine.record_simulated_event(
        2000,
        "Octopus::Action::\"Grant\"",
        EventKind::Request,
        "user_bob",
        "secure_vault",
        fields.clone(),
    );

    // 2. Intervening innocuous events (heartbeats)
    engine.record_simulated_event(
        2100,
        "Octopus::Action::\"Heartbeat\"",
        EventKind::Request,
        "user_bob",
        "system",
        HashMap::new(),
    );

    let decision_ctx = DecisionContext {
        current_time_secs: 2200,
        principal: "user_bob".to_string(),
        resource: "secure_vault".to_string(),
        context_fields: HashMap::new(),
    };

    // Permitted if no Revoke has happened since Grant
    let policy = r#"when temporal { !Octopus::Action::"Revoke"::request{ callerPrincipal: principal } since within 24h Octopus::Action::"Grant"::request{ callerPrincipal: principal } };"#;
    let verdict = engine
        .evaluate_policy(policy, &decision_ctx)
        .expect("Should evaluate");
    assert!(
        verdict,
        "Session should be valid: grant exists and no revoke occurred since"
    );

    // 3. Now record a Revoke event at t = 2300
    engine.record_simulated_event(
        2300,
        "Octopus::Action::\"Revoke\"",
        EventKind::Request,
        "user_bob",
        "secure_vault",
        fields,
    );

    let decision_ctx_after_revoke = DecisionContext {
        current_time_secs: 2400,
        principal: "user_bob".to_string(),
        resource: "secure_vault".to_string(),
        context_fields: HashMap::new(),
    };

    let verdict2 = engine
        .evaluate_policy(policy, &decision_ctx_after_revoke)
        .expect("Should evaluate");
    assert!(!verdict2, "Session must fail: revoke occurred after grant!");
}

#[test]
fn test_dogwood_cumulative_spend_ceiling() {
    let trace = Arc::new(TemporalEventTrace::default());
    let engine = DogwoodTemporalEngine::new(trace);

    // Record 3 transfers of 200, 300, 400 (total = 900)
    for amount in [200, 300, 400] {
        let mut fields = HashMap::new();
        fields.insert("amount".to_string(), serde_json::json!(amount));
        engine.record_simulated_event(
            5000,
            "Octopus::Action::\"Transfer\"",
            EventKind::Response,
            "agent_treasury",
            "vault",
            fields,
        );
    }

    let decision_ctx = DecisionContext {
        current_time_secs: 5500,
        principal: "agent_treasury".to_string(),
        resource: "vault".to_string(),
        context_fields: HashMap::new(),
    };

    // Check sum > 800
    let policy = r#"when temporal { (sum amount for (amount: Long), (t: Timepoint). where (formerly within 1h (Octopus::Action::"Transfer"::response{ amount: amount } && tp(t)))) > 800 };"#;
    let verdict = engine
        .evaluate_policy(policy, &decision_ctx)
        .expect("Should evaluate");
    assert!(verdict, "Cumulative sum (900) exceeds threshold of 800");

    // Check sum > 1000
    let policy_high = r#"when temporal { (sum amount for (amount: Long), (t: Timepoint). where (formerly within 1h (Octopus::Action::"Transfer"::response{ amount: amount } && tp(t)))) > 1000 };"#;
    let verdict_high = engine
        .evaluate_policy(policy_high, &decision_ctx)
        .expect("Should evaluate");
    assert!(!verdict_high, "Cumulative sum (900) does not exceed 1000");
}

#[test]
fn test_dogwood_previous_step_sequencing() {
    let trace = Arc::new(TemporalEventTrace::default());
    let engine = DogwoodTemporalEngine::new(trace);

    // Record Step 1: CredentialsVerified at t = 3000
    engine.record_simulated_event(
        3000,
        "Octopus::Action::\"CredentialsVerified\"",
        EventKind::Response,
        "agent_operator",
        "cluster",
        HashMap::new(),
    );

    let decision_ctx = DecisionContext {
        current_time_secs: 3015, // 15s later
        principal: "agent_operator".to_string(),
        resource: "cluster".to_string(),
        context_fields: HashMap::new(),
    };

    // Permit ExecutePrivilegedCommand only if immediately preceded within 30s by CredentialsVerified
    let policy = r#"when temporal { previous within 30s Octopus::Action::"CredentialsVerified"::response{ callerPrincipal: principal } };"#;
    let verdict = engine
        .evaluate_policy(policy, &decision_ctx)
        .expect("Should evaluate");
    assert!(
        verdict,
        "Sequence permitted: immediate previous event was verification within 15s"
    );
}

#[test]
fn test_event_history_persistence_and_tamper_resistance() {
    let temp_dir = std::env::temp_dir().join(format!(
        "octopus_audit_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let audit_file = temp_dir.join("audit.jsonl");
    let durable_temporal_file = temp_dir.join("temporal_events.jsonl");

    let audit_log = Arc::new(SecurityAuditLog::with_disk_persistence(&audit_file));
    let trace = TemporalEventTrace::new_production(audit_log.clone(), &durable_temporal_file);

    assert!(
        !trace.is_simulation(),
        "Production trace must flag is_simulation as false"
    );

    // 1. Record authentic production event (uses SystemTime::now() monotonic timestamp)
    let mut fields = HashMap::new();
    fields.insert("doc_id".to_string(), serde_json::json!("classified_v1"));
    let event_id = trace.record_event(
        "Octopus::Action::\"LedgerRead\"",
        EventKind::Response,
        "agent_auditor",
        "classified_v1",
        fields,
    );

    assert_eq!(event_id, 0);
    assert_eq!(trace.len(), 1);

    let history = trace.get_history_up_to(None);
    assert_eq!(history.len(), 1);
    assert!(
        !history[0].record_hash.is_empty(),
        "Event must have cryptographic hash"
    );
    assert_ne!(history[0].record_hash, "SIMULATION_SANDBOX_HASH");

    // 2. Tamper resistance: attempting to clear() production history MUST be rejected
    let clear_result = trace.clear();
    assert!(
        clear_result.is_err(),
        "Clearing production temporal history must fail"
    );
    assert_eq!(
        trace.len(),
        1,
        "Trace length must remain intact after clear attempt"
    );

    // 3. File persistence check
    assert!(
        durable_temporal_file.exists(),
        "Durable log file must exist on disk"
    );
    let contents = std::fs::read_to_string(&durable_temporal_file).expect("File must be readable");
    assert!(
        contents.contains("LedgerRead"),
        "Durable log must contain recorded event"
    );

    // 4. Persistence recovery check: re-instantiate from same durable path
    let trace2 = TemporalEventTrace::new_production(audit_log, &durable_temporal_file);
    assert_eq!(
        trace2.len(),
        1,
        "Recovered trace must contain persisted event"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_simulation_vs_production_trace_isolation() {
    let temp_dir = std::env::temp_dir().join(format!(
        "octopus_iso_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let audit_file = temp_dir.join("audit.jsonl");
    let durable_temporal_file = temp_dir.join("temporal_events.jsonl");

    let audit_log = Arc::new(SecurityAuditLog::with_disk_persistence(&audit_file));
    let prod_engine = DogwoodTemporalEngine::new_production(audit_log, &durable_temporal_file);
    let sim_engine = DogwoodTemporalEngine::new_simulation();

    assert!(!prod_engine.is_simulation());
    assert!(sim_engine.is_simulation());

    // Record an event strictly into the simulation engine
    sim_engine.record_simulated_event(
        1000,
        "Octopus::Action::\"LedgerRead\"",
        EventKind::Response,
        "agent_adversary",
        "secret_vault",
        HashMap::new(),
    );

    // Verify complete isolation
    assert_eq!(sim_engine.trace().len(), 1, "Simulation engine has 1 event");
    assert_eq!(
        prod_engine.trace().len(),
        0,
        "Production engine must remain completely uncontaminated with 0 events"
    );
    assert!(
        !durable_temporal_file.exists(),
        "Simulation event must not create durable disk file"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_joint_cedar_dogwood_authorization_enforcement() {
    let secret = b"secret_seed_for_cedar_dogwood_test_32_bytes!!";
    let policy_fp = "test_fp_v1";

    let temp_dir = std::env::temp_dir().join(format!(
        "octopus_joint_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let audit_file = temp_dir.join("audit.jsonl");
    let durable_temporal_file = temp_dir.join("temporal_events.jsonl");

    let audit_log = Arc::new(SecurityAuditLog::with_disk_persistence(&audit_file));
    let prod_temporal = Arc::new(DogwoodTemporalEngine::new_production(
        audit_log.clone(),
        &durable_temporal_file,
    ));

    let gateway = CedarAuthorizationGateway::new(secret, policy_fp)
        .with_temporal_engine(prod_temporal.clone())
        .with_audit_log((*audit_log).clone());

    // Issue capability token for ledger_arm to invoke ledger_writer
    let token = gateway.auth_engine().issue_capability(
        "ledger_arm",
        "ledger_arm",
        agent_octopus::core::types::ArmRole::AccountingLedgerWrite,
        "ledger_writer",
        "Ledger",
    );

    // 1. Initial attempt: Cedar would permit (amount <= $100k and supervisor approved), but
    // Dogwood temporal prerequisite ("formerly within 1h LedgerRead") is NOT satisfied!
    // Must FAIL CLOSED!
    let supervisor_receipt = gateway
        .issue_supervisor_approval("supervisor_bob", "ledger_arm", "Ledger", 500_000, 300)
        .expect("Receipt");
    let untrusted_context = serde_json::json!({
        "amount_cents": 50000,
        "approved": true
    });

    let first_res = gateway.authorize_tool_invocation_with_approval(
        &token,
        "ledger_arm",
        "ledger_writer",
        "Ledger",
        untrusted_context.clone(),
        Some(&supervisor_receipt),
    );

    assert!(first_res.is_err(), "First attempt must be DENIED fail-closed because temporal prerequisite (LedgerRead) is missing");

    // 2. Now record genuine prerequisite event (LedgerRead) into the production temporal engine
    let mut read_fields = HashMap::new();
    read_fields.insert("input.user".to_string(), serde_json::json!("ledger_arm"));
    prod_temporal.record_event(
        "Octopus::Action::\"LedgerRead\"",
        EventKind::Response,
        "ledger_arm",
        "Ledger",
        read_fields,
    );

    // 3. Retry attempt: NOW both Cedar and Dogwood temporal policy permit!
    let second_res = gateway.authorize_tool_invocation_with_approval(
        &token,
        "ledger_arm",
        "ledger_writer",
        "Ledger",
        untrusted_context,
        Some(&supervisor_receipt),
    );

    assert!(
        second_res.is_ok(),
        "Second attempt must SUCCEED because both Cedar and Dogwood permit"
    );
    let verdict = second_res.unwrap();
    assert!(verdict.is_allowed);

    // 4. Verify the approved action was committed to the production temporal trace
    assert!(
        prod_temporal.trace().len() >= 2,
        "Production trace must contain both LedgerRead and the approved action"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}
