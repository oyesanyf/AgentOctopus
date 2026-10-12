use agent_octopus::security::cedar_arm::temporal::*;
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
    engine.record_event(
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
    let verdict = engine.evaluate_policy(policy, &decision_ctx).expect("Should evaluate");
    assert!(verdict, "Write should be permitted because read occurred 500s ago (within 1h)");
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
    let verdict = engine.evaluate_policy(policy, &decision_ctx).expect("Should evaluate");
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
        engine.record_event(
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
    let verdict = engine.evaluate_policy(policy, &decision_ctx).expect("Should evaluate");
    assert!(verdict, "Rate limit condition should trigger (count is 4, > 3)");
}

#[test]
fn test_dogwood_open_session_since_revocation() {
    let trace = Arc::new(TemporalEventTrace::default());
    let engine = DogwoodTemporalEngine::new(trace);

    let mut fields = HashMap::new();
    fields.insert("user".to_string(), serde_json::json!("bob"));

    // 1. Grant event at t = 2000
    engine.record_event(
        2000,
        "Octopus::Action::\"Grant\"",
        EventKind::Request,
        "user_bob",
        "secure_vault",
        fields.clone(),
    );

    // 2. Intervening innocuous events (heartbeats)
    engine.record_event(
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
    let verdict = engine.evaluate_policy(policy, &decision_ctx).expect("Should evaluate");
    assert!(verdict, "Session should be valid: grant exists and no revoke occurred since");

    // 3. Now record a Revoke event at t = 2300
    engine.record_event(
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

    let verdict2 = engine.evaluate_policy(policy, &decision_ctx_after_revoke).expect("Should evaluate");
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
        engine.record_event(
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
    let verdict = engine.evaluate_policy(policy, &decision_ctx).expect("Should evaluate");
    assert!(verdict, "Cumulative sum (900) exceeds threshold of 800");

    // Check sum > 1000
    let policy_high = r#"when temporal { (sum amount for (amount: Long), (t: Timepoint). where (formerly within 1h (Octopus::Action::"Transfer"::response{ amount: amount } && tp(t)))) > 1000 };"#;
    let verdict_high = engine.evaluate_policy(policy_high, &decision_ctx).expect("Should evaluate");
    assert!(!verdict_high, "Cumulative sum (900) does not exceed 1000");
}

#[test]
fn test_dogwood_previous_step_sequencing() {
    let trace = Arc::new(TemporalEventTrace::default());
    let engine = DogwoodTemporalEngine::new(trace);

    // Record Step 1: CredentialsVerified at t = 3000
    engine.record_event(
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
    let verdict = engine.evaluate_policy(policy, &decision_ctx).expect("Should evaluate");
    assert!(verdict, "Sequence permitted: immediate previous event was verification within 15s");
}
