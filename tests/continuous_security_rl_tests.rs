use agent_octopus::security::breakouts::{
    BehavioralBreakoutGuard, BreakoutDefenseCoordinator, DataBreakoutGuard,
    OperationalContainmentGuard, TechnicalBreakoutGuard,
};
use agent_octopus::security::continuous_eval::ContinuousEvaluationEngine;
use agent_octopus::security::rl_defense::{
    AdaptiveDefenseAction, AdaptiveRlDefenseEngine, AdaptiveStateVector,
};
use agent_octopus::telemetry::otel::{OtelSessionTelemetry, OtelSpanKind, OtelStatusCode};
use std::sync::Arc;

#[test]
fn test_technical_breakout_guard_intercepts_unmasked_docker_socket() {
    let guard = TechnicalBreakoutGuard::default();

    // 1. Docker socket probe inside container
    let verdict = guard.evaluate_execution("/var/run/docker.sock", "POST /v1.41/containers/create");
    assert!(!verdict.is_clean);
    assert!(verdict.sandbox_quarantine_required);
    assert!(verdict
        .detected_vectors
        .iter()
        .any(|v| v.contains("docker.sock")));

    // 2. Windows named pipe container engine probe
    let verdict2 =
        guard.evaluate_execution(r"\\.\pipe\docker_engine", "docker run -v /:/host alpine");
    assert!(!verdict2.is_clean);

    // 3. Clean execution
    let clean = guard.evaluate_execution("standard_worker.py", "print('hello world')");
    assert!(clean.is_clean);
}

#[test]
fn test_operational_containment_guard_scrubs_cloud_credentials() {
    let guard = OperationalContainmentGuard::default();

    // 1. Leaked Anthropic API token
    let verdict = guard.evaluate_context_leakage("export ANTHROPIC_API_KEY=sk-ant-api03-live-test");
    assert!(!verdict.is_clean);
    assert!(verdict.token_revocation_recommended);

    // 2. Leaked OpenAI live key
    let verdict2 = guard.evaluate_context_leakage("OPENAI_API_KEY=sk-proj-999888777");
    assert!(!verdict2.is_clean);

    // 3. Dynamic STS short-lived token issuance
    let token = guard.issue_short_lived_sts_token("ledger_arm", "task_99", 60);
    assert!(token.starts_with("sts-"));

    // 4. Clean context
    let clean = guard.evaluate_context_leakage("{\"status\": \"OK\", \"rows_processed\": 42}");
    assert!(clean.is_clean);
}

#[test]
fn test_behavioral_breakout_guard_detects_harness_tampering_and_route_evasion() {
    let guard = BehavioralBreakoutGuard::default();

    // 1. Attempting to overwrite evaluation harness
    let verdict = guard.evaluate_action(
        "write",
        "tests/strix_llm_adversarial_tester.py",
        "modify_all_assertions_to_pass()",
    );
    assert!(!verdict.is_clean);
    assert!(verdict.circuit_breaker_triggered);

    // 2. Network routing table inspection
    let verdict2 = guard.evaluate_action("execute_code", "route print", "ip route show");
    assert!(!verdict2.is_clean);

    // 3. Local hosts file tampering
    let verdict3 = guard.evaluate_action(
        "write",
        r"c:\windows\system32\drivers\etc\hosts",
        "127.0.0.1 google.com",
    );
    assert!(!verdict3.is_clean);

    // 4. Clean action
    let clean = guard.evaluate_action("extract", "contracts.pdf", "read_clause_1");
    assert!(clean.is_clean);
}

#[test]
fn test_data_breakout_guard_blocks_cross_agent_scratchpad_pollution() {
    let guard = DataBreakoutGuard::default();

    // 1. Low privilege document_arm attempts to write to privileged ledger state
    let verdict = guard.evaluate_data_access(
        "document_arm",
        "/shared/state/ledger",
        "{\"unauthorized_balance\": 99999999}",
    );
    assert!(!verdict.is_clean);
    assert!(verdict.memory_isolation_breached);

    // 2. Process memory dump attempt
    let verdict2 =
        guard.evaluate_data_access("document_arm", "printenv", "dumping_host_memory_proc_self");
    assert!(!verdict2.is_clean);

    // 3. Authorized high privilege ledger_arm writes to ledger
    let clean =
        guard.evaluate_data_access("ledger_arm", "/shared/state/ledger", "{\"verified\": true}");
    assert!(clean.is_clean);
}

#[test]
fn test_rl_adaptive_defense_engine_q_learning_and_reward() {
    let rl = AdaptiveRlDefenseEngine::new("config/test_rl_policy.json");

    // Construct high threat state (Docker socket probe)
    let mut threat_state = AdaptiveStateVector::default();
    threat_state.credential_access_pressure = 0.95;
    threat_state.step_count_drift = 0.1;

    // Must escalate to containment for high threat severity
    let action = rl.select_action(&threat_state);
    assert!(
        action.is_containment(),
        "Action should be containment, got {:?}",
        action
    );

    // Reward for true containment
    let mut next_state = threat_state.clone();
    next_state.step_count_drift += 0.01;
    let reward = rl.step(
        &threat_state,
        AdaptiveDefenseAction::HardMitigation,
        true,
        true,
        25.0,
        &next_state,
        true,
    );
    assert!(
        reward > 50.0,
        "Expected positive containment reward, got {}",
        reward
    );

    let stats = rl.stats();
    assert_eq!(stats.total_episodes, 1);
    assert_eq!(stats.total_steps, 1);
}

#[test]
fn test_prioritized_experience_replay_weighted_sampling_and_training() {
    let rl = AdaptiveRlDefenseEngine::new("config/test_per_rl.json");

    // Seed the replay buffer with distinct transitions having different TD priorities
    for i in 0..20 {
        let mut s = AdaptiveStateVector::default();
        s.credential_access_pressure = (i as f32 * 0.05).min(1.0);
        s.step_count_drift = 0.1;
        let mut s_next = s.clone();
        s_next.step_count_drift += 0.05;

        let action = if i % 2 == 0 {
            AdaptiveDefenseAction::HardMitigation
        } else {
            AdaptiveDefenseAction::PassiveObserve
        };
        let is_threat = i >= 10;
        let is_contained = action.is_containment();

        let _ = rl.step(&s, action, is_threat, is_contained, 15.0, &s_next, false);
    }

    assert!(rl.stats().replay_buffer_size >= 20);

    // Execute explicit PER batch training pass
    let metrics = rl.train_prioritized_replay(8);
    assert!(
        metrics.is_some(),
        "PER training pass must execute successfully"
    );
    let m = metrics.unwrap();
    assert_eq!(m.sampled_batch_size, 8);
    assert!(m.max_importance_weight > 0.0);
    assert_eq!(m.priorities_updated, 8);
}

#[test]
fn test_rl_policy_empirical_baseline_comparison() {
    let rl = AdaptiveRlDefenseEngine::new("config/test_eval_rl.json");

    // Train on 30 initial exploration steps
    for i in 0..30 {
        let mut s = AdaptiveStateVector::default();
        let is_threat = i % 2 == 0;
        if is_threat {
            s.credential_access_pressure = 0.85;
            s.step_count_drift = 0.5;
        } else {
            s.credential_access_pressure = 0.05;
            s.step_count_drift = 0.02;
        }
        let action = rl.select_action(&s);
        let is_contained = action.is_containment();
        let mut s_next = s.clone();
        s_next.step_count_drift += 0.01;
        let _ = rl.step(&s, action, is_threat, is_contained, 10.0, &s_next, true);
    }

    // Evaluate against 50 held-out evaluation episodes
    let benchmark = rl.evaluate_policy_against_baselines(50);
    assert_eq!(benchmark.episodes_evaluated, 50);
    assert!(
        benchmark.learned_containment_rate >= 0.80,
        "Learned policy must contain at least 80% of threats, got {:.2}",
        benchmark.learned_containment_rate
    );
    assert!(
        benchmark.learned_false_positive_rate <= 0.20,
        "Learned policy FP rate must be <= 20%, got {:.2}",
        benchmark.learned_false_positive_rate
    );
    assert!(
        benchmark.learned_cumulative_reward > benchmark.random_cumulative_reward,
        "Learned RL must outperform random defender"
    );
    assert!(
        benchmark.learned_cumulative_reward > benchmark.disabled_cumulative_reward,
        "Learned RL must outperform disabled baseline"
    );
}

#[test]
fn test_opentelemetry_session_telemetry_and_resilience_metrics() {
    let otel = OtelSessionTelemetry::new("logs/test_otel_sessions.jsonl", 100);

    let (session_id, trace_id) = otel.get_or_start_session("sess_agent_123", "network_arm");
    assert_eq!(session_id, "sess_agent_123");
    assert_eq!(trace_id.len(), 32);

    // Record resilience event (MTTD = 12.5ms, MTTR = 18.2ms)
    otel.record_resilience_event(12.5, 18.2, Some(&session_id));

    // Record span
    let span = otel.record_span(
        &trace_id,
        None,
        "test_tool_execution",
        OtelSpanKind::Server,
        1_000_000,
        2_000_000,
        OtelStatusCode::Ok,
        None,
        std::collections::HashMap::new(),
        vec![],
    );
    assert_eq!(span.trace_id, trace_id);
    assert_eq!(span.name, "test_tool_execution");

    let metrics = otel.get_resilience_metrics();
    assert!(metrics.mttd_ms > 0.0);
    assert!(metrics.mttr_ms > 0.0);
    assert!(metrics.cumulative_survival_prob <= 1.0);
}

#[tokio::test]
async fn test_continuous_evaluation_cycle_executes_all_perimeters() {
    let breakout_coord = Arc::new(BreakoutDefenseCoordinator::default());
    let rl_engine = Arc::new(AdaptiveRlDefenseEngine::new(
        "config/test_continuous_rl.json",
    ));
    let otel_telemetry = Arc::new(OtelSessionTelemetry::new(
        "logs/test_continuous_otel.jsonl",
        200,
    ));

    let engine = ContinuousEvaluationEngine::new(breakout_coord, rl_engine, otel_telemetry);

    let report = engine.run_continuous_training_cycle().await;
    assert!(
        report.total_probes >= 25,
        "Expected at least 25 probes across perimeters, got {}",
        report.total_probes
    );
    assert_eq!(
        report.defensive_breaches, 0,
        "Zero defensive breaches invariant violated!"
    );
    assert_eq!(report.passed_invariants, report.total_probes);
    assert!(report.average_reward > 0.0);
}
