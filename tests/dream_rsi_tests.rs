use agent_octopus::containment_ring::arm_ring::ArmRingRegistry;
use agent_octopus::core::types::ArmRole;
use agent_octopus::security::dream_rsi::{
    DreamRsiOptimizerArm, DreamRsiPolicyOptimizer, ProtocolWorldModel, ResearchPolicy,
    TrajectoryEvent,
};

#[test]
fn test_dream_rsi_world_model_priors_and_transitions() {
    let wm = ProtocolWorldModel::new();
    assert!(
        wm.total_states() >= 8,
        "Expected at least 8 seeded prior states"
    );

    let trans = wm.get_transition(9112, "abnf_delimiter");
    assert!(
        trans.is_some(),
        "RFC 9112 abnf_delimiter transition must exist"
    );
    let t = trans.unwrap();
    assert!(t.predicted_divergence > 0.0 && t.predicted_divergence < 1.0);
    assert!(t.information_entropy > 0.0);
}

#[test]
fn test_dream_rsi_trajectory_ingestion() {
    let mut wm = ProtocolWorldModel::new();
    let initial_pred = wm
        .get_transition(9112, "abnf_delimiter")
        .unwrap()
        .predicted_divergence;

    let events = vec![
        TrajectoryEvent {
            event_id: "ev-1".to_string(),
            rfc_number: 9112,
            section: "3.2".to_string(),
            mutation_type: "abnf_delimiter".to_string(),
            is_anomalous: true,
            divergence_score: 0.95,
            reproducibility_rate: 1.0,
            latency_ms: 15.0,
            finding_status: "REPRODUCIBLE_DIVERGENCE".to_string(),
            timestamp: 1000,
        },
        TrajectoryEvent {
            event_id: "ev-2".to_string(),
            rfc_number: 9112,
            section: "3.2".to_string(),
            mutation_type: "abnf_delimiter".to_string(),
            is_anomalous: true,
            divergence_score: 0.90,
            reproducibility_rate: 1.0,
            latency_ms: 12.0,
            finding_status: "CONFIRMED_VULNERABILITY".to_string(),
            timestamp: 1001,
        },
    ];

    wm.ingest_trajectories(&events);
    assert_eq!(wm.total_samples(), 2);

    let updated_pred = wm
        .get_transition(9112, "abnf_delimiter")
        .unwrap()
        .predicted_divergence;
    assert!(
        updated_pred > initial_pred,
        "Divergence probability should increase with anomalous evidence"
    );
}

#[test]
fn test_dream_rsi_policy_simulation_rollout() {
    let wm = ProtocolWorldModel::new();
    let policy = ResearchPolicy::default();

    let report = wm.simulate_rollout(&policy, 500);
    assert_eq!(report.simulated_steps, 500);
    assert!(report.projected_yield >= 0.0);
    assert!(report.projected_reproducibility >= 0.0);
    assert_eq!(report.policy_id, policy.policy_id);
}

#[test]
fn test_dream_rsi_policy_optimization() {
    let mut optimizer = DreamRsiPolicyOptimizer::new();
    let evolved = optimizer.optimize_policy(5, 200);

    assert!(evolved.generation >= 1);
    assert!(evolved.fitness_score > 0.0);
    assert_eq!(optimizer.active_policy().generation, evolved.generation);
}

#[test]
fn test_dream_rsi_plan_generation() {
    let optimizer = DreamRsiPolicyOptimizer::new();
    let plan = optimizer.generate_experiment_plan();

    assert!(!plan.prioritized_rfcs.is_empty());
    assert!(!plan.prioritized_mutations.is_empty());
    assert!(plan.recommended_trial_budget >= 2);
    assert!(plan.rationale.contains("Dream-RSI"));

    // Verify ordering: descending priority score
    for i in 0..(plan.prioritized_rfcs.len() - 1) {
        assert!(
            plan.prioritized_rfcs[i].priority_score >= plan.prioritized_rfcs[i + 1].priority_score
        );
    }
}

#[tokio::test]
async fn test_dream_rsi_arm110_ring_containment() {
    let registry = std::sync::Arc::new(ArmRingRegistry::new(
        50,
        b"test_seed_dream_rsi_1234567890123456",
    ));
    let arm = DreamRsiOptimizerArm::with_registry(&registry);

    let status = arm.get_status().await;
    assert_eq!(status.arm_id, 110);
    assert!(status.is_contained);
    assert!(!status.is_severed);
    assert_eq!(
        status.offline_isolation_mode,
        "RING2_STRICT_NO_SOCKET_EGRESS"
    );

    // Verify Ring 110 has the registered tools and prefixes
    let ring = registry
        .get_ring(110)
        .await
        .expect("Ring 110 must exist in registry");
    assert_eq!(ring.role, ArmRole::DreamRsiOptimizer);
    let ring_dto = ring.to_status_dto().await;
    assert!(ring_dto
        .allowed_tools
        .contains(&"dream_rsi_replay".to_string()));
    assert!(ring_dto
        .allowed_tools
        .contains(&"dream_rsi_train_world_model".to_string()));
    assert!(ring_dto
        .allowed_tools
        .contains(&"dream_rsi_policy_rollout".to_string()));
    assert!(ring_dto
        .allowed_tools
        .contains(&"dream_rsi_recommend_priorities".to_string()));
    assert!(ring_dto
        .allowed_resource_prefixes
        .contains(&"dream_rsi://".to_string()));
    assert!(!ring_dto
        .allowed_tools
        .contains(&"live_socket_connect".to_string()));
}

#[tokio::test]
async fn test_dream_rsi_arm110_sever_autotomy() {
    let registry = std::sync::Arc::new(ArmRingRegistry::new(
        50,
        b"test_seed_dream_rsi_1234567890123456",
    ));
    let arm = DreamRsiOptimizerArm::with_registry(&registry);

    registry.sever_arm(110, "simulated breach").await.unwrap();

    let status = arm.get_status().await;
    assert!(status.is_severed);
    assert_eq!(status.status, "SEVERED_AUTOTOMY_CONTAINED");

    // Operations must fail closed when severed
    let res = arm.train_offline(2, 50).await;
    assert!(res.is_err(), "Severed arm must deny training");
}

#[tokio::test]
async fn test_dream_rsi_arm110_training_and_recommendations() {
    let arm = DreamRsiOptimizerArm::new();

    let res = arm.train_offline(3, 100).await;
    assert!(res.is_ok(), "Offline training must succeed");

    let status_after = arm.get_status().await;
    assert!(status_after.last_training_timestamp > 0);

    let recs = arm.get_recommendations().await;
    assert!(!recs.prioritized_rfcs.is_empty());
    assert!(!recs.prioritized_mutations.is_empty());
}
