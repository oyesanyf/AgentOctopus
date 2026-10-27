use agent_octopus::security::math_validator::{ResilienceBreachEvent, VassilevMathValidator};
use agent_octopus::security::rl_defense::{
    AdaptiveDefenseAction, AdaptiveRlDefenseEngine, AdaptiveStateVector,
};

#[test]
fn test_vassilev_equation_10_numerical_benchmark() {
    let p_500 = VassilevMathValidator::benchmark_equation_10();
    // In the paper: P_secure(500) <= (1 - 0.01)^500 ~= 0.00657
    assert!(
        (p_500 - 0.006570699).abs() < 1e-6,
        "Expected benchmark value ~0.0065707, got {}",
        p_500
    );
    assert!(
        p_500 < 0.007,
        "Static defense should have < 0.7% survival after 500 steps, got {}",
        p_500
    );
}

#[test]
fn test_static_survival_bound_monotonic_decay() {
    let eps = 0.02;
    let mut prev_prob = 1.0;
    for n in [1, 10, 50, 100, 500, 1000] {
        let prob = VassilevMathValidator::compute_static_survival_bound(n, eps);
        assert!(
            prob < prev_prob,
            "Probability must strictly decrease monotonically: step {} got {}, prev {}",
            n,
            prob,
            prev_prob
        );
        prev_prob = prob;
    }
    // At N=1000 with eps=0.02, prob is essentially 0 (1.68e-9)
    assert!(prev_prob < 1e-8);
}

#[test]
fn test_rl_asymptotic_floor_transference_theorem() {
    // Theorem 1: With gamma = 1.25 > 1.0, \sum eps(t) < \infty, so P_infty > 0
    let epsilon_0 = 0.05;
    let lambda = 0.05;
    let gamma = 1.25;

    let p_infty = VassilevMathValidator::compute_rl_asymptotic_floor(epsilon_0, lambda, gamma);
    assert!(
        p_infty > 0.01,
        "Theorem 1 requires strictly positive asymptotic survival floor, got {}",
        p_infty
    );

    // Compare with static bound at N=5000: static bound is negligible (~0.0)
    let static_5000 = VassilevMathValidator::compute_static_survival_bound(5000, 0.01);
    assert!(
        static_5000 < 1e-15,
        "Static survival should be near-zero at 5000 steps, got {}",
        static_5000
    );
    assert!(
        p_infty > static_5000 * 1_000_000.0,
        "RL asymptotic floor must crush the static Sisyphean decay"
    );
}

#[test]
fn test_equations_11_and_12_mttd_and_mttr() {
    let events = vec![
        ResilienceBreachEvent {
            event_id: "evt_1".to_string(),
            t_breach_ms: 100.0,
            t_detect_ms: 102.5,    // detection latency = 2.5ms
            t_contained_ms: 106.0, // containment latency = 3.5ms
            perimeter: "Technical".to_string(),
        },
        ResilienceBreachEvent {
            event_id: "evt_2".to_string(),
            t_breach_ms: 200.0,
            t_detect_ms: 201.5,    // detection latency = 1.5ms
            t_contained_ms: 204.0, // containment latency = 2.5ms
            perimeter: "Operational".to_string(),
        },
    ];

    let mttd = VassilevMathValidator::compute_mttd(&events);
    let mttr = VassilevMathValidator::compute_mttr(&events);

    // MTTD = (2.5 + 1.5) / 2 = 2.0 ms
    assert!(
        (mttd - 2.0).abs() < 1e-6,
        "Expected MTTD = 2.0, got {}",
        mttd
    );

    // MTTR = (3.5 + 2.5) / 2 = 3.0 ms
    assert!(
        (mttr - 3.0).abs() < 1e-6,
        "Expected MTTR = 3.0, got {}",
        mttr
    );
}

#[test]
fn test_monte_carlo_simulation_and_hypothesis_test() {
    let mc = VassilevMathValidator::simulate_monte_carlo(
        5_000, // 5,000 trajectories
        200,   // 200 steps
        0.02,  // static error = 2%
        0.05,  // RL initial error = 5%
        0.05,  // lambda
        1.25,  // gamma
    );

    assert_eq!(mc.total_trajectories, 5_000);
    assert_eq!(mc.steps_per_trajectory, 200);

    // Static survival across 200 steps with eps=0.02: (1 - 0.02)^200 ~= 0.0175 (1.75%)
    assert!(mc.static_survival_rate < 0.05);

    // RL survival should be significantly higher due to algebraic decay (~16.7% vs 1.75%)
    assert!(
        mc.rl_survival_rate > 0.10,
        "Expected RL survival > 10%, got {}",
        mc.rl_survival_rate
    );
    assert!(
        mc.rl_survival_rate > mc.static_survival_rate * 4.0,
        "RL survival rate must be at least 4x higher than static"
    );

    let (z, p, _verdict) = VassilevMathValidator::hypothesis_test(
        mc.rl_survivors,
        mc.total_trajectories,
        mc.static_survivors,
        mc.total_trajectories,
    );

    assert!(z > 10.0, "Expected massive positive Z score, got {}", z);
    assert!(p < 0.001, "Expected p < 0.001, got {}", p);
}

#[test]
fn test_enhanced_dueling_q_and_epistemic_uncertainty() {
    let rl = AdaptiveRlDefenseEngine::new("config/test_enhanced_rl.json");

    // 1. Initial epistemic uncertainty should be high for unseen state
    let mut s = AdaptiveStateVector::default();
    s.credential_access_pressure = 0.85;
    let bucket = s.discretize_bucket();
    let initial_unc = rl.composite_uncertainty_for_state(bucket);
    assert_eq!(
        initial_unc, 1.0,
        "Expected max uncertainty for unseen state"
    );

    // 2. Perform steps to train the state
    for i in 0..15 {
        let mut s_next = s.clone();
        s_next.step_count_drift += 0.01;

        rl.step(
            &s,
            AdaptiveDefenseAction::MicroContainment,
            true,
            true,
            12.0,
            &s_next,
            i == 14,
        );
    }

    // 3. Epistemic uncertainty should decrease with observations for the trained action
    let action_idx = AdaptiveDefenseAction::MicroContainment.to_index();
    let initial_action_unc = 1.0;
    let trained_unc = rl.epistemic_uncertainty(bucket, action_idx);
    assert!(
        trained_unc < initial_action_unc,
        "Epistemic uncertainty must decrease with experience: initial {}, trained {}",
        initial_action_unc,
        trained_unc
    );

    // 4. Verify Dueling Q evaluation
    let dueling_q =
        rl.evaluate_dueling_q(bucket, AdaptiveDefenseAction::MicroContainment.to_index());
    assert!(
        dueling_q > 0.0,
        "Expected positive dueling Q-value after containment rewards"
    );

    let stats = rl.stats();
    assert!(stats.dueling_state_values_count > 0);
    assert!(stats.prioritized_replay_p95_weight > 0.0);
}
