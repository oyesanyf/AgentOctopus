use agent_octopus::security::governor::{
    spawn_continuous_governor, GovernorConfig, GovernorError, GovernorStage, KernelEventKind,
    SecurityGovernorState, TelemetrySample, WeightMatrix,
};
use agent_octopus::security::rl_defense::AdaptiveRlDefenseEngine;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[test]
fn test_governor_step_risk_computation() {
    let config = GovernorConfig::default();
    let state = SecurityGovernorState::new(config);

    // 1. Benign file access
    let benign_file = KernelEventKind::FileAccess {
        path: PathBuf::from("/workspace/src/main.rs"),
        is_read_only: false,
        is_restricted_virtual_fs: false,
    };
    let risk_benign = state.compute_step_risk(&benign_file);
    // Baseline risk = 1.0 - exp(-0.002) ~= 0.001998
    assert!(
        (risk_benign - 0.001998).abs() < 1e-4,
        "Expected baseline risk ~0.002, got {}",
        risk_benign
    );

    // 2. Interactive shell / compiler execution (weight = 3.8)
    let shell_exec = KernelEventKind::ProcessExec {
        executable_path: PathBuf::from("/bin/bash"),
        arguments: vec!["-i".to_string()],
        is_interactive_shell_or_compiler: true,
    };
    let risk_shell = state.compute_step_risk(&shell_exec);
    // 1.0 - exp(-(0.002 + 3.8)) = 1.0 - exp(-3.802) ~= 0.9776
    assert!(
        risk_shell > 0.97,
        "Interactive shell risk should be > 0.97, got {}",
        risk_shell
    );

    // 3. Unauthorized network socket egress (weight = 4.2)
    let unauthorized_socket = KernelEventKind::SocketConnect {
        destination_ip: "198.51.100.1".parse::<IpAddr>().unwrap(),
        port: 4444,
        is_whitelisted_endpoint: false,
    };
    let risk_socket = state.compute_step_risk(&unauthorized_socket);
    // 1.0 - exp(-(0.002 + 4.2)) ~= 0.985
    assert!(
        risk_socket > 0.98,
        "Unauthorized egress risk should be > 0.98, got {}",
        risk_socket
    );

    // 4. Restricted virtual filesystem access (weight = 3.1)
    let restricted_fs = KernelEventKind::FileAccess {
        path: PathBuf::from("/proc/kcore"),
        is_read_only: true,
        is_restricted_virtual_fs: true,
    };
    let risk_fs = state.compute_step_risk(&restricted_fs);
    // 1.0 - exp(-(0.002 + 3.1)) ~= 0.955
    assert!(
        risk_fs > 0.95,
        "Restricted filesystem access risk should be > 0.95, got {}",
        risk_fs
    );

    // 5. Tool schema drift
    let drift = KernelEventKind::ToolSchemaDrift {
        tool_name: "sql_exec".to_string(),
        entropy_divergence: 0.5,
        unrecognized_parameters: 2,
    };
    let risk_drift = state.compute_step_risk(&drift);
    // score = 0.002 + 0.85*0.5 + 0.5*2 = 0.002 + 0.425 + 1.0 = 1.427
    // 1.0 - exp(-1.427) ~= 0.760
    assert!(
        risk_drift > 0.70 && risk_drift < 0.85,
        "Tool schema drift risk should be ~0.76, got {}",
        risk_drift
    );
}

#[test]
fn test_governor_survival_decay_monotonic() {
    let mut config = GovernorConfig::default();
    config.weights = WeightMatrix::default();
    let mut state = SecurityGovernorState::new(config);

    let mut prev_prob = 1.0;

    for step in 1..=5 {
        let sample = TelemetrySample {
            step,
            timestamp: Instant::now(),
            breach_time_estimate: None,
            event: KernelEventKind::FileAccess {
                path: PathBuf::from(format!("/workspace/file_{}.txt", step)),
                is_read_only: false,
                is_restricted_virtual_fs: false,
            },
        };

        let (epsilon, survival_prob) = state.evaluate_sample(sample).unwrap();
        assert!(
            survival_prob < prev_prob,
            "Survival probability must strictly decrease monotonically"
        );
        assert!(
            (survival_prob - prev_prob * (1.0 - epsilon)).abs() < 1e-6,
            "Survival probability must equal previous * (1 - epsilon)"
        );
        prev_prob = survival_prob;
    }

    assert_eq!(state.current_step, 5);
}

#[test]
fn test_governor_mttd_and_mttr_calculation() {
    let config = GovernorConfig::default();
    let mut state = SecurityGovernorState::new(config);

    let t0 = Instant::now();
    let t_breach_1 = t0;

    // Simulate an anomaly event at step 10
    let sample = TelemetrySample {
        step: 10,
        timestamp: t0 + Duration::from_millis(5),
        breach_time_estimate: Some(t_breach_1),
        event: KernelEventKind::ProcessExec {
            executable_path: PathBuf::from("/bin/sh"),
            arguments: vec!["-c".to_string(), "whoami".to_string()],
            is_interactive_shell_or_compiler: true,
        },
    };

    let (_eps, _prob) = state.evaluate_sample(sample).unwrap();
    assert_eq!(state.incidents.len(), 1);

    // Record containment for step 10
    state.record_containment(10);

    let summary = state.get_metrics_summary();
    assert_eq!(summary.total_incidents, 1);
    assert_eq!(summary.total_containment_failures, 0);
    // MTTD and MTTR must be non-negative
    assert!(summary.mean_time_to_detect >= Duration::ZERO);
    assert!(summary.mean_time_to_remediate >= Duration::ZERO);
}

#[tokio::test]
async fn test_continuous_governor_async_channel_and_trip() {
    let mut config = GovernorConfig::default();
    config.warning_threshold = 0.75;
    config.critical_termination_threshold = 0.35;
    // Set dummy PID for testing circuit breaker
    config.target_pid = 999999;

    let (governor, supervisor_task) = spawn_continuous_governor(config);

    // 1. Submit benign samples
    for step in 1..=3 {
        let sample = TelemetrySample {
            step,
            timestamp: Instant::now(),
            breach_time_estimate: None,
            event: KernelEventKind::FileAccess {
                path: Path::new("/workspace/project/main.py").to_path_buf(),
                is_read_only: false,
                is_restricted_virtual_fs: false,
            },
        };
        governor.submit_sample(sample).await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !governor.is_halted(),
        "Governor should not trip on benign samples"
    );

    // 2. Submit high-severity attack: interactive shell + unauthorized egress
    // Each carries risk ~0.98, so P_secure drops below 0.35 quickly!
    let hostile_shell = TelemetrySample {
        step: 4,
        timestamp: Instant::now(),
        breach_time_estimate: Some(Instant::now() - Duration::from_millis(10)),
        event: KernelEventKind::ProcessExec {
            executable_path: Path::new("/bin/bash").to_path_buf(),
            arguments: vec!["-c".to_string(), "id".to_string()],
            is_interactive_shell_or_compiler: true,
        },
    };
    governor.submit_sample(hostile_shell).await.unwrap();

    // Give supervisor loop time to process and trigger breaker
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Circuit breaker must trip because survival dropped below 0.35
    assert!(
        governor.is_halted(),
        "Circuit breaker must be tripped after high severity breach"
    );

    // Further submission should fail with ProcessTerminated error
    let rejected_sample = TelemetrySample {
        step: 5,
        timestamp: Instant::now(),
        breach_time_estimate: None,
        event: KernelEventKind::FileAccess {
            path: Path::new("/workspace/file.txt").to_path_buf(),
            is_read_only: true,
            is_restricted_virtual_fs: false,
        },
    };
    let res = governor.submit_sample(rejected_sample).await;
    assert!(res.is_err());
    match res.unwrap_err() {
        GovernorError::ProcessTerminated(msg) => {
            assert!(msg.contains("Circuit breaker already tripped"));
        }
        other => panic!("Expected ProcessTerminated error, got {:?}", other),
    }

    let _ = governor.shutdown().await;
    let _ = supervisor_task.await;
}

#[test]
fn test_governor_breakout_perimeters_risk() {
    let config = GovernorConfig::default();
    let state = SecurityGovernorState::new(config);

    // 1. Technical Breakout: Docker socket escape (weight = 4.5)
    let tech_ev = KernelEventKind::TechnicalBreakout {
        detail: "Docker daemon socket unmasked".to_string(),
        is_docker_socket: true,
        is_wasm_fuel_exhaust: false,
        is_ring0_driver: false,
    };
    let risk_tech = state.compute_step_risk(&tech_ev);
    assert!(
        risk_tech > 0.98,
        "Technical breakout risk must exceed 0.98, got {}",
        risk_tech
    );

    // 2. Operational Breakout: STS token exfiltration (weight = 3.9)
    let op_ev = KernelEventKind::OperationalBreakout {
        detail: "Sts token scrape detected".to_string(),
        is_sts_token_leak: true,
        is_route_table_hijack: false,
        is_env_scrape: false,
    };
    let risk_op = state.compute_step_risk(&op_ev);
    assert!(
        risk_op > 0.97,
        "Operational breakout risk must exceed 0.97, got {}",
        risk_op
    );

    // 3. Behavioral Breakout: Evaluation harness tampering (weight = 4.1)
    let beh_ev = KernelEventKind::BehavioralBreakout {
        detail: "Self-grading hash mismatch".to_string(),
        is_harness_tamper: true,
        is_prompt_injection: false,
        is_self_grading_bypass: false,
    };
    let risk_beh = state.compute_step_risk(&beh_ev);
    assert!(
        risk_beh > 0.98,
        "Behavioral breakout risk must exceed 0.98, got {}",
        risk_beh
    );

    // 4. Data Breakout: Cross-agent scratchpad leak (weight = 3.6)
    let data_ev = KernelEventKind::DataBreakout {
        detail: "Memory dump attempt".to_string(),
        is_scratchpad_pollution: true,
        is_memory_dump: false,
    };
    let risk_data = state.compute_step_risk(&data_ev);
    assert!(
        risk_data > 0.96,
        "Data breakout risk must exceed 0.96, got {}",
        risk_data
    );
}

#[test]
fn test_governor_4_stage_progressive_ladder() {
    let mut config = GovernorConfig::default();
    config.stage_trace_elevation_threshold = 0.85;
    config.stage_micro_containment_threshold = 0.70;
    config.critical_termination_threshold = 0.35;
    let mut state = SecurityGovernorState::new(config);

    assert_eq!(state.current_stage(), GovernorStage::Stage0PassiveObserve);

    // Minor event drops survival to ~0.80 -> Stage 1
    state.current_survival_prob = 0.80;
    assert_eq!(state.current_stage(), GovernorStage::Stage1TraceElevation);

    // Further degradation drops survival to ~0.55 -> Stage 2
    state.current_survival_prob = 0.55;
    assert_eq!(state.current_stage(), GovernorStage::Stage2MicroContainment);

    // Critical breach drops survival below 0.35 -> Stage 3 Hard Mitigation
    state.current_survival_prob = 0.25;
    assert_eq!(state.current_stage(), GovernorStage::Stage3HardMitigation);
}

#[test]
fn test_governor_rl_closed_loop_mitigation_attenuation() {
    let config = GovernorConfig::default();
    let mut state = SecurityGovernorState::new(config);
    let rl = AdaptiveRlDefenseEngine::new("config/test_gov_rl.json");

    let sample = TelemetrySample {
        step: 1,
        timestamp: Instant::now(),
        breach_time_estimate: None,
        event: KernelEventKind::ProcessExec {
            executable_path: PathBuf::from("/bin/sh"),
            arguments: vec!["-i".to_string()],
            is_interactive_shell_or_compiler: true,
        },
    };

    // Evaluate with closed-loop RL mitigation
    let (eff_eps, surv_prob, action_opt) =
        state.evaluate_sample_with_rl(sample, Some(&rl)).unwrap();

    assert!(action_opt.is_some(), "RL action should be selected");
    // Raw risk for interactive shell is ~0.9776. With RL containment mitigation (factor >= 0.65),
    // effective risk should be significantly lower!
    assert!(
        eff_eps < 0.60,
        "RL active defense mitigation must attenuate effective hazard risk: got {}",
        eff_eps
    );
    assert!(
        surv_prob > 0.40,
        "Survival probability must be preserved above critical threshold by active RL mitigation: got {}",
        surv_prob
    );
}

#[test]
fn test_governor_sisyphean_algebraic_decay_preserves_floor() {
    let mut config = GovernorConfig::default();
    config.enable_sisyphean_algebraic_decay = true;
    config.sisyphean_gamma = 1.25;
    config.sisyphean_lambda = 0.05;
    let mut state = SecurityGovernorState::new(config);

    let benign = KernelEventKind::FileAccess {
        path: PathBuf::from("/workspace/file.txt"),
        is_read_only: false,
        is_restricted_virtual_fs: false,
    };

    state.current_step = 1;
    let risk_step_1 = state.compute_step_risk(&benign);

    state.current_step = 500;
    let risk_step_500 = state.compute_step_risk(&benign);

    // Due to Theorem 1 algebraic decay (1 / (1 + lambda*t)^gamma),
    // risk at step 500 must be dramatically lower than at step 1!
    assert!(
        risk_step_500 < risk_step_1 * 0.1,
        "Sisyphean algebraic decay must drive baseline error toward zero: step 1 = {}, step 500 = {}",
        risk_step_1,
        risk_step_500
    );
}
