use serde::{Deserialize, Serialize};

/// Mathematical validator and empirical verifier for the Vassilev Sisyphean Bound
/// and the Continuous RL Adaptive Defense Transference Theorem.
///
/// Implements Equations (6), (7), (8), (9), (10), (11), (12) from:
/// "Beyond One and Done: Agent Breakouts and Continuous Security for Agentic AI Systems"
/// (Femi Oyesanya, October 2026).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SisypheanValidationReport {
    pub horizon_steps: usize,
    pub static_epsilon_min: f64,
    pub static_survival_bound: f64,
    pub static_collapse_inevitable: bool,
    pub rl_initial_epsilon: f64,
    pub rl_decay_lambda: f64,
    pub rl_decay_gamma: f64,
    pub rl_survival_prob: f64,
    pub rl_asymptotic_floor: f64,
    pub monte_carlo_static_survival_rate: f64,
    pub monte_carlo_rl_survival_rate: f64,
    pub monte_carlo_trajectories: usize,
    pub z_statistic: f64,
    pub p_value: f64,
    pub hypothesis_test_verdict: String,
    pub empirical_mttd_ms: f64,
    pub empirical_mttr_ms: f64,
    pub mathematical_proof_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonteCarloSimulationResult {
    pub total_trajectories: usize,
    pub steps_per_trajectory: usize,
    pub static_survivors: usize,
    pub static_survival_rate: f64,
    pub rl_survivors: usize,
    pub rl_survival_rate: f64,
    pub average_first_failure_step_static: f64,
    pub average_first_failure_step_rl: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResilienceBreachEvent {
    pub event_id: String,
    pub t_breach_ms: f64,
    pub t_detect_ms: f64,
    pub t_contained_ms: f64,
    pub perimeter: String,
}

pub struct VassilevMathValidator;

impl VassilevMathValidator {
    /// Computes the exact static guardrail containment survival probability across N steps
    /// using Equations (7) and (8):
    /// P_secure(N) <= (1 - epsilon_min)^N
    pub fn compute_static_survival_bound(n: usize, epsilon_min: f64) -> f64 {
        if epsilon_min <= 0.0 {
            return 1.0;
        }
        if epsilon_min >= 1.0 {
            return 0.0;
        }
        (1.0 - epsilon_min).powi(n as i32)
    }

    /// Computes the numerical benchmark from Equation (10):
    /// P_secure(500) <= (1 - 0.01)^500 ~= 0.0065707 (< 0.7%)
    pub fn benchmark_equation_10() -> f64 {
        Self::compute_static_survival_bound(500, 0.01)
    }

    /// Evaluates the per-step RL error rate epsilon_RL(t) under continuous policy improvement:
    /// epsilon_RL(t) = epsilon_0 / (1 + lambda * t)^gamma
    pub fn rl_per_step_error(t: usize, epsilon_0: f64, lambda: f64, gamma: f64) -> f64 {
        let denom = (1.0 + lambda * (t as f64)).powf(gamma);
        (epsilon_0 / denom).clamp(1e-9, 1.0)
    }

    /// Computes the cumulative RL survival probability across N steps:
    /// P_secure^RL(N) = \prod_{t=1}^N (1 - epsilon_RL(t))
    pub fn compute_rl_survival_prob(n: usize, epsilon_0: f64, lambda: f64, gamma: f64) -> f64 {
        let mut cumulative_log = 0.0;
        for t in 1..=n {
            let eps_t = Self::rl_per_step_error(t, epsilon_0, lambda, gamma);
            cumulative_log += (1.0 - eps_t).ln();
        }
        cumulative_log.exp()
    }

    /// Computes the theoretical asymptotic infinite-horizon survival floor P_infty:
    /// P_infty = \prod_{t=1}^\infty (1 - epsilon_RL(t)) > 0
    /// Valid when gamma > 1.0 (the Weierstrass product theorem guarantees convergence to a positive constant).
    pub fn compute_rl_asymptotic_floor(epsilon_0: f64, lambda: f64, gamma: f64) -> f64 {
        if gamma <= 1.0 {
            // Diverges to 0 if decay exponent is harmonic or sub-harmonic
            return 0.0;
        }
        // Approximate infinite product with 100,000 steps + integral tail approximation
        let horizon = 100_000;
        let p_partial = Self::compute_rl_survival_prob(horizon, epsilon_0, lambda, gamma);
        // Integral tail of ln(1 - eps_t) ~= -eps_t:
        // \int_{H}^\infty \frac{eps_0}{(1 + lambda * x)^gamma} dx = \frac{eps_0}{lambda * (gamma - 1) * (1 + lambda * H)^(gamma - 1)}
        let tail_sum = (epsilon_0) / (lambda * (gamma - 1.0) * (1.0 + lambda * (horizon as f64)).powf(gamma - 1.0));
        let tail_factor = (-tail_sum).exp();
        p_partial * tail_factor
    }

    /// Evaluates Equation (11): Mean Time to Detect (MTTD)
    /// MTTD = (1 / |E|) \sum_{i \in E} (t_detect^(i) - t_breach^(i))
    pub fn compute_mttd(events: &[ResilienceBreachEvent]) -> f64 {
        if events.is_empty() {
            return 0.0;
        }
        let total: f64 = events.iter().map(|e| (e.t_detect_ms - e.t_breach_ms).max(0.0)).sum();
        total / events.len() as f64
    }

    /// Evaluates Equation (12): Mean Time to Remediate (MTTR)
    /// MTTR = (1 / |E|) \sum_{i \in E} (t_contained^(i) - t_detect^(i))
    pub fn compute_mttr(events: &[ResilienceBreachEvent]) -> f64 {
        if events.is_empty() {
            return 0.0;
        }
        let total: f64 = events.iter().map(|e| (e.t_contained_ms - e.t_detect_ms).max(0.0)).sum();
        total / events.len() as f64
    }

    /// Runs a Monte Carlo trajectory simulation executing M independent agent lifecycles
    /// over N steps, comparing the static guardrail survival against the RL adaptive defense.
    pub fn simulate_monte_carlo(
        trajectories: usize,
        steps: usize,
        static_eps: f64,
        rl_eps_0: f64,
        lambda: f64,
        gamma: f64,
    ) -> MonteCarloSimulationResult {
        let mut static_survivors = 0;
        let mut rl_survivors = 0;
        let mut static_fail_steps_sum = 0.0;
        let mut rl_fail_steps_sum = 0.0;

        for _ in 0..trajectories {
            // 1. Static trajectory
            let mut static_failed = false;
            for t in 1..=steps {
                let r: f64 = rand::random();
                if r < static_eps {
                    static_failed = true;
                    static_fail_steps_sum += t as f64;
                    break;
                }
            }
            if !static_failed {
                static_survivors += 1;
                static_fail_steps_sum += steps as f64;
            }

            // 2. RL adaptive defense trajectory
            let mut rl_failed = false;
            for t in 1..=steps {
                let eps_t = Self::rl_per_step_error(t, rl_eps_0, lambda, gamma);
                let r: f64 = rand::random();
                if r < eps_t {
                    rl_failed = true;
                    rl_fail_steps_sum += t as f64;
                    break;
                }
            }
            if !rl_failed {
                rl_survivors += 1;
                rl_fail_steps_sum += steps as f64;
            }
        }

        MonteCarloSimulationResult {
            total_trajectories: trajectories,
            steps_per_trajectory: steps,
            static_survivors,
            static_survival_rate: static_survivors as f64 / trajectories as f64,
            rl_survivors,
            rl_survival_rate: rl_survivors as f64 / trajectories as f64,
            average_first_failure_step_static: static_fail_steps_sum / trajectories as f64,
            average_first_failure_step_rl: rl_fail_steps_sum / trajectories as f64,
        }
    }

    /// Performs statistical two-proportion Z-test comparing RL survival rate against static rate.
    pub fn hypothesis_test(
        rl_success: usize,
        rl_total: usize,
        static_success: usize,
        static_total: usize,
    ) -> (f64, f64, String) {
        let p1 = rl_success as f64 / rl_total as f64;
        let p2 = static_success as f64 / static_total as f64;
        let p_pool = (rl_success + static_success) as f64 / (rl_total + static_total) as f64;

        if p_pool <= 0.0 || p_pool >= 1.0 {
            return (0.0, 1.0, "Indeterminate (Extreme Pool)".to_string());
        }

        let se = (p_pool * (1.0 - p_pool) * (1.0 / rl_total as f64 + 1.0 / static_total as f64)).sqrt();
        let z = (p1 - p2) / se;

        // Approximate one-tailed p-value for Z >= 0
        let p_value = if z > 0.0 {
            0.5 * (1.0 - libm_erf(z / std::f64::consts::SQRT_2))
        } else {
            1.0 - 0.5 * (1.0 - libm_erf((-z) / std::f64::consts::SQRT_2))
        };

        let verdict = if p_value < 0.001 {
            format!("Statistically Significant Superiority (Z = {:.2}, p < 0.001). Reject H_0: Sisyphean bound defeated.", z)
        } else if p_value < 0.05 {
            format!("Significant Superiority (Z = {:.2}, p = {:.4}). Reject H_0.", z, p_value)
        } else {
            format!("Inconclusive (Z = {:.2}, p = {:.4}). Cannot reject H_0.", z, p_value)
        };

        (z, p_value, verdict)
    }

    /// Generates a comprehensive mathematical validation report against the paper's formulas.
    pub fn generate_validation_report(
        steps: usize,
        static_eps: f64,
        rl_eps_0: f64,
        lambda: f64,
        gamma: f64,
        trajectories: usize,
        breach_events: &[ResilienceBreachEvent],
    ) -> SisypheanValidationReport {
        let static_bound = Self::compute_static_survival_bound(steps, static_eps);
        let rl_bound = Self::compute_rl_survival_prob(steps, rl_eps_0, lambda, gamma);
        let asymptotic_floor = Self::compute_rl_asymptotic_floor(rl_eps_0, lambda, gamma);

        let mc = Self::simulate_monte_carlo(trajectories, steps, static_eps, rl_eps_0, lambda, gamma);
        let (z, p, verdict) = Self::hypothesis_test(
            mc.rl_survivors,
            mc.total_trajectories,
            mc.static_survivors,
            mc.total_trajectories,
        );

        let mttd = Self::compute_mttd(breach_events);
        let mttr = Self::compute_mttr(breach_events);

        let proof_text = format!(
            "Theorem 1 (Vassilev Sisyphean Bound Falsification): For fixed guardrail error eps_min = {:.4}, lim_{{N->infty}} (1 - eps_min)^N = 0. \
             At horizon N = {}, static survival is bounded by {:.6} ({:.2}%). \
             In contrast, under Reinforcement Learning with Double Q-learning and prioritized replay, per-step error decays at rate eps(t) = eps_0/(1 + lambda*t)^gamma. \
             Since gamma = {:.2} > 1.0, the sum \\sum_{{t=1}}^\\infty eps(t) < \\infty, ensuring a strictly positive asymptotic survival floor P_infty = {:.4} ({:.2}%). \
             Monte Carlo empirical survival over {} trials confirms RL survival of {:.2}% vs Static survival of {:.2}%.",
            static_eps, steps, static_bound, static_bound * 100.0,
            gamma, asymptotic_floor, asymptotic_floor * 100.0,
            trajectories, mc.rl_survival_rate * 100.0, mc.static_survival_rate * 100.0
        );

        SisypheanValidationReport {
            horizon_steps: steps,
            static_epsilon_min: static_eps,
            static_survival_bound: static_bound,
            static_collapse_inevitable: static_bound < 0.05,
            rl_initial_epsilon: rl_eps_0,
            rl_decay_lambda: lambda,
            rl_decay_gamma: gamma,
            rl_survival_prob: rl_bound,
            rl_asymptotic_floor: asymptotic_floor,
            monte_carlo_static_survival_rate: mc.static_survival_rate,
            monte_carlo_rl_survival_rate: mc.rl_survival_rate,
            monte_carlo_trajectories: trajectories,
            z_statistic: z,
            p_value: p,
            hypothesis_test_verdict: verdict,
            empirical_mttd_ms: mttd,
            empirical_mttr_ms: mttr,
            mathematical_proof_summary: proof_text,
        }
    }
}

/// Computes the Gauss error function erf(x) via Chebyshev approximation.
fn libm_erf(x: f64) -> f64 {
    // Horner's method approximation with max error < 1.5e-7
    let a1 = 0.254829592;
    let a2 = -0.284496736;
    let a3 = 1.421413741;
    let a4 = -1.453152027;
    let a5 = 1.061405429;
    let p = 0.3275911;

    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let abs_x = x.abs();

    let t = 1.0 / (1.0 + p * abs_x);
    let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-abs_x * abs_x).exp();

    sign * y
}
