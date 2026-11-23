//! Law 3 — Analytical Mechanics: Hamiltonian Phase-Space Separatrix, Discrete CBF,
//! and Buehler-Cranford Spider-Silk Continuum Mechanics (`OrbWebContainmentEngine`).
//!
//! Models an agent's instantaneous security trajectory in 5D configuration space
//! $\mathbf{q} = (q_{\text{priv}}, q_{\text{untrusted}}, q_{\text{egress}}, q_{\text{priv\_esc}}, q_{\text{persist}}) \in [0, 1]^5$
//! with conjugate action-velocity momentum $\mathbf{p} \in \mathbb{R}^5$:
//!
//! $$H(\mathbf{q}, \mathbf{p}) = T(\mathbf{p}) + V_{\text{trifecta}}(\mathbf{q})$$
//!
//! When the Lethal Trifecta axes $(q_{\text{priv}}, q_{\text{untrusted}}, q_{\text{egress}})$
//! converge simultaneously, the hyperbolic coupling potential well diverges, forcing
//! $H(\mathbf{q}, \mathbf{p}) > H_{\max}$ and violating the discrete Control Barrier Function
//! $h(\mathbf{q}_{k+1}) = H_{\max} - H(\mathbf{q}_{k+1}, \mathbf{p}_{k+1}) > 0$.

use crate::security::spider_physics::{OrbWebContainmentEngine, SilkRegime};
use serde::{Deserialize, Serialize};

/// 5D ABIBO Phase-Space coordinate vector $\mathbf{q} \in [0, 1]^5$.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PhaseSpaceState {
    /// Sensitive / private data exposure axis ($q_1 \in [0, 1]$).
    pub q_private_data: f64,
    /// Untrusted Break-In input / taint exposure axis ($q_2 \in [0, 1]$).
    pub q_untrusted_input: f64,
    /// Outbound external communication / SaaS write axis ($q_3 \in [0, 1]$).
    pub q_external_egress: f64,
    /// Privilege escalation / shell / host-exec axis ($q_4 \in [0, 1]$).
    pub q_privilege_escalation: f64,
    /// Persistence / memory / startup modification axis ($q_5 \in [0, 1]$).
    pub q_persistence: f64,
    /// Conjugate action momentum / burst velocity ($|\mathbf{p}| \ge 0$).
    pub momentum_norm: f64,
}

/// Verdict produced by Law 3 (Hamiltonian Separatrix + Discrete CBF + OrbWeb Autotomy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HamiltonianVerdict {
    pub allowed: bool,
    pub kinetic_energy: f64,
    pub potential_energy: f64,
    pub total_hamiltonian: f64,
    pub h_max_separatrix: f64,
    pub cbf_margin: f64,
    pub cbf_forward_invariant: bool,
    pub lethal_trifecta_coupled: bool,
    pub orbweb_regime: SilkRegime,
    pub localized_autotomy_triggered: bool,
    pub reason: String,
}

/// Evaluates Law 3 (Hamiltonian Phase-Space Separatrix + Discrete CBF + Spider-Web Autotomy).
#[derive(Debug, Clone)]
pub struct HamiltonianBarrierEngine {
    pub h_max: f64,
    pub cbf_gamma: f64,
    pub trifecta_coupling_kappa: f64,
    pub effective_mass: f64,
    pub orbweb: OrbWebContainmentEngine,
}

impl Default for HamiltonianBarrierEngine {
    fn default() -> Self {
        Self {
            h_max: 6.0,
            cbf_gamma: 0.65,
            trifecta_coupling_kappa: 8.5,
            effective_mass: 1.0,
            orbweb: OrbWebContainmentEngine::default(),
        }
    }
}

impl HamiltonianBarrierEngine {
    /// Computes $T(\mathbf{p})$, $V_{\text{trifecta}}(\mathbf{q})$, and total $H(\mathbf{q}, \mathbf{p})$.
    #[must_use]
    pub fn compute_energy(&self, state: PhaseSpaceState) -> (f64, f64, f64, bool) {
        let q1 = state.q_private_data.clamp(0.0, 1.0);
        let q2 = state.q_untrusted_input.clamp(0.0, 1.0);
        let q3 = state.q_external_egress.clamp(0.0, 1.0);
        let q4 = state.q_privilege_escalation.clamp(0.0, 1.0);
        let q5 = state.q_persistence.clamp(0.0, 1.0);
        let p = state.momentum_norm.max(0.0);

        let kinetic = 0.5 * (p * p) / self.effective_mass.max(0.1);

        // Quadratic baseline potential + hyperbolic Lethal Trifecta coupling barrier
        let base_potential =
            1.4 * q1 * q1 + 1.4 * q2 * q2 + 1.4 * q3 * q3 + 3.2 * q4 * q4 + 2.8 * q5 * q5;

        let trifecta_prod = q1 * q2 * q3;
        let geo_mean = trifecta_prod.cbrt();
        let denom = (1.0 - geo_mean).max(0.05);
        let trifecta_potential = self.trifecta_coupling_kappa * trifecta_prod / denom;
        let potential = base_potential + trifecta_potential;

        let total = kinetic + potential;
        let lethal_trifecta = q1 >= 0.5 && q2 >= 0.5 && q3 >= 0.5;
        (kinetic, potential, total, lethal_trifecta)
    }

    /// Evaluates whether transitioning from `previous_cbf_margin` to `next_state` remains
    /// strictly inside the safe Hamiltonian separatrix and satisfies discrete CBF forward
    /// invariance + Buehler-Cranford spider-silk autotomy bounds.
    #[must_use]
    pub fn evaluate(
        &self,
        next_state: PhaseSpaceState,
        previous_cbf_margin: Option<f64>,
        requested_egress_bytes: usize,
    ) -> HamiltonianVerdict {
        let (kinetic, potential, total, lethal_trifecta) = self.compute_energy(next_state);
        let cbf_margin = self.h_max - total;

        let cbf_forward_invariant = match previous_cbf_margin {
            Some(prev_h) if prev_h > 0.0 => cbf_margin >= (1.0 - self.cbf_gamma) * prev_h,
            _ => cbf_margin > 0.0,
        };

        // Map normalized Hamiltonian ratio onto spider-silk strain (ultimate_strain = 0.60)
        let strain = (total / self.h_max).max(0.0) * 0.62;
        let orb = self.orbweb.evaluate_impact(
            strain,
            requested_egress_bytes as f64,
            0.01,
            0.01,
            10_000_000.0,
            None,
            None,
        );

        let allowed = cbf_margin > 0.0
            && cbf_forward_invariant
            && !lethal_trifecta
            && !orb.localized_autotomy_triggered;

        let reason = if lethal_trifecta {
            format!(
                "LAW3_LETHAL_TRIFECTA_SEPARATRIX_DENY: Coupled private ({:.2}) + untrusted ({:.2}) + egress ({:.2}) exploded H={total:.2} > H_max={:.2}; {:?}",
                next_state.q_private_data,
                next_state.q_untrusted_input,
                next_state.q_external_egress,
                self.h_max,
                orb.regime
            )
        } else if cbf_margin <= 0.0 || orb.localized_autotomy_triggered {
            format!(
                "LAW3_HAMILTONIAN_SEPARATRIX_DENY: Total energy H={total:.2} exceeded separatrix H_max={:.2} (CBF h={cbf_margin:.2}, {:?})",
                self.h_max, orb.regime
            )
        } else if !cbf_forward_invariant {
            format!(
                "LAW3_CBF_TRAJECTORY_DENY: Rapid approach toward separatrix violated discrete CBF forward invariance (h_next={cbf_margin:.2}, gamma={:.2})",
                self.cbf_gamma
            )
        } else {
            format!(
                "LAW3_HAMILTONIAN_CONTAINED: H={total:.2} <= H_max={:.2} (T={kinetic:.2}, V={potential:.2}, CBF h={cbf_margin:.2}, {:?})",
                self.h_max, orb.regime
            )
        };

        HamiltonianVerdict {
            allowed,
            kinetic_energy: kinetic,
            potential_energy: potential,
            total_hamiltonian: total,
            h_max_separatrix: self.h_max,
            cbf_margin,
            cbf_forward_invariant,
            lethal_trifecta_coupled: lethal_trifecta,
            orbweb_regime: orb.regime,
            localized_autotomy_triggered: orb.localized_autotomy_triggered,
            reason,
        }
    }
}
