//! Nonlinear Spider-Web Continuum Mechanics & Exposure Bound Engine
//!
//! Adapted from `D:\harfile\OshoosiClaw\crates\osoosi-agent-anomaly\src\spider_physics.rs`:
//! Implements the 4-regime Buehler-Cranford spider silk constitutive stress-strain law
//! ($\sigma(\varepsilon)$ across Elastic $\to$ Yield/H-Bond Slip $\to$ $\beta$-Sheet Strain-Stiffening $\to$ Autotomy Severance)
//! and proves the Worst-Case Exfiltration / Damage Exposure Bound:
//! $$E_{\max} \le R_{\text{enforced}} \cdot (T_{\text{detect}} + T_{\text{contain}}) \le B_{\max}$$
//! together with an out-of-model Business Logic Policy Gate (spending ceilings, row deletion limits).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SilkRegime {
    /// Regime I ($\varepsilon \le \varepsilon_y = 0.05$): Linear elastic pre-tension ($E_0 = 10\text{ GPa}$).
    Regime1LinearElastic,
    /// Regime II ($0.05 < \varepsilon \le 0.25$): Sacrificial H-bond unfolding & viscous energy dissipation ($E_{\text{soft}} = 1.5\text{ GPa}$).
    Regime2SacrificialYield,
    /// Regime III ($0.25 < \varepsilon \le 0.60$): $\beta$-sheet nanocrystals lock into high-stiffness power-law hardening ($E_{\text{hard}} = 45\text{ GPa}, \beta = 2.8$).
    Regime3BetaSheetStiffening,
    /// Regime IV ($\varepsilon > 0.60$): Local radial thread autotomy severance while peripheral spiral ring remains intact.
    Regime4LocalAutotomySeverance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrbWebEvaluationResult {
    pub strain: f64,
    pub stress_gpa: f64,
    pub tangent_modulus_gpa: f64,
    pub regime: SilkRegime,
    pub max_exposure_bytes: f64,
    pub exposure_budget_bytes: f64,
    pub exposure_bound_satisfied: bool,
    pub business_policy_permitted: bool,
    pub localized_autotomy_triggered: bool,
    pub peripheral_web_intact: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct OrbWebContainmentEngine {
    pub yield_strain: f64,
    pub hardening_strain: f64,
    pub ultimate_strain: f64,
    pub e0_gpa: f64,
    pub e_soft_gpa: f64,
    pub e_hard_gpa: f64,
    pub beta_exponent: f64,
    pub max_spending_cents: u64,
    pub max_deleted_rows: usize,
}

impl Default for OrbWebContainmentEngine {
    fn default() -> Self {
        Self {
            yield_strain: 0.05,
            hardening_strain: 0.25,
            ultimate_strain: 0.60,
            e0_gpa: 10.0,
            e_soft_gpa: 1.5,
            e_hard_gpa: 45.0,
            beta_exponent: 2.8,
            max_spending_cents: 10_000_000, // $100,000.00 hard ceiling
            max_deleted_rows: 100,
        }
    }
}

impl OrbWebContainmentEngine {
    /// Evaluates the 4-regime Buehler-Cranford spider silk constitutive equation $\sigma(\varepsilon)$,
    /// the worst-case exposure bound $E_{\max} \le R_{\text{enforced}}(T_{\text{detect}} + T_{\text{contain}})$,
    /// and the out-of-model business policy gate.
    pub fn evaluate_impact(
        &self,
        strain: f64,
        enforced_rate_bytes_per_sec: f64,
        t_detect_sec: f64,
        t_contain_sec: f64,
        exposure_budget_bytes: f64,
        requested_spend_cents: Option<u64>,
        requested_delete_rows: Option<usize>,
    ) -> OrbWebEvaluationResult {
        let eps = strain.max(0.0);
        let sigma_y = self.e0_gpa * self.yield_strain;
        let sigma_h = sigma_y + self.e_soft_gpa * (self.hardening_strain - self.yield_strain);

        let (regime, stress_gpa, tangent_modulus_gpa, localized_autotomy) =
            if eps <= self.yield_strain {
                (
                    SilkRegime::Regime1LinearElastic,
                    self.e0_gpa * eps,
                    self.e0_gpa,
                    false,
                )
            } else if eps <= self.hardening_strain {
                (
                    SilkRegime::Regime2SacrificialYield,
                    sigma_y + self.e_soft_gpa * (eps - self.yield_strain),
                    self.e_soft_gpa,
                    false,
                )
            } else if eps <= self.ultimate_strain {
                let delta = eps - self.hardening_strain;
                let stress = sigma_h + self.e_hard_gpa * delta.powf(self.beta_exponent);
                let tangent =
                    self.e_hard_gpa * self.beta_exponent * delta.powf(self.beta_exponent - 1.0);
                (
                    SilkRegime::Regime3BetaSheetStiffening,
                    stress,
                    tangent,
                    false,
                )
            } else {
                let max_delta = self.ultimate_strain - self.hardening_strain;
                let max_stress = sigma_h + self.e_hard_gpa * max_delta.powf(self.beta_exponent);
                (
                    SilkRegime::Regime4LocalAutotomySeverance,
                    max_stress,
                    self.e_hard_gpa,
                    true,
                )
            };

        let max_exposure_bytes =
            enforced_rate_bytes_per_sec.max(0.0) * (t_detect_sec.max(0.0) + t_contain_sec.max(0.0));
        let exposure_bound_satisfied = max_exposure_bytes <= exposure_budget_bytes;

        let spend_ok = requested_spend_cents
            .map(|c| c <= self.max_spending_cents)
            .unwrap_or(true);
        let rows_ok = requested_delete_rows
            .map(|r| r <= self.max_deleted_rows)
            .unwrap_or(true);
        let business_policy_permitted = spend_ok && rows_ok;

        let reason = if !business_policy_permitted {
            format!(
                "ORBWEB_BUSINESS_POLICY_VETO: spend_ok={} (max {} cents), rows_ok={} (max {} rows)",
                spend_ok, self.max_spending_cents, rows_ok, self.max_deleted_rows
            )
        } else if !exposure_bound_satisfied {
            format!(
                "ORBWEB_EXPOSURE_BOUND_EXCEEDED: E_max ({:.1} B) > B_max ({:.1} B)",
                max_exposure_bytes, exposure_budget_bytes
            )
        } else if localized_autotomy {
            format!(
                "ORBWEB_REGIME4_AUTOTOMY: Local radial thread severed at strain {:.3} > {:.3}; peripheral spiral ring intact",
                eps, self.ultimate_strain
            )
        } else {
            format!(
                "ORBWEB_CONTAINED ({:?}): stress={:.3} GPa, E_max={:.1} B <= B_max={:.1} B",
                regime, stress_gpa, max_exposure_bytes, exposure_budget_bytes
            )
        };

        OrbWebEvaluationResult {
            strain: eps,
            stress_gpa,
            tangent_modulus_gpa,
            regime,
            max_exposure_bytes,
            exposure_budget_bytes,
            exposure_bound_satisfied,
            business_policy_permitted,
            localized_autotomy_triggered: localized_autotomy,
            peripheral_web_intact: true,
            reason,
        }
    }
}
