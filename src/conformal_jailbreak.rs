//! Multi-Source Conformal Unseen Jailbreak Source Detection (`Persist-3` & `SR-DKW`).
//!
//! Synchronized with OshoosiClaw (`crates/osoosi-behavioral/src/conformal_jailbreak.rs`).
//! Implements the mathematical and statistical framework from:
//! *"Detecting Unseen Jailbreak Sources: A Multi-Source Conformal Detection Perspective"*
//! (Xunlei Qian, Yingqian Cui, Yuping Lin, Jun Wu, Yue Xing — Michigan State University,
//! `arXiv:2610.09167v1`, October 2026).

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// The 11 canonical jailbreak attack families evaluated in Qian et al. (2026), Appendix K.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KnownJailbreakSourceFamily {
    Gcg,
    Adc,
    Pair,
    Tap,
    Autodan,
    AutodanTurbo,
    FlipAttack,
    DanInTheWild,
    SimpleBlackBox,
    FirstTokenSteering,
    JailbreakZero,
}

impl KnownJailbreakSourceFamily {
    pub fn all() -> &'static [Self; 11] {
        &[
            Self::Gcg,
            Self::Adc,
            Self::Pair,
            Self::Tap,
            Self::Autodan,
            Self::AutodanTurbo,
            Self::FlipAttack,
            Self::DanInTheWild,
            Self::SimpleBlackBox,
            Self::FirstTokenSteering,
            Self::JailbreakZero,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Gcg => "GCG",
            Self::Adc => "ADC",
            Self::Pair => "PAIR",
            Self::Tap => "TAP",
            Self::Autodan => "AutoDAN",
            Self::AutodanTurbo => "AutoDAN-Turbo",
            Self::FlipAttack => "FlipAttack",
            Self::DanInTheWild => "DAN-InTheWild",
            Self::SimpleBlackBox => "SimpleBlackBox",
            Self::FirstTokenSteering => "FirstTokenSteering",
            Self::JailbreakZero => "Jailbreak-Zero",
        }
    }
}

/// Offline parameters for a single known attack source $P_k$ in the PCA-projected space $\mathbb{R}^d$.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibratedSource {
    pub name: String,
    pub mean: Vec<f64>,
    pub precision: Vec<Vec<f64>>,
    pub calibration_scores: Vec<f64>,
}

impl CalibratedSource {
    pub fn new(
        name: impl Into<String>,
        mean: Vec<f64>,
        precision: Vec<Vec<f64>>,
        mut calibration_scores: Vec<f64>,
    ) -> Self {
        calibration_scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        Self {
            name: name.into(),
            mean,
            precision,
            calibration_scores,
        }
    }

    /// Equation (1): Mahalanobis nonconformity score $S_k(x) = (z - \hat{\mu}_k)^\top \hat{\Sigma}_k^+ (z - \hat{\mu}_k)$.
    pub fn nonconformity_score(&self, z: &[f64]) -> f64 {
        let d = self.mean.len().min(z.len());
        let mut diff = vec![0.0_f64; d];
        for i in 0..d {
            diff[i] = z[i] - self.mean[i];
        }
        let mut total = 0.0_f64;
        for r in 0..d {
            let mut row_dot = 0.0_f64;
            for c in 0..d {
                row_dot += self.precision[r][c] * diff[c];
            }
            total += diff[r] * row_dot;
        }
        total.max(0.0)
    }

    /// Equation (2): Split-conformal p-value $p_k(x) = \frac{1 + \sum_{i=1}^{n_k} \mathbb{I}\{R_{k,i} \ge S_k(x)\}}{n_k + 1}$.
    pub fn conformal_p_value(&self, z: &[f64]) -> f64 {
        let s = self.nonconformity_score(z);
        let n_k = self.calibration_scores.len();
        let idx = self.calibration_scores.partition_point(|&r| r < s);
        let count_ge = n_k - idx;
        (1.0 + count_ge as f64) / (n_k as f64 + 1.0)
    }

    /// Pointwise evidence $Z_k(x) = -\ln p_k(x)$.
    pub fn evidence(&self, z: &[f64]) -> f64 {
        -self.conformal_p_value(z).ln()
    }
}

/// Shared PCA projection $\Pi$ and the collection of $K$ known calibrated sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSourceCalibration {
    pub pca_mean: Vec<f64>,
    /// Columns are principal components (`pca_components[raw_idx][proj_idx]`).
    pub pca_components: Vec<Vec<f64>>,
    pub sources: Vec<CalibratedSource>,
}

impl MultiSourceCalibration {
    pub fn project(&self, x: &[f64]) -> Vec<f64> {
        let d_raw = self.pca_mean.len().min(x.len());
        let d_proj = if self.pca_components.is_empty() {
            0
        } else {
            self.pca_components[0].len()
        };
        let mut z = vec![0.0_f64; d_proj];
        for j in 0..d_proj {
            let mut acc = 0.0_f64;
            for i in 0..d_raw {
                acc += (x[i] - self.pca_mean[i]) * self.pca_components[i][j];
            }
            z[j] = acc;
        }
        z
    }

    pub fn p_values(&self, x: &[f64]) -> Vec<f64> {
        let z = self.project(x);
        self.sources
            .iter()
            .map(|src| src.conformal_p_value(&z))
            .collect()
    }
}

/// Output of a single online step of the `Persist-3` detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistStepResult {
    pub step: usize,
    pub p_values: Vec<f64>,
    pub c_k_t: Vec<f64>,
    pub c_fam: f64,
    pub best_matching_source_idx: usize,
    pub best_matching_source_name: String,
    pub exceeded: bool,
    pub d_t: bool,
    pub alarm_time: Option<usize>,
    pub escalated: bool,
}

/// Window-based Multi-Source Conformal Detector (`Persist-3`, $W = 10, L = 3, B = 12$).
#[derive(Debug, Clone)]
pub struct PersistDetector {
    pub calibration: MultiSourceCalibration,
    pub window_size: usize,
    pub persistence_length: usize,
    pub tau: f64,
    windows: Vec<VecDeque<f64>>,
    window_sums: Vec<f64>,
    consecutive_exceedances: usize,
    step: usize,
    alarm_time: Option<usize>,
}

impl PersistDetector {
    pub const DEFAULT_TAU_ORIGINAL_SPLIT: f64 = 2.386;
    pub const DEFAULT_TAU_ROBUSTNESS_RESPLIT: f64 = 2.374;

    pub fn new(
        calibration: MultiSourceCalibration,
        window_size: usize,
        persistence_length: usize,
        tau: f64,
    ) -> Self {
        let k = calibration.sources.len();
        Self {
            calibration,
            window_size,
            persistence_length,
            tau,
            windows: (0..k)
                .map(|_| VecDeque::with_capacity(window_size))
                .collect(),
            window_sums: vec![0.0; k],
            consecutive_exceedances: 0,
            step: 0,
            alarm_time: None,
        }
    }

    pub fn persist_3(calibration: MultiSourceCalibration, tau: f64) -> Self {
        Self::new(calibration, 10, 3, tau)
    }

    pub fn finite_memory_horizon(&self) -> usize {
        self.window_size + self.persistence_length - 1
    }

    pub fn reset(&mut self) {
        for w in &mut self.windows {
            w.clear();
        }
        self.window_sums.fill(0.0);
        self.consecutive_exceedances = 0;
        self.step = 0;
        self.alarm_time = None;
    }

    pub fn observe(&mut self, x_t: &[f64]) -> PersistStepResult {
        self.step += 1;
        let t = self.step;
        let z = self.calibration.project(x_t);
        let k_count = self.calibration.sources.len();
        let mut p_values = Vec::with_capacity(k_count);
        let mut c_k_t = Vec::with_capacity(k_count);

        for (k, src) in self.calibration.sources.iter().enumerate() {
            let p_k = src.conformal_p_value(&z);
            let z_k = -p_k.ln();
            p_values.push(p_k);

            if self.windows[k].len() == self.window_size {
                if let Some(oldest) = self.windows[k].pop_front() {
                    self.window_sums[k] -= oldest;
                }
            }
            self.windows[k].push_back(z_k);
            self.window_sums[k] += z_k;
            let m_t = self.windows[k].len() as f64;
            c_k_t.push(self.window_sums[k] / m_t);
        }

        let mut best_idx = 0;
        let mut c_fam = f64::INFINITY;
        for (k, &val) in c_k_t.iter().enumerate() {
            if val < c_fam {
                c_fam = val;
                best_idx = k;
            }
        }
        let best_name = self
            .calibration
            .sources
            .get(best_idx)
            .map(|s| s.name.clone())
            .unwrap_or_default();

        let exceeded = c_fam >= self.tau;
        if exceeded {
            self.consecutive_exceedances += 1;
        } else {
            self.consecutive_exceedances = 0;
        }

        let d_t = t >= self.persistence_length
            && self.consecutive_exceedances >= self.persistence_length;
        if d_t && self.alarm_time.is_none() {
            self.alarm_time = Some(t);
        }

        PersistStepResult {
            step: t,
            p_values,
            c_k_t,
            c_fam,
            best_matching_source_idx: best_idx,
            best_matching_source_name: best_name,
            exceeded,
            d_t,
            alarm_time: self.alarm_time,
            escalated: self.alarm_time.is_some(),
        }
    }
}

/// Theoretical finite-sample bounds from Section 4 of Qian et al. (2026).
pub mod bounds {
    pub fn overlap_weight_sum_sq(w: usize, l: usize) -> usize {
        assert!(w >= l, "Bound formula assumes W >= L");
        let sum_r2: usize = (1..l).map(|r| r * r).sum();
        2 * sum_r2 + (w - l + 1) * l * l
    }

    pub fn stationary_false_alarm_bound(
        w: usize,
        l: usize,
        tau: f64,
        mu_0_j: f64,
        n_j: usize,
    ) -> f64 {
        if tau <= mu_0_j {
            return 1.0;
        }
        let b_j = ((n_j + 1) as f64).ln();
        let a_wl = overlap_weight_sum_sq(w, l) as f64;
        let lw = (l * w) as f64;
        let num = -2.0 * lw * lw * (tau - mu_0_j).powi(2);
        let den = b_j * b_j * a_wl;
        (num / den).exp().min(1.0)
    }

    pub fn nearest_source_power_bound(
        w: usize,
        l: usize,
        k_sources: usize,
        delta_star: f64,
        b_max: f64,
    ) -> f64 {
        if delta_star <= 0.0 {
            return 0.0;
        }
        let exponent = -2.0 * (w as f64) * delta_star.powi(2) / (b_max * b_max);
        (1.0 - (l * k_sources) as f64 * exponent.exp()).max(0.0)
    }

    pub fn required_window_size(
        l: usize,
        k_sources: usize,
        delta_star: f64,
        b_max: f64,
        eta: f64,
    ) -> usize {
        assert!(delta_star > 0.0 && eta > 0.0 && eta < 1.0);
        let ratio = ((l * k_sources) as f64 / eta).ln();
        let w = (b_max * b_max) / (2.0 * delta_star * delta_star) * ratio;
        w.ceil() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persist3_finite_forgetting_and_bounds() {
        assert_eq!(bounds::overlap_weight_sum_sq(10, 3), 82);
        let scores: Vec<f64> = (1..=100).map(|i| (i as f64) * 0.1).collect();
        let src1 = CalibratedSource::new(
            "GCG",
            vec![0.0, 0.0],
            vec![vec![1.0, 0.0], vec![0.0, 1.0]],
            scores.clone(),
        );
        let src2 = CalibratedSource::new(
            "PAIR",
            vec![5.0, 5.0],
            vec![vec![1.0, 0.0], vec![0.0, 1.0]],
            scores,
        );
        let cal = MultiSourceCalibration {
            pca_mean: vec![0.0, 0.0],
            pca_components: vec![vec![1.0, 0.0], vec![0.0, 1.0]],
            sources: vec![src1, src2],
        };
        let mut det = PersistDetector::persist_3(cal, 2.386);
        for _ in 0..12 {
            assert!(!det.observe(&[0.1, -0.1]).escalated);
        }
        for step in 1..=12 {
            let res = det.observe(&[-10.0, 10.0]);
            if step == 12 {
                assert!(res.escalated);
            }
        }
    }
}