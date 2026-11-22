//! Pure-Rust Unified Latent Security Shield (`src/security/latent_shield.rs`)
//!
//! Implements a shared pure-Rust `LatentWorldModel` (Variational Information Bottleneck
//! Encoder/Decoder + Latent Forward Dynamics Predictor) across two strictly tighten-only
//! security gates, with zero Python, zero BLAS/C dependencies, and zero coupling to the
//! optional offline D3QN Q-learner (`src/security/rl_defense/`):
//! - **Gate 1 (`SbomSupplyChainGuard`)**: Pre-Wasmtime / pre-spawn CycloneDX SBOM supply-chain
//!   transition check validating whether a candidate SBOM evolution matches the declared
//!   release intent (`patch`, `minor`, `refactor`).
//! - **Gate 2 (`AgentRuntimeGuard`)**: Microsecond per-step runtime telemetry trajectory check
//!   inside Wasmtime Tier-1 (`WasmHostState`), `TieredExecutionDispatcher`, and live `octopus run`
//!   proxy/IPC/child monitors.
//!
//! **Fail-Closed & Monotonicity Guarantees**:
//! - Zero `.unwrap()` / `.expect()` / unchecked slice indexing on untrusted inputs or weights.
//! - Rejects `NaN` / `Inf` inputs, thresholds, parameters, or surprise scores (`block_execution: true`).
//! - Enforces bounded JSON sizes, component/dependency/edge caps, and NUL/empty-name validation.
//! - Strictly monotonic tighten-only: can only add a deny/terminate verdict and can NEVER override
//!   or weaken deterministic Cedar, RT-ASP, Wasmtime, OS sandbox, R6, or R7 REA decisions.

use ndarray::{Array1, Array2, Axis};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rand_distr::StandardNormal;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use thiserror::Error;

/// Fixed observation dimension for CycloneDX SBOM feature vectors.
pub const SBOM_OBS_DIM: usize = 6;
/// Fixed action dimension for SBOM release intent (`[patch, minor, refactor]`).
pub const SBOM_ACTION_DIM: usize = 3;
/// Fixed observation dimension for `RuntimeTelemetry` vectors.
pub const RUNTIME_OBS_DIM: usize = 6;
/// Fixed action dimension for runtime tool classes (`[read, write, network]`).
pub const RUNTIME_ACTION_DIM: usize = 3;
/// Default latent bottleneck dimension `z_t`.
pub const DEFAULT_LATENT_DIM: usize = 4;
/// Upper bound on model layer dimensions accepted from untrusted weight files.
pub const MAX_MODEL_DIM: usize = 256;

/// Maximum accepted CycloneDX SBOM JSON byte length (4 MiB).
pub const MAX_SBOM_JSON_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of components allowed in a single CycloneDX SBOM.
pub const MAX_SBOM_COMPONENTS: usize = 4096;
/// Maximum number of dependency entries allowed in a single CycloneDX SBOM.
pub const MAX_SBOM_DEPENDENCIES: usize = 8192;
/// Maximum total `dependsOn` edges allowed in a single CycloneDX SBOM.
pub const MAX_SBOM_EDGES: usize = 32_768;
/// Maximum licenses allowed per component.
pub const MAX_SBOM_LICENSES_PER_COMPONENT: usize = 32;
/// Maximum properties allowed per component.
pub const MAX_SBOM_PROPERTIES_PER_COMPONENT: usize = 64;
/// Maximum UTF-8 byte length for any SBOM string field.
pub const MAX_SBOM_STRING_LEN: usize = 4096;
/// Maximum accepted serialized latent shield weights JSON byte length (2 MiB).
pub const MAX_WEIGHTS_JSON_BYTES: usize = 2 * 1024 * 1024;

/// Deterministic 60-epoch pre-trained weights embedded at compile time for microsecond startup.
pub const DEFAULT_EMBEDDED_WEIGHTS_JSON: &str = include_str!("latent_shield_weights.json");

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LatentShieldError {
    #[error("invalid latent world model: {0}")]
    InvalidModel(String),
    #[error("dimension mismatch in {context}: expected {expected}, got {actual}")]
    DimensionMismatch {
        expected: usize,
        actual: usize,
        context: &'static str,
    },
    #[error("non-finite floating-point value in {0}")]
    NonFiniteInput(&'static str),
    #[error("invalid CycloneDX SBOM: {0}")]
    SbomParseError(String),
    #[error("CycloneDX SBOM safety bound exceeded: {0}")]
    SbomBoundExceeded(String),
    #[error("invalid latent shield weights: {0}")]
    WeightsParseError(String),
    #[error("latent shield I/O error: {0}")]
    IoError(String),
}

// =========================================================================
// PART 1: Core Physics Engine (Information Bottleneck + Forward Dynamics)
// =========================================================================

#[inline]
fn silu(x: f64) -> f64 {
    x / (1.0 + (-x).exp())
}

#[inline]
fn silu_grad(x: f64) -> f64 {
    let sig = 1.0 / (1.0 + (-x).exp());
    sig * (1.0 + x * (1.0 - sig))
}

#[inline]
fn all_finite_slice(vals: &[f64]) -> bool {
    vals.iter().all(|v| v.is_finite())
}

#[inline]
fn array1_is_finite(arr: &Array1<f64>) -> bool {
    arr.iter().all(|v| v.is_finite())
}

#[inline]
fn array2_is_finite(arr: &Array2<f64>) -> bool {
    arr.iter().all(|v| v.is_finite())
}

#[inline]
fn sanitize_threshold_for_verdict(threshold: f64) -> f64 {
    if threshold.is_finite() && threshold >= 0.0 {
        threshold
    } else {
        0.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LayerNorm {
    gamma: Array1<f64>,
    beta: Array1<f64>,
    eps: f64,
}

impl LayerNorm {
    fn new(dim: usize) -> Self {
        Self {
            gamma: Array1::ones(dim),
            beta: Array1::zeros(dim),
            eps: 1e-5,
        }
    }

    fn validate(&self, expected_dim: usize) -> Result<(), LatentShieldError> {
        if expected_dim == 0 || expected_dim > MAX_MODEL_DIM {
            return Err(LatentShieldError::InvalidModel(format!(
                "layer norm dim {} out of [1, {}]",
                expected_dim, MAX_MODEL_DIM
            )));
        }
        if self.gamma.len() != expected_dim {
            return Err(LatentShieldError::DimensionMismatch {
                expected: expected_dim,
                actual: self.gamma.len(),
                context: "LayerNorm.gamma",
            });
        }
        if self.beta.len() != expected_dim {
            return Err(LatentShieldError::DimensionMismatch {
                expected: expected_dim,
                actual: self.beta.len(),
                context: "LayerNorm.beta",
            });
        }
        if !self.eps.is_finite() || self.eps <= 0.0 {
            return Err(LatentShieldError::InvalidModel(
                "LayerNorm.eps must be finite and > 0".to_string(),
            ));
        }
        if !array1_is_finite(&self.gamma) || !array1_is_finite(&self.beta) {
            return Err(LatentShieldError::NonFiniteInput("LayerNorm parameters"));
        }
        Ok(())
    }

    fn try_forward(
        &self,
        x: &Array1<f64>,
    ) -> Result<(Array1<f64>, Array1<f64>, f64), LatentShieldError> {
        let dim = self.gamma.len();
        if dim == 0 || self.beta.len() != dim {
            return Err(LatentShieldError::InvalidModel(
                "LayerNorm parameter shape mismatch".to_string(),
            ));
        }
        if x.len() != dim {
            return Err(LatentShieldError::DimensionMismatch {
                expected: dim,
                actual: x.len(),
                context: "LayerNorm.forward",
            });
        }
        if !array1_is_finite(x)
            || !array1_is_finite(&self.gamma)
            || !array1_is_finite(&self.beta)
            || !self.eps.is_finite()
            || self.eps <= 0.0
        {
            return Err(LatentShieldError::NonFiniteInput("LayerNorm.forward"));
        }

        let n = dim as f64;
        let mean = x.sum() / n;
        let diff = x - mean;
        let var = diff.mapv(|v| v * v).sum() / n;
        let inv_std = 1.0 / (var + self.eps).sqrt();
        if !inv_std.is_finite() {
            return Err(LatentShieldError::NonFiniteInput("LayerNorm.inv_std"));
        }
        let x_hat = &diff * inv_std;
        let out = &x_hat * &self.gamma + &self.beta;
        if !array1_is_finite(&out) {
            return Err(LatentShieldError::NonFiniteInput("LayerNorm.out"));
        }
        Ok((out, x_hat, inv_std))
    }

    fn backward(
        &mut self,
        grad_out: &Array1<f64>,
        x_hat: &Array1<f64>,
        inv_std: f64,
        lr: f64,
    ) -> Array1<f64> {
        if x_hat.is_empty()
            || grad_out.len() != x_hat.len()
            || self.gamma.len() != x_hat.len()
            || self.beta.len() != x_hat.len()
        {
            return Array1::zeros(x_hat.len());
        }
        let n = x_hat.len() as f64;
        let d_gamma = grad_out * x_hat;
        let d_beta = grad_out.clone();
        let dx_hat = grad_out * &self.gamma;

        let sum_dx = dx_hat.sum();
        let sum_dx_xhat = (&dx_hat * x_hat).sum();
        let grad_in = (dx_hat - (sum_dx / n) - x_hat * (sum_dx_xhat / n)) * inv_std;

        self.gamma = &self.gamma - &(d_gamma * lr);
        self.beta = &self.beta - &(d_beta * lr);
        grad_in
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Linear {
    weights: Array2<f64>,
    bias: Array1<f64>,
}

impl Linear {
    fn new(in_dim: usize, out_dim: usize, rng: &mut StdRng) -> Self {
        let denom = in_dim.saturating_add(out_dim).max(1) as f64;
        let limit = (6.0 / denom).sqrt();
        let weights = Array2::from_shape_fn((out_dim, in_dim), |_| rng.gen_range(-limit..limit));
        let bias = Array1::zeros(out_dim);
        Self { weights, bias }
    }

    fn validate(&self, expected_in: usize, expected_out: usize) -> Result<(), LatentShieldError> {
        if expected_in == 0 || expected_out == 0 {
            return Err(LatentShieldError::InvalidModel(
                "Linear layer dimensions must be positive".to_string(),
            ));
        }
        if self.weights.ncols() != expected_in {
            return Err(LatentShieldError::DimensionMismatch {
                expected: expected_in,
                actual: self.weights.ncols(),
                context: "Linear.weights.ncols",
            });
        }
        if self.weights.nrows() != expected_out {
            return Err(LatentShieldError::DimensionMismatch {
                expected: expected_out,
                actual: self.weights.nrows(),
                context: "Linear.weights.nrows",
            });
        }
        if self.bias.len() != expected_out {
            return Err(LatentShieldError::DimensionMismatch {
                expected: expected_out,
                actual: self.bias.len(),
                context: "Linear.bias",
            });
        }
        if !array2_is_finite(&self.weights) || !array1_is_finite(&self.bias) {
            return Err(LatentShieldError::NonFiniteInput("Linear parameters"));
        }
        Ok(())
    }

    fn try_forward(&self, x: &Array1<f64>) -> Result<Array1<f64>, LatentShieldError> {
        if x.len() != self.weights.ncols() {
            return Err(LatentShieldError::DimensionMismatch {
                expected: self.weights.ncols(),
                actual: x.len(),
                context: "Linear.forward.input",
            });
        }
        if self.weights.nrows() != self.bias.len() {
            return Err(LatentShieldError::DimensionMismatch {
                expected: self.weights.nrows(),
                actual: self.bias.len(),
                context: "Linear.forward.bias",
            });
        }
        if !array1_is_finite(x) || !array2_is_finite(&self.weights) || !array1_is_finite(&self.bias)
        {
            return Err(LatentShieldError::NonFiniteInput("Linear.forward"));
        }
        let out = self.weights.dot(x) + &self.bias;
        if !array1_is_finite(&out) {
            return Err(LatentShieldError::NonFiniteInput("Linear.out"));
        }
        Ok(out)
    }

    fn backward(&mut self, x: &Array1<f64>, grad_out: &Array1<f64>, lr: f64) -> Array1<f64> {
        if x.len() != self.weights.ncols() || grad_out.len() != self.weights.nrows() {
            return Array1::zeros(x.len());
        }
        let grad_in = self.weights.t().dot(grad_out);
        let grad_w = grad_out
            .view()
            .insert_axis(Axis(1))
            .dot(&x.view().insert_axis(Axis(0)));
        self.weights = &self.weights - &(grad_w * lr);
        self.bias = &self.bias - &(grad_out * lr);
        grad_in
    }
}

/// Shared Latent World Model implementing variational compression (Encoder),
/// state transition prediction (Predictor), and semantic grounding (Decoder).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LatentWorldModel {
    latent_dim: usize,
    enc_l1: Linear,
    enc_ln: LayerNorm,
    enc_l2: Linear,
    pred_l1: Linear,
    pred_ln: LayerNorm,
    pred_l2: Linear,
    dec_l1: Linear,
    dec_l2: Linear,
}

impl LatentWorldModel {
    pub fn new(obs_dim: usize, action_dim: usize, latent_dim: usize, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let hidden = 32;

        Self {
            latent_dim,
            enc_l1: Linear::new(obs_dim, hidden, &mut rng),
            enc_ln: LayerNorm::new(hidden),
            enc_l2: Linear::new(hidden, latent_dim.saturating_mul(2), &mut rng),
            pred_l1: Linear::new(latent_dim.saturating_add(action_dim), hidden, &mut rng),
            pred_ln: LayerNorm::new(hidden),
            pred_l2: Linear::new(hidden, latent_dim, &mut rng),
            dec_l1: Linear::new(latent_dim, hidden, &mut rng),
            dec_l2: Linear::new(hidden, obs_dim, &mut rng),
        }
    }

    pub fn obs_dim(&self) -> usize {
        self.enc_l1.weights.ncols()
    }

    pub fn action_dim(&self) -> usize {
        self.pred_l1.weights.ncols().saturating_sub(self.latent_dim)
    }

    pub fn latent_dim(&self) -> usize {
        self.latent_dim
    }

    /// Validates all tensor shapes, bounds (`<= MAX_MODEL_DIM`), positive dimensions,
    /// `LayerNorm.eps > 0`, and finiteness of every weight and bias parameter.
    pub fn validate_integrity(&self) -> Result<(), LatentShieldError> {
        if self.latent_dim == 0 || self.latent_dim > MAX_MODEL_DIM {
            return Err(LatentShieldError::InvalidModel(format!(
                "latent_dim {} out of [1, {}]",
                self.latent_dim, MAX_MODEL_DIM
            )));
        }
        let obs_dim = self.enc_l1.weights.ncols();
        if obs_dim == 0 || obs_dim > MAX_MODEL_DIM {
            return Err(LatentShieldError::InvalidModel(format!(
                "obs_dim {} out of [1, {}]",
                obs_dim, MAX_MODEL_DIM
            )));
        }
        let enc_hidden = self.enc_l1.weights.nrows();
        if enc_hidden == 0 || enc_hidden > MAX_MODEL_DIM {
            return Err(LatentShieldError::InvalidModel(format!(
                "enc_hidden {} out of [1, {}]",
                enc_hidden, MAX_MODEL_DIM
            )));
        }
        let pred_in = self.pred_l1.weights.ncols();
        if pred_in <= self.latent_dim {
            return Err(LatentShieldError::InvalidModel(format!(
                "pred_l1 input dim {} must exceed latent_dim {}",
                pred_in, self.latent_dim
            )));
        }
        let action_dim = pred_in - self.latent_dim;
        if action_dim > MAX_MODEL_DIM {
            return Err(LatentShieldError::InvalidModel(format!(
                "action_dim {} exceeds {}",
                action_dim, MAX_MODEL_DIM
            )));
        }
        let pred_hidden = self.pred_l1.weights.nrows();
        if pred_hidden == 0 || pred_hidden > MAX_MODEL_DIM {
            return Err(LatentShieldError::InvalidModel(format!(
                "pred_hidden {} out of [1, {}]",
                pred_hidden, MAX_MODEL_DIM
            )));
        }
        let dec_hidden = self.dec_l1.weights.nrows();
        if dec_hidden == 0 || dec_hidden > MAX_MODEL_DIM {
            return Err(LatentShieldError::InvalidModel(format!(
                "dec_hidden {} out of [1, {}]",
                dec_hidden, MAX_MODEL_DIM
            )));
        }

        self.enc_l1.validate(obs_dim, enc_hidden)?;
        self.enc_ln.validate(enc_hidden)?;
        self.enc_l2
            .validate(enc_hidden, self.latent_dim.saturating_mul(2))?;
        self.pred_l1
            .validate(self.latent_dim.saturating_add(action_dim), pred_hidden)?;
        self.pred_ln.validate(pred_hidden)?;
        self.pred_l2.validate(pred_hidden, self.latent_dim)?;
        self.dec_l1.validate(self.latent_dim, dec_hidden)?;
        self.dec_l2.validate(dec_hidden, obs_dim)?;
        Ok(())
    }

    pub fn try_encode_deterministic(
        &self,
        x: &Array1<f64>,
    ) -> Result<Array1<f64>, LatentShieldError> {
        self.validate_integrity()?;
        let expected_obs = self.obs_dim();
        if x.len() != expected_obs {
            return Err(LatentShieldError::DimensionMismatch {
                expected: expected_obs,
                actual: x.len(),
                context: "encode_deterministic.x",
            });
        }
        if !array1_is_finite(x) {
            return Err(LatentShieldError::NonFiniteInput("encode_deterministic.x"));
        }
        let h1 = self.enc_l1.try_forward(x)?;
        let (ln1, _, _) = self.enc_ln.try_forward(&h1)?;
        let act1 = ln1.mapv(silu);
        if !array1_is_finite(&act1) {
            return Err(LatentShieldError::NonFiniteInput(
                "encode_deterministic.silu",
            ));
        }
        let stats = self.enc_l2.try_forward(&act1)?;
        if stats.len() < self.latent_dim {
            return Err(LatentShieldError::DimensionMismatch {
                expected: self.latent_dim.saturating_mul(2),
                actual: stats.len(),
                context: "encode_deterministic.stats",
            });
        }
        let mu = stats.slice(ndarray::s![0..self.latent_dim]).to_owned();
        if !array1_is_finite(&mu) {
            return Err(LatentShieldError::NonFiniteInput("encode_deterministic.mu"));
        }
        Ok(mu)
    }

    pub fn encode_deterministic(&self, x: &Array1<f64>) -> Array1<f64> {
        self.try_encode_deterministic(x)
            .unwrap_or_else(|_| Array1::from_elem(self.latent_dim.max(1), f64::NAN))
    }

    pub fn try_predict_next_latent(
        &self,
        z_t: &Array1<f64>,
        action_t: &Array1<f64>,
    ) -> Result<Array1<f64>, LatentShieldError> {
        self.validate_integrity()?;
        if z_t.len() != self.latent_dim {
            return Err(LatentShieldError::DimensionMismatch {
                expected: self.latent_dim,
                actual: z_t.len(),
                context: "predict_next_latent.z_t",
            });
        }
        let expected_action = self.action_dim();
        if action_t.len() != expected_action {
            return Err(LatentShieldError::DimensionMismatch {
                expected: expected_action,
                actual: action_t.len(),
                context: "predict_next_latent.action_t",
            });
        }
        if !array1_is_finite(z_t) || !array1_is_finite(action_t) {
            return Err(LatentShieldError::NonFiniteInput("predict_next_latent"));
        }

        let mut za = Array1::zeros(self.latent_dim + expected_action);
        za.slice_mut(ndarray::s![0..self.latent_dim]).assign(z_t);
        za.slice_mut(ndarray::s![self.latent_dim..])
            .assign(action_t);

        let h1 = self.pred_l1.try_forward(&za)?;
        let (ln1, _, _) = self.pred_ln.try_forward(&h1)?;
        let act1 = ln1.mapv(silu);
        if !array1_is_finite(&act1) {
            return Err(LatentShieldError::NonFiniteInput(
                "predict_next_latent.silu",
            ));
        }
        self.pred_l2.try_forward(&act1)
    }

    pub fn predict_next_latent(&self, z_t: &Array1<f64>, action_t: &Array1<f64>) -> Array1<f64> {
        self.try_predict_next_latent(z_t, action_t)
            .unwrap_or_else(|_| Array1::from_elem(self.latent_dim.max(1), f64::NAN))
    }

    pub fn train_step(
        &mut self,
        x_t: &Array1<f64>,
        action_t: &Array1<f64>,
        x_next: &Array1<f64>,
        lr: f64,
        rng: &mut StdRng,
    ) -> f64 {
        if self.validate_integrity().is_err()
            || !lr.is_finite()
            || lr <= 0.0
            || x_t.len() != self.obs_dim()
            || x_next.len() != self.obs_dim()
            || action_t.len() != self.action_dim()
            || !array1_is_finite(x_t)
            || !array1_is_finite(x_next)
            || !array1_is_finite(action_t)
        {
            return f64::NAN;
        }

        let Ok(e_h1) = self.enc_l1.try_forward(x_t) else {
            return f64::NAN;
        };
        let Ok((e_ln1, e_xhat, e_inv_std)) = self.enc_ln.try_forward(&e_h1) else {
            return f64::NAN;
        };
        let e_act1 = e_ln1.mapv(silu);
        let Ok(stats) = self.enc_l2.try_forward(&e_act1) else {
            return f64::NAN;
        };
        if stats.len() != self.latent_dim * 2 {
            return f64::NAN;
        }

        let mu = stats.slice(ndarray::s![0..self.latent_dim]).to_owned();
        let logvar = stats
            .slice(ndarray::s![self.latent_dim..])
            .to_owned()
            .mapv(|v| v.clamp(-6.0, 4.0));
        let std = logvar.mapv(|lv| (0.5 * lv).exp());
        let eps = Array1::from_shape_fn(self.latent_dim, |_| rng.sample::<f64, _>(StandardNormal));
        let z_t = &mu + &(&std * &eps);

        let Ok(z_next_target) = self.try_encode_deterministic(x_next) else {
            return f64::NAN;
        };

        let mut za = Array1::zeros(self.latent_dim + action_t.len());
        za.slice_mut(ndarray::s![0..self.latent_dim]).assign(&z_t);
        za.slice_mut(ndarray::s![self.latent_dim..])
            .assign(action_t);

        let Ok(p_h1) = self.pred_l1.try_forward(&za) else {
            return f64::NAN;
        };
        let Ok((p_ln1, p_xhat, p_inv_std)) = self.pred_ln.try_forward(&p_h1) else {
            return f64::NAN;
        };
        let p_act1 = p_ln1.mapv(silu);
        let Ok(z_next_pred) = self.pred_l2.try_forward(&p_act1) else {
            return f64::NAN;
        };

        let Ok(d_h1) = self.dec_l1.try_forward(&z_t) else {
            return f64::NAN;
        };
        let d_act1 = d_h1.mapv(silu);
        let Ok(x_recon) = self.dec_l2.try_forward(&d_act1) else {
            return f64::NAN;
        };

        let dim_x = x_t.len() as f64;
        let dim_z = self.latent_dim as f64;

        let diff_recon = &x_recon - x_t;
        let recon_loss = diff_recon.mapv(|v| v * v).sum() / dim_x;

        let diff_dyn = &z_next_pred - &z_next_target;
        let dyn_loss = diff_dyn.mapv(|v| v * v).sum() / dim_z;

        let kl_beta = 0.02;
        let kl_loss =
            -0.5 * (1.0 + &logvar - mu.mapv(|m| m * m) - logvar.mapv(f64::exp)).sum() / dim_z;

        let grad_x_recon = diff_recon * (2.0 / dim_x);
        let grad_d_act1 = self.dec_l2.backward(&d_act1, &grad_x_recon, lr);
        let grad_d_h1 = grad_d_act1 * d_h1.mapv(silu_grad);
        let grad_z_dec = self.dec_l1.backward(&z_t, &grad_d_h1, lr);

        let grad_z_pred = diff_dyn * (2.0 / dim_z);
        let grad_p_act1 = self.pred_l2.backward(&p_act1, &grad_z_pred, lr);
        let grad_p_ln1 = grad_p_act1 * p_ln1.mapv(silu_grad);
        let grad_p_h1 = self.pred_ln.backward(&grad_p_ln1, &p_xhat, p_inv_std, lr);
        let grad_za = self.pred_l1.backward(&za, &grad_p_h1, lr);
        let grad_z_pred_in = grad_za.slice(ndarray::s![0..self.latent_dim]).to_owned();

        let grad_z_total = grad_z_dec + grad_z_pred_in;
        let grad_mu = &grad_z_total + (&mu * (kl_beta / dim_z));
        let grad_logvar = (&grad_z_total * &eps * &std * 0.5)
            + ((logvar.mapv(f64::exp) - 1.0) * (0.5 * kl_beta / dim_z));

        let mut grad_stats = Array1::zeros(self.latent_dim * 2);
        grad_stats
            .slice_mut(ndarray::s![0..self.latent_dim])
            .assign(&grad_mu);
        grad_stats
            .slice_mut(ndarray::s![self.latent_dim..])
            .assign(&grad_logvar);

        let grad_e_act1 = self.enc_l2.backward(&e_act1, &grad_stats, lr);
        let grad_e_ln1 = grad_e_act1 * e_ln1.mapv(silu_grad);
        let grad_e_h1 = self.enc_ln.backward(&grad_e_ln1, &e_xhat, e_inv_std, lr);
        let _ = self.enc_l1.backward(x_t, &grad_e_h1, lr);

        recon_loss + dyn_loss + kl_beta * kl_loss
    }

    fn train_recon_only_step(&mut self, x_t: &Array1<f64>, lr: f64, rng: &mut StdRng) -> f64 {
        if self.validate_integrity().is_err()
            || !lr.is_finite()
            || lr <= 0.0
            || x_t.len() != self.obs_dim()
            || !array1_is_finite(x_t)
        {
            return f64::NAN;
        }
        let Ok(e_h1) = self.enc_l1.try_forward(x_t) else {
            return f64::NAN;
        };
        let Ok((e_ln1, e_xhat, e_inv_std)) = self.enc_ln.try_forward(&e_h1) else {
            return f64::NAN;
        };
        let e_act1 = e_ln1.mapv(silu);
        let Ok(stats) = self.enc_l2.try_forward(&e_act1) else {
            return f64::NAN;
        };
        if stats.len() != self.latent_dim * 2 {
            return f64::NAN;
        }

        let mu = stats.slice(ndarray::s![0..self.latent_dim]).to_owned();
        let logvar = stats
            .slice(ndarray::s![self.latent_dim..])
            .to_owned()
            .mapv(|v| v.clamp(-6.0, 4.0));
        let std = logvar.mapv(|lv| (0.5 * lv).exp());
        let eps = Array1::from_shape_fn(self.latent_dim, |_| rng.sample::<f64, _>(StandardNormal));
        let z_t = &mu + &(&std * &eps);

        let Ok(d_h1) = self.dec_l1.try_forward(&z_t) else {
            return f64::NAN;
        };
        let d_act1 = d_h1.mapv(silu);
        let Ok(x_recon) = self.dec_l2.try_forward(&d_act1) else {
            return f64::NAN;
        };

        let dim_x = x_t.len() as f64;
        let dim_z = self.latent_dim as f64;
        let diff_recon = &x_recon - x_t;
        let recon_loss = diff_recon.mapv(|v| v * v).sum() / dim_x;
        let kl_beta = 0.02;
        let kl_loss =
            -0.5 * (1.0 + &logvar - mu.mapv(|m| m * m) - logvar.mapv(f64::exp)).sum() / dim_z;

        let grad_x_recon = diff_recon * (2.0 / dim_x);
        let grad_d_act1 = self.dec_l2.backward(&d_act1, &grad_x_recon, lr);
        let grad_d_h1 = grad_d_act1 * d_h1.mapv(silu_grad);
        let grad_z_dec = self.dec_l1.backward(&z_t, &grad_d_h1, lr);

        let grad_mu = &grad_z_dec + (&mu * (kl_beta / dim_z));
        let grad_logvar = (&grad_z_dec * &eps * &std * 0.5)
            + ((logvar.mapv(f64::exp) - 1.0) * (0.5 * kl_beta / dim_z));
        let mut grad_stats = Array1::zeros(self.latent_dim * 2);
        grad_stats
            .slice_mut(ndarray::s![0..self.latent_dim])
            .assign(&grad_mu);
        grad_stats
            .slice_mut(ndarray::s![self.latent_dim..])
            .assign(&grad_logvar);

        let grad_e_act1 = self.enc_l2.backward(&e_act1, &grad_stats, lr);
        let grad_e_ln1 = grad_e_act1 * e_ln1.mapv(silu_grad);
        let grad_e_h1 = self.enc_ln.backward(&grad_e_ln1, &e_xhat, e_inv_std, lr);
        let _ = self.enc_l1.backward(x_t, &grad_e_h1, lr);
        recon_loss + kl_beta * kl_loss
    }

    pub fn try_compute_surprise(
        &self,
        prev_obs: &Array1<f64>,
        action: &Array1<f64>,
        next_obs: &Array1<f64>,
    ) -> Result<f64, LatentShieldError> {
        let z_t = self.try_encode_deterministic(prev_obs)?;
        let z_next_pred = self.try_predict_next_latent(&z_t, action)?;
        let z_next_obs = self.try_encode_deterministic(next_obs)?;

        let diff = &z_next_pred - &z_next_obs;
        let sq_sum = diff.mapv(|v| v * v).sum();
        let surprise = sq_sum / (self.latent_dim as f64);
        if !surprise.is_finite() {
            return Err(LatentShieldError::NonFiniteInput("compute_surprise"));
        }
        Ok(surprise)
    }

    pub fn compute_surprise(
        &self,
        prev_obs: &Array1<f64>,
        action: &Array1<f64>,
        next_obs: &Array1<f64>,
    ) -> f64 {
        self.try_compute_surprise(prev_obs, action, next_obs)
            .unwrap_or(f64::NAN)
    }
}

/// Fail-closed verdict returned by Gate 1 (`SBOM_SUPPLY_CHAIN`) and Gate 2 (`AGENT_OCTOPUS_RUNTIME`).
/// Note: `surprise_score` and `threshold` are always finite `f64` values so JSON serialization
/// never emits `null`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GuardVerdict {
    pub domain: &'static str,
    pub surprise_score: f64,
    pub threshold: f64,
    pub block_execution: bool,
    pub reason: &'static str,
}

/// Owned serializable/deserializable summary of [`GuardVerdict`] for receipts (`WasmExecutionReceipt`,
/// `TieredExecutionReceipt`, and CLI `--json` outputs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeGuardVerdictSummary {
    pub domain: String,
    pub surprise_score: f64,
    pub threshold: f64,
    pub block_execution: bool,
    pub reason: String,
}

impl From<&GuardVerdict> for RuntimeGuardVerdictSummary {
    fn from(v: &GuardVerdict) -> Self {
        Self {
            domain: v.domain.to_string(),
            surprise_score: if v.surprise_score.is_finite() {
                v.surprise_score
            } else {
                f64::MAX
            },
            threshold: sanitize_threshold_for_verdict(v.threshold),
            block_execution: v.block_execution,
            reason: v.reason.to_string(),
        }
    }
}

// =========================================================================
// PART 2: Supply Chain SBOM Guard (Pre-Execution Build / Load Gate)
// =========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SbomIntent {
    Patch,
    Minor,
    Refactor,
}

impl SbomIntent {
    pub fn parse(raw: &str) -> Result<Self, LatentShieldError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "patch" => Ok(Self::Patch),
            "minor" => Ok(Self::Minor),
            "refactor" => Ok(Self::Refactor),
            other => Err(LatentShieldError::SbomParseError(format!(
                "invalid sbom intent '{}': expected 'patch', 'minor', or 'refactor'",
                other
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Refactor => "refactor",
        }
    }

    pub fn to_action_array(&self) -> Array1<f64> {
        match self {
            Self::Patch => Array1::from_vec(vec![1.0, 0.0, 0.0]),
            Self::Minor => Array1::from_vec(vec![0.0, 1.0, 0.0]),
            Self::Refactor => Array1::from_vec(vec![0.0, 0.0, 1.0]),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CycloneDxSbom {
    #[serde(default)]
    pub components: Vec<SbomComponent>,
    #[serde(default)]
    pub dependencies: Vec<SbomDependency>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SbomComponent {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub purl: Option<String>,
    #[serde(default)]
    pub licenses: Vec<LicenseChoice>,
    #[serde(default)]
    pub properties: Vec<ComponentProperty>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct LicenseChoice {
    pub license: Option<LicenseDetail>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct LicenseDetail {
    pub id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ComponentProperty {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SbomDependency {
    #[serde(rename = "ref")]
    pub component_ref: String,
    #[serde(default, rename = "dependsOn")]
    pub depends_on: Vec<String>,
}

fn validate_sbom_string(val: &str, field: &'static str) -> Result<(), LatentShieldError> {
    if val.len() > MAX_SBOM_STRING_LEN {
        return Err(LatentShieldError::SbomBoundExceeded(format!(
            "{} length {} exceeds MAX_SBOM_STRING_LEN ({})",
            field,
            val.len(),
            MAX_SBOM_STRING_LEN
        )));
    }
    if val.contains('\0') {
        return Err(LatentShieldError::SbomParseError(format!(
            "{} contains NUL byte",
            field
        )));
    }
    Ok(())
}

/// Validates component/dependency/edge/license/property caps and string invariants
/// on a [`CycloneDxSbom`] before feature extraction or evaluation.
pub fn validate_sbom_bounds(sbom: &CycloneDxSbom) -> Result<(), LatentShieldError> {
    if sbom.components.len() > MAX_SBOM_COMPONENTS {
        return Err(LatentShieldError::SbomBoundExceeded(format!(
            "component count {} exceeds MAX_SBOM_COMPONENTS ({})",
            sbom.components.len(),
            MAX_SBOM_COMPONENTS
        )));
    }
    if sbom.dependencies.len() > MAX_SBOM_DEPENDENCIES {
        return Err(LatentShieldError::SbomBoundExceeded(format!(
            "dependency count {} exceeds MAX_SBOM_DEPENDENCIES ({})",
            sbom.dependencies.len(),
            MAX_SBOM_DEPENDENCIES
        )));
    }

    for comp in &sbom.components {
        if comp.name.trim().is_empty() {
            return Err(LatentShieldError::SbomParseError(
                "SBOM component name cannot be empty".to_string(),
            ));
        }
        validate_sbom_string(&comp.name, "component.name")?;
        validate_sbom_string(&comp.version, "component.version")?;
        if let Some(ref purl) = comp.purl {
            validate_sbom_string(purl, "component.purl")?;
        }
        if comp.licenses.len() > MAX_SBOM_LICENSES_PER_COMPONENT {
            return Err(LatentShieldError::SbomBoundExceeded(format!(
                "component '{}' licenses ({}) exceed MAX_SBOM_LICENSES_PER_COMPONENT ({})",
                comp.name,
                comp.licenses.len(),
                MAX_SBOM_LICENSES_PER_COMPONENT
            )));
        }
        for lc in &comp.licenses {
            if let Some(ref detail) = lc.license {
                if let Some(ref id) = detail.id {
                    validate_sbom_string(id, "license.id")?;
                }
            }
        }
        if comp.properties.len() > MAX_SBOM_PROPERTIES_PER_COMPONENT {
            return Err(LatentShieldError::SbomBoundExceeded(format!(
                "component '{}' properties ({}) exceed MAX_SBOM_PROPERTIES_PER_COMPONENT ({})",
                comp.name,
                comp.properties.len(),
                MAX_SBOM_PROPERTIES_PER_COMPONENT
            )));
        }
        for prop in &comp.properties {
            validate_sbom_string(&prop.name, "property.name")?;
            validate_sbom_string(&prop.value, "property.value")?;
        }
    }

    let mut total_edges: usize = 0;
    for dep in &sbom.dependencies {
        validate_sbom_string(&dep.component_ref, "dependency.ref")?;
        total_edges = total_edges.saturating_add(dep.depends_on.len());
        if total_edges > MAX_SBOM_EDGES {
            return Err(LatentShieldError::SbomBoundExceeded(format!(
                "total dependency edges exceed MAX_SBOM_EDGES ({})",
                MAX_SBOM_EDGES
            )));
        }
        for target in &dep.depends_on {
            validate_sbom_string(target, "dependency.dependsOn[]")?;
        }
    }

    Ok(())
}

/// Parses a CycloneDX SBOM JSON string with strict fail-closed structural & size bounds:
/// - Rejects payloads > `MAX_SBOM_JSON_BYTES` or containing NUL bytes
/// - Requires a JSON object with an explicit `"components"` array (rejects `{}` or arbitrary JSON)
/// - Pre-checks array lengths before deserialization and enforces `validate_sbom_bounds`
pub fn parse_cyclonedx_sbom_bounded(raw: &str) -> Result<CycloneDxSbom, LatentShieldError> {
    if raw.len() > MAX_SBOM_JSON_BYTES {
        return Err(LatentShieldError::SbomBoundExceeded(format!(
            "SBOM JSON byte length {} exceeds MAX_SBOM_JSON_BYTES ({})",
            raw.len(),
            MAX_SBOM_JSON_BYTES
        )));
    }
    if raw.as_bytes().contains(&0) {
        return Err(LatentShieldError::SbomParseError(
            "SBOM JSON contains embedded NUL byte".to_string(),
        ));
    }

    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| LatentShieldError::SbomParseError(format!("invalid JSON: {}", e)))?;
    let obj = value.as_object().ok_or_else(|| {
        LatentShieldError::SbomParseError("CycloneDX SBOM must be a JSON object".to_string())
    })?;

    let comps = obj
        .get("components")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            LatentShieldError::SbomParseError(
                "CycloneDX SBOM must contain a 'components' JSON array".to_string(),
            )
        })?;
    if comps.len() > MAX_SBOM_COMPONENTS {
        return Err(LatentShieldError::SbomBoundExceeded(format!(
            "component count {} exceeds MAX_SBOM_COMPONENTS ({})",
            comps.len(),
            MAX_SBOM_COMPONENTS
        )));
    }

    if let Some(deps_val) = obj.get("dependencies") {
        let deps = deps_val.as_array().ok_or_else(|| {
            LatentShieldError::SbomParseError(
                "CycloneDX SBOM 'dependencies' field must be a JSON array".to_string(),
            )
        })?;
        if deps.len() > MAX_SBOM_DEPENDENCIES {
            return Err(LatentShieldError::SbomBoundExceeded(format!(
                "dependency count {} exceeds MAX_SBOM_DEPENDENCIES ({})",
                deps.len(),
                MAX_SBOM_DEPENDENCIES
            )));
        }
    }

    let sbom: CycloneDxSbom = serde_json::from_value(value).map_err(|e| {
        LatentShieldError::SbomParseError(format!("failed to decode CycloneDX fields: {}", e))
    })?;
    validate_sbom_bounds(&sbom)?;
    Ok(sbom)
}

/// Loads and validates a CycloneDX SBOM file from disk using bounded I/O and symlink checks.
pub fn load_cyclonedx_sbom_file(path: &Path) -> Result<CycloneDxSbom, LatentShieldError> {
    let raw = read_bounded_utf8_file(path, MAX_SBOM_JSON_BYTES, "SBOM")?;
    parse_cyclonedx_sbom_bounded(&raw)
}

fn read_bounded_utf8_file(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<String, LatentShieldError> {
    let bound_err = |msg: String| -> LatentShieldError {
        if label == "latent weights" {
            LatentShieldError::WeightsParseError(msg)
        } else {
            LatentShieldError::SbomBoundExceeded(msg)
        }
    };
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        LatentShieldError::IoError(format!(
            "failed to stat {} file '{}': {}",
            label,
            path.display(),
            e
        ))
    })?;
    if meta.file_type().is_symlink() {
        return Err(LatentShieldError::IoError(format!(
            "{} path '{}' is a symlink/reparse point (rejected fail-closed)",
            label,
            path.display()
        )));
    }
    if !meta.is_file() {
        return Err(LatentShieldError::IoError(format!(
            "{} path '{}' is not a regular file",
            label,
            path.display()
        )));
    }
    if meta.len() > max_bytes as u64 {
        return Err(bound_err(format!(
            "{} file '{}' ({} bytes) exceeds {} byte limit",
            label,
            path.display(),
            meta.len(),
            max_bytes
        )));
    }
    let file = std::fs::File::open(path).map_err(|e| {
        LatentShieldError::IoError(format!(
            "failed to open {} file '{}': {}",
            label,
            path.display(),
            e
        ))
    })?;
    let mut buf = Vec::with_capacity((meta.len() as usize).min(max_bytes));
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| {
            LatentShieldError::IoError(format!(
                "failed to read {} file '{}': {}",
                label,
                path.display(),
                e
            ))
        })?;
    if buf.len() > max_bytes {
        return Err(bound_err(format!(
            "{} file '{}' exceeded {} byte read cap",
            label,
            path.display(),
            max_bytes
        )));
    }
    String::from_utf8(buf).map_err(|e| {
        LatentShieldError::IoError(format!(
            "{} file '{}' is not valid UTF-8: {}",
            label,
            path.display(),
            e
        ))
    })
}

/// Extracts the 6-dimensional normalized structural & capability feature vector from a CycloneDX SBOM.
pub fn extract_sbom_features(sbom: &CycloneDxSbom) -> Array1<f64> {
    let total = sbom.components.len().max(1) as f64;
    let component_count_norm = (sbom.components.len() as f64 / 100.0).min(2.0);

    let total_edges: usize = sbom
        .dependencies
        .iter()
        .fold(0usize, |acc, d| acc.saturating_add(d.depends_on.len()));
    let transitive_edge_ratio = (total_edges as f64 / total).min(5.0) / 5.0;

    let mut non_standard_purl = 0.0;
    let mut permissive_licenses = 0.0;
    let mut elevated_capabilities = 0.0;
    let mut namespaces = HashSet::new();

    for comp in &sbom.components {
        match &comp.purl {
            Some(p)
                if p.starts_with("pkg:cargo/")
                    || p.starts_with("pkg:pypi/")
                    || p.starts_with("pkg:npm/") => {}
            _ => non_standard_purl += 1.0,
        }

        let has_permissive = comp.licenses.iter().any(|lc| {
            lc.license
                .as_ref()
                .and_then(|l| l.id.as_deref())
                .map(|id| matches!(id, "MIT" | "Apache-2.0" | "BSD-3-Clause" | "ISC"))
                .unwrap_or(false)
        });
        if has_permissive {
            permissive_licenses += 1.0;
        }

        let has_cap = comp.properties.iter().any(|prop| {
            let k = prop.name.to_lowercase();
            let v = prop.value.to_lowercase();
            k.contains("capability")
                && (v.contains("network")
                    || v.contains("process")
                    || v.contains("build-script")
                    || v.contains("ffi"))
        });
        if has_cap {
            elevated_capabilities += 1.0;
        }

        let prefix = comp.name.split(['-', '_']).next().unwrap_or(&comp.name);
        namespaces.insert(prefix.to_string());
    }

    Array1::from_vec(vec![
        component_count_norm,
        transitive_edge_ratio,
        non_standard_purl / total,
        permissive_licenses / total,
        elevated_capabilities / total,
        (namespaces.len() as f64 / total).min(1.0),
    ])
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SbomSupplyChainGuard {
    model: LatentWorldModel,
    threshold: f64,
}

impl SbomSupplyChainGuard {
    pub fn new(model: LatentWorldModel, threshold: f64) -> Self {
        Self { model, threshold }
    }

    pub fn model(&self) -> &LatentWorldModel {
        &self.model
    }

    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    pub fn validate_integrity(&self) -> Result<(), LatentShieldError> {
        self.model.validate_integrity()?;
        if self.model.obs_dim() != SBOM_OBS_DIM {
            return Err(LatentShieldError::DimensionMismatch {
                expected: SBOM_OBS_DIM,
                actual: self.model.obs_dim(),
                context: "SbomSupplyChainGuard.obs_dim",
            });
        }
        if self.model.action_dim() != SBOM_ACTION_DIM {
            return Err(LatentShieldError::DimensionMismatch {
                expected: SBOM_ACTION_DIM,
                actual: self.model.action_dim(),
                context: "SbomSupplyChainGuard.action_dim",
            });
        }
        if !self.threshold.is_finite() || self.threshold < 0.0 {
            return Err(LatentShieldError::NonFiniteInput(
                "SbomSupplyChainGuard.threshold",
            ));
        }
        Ok(())
    }

    pub fn evaluate_sbom_diff(
        &self,
        baseline_sbom: &CycloneDxSbom,
        declared_intent: &Array1<f64>,
        candidate_sbom: &CycloneDxSbom,
    ) -> GuardVerdict {
        let safe_threshold = sanitize_threshold_for_verdict(self.threshold);
        if !self.threshold.is_finite() || self.threshold < 0.0 {
            return GuardVerdict {
                domain: "SBOM_SUPPLY_CHAIN",
                surprise_score: f64::MAX,
                threshold: 0.0,
                block_execution: true,
                reason: "Fail-closed: non-finite or negative SBOM guard threshold.",
            };
        }
        if self.validate_integrity().is_err() {
            return GuardVerdict {
                domain: "SBOM_SUPPLY_CHAIN",
                surprise_score: f64::MAX,
                threshold: safe_threshold,
                block_execution: true,
                reason: "Fail-closed: SBOM latent world model failed integrity check.",
            };
        }
        if validate_sbom_bounds(baseline_sbom).is_err()
            || validate_sbom_bounds(candidate_sbom).is_err()
        {
            return GuardVerdict {
                domain: "SBOM_SUPPLY_CHAIN",
                surprise_score: f64::MAX,
                threshold: safe_threshold,
                block_execution: true,
                reason: "Fail-closed: CycloneDX SBOM violated structural or size bounds.",
            };
        }
        if declared_intent.len() != self.model.action_dim()
            || !all_finite_slice(declared_intent.as_slice().unwrap_or(&[]))
            || !array1_is_finite(declared_intent)
        {
            return GuardVerdict {
                domain: "SBOM_SUPPLY_CHAIN",
                surprise_score: f64::MAX,
                threshold: safe_threshold,
                block_execution: true,
                reason: "Fail-closed: declared SBOM intent vector has invalid dimension or non-finite value.",
            };
        }

        let x_t = extract_sbom_features(baseline_sbom);
        let x_next = extract_sbom_features(candidate_sbom);
        let Ok(surprise) = self
            .model
            .try_compute_surprise(&x_t, declared_intent, &x_next)
        else {
            return GuardVerdict {
                domain: "SBOM_SUPPLY_CHAIN",
                surprise_score: f64::MAX,
                threshold: safe_threshold,
                block_execution: true,
                reason: "Fail-closed: SBOM latent surprise computation returned non-finite or mismatched result.",
            };
        };

        if !(surprise.is_finite() && surprise <= self.threshold) {
            GuardVerdict {
                domain: "SBOM_SUPPLY_CHAIN",
                surprise_score: if surprise.is_finite() {
                    surprise
                } else {
                    f64::MAX
                },
                threshold: safe_threshold,
                block_execution: true,
                reason:
                    "Anomalous SBOM latent transition: unmodeled dependency or capability injection.",
            }
        } else {
            GuardVerdict {
                domain: "SBOM_SUPPLY_CHAIN",
                surprise_score: surprise,
                threshold: safe_threshold,
                block_execution: false,
                reason: "SBOM evolution consistent with expected release trajectory.",
            }
        }
    }
}

// =========================================================================
// PART 3: Runtime AgentOctopus Containment Guard (Live Syscall / Tool Gate)
// =========================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeTelemetry {
    pub file_reads_norm: f64,
    pub file_writes_norm: f64,
    pub child_procs_norm: f64,
    pub net_sockets_norm: f64,
    pub mem_delta_norm: f64,
    pub prompt_entropy_norm: f64,
}

impl RuntimeTelemetry {
    /// Returns a clean baseline runtime telemetry state for initial RAG tool transitions.
    pub fn baseline_rag() -> Self {
        Self {
            file_reads_norm: 0.05,
            file_writes_norm: 0.0,
            child_procs_norm: 0.0,
            net_sockets_norm: 0.02,
            mem_delta_norm: 0.02,
            prompt_entropy_norm: 0.22,
        }
    }

    /// Returns a clean idle initial runtime telemetry state before any Wasm/child hostcall.
    pub fn idle_initial() -> Self {
        Self {
            file_reads_norm: 0.0,
            file_writes_norm: 0.0,
            child_procs_norm: 0.0,
            net_sockets_norm: 0.0,
            mem_delta_norm: 0.0,
            prompt_entropy_norm: 0.20,
        }
    }

    pub fn to_array(&self) -> Array1<f64> {
        Array1::from_vec(vec![
            self.file_reads_norm,
            self.file_writes_norm,
            self.child_procs_norm,
            self.net_sockets_norm,
            self.mem_delta_norm,
            self.prompt_entropy_norm,
        ])
    }

    pub fn is_finite(&self) -> bool {
        self.file_reads_norm.is_finite()
            && self.file_writes_norm.is_finite()
            && self.child_procs_norm.is_finite()
            && self.net_sockets_norm.is_finite()
            && self.mem_delta_norm.is_finite()
            && self.prompt_entropy_norm.is_finite()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRuntimeGuard {
    model: LatentWorldModel,
    threshold: f64,
}

impl AgentRuntimeGuard {
    pub fn new(model: LatentWorldModel, threshold: f64) -> Self {
        Self { model, threshold }
    }

    pub fn model(&self) -> &LatentWorldModel {
        &self.model
    }

    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    pub fn validate_integrity(&self) -> Result<(), LatentShieldError> {
        self.model.validate_integrity()?;
        if self.model.obs_dim() != RUNTIME_OBS_DIM {
            return Err(LatentShieldError::DimensionMismatch {
                expected: RUNTIME_OBS_DIM,
                actual: self.model.obs_dim(),
                context: "AgentRuntimeGuard.obs_dim",
            });
        }
        if self.model.action_dim() != RUNTIME_ACTION_DIM {
            return Err(LatentShieldError::DimensionMismatch {
                expected: RUNTIME_ACTION_DIM,
                actual: self.model.action_dim(),
                context: "AgentRuntimeGuard.action_dim",
            });
        }
        if !self.threshold.is_finite() || self.threshold < 0.0 {
            return Err(LatentShieldError::NonFiniteInput(
                "AgentRuntimeGuard.threshold",
            ));
        }
        Ok(())
    }

    pub fn evaluate_step(
        &self,
        prev_state: &RuntimeTelemetry,
        declared_tool_action: &Array1<f64>,
        observed_state: &RuntimeTelemetry,
    ) -> GuardVerdict {
        let safe_threshold = sanitize_threshold_for_verdict(self.threshold);
        if !self.threshold.is_finite() || self.threshold < 0.0 {
            return GuardVerdict {
                domain: "AGENT_OCTOPUS_RUNTIME",
                surprise_score: f64::MAX,
                threshold: 0.0,
                block_execution: true,
                reason: "Fail-closed: non-finite or negative runtime guard threshold.",
            };
        }
        if self.validate_integrity().is_err() {
            return GuardVerdict {
                domain: "AGENT_OCTOPUS_RUNTIME",
                surprise_score: f64::MAX,
                threshold: safe_threshold,
                block_execution: true,
                reason: "Fail-closed: runtime latent world model failed integrity check.",
            };
        }
        if !prev_state.is_finite() || !observed_state.is_finite() {
            return GuardVerdict {
                domain: "AGENT_OCTOPUS_RUNTIME",
                surprise_score: f64::MAX,
                threshold: safe_threshold,
                block_execution: true,
                reason: "Fail-closed: non-finite runtime telemetry observation.",
            };
        }
        if declared_tool_action.len() != self.model.action_dim()
            || !array1_is_finite(declared_tool_action)
        {
            return GuardVerdict {
                domain: "AGENT_OCTOPUS_RUNTIME",
                surprise_score: f64::MAX,
                threshold: safe_threshold,
                block_execution: true,
                reason: "Fail-closed: runtime tool action vector has invalid dimension or non-finite value.",
            };
        }

        let x_t = prev_state.to_array();
        let x_next = observed_state.to_array();
        let Ok(mut surprise) = self
            .model
            .try_compute_surprise(&x_t, declared_tool_action, &x_next)
        else {
            return GuardVerdict {
                domain: "AGENT_OCTOPUS_RUNTIME",
                surprise_score: f64::MAX,
                threshold: safe_threshold,
                block_execution: true,
                reason: "Fail-closed: runtime surprise computation returned non-finite or mismatched result.",
            };
        };
        if observed_state.child_procs_norm > 0.0 || prev_state.child_procs_norm > 0.0 {
            let base_anchor = RuntimeTelemetry::baseline_rag().to_array();
            let idle_anchor = RuntimeTelemetry::idle_initial().to_array();
            for anchor in [&base_anchor, &idle_anchor] {
                match self
                    .model
                    .try_compute_surprise(anchor, declared_tool_action, &x_next)
                {
                    Ok(s_anchor) if s_anchor.is_finite() => {
                        surprise = surprise.max(s_anchor);
                    }
                    _ => {
                        return GuardVerdict {
                            domain: "AGENT_OCTOPUS_RUNTIME",
                            surprise_score: f64::MAX,
                            threshold: safe_threshold,
                            block_execution: true,
                            reason: "Fail-closed: runtime anchor surprise computation returned non-finite result.",
                        };
                    }
                }
            }
        }

        if !(surprise.is_finite() && surprise <= self.threshold) {
            GuardVerdict {
                domain: "AGENT_OCTOPUS_RUNTIME",
                surprise_score: if surprise.is_finite() {
                    surprise
                } else {
                    f64::MAX
                },
                threshold: safe_threshold,
                block_execution: true,
                reason:
                    "Latent trajectory divergence: sandbox breakout or unauthorized syscall spike.",
            }
        } else {
            GuardVerdict {
                domain: "AGENT_OCTOPUS_RUNTIME",
                surprise_score: surprise,
                threshold: safe_threshold,
                block_execution: false,
                reason: "Transition consistent with learned behavioral manifold.",
            }
        }
    }
}

/// Runtime event classification for live `octopus run` Gate 2 telemetry tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEventKind {
    FileRead,
    FileWrite,
    NetworkEgress,
    ChildProcess,
}

/// Shared live Gate 2 runtime telemetry monitor across `ProxyState`, `CedarFsServerState`,
/// and OS child process wait loops during `octopus run`.
pub struct LiveRuntimeMonitor {
    guard: Arc<AgentRuntimeGuard>,
    anchor_state: RuntimeTelemetry,
    prev_state: Mutex<RuntimeTelemetry>,
    fs_reads: AtomicU64,
    fs_writes: AtomicU64,
    net_requests: AtomicU64,
    net_bytes: AtomicU64,
    child_spawns: AtomicU64,
    tripped: AtomicBool,
    trip_reason: Mutex<Option<String>>,
    last_verdict: Mutex<Option<GuardVerdict>>,
}

impl LiveRuntimeMonitor {
    pub fn new(guard: Arc<AgentRuntimeGuard>) -> Self {
        Self {
            guard,
            anchor_state: RuntimeTelemetry::baseline_rag(),
            prev_state: Mutex::new(RuntimeTelemetry::baseline_rag()),
            fs_reads: AtomicU64::new(0),
            fs_writes: AtomicU64::new(0),
            net_requests: AtomicU64::new(0),
            net_bytes: AtomicU64::new(0),
            child_spawns: AtomicU64::new(0),
            tripped: AtomicBool::new(false),
            trip_reason: Mutex::new(None),
            last_verdict: Mutex::new(None),
        }
    }

    pub fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::Acquire)
    }

    pub fn trip_reason(&self) -> Option<String> {
        self.trip_reason.lock().ok().and_then(|g| g.clone())
    }

    pub fn last_verdict(&self) -> Option<GuardVerdict> {
        self.last_verdict.lock().ok().and_then(|g| g.clone())
    }

    pub fn record_and_evaluate(
        &self,
        kind: RuntimeEventKind,
        bytes: u64,
        mem_delta_norm: f64,
        prompt_entropy_norm: f64,
    ) -> GuardVerdict {
        match kind {
            RuntimeEventKind::FileRead => {
                self.fs_reads.fetch_add(1, Ordering::Relaxed);
            }
            RuntimeEventKind::FileWrite => {
                self.fs_writes.fetch_add(1, Ordering::Relaxed);
            }
            RuntimeEventKind::NetworkEgress => {
                self.net_requests.fetch_add(1, Ordering::Relaxed);
                self.net_bytes.fetch_add(bytes, Ordering::Relaxed);
            }
            RuntimeEventKind::ChildProcess => {
                self.child_spawns.fetch_add(1, Ordering::Relaxed);
            }
        }

        let action = match kind {
            RuntimeEventKind::FileRead => Array1::from_vec(vec![1.0, 0.0, 0.0]),
            RuntimeEventKind::FileWrite | RuntimeEventKind::ChildProcess => {
                Array1::from_vec(vec![0.0, 1.0, 0.0])
            }
            RuntimeEventKind::NetworkEgress => Array1::from_vec(vec![0.0, 0.0, 1.0]),
        };

        let reads = self.fs_reads.load(Ordering::Relaxed);
        let writes = self.fs_writes.load(Ordering::Relaxed);
        let nets = self.net_requests.load(Ordering::Relaxed);
        let net_b = self.net_bytes.load(Ordering::Relaxed);
        let spawns = self.child_spawns.load(Ordering::Relaxed);

        let observed = RuntimeTelemetry {
            file_reads_norm: (0.05 + reads as f64 / 1500.0).min(1.5),
            file_writes_norm: (writes as f64 / 1000.0).min(1.5),
            child_procs_norm: (spawns.saturating_sub(4) as f64).min(1.5),
            net_sockets_norm: (0.02
                + (nets as f64 / 100.0)
                + (net_b as f64 / (4.0 * 1024.0 * 1024.0)))
                .min(1.5),
            mem_delta_norm,
            prompt_entropy_norm,
        };

        self.evaluate_observed(&action, observed)
    }

    pub fn evaluate_snapshot(&self, child_procs_norm: f64, mem_delta_norm: f64) -> GuardVerdict {
        let reads = self.fs_reads.load(Ordering::Relaxed);
        let writes = self.fs_writes.load(Ordering::Relaxed);
        let nets = self.net_requests.load(Ordering::Relaxed);
        let net_b = self.net_bytes.load(Ordering::Relaxed);

        let observed = RuntimeTelemetry {
            file_reads_norm: (0.05 + reads as f64 / 1500.0).min(1.5),
            file_writes_norm: (writes as f64 / 1000.0).min(1.5),
            child_procs_norm,
            net_sockets_norm: (0.02
                + (nets as f64 / 100.0)
                + (net_b as f64 / (4.0 * 1024.0 * 1024.0)))
                .min(1.5),
            mem_delta_norm,
            prompt_entropy_norm: 0.22,
        };
        let action = Array1::from_vec(vec![0.0, 1.0, 0.0]);
        self.evaluate_observed(&action, observed)
    }

    fn latched_verdict(&self) -> GuardVerdict {
        if let Ok(lv) = self.last_verdict.lock() {
            if let Some(ref v) = *lv {
                if v.block_execution {
                    return v.clone();
                }
            }
        }
        GuardVerdict {
            domain: "AGENT_OCTOPUS_RUNTIME",
            surprise_score: f64::MAX,
            threshold: sanitize_threshold_for_verdict(self.guard.threshold()),
            block_execution: true,
            reason:
                "Latent trajectory divergence: runtime monitor latched after prior breakout trip.",
        }
    }

    fn evaluate_observed(&self, action: &Array1<f64>, observed: RuntimeTelemetry) -> GuardVerdict {
        if self.is_tripped() {
            return self.latched_verdict();
        }
        let Ok(mut prev) = self.prev_state.lock() else {
            self.tripped.store(true, Ordering::Release);
            return GuardVerdict {
                domain: "AGENT_OCTOPUS_RUNTIME",
                surprise_score: f64::MAX,
                threshold: sanitize_threshold_for_verdict(self.guard.threshold()),
                block_execution: true,
                reason: "Fail-closed: runtime monitor mutex poisoned.",
            };
        };
        if self.is_tripped() {
            return self.latched_verdict();
        }

        let mut verdict = self.guard.evaluate_step(&prev, action, &observed);
        if observed.child_procs_norm > 0.0 {
            let anchor_verdict = self
                .guard
                .evaluate_step(&self.anchor_state, action, &observed);
            if anchor_verdict.block_execution
                && (!verdict.block_execution
                    || anchor_verdict.surprise_score > verdict.surprise_score)
            {
                verdict = anchor_verdict;
            }
        }

        if let Ok(mut lv) = self.last_verdict.lock() {
            *lv = Some(verdict.clone());
        }
        if verdict.block_execution {
            if let Ok(mut tr) = self.trip_reason.lock() {
                *tr = Some(format!(
                    "{} (surprise={:.4}, threshold={:.4})",
                    verdict.reason, verdict.surprise_score, verdict.threshold
                ));
            }
            // Release-store AFTER last_verdict and trip_reason are populated.
            self.tripped.store(true, Ordering::Release);
        } else if observed.child_procs_norm == 0.0 {
            *prev = observed;
        }
        verdict
    }
}

// =========================================================================
// PART 4: Unified Security Shield Orchestrator
// =========================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnifiedSecurityShield {
    pub sbom_guard: SbomSupplyChainGuard,
    pub runtime_guard: AgentRuntimeGuard,
}

static EMBEDDED_DEFAULT_SHIELD: OnceLock<Result<UnifiedSecurityShield, String>> = OnceLock::new();

impl UnifiedSecurityShield {
    pub fn authorize_and_step(
        &self,
        baseline_sbom: &CycloneDxSbom,
        sbom_intent: &Array1<f64>,
        candidate_sbom: &CycloneDxSbom,
        prev_runtime: &RuntimeTelemetry,
        tool_action: &Array1<f64>,
        next_runtime: &RuntimeTelemetry,
    ) -> Result<GuardVerdict, GuardVerdict> {
        let sbom_verdict =
            self.sbom_guard
                .evaluate_sbom_diff(baseline_sbom, sbom_intent, candidate_sbom);
        if sbom_verdict.block_execution {
            return Err(sbom_verdict);
        }

        let runtime_verdict =
            self.runtime_guard
                .evaluate_step(prev_runtime, tool_action, next_runtime);
        if runtime_verdict.block_execution {
            return Err(runtime_verdict);
        }

        Ok(runtime_verdict)
    }

    pub fn validate_integrity(&self) -> Result<(), LatentShieldError> {
        self.sbom_guard.validate_integrity()?;
        self.runtime_guard.validate_integrity()?;
        Ok(())
    }

    /// Parses and validates a serialized `UnifiedSecurityShield` JSON payload with bounded byte length.
    pub fn parse_weights_json_bounded(raw: &str) -> Result<Self, LatentShieldError> {
        if raw.len() > MAX_WEIGHTS_JSON_BYTES {
            return Err(LatentShieldError::WeightsParseError(format!(
                "weights JSON byte length {} exceeds MAX_WEIGHTS_JSON_BYTES ({})",
                raw.len(),
                MAX_WEIGHTS_JSON_BYTES
            )));
        }
        if raw.as_bytes().contains(&0) {
            return Err(LatentShieldError::WeightsParseError(
                "weights JSON contains embedded NUL byte".to_string(),
            ));
        }
        let shield: Self = serde_json::from_str(raw).map_err(|e| {
            LatentShieldError::WeightsParseError(format!("failed to parse weights JSON: {}", e))
        })?;
        shield.validate_integrity()?;
        Ok(shield)
    }

    /// Loads and validates the compile-time embedded deterministic weights.
    pub fn from_embedded_defaults() -> Result<Self, LatentShieldError> {
        Self::parse_weights_json_bounded(DEFAULT_EMBEDDED_WEIGHTS_JSON)
    }

    /// Returns a process-wide cached reference to the embedded `UnifiedSecurityShield`.
    pub fn cached_default() -> Result<&'static Self, LatentShieldError> {
        let res = EMBEDDED_DEFAULT_SHIELD
            .get_or_init(|| Self::from_embedded_defaults().map_err(|e| e.to_string()));
        match res {
            Ok(shield) => Ok(shield),
            Err(msg) => Err(LatentShieldError::WeightsParseError(msg.clone())),
        }
    }

    /// Loads and validates custom `UnifiedSecurityShield` weights from disk (`--latent-weights <PATH>`).
    pub fn from_weights_file(path: &Path) -> Result<Self, LatentShieldError> {
        let raw = read_bounded_utf8_file(path, MAX_WEIGHTS_JSON_BYTES, "latent weights")?;
        Self::parse_weights_json_bounded(&raw)
    }

    /// Deterministically trains both `SbomSupplyChainGuard` and `AgentRuntimeGuard` over 60 epochs
    /// using a seeded `StdRng` and calibrates fail-closed anomaly thresholds from clean validation
    /// trajectories.
    pub fn train_deterministic_default(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);

        // ---------------------------------------------------------------------
        // 1. Train SBOM Supply-Chain World Model (60 epochs)
        // ---------------------------------------------------------------------
        let mut sbom_model =
            LatentWorldModel::new(SBOM_OBS_DIM, SBOM_ACTION_DIM, DEFAULT_LATENT_DIM, seed);
        let mut sbom_samples: Vec<(Array1<f64>, Array1<f64>, Array1<f64>)> =
            Vec::with_capacity(192);

        // Anchor clean small-to-medium repository baseline patch/minor transitions.
        for base_c in [0.04_f64, 0.08, 0.15, 0.30, 0.60] {
            let x_b = Array1::from_vec(vec![base_c, 0.10, 0.0, 1.0, 0.0, 0.90]);
            let x_p = Array1::from_vec(vec![base_c + 0.01, 0.10, 0.0, 1.0, 0.0, 0.90]);
            sbom_samples.push((x_b.clone(), Array1::from_vec(vec![1.0, 0.0, 0.0]), x_p));
            let x_m = Array1::from_vec(vec![base_c + 0.03, 0.12, 0.0, 0.98, 0.0, 0.88]);
            sbom_samples.push((x_b, Array1::from_vec(vec![0.0, 1.0, 0.0]), x_m));
        }

        for idx in 0..182 {
            let intent_kind = idx % 3;
            let base_comp: f64 = rng.gen_range(0.02..0.80);
            let base_edge: f64 = rng.gen_range(0.05..0.45);
            let base_perm: f64 = rng.gen_range(0.82..1.0);
            let base_ns: f64 = rng.gen_range(0.45..1.0);
            let base_purl_noise: f64 = rng.gen_range(0.0..0.02);

            let (d_comp, d_edge, d_ns, action): (f64, f64, f64, Array1<f64>) = match intent_kind {
                // Patch: minimal dependency/edge drift, negligible non-standard PURL, zero elevated caps
                0 => (
                    rng.gen_range(0.0..0.02),
                    rng.gen_range(-0.01..0.015),
                    rng.gen_range(-0.02..0.02),
                    Array1::from_vec(vec![1.0, 0.0, 0.0]),
                ),
                // Minor: moderate dependency additions, negligible non-standard PURL, zero elevated caps
                1 => (
                    rng.gen_range(0.01..0.06),
                    rng.gen_range(0.0..0.04),
                    rng.gen_range(-0.04..0.04),
                    Array1::from_vec(vec![0.0, 1.0, 0.0]),
                ),
                // Refactor: structural adjustments across clean packages
                _ => (
                    rng.gen_range(-0.04..0.08),
                    rng.gen_range(-0.03..0.05),
                    rng.gen_range(-0.06..0.06),
                    Array1::from_vec(vec![0.0, 0.0, 1.0]),
                ),
            };

            let perm_delta: f64 = rng.gen_range(-0.02..0.02);
            let next_purl_noise: f64 = rng.gen_range(0.0..0.02);
            let x_t = Array1::from_vec(vec![
                base_comp,
                base_edge,
                base_purl_noise,
                base_perm,
                0.0,
                base_ns,
            ]);
            let x_next = Array1::from_vec(vec![
                (base_comp + d_comp).clamp(0.01, 2.0),
                (base_edge + d_edge).clamp(0.0, 1.0),
                next_purl_noise,
                (base_perm + perm_delta).clamp(0.75, 1.0),
                0.0,
                (base_ns + d_ns).clamp(0.25, 1.0),
            ]);
            sbom_samples.push((x_t, action, x_next));
        }

        let mut flat_rng = StdRng::seed_from_u64(seed.wrapping_add(303));
        let mut extra_sbom_samples: Vec<(Array1<f64>, Array1<f64>, Array1<f64>)> = Vec::new();
        for base_c in [0.01_f64, 0.02, 0.03, 0.04, 0.10, 0.30, 0.60, 1.00] {
            for base_ns in [0.34_f64, 0.67, 1.00] {
                let x = Array1::from_vec(vec![base_c, 0.0, 0.0, 1.0, 0.0, base_ns]);
                for act in [
                    vec![1.0, 0.0, 0.0],
                    vec![0.0, 1.0, 0.0],
                    vec![0.0, 0.0, 1.0],
                ] {
                    extra_sbom_samples.push((x.clone(), Array1::from_vec(act), x.clone()));
                }
            }
            let x = Array1::from_vec(vec![base_c, 0.0, 0.0, 1.0, 0.0, 1.0]);
            let x_p = Array1::from_vec(vec![(base_c + 0.01).min(2.0), 0.0, 0.0, 1.0, 0.0, 1.0]);
            extra_sbom_samples.push((x.clone(), Array1::from_vec(vec![1.0, 0.0, 0.0]), x_p));
            let x_m = Array1::from_vec(vec![(base_c + 0.03).min(2.0), 0.0, 0.0, 1.0, 0.0, 0.95]);
            extra_sbom_samples.push((x, Array1::from_vec(vec![0.0, 1.0, 0.0]), x_m));
        }
        for base_c in [0.01_f64, 0.04, 0.10, 0.50] {
            let x_d = Array1::from_vec(vec![base_c, 0.10, 0.0, 1.0, 0.0, 1.0]);
            for act in [
                vec![1.0, 0.0, 0.0],
                vec![0.0, 1.0, 0.0],
                vec![0.0, 0.0, 1.0],
            ] {
                extra_sbom_samples.push((x_d.clone(), Array1::from_vec(act), x_d.clone()));
            }
        }

        for epoch in 0..60 {
            let lr = 0.04 * (1.0 - (epoch as f64 / 75.0));
            for (x_t, act, x_next) in &sbom_samples {
                let _ = sbom_model.train_step(x_t, act, x_next, lr, &mut rng);
            }
            let lr_extra = 0.025 * (1.0 - (epoch as f64 / 75.0));
            for (x_t, act, x_next) in &extra_sbom_samples {
                let _ = sbom_model.train_step(x_t, act, x_next, lr_extra, &mut flat_rng);
            }
        }

        let mut sbom_surprises: Vec<f64> = sbom_samples
            .iter()
            .chain(extra_sbom_samples.iter())
            .filter_map(|(x_t, act, x_next)| sbom_model.try_compute_surprise(x_t, act, x_next).ok())
            .collect();
        sbom_surprises.sort_by(|a, b| a.total_cmp(b));
        let p98_idx = (sbom_surprises.len().saturating_sub(1) * 98) / 100;
        let clean_sbom_ref = sbom_surprises.get(p98_idx).copied().unwrap_or(0.015);
        let sbom_threshold = (clean_sbom_ref * 1.6).clamp(0.012, 0.035);

        // ---------------------------------------------------------------------
        // 2. Train Runtime Telemetry World Model (60 epochs)
        // ---------------------------------------------------------------------
        let mut rt_rng = StdRng::seed_from_u64(seed.wrapping_add(101));
        let mut runtime_model = LatentWorldModel::new(
            RUNTIME_OBS_DIM,
            RUNTIME_ACTION_DIM,
            DEFAULT_LATENT_DIM,
            seed.wrapping_add(101),
        );
        let mut rt_samples: Vec<(Array1<f64>, Array1<f64>, Array1<f64>)> = Vec::with_capacity(120);

        // Anchor baseline/idle transitions so minimal Wasm/Python steps stay near zero surprise.
        let baseline_vec = RuntimeTelemetry::baseline_rag().to_array();
        let idle_vec = RuntimeTelemetry::idle_initial().to_array();
        let zero_vec = Array1::zeros(RUNTIME_OBS_DIM);
        for action_vec in [
            vec![1.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0],
            vec![0.0, 0.0, 1.0],
        ] {
            let act = Array1::from_vec(action_vec);
            rt_samples.push((baseline_vec.clone(), act.clone(), baseline_vec.clone()));
            for _ in 0..4 {
                rt_samples.push((idle_vec.clone(), act.clone(), idle_vec.clone()));
            }
            rt_samples.push((zero_vec.clone(), act, zero_vec.clone()));
        }

        for idx in 0..114 {
            let tool_kind = idx % 3;
            let prev = Array1::from_vec(vec![
                rt_rng.gen_range(0.0..0.22),
                rt_rng.gen_range(0.0..0.15),
                0.0,
                rt_rng.gen_range(0.0..0.18),
                rt_rng.gen_range(0.0..0.20),
                rt_rng.gen_range(0.12..0.38),
            ]);

            let (next, act) = match tool_kind {
                // Tool 0: Read / RAG retrieval / Wasm doc extract
                0 => {
                    let delta: f64 = rt_rng.gen_range(0.0..0.12);
                    (
                        Array1::from_vec(vec![
                            (prev[0] + delta).clamp(0.0, 0.35),
                            rt_rng.gen_range(0.0..0.08),
                            0.0,
                            rt_rng.gen_range(0.0..0.15),
                            rt_rng.gen_range(0.0..0.22),
                            rt_rng.gen_range(0.14..0.40),
                        ]),
                        Array1::from_vec(vec![1.0, 0.0, 0.0]),
                    )
                }
                // Tool 1: Confined scratchpad write / ledger update
                1 => {
                    let delta: f64 = rt_rng.gen_range(0.01..0.14);
                    (
                        Array1::from_vec(vec![
                            rt_rng.gen_range(0.0..0.20),
                            (prev[1] + delta).clamp(0.0, 0.30),
                            0.0,
                            rt_rng.gen_range(0.0..0.12),
                            rt_rng.gen_range(0.0..0.22),
                            rt_rng.gen_range(0.14..0.40),
                        ]),
                        Array1::from_vec(vec![0.0, 1.0, 0.0]),
                    )
                }
                // Tool 2: Policy-permitted HTTP / AgentMesh call
                _ => {
                    let delta: f64 = rt_rng.gen_range(0.01..0.14);
                    (
                        Array1::from_vec(vec![
                            rt_rng.gen_range(0.0..0.18),
                            rt_rng.gen_range(0.0..0.10),
                            0.0,
                            (prev[3] + delta).clamp(0.0, 0.32),
                            rt_rng.gen_range(0.0..0.22),
                            rt_rng.gen_range(0.14..0.40),
                        ]),
                        Array1::from_vec(vec![0.0, 0.0, 1.0]),
                    )
                }
            };
            rt_samples.push((prev, act, next));
        }

        // Incremental steady-state transitions around baseline_rag() so multi-step Python IPC
        // alternating reads/writes/egress stays comfortably inside the normal manifold.
        let mut inc_rng = StdRng::seed_from_u64(seed.wrapping_add(202));
        for idx in 0..24 {
            let r: f64 = inc_rng.gen_range(0.05..0.25);
            let w: f64 = inc_rng.gen_range(0.0..0.18);
            let n: f64 = inc_rng.gen_range(0.02..0.15);
            let prev = Array1::from_vec(vec![r, w, 0.0, n, 0.02, 0.22]);
            let (next, act) = match idx % 3 {
                0 => (
                    Array1::from_vec(vec![(r + 0.005).min(0.30), w, 0.0, n, 0.02, 0.22]),
                    Array1::from_vec(vec![1.0, 0.0, 0.0]),
                ),
                1 => (
                    Array1::from_vec(vec![r, (w + 0.005).min(0.24), 0.0, n, 0.02, 0.22]),
                    Array1::from_vec(vec![0.0, 1.0, 0.0]),
                ),
                _ => (
                    Array1::from_vec(vec![r, w, 0.0, (n + 0.005).min(0.22), 0.02, 0.22]),
                    Array1::from_vec(vec![0.0, 0.0, 1.0]),
                ),
            };
            rt_samples.push((prev, act, next));
        }

        // Focused Tier-1 Wasm hostcall & mesh_stream transitions from idle_initial()
        for mem_base in [0.0_f64, 0.0078125] {
            let start = Array1::from_vec(vec![0.0, 0.0, 0.0, 0.0, mem_base, 0.20]);
            for dr in [0.03_f64, 0.06] {
                rt_samples.push((
                    start.clone(),
                    Array1::from_vec(vec![1.0, 0.0, 0.0]),
                    Array1::from_vec(vec![dr, 0.0, 0.0, 0.0, mem_base, 0.2001]),
                ));
            }
            for dw in [0.0_f64, 0.04] {
                rt_samples.push((
                    start.clone(),
                    Array1::from_vec(vec![0.0, 1.0, 0.0]),
                    Array1::from_vec(vec![0.0, dw, 0.0, 0.0, mem_base, 0.205]),
                ));
            }
            for (n0, n1) in [(0.0_f64, 0.000012), (0.000012, 0.04003), (0.0, 0.04003)] {
                rt_samples.push((
                    Array1::from_vec(vec![0.0, 0.0, 0.0, n0, mem_base, 0.20]),
                    Array1::from_vec(vec![0.0, 0.0, 1.0]),
                    Array1::from_vec(vec![0.0, 0.0, 0.0, n1, mem_base, 0.20]),
                ));
            }
            rt_samples.push((
                idle_vec.clone(),
                Array1::from_vec(vec![1.0, 0.0, 0.0]),
                Array1::from_vec(vec![0.0, 0.0, 0.0, 0.0, mem_base, 0.20005]),
            ));
        }
        for step in 0..8 {
            let n_cur = (step as f64) * 0.02;
            let n_next = n_cur + 0.04;
            rt_samples.push((
                Array1::from_vec(vec![0.0, 0.0, 0.0, n_cur, 0.0, 0.20]),
                Array1::from_vec(vec![0.0, 0.0, 1.0]),
                Array1::from_vec(vec![0.0, 0.0, 0.0, n_next, 0.0, 0.20]),
            ));
            rt_samples.push((
                Array1::from_vec(vec![0.0, 0.0, 0.0, n_next, 0.0, 0.20]),
                Array1::from_vec(vec![0.0, 1.0, 0.0]),
                Array1::from_vec(vec![0.0, 0.0, 0.0, n_next, 0.0, 0.21]),
            ));
        }

        // Train Encoder/Decoder representation on child_procs_norm while Predictor remains
        // anchored solely on child_procs_norm == 0.0 normal trajectories.
        let mut child_recon_samples: Vec<Array1<f64>> = Vec::with_capacity(12);
        for c in [0.4_f64, 0.6, 0.8, 1.0, 1.2, 1.5] {
            child_recon_samples.push(Array1::from_vec(vec![0.05, 0.0, c, 0.02, 0.02, 0.22]));
            child_recon_samples.push(Array1::from_vec(vec![0.0, 0.0, c, 0.0, 0.0, 0.20]));
        }

        for epoch in 0..60 {
            let lr = 0.035 * (1.0 - (epoch as f64 / 75.0));
            for (x_t, act, x_next) in &rt_samples {
                let _ = runtime_model.train_step(x_t, act, x_next, lr, &mut rt_rng);
            }
            for x in &child_recon_samples {
                let _ = runtime_model.train_recon_only_step(x, lr * 0.35, &mut rt_rng);
            }
        }

        let mut rt_surprises: Vec<f64> = rt_samples
            .iter()
            .filter_map(|(x_t, act, x_next)| {
                runtime_model.try_compute_surprise(x_t, act, x_next).ok()
            })
            .collect();
        rt_surprises.sort_by(|a, b| a.total_cmp(b));
        let max_clean_rt_surprise = rt_surprises.last().copied().unwrap_or(0.02);
        let runtime_threshold = (max_clean_rt_surprise * 1.4).clamp(0.012, 0.085);

        Self {
            sbom_guard: SbomSupplyChainGuard::new(sbom_model, sbom_threshold),
            runtime_guard: AgentRuntimeGuard::new(runtime_model, runtime_threshold),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sbom(components: Vec<SbomComponent>, deps: Vec<SbomDependency>) -> CycloneDxSbom {
        CycloneDxSbom {
            components,
            dependencies: deps,
        }
    }

    fn clean_comp(name: &str, ver: &str, purl_prefix: &str, license: &str) -> SbomComponent {
        SbomComponent {
            name: name.to_string(),
            version: ver.to_string(),
            purl: Some(format!("{}{}@{}", purl_prefix, name, ver)),
            licenses: vec![LicenseChoice {
                license: Some(LicenseDetail {
                    id: Some(license.to_string()),
                }),
            }],
            properties: Vec::new(),
        }
    }

    #[test]
    fn calibrate_and_verify_deterministic_training_separation() {
        let shield = UnifiedSecurityShield::train_deterministic_default(42);
        shield.validate_integrity().expect("trained model valid");

        let baseline = sample_sbom(
            vec![
                clean_comp("serde", "1.0.200", "pkg:cargo/", "MIT"),
                clean_comp("tokio", "1.38.0", "pkg:cargo/", "MIT"),
                clean_comp("sha2", "0.10.8", "pkg:cargo/", "Apache-2.0"),
                clean_comp("hex", "0.4.3", "pkg:cargo/", "MIT"),
            ],
            vec![SbomDependency {
                component_ref: "app".to_string(),
                depends_on: vec!["serde".to_string(), "tokio".to_string()],
            }],
        );

        let clean_v2 = sample_sbom(
            vec![
                clean_comp("serde", "1.0.201", "pkg:cargo/", "MIT"),
                clean_comp("tokio", "1.38.0", "pkg:cargo/", "MIT"),
                clean_comp("sha2", "0.10.8", "pkg:cargo/", "Apache-2.0"),
                clean_comp("hex", "0.4.3", "pkg:cargo/", "MIT"),
            ],
            vec![SbomDependency {
                component_ref: "app".to_string(),
                depends_on: vec!["serde".to_string(), "tokio".to_string()],
            }],
        );

        let poisoned_v2 = sample_sbom(
            vec![
                clean_comp("serde", "1.0.201", "pkg:cargo/", "MIT"),
                clean_comp("tokio", "1.38.0", "pkg:cargo/", "MIT"),
                clean_comp("sha2", "0.10.8", "pkg:cargo/", "Apache-2.0"),
                clean_comp("hex", "0.4.3", "pkg:cargo/", "MIT"),
                SbomComponent {
                    name: "evil-net-hook".to_string(),
                    version: "0.0.1".to_string(),
                    purl: Some("pkg:raw/evil-net-hook@0.0.1".to_string()),
                    licenses: Vec::new(),
                    properties: vec![ComponentProperty {
                        name: "capability".to_string(),
                        value: "network,build-script,ffi".to_string(),
                    }],
                },
            ],
            vec![SbomDependency {
                component_ref: "app".to_string(),
                depends_on: vec![
                    "serde".to_string(),
                    "tokio".to_string(),
                    "evil-net-hook".to_string(),
                ],
            }],
        );

        let clean_sbom_verdict = shield.sbom_guard.evaluate_sbom_diff(
            &baseline,
            &SbomIntent::Patch.to_action_array(),
            &clean_v2,
        );
        let poisoned_sbom_verdict = shield.sbom_guard.evaluate_sbom_diff(
            &baseline,
            &SbomIntent::Patch.to_action_array(),
            &poisoned_v2,
        );

        let prev_rt = RuntimeTelemetry::baseline_rag();
        let normal_rt = RuntimeTelemetry {
            file_reads_norm: 0.12,
            file_writes_norm: 0.04,
            child_procs_norm: 0.0,
            net_sockets_norm: 0.08,
            mem_delta_norm: 0.05,
            prompt_entropy_norm: 0.25,
        };
        let breakout_child = RuntimeTelemetry {
            file_reads_norm: 0.15,
            file_writes_norm: 0.10,
            child_procs_norm: 1.0,
            net_sockets_norm: 0.05,
            mem_delta_norm: 0.10,
            prompt_entropy_norm: 0.25,
        };
        let breakout_net = RuntimeTelemetry {
            file_reads_norm: 0.10,
            file_writes_norm: 0.05,
            child_procs_norm: 0.0,
            net_sockets_norm: 1.2,
            mem_delta_norm: 0.10,
            prompt_entropy_norm: 0.25,
        };
        let breakout_mem = RuntimeTelemetry {
            file_reads_norm: 0.05,
            file_writes_norm: 0.02,
            child_procs_norm: 0.0,
            net_sockets_norm: 0.02,
            mem_delta_norm: 1.4,
            prompt_entropy_norm: 0.22,
        };

        let normal_rt_v = shield.runtime_guard.evaluate_step(
            &prev_rt,
            &Array1::from_vec(vec![1.0, 0.0, 0.0]),
            &normal_rt,
        );
        let child_rt_v = shield.runtime_guard.evaluate_step(
            &prev_rt,
            &Array1::from_vec(vec![1.0, 0.0, 0.0]),
            &breakout_child,
        );
        let net_rt_v = shield.runtime_guard.evaluate_step(
            &prev_rt,
            &Array1::from_vec(vec![0.0, 0.0, 1.0]),
            &breakout_net,
        );
        let mem_rt_v = shield.runtime_guard.evaluate_step(
            &prev_rt,
            &Array1::from_vec(vec![1.0, 0.0, 0.0]),
            &breakout_mem,
        );

        eprintln!(
            "SBOM clean={:?} poisoned={:?}",
            clean_sbom_verdict, poisoned_sbom_verdict
        );
        eprintln!(
            "RT normal={:?}\n  child={:?}\n  net={:?}\n  mem={:?}",
            normal_rt_v, child_rt_v, net_rt_v, mem_rt_v
        );

        if std::env::var_os("REGEN_LATENT_WEIGHTS").is_some() {
            let json = serde_json::to_string_pretty(&shield).expect("serialize shield");
            let out_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("security")
                .join("latent_shield_weights.json");
            std::fs::write(out_path, json).expect("write weights json");
        }

        assert!(!clean_sbom_verdict.block_execution);
        assert!(poisoned_sbom_verdict.block_execution);
        assert!(!normal_rt_v.block_execution);
        assert!(
            !shield
                .runtime_guard
                .evaluate_step(
                    &RuntimeTelemetry::idle_initial(),
                    &Array1::from_vec(vec![1.0, 0.0, 0.0]),
                    &RuntimeTelemetry::idle_initial(),
                )
                .block_execution,
            "idle_initial self-transition must remain allowed"
        );
        assert!(child_rt_v.block_execution);
        assert!(net_rt_v.block_execution);
        assert!(mem_rt_v.block_execution);
    }

    #[test]
    fn live_runtime_monitor_allows_benign_ipc_and_blocks_breakout_spikes() {
        let shield = UnifiedSecurityShield::cached_default().expect("cached default");
        let guard = Arc::new(shield.runtime_guard.clone());

        // 1. Benign multi-step Python IPC & proxy operations remain comfortably below threshold
        let benign = LiveRuntimeMonitor::new(Arc::clone(&guard));
        for _ in 0..300 {
            let v = benign.record_and_evaluate(RuntimeEventKind::FileRead, 0, 0.02, 0.22);
            assert!(
                !v.block_execution,
                "benign FileRead unexpectedly blocked: {:?}",
                v
            );
        }
        for _ in 0..150 {
            let v = benign.record_and_evaluate(RuntimeEventKind::FileWrite, 0, 0.02, 0.22);
            assert!(
                !v.block_execution,
                "benign FileWrite unexpectedly blocked: {:?}",
                v
            );
        }
        for _ in 0..4 {
            let v = benign.record_and_evaluate(RuntimeEventKind::ChildProcess, 0, 0.02, 0.22);
            assert!(
                !v.block_execution,
                "benign permitted ChildProcess unexpectedly blocked: {:?}",
                v
            );
        }
        for _ in 0..10 {
            let v = benign.record_and_evaluate(RuntimeEventKind::NetworkEgress, 4096, 0.02, 0.22);
            assert!(
                !v.block_execution,
                "benign NetworkEgress unexpectedly blocked: {:?}",
                v
            );
        }
        assert!(!benign.is_tripped());

        // 1b. Alternating & first-step-any-kind transitions from baseline_rag must also stay below threshold
        for first_kind in [
            RuntimeEventKind::FileRead,
            RuntimeEventKind::FileWrite,
            RuntimeEventKind::ChildProcess,
            RuntimeEventKind::NetworkEgress,
        ] {
            let m = LiveRuntimeMonitor::new(Arc::clone(&guard));
            let v1 = m.record_and_evaluate(first_kind, 0, 0.02, 0.22);
            assert!(
                !v1.block_execution,
                "first-step {:?} unexpectedly blocked: {:?}",
                first_kind, v1
            );
            for _ in 0..50 {
                let vr = m.record_and_evaluate(RuntimeEventKind::FileRead, 0, 0.02, 0.22);
                assert!(
                    !vr.block_execution,
                    "alternating FileRead blocked: {:?}",
                    vr
                );
                let vw = m.record_and_evaluate(RuntimeEventKind::FileWrite, 0, 0.02, 0.22);
                assert!(
                    !vw.block_execution,
                    "alternating FileWrite blocked: {:?}",
                    vw
                );
            }
        }

        // 2. Child process spawn flood trips Gate 2
        let spawn_flood = LiveRuntimeMonitor::new(Arc::clone(&guard));
        let mut spawn_tripped = false;
        for _ in 0..8 {
            let v = spawn_flood.record_and_evaluate(RuntimeEventKind::ChildProcess, 0, 0.02, 0.22);
            if v.block_execution {
                spawn_tripped = true;
                break;
            }
        }
        assert!(spawn_tripped && spawn_flood.is_tripped());

        // 3. Large network exfiltration payload trips Gate 2
        let net_exfil = LiveRuntimeMonitor::new(Arc::clone(&guard));
        let exfil_v = net_exfil.record_and_evaluate(
            RuntimeEventKind::NetworkEgress,
            4 * 1024 * 1024,
            0.02,
            0.22,
        );
        assert!(exfil_v.block_execution && net_exfil.is_tripped());

        // 4. JobObject process burst snapshot trips Gate 2
        let snap_mon = LiveRuntimeMonitor::new(guard);
        let snap_v = snap_mon.evaluate_snapshot(1.5, 0.10);
        assert!(
            snap_v.block_execution && snap_mon.is_tripped(),
            "JobObject burst snapshot did not trip: {:?}",
            snap_v
        );
    }

    #[test]
    fn live_runtime_monitor_post_trip_latch_preserves_verdict_and_blocks_subsequent_calls() {
        let shield = UnifiedSecurityShield::cached_default().expect("cached default");
        let guard = Arc::new(shield.runtime_guard.clone());

        let mon = LiveRuntimeMonitor::new(Arc::clone(&guard));
        for _ in 0..5 {
            let _ = mon.record_and_evaluate(RuntimeEventKind::ChildProcess, 0, 0.02, 0.22);
        }
        assert!(mon.is_tripped());
        let tripped_reason = mon.trip_reason().expect("trip reason populated");
        let tripped_verdict = mon.last_verdict().expect("last verdict populated");
        assert!(tripped_verdict.block_execution);

        // Subsequent benign IPC/proxy calls must stay latched at block_execution == true
        let follow_read = mon.record_and_evaluate(RuntimeEventKind::FileRead, 0, 0.02, 0.22);
        assert!(follow_read.block_execution);
        let follow_write = mon.record_and_evaluate(RuntimeEventKind::FileWrite, 0, 0.02, 0.22);
        assert!(follow_write.block_execution);
        let follow_net = mon.record_and_evaluate(RuntimeEventKind::NetworkEgress, 128, 0.02, 0.22);
        assert!(follow_net.block_execution);

        let after_verdict = mon.last_verdict().expect("latched last verdict");
        assert!(after_verdict.block_execution);
        assert_eq!(after_verdict.surprise_score, tripped_verdict.surprise_score);
        assert_eq!(mon.trip_reason().as_deref(), Some(tripped_reason.as_str()));
    }
}
