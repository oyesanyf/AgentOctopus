//! Law 7 — Wave Physics (Red-Team Upgrade #5): Discrete Fourier Transform (DFT)
//! Spectral Beacon & Periodic Overnight Polling Detector.
//!
//! Catches low-and-slow autonomous vendor bots (e.g., the NewCore Nov 2026 xAI Grok
//! 31-request overnight polling campaign) whose individual requests look small and benign,
//! by transforming per-NHI request timestamps into the frequency domain via a real
//! $N$-point Discrete Fourier Transform:
//!
//! $$X[k] = \sum_{n=0}^{N-1} x[n] e^{-i 2\pi k n / N}, \qquad P[k] = |X[k]|^2$$
//!
//! and combining the **Peak-to-Average Power Ratio (PAPR)** with the inter-arrival
//! **Coefficient of Variation ($CV = \sigma / \mu$)** to identify machine-periodic beacons
//! deterministically without any ML model.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

const MAX_TIMESTAMPS_PER_NHI: usize = 128;
const DFT_BINS: usize = 64;

/// Verdict produced by Law 7 (Wave Physics Spectral Beacon Detector).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpectralBeaconVerdict {
    pub allowed: bool,
    pub beacon_detected: bool,
    pub sample_count: usize,
    pub mean_interval_secs: f64,
    pub interval_cv: f64,
    pub dft_peak_power_ratio: f64,
    pub dominant_frequency_bin: usize,
    pub reason: String,
}

/// Per-NHI frequency-domain beacon analyzer.
pub struct SpectralBeaconDetector {
    min_samples: usize,
    max_cv_for_beacon: f64,
    min_papr_for_beacon: f64,
    history: Mutex<HashMap<String, VecDeque<u64>>>,
}

impl Default for SpectralBeaconDetector {
    fn default() -> Self {
        Self::new(6, 0.18, 3.2)
    }
}

impl SpectralBeaconDetector {
    #[must_use]
    pub fn new(min_samples: usize, max_cv_for_beacon: f64, min_papr_for_beacon: f64) -> Self {
        Self {
            min_samples: min_samples.max(4),
            max_cv_for_beacon: max_cv_for_beacon.clamp(0.01, 0.5),
            min_papr_for_beacon: min_papr_for_beacon.max(1.5),
            history: Mutex::new(HashMap::new()),
        }
    }

    /// Records a timestamp for `nhi_id` and evaluates its DFT power spectrum and inter-arrival regularity.
    /// `unattended` lowers the trigger tolerance when requests arrive while the human is absent.
    #[must_use]
    pub fn observe_and_evaluate(
        &self,
        nhi_id: &str,
        ts_unix: u64,
        unattended: bool,
    ) -> SpectralBeaconVerdict {
        let key = nhi_id.to_ascii_lowercase();
        let timestamps: Vec<u64> = {
            let mut map = self.history.lock();
            let q = map
                .entry(key)
                .or_insert_with(|| VecDeque::with_capacity(64));
            if q.len() >= MAX_TIMESTAMPS_PER_NHI {
                q.pop_front();
            }
            q.push_back(ts_unix);
            q.iter().copied().collect()
        };

        let n_samples = timestamps.len();
        if n_samples < self.min_samples {
            return SpectralBeaconVerdict {
                allowed: true,
                beacon_detected: false,
                sample_count: n_samples,
                mean_interval_secs: 0.0,
                interval_cv: 1.0,
                dft_peak_power_ratio: 0.0,
                dominant_frequency_bin: 0,
                reason: format!(
                    "LAW7_SPECTRAL_WARMUP: {n_samples}/{} samples collected",
                    self.min_samples
                ),
            };
        }

        // Compute inter-arrival deltas (in seconds)
        let mut sorted = timestamps;
        sorted.sort_unstable();
        let deltas: Vec<f64> = sorted
            .windows(2)
            .map(|w| w[1].saturating_sub(w[0]) as f64)
            .filter(|&d| d > 0.0)
            .collect();

        if deltas.len() < self.min_samples - 1 {
            return SpectralBeaconVerdict {
                allowed: true,
                beacon_detected: false,
                sample_count: n_samples,
                mean_interval_secs: 0.0,
                interval_cv: 1.0,
                dft_peak_power_ratio: 0.0,
                dominant_frequency_bin: 0,
                reason: "LAW7_SPECTRAL_ALLOW: Burst within single second (no periodic beacon)"
                    .to_string(),
            };
        }

        let m = deltas.len() as f64;
        let mean = deltas.iter().sum::<f64>() / m;
        let var = deltas.iter().map(|&d| (d - mean).powi(2)).sum::<f64>() / m;
        let std_dev = var.sqrt();
        let cv = if mean > 1e-6 { std_dev / mean } else { 1.0 };

        // Bin arrival impulses across [t_first, t_last] into DFT_BINS buckets and run genuine DFT
        let t0 = sorted[0];
        let t_span = sorted[sorted.len() - 1].saturating_sub(t0).max(1) as f64;
        let mut signal = [0.0f64; DFT_BINS];
        for &ts in &sorted {
            let pos = (((ts - t0) as f64) / t_span) * ((DFT_BINS - 1) as f64);
            let idx = (pos.round() as usize).min(DFT_BINS - 1);
            signal[idx] += 1.0;
        }
        // Subtract DC mean so zero-frequency energy does not bias AC harmonics
        let sig_mean = signal.iter().sum::<f64>() / (DFT_BINS as f64);
        for s in &mut signal {
            *s -= sig_mean;
        }

        let mut max_power = 0.0f64;
        let mut max_bin = 0usize;
        let mut sum_power = 0.0f64;
        let nyquist = DFT_BINS / 2;
        for k in 1..nyquist {
            let mut re = 0.0f64;
            let mut im = 0.0f64;
            let base_angle = -2.0 * std::f64::consts::PI * (k as f64) / (DFT_BINS as f64);
            for (n, &xn) in signal.iter().enumerate() {
                let angle = base_angle * (n as f64);
                re += xn * angle.cos();
                im += xn * angle.sin();
            }
            let power = re * re + im * im;
            sum_power += power;
            if power > max_power {
                max_power = power;
                max_bin = k;
            }
        }
        let avg_power = sum_power / ((nyquist - 1).max(1) as f64);
        let papr = if avg_power > 1e-9 {
            max_power / avg_power
        } else {
            0.0
        };

        let cv_limit = if unattended {
            self.max_cv_for_beacon * 1.35
        } else {
            self.max_cv_for_beacon
        };
        let papr_limit = if unattended {
            self.min_papr_for_beacon * 0.85
        } else {
            self.min_papr_for_beacon
        };

        // Machine-periodic beacon: regular inter-arrival intervals (>= 5s period) + sharp DFT spectral peak
        let beacon_detected = mean >= 5.0 && cv <= cv_limit && papr >= papr_limit;

        let reason = if beacon_detected {
            format!(
                "LAW7_SPECTRAL_BEACON_DENY: Periodic automated polling detected for '{}' (mean={mean:.1}s, CV={cv:.3} <= {cv_limit:.3}, DFT PAPR={papr:.2} >= {papr_limit:.2} at bin {max_bin})",
                nhi_id
            )
        } else {
            format!(
                "LAW7_SPECTRAL_ALLOW: Non-periodic cadence (samples={n_samples}, mean={mean:.1}s, CV={cv:.3}, PAPR={papr:.2})"
            )
        };

        SpectralBeaconVerdict {
            allowed: !beacon_detected,
            beacon_detected,
            sample_count: n_samples,
            mean_interval_secs: mean,
            interval_cv: cv,
            dft_peak_power_ratio: papr,
            dominant_frequency_bin: max_bin,
            reason,
        }
    }

    pub fn clear_history(&self, nhi_id: &str) {
        self.history.lock().remove(&nhi_id.to_ascii_lowercase());
    }
}
