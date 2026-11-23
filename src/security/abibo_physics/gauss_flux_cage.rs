//! Law 5 — Electromagnetism: Gauss's Law Information Flux & Faraday-Cage Lockout.
//!
//! Treats the local agent runtime + vault boundary as a closed Gaussian surface $\partial\Omega$.
//! Outward sensitive data / mutation flux $\Phi_{\text{out}}$ integrated across a sliding window
//! MUST NEVER exceed the authorized internal charge $Q_{\text{authorized}}$:
//!
//! $$\Phi_{\text{out}} = \oint_{\partial\Omega} \mathbf{E}_{\text{data}} \cdot d\mathbf{A} \le Q_{\text{authorized}}$$
//!
//! Crucially, when the human workstation is offline, idle beyond horizon, or screen-locked:
//! $$Q_{\text{authorized}} \equiv 0$$
//! enforcing an unconditional **Faraday-Cage Lockout** with optional opt-in escalation into
//! AgentOctopus's OS Kernel Firewall (`host_network_isolation`).

use crate::security::artemis_dfir::WorkstationLivenessSnapshot;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};

/// Verdict produced by Law 5 (Gauss's Law Information Flux & Faraday-Cage Lockout).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GaussFluxVerdict {
    pub allowed: bool,
    pub window_flux_units: f64,
    pub requested_flux_units: f64,
    pub authorized_charge_q: f64,
    pub faraday_cage_engaged: bool,
    pub os_firewall_escalated: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Copy)]
struct FluxSample {
    ts_unix: u64,
    flux_units: f64,
}

/// Enforces Gauss's Law outbound flux conservation and Faraday-Cage lockout.
pub struct GaussFluxCage {
    window_secs: u64,
    base_authorized_charge: f64,
    escalate_os_firewall: AtomicBool,
    faraday_engaged: AtomicBool,
    samples: Mutex<VecDeque<FluxSample>>,
}

impl Default for GaussFluxCage {
    fn default() -> Self {
        Self::new(60, 65_536.0, false)
    }
}

impl GaussFluxCage {
    #[must_use]
    pub fn new(window_secs: u64, base_authorized_charge: f64, escalate_os_firewall: bool) -> Self {
        Self {
            window_secs: window_secs.max(5),
            base_authorized_charge: base_authorized_charge.max(1024.0),
            escalate_os_firewall: AtomicBool::new(escalate_os_firewall),
            faraday_engaged: AtomicBool::new(false),
            samples: Mutex::new(VecDeque::with_capacity(256)),
        }
    }

    pub fn set_os_firewall_escalation(&self, enabled: bool) {
        self.escalate_os_firewall.store(enabled, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_faraday_engaged(&self) -> bool {
        self.faraday_engaged.load(Ordering::SeqCst)
    }

    pub fn disarm_faraday_cage(&self) {
        self.faraday_engaged.store(false, Ordering::SeqCst);
    }

    /// Evaluates whether an outbound call carrying `payload_bytes` at `sensitivity_weight`
    /// (`1.0` = public, `4.0` = confidential/write, `16.0` = secret/PII) satisfies Gauss's Law.
    #[must_use]
    pub fn evaluate(
        &self,
        liveness: &WorkstationLivenessSnapshot,
        now_unix: u64,
        payload_bytes: usize,
        sensitivity_weight: f64,
        is_outbound_or_write: bool,
    ) -> GaussFluxVerdict {
        let weight = sensitivity_weight.max(0.5);
        let requested_flux = if is_outbound_or_write {
            (payload_bytes.max(1) as f64) * weight
        } else {
            0.0
        };

        // Prune expired sliding window samples
        let cutoff = now_unix.saturating_sub(self.window_secs);
        let mut samples = self.samples.lock();
        while let Some(front) = samples.front() {
            if front.ts_unix < cutoff {
                samples.pop_front();
            } else {
                break;
            }
        }
        let current_flux: f64 = samples.iter().map(|s| s.flux_units).sum();

        // Gauss's Law boundary condition: Q_authorized === 0 whenever workstation is locked or offline!
        let q_authorized = if liveness.human_live && !liveness.workstation_locked {
            self.base_authorized_charge
        } else {
            0.0
        };

        let projected = current_flux + requested_flux;
        if is_outbound_or_write && projected > q_authorized {
            self.faraday_engaged.store(true, Ordering::SeqCst);
            let mut os_fw = false;
            if self.escalate_os_firewall.load(Ordering::SeqCst) {
                let _ = crate::security::host_network_isolation::global_host_killswitch().engage(
                    "abibo_law5_faraday_cage",
                    "Gauss's Law outbound flux boundary exceeded (Faraday-Cage Lockout)",
                );
                os_fw = true;
            }
            let reason = if q_authorized <= 0.0 {
                format!(
                    "LAW5_FARADAY_CAGE_DENY: Workstation offline/locked => Q_authorized=0.0; outbound flux {requested_flux:.1} blocked"
                )
            } else {
                format!(
                    "LAW5_GAUSS_FLUX_OVERFLOW_DENY: Projected flux {projected:.1} > Q_authorized {q_authorized:.1} in {}s window; Faraday Cage engaged",
                    self.window_secs
                )
            };
            return GaussFluxVerdict {
                allowed: false,
                window_flux_units: current_flux,
                requested_flux_units: requested_flux,
                authorized_charge_q: q_authorized,
                faraday_cage_engaged: true,
                os_firewall_escalated: os_fw,
                reason,
            };
        }

        if is_outbound_or_write && requested_flux > 0.0 {
            if samples.len() >= 1024 {
                samples.pop_front();
            }
            samples.push_back(FluxSample {
                ts_unix: now_unix,
                flux_units: requested_flux,
            });
        }

        GaussFluxVerdict {
            allowed: true,
            window_flux_units: projected,
            requested_flux_units: requested_flux,
            authorized_charge_q: q_authorized,
            faraday_cage_engaged: false,
            os_firewall_escalated: false,
            reason: format!(
                "LAW5_GAUSS_FLUX_ALLOW: Projected flux {projected:.1} <= Q_authorized {q_authorized:.1}"
            ),
        }
    }
}
