//! Liquid Mercury Multi-Pore Capillary & Coalescence Containment Engine
//!
//! Adapted from `D:\harfile\OshoosiClaw\crates\osoosi-agent-anomaly\src\mercury_guard.rs`:
//! Models an adversarial agent's multi-channel escape pressure as a high-surface-tension
//! non-wetting fluid ($\gamma = 0.4865\text{ N/m}$, contact angle $\theta = 140^\circ$) attempting
//! to penetrate 8 host actuation pore classes:
//! 1. **Washburn Capillary Entry Barrier**: $P_{\text{cap}}(r_i) = \frac{2 \gamma |\cos \theta|}{r_i}$.
//! 2. **Rayleigh-Plateau / Weber Shattering**: Detects high-velocity micro-droplet bursts ($We = \frac{\rho v^2 L}{\gamma} > We_{\text{crit}}$).
//! 3. **Smoluchowski Cross-Pore Coalescence**: Detects split payload fragments re-coalescing across pores.
//! 4. **Sulfur Passivation (`Hg + S -> HgS`)**: Binds escaped mercury into immobile cinnabar (`HgS`) upon tripwire contact.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// Mercury surface tension $\gamma = 0.4865\text{ N/m}$ at $20^\circ\text{C}$.
pub const MERCURY_SURFACE_TENSION_N_PER_M: f64 = 0.4865;
/// Mercury non-wetting contact angle $\theta = 140^\circ$ ($|\cos 140^\circ| \approx 0.766044$).
pub const MERCURY_ABS_COS_THETA: f64 = 0.766044443118978;
/// Mercury density $\rho = 13,534\text{ kg/m}^3$.
pub const MERCURY_DENSITY_KG_M3: f64 = 13534.0;
/// Critical Weber number $We_{\text{crit}} = 12.0$ for Rayleigh-Plateau droplet shattering.
pub const CRITICAL_WEBER_NUMBER: f64 = 12.0;

/// Eight host actuation pore classes governed by Washburn capillary entry barriers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HostActuationPore {
    SubprocessSpawn,
    FilesystemWrite,
    NetworkSocketEgress,
    CredentialStoreRead,
    KernelDriverIoctl,
    InterAgentMeshIpc,
    SharedMemoryMapping,
    ClipboardWindowMessage,
}

impl HostActuationPore {
    /// Effective pore radius $r_i$ in meters (smaller radius = higher capillary entry barrier).
    pub fn default_pore_radius_m(self) -> f64 {
        match self {
            Self::KernelDriverIoctl => 0.0005,      // Highest barrier (~1490 Pa)
            Self::CredentialStoreRead => 0.0006,    // ~1242 Pa
            Self::SubprocessSpawn => 0.0008,        // ~931 Pa
            Self::SharedMemoryMapping => 0.0010,    // ~745 Pa
            Self::NetworkSocketEgress => 0.0012,    // ~621 Pa
            Self::ClipboardWindowMessage => 0.0014, // ~532 Pa
            Self::FilesystemWrite => 0.0015,        // ~497 Pa
            Self::InterAgentMeshIpc => 0.0020,      // ~372 Pa
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercuryEvaluationResult {
    pub pore: HostActuationPore,
    pub applied_pressure_pa: f64,
    pub washburn_barrier_pa: f64,
    pub weber_number: f64,
    pub coalescence_mass: f64,
    pub pore_breached: bool,
    pub droplet_shattering_detected: bool,
    pub cross_pore_coalescence_detected: bool,
    pub sulfur_passivated_hgs: bool,
    pub reason: String,
}

pub struct MercuryContainmentEngine {
    pore_radii: RwLock<HashMap<HostActuationPore, f64>>,
    coalescence_ledger: RwLock<HashMap<String, f64>>,
    passivated_agents: RwLock<HashMap<String, bool>>,
}

impl Default for MercuryContainmentEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MercuryContainmentEngine {
    pub fn new() -> Self {
        let mut radii = HashMap::new();
        for pore in [
            HostActuationPore::SubprocessSpawn,
            HostActuationPore::FilesystemWrite,
            HostActuationPore::NetworkSocketEgress,
            HostActuationPore::CredentialStoreRead,
            HostActuationPore::KernelDriverIoctl,
            HostActuationPore::InterAgentMeshIpc,
            HostActuationPore::SharedMemoryMapping,
            HostActuationPore::ClipboardWindowMessage,
        ] {
            radii.insert(pore, pore.default_pore_radius_m());
        }
        Self {
            pore_radii: RwLock::new(radii),
            coalescence_ledger: RwLock::new(HashMap::new()),
            passivated_agents: RwLock::new(HashMap::new()),
        }
    }

    /// Washburn capillary entry pressure $P_{\text{cap}}(r_i) = \frac{2 \gamma |\cos \theta|}{r_i}$.
    pub fn washburn_barrier_pa(&self, pore: HostActuationPore) -> f64 {
        let r = self
            .pore_radii
            .read()
            .unwrap()
            .get(&pore)
            .copied()
            .unwrap_or_else(|| pore.default_pore_radius_m())
            .max(1e-6);
        (2.0 * MERCURY_SURFACE_TENSION_N_PER_M * MERCURY_ABS_COS_THETA) / r
    }

    /// Evaluates an agent's actuation attempt against Washburn capillary pressure,
    /// Weber droplet shattering, Smoluchowski cross-pore coalescence, and HgS passivation.
    pub fn evaluate_pore_pressure(
        &self,
        agent_id: &str,
        pore: HostActuationPore,
        applied_pressure_pa: f64,
        droplet_velocity_m_s: f64,
        characteristic_length_m: f64,
        fragment_mass: f64,
    ) -> MercuryEvaluationResult {
        let already_passivated = self
            .passivated_agents
            .read()
            .unwrap()
            .get(agent_id)
            .copied()
            .unwrap_or(false);

        let barrier_pa = self.washburn_barrier_pa(pore);
        let weber_number = (MERCURY_DENSITY_KG_M3
            * droplet_velocity_m_s.powi(2)
            * characteristic_length_m.max(1e-5))
            / MERCURY_SURFACE_TENSION_N_PER_M;

        let mut coal_map = self.coalescence_ledger.write().unwrap();
        let accumulated_mass = {
            let entry = coal_map.entry(agent_id.to_string()).or_insert(0.0);
            *entry = (*entry * 0.92) + fragment_mass.max(0.0);
            *entry
        };
        drop(coal_map);

        let pore_breached = applied_pressure_pa > barrier_pa;
        let droplet_shattering_detected = weber_number > CRITICAL_WEBER_NUMBER;
        let cross_pore_coalescence_detected = accumulated_mass >= 1.0;

        let sulfur_passivated_hgs = already_passivated
            || pore_breached
            || droplet_shattering_detected
            || cross_pore_coalescence_detected;

        if sulfur_passivated_hgs {
            self.passivated_agents
                .write()
                .unwrap()
                .insert(agent_id.to_string(), true);
            // Tighten pore radius by 50% upon attack detection
            if let Some(r) = self.pore_radii.write().unwrap().get_mut(&pore) {
                *r = (*r * 0.5).max(1e-5);
            }
        }

        let reason = if !sulfur_passivated_hgs {
            format!(
                "MERCURY_CONTAINED: P_applied ({:.1} Pa) <= P_Washburn ({:.1} Pa), We={:.2} <= 12.0",
                applied_pressure_pa, barrier_pa, weber_number
            )
        } else {
            format!(
                "MERCURY_HGS_PASSIVATION_TRIGGERED: pore_breach={} (P={:.1}/{:.1} Pa), shattering={} (We={:.2}), coalescence={} (mass={:.2})",
                pore_breached,
                applied_pressure_pa,
                barrier_pa,
                droplet_shattering_detected,
                weber_number,
                cross_pore_coalescence_detected,
                accumulated_mass
            )
        };

        MercuryEvaluationResult {
            pore,
            applied_pressure_pa,
            washburn_barrier_pa: barrier_pa,
            weber_number,
            coalescence_mass: accumulated_mass,
            pore_breached,
            droplet_shattering_detected,
            cross_pore_coalescence_detected,
            sulfur_passivated_hgs,
            reason,
        }
    }
}
