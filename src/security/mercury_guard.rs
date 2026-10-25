//! Liquid Mercury Multi-Pore Capillary & Coalescence Containment Engine
//!
//! Adapted from `D:\harfile\OshoosiClaw\crates\osoosi-agent-anomaly\src\mercury_guard.rs`:
//! Models an adversarial agent's multi-channel escape pressure as a high-surface-tension
//! non-wetting fluid ($\gamma = 0.4865\text{ N/m}$, contact angle $\theta = 140^\circ$) attempting
//! to penetrate 8 host actuation pore classes:
//! 1. **Washburn Capillary Entry Barrier**: $P_{\text{cap}}(r_i) = \frac{2 \gamma |\cos \theta|}{r_i}$.
//! 2. **Rayleigh-Plateau / Weber Shattering**: Detects high-velocity micro-droplet bursts ($We = \frac{\rho v^2 L}{\gamma} > We_{\text{crit}}$).
//! 3. **Smoluchowski Cross-Pore Coalescence (Non-Decaying + Sliding Window)**: Detects both rapid
//!    multi-pore fragment re-coalescence and slow drip-leak exfiltration (`f < 0.08` per call) via a
//!    non-decaying lifetime cumulative mass budget AND a 1-hour sliding window.
//! 4. **Sulfur Passivation (`Hg + S -> HgS`)**: Binds escaped mercury into immobile cinnabar (`HgS`) upon tripwire contact.
//! 5. **Kernel-Measured Actuation Telemetry (`MeasuredActuationSample`)**: Computes pressure, velocity,
//!    and fragment mass directly from Windows Job Object kernel I/O accounting counters
//!    (`QueryInformationJobObject(JobObjectBasicAndIoAccountingInformation)`) rather than trusting
//!    agent-supplied telemetry estimates.

use crate::core::types::OctopusSecurityError;
use crate::security::windows_sandbox::WindowsJobObject;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Mercury surface tension $\gamma = 0.4865\text{ N/m}$ at $20^\circ\text{C}$.
pub const MERCURY_SURFACE_TENSION_N_PER_M: f64 = 0.4865;
/// Mercury non-wetting contact angle $\theta = 140^\circ$ ($|\cos 140^\circ| \approx 0.766044$).
pub const MERCURY_ABS_COS_THETA: f64 = 0.766044443118978;
/// Mercury density $\rho = 13,534\text{ kg/m}^3$.
pub const MERCURY_DENSITY_KG_M3: f64 = 13534.0;
/// Critical Weber number $We_{\text{crit}} = 12.0$ for Rayleigh-Plateau droplet shattering.
pub const CRITICAL_WEBER_NUMBER: f64 = 12.0;
/// Maximum cumulative lifetime exfiltration mass before irreversible HgS passivation.
pub const LIFETIME_COALESCENCE_BUDGET: f64 = 1.0;
/// Sliding window duration (1 hour) for secondary rate-window accounting.
pub const SLIDING_WINDOW_DURATION: Duration = Duration::from_secs(3600);
/// Default byte budget (1 MiB) that maps to `1.0` normalized coalescence mass when derived from kernel I/O counters.
pub const KERNEL_IO_COALESCENCE_BUDGET_BYTES: f64 = 1_048_576.0;

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

/// Supervisor-measured actuation sample derived from OS kernel Job Object accounting counters,
/// immune to agent self-reporting or spoofing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasuredActuationSample {
    pub pore: HostActuationPore,
    pub total_processes_spawned: u32,
    pub active_processes: u32,
    pub read_transfer_bytes: u64,
    pub write_transfer_bytes: u64,
    pub other_transfer_bytes: u64,
    pub elapsed_s: f64,
    pub derived_pressure_pa: f64,
    pub derived_velocity_m_s: f64,
    pub derived_characteristic_length_m: f64,
    pub derived_fragment_mass: f64,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct JobObjectBasicAccountingInformation {
    total_user_time: i64,
    total_kernel_time: i64,
    this_period_total_user_time: i64,
    this_period_total_kernel_time: i64,
    total_page_fault_count: u32,
    total_processes: u32,
    active_processes: u32,
    total_terminated_processes: u32,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoCounters {
    read_operation_count: u64,
    write_operation_count: u64,
    other_operation_count: u64,
    read_transfer_count: u64,
    write_transfer_count: u64,
    other_transfer_count: u64,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct JobObjectBasicAndIoAccountingInformation {
    basic_info: JobObjectBasicAccountingInformation,
    io_info: IoCounters,
}

#[cfg(windows)]
mod win32_job_io {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        pub fn QueryInformationJobObject(
            hJob: *mut c_void,
            JobObjectInformationClass: u32,
            lpJobObjectInformation: *mut c_void,
            cbJobObjectInformationLength: u32,
            lpReturnLength: *mut u32,
        ) -> i32;
        pub fn GetLastError() -> u32;
    }
}

impl MeasuredActuationSample {
    /// Reads kernel-enforced process and I/O counters directly from a `WindowsJobObject`
    /// via `QueryInformationJobObject(JobObjectBasicAndIoAccountingInformation = 8)`.
    pub fn sample_from_job(
        job: &WindowsJobObject,
        pore: HostActuationPore,
        elapsed_s: f64,
    ) -> Result<Self, OctopusSecurityError> {
        let dt = elapsed_s.max(0.001);
        #[cfg(windows)]
        {
            const JOB_OBJECT_BASIC_AND_IO_ACCOUNTING_INFO_CLASS: u32 = 8;
            let mut accounting = JobObjectBasicAndIoAccountingInformation::default();
            let mut ret_len: u32 = 0;
            let ok = unsafe {
                win32_job_io::QueryInformationJobObject(
                    job.handle,
                    JOB_OBJECT_BASIC_AND_IO_ACCOUNTING_INFO_CLASS,
                    &mut accounting as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of::<JobObjectBasicAndIoAccountingInformation>() as u32,
                    &mut ret_len,
                )
            };
            if ok == 0 {
                let err = unsafe { win32_job_io::GetLastError() };
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: QueryInformationJobObject(BasicAndIoAccounting) failed with OS error {}",
                    err
                )));
            }

            let write_bytes = accounting.io_info.write_transfer_count;
            let other_bytes = accounting.io_info.other_transfer_count;
            let read_bytes = accounting.io_info.read_transfer_count;
            let total_procs = accounting.basic_info.total_processes;
            let active_procs = accounting.basic_info.active_processes;

            let egress_bytes = write_bytes.saturating_add(other_bytes) as f64;
            let bytes_per_sec = egress_bytes / dt;

            let derived_pressure_pa =
                (bytes_per_sec / 64.0) + (total_procs as f64 * 180.0) + (active_procs as f64 * 120.0);
            let derived_velocity_m_s = (bytes_per_sec / 65_536.0) + (total_procs as f64 * 0.15);
            let derived_characteristic_length_m = pore.default_pore_radius_m();
            let derived_fragment_mass =
                (egress_bytes / KERNEL_IO_COALESCENCE_BUDGET_BYTES).max(total_procs as f64 * 0.02);

            Ok(Self {
                pore,
                total_processes_spawned: total_procs,
                active_processes: active_procs,
                read_transfer_bytes: read_bytes,
                write_transfer_bytes: write_bytes,
                other_transfer_bytes: other_bytes,
                elapsed_s: dt,
                derived_pressure_pa,
                derived_velocity_m_s,
                derived_characteristic_length_m,
                derived_fragment_mass,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = job;
            Ok(Self {
                pore,
                total_processes_spawned: 1,
                active_processes: 0,
                read_transfer_bytes: 0,
                write_transfer_bytes: 0,
                other_transfer_bytes: 0,
                elapsed_s: dt,
                derived_pressure_pa: 180.0,
                derived_velocity_m_s: 0.15,
                derived_characteristic_length_m: pore.default_pore_radius_m(),
                derived_fragment_mass: 0.02,
            })
        }
    }
}

#[derive(Debug, Clone)]
struct CoalescenceAccumulator {
    /// Non-decaying monotonic lifetime mass (prevents infinite slow drip leaks `f < 0.08`).
    lifetime_mass: f64,
    /// Timestamped fragments within the active 1-hour sliding window.
    sliding_window: VecDeque<(Instant, f64)>,
}

impl Default for CoalescenceAccumulator {
    fn default() -> Self {
        Self {
            lifetime_mass: 0.0,
            sliding_window: VecDeque::new(),
        }
    }
}

impl CoalescenceAccumulator {
    fn record_fragment(&mut self, fragment_mass: f64, now: Instant) -> (f64, f64) {
        let positive = if fragment_mass.is_nan() || fragment_mass < 0.0 {
            0.0
        } else {
            fragment_mass
        };
        self.lifetime_mass += positive;
        self.sliding_window.push_back((now, positive));
        while let Some(&(ts, _)) = self.sliding_window.front() {
            if now.duration_since(ts) > SLIDING_WINDOW_DURATION {
                self.sliding_window.pop_front();
            } else {
                break;
            }
        }
        let window_mass: f64 = self.sliding_window.iter().map(|(_, m)| *m).sum();
        (self.lifetime_mass, window_mass)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercuryEvaluationResult {
    pub pore: HostActuationPore,
    pub applied_pressure_pa: f64,
    pub washburn_barrier_pa: f64,
    pub weber_number: f64,
    /// Effective coalescence mass (`max(lifetime_mass, sliding_window_mass)`).
    pub coalescence_mass: f64,
    pub pore_breached: bool,
    pub droplet_shattering_detected: bool,
    pub cross_pore_coalescence_detected: bool,
    pub sulfur_passivated_hgs: bool,
    pub reason: String,
}

pub struct MercuryContainmentEngine {
    pore_radii: RwLock<HashMap<HostActuationPore, f64>>,
    coalescence_ledger: RwLock<HashMap<String, CoalescenceAccumulator>>,
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

    /// Evaluates a kernel-measured `MeasuredActuationSample` obtained from a `WindowsJobObject`.
    pub fn evaluate_measured_sample(
        &self,
        agent_id: &str,
        sample: &MeasuredActuationSample,
    ) -> MercuryEvaluationResult {
        self.evaluate_pore_pressure(
            agent_id,
            sample.pore,
            sample.derived_pressure_pa,
            sample.derived_velocity_m_s,
            sample.derived_characteristic_length_m,
            sample.derived_fragment_mass,
        )
    }

    /// Evaluates an agent's actuation attempt against Washburn capillary pressure,
    /// Weber droplet shattering, non-decaying Smoluchowski cross-pore coalescence, and HgS passivation.
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

        let now = Instant::now();
        let (lifetime_mass, window_mass) = {
            let mut coal_map = self.coalescence_ledger.write().unwrap();
            let entry = coal_map.entry(agent_id.to_string()).or_default();
            entry.record_fragment(fragment_mass, now)
        };
        let accumulated_mass = lifetime_mass.max(window_mass);

        let pore_breached = applied_pressure_pa > barrier_pa;
        let droplet_shattering_detected = weber_number > CRITICAL_WEBER_NUMBER;
        let cross_pore_coalescence_detected =
            lifetime_mass >= LIFETIME_COALESCENCE_BUDGET || window_mass >= LIFETIME_COALESCENCE_BUDGET;

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
                "MERCURY_CONTAINED: P_applied ({:.1} Pa) <= P_Washburn ({:.1} Pa), We={:.2} <= 12.0, lifetime_mass={:.3} < 1.0",
                applied_pressure_pa, barrier_pa, weber_number, accumulated_mass
            )
        } else {
            format!(
                "MERCURY_HGS_PASSIVATION_TRIGGERED: pore_breach={} (P={:.1}/{:.1} Pa), shattering={} (We={:.2}), coalescence={} (lifetime_mass={:.3}, window_mass={:.3})",
                pore_breached,
                applied_pressure_pa,
                barrier_pa,
                droplet_shattering_detected,
                weber_number,
                cross_pore_coalescence_detected,
                lifetime_mass,
                window_mass
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
