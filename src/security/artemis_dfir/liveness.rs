//! Native Cross-OS Workstation Liveness & Spacetime Event-Horizon Sensor.
//!
//! Directly mitigates ABIBO Unconsented Control Plane Activation (e.g., background
//! vendor polling while a workstation is locked or asleep) by maintaining a monotonic
//! `human_session_epoch` that increments immediately upon lock/sleep/idle transitions.

use super::types::{LivenessEventRecord, SleepLockWindow, WorkstationLivenessSnapshot};
use chrono::Utc;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LIVENESS_HISTORY: usize = 512;

/// Native OS idle and screen-lock telemetry reading.
#[derive(Debug, Clone)]
pub struct OsLivenessReading {
    pub idle_secs: u64,
    pub os_locked: bool,
    pub probe_method: String,
}

#[must_use]
pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Probes native OS workstation idle duration and screen-lock state without spawning shells.
#[must_use]
pub fn probe_os_workstation_liveness() -> OsLivenessReading {
    #[cfg(windows)]
    {
        probe_windows_liveness()
    }
    #[cfg(target_os = "linux")]
    {
        probe_linux_liveness()
    }
    #[cfg(target_os = "macos")]
    {
        probe_macos_liveness()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        OsLivenessReading {
            idle_secs: 0,
            os_locked: false,
            probe_method: "posix_fallback".to_string(),
        }
    }
}

#[cfg(windows)]
fn probe_windows_liveness() -> OsLivenessReading {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    #[repr(C)]
    struct LastInputInfo {
        cb_size: u32,
        dw_time: u32,
    }

    type FnGetLastInputInfo = unsafe extern "system" fn(*mut LastInputInfo) -> i32;
    type FnGetTickCount = unsafe extern "system" fn() -> u32;
    type FnWtsQuerySessionInfoW = unsafe extern "system" fn(
        *mut std::ffi::c_void,
        u32,
        u32,
        *mut *mut std::ffi::c_void,
        *mut u32,
    ) -> i32;
    type FnWtsFreeMemory = unsafe extern "system" fn(*mut std::ffi::c_void);

    let mut idle_secs = 0u64;
    let mut os_locked = false;
    let mut method = String::from("win32_getlastinputinfo");

    unsafe {
        let user32_w: Vec<u16> = "user32.dll\0".encode_utf16().collect();
        let k32_w: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let h_u32 = LoadLibraryW(user32_w.as_ptr());
        let h_k32 = LoadLibraryW(k32_w.as_ptr());
        if !h_u32.is_null() && !h_k32.is_null() {
            if let (Some(p_lii), Some(p_tick)) = (
                GetProcAddress(h_u32, b"GetLastInputInfo\0".as_ptr()),
                GetProcAddress(h_k32, b"GetTickCount\0".as_ptr()),
            ) {
                let fn_lii: FnGetLastInputInfo = std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    FnGetLastInputInfo,
                >(p_lii);
                let fn_tick: FnGetTickCount = std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    FnGetTickCount,
                >(p_tick);
                let mut lii = LastInputInfo {
                    cb_size: std::mem::size_of::<LastInputInfo>() as u32,
                    dw_time: 0,
                };
                if fn_lii(&mut lii) != 0 {
                    let now_tick = fn_tick();
                    let delta_ms = now_tick.wrapping_sub(lii.dw_time);
                    idle_secs = (delta_ms / 1000) as u64;
                }
            }
        }

        // Probe WTS session connect state (`WTSConnectState` = 8): 4 = WTSDisconnected
        let wts_w: Vec<u16> = "wtsapi32.dll\0".encode_utf16().collect();
        let h_wts = LoadLibraryW(wts_w.as_ptr());
        if !h_wts.is_null() {
            if let (Some(p_q), Some(p_f)) = (
                GetProcAddress(h_wts, b"WTSQuerySessionInformationW\0".as_ptr()),
                GetProcAddress(h_wts, b"WTSFreeMemory\0".as_ptr()),
            ) {
                let fn_q: FnWtsQuerySessionInfoW = std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    FnWtsQuerySessionInfoW,
                >(p_q);
                let fn_f: FnWtsFreeMemory = std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    FnWtsFreeMemory,
                >(p_f);
                let mut buf: *mut std::ffi::c_void = std::ptr::null_mut();
                let mut bytes: u32 = 0;
                // WTS_CURRENT_SERVER_HANDLE = 0, WTS_CURRENT_SESSION = 0xFFFF_FFFF, WTSConnectState = 8
                if fn_q(std::ptr::null_mut(), 0xFFFF_FFFF, 8, &mut buf, &mut bytes) != 0
                    && !buf.is_null()
                    && bytes >= 4
                {
                    let state = *(buf as *const i32);
                    // 4 = WTSDisconnected, 6 = WTSIdle, 8 = WTSDown
                    if state == 4 || state == 8 {
                        os_locked = true;
                    }
                    fn_f(buf);
                    method.push_str("+wts_session_state");
                }
            }
        }
    }

    OsLivenessReading {
        idle_secs,
        os_locked,
        probe_method: method,
    }
}

#[cfg(target_os = "linux")]
fn probe_linux_liveness() -> OsLivenessReading {
    let mut os_locked = false;
    let mut saw_session = false;
    if let Ok(entries) = std::fs::read_dir("/run/systemd/sessions") {
        for entry in entries.flatten().take(32) {
            let p = entry.path();
            if p.is_file() {
                if let Ok(txt) = std::fs::read_to_string(&p) {
                    if txt.contains("CLASS=user") {
                        saw_session = true;
                        let is_locked = txt.lines().any(|l| l.trim() == "LOCKED_HINT=yes");
                        let is_closing = txt.lines().any(|l| l.trim() == "STATE=closing");
                        if is_locked || is_closing {
                            os_locked = true;
                        }
                    }
                }
            }
        }
    }
    OsLivenessReading {
        idle_secs: 0,
        os_locked,
        probe_method: if saw_session {
            "linux_systemd_logind_sessions".to_string()
        } else {
            "linux_headless_heartbeat".to_string()
        },
    }
}

#[cfg(target_os = "macos")]
fn probe_macos_liveness() -> OsLivenessReading {
    OsLivenessReading {
        idle_secs: 0,
        os_locked: false,
        probe_method: "macos_session_heartbeat".to_string(),
    }
}

/// Thread-safe monotonic workstation presence tracker and Event-Horizon coordinator.
pub struct WorkstationLivenessTracker {
    epoch: AtomicU64,
    workstation_locked: AtomicBool,
    last_heartbeat_unix: AtomicU64,
    max_idle_secs: AtomicU64,
    event_horizon_count: AtomicU64,
    last_horizon_reason: RwLock<Option<String>>,
    history: RwLock<VecDeque<LivenessEventRecord>>,
    sleep_windows: RwLock<VecDeque<SleepLockWindow>>,
    active_sleep_start: AtomicU64,
}

impl Default for WorkstationLivenessTracker {
    fn default() -> Self {
        Self::new(300)
    }
}

impl WorkstationLivenessTracker {
    #[must_use]
    pub fn new(max_idle_secs: u64) -> Self {
        let now = unix_now_secs();
        let mut hist = VecDeque::with_capacity(64);
        hist.push_back(LivenessEventRecord {
            epoch: 1,
            state: "active".to_string(),
            idle_secs: 0,
            event_horizon_reason: "initial_human_session_anchor".to_string(),
            timestamp_utc: Utc::now().to_rfc3339(),
            timestamp_unix: now,
        });
        Self {
            epoch: AtomicU64::new(1),
            workstation_locked: AtomicBool::new(false),
            last_heartbeat_unix: AtomicU64::new(now),
            max_idle_secs: AtomicU64::new(max_idle_secs.max(10)),
            event_horizon_count: AtomicU64::new(0),
            last_horizon_reason: RwLock::new(None),
            history: RwLock::new(hist),
            sleep_windows: RwLock::new(VecDeque::with_capacity(64)),
            active_sleep_start: AtomicU64::new(0),
        }
    }

    #[inline]
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    #[inline]
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.workstation_locked.load(Ordering::SeqCst)
    }

    #[inline]
    #[must_use]
    pub fn last_heartbeat_unix(&self) -> u64 {
        self.last_heartbeat_unix.load(Ordering::SeqCst)
    }

    #[inline]
    #[must_use]
    pub fn max_idle_secs(&self) -> u64 {
        self.max_idle_secs.load(Ordering::SeqCst)
    }

    /// Records a verified interactive human presence heartbeat (keeping the causal light cone open).
    pub fn record_human_heartbeat(&self) -> WorkstationLivenessSnapshot {
        self.record_human_heartbeat_at(unix_now_secs())
    }

    /// Deterministic timestamp variant used by both live heartbeats and exact simulation tests.
    pub fn record_human_heartbeat_at(&self, ts_unix: u64) -> WorkstationLivenessSnapshot {
        self.last_heartbeat_unix.store(ts_unix, Ordering::SeqCst);
        let prev_locked = self.workstation_locked.swap(false, Ordering::SeqCst);
        if prev_locked {
            let start = self.active_sleep_start.swap(0, Ordering::SeqCst);
            if start > 0 && ts_unix >= start {
                let mut w = self
                    .sleep_windows
                    .write()
                    .unwrap_or_else(|e| e.into_inner());
                if w.len() >= 128 {
                    w.pop_front();
                }
                w.push_back(SleepLockWindow {
                    start_unix: start,
                    end_unix: ts_unix,
                });
            }
            self.push_record(
                self.current_epoch(),
                "unlocked",
                0,
                "human_interactive_heartbeat_verified",
                ts_unix,
            );
        }
        self.snapshot_at(ts_unix, false)
    }

    /// Triggers an irreversible Spacetime Event Horizon (screen lock, laptop lid close, sleep/suspend),
    /// monotonically advancing `human_session_epoch` (`N -> N + 1`) to invalidate all prior capability tokens.
    pub fn trigger_event_horizon(&self, reason: &str) -> WorkstationLivenessSnapshot {
        self.trigger_event_horizon_at(reason, unix_now_secs())
    }

    /// Deterministic timestamp variant for triggering an Event Horizon.
    pub fn trigger_event_horizon_at(
        &self,
        reason: &str,
        ts_unix: u64,
    ) -> WorkstationLivenessSnapshot {
        let new_epoch = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;
        self.event_horizon_count.fetch_add(1, Ordering::SeqCst);
        self.workstation_locked.store(true, Ordering::SeqCst);
        let _ = self.active_sleep_start.compare_exchange(
            0,
            ts_unix,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        if let Ok(mut guard) = self.last_horizon_reason.write() {
            *guard = Some(reason.to_string());
        }
        self.push_record(new_epoch, "event_horizon_locked", 0, reason, ts_unix);
        self.snapshot_at(ts_unix, false)
    }

    /// Unlocks workstation under a newly incremented clean human session epoch.
    pub fn unlock_workstation(&self) -> WorkstationLivenessSnapshot {
        let now = unix_now_secs();
        let new_epoch = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;
        let start = self.active_sleep_start.swap(0, Ordering::SeqCst);
        if start > 0 && now >= start {
            let mut w = self
                .sleep_windows
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if w.len() >= 128 {
                w.pop_front();
            }
            w.push_back(SleepLockWindow {
                start_unix: start,
                end_unix: now,
            });
        }
        self.workstation_locked.store(false, Ordering::SeqCst);
        self.last_heartbeat_unix.store(now, Ordering::SeqCst);
        self.push_record(
            new_epoch,
            "active",
            0,
            "workstation_unlocked_new_epoch",
            now,
        );
        self.snapshot_at(now, false)
    }

    /// Returns recorded workstation sleep/lock windows (including any currently active lock window).
    #[must_use]
    pub fn sleep_windows(&self) -> Vec<SleepLockWindow> {
        let mut out: Vec<SleepLockWindow> = self
            .sleep_windows
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .copied()
            .collect();
        let active_start = self.active_sleep_start.load(Ordering::SeqCst);
        if active_start > 0 {
            out.push(SleepLockWindow {
                start_unix: active_start,
                end_unix: unix_now_secs().max(active_start),
            });
        }
        out
    }

    /// Returns recent liveness transition history for `artemis_liveness_events` SQL table.
    #[must_use]
    pub fn history_records(&self) -> Vec<LivenessEventRecord> {
        self.history
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// Captures a live snapshot, optionally invoking the native OS probe.
    #[must_use]
    pub fn snapshot(&self) -> WorkstationLivenessSnapshot {
        self.snapshot_at(unix_now_secs(), !cfg!(test))
    }

    /// Captures a deterministic snapshot at `now_unix`.
    #[must_use]
    pub fn snapshot_at(&self, now_unix: u64, run_os_probe: bool) -> WorkstationLivenessSnapshot {
        let os_reading = if run_os_probe {
            probe_os_workstation_liveness()
        } else {
            OsLivenessReading {
                idle_secs: 0,
                os_locked: false,
                probe_method: "monotonic_heartbeat_tracker".to_string(),
            }
        };

        let last_hb = self.last_heartbeat_unix.load(Ordering::SeqCst);
        let hb_elapsed = now_unix.saturating_sub(last_hb);
        let idle_secs = hb_elapsed.min(if run_os_probe && os_reading.idle_secs > 0 {
            os_reading.idle_secs
        } else {
            hb_elapsed
        });

        let mut locked = self.workstation_locked.load(Ordering::SeqCst);
        if os_reading.os_locked && !locked {
            let new_epoch = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;
            self.event_horizon_count.fetch_add(1, Ordering::SeqCst);
            self.workstation_locked.store(true, Ordering::SeqCst);
            let _ = self.active_sleep_start.compare_exchange(
                0,
                now_unix,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            if let Ok(mut guard) = self.last_horizon_reason.write() {
                *guard = Some(format!("os_lock_detected:{}", os_reading.probe_method));
            }
            self.push_record(
                new_epoch,
                "event_horizon_locked",
                idle_secs,
                "os_lock_detected",
                now_unix,
            );
            locked = true;
        }

        let max_idle = self.max_idle_secs.load(Ordering::SeqCst);
        let human_live = !locked && idle_secs <= max_idle;
        let last_reason = self.last_horizon_reason.read().ok().and_then(|g| g.clone());

        WorkstationLivenessSnapshot {
            epoch: self.current_epoch(),
            human_live,
            workstation_locked: locked,
            idle_secs,
            max_idle_secs: max_idle,
            last_heartbeat_unix: last_hb,
            event_horizon_count: self.event_horizon_count.load(Ordering::SeqCst),
            last_horizon_reason: last_reason,
            os_probe_method: os_reading.probe_method,
        }
    }

    fn push_record(&self, epoch: u64, state: &str, idle_secs: u64, reason: &str, ts_unix: u64) {
        let mut h = self.history.write().unwrap_or_else(|e| e.into_inner());
        if h.len() >= MAX_LIVENESS_HISTORY {
            h.pop_front();
        }
        h.push_back(LivenessEventRecord {
            epoch,
            state: state.to_string(),
            idle_secs,
            event_horizon_reason: reason.to_string(),
            timestamp_utc: Utc::now().to_rfc3339(),
            timestamp_unix: ts_unix,
        });
    }
}
