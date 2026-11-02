// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Reference: Google Cybernetic Agent Governance Engine (CAGE), arXiv:2606.12320

//! Tier 3a Discrete-Time Control Barrier Function (CBF) & Tier 4 Debit Ledger
//!
//! Enforces formal mathematical safety bounds on fiscal resources and system budgets.
//! Governed by the discrete-time exponential barrier condition:
//!
//! $$h(S_{t+1}) = (B_t - c) - B_{\min} \ge (1 - \gamma) h(S_t) \ge 0$$
//!
//! where:
//! - $B_t$ is the active budget balance
//! - $c \ge 0$ is the proposed action expenditure
//! - $B_{\min}$ is the reserve floor threshold
//! - $\gamma \in (0, 1]$ is the fractional safety margin decay rate per step
//! - $\epsilon = 10^{-9}$ is the floating-point tolerance buffer
//!
//! Implements atomic sequence replay high-water marks, monotonic fence epoch validation,
//! and two-phase pre-reservation (`preview`, `pre_reserve`, `rollback`, `rollback_lifo`, `confirm`).

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Epsilon tolerance for floating-point barrier comparisons.
pub const CBF_EPSILON: f64 = 1e-9;

/// Specific violation condition when a Control Barrier Function inequality fails.
#[derive(Debug, Clone, PartialEq, thiserror::Error, Serialize, Deserialize)]
pub enum CbfViolation {
    #[error("Budget below safety floor: projected {projected_budget:.4} < floor {b_min:.4}")]
    FloorBreach { projected_budget: f64, b_min: f64 },

    #[error("Barrier decay rate exceeded: projected h {h_next:.4} < required {h_min_allowed:.4} (gamma={gamma:.4})")]
    DecayRateExceeded {
        h_next: f64,
        h_min_allowed: f64,
        gamma: f64,
    },

    #[error("Current state already in violation: budget {current_budget:.4} < floor {b_min:.4}")]
    CurrentStateUnsafe { current_budget: f64, b_min: f64 },

    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    #[error("Debit reservation not found or already released: {0}")]
    ReservationNotFound(String),

    #[error("Debit already committed and settled (cannot be rolled back): {0}")]
    AlreadyCommitted(String),

    #[error("Sequence replay regression detected: incoming seq {incoming} <= last accepted {last_accepted}")]
    SequenceReplay { incoming: u64, last_accepted: u64 },

    #[error("Stale fence epoch detected: incoming epoch {incoming} < fence epoch {fence_epoch}")]
    StaleFenceEpoch { incoming: u64, fence_epoch: u64 },
}

/// Cryptographic and accounting receipt issued when fuel cost is safely pre-reserved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitReceipt {
    pub debit_id: String,
    pub reserved_fuel: f64,
    pub remaining_budget: f64,
    pub barrier_val: f64,
    pub timestamp: u64,
}

/// Discrete-Time Control Barrier Function Safety Engine (Tier 3a).
#[derive(Debug)]
pub struct CbfSafetyEngine {
    gamma: f64,
    b_min: f64,
    sequence_hwm: AtomicU64,
    fence_epoch_hwm: AtomicU64,
}

impl CbfSafetyEngine {
    /// Creates a new CBF safety engine with specified decay rate $\gamma$ and floor $B_{\min}$.
    pub fn new(gamma: f64, b_min: f64) -> Result<Self, CbfViolation> {
        if !gamma.is_finite() || gamma <= 0.0 || gamma > 1.0 {
            return Err(CbfViolation::InvalidParameters(format!(
                "Decay rate gamma must be a finite number in (0, 1], got {}",
                gamma
            )));
        }
        if !b_min.is_finite() || b_min < 0.0 {
            return Err(CbfViolation::InvalidParameters(format!(
                "Minimum reserve floor b_min must be a finite non-negative number, got {}",
                b_min
            )));
        }
        Ok(Self {
            gamma,
            b_min,
            sequence_hwm: AtomicU64::new(0),
            fence_epoch_hwm: AtomicU64::new(1),
        })
    }

    /// Evaluates the discrete-time exponential barrier condition:
    ///
    /// $$h(S_{t+1}) = (B_t - c) - B_{\min} \ge (1 - \gamma) h(S_t) \ge 0$$
    pub fn evaluate_step(
        &self,
        current_budget: f64,
        cost: f64,
        current_h: f64,
    ) -> Result<f64, CbfViolation> {
        if cost.is_nan() || cost < 0.0 {
            return Err(CbfViolation::InvalidParameters(format!(
                "Cost cannot be negative or NaN: {}",
                cost
            )));
        }

        if current_budget.is_nan() || !current_budget.is_finite() {
            return Err(CbfViolation::InvalidParameters(format!(
                "Current budget must be a finite number: {}",
                current_budget
            )));
        }

        if current_h.is_nan() || !current_h.is_finite() {
            return Err(CbfViolation::InvalidParameters(format!(
                "Current safety margin current_h must be a finite number: {}",
                current_h
            )));
        }

        // Current safety margin check
        if current_h < -CBF_EPSILON {
            return Err(CbfViolation::CurrentStateUnsafe {
                current_budget,
                b_min: self.b_min,
            });
        }

        let projected_budget = current_budget - cost;
        let h_next = projected_budget - self.b_min;

        // Guard against any arithmetic producing NaN
        if h_next.is_nan() {
            return Err(CbfViolation::InvalidParameters(
                "Projected safety barrier h_next evaluated to NaN".to_string(),
            ));
        }

        // Condition 1: Non-negativity floor h_{t+1} >= 0
        if h_next < -CBF_EPSILON {
            return Err(CbfViolation::FloorBreach {
                projected_budget,
                b_min: self.b_min,
            });
        }

        // Condition 2: Monotonic decay bound h_{t+1} >= (1 - gamma) * h_t
        let h_min_allowed = (1.0 - self.gamma) * current_h;
        if h_next + CBF_EPSILON < h_min_allowed {
            return Err(CbfViolation::DecayRateExceeded {
                h_next,
                h_min_allowed,
                gamma: self.gamma,
            });
        }

        Ok(h_next)
    }

    /// Validates monotonically advancing sequence number and fence epoch.
    pub fn verify_sequence_and_epoch(&self, sequence: u64, epoch: u64) -> Result<(), CbfViolation> {
        let active_epoch = self.fence_epoch_hwm.load(Ordering::SeqCst);
        if epoch < active_epoch {
            return Err(CbfViolation::StaleFenceEpoch {
                incoming: epoch,
                fence_epoch: active_epoch,
            });
        }

        let mut current_seq = self.sequence_hwm.load(Ordering::SeqCst);
        loop {
            if sequence <= current_seq {
                return Err(CbfViolation::SequenceReplay {
                    incoming: sequence,
                    last_accepted: current_seq,
                });
            }
            match self.sequence_hwm.compare_exchange_weak(
                current_seq,
                sequence,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => current_seq = actual,
            }
        }

        Ok(())
    }

    /// Monotonically advances the fence epoch (e.g. upon arm restart or severance).
    pub fn advance_epoch(&self) -> u64 {
        self.fence_epoch_hwm.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Returns current fence epoch.
    pub fn current_epoch(&self) -> u64 {
        self.fence_epoch_hwm.load(Ordering::SeqCst)
    }

    /// Returns safety floor $B_{\min}$.
    pub fn floor(&self) -> f64 {
        self.b_min
    }

    /// Returns decay rate $\gamma$.
    pub fn gamma(&self) -> f64 {
        self.gamma
    }
}

/// Internal reservation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReservationEntry {
    debit_id: String,
    amount: f64,
    timestamp: u64,
    committed: bool,
    rolled_back: bool,
}

/// In-memory state of the debit ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerState {
    available_budget: f64,
    initial_budget: f64,
    reservations: Vec<ReservationEntry>,
}

/// Tier 4 Two-Phase Debit Ledger governing resource pre-reservation and LIFO rollback.
#[derive(Debug)]
pub struct DebitLedger {
    cbf: CbfSafetyEngine,
    state: RwLock<LedgerState>,
}

impl DebitLedger {
    /// Creates a new debit ledger initialized with a starting budget and CBF parameters.
    pub fn new(initial_budget: f64, gamma: f64, b_min: f64) -> Result<Self, CbfViolation> {
        let cbf = CbfSafetyEngine::new(gamma, b_min)?;
        if initial_budget.is_nan() || !initial_budget.is_finite() {
            return Err(CbfViolation::InvalidParameters(format!(
                "Initial budget must be a finite number, got {}",
                initial_budget
            )));
        }
        if initial_budget < b_min {
            return Err(CbfViolation::CurrentStateUnsafe {
                current_budget: initial_budget,
                b_min,
            });
        }

        Ok(Self {
            cbf,
            state: RwLock::new(LedgerState {
                available_budget: initial_budget,
                initial_budget,
                reservations: Vec::new(),
            }),
        })
    }

    /// Returns the current available budget balance.
    pub fn available_budget(&self) -> f64 {
        self.state.read().unwrap().available_budget
    }

    /// Returns the current barrier safety margin $h_t = B_t - B_{\min}$.
    pub fn barrier_margin(&self) -> f64 {
        let b = self.available_budget();
        b - self.cbf.b_min
    }

    /// Returns the minimum reserve floor $B_{\min}$.
    pub fn floor_threshold(&self) -> f64 {
        self.cbf.b_min
    }

    /// Returns the decay rate $\gamma$.
    pub fn gamma(&self) -> f64 {
        self.cbf.gamma
    }

    /// Previews whether a fuel expenditure would pass the CBF barrier without mutating state.
    pub fn preview(&self, cost: f64) -> Result<(f64, f64), CbfViolation> {
        if cost.is_nan() {
            return Err(CbfViolation::InvalidParameters(format!(
                "Cost cannot be NaN: {}",
                cost
            )));
        }
        let state = self.state.read().unwrap();
        let current_budget = state.available_budget;
        let current_h = current_budget - self.cbf.b_min;
        let h_next = self.cbf.evaluate_step(current_budget, cost, current_h)?;
        let projected_budget = current_budget - cost;
        Ok((projected_budget, h_next))
    }

    /// Pre-reserves fuel expenditure atomically. Deducts cost only if CBF barrier passes.
    /// Emits a `CommitReceipt`. On barrier failure, budget is untouched ($B_{t+1} = B_t$).
    pub fn pre_reserve(&self, cost: f64, debit_id: &str) -> Result<CommitReceipt, CbfViolation> {
        if cost.is_nan() {
            return Err(CbfViolation::InvalidParameters(format!(
                "Cost cannot be NaN: {}",
                cost
            )));
        }
        let mut state = self.state.write().unwrap();
        let current_budget = state.available_budget;
        let current_h = current_budget - self.cbf.b_min;

        let h_next = self.cbf.evaluate_step(current_budget, cost, current_h)?;

        let remaining_budget = current_budget - cost;
        state.available_budget = remaining_budget;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        state.reservations.push(ReservationEntry {
            debit_id: debit_id.to_string(),
            amount: cost,
            timestamp: now,
            committed: false,
            rolled_back: false,
        });

        Ok(CommitReceipt {
            debit_id: debit_id.to_string(),
            reserved_fuel: cost,
            remaining_budget,
            barrier_val: h_next,
            timestamp: now,
        })
    }

    /// Confirms and permanently settles a reservation once actuation completes.
    /// Rollback is forbidden once confirmed.
    pub fn confirm(&self, debit_id: &str) -> Result<(), CbfViolation> {
        let mut state = self.state.write().unwrap();
        for entry in state.reservations.iter_mut().rev() {
            if entry.debit_id == debit_id {
                if entry.rolled_back {
                    return Err(CbfViolation::ReservationNotFound(format!(
                        "Reservation {} was already rolled back",
                        debit_id
                    )));
                }
                entry.committed = true;
                return Ok(());
            }
        }
        Err(CbfViolation::ReservationNotFound(debit_id.to_string()))
    }

    /// Rolls back a specific reservation by debit ID, restoring fuel with zero leakage.
    pub fn rollback(&self, debit_id: &str) -> Result<f64, CbfViolation> {
        let mut state = self.state.write().unwrap();
        let mut found_amount = None;
        for entry in state.reservations.iter_mut().rev() {
            if entry.debit_id == debit_id {
                if entry.committed {
                    return Err(CbfViolation::AlreadyCommitted(debit_id.to_string()));
                }
                if entry.rolled_back {
                    return Err(CbfViolation::ReservationNotFound(format!(
                        "Reservation {} was already rolled back",
                        debit_id
                    )));
                }

                entry.rolled_back = true;
                found_amount = Some(entry.amount);
                break;
            }
        }

        if let Some(amount) = found_amount {
            state.available_budget += amount;
            Ok(state.available_budget)
        } else {
            Err(CbfViolation::ReservationNotFound(debit_id.to_string()))
        }
    }

    /// Rolls back the most recent uncommitted reservation in LIFO order.
    pub fn rollback_lifo(&self) -> Result<(String, f64), CbfViolation> {
        let mut state = self.state.write().unwrap();
        let mut found = None;
        for entry in state.reservations.iter_mut().rev() {
            if !entry.committed && !entry.rolled_back {
                entry.rolled_back = true;
                found = Some((entry.debit_id.clone(), entry.amount));
                break;
            }
        }

        if let Some((debit_id, amount)) = found {
            state.available_budget += amount;
            Ok((debit_id, state.available_budget))
        } else {
            Err(CbfViolation::ReservationNotFound(
                "No uncommitted reservations available to rollback".to_string(),
            ))
        }
    }

    /// Returns the count of pending, uncommitted reservations.
    pub fn active_reservation_count(&self) -> usize {
        let state = self.state.read().unwrap();
        state
            .reservations
            .iter()
            .filter(|r| !r.committed && !r.rolled_back)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbf_barrier_satisfaction() {
        // Initial budget = 100.0, gamma = 0.5, b_min = 10.0
        // h_0 = 90.0, min_allowed = (1 - 0.5) * 90.0 = 45.0
        // cost = 20.0 -> projected = 80.0, h_next = 70.0 >= 45.0 -> Pass
        let cbf = CbfSafetyEngine::new(0.5, 10.0).unwrap();
        let h_next = cbf.evaluate_step(100.0, 20.0, 90.0).unwrap();
        assert_eq!(h_next, 70.0);

        // cost = 50.0 -> projected = 50.0, h_next = 40.0 < 45.0 -> DecayRateExceeded
        let breach = cbf.evaluate_step(100.0, 50.0, 90.0).unwrap_err();
        assert!(matches!(breach, CbfViolation::DecayRateExceeded { .. }));
    }

    #[test]
    fn test_sequence_and_epoch_defense() {
        let cbf = CbfSafetyEngine::new(0.1, 10.0).unwrap();
        assert!(cbf.verify_sequence_and_epoch(1, 1).is_ok());
        assert!(cbf.verify_sequence_and_epoch(2, 1).is_ok());

        // Replay of sequence 2
        let replay_err = cbf.verify_sequence_and_epoch(2, 1).unwrap_err();
        assert!(matches!(replay_err, CbfViolation::SequenceReplay { .. }));

        // Monotonic epoch advancement
        cbf.advance_epoch();
        let stale_epoch_err = cbf.verify_sequence_and_epoch(3, 1).unwrap_err();
        assert!(matches!(stale_epoch_err, CbfViolation::StaleFenceEpoch { .. }));
        assert!(cbf.verify_sequence_and_epoch(3, 2).is_ok());
    }

    #[test]
    fn test_two_phase_pre_reservation_and_lifo_rollback() {
        let ledger = DebitLedger::new(100.0, 0.5, 10.0).unwrap();

        // Preview does not mutate budget
        let (projected, _) = ledger.preview(10.0).unwrap();
        assert_eq!(projected, 90.0);
        assert_eq!(ledger.available_budget(), 100.0);

        // Pre-reserve 10.0
        let r1 = ledger.pre_reserve(10.0, "debit-1").unwrap();
        assert_eq!(r1.remaining_budget, 90.0);
        assert_eq!(ledger.available_budget(), 90.0);

        // Pre-reserve 15.0
        let r2 = ledger.pre_reserve(15.0, "debit-2").unwrap();
        assert_eq!(r2.remaining_budget, 75.0);
        assert_eq!(ledger.available_budget(), 75.0);

        // LIFO Rollback should roll back debit-2 first
        let (rolled_id, restored_budget) = ledger.rollback_lifo().unwrap();
        assert_eq!(rolled_id, "debit-2");
        assert_eq!(restored_budget, 90.0);
        assert_eq!(ledger.available_budget(), 90.0);

        // Confirm debit-1
        ledger.confirm("debit-1").unwrap();
        let commit_err = ledger.rollback("debit-1").unwrap_err();
        assert!(matches!(commit_err, CbfViolation::AlreadyCommitted(_)));
    }

    #[test]
    fn test_cbf_nan_and_infinity_defense() {
        let cbf = CbfSafetyEngine::new(0.5, 10.0).unwrap();

        // 1. evaluate_step rejects NaN cost
        let nan_cost_err = cbf.evaluate_step(100.0, f64::NAN, 90.0).unwrap_err();
        assert!(matches!(nan_cost_err, CbfViolation::InvalidParameters(_)));

        // 2. evaluate_step rejects NaN current_budget
        let nan_budget_err = cbf.evaluate_step(f64::NAN, 10.0, 90.0).unwrap_err();
        assert!(matches!(nan_budget_err, CbfViolation::InvalidParameters(_)));

        // 3. evaluate_step rejects NaN current_h
        let nan_h_err = cbf.evaluate_step(100.0, 10.0, f64::NAN).unwrap_err();
        assert!(matches!(nan_h_err, CbfViolation::InvalidParameters(_)));

        // 4. evaluate_step rejects non-finite current_budget
        let inf_budget_err = cbf.evaluate_step(f64::INFINITY, 10.0, 90.0).unwrap_err();
        assert!(matches!(inf_budget_err, CbfViolation::InvalidParameters(_)));

        // 5. evaluate_step rejects non-finite current_h
        let inf_h_err = cbf.evaluate_step(100.0, 10.0, f64::INFINITY).unwrap_err();
        assert!(matches!(inf_h_err, CbfViolation::InvalidParameters(_)));

        // 6. CbfSafetyEngine::new rejects NaN and infinite parameters
        assert!(matches!(
            CbfSafetyEngine::new(f64::NAN, 10.0).unwrap_err(),
            CbfViolation::InvalidParameters(_)
        ));
        assert!(matches!(
            CbfSafetyEngine::new(0.5, f64::NAN).unwrap_err(),
            CbfViolation::InvalidParameters(_)
        ));
        assert!(matches!(
            CbfSafetyEngine::new(f64::INFINITY, 10.0).unwrap_err(),
            CbfViolation::InvalidParameters(_)
        ));
        assert!(matches!(
            CbfSafetyEngine::new(0.5, f64::INFINITY).unwrap_err(),
            CbfViolation::InvalidParameters(_)
        ));

        // 7. DebitLedger::new rejects NaN and infinite initial budget
        assert!(matches!(
            DebitLedger::new(f64::NAN, 0.5, 10.0).unwrap_err(),
            CbfViolation::InvalidParameters(_)
        ));
        assert!(matches!(
            DebitLedger::new(f64::INFINITY, 0.5, 10.0).unwrap_err(),
            CbfViolation::InvalidParameters(_)
        ));
        assert!(matches!(
            DebitLedger::new(5.0, 0.5, 10.0).unwrap_err(),
            CbfViolation::CurrentStateUnsafe { .. }
        ));

        // 8. DebitLedger preview rejects NaN cost
        let ledger = DebitLedger::new(100.0, 0.5, 10.0).unwrap();
        assert!(matches!(
            ledger.preview(f64::NAN).unwrap_err(),
            CbfViolation::InvalidParameters(_)
        ));

        // 9. DebitLedger pre_reserve rejects NaN cost without mutating budget
        assert!(matches!(
            ledger.pre_reserve(f64::NAN, "debit-nan").unwrap_err(),
            CbfViolation::InvalidParameters(_)
        ));
        assert_eq!(ledger.available_budget(), 100.0);
        assert_eq!(ledger.active_reservation_count(), 0);

        // 10. Subsequent valid transaction succeeds and is unaffected
        let r = ledger.pre_reserve(20.0, "debit-valid").unwrap();
        assert_eq!(r.remaining_budget, 80.0);
        assert_eq!(ledger.available_budget(), 80.0);
        assert_eq!(ledger.active_reservation_count(), 1);
    }
}
