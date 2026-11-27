namespace AgentOctopusFormal

/-- Exact 18-variant mirror of `crate::core::types::ArmRole` (`src/core/types.rs:62-81`). -/
inductive ArmRole : Type where
  | UntrustedDocIngest
  | AccountingLedgerWrite
  | OutboundNotification
  | NetworkEgress
  | TarpitDecoyDefense
  | KernelLevelSentinel
  | CedarPolicyEvaluation
  | AtlasThreatIntelligence
  | AnomalyDetection
  | VulnerabilityResearch
  | ContinuousOssFuzz
  | ContinuousOsvScanner
  | DifferentialProtocolAnalyzer
  | AutonomousProtocolResearch
  | PostQuantumAttestation
  | EvolutionaryOptimizer
  | DreamRsiOptimizer
  | RecursiveHarnessOptimizer
  deriving DecidableEq, Repr, BEq

namespace ArmRole

def all : List ArmRole :=
  [ .UntrustedDocIngest
  , .AccountingLedgerWrite
  , .OutboundNotification
  , .NetworkEgress
  , .TarpitDecoyDefense
  , .KernelLevelSentinel
  , .CedarPolicyEvaluation
  , .AtlasThreatIntelligence
  , .AnomalyDetection
  , .VulnerabilityResearch
  , .ContinuousOssFuzz
  , .ContinuousOsvScanner
  , .DifferentialProtocolAnalyzer
  , .AutonomousProtocolResearch
  , .PostQuantumAttestation
  , .EvolutionaryOptimizer
  , .DreamRsiOptimizer
  , .RecursiveHarnessOptimizer
  ]

theorem all_length : all.length = 18 := rfl

theorem all_complete (r : ArmRole) : r ∈ all := by
  cases r <;> simp [all]

end ArmRole

/-- Exact mirror of `crate::containment_ring::mesh_guard::TrustTier` (`mesh_guard.rs:233-246`). -/
inductive TrustTier : Type where
  | Untrusted
  | Worker
  | PrivilegedSink
  deriving DecidableEq, Repr, BEq

namespace TrustTier

instance : LawfulBEq TrustTier where
  eq_of_beq {a b} h := by cases a <;> cases b <;> first | rfl | cases h
  rfl {a} := by cases a <;> rfl

def rank : TrustTier → Nat
  | .Untrusted => 10
  | .Worker => 50
  | .PrivilegedSink => 100

def potential (t : TrustTier) : Int :=
  Int.ofNat t.rank

instance : LE TrustTier where
  le a b := a.rank ≤ b.rank

instance : LT TrustTier where
  lt a b := a.rank < b.rank

instance (a b : TrustTier) : Decidable (a ≤ b) :=
  inferInstanceAs (Decidable (a.rank ≤ b.rank))

instance (a b : TrustTier) : Decidable (a < b) :=
  inferInstanceAs (Decidable (a.rank < b.rank))

theorem rank_strict_order :
    TrustTier.Untrusted.rank < TrustTier.Worker.rank ∧
    TrustTier.Worker.rank < TrustTier.PrivilegedSink.rank := by
  decide

theorem rank_injective {a b : TrustTier} (h : a.rank = b.rank) : a = b := by
  cases a <;> cases b <;> simp_all [rank]

theorem le_iff_rank_le (a b : TrustTier) : a ≤ b ↔ a.rank ≤ b.rank := Iff.rfl

theorem lt_iff_rank_lt (a b : TrustTier) : a < b ↔ a.rank < b.rank := Iff.rfl

theorem min_rank_lower_bound (a b : TrustTier) :
    (if a.rank ≤ b.rank then a else b).rank ≤ a.rank ∧
    (if a.rank ≤ b.rank then a else b).rank ≤ b.rank := by
  cases a <;> cases b <;> decide

end TrustTier

/-- Ordering and meet operations on `TrustTier` matching `#[derive(PartialOrd, Ord)]`. -/
abbrev tierLe (a b : TrustTier) : Prop := a.rank ≤ b.rank

instance (a b : TrustTier) : Decidable (tierLe a b) :=
  inferInstanceAs (Decidable (a.rank ≤ b.rank))

def tierBle (a b : TrustTier) : Bool := decide (a.rank ≤ b.rank)

def tierMin (a b : TrustTier) : TrustTier :=
  if a.rank ≤ b.rank then a else b

theorem tierLe_refl (a : TrustTier) : tierLe a a :=
  Nat.le_refl a.rank

theorem tierLe_trans {a b c : TrustTier} (h1 : tierLe a b) (h2 : tierLe b c) : tierLe a c :=
  Nat.le_trans h1 h2

theorem tierMin_le_left (a b : TrustTier) : tierLe (tierMin a b) a := by
  cases a <;> cases b <;> decide

theorem tierMin_le_right (a b : TrustTier) : tierLe (tierMin a b) b := by
  cases a <;> cases b <;> decide

theorem tierMin_eq_untrusted_iff (a b : TrustTier) :
    tierMin a b = .Untrusted ↔ a = .Untrusted ∨ b = .Untrusted := by
  cases a <;> cases b <;> decide

theorem tierBle_eq_true_iff (a b : TrustTier) : tierBle a b = true ↔ tierLe a b := by
  cases a <;> cases b <;> decide

/-- Exhaustive role -> trust tier map (`mesh_guard.rs:250-273`), zero wildcard arm. -/
def roleTrustTier : ArmRole → TrustTier
  | .UntrustedDocIngest => .Untrusted
  | .DifferentialProtocolAnalyzer => .Untrusted
  | .AutonomousProtocolResearch => .Untrusted
  | .ContinuousOssFuzz => .Untrusted
  | .TarpitDecoyDefense => .Untrusted
  | .AccountingLedgerWrite => .PrivilegedSink
  | .KernelLevelSentinel => .PrivilegedSink
  | .CedarPolicyEvaluation => .PrivilegedSink
  | .PostQuantumAttestation => .PrivilegedSink
  | .OutboundNotification => .Worker
  | .NetworkEgress => .Worker
  | .AtlasThreatIntelligence => .Worker
  | .AnomalyDetection => .Worker
  | .VulnerabilityResearch => .Worker
  | .ContinuousOsvScanner => .Worker
  | .EvolutionaryOptimizer => .Worker
  | .DreamRsiOptimizer => .Worker
  | .RecursiveHarnessOptimizer => .Worker

theorem roleTrustTier_total (r : ArmRole) : ∃ t : TrustTier, roleTrustTier r = t :=
  ⟨roleTrustTier r, rfl⟩

theorem roleTrustTier_valid_ranks (r : ArmRole) :
    (roleTrustTier r).rank = 10 ∨
    (roleTrustTier r).rank = 50 ∨
    (roleTrustTier r).rank = 100 := by
  cases r <;> decide

theorem untrusted_lt_privileged :
    TrustTier.Untrusted < TrustTier.PrivilegedSink := by
  decide

end AgentOctopusFormal
