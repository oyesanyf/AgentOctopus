import AgentOctopusFormal.CoreTypes

namespace AgentOctopusFormal

/-!
# Milestone M2 Part 2: CAGE `NoDirectBind` BFS, Routing Seal, CBF & DebitLedger

Formalizes 1-to-1 with:
- `src/security/cage_governance/no_direct_bind_proof.rs` (`FormalBfsModel`, `BfsPhase`, `BfsState`)
- `src/security/cage_governance/pipeline.rs` (`Phase2Mode`, `GovernanceVerdict`, `CagePipeline`)
- `src/security/cage_governance/ftra_stpa.rs` (`ActionReversibility`, SR 26-2 thresholds)
- `src/security/cage_governance/routing_seal.rs` (`CageRoutingSeal`, `RoutingSealSigner`)
- `src/security/cage_governance/cbf_fiscal.rs` (`CbfSafetyEngine`, `DebitLedger`)
-/

/-! ### Part 1: Constants & CAGE Governance Enums -/

def ROUTING_SEAL_TTL_SECS : Nat := 30
def CLOCK_DRIFT_TOLERANCE_SECS : Nat := 5
def NUM_CAGE_TIERS : Nat := 7
def GATED_REACHABLE_COUNT : Nat := 34
def UNGATED_REACHABLE_COUNT : Nat := 17
def SKIPPED_TIER_REACHABLE_COUNT : Nat := 31
def SR_26_2_ALLOW_BPS : Nat := 9500
def SR_26_2_APPROVAL_BPS : Nat := 7000
def CBF_SCALE : Nat := 1_000_000_000

inductive CageTier : Type where
  | FTRA
  | STPA
  | CedarOpa
  | Sr26_2
  | BayesianConsensus
  | Cbf
  | DebitLedger
  deriving DecidableEq, Repr

instance : BEq CageTier where
  beq a b := decide (a = b)

instance : LawfulBEq CageTier where
  eq_of_beq h := of_decide_eq_true h
  rfl := decide_eq_true rfl

namespace CageTier

def all : List CageTier :=
  [.FTRA, .STPA, .CedarOpa, .Sr26_2, .BayesianConsensus, .Cbf, .DebitLedger]

def idx : CageTier → Fin 7
  | .FTRA => ⟨0, by decide⟩
  | .STPA => ⟨1, by decide⟩
  | .CedarOpa => ⟨2, by decide⟩
  | .Sr26_2 => ⟨3, by decide⟩
  | .BayesianConsensus => ⟨4, by decide⟩
  | .Cbf => ⟨5, by decide⟩
  | .DebitLedger => ⟨6, by decide⟩

def ofFin : Fin 7 → CageTier
  | ⟨0, _⟩ => .FTRA
  | ⟨1, _⟩ => .STPA
  | ⟨2, _⟩ => .CedarOpa
  | ⟨3, _⟩ => .Sr26_2
  | ⟨4, _⟩ => .BayesianConsensus
  | ⟨5, _⟩ => .Cbf
  | ⟨6, _⟩ => .DebitLedger

def canonicalName : CageTier → String
  | .FTRA => "ftra"
  | .STPA => "stpa"
  | .CedarOpa => "opa"
  | .Sr26_2 => "confidence"
  | .BayesianConsensus => "consensus"
  | .Cbf => "cbf"
  | .DebitLedger => "fiscal"

theorem ofFin_idx (t : CageTier) : ofFin t.idx = t := by
  cases t <;> rfl

theorem idx_ofFin (i : Fin 7) : (ofFin i).idx = i := by
  rcases i with ⟨v, hv⟩
  match v with
  | 0 => rfl
  | 1 => rfl
  | 2 => rfl
  | 3 => rfl
  | 4 => rfl
  | 5 => rfl
  | 6 => rfl
  | _ + 7 => exact False.elim (by omega)

end CageTier

def stageMatchesRequired (requiredStage evaluatedStage : String) : Bool :=
  if requiredStage == evaluatedStage then
    true
  else if requiredStage == "opa" || requiredStage == "cedar" then
    evaluatedStage == "opa" || evaluatedStage == "cedar"
  else
    false

inductive BfsPhase : Type where
  | Initial
  | Checking
  | NarrowEval
  | NarrowPassed
  | SealIssued
  | Executed
  | Denied
  deriving DecidableEq, Repr

instance : BEq BfsPhase where
  beq a b := decide (a = b)

instance : LawfulBEq BfsPhase where
  eq_of_beq h := of_decide_eq_true h
  rfl := decide_eq_true rfl

def BfsPhase.asStr : BfsPhase → String
  | .Initial => "INITIAL"
  | .Checking => "CHECKING"
  | .NarrowEval => "NARROW_EVAL"
  | .NarrowPassed => "NARROW_PASSED"
  | .SealIssued => "SEAL_ISSUED"
  | .Executed => "EXECUTED"
  | .Denied => "DENIED"

inductive Phase2Mode : Type where
  | Skip
  | Preview
  | Commit
  deriving DecidableEq, Repr

instance : BEq Phase2Mode where
  beq a b := decide (a = b)

instance : LawfulBEq Phase2Mode where
  eq_of_beq h := of_decide_eq_true h
  rfl := decide_eq_true rfl

inductive GovernanceVerdictKind : Type where
  | Allow
  | Narrow
  | RequireApproval
  | Defer
  | Deny
  deriving DecidableEq, Repr

def selectPhase2Mode (isDryRun : Bool) : GovernanceVerdictKind → Phase2Mode
  | .Deny => .Skip
  | .RequireApproval => .Preview
  | .Defer => .Preview
  | .Allow => if isDryRun then .Preview else .Commit
  | .Narrow => if isDryRun then .Preview else .Commit

inductive ActionReversibility : Type where
  | ReadOnly
  | Reversible
  | Compensatable
  | ConditionalAutonomous
  | IrreversibleTerminal
  deriving DecidableEq, Repr

def ActionReversibility.requiredAuthorityRank : ActionReversibility → Nat
  | .ReadOnly => 5
  | .Reversible => 3
  | .Compensatable => 3
  | .ConditionalAutonomous => 3
  | .IrreversibleTerminal => 2

/-! ### Part 2: `FormalBfsModel` (`no_direct_bind_proof.rs`) -/

inductive BfsLabel : Type where
  | pending
  | tier (t : CageTier)
  | completed
  | directTier (i : Fin 7)
  | narrowTier (i : Fin 7)
  | narrowRerunTier (i : Fin 7)
  | allClamped
  | valid
  | executed
  | sealExpired
  | ungatedDirectBind
  | ungatedDenyTier (i : Fin 7)
  | terminalFailure
  deriving DecidableEq, Repr

instance : BEq BfsLabel where
  beq a b := decide (a = b)

instance : LawfulBEq BfsLabel where
  eq_of_beq h := of_decide_eq_true h
  rfl := decide_eq_true rfl

def BfsLabel.asString : BfsLabel → String
  | .pending => "PENDING"
  | .tier t => t.canonicalName
  | .completed => "completed"
  | .directTier i => s!"direct_tier_{i.val}"
  | .narrowTier i => s!"tier_{i.val}"
  | .narrowRerunTier i => s!"narrow_rerun_tier_{i.val}"
  | .allClamped => "all_clamped"
  | .valid => "valid"
  | .executed => "executed"
  | .sealExpired => "seal_expired"
  | .ungatedDirectBind => "ungated_direct_bind"
  | .ungatedDenyTier i => s!"tier_{i.val}"
  | .terminalFailure => "terminal_failure"

structure BfsState where
  phase : BfsPhase
  label : BfsLabel
  tier : Nat
  sealPresent : Bool
  resolvedAllow : Bool
  executedOrNarrow : Bool
  deriving DecidableEq, Repr

instance : BEq BfsState where
  beq a b := decide (a = b)

instance : LawfulBEq BfsState where
  eq_of_beq h := of_decide_eq_true h
  rfl := decide_eq_true rfl

def bfsInitialState : BfsState :=
  { phase := .Initial
  , label := .pending
  , tier := 0
  , sealPresent := false
  , resolvedAllow := false
  , executedOrNarrow := false }

def checkState (t : CageTier) : BfsState :=
  { phase := .Checking
  , label := .tier t
  , tier := t.idx.val
  , sealPresent := false
  , resolvedAllow := false
  , executedOrNarrow := false }

def completedCheckState : BfsState :=
  { phase := .Checking
  , label := .completed
  , tier := 7
  , sealPresent := false
  , resolvedAllow := false
  , executedOrNarrow := false }

def directDenyState (i : Fin 7) : BfsState :=
  { phase := .Denied
  , label := .directTier i
  , tier := i.val
  , sealPresent := false
  , resolvedAllow := false
  , executedOrNarrow := false }

def narrowState (i : Fin 7) : BfsState :=
  { phase := .NarrowEval
  , label := .narrowTier i
  , tier := i.val
  , sealPresent := false
  , resolvedAllow := false
  , executedOrNarrow := true }

def narrowRerunDenyState (i : Fin 7) : BfsState :=
  { phase := .Denied
  , label := .narrowRerunTier i
  , tier := i.val
  , sealPresent := false
  , resolvedAllow := false
  , executedOrNarrow := false }

def narrowPassedState : BfsState :=
  { phase := .NarrowPassed
  , label := .allClamped
  , tier := 7
  , sealPresent := true
  , resolvedAllow := true
  , executedOrNarrow := true }

def sealIssuedState : BfsState :=
  { phase := .SealIssued
  , label := .valid
  , tier := 7
  , sealPresent := true
  , resolvedAllow := true
  , executedOrNarrow := false }

def executedState : BfsState :=
  { phase := .Executed
  , label := .executed
  , tier := 7
  , sealPresent := true
  , resolvedAllow := true
  , executedOrNarrow := true }

def sealExpiredState : BfsState :=
  { phase := .Denied
  , label := .sealExpired
  , tier := 7
  , sealPresent := true
  , resolvedAllow := false
  , executedOrNarrow := false }

def ungatedDirectBindState : BfsState :=
  { phase := .Executed
  , label := .ungatedDirectBind
  , tier := 7
  , sealPresent := false
  , resolvedAllow := false
  , executedOrNarrow := true }

def ungatedDenyState (i : Fin 7) : BfsState :=
  { phase := .Denied
  , label := .ungatedDenyTier i
  , tier := i.val
  , sealPresent := false
  , resolvedAllow := false
  , executedOrNarrow := false }

def terminalFailureState : BfsState :=
  { phase := .Denied
  , label := .terminalFailure
  , tier := 7
  , sealPresent := false
  , resolvedAllow := false
  , executedOrNarrow := false }

private def fin0 : Fin 7 := ⟨0, by decide⟩
private def fin1 : Fin 7 := ⟨1, by decide⟩
private def fin2 : Fin 7 := ⟨2, by decide⟩
private def fin3 : Fin 7 := ⟨3, by decide⟩
private def fin4 : Fin 7 := ⟨4, by decide⟩
private def fin5 : Fin 7 := ⟨5, by decide⟩
private def fin6 : Fin 7 := ⟨6, by decide⟩

/-- Exact gated transition map matching `FormalBfsModel::explore_gated_model` (`no_direct_bind_proof.rs:262-385`). -/
def gatedNext (s : BfsState) : List BfsState :=
  if s == bfsInitialState then
    [checkState .FTRA]
  else if s == completedCheckState then
    [sealIssuedState]
  else if s == narrowPassedState then
    [sealIssuedState]
  else if s == sealIssuedState then
    [executedState, sealExpiredState]
  else
    match s.phase, s.label with
    | .Checking, .tier t =>
      if s == checkState t then
        let i := t.idx
        let nextCheck :=
          if h : i.val + 1 < 7 then
            checkState (CageTier.ofFin ⟨i.val + 1, h⟩)
          else
            completedCheckState
        [nextCheck, directDenyState i, narrowState i]
      else []
    | .NarrowEval, .narrowTier i =>
      if s == narrowState i then
        let nextNarrow :=
          if h : i.val + 1 < 7 then
            narrowState ⟨i.val + 1, h⟩
          else
            narrowPassedState
        [nextNarrow, narrowRerunDenyState i]
      else []
    | _, _ => []

inductive GatedReachable : BfsState → Prop where
  | init : GatedReachable bfsInitialState
  | step {s s' : BfsState} : GatedReachable s → s' ∈ gatedNext s → GatedReachable s'

/-- Canonical 34-state universe of `explore_gated_model`. -/
def gatedCanonicalStates : List BfsState :=
  [ bfsInitialState
  , checkState .FTRA, checkState .STPA, checkState .CedarOpa, checkState .Sr26_2
  , checkState .BayesianConsensus, checkState .Cbf, checkState .DebitLedger
  , completedCheckState
  , directDenyState fin0, directDenyState fin1, directDenyState fin2, directDenyState fin3
  , directDenyState fin4, directDenyState fin5, directDenyState fin6
  , narrowState fin0, narrowState fin1, narrowState fin2, narrowState fin3
  , narrowState fin4, narrowState fin5, narrowState fin6
  , narrowRerunDenyState fin0, narrowRerunDenyState fin1, narrowRerunDenyState fin2
  , narrowRerunDenyState fin3, narrowRerunDenyState fin4, narrowRerunDenyState fin5
  , narrowRerunDenyState fin6
  , narrowPassedState
  , sealIssuedState
  , executedState
  , sealExpiredState
  ]

private theorem gatedNext_subset_canonical :
    ∀ s ∈ gatedCanonicalStates, ∀ s' ∈ gatedNext s, s' ∈ gatedCanonicalStates := by
  decide

private theorem gated_all_reachable :
    ∀ s ∈ gatedCanonicalStates, GatedReachable s := by
  have hInit : GatedReachable bfsInitialState := GatedReachable.init
  have hC0 : GatedReachable (checkState .FTRA) := GatedReachable.step hInit (by decide)
  have hC1 : GatedReachable (checkState .STPA) := GatedReachable.step hC0 (by decide)
  have hC2 : GatedReachable (checkState .CedarOpa) := GatedReachable.step hC1 (by decide)
  have hC3 : GatedReachable (checkState .Sr26_2) := GatedReachable.step hC2 (by decide)
  have hC4 : GatedReachable (checkState .BayesianConsensus) := GatedReachable.step hC3 (by decide)
  have hC5 : GatedReachable (checkState .Cbf) := GatedReachable.step hC4 (by decide)
  have hC6 : GatedReachable (checkState .DebitLedger) := GatedReachable.step hC5 (by decide)
  have hComp : GatedReachable completedCheckState := GatedReachable.step hC6 (by decide)
  have hD0 : GatedReachable (directDenyState fin0) := GatedReachable.step hC0 (by decide)
  have hD1 : GatedReachable (directDenyState fin1) := GatedReachable.step hC1 (by decide)
  have hD2 : GatedReachable (directDenyState fin2) := GatedReachable.step hC2 (by decide)
  have hD3 : GatedReachable (directDenyState fin3) := GatedReachable.step hC3 (by decide)
  have hD4 : GatedReachable (directDenyState fin4) := GatedReachable.step hC4 (by decide)
  have hD5 : GatedReachable (directDenyState fin5) := GatedReachable.step hC5 (by decide)
  have hD6 : GatedReachable (directDenyState fin6) := GatedReachable.step hC6 (by decide)
  have hN0 : GatedReachable (narrowState fin0) := GatedReachable.step hC0 (by decide)
  have hN1 : GatedReachable (narrowState fin1) := GatedReachable.step hC1 (by decide)
  have hN2 : GatedReachable (narrowState fin2) := GatedReachable.step hC2 (by decide)
  have hN3 : GatedReachable (narrowState fin3) := GatedReachable.step hC3 (by decide)
  have hN4 : GatedReachable (narrowState fin4) := GatedReachable.step hC4 (by decide)
  have hN5 : GatedReachable (narrowState fin5) := GatedReachable.step hC5 (by decide)
  have hN6 : GatedReachable (narrowState fin6) := GatedReachable.step hC6 (by decide)
  have hNR0 : GatedReachable (narrowRerunDenyState fin0) := GatedReachable.step hN0 (by decide)
  have hNR1 : GatedReachable (narrowRerunDenyState fin1) := GatedReachable.step hN1 (by decide)
  have hNR2 : GatedReachable (narrowRerunDenyState fin2) := GatedReachable.step hN2 (by decide)
  have hNR3 : GatedReachable (narrowRerunDenyState fin3) := GatedReachable.step hN3 (by decide)
  have hNR4 : GatedReachable (narrowRerunDenyState fin4) := GatedReachable.step hN4 (by decide)
  have hNR5 : GatedReachable (narrowRerunDenyState fin5) := GatedReachable.step hN5 (by decide)
  have hNR6 : GatedReachable (narrowRerunDenyState fin6) := GatedReachable.step hN6 (by decide)
  have hNP : GatedReachable narrowPassedState := GatedReachable.step hN6 (by decide)
  have hSI : GatedReachable sealIssuedState := GatedReachable.step hComp (by decide)
  have hEX : GatedReachable executedState := GatedReachable.step hSI (by decide)
  have hSE : GatedReachable sealExpiredState := GatedReachable.step hSI (by decide)
  intro s hs
  simp only [gatedCanonicalStates, List.mem_cons, List.not_mem_nil, or_false] at hs
  rcases hs with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals assumption

/-- Exact equivalence between `GatedReachable` and the 34-state canonical set. -/
theorem gatedReachable_iff_mem (s : BfsState) :
    GatedReachable s ↔ s ∈ gatedCanonicalStates := by
  constructor
  · intro h
    induction h with
    | init => decide
    | step _ hstep ih => exact gatedNext_subset_canonical _ ih _ hstep
  · exact gated_all_reachable s

/-- Theorem (`NoDirectBind`): Every reachable `Executed` state in the gated model has
    both `sealPresent = true` and `resolvedAllow = true`. -/
theorem no_direct_bind (s : BfsState) (h : GatedReachable s)
    (hex : s.phase = .Executed) :
    s.sealPresent = true ∧ s.resolvedAllow = true := by
  have hmem := (gatedReachable_iff_mem s).mp h
  have hinvariant : ∀ x ∈ gatedCanonicalStates, x.phase = .Executed → x.sealPresent = true ∧ x.resolvedAllow = true := by
    decide
  exact hinvariant s hmem hex

/-- Theorem: The gated BFS model has exactly 34 distinct reachable states and 1 `Executed` state. -/
theorem gated_bfs_state_count_34 :
    gatedCanonicalStates.length = GATED_REACHABLE_COUNT ∧
    gatedCanonicalStates.Nodup ∧
    (∀ s : BfsState, GatedReachable s ↔ s ∈ gatedCanonicalStates) ∧
    (gatedCanonicalStates.filter (fun s => s.phase == .Executed)).length = 1 := by
  refine ⟨rfl, ?_, gatedReachable_iff_mem, rfl⟩
  decide

/-- Exact ungated counterexample transition map (`no_direct_bind_proof.rs:438-499`). -/
def ungatedNext (s : BfsState) : List BfsState :=
  if s == bfsInitialState then
    [checkState .FTRA]
  else if s == ungatedDirectBindState then
    [terminalFailureState]
  else
    match s.phase, s.label with
    | .Checking, .tier t =>
      if s == checkState t then
        let i := t.idx
        let nextCheck :=
          if h : i.val + 1 < 7 then
            checkState (CageTier.ofFin ⟨i.val + 1, h⟩)
          else
            ungatedDirectBindState
        [nextCheck, ungatedDenyState i]
      else []
    | _, _ => []

inductive UngatedReachable : BfsState → Prop where
  | init : UngatedReachable bfsInitialState
  | step {s s' : BfsState} : UngatedReachable s → s' ∈ ungatedNext s → UngatedReachable s'

def ungatedCanonicalStates : List BfsState :=
  [ bfsInitialState
  , checkState .FTRA, checkState .STPA, checkState .CedarOpa, checkState .Sr26_2
  , checkState .BayesianConsensus, checkState .Cbf, checkState .DebitLedger
  , ungatedDenyState fin0, ungatedDenyState fin1, ungatedDenyState fin2, ungatedDenyState fin3
  , ungatedDenyState fin4, ungatedDenyState fin5, ungatedDenyState fin6
  , ungatedDirectBindState
  , terminalFailureState
  ]

private theorem ungatedNext_subset_canonical :
    ∀ s ∈ ungatedCanonicalStates, ∀ s' ∈ ungatedNext s, s' ∈ ungatedCanonicalStates := by
  decide

private theorem ungated_all_reachable :
    ∀ s ∈ ungatedCanonicalStates, UngatedReachable s := by
  have hInit : UngatedReachable bfsInitialState := UngatedReachable.init
  have hC0 : UngatedReachable (checkState .FTRA) := UngatedReachable.step hInit (by decide)
  have hC1 : UngatedReachable (checkState .STPA) := UngatedReachable.step hC0 (by decide)
  have hC2 : UngatedReachable (checkState .CedarOpa) := UngatedReachable.step hC1 (by decide)
  have hC3 : UngatedReachable (checkState .Sr26_2) := UngatedReachable.step hC2 (by decide)
  have hC4 : UngatedReachable (checkState .BayesianConsensus) := UngatedReachable.step hC3 (by decide)
  have hC5 : UngatedReachable (checkState .Cbf) := UngatedReachable.step hC4 (by decide)
  have hC6 : UngatedReachable (checkState .DebitLedger) := UngatedReachable.step hC5 (by decide)
  have hD0 : UngatedReachable (ungatedDenyState fin0) := UngatedReachable.step hC0 (by decide)
  have hD1 : UngatedReachable (ungatedDenyState fin1) := UngatedReachable.step hC1 (by decide)
  have hD2 : UngatedReachable (ungatedDenyState fin2) := UngatedReachable.step hC2 (by decide)
  have hD3 : UngatedReachable (ungatedDenyState fin3) := UngatedReachable.step hC3 (by decide)
  have hD4 : UngatedReachable (ungatedDenyState fin4) := UngatedReachable.step hC4 (by decide)
  have hD5 : UngatedReachable (ungatedDenyState fin5) := UngatedReachable.step hC5 (by decide)
  have hD6 : UngatedReachable (ungatedDenyState fin6) := UngatedReachable.step hC6 (by decide)
  have hExec : UngatedReachable ungatedDirectBindState := UngatedReachable.step hC6 (by decide)
  have hTerm : UngatedReachable terminalFailureState := UngatedReachable.step hExec (by decide)
  intro s hs
  simp only [ungatedCanonicalStates, List.mem_cons, List.not_mem_nil, or_false] at hs
  rcases hs with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl
  all_goals assumption

/-- Theorem: The ungated counterexample reaches an `Executed` state without a routing seal or `resolvedAllow`. -/
theorem ungated_has_counterexample :
    ∃ s : BfsState,
      UngatedReachable s ∧
      s.phase = .Executed ∧
      s.sealPresent = false ∧
      s.resolvedAllow = false := by
  refine ⟨ungatedDirectBindState, ?_, rfl, rfl, rfl⟩
  exact ungated_all_reachable ungatedDirectBindState (by decide)

/-- Theorem: The ungated counterexample has exactly 17 distinct reachable states. -/
theorem ungated_bfs_state_count_17 :
    ungatedCanonicalStates.length = UNGATED_REACHABLE_COUNT ∧
    ungatedCanonicalStates.Nodup ∧
    (∀ s : BfsState, UngatedReachable s ↔ s ∈ ungatedCanonicalStates) := by
  refine ⟨rfl, ?_, ?_⟩
  · decide
  · intro s
    constructor
    · intro h
      induction h with
      | init => decide
      | step _ hstep ih => exact ungatedNext_subset_canonical _ ih _ hstep
    · exact ungated_all_reachable s

/-- Exact skipped-tier transition map (`no_direct_bind_proof.rs:553-668`). -/
def skippedNext (skipTier : Fin 7) (s : BfsState) : List BfsState :=
  if s == bfsInitialState then
    let firstCheck : Fin 7 := if skipTier.val != 0 then fin0 else fin1
    let initTargets := [checkState (CageTier.ofFin firstCheck)]
    if skipTier.val == 0 then
      initTargets ++ [narrowState fin0]
    else
      initTargets
  else if s == completedCheckState then
    [sealIssuedState]
  else if s == narrowPassedState then
    [sealIssuedState]
  else if s == sealIssuedState then
    [sealExpiredState]
  else
    match s.phase, s.label with
    | .Checking, .tier t =>
      if t.idx == skipTier then
        []
      else if s == checkState t then
        let i := t.idx
        let nextIdx0 := i.val + 1
        let nextIdx := if nextIdx0 == skipTier.val then nextIdx0 + 1 else nextIdx0
        let nextCheck :=
          if h : nextIdx < 7 then
            checkState (CageTier.ofFin ⟨nextIdx, h⟩)
          else
            completedCheckState
        [nextCheck, directDenyState i, narrowState i]
      else []
    | .NarrowEval, .narrowTier i =>
      if s == narrowState i then
        let nextNarrow :=
          if h : i.val + 1 < 7 then
            narrowState ⟨i.val + 1, h⟩
          else
            narrowPassedState
        [nextNarrow, narrowRerunDenyState i]
      else []
    | _, _ => []

inductive SkippedReachable (skipTier : Fin 7) : BfsState → Prop where
  | init : SkippedReachable skipTier bfsInitialState
  | step {s s' : BfsState} :
      SkippedReachable skipTier s → s' ∈ skippedNext skipTier s → SkippedReachable skipTier s'

private theorem ite_checkState_phase (P : Prop) [Decidable P] (f : P → CageTier) :
    (if h : P then checkState (f h) else completedCheckState).phase = .Checking := by
  by_cases h : P <;> simp [h, checkState, completedCheckState]

private theorem ite_narrowState_phase (P : Prop) [Decidable P] (f : P → Fin 7) :
    (if h : P then narrowState (f h) else narrowPassedState).phase ≠ .Executed := by
  by_cases h : P <;> simp [h, narrowState, narrowPassedState]

private theorem skippedNext_no_executed (skipTier : Fin 7) (s s' : BfsState)
    (hmem : s' ∈ skippedNext skipTier s) : s'.phase ≠ .Executed := by
  unfold skippedNext at hmem
  split at hmem
  · dsimp only at hmem
    split at hmem
    · rcases List.mem_append.mp hmem with hL | hR
      · rcases List.mem_singleton.mp hL with rfl; intro h; cases h
      · rcases List.mem_singleton.mp hR with rfl; intro h; cases h
    · rcases List.mem_singleton.mp hmem with rfl; intro h; cases h
  · split at hmem
    · rcases List.mem_singleton.mp hmem with rfl; intro h; cases h
    · split at hmem
      · rcases List.mem_singleton.mp hmem with rfl; intro h; cases h
      · split at hmem
        · rcases List.mem_singleton.mp hmem with rfl; intro h; cases h
        · split at hmem
          · split at hmem
            · cases hmem
            · split at hmem
              · simp only [List.mem_cons, List.not_mem_nil, or_false] at hmem
                rcases hmem with rfl | rfl | rfl
                · intro h
                  rw [ite_checkState_phase] at h
                  cases h
                · intro h; cases h
                · intro h; cases h
              · cases hmem
          · split at hmem
            · simp only [List.mem_cons, List.not_mem_nil, or_false] at hmem
              rcases hmem with rfl | rfl
              · exact ite_narrowState_phase _ _
              · intro h; cases h
            · cases hmem
          · cases hmem

/-- Theorem: Skipping any required tier makes `Executed` completely unreachable. -/
theorem skipped_tier_unreachable_executed (skipTier : Fin 7) (s : BfsState)
    (h : SkippedReachable skipTier s) :
    s.phase ≠ .Executed := by
  induction h with
  | init =>
    intro hEq
    cases hEq
  | step _ hmem _ =>
    exact skippedNext_no_executed skipTier _ _ hmem

def skippedCanonicalStates (skipTier : Fin 7) : List BfsState :=
  gatedCanonicalStates.filter (fun s =>
    s != checkState (CageTier.ofFin skipTier) &&
    s != directDenyState skipTier &&
    s != executedState)

private theorem skipped_count_0 :
    (skippedCanonicalStates fin0).length = SKIPPED_TIER_REACHABLE_COUNT ∧
    (skippedCanonicalStates fin0).Nodup ∧
    (∀ s : BfsState, SkippedReachable fin0 s ↔ s ∈ skippedCanonicalStates fin0) := by
  refine ⟨rfl, by decide, ?_⟩
  have hcl : ∀ s ∈ skippedCanonicalStates fin0, ∀ s' ∈ skippedNext fin0 s, s' ∈ skippedCanonicalStates fin0 := by
    decide
  have hreach : ∀ s ∈ skippedCanonicalStates fin0, SkippedReachable fin0 s := by
    have hInit : SkippedReachable fin0 bfsInitialState := SkippedReachable.init
    have hC1 : SkippedReachable fin0 (checkState .STPA) := SkippedReachable.step hInit (by decide)
    have hC2 : SkippedReachable fin0 (checkState .CedarOpa) := SkippedReachable.step hC1 (by decide)
    have hC3 : SkippedReachable fin0 (checkState .Sr26_2) := SkippedReachable.step hC2 (by decide)
    have hC4 : SkippedReachable fin0 (checkState .BayesianConsensus) := SkippedReachable.step hC3 (by decide)
    have hC5 : SkippedReachable fin0 (checkState .Cbf) := SkippedReachable.step hC4 (by decide)
    have hC6 : SkippedReachable fin0 (checkState .DebitLedger) := SkippedReachable.step hC5 (by decide)
    have hComp : SkippedReachable fin0 completedCheckState := SkippedReachable.step hC6 (by decide)
    have hD1 : SkippedReachable fin0 (directDenyState fin1) := SkippedReachable.step hC1 (by decide)
    have hD2 : SkippedReachable fin0 (directDenyState fin2) := SkippedReachable.step hC2 (by decide)
    have hD3 : SkippedReachable fin0 (directDenyState fin3) := SkippedReachable.step hC3 (by decide)
    have hD4 : SkippedReachable fin0 (directDenyState fin4) := SkippedReachable.step hC4 (by decide)
    have hD5 : SkippedReachable fin0 (directDenyState fin5) := SkippedReachable.step hC5 (by decide)
    have hD6 : SkippedReachable fin0 (directDenyState fin6) := SkippedReachable.step hC6 (by decide)
    have hN0 : SkippedReachable fin0 (narrowState fin0) := SkippedReachable.step hInit (by decide)
    have hN1 : SkippedReachable fin0 (narrowState fin1) := SkippedReachable.step hC1 (by decide)
    have hN2 : SkippedReachable fin0 (narrowState fin2) := SkippedReachable.step hC2 (by decide)
    have hN3 : SkippedReachable fin0 (narrowState fin3) := SkippedReachable.step hC3 (by decide)
    have hN4 : SkippedReachable fin0 (narrowState fin4) := SkippedReachable.step hC4 (by decide)
    have hN5 : SkippedReachable fin0 (narrowState fin5) := SkippedReachable.step hC5 (by decide)
    have hN6 : SkippedReachable fin0 (narrowState fin6) := SkippedReachable.step hC6 (by decide)
    have hNR0 : SkippedReachable fin0 (narrowRerunDenyState fin0) := SkippedReachable.step hN0 (by decide)
    have hNR1 : SkippedReachable fin0 (narrowRerunDenyState fin1) := SkippedReachable.step hN1 (by decide)
    have hNR2 : SkippedReachable fin0 (narrowRerunDenyState fin2) := SkippedReachable.step hN2 (by decide)
    have hNR3 : SkippedReachable fin0 (narrowRerunDenyState fin3) := SkippedReachable.step hN3 (by decide)
    have hNR4 : SkippedReachable fin0 (narrowRerunDenyState fin4) := SkippedReachable.step hN4 (by decide)
    have hNR5 : SkippedReachable fin0 (narrowRerunDenyState fin5) := SkippedReachable.step hN5 (by decide)
    have hNR6 : SkippedReachable fin0 (narrowRerunDenyState fin6) := SkippedReachable.step hN6 (by decide)
    have hNP : SkippedReachable fin0 narrowPassedState := SkippedReachable.step hN6 (by decide)
    have hSI : SkippedReachable fin0 sealIssuedState := SkippedReachable.step hComp (by decide)
    have hSE : SkippedReachable fin0 sealExpiredState := SkippedReachable.step hSI (by decide)
    intro s hs
    change s ∈ ([ bfsInitialState
      , checkState .STPA, checkState .CedarOpa, checkState .Sr26_2
      , checkState .BayesianConsensus, checkState .Cbf, checkState .DebitLedger
      , completedCheckState
      , directDenyState fin1, directDenyState fin2, directDenyState fin3
      , directDenyState fin4, directDenyState fin5, directDenyState fin6
      , narrowState fin0, narrowState fin1, narrowState fin2, narrowState fin3
      , narrowState fin4, narrowState fin5, narrowState fin6
      , narrowRerunDenyState fin0, narrowRerunDenyState fin1, narrowRerunDenyState fin2
      , narrowRerunDenyState fin3, narrowRerunDenyState fin4, narrowRerunDenyState fin5
      , narrowRerunDenyState fin6
      , narrowPassedState, sealIssuedState, sealExpiredState ] : List BfsState) at hs
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hs
    rcases hs with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals assumption
  intro s
  constructor
  · intro h
    induction h with
    | init => decide
    | step _ hstep ih => exact hcl _ ih _ hstep
  · exact hreach s

private theorem skipped_count_1 :
    (skippedCanonicalStates fin1).length = SKIPPED_TIER_REACHABLE_COUNT ∧
    (skippedCanonicalStates fin1).Nodup ∧
    (∀ s : BfsState, SkippedReachable fin1 s ↔ s ∈ skippedCanonicalStates fin1) := by
  refine ⟨rfl, by decide, ?_⟩
  have hcl : ∀ s ∈ skippedCanonicalStates fin1, ∀ s' ∈ skippedNext fin1 s, s' ∈ skippedCanonicalStates fin1 := by
    decide
  have hreach : ∀ s ∈ skippedCanonicalStates fin1, SkippedReachable fin1 s := by
    have hInit : SkippedReachable fin1 bfsInitialState := SkippedReachable.init
    have hC0 : SkippedReachable fin1 (checkState .FTRA) := SkippedReachable.step hInit (by decide)
    have hC2 : SkippedReachable fin1 (checkState .CedarOpa) := SkippedReachable.step hC0 (by decide)
    have hC3 : SkippedReachable fin1 (checkState .Sr26_2) := SkippedReachable.step hC2 (by decide)
    have hC4 : SkippedReachable fin1 (checkState .BayesianConsensus) := SkippedReachable.step hC3 (by decide)
    have hC5 : SkippedReachable fin1 (checkState .Cbf) := SkippedReachable.step hC4 (by decide)
    have hC6 : SkippedReachable fin1 (checkState .DebitLedger) := SkippedReachable.step hC5 (by decide)
    have hComp : SkippedReachable fin1 completedCheckState := SkippedReachable.step hC6 (by decide)
    have hD0 : SkippedReachable fin1 (directDenyState fin0) := SkippedReachable.step hC0 (by decide)
    have hD2 : SkippedReachable fin1 (directDenyState fin2) := SkippedReachable.step hC2 (by decide)
    have hD3 : SkippedReachable fin1 (directDenyState fin3) := SkippedReachable.step hC3 (by decide)
    have hD4 : SkippedReachable fin1 (directDenyState fin4) := SkippedReachable.step hC4 (by decide)
    have hD5 : SkippedReachable fin1 (directDenyState fin5) := SkippedReachable.step hC5 (by decide)
    have hD6 : SkippedReachable fin1 (directDenyState fin6) := SkippedReachable.step hC6 (by decide)
    have hN0 : SkippedReachable fin1 (narrowState fin0) := SkippedReachable.step hC0 (by decide)
    have hN1 : SkippedReachable fin1 (narrowState fin1) := SkippedReachable.step hN0 (by decide)
    have hN2 : SkippedReachable fin1 (narrowState fin2) := SkippedReachable.step hC2 (by decide)
    have hN3 : SkippedReachable fin1 (narrowState fin3) := SkippedReachable.step hC3 (by decide)
    have hN4 : SkippedReachable fin1 (narrowState fin4) := SkippedReachable.step hC4 (by decide)
    have hN5 : SkippedReachable fin1 (narrowState fin5) := SkippedReachable.step hC5 (by decide)
    have hN6 : SkippedReachable fin1 (narrowState fin6) := SkippedReachable.step hC6 (by decide)
    have hNR0 : SkippedReachable fin1 (narrowRerunDenyState fin0) := SkippedReachable.step hN0 (by decide)
    have hNR1 : SkippedReachable fin1 (narrowRerunDenyState fin1) := SkippedReachable.step hN1 (by decide)
    have hNR2 : SkippedReachable fin1 (narrowRerunDenyState fin2) := SkippedReachable.step hN2 (by decide)
    have hNR3 : SkippedReachable fin1 (narrowRerunDenyState fin3) := SkippedReachable.step hN3 (by decide)
    have hNR4 : SkippedReachable fin1 (narrowRerunDenyState fin4) := SkippedReachable.step hN4 (by decide)
    have hNR5 : SkippedReachable fin1 (narrowRerunDenyState fin5) := SkippedReachable.step hN5 (by decide)
    have hNR6 : SkippedReachable fin1 (narrowRerunDenyState fin6) := SkippedReachable.step hN6 (by decide)
    have hNP : SkippedReachable fin1 narrowPassedState := SkippedReachable.step hN6 (by decide)
    have hSI : SkippedReachable fin1 sealIssuedState := SkippedReachable.step hComp (by decide)
    have hSE : SkippedReachable fin1 sealExpiredState := SkippedReachable.step hSI (by decide)
    intro s hs
    change s ∈ ([ bfsInitialState
      , checkState .FTRA, checkState .CedarOpa, checkState .Sr26_2
      , checkState .BayesianConsensus, checkState .Cbf, checkState .DebitLedger
      , completedCheckState
      , directDenyState fin0, directDenyState fin2, directDenyState fin3
      , directDenyState fin4, directDenyState fin5, directDenyState fin6
      , narrowState fin0, narrowState fin1, narrowState fin2, narrowState fin3
      , narrowState fin4, narrowState fin5, narrowState fin6
      , narrowRerunDenyState fin0, narrowRerunDenyState fin1, narrowRerunDenyState fin2
      , narrowRerunDenyState fin3, narrowRerunDenyState fin4, narrowRerunDenyState fin5
      , narrowRerunDenyState fin6
      , narrowPassedState, sealIssuedState, sealExpiredState ] : List BfsState) at hs
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hs
    rcases hs with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals assumption
  intro s
  constructor
  · intro h
    induction h with
    | init => decide
    | step _ hstep ih => exact hcl _ ih _ hstep
  · exact hreach s

private theorem skipped_count_2 :
    (skippedCanonicalStates fin2).length = SKIPPED_TIER_REACHABLE_COUNT ∧
    (skippedCanonicalStates fin2).Nodup ∧
    (∀ s : BfsState, SkippedReachable fin2 s ↔ s ∈ skippedCanonicalStates fin2) := by
  refine ⟨rfl, by decide, ?_⟩
  have hcl : ∀ s ∈ skippedCanonicalStates fin2, ∀ s' ∈ skippedNext fin2 s, s' ∈ skippedCanonicalStates fin2 := by
    decide
  have hreach : ∀ s ∈ skippedCanonicalStates fin2, SkippedReachable fin2 s := by
    have hInit : SkippedReachable fin2 bfsInitialState := SkippedReachable.init
    have hC0 : SkippedReachable fin2 (checkState .FTRA) := SkippedReachable.step hInit (by decide)
    have hC1 : SkippedReachable fin2 (checkState .STPA) := SkippedReachable.step hC0 (by decide)
    have hC3 : SkippedReachable fin2 (checkState .Sr26_2) := SkippedReachable.step hC1 (by decide)
    have hC4 : SkippedReachable fin2 (checkState .BayesianConsensus) := SkippedReachable.step hC3 (by decide)
    have hC5 : SkippedReachable fin2 (checkState .Cbf) := SkippedReachable.step hC4 (by decide)
    have hC6 : SkippedReachable fin2 (checkState .DebitLedger) := SkippedReachable.step hC5 (by decide)
    have hComp : SkippedReachable fin2 completedCheckState := SkippedReachable.step hC6 (by decide)
    have hD0 : SkippedReachable fin2 (directDenyState fin0) := SkippedReachable.step hC0 (by decide)
    have hD1 : SkippedReachable fin2 (directDenyState fin1) := SkippedReachable.step hC1 (by decide)
    have hD3 : SkippedReachable fin2 (directDenyState fin3) := SkippedReachable.step hC3 (by decide)
    have hD4 : SkippedReachable fin2 (directDenyState fin4) := SkippedReachable.step hC4 (by decide)
    have hD5 : SkippedReachable fin2 (directDenyState fin5) := SkippedReachable.step hC5 (by decide)
    have hD6 : SkippedReachable fin2 (directDenyState fin6) := SkippedReachable.step hC6 (by decide)
    have hN0 : SkippedReachable fin2 (narrowState fin0) := SkippedReachable.step hC0 (by decide)
    have hN1 : SkippedReachable fin2 (narrowState fin1) := SkippedReachable.step hC1 (by decide)
    have hN2 : SkippedReachable fin2 (narrowState fin2) := SkippedReachable.step hN1 (by decide)
    have hN3 : SkippedReachable fin2 (narrowState fin3) := SkippedReachable.step hC3 (by decide)
    have hN4 : SkippedReachable fin2 (narrowState fin4) := SkippedReachable.step hC4 (by decide)
    have hN5 : SkippedReachable fin2 (narrowState fin5) := SkippedReachable.step hC5 (by decide)
    have hN6 : SkippedReachable fin2 (narrowState fin6) := SkippedReachable.step hC6 (by decide)
    have hNR0 : SkippedReachable fin2 (narrowRerunDenyState fin0) := SkippedReachable.step hN0 (by decide)
    have hNR1 : SkippedReachable fin2 (narrowRerunDenyState fin1) := SkippedReachable.step hN1 (by decide)
    have hNR2 : SkippedReachable fin2 (narrowRerunDenyState fin2) := SkippedReachable.step hN2 (by decide)
    have hNR3 : SkippedReachable fin2 (narrowRerunDenyState fin3) := SkippedReachable.step hN3 (by decide)
    have hNR4 : SkippedReachable fin2 (narrowRerunDenyState fin4) := SkippedReachable.step hN4 (by decide)
    have hNR5 : SkippedReachable fin2 (narrowRerunDenyState fin5) := SkippedReachable.step hN5 (by decide)
    have hNR6 : SkippedReachable fin2 (narrowRerunDenyState fin6) := SkippedReachable.step hN6 (by decide)
    have hNP : SkippedReachable fin2 narrowPassedState := SkippedReachable.step hN6 (by decide)
    have hSI : SkippedReachable fin2 sealIssuedState := SkippedReachable.step hComp (by decide)
    have hSE : SkippedReachable fin2 sealExpiredState := SkippedReachable.step hSI (by decide)
    intro s hs
    change s ∈ ([ bfsInitialState
      , checkState .FTRA, checkState .STPA, checkState .Sr26_2
      , checkState .BayesianConsensus, checkState .Cbf, checkState .DebitLedger
      , completedCheckState
      , directDenyState fin0, directDenyState fin1, directDenyState fin3
      , directDenyState fin4, directDenyState fin5, directDenyState fin6
      , narrowState fin0, narrowState fin1, narrowState fin2, narrowState fin3
      , narrowState fin4, narrowState fin5, narrowState fin6
      , narrowRerunDenyState fin0, narrowRerunDenyState fin1, narrowRerunDenyState fin2
      , narrowRerunDenyState fin3, narrowRerunDenyState fin4, narrowRerunDenyState fin5
      , narrowRerunDenyState fin6
      , narrowPassedState, sealIssuedState, sealExpiredState ] : List BfsState) at hs
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hs
    rcases hs with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals assumption
  intro s
  constructor
  · intro h
    induction h with
    | init => decide
    | step _ hstep ih => exact hcl _ ih _ hstep
  · exact hreach s

private theorem skipped_count_3 :
    (skippedCanonicalStates fin3).length = SKIPPED_TIER_REACHABLE_COUNT ∧
    (skippedCanonicalStates fin3).Nodup ∧
    (∀ s : BfsState, SkippedReachable fin3 s ↔ s ∈ skippedCanonicalStates fin3) := by
  refine ⟨rfl, by decide, ?_⟩
  have hcl : ∀ s ∈ skippedCanonicalStates fin3, ∀ s' ∈ skippedNext fin3 s, s' ∈ skippedCanonicalStates fin3 := by
    decide
  have hreach : ∀ s ∈ skippedCanonicalStates fin3, SkippedReachable fin3 s := by
    have hInit : SkippedReachable fin3 bfsInitialState := SkippedReachable.init
    have hC0 : SkippedReachable fin3 (checkState .FTRA) := SkippedReachable.step hInit (by decide)
    have hC1 : SkippedReachable fin3 (checkState .STPA) := SkippedReachable.step hC0 (by decide)
    have hC2 : SkippedReachable fin3 (checkState .CedarOpa) := SkippedReachable.step hC1 (by decide)
    have hC4 : SkippedReachable fin3 (checkState .BayesianConsensus) := SkippedReachable.step hC2 (by decide)
    have hC5 : SkippedReachable fin3 (checkState .Cbf) := SkippedReachable.step hC4 (by decide)
    have hC6 : SkippedReachable fin3 (checkState .DebitLedger) := SkippedReachable.step hC5 (by decide)
    have hComp : SkippedReachable fin3 completedCheckState := SkippedReachable.step hC6 (by decide)
    have hD0 : SkippedReachable fin3 (directDenyState fin0) := SkippedReachable.step hC0 (by decide)
    have hD1 : SkippedReachable fin3 (directDenyState fin1) := SkippedReachable.step hC1 (by decide)
    have hD2 : SkippedReachable fin3 (directDenyState fin2) := SkippedReachable.step hC2 (by decide)
    have hD4 : SkippedReachable fin3 (directDenyState fin4) := SkippedReachable.step hC4 (by decide)
    have hD5 : SkippedReachable fin3 (directDenyState fin5) := SkippedReachable.step hC5 (by decide)
    have hD6 : SkippedReachable fin3 (directDenyState fin6) := SkippedReachable.step hC6 (by decide)
    have hN0 : SkippedReachable fin3 (narrowState fin0) := SkippedReachable.step hC0 (by decide)
    have hN1 : SkippedReachable fin3 (narrowState fin1) := SkippedReachable.step hC1 (by decide)
    have hN2 : SkippedReachable fin3 (narrowState fin2) := SkippedReachable.step hC2 (by decide)
    have hN3 : SkippedReachable fin3 (narrowState fin3) := SkippedReachable.step hN2 (by decide)
    have hN4 : SkippedReachable fin3 (narrowState fin4) := SkippedReachable.step hC4 (by decide)
    have hN5 : SkippedReachable fin3 (narrowState fin5) := SkippedReachable.step hC5 (by decide)
    have hN6 : SkippedReachable fin3 (narrowState fin6) := SkippedReachable.step hC6 (by decide)
    have hNR0 : SkippedReachable fin3 (narrowRerunDenyState fin0) := SkippedReachable.step hN0 (by decide)
    have hNR1 : SkippedReachable fin3 (narrowRerunDenyState fin1) := SkippedReachable.step hN1 (by decide)
    have hNR2 : SkippedReachable fin3 (narrowRerunDenyState fin2) := SkippedReachable.step hN2 (by decide)
    have hNR3 : SkippedReachable fin3 (narrowRerunDenyState fin3) := SkippedReachable.step hN3 (by decide)
    have hNR4 : SkippedReachable fin3 (narrowRerunDenyState fin4) := SkippedReachable.step hN4 (by decide)
    have hNR5 : SkippedReachable fin3 (narrowRerunDenyState fin5) := SkippedReachable.step hN5 (by decide)
    have hNR6 : SkippedReachable fin3 (narrowRerunDenyState fin6) := SkippedReachable.step hN6 (by decide)
    have hNP : SkippedReachable fin3 narrowPassedState := SkippedReachable.step hN6 (by decide)
    have hSI : SkippedReachable fin3 sealIssuedState := SkippedReachable.step hComp (by decide)
    have hSE : SkippedReachable fin3 sealExpiredState := SkippedReachable.step hSI (by decide)
    intro s hs
    change s ∈ ([ bfsInitialState
      , checkState .FTRA, checkState .STPA, checkState .CedarOpa
      , checkState .BayesianConsensus, checkState .Cbf, checkState .DebitLedger
      , completedCheckState
      , directDenyState fin0, directDenyState fin1, directDenyState fin2
      , directDenyState fin4, directDenyState fin5, directDenyState fin6
      , narrowState fin0, narrowState fin1, narrowState fin2, narrowState fin3
      , narrowState fin4, narrowState fin5, narrowState fin6
      , narrowRerunDenyState fin0, narrowRerunDenyState fin1, narrowRerunDenyState fin2
      , narrowRerunDenyState fin3, narrowRerunDenyState fin4, narrowRerunDenyState fin5
      , narrowRerunDenyState fin6
      , narrowPassedState, sealIssuedState, sealExpiredState ] : List BfsState) at hs
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hs
    rcases hs with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals assumption
  intro s
  constructor
  · intro h
    induction h with
    | init => decide
    | step _ hstep ih => exact hcl _ ih _ hstep
  · exact hreach s

private theorem skipped_count_4 :
    (skippedCanonicalStates fin4).length = SKIPPED_TIER_REACHABLE_COUNT ∧
    (skippedCanonicalStates fin4).Nodup ∧
    (∀ s : BfsState, SkippedReachable fin4 s ↔ s ∈ skippedCanonicalStates fin4) := by
  refine ⟨rfl, by decide, ?_⟩
  have hcl : ∀ s ∈ skippedCanonicalStates fin4, ∀ s' ∈ skippedNext fin4 s, s' ∈ skippedCanonicalStates fin4 := by
    decide
  have hreach : ∀ s ∈ skippedCanonicalStates fin4, SkippedReachable fin4 s := by
    have hInit : SkippedReachable fin4 bfsInitialState := SkippedReachable.init
    have hC0 : SkippedReachable fin4 (checkState .FTRA) := SkippedReachable.step hInit (by decide)
    have hC1 : SkippedReachable fin4 (checkState .STPA) := SkippedReachable.step hC0 (by decide)
    have hC2 : SkippedReachable fin4 (checkState .CedarOpa) := SkippedReachable.step hC1 (by decide)
    have hC3 : SkippedReachable fin4 (checkState .Sr26_2) := SkippedReachable.step hC2 (by decide)
    have hC5 : SkippedReachable fin4 (checkState .Cbf) := SkippedReachable.step hC3 (by decide)
    have hC6 : SkippedReachable fin4 (checkState .DebitLedger) := SkippedReachable.step hC5 (by decide)
    have hComp : SkippedReachable fin4 completedCheckState := SkippedReachable.step hC6 (by decide)
    have hD0 : SkippedReachable fin4 (directDenyState fin0) := SkippedReachable.step hC0 (by decide)
    have hD1 : SkippedReachable fin4 (directDenyState fin1) := SkippedReachable.step hC1 (by decide)
    have hD2 : SkippedReachable fin4 (directDenyState fin2) := SkippedReachable.step hC2 (by decide)
    have hD3 : SkippedReachable fin4 (directDenyState fin3) := SkippedReachable.step hC3 (by decide)
    have hD5 : SkippedReachable fin4 (directDenyState fin5) := SkippedReachable.step hC5 (by decide)
    have hD6 : SkippedReachable fin4 (directDenyState fin6) := SkippedReachable.step hC6 (by decide)
    have hN0 : SkippedReachable fin4 (narrowState fin0) := SkippedReachable.step hC0 (by decide)
    have hN1 : SkippedReachable fin4 (narrowState fin1) := SkippedReachable.step hC1 (by decide)
    have hN2 : SkippedReachable fin4 (narrowState fin2) := SkippedReachable.step hC2 (by decide)
    have hN3 : SkippedReachable fin4 (narrowState fin3) := SkippedReachable.step hC3 (by decide)
    have hN4 : SkippedReachable fin4 (narrowState fin4) := SkippedReachable.step hN3 (by decide)
    have hN5 : SkippedReachable fin4 (narrowState fin5) := SkippedReachable.step hC5 (by decide)
    have hN6 : SkippedReachable fin4 (narrowState fin6) := SkippedReachable.step hC6 (by decide)
    have hNR0 : SkippedReachable fin4 (narrowRerunDenyState fin0) := SkippedReachable.step hN0 (by decide)
    have hNR1 : SkippedReachable fin4 (narrowRerunDenyState fin1) := SkippedReachable.step hN1 (by decide)
    have hNR2 : SkippedReachable fin4 (narrowRerunDenyState fin2) := SkippedReachable.step hN2 (by decide)
    have hNR3 : SkippedReachable fin4 (narrowRerunDenyState fin3) := SkippedReachable.step hN3 (by decide)
    have hNR4 : SkippedReachable fin4 (narrowRerunDenyState fin4) := SkippedReachable.step hN4 (by decide)
    have hNR5 : SkippedReachable fin4 (narrowRerunDenyState fin5) := SkippedReachable.step hN5 (by decide)
    have hNR6 : SkippedReachable fin4 (narrowRerunDenyState fin6) := SkippedReachable.step hN6 (by decide)
    have hNP : SkippedReachable fin4 narrowPassedState := SkippedReachable.step hN6 (by decide)
    have hSI : SkippedReachable fin4 sealIssuedState := SkippedReachable.step hComp (by decide)
    have hSE : SkippedReachable fin4 sealExpiredState := SkippedReachable.step hSI (by decide)
    intro s hs
    change s ∈ ([ bfsInitialState
      , checkState .FTRA, checkState .STPA, checkState .CedarOpa, checkState .Sr26_2
      , checkState .Cbf, checkState .DebitLedger
      , completedCheckState
      , directDenyState fin0, directDenyState fin1, directDenyState fin2, directDenyState fin3
      , directDenyState fin5, directDenyState fin6
      , narrowState fin0, narrowState fin1, narrowState fin2, narrowState fin3
      , narrowState fin4, narrowState fin5, narrowState fin6
      , narrowRerunDenyState fin0, narrowRerunDenyState fin1, narrowRerunDenyState fin2
      , narrowRerunDenyState fin3, narrowRerunDenyState fin4, narrowRerunDenyState fin5
      , narrowRerunDenyState fin6
      , narrowPassedState, sealIssuedState, sealExpiredState ] : List BfsState) at hs
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hs
    rcases hs with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals assumption
  intro s
  constructor
  · intro h
    induction h with
    | init => decide
    | step _ hstep ih => exact hcl _ ih _ hstep
  · exact hreach s

private theorem skipped_count_5 :
    (skippedCanonicalStates fin5).length = SKIPPED_TIER_REACHABLE_COUNT ∧
    (skippedCanonicalStates fin5).Nodup ∧
    (∀ s : BfsState, SkippedReachable fin5 s ↔ s ∈ skippedCanonicalStates fin5) := by
  refine ⟨rfl, by decide, ?_⟩
  have hcl : ∀ s ∈ skippedCanonicalStates fin5, ∀ s' ∈ skippedNext fin5 s, s' ∈ skippedCanonicalStates fin5 := by
    decide
  have hreach : ∀ s ∈ skippedCanonicalStates fin5, SkippedReachable fin5 s := by
    have hInit : SkippedReachable fin5 bfsInitialState := SkippedReachable.init
    have hC0 : SkippedReachable fin5 (checkState .FTRA) := SkippedReachable.step hInit (by decide)
    have hC1 : SkippedReachable fin5 (checkState .STPA) := SkippedReachable.step hC0 (by decide)
    have hC2 : SkippedReachable fin5 (checkState .CedarOpa) := SkippedReachable.step hC1 (by decide)
    have hC3 : SkippedReachable fin5 (checkState .Sr26_2) := SkippedReachable.step hC2 (by decide)
    have hC4 : SkippedReachable fin5 (checkState .BayesianConsensus) := SkippedReachable.step hC3 (by decide)
    have hC6 : SkippedReachable fin5 (checkState .DebitLedger) := SkippedReachable.step hC4 (by decide)
    have hComp : SkippedReachable fin5 completedCheckState := SkippedReachable.step hC6 (by decide)
    have hD0 : SkippedReachable fin5 (directDenyState fin0) := SkippedReachable.step hC0 (by decide)
    have hD1 : SkippedReachable fin5 (directDenyState fin1) := SkippedReachable.step hC1 (by decide)
    have hD2 : SkippedReachable fin5 (directDenyState fin2) := SkippedReachable.step hC2 (by decide)
    have hD3 : SkippedReachable fin5 (directDenyState fin3) := SkippedReachable.step hC3 (by decide)
    have hD4 : SkippedReachable fin5 (directDenyState fin4) := SkippedReachable.step hC4 (by decide)
    have hD6 : SkippedReachable fin5 (directDenyState fin6) := SkippedReachable.step hC6 (by decide)
    have hN0 : SkippedReachable fin5 (narrowState fin0) := SkippedReachable.step hC0 (by decide)
    have hN1 : SkippedReachable fin5 (narrowState fin1) := SkippedReachable.step hC1 (by decide)
    have hN2 : SkippedReachable fin5 (narrowState fin2) := SkippedReachable.step hC2 (by decide)
    have hN3 : SkippedReachable fin5 (narrowState fin3) := SkippedReachable.step hC3 (by decide)
    have hN4 : SkippedReachable fin5 (narrowState fin4) := SkippedReachable.step hC4 (by decide)
    have hN5 : SkippedReachable fin5 (narrowState fin5) := SkippedReachable.step hN4 (by decide)
    have hN6 : SkippedReachable fin5 (narrowState fin6) := SkippedReachable.step hC6 (by decide)
    have hNR0 : SkippedReachable fin5 (narrowRerunDenyState fin0) := SkippedReachable.step hN0 (by decide)
    have hNR1 : SkippedReachable fin5 (narrowRerunDenyState fin1) := SkippedReachable.step hN1 (by decide)
    have hNR2 : SkippedReachable fin5 (narrowRerunDenyState fin2) := SkippedReachable.step hN2 (by decide)
    have hNR3 : SkippedReachable fin5 (narrowRerunDenyState fin3) := SkippedReachable.step hN3 (by decide)
    have hNR4 : SkippedReachable fin5 (narrowRerunDenyState fin4) := SkippedReachable.step hN4 (by decide)
    have hNR5 : SkippedReachable fin5 (narrowRerunDenyState fin5) := SkippedReachable.step hN5 (by decide)
    have hNR6 : SkippedReachable fin5 (narrowRerunDenyState fin6) := SkippedReachable.step hN6 (by decide)
    have hNP : SkippedReachable fin5 narrowPassedState := SkippedReachable.step hN6 (by decide)
    have hSI : SkippedReachable fin5 sealIssuedState := SkippedReachable.step hComp (by decide)
    have hSE : SkippedReachable fin5 sealExpiredState := SkippedReachable.step hSI (by decide)
    intro s hs
    change s ∈ ([ bfsInitialState
      , checkState .FTRA, checkState .STPA, checkState .CedarOpa, checkState .Sr26_2
      , checkState .BayesianConsensus, checkState .DebitLedger
      , completedCheckState
      , directDenyState fin0, directDenyState fin1, directDenyState fin2, directDenyState fin3
      , directDenyState fin4, directDenyState fin6
      , narrowState fin0, narrowState fin1, narrowState fin2, narrowState fin3
      , narrowState fin4, narrowState fin5, narrowState fin6
      , narrowRerunDenyState fin0, narrowRerunDenyState fin1, narrowRerunDenyState fin2
      , narrowRerunDenyState fin3, narrowRerunDenyState fin4, narrowRerunDenyState fin5
      , narrowRerunDenyState fin6
      , narrowPassedState, sealIssuedState, sealExpiredState ] : List BfsState) at hs
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hs
    rcases hs with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals assumption
  intro s
  constructor
  · intro h
    induction h with
    | init => decide
    | step _ hstep ih => exact hcl _ ih _ hstep
  · exact hreach s

private theorem skipped_count_6 :
    (skippedCanonicalStates fin6).length = SKIPPED_TIER_REACHABLE_COUNT ∧
    (skippedCanonicalStates fin6).Nodup ∧
    (∀ s : BfsState, SkippedReachable fin6 s ↔ s ∈ skippedCanonicalStates fin6) := by
  refine ⟨rfl, by decide, ?_⟩
  have hcl : ∀ s ∈ skippedCanonicalStates fin6, ∀ s' ∈ skippedNext fin6 s, s' ∈ skippedCanonicalStates fin6 := by
    decide
  have hreach : ∀ s ∈ skippedCanonicalStates fin6, SkippedReachable fin6 s := by
    have hInit : SkippedReachable fin6 bfsInitialState := SkippedReachable.init
    have hC0 : SkippedReachable fin6 (checkState .FTRA) := SkippedReachable.step hInit (by decide)
    have hC1 : SkippedReachable fin6 (checkState .STPA) := SkippedReachable.step hC0 (by decide)
    have hC2 : SkippedReachable fin6 (checkState .CedarOpa) := SkippedReachable.step hC1 (by decide)
    have hC3 : SkippedReachable fin6 (checkState .Sr26_2) := SkippedReachable.step hC2 (by decide)
    have hC4 : SkippedReachable fin6 (checkState .BayesianConsensus) := SkippedReachable.step hC3 (by decide)
    have hC5 : SkippedReachable fin6 (checkState .Cbf) := SkippedReachable.step hC4 (by decide)
    have hComp : SkippedReachable fin6 completedCheckState := SkippedReachable.step hC5 (by decide)
    have hD0 : SkippedReachable fin6 (directDenyState fin0) := SkippedReachable.step hC0 (by decide)
    have hD1 : SkippedReachable fin6 (directDenyState fin1) := SkippedReachable.step hC1 (by decide)
    have hD2 : SkippedReachable fin6 (directDenyState fin2) := SkippedReachable.step hC2 (by decide)
    have hD3 : SkippedReachable fin6 (directDenyState fin3) := SkippedReachable.step hC3 (by decide)
    have hD4 : SkippedReachable fin6 (directDenyState fin4) := SkippedReachable.step hC4 (by decide)
    have hD5 : SkippedReachable fin6 (directDenyState fin5) := SkippedReachable.step hC5 (by decide)
    have hN0 : SkippedReachable fin6 (narrowState fin0) := SkippedReachable.step hC0 (by decide)
    have hN1 : SkippedReachable fin6 (narrowState fin1) := SkippedReachable.step hC1 (by decide)
    have hN2 : SkippedReachable fin6 (narrowState fin2) := SkippedReachable.step hC2 (by decide)
    have hN3 : SkippedReachable fin6 (narrowState fin3) := SkippedReachable.step hC3 (by decide)
    have hN4 : SkippedReachable fin6 (narrowState fin4) := SkippedReachable.step hC4 (by decide)
    have hN5 : SkippedReachable fin6 (narrowState fin5) := SkippedReachable.step hC5 (by decide)
    have hN6 : SkippedReachable fin6 (narrowState fin6) := SkippedReachable.step hN5 (by decide)
    have hNR0 : SkippedReachable fin6 (narrowRerunDenyState fin0) := SkippedReachable.step hN0 (by decide)
    have hNR1 : SkippedReachable fin6 (narrowRerunDenyState fin1) := SkippedReachable.step hN1 (by decide)
    have hNR2 : SkippedReachable fin6 (narrowRerunDenyState fin2) := SkippedReachable.step hN2 (by decide)
    have hNR3 : SkippedReachable fin6 (narrowRerunDenyState fin3) := SkippedReachable.step hN3 (by decide)
    have hNR4 : SkippedReachable fin6 (narrowRerunDenyState fin4) := SkippedReachable.step hN4 (by decide)
    have hNR5 : SkippedReachable fin6 (narrowRerunDenyState fin5) := SkippedReachable.step hN5 (by decide)
    have hNR6 : SkippedReachable fin6 (narrowRerunDenyState fin6) := SkippedReachable.step hN6 (by decide)
    have hNP : SkippedReachable fin6 narrowPassedState := SkippedReachable.step hN6 (by decide)
    have hSI : SkippedReachable fin6 sealIssuedState := SkippedReachable.step hComp (by decide)
    have hSE : SkippedReachable fin6 sealExpiredState := SkippedReachable.step hSI (by decide)
    intro s hs
    change s ∈ ([ bfsInitialState
      , checkState .FTRA, checkState .STPA, checkState .CedarOpa, checkState .Sr26_2
      , checkState .BayesianConsensus, checkState .Cbf
      , completedCheckState
      , directDenyState fin0, directDenyState fin1, directDenyState fin2, directDenyState fin3
      , directDenyState fin4, directDenyState fin5
      , narrowState fin0, narrowState fin1, narrowState fin2, narrowState fin3
      , narrowState fin4, narrowState fin5, narrowState fin6
      , narrowRerunDenyState fin0, narrowRerunDenyState fin1, narrowRerunDenyState fin2
      , narrowRerunDenyState fin3, narrowRerunDenyState fin4, narrowRerunDenyState fin5
      , narrowRerunDenyState fin6
      , narrowPassedState, sealIssuedState, sealExpiredState ] : List BfsState) at hs
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hs
    rcases hs with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals assumption
  intro s
  constructor
  · intro h
    induction h with
    | init => decide
    | step _ hstep ih => exact hcl _ ih _ hstep
  · exact hreach s

/-- Theorem: For every `skipTier : Fin 7`, the skipped-tier BFS has exactly 31 distinct reachable states. -/
theorem skipped_bfs_state_count_31 (skipTier : Fin 7) :
    (skippedCanonicalStates skipTier).length = SKIPPED_TIER_REACHABLE_COUNT ∧
    (skippedCanonicalStates skipTier).Nodup ∧
    (∀ s : BfsState, SkippedReachable skipTier s ↔ s ∈ skippedCanonicalStates skipTier) := by
  rcases skipTier with ⟨v, hv⟩
  match v with
  | 0 => exact skipped_count_0
  | 1 => exact skipped_count_1
  | 2 => exact skipped_count_2
  | 3 => exact skipped_count_3
  | 4 => exact skipped_count_4
  | 5 => exact skipped_count_5
  | 6 => exact skipped_count_6
  | _ + 7 => exact False.elim (by omega)

/-! ### Part 3: `CageRoutingSeal` (`routing_seal.rs`) -/

def isAsciiHexChar (c : Char) : Bool :=
  let n := c.toNat
  (48 ≤ n && n ≤ 57) || (97 ≤ n && n ≤ 102) || (65 ≤ n && n ≤ 70)

def isLowerHexChar (c : Char) : Bool :=
  let n := c.toNat
  (48 ≤ n && n ≤ 57) || (97 ≤ n && n ≤ 102)

structure CageRoutingSeal where
  sealId : String
  policyVersionId : String
  actionDigest : String
  recordHash : String
  issuedAt : Nat
  expiresAt : Nat
  signature : String
  deriving DecidableEq, Repr

instance : BEq CageRoutingSeal where
  beq a b := decide (a = b)

instance : LawfulBEq CageRoutingSeal where
  eq_of_beq h := of_decide_eq_true h
  rfl := decide_eq_true rfl

def CageRoutingSeal.isExpired (rseal : CageRoutingSeal) (currentTime : Nat) : Bool :=
  (currentTime > rseal.expiresAt) || (currentTime > rseal.issuedAt + ROUTING_SEAL_TTL_SECS)

def CageRoutingSeal.validateFormat (rseal : CageRoutingSeal) : Bool :=
  rseal.policyVersionId.length == 16 &&
  rseal.policyVersionId.toList.all isAsciiHexChar &&
  rseal.actionDigest.length == 64 &&
  rseal.actionDigest.toList.all isLowerHexChar &&
  rseal.recordHash.length == 64 &&
  rseal.recordHash.toList.all isLowerHexChar &&
  !rseal.sealId.isEmpty &&
  !rseal.signature.isEmpty &&
  (rseal.expiresAt == rseal.issuedAt + ROUTING_SEAL_TTL_SECS)

inductive SealRejection : Type where
  | InvalidSignature
  | Expired (currentTime expiresAt : Nat)
  | FutureTimestamp (currentTime issuedAt : Nat)
  | AlreadyConsumed (sealId : String)
  | PolicyVersionMismatch (expected actual : String)
  | ActionDigestMismatch (expected actual : String)
  | RecordHashMismatch (expected actual : String)
  | UnanchoredEvidence (detail : String)
  | MalformedSeal (detail : String)
  deriving DecidableEq, Repr

structure RoutingSealStore where
  activePolicyVersion : String
  consumedSeals : List (String × Nat)
  lastPruneTime : Nat
  deriving DecidableEq, Repr

def pruneSealEntries (entries : List (String × Nat)) (currentTime : Nat) : List (String × Nat) :=
  entries.filter (fun p => p.2 + CLOCK_DRIFT_TOLERANCE_SECS ≥ currentTime)

def validateAndConsume
    (sigValid : CageRoutingSeal → Bool)
    (store : RoutingSealStore)
    (rseal : CageRoutingSeal)
    (expectedActionDigest expectedRecordHash : String)
    (currentTime : Nat) : Except SealRejection RoutingSealStore :=
  if !rseal.validateFormat then
    .error (.MalformedSeal "format")
  else if rseal.expiresAt != rseal.issuedAt + ROUTING_SEAL_TTL_SECS then
    .error (.MalformedSeal "ttl")
  else if rseal.policyVersionId != store.activePolicyVersion then
    .error (.PolicyVersionMismatch store.activePolicyVersion rseal.policyVersionId)
  else if rseal.actionDigest != expectedActionDigest then
    .error (.ActionDigestMismatch expectedActionDigest rseal.actionDigest)
  else if rseal.recordHash != expectedRecordHash then
    .error (.RecordHashMismatch expectedRecordHash rseal.recordHash)
  else if rseal.issuedAt > currentTime + CLOCK_DRIFT_TOLERANCE_SECS then
    .error (.FutureTimestamp currentTime rseal.issuedAt)
  else if currentTime > rseal.expiresAt || currentTime > rseal.issuedAt + ROUTING_SEAL_TTL_SECS then
    .error (.Expired currentTime rseal.expiresAt)
  else if !sigValid rseal then
    .error .InvalidSignature
  else
    let pruned :=
      if currentTime > store.lastPruneTime || store.consumedSeals.length > 1024 then
        pruneSealEntries store.consumedSeals currentTime
      else
        store.consumedSeals
    let nextLastPrune :=
      if currentTime > store.lastPruneTime || store.consumedSeals.length > 1024 then
        currentTime
      else
        store.lastPruneTime
    if pruned.any (fun p => p.1 == rseal.sealId) then
      .error (.AlreadyConsumed rseal.sealId)
    else
      .ok { store with
            consumedSeals := (rseal.sealId, rseal.expiresAt) :: pruned
            lastPruneTime := nextLastPrune }

def pruneExpiredStore (store : RoutingSealStore) (currentTime : Nat) : RoutingSealStore :=
  { store with
    consumedSeals := pruneSealEntries store.consumedSeals currentTime
    lastPruneTime := currentTime }

inductive SealStoreReachable (sigValid : CageRoutingSeal → Bool) :
    Nat → RoutingSealStore → Nat → RoutingSealStore → Prop where
  | refl (t : Nat) (st : RoutingSealStore) :
      SealStoreReachable sigValid t st t st
  | consume {t0 t1 t2 : Nat} {st0 st1 st2 : RoutingSealStore}
      (rseal : CageRoutingSeal) (expDig expRec : String) :
      SealStoreReachable sigValid t0 st0 t1 st1 →
      t1 ≤ t2 →
      validateAndConsume sigValid st1 rseal expDig expRec t2 = .ok st2 →
      SealStoreReachable sigValid t0 st0 t2 st2
  | prune {t0 t1 t2 : Nat} {st0 st1 : RoutingSealStore} :
      SealStoreReachable sigValid t0 st0 t1 st1 →
      t1 ≤ t2 →
      SealStoreReachable sigValid t0 st0 t2 (pruneExpiredStore st1 t2)

private theorem any_fst_beq_iff (sid : String) :
    ∀ (xs : List (String × Nat)), xs.any (fun p => p.1 == sid) = true ↔ ∃ exp, (sid, exp) ∈ xs
  | [] => by
    rw [List.any_nil]
    constructor
    · intro h; cases h
    · intro h; rcases h with ⟨_, hm⟩; cases hm
  | (k, v) :: xs => by
    rw [List.any_cons, Bool.or_eq_true, beq_iff_eq]
    have ih := any_fst_beq_iff sid xs
    constructor
    · intro h
      cases h with
      | inl hk =>
        subst hk
        exact ⟨v, List.Mem.head xs⟩
      | inr hxs =>
        rcases ih.mp hxs with ⟨exp, hm⟩
        exact ⟨exp, List.Mem.tail (k, v) hm⟩
    · intro h
      rcases h with ⟨exp, hm⟩
      cases hm with
      | head => exact Or.inl rfl
      | tail _ hm' => exact Or.inr (ih.mpr ⟨exp, hm'⟩)

private theorem mem_pruneSealEntries_iff (entries : List (String × Nat)) (t : Nat) (p : String × Nat) :
    p ∈ pruneSealEntries entries t ↔ p ∈ entries ∧ p.2 + CLOCK_DRIFT_TOLERANCE_SECS ≥ t := by
  unfold pruneSealEntries
  rw [List.mem_filter]
  simp only [decide_eq_true_eq]

private theorem seal_store_trace_tracks_consumed
    (sigValid : CageRoutingSeal → Bool)
    {t0 t2 : Nat} {st0 st2 : RoutingSealStore}
    (hTrace : SealStoreReachable sigValid t0 st0 t2 st2)
    {sid : String} {exp : Nat}
    (hTracked : (sid, exp) ∈ st0.consumedSeals ∨ exp + CLOCK_DRIFT_TOLERANCE_SECS < t0) :
    (sid, exp) ∈ st2.consumedSeals ∨ exp + CLOCK_DRIFT_TOLERANCE_SECS < t2 := by
  induction hTrace with
  | refl => exact hTracked
  | @consume t1 t2' _ st1 st2' rseal' expDig' expRec' _ hMono12 hOk ih =>
    have ih' := ih hTracked
    cases ih' with
    | inr hPast => exact Or.inr (Nat.lt_of_lt_of_le hPast hMono12)
    | inl hMem1 =>
      unfold validateAndConsume at hOk
      split at hOk <;> try cases hOk
      split at hOk <;> try cases hOk
      split at hOk <;> try cases hOk
      split at hOk <;> try cases hOk
      split at hOk <;> try cases hOk
      split at hOk <;> try cases hOk
      split at hOk <;> try cases hOk
      split at hOk <;> try cases hOk
      dsimp only at hOk
      by_cases hAny : ((if t2' > st1.lastPruneTime || st1.consumedSeals.length > 1024 then
          pruneSealEntries st1.consumedSeals t2'
        else
          st1.consumedSeals).any (fun p => p.1 == rseal'.sealId)) = true
      · simp only [eq_true hAny, ite_true] at hOk; cases hOk
      · simp only [eq_false hAny, ite_false] at hOk
        injection hOk with hEq
        subst hEq
        by_cases hcond : (t2' > st1.lastPruneTime || st1.consumedSeals.length > 1024) = true
        · simp only [eq_true hcond, ite_true]
          by_cases hKeep : exp + CLOCK_DRIFT_TOLERANCE_SECS ≥ t2'
          · left
            apply List.Mem.tail
            exact (mem_pruneSealEntries_iff st1.consumedSeals t2' (sid, exp)).mpr ⟨hMem1, hKeep⟩
          · right
            omega
        · simp only [eq_false hcond, ite_false]
          exact Or.inl (List.Mem.tail _ hMem1)
  | @prune t1 t2' _ st1 _ hMono12 ih =>
    have ih' := ih hTracked
    cases ih' with
    | inr hPast => exact Or.inr (Nat.lt_of_lt_of_le hPast hMono12)
    | inl hMem1 =>
      unfold pruneExpiredStore
      dsimp only
      by_cases hKeep : exp + CLOCK_DRIFT_TOLERANCE_SECS ≥ t2'
      · left
        exact (mem_pruneSealEntries_iff st1.consumedSeals t2' (sid, exp)).mpr ⟨hMem1, hKeep⟩
      · right
        omega

/-- Theorem: A validly consumed `CageRoutingSeal` satisfies exact 30s TTL and clock-drift bounds,
    binds policy version / action digest / record hash / signature, and CANNOT succeed on any
    subsequent `validateAndConsume` at `t2 ≥ t1` (either `AlreadyConsumed` or `Expired` if pruned). -/
theorem seal_single_use_and_ttl
    (sigValid : CageRoutingSeal → Bool)
    (store0 store1 store2 : RoutingSealStore)
    (rseal : CageRoutingSeal)
    (expDigest1 expRec1 expDigest2 expRec2 : String)
    (t1 t2 : Nat)
    (hConsume : validateAndConsume sigValid store0 rseal expDigest1 expRec1 t1 = .ok store1)
    (_hMono : t1 ≤ t2)
    (hTrace : SealStoreReachable sigValid t1 store1 t2 store2) :
    rseal.expiresAt = rseal.issuedAt + ROUTING_SEAL_TTL_SECS ∧
    rseal.issuedAt ≤ t1 + CLOCK_DRIFT_TOLERANCE_SECS ∧
    t1 ≤ rseal.expiresAt ∧
    rseal.policyVersionId = store0.activePolicyVersion ∧
    rseal.actionDigest = expDigest1 ∧
    rseal.recordHash = expRec1 ∧
    sigValid rseal = true ∧
    (∃ err : SealRejection,
      validateAndConsume sigValid store2 rseal expDigest2 expRec2 t2 = .error err) := by
  have hCopy := hConsume
  unfold validateAndConsume at hCopy
  by_cases hf : (!rseal.validateFormat) = true
  · simp only [eq_true hf, ite_true] at hCopy; cases hCopy
  · simp only [eq_false hf, ite_false] at hCopy
    by_cases httl : (rseal.expiresAt != rseal.issuedAt + ROUTING_SEAL_TTL_SECS) = true
    · simp only [eq_true httl, ite_true] at hCopy; cases hCopy
    · have httlF : (rseal.expiresAt != rseal.issuedAt + ROUTING_SEAL_TTL_SECS) = false := by
        cases hb : (rseal.expiresAt != rseal.issuedAt + ROUTING_SEAL_TTL_SECS) with
        | false => rfl | true => exact False.elim (httl hb)
      simp only [eq_false httl, ite_false] at hCopy
      have hTtlEq : rseal.expiresAt = rseal.issuedAt + ROUTING_SEAL_TTL_SECS := by
        by_cases heq : rseal.expiresAt = rseal.issuedAt + ROUTING_SEAL_TTL_SECS
        · exact heq
        · have ht : (rseal.expiresAt != rseal.issuedAt + ROUTING_SEAL_TTL_SECS) = true := bne_iff_ne.mpr heq
          rw [ht] at httlF; cases httlF
      by_cases hpol : (rseal.policyVersionId != store0.activePolicyVersion) = true
      · simp only [eq_true hpol, ite_true] at hCopy; cases hCopy
      · have hpolF : (rseal.policyVersionId != store0.activePolicyVersion) = false := by
          cases hb : (rseal.policyVersionId != store0.activePolicyVersion) with
          | false => rfl | true => exact False.elim (hpol hb)
        simp only [eq_false hpol, ite_false] at hCopy
        have hPolEq : rseal.policyVersionId = store0.activePolicyVersion := by
          by_cases heq : rseal.policyVersionId = store0.activePolicyVersion
          · exact heq
          · have ht : (rseal.policyVersionId != store0.activePolicyVersion) = true := bne_iff_ne.mpr heq
            rw [ht] at hpolF; cases hpolF
        by_cases hdig : (rseal.actionDigest != expDigest1) = true
        · simp only [eq_true hdig, ite_true] at hCopy; cases hCopy
        · have hdigF : (rseal.actionDigest != expDigest1) = false := by
            cases hb : (rseal.actionDigest != expDigest1) with
            | false => rfl | true => exact False.elim (hdig hb)
          simp only [eq_false hdig, ite_false] at hCopy
          have hDigEq : rseal.actionDigest = expDigest1 := by
            by_cases heq : rseal.actionDigest = expDigest1
            · exact heq
            · have ht : (rseal.actionDigest != expDigest1) = true := bne_iff_ne.mpr heq
              rw [ht] at hdigF; cases hdigF
          by_cases hrec : (rseal.recordHash != expRec1) = true
          · simp only [eq_true hrec, ite_true] at hCopy; cases hCopy
          · have hrecF : (rseal.recordHash != expRec1) = false := by
              cases hb : (rseal.recordHash != expRec1) with
              | false => rfl | true => exact False.elim (hrec hb)
            simp only [eq_false hrec, ite_false] at hCopy
            have hRecEq : rseal.recordHash = expRec1 := by
              by_cases heq : rseal.recordHash = expRec1
              · exact heq
              · have ht : (rseal.recordHash != expRec1) = true := bne_iff_ne.mpr heq
                rw [ht] at hrecF; cases hrecF
            by_cases hfut : rseal.issuedAt > t1 + CLOCK_DRIFT_TOLERANCE_SECS
            · simp only [eq_true hfut, ite_true] at hCopy; cases hCopy
            · simp only [eq_false hfut, ite_false] at hCopy
              have hIssuedBound : rseal.issuedAt ≤ t1 + CLOCK_DRIFT_TOLERANCE_SECS := Nat.le_of_not_gt hfut
              by_cases hexp : (t1 > rseal.expiresAt || t1 > rseal.issuedAt + ROUTING_SEAL_TTL_SECS) = true
              · simp only [eq_true hexp, ite_true] at hCopy; cases hCopy
              · have hexpF : (t1 > rseal.expiresAt || t1 > rseal.issuedAt + ROUTING_SEAL_TTL_SECS) = false := by
                  cases hb : (t1 > rseal.expiresAt || t1 > rseal.issuedAt + ROUTING_SEAL_TTL_SECS) with
                  | false => rfl | true => exact False.elim (hexp hb)
                simp only [eq_false hexp, ite_false] at hCopy
                have hT1Bound : t1 ≤ rseal.expiresAt := by
                  by_cases hgt : t1 > rseal.expiresAt
                  · have ht : (t1 > rseal.expiresAt || t1 > rseal.issuedAt + ROUTING_SEAL_TTL_SECS) = true := by
                      simp [hgt]
                    rw [ht] at hexpF; cases hexpF
                  · exact Nat.le_of_not_gt hgt
                by_cases hsig : (!sigValid rseal) = true
                · simp only [eq_true hsig, ite_true] at hCopy; cases hCopy
                · have hsigF : (!sigValid rseal) = false := by
                    cases hb : (!sigValid rseal) with
                    | false => rfl | true => exact False.elim (hsig hb)
                  simp only [eq_false hsig, ite_false] at hCopy
                  have hSigTrue : sigValid rseal = true := by
                    cases hb : sigValid rseal with
                    | true => rfl
                    | false => simp [hb] at hsigF
                  have hMem1 : (rseal.sealId, rseal.expiresAt) ∈ store1.consumedSeals := by
                    by_cases hAny0 : ((if t1 > store0.lastPruneTime || store0.consumedSeals.length > 1024 then
                        pruneSealEntries store0.consumedSeals t1
                      else
                        store0.consumedSeals).any (fun p => p.1 == rseal.sealId)) = true
                    · simp only [eq_true hAny0, ite_true] at hCopy; cases hCopy
                    · simp only [eq_false hAny0, ite_false] at hCopy
                      injection hCopy with hSt1
                      rw [← hSt1]
                      exact List.Mem.head _
                  have hTracked2 := seal_store_trace_tracks_consumed sigValid hTrace (Or.inl hMem1)
                  refine ⟨hTtlEq, hIssuedBound, hT1Bound, hPolEq, hDigEq, hRecEq, hSigTrue, ?_⟩
                  unfold validateAndConsume
                  by_cases h1 : (!rseal.validateFormat) = true
                  · simp only [eq_true h1, ite_true]; exact ⟨_, rfl⟩
                  · simp only [eq_false h1, ite_false]
                    by_cases h2 : (rseal.expiresAt != rseal.issuedAt + ROUTING_SEAL_TTL_SECS) = true
                    · simp only [eq_true h2, ite_true]; exact ⟨_, rfl⟩
                    · simp only [eq_false h2, ite_false]
                      by_cases h3 : (rseal.policyVersionId != store2.activePolicyVersion) = true
                      · simp only [eq_true h3, ite_true]; exact ⟨_, rfl⟩
                      · simp only [eq_false h3, ite_false]
                        by_cases h4 : (rseal.actionDigest != expDigest2) = true
                        · simp only [eq_true h4, ite_true]; exact ⟨_, rfl⟩
                        · simp only [eq_false h4, ite_false]
                          by_cases h5 : (rseal.recordHash != expRec2) = true
                          · simp only [eq_true h5, ite_true]; exact ⟨_, rfl⟩
                          · simp only [eq_false h5, ite_false]
                            by_cases h6 : rseal.issuedAt > t2 + CLOCK_DRIFT_TOLERANCE_SECS
                            · simp only [eq_true h6, ite_true]; exact ⟨_, rfl⟩
                            · simp only [eq_false h6, ite_false]
                              by_cases h7 : (t2 > rseal.expiresAt || t2 > rseal.issuedAt + ROUTING_SEAL_TTL_SECS) = true
                              · simp only [eq_true h7, ite_true]; exact ⟨_, rfl⟩
                              · have h7F : (t2 > rseal.expiresAt || t2 > rseal.issuedAt + ROUTING_SEAL_TTL_SECS) = false := by
                                  cases hb : (t2 > rseal.expiresAt || t2 > rseal.issuedAt + ROUTING_SEAL_TTL_SECS) with
                                  | false => rfl | true => exact False.elim (h7 hb)
                                simp only [eq_false h7, ite_false]
                                have hNotPast : ¬(rseal.expiresAt + CLOCK_DRIFT_TOLERANCE_SECS < t2) := by
                                  intro hlt
                                  have ht2gt : t2 > rseal.expiresAt := by
                                    have : CLOCK_DRIFT_TOLERANCE_SECS = 5 := rfl
                                    omega
                                  have ht : (t2 > rseal.expiresAt || t2 > rseal.issuedAt + ROUTING_SEAL_TTL_SECS) = true := by
                                    simp [ht2gt]
                                  rw [ht] at h7F
                                  cases h7F
                                have hMem2 : (rseal.sealId, rseal.expiresAt) ∈ store2.consumedSeals := by
                                  cases hTracked2 with
                                  | inl hm => exact hm
                                  | inr hpast => exact False.elim (hNotPast hpast)
                                simp only [eq_false hsig, ite_false]
                                have hInPruned : ∃ exp, (rseal.sealId, exp) ∈
                                    (if t2 > store2.lastPruneTime || store2.consumedSeals.length > 1024 then
                                      pruneSealEntries store2.consumedSeals t2
                                    else
                                      store2.consumedSeals) := by
                                  by_cases hpr : (t2 > store2.lastPruneTime || store2.consumedSeals.length > 1024) = true
                                  · simp only [eq_true hpr, ite_true]
                                    refine ⟨rseal.expiresAt, (mem_pruneSealEntries_iff store2.consumedSeals t2 _).mpr ⟨hMem2, ?_⟩⟩
                                    exact Nat.le_of_not_lt hNotPast
                                  · simp only [eq_false hpr, ite_false]
                                    exact ⟨rseal.expiresAt, hMem2⟩
                                have hAny : (if t2 > store2.lastPruneTime || store2.consumedSeals.length > 1024 then
                                      pruneSealEntries store2.consumedSeals t2
                                    else
                                      store2.consumedSeals).any (fun p => p.1 == rseal.sealId) = true :=
                                  (any_fst_beq_iff rseal.sealId _).mpr hInPruned
                                simp only [eq_true hAny, ite_true]
                                exact ⟨.AlreadyConsumed rseal.sealId, rfl⟩

/-! ### Part 4: `CbfSafetyEngine` & `DebitLedger` (`cbf_fiscal.rs`) -/

structure RationalGamma where
  num : Nat
  den : Nat
  numPos : 0 < num
  leOne : num ≤ den
  deriving DecidableEq, Repr

structure CbfConfig where
  gamma : RationalGamma
  bMin : Int
  bMinNonNeg : 0 ≤ bMin
  eps : Nat := 0
  deriving DecidableEq, Repr

inductive CbfViolation : Type where
  | InvalidParameters
  | CurrentStateUnsafe
  | FloorBreach
  | DecayRateExceeded
  | ReservationNotFound
  | AlreadyCommitted
  deriving DecidableEq, Repr

def evaluateStep
    (cfg : CbfConfig)
    (currentBudget cost currentH : Int) : Except CbfViolation Int :=
  if cost < 0 then
    .error .InvalidParameters
  else if currentH < - Int.ofNat cfg.eps then
    .error .CurrentStateUnsafe
  else
    let projectedBudget := currentBudget - cost
    let hNext := projectedBudget - cfg.bMin
    if hNext < - Int.ofNat cfg.eps then
      .error .FloorBreach
    else if Int.ofNat cfg.gamma.den * (hNext + Int.ofNat cfg.eps) <
        Int.ofNat (cfg.gamma.den - cfg.gamma.num) * currentH then
      .error .DecayRateExceeded
    else
      .ok hNext

theorem evaluateStep_preserves_barrier
    (cfg : CbfConfig) (b cost hNext : Int)
    (hOk : evaluateStep cfg b cost (b - cfg.bMin) = .ok hNext) :
    0 ≤ cost ∧
    hNext = (b - cost) - cfg.bMin ∧
    - Int.ofNat cfg.eps ≤ hNext ∧
    Int.ofNat cfg.gamma.den * (hNext + Int.ofNat cfg.eps) ≥
      Int.ofNat (cfg.gamma.den - cfg.gamma.num) * (b - cfg.bMin) := by
  unfold evaluateStep at hOk
  by_cases hc : cost < 0
  · simp only [eq_true hc, ite_true] at hOk; cases hOk
  · simp only [eq_false hc, ite_false] at hOk
    by_cases hcur : b - cfg.bMin < - Int.ofNat cfg.eps
    · simp only [eq_true hcur, ite_true] at hOk; cases hOk
    · simp only [eq_false hcur, ite_false] at hOk
      by_cases hfl : (b - cost) - cfg.bMin < - Int.ofNat cfg.eps
      · simp only [eq_true hfl, ite_true] at hOk; cases hOk
      · simp only [eq_false hfl, ite_false] at hOk
        by_cases hdec : Int.ofNat cfg.gamma.den * ((b - cost) - cfg.bMin + Int.ofNat cfg.eps) <
            Int.ofNat (cfg.gamma.den - cfg.gamma.num) * (b - cfg.bMin)
        · simp only [eq_true hdec, ite_true] at hOk; cases hOk
        · simp only [eq_false hdec, ite_false] at hOk
          injection hOk with hEq
          subst hEq
          omega

structure ReservationEntry where
  debitId : String
  amount : Int
  committed : Bool
  rolledBack : Bool
  deriving DecidableEq, Repr

structure DebitLedgerState where
  cfg : CbfConfig
  initialBudget : Int
  availableBudget : Int
  reservations : List ReservationEntry
  deriving DecidableEq, Repr

def DebitLedgerState.init (cfg : CbfConfig) (initBudget : Int) : DebitLedgerState :=
  { cfg := cfg
  , initialBudget := initBudget
  , availableBudget := initBudget
  , reservations := [] }

def preReserve (st : DebitLedgerState) (cost : Int) (debitId : String) :
    Except CbfViolation DebitLedgerState :=
  let currentH := st.availableBudget - st.cfg.bMin
  match evaluateStep st.cfg st.availableBudget cost currentH with
  | .error e => .error e
  | .ok _ =>
    .ok { st with
          availableBudget := st.availableBudget - cost
          reservations :=
            { debitId := debitId
            , amount := cost
            , committed := false
            , rolledBack := false } :: st.reservations }

private def confirmEntries (debitId : String) :
    List ReservationEntry → Except CbfViolation (List ReservationEntry)
  | [] => .error .ReservationNotFound
  | e :: es =>
    if e.debitId == debitId then
      if e.rolledBack then
        .error .ReservationNotFound
      else
        .ok ({ e with committed := true } :: es)
    else
      match confirmEntries debitId es with
      | .error err => .error err
      | .ok es' => .ok (e :: es')

def confirmLedger (st : DebitLedgerState) (debitId : String) :
    Except CbfViolation DebitLedgerState :=
  match confirmEntries debitId st.reservations with
  | .error err => .error err
  | .ok rs' => .ok { st with reservations := rs' }

private def rollbackEntries (debitId : String) :
    List ReservationEntry → Except CbfViolation (Int × List ReservationEntry)
  | [] => .error .ReservationNotFound
  | e :: es =>
    if e.debitId == debitId then
      if e.committed then
        .error .AlreadyCommitted
      else if e.rolledBack then
        .error .ReservationNotFound
      else
        .ok (e.amount, { e with rolledBack := true } :: es)
    else
      match rollbackEntries debitId es with
      | .error err => .error err
      | .ok (amt, es') => .ok (amt, e :: es')

def rollbackLedger (st : DebitLedgerState) (debitId : String) :
    Except CbfViolation DebitLedgerState :=
  match rollbackEntries debitId st.reservations with
  | .error err => .error err
  | .ok (amt, rs') =>
    .ok { st with
          availableBudget := st.availableBudget + amt
          reservations := rs' }

private def rollbackLifoEntries :
    List ReservationEntry → Except CbfViolation (Int × List ReservationEntry)
  | [] => .error .ReservationNotFound
  | e :: es =>
    if !e.committed && !e.rolledBack then
      .ok (e.amount, { e with rolledBack := true } :: es)
    else
      match rollbackLifoEntries es with
      | .error err => .error err
      | .ok (amt, es') => .ok (amt, e :: es')

def rollbackLifoLedger (st : DebitLedgerState) :
    Except CbfViolation DebitLedgerState :=
  match rollbackLifoEntries st.reservations with
  | .error err => .error err
  | .ok (amt, rs') =>
    .ok { st with
          availableBudget := st.availableBudget + amt
          reservations := rs' }

inductive LedgerReachable (cfg : CbfConfig) (initBudget : Int) : DebitLedgerState → Prop where
  | init : LedgerReachable cfg initBudget (DebitLedgerState.init cfg initBudget)
  | reserve {st st' : DebitLedgerState} (cost : Int) (debitId : String) :
      LedgerReachable cfg initBudget st →
      preReserve st cost debitId = .ok st' →
      LedgerReachable cfg initBudget st'
  | confirm {st st' : DebitLedgerState} (debitId : String) :
      LedgerReachable cfg initBudget st →
      confirmLedger st debitId = .ok st' →
      LedgerReachable cfg initBudget st'
  | rollback {st st' : DebitLedgerState} (debitId : String) :
      LedgerReachable cfg initBudget st →
      rollbackLedger st debitId = .ok st' →
      LedgerReachable cfg initBudget st'
  | rollbackLifo {st st' : DebitLedgerState} :
      LedgerReachable cfg initBudget st →
      rollbackLifoLedger st = .ok st' →
      LedgerReachable cfg initBudget st'

def activeReservedSum : List ReservationEntry → Int
  | [] => 0
  | e :: es => (if !e.committed && !e.rolledBack then e.amount else 0) + activeReservedSum es

def committedSum : List ReservationEntry → Int
  | [] => 0
  | e :: es => (if e.committed then e.amount else 0) + committedSum es

private theorem activeReservedSum_nonneg {rs : List ReservationEntry}
    (hnn : ∀ r ∈ rs, 0 ≤ r.amount) : 0 ≤ activeReservedSum rs := by
  induction rs with
  | nil => decide
  | cons e es ih =>
    have he : 0 ≤ e.amount := hnn e (List.Mem.head es)
    have hes : 0 ≤ activeReservedSum es := ih (fun r hr => hnn r (List.Mem.tail e hr))
    simp only [activeReservedSum]
    split <;> omega

private theorem committedSum_nonneg {rs : List ReservationEntry}
    (hnn : ∀ r ∈ rs, 0 ≤ r.amount) : 0 ≤ committedSum rs := by
  induction rs with
  | nil => decide
  | cons e es ih =>
    have he : 0 ≤ e.amount := hnn e (List.Mem.head es)
    have hes : 0 ≤ committedSum es := ih (fun r hr => hnn r (List.Mem.tail e hr))
    simp only [committedSum]
    split <;> omega

private theorem confirmEntries_preserves
    (debitId : String) {rs rs' : List ReservationEntry}
    (hOk : confirmEntries debitId rs = .ok rs')
    (hnn : ∀ r ∈ rs, 0 ≤ r.amount) :
    activeReservedSum rs' + committedSum rs' = activeReservedSum rs + committedSum rs ∧
    (∀ r ∈ rs', 0 ≤ r.amount) := by
  induction rs generalizing rs' with
  | nil => cases hOk
  | cons e es ih =>
    unfold confirmEntries at hOk
    by_cases hid : (e.debitId == debitId) = true
    · simp only [eq_true hid, ite_true] at hOk
      by_cases hrb : e.rolledBack = true
      · simp only [eq_true hrb, ite_true] at hOk; cases hOk
      · have hrbF : e.rolledBack = false := by
          cases hb : e.rolledBack with | false => rfl | true => exact False.elim (hrb hb)
        simp only [eq_false hrb, ite_false] at hOk
        injection hOk with hEq
        subst hEq
        refine ⟨?_, ?_⟩
        · simp only [activeReservedSum, committedSum, hrbF]
          cases hc : e.committed <;> simp <;> omega
        · intro r hr
          cases hr with
          | head => exact hnn e (List.Mem.head es)
          | tail _ hm => exact hnn r (List.Mem.tail e hm)
    · simp only [eq_false hid, ite_false] at hOk
      cases hrec : confirmEntries debitId es with
      | error err => rw [hrec] at hOk; cases hOk
      | ok es' =>
        rw [hrec] at hOk
        injection hOk with hEq
        subst hEq
        have ih' := ih hrec (fun r hr => hnn r (List.Mem.tail e hr))
        refine ⟨?_, ?_⟩
        · simp only [activeReservedSum, committedSum]
          omega
        · intro r hr
          cases hr with
          | head => exact hnn e (List.Mem.head es)
          | tail _ hm => exact ih'.2 r hm

private theorem rollbackEntries_preserves
    (debitId : String) {rs rs' : List ReservationEntry} {amt : Int}
    (hOk : rollbackEntries debitId rs = .ok (amt, rs'))
    (hnn : ∀ r ∈ rs, 0 ≤ r.amount) :
    0 ≤ amt ∧
    activeReservedSum rs' + amt = activeReservedSum rs ∧
    committedSum rs' = committedSum rs ∧
    (∀ r ∈ rs', 0 ≤ r.amount) := by
  induction rs generalizing rs' amt with
  | nil => cases hOk
  | cons e es ih =>
    unfold rollbackEntries at hOk
    by_cases hid : (e.debitId == debitId) = true
    · simp only [eq_true hid, ite_true] at hOk
      by_cases hc : e.committed = true
      · simp only [eq_true hc, ite_true] at hOk; cases hOk
      · have hcF : e.committed = false := by
          cases hb : e.committed with | false => rfl | true => exact False.elim (hc hb)
        simp only [eq_false hc, ite_false] at hOk
        by_cases hrb : e.rolledBack = true
        · simp only [eq_true hrb, ite_true] at hOk; cases hOk
        · have hrbF : e.rolledBack = false := by
            cases hb : e.rolledBack with | false => rfl | true => exact False.elim (hrb hb)
          simp only [eq_false hrb, ite_false] at hOk
          injection hOk with hPair
          have hAmt : e.amount = amt := congrArg Prod.fst hPair
          have hRs : ({ e with rolledBack := true } :: es) = rs' := congrArg Prod.snd hPair
          subst hAmt
          subst hRs
          have he : 0 ≤ e.amount := hnn e (List.Mem.head es)
          refine ⟨he, ?_, ?_, ?_⟩
          · simp only [activeReservedSum, hcF, hrbF]
            simp; omega
          · simp only [committedSum, hcF]
          · intro r hr
            cases hr with
            | head => exact he
            | tail _ hm => exact hnn r (List.Mem.tail e hm)
    · simp only [eq_false hid, ite_false] at hOk
      cases hrec : rollbackEntries debitId es with
      | error err => rw [hrec] at hOk; cases hOk
      | ok p =>
        rw [hrec] at hOk
        rcases p with ⟨amt', es'⟩
        injection hOk with hPair
        have hAmt : amt' = amt := congrArg Prod.fst hPair
        have hRs : (e :: es') = rs' := congrArg Prod.snd hPair
        subst hAmt
        subst hRs
        have ih' := ih hrec (fun r hr => hnn r (List.Mem.tail e hr))
        refine ⟨ih'.1, ?_, ?_, ?_⟩
        · simp only [activeReservedSum]; omega
        · simp only [committedSum]; omega
        · intro r hr
          cases hr with
          | head => exact hnn e (List.Mem.head es)
          | tail _ hm => exact ih'.2.2.2 r hm

private theorem rollbackLifoEntries_preserves
    {rs rs' : List ReservationEntry} {amt : Int}
    (hOk : rollbackLifoEntries rs = .ok (amt, rs'))
    (hnn : ∀ r ∈ rs, 0 ≤ r.amount) :
    0 ≤ amt ∧
    activeReservedSum rs' + amt = activeReservedSum rs ∧
    committedSum rs' = committedSum rs ∧
    (∀ r ∈ rs', 0 ≤ r.amount) := by
  induction rs generalizing rs' amt with
  | nil => cases hOk
  | cons e es ih =>
    unfold rollbackLifoEntries at hOk
    by_cases hact : (!e.committed && !e.rolledBack) = true
    · simp only [eq_true hact, ite_true] at hOk
      injection hOk with hPair
      have hAmt : e.amount = amt := congrArg Prod.fst hPair
      have hRs : ({ e with rolledBack := true } :: es) = rs' := congrArg Prod.snd hPair
      subst hAmt
      subst hRs
      have hcF : e.committed = false := by
        cases hb : e.committed with | false => rfl | true => simp [hb] at hact
      have hrbF : e.rolledBack = false := by
        cases hb : e.rolledBack with | false => rfl | true => simp [hb] at hact
      have he : 0 ≤ e.amount := hnn e (List.Mem.head es)
      refine ⟨he, ?_, ?_, ?_⟩
      · simp only [activeReservedSum, hcF, hrbF]
        simp; omega
      · simp only [committedSum, hcF]
      · intro r hr
        cases hr with
        | head => exact he
        | tail _ hm => exact hnn r (List.Mem.tail e hm)
    · simp only [eq_false hact, ite_false] at hOk
      cases hrec : rollbackLifoEntries es with
      | error err => rw [hrec] at hOk; cases hOk
      | ok p =>
        rw [hrec] at hOk
        rcases p with ⟨amt', es'⟩
        injection hOk with hPair
        have hAmt : amt' = amt := congrArg Prod.fst hPair
        have hRs : (e :: es') = rs' := congrArg Prod.snd hPair
        subst hAmt
        subst hRs
        have ih' := ih hrec (fun r hr => hnn r (List.Mem.tail e hr))
        refine ⟨ih'.1, ?_, ?_, ?_⟩
        · simp only [activeReservedSum]; omega
        · simp only [committedSum]; omega
        · intro r hr
          cases hr with
          | head => exact hnn e (List.Mem.head es)
          | tail _ hm => exact ih'.2.2.2 r hm

private theorem ledger_master_invariant
    (cfg : CbfConfig) (initBudget : Int)
    (hInit : cfg.bMin ≤ initBudget)
    {st : DebitLedgerState}
    (hReach : LedgerReachable cfg initBudget st) :
    st.cfg = cfg ∧
    st.initialBudget = initBudget ∧
    - Int.ofNat cfg.eps ≤ st.availableBudget - cfg.bMin ∧
    st.availableBudget + activeReservedSum st.reservations + committedSum st.reservations = initBudget ∧
    (∀ r ∈ st.reservations, 0 ≤ r.amount) := by
  induction hReach with
  | init =>
    refine ⟨rfl, rfl, ?_, ?_, ?_⟩
    · simp only [DebitLedgerState.init]
      have heps : (0 : Int) ≤ Int.ofNat cfg.eps := Int.natCast_nonneg cfg.eps
      omega
    · simp only [DebitLedgerState.init, activeReservedSum, committedSum]
      omega
    · intro r hr; cases hr
  | @reserve st0 st1 cost debitId _ hRes ih =>
    rcases ih with ⟨hcfg, hinit, hbar, hsum, hnn⟩
    unfold preReserve at hRes
    dsimp only at hRes
    cases hev : evaluateStep st0.cfg st0.availableBudget cost (st0.availableBudget - st0.cfg.bMin) with
    | error err => rw [hev] at hRes; cases hRes
    | ok hNext =>
      rw [hev] at hRes
      injection hRes with hEq
      subst hEq
      rw [hcfg] at hev
      have hStep := evaluateStep_preserves_barrier cfg st0.availableBudget cost hNext hev
      refine ⟨hcfg, hinit, ?_, ?_, ?_⟩
      · dsimp only
        rw [← hStep.2.1]
        exact hStep.2.2.1
      · simp [activeReservedSum, committedSum]
        omega
      · intro r hr
        cases hr with
        | head => exact hStep.1
        | tail _ hm => exact hnn r hm
  | @confirm st0 st1 debitId _ hConf ih =>
    rcases ih with ⟨hcfg, hinit, hbar, hsum, hnn⟩
    unfold confirmLedger at hConf
    cases hc : confirmEntries debitId st0.reservations with
    | error err => rw [hc] at hConf; cases hConf
    | ok rs' =>
      rw [hc] at hConf
      injection hConf with hEq
      subst hEq
      have hp := confirmEntries_preserves debitId hc hnn
      refine ⟨hcfg, hinit, hbar, ?_, hp.2⟩
      dsimp only
      omega
  | @rollback st0 st1 debitId _ hRb ih =>
    rcases ih with ⟨hcfg, hinit, hbar, hsum, hnn⟩
    unfold rollbackLedger at hRb
    cases hrb : rollbackEntries debitId st0.reservations with
    | error err => rw [hrb] at hRb; cases hRb
    | ok p =>
      rw [hrb] at hRb
      rcases p with ⟨amt, rs'⟩
      injection hRb with hEq
      subst hEq
      have hp := rollbackEntries_preserves debitId hrb hnn
      refine ⟨hcfg, hinit, ?_, ?_, hp.2.2.2⟩
      · dsimp only; omega
      · dsimp only; omega
  | @rollbackLifo st0 st1 _ hRb ih =>
    rcases ih with ⟨hcfg, hinit, hbar, hsum, hnn⟩
    unfold rollbackLifoLedger at hRb
    cases hrb : rollbackLifoEntries st0.reservations with
    | error err => rw [hrb] at hRb; cases hRb
    | ok p =>
      rw [hrb] at hRb
      rcases p with ⟨amt, rs'⟩
      injection hRb with hEq
      subst hEq
      have hp := rollbackLifoEntries_preserves hrb hnn
      refine ⟨hcfg, hinit, ?_, ?_, hp.2.2.2⟩
      · dsimp only; omega
      · dsimp only; omega

/-- Theorem: Discrete-time CBF forward invariance across all reachable `DebitLedgerState`s. -/
theorem cbf_forward_invariance
    (cfg : CbfConfig) (initBudget : Int)
    (hInit : cfg.bMin ≤ initBudget)
    (st : DebitLedgerState)
    (hReach : LedgerReachable cfg initBudget st) :
    - Int.ofNat cfg.eps ≤ st.availableBudget - cfg.bMin ∧
    (cfg.eps = 0 → cfg.bMin ≤ st.availableBudget ∧ 0 ≤ st.availableBudget - cfg.bMin) := by
  have hm := ledger_master_invariant cfg initBudget hInit hReach
  refine ⟨hm.2.2.1, ?_⟩
  intro heps
  have hbar := hm.2.2.1
  have hzero : Int.ofNat 0 = 0 := rfl
  rw [heps, hzero] at hbar
  omega

/-- Theorem: Exact fiscal conservation (zero debit leakage) across all reachable ledger states. -/
theorem debit_no_leakage
    (cfg : CbfConfig) (initBudget : Int)
    (hInit : cfg.bMin ≤ initBudget)
    (st : DebitLedgerState)
    (hReach : LedgerReachable cfg initBudget st) :
    st.availableBudget + activeReservedSum st.reservations + committedSum st.reservations = initBudget ∧
    st.availableBudget ≤ initBudget ∧
    (∀ r ∈ st.reservations, 0 ≤ r.amount) := by
  have hm := ledger_master_invariant cfg initBudget hInit hReach
  have ha := activeReservedSum_nonneg hm.2.2.2.2
  have hc := committedSum_nonneg hm.2.2.2.2
  refine ⟨hm.2.2.2.1, ?_, hm.2.2.2.2⟩
  omega

/-- Compensating rollback after a failed seal issuance restores exact `availableBudget` (`pipeline.rs:584`). -/
theorem preReserve_rollback_exact
    (st st1 st2 : DebitLedgerState) (cost : Int) (debitId : String)
    (hRes : preReserve st cost debitId = .ok st1)
    (hRb : rollbackLedger st1 debitId = .ok st2) :
    st2.availableBudget = st.availableBudget := by
  unfold preReserve at hRes
  dsimp only at hRes
  cases hev : evaluateStep st.cfg st.availableBudget cost (st.availableBudget - st.cfg.bMin) with
  | error err => rw [hev] at hRes; cases hRes
  | ok hNext =>
    rw [hev] at hRes
    injection hRes with hEq1
    subst hEq1
    unfold rollbackLedger at hRb
    dsimp only at hRb
    simp only [rollbackEntries, beq_self_eq_true, ite_true, Bool.false_eq_true, ite_false] at hRb
    injection hRb with hEq2
    subst hEq2
    dsimp only
    omega

end AgentOctopusFormal
