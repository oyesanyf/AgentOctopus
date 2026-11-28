import AgentOctopusFormal.CoreTypes

namespace AgentOctopusFormal

/-- Exact 6-state mirror of `crate::deterministic::fsm::ArmState` (`src/deterministic/fsm.rs:5-12`). -/
inductive ArmState : Type where
  | Created
  | DirectiveAccepted
  | EnclaveDigesting
  | MerkleSealed
  | Completed
  | Quarantined
  deriving DecidableEq, Repr, BEq

/-- Exact transition relation matching `FsmTransitionGuard::transition_to` (`fsm.rs:47-62`).
    Note: `(_, .Quarantined)` precedes `(.Quarantined, _)`, so `(.Quarantined, .Quarantined)` is true. -/
def isValidTransition (cur next : ArmState) : Bool :=
  match cur, next with
  | .Created, .DirectiveAccepted => true
  | .DirectiveAccepted, .EnclaveDigesting => true
  | .EnclaveDigesting, .MerkleSealed => true
  | .MerkleSealed, .Completed => true
  | _, .Quarantined => true
  | .Quarantined, _ => false
  | _, _ => false

def transitionTo (cur next : ArmState) : Option ArmState :=
  if isValidTransition cur next then some next else none

/-- Multi-step reachability from an arbitrary start state `s0`. -/
inductive ReachableFrom : ArmState → ArmState → Prop where
  | refl (s0 : ArmState) : ReachableFrom s0 s0
  | step {s0 s s' : ArmState} :
      ReachableFrom s0 s → isValidTransition s s' = true → ReachableFrom s0 s'

/-- Trace-indexed reachability from initial state `.Created` (`FsmTransitionGuard::new()`). -/
inductive ReachTrace : List ArmState → ArmState → Prop where
  | init : ReachTrace [.Created] .Created
  | step {hist : List ArmState} {s s' : ArmState} :
      ReachTrace hist s → isValidTransition s s' = true → ReachTrace (hist ++ [s']) s'

def ReachableState (s : ArmState) : Prop :=
  ReachableFrom .Created s

-- Unique-predecessor inversion lemmas
theorem no_transition_to_created (s : ArmState) :
    isValidTransition s .Created = false := by
  cases s <;> rfl

theorem pred_of_directive_accepted {s : ArmState}
    (h : isValidTransition s .DirectiveAccepted = true) : s = .Created := by
  cases s <;> simp_all [isValidTransition]

theorem pred_of_enclave_digesting {s : ArmState}
    (h : isValidTransition s .EnclaveDigesting = true) : s = .DirectiveAccepted := by
  cases s <;> simp_all [isValidTransition]

theorem pred_of_merkle_sealed {s : ArmState}
    (h : isValidTransition s .MerkleSealed = true) : s = .EnclaveDigesting := by
  cases s <;> simp_all [isValidTransition]

theorem pred_of_completed {s : ArmState}
    (h : isValidTransition s .Completed = true) : s = .MerkleSealed := by
  cases s <;> simp_all [isValidTransition]

-- Exact trace characterization lemmas
theorem trace_created_eq {hist : List ArmState} (h : ReachTrace hist .Created) :
    hist = [.Created] := by
  cases h with
  | init => rfl
  | step _ htr =>
    rw [no_transition_to_created] at htr
    contradiction

theorem trace_directive_accepted_eq {hist : List ArmState}
    (h : ReachTrace hist .DirectiveAccepted) :
    hist = [.Created, .DirectiveAccepted] := by
  cases h with
  | step hprev htr =>
    have hs := pred_of_directive_accepted htr
    subst hs
    rw [trace_created_eq hprev]
    rfl

theorem trace_enclave_digesting_eq {hist : List ArmState}
    (h : ReachTrace hist .EnclaveDigesting) :
    hist = [.Created, .DirectiveAccepted, .EnclaveDigesting] := by
  cases h with
  | step hprev htr =>
    have hs := pred_of_enclave_digesting htr
    subst hs
    rw [trace_directive_accepted_eq hprev]
    rfl

theorem trace_merkle_sealed_eq {hist : List ArmState}
    (h : ReachTrace hist .MerkleSealed) :
    hist = [.Created, .DirectiveAccepted, .EnclaveDigesting, .MerkleSealed] := by
  cases h with
  | step hprev htr =>
    have hs := pred_of_merkle_sealed htr
    subst hs
    rw [trace_enclave_digesting_eq hprev]
    rfl

/-- Theorem 1: Any trace reaching `Completed` from `Created` must follow the exact 5-state chain
    and therefore visited `DirectiveAccepted`, `EnclaveDigesting`, and `MerkleSealed` without skipping. -/
theorem fsm_no_skip_to_completed {hist : List ArmState} (h : ReachTrace hist .Completed) :
    hist = [.Created, .DirectiveAccepted, .EnclaveDigesting, .MerkleSealed, .Completed] ∧
    .DirectiveAccepted ∈ hist ∧
    .EnclaveDigesting ∈ hist ∧
    .MerkleSealed ∈ hist := by
  cases h with
  | step hprev htr =>
    have hs := pred_of_completed htr
    subst hs
    have hms := trace_merkle_sealed_eq hprev
    rw [hms]
    simp

/-- Theorem 2 (Single-step & Multi-step): `Quarantined` is strictly absorbing. -/
theorem quarantined_step_absorbing (next : ArmState)
    (h : isValidTransition .Quarantined next = true) : next = .Quarantined := by
  cases next <;> simp_all [isValidTransition]

theorem quarantined_is_absorbing {s : ArmState}
    (h : ReachableFrom .Quarantined s) : s = .Quarantined := by
  induction h with
  | refl => rfl
  | step _ htr ih =>
    subst ih
    exact quarantined_step_absorbing _ htr

theorem quarantined_cannot_complete {s : ArmState}
    (h : ReachableFrom .Quarantined s) : s ≠ .Completed := by
  have hq := quarantined_is_absorbing h
  subst hq
  intro hc
  cases hc

/-! ### PolicyGuard & DeterministicLayer Specifications -/

def DEFAULT_MAX_AMOUNT_CENTS : Nat := 10_000_000
def DEFAULT_MAX_STEPS_PERMITTED : Nat := 5
def DEFAULT_REQUIRED_CURRENCY : String := "USD"
def MERKLE_ROOT_LEN : Nat := 64

def DEFAULT_ALLOWED_SOURCE_PREFIXES : List String :=
  ["s3://invoices/", "https://www.google.com/", "https://google.com/", "s3://accounting/"]

/-- Exact mirror of `crate::deterministic::policy_guard::PolicyGuard` (`policy_guard.rs:5-26`). -/
structure PolicyGuard where
  maxAmountCents : Nat := DEFAULT_MAX_AMOUNT_CENTS
  allowedSourcePrefixes : List String := DEFAULT_ALLOWED_SOURCE_PREFIXES
  maxStepsPermitted : Nat := DEFAULT_MAX_STEPS_PERMITTED
  requiredCurrency : String := DEFAULT_REQUIRED_CURRENCY
  deriving Repr, DecidableEq

structure StrategicDirectiveSpec where
  sourceUri : String
  maxStepBudget : Nat
  deriving Repr, DecidableEq

structure VerifiedInvoiceArtifactSpec where
  amountCents : Nat
  currency : String
  merkleRoot : String
  schemaLexicalValid : Bool := true
  deriving Repr, DecidableEq

def enforceDirective (pg : PolicyGuard) (d : StrategicDirectiveSpec) : Bool :=
  decide (d.maxStepBudget ≤ pg.maxStepsPermitted) &&
  pg.allowedSourcePrefixes.any (fun p => d.sourceUri.startsWith p)

def enforceArtifact (pg : PolicyGuard) (a : VerifiedInvoiceArtifactSpec) : Bool :=
  decide (a.amountCents ≤ pg.maxAmountCents) &&
  (a.currency == pg.requiredCurrency) &&
  (a.merkleRoot.length == MERKLE_ROOT_LEN)

/-- Mirror of `SchemaGuard::validate_fields` (`schema_guard.rs:26-53`) for amount & lexical flag. -/
def validateSchemaFields (a : VerifiedInvoiceArtifactSpec) : Bool :=
  a.schemaLexicalValid && decide (a.amountCents ≠ 0)

private theorem any_eq_true_exists {α : Type} (p : α → Bool) :
    ∀ (xs : List α), xs.any p = true → ∃ x, x ∈ xs ∧ p x = true
  | [], h => by rw [List.any_nil] at h; cases h
  | x :: xs, h => by
    cases hpx : p x
    · rw [List.any_cons, hpx, Bool.false_or] at h
      obtain ⟨y, hy, hpy⟩ := any_eq_true_exists p xs h
      exact ⟨y, List.Mem.tail _ hy, hpy⟩
    · exact ⟨x, List.Mem.head _, hpx⟩

theorem enforceDirective_implies_caps {pg : PolicyGuard} {d : StrategicDirectiveSpec}
    (h : enforceDirective pg d = true) :
    d.maxStepBudget ≤ pg.maxStepsPermitted ∧
    ∃ p, p ∈ pg.allowedSourcePrefixes ∧ d.sourceUri.startsWith p = true := by
  unfold enforceDirective at h
  rw [Bool.and_eq_true] at h
  exact ⟨of_decide_eq_true h.1, any_eq_true_exists _ pg.allowedSourcePrefixes h.2⟩

theorem enforceArtifact_implies_caps {pg : PolicyGuard} {a : VerifiedInvoiceArtifactSpec}
    (h : enforceArtifact pg a = true) :
    a.amountCents ≤ pg.maxAmountCents ∧
    a.currency = pg.requiredCurrency ∧
    a.merkleRoot.length = MERKLE_ROOT_LEN := by
  unfold enforceArtifact at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at h
  exact ⟨h.1.1, h.1.2, h.2⟩

theorem validateSchemaFields_implies_nonzero {a : VerifiedInvoiceArtifactSpec}
    (h : validateSchemaFields a = true) : 0 < a.amountCents := by
  unfold validateSchemaFields at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  exact Nat.pos_of_ne_zero h.2

/-- Combined `DeterministicLayer` state (`src/deterministic/layer.rs:9-84`). -/
structure DeterministicLayerState where
  fsmState : ArmState
  policy : PolicyGuard
  acceptedDirective : Option StrategicDirectiveSpec
  sealedRoot : Option String
  finalizedArtifact : Option VerifiedInvoiceArtifactSpec
  deriving Repr, DecidableEq

def DeterministicLayerState.init (pg : PolicyGuard := {}) : DeterministicLayerState :=
  { fsmState := .Created
  , policy := pg
  , acceptedDirective := none
  , sealedRoot := none
  , finalizedArtifact := none }

inductive LayerAction : Type where
  | acceptDirective (d : StrategicDirectiveSpec)
  | enterEnclaveDigest
  | sealMerkleTrace (rootHex : String)
  | finalizeArtifact (a : VerifiedInvoiceArtifactSpec)
  | quarantine
  deriving Repr, DecidableEq

def stepLayer (st : DeterministicLayerState) (act : LayerAction) : Option DeterministicLayerState :=
  match act with
  | .acceptDirective d =>
    if enforceDirective st.policy d then
      match transitionTo st.fsmState .DirectiveAccepted with
      | some next => some { st with fsmState := next, acceptedDirective := some d }
      | none => none
    else none
  | .enterEnclaveDigest =>
    match transitionTo st.fsmState .EnclaveDigesting with
    | some next => some { st with fsmState := next }
    | none => none
  | .sealMerkleTrace rootHex =>
    if rootHex.length == MERKLE_ROOT_LEN then
      match transitionTo st.fsmState .MerkleSealed with
      | some next => some { st with fsmState := next, sealedRoot := some rootHex }
      | none => none
    else none
  | .finalizeArtifact a =>
    if validateSchemaFields a && enforceArtifact st.policy a then
      match transitionTo st.fsmState .Completed with
      | some next => some { st with fsmState := next, finalizedArtifact := some a }
      | none => none
    else none
  | .quarantine =>
    match transitionTo st.fsmState .Quarantined with
    | some next => some { st with fsmState := next }
    | none => none

/-- Invariant maintained across all `DeterministicLayer` transitions. -/
def LayerCapsInvariant (st : DeterministicLayerState) : Prop :=
  (∀ d, st.acceptedDirective = some d →
    d.maxStepBudget ≤ st.policy.maxStepsPermitted ∧
    ∃ p, p ∈ st.policy.allowedSourcePrefixes ∧ d.sourceUri.startsWith p = true) ∧
  (∀ r, st.sealedRoot = some r → r.length = MERKLE_ROOT_LEN) ∧
  (∀ a, st.finalizedArtifact = some a →
    0 < a.amountCents ∧
    a.amountCents ≤ st.policy.maxAmountCents ∧
    a.currency = st.policy.requiredCurrency ∧
    a.merkleRoot.length = MERKLE_ROOT_LEN) ∧
  (st.fsmState = .DirectiveAccepted → st.acceptedDirective.isSome = true) ∧
  (st.fsmState = .EnclaveDigesting → st.acceptedDirective.isSome = true) ∧
  (st.fsmState = .MerkleSealed →
    st.acceptedDirective.isSome = true ∧ st.sealedRoot.isSome = true) ∧
  (st.fsmState = .Completed →
    st.acceptedDirective.isSome = true ∧
    st.sealedRoot.isSome = true ∧
    st.finalizedArtifact.isSome = true)

inductive LayerReachable (pg : PolicyGuard) : DeterministicLayerState → Prop where
  | init : LayerReachable pg (DeterministicLayerState.init pg)
  | step {st st' : DeterministicLayerState} {act : LayerAction} :
      LayerReachable pg st → stepLayer st act = some st' → LayerReachable pg st'

private theorem transitionTo_some_valid {cur target next : ArmState}
    (h : transitionTo cur target = some next) :
    isValidTransition cur target = true ∧ next = target := by
  unfold transitionTo at h
  by_cases hv : isValidTransition cur target = true
  · simp only [eq_true hv, ite_true] at h
    injection h with hn
    exact ⟨hv, hn.symm⟩
  · simp only [eq_false hv, ite_false] at h
    cases h

/-- Theorem 3: `PolicyGuard` & `SchemaGuard` caps are preserved across every reachable
    `DeterministicLayer` state, and reaching `.Completed` guarantees a compliant finalized artifact
    along with accepted directive and sealed Merkle root prerequisites. -/
theorem policy_guard_caps_enforced {pg : PolicyGuard} {st : DeterministicLayerState}
    (h : LayerReachable pg st) : LayerCapsInvariant st ∧ st.policy = pg := by
  induction h with
  | init =>
    refine ⟨⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩, rfl⟩
    · intro d hd; cases hd
    · intro r hr; cases hr
    · intro a ha; cases ha
    · intro hda; cases hda
    · intro hed; cases hed
    · intro hms; cases hms
    · intro hcomp; cases hcomp
  | @step st_prev _st_next act _ hstep ih =>
    rcases ih with ⟨⟨ihDir, ihRoot, ihArt, ihDA, ihED, ihMS, _ihComp⟩, ihPol⟩
    cases act with
    | acceptDirective d =>
      dsimp only [stepLayer] at hstep
      by_cases henf : enforceDirective st_prev.policy d = true
      · simp only [eq_true henf, ite_true] at hstep
        cases htr : transitionTo st_prev.fsmState .DirectiveAccepted with
        | none => rw [htr] at hstep; cases hstep
        | some next =>
          rw [htr] at hstep
          injection hstep with hst
          subst hst
          obtain ⟨_, hnext⟩ := transitionTo_some_valid htr
          subst hnext
          refine ⟨⟨?_, ihRoot, ihArt, ?_, ?_, ?_, ?_⟩, ihPol⟩
          · intro d' hd'
            injection hd' with heq
            subst heq
            exact enforceDirective_implies_caps henf
          · intro _; rfl
          · intro hed; cases hed
          · intro hms; cases hms
          · intro hcomp; cases hcomp
      · simp only [eq_false henf, ite_false] at hstep; cases hstep
    | enterEnclaveDigest =>
      dsimp only [stepLayer] at hstep
      cases htr : transitionTo st_prev.fsmState .EnclaveDigesting with
      | none => rw [htr] at hstep; cases hstep
      | some next =>
        rw [htr] at hstep
        injection hstep with hst
        subst hst
        obtain ⟨hvalid, hnext⟩ := transitionTo_some_valid htr
        subst hnext
        have hprev := pred_of_enclave_digesting hvalid
        refine ⟨⟨ihDir, ihRoot, ihArt, ?_, ?_, ?_, ?_⟩, ihPol⟩
        · intro hda; cases hda
        · intro _; exact ihDA hprev
        · intro hms; cases hms
        · intro hcomp; cases hcomp
    | sealMerkleTrace rootHex =>
      dsimp only [stepLayer] at hstep
      by_cases hlen : (rootHex.length == MERKLE_ROOT_LEN) = true
      · simp only [eq_true hlen, ite_true] at hstep
        cases htr : transitionTo st_prev.fsmState .MerkleSealed with
        | none => rw [htr] at hstep; cases hstep
        | some next =>
          rw [htr] at hstep
          injection hstep with hst
          subst hst
          obtain ⟨hvalid, hnext⟩ := transitionTo_some_valid htr
          subst hnext
          have hprev := pred_of_merkle_sealed hvalid
          refine ⟨⟨ihDir, ?_, ihArt, ?_, ?_, ?_, ?_⟩, ihPol⟩
          · intro r hr
            injection hr with heq
            subst heq
            exact beq_iff_eq.mp hlen
          · intro hda; cases hda
          · intro hed; cases hed
          · intro _; exact ⟨ihED hprev, rfl⟩
          · intro hcomp; cases hcomp
      · simp only [eq_false hlen, ite_false] at hstep; cases hstep
    | finalizeArtifact a =>
      dsimp only [stepLayer] at hstep
      by_cases hok : (validateSchemaFields a && enforceArtifact st_prev.policy a) = true
      · simp only [eq_true hok, ite_true] at hstep
        rw [Bool.and_eq_true] at hok
        cases htr : transitionTo st_prev.fsmState .Completed with
        | none => rw [htr] at hstep; cases hstep
        | some next =>
          rw [htr] at hstep
          injection hstep with hst
          subst hst
          obtain ⟨hvalid, hnext⟩ := transitionTo_some_valid htr
          subst hnext
          have hprev := pred_of_completed hvalid
          obtain ⟨hdir, hseal⟩ := ihMS hprev
          refine ⟨⟨ihDir, ihRoot, ?_, ?_, ?_, ?_, ?_⟩, ihPol⟩
          · intro a' ha'
            injection ha' with heq
            subst heq
            obtain ⟨hamt, hcur, hroot⟩ := enforceArtifact_implies_caps hok.2
            exact ⟨validateSchemaFields_implies_nonzero hok.1, hamt, hcur, hroot⟩
          · intro hda; cases hda
          · intro hed; cases hed
          · intro hms; cases hms
          · intro _; exact ⟨hdir, hseal, rfl⟩
      · simp only [eq_false hok, ite_false] at hstep; cases hstep
    | quarantine =>
      dsimp only [stepLayer] at hstep
      cases htr : transitionTo st_prev.fsmState .Quarantined with
      | none => rw [htr] at hstep; cases hstep
      | some next =>
        rw [htr] at hstep
        injection hstep with hst
        subst hst
        obtain ⟨_, hnext⟩ := transitionTo_some_valid htr
        subst hnext
        refine ⟨⟨ihDir, ihRoot, ihArt, ?_, ?_, ?_, ?_⟩, ihPol⟩
        · intro hda; cases hda
        · intro hed; cases hed
        · intro hms; cases hms
        · intro hcomp; cases hcomp

end AgentOctopusFormal
