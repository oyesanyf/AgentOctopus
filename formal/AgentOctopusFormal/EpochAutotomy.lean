import AgentOctopusFormal.CoreTypes

namespace AgentOctopusFormal

/-!
# Milestone M2 Part 1: Epoch Autotomy, Law 3 Dirac Tickets & 3-Layer Orthogonal Gate

Formalizes 1-to-1 with:
- `src/containment_ring/arm_ring.rs` (`ArmContainmentRing`: `sever`, `sever_and_regenerate`, `validate_epoch`)
- `src/sentinel_ring/epoch_registry.rs` (`ArmEpochState`, `EpochRegistry`)
- `src/containment_ring/primitives.rs` (`DiracDeltaCapabilityTicket`, `IndependentTrustBoundaryVerifier`)
-/

/-! ### Part 1: Epoch Autotomy (`arm_ring.rs` & `epoch_registry.rs`) -/

/-- Initial generation for Sentinel arms (`epoch_registry.rs:42`: arm 17 starts at 8, others at 1). -/
def sentinelInitialGeneration (armId : Nat) : Nat :=
  if armId == 17 then 8 else 1

/-- Per-arm epoch autotomy state mirroring `ArmContainmentRing` & `ArmEpochState`. -/
structure ArmEpochState where
  armId : Nat
  currentGeneration : Nat
  isSevered : Bool
  revokedEpochs : List Nat
  deriving DecidableEq, Repr

def ArmEpochState.init (armId : Nat) (initialGeneration : Nat := 1) : ArmEpochState :=
  { armId := armId
  , currentGeneration := initialGeneration
  , isSevered := false
  , revokedEpochs := [] }

inductive EpochValidationError : Type where
  | LimbKilled
  | EpochRevoked
  | EpochMismatch
  deriving DecidableEq, Repr, BEq

instance : LawfulBEq EpochValidationError where
  eq_of_beq {a b} h := by cases a <;> cases b <;> first | rfl | cases h
  rfl {a} := by cases a <;> rfl

/-- Mirror of `ArmContainmentRing::sever` (`arm_ring.rs:656-673`) and
    `EpochRegistry::revoke_arm_generation` (`epoch_registry.rs:98-121`). -/
def severArm (st : ArmEpochState) : ArmEpochState :=
  { st with
    isSevered := true
    revokedEpochs := st.currentGeneration :: st.revokedEpochs }

abbrev ArmEpochState.sever (st : ArmEpochState) : ArmEpochState := severArm st

/-- Mirror of `ArmContainmentRing::sever_and_regenerate` (`arm_ring.rs:678-705`) and
    `EpochRegistry::advance_generation` (`epoch_registry.rs:124-144`). -/
def severAndRegenerate (st : ArmEpochState) : ArmEpochState :=
  { st with
    currentGeneration := st.currentGeneration + 1
    isSevered := false
    revokedEpochs := st.currentGeneration :: st.revokedEpochs }

inductive EpochAction : Type where
  | sever
  | severAndRegenerate
  deriving DecidableEq, Repr, BEq

instance : LawfulBEq EpochAction where
  eq_of_beq {a b} h := by cases a <;> cases b <;> first | rfl | cases h
  rfl {a} := by cases a <;> rfl

def stepEpoch (st : ArmEpochState) : EpochAction → ArmEpochState
  | .sever => severArm st
  | .severAndRegenerate => severAndRegenerate st

inductive EpochTrace : ArmEpochState → ArmEpochState → Prop where
  | refl (st : ArmEpochState) : EpochTrace st st
  | step {s0 s : ArmEpochState} (act : EpochAction) :
      EpochTrace s0 s → EpochTrace s0 (stepEpoch s act)

/-- Mirror of `ArmContainmentRing::validate_epoch` (`arm_ring.rs:709-735`) and
    `EpochRegistry::is_generation_active` (`epoch_registry.rs:63-95`). -/
def validateEpochResult (st : ArmEpochState) (epoch : Nat) : Except EpochValidationError Unit :=
  if st.isSevered then
    .error .LimbKilled
  else if st.revokedEpochs.any (fun e => e == epoch) then
    .error .EpochRevoked
  else if epoch != st.currentGeneration then
    .error .EpochMismatch
  else
    .ok ()

def validateEpoch (st : ArmEpochState) (epoch : Nat) : Bool :=
  match validateEpochResult st epoch with
  | .ok () => true
  | .error _ => false

private theorem any_beq_nat_iff (epoch : Nat) :
    ∀ (xs : List Nat), xs.any (fun e => e == epoch) = true ↔ epoch ∈ xs
  | [] => by
    rw [List.any_nil]
    constructor
    · intro h; cases h
    · intro h; cases h
  | x :: xs => by
    rw [List.any_cons, Bool.or_eq_true, beq_iff_eq]
    have ih := any_beq_nat_iff epoch xs
    constructor
    · intro h
      cases h with
      | inl hx =>
        subst hx
        exact List.Mem.head xs
      | inr hxs =>
        exact List.Mem.tail x (ih.mp hxs)
    · intro h
      cases h with
      | head => exact Or.inl rfl
      | tail _ hmem => exact Or.inr (ih.mpr hmem)

private theorem any_beq_nat_false_iff (epoch : Nat) (xs : List Nat) :
    xs.any (fun e => e == epoch) = false ↔ epoch ∉ xs := by
  have h := any_beq_nat_iff epoch xs
  constructor
  · intro hf hmem
    have ht := h.mpr hmem
    rw [hf] at ht
    cases ht
  · intro hnot
    cases hb : xs.any (fun e => e == epoch) with
    | false => rfl
    | true => exact False.elim (hnot (h.mp hb))

/-- Theorem: `severAndRegenerate` strictly advances `currentGeneration` by exactly 1 (`N -> N + 1`). -/
theorem epoch_strictly_monotonic (st : ArmEpochState) :
    st.currentGeneration < (severAndRegenerate st).currentGeneration ∧
    (severAndRegenerate st).currentGeneration = st.currentGeneration + 1 := by
  dsimp only [severAndRegenerate]
  exact ⟨Nat.lt_succ_self st.currentGeneration, rfl⟩

/-- Auxiliary trace monotonicity: no `EpochTrace` step ever decreases `currentGeneration`. -/
theorem epoch_trace_non_decreasing {s0 s : ArmEpochState} (h : EpochTrace s0 s) :
    s0.currentGeneration ≤ s.currentGeneration := by
  induction h with
  | refl => exact Nat.le_refl _
  | step act _ ih =>
    cases act with
    | sever => exact ih
    | severAndRegenerate => exact Nat.le_trans ih (Nat.le_succ _)

/-- Exact characterization of `validateEpoch`. -/
theorem validateEpoch_eq_true_iff (st : ArmEpochState) (epoch : Nat) :
    validateEpoch st epoch = true ↔
      st.isSevered = false ∧ epoch ∉ st.revokedEpochs ∧ epoch = st.currentGeneration := by
  unfold validateEpoch validateEpochResult
  by_cases hsev : st.isSevered = true
  · simp only [eq_true hsev, ite_true]
    constructor
    · intro h; cases h
    · intro h; rw [h.1] at hsev; cases hsev
  · have hsevFalse : st.isSevered = false := by
      cases hb : st.isSevered with
      | false => rfl
      | true => exact False.elim (hsev hb)
    simp only [eq_false hsev, ite_false]
    by_cases hrev : st.revokedEpochs.any (fun e => e == epoch) = true
    · simp only [eq_true hrev, ite_true]
      have hmem : epoch ∈ st.revokedEpochs := (any_beq_nat_iff epoch st.revokedEpochs).mp hrev
      constructor
      · intro h; cases h
      · intro h; exact False.elim (h.2.1 hmem)
    · have hrevFalse : st.revokedEpochs.any (fun e => e == epoch) = false := by
        cases hb : st.revokedEpochs.any (fun e => e == epoch) with
        | false => rfl
        | true => exact False.elim (hrev hb)
      have hnotMem : epoch ∉ st.revokedEpochs :=
        (any_beq_nat_false_iff epoch st.revokedEpochs).mp hrevFalse
      simp only [eq_false hrev, ite_false]
      by_cases hne : (epoch != st.currentGeneration) = true
      · simp only [eq_true hne, ite_true]
        have hneq : epoch ≠ st.currentGeneration := by
          intro heq
          subst heq
          simp only [bne_self_eq_false] at hne
          cases hne
        constructor
        · intro h; cases h
        · intro h; exact False.elim (hneq h.2.2)
      · have hneFalse : (epoch != st.currentGeneration) = false := by
          cases hb : (epoch != st.currentGeneration) with
          | false => rfl
          | true => exact False.elim (hne hb)
        have heq : epoch = st.currentGeneration := by
          by_cases h0 : epoch = st.currentGeneration
          · exact h0
          · have ht : (epoch != st.currentGeneration) = true := bne_iff_ne.mpr h0
            rw [ht] at hneFalse
            cases hneFalse
        simp only [eq_false hne, ite_false]
        constructor
        · intro _
          exact ⟨hsevFalse, hnotMem, heq⟩
        · intro _
          trivial

/-- Theorem: Any severed arm, revoked epoch, or mismatched epoch is rejected by `validateEpoch`. -/
theorem revoked_epoch_never_valid (st : ArmEpochState) (epoch : Nat)
    (h : st.isSevered = true ∨ epoch ∈ st.revokedEpochs ∨ epoch ≠ st.currentGeneration) :
    validateEpoch st epoch = false := by
  cases hb : validateEpoch st epoch with
  | false => rfl
  | true =>
    have hacc := (validateEpoch_eq_true_iff st epoch).mp hb
    cases h with
    | inl hsev =>
      rw [hacc.1] at hsev
      cases hsev
    | inr hrest =>
      cases hrest with
      | inl hmem => exact False.elim (hacc.2.1 hmem)
      | inr hne => exact False.elim (hne hacc.2.2)

/-- Severing an arm immediately rejects every presented epoch. -/
theorem sever_rejects_all_epochs (st : ArmEpochState) (epoch : Nat) :
    validateEpoch (severArm st) epoch = false :=
  revoked_epoch_never_valid (severArm st) epoch (Or.inl rfl)

/-- `severAndRegenerate` places the prior generation in `revokedEpochs` and rejects it. -/
theorem severAndRegenerate_revokes_old_epoch (st : ArmEpochState) :
    st.currentGeneration ∈ (severAndRegenerate st).revokedEpochs ∧
    validateEpoch (severAndRegenerate st) st.currentGeneration = false := by
  have hmem : st.currentGeneration ∈ (severAndRegenerate st).revokedEpochs :=
    List.Mem.head st.revokedEpochs
  exact ⟨hmem, revoked_epoch_never_valid (severAndRegenerate st) st.currentGeneration (Or.inr (Or.inl hmem))⟩

/-- Any `EpochTrace` monotonically preserves every previously revoked epoch. -/
theorem epoch_trace_preserves_revoked {s0 s : ArmEpochState} (h : EpochTrace s0 s) :
    ∀ e ∈ s0.revokedEpochs, e ∈ s.revokedEpochs := by
  induction h with
  | refl =>
    intro e he
    exact he
  | step act _ ih =>
    intro e he
    have hePrev := ih e he
    cases act with
    | sever => exact List.Mem.tail _ hePrev
    | severAndRegenerate => exact List.Mem.tail _ hePrev

/-- Once revoked, an epoch remains permanently invalid across all future `EpochTrace` steps. -/
theorem epoch_trace_revoked_never_valid {s0 s : ArmEpochState}
    (htr : EpochTrace s0 s) {e : Nat} (hrev : e ∈ s0.revokedEpochs) :
    validateEpoch s e = false :=
  revoked_epoch_never_valid s e (Or.inr (Or.inl (epoch_trace_preserves_revoked htr e hrev)))

/-! ### Part 2: Law 3 `DiracDeltaCapabilityTicket` (`primitives.rs:38-217`) -/

def DIRAC_MIN_WINDOW_US : Nat := 1
def DIRAC_MAX_WINDOW_US : Nat := 5_000_000

def clampDiracWindowUs (w : Nat) : Nat :=
  if w < DIRAC_MIN_WINDOW_US then DIRAC_MIN_WINDOW_US
  else if w > DIRAC_MAX_WINDOW_US then DIRAC_MAX_WINDOW_US
  else w

theorem clampDiracWindowUs_bounds (w : Nat) :
    DIRAC_MIN_WINDOW_US ≤ clampDiracWindowUs w ∧
    clampDiracWindowUs w ≤ DIRAC_MAX_WINDOW_US := by
  unfold clampDiracWindowUs DIRAC_MIN_WINDOW_US DIRAC_MAX_WINDOW_US
  by_cases hlow : w < 1
  · simp only [eq_true hlow, ite_true]
    decide
  · simp only [eq_false hlow, ite_false]
    by_cases hhigh : w > 5_000_000
    · simp only [eq_true hhigh, ite_true]
      decide
    · simp only [eq_false hhigh, ite_false]
      omega

inductive DiracConsumedState : Type where
  | fresh         -- 0
  | consumed      -- 1
  | canaryTripped -- 2
  deriving DecidableEq, Repr, BEq

instance : LawfulBEq DiracConsumedState where
  eq_of_beq {a b} h := by cases a <;> cases b <;> first | rfl | cases h
  rfl {a} := by cases a <;> rfl

def DiracConsumedState.code : DiracConsumedState → Nat
  | .fresh => 0
  | .consumed => 1
  | .canaryTripped => 2

inductive DiracConsumeError : Type where
  | CanaryTrapTripped
  | ReplayBlocked
  | WindowExpired
  | EpochMismatch
  | ScopeMismatch
  | SignatureInvalid
  deriving DecidableEq, Repr, BEq

instance : LawfulBEq DiracConsumeError where
  eq_of_beq {a b} h := by cases a <;> cases b <;> first | rfl | cases h
  rfl {a} := by cases a <;> rfl

structure DiracDeltaCapabilityTicket where
  armId : String
  generationEpoch : Nat
  authorizedTool : String
  authorizedTarget : String
  issuedAtUs : Nat
  windowUs : Nat
  state : DiracConsumedState
  secretZeroized : Bool
  canaryTokenHash : Option String
  deriving DecidableEq, Repr

structure DiracConsumeContext where
  requestedTool : String
  requestedTarget : String
  activeEpoch : Nat
  nowUs : Nat
  hmacValid : Bool
  observedCanaryHash : Option String
  deriving DecidableEq, Repr

def DiracDeltaCapabilityTicket.issue
    (armId : String)
    (generationEpoch : Nat)
    (authorizedTool authorizedTarget : String)
    (issuedAtUs rawWindowUs : Nat)
    (canaryTokenHash : Option String) : DiracDeltaCapabilityTicket :=
  { armId := armId
  , generationEpoch := generationEpoch
  , authorizedTool := authorizedTool
  , authorizedTarget := authorizedTarget
  , issuedAtUs := issuedAtUs
  , windowUs := clampDiracWindowUs rawWindowUs
  , state := .fresh
  , secretZeroized := false
  , canaryTokenHash := canaryTokenHash }

def DiracDeltaCapabilityTicket.isConsumed (t : DiracDeltaCapabilityTicket) : Bool :=
  t.state != .fresh

def DiracDeltaCapabilityTicket.dropTicket (t : DiracDeltaCapabilityTicket) : DiracDeltaCapabilityTicket :=
  { t with secretZeroized := true }

/-- Mirror of `DiracDeltaCapabilityTicket::consume_once` (`primitives.rs:109-192`). -/
def DiracDeltaCapabilityTicket.consumeOnce
    (t : DiracDeltaCapabilityTicket)
    (ctx : DiracConsumeContext) :
    DiracDeltaCapabilityTicket × Except DiracConsumeError Unit :=
  if t.canaryTokenHash.isSome && ctx.observedCanaryHash == t.canaryTokenHash then
    ({ t with state := .canaryTripped, secretZeroized := true }, .error .CanaryTrapTripped)
  else
    match t.state with
    | .consumed => ({ t with secretZeroized := true }, .error .ReplayBlocked)
    | .canaryTripped => ({ t with secretZeroized := true }, .error .ReplayBlocked)
    | .fresh =>
      let tCas := { t with state := .consumed, secretZeroized := true }
      let elapsedUs := ctx.nowUs - t.issuedAtUs
      if elapsedUs > t.windowUs then
        (tCas, .error .WindowExpired)
      else if ctx.activeEpoch != t.generationEpoch then
        (tCas, .error .EpochMismatch)
      else if ctx.requestedTool != t.authorizedTool || ctx.requestedTarget != t.authorizedTarget then
        (tCas, .error .ScopeMismatch)
      else if !ctx.hmacValid then
        (tCas, .error .SignatureInvalid)
      else
        (tCas, .ok ())

/-- Every invocation of `consumeOnce` (regardless of error or success) leaves the ticket
    non-fresh (`isConsumed = true`) and `secretZeroized = true`. -/
theorem dirac_consume_always_zeroizes_and_marks
    (t : DiracDeltaCapabilityTicket) (ctx : DiracConsumeContext) :
    let res := t.consumeOnce ctx
    res.1.state ≠ .fresh ∧
    res.1.isConsumed = true ∧
    res.1.secretZeroized = true := by
  unfold DiracDeltaCapabilityTicket.consumeOnce DiracDeltaCapabilityTicket.isConsumed
  by_cases hcan : (t.canaryTokenHash.isSome && ctx.observedCanaryHash == t.canaryTokenHash) = true
  · simp only [eq_true hcan, ite_true]
    refine ⟨?_, rfl, trivial⟩
    intro h; cases h
  · simp only [eq_false hcan, ite_false]
    cases hs : t.state with
    | consumed =>
      refine ⟨?_, rfl, rfl⟩
      intro h; cases h
    | canaryTripped =>
      refine ⟨?_, rfl, rfl⟩
      intro h; cases h
    | fresh =>
      dsimp only
      by_cases hexp : ctx.nowUs - t.issuedAtUs > t.windowUs
      · simp only [eq_true hexp, ite_true]
        refine ⟨?_, rfl, trivial⟩
        intro h; cases h
      · simp only [eq_false hexp, ite_false]
        by_cases hep : (ctx.activeEpoch != t.generationEpoch) = true
        · simp only [eq_true hep, ite_true]
          refine ⟨?_, rfl, trivial⟩
          intro h; cases h
        · simp only [eq_false hep, ite_false]
          by_cases hsc : (ctx.requestedTool != t.authorizedTool || ctx.requestedTarget != t.authorizedTarget) = true
          · simp only [eq_true hsc, ite_true]
            refine ⟨?_, rfl, trivial⟩
            intro h; cases h
          · simp only [eq_false hsc, ite_false]
            by_cases hhmac : (!ctx.hmacValid) = true
            · simp only [eq_true hhmac, ite_true]
              refine ⟨?_, rfl, trivial⟩
              intro h; cases h
            · simp only [eq_false hhmac, ite_false]
              refine ⟨?_, rfl, trivial⟩
              intro h; cases h

private theorem dirac_nonfresh_replay_always_errors
    (t : DiracDeltaCapabilityTicket) (ctx : DiracConsumeContext)
    (hNonFresh : t.state ≠ .fresh) :
    (∃ err, (t.consumeOnce ctx).2 = .error err) ∧
    (t.consumeOnce ctx).1.state ≠ .fresh ∧
    (t.consumeOnce ctx).1.secretZeroized = true ∧
    (t.canaryTokenHash.isSome = true ∧ ctx.observedCanaryHash = t.canaryTokenHash →
      (t.consumeOnce ctx).1.state = .canaryTripped ∧
      (t.consumeOnce ctx).1.state.code = 2 ∧
      (t.consumeOnce ctx).2 = .error .CanaryTrapTripped) := by
  unfold DiracDeltaCapabilityTicket.consumeOnce
  by_cases hcan : (t.canaryTokenHash.isSome && ctx.observedCanaryHash == t.canaryTokenHash) = true
  · simp only [eq_true hcan, ite_true]
    refine ⟨⟨.CanaryTrapTripped, rfl⟩, ?_, trivial, ?_⟩
    · intro h; cases h
    · intro _; exact ⟨trivial, rfl, trivial⟩
  · have hcanF : (t.canaryTokenHash.isSome && ctx.observedCanaryHash == t.canaryTokenHash) = false := by
      cases hb : (t.canaryTokenHash.isSome && ctx.observedCanaryHash == t.canaryTokenHash) with
      | false => rfl
      | true => exact False.elim (hcan hb)
    simp only [eq_false hcan, ite_false]
    have hcanaryContra : ¬(t.canaryTokenHash.isSome = true ∧ ctx.observedCanaryHash = t.canaryTokenHash) := by
      intro hpair
      have hbeq : (ctx.observedCanaryHash == t.canaryTokenHash) = true := beq_iff_eq.mpr hpair.2
      have ht : (t.canaryTokenHash.isSome && ctx.observedCanaryHash == t.canaryTokenHash) = true := by
        rw [hpair.1, hbeq]
        rfl
      rw [ht] at hcanF
      cases hcanF
    cases hs : t.state with
    | fresh =>
      exact False.elim (hNonFresh hs)
    | consumed =>
      refine ⟨⟨.ReplayBlocked, rfl⟩, ?_, rfl, ?_⟩
      · intro h; cases h
      · intro hp; exact False.elim (hcanaryContra hp)
    | canaryTripped =>
      refine ⟨⟨.ReplayBlocked, rfl⟩, ?_, rfl, ?_⟩
      · intro h; cases h
      · intro hp; exact False.elim (hcanaryContra hp)

/-- Theorem: Any second `consumeOnce` attempt (replay) on a ticket ALWAYS fails with an error,
    keeps `state ≠ .fresh` and `secretZeroized = true`, and trips the canary trap (`code = 2`)
    if the canary token is observed. -/
theorem dirac_single_use_no_replay
    (t : DiracDeltaCapabilityTicket)
    (ctx1 ctx2 : DiracConsumeContext) :
    let r1 := t.consumeOnce ctx1
    let r2 := r1.1.consumeOnce ctx2
    (∃ err, r2.2 = .error err) ∧
    r2.1.state ≠ .fresh ∧
    r2.1.secretZeroized = true ∧
    (r1.1.canaryTokenHash.isSome = true ∧ ctx2.observedCanaryHash = r1.1.canaryTokenHash →
      r2.1.state = .canaryTripped ∧
      r2.1.state.code = 2 ∧
      r2.2 = .error .CanaryTrapTripped) := by
  have h1 := dirac_consume_always_zeroizes_and_marks t ctx1
  exact dirac_nonfresh_replay_always_errors (t.consumeOnce ctx1).1 ctx2 h1.1

/-- An expired Dirac ticket can never succeed on `consumeOnce`. -/
theorem dirac_expired_never_ok
    (t : DiracDeltaCapabilityTicket) (ctx : DiracConsumeContext)
    (hexp : ctx.nowUs - t.issuedAtUs > t.windowUs) :
    ∃ err, (t.consumeOnce ctx).2 = .error err := by
  unfold DiracDeltaCapabilityTicket.consumeOnce
  by_cases hcan : (t.canaryTokenHash.isSome && ctx.observedCanaryHash == t.canaryTokenHash) = true
  · simp only [eq_true hcan, ite_true]
    exact ⟨.CanaryTrapTripped, rfl⟩
  · simp only [eq_false hcan, ite_false]
    cases hs : t.state with
    | consumed => exact ⟨.ReplayBlocked, rfl⟩
    | canaryTripped => exact ⟨.ReplayBlocked, rfl⟩
    | fresh =>
      dsimp only
      simp only [eq_true hexp, ite_true]
      exact ⟨.WindowExpired, rfl⟩

/-! ### Part 3: `IndependentTrustBoundaryVerifier` (`primitives.rs:543-656`) -/

inductive TrustLayerDomain : Type where
  | L1UserspaceCedar
  | L2TpmMerkle
  | L3OsKernel
  deriving DecidableEq, Repr, BEq

instance : LawfulBEq TrustLayerDomain where
  eq_of_beq {a b} h := by cases a <;> cases b <;> first | rfl | cases h
  rfl {a} := by cases a <;> rfl

structure MultiLayerGateVerdict where
  allowed : Bool
  layer1UserspaceCedarOk : Bool
  layer2TpmMerkleAttestationOk : Bool
  layer3KernelConfinementOk : Bool
  deriving DecidableEq, Repr

structure IndependentTrustBoundaryVerifier where
  layer1Epoch : Nat := 1
  layer2Epoch : Nat := 1
  layer3Epoch : Nat := 1
  deriving DecidableEq, Repr

structure LayerProofToken where
  domain : TrustLayerDomain
  epoch : Nat
  tokenValid : Bool
  deriving DecidableEq, Repr

structure ThreeLayerGateInput where
  l1Proof : LayerProofToken
  l2Proof : LayerProofToken
  l3Proof : LayerProofToken
  kernelProcessInJob : Bool
  deriving DecidableEq, Repr

def verifyLayerProof
    (expectedDomain : TrustLayerDomain)
    (expectedEpoch : Nat)
    (proof : LayerProofToken) : Bool :=
  (proof.domain == expectedDomain) && (proof.epoch == expectedEpoch) && proof.tokenValid

def evaluateThreeLayerGate
    (v : IndependentTrustBoundaryVerifier)
    (inp : ThreeLayerGateInput) : MultiLayerGateVerdict :=
  let l1Ok := verifyLayerProof .L1UserspaceCedar v.layer1Epoch inp.l1Proof
  let l2Ok := verifyLayerProof .L2TpmMerkle v.layer2Epoch inp.l2Proof
  let l3Ok := verifyLayerProof .L3OsKernel v.layer3Epoch inp.l3Proof && inp.kernelProcessInJob
  { allowed := l1Ok && l2Ok && l3Ok
  , layer1UserspaceCedarOk := l1Ok
  , layer2TpmMerkleAttestationOk := l2Ok
  , layer3KernelConfinementOk := l3Ok }

/-- Theorem: 3-layer orthogonal non-circular AND gate: `allowed = true` iff all three
    independent domains (`L1UserspaceCedar`, `L2TpmMerkle`, `L3OsKernel`), their epochs,
    cryptographic validity flags, AND `kernelProcessInJob` all hold simultaneously. -/
theorem three_layer_non_circular_gate
    (v : IndependentTrustBoundaryVerifier)
    (inp : ThreeLayerGateInput) :
    let verdict := evaluateThreeLayerGate v inp
    (verdict.allowed = true ↔
      verdict.layer1UserspaceCedarOk = true ∧
      verdict.layer2TpmMerkleAttestationOk = true ∧
      verdict.layer3KernelConfinementOk = true) ∧
    (verdict.allowed = true ↔
      inp.l1Proof.domain = .L1UserspaceCedar ∧
      inp.l1Proof.epoch = v.layer1Epoch ∧
      inp.l1Proof.tokenValid = true ∧
      inp.l2Proof.domain = .L2TpmMerkle ∧
      inp.l2Proof.epoch = v.layer2Epoch ∧
      inp.l2Proof.tokenValid = true ∧
      inp.l3Proof.domain = .L3OsKernel ∧
      inp.l3Proof.epoch = v.layer3Epoch ∧
      inp.l3Proof.tokenValid = true ∧
      inp.kernelProcessInJob = true) := by
  unfold evaluateThreeLayerGate verifyLayerProof
  dsimp only
  simp only [Bool.and_eq_true, beq_iff_eq]
  constructor
  · constructor
    · intro h; exact ⟨h.1.1, h.1.2, h.2⟩
    · intro h; exact ⟨⟨h.1, h.2.1⟩, h.2.2⟩
  · constructor
    · intro h
      exact ⟨h.1.1.1.1, h.1.1.1.2, h.1.1.2,
             h.1.2.1.1, h.1.2.1.2, h.1.2.2,
             h.2.1.1.1, h.2.1.1.2, h.2.1.2, h.2.2⟩
    · intro h
      rcases h with ⟨h1d, h1e, h1v, h2d, h2e, h2v, h3d, h3e, h3v, hk⟩
      exact ⟨⟨⟨⟨h1d, h1e⟩, h1v⟩, ⟨⟨h2d, h2e⟩, h2v⟩⟩, ⟨⟨⟨h3d, h3e⟩, h3v⟩, hk⟩⟩

/-- Failure of any single layer (or kernel job confinement) forces `allowed = false`. -/
theorem three_layer_single_failure_denies
    (v : IndependentTrustBoundaryVerifier)
    (inp : ThreeLayerGateInput)
    (hFail : (evaluateThreeLayerGate v inp).layer1UserspaceCedarOk = false ∨
             (evaluateThreeLayerGate v inp).layer2TpmMerkleAttestationOk = false ∨
             (evaluateThreeLayerGate v inp).layer3KernelConfinementOk = false ∨
             inp.kernelProcessInJob = false) :
    (evaluateThreeLayerGate v inp).allowed = false := by
  cases hb : (evaluateThreeLayerGate v inp).allowed with
  | false => rfl
  | true =>
    have h1 := ((three_layer_non_circular_gate v inp).1).mp hb
    have h2 := ((three_layer_non_circular_gate v inp).2).mp hb
    rcases hFail with hf1 | hf2 | hf3 | hfk
    · rw [h1.1] at hf1; cases hf1
    · rw [h1.2.1] at hf2; cases hf2
    · rw [h1.2.2] at hf3; cases hf3
    · rw [h2.2.2.2.2.2.2.2.2.2] at hfk; cases hfk

/-- Domain separation guarantees no single proof token can satisfy two distinct layers. -/
theorem three_layer_non_circular_domains (e1 e2 : Nat) (p : LayerProofToken) :
    ¬(verifyLayerProof .L1UserspaceCedar e1 p = true ∧ verifyLayerProof .L2TpmMerkle e2 p = true) ∧
    ¬(verifyLayerProof .L2TpmMerkle e1 p = true ∧ verifyLayerProof .L3OsKernel e2 p = true) ∧
    ¬(verifyLayerProof .L1UserspaceCedar e1 p = true ∧ verifyLayerProof .L3OsKernel e2 p = true) := by
  unfold verifyLayerProof
  simp only [Bool.and_eq_true, beq_iff_eq]
  refine ⟨?_, ?_, ?_⟩ <;>
  · intro ⟨h1, h2⟩
    have hd1 := h1.1.1
    have hd2 := h2.1.1
    rw [hd1] at hd2
    cases hd2

end AgentOctopusFormal
