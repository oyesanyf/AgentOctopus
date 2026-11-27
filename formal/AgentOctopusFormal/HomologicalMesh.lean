import AgentOctopusFormal.CoreTypes

namespace AgentOctopusFormal

/-- `MAX_RELAY_HOPS` (`src/containment_ring/mesh_guard.rs:229`). -/
def MAX_RELAY_HOPS : Nat := 16

/-- Default `max_delegation_depth` (`src/security/delegation.rs:13`). -/
def MAX_DELEGATION_DEPTH : Nat := 2

/-- Maximum correlation ID length (`src/containment_ring/mesh_guard.rs:369`). -/
def MAX_CORRELATION_ID_BYTES : Nat := 128

/-- Maximum mesh payload length (`src/containment_ring/mesh_guard.rs:374`). -/
def MAX_MESH_PAYLOAD_BYTES : Nat := 16 * 1024

/-- Mirror of `crate::neural_mesh::MessageKind` (`src/neural_mesh.rs:30-35`). -/
inductive MessageKind : Type where
  | Finding
  | ThreatMapping
  | ChainCandidate
  | Alert
  deriving DecidableEq, Repr, BEq

/-- Mirror of `crate::containment_ring::mesh_guard::HomologicalAuditReport` (`mesh_guard.rs:10-22`). -/
structure HomologicalAuditReport where
  allowed : Bool
  senderPotential : Int
  intermediaryPotential : Option Int
  recipientPotential : Int
  coboundaryResidue : Int
  boundarySquaredZero : Bool
  proxyLaunderingDetected : Bool
  deriving DecidableEq, Repr

/-! ### Total Helpers for Telescoping Sum, Minimum, and Chain Partition -/

def adjacentDiffSum : List Int → Int
  | [] => 0
  | [_] => 0
  | x :: y :: rest => (y - x) + adjacentDiffSum (y :: rest)

def listLastInt (x : Int) : List Int → Int
  | [] => x
  | y :: ys => listLastInt y ys

def listMinInt (acc : Int) : List Int → Int
  | [] => acc
  | x :: xs => listMinInt (if x ≤ acc then x else acc) xs

def listMinIntOpt : List Int → Option Int
  | [] => none
  | x :: xs => some (listMinInt x xs)

def dropLastCons {α : Type} (y : α) : List α → List α
  | [] => []
  | z :: zs => y :: dropLastCons z zs

def listLast {α : Type} (y : α) : List α → α
  | [] => y
  | z :: zs => listLast z zs

theorem adjacentDiffSum_telescopes (x : Int) (xs : List Int) :
    adjacentDiffSum (x :: xs) = listLastInt x xs - x := by
  induction xs generalizing x with
  | nil => simp [adjacentDiffSum, listLastInt]
  | cons y ys ih =>
    simp only [adjacentDiffSum, listLastInt]
    have h := ih y
    omega

theorem listLastInt_map {α : Type} (f : α → Int) (x : α) (xs : List α) :
    listLastInt (f x) (xs.map f) = f (listLast x xs) := by
  induction xs generalizing x with
  | nil => rfl
  | cons y ys ih =>
    simp only [List.map, listLastInt, listLast]
    exact ih y

theorem getLast?_cons_eq_some_listLast {α : Type} (y : α) (ys : List α) :
    (y :: ys).getLast? = some (listLast y ys) := by
  induction ys generalizing y with
  | nil => rfl
  | cons z zs ih =>
    simp only [List.getLast?, listLast]
    exact ih z

theorem listMinInt_le_acc (acc : Int) (xs : List Int) : listMinInt acc xs ≤ acc := by
  induction xs generalizing acc with
  | nil => exact Int.le_refl acc
  | cons x xs ih =>
    simp only [listMinInt]
    by_cases hx : x ≤ acc
    · simp only [eq_true hx, ite_true]
      exact Int.le_trans (ih x) hx
    · simp only [eq_false hx, ite_false]
      exact ih acc

theorem listMinInt_le_mem (acc : Int) (xs : List Int) (z : Int) (hz : z ∈ xs) :
    listMinInt acc xs ≤ z := by
  induction xs generalizing acc with
  | nil => cases hz
  | cons x xs ih =>
    simp only [listMinInt]
    cases hz with
    | head =>
      by_cases hx : z ≤ acc
      · simp only [eq_true hx, ite_true]
        exact listMinInt_le_acc z xs
      · simp only [eq_false hx, ite_false]
        have hgt : acc ≤ z := Int.le_of_not_le hx
        exact Int.le_trans (listMinInt_le_acc acc xs) hgt
    | tail _ hmem =>
      exact ih (if x ≤ acc then x else acc) hmem

theorem chain_mem_partition {α : Type} (y : α) (ys : List α) (r : α)
    (hr : r ∈ y :: ys) : r ∈ dropLastCons y ys ∨ r = listLast y ys := by
  induction ys generalizing y with
  | nil =>
    cases hr with
    | head => exact Or.inr rfl
    | tail _ hnil => cases hnil
  | cons z zs ih =>
    cases hr with
    | head => exact Or.inl (List.Mem.head _)
    | tail _ hmem =>
      rcases ih z hmem with hdrop | hlast
      · exact Or.inl (List.Mem.tail _ hdrop)
      · exact Or.inr hlast

/-- Models `HomologicalBoundaryAuditor::audit_role_chain` (`mesh_guard.rs:120-210`). -/
def auditRoleChain (chain : List ArmRole) : HomologicalAuditReport :=
  if chain.length < 2 || chain.length > MAX_RELAY_HOPS + 1 then
    { allowed := false
      senderPotential := 0
      intermediaryPotential := none
      recipientPotential := 0
      coboundaryResidue := 0
      boundarySquaredZero := false
      proxyLaunderingDetected := true }
  else
    match chain with
    | [] =>
      { allowed := false
        senderPotential := 0
        intermediaryPotential := none
        recipientPotential := 0
        coboundaryResidue := 0
        boundarySquaredZero := false
        proxyLaunderingDetected := true }
    | [_] =>
      { allowed := false
        senderPotential := 0
        intermediaryPotential := none
        recipientPotential := 0
        coboundaryResidue := 0
        boundarySquaredZero := false
        proxyLaunderingDetected := true }
    | x :: y :: ys =>
      let potentials := (x :: y :: ys).map (fun r => (roleTrustTier r).potential)
      let phiS := (roleTrustTier x).potential
      let phiR := (roleTrustTier (listLast y ys)).potential
      let middlePotentials := (dropLastCons y ys).map (fun r => (roleTrustTier r).potential)
      let phiI := listMinIntOpt middlePotentials
      let telescoped := adjacentDiffSum potentials
      let coboundaryResidue := telescoped - (phiR - phiS)
      let boundarySquaredZero := decide (coboundaryResidue = 0)
      let upstreamPotentials := (x :: dropLastCons y ys).map (fun r => (roleTrustTier r).potential)
      let originFloor := listMinInt phiS upstreamPotentials
      let directViolation :=
        ys.isEmpty && decide (phiS ≤ TrustTier.Untrusted.potential) &&
          decide (phiR ≥ TrustTier.PrivilegedSink.potential)
      let transitiveLaundering :=
        (!ys.isEmpty) && decide (originFloor ≤ TrustTier.Untrusted.potential) &&
          decide (phiR ≥ TrustTier.PrivilegedSink.potential)
      let proxyLaundering := directViolation || transitiveLaundering || (!boundarySquaredZero)
      { allowed := !proxyLaundering
        senderPotential := phiS
        intermediaryPotential := phiI
        recipientPotential := phiR
        coboundaryResidue := coboundaryResidue
        boundarySquaredZero := boundarySquaredZero
        proxyLaunderingDetected := proxyLaundering }

private theorem telescoped_chain_eq (x y : ArmRole) (ys : List ArmRole) :
    adjacentDiffSum ((x :: y :: ys).map (fun r => (roleTrustTier r).potential)) -
      ((roleTrustTier (listLast y ys)).potential - (roleTrustTier x).potential) = 0 := by
  let f : ArmRole → Int := fun r => (roleTrustTier r).potential
  have ht := adjacentDiffSum_telescopes (f x) ((y :: ys).map f)
  have hl := listLastInt_map f y ys
  change adjacentDiffSum (f x :: (y :: ys).map f) - (f (listLast y ys) - f x) = 0
  rw [ht]
  have hli : listLastInt (f x) ((y :: ys).map f) = f (listLast y ys) := by
    simp only [List.map, listLastInt]
    exact hl
  rw [hli]
  omega

private theorem mem_map_potential_of_untrusted {r : ArmRole} {xs : List ArmRole}
    (hr : r ∈ xs) (hu : roleTrustTier r = .Untrusted) :
    TrustTier.Untrusted.potential ∈ xs.map (fun a => (roleTrustTier a).potential) := by
  induction xs with
  | nil => cases hr
  | cons a as ih =>
    cases hr with
    | head =>
      simp only [List.map, hu]
      exact List.Mem.head _
    | tail _ hmem =>
      simp only [List.map]
      exact List.Mem.tail _ (ih hmem)

/-- Law 1 guarantees any authenticated chain containing an `Untrusted` arm and ending at a
    `PrivilegedSink` arm is rejected (`allowed = false`), regardless of chain length. -/
theorem auditRoleChain_blocks_untrusted_to_privileged
    (chain : List ArmRole)
    (recipient : ArmRole)
    (hLast : chain.getLast? = some recipient)
    (hSink : roleTrustTier recipient = .PrivilegedSink)
    (hUntrusted : ∃ r ∈ chain, roleTrustTier r = .Untrusted) :
    (auditRoleChain chain).allowed = false := by
  unfold auditRoleChain
  by_cases hlen : (chain.length < 2 || chain.length > MAX_RELAY_HOPS + 1) = true
  · simp only [eq_true hlen, ite_true]
  · simp only [eq_false hlen, ite_false]
    cases chain with
    | nil => rfl
    | cons x xs =>
      cases xs with
      | nil => rfl
      | cons y ys =>
        dsimp only
        have hgl := getLast?_cons_eq_some_listLast x (y :: ys)
        rw [hLast] at hgl
        injection hgl with hrec
        have hLastEq : listLast y ys = recipient := hrec.symm
        have hLastSink : roleTrustTier (listLast y ys) = .PrivilegedSink := by
          rw [hLastEq]; exact hSink
        obtain ⟨r, hrmem, hrunt⟩ := hUntrusted
        have hne : r ≠ listLast y ys := by
          intro heq
          rw [heq, hLastSink] at hrunt
          cases hrunt
        have hr_up : r ∈ x :: dropLastCons y ys := by
          cases hrmem with
          | head => exact List.Mem.head _
          | tail _ hmem =>
            rcases chain_mem_partition y ys r hmem with hdrop | hlast
            · exact List.Mem.tail _ hdrop
            · exact absurd hlast hne
        have hphiR : (roleTrustTier (listLast y ys)).potential = TrustTier.PrivilegedSink.potential := by
          rw [hLastSink]
        cases ys with
        | nil =>
          have hrx : r = x := by
            cases hr_up with
            | head => rfl
            | tail _ htail => cases htail
          have hphiS : (roleTrustTier x).potential = TrustTier.Untrusted.potential := by
            rw [← hrx, hrunt]
          rw [hphiR, hphiS]
          simp
        | cons z zs =>
          have hmem_pot : TrustTier.Untrusted.potential ∈
              (x :: dropLastCons y (z :: zs)).map (fun a => (roleTrustTier a).potential) :=
            mem_map_potential_of_untrusted hr_up hrunt
          have hfloor : listMinInt (roleTrustTier x).potential
              ((x :: dropLastCons y (z :: zs)).map (fun a => (roleTrustTier a).potential)) ≤
              TrustTier.Untrusted.potential :=
            listMinInt_le_mem _ _ _ hmem_pot
          have hdec_floor : decide (listMinInt (roleTrustTier x).potential
              ((x :: dropLastCons y (z :: zs)).map (fun a => (roleTrustTier a).potential)) ≤
              TrustTier.Untrusted.potential) = true :=
            decide_eq_true hfloor
          have hdec_sink : decide ((roleTrustTier (listLast y (z :: zs))).potential ≥
              TrustTier.PrivilegedSink.potential) = true := by
            rw [hLastSink]; decide
          simp only [List.isEmpty_cons, Bool.not_false, Bool.true_and, Bool.false_and, Bool.false_or,
            hdec_floor, hdec_sink, Bool.true_or, Bool.not_true]

private theorem auditRoleChain_allowed_props {chain : List ArmRole}
    (h : (auditRoleChain chain).allowed = true) :
    (auditRoleChain chain).coboundaryResidue = 0 ∧
    (auditRoleChain chain).boundarySquaredZero = true ∧
    2 ≤ chain.length ∧
    chain.length ≤ MAX_RELAY_HOPS + 1 := by
  unfold auditRoleChain at h ⊢
  by_cases hlen : (chain.length < 2 || chain.length > MAX_RELAY_HOPS + 1) = true
  · simp only [eq_true hlen, ite_true] at h; cases h
  · simp only [eq_false hlen, ite_false] at h ⊢
    have hnot : ¬(chain.length < 2) ∧ ¬(chain.length > MAX_RELAY_HOPS + 1) := by
      rw [Bool.or_eq_true] at hlen
      exact ⟨fun h1 => hlen (Or.inl (decide_eq_true h1)), fun h2 => hlen (Or.inr (decide_eq_true h2))⟩
    have hlen_bounds : 2 ≤ chain.length ∧ chain.length ≤ MAX_RELAY_HOPS + 1 := by omega
    cases chain with
    | nil => cases h
    | cons x xs =>
      cases xs with
      | nil => cases h
      | cons y ys =>
        dsimp only
        have hcb := telescoped_chain_eq x y ys
        refine ⟨hcb, decide_eq_true hcb, hlen_bounds.1, hlen_bounds.2⟩

/-! ### Sticky Taint, Provenance Truncation & MeshGuard Model -/

structure ProvenanceHop where
  armId : Nat
  role : ArmRole
  generation : Nat
  deriving DecidableEq, Repr, BEq

structure TaintState where
  floor : TrustTier
  provenance : List ProvenanceHop
  deriving DecidableEq, Repr

def TaintState.init (role : ArmRole) : TaintState :=
  { floor := roleTrustTier role, provenance := [] }

/-- Sticky floor update (`arm_ring.rs:1081`): `taint.0 = taint.0.min(effective_floor)`. -/
def updateTaintFloor (ts : TaintState) (effectiveFloor : TrustTier) : TrustTier :=
  tierMin ts.floor effectiveFloor

/-- Outbound floor (`arm_ring.rs:939`): `taint.0.min(role_trust_tier(&self.role))`. -/
def outboundTaintFloor (selfRole : ArmRole) (ts : TaintState) : TrustTier :=
  tierMin ts.floor (roleTrustTier selfRole)

/-- Effective floor computation (`arm_ring.rs:1051-1055`). -/
def computeEffectiveFloor
    (provenance : List ProvenanceHop)
    (msgTaintFloor : TrustTier)
    (senderRole : ArmRole) : TrustTier :=
  provenance.foldl (fun acc hp => tierMin acc (roleTrustTier hp.role))
    (tierMin msgTaintFloor (roleTrustTier senderRole))

private theorem list_take_append_drop {α : Type} (n : Nat) (l : List α) :
    l.take n ++ l.drop n = l := by
  induction n generalizing l with
  | zero => simp [List.take, List.drop]
  | succ n ih =>
    cases l with
    | nil => simp [List.take, List.drop]
    | cons a as =>
      simp only [List.take, List.drop, List.cons_append]
      rw [ih as]

private theorem list_drop_length {α : Type} (n : Nat) (l : List α) :
    (l.drop n).length = l.length - n := by
  induction n generalizing l with
  | zero => simp [List.drop]
  | succ n ih =>
    cases l with
    | nil => simp [List.drop]
    | cons _ as =>
      simp only [List.drop, List.length_cons]
      rw [ih as]
      omega

private theorem list_find?_some {α : Type} (p : α → Bool) (l : List α) (u : α)
    (h : l.find? p = some u) : p u = true := by
  induction l with
  | nil => rw [List.find?_nil] at h; cases h
  | cons a as ih =>
    cases hpa : p a
    · rw [List.find?_cons, hpa] at h
      exact ih h
    · rw [List.find?_cons, hpa] at h
      injection h with heq
      subst heq
      exact hpa

private theorem list_find?_none {α : Type} (p : α → Bool) (l : List α)
    (h : l.find? p = none) : ∀ x ∈ l, p x = false := by
  induction l with
  | nil => intro x hx; cases hx
  | cons a as ih =>
    cases hpa : p a
    · rw [List.find?_cons, hpa] at h
      intro x hx
      cases hx with
      | head => exact hpa
      | tail _ hmem => exact ih h x hmem
    · rw [List.find?_cons, hpa] at h
      cases h

private theorem list_any_eq_true_exists {α : Type} (p : α → Bool) :
    ∀ (xs : List α), xs.any p = true → ∃ x, x ∈ xs ∧ p x = true
  | [], h => by rw [List.any_nil] at h; cases h
  | x :: xs, h => by
    cases hpx : p x
    · rw [List.any_cons, hpx, Bool.false_or] at h
      obtain ⟨y, hy, hpy⟩ := list_any_eq_true_exists p xs h
      exact ⟨y, List.Mem.tail _ hy, hpy⟩
    · exact ⟨x, List.Mem.head _, hpx⟩

private theorem list_mem_append_split {α : Type} {x : α} :
    ∀ {xs ys : List α}, x ∈ xs ++ ys → x ∈ xs ∨ x ∈ ys
  | [], _, h => Or.inr h
  | a :: xs, ys, h => by
    cases h with
    | head => exact Or.inl (List.Mem.head _)
    | tail _ hmem =>
      rcases list_mem_append_split hmem with h1 | h2
      · exact Or.inl (List.Mem.tail _ h1)
      · exact Or.inr h2

/-- Provenance truncation (`arm_ring.rs:1093-1117`). -/
def truncateProvenance (hops : List ProvenanceHop) : List ProvenanceHop :=
  let maxLen := MAX_RELAY_HOPS - 1
  if hops.length ≤ maxLen then
    hops
  else
    let excess := hops.length - maxLen
    let pref := hops.take excess
    let suff := hops.drop excess
    match pref.find? (fun h => roleTrustTier h.role == .Untrusted) with
    | none => suff
    | some u =>
      if suff.any (fun h => roleTrustTier h.role == .Untrusted) then
        suff
      else
        match suff with
        | [] => [u]
        | _ :: rest => u :: rest

inductive MeshSecurityError : Type where
  | EnclaveViolation
  | IdentitySpoofingDetected
  | DelegationScopeViolation
  | CapabilityDenied
  deriving DecidableEq, Repr

structure ArmRingMeshMessage where
  senderArmId : Nat
  senderRole : ArmRole
  senderGeneration : Nat
  targetArmId : Nat
  targetGeneration : Nat
  kind : MessageKind
  correlationIdLen : Nat
  payloadLen : Nat
  provenance : List ProvenanceHop
  taintFloor : TrustTier
  hmacVerified : Bool
  deriving DecidableEq, Repr

structure VerifiedMeshMessage where
  message : ArmRingMeshMessage
  recipientArmId : Nat
  recipientRole : ArmRole
  roleChain : List ArmRole
  effectiveTaintFloor : TrustTier
  deriving DecidableEq, Repr

/-- Models `ArmContainmentRing::verify_incoming_message` (`arm_ring.rs:984-1127`)
    given authenticated active epoch and HMAC verification. -/
def verifyIncomingMessage
    (selfArmId : Nat)
    (selfRole : ArmRole)
    (selfEpochValid : Bool)
    (ts : TaintState)
    (msg : ArmRingMeshMessage) :
    Except MeshSecurityError (VerifiedMeshMessage × TaintState) :=
  if msg.targetArmId != selfArmId then
    .error .IdentitySpoofingDetected
  else if msg.senderGeneration == 0 then
    .error .IdentitySpoofingDetected
  else if msg.provenance.length > MAX_RELAY_HOPS - 1 then
    .error .DelegationScopeViolation
  else if !selfEpochValid then
    .error .CapabilityDenied
  else if !msg.hmacVerified then
    .error .IdentitySpoofingDetected
  else if !(tierBle msg.taintFloor (roleTrustTier msg.senderRole)) then
    .error .IdentitySpoofingDetected
  else
    let roleChain := msg.provenance.map (·.role) ++ [msg.senderRole, selfRole]
    let effectiveFloor := computeEffectiveFloor msg.provenance msg.taintFloor msg.senderRole
    let audit := auditRoleChain roleChain
    let stickyVeto :=
      audit.allowed && (effectiveFloor == .Untrusted) &&
        (roleTrustTier selfRole == .PrivilegedSink)
    if (!audit.allowed) || stickyVeto then
      .error .DelegationScopeViolation
    else
      let newFloor := updateTaintFloor ts effectiveFloor
      let senderHop : ProvenanceHop :=
        { armId := msg.senderArmId, role := msg.senderRole, generation := msg.senderGeneration }
      let appended := (msg.provenance ++ [senderHop]).foldl
        (fun acc h => if acc.contains h then acc else acc ++ [h]) ts.provenance
      let newState : TaintState := { floor := newFloor, provenance := truncateProvenance appended }
      .ok ({ message := msg
             recipientArmId := selfArmId
             recipientRole := selfRole
             roleChain := roleChain
             effectiveTaintFloor := effectiveFloor }, newState)

structure RouteEntry where
  senderArmId : Nat
  recipientArmId : Nat
  kind : Option MessageKind
  deriving DecidableEq, Repr, BEq

structure MeshGuard where
  allowedRoutes : List RouteEntry
  deriving DecidableEq, Repr

/-- Models `MeshGuard::validate_message` (`mesh_guard.rs:362-419`). -/
def validateMeshMessage
    (guard : MeshGuard)
    (verified : VerifiedMeshMessage) :
    Except MeshSecurityError HomologicalAuditReport :=
  let msg := verified.message
  if msg.correlationIdLen > MAX_CORRELATION_ID_BYTES then
    .error .EnclaveViolation
  else if msg.payloadLen > MAX_MESH_PAYLOAD_BYTES then
    .error .EnclaveViolation
  else if verified.effectiveTaintFloor == .Untrusted &&
      roleTrustTier verified.recipientRole == .PrivilegedSink then
    .error .DelegationScopeViolation
  else
    let report := auditRoleChain verified.roleChain
    if !report.allowed then
      .error .DelegationScopeViolation
    else
      let exactRoute : RouteEntry :=
        { senderArmId := msg.senderArmId, recipientArmId := verified.recipientArmId, kind := some msg.kind }
      let wildRoute : RouteEntry :=
        { senderArmId := msg.senderArmId, recipientArmId := verified.recipientArmId, kind := none }
      if guard.allowedRoutes.contains exactRoute || guard.allowedRoutes.contains wildRoute then
        .ok report
      else
        .error .CapabilityDenied

/-- Theorem: Passing `MeshGuard::validate_message` guarantees zero coboundary residue,
    valid bounded chain length, no `Untrusted` taint floor reaching a `PrivilegedSink`,
    and no `Untrusted` hop anywhere in the chain ending at a `PrivilegedSink`. -/
theorem no_proxy_laundering
    (guard : MeshGuard)
    (verified : VerifiedMeshMessage)
    (report : HomologicalAuditReport)
    (hValid : validateMeshMessage guard verified = .ok report) :
    report.allowed = true ∧
    report.coboundaryResidue = 0 ∧
    report.boundarySquaredZero = true ∧
    2 ≤ verified.roleChain.length ∧
    verified.roleChain.length ≤ MAX_RELAY_HOPS + 1 ∧
    (roleTrustTier verified.recipientRole = .PrivilegedSink →
      verified.roleChain.getLast? = some verified.recipientRole →
      verified.effectiveTaintFloor ≠ .Untrusted ∧
      ∀ r ∈ verified.roleChain, roleTrustTier r ≠ .Untrusted) := by
  unfold validateMeshMessage at hValid
  dsimp only at hValid
  by_cases hcid : verified.message.correlationIdLen > MAX_CORRELATION_ID_BYTES
  · simp only [eq_true hcid, ite_true] at hValid; cases hValid
  · simp only [eq_false hcid, ite_false] at hValid
    by_cases hpay : verified.message.payloadLen > MAX_MESH_PAYLOAD_BYTES
    · simp only [eq_true hpay, ite_true] at hValid; cases hValid
    · simp only [eq_false hpay, ite_false] at hValid
      by_cases hst : (verified.effectiveTaintFloor == .Untrusted &&
          roleTrustTier verified.recipientRole == .PrivilegedSink) = true
      · simp only [eq_true hst, ite_true] at hValid; cases hValid
      · simp only [eq_false hst, ite_false] at hValid
        by_cases hallow : (!(auditRoleChain verified.roleChain).allowed) = true
        · simp only [eq_true hallow, ite_true] at hValid; cases hValid
        · simp only [eq_false hallow, ite_false] at hValid
          have ha : (auditRoleChain verified.roleChain).allowed = true := by
            cases hca : (auditRoleChain verified.roleChain).allowed
            · rw [hca] at hallow; exact absurd rfl hallow
            · rfl
          have hrep : report = auditRoleChain verified.roleChain := by
            by_cases hrt : (guard.allowedRoutes.contains
                { senderArmId := verified.message.senderArmId
                  recipientArmId := verified.recipientArmId
                  kind := some verified.message.kind } ||
                guard.allowedRoutes.contains
                { senderArmId := verified.message.senderArmId
                  recipientArmId := verified.recipientArmId
                  kind := none }) = true
            · simp only [eq_true hrt, ite_true] at hValid
              injection hValid with hr
              exact hr.symm
            · simp only [eq_false hrt, ite_false] at hValid; cases hValid
          subst hrep
          obtain ⟨hcb, hbsq, hmin, hmax⟩ := auditRoleChain_allowed_props ha
          refine ⟨ha, hcb, hbsq, hmin, hmax, ?_⟩
          intro hSink hLast
          refine ⟨?_, ?_⟩
          · intro hUnt
            have hboth : (verified.effectiveTaintFloor == .Untrusted &&
                roleTrustTier verified.recipientRole == .PrivilegedSink) = true := by
              simp [hUnt, hSink]
            exact hst hboth
          · intro r hr hru
            have hblocked := auditRoleChain_blocks_untrusted_to_privileged
              verified.roleChain verified.recipientRole hLast hSink ⟨r, hr, hru⟩
            rw [hblocked] at ha
            cases ha

/-- Theorem: `MeshGuard` is fail-closed when `allowedRoutes` is empty. -/
theorem meshGuard_empty_routes_deny
    (verified : VerifiedMeshMessage) :
    ∃ e, validateMeshMessage { allowedRoutes := [] } verified = .error e := by
  unfold validateMeshMessage
  dsimp only
  by_cases hcid : verified.message.correlationIdLen > MAX_CORRELATION_ID_BYTES
  · simp only [eq_true hcid, ite_true]; exact ⟨_, rfl⟩
  · simp only [eq_false hcid, ite_false]
    by_cases hpay : verified.message.payloadLen > MAX_MESH_PAYLOAD_BYTES
    · simp only [eq_true hpay, ite_true]; exact ⟨_, rfl⟩
    · simp only [eq_false hpay, ite_false]
      by_cases hst : (verified.effectiveTaintFloor == .Untrusted &&
          roleTrustTier verified.recipientRole == .PrivilegedSink) = true
      · simp only [eq_true hst, ite_true]; exact ⟨_, rfl⟩
      · simp only [eq_false hst, ite_false]
        by_cases hallow : (!(auditRoleChain verified.roleChain).allowed) = true
        · simp only [eq_true hallow, ite_true]; exact ⟨_, rfl⟩
        · simp only [eq_false hallow, ite_false]
          have hfalse : (([] : List RouteEntry).contains
              { senderArmId := verified.message.senderArmId
                recipientArmId := verified.recipientArmId
                kind := some verified.message.kind } ||
              ([] : List RouteEntry).contains
              { senderArmId := verified.message.senderArmId
                recipientArmId := verified.recipientArmId
                kind := none }) = false := rfl
          rw [hfalse]
          simp only [Bool.false_eq_true, ite_false]
          exact ⟨_, rfl⟩

private theorem foldl_tierMin_eq_untrusted_of_init (acc : TrustTier) (hops : List ProvenanceHop)
    (h : acc = .Untrusted) :
    hops.foldl (fun a hp => tierMin a (roleTrustTier hp.role)) acc = .Untrusted := by
  induction hops generalizing acc with
  | nil => exact h
  | cons hp rest ih =>
    simp only [List.foldl]
    apply ih
    rw [tierMin_eq_untrusted_iff]
    exact Or.inl h

private theorem foldl_tierMin_eq_untrusted_of_mem (acc : TrustTier) (hops : List ProvenanceHop)
    (hmem : ∃ hp ∈ hops, roleTrustTier hp.role = .Untrusted) :
    hops.foldl (fun a hp => tierMin a (roleTrustTier hp.role)) acc = .Untrusted := by
  induction hops generalizing acc with
  | nil =>
    obtain ⟨_, h, _⟩ := hmem
    cases h
  | cons hp rest ih =>
    obtain ⟨x, hxmem, hxu⟩ := hmem
    simp only [List.foldl]
    cases hxmem with
    | head =>
      apply foldl_tierMin_eq_untrusted_of_init
      rw [tierMin_eq_untrusted_iff]
      exact Or.inr hxu
    | tail _ htail =>
      exact ih (tierMin acc (roleTrustTier hp.role)) ⟨x, htail, hxu⟩

/-- Corollary: `ArmContainmentRing::verify_incoming_message` rejects any message carrying
    `Untrusted` taint floor, an `Untrusted` sender, or any `Untrusted` provenance hop
    when the recipient is a `PrivilegedSink`. -/
theorem verifyIncomingMessage_blocks_untrusted_to_privileged
    (selfArmId : Nat)
    (selfRole : ArmRole)
    (selfEpochValid : Bool)
    (ts : TaintState)
    (msg : ArmRingMeshMessage)
    (verified : VerifiedMeshMessage)
    (newState : TaintState)
    (hOk : verifyIncomingMessage selfArmId selfRole selfEpochValid ts msg = .ok (verified, newState))
    (hSink : roleTrustTier selfRole = .PrivilegedSink) :
    verified.effectiveTaintFloor ≠ .Untrusted ∧
    msg.taintFloor ≠ .Untrusted ∧
    roleTrustTier msg.senderRole ≠ .Untrusted ∧
    ∀ hp ∈ msg.provenance, roleTrustTier hp.role ≠ .Untrusted := by
  unfold verifyIncomingMessage at hOk
  by_cases h1 : (msg.targetArmId != selfArmId) = true
  · simp only [eq_true h1, ite_true] at hOk; cases hOk
  · simp only [eq_false h1, ite_false] at hOk
    by_cases h2 : (msg.senderGeneration == 0) = true
    · simp only [eq_true h2, ite_true] at hOk; cases hOk
    · simp only [eq_false h2, ite_false] at hOk
      by_cases h3 : msg.provenance.length > MAX_RELAY_HOPS - 1
      · simp only [eq_true h3, ite_true] at hOk; cases hOk
      · simp only [eq_false h3, ite_false] at hOk
        by_cases h4 : (!selfEpochValid) = true
        · simp only [eq_true h4, ite_true] at hOk; cases hOk
        · simp only [eq_false h4, ite_false] at hOk
          by_cases h5 : (!msg.hmacVerified) = true
          · simp only [eq_true h5, ite_true] at hOk; cases hOk
          · simp only [eq_false h5, ite_false] at hOk
            by_cases h6 : (!(tierBle msg.taintFloor (roleTrustTier msg.senderRole))) = true
            · simp only [eq_true h6, ite_true] at hOk; cases hOk
            · simp only [eq_false h6, ite_false] at hOk
              by_cases hveto : ((!(auditRoleChain (msg.provenance.map (·.role) ++ [msg.senderRole, selfRole])).allowed) ||
                  ((auditRoleChain (msg.provenance.map (·.role) ++ [msg.senderRole, selfRole])).allowed &&
                    (computeEffectiveFloor msg.provenance msg.taintFloor msg.senderRole == .Untrusted) &&
                    (roleTrustTier selfRole == .PrivilegedSink))) = true
              · simp only [eq_true hveto, ite_true] at hOk; cases hOk
              · simp only [eq_false hveto, ite_false] at hOk
                injection hOk with hpair
                have hvis : verified.effectiveTaintFloor =
                    computeEffectiveFloor msg.provenance msg.taintFloor msg.senderRole := by
                  have hfst := congrArg (fun v => v.effectiveTaintFloor) (congrArg Prod.fst hpair)
                  exact hfst.symm
                have hne_eff : computeEffectiveFloor msg.provenance msg.taintFloor msg.senderRole ≠ .Untrusted := by
                  intro heq
                  by_cases ha : (auditRoleChain (msg.provenance.map (·.role) ++ [msg.senderRole, selfRole])).allowed = true
                  · apply hveto
                    simp [ha, heq, hSink]
                  · apply hveto
                    have haf : (auditRoleChain (msg.provenance.map (·.role) ++ [msg.senderRole, selfRole])).allowed = false := by
                      cases hca : (auditRoleChain (msg.provenance.map (·.role) ++ [msg.senderRole, selfRole])).allowed
                      · rfl
                      · exact absurd hca ha
                    simp [haf]
                refine ⟨by rw [hvis]; exact hne_eff, ?_, ?_, ?_⟩
                · intro hmsg
                  apply hne_eff
                  unfold computeEffectiveFloor
                  apply foldl_tierMin_eq_untrusted_of_init
                  rw [tierMin_eq_untrusted_iff]
                  exact Or.inl hmsg
                · intro hsnd
                  apply hne_eff
                  unfold computeEffectiveFloor
                  apply foldl_tierMin_eq_untrusted_of_init
                  rw [tierMin_eq_untrusted_iff]
                  exact Or.inr hsnd
                · intro hp hmem hpu
                  apply hne_eff
                  unfold computeEffectiveFloor
                  exact foldl_tierMin_eq_untrusted_of_mem _ _ ⟨hp, hmem, hpu⟩

/-- Theorem: Sticky taint updates are monotonically non-increasing in privilege tier. -/
theorem sticky_taint_monotonic
    (ts : TaintState)
    (effectiveFloor : TrustTier) :
    tierLe (updateTaintFloor ts effectiveFloor) ts.floor ∧
    tierLe (updateTaintFloor ts effectiveFloor) effectiveFloor :=
  ⟨tierMin_le_left ts.floor effectiveFloor, tierMin_le_right ts.floor effectiveFloor⟩

theorem sticky_taint_fold_monotonic
    (init : TrustTier)
    (floors : List TrustTier) :
    tierLe (floors.foldl tierMin init) init := by
  induction floors generalizing init with
  | nil => exact tierLe_refl init
  | cons f fs ih =>
    simp only [List.foldl]
    exact tierLe_trans (ih (tierMin init f)) (tierMin_le_left init f)

/-- Theorem: Once a ring's sticky taint floor reaches `Untrusted`, it remains `Untrusted`
    across all inbound updates and all outbound signed messages within that epoch. -/
theorem sticky_taint_untrusted_absorbing
    (ts : TaintState)
    (effectiveFloor : TrustTier)
    (selfRole : ArmRole)
    (hUntrusted : ts.floor = .Untrusted) :
    updateTaintFloor ts effectiveFloor = .Untrusted ∧
    outboundTaintFloor selfRole { ts with floor := updateTaintFloor ts effectiveFloor } = .Untrusted := by
  unfold updateTaintFloor outboundTaintFloor
  rw [hUntrusted]
  dsimp only
  cases effectiveFloor <;> cases roleTrustTier selfRole <;> decide

/-- Theorem: Provenance truncation keeps chain length ≤ `MAX_RELAY_HOPS - 1` (15)
    while always preserving at least one `Untrusted` hop if any existed before truncation. -/
theorem provenance_truncation_preserves_untrusted
    (hops : List ProvenanceHop)
    (hHas : ∃ h ∈ hops, roleTrustTier h.role = .Untrusted) :
    (truncateProvenance hops).length ≤ MAX_RELAY_HOPS - 1 ∧
    ∃ h ∈ truncateProvenance hops, roleTrustTier h.role = .Untrusted := by
  unfold truncateProvenance
  dsimp only
  by_cases hlen : hops.length ≤ MAX_RELAY_HOPS - 1
  · simp only [eq_true hlen, ite_true]
    exact ⟨trivial, hHas⟩
  · simp only [eq_false hlen, ite_false]
    have hsuff_len : (hops.drop (hops.length - (MAX_RELAY_HOPS - 1))).length = MAX_RELAY_HOPS - 1 := by
      rw [list_drop_length]
      omega
    have hsplit : hops.take (hops.length - (MAX_RELAY_HOPS - 1)) ++
        hops.drop (hops.length - (MAX_RELAY_HOPS - 1)) = hops :=
      list_take_append_drop _ hops
    cases hfind : (hops.take (hops.length - (MAX_RELAY_HOPS - 1))).find?
        (fun h => roleTrustTier h.role == .Untrusted) with
    | none =>
      dsimp only
      refine ⟨Nat.le_of_eq hsuff_len, ?_⟩
      obtain ⟨h, hh_mem, hh_tier⟩ := hHas
      have h_app : h ∈ hops.take (hops.length - (MAX_RELAY_HOPS - 1)) ++
          hops.drop (hops.length - (MAX_RELAY_HOPS - 1)) := by
        rw [hsplit]; exact hh_mem
      rcases list_mem_append_split h_app with hpref | hsuff
      · have hnone := list_find?_none (fun h => roleTrustTier h.role == .Untrusted) _ hfind h hpref
        simp [hh_tier] at hnone
      · exact ⟨h, hsuff, hh_tier⟩
    | some u =>
      dsimp only
      have hu_tier : roleTrustTier u.role = .Untrusted := by
        have hfp := list_find?_some (fun h => roleTrustTier h.role == .Untrusted) _ u hfind
        exact beq_iff_eq.mp hfp
      by_cases hany : (hops.drop (hops.length - (MAX_RELAY_HOPS - 1))).any
          (fun h => roleTrustTier h.role == .Untrusted) = true
      · simp only [eq_true hany, ite_true]
        obtain ⟨h, hh_mem, hh_tier⟩ :=
          list_any_eq_true_exists (fun (h : ProvenanceHop) => roleTrustTier h.role == .Untrusted) _ hany
        exact ⟨Nat.le_of_eq hsuff_len, ⟨h, hh_mem, beq_iff_eq.mp hh_tier⟩⟩
      · simp only [eq_false hany, ite_false]
        cases hsuff : hops.drop (hops.length - (MAX_RELAY_HOPS - 1)) with
        | nil =>
          dsimp only
          refine ⟨by simp [MAX_RELAY_HOPS], ⟨u, List.Mem.head _, hu_tier⟩⟩
        | cons _ rest =>
          dsimp only
          rw [hsuff] at hsuff_len
          have hlen_cons : (u :: rest).length = MAX_RELAY_HOPS - 1 := by
            simp only [List.length_cons] at hsuff_len ⊢
            exact hsuff_len
          exact ⟨Nat.le_of_eq hlen_cons, ⟨u, List.Mem.head _, hu_tier⟩⟩

/-! ### `DelegationScopeGuard` Model (`src/security/delegation.rs:7-156`) -/

/-- Exact static capability sets matching `DelegationScopeGuard::permitted_tools_for_role` (`delegation.rs:25-102`). -/
def delegationPermittedTools : ArmRole → List String
  | .UntrustedDocIngest => ["doc_extractor"]
  | .AccountingLedgerWrite => ["ledger_writer"]
  | .NetworkEgress => ["http_egress"]
  | .OutboundNotification => ["notifier"]
  | .TarpitDecoyDefense => ["quarantine"]
  | .KernelLevelSentinel => ["kernel_sentinel", "hardware_clamp", "autotomy_kill"]
  | .CedarPolicyEvaluation => ["cedar_evaluator", "policy_compiler"]
  | .AtlasThreatIntelligence => ["atlas_sync", "stix_parser"]
  | .AnomalyDetection => ["behavioral_sentinel", "entropy_calc"]
  | .VulnerabilityResearch => ["vulnerability_scanner", "attack_chain"]
  | .ContinuousOssFuzz => ["fuzz_mutator", "corpus_manager"]
  | .ContinuousOsvScanner => ["osv_client", "dep_advisor"]
  | .AutonomousProtocolResearch => []
  | .DifferentialProtocolAnalyzer => ["protocol_analyzer", "fuzz_divergence"]
  | .PostQuantumAttestation =>
      ["pqc_kem_encapsulate", "pqc_kem_decapsulate", "pqc_dsa_sign", "pqc_dsa_verify", "pqc_cbom_scanner"]
  | .EvolutionaryOptimizer => ["evolution_evaluate", "evolution_stage"]
  | .DreamRsiOptimizer => ["dream_rsi_replay", "dream_rsi_rollout", "dream_rsi_prioritize"]
  | .RecursiveHarnessOptimizer =>
      ["harness2_propose_probe_compose", "harness2_validate_tree", "harness2_experience_library"]

structure DelegationScopeGuard where
  maxDelegationDepth : Nat := MAX_DELEGATION_DEPTH
  deriving DecidableEq, Repr

/-- Models `DelegationScopeGuard::validate_delegation` (`delegation.rs:107-155`). -/
def validateDelegation
    (guard : DelegationScopeGuard)
    (originatorRole : ArmRole)
    (delegationChain : List ArmRole)
    (targetRole : ArmRole)
    (requestedTool : String) :
    Except MeshSecurityError Unit :=
  if delegationChain.length > guard.maxDelegationDepth then
    .error .DelegationScopeViolation
  else if !(delegationPermittedTools originatorRole).contains requestedTool then
    .error .DelegationScopeViolation
  else if !(delegationChain.all (fun hop => (delegationPermittedTools hop).contains requestedTool)) then
    .error .DelegationScopeViolation
  else if !(delegationPermittedTools targetRole).contains requestedTool then
    .error .DelegationScopeViolation
  else
    .ok ()

private theorem list_all_eq_true {α : Type} (p : α → Bool) :
    ∀ (xs : List α), xs.all p = true → ∀ x ∈ xs, p x = true
  | [], _ => fun _ hx => by cases hx
  | a :: as, h => by
    cases hpa : p a
    · rw [List.all_cons, hpa, Bool.false_and] at h
      cases h
    · rw [List.all_cons, hpa, Bool.true_and] at h
      intro x hx
      cases hx with
      | head => exact hpa
      | tail _ hmem => exact list_all_eq_true p as h x hmem

/-- Theorem: Validated delegation cannot escalate authority beyond the intersection
    of `originatorRole`, every intermediate hop in `delegationChain`, and `targetRole`,
    and strictly respects `maxDelegationDepth`. -/
theorem delegation_no_escalation
    (guard : DelegationScopeGuard)
    (originatorRole : ArmRole)
    (delegationChain : List ArmRole)
    (targetRole : ArmRole)
    (requestedTool : String)
    (hOk : validateDelegation guard originatorRole delegationChain targetRole requestedTool = .ok ()) :
    delegationChain.length ≤ guard.maxDelegationDepth ∧
    (delegationPermittedTools originatorRole).contains requestedTool = true ∧
    (∀ hop ∈ delegationChain, (delegationPermittedTools hop).contains requestedTool = true) ∧
    (delegationPermittedTools targetRole).contains requestedTool = true := by
  unfold validateDelegation at hOk
  by_cases h1 : delegationChain.length > guard.maxDelegationDepth
  · simp only [eq_true h1, ite_true] at hOk; cases hOk
  · simp only [eq_false h1, ite_false] at hOk
    by_cases h2 : (!(delegationPermittedTools originatorRole).contains requestedTool) = true
    · simp only [eq_true h2, ite_true] at hOk; cases hOk
    · simp only [eq_false h2, ite_false] at hOk
      by_cases h3 : (!(delegationChain.all (fun hop => (delegationPermittedTools hop).contains requestedTool))) = true
      · simp only [eq_true h3, ite_true] at hOk; cases hOk
      · simp only [eq_false h3, ite_false] at hOk
        by_cases h4 : (!(delegationPermittedTools targetRole).contains requestedTool) = true
        · simp only [eq_true h4, ite_true] at hOk; cases hOk
        · simp only [eq_false h4, ite_false] at hOk
          have hOrig : (delegationPermittedTools originatorRole).contains requestedTool = true := by
            cases hc : (delegationPermittedTools originatorRole).contains requestedTool
            · rw [hc] at h2; exact absurd rfl h2
            · rfl
          have hAll : delegationChain.all (fun hop => (delegationPermittedTools hop).contains requestedTool) = true := by
            cases hc : delegationChain.all (fun hop => (delegationPermittedTools hop).contains requestedTool)
            · rw [hc] at h3; exact absurd rfl h3
            · rfl
          have hTarg : (delegationPermittedTools targetRole).contains requestedTool = true := by
            cases hc : (delegationPermittedTools targetRole).contains requestedTool
            · rw [hc] at h4; exact absurd rfl h4
            · rfl
          exact ⟨Nat.le_of_not_lt h1, hOrig, list_all_eq_true _ delegationChain hAll, hTarg⟩

theorem delegation_depth_exceeded_denied
    (guard : DelegationScopeGuard)
    (originatorRole : ArmRole)
    (delegationChain : List ArmRole)
    (targetRole : ArmRole)
    (requestedTool : String)
    (hDeep : guard.maxDelegationDepth < delegationChain.length) :
    validateDelegation guard originatorRole delegationChain targetRole requestedTool =
      .error .DelegationScopeViolation := by
  unfold validateDelegation
  simp only [eq_true hDeep, ite_true]

theorem delegation_empty_chain_iff_intersection
    (guard : DelegationScopeGuard)
    (originatorRole targetRole : ArmRole)
    (requestedTool : String) :
    validateDelegation guard originatorRole [] targetRole requestedTool = .ok () ↔
      ((delegationPermittedTools originatorRole).contains requestedTool = true ∧
       (delegationPermittedTools targetRole).contains requestedTool = true) := by
  constructor
  · intro hOk
    obtain ⟨_, hOrig, _, hTarg⟩ := delegation_no_escalation guard originatorRole [] targetRole requestedTool hOk
    exact ⟨hOrig, hTarg⟩
  · rintro ⟨hOrig, hTarg⟩
    unfold validateDelegation
    have h0 : ¬(([] : List ArmRole).length > guard.maxDelegationDepth) := by simp
    simp only [eq_false h0, ite_false, hOrig, hTarg, List.all_nil, Bool.not_true,
      Bool.false_eq_true]

end AgentOctopusFormal
