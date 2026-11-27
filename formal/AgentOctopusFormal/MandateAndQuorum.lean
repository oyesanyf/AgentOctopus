import AgentOctopusFormal.CoreTypes

namespace AgentOctopusFormal

/-! # AgentMesh Mandate Attenuation & M-of-N Quorum Policy Guard Formalization

Faithfully mirrors:
- `src/security/agentmesh/mandate_attenuation.rs` (`MAX_DELEGATION_DEPTH = 8`, `ALLOWED_SCHEMES`,
  `validate_mesh_uri`, `AttenuatedMandate::{create_root, attenuate, verify_chain}`,
  `authorize_service_call`, `authorize_publish`)
- `src/ledger/quorum.rs` & `src/ledger/receipt.rs` (`PolicyProposal`, `PolicyAttestation`,
  `QuorumPolicyGuard::submit_and_commit_proposal`, anti-sybil duplicate rejection)
-/

/-! ### Constants (`mandate_attenuation.rs:19-20`) -/

/-- Named `MANDATE_MAX_DELEGATION_DEPTH` to avoid colliding with
    `HomologicalMesh.MAX_DELEGATION_DEPTH := 2` in `namespace AgentOctopusFormal`. -/
def MANDATE_MAX_DELEGATION_DEPTH : Nat := 8

def ALLOWED_SCHEMES : List String :=
  ["mcp://", "a2a://", "inference://", "egress://"]

/-! ### Decidable List Membership & Subset Helpers -/

def listMemBool {α : Type} [DecidableEq α] (x : α) : List α → Bool
  | [] => false
  | y :: ys => decide (x = y) || listMemBool x ys

def listSubset {α : Type} [DecidableEq α] (xs ys : List α) : Bool :=
  xs.all (fun x => listMemBool x ys)

private theorem mandate_list_all_eq_true {α : Type} (p : α → Bool) :
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
      | tail _ hmem => exact mandate_list_all_eq_true p as h x hmem

theorem listMemBool_eq_true_iff {α : Type} [DecidableEq α] (x : α) (ys : List α) :
    listMemBool x ys = true ↔ x ∈ ys := by
  induction ys with
  | nil =>
    simp [listMemBool]
  | cons y ys ih =>
    unfold listMemBool
    rw [Bool.or_eq_true, decide_eq_true_eq, ih]
    constructor
    · rintro (rfl | hmem)
      · exact List.Mem.head _
      · exact List.Mem.tail _ hmem
    · intro hmem
      cases hmem with
      | head => exact Or.inl rfl
      | tail _ htail => exact Or.inr htail

theorem listMemBool_eq_false_iff {α : Type} [DecidableEq α] (x : α) (ys : List α) :
    listMemBool x ys = false ↔ x ∉ ys := by
  constructor
  · intro hf hmem
    have ht := (listMemBool_eq_true_iff x ys).mpr hmem
    rw [hf] at ht
    cases ht
  · intro hnot
    cases hb : listMemBool x ys
    · rfl
    · exact absurd ((listMemBool_eq_true_iff x ys).mp hb) hnot

theorem listSubset_eq_true_iff {α : Type} [DecidableEq α] (xs ys : List α) :
    listSubset xs ys = true ↔ ∀ x, x ∈ xs → x ∈ ys := by
  unfold listSubset
  constructor
  · intro hAll x hx
    have hMem := mandate_list_all_eq_true (fun z => listMemBool z ys) xs hAll x hx
    exact (listMemBool_eq_true_iff x ys).mp hMem
  · intro hSub
    induction xs with
    | nil => rfl
    | cons x xs ih =>
      rw [List.all_cons, Bool.and_eq_true]
      refine ⟨(listMemBool_eq_true_iff x ys).mpr (hSub x (List.Mem.head _)), ?_⟩
      exact ih (fun z hz => hSub z (List.Mem.tail _ hz))

theorem listSubset_trans {α : Type} [DecidableEq α] {xs ys zs : List α}
    (h1 : listSubset xs ys = true) (h2 : listSubset ys zs = true) :
    listSubset xs zs = true := by
  rw [listSubset_eq_true_iff] at h1 h2 ⊢
  intro x hx
  exact h2 x (h1 x hx)

/-! ### Part A: Mesh URI Validation & `AttenuatedMandate` (`mandate_attenuation.rs`) -/

inductive MeshScheme : Type where
  | mcp
  | a2a
  | inference
  | egress
  | invalid
  deriving DecidableEq, Repr, BEq

def MeshScheme.toPrefix : MeshScheme → String
  | .mcp => "mcp://"
  | .a2a => "a2a://"
  | .inference => "inference://"
  | .egress => "egress://"
  | .invalid => ""

def isAllowedScheme : MeshScheme → Bool
  | .mcp => true
  | .a2a => true
  | .inference => true
  | .egress => true
  | .invalid => false

theorem isAllowedScheme_iff_mem_allowed_schemes (s : MeshScheme) :
    isAllowedScheme s = true ↔ s.toPrefix ∈ ALLOWED_SCHEMES := by
  cases s <;> decide

/-- URI abstraction capturing scheme prefix and target safety checks
    (`validate_mesh_uri`, `mandate_attenuation.rs:78-222`). -/
structure MeshUri where
  scheme : MeshScheme
  hostPath : String
  safeTarget : Bool
  deriving DecidableEq, Repr, BEq

def validateMeshUri (u : MeshUri) : Bool :=
  isAllowedScheme u.scheme && u.safeTarget

inductive MandateError : Type where
  | InvalidUriScheme
  | ProhibitedTarget
  | PrivilegeEscalationService
  | PrivilegeEscalationPublish
  | MaxDelegationDepthExceeded
  | MandateExpired
  | MandateNotYetValid
  | SignatureFailure
  | HolderMismatch
  | ServiceCallUnauthorized
  | PublishUnauthorized
  deriving DecidableEq, Repr, BEq

structure DelegationLink where
  depth : Nat
  delegatorSpiffeId : String
  delegatorKey : Nat
  delegateeSpiffeId : String
  delegateeKey : Nat
  attenuatedServices : List MeshUri
  attenuatedPublish : List MeshUri
  delegatedAt : Nat
  expiresAt : Nat
  signatureValid : Bool
  deriving DecidableEq, Repr

structure AttenuatedMandate where
  mandateId : String
  rootIssuerSpiffeId : String
  rootVerifyingKey : Nat
  currentHolderSpiffeId : String
  depth : Nat
  allowedServices : List MeshUri
  allowedPublish : List MeshUri
  notBefore : Nat
  expiresAt : Nat
  delegationChain : List DelegationLink
  deriving DecidableEq, Repr

private def validateUriList : List MeshUri → Except MandateError Unit
  | [] => .ok ()
  | u :: us =>
    if !isAllowedScheme u.scheme then
      .error .InvalidUriScheme
    else if !u.safeTarget then
      .error .ProhibitedTarget
    else
      validateUriList us

private theorem validateUriList_ok_implies_valid :
    ∀ (us : List MeshUri), validateUriList us = .ok () →
      ∀ u ∈ us, validateMeshUri u = true
  | [], _ => fun _ hu => by cases hu
  | u :: us, hOk => by
    unfold validateUriList at hOk
    by_cases hSch : (!isAllowedScheme u.scheme) = true
    · simp only [eq_true hSch, ite_true] at hOk; cases hOk
    · simp only [eq_false hSch, ite_false] at hOk
      by_cases hSafe : (!u.safeTarget) = true
      · simp only [eq_true hSafe, ite_true] at hOk; cases hOk
      · simp only [eq_false hSafe, ite_false] at hOk
        have hSchTrue : isAllowedScheme u.scheme = true := by
          cases hc : isAllowedScheme u.scheme
          · rw [hc] at hSch; exact absurd rfl hSch
          · rfl
        have hSafeTrue : u.safeTarget = true := by
          cases hc : u.safeTarget
          · rw [hc] at hSafe; exact absurd rfl hSafe
          · rfl
        intro x hx
        cases hx with
        | head =>
          unfold validateMeshUri
          simp [hSchTrue, hSafeTrue]
        | tail _ hmem =>
          exact validateUriList_ok_implies_valid us hOk x hmem

/-- Models `AttenuatedMandate::create_root` (`mandate_attenuation.rs:298-358`). -/
def createRootMandate
    (mandateId rootIssuerSpiffeId : String)
    (rootVerifyingKey : Nat)
    (initialHolderSpiffeId : String)
    (initialHolderKey : Nat)
    (allowedServices allowedPublish : List MeshUri)
    (notBefore expiresAt : Nat)
    (rootSignatureValid : Bool) : Except MandateError AttenuatedMandate :=
  match validateUriList allowedServices, validateUriList allowedPublish with
  | .error e, _ => .error e
  | _, .error e => .error e
  | .ok (), .ok () =>
    if !rootSignatureValid then
      .error .SignatureFailure
    else
      let rootLink : DelegationLink :=
        { depth := 0
        , delegatorSpiffeId := rootIssuerSpiffeId
        , delegatorKey := rootVerifyingKey
        , delegateeSpiffeId := initialHolderSpiffeId
        , delegateeKey := initialHolderKey
        , attenuatedServices := allowedServices
        , attenuatedPublish := allowedPublish
        , delegatedAt := notBefore
        , expiresAt := expiresAt
        , signatureValid := true }
      .ok
        { mandateId := mandateId
        , rootIssuerSpiffeId := rootIssuerSpiffeId
        , rootVerifyingKey := rootVerifyingKey
        , currentHolderSpiffeId := initialHolderSpiffeId
        , depth := 0
        , allowedServices := allowedServices
        , allowedPublish := allowedPublish
        , notBefore := notBefore
        , expiresAt := expiresAt
        , delegationChain := [rootLink] }

/-- Models `AttenuatedMandate::attenuate` (`mandate_attenuation.rs:366-491`). -/
def attenuateMandate
    (m : AttenuatedMandate)
    (delegatorKey : Nat)
    (delegateeSpiffeId : String)
    (delegateeKey : Nat)
    (narrowedServices narrowedPublish : List MeshUri)
    (newExpiresAt now : Nat)
    (childSignatureValid : Bool) : Except MandateError AttenuatedMandate :=
  if now < m.notBefore then
    .error .MandateNotYetValid
  else if m.expiresAt < now then
    .error .MandateExpired
  else
    let nextDepth := m.depth + 1
    if MANDATE_MAX_DELEGATION_DEPTH < nextDepth then
      .error .MaxDelegationDepthExceeded
    else
      match validateUriList narrowedServices, validateUriList narrowedPublish with
      | .error e, _ => .error e
      | _, .error e => .error e
      | .ok (), .ok () =>
        if !listSubset narrowedServices m.allowedServices then
          .error .PrivilegeEscalationService
        else if !listSubset narrowedPublish m.allowedPublish then
          .error .PrivilegeEscalationPublish
        else
          match m.delegationChain.getLast? with
          | none => .error .SignatureFailure
          | some parentLink =>
            if delegatorKey != parentLink.delegateeKey then
              .error .SignatureFailure
            else if !decide (m.currentHolderSpiffeId = parentLink.delegateeSpiffeId) then
              .error .SignatureFailure
            else if !childSignatureValid then
              .error .SignatureFailure
            else
              let clampedExp := Nat.min newExpiresAt m.expiresAt
              let childLink : DelegationLink :=
                { depth := nextDepth
                , delegatorSpiffeId := m.currentHolderSpiffeId
                , delegatorKey := delegatorKey
                , delegateeSpiffeId := delegateeSpiffeId
                , delegateeKey := delegateeKey
                , attenuatedServices := narrowedServices
                , attenuatedPublish := narrowedPublish
                , delegatedAt := now
                , expiresAt := clampedExp
                , signatureValid := true }
              .ok
                { mandateId := m.mandateId
                , rootIssuerSpiffeId := m.rootIssuerSpiffeId
                , rootVerifyingKey := m.rootVerifyingKey
                , currentHolderSpiffeId := delegateeSpiffeId
                , depth := nextDepth
                , allowedServices := narrowedServices
                , allowedPublish := narrowedPublish
                , notBefore := m.notBefore
                , expiresAt := clampedExp
                , delegationChain := m.delegationChain ++ [childLink] }

def verifyLinksFrom (idx : Nat) (prev : DelegationLink) :
    List DelegationLink → Except MandateError DelegationLink
  | [] => .ok prev
  | link :: rest =>
    if link.depth != idx then
      .error .SignatureFailure
    else if link.delegatorKey != prev.delegateeKey then
      .error .SignatureFailure
    else if !decide (link.delegatorSpiffeId = prev.delegateeSpiffeId) then
      .error .SignatureFailure
    else if !link.signatureValid then
      .error .SignatureFailure
    else if !listSubset link.attenuatedServices prev.attenuatedServices then
      .error .PrivilegeEscalationService
    else if !listSubset link.attenuatedPublish prev.attenuatedPublish then
      .error .PrivilegeEscalationPublish
    else if prev.expiresAt < link.expiresAt then
      .error .MandateExpired
    else if link.delegatedAt < prev.delegatedAt then
      .error .MandateNotYetValid
    else
      verifyLinksFrom (idx + 1) link rest

/-- Models `AttenuatedMandate::verify_chain` (`mandate_attenuation.rs:501-663`), adding explicit
    fail-closed `m.depth > MANDATE_MAX_DELEGATION_DEPTH` enforcement, root URI validation,
    strict binding of top-level `allowedServices`, `allowedPublish`, and `expiresAt`
    to the verified leaf delegation link, and binding of `m.notBefore` / `now` to signed
    `rootLink.delegatedAt` and `leaf.delegatedAt`. -/
def verifyMandateChain (m : AttenuatedMandate) (expectedRootKey now : Nat) :
    Except MandateError Unit :=
  if now < m.notBefore then
    .error .MandateNotYetValid
  else if m.expiresAt < now then
    .error .MandateExpired
  else if MANDATE_MAX_DELEGATION_DEPTH < m.depth then
    .error .MaxDelegationDepthExceeded
  else if m.rootVerifyingKey != expectedRootKey then
    .error .SignatureFailure
  else if m.delegationChain.length != m.depth + 1 then
    .error .SignatureFailure
  else
    match m.delegationChain with
    | [] => .error .SignatureFailure
    | rootLink :: rest =>
      if rootLink.depth != 0 then
        .error .SignatureFailure
      else if rootLink.delegatorKey != expectedRootKey then
        .error .SignatureFailure
      else if !decide (rootLink.delegatorSpiffeId = m.rootIssuerSpiffeId) then
        .error .SignatureFailure
      else if !rootLink.signatureValid then
        .error .SignatureFailure
      else
        match validateUriList rootLink.attenuatedServices, validateUriList rootLink.attenuatedPublish with
        | .error e, _ => .error e
        | _, .error e => .error e
        | .ok (), .ok () =>
          match verifyLinksFrom 1 rootLink rest with
          | .error e => .error e
          | .ok leaf =>
            if !decide (m.currentHolderSpiffeId = leaf.delegateeSpiffeId) then
              .error .HolderMismatch
            else if !listSubset m.allowedServices leaf.attenuatedServices ||
                    !listSubset leaf.attenuatedServices m.allowedServices then
              .error .PrivilegeEscalationService
            else if !listSubset m.allowedPublish leaf.attenuatedPublish ||
                    !listSubset leaf.attenuatedPublish m.allowedPublish then
              .error .PrivilegeEscalationPublish
            else if m.expiresAt != leaf.expiresAt then
              .error .MandateExpired
            else if m.notBefore < rootLink.delegatedAt then
              .error .MandateNotYetValid
            else if now < rootLink.delegatedAt then
              .error .MandateNotYetValid
            else if now < leaf.delegatedAt then
              .error .MandateNotYetValid
            else
              .ok ()

/-- Models `AttenuatedMandate::authorize_service_call` (`mandate_attenuation.rs:666-693`). -/
def authorizeServiceCall (m : AttenuatedMandate) (callerSpiffeId : String)
    (targetUri : MeshUri) (now : Nat) : Except MandateError Unit :=
  if !decide (m.currentHolderSpiffeId = callerSpiffeId) then
    .error .HolderMismatch
  else if m.expiresAt < now then
    .error .MandateExpired
  else if !isAllowedScheme targetUri.scheme then
    .error .InvalidUriScheme
  else if !targetUri.safeTarget then
    .error .ProhibitedTarget
  else if !listMemBool targetUri m.allowedServices then
    .error .ServiceCallUnauthorized
  else
    .ok ()

/-- Models `AttenuatedMandate::authorize_publish` (`mandate_attenuation.rs:696-723`). -/
def authorizePublish (m : AttenuatedMandate) (callerSpiffeId : String)
    (targetUri : MeshUri) (now : Nat) : Except MandateError Unit :=
  if !decide (m.currentHolderSpiffeId = callerSpiffeId) then
    .error .HolderMismatch
  else if m.expiresAt < now then
    .error .MandateExpired
  else if !isAllowedScheme targetUri.scheme then
    .error .InvalidUriScheme
  else if !targetUri.safeTarget then
    .error .ProhibitedTarget
  else if !listMemBool targetUri m.allowedPublish then
    .error .PublishUnauthorized
  else
    .ok ()

/-- Inductive set of mandates reachable from `root` via `createRootMandate` and `attenuateMandate`. -/
inductive MandateReachable (root : AttenuatedMandate) : AttenuatedMandate → Prop where
  | root
      (mandateId rootIssuerSpiffeId : String)
      (rootVerifyingKey : Nat)
      (initialHolderSpiffeId : String)
      (initialHolderKey : Nat)
      (allowedServices allowedPublish : List MeshUri)
      (notBefore expiresAt : Nat)
      (rootSignatureValid : Bool) :
      createRootMandate mandateId rootIssuerSpiffeId rootVerifyingKey
        initialHolderSpiffeId initialHolderKey allowedServices allowedPublish
        notBefore expiresAt rootSignatureValid = .ok root →
      MandateReachable root root
  | step
      (m m' : AttenuatedMandate)
      (delegatorKey : Nat)
      (delegateeSpiffeId : String)
      (delegateeKey : Nat)
      (narrowedServices narrowedPublish : List MeshUri)
      (newExpiresAt now : Nat)
      (childSignatureValid : Bool) :
      MandateReachable root m →
      attenuateMandate m delegatorKey delegateeSpiffeId delegateeKey
        narrowedServices narrowedPublish newExpiresAt now childSignatureValid = .ok m' →
      MandateReachable root m'

/-- **Theorem 7 (`mandate_monotonic_attenuation`)**:
    Every reachable attenuated mandate satisfies:
    1. Delegation depth never exceeds `MANDATE_MAX_DELEGATION_DEPTH` (`8`),
    2. Allowed services and publish targets are strictly subsets of the root mandate,
    3. Expiration is monotonically non-increasing (`m.expiresAt ≤ root.expiresAt`),
    4. Every allowed URI passes `validateMeshUri`,
    5. Root identity/key remain immutable, and `delegationChain.length = depth + 1`. -/
theorem mandate_monotonic_attenuation {root m : AttenuatedMandate}
    (hReach : MandateReachable root m) :
    m.depth ≤ MANDATE_MAX_DELEGATION_DEPTH ∧
    (∀ s, s ∈ m.allowedServices → s ∈ root.allowedServices) ∧
    (∀ p, p ∈ m.allowedPublish → p ∈ root.allowedPublish) ∧
    m.expiresAt ≤ root.expiresAt ∧
    (∀ s, s ∈ m.allowedServices → validateMeshUri s = true) ∧
    (∀ p, p ∈ m.allowedPublish → validateMeshUri p = true) ∧
    m.rootVerifyingKey = root.rootVerifyingKey ∧
    m.rootIssuerSpiffeId = root.rootIssuerSpiffeId ∧
    m.delegationChain.length = m.depth + 1 := by
  induction hReach with
  | root mandateId rootIssuerSpiffeId rootVerifyingKey initialHolderSpiffeId
      initialHolderKey allowedServices allowedPublish notBefore expiresAt rootSig hCreate =>
    unfold createRootMandate at hCreate
    cases hS : validateUriList allowedServices with
    | error e => rw [hS] at hCreate; cases hCreate
    | ok _ =>
      cases hP : validateUriList allowedPublish with
      | error e => rw [hS, hP] at hCreate; cases hCreate
      | ok _ =>
        rw [hS, hP] at hCreate
        dsimp only at hCreate
        by_cases hSig : (!rootSig) = true
        · simp only [eq_true hSig, ite_true] at hCreate; cases hCreate
        · simp only [eq_false hSig, ite_false] at hCreate
          injection hCreate with hRootEq
          subst hRootEq
          refine ⟨by simp [MANDATE_MAX_DELEGATION_DEPTH], ?_, ?_, Nat.le_refl _, ?_, ?_, rfl, rfl, rfl⟩
          · intro s hs; exact hs
          · intro p hp; exact hp
          · exact validateUriList_ok_implies_valid allowedServices hS
          · exact validateUriList_ok_implies_valid allowedPublish hP
  | step mPrev mNext delegatorKey delegateeSpiffeId delegateeKey
      narrowedServices narrowedPublish newExpiresAt now childSig _ hStep ih =>
    rcases ih with ⟨_ihDepth, ihServ, ihPub, ihExp, _ihServValid, _ihPubValid, ihKey, ihIssuer, ihLen⟩
    unfold attenuateMandate at hStep
    by_cases hNb : now < mPrev.notBefore
    · simp only [eq_true hNb, ite_true] at hStep; cases hStep
    · simp only [eq_false hNb, ite_false] at hStep
      by_cases hExp : mPrev.expiresAt < now
      · simp only [eq_true hExp, ite_true] at hStep; cases hStep
      · simp only [eq_false hExp, ite_false] at hStep
        by_cases hDeep : MANDATE_MAX_DELEGATION_DEPTH < mPrev.depth + 1
        · simp only [eq_true hDeep, ite_true] at hStep; cases hStep
        · simp only [eq_false hDeep, ite_false] at hStep
          cases hS : validateUriList narrowedServices with
          | error e => rw [hS] at hStep; cases hStep
          | ok _ =>
            cases hP : validateUriList narrowedPublish with
            | error e => rw [hS, hP] at hStep; cases hStep
            | ok _ =>
              rw [hS, hP] at hStep
              dsimp only at hStep
              by_cases hSubS : (!listSubset narrowedServices mPrev.allowedServices) = true
              · simp only [eq_true hSubS, ite_true] at hStep; cases hStep
              · simp only [eq_false hSubS, ite_false] at hStep
                by_cases hSubP : (!listSubset narrowedPublish mPrev.allowedPublish) = true
                · simp only [eq_true hSubP, ite_true] at hStep; cases hStep
                · simp only [eq_false hSubP, ite_false] at hStep
                  cases hLast : mPrev.delegationChain.getLast? with
                  | none => rw [hLast] at hStep; cases hStep
                  | some parentLink =>
                    rw [hLast] at hStep
                    dsimp only at hStep
                    by_cases hKey : (delegatorKey != parentLink.delegateeKey) = true
                    · simp only [eq_true hKey, ite_true] at hStep; cases hStep
                    · simp only [eq_false hKey, ite_false] at hStep
                      by_cases hHolder : (!decide (mPrev.currentHolderSpiffeId = parentLink.delegateeSpiffeId)) = true
                      · simp only [eq_true hHolder, ite_true] at hStep; cases hStep
                      · simp only [eq_false hHolder, ite_false] at hStep
                        by_cases hCSig : (!childSig) = true
                        · simp only [eq_true hCSig, ite_true] at hStep; cases hStep
                        · simp only [eq_false hCSig, ite_false] at hStep
                          injection hStep with hNextEq
                          subst hNextEq
                          have hSubS_true : listSubset narrowedServices mPrev.allowedServices = true := by
                            cases hc : listSubset narrowedServices mPrev.allowedServices
                            · rw [hc] at hSubS; exact absurd rfl hSubS
                            · rfl
                          have hSubP_true : listSubset narrowedPublish mPrev.allowedPublish = true := by
                            cases hc : listSubset narrowedPublish mPrev.allowedPublish
                            · rw [hc] at hSubP; exact absurd rfl hSubP
                            · rfl
                          have hS_iff := (listSubset_eq_true_iff narrowedServices mPrev.allowedServices).mp hSubS_true
                          have hP_iff := (listSubset_eq_true_iff narrowedPublish mPrev.allowedPublish).mp hSubP_true
                          refine ⟨Nat.le_of_not_lt hDeep, ?_, ?_, ?_, ?_, ?_, ihKey, ihIssuer, ?_⟩
                          · intro s hs; exact ihServ s (hS_iff s hs)
                          · intro p hp; exact ihPub p (hP_iff p hp)
                          · exact Nat.le_trans (Nat.min_le_right newExpiresAt mPrev.expiresAt) ihExp
                          · exact validateUriList_ok_implies_valid narrowedServices hS
                          · exact validateUriList_ok_implies_valid narrowedPublish hP
                          · simp [List.length_append, ihLen]

private theorem verifyLinksFrom_monotonic :
    ∀ (rest : List DelegationLink) (idx : Nat) (prev leaf : DelegationLink),
      verifyLinksFrom idx prev rest = .ok leaf →
      (leaf = prev ∨ leaf ∈ rest) ∧
      ∀ l ∈ rest,
        l.signatureValid = true ∧
        (∀ s, s ∈ l.attenuatedServices → s ∈ prev.attenuatedServices) ∧
        (∀ p, p ∈ l.attenuatedPublish → p ∈ prev.attenuatedPublish) ∧
        l.expiresAt ≤ prev.expiresAt ∧
        prev.delegatedAt ≤ l.delegatedAt
  | [], _, prev, leaf, hOk => by
    unfold verifyLinksFrom at hOk
    injection hOk with hEq
    exact ⟨Or.inl hEq.symm, fun _ hl => by cases hl⟩
  | link :: rest, idx, prev, leaf, hOk => by
    unfold verifyLinksFrom at hOk
    by_cases h1 : (link.depth != idx) = true
    · simp only [eq_true h1, ite_true] at hOk; cases hOk
    · simp only [eq_false h1, ite_false] at hOk
      by_cases h2 : (link.delegatorKey != prev.delegateeKey) = true
      · simp only [eq_true h2, ite_true] at hOk; cases hOk
      · simp only [eq_false h2, ite_false] at hOk
        by_cases h3 : (!decide (link.delegatorSpiffeId = prev.delegateeSpiffeId)) = true
        · simp only [eq_true h3, ite_true] at hOk; cases hOk
        · simp only [eq_false h3, ite_false] at hOk
          by_cases h4 : (!link.signatureValid) = true
          · simp only [eq_true h4, ite_true] at hOk; cases hOk
          · simp only [eq_false h4, ite_false] at hOk
            by_cases h5 : (!listSubset link.attenuatedServices prev.attenuatedServices) = true
            · simp only [eq_true h5, ite_true] at hOk; cases hOk
            · simp only [eq_false h5, ite_false] at hOk
              by_cases h6 : (!listSubset link.attenuatedPublish prev.attenuatedPublish) = true
              · simp only [eq_true h6, ite_true] at hOk; cases hOk
              · simp only [eq_false h6, ite_false] at hOk
                by_cases h7 : prev.expiresAt < link.expiresAt
                · simp only [eq_true h7, ite_true] at hOk; cases hOk
                · simp only [eq_false h7, ite_false] at hOk
                  by_cases h8 : link.delegatedAt < prev.delegatedAt
                  · simp only [eq_true h8, ite_true] at hOk; cases hOk
                  · simp only [eq_false h8, ite_false] at hOk
                    have hSigTrue : link.signatureValid = true := by
                      cases hc : link.signatureValid
                      · rw [hc] at h4; exact absurd rfl h4
                      · rfl
                    have hSubS_true : listSubset link.attenuatedServices prev.attenuatedServices = true := by
                      cases hc : listSubset link.attenuatedServices prev.attenuatedServices
                      · rw [hc] at h5; exact absurd rfl h5
                      · rfl
                    have hSubP_true : listSubset link.attenuatedPublish prev.attenuatedPublish = true := by
                      cases hc : listSubset link.attenuatedPublish prev.attenuatedPublish
                      · rw [hc] at h6; exact absurd rfl h6
                      · rfl
                    have hSubS := (listSubset_eq_true_iff _ _).mp hSubS_true
                    have hSubP := (listSubset_eq_true_iff _ _).mp hSubP_true
                    have hExpLe : link.expiresAt ≤ prev.expiresAt := Nat.le_of_not_lt h7
                    have hDelGe : prev.delegatedAt ≤ link.delegatedAt := Nat.le_of_not_lt h8
                    have ih := verifyLinksFrom_monotonic rest (idx + 1) link leaf hOk
                    refine ⟨?_, ?_⟩
                    · rcases ih.1 with rfl | hLeafMem
                      · exact Or.inr (List.Mem.head _)
                      · exact Or.inr (List.Mem.tail _ hLeafMem)
                    · intro l hl
                      cases hl with
                      | head => exact ⟨hSigTrue, hSubS, hSubP, hExpLe, hDelGe⟩
                      | tail _ hmem =>
                        obtain ⟨hsig, hs, hp, hexp, hdel⟩ := ih.2 l hmem
                        exact ⟨hsig, fun s hms => hSubS s (hs s hms),
                          fun p hmp => hSubP p (hp p hmp),
                          Nat.le_trans hexp hExpLe, Nat.le_trans hDelGe hdel⟩

/-- Companion chain-verifier soundness: any `AttenuatedMandate` passing `verifyMandateChain`
    satisfies `depth ≤ 8`, root key binding, top-level capability/TTL/URI invariants bound
    to `rootLink`, monotonic attenuation across every link, and `rootLink.delegatedAt`
    binding on both `m.notBefore` and `now`. -/
theorem verifyMandateChain_monotonic
    (m : AttenuatedMandate) (expectedRootKey now : Nat)
    (rootLink : DelegationLink) (rest : List DelegationLink)
    (hChain : m.delegationChain = rootLink :: rest)
    (hOk : verifyMandateChain m expectedRootKey now = .ok ()) :
    m.depth ≤ MANDATE_MAX_DELEGATION_DEPTH ∧
    rootLink.delegatorKey = expectedRootKey ∧
    (∀ s, s ∈ m.allowedServices → s ∈ rootLink.attenuatedServices ∧ validateMeshUri s = true) ∧
    (∀ p, p ∈ m.allowedPublish → p ∈ rootLink.attenuatedPublish ∧ validateMeshUri p = true) ∧
    m.expiresAt ≤ rootLink.expiresAt ∧
    (∀ l ∈ m.delegationChain,
      l.signatureValid = true ∧
      (∀ s, s ∈ l.attenuatedServices → s ∈ rootLink.attenuatedServices) ∧
      (∀ p, p ∈ l.attenuatedPublish → p ∈ rootLink.attenuatedPublish) ∧
      l.expiresAt ≤ rootLink.expiresAt ∧
      rootLink.delegatedAt ≤ l.delegatedAt) ∧
    rootLink.delegatedAt ≤ m.notBefore ∧
    rootLink.delegatedAt ≤ now := by
  unfold verifyMandateChain at hOk
  by_cases h1 : now < m.notBefore
  · simp only [eq_true h1, ite_true] at hOk; cases hOk
  · simp only [eq_false h1, ite_false] at hOk
    by_cases h2 : m.expiresAt < now
    · simp only [eq_true h2, ite_true] at hOk; cases hOk
    · simp only [eq_false h2, ite_false] at hOk
      by_cases h3 : MANDATE_MAX_DELEGATION_DEPTH < m.depth
      · simp only [eq_true h3, ite_true] at hOk; cases hOk
      · simp only [eq_false h3, ite_false] at hOk
        by_cases h4 : (m.rootVerifyingKey != expectedRootKey) = true
        · simp only [eq_true h4, ite_true] at hOk; cases hOk
        · simp only [eq_false h4, ite_false] at hOk
          by_cases h5 : (m.delegationChain.length != m.depth + 1) = true
          · simp only [eq_true h5, ite_true] at hOk; cases hOk
          · simp only [eq_false h5, ite_false] at hOk
            rw [hChain] at hOk
            dsimp only at hOk
            by_cases h6 : (rootLink.depth != 0) = true
            · simp only [eq_true h6, ite_true] at hOk; cases hOk
            · simp only [eq_false h6, ite_false] at hOk
              by_cases h7 : (rootLink.delegatorKey != expectedRootKey) = true
              · simp only [eq_true h7, ite_true] at hOk; cases hOk
              · simp only [eq_false h7, ite_false] at hOk
                by_cases h8 : (!decide (rootLink.delegatorSpiffeId = m.rootIssuerSpiffeId)) = true
                · simp only [eq_true h8, ite_true] at hOk; cases hOk
                · simp only [eq_false h8, ite_false] at hOk
                  by_cases h9 : (!rootLink.signatureValid) = true
                  · simp only [eq_true h9, ite_true] at hOk; cases hOk
                  · simp only [eq_false h9, ite_false] at hOk
                    cases hVS : validateUriList rootLink.attenuatedServices with
                    | error e => rw [hVS] at hOk; cases hOk
                    | ok _ =>
                      cases hVP : validateUriList rootLink.attenuatedPublish with
                      | error e => rw [hVS, hVP] at hOk; cases hOk
                      | ok _ =>
                        rw [hVS, hVP] at hOk
                        dsimp only at hOk
                        cases hV : verifyLinksFrom 1 rootLink rest with
                        | error e => rw [hV] at hOk; cases hOk
                        | ok leaf =>
                          rw [hV] at hOk
                          dsimp only at hOk
                          by_cases hHold : (!decide (m.currentHolderSpiffeId = leaf.delegateeSpiffeId)) = true
                          · simp only [eq_true hHold, ite_true] at hOk; cases hOk
                          · simp only [eq_false hHold, ite_false] at hOk
                            by_cases hServ : (!listSubset m.allowedServices leaf.attenuatedServices ||
                                !listSubset leaf.attenuatedServices m.allowedServices) = true
                            · simp only [eq_true hServ, ite_true] at hOk; cases hOk
                            · simp only [eq_false hServ, ite_false] at hOk
                              by_cases hPub : (!listSubset m.allowedPublish leaf.attenuatedPublish ||
                                  !listSubset leaf.attenuatedPublish m.allowedPublish) = true
                              · simp only [eq_true hPub, ite_true] at hOk; cases hOk
                              · simp only [eq_false hPub, ite_false] at hOk
                                by_cases hExp : (m.expiresAt != leaf.expiresAt) = true
                                · simp only [eq_true hExp, ite_true] at hOk; cases hOk
                                · simp only [eq_false hExp, ite_false] at hOk
                                  by_cases hNbRoot : m.notBefore < rootLink.delegatedAt
                                  · simp only [eq_true hNbRoot, ite_true] at hOk; cases hOk
                                  · simp only [eq_false hNbRoot, ite_false] at hOk
                                    by_cases hNowRoot : now < rootLink.delegatedAt
                                    · simp only [eq_true hNowRoot, ite_true] at hOk; cases hOk
                                    · simp only [eq_false hNowRoot, ite_false] at hOk
                                      by_cases hNowLeaf : now < leaf.delegatedAt
                                      · simp only [eq_true hNowLeaf, ite_true] at hOk; cases hOk
                                      · simp only [eq_false hNowLeaf, ite_false] at hOk
                                        have hRootKey : rootLink.delegatorKey = expectedRootKey := by
                                          by_cases heq : rootLink.delegatorKey = expectedRootKey
                                          · exact heq
                                          · have hne : (rootLink.delegatorKey != expectedRootKey) = true := bne_iff_ne.mpr heq
                                            rw [hne] at h7
                                            exact absurd rfl h7
                                        have hRootSig : rootLink.signatureValid = true := by
                                          cases hc : rootLink.signatureValid
                                          · rw [hc] at h9; exact absurd rfl h9
                                          · rfl
                                        have hServSub : listSubset m.allowedServices leaf.attenuatedServices = true := by
                                          cases hc : listSubset m.allowedServices leaf.attenuatedServices
                                          · rw [hc] at hServ; simp at hServ
                                          · rfl
                                        have hPubSub : listSubset m.allowedPublish leaf.attenuatedPublish = true := by
                                          cases hc : listSubset m.allowedPublish leaf.attenuatedPublish
                                          · rw [hc] at hPub; simp at hPub
                                          · rfl
                                        have hExpEq : m.expiresAt = leaf.expiresAt := by
                                          by_cases heq : m.expiresAt = leaf.expiresAt
                                          · exact heq
                                          · have hne : (m.expiresAt != leaf.expiresAt) = true := bne_iff_ne.mpr heq
                                            rw [hne] at hExp
                                            exact absurd rfl hExp
                                        obtain ⟨hLeafMem, hLinks⟩ := verifyLinksFrom_monotonic rest 1 rootLink leaf hV
                                        have hLeafBound :
                                            (∀ s, s ∈ leaf.attenuatedServices → s ∈ rootLink.attenuatedServices) ∧
                                            (∀ p, p ∈ leaf.attenuatedPublish → p ∈ rootLink.attenuatedPublish) ∧
                                            leaf.expiresAt ≤ rootLink.expiresAt := by
                                          rcases hLeafMem with rfl | hMem
                                          · exact ⟨fun s hs => hs, fun p hp => hp, Nat.le_refl _⟩
                                          · obtain ⟨_, hS, hP, hE, _⟩ := hLinks leaf hMem
                                            exact ⟨hS, hP, hE⟩
                                        have hValidS := validateUriList_ok_implies_valid rootLink.attenuatedServices hVS
                                        have hValidP := validateUriList_ok_implies_valid rootLink.attenuatedPublish hVP
                                        refine ⟨Nat.le_of_not_lt h3, hRootKey, ?_, ?_, ?_, ?_,
                                          Nat.le_of_not_lt hNbRoot, Nat.le_of_not_lt hNowRoot⟩
                                        · intro s hs
                                          have hsLeaf : s ∈ leaf.attenuatedServices := (listSubset_eq_true_iff _ _).mp hServSub s hs
                                          have hsRoot : s ∈ rootLink.attenuatedServices := hLeafBound.1 s hsLeaf
                                          exact ⟨hsRoot, hValidS s hsRoot⟩
                                        · intro p hp
                                          have hpLeaf : p ∈ leaf.attenuatedPublish := (listSubset_eq_true_iff _ _).mp hPubSub p hp
                                          have hpRoot : p ∈ rootLink.attenuatedPublish := hLeafBound.2.1 p hpLeaf
                                          exact ⟨hpRoot, hValidP p hpRoot⟩
                                        · rw [hExpEq]; exact hLeafBound.2.2
                                        · intro l hl
                                          rw [hChain] at hl
                                          cases hl with
                                          | head =>
                                            exact ⟨hRootSig, fun s hs => hs, fun p hp => hp,
                                              Nat.le_refl _, Nat.le_refl _⟩
                                          | tail _ hmem => exact hLinks l hmem

theorem attenuate_depth_exceeded_rejected
    (m : AttenuatedMandate)
    (delegatorKey : Nat) (delegateeSpiffeId : String) (delegateeKey : Nat)
    (narrowedServices narrowedPublish : List MeshUri)
    (newExpiresAt now : Nat) (childSig : Bool)
    (hNb : m.notBefore ≤ now) (hExp : now ≤ m.expiresAt)
    (hDepth : MANDATE_MAX_DELEGATION_DEPTH ≤ m.depth) :
    attenuateMandate m delegatorKey delegateeSpiffeId delegateeKey
      narrowedServices narrowedPublish newExpiresAt now childSig =
      .error .MaxDelegationDepthExceeded := by
  unfold attenuateMandate
  have h1 : ¬(now < m.notBefore) := Nat.not_lt_of_ge hNb
  have h2 : ¬(m.expiresAt < now) := Nat.not_lt_of_ge hExp
  have h3 : MANDATE_MAX_DELEGATION_DEPTH < m.depth + 1 := Nat.lt_succ_of_le hDepth
  simp only [eq_false h1, ite_false, eq_false h2, eq_true h3, ite_true]

theorem verifyMandateChain_depth_gt_8_rejected
    (m : AttenuatedMandate) (expectedRootKey now : Nat)
    (hDepth : MANDATE_MAX_DELEGATION_DEPTH < m.depth) :
    ∃ e : MandateError, verifyMandateChain m expectedRootKey now = .error e := by
  unfold verifyMandateChain
  by_cases h1 : now < m.notBefore
  · simp only [eq_true h1, ite_true]; exact ⟨.MandateNotYetValid, rfl⟩
  · simp only [eq_false h1, ite_false]
    by_cases h2 : m.expiresAt < now
    · simp only [eq_true h2, ite_true]; exact ⟨.MandateExpired, rfl⟩
    · simp only [eq_false h2, ite_false, eq_true hDepth, ite_true]
      exact ⟨.MaxDelegationDepthExceeded, rfl⟩

theorem segregated_publish_does_not_grant_service_call
    (m : AttenuatedMandate) (callerSpiffeId : String) (u : MeshUri) (now : Nat)
    (hNotServ : u ∉ m.allowedServices) :
    ∃ e : MandateError, authorizeServiceCall m callerSpiffeId u now = .error e := by
  unfold authorizeServiceCall
  by_cases h1 : (!decide (m.currentHolderSpiffeId = callerSpiffeId)) = true
  · simp only [eq_true h1, ite_true]; exact ⟨.HolderMismatch, rfl⟩
  · simp only [eq_false h1, ite_false]
    by_cases h2 : m.expiresAt < now
    · simp only [eq_true h2, ite_true]; exact ⟨.MandateExpired, rfl⟩
    · simp only [eq_false h2, ite_false]
      by_cases h3 : (!isAllowedScheme u.scheme) = true
      · simp only [eq_true h3, ite_true]; exact ⟨.InvalidUriScheme, rfl⟩
      · simp only [eq_false h3, ite_false]
        by_cases h4 : (!u.safeTarget) = true
        · simp only [eq_true h4, ite_true]; exact ⟨.ProhibitedTarget, rfl⟩
        · simp only [eq_false h4, ite_false]
          have hMemFalse : listMemBool u m.allowedServices = false :=
            (listMemBool_eq_false_iff u m.allowedServices).mpr hNotServ
          simp [hMemFalse]

/-! ### Part B: `QuorumPolicyGuard` & Anti-Sybil Deduplication (`src/ledger/quorum.rs`) -/

inductive LedgerError : Type where
  | InvalidSignature
  | QuorumNotMet
  | DuplicateAuthority
  | UnauthorizedAuthority
  | ZeroThreshold
  deriving DecidableEq, Repr, BEq

structure PolicyProposal where
  proposalId : String
  proposedPolicyHash : Nat
  newEgressDomains : List String
  timestampMs : Nat
  deriving DecidableEq, Repr

structure PolicyAttestation where
  proposalId : String
  authorityId : String
  authorityPubkey : Nat
  signedDigest : PolicyProposal
  signatureValid : Bool
  deriving DecidableEq, Repr

structure RegisteredAuthority where
  authorityId : String
  verifyingKey : Nat
  deriving DecidableEq, Repr

structure QuorumPolicyGuard where
  quorumThreshold : Nat
  authorities : List RegisteredAuthority
  activePolicyHash : Nat
  activeEgressDomains : List String
  committedHistory : List PolicyProposal
  deriving DecidableEq, Repr

def lookupAuthority (auths : List RegisteredAuthority) (aid : String) : Option Nat :=
  match auths.find? (fun a => decide (a.authorityId = aid)) with
  | some a => some a.verifyingKey
  | none => none

def validAttestation (guard : QuorumPolicyGuard) (proposal : PolicyProposal)
    (att : PolicyAttestation) : Bool :=
  decide (att.proposalId = proposal.proposalId) &&
  (lookupAuthority guard.authorities att.authorityId == some att.authorityPubkey) &&
  att.signatureValid &&
  decide (att.signedDigest = proposal)

/-- Models the attestation loop in `QuorumPolicyGuard::submit_and_commit_proposal`
    (`quorum.rs:108-155`): rejects mismatches, unauthorized IDs, duplicate authority IDs
    (`DuplicateAuthority`), and invalid signatures over `proposal.digest()`. -/
def collectVerifiedAuthorities
    (guard : QuorumPolicyGuard) (proposal : PolicyProposal)
    (acc : List String) : List PolicyAttestation → Except LedgerError (List String)
  | [] => .ok acc
  | att :: rest =>
    if !decide (att.proposalId = proposal.proposalId) then
      .error .InvalidSignature
    else
      match lookupAuthority guard.authorities att.authorityId with
      | none => .error .UnauthorizedAuthority
      | some trustedKey =>
        if trustedKey != att.authorityPubkey then
          .error .InvalidSignature
        else if listMemBool att.authorityId acc then
          .error .DuplicateAuthority
        else if !att.signatureValid || !decide (att.signedDigest = proposal) then
          .error .InvalidSignature
        else
          collectVerifiedAuthorities guard proposal (att.authorityId :: acc) rest

/-- Models `QuorumPolicyGuard::submit_and_commit_proposal` (`quorum.rs:100-170`) with fail-closed
    `quorumThreshold = 0` guard (`ZeroThreshold`). -/
def submitAndCommitProposal
    (guard : QuorumPolicyGuard) (proposal : PolicyProposal)
    (attestations : List PolicyAttestation) : Except LedgerError QuorumPolicyGuard :=
  if guard.quorumThreshold == 0 then
    .error .ZeroThreshold
  else
    match collectVerifiedAuthorities guard proposal [] attestations with
    | .error e => .error e
    | .ok verified =>
      if verified.length < guard.quorumThreshold then
        .error .QuorumNotMet
      else
        .ok
          { guard with
            activePolicyHash := proposal.proposedPolicyHash
            activeEgressDomains := proposal.newEgressDomains
            committedHistory := guard.committedHistory ++ [proposal] }

/-! ### Explicit `NoDup` & `dedupIds` Anti-Sybil Lemmas -/

inductive NoDup {α : Type} : List α → Prop where
  | nil : NoDup []
  | cons {x : α} {xs : List α} : x ∉ xs → NoDup xs → NoDup (x :: xs)

def dedupIds : List String → List String
  | [] => []
  | x :: xs =>
    let rest := dedupIds xs
    if listMemBool x rest then rest else x :: rest

theorem mem_dedupIds_iff (x : String) (xs : List String) :
    x ∈ dedupIds xs ↔ x ∈ xs := by
  induction xs generalizing x with
  | nil => simp [dedupIds]
  | cons y ys ih =>
    unfold dedupIds
    by_cases hMem : listMemBool y (dedupIds ys) = true
    · simp only [eq_true hMem, ite_true]
      have hy : y ∈ ys := (ih y).mp ((listMemBool_eq_true_iff y (dedupIds ys)).mp hMem)
      constructor
      · intro hx; exact List.Mem.tail _ ((ih x).mp hx)
      · intro hx
        cases hx with
        | head => exact (ih _).mpr hy
        | tail _ htail => exact (ih x).mpr htail
    · simp only [eq_false hMem, ite_false]
      constructor
      · intro hx
        cases hx with
        | head => exact List.Mem.head _
        | tail _ htail => exact List.Mem.tail _ ((ih x).mp htail)
      · intro hx
        cases hx with
        | head => exact List.Mem.head _
        | tail _ htail => exact List.Mem.tail _ ((ih x).mpr htail)

theorem dedupIds_nodup (xs : List String) : NoDup (dedupIds xs) := by
  induction xs with
  | nil => exact NoDup.nil
  | cons y ys ih =>
    unfold dedupIds
    by_cases hMem : listMemBool y (dedupIds ys) = true
    · simp only [eq_true hMem, ite_true]
      exact ih
    · simp only [eq_false hMem, ite_false]
      have hNot : y ∉ dedupIds ys := (listMemBool_eq_false_iff y (dedupIds ys)).mp (by
        cases hc : listMemBool y (dedupIds ys)
        · rfl
        · exact absurd hc hMem)
      exact NoDup.cons hNot ih

theorem dedupIds_length_le (xs : List String) : (dedupIds xs).length ≤ xs.length := by
  induction xs with
  | nil => simp [dedupIds]
  | cons y ys ih =>
    unfold dedupIds
    by_cases hMem : listMemBool y (dedupIds ys) = true
    · simp only [eq_true hMem, ite_true]
      exact Nat.le_trans ih (Nat.le_succ _)
    · simp only [eq_false hMem, ite_false]
      exact Nat.succ_le_succ ih

theorem dedupIds_replicate_le_one (aid : String) (n : Nat) :
    (dedupIds (List.replicate n aid)).length ≤ 1 := by
  induction n with
  | zero => simp [dedupIds]
  | succ k ih =>
    simp only [List.replicate_succ, dedupIds]
    by_cases hMem : listMemBool aid (dedupIds (List.replicate k aid)) = true
    · simp only [eq_true hMem, ite_true]
      exact ih
    · simp only [eq_false hMem, ite_false]
      cases hList : dedupIds (List.replicate k aid) with
      | nil => simp
      | cons z zs =>
        exfalso
        have hz_mem : z ∈ List.replicate k aid :=
          (mem_dedupIds_iff z (List.replicate k aid)).mp (by rw [hList]; exact List.Mem.head _)
        have hz_eq : z = aid := List.eq_of_mem_replicate hz_mem
        rw [hz_eq] at hList
        have haid_in : aid ∈ dedupIds (List.replicate k aid) := by
          rw [hList]; exact List.Mem.head _
        have hTrue : listMemBool aid (dedupIds (List.replicate k aid)) = true :=
          (listMemBool_eq_true_iff aid _).mpr haid_in
        exact hMem hTrue

private def eraseFirst {α : Type} [DecidableEq α] (x : α) : List α → List α
  | [] => []
  | y :: ys => if x = y then ys else y :: eraseFirst x ys

private theorem mem_eraseFirst_of_ne {α : Type} [DecidableEq α] {x z : α} :
    ∀ {ys : List α}, z ∈ ys → z ≠ x → z ∈ eraseFirst x ys
  | [], hz, _ => by cases hz
  | y :: ys, hz, hne => by
    unfold eraseFirst
    by_cases hxy : x = y
    · simp only [eq_true hxy, ite_true]
      cases hz with
      | head => exact absurd hxy.symm hne
      | tail _ htail => exact htail
    · simp only [eq_false hxy, ite_false]
      cases hz with
      | head => exact List.Mem.head _
      | tail _ htail => exact List.Mem.tail _ (mem_eraseFirst_of_ne htail hne)

private theorem eraseFirst_length_succ {α : Type} [DecidableEq α] {x : α} :
    ∀ {ys : List α}, x ∈ ys → (eraseFirst x ys).length + 1 = ys.length
  | [], hx => by cases hx
  | y :: ys, hx => by
    unfold eraseFirst
    by_cases hxy : x = y
    · simp only [eq_true hxy, ite_true]; rfl
    · simp only [eq_false hxy, ite_false]
      cases hx with
      | head => exact absurd rfl hxy
      | tail _ htail =>
        simp only [List.length_cons]
        rw [eraseFirst_length_succ htail]

private theorem nodup_subset_length_le {α : Type} [DecidableEq α] :
    ∀ (xs ys : List α), NoDup xs → (∀ x, x ∈ xs → x ∈ ys) → xs.length ≤ ys.length
  | [], _, _, _ => Nat.zero_le _
  | x :: xs, ys, hnd, hsub => by
    cases hnd with
    | cons hxNot hndTail =>
      have hxInYs : x ∈ ys := hsub x (List.Mem.head _)
      have hLen : (eraseFirst x ys).length + 1 = ys.length := eraseFirst_length_succ hxInYs
      have hSubTail : ∀ z, z ∈ xs → z ∈ eraseFirst x ys := by
        intro z hz
        have hzne : z ≠ x := by
          intro hEq
          subst hEq
          exact hxNot hz
        exact mem_eraseFirst_of_ne (hsub z (List.Mem.tail _ hz)) hzne
      have ih := nodup_subset_length_le xs (eraseFirst x ys) hndTail hSubTail
      rw [← hLen]
      exact Nat.succ_le_succ ih

private theorem collectVerifiedAuthorities_invariants
    (guard : QuorumPolicyGuard) (proposal : PolicyProposal) :
    ∀ (atts : List PolicyAttestation) (acc verified : List String),
      NoDup acc →
      collectVerifiedAuthorities guard proposal acc atts = .ok verified →
      NoDup verified ∧
      NoDup (atts.map (·.authorityId)) ∧
      (∀ aid ∈ atts.map (·.authorityId), aid ∉ acc) ∧
      (∀ aid ∈ verified,
        aid ∈ acc ∨ ∃ att ∈ atts, att.authorityId = aid ∧ validAttestation guard proposal att = true)
  | [], acc, verified, hNoDupAcc, hOk => by
    unfold collectVerifiedAuthorities at hOk
    injection hOk with hEq
    subst hEq
    exact ⟨hNoDupAcc, NoDup.nil, fun _ hm => by simp at hm, fun _ hm => Or.inl hm⟩
  | att :: rest, acc, verified, hNoDupAcc, hOk => by
    unfold collectVerifiedAuthorities at hOk
    by_cases h1 : (!decide (att.proposalId = proposal.proposalId)) = true
    · simp only [eq_true h1, ite_true] at hOk; cases hOk
    · simp only [eq_false h1, ite_false] at hOk
      cases hAuth : lookupAuthority guard.authorities att.authorityId with
      | none => rw [hAuth] at hOk; cases hOk
      | some trustedKey =>
        rw [hAuth] at hOk
        dsimp only at hOk
        by_cases h2 : (trustedKey != att.authorityPubkey) = true
        · simp only [eq_true h2, ite_true] at hOk; cases hOk
        · simp only [eq_false h2, ite_false] at hOk
          by_cases h3 : listMemBool att.authorityId acc = true
          · simp only [eq_true h3, ite_true] at hOk; cases hOk
          · simp only [eq_false h3, ite_false] at hOk
            by_cases h4 : (!att.signatureValid || !decide (att.signedDigest = proposal)) = true
            · simp only [eq_true h4, ite_true] at hOk; cases hOk
            · simp only [eq_false h4, ite_false] at hOk
              have hNotInAcc : att.authorityId ∉ acc := by
                intro hmem
                have hTrue : listMemBool att.authorityId acc = true :=
                  (listMemBool_eq_true_iff att.authorityId acc).mpr hmem
                exact h3 hTrue
              have hNoDupCons : NoDup (att.authorityId :: acc) := NoDup.cons hNotInAcc hNoDupAcc
              obtain ⟨ihNdVer, ihNdMap, ihNotInCons, ihMem⟩ :=
                collectVerifiedAuthorities_invariants guard proposal rest (att.authorityId :: acc) verified hNoDupCons hOk
              have hValid : validAttestation guard proposal att = true := by
                unfold validAttestation
                have hPid : decide (att.proposalId = proposal.proposalId) = true := by
                  cases hc : decide (att.proposalId = proposal.proposalId)
                  · rw [hc] at h1; exact absurd rfl h1
                  · rfl
                have hKeyEq : trustedKey = att.authorityPubkey := by
                  by_cases heq : trustedKey = att.authorityPubkey
                  · exact heq
                  · have hne : (trustedKey != att.authorityPubkey) = true := bne_iff_ne.mpr heq
                    rw [hne] at h2
                    exact absurd rfl h2
                have hSig : att.signatureValid = true := by
                  cases hc : att.signatureValid
                  · rw [hc] at h4; simp at h4
                  · rfl
                have hDig : decide (att.signedDigest = proposal) = true := by
                  cases hc : decide (att.signedDigest = proposal)
                  · rw [hc] at h4; simp at h4
                  · rfl
                simp [hPid, hAuth, hKeyEq, hSig, hDig]
              have hNotInRest : att.authorityId ∉ rest.map (·.authorityId) := by
                intro hmem
                exact ihNotInCons att.authorityId hmem (List.Mem.head _)
              have hNotInAccRest : ∀ aid ∈ rest.map (·.authorityId), aid ∉ acc := by
                intro aid hmem ha
                exact ihNotInCons aid hmem (List.Mem.tail _ ha)
              refine ⟨ihNdVer, NoDup.cons hNotInRest ihNdMap, ?_, ?_⟩
              · intro aid haid
                simp only [List.map_cons] at haid
                cases haid with
                | head => exact hNotInAcc
                | tail _ htail => exact hNotInAccRest aid htail
              · intro aid haid
                rcases ihMem aid haid with hInCons | ⟨a, haMem, haId, haVal⟩
                · cases hInCons with
                  | head => exact Or.inr ⟨att, List.Mem.head _, rfl, hValid⟩
                  | tail _ hInAcc => exact Or.inl hInAcc
                · exact Or.inr ⟨a, List.Mem.tail _ haMem, haId, haVal⟩

/-- **Theorem 8 (`quorum_threshold_anti_sybil`)**:
    Any committed policy change requires `0 < guard.quorumThreshold`, at least `guard.quorumThreshold`
    pairwise distinct (`NoDup`) registered authorities with valid signatures bound to `proposal`,
    and at least `guard.quorumThreshold` deduplicated valid authority IDs (`dedupIds`),
    preventing sybil duplicate inflation. -/
theorem quorum_threshold_anti_sybil
    (guard nextGuard : QuorumPolicyGuard)
    (proposal : PolicyProposal)
    (attestations : List PolicyAttestation)
    (hCommit : submitAndCommitProposal guard proposal attestations = .ok nextGuard) :
    0 < guard.quorumThreshold ∧
    (∃ verified : List String,
      NoDup verified ∧
      guard.quorumThreshold ≤ verified.length ∧
      (∀ aid ∈ verified,
        ∃ att ∈ attestations, att.authorityId = aid ∧ validAttestation guard proposal att = true)) ∧
    guard.quorumThreshold ≤
      (dedupIds ((attestations.filter (validAttestation guard proposal)).map (·.authorityId))).length ∧
    nextGuard.activePolicyHash = proposal.proposedPolicyHash ∧
    nextGuard.activeEgressDomains = proposal.newEgressDomains := by
  unfold submitAndCommitProposal at hCommit
  by_cases hZero : (guard.quorumThreshold == 0) = true
  · simp only [eq_true hZero, ite_true] at hCommit; cases hCommit
  · simp only [eq_false hZero, ite_false] at hCommit
    have hPos : 0 < guard.quorumThreshold := by
      apply Nat.pos_of_ne_zero
      intro hz
      simp [hz] at hZero
    cases hCol : collectVerifiedAuthorities guard proposal [] attestations with
    | error e => rw [hCol] at hCommit; cases hCommit
    | ok verified =>
      rw [hCol] at hCommit
      dsimp only at hCommit
      by_cases hLt : verified.length < guard.quorumThreshold
      · simp only [eq_true hLt, ite_true] at hCommit; cases hCommit
      · simp only [eq_false hLt, ite_false] at hCommit
        injection hCommit with hNextEq
        subst hNextEq
        have hGe : guard.quorumThreshold ≤ verified.length := Nat.le_of_not_lt hLt
        obtain ⟨hNdVer, _, _, hVerMem⟩ :=
          collectVerifiedAuthorities_invariants guard proposal attestations [] verified NoDup.nil hCol
        have hEachAtt : ∀ aid ∈ verified,
            ∃ att ∈ attestations, att.authorityId = aid ∧ validAttestation guard proposal att = true := by
          intro aid haid
          rcases hVerMem aid haid with hEmpty | hEx
          · cases hEmpty
          · exact hEx
        have hSubDedup : ∀ aid, aid ∈ verified →
            aid ∈ dedupIds ((attestations.filter (validAttestation guard proposal)).map (·.authorityId)) := by
          intro aid haid
          obtain ⟨att, haMem, haId, haVal⟩ := hEachAtt aid haid
          rw [mem_dedupIds_iff]
          rw [List.mem_map]
          refine ⟨att, List.mem_filter.mpr ⟨haMem, haVal⟩, haId⟩
        have hDedupGe : verified.length ≤
            (dedupIds ((attestations.filter (validAttestation guard proposal)).map (·.authorityId))).length :=
          nodup_subset_length_le verified _ hNdVer hSubDedup
        exact ⟨hPos, ⟨verified, hNdVer, hGe, hEachAtt⟩, Nat.le_trans hGe hDedupGe, rfl, rfl⟩

theorem quorum_zero_threshold_rejected
    (guard : QuorumPolicyGuard) (proposal : PolicyProposal)
    (attestations : List PolicyAttestation)
    (hZero : guard.quorumThreshold = 0) :
    submitAndCommitProposal guard proposal attestations = .error .ZeroThreshold := by
  unfold submitAndCommitProposal
  simp [hZero]

theorem quorum_duplicate_authority_rejected
    (guard : QuorumPolicyGuard) (proposal : PolicyProposal)
    (attestations : List PolicyAttestation)
    (hDup : ¬ NoDup (attestations.map (·.authorityId))) :
    ∃ e : LedgerError, submitAndCommitProposal guard proposal attestations = .error e := by
  unfold submitAndCommitProposal
  by_cases hZero : (guard.quorumThreshold == 0) = true
  · simp only [eq_true hZero, ite_true]; exact ⟨.ZeroThreshold, rfl⟩
  · simp only [eq_false hZero, ite_false]
    cases hCol : collectVerifiedAuthorities guard proposal [] attestations with
    | error e => exact ⟨e, rfl⟩
    | ok verified =>
      exfalso
      obtain ⟨_, hNd, _, _⟩ :=
        collectVerifiedAuthorities_invariants guard proposal attestations [] verified NoDup.nil hCol
      exact hDup hNd

theorem quorum_sybil_flood_blocked
    (guard : QuorumPolicyGuard) (proposal : PolicyProposal)
    (attestations : List PolicyAttestation) (sybilId : String)
    (hMin : 2 ≤ guard.quorumThreshold)
    (hAllSybil : ∀ att ∈ attestations, att.authorityId = sybilId) :
    ∃ e : LedgerError, submitAndCommitProposal guard proposal attestations = .error e := by
  cases hRes : submitAndCommitProposal guard proposal attestations with
  | error e => exact ⟨e, rfl⟩
  | ok nextGuard =>
    exfalso
    have hAnti := quorum_threshold_anti_sybil guard nextGuard proposal attestations hRes
    have hGe := hAnti.2.2.1
    have hFiltLen :
        (dedupIds ((attestations.filter (validAttestation guard proposal)).map (·.authorityId))).length ≤ 1 := by
      have hSub : ∀ aid,
          aid ∈ dedupIds ((attestations.filter (validAttestation guard proposal)).map (·.authorityId)) →
          aid ∈ [sybilId] := by
        intro aid haid
        rw [mem_dedupIds_iff, List.mem_map] at haid
        obtain ⟨att, haFilt, haId⟩ := haid
        have haMem : att ∈ attestations := (List.mem_filter.mp haFilt).1
        have hEq : aid = sybilId := by rw [← haId]; exact hAllSybil att haMem
        subst hEq
        exact List.Mem.head _
      have hNd := dedupIds_nodup ((attestations.filter (validAttestation guard proposal)).map (·.authorityId))
      have hLe := nodup_subset_length_le _ [sybilId] hNd hSub
      simpa using hLe
    omega

/-! ### Non-Vacuity Witnesses (`rfl` / `decide`) -/

section NonVacuityWitnesses

private def witnessUriDoc : MeshUri :=
  { scheme := .mcp, hostPath := "docs.internal/invoices", safeTarget := true }

private def witnessUriLedger : MeshUri :=
  { scheme := .a2a, hostPath := "ledger.internal/post", safeTarget := true }

private def witnessUriEgress : MeshUri :=
  { scheme := .egress, hostPath := "google.com/search", safeTarget := true }

-- Witness 1: Valid root creation and monotonic depth-1 attenuation succeed, while depth-8 -> depth-9 is rejected.
private def witnessRootMandate : AttenuatedMandate :=
  { mandateId := "m-001"
  , rootIssuerSpiffeId := "spiffe://octopus/root"
  , rootVerifyingKey := 1001
  , currentHolderSpiffeId := "spiffe://octopus/arm1"
  , depth := 0
  , allowedServices := [witnessUriDoc, witnessUriLedger]
  , allowedPublish := [witnessUriEgress]
  , notBefore := 100
  , expiresAt := 500
  , delegationChain :=
      [ { depth := 0
        , delegatorSpiffeId := "spiffe://octopus/root"
        , delegatorKey := 1001
        , delegateeSpiffeId := "spiffe://octopus/arm1"
        , delegateeKey := 2001
        , attenuatedServices := [witnessUriDoc, witnessUriLedger]
        , attenuatedPublish := [witnessUriEgress]
        , delegatedAt := 100
        , expiresAt := 500
        , signatureValid := true } ] }

example :
    createRootMandate "m-001" "spiffe://octopus/root" 1001 "spiffe://octopus/arm1" 2001
      [witnessUriDoc, witnessUriLedger] [witnessUriEgress] 100 500 true =
      .ok witnessRootMandate := by
  rfl

example :
    ∃ m1,
      attenuateMandate witnessRootMandate 2001 "spiffe://octopus/arm2" 2002
        [witnessUriDoc] [witnessUriEgress] 400 120 true = .ok m1 ∧
      m1.depth = 1 ∧
      m1.expiresAt = 400 := by
  refine ⟨_, rfl, rfl, rfl⟩

example :
    attenuateMandate { witnessRootMandate with depth := MANDATE_MAX_DELEGATION_DEPTH }
      2001 "spiffe://octopus/arm9" 2009 [witnessUriDoc] [] 400 120 true =
      .error .MaxDelegationDepthExceeded := by
  rfl

-- Regression Witness 1b: `verifyMandateChain` accepts validly attenuated chains...
example :
    verifyMandateChain witnessRootMandate 1001 150 = .ok () := by
  rfl

example :
    ∃ m1,
      attenuateMandate witnessRootMandate 2001 "spiffe://octopus/arm2" 2002
        [witnessUriDoc] [witnessUriEgress] 400 120 true = .ok m1 ∧
      verifyMandateChain m1 1001 150 = .ok () := by
  refine ⟨_, rfl, rfl⟩

-- Regression Witness 1c: `verifyMandateChain` rejects tampered top-level `allowedServices`,
-- `allowedPublish`, and `expiresAt` even when `delegationChain` is validly signed.
example :
    verifyMandateChain
      { witnessRootMandate with allowedServices := [witnessUriEgress, witnessUriDoc, witnessUriLedger] }
      1001 150 = .error .PrivilegeEscalationService := by
  rfl

example :
    verifyMandateChain
      { witnessRootMandate with allowedPublish := [witnessUriDoc, witnessUriEgress] }
      1001 150 = .error .PrivilegeEscalationPublish := by
  rfl

example :
    verifyMandateChain
      { witnessRootMandate with expiresAt := 999_999 }
      1001 150 = .error .MandateExpired := by
  rfl

-- Regression Witness 1d: `verifyMandateChain` rejects `.invalid` URI schemes in `rootLink` / top-level fields.
private def witnessUriInvalidScheme : MeshUri :=
  { scheme := .invalid, hostPath := "evil.example/exfil", safeTarget := true }

private def witnessInvalidSchemeMandate : AttenuatedMandate :=
  { witnessRootMandate with
    allowedServices := [witnessUriInvalidScheme]
    delegationChain :=
      [ { depth := 0
        , delegatorSpiffeId := "spiffe://octopus/root"
        , delegatorKey := 1001
        , delegateeSpiffeId := "spiffe://octopus/arm1"
        , delegateeKey := 2001
        , attenuatedServices := [witnessUriInvalidScheme]
        , attenuatedPublish := [witnessUriEgress]
        , delegatedAt := 100
        , expiresAt := 500
        , signatureValid := true } ] }

example :
    verifyMandateChain witnessInvalidSchemeMandate 1001 150 = .error .InvalidUriScheme := by
  rfl

-- Regression Witness 1e (Challenger Iter 2): `verifyMandateChain` rejects tampered `notBefore := 0`
-- on a post-dated root mandate (`notBefore = 1000`, `expiresAt = 2000`, `rootLink.delegatedAt = 1000`).
private def postDatedRoot : AttenuatedMandate :=
  { mandateId := "m-future"
  , rootIssuerSpiffeId := "spiffe://root"
  , rootVerifyingKey := 100
  , currentHolderSpiffeId := "spiffe://h0"
  , depth := 0
  , allowedServices := [witnessUriDoc]
  , allowedPublish := [witnessUriEgress]
  , notBefore := 1000
  , expiresAt := 2000
  , delegationChain :=
      [ { depth := 0
        , delegatorSpiffeId := "spiffe://root"
        , delegatorKey := 100
        , delegateeSpiffeId := "spiffe://h0"
        , delegateeKey := 200
        , attenuatedServices := [witnessUriDoc]
        , attenuatedPublish := [witnessUriEgress]
        , delegatedAt := 1000
        , expiresAt := 2000
        , signatureValid := true } ] }

private def tamperedNotBeforeMandate : AttenuatedMandate :=
  { postDatedRoot with notBefore := 0 }

example :
    createRootMandate "m-future" "spiffe://root" 100 "spiffe://h0" 200
      [witnessUriDoc] [witnessUriEgress] 1000 2000 true =
      .ok postDatedRoot := by
  rfl

example :
    verifyMandateChain postDatedRoot 100 500 = .error .MandateNotYetValid := by
  rfl

example :
    verifyMandateChain tamperedNotBeforeMandate 100 500 = .error .MandateNotYetValid := by
  rfl

example :
    verifyMandateChain tamperedNotBeforeMandate 100 1500 = .error .MandateNotYetValid := by
  rfl

example :
    verifyMandateChain postDatedRoot 100 1000 = .ok () := by
  rfl

-- Witness 2: 2-of-3 Quorum commits with 2 distinct valid authorities, and rejects 2 duplicate sybil attestations.
private def witnessProposal : PolicyProposal :=
  { proposalId := "prop-1"
  , proposedPolicyHash := 9999
  , newEgressDomains := ["google.com"]
  , timestampMs := 1000 }

private def witnessGuard : QuorumPolicyGuard :=
  { quorumThreshold := 2
  , authorities :=
      [ { authorityId := "auth_a", verifyingKey := 11 }
      , { authorityId := "auth_b", verifyingKey := 22 }
      , { authorityId := "auth_c", verifyingKey := 33 } ]
  , activePolicyHash := 0
  , activeEgressDomains := []
  , committedHistory := [] }

private def witnessAttA : PolicyAttestation :=
  { proposalId := "prop-1", authorityId := "auth_a", authorityPubkey := 11
  , signedDigest := witnessProposal, signatureValid := true }

private def witnessAttB : PolicyAttestation :=
  { proposalId := "prop-1", authorityId := "auth_b", authorityPubkey := 22
  , signedDigest := witnessProposal, signatureValid := true }

example :
    (submitAndCommitProposal witnessGuard witnessProposal [witnessAttA, witnessAttB]).isOk = true := by
  rfl

example :
    submitAndCommitProposal witnessGuard witnessProposal [witnessAttA, witnessAttA] =
      .error .DuplicateAuthority := by
  rfl

end NonVacuityWitnesses

end AgentOctopusFormal
