import AgentOctopusFormal.CoreTypes
import AgentOctopusFormal.FsmContainment
import AgentOctopusFormal.HomologicalMesh
import AgentOctopusFormal.EpochAutotomy
import AgentOctopusFormal.CageNoDirectBind
import AgentOctopusFormal.CedarAndTemporal
import AgentOctopusFormal.MandateAndQuorum
import AgentOctopusFormal.IsolationAndPerimeter

namespace AgentOctopusFormal

/-!
# Master Formal Verification Composition: `no_breakout` & `no_breach`

Composes Rings 1–4, CAGE (`NoDirectBind`, `CageRoutingSeal`, `CbfSafetyEngine`, `DebitLedger`),
Cedar PARC + Dogwood Temporal MFOTL, AgentMesh Mandate Attenuation + M-of-N Quorum,
and Isolation & Perimeter guards (`openConfined`, SSRF/DNS pinning, `TokenPosture` + Windows
pre-resume confinement, `KernelShieldPosture`, and Ring 4 `SentinelSupervisor` + `SEC-RING-01`).
-/

structure AgentOctopusSystemState where
  armRole : ArmRole
  armLayer : DeterministicLayerState
  armEpoch : ArmEpochState
  taint : TaintState
  meshGuard : MeshGuard
  delegationGuard : DelegationScopeGuard
  trustVerifier : IndependentTrustBoundaryVerifier
  bfsState : BfsState
  sealStore : RoutingSealStore
  ledger : DebitLedgerState
  cedarEnabled : Bool
  cedarPolicies : List CedarPolicy
  temporalTrace : TemporalTrace
  rootMandate : AttenuatedMandate
  activeMandate : AttenuatedMandate
  quorumGuard : QuorumPolicyGuard
  shieldPosture : KernelShieldPosture
  sentinelState : SentinelSupervisorState
  winPolicy : WindowsConfinementPolicy

def SystemInitialValid (sys : AgentOctopusSystemState) : Prop :=
  sys.armLayer = DeterministicLayerState.init sys.armLayer.policy ∧
  sys.armEpoch.revokedEpochs = [] ∧
  sys.taint.floor = roleTrustTier sys.armRole ∧
  sys.bfsState = bfsInitialState ∧
  sys.ledger.cfg.bMin ≤ sys.ledger.initialBudget ∧
  sys.ledger = DebitLedgerState.init sys.ledger.cfg sys.ledger.initialBudget ∧
  MandateReachable sys.rootMandate sys.activeMandate ∧
  0 < sys.quorumGuard.quorumThreshold ∧
  sys.cedarEnabled = true ∧
  sys.sentinelState.systemState = .Healthy ∧
  sys.sentinelState.isLockedDown = false ∧
  verifyWindowsConfinementInvariants sys.winPolicy = true

inductive SystemAction : Type where
  | fsmStep (act : LayerAction)
  | epochStep (act : EpochAction)
  | meshIngest (selfArmId : Nat) (selfEpochValid : Bool) (msg : ArmRingMeshMessage)
  | delegationInvoke (originator target : ArmRole) (chain : List ArmRole) (tool : String)
  | consumeDiracAndThreeLayer
      (t : DiracDeltaCapabilityTicket) (ctx : DiracConsumeContext) (gateInp : ThreeLayerGateInput)
  | cageAdvance (nextBfs : BfsState)
  | cageConsumeSeal
      (sigValid : CageRoutingSeal → Bool) (rseal : CageRoutingSeal) (expDig expRec : String) (now : Nat)
  | ledgerReserve (cost : Int) (debitId : String)
  | ledgerConfirm (debitId : String)
  | ledgerRollback (debitId : String)
  | ledgerRollbackLifo
  | cedarTighten (p : CedarPolicy)
  | cedarTemporalAuthorize
      (agentId : PrincipalId) (action : CedarAction) (resType : CedarEntityType)
      (resId : String) (cCtx : CedarContext) (clause : Option TemporalClauseStatus) (tCtx : TemporalContext)
  | attenuateMandateStep
      (delegatorKey : Nat) (delegateeSpiffeId : String) (delegateeKey : Nat)
      (narrowedServices narrowedPublish : List MeshUri) (newExpiresAt now : Nat) (childSigValid : Bool)
  | quorumCommitStep (proposal : PolicyProposal) (atts : List PolicyAttestation)
  | perimeterFileOpen
      (root : ConfinedHandleNode) (inp : SandboxPathInput) (dirs : List ConfinedHandleNode) (leaf : ConfinedHandleNode)
  | perimeterEgress
      (req : EgressUrlRequest) (allowedDomains : List String) (resolvedIps : List IpAddrSpec)
  | spawnChild (attempt : ChildSpawnAttempt)
  | shieldApply (nextPosture : KernelShieldPosture)
  | sentinelObserve (obs : SentinelObservation)
  | sentinelHeartbeat (seq uptimeMs : Nat) (policyOk containmentOk hmacOk : Bool)

def stepSystem (sys : AgentOctopusSystemState) (act : SystemAction) : Option AgentOctopusSystemState :=
  match act with
  | .fsmStep lact =>
    match stepLayer sys.armLayer lact with
    | some nextLayer => some { sys with armLayer := nextLayer }
    | none => none
  | .epochStep eact =>
    some { sys with armEpoch := stepEpoch sys.armEpoch eact }
  | .meshIngest selfArmId selfEpochValid msg =>
    match verifyIncomingMessage selfArmId sys.armRole selfEpochValid sys.taint msg with
    | .error _ => none
    | .ok (verified, nextTaint) =>
      match validateMeshMessage sys.meshGuard verified with
      | .error _ => none
      | .ok _ => some { sys with taint := nextTaint }
  | .delegationInvoke orig target chain tool =>
    match validateDelegation sys.delegationGuard orig chain target tool with
    | .ok () => some sys
    | .error _ => none
  | .consumeDiracAndThreeLayer t ctx gateInp =>
    if (t.consumeOnce ctx).2.isOk && (evaluateThreeLayerGate sys.trustVerifier gateInp).allowed then
      some sys
    else
      none
  | .cageAdvance nextBfs =>
    if nextBfs ∈ gatedNext sys.bfsState then
      some { sys with bfsState := nextBfs }
    else
      none
  | .cageConsumeSeal sigValid rseal expDig expRec now =>
    match validateAndConsume sigValid sys.sealStore rseal expDig expRec now with
    | .ok nextStore => some { sys with sealStore := nextStore }
    | .error _ => none
  | .ledgerReserve cost debitId =>
    match preReserve sys.ledger cost debitId with
    | .ok nextLedger => some { sys with ledger := nextLedger }
    | .error _ => none
  | .ledgerConfirm debitId =>
    match confirmLedger sys.ledger debitId with
    | .ok nextLedger => some { sys with ledger := nextLedger }
    | .error _ => none
  | .ledgerRollback debitId =>
    match rollbackLedger sys.ledger debitId with
    | .ok nextLedger => some { sys with ledger := nextLedger }
    | .error _ => none
  | .ledgerRollbackLifo =>
    match rollbackLifoLedger sys.ledger with
    | .ok nextLedger => some { sys with ledger := nextLedger }
    | .error _ => none
  | .cedarTighten p =>
    match addTightenOnlyForbidPolicy sys.cedarPolicies p with
    | some nextPols => some { sys with cedarPolicies := nextPols }
    | none => none
  | .cedarTemporalAuthorize agentId action resType resId cCtx clause tCtx =>
    if evaluateCedarAndTemporalGate sys.cedarEnabled sys.cedarPolicies agentId sys.armRole
        action resType resId cCtx clause sys.temporalTrace tCtx then
      some sys
    else
      none
  | .attenuateMandateStep delegatorKey delegateeSpiffeId delegateeKey
      narrowedServices narrowedPublish newExpiresAt now childSigValid =>
    match attenuateMandate sys.activeMandate delegatorKey delegateeSpiffeId delegateeKey
        narrowedServices narrowedPublish newExpiresAt now childSigValid with
    | .ok nextMandate => some { sys with activeMandate := nextMandate }
    | .error _ => none
  | .quorumCommitStep proposal atts =>
    match submitAndCommitProposal sys.quorumGuard proposal atts with
    | .ok nextGuard => some { sys with quorumGuard := nextGuard }
    | .error _ => none
  | .perimeterFileOpen root inp dirs leaf =>
    match openConfined root inp dirs leaf with
    | .ok _ => some sys
    | .error _ => none
  | .perimeterEgress req allowedDomains resolvedIps =>
    match resolveAndPin req allowedDomains resolvedIps with
    | .ok _ => some sys
    | .error _ => none
  | .spawnChild attempt =>
    match tryResumeChild sys.winPolicy attempt with
    | .Resumed => some sys
    | .TerminatedBeforeResume => none
  | .shieldApply nextPosture =>
    match applyPosture sys.shieldPosture nextPosture with
    | .ok nextSh => some { sys with shieldPosture := nextSh }
    | .error _ => none
  | .sentinelObserve obs =>
    some { sys with sentinelState := (stepObservation sys.sentinelState obs).1 }
  | .sentinelHeartbeat seq uptimeMs policyOk containmentOk hmacOk =>
    some { sys with sentinelState := (stepHeartbeat sys.sentinelState seq uptimeMs policyOk containmentOk hmacOk).1 }

inductive SystemReachable (initSys : AgentOctopusSystemState) : AgentOctopusSystemState → Prop where
  | init : SystemReachable initSys initSys
  | step {s s' : AgentOctopusSystemState} (act : SystemAction) :
      SystemReachable initSys s → stepSystem s act = some s' → SystemReachable initSys s'

private theorem stepSystem_preserves_invariants
    (initSys sys : AgentOctopusSystemState)
    (hInit : SystemInitialValid initSys)
    (hReach : SystemReachable initSys sys) :
    LayerReachable initSys.armLayer.policy sys.armLayer ∧
    EpochTrace initSys.armEpoch sys.armEpoch ∧
    GatedReachable sys.bfsState ∧
    LedgerReachable initSys.ledger.cfg initSys.ledger.initialBudget sys.ledger ∧
    MandateReachable initSys.rootMandate sys.activeMandate ∧
    sys.rootMandate = initSys.rootMandate ∧
    0 < sys.quorumGuard.quorumThreshold ∧
    sys.cedarEnabled = true ∧
    ShieldApplyTrace initSys.shieldPosture sys.shieldPosture ∧
    verifyWindowsConfinementInvariants sys.winPolicy = true := by
  induction hReach with
  | init =>
    rcases hInit with ⟨hL, _, _, hBfs, _, hLed, hMand, hQuo, hCed, _, _, hWin⟩
    refine ⟨?_, EpochTrace.refl _, ?_, ?_, hMand, rfl, hQuo, hCed, ShieldApplyTrace.refl _, hWin⟩
    · rw [hL]; exact LayerReachable.init
    · rw [hBfs]; exact GatedReachable.init
    · rw [hLed]; exact LedgerReachable.init
  | @step s s' act _ hStep ih =>
    rcases ih with ⟨ihLayer, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    cases act with
    | fsmStep lact =>
      dsimp only [stepSystem] at hStep
      cases hL : stepLayer s.armLayer lact with
      | none => rw [hL] at hStep; cases hStep
      | some nextLayer =>
        rw [hL] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨LayerReachable.step ihLayer hL, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | epochStep eact =>
      dsimp only [stepSystem] at hStep
      injection hStep with hEq; subst hEq
      exact ⟨ihLayer, EpochTrace.step eact ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | meshIngest selfArmId selfEpochValid msg =>
      dsimp only [stepSystem] at hStep
      cases hV : verifyIncomingMessage selfArmId s.armRole selfEpochValid s.taint msg with
      | error e => rw [hV] at hStep; cases hStep
      | ok p =>
        rcases p with ⟨verified, nextTaint⟩
        rw [hV] at hStep
        dsimp only at hStep
        cases hM : validateMeshMessage s.meshGuard verified with
        | error e => rw [hM] at hStep; cases hStep
        | ok r =>
          rw [hM] at hStep
          injection hStep with hEq; subst hEq
          exact ⟨ihLayer, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | delegationInvoke orig target chain tool =>
      dsimp only [stepSystem] at hStep
      cases hD : validateDelegation s.delegationGuard orig chain target tool with
      | error e => rw [hD] at hStep; cases hStep
      | ok u =>
        rw [hD] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | consumeDiracAndThreeLayer t ctx gateInp =>
      dsimp only [stepSystem] at hStep
      by_cases hc : ((t.consumeOnce ctx).2.isOk && (evaluateThreeLayerGate s.trustVerifier gateInp).allowed) = true
      · simp only [eq_true hc, ite_true] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
      · simp only [eq_false hc, ite_false] at hStep; cases hStep
    | cageAdvance nextBfs =>
      dsimp only [stepSystem] at hStep
      by_cases hMem : nextBfs ∈ gatedNext s.bfsState
      · simp only [eq_true hMem, ite_true] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, GatedReachable.step ihBfs hMem, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
      · simp only [eq_false hMem, ite_false] at hStep; cases hStep
    | cageConsumeSeal sigValid rseal expDig expRec now =>
      dsimp only [stepSystem] at hStep
      cases hC : validateAndConsume sigValid s.sealStore rseal expDig expRec now with
      | error e => rw [hC] at hStep; cases hStep
      | ok nextStore =>
        rw [hC] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | ledgerReserve cost debitId =>
      dsimp only [stepSystem] at hStep
      cases hR : preReserve s.ledger cost debitId with
      | error e => rw [hR] at hStep; cases hStep
      | ok nextLed =>
        rw [hR] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, ihBfs, LedgerReachable.reserve cost debitId ihLedger hR, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | ledgerConfirm debitId =>
      dsimp only [stepSystem] at hStep
      cases hR : confirmLedger s.ledger debitId with
      | error e => rw [hR] at hStep; cases hStep
      | ok nextLed =>
        rw [hR] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, ihBfs, LedgerReachable.confirm debitId ihLedger hR, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | ledgerRollback debitId =>
      dsimp only [stepSystem] at hStep
      cases hR : rollbackLedger s.ledger debitId with
      | error e => rw [hR] at hStep; cases hStep
      | ok nextLed =>
        rw [hR] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, ihBfs, LedgerReachable.rollback debitId ihLedger hR, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | ledgerRollbackLifo =>
      dsimp only [stepSystem] at hStep
      cases hR : rollbackLifoLedger s.ledger with
      | error e => rw [hR] at hStep; cases hStep
      | ok nextLed =>
        rw [hR] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, ihBfs, LedgerReachable.rollbackLifo ihLedger hR, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | cedarTighten p =>
      dsimp only [stepSystem] at hStep
      cases hC : addTightenOnlyForbidPolicy s.cedarPolicies p with
      | none => rw [hC] at hStep; cases hStep
      | some nextPols =>
        rw [hC] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | cedarTemporalAuthorize agentId action resType resId cCtx clause tCtx =>
      dsimp only [stepSystem] at hStep
      by_cases hG : evaluateCedarAndTemporalGate s.cedarEnabled s.cedarPolicies agentId s.armRole
          action resType resId cCtx clause s.temporalTrace tCtx = true
      · simp only [eq_true hG, ite_true] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
      · simp only [eq_false hG, ite_false] at hStep; cases hStep
    | attenuateMandateStep delegatorKey delegateeSpiffeId delegateeKey
        narrowedServices narrowedPublish newExpiresAt now childSigValid =>
      dsimp only [stepSystem] at hStep
      cases hA : attenuateMandate s.activeMandate delegatorKey delegateeSpiffeId delegateeKey
          narrowedServices narrowedPublish newExpiresAt now childSigValid with
      | error e => rw [hA] at hStep; cases hStep
      | ok nextM =>
        rw [hA] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, ihBfs, ihLedger,
          MandateReachable.step s.activeMandate nextM delegatorKey delegateeSpiffeId delegateeKey
            narrowedServices narrowedPublish newExpiresAt now childSigValid ihMand hA,
          ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | quorumCommitStep proposal atts =>
      dsimp only [stepSystem] at hStep
      cases hQ : submitAndCommitProposal s.quorumGuard proposal atts with
      | error e => rw [hQ] at hStep; cases hStep
      | ok nextG =>
        rw [hQ] at hStep
        injection hStep with hEq; subst hEq
        have hAnti := quorum_threshold_anti_sybil s.quorumGuard nextG proposal atts hQ
        have hEqThresh : nextG.quorumThreshold = s.quorumGuard.quorumThreshold := by
          unfold submitAndCommitProposal at hQ
          split at hQ
          · cases hQ
          · split at hQ
            · cases hQ
            · split at hQ
              · cases hQ
              · injection hQ with hNext
                rw [← hNext]
        refine ⟨ihLayer, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ?_, ihCed, ihShield, ihWin⟩
        rw [hEqThresh]
        exact hAnti.1
    | perimeterFileOpen root inp dirs leaf =>
      dsimp only [stepSystem] at hStep
      cases hO : openConfined root inp dirs leaf with
      | error e => rw [hO] at hStep; cases hStep
      | ok _ =>
        rw [hO] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | perimeterEgress req allowedDomains resolvedIps =>
      dsimp only [stepSystem] at hStep
      cases hE : resolveAndPin req allowedDomains resolvedIps with
      | error e => rw [hE] at hStep; cases hStep
      | ok _ =>
        rw [hE] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | spawnChild attempt =>
      dsimp only [stepSystem] at hStep
      cases hS : tryResumeChild s.winPolicy attempt with
      | TerminatedBeforeResume => rw [hS] at hStep; cases hStep
      | Resumed =>
        rw [hS] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | shieldApply nextPosture =>
      dsimp only [stepSystem] at hStep
      cases hSh : applyPosture s.shieldPosture nextPosture with
      | error e => rw [hSh] at hStep; cases hStep
      | ok nextSh =>
        rw [hSh] at hStep
        injection hStep with hEq; subst hEq
        exact ⟨ihLayer, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed,
          ShieldApplyTrace.step nextPosture ihShield hSh, ihWin⟩
    | sentinelObserve obs =>
      dsimp only [stepSystem] at hStep
      injection hStep with hEq; subst hEq
      exact ⟨ihLayer, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩
    | sentinelHeartbeat seq uptimeMs policyOk containmentOk hmacOk =>
      dsimp only [stepSystem] at hStep
      injection hStep with hEq; subst hEq
      exact ⟨ihLayer, ihEpoch, ihBfs, ihLedger, ihMand, ihRootEq, ihQuo, ihCed, ihShield, ihWin⟩

/-- Explicit non-vacuous system breakout-freedom invariant across Rings 1–4 + Perimeter. -/
def BreakoutFree (sys : AgentOctopusSystemState) : Prop :=
  ((roleTrustTier sys.armRole).rank = 10 ∨
   (roleTrustTier sys.armRole).rank = 50 ∨
   (roleTrustTier sys.armRole).rank = 100) ∧
  LayerCapsInvariant sys.armLayer ∧
  (∀ s, ReachableFrom .Quarantined s → s ≠ .Completed) ∧
  (∀ e ∈ sys.armEpoch.revokedEpochs, validateEpoch sys.armEpoch e = false) ∧
  (∀ inp, (evaluateThreeLayerGate sys.trustVerifier inp).allowed = true →
    inp.l1Proof.domain = .L1UserspaceCedar ∧
    inp.l2Proof.domain = .L2TpmMerkle ∧
    inp.l3Proof.domain = .L3OsKernel ∧
    inp.kernelProcessInJob = true) ∧
  (∀ v r, validateMeshMessage sys.meshGuard v = .ok r →
    r.coboundaryResidue = 0 ∧
    (roleTrustTier v.recipientRole = .PrivilegedSink →
      v.roleChain.getLast? = some v.recipientRole →
      v.effectiveTaintFloor ≠ .Untrusted ∧ ∀ x ∈ v.roleChain, roleTrustTier x ≠ .Untrusted)) ∧
  (∀ ts eff r, ts.floor = .Untrusted →
    updateTaintFloor ts eff = .Untrusted ∧
    outboundTaintFloor r { ts with floor := updateTaintFloor ts eff } = .Untrusted) ∧
  (∀ root inp dirs leaf opened, openConfined root inp dirs leaf = .ok opened →
    isStrictlyInside root.finalPathSegments opened.finalPathSegments = true ∧
    opened.isReparsePoint = false ∧
    opened.numLinks ≤ 1) ∧
  ((∀ v4, ipv4InRestrictedRange v4 → isRestrictedRebindingIp (.v4 v4) = true) ∧
   (∀ v6, ipv6InRestrictedRange v6 → isRestrictedRebindingIp (.v6 v6) = true) ∧
   (∀ req allowed ips pinned, resolveAndPin req allowed ips = .ok pinned →
    ∀ ip ∈ pinned.pinnedAddrs, isRestrictedRebindingIp ip = false)) ∧
  (∀ attempt, tryResumeChild sys.winPolicy attempt = .Resumed →
    attempt.tokenPosture.elevated = false ∧
    attempt.tokenPosture.integrityRid ≤ INTEGRITY_MEDIUM ∧
    attempt.tokenPosture.adminsEnabled = false ∧
    attempt.createdSuspended = true ∧
    attempt.assignedToJob = true ∧
    attempt.verifiedInJob = true) ∧
  (∀ next out, applyPosture sys.shieldPosture next = .ok out →
    sys.shieldPosture.monotonicRevision < out.monotonicRevision ∧
    (sys.shieldPosture.shieldLockedUntilReboot = true → out.shieldLockedUntilReboot = true)) ∧
  (∀ obs, (obs.supervisorHealthy = false ∨ obs.authorizationHealthy = false ∨
    obs.sandboxVerified = false ∨ obs.proxyEnforcementIntact = false) →
    evaluateSentinel obs = .LockdownSystem ∧
    (stepObservation sys.sentinelState obs).1.systemState = .Lockdown ∧
    (stepObservation sys.sentinelState obs).1.isLockedDown = true)

/-- Explicit non-vacuous system breach-freedom invariant across PolicyGuard, Law 3 Dirac,
    CAGE (`NoDirectBind`, `RoutingSeal`, `CbfSafetyEngine`, `DebitLedger`), Cedar + Dogwood,
    and AgentMesh (`AttenuatedMandate`, `QuorumPolicyGuard`). -/
def BreachFree (sys : AgentOctopusSystemState) : Prop :=
  LayerCapsInvariant sys.armLayer ∧
  (∀ (t : DiracDeltaCapabilityTicket) ctx1 ctx2, ∃ err : DiracConsumeError, ((t.consumeOnce ctx1).1.consumeOnce ctx2).2 = .error err) ∧
  (GatedReachable sys.bfsState ∧
    (sys.bfsState.phase = .Executed → sys.bfsState.sealPresent = true ∧ sys.bfsState.resolvedAllow = true)) ∧
  (∀ sig store1 store2 rseal d1 r1 d2 r2 t1 t2,
    validateAndConsume sig sys.sealStore rseal d1 r1 t1 = .ok store1 →
    t1 ≤ t2 →
    SealStoreReachable sig t1 store1 t2 store2 →
    ∃ err, validateAndConsume sig store2 rseal d2 r2 t2 = .error err) ∧
  (- Int.ofNat sys.ledger.cfg.eps ≤ sys.ledger.availableBudget - sys.ledger.cfg.bMin ∧
    sys.ledger.availableBudget + activeReservedSum sys.ledger.reservations +
      committedSum sys.ledger.reservations = sys.ledger.initialBudget) ∧
  (∀ pF req, pF ∈ sys.cedarPolicies → pF.effect = .Forbid → pF.matchesRequest req = true →
    evalPolicySet sys.cedarPolicies req = false) ∧
  (∀ claimed auth act rtype rid ctx, claimed ≠ auth →
    evaluateCedarGate sys.cedarEnabled sys.cedarPolicies (.reserved claimed) auth act rtype rid ctx = false) ∧
  (∀ agentId role act rtype rid ctx amt,
    ctx.amountCents = some amt → amt > CEDAR_MAX_SPEND_CENTS →
    evaluateCedarGate sys.cedarEnabled sys.cedarPolicies agentId role act rtype rid ctx = false) ∧
  (∀ clause trace tCtx,
    (clause = .parseError ∨ trace.airVerified = false ∨ traceWellFormed trace tCtx.currentTimeSecs = false) →
    evalTemporalGate clause trace tCtx = false) ∧
  (MandateReachable sys.rootMandate sys.activeMandate ∧
    sys.activeMandate.depth ≤ MANDATE_MAX_DELEGATION_DEPTH ∧
    (∀ s ∈ sys.activeMandate.allowedServices, s ∈ sys.rootMandate.allowedServices) ∧
    sys.activeMandate.expiresAt ≤ sys.rootMandate.expiresAt) ∧
  (0 < sys.quorumGuard.quorumThreshold ∧
    ∀ prop atts nextG, submitAndCommitProposal sys.quorumGuard prop atts = .ok nextG →
      sys.quorumGuard.quorumThreshold ≤
        (dedupIds ((atts.filter (validAttestation sys.quorumGuard prop)).map (·.authorityId))).length)

/-- **Master Theorem 1 (`no_breakout`)**:
    For every initial valid configuration `initSys` and every reachable system state `sys`:
    1. `BreakoutFree sys` holds across all 4 containment rings and perimeter subsystems, AND
    2. Every concrete breakout vector (path traversal, restricted SSRF IP, elevated/uncontained child,
       `Untrusted -> PrivilegedSink` mesh message, revoked epoch, shield unlock during pending reboot,
       and unhealthy sentinel observation) is unconditionally rejected. -/
theorem no_breakout
    (initSys sys : AgentOctopusSystemState)
    (hInit : SystemInitialValid initSys)
    (hReach : SystemReachable initSys sys) :
    BreakoutFree sys ∧
    (∀ root inp dirs leaf, inp.hasDotDot = true ∨ inp.hasPercentTraversal = true →
      ∃ e, openConfined root inp dirs leaf = .error e) ∧
    (∀ req allowed ips ip, ip ∈ ips → isRestrictedRebindingIp ip = true →
      ∃ e, resolveAndPin req allowed ips = .error e) ∧
    (∀ attempt, (attempt.tokenPosture.elevated = true ∨ attempt.tokenPosture.integrityRid > INTEGRITY_MEDIUM ∨
      attempt.verifiedInJob = false) →
      stepSystem sys (.spawnChild attempt) = none) ∧
    (∀ chain rec, chain.getLast? = some rec → roleTrustTier rec = .PrivilegedSink →
      (∃ r ∈ chain, roleTrustTier r = .Untrusted) → (auditRoleChain chain).allowed = false) ∧
    (∀ e, e ∈ sys.armEpoch.revokedEpochs → validateEpoch sys.armEpoch e = false) ∧
    (∀ next, sys.shieldPosture.shieldLockedUntilReboot = true → next.shieldLockedUntilReboot = false →
      stepSystem sys (.shieldApply next) = none) ∧
    (∀ obs, obs.supervisorHealthy = false →
      (stepObservation sys.sentinelState obs).1.systemState = .Lockdown) := by
  obtain ⟨hLayer, _, _, _, _, _, _, _, _, _⟩ :=
    stepSystem_preserves_invariants initSys sys hInit hReach
  have hCaps := (policy_guard_caps_enforced hLayer).1
  have hBreakout : BreakoutFree sys := by
    refine ⟨roleTrustTier_valid_ranks sys.armRole, hCaps, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · intro s hs; exact quarantined_cannot_complete hs
    · intro e he; exact revoked_epoch_never_valid sys.armEpoch e (Or.inr (Or.inl he))
    · intro inp hAll
      have hG := ((three_layer_non_circular_gate sys.trustVerifier inp).2).mp hAll
      exact ⟨hG.1, hG.2.2.2.1, hG.2.2.2.2.2.2.1, hG.2.2.2.2.2.2.2.2.2⟩
    · intro v r hVal
      have hNp := no_proxy_laundering sys.meshGuard v r hVal
      exact ⟨hNp.2.1, hNp.2.2.2.2.2⟩
    · intro ts eff r hUnt
      exact sticky_taint_untrusted_absorbing ts eff r hUnt
    · intro root inp dirs leaf opened hOpen
      rcases path_join_no_escape root inp dirs leaf opened hOpen with
        ⟨_, _, _, _, _, _, _, _, _, _, _, _, hRep, _, hLnk, hIn, _⟩
      exact ⟨hIn, hRep, hLnk⟩
    · refine ⟨fun v4 h => (isIpv4Restricted_iff v4).mpr h, fun v6 h => (isIpv6Restricted_iff v6).mpr h, ?_⟩
      intro req allowed ips pinned hPin ip hip
      exact (ssrf_blocks_all_restricted_ranges req allowed ips).2.2 pinned hPin |>.2.2.2.2.2.2.2.2.2 ip hip
    · intro attempt hRes
      rcases (pre_resume_no_elevated_uncontained_child sys.winPolicy attempt).1 hRes with
        ⟨hEl, hRid, hAdm, _, hSus, hJob, hVer, _⟩
      exact ⟨hEl, hRid, hAdm, hSus, hJob, hVer⟩
    · intro next out hApp
      have hSh := (shield_latch_monotonic sys.shieldPosture sys.shieldPosture next out "" false).2.1 hApp
      exact ⟨hSh.1, fun hL => (hSh.2 hL).1⟩
    · intro obs hFail
      exact (sentinel_fail_closed_lockdown sys.sentinelState obs 0 0 0 0 true true true).1 hFail
  refine ⟨hBreakout, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro root inp dirs leaf hTrav
    unfold openConfined validateSandboxRelativePath
    by_cases hE : inp.rawTrimmed.isEmpty = true
    · simp only [eq_true hE, ite_true]; exact ⟨_, rfl⟩
    · simp only [eq_false hE, ite_false]
      by_cases hR : (inp.hasNull || inp.hasColon || inp.startsWithSlashOrBackslash) = true
      · simp only [eq_true hR, ite_true]; exact ⟨_, rfl⟩
      · simp only [eq_false hR, ite_false]
        rcases hTrav with hDD | hPct
        · simp [hDD]
        · simp [hPct]
  · intro req allowed ips ip hipMem hipRes
    unfold resolveAndPin
    cases hV : validateAgentEgressUrl req allowed with
    | error e => exact ⟨e, rfl⟩
    | ok _ =>
      dsimp only
      by_cases hEmp : ips.isEmpty = true
      · simp only [eq_true hEmp, ite_true]; exact ⟨_, rfl⟩
      · simp only [eq_false hEmp, ite_false]
        have hAny : ips.any isRestrictedRebindingIp = true := by
          clear hV hEmp
          induction ips with
          | nil => cases hipMem
          | cons x xs ih =>
            rw [List.any_cons]
            cases hipMem with
            | head => rw [hipRes, Bool.true_or]
            | tail _ hm => rw [ih hm, Bool.or_true]
        simp [hAny]
  · intro attempt hBad
    have hTerm : tryResumeChild sys.winPolicy attempt = .TerminatedBeforeResume := by
      apply (pre_resume_no_elevated_uncontained_child sys.winPolicy attempt).2
      rcases hBad with h1 | h2 | h3
      · exact Or.inl h1
      · exact Or.inr (Or.inl h2)
      · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl h3))))))
    simp [stepSystem, hTerm]
  · intro chain rec hLast hSink hUnt
    exact auditRoleChain_blocks_untrusted_to_privileged chain rec hLast hSink hUnt
  · intro e he
    exact revoked_epoch_never_valid sys.armEpoch e (Or.inr (Or.inl he))
  · intro next hLock hUnlock
    have hErr : applyPosture sys.shieldPosture next = .error .MonotonicLatchViolation := by
      unfold applyPosture
      simp [hLock, hUnlock]
    simp [stepSystem, hErr]
  · intro obs hSup
    exact ((sentinel_fail_closed_lockdown sys.sentinelState obs 0 0 0 0 true true true).1 (Or.inl hSup)).2.1

/-- **Master Theorem 2 (`no_breach`)**:
    For every initial valid configuration `initSys` and every reachable system state `sys`:
    1. `BreachFree sys` holds across PolicyGuard, Law 3 Dirac, CAGE (`NoDirectBind`, `CageRoutingSeal`,
       `CbfSafetyEngine`, `DebitLedger`), Cedar + Dogwood, and AgentMesh (`AttenuatedMandate`,
       `QuorumPolicyGuard`), AND
    2. Every concrete breach vector (over-`$100k` artifact or Cedar spend, Dirac replay, CAGE seal replay,
       ungated or skipped-tier direct bind, Cedar `Forbid` override / principal spoof / unmapped role,
       unproven Dogwood trace, mandate depth `> 8`, and Sybil/zero-threshold quorum) is unconditionally rejected. -/
private theorem ledgerReachable_cfg_init_eq
    (cfg : CbfConfig) (initBudget : Int) {st : DebitLedgerState}
    (hReach : LedgerReachable cfg initBudget st) :
    st.cfg = cfg ∧ st.initialBudget = initBudget := by
  induction hReach with
  | init => exact ⟨rfl, rfl⟩
  | @reserve _ _ _ _ _ hRes ih =>
    unfold preReserve at hRes
    dsimp only at hRes
    split at hRes
    · cases hRes
    · injection hRes with hEq; rw [← hEq]; exact ih
  | @confirm _ _ _ _ hConf ih =>
    unfold confirmLedger at hConf
    split at hConf
    · cases hConf
    · injection hConf with hEq; rw [← hEq]; exact ih
  | @rollback _ _ _ _ hRb ih =>
    unfold rollbackLedger at hRb
    split at hRb
    · cases hRb
    · injection hRb with hEq; rw [← hEq]; exact ih
  | @rollbackLifo _ _ _ hRb ih =>
    unfold rollbackLifoLedger at hRb
    split at hRb
    · cases hRb
    · injection hRb with hEq; rw [← hEq]; exact ih

theorem no_breach
    (initSys sys : AgentOctopusSystemState)
    (hInit : SystemInitialValid initSys)
    (hReach : SystemReachable initSys sys) :
    BreachFree sys ∧
    (∀ pg a, a.amountCents > pg.maxAmountCents → enforceArtifact pg a = false) ∧
    (∀ (t : DiracDeltaCapabilityTicket) ctx1 ctx2, ∃ err : DiracConsumeError, ((t.consumeOnce ctx1).1.consumeOnce ctx2).2 = .error err) ∧
    (∀ s, SkippedReachable 0 s → s.phase ≠ .Executed) ∧
    (∃ s, UngatedReachable s ∧ s.phase = .Executed ∧ s.sealPresent = false) ∧
    (∀ roleStr agentId act rtype rid ctx, parseArmRole roleStr = none →
      authorizeWithRoleStr sys.cedarEnabled sys.cedarPolicies agentId roleStr act rtype rid ctx = false) ∧
    (∀ pF req, pF ∈ sys.cedarPolicies → pF.effect = .Forbid → pF.matchesRequest req = true →
      evalPolicySet sys.cedarPolicies req = false) ∧
    (∀ m k now, MANDATE_MAX_DELEGATION_DEPTH < m.depth →
      ∃ e, verifyMandateChain m k now = .error e) ∧
    (∀ guard prop atts sybilId, 2 ≤ guard.quorumThreshold →
      (∀ att ∈ atts, att.authorityId = sybilId) →
      ∃ e, submitAndCommitProposal guard prop atts = .error e) := by
  obtain ⟨hLayer, _, hBfs, hLedger, hMand, hRootEq, hQuo, _, _, _⟩ :=
    stepSystem_preserves_invariants initSys sys hInit hReach
  have hCaps := (policy_guard_caps_enforced hLayer).1
  have hInitLed := hInit.2.2.2.2.1
  have hCbf := cbf_forward_invariance initSys.ledger.cfg initSys.ledger.initialBudget hInitLed sys.ledger hLedger
  have hDeb := debit_no_leakage initSys.ledger.cfg initSys.ledger.initialBudget hInitLed sys.ledger hLedger
  have hMandAtt := mandate_monotonic_attenuation hMand
  obtain ⟨hLedCfgEq, hLedInitEq⟩ :=
    ledgerReachable_cfg_init_eq initSys.ledger.cfg initSys.ledger.initialBudget hLedger
  have hBreach : BreachFree sys := by
    refine ⟨hCaps, ?_, ⟨hBfs, fun hex => no_direct_bind sys.bfsState hBfs hex⟩, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · intro t ctx1 ctx2; exact (dirac_single_use_no_replay t ctx1 ctx2).1
    · intro sig s1 s2 rseal d1 r1 d2 r2 t1 t2 hCon hMono hTr
      exact (seal_single_use_and_ttl sig sys.sealStore s1 s2 rseal d1 r1 d2 r2 t1 t2 hCon hMono hTr).2.2.2.2.2.2.2
    · refine ⟨?_, ?_⟩
      · rw [hLedCfgEq]; exact hCbf.1
      · rw [hLedInitEq]; exact hDeb.1
    · intro pF req hm he hmat; exact forbid_dominates_permit sys.cedarPolicies req pF hm he hmat
    · intro claimed auth act rtype rid ctx hne
      exact no_principal_spoofing sys.cedarEnabled sys.cedarPolicies claimed auth act rtype rid ctx hne
    · intro agentId role act rtype rid ctx amt hAmt hOver
      exact spending_cap_enforced sys.cedarEnabled sys.cedarPolicies agentId role act rtype rid ctx amt hAmt hOver
    · intro clause trace tCtx hBad
      have hTfc := temporal_fail_closed clause trace tCtx
      rcases hBad with hErr | hAir | hWf
      · exact hTfc.1 hErr
      · exact hTfc.2.1 hAir
      · exact hTfc.2.2.1 hWf
    · rw [hRootEq]
      exact ⟨hMand, hMandAtt.1, hMandAtt.2.1, hMandAtt.2.2.2.1⟩
    · refine ⟨hQuo, ?_⟩
      intro prop atts nextG hCom
      exact (quorum_threshold_anti_sybil sys.quorumGuard nextG prop atts hCom).2.2.1
  refine ⟨hBreach, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro pg a hOver
    unfold enforceArtifact
    have hF : decide (a.amountCents ≤ pg.maxAmountCents) = false := decide_eq_false (Nat.not_le_of_gt hOver)
    simp [hF]
  · intro t ctx1 ctx2; exact (dirac_single_use_no_replay t ctx1 ctx2).1
  · intro s hs; exact skipped_tier_unreachable_executed 0 s hs
  · obtain ⟨s, hr, hp, hs, _⟩ := ungated_has_counterexample
    exact ⟨s, hr, hp, hs⟩
  · intro roleStr agentId act rtype rid ctx hNone
    exact default_deny_unmapped_role sys.cedarEnabled sys.cedarPolicies agentId roleStr act rtype rid ctx hNone
  · intro pF req hm he hmat
    exact forbid_dominates_permit sys.cedarPolicies req pF hm he hmat
  · intro m k now hDeep
    exact verifyMandateChain_depth_gt_8_rejected m k now hDeep
  · intro guard prop atts sybilId hMin hSyb
    exact quorum_sybil_flood_blocked guard prop atts sybilId hMin hSyb

/-! ### Non-Vacuity Witnesses (`rfl` / `decide` / concrete initial state) -/

section NonVacuityWitnesses

private def witnessSysUri : MeshUri :=
  { scheme := .mcp, hostPath := "docs.internal/invoices", safeTarget := true }

private def witnessSysRootMandate : AttenuatedMandate :=
  { mandateId := "m-sys-1"
  , rootIssuerSpiffeId := "spiffe://octopus/root"
  , rootVerifyingKey := 1001
  , currentHolderSpiffeId := "spiffe://octopus/arm0"
  , depth := 0
  , allowedServices := [witnessSysUri]
  , allowedPublish := []
  , notBefore := 100
  , expiresAt := 500
  , delegationChain :=
      [ { depth := 0
        , delegatorSpiffeId := "spiffe://octopus/root"
        , delegatorKey := 1001
        , delegateeSpiffeId := "spiffe://octopus/arm0"
        , delegateeKey := 2001
        , attenuatedServices := [witnessSysUri]
        , attenuatedPublish := []
        , delegatedAt := 100
        , expiresAt := 500
        , signatureValid := true } ] }

private def witnessCbfCfg : CbfConfig :=
  { gamma := { num := 1, den := 2, numPos := by decide, leOne := by decide }
  , bMin := 100
  , bMinNonNeg := by decide
  , eps := 0 }

private def witnessInitSys : AgentOctopusSystemState :=
  { armRole := .AccountingLedgerWrite
  , armLayer := DeterministicLayerState.init {}
  , armEpoch := ArmEpochState.init 1 1
  , taint := TaintState.init .AccountingLedgerWrite
  , meshGuard := { allowedRoutes := [] }
  , delegationGuard := {}
  , trustVerifier := {}
  , bfsState := bfsInitialState
  , sealStore := { activePolicyVersion := "0123456789abcdef", consumedSeals := [], lastPruneTime := 0 }
  , ledger := DebitLedgerState.init witnessCbfCfg 1000
  , cedarEnabled := true
  , cedarPolicies := defaultOctopusPolicies
  , temporalTrace := { events := [], airVerified := true }
  , rootMandate := witnessSysRootMandate
  , activeMandate := witnessSysRootMandate
  , quorumGuard :=
      { quorumThreshold := 2
      , authorities := [{ authorityId := "a1", verifyingKey := 1 }, { authorityId := "a2", verifyingKey := 2 }]
      , activePolicyHash := 0
      , activeEgressDomains := []
      , committedHistory := [] }
  , shieldPosture := KernelShieldPosture.defaultFailClosed
  , sentinelState :=
      { systemState := .Healthy
      , isLockedDown := false
      , watchdogActive := true
      , lastSequence := 0
      , lastUptimeMs := 0 }
  , winPolicy :=
      { requireAppcontainer := true
      , createSuspendedBeforeJobAssign := true
      , killOnJobClose := true
      , activeProcessLimit := 1
      , maxMemoryBytes := 256 * 1024 * 1024
      , enforceUiLimits := true } }

example : SystemInitialValid witnessInitSys := by
  refine ⟨rfl, rfl, rfl, rfl, by decide, rfl, ?_, by decide, rfl, rfl, rfl, by decide⟩
  exact MandateReachable.root "m-sys-1" "spiffe://octopus/root" 1001 "spiffe://octopus/arm0" 2001
    [witnessSysUri] [] 100 500 true rfl

example : BreakoutFree witnessInitSys ∧ BreachFree witnessInitSys := by
  have hInit : SystemInitialValid witnessInitSys := by
    refine ⟨rfl, rfl, rfl, rfl, by decide, rfl, ?_, by decide, rfl, rfl, rfl, by decide⟩
    exact MandateReachable.root "m-sys-1" "spiffe://octopus/root" 1001 "spiffe://octopus/arm0" 2001
      [witnessSysUri] [] 100 500 true rfl
  exact ⟨(no_breakout witnessInitSys witnessInitSys hInit (SystemReachable.init)).1,
         (no_breach witnessInitSys witnessInitSys hInit (SystemReachable.init)).1⟩

end NonVacuityWitnesses

end AgentOctopusFormal
