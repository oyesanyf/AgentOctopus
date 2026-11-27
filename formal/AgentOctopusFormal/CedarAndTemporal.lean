import AgentOctopusFormal.CoreTypes
import AgentOctopusFormal.FsmContainment

namespace AgentOctopusFormal

/-! # Cedar PARC & Dogwood Past-Only MFOTL Formalization

Faithfully mirrors:
- `src/security/cedar_arm/policy_schema.rs` (11 entity types, 13 actions)
- `src/security/cedar_arm/policy_engine.rs` (`DEFAULT_OCTOPUS_POLICIES`, `forbid`-dominates-`permit`, `add_tighten_only_forbid_policy`)
- `src/containment_ring/cedar_gate.rs` (18 `ArmRole` principal mappings, `$100,000` ceiling, zero-trust sink isolation, principal spoof check, Dogwood + trace-proof fail-closed gating)
- `src/containment_ring/trusted_controller.rs` (`CedarAuthorizer::authorize` fail-closed unmapped role check)
- `src/security/cedar_arm/temporal/` (Dogwood past-only MFOTL: `Formerly`, `Previous`, `Since`, `unless`)
-/

/-! ### Constants (`policy_schema.rs`, `cedar_gate.rs`) -/

def CEDAR_MAX_SPEND_CENTS : Nat := DEFAULT_MAX_AMOUNT_CENTS -- 10_000_000 ($100,000)
def CEDAR_ENTITY_TYPE_COUNT : Nat := 11
def CEDAR_ACTION_COUNT : Nat := 13

def CEDAR_ENTITY_TYPE_NAMES : List String :=
  [ "Agent"
  , "Document"
  , "Ledger"
  , "NetworkTarget"
  , "SystemPolicy"
  , "DecoyTrap"
  , "KernelSubstrate"
  , "Command"
  , "FilePath"
  , "Tool"
  , "Host"
  ]

def CEDAR_ACTION_NAMES : List String :=
  [ "extract"
  , "write"
  , "egress"
  , "notify"
  , "change_security_policy"
  , "quarantine"
  , "kernel_enforce"
  , "evaluate"
  , "inbound_perimeter"
  , "exec"
  , "fs_read"
  , "fs_write"
  , "tool_call"
  ]

theorem cedar_entity_type_names_length :
    CEDAR_ENTITY_TYPE_NAMES.length = CEDAR_ENTITY_TYPE_COUNT := rfl

theorem cedar_action_names_length :
    CEDAR_ACTION_NAMES.length = CEDAR_ACTION_COUNT := rfl

/-! ### 11-Entity / 13-Action Cedar PARC Schema (`policy_schema.rs:12-323`) -/

inductive CedarEntityType : Type where
  | Agent
  | Document
  | Ledger
  | NetworkTarget
  | SystemPolicy
  | DecoyTrap
  | KernelSubstrate
  | Command
  | FilePath
  | Tool
  | Host
  deriving DecidableEq, Repr, BEq

instance : LawfulBEq CedarEntityType where
  eq_of_beq {a b} h := by cases a <;> cases b <;> first | rfl | cases h
  rfl {a} := by cases a <;> rfl

namespace CedarEntityType

def all : List CedarEntityType :=
  [ .Agent
  , .Document
  , .Ledger
  , .NetworkTarget
  , .SystemPolicy
  , .DecoyTrap
  , .KernelSubstrate
  , .Command
  , .FilePath
  , .Tool
  , .Host
  ]

theorem all_length : all.length = CEDAR_ENTITY_TYPE_COUNT := rfl

theorem all_complete (e : CedarEntityType) : e ∈ all := by
  cases e <;> simp [all]

end CedarEntityType

inductive CedarAction : Type where
  | extract
  | write
  | egress
  | notify
  | changeSecurityPolicy
  | quarantine
  | kernelEnforce
  | evaluate
  | inboundPerimeter
  | exec
  | fsRead
  | fsWrite
  | toolCall
  deriving DecidableEq, Repr, BEq

instance : LawfulBEq CedarAction where
  eq_of_beq {a b} h := by cases a <;> cases b <;> first | rfl | cases h
  rfl {a} := by cases a <;> rfl

namespace CedarAction

def all : List CedarAction :=
  [ .extract
  , .write
  , .egress
  , .notify
  , .changeSecurityPolicy
  , .quarantine
  , .kernelEnforce
  , .evaluate
  , .inboundPerimeter
  , .exec
  , .fsRead
  , .fsWrite
  , .toolCall
  ]

theorem all_length : all.length = CEDAR_ACTION_COUNT := rfl

theorem all_complete (a : CedarAction) : a ∈ all := by
  cases a <;> simp [all]

end CedarAction

/-- Exact `appliesTo.resourceTypes` mapping from `OCTOPUS_CEDAR_SCHEMA_JSON` (`policy_schema.rs:112-320`). -/
def actionAllowedResourceTypes : CedarAction → List CedarEntityType
  | .extract => [.Document]
  | .write => [.Ledger]
  | .egress => [.NetworkTarget, .Host]
  | .notify => [.Agent]
  | .changeSecurityPolicy => [.SystemPolicy]
  | .quarantine => [.DecoyTrap]
  | .kernelEnforce => [.KernelSubstrate]
  | .evaluate => [.NetworkTarget]
  | .inboundPerimeter => [.Host, .NetworkTarget]
  | .exec => [.Command]
  | .fsRead => [.FilePath, .Document]
  | .fsWrite => [.FilePath, .Ledger]
  | .toolCall => [.Tool]

/-! ### 18 `ArmRole` Principal Mapping, Unmapped Role Lookup & Principal Spoofing -/

inductive PrincipalId : Type where
  | reserved (role : ArmRole)
  | rogueAdversary
  | agent (id : String)
  deriving DecidableEq, Repr, BEq

/-- Exhaustive 18-variant `ArmRole` -> Cedar principal ID mapping (`cedar_gate.rs:408-427`). -/
def roleToPrincipalName : ArmRole → String
  | .UntrustedDocIngest => "document_arm"
  | .AccountingLedgerWrite => "ledger_arm"
  | .NetworkEgress => "network_arm"
  | .TarpitDecoyDefense => "tarpit_arm"
  | .KernelLevelSentinel => "kernel_sentinel_arm"
  | .OutboundNotification => "notifier_arm"
  | .CedarPolicyEvaluation => "cedar_arm"
  | .AtlasThreatIntelligence => "atlas_arm"
  | .AnomalyDetection => "anomaly_arm"
  | .VulnerabilityResearch => "vulnerability_arm"
  | .ContinuousOssFuzz => "oss_fuzz_arm"
  | .ContinuousOsvScanner => "osv_scanner_arm"
  | .DifferentialProtocolAnalyzer => "protocol_analyzer_arm"
  | .AutonomousProtocolResearch => "protocol_research_arm"
  | .PostQuantumAttestation => "pqc_arm"
  | .EvolutionaryOptimizer => "evolution_arm"
  | .DreamRsiOptimizer => "dream_rsi_arm"
  | .RecursiveHarnessOptimizer => "harness2_arm"

theorem roleToPrincipalName_total (r : ArmRole) : ∃ s : String, roleToPrincipalName r = s :=
  ⟨roleToPrincipalName r, rfl⟩

/-- Exact `role_str` lookup matching `CedarAuthorizer::authorize` (`trusted_controller.rs:302-350`),
    returning `none` (fail-closed) on any unmapped or unknown role string. -/
def parseArmRole (roleStr : String) : Option ArmRole :=
  match roleStr with
  | "ingest" | "doc_extractor" | "UntrustedDocIngest" | "DocumentRead" => some .UntrustedDocIngest
  | "ledger" | "ledger_writer" | "AccountingLedgerWrite" | "LedgerWrite" => some .AccountingLedgerWrite
  | "egress" | "http_egress" | "NetworkEgress" | "HttpEgress" => some .NetworkEgress
  | "tarpit" | "TarpitDecoyDefense" => some .TarpitDecoyDefense
  | "sentinel" | "kernel" | "KernelLevelSentinel" => some .KernelLevelSentinel
  | "notifier" | "OutboundNotification" => some .OutboundNotification
  | "cedar" | "CedarPolicyEvaluation" => some .CedarPolicyEvaluation
  | "atlas" | "AtlasThreatIntelligence" => some .AtlasThreatIntelligence
  | "anomaly" | "AnomalyDetection" => some .AnomalyDetection
  | "vulnerability" | "VulnerabilityResearch" => some .VulnerabilityResearch
  | "oss_fuzz" | "ContinuousOssFuzz" => some .ContinuousOssFuzz
  | "osv_scanner" | "ContinuousOsvScanner" => some .ContinuousOsvScanner
  | "differential" | "DifferentialProtocolAnalyzer" => some .DifferentialProtocolAnalyzer
  | "protocol_research" | "AutonomousProtocolResearch" => some .AutonomousProtocolResearch
  | "pqc" | "PostQuantumAttestation" => some .PostQuantumAttestation
  | "evolution" | "EvolutionaryOptimizer" => some .EvolutionaryOptimizer
  | "dream_rsi" | "DreamRsiOptimizer" => some .DreamRsiOptimizer
  | "harness2" | "RecursiveHarnessOptimizer" => some .RecursiveHarnessOptimizer
  | _ => none

/-! ### Cedar PARC Request, Policy, Evaluation & Tighten-Only Mutation -/

inductive CedarEffect : Type where
  | Permit
  | Forbid
  deriving DecidableEq, Repr, BEq

instance : LawfulBEq CedarEffect where
  eq_of_beq {a b} h := by cases a <;> cases b <;> first | rfl | cases h
  rfl {a} := by cases a <;> rfl

structure CedarContext where
  amountCents : Option Nat := none
  approved : Bool := false
  destinationDomain : String := ""
  destinationHost : String := ""
  quorumAuthorized : Bool := false
  deriving DecidableEq, Repr

structure CedarRequest where
  principal : PrincipalId
  action : CedarAction
  resourceType : CedarEntityType
  resourceId : String := ""
  context : CedarContext := {}
  deriving DecidableEq, Repr

structure CedarPolicy where
  id : String
  effect : CedarEffect
  schemaValid : Bool := true
  matchesRequest : CedarRequest → Bool

def isSchemaValidRequest (req : CedarRequest) : Bool :=
  (actionAllowedResourceTypes req.action).contains req.resourceType

/-- Models `Authorizer::is_authorized` (`policy_engine.rs:194-276`):
    schema-validated PARC evaluation where `Decision::Allow` requires at least one matching
    `Permit` policy and zero matching `Forbid` policies. -/
def evalPolicySet (ps : List CedarPolicy) (req : CedarRequest) : Bool :=
  isSchemaValidRequest req &&
  ps.any (fun p => p.effect == .Permit && p.matchesRequest req) &&
  !(ps.any (fun p => p.effect == .Forbid && p.matchesRequest req))

/-- Exact formalization of `DEFAULT_OCTOPUS_POLICIES` (`policy_engine.rs:24-91`). -/
def defaultOctopusPolicies : List CedarPolicy :=
  [ { id := "policy_1_document_extract"
    , effect := .Permit
    , schemaValid := true
    , matchesRequest := fun req =>
        decide (req.principal = .reserved .UntrustedDocIngest) &&
        (req.action == .extract) &&
        (req.resourceType == .Document) }
  , { id := "policy_2_ledger_write"
    , effect := .Permit
    , schemaValid := true
    , matchesRequest := fun req =>
        decide (req.principal = .reserved .AccountingLedgerWrite) &&
        (req.action == .write) &&
        (req.resourceType == .Ledger) &&
        (match req.context.amountCents with
         | some amt => decide (amt ≤ CEDAR_MAX_SPEND_CENTS)
         | none => false) &&
        req.context.approved }
  , { id := "policy_3_network_egress"
    , effect := .Permit
    , schemaValid := true
    , matchesRequest := fun req =>
        decide (req.principal = .reserved .NetworkEgress) &&
        (req.action == .egress) &&
        (req.resourceType == .NetworkTarget) &&
        (decide (req.context.destinationDomain = "google.com") ||
         decide (req.context.destinationDomain = "www.google.com")) }
  , { id := "policy_4_quorum_policy_guard"
    , effect := .Forbid
    , schemaValid := true
    , matchesRequest := fun req =>
        (req.action == .changeSecurityPolicy) &&
        (req.resourceType == .SystemPolicy) &&
        !req.context.quorumAuthorized }
  , { id := "policy_5_tarpit_quarantine"
    , effect := .Permit
    , schemaValid := true
    , matchesRequest := fun req =>
        decide (req.principal = .reserved .TarpitDecoyDefense) &&
        (req.action == .quarantine) &&
        (req.resourceType == .DecoyTrap) }
  , { id := "policy_6_kernel_sentinel"
    , effect := .Permit
    , schemaValid := true
    , matchesRequest := fun req =>
        decide (req.principal = .reserved .KernelLevelSentinel) &&
        (req.action == .kernelEnforce) &&
        (req.resourceType == .KernelSubstrate) }
  , { id := "ALL"
    , effect := .Forbid
    , schemaValid := true
    , matchesRequest := fun req =>
        decide (req.principal = .rogueAdversary) }
  , { id := "policy_8_protocol_research"
    , effect := .Permit
    , schemaValid := true
    , matchesRequest := fun req =>
        decide (req.principal = .reserved .AutonomousProtocolResearch) &&
        (req.action == .evaluate) &&
        (req.resourceType == .NetworkTarget) &&
        (decide (req.context.destinationHost = "127.0.0.1") ||
         decide (req.context.destinationHost = "localhost") ||
         decide (req.context.destinationHost = "::1") ||
         decide (req.context.destinationHost = "[::1]")) }
  ]

/-- Models `CedarPolicyEngine::add_tighten_only_forbid_policy` (`policy_engine.rs:303-364`):
    only schema-valid `Forbid` policies with non-colliding IDs may be inserted; `Permit` policies,
    invalid schemas, and conflicting policy IDs are rejected (`none`). -/
def addTightenOnlyForbidPolicy (ps : List CedarPolicy) (p : CedarPolicy) :
    Option (List CedarPolicy) :=
  if p.effect == .Forbid && p.schemaValid then
    if ps.any (fun q => q.id == p.id) then
      none
    else
      some (p :: ps)
  else
    none

/-- Zero-trust sink isolation matrix (`cedar_gate.rs:310-351`). -/
def isSinkForbidden (role : ArmRole) (action : CedarAction) : Bool :=
  match role, action with
  | .UntrustedDocIngest, .write
  | .UntrustedDocIngest, .egress
  | .UntrustedDocIngest, .exec
  | .UntrustedDocIngest, .inboundPerimeter => true
  | .AccountingLedgerWrite, .egress
  | .AccountingLedgerWrite, .exec
  | .AccountingLedgerWrite, .inboundPerimeter
  | .AccountingLedgerWrite, .extract => true
  | .NetworkEgress, .write
  | .NetworkEgress, .exec
  | .NetworkEgress, .extract => true
  | _, _ => false

/-- Models `CedarGate::evaluate_authorization` (`cedar_gate.rs:285-548`) under active enforcement
    (`gateEnabled = true`; disabling requires out-of-band `NegativeControlToken`). -/
def evaluateCedarGate
    (gateEnabled : Bool) (ps : List CedarPolicy)
    (agentId : PrincipalId) (role : ArmRole)
    (action : CedarAction) (resourceType : CedarEntityType)
    (resourceId : String) (ctx : CedarContext) : Bool :=
  if !gateEnabled then false
  else
    let capOk := match ctx.amountCents with
      | some amt => decide (amt ≤ CEDAR_MAX_SPEND_CENTS)
      | none => true
    let spoofBlocked := match agentId with
      | .reserved claimed => !decide (claimed = role)
      | _ => false
    if !capOk || isSinkForbidden role action || spoofBlocked then false
    else
      let effPrincipal := match agentId with
        | .rogueAdversary => .rogueAdversary
        | _ => .reserved role
      evalPolicySet ps
        { principal := effPrincipal
        , action := action
        , resourceType := resourceType
        , resourceId := resourceId
        , context := ctx }

/-- Models `CedarAuthorizer::authorize` (`trusted_controller.rs:302-378`):
    unmapped `roleStr` fails closed (`false`) before reaching `CedarGate`. -/
def authorizeWithRoleStr
    (gateEnabled : Bool) (ps : List CedarPolicy)
    (agentId : PrincipalId) (roleStr : String)
    (action : CedarAction) (resourceType : CedarEntityType)
    (resourceId : String) (ctx : CedarContext) : Bool :=
  match parseArmRole roleStr with
  | none => false
  | some role =>
      evaluateCedarGate gateEnabled ps agentId role action resourceType resourceId ctx

/-! ### Supervisor Approval Receipt Binding (`authorization.rs:390-422, 572-590`) -/

structure SupervisorApprovalReceipt where
  authorizedSupervisor : PrincipalId
  requestingAgent : PrincipalId
  maxAmountCents : Nat
  signatureValid : Bool
  deriving DecidableEq, Repr

def verifySupervisorApproval
    (receipt : SupervisorApprovalReceipt)
    (caller : PrincipalId)
    (requestedAmountCents : Nat) : Bool :=
  receipt.signatureValid &&
  !decide (receipt.authorizedSupervisor = caller) &&
  decide (receipt.requestingAgent = caller) &&
  decide (requestedAmountCents ≤ receipt.maxAmountCents)

/-! ### Dogwood Past-Only MFOTL (`src/security/cedar_arm/temporal/`) -/

inductive TemporalEventKind : Type where
  | Request
  | Response
  | Attempt
  | Custom (name : String)
  deriving DecidableEq, Repr, BEq

structure TemporalEvent where
  id : Nat
  timestampSecs : Nat
  action : CedarAction
  kind : TemporalEventKind
  callerPrincipal : PrincipalId
  callerResource : String
  deriving DecidableEq, Repr

structure TemporalContext where
  currentTimeSecs : Nat
  principal : PrincipalId
  resource : String
  deriving DecidableEq, Repr

structure EventPredicate where
  action : CedarAction
  kind : TemporalEventKind
  matchPrincipal : Bool := true
  matchResource : Bool := false
  deriving DecidableEq, Repr

/-- Strictly past-only MFOTL AST (`temporal/types.rs:123-165`). -/
inductive TemporalExpr : Type where
  | predicate (pred : EventPredicate)
  | and (a b : TemporalExpr)
  | not (sub : TemporalExpr)
  | formerly (windowSecs : Nat) (body : TemporalExpr)
  | previous (windowSecs : Nat) (body : TemporalExpr)
  | since (left : TemporalExpr) (windowSecs : Nat) (right : TemporalExpr)
  deriving DecidableEq, Repr

inductive TemporalClauseStatus : Type where
  | parsed (isUnless : Bool) (expr : TemporalExpr)
  | parseError
  deriving DecidableEq, Repr

structure TemporalTrace where
  events : List TemporalEvent
  airVerified : Bool
  deriving DecidableEq, Repr

def eventsMonotonicAux (prevTime : Nat) : List TemporalEvent → Bool
  | [] => true
  | ev :: rest => decide (prevTime ≤ ev.timestampSecs) && eventsMonotonicAux ev.timestampSecs rest

/-- Trace integrity invariant (`temporal/event_trace.rs` + `VanishingPolynomialTraceVerifier`):
    execution trace proof verified, non-decreasing timestamps, and no future-dated events. -/
def traceWellFormed (trace : TemporalTrace) (nowSecs : Nat) : Bool :=
  trace.airVerified &&
  (match trace.events with
   | [] => true
   | e0 :: rest => eventsMonotonicAux e0.timestampSecs rest) &&
  trace.events.all (fun ev => decide (ev.timestampSecs ≤ nowSecs))

def getEventAt? : List TemporalEvent → Nat → Option TemporalEvent
  | [], _ => none
  | e :: _, 0 => some e
  | _ :: es, n + 1 => getEventAt? es n

def getTimepointTime (events : List TemporalEvent) (nowSecs : Nat) (idx : Nat) : Nat :=
  match getEventAt? events idx with
  | some ev => ev.timestampSecs
  | none => nowSecs

def evalAnyPast (events : List TemporalEvent) (currTime wSecs : Nat) (f : Nat → Bool) : Nat → Bool
  | 0 => false
  | n + 1 =>
    let cond := match getEventAt? events n with
      | some ev =>
          decide (ev.timestampSecs ≤ currTime) &&
          decide (currTime - ev.timestampSecs ≤ wSecs) &&
          f n
      | none => false
    cond || evalAnyPast events currTime wSecs f n

def evalAllSpan (lo : Nat) (f : Nat → Bool) : Nat → Bool
  | 0 => true
  | rem + 1 => f lo && evalAllSpan (lo + 1) f rem

def evalSinceAux (events : List TemporalEvent) (currTime wSecs : Nat)
    (fLeft fRight : Nat → Bool) : Nat → Bool
  | 0 => false
  | n + 1 =>
    let cond := match getEventAt? events n with
      | some ev =>
          decide (ev.timestampSecs ≤ currTime) &&
          decide (currTime - ev.timestampSecs ≤ wSecs) &&
          fRight n &&
          evalAllSpan (n + 1) fLeft (events.length - (n + 1))
      | none => false
    cond || evalSinceAux events currTime wSecs fLeft fRight n

/-- Structurally recursive past-only MFOTL evaluator (`temporal/evaluator.rs:31-221`). -/
def evalTemporalExpr (events : List TemporalEvent) (nowSecs : Nat) (ctx : TemporalContext) :
    TemporalExpr → Nat → Bool
  | .predicate pred, currIdx =>
    match getEventAt? events currIdx with
    | none => false
    | some ev =>
      (ev.action == pred.action) &&
      (ev.kind == pred.kind) &&
      (!pred.matchPrincipal || decide (ev.callerPrincipal = ctx.principal)) &&
      (!pred.matchResource || decide (ev.callerResource = ctx.resource))
  | .and a b, currIdx =>
    evalTemporalExpr events nowSecs ctx a currIdx &&
    evalTemporalExpr events nowSecs ctx b currIdx
  | .not sub, currIdx =>
    !(evalTemporalExpr events nowSecs ctx sub currIdx)
  | .formerly w body, currIdx =>
    let currTime := getTimepointTime events nowSecs currIdx
    evalAnyPast events currTime w (evalTemporalExpr events nowSecs ctx body) events.length
  | .previous w body, currIdx =>
    match currIdx with
    | 0 => false
    | prevIdx + 1 =>
      match getEventAt? events prevIdx with
      | none => false
      | some ev =>
        let currTime := getTimepointTime events nowSecs currIdx
        decide (ev.timestampSecs ≤ currTime) &&
        decide (currTime - ev.timestampSecs ≤ w) &&
        evalTemporalExpr events nowSecs ctx body prevIdx
  | .since left w right, currIdx =>
    let currTime := getTimepointTime events nowSecs currIdx
    evalSinceAux events currTime w
      (evalTemporalExpr events nowSecs ctx left)
      (evalTemporalExpr events nowSecs ctx right)
      events.length

/-- Fail-closed Dogwood temporal policy gate (`temporal/mod.rs:51-68`, `cedar_gate.rs:482-530`). -/
def evalTemporalGate (clause : TemporalClauseStatus) (trace : TemporalTrace)
    (ctx : TemporalContext) : Bool :=
  if !traceWellFormed trace ctx.currentTimeSecs then false
  else
    match clause with
    | .parseError => false
    | .parsed isUnless expr =>
      let holds := evalTemporalExpr trace.events ctx.currentTimeSecs ctx expr trace.events.length
      if isUnless then !holds else holds

/-- Combined Cedar + Dogwood joint authorization gate (`cedar_gate.rs:285-548`). -/
def evaluateCedarAndTemporalGate
    (gateEnabled : Bool) (ps : List CedarPolicy)
    (agentId : PrincipalId) (role : ArmRole)
    (action : CedarAction) (resourceType : CedarEntityType)
    (resourceId : String) (ctx : CedarContext)
    (temporalClause : Option TemporalClauseStatus)
    (trace : TemporalTrace) (tCtx : TemporalContext) : Bool :=
  evaluateCedarGate gateEnabled ps agentId role action resourceType resourceId ctx &&
  match temporalClause with
  | none => true
  | some c => evalTemporalGate c trace tCtx

/-! ### Helper Lemmas -/

private theorem cedar_list_any_of_mem {α : Type} (p : α → Bool) :
    ∀ {xs : List α} {x : α}, x ∈ xs → p x = true → xs.any p = true
  | [], _, hx, _ => by cases hx
  | a :: as, x, hx, hpx => by
    rw [List.any_cons]
    cases hx with
    | head =>
      rw [hpx, Bool.true_or]
    | tail _ hmem =>
      have htail := cedar_list_any_of_mem p hmem hpx
      rw [htail, Bool.or_true]

/-! ### Required Theorems (6 Core Security Invariants + Companion Corollaries) -/

/-- **Theorem 1 (`forbid_dominates_permit`)**:
    In any Cedar policy set `ps`, if any `Forbid` policy `pForbid ∈ ps` matches `req`,
    `evalPolicySet ps req` MUST return `false`, regardless of how many `Permit` policies match. -/
theorem forbid_dominates_permit
    (ps : List CedarPolicy) (req : CedarRequest)
    (pForbid : CedarPolicy)
    (hMem : pForbid ∈ ps)
    (hEff : pForbid.effect = .Forbid)
    (hMatch : pForbid.matchesRequest req = true) :
    evalPolicySet ps req = false := by
  have hPred : (fun p => p.effect == .Forbid && p.matchesRequest req) pForbid = true := by
    simp [hEff, hMatch]
  have hAny : ps.any (fun p => p.effect == .Forbid && p.matchesRequest req) = true :=
    cedar_list_any_of_mem _ hMem hPred
  unfold evalPolicySet
  simp [hAny]

/-- **Theorem 2 (`tighten_only_monotonic`)**:
    `addTightenOnlyForbidPolicy` can only preserve or strengthen denials: any request denied under `ps`
    remains denied under `ps'`. -/
theorem tighten_only_monotonic
    (ps ps' : List CedarPolicy) (newPolicy : CedarPolicy) (req : CedarRequest)
    (hAdd : addTightenOnlyForbidPolicy ps newPolicy = some ps')
    (hDenied : evalPolicySet ps req = false) :
    evalPolicySet ps' req = false := by
  unfold addTightenOnlyForbidPolicy at hAdd
  by_cases hOk : (newPolicy.effect == .Forbid && newPolicy.schemaValid) = true
  · simp only [eq_true hOk, ite_true] at hAdd
    by_cases hId : ps.any (fun q => q.id == newPolicy.id) = true
    · simp only [eq_true hId, ite_true] at hAdd
      cases hAdd
    · simp only [eq_false hId, ite_false] at hAdd
      injection hAdd with hEq
      subst hEq
      rw [Bool.and_eq_true] at hOk
      have hForbid : newPolicy.effect = .Forbid := beq_iff_eq.mp hOk.1
      unfold evalPolicySet at hDenied ⊢
      have hPerm : (newPolicy :: ps).any (fun p => p.effect == .Permit && p.matchesRequest req) =
          ps.any (fun p => p.effect == .Permit && p.matchesRequest req) := by
        rw [List.any_cons]
        simp [hForbid]
      have hForb : (newPolicy :: ps).any (fun p => p.effect == .Forbid && p.matchesRequest req) =
          (newPolicy.matchesRequest req || ps.any (fun p => p.effect == .Forbid && p.matchesRequest req)) := by
        rw [List.any_cons]
        simp [hForbid]
      rw [hPerm, hForb]
      cases hSch : isSchemaValidRequest req
      · simp
      · cases hAnyP : ps.any (fun p => p.effect == .Permit && p.matchesRequest req)
        · simp
        · rw [hSch, hAnyP] at hDenied
          simp at hDenied
          simp [hDenied]
  · simp only [eq_false hOk, ite_false] at hAdd
    cases hAdd

theorem tighten_only_rejects_permit
    (ps : List CedarPolicy) (newPolicy : CedarPolicy)
    (hPermit : newPolicy.effect = .Permit) :
    addTightenOnlyForbidPolicy ps newPolicy = none := by
  unfold addTightenOnlyForbidPolicy
  simp [hPermit]

/-- **Theorem 3 (`default_deny_unmapped_role`)**:
    Unknown or unmapped `roleStr` values fail closed immediately at `CedarAuthorizer`. -/
theorem default_deny_unmapped_role
    (gateEnabled : Bool) (ps : List CedarPolicy)
    (agentId : PrincipalId) (roleStr : String)
    (action : CedarAction) (resourceType : CedarEntityType)
    (resourceId : String) (ctx : CedarContext)
    (hUnmapped : parseArmRole roleStr = none) :
    authorizeWithRoleStr gateEnabled ps agentId roleStr action resourceType resourceId ctx = false := by
  unfold authorizeWithRoleStr
  rw [hUnmapped]

theorem empty_policy_set_default_deny (req : CedarRequest) :
    evalPolicySet [] req = false := by
  simp [evalPolicySet]

/-- **Theorem 4 (`no_principal_spoofing`)**:
    An arm holding authenticated role `authRole` cannot spoof a different reserved role principal
    `claimedRole ≠ authRole`. -/
theorem no_principal_spoofing
    (gateEnabled : Bool) (ps : List CedarPolicy)
    (claimedRole authRole : ArmRole)
    (action : CedarAction) (resourceType : CedarEntityType)
    (resourceId : String) (ctx : CedarContext)
    (hMismatch : claimedRole ≠ authRole) :
    evaluateCedarGate gateEnabled ps (.reserved claimedRole) authRole action resourceType resourceId ctx = false := by
  unfold evaluateCedarGate
  by_cases hEn : gateEnabled = true
  · have hNotEn : (!gateEnabled) = false := by simp [hEn]
    simp only [hNotEn, Bool.false_eq_true, ite_false]
    have hSpoof : (!decide (claimedRole = authRole)) = true := by
      simp [decide_eq_false hMismatch]
    simp [hSpoof]
  · have hNotEn : (!gateEnabled) = true := by
      cases gateEnabled
      · rfl
      · exact absurd rfl hEn
    simp only [eq_true hNotEn, ite_true]

theorem rogue_adversary_blocked_by_default_policies
    (gateEnabled : Bool) (authRole : ArmRole)
    (action : CedarAction) (resourceType : CedarEntityType)
    (resourceId : String) (ctx : CedarContext) :
    evaluateCedarGate gateEnabled defaultOctopusPolicies .rogueAdversary authRole action resourceType resourceId ctx = false := by
  unfold evaluateCedarGate
  by_cases hEn : gateEnabled = true
  · have hNotEn : (!gateEnabled) = false := by simp [hEn]
    simp only [hNotEn, Bool.false_eq_true, ite_false]
    by_cases hEarly : (!(match ctx.amountCents with | some amt => decide (amt ≤ CEDAR_MAX_SPEND_CENTS) | none => true) ||
        isSinkForbidden authRole action || false) = true
    · simp only [eq_true hEarly, ite_true]
    · simp only [eq_false hEarly, ite_false]
      let rogueReq : CedarRequest :=
        { principal := .rogueAdversary
        , action := action
        , resourceType := resourceType
        , resourceId := resourceId
        , context := ctx }
      let pAll : CedarPolicy :=
        { id := "ALL"
        , effect := .Forbid
        , schemaValid := true
        , matchesRequest := fun req => decide (req.principal = .rogueAdversary) }
      have hMem : pAll ∈ defaultOctopusPolicies := by
        simp [defaultOctopusPolicies, pAll]
      exact forbid_dominates_permit defaultOctopusPolicies rogueReq pAll hMem rfl rfl
  · have hNotEn : (!gateEnabled) = true := by
      cases gateEnabled
      · rfl
      · exact absurd rfl hEn
    simp only [eq_true hNotEn, ite_true]

/-- **Theorem 5 (`spending_cap_enforced`)**:
    Any request whose `amountCents` exceeds `CEDAR_MAX_SPEND_CENTS` (`10_000_000` cents = `$100,000`)
    is unconditionally denied by `CedarGate`. -/
theorem spending_cap_enforced
    (gateEnabled : Bool) (ps : List CedarPolicy)
    (agentId : PrincipalId) (role : ArmRole)
    (action : CedarAction) (resourceType : CedarEntityType)
    (resourceId : String) (ctx : CedarContext) (amt : Nat)
    (hAmt : ctx.amountCents = some amt)
    (hOver : amt > CEDAR_MAX_SPEND_CENTS) :
    evaluateCedarGate gateEnabled ps agentId role action resourceType resourceId ctx = false := by
  unfold evaluateCedarGate
  by_cases hEn : gateEnabled = true
  · have hNotEn : (!gateEnabled) = false := by simp [hEn]
    simp only [hNotEn, Bool.false_eq_true, ite_false, hAmt]
    have hCapFalse : decide (amt ≤ CEDAR_MAX_SPEND_CENTS) = false :=
      decide_eq_false (Nat.not_le_of_gt hOver)
    simp [hCapFalse]
  · have hNotEn : (!gateEnabled) = true := by
      cases gateEnabled
      · rfl
      · exact absurd rfl hEn
    simp only [eq_true hNotEn, ite_true]

theorem default_policies_ledger_cap_enforced
    (req : CedarRequest) (amt : Nat)
    (hAct : req.action = .write)
    (hAmt : req.context.amountCents = some amt)
    (hOver : amt > CEDAR_MAX_SPEND_CENTS) :
    evalPolicySet defaultOctopusPolicies req = false := by
  unfold evalPolicySet defaultOctopusPolicies
  have hCapFalse : decide (amt ≤ CEDAR_MAX_SPEND_CENTS) = false :=
    decide_eq_false (Nat.not_le_of_gt hOver)
  simp [hAct, hAmt, hCapFalse]

theorem sink_isolation_enforced
    (gateEnabled : Bool) (ps : List CedarPolicy)
    (agentId : PrincipalId) (role : ArmRole)
    (action : CedarAction) (resourceType : CedarEntityType)
    (resourceId : String) (ctx : CedarContext)
    (hSink : isSinkForbidden role action = true) :
    evaluateCedarGate gateEnabled ps agentId role action resourceType resourceId ctx = false := by
  unfold evaluateCedarGate
  by_cases hEn : gateEnabled = true
  · have hNotEn : (!gateEnabled) = false := by simp [hEn]
    simp only [hNotEn, Bool.false_eq_true, ite_false, hSink]
    simp
  · have hNotEn : (!gateEnabled) = true := by
      cases gateEnabled
      · rfl
      · exact absurd rfl hEn
    simp only [eq_true hNotEn, ite_true]

theorem no_self_approval_or_overlimit
    (receipt : SupervisorApprovalReceipt) (caller : PrincipalId) (amt : Nat) :
    (receipt.authorizedSupervisor = caller → verifySupervisorApproval receipt caller amt = false) ∧
    (amt > receipt.maxAmountCents → verifySupervisorApproval receipt caller amt = false) ∧
    (receipt.signatureValid = false → verifySupervisorApproval receipt caller amt = false) := by
  refine ⟨?_, ?_, ?_⟩
  · intro hSelf
    unfold verifySupervisorApproval
    simp [hSelf]
  · intro hOver
    unfold verifySupervisorApproval
    have hFalse : decide (amt ≤ receipt.maxAmountCents) = false :=
      decide_eq_false (Nat.not_le_of_gt hOver)
    simp [hFalse]
  · intro hSig
    unfold verifySupervisorApproval
    simp [hSig]

/-- **Theorem 6 (`temporal_fail_closed`)**:
    Dogwood temporal policy evaluation is strictly fail-closed on parse/evaluation errors,
    unproven/non-AIR-verified traces, malformed/future-dated/non-monotonic traces,
    unsatisfied `when temporal` requirements, and violated `unless temporal` prohibitions. -/
theorem temporal_fail_closed
    (clause : TemporalClauseStatus) (trace : TemporalTrace) (tCtx : TemporalContext) :
    (clause = .parseError → evalTemporalGate clause trace tCtx = false) ∧
    (trace.airVerified = false → evalTemporalGate clause trace tCtx = false) ∧
    (traceWellFormed trace tCtx.currentTimeSecs = false → evalTemporalGate clause trace tCtx = false) ∧
    (∀ expr, clause = .parsed false expr →
      evalTemporalExpr trace.events tCtx.currentTimeSecs tCtx expr trace.events.length = false →
      evalTemporalGate clause trace tCtx = false) ∧
    (∀ expr, clause = .parsed true expr →
      evalTemporalExpr trace.events tCtx.currentTimeSecs tCtx expr trace.events.length = true →
      evalTemporalGate clause trace tCtx = false) := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro hErr
    subst hErr
    unfold evalTemporalGate
    cases traceWellFormed trace tCtx.currentTimeSecs <;> simp
  · intro hAir
    have hWf : traceWellFormed trace tCtx.currentTimeSecs = false := by
      unfold traceWellFormed
      simp [hAir]
    unfold evalTemporalGate
    simp [hWf]
  · intro hWf
    unfold evalTemporalGate
    simp [hWf]
  · intro expr hParsed hEval
    subst hParsed
    unfold evalTemporalGate
    cases hWf : traceWellFormed trace tCtx.currentTimeSecs
    · simp
    · simp [hEval]
  · intro expr hParsed hEval
    subst hParsed
    unfold evalTemporalGate
    cases hWf : traceWellFormed trace tCtx.currentTimeSecs
    · simp
    · simp [hEval]

theorem empty_trace_denies_past_prereqs
    (nowSecs : Nat) (ctx : TemporalContext) (w : Nat) (left body : TemporalExpr) :
    evalTemporalExpr [] nowSecs ctx (.formerly w body) 0 = false ∧
    evalTemporalExpr [] nowSecs ctx (.previous w body) 0 = false ∧
    evalTemporalExpr [] nowSecs ctx (.since left w body) 0 = false := by
  simp [evalTemporalExpr, evalAnyPast, evalSinceAux]

theorem joint_gate_temporal_fail_closed
    (gateEnabled : Bool) (ps : List CedarPolicy)
    (agentId : PrincipalId) (role : ArmRole)
    (action : CedarAction) (resourceType : CedarEntityType)
    (resourceId : String) (ctx : CedarContext)
    (clause : TemporalClauseStatus) (trace : TemporalTrace) (tCtx : TemporalContext)
    (hTemp : evalTemporalGate clause trace tCtx = false) :
    evaluateCedarAndTemporalGate gateEnabled ps agentId role action resourceType resourceId ctx
      (some clause) trace tCtx = false := by
  unfold evaluateCedarAndTemporalGate
  simp [hTemp]

/-! ### Non-Vacuity Witnesses (`rfl` / `decide`) -/

section NonVacuityWitnesses

private def witnessValidLedgerReq : CedarRequest :=
  { principal := .reserved .AccountingLedgerWrite
  , action := .write
  , resourceType := .Ledger
  , resourceId := "acct_001"
  , context := { amountCents := some 500_000, approved := true } }

private def witnessForbidAcct001 : CedarPolicy :=
  { id := "forbid_acct_001"
  , effect := .Forbid
  , schemaValid := true
  , matchesRequest := fun req => decide (req.resourceId = "acct_001") }

-- Witness 1: Valid request is allowed under baseline policies...
example : evalPolicySet defaultOctopusPolicies witnessValidLedgerReq = true := by
  rfl

-- ...and denied once a matching Forbid policy is added via tighten-only insertion.
example :
    ∃ ps', addTightenOnlyForbidPolicy defaultOctopusPolicies witnessForbidAcct001 = some ps' ∧
      evalPolicySet ps' witnessValidLedgerReq = false := by
  refine ⟨witnessForbidAcct001 :: defaultOctopusPolicies, rfl, ?_⟩
  rfl

-- ...and colliding Forbid policy IDs are rejected rather than silently dropped.
example :
    addTightenOnlyForbidPolicy defaultOctopusPolicies { witnessForbidAcct001 with id := "ALL" } = none := by
  rfl

-- Witness 2: Unmapped role string denied.
example :
    authorizeWithRoleStr true defaultOctopusPolicies (.agent "attacker")
      "unmapped_attacker_role" .write .Ledger "acct_001"
      { amountCents := some 100, approved := true } = false := by
  rfl

-- Witness 3: Principal spoofing denied (`UntrustedDocIngest` claiming `AccountingLedgerWrite`).
example :
    evaluateCedarGate true defaultOctopusPolicies (.reserved .AccountingLedgerWrite)
      .UntrustedDocIngest .extract .Document "doc_1" {} = false := by
  rfl

-- Witness 4: Over-cap ($100,000.01 = 10_000_001 cents) denied.
example :
    evaluateCedarGate true defaultOctopusPolicies (.reserved .AccountingLedgerWrite)
      .AccountingLedgerWrite .write .Ledger "acct_001"
      { amountCents := some 10_000_001, approved := true } = false := by
  rfl

-- Witness 5: Dogwood `formerly` allows when prior valid event exists, and fails closed when trace unproven.
private def witnessTrace : TemporalTrace :=
  { events :=
      [ { id := 1
        , timestampSecs := 100
        , action := .fsRead
        , kind := .Response
        , callerPrincipal := .reserved .AccountingLedgerWrite
        , callerResource := "invoice_42" } ]
  , airVerified := true }

private def witnessTemporalCtx : TemporalContext :=
  { currentTimeSecs := 130
  , principal := .reserved .AccountingLedgerWrite
  , resource := "invoice_42" }

private def witnessFormerlyClause : TemporalClauseStatus :=
  .parsed false (.formerly 60 (.predicate { action := .fsRead, kind := .Response }))

example : evalTemporalGate witnessFormerlyClause witnessTrace witnessTemporalCtx = true := by
  rfl

example :
    evalTemporalGate witnessFormerlyClause { witnessTrace with airVerified := false } witnessTemporalCtx = false := by
  rfl

end NonVacuityWitnesses

end AgentOctopusFormal
