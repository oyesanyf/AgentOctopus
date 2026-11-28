import AgentOctopusFormal.CoreTypes

namespace AgentOctopusFormal

/-!
# Milestone M4: Isolation, Perimeter Confinement, Shield Latch & Ring 4 Sentinel

Faithfully formalizes 1-to-1 with:
- `src/security/breakouts/mod.rs` (`validate_sandbox_relative_path`, `open_confined`, `BreakoutDefenseCoordinator`)
- `src/containment_ring/egress_proxy.rs` (`is_restricted_rebinding_ip`, `validate_agent_egress_url`, `resolve_and_pin`)
- `src/security/token_posture.rs` & `src/security/windows_sandbox.rs` (`INTEGRITY_MEDIUM = 0x2000`, `DANGEROUS_PRIVILEGES`, `TokenPosture::verify_agent_safe`, `WindowsConfinementPolicy`, `evaluate_pre_resume_confinement_gate`, pre-resume `TerminateProcess`)
- `src/security/virtual_patch_shield.rs` (`KernelAttackSurface`, `KernelShieldPosture`, `finalize`, `VirtualPatchShieldStore::{apply_posture, confirm_reboot_cleared}`)
- `src/containment_ring/sentinel.rs`, `src/sentinel_ring/sentinel_supervisor.rs`, `src/containment_ring/arm_ring.rs` (`SentinelSystemState`, `SentinelAction`, `evaluate`, `SentinelSupervisor`, `SEC-RING-01` `verify_terminable_child_pid`)
-/

/-! ### Part 1: Path Validation & Confined Open (`src/security/breakouts/mod.rs`) -/

def strContainsChar (s : String) (c : Char) : Bool :=
  s.toList.any (fun ch => ch == c)

inductive PerimeterPathError : Type where
  | EmptyPath
  | ReplacementBlocked
  | TraversalBlocked
  | ComponentBlocked
  | NonRelativeComponent
  | EmptyComponents
  | ReparsePointDetected
  | NotDirectory
  | UnexpectedDirectory
  | HardlinkBlocked
  | EscapeOutsideSandbox
  deriving DecidableEq, Repr, BEq

inductive PathComponent : Type where
  | curDir
  | parentDir
  | rootDir
  | prefix (drive : String)
  | normal (name : String)
  deriving DecidableEq, Repr, BEq

structure SandboxPathInput where
  rawTrimmed : String
  components : List PathComponent
  hasNull : Bool
  hasColon : Bool
  startsWithSlashOrBackslash : Bool
  hasPercentTraversal : Bool
  hasDotDot : Bool
  deriving DecidableEq, Repr

def extractSafeNormalComponents : List PathComponent → Except PerimeterPathError (List String)
  | [] => .ok []
  | .curDir :: rest => extractSafeNormalComponents rest
  | .parentDir :: _ => .error .NonRelativeComponent
  | .rootDir :: _ => .error .NonRelativeComponent
  | .prefix _ :: _ => .error .NonRelativeComponent
  | .normal s :: rest =>
    if strContainsChar s ':' || s == ".." then
      .error .ComponentBlocked
    else
      match extractSafeNormalComponents rest with
      | .error e => .error e
      | .ok tail => .ok (s :: tail)

/-- Mirror of `validate_sandbox_relative_path` (`src/security/breakouts/mod.rs:308-369`). -/
def validateSandboxRelativePath (inp : SandboxPathInput) : Except PerimeterPathError (List String) :=
  if inp.rawTrimmed.isEmpty then
    .error .EmptyPath
  else if inp.hasNull || inp.hasColon || inp.startsWithSlashOrBackslash then
    .error .ReplacementBlocked
  else if inp.hasPercentTraversal || inp.hasDotDot then
    .error .TraversalBlocked
  else
    extractSafeNormalComponents inp.components

structure ConfinedHandleNode where
  name : String
  isReparsePoint : Bool
  isDir : Bool
  numLinks : Nat
  finalPathSegments : List String
  deriving DecidableEq, Repr

/-- Mirror of `is_strictly_inside_or_equal` (`mod.rs:779-788`). -/
def isStrictlyInsideOrEqual (rootSegs candSegs : List String) : Bool :=
  decide (rootSegs.length ≤ candSegs.length) && (candSegs.take rootSegs.length == rootSegs)

/-- Strict descendant check (`is_strictly_inside_or_equal && cand != root`, `mod.rs:925-926`). -/
def isStrictlyInside (rootSegs candSegs : List String) : Bool :=
  decide (rootSegs.length < candSegs.length) && (candSegs.take rootSegs.length == rootSegs)

def verifyIntermediateDir (rootSegs : List String) (d : ConfinedHandleNode) : Bool :=
  !d.isReparsePoint &&
  d.isDir &&
  !d.name.isEmpty &&
  d.name != "." &&
  d.name != ".." &&
  isStrictlyInsideOrEqual rootSegs d.finalPathSegments

/-- Mirror of handle-relative `open_confined` (`src/security/breakouts/mod.rs:477-947`). -/
def openConfined
    (sandboxRoot : ConfinedHandleNode)
    (inp : SandboxPathInput)
    (dirs : List ConfinedHandleNode)
    (leaf : ConfinedHandleNode) : Except PerimeterPathError ConfinedHandleNode :=
  match validateSandboxRelativePath inp with
  | .error e => .error e
  | .ok normalComps =>
    if sandboxRoot.isReparsePoint then
      .error .ReparsePointDetected
    else if !sandboxRoot.isDir then
      .error .NotDirectory
    else if normalComps.isEmpty then
      .error .EmptyComponents
    else if !(dirs.all (verifyIntermediateDir sandboxRoot.finalPathSegments)) then
      .error .EscapeOutsideSandbox
    else if leaf.isReparsePoint then
      .error .ReparsePointDetected
    else if leaf.isDir then
      .error .UnexpectedDirectory
    else if leaf.numLinks > 1 then
      .error .HardlinkBlocked
    else if !isStrictlyInside sandboxRoot.finalPathSegments leaf.finalPathSegments then
      .error .EscapeOutsideSandbox
    else
      .ok leaf

private theorem perim_list_all_eq_true {α : Type} (p : α → Bool) :
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
      | tail _ hmem => exact perim_list_all_eq_true p as h x hmem

private theorem extractSafeNormalComponents_safe :
    ∀ (cs : List PathComponent) (out : List String),
      extractSafeNormalComponents cs = .ok out →
      ∀ c ∈ cs,
        c ≠ .parentDir ∧
        c ≠ .rootDir ∧
        (∀ d, c ≠ .prefix d) ∧
        (∀ s, c = .normal s → s ≠ ".." ∧ strContainsChar s ':' = false)
  | [], out, _, c, hc => by cases hc
  | .curDir :: rest, out, hOk, c, hc => by
    cases hc with
    | head =>
      refine ⟨(by intro h; cases h), (by intro h; cases h), ?_, ?_⟩
      · intro _ h; cases h
      · intro _ h; cases h
    | tail _ hm => exact extractSafeNormalComponents_safe rest out hOk c hm
  | .parentDir :: _, _, hOk, _, _ => by cases hOk
  | .rootDir :: _, _, hOk, _, _ => by cases hOk
  | .prefix _ :: _, _, hOk, _, _ => by cases hOk
  | .normal s :: rest, out, hOk, c, hc => by
    unfold extractSafeNormalComponents at hOk
    by_cases hBad : (strContainsChar s ':' || s == "..") = true
    · simp only [eq_true hBad, ite_true] at hOk; cases hOk
    · simp only [eq_false hBad, ite_false] at hOk
      cases hRec : extractSafeNormalComponents rest with
      | error e => rw [hRec] at hOk; cases hOk
      | ok tail =>
        have hBadF : (strContainsChar s ':' || s == "..") = false := by
          cases hb : (strContainsChar s ':' || s == "..")
          · rfl
          · exact False.elim (hBad hb)
        rw [Bool.or_eq_false_iff] at hBadF
        have hNoColon : strContainsChar s ':' = false := hBadF.1
        have hNeDotDot : s ≠ ".." := by
          intro hEq
          subst hEq
          simp at hBadF
        cases hc with
        | head =>
          refine ⟨(by intro h; cases h), (by intro h; cases h), (fun _ h => by cases h), ?_⟩
          intro s' hs'
          injection hs' with hEq
          subst hEq
          exact ⟨hNeDotDot, hNoColon⟩
        | tail _ hm =>
          exact extractSafeNormalComponents_safe rest tail hRec c hm

theorem isStrictlyInside_implies_ne {rootSegs candSegs : List String}
    (h : isStrictlyInside rootSegs candSegs = true) :
    candSegs ≠ rootSegs := by
  unfold isStrictlyInside at h
  rw [Bool.and_eq_true, decide_eq_true_eq] at h
  intro hEq
  rw [hEq] at h
  exact Nat.lt_irrefl _ h.1

/-- **Theorem 1 (`path_join_no_escape`)**:
    Any path and handle chain accepted by `openConfined` passes lexical validation (non-empty,
    no NUL, no colon/drive/NTFS ADS, no leading slash/backslash, no `%2e`/`%2f`/`%5c`/`%00`/`..`,
    no `ParentDir`/`RootDir`/`Prefix`), uses at least one normal component, traverses no reparse
    points or non-directory intermediates, rejects hardlinks (`numLinks ≤ 1`), and resolves
    strictly inside `sandboxRoot.finalPathSegments` (never escaping and never equal to root). -/
theorem path_join_no_escape
    (sandboxRoot : ConfinedHandleNode)
    (inp : SandboxPathInput)
    (dirs : List ConfinedHandleNode)
    (leaf opened : ConfinedHandleNode)
    (hOpen : openConfined sandboxRoot inp dirs leaf = .ok opened) :
    opened = leaf ∧
    inp.rawTrimmed.isEmpty = false ∧
    inp.hasNull = false ∧
    inp.hasColon = false ∧
    inp.startsWithSlashOrBackslash = false ∧
    inp.hasPercentTraversal = false ∧
    inp.hasDotDot = false ∧
    (∀ c ∈ inp.components,
      c ≠ .parentDir ∧
      c ≠ .rootDir ∧
      (∀ d, c ≠ .prefix d) ∧
      (∀ s, c = .normal s → s ≠ ".." ∧ strContainsChar s ':' = false)) ∧
    (∃ normalComps, validateSandboxRelativePath inp = .ok normalComps ∧ normalComps ≠ []) ∧
    sandboxRoot.isReparsePoint = false ∧
    sandboxRoot.isDir = true ∧
    (∀ d ∈ dirs,
      d.isReparsePoint = false ∧
      d.isDir = true ∧
      isStrictlyInsideOrEqual sandboxRoot.finalPathSegments d.finalPathSegments = true) ∧
    opened.isReparsePoint = false ∧
    opened.isDir = false ∧
    opened.numLinks ≤ 1 ∧
    isStrictlyInside sandboxRoot.finalPathSegments opened.finalPathSegments = true ∧
    opened.finalPathSegments ≠ sandboxRoot.finalPathSegments := by
  unfold openConfined at hOpen
  have hValCopy : ∃ nc, validateSandboxRelativePath inp = .ok nc ∧ nc ≠ [] := by
    cases hV : validateSandboxRelativePath inp with
    | error e => rw [hV] at hOpen; cases hOpen
    | ok nc =>
      rw [hV] at hOpen
      dsimp only at hOpen
      by_cases h1 : sandboxRoot.isReparsePoint = true
      · simp only [eq_true h1, ite_true] at hOpen; cases hOpen
      · simp only [eq_false h1, ite_false] at hOpen
        by_cases h2 : (!sandboxRoot.isDir) = true
        · simp only [eq_true h2, ite_true] at hOpen; cases hOpen
        · simp only [eq_false h2, ite_false] at hOpen
          by_cases h3 : nc.isEmpty = true
          · simp only [eq_true h3, ite_true] at hOpen; cases hOpen
          · refine ⟨nc, rfl, ?_⟩
            intro hNil; rw [hNil] at h3; simp at h3
  obtain ⟨normalComps, hVal, hCompsNe⟩ := hValCopy
  rw [hVal] at hOpen
  dsimp only at hOpen
  by_cases hRootRep : sandboxRoot.isReparsePoint = true
  · simp only [eq_true hRootRep, ite_true] at hOpen; cases hOpen
  · simp only [eq_false hRootRep, ite_false] at hOpen
    have hRootRepF : sandboxRoot.isReparsePoint = false := by
      cases hb : sandboxRoot.isReparsePoint
      · rfl
      · exact False.elim (hRootRep hb)
    by_cases hRootNotDir : (!sandboxRoot.isDir) = true
    · simp only [eq_true hRootNotDir, ite_true] at hOpen; cases hOpen
    · simp only [eq_false hRootNotDir, ite_false] at hOpen
      have hRootDirT : sandboxRoot.isDir = true := by
        cases hb : sandboxRoot.isDir
        · simp [hb] at hRootNotDir
        · rfl
      have hEmptyF : normalComps.isEmpty = false := by
        cases normalComps with
        | nil => exact absurd rfl hCompsNe
        | cons _ _ => rfl
      simp only [hEmptyF, Bool.false_eq_true, ite_false] at hOpen
      by_cases hDirsBad : (!(dirs.all (verifyIntermediateDir sandboxRoot.finalPathSegments))) = true
      · simp only [eq_true hDirsBad, ite_true] at hOpen; cases hOpen
      · simp only [eq_false hDirsBad, ite_false] at hOpen
        have hDirsAll : dirs.all (verifyIntermediateDir sandboxRoot.finalPathSegments) = true := by
          cases hb : dirs.all (verifyIntermediateDir sandboxRoot.finalPathSegments)
          · simp [hb] at hDirsBad
          · rfl
        by_cases hLeafRep : leaf.isReparsePoint = true
        · simp only [eq_true hLeafRep, ite_true] at hOpen; cases hOpen
        · simp only [eq_false hLeafRep, ite_false] at hOpen
          have hLeafRepF : leaf.isReparsePoint = false := by
            cases hb : leaf.isReparsePoint
            · rfl
            · exact False.elim (hLeafRep hb)
          by_cases hLeafDir : leaf.isDir = true
          · simp only [eq_true hLeafDir, ite_true] at hOpen; cases hOpen
          · simp only [eq_false hLeafDir, ite_false] at hOpen
            have hLeafDirF : leaf.isDir = false := by
              cases hb : leaf.isDir
              · rfl
              · exact False.elim (hLeafDir hb)
            by_cases hLinks : leaf.numLinks > 1
            · simp only [eq_true hLinks, ite_true] at hOpen; cases hOpen
            · simp only [eq_false hLinks, ite_false] at hOpen
              have hLinksLe : leaf.numLinks ≤ 1 := Nat.le_of_not_lt hLinks
              by_cases hOut : (!isStrictlyInside sandboxRoot.finalPathSegments leaf.finalPathSegments) = true
              · simp only [eq_true hOut, ite_true] at hOpen; cases hOpen
              · simp only [eq_false hOut, ite_false] at hOpen
                injection hOpen with hLeafEq
                have hOpenedEq : opened = leaf := hLeafEq.symm
                subst hOpenedEq
                have hInside : isStrictlyInside sandboxRoot.finalPathSegments opened.finalPathSegments = true := by
                  cases hb : isStrictlyInside sandboxRoot.finalPathSegments opened.finalPathSegments
                  · exfalso; apply hOut; simp [hb]
                  · rfl
                have hValUnf := hVal
                unfold validateSandboxRelativePath at hValUnf
                by_cases hRawE : inp.rawTrimmed.isEmpty = true
                · simp only [eq_true hRawE, ite_true] at hValUnf; cases hValUnf
                · simp only [eq_false hRawE, ite_false] at hValUnf
                  have hRawF : inp.rawTrimmed.isEmpty = false := by
                    cases hb : inp.rawTrimmed.isEmpty
                    · rfl
                    · exact False.elim (hRawE hb)
                  by_cases hRepBlk : (inp.hasNull || inp.hasColon || inp.startsWithSlashOrBackslash) = true
                  · simp only [eq_true hRepBlk, ite_true] at hValUnf; cases hValUnf
                  · simp only [eq_false hRepBlk, ite_false] at hValUnf
                    have hRepF : (inp.hasNull || inp.hasColon || inp.startsWithSlashOrBackslash) = false := by
                      cases hb : (inp.hasNull || inp.hasColon || inp.startsWithSlashOrBackslash)
                      · rfl
                      · exact False.elim (hRepBlk hb)
                    rw [Bool.or_eq_false_iff, Bool.or_eq_false_iff] at hRepF
                    by_cases hTravBlk : (inp.hasPercentTraversal || inp.hasDotDot) = true
                    · simp only [eq_true hTravBlk, ite_true] at hValUnf; cases hValUnf
                    · simp only [eq_false hTravBlk, ite_false] at hValUnf
                      have hTravF : (inp.hasPercentTraversal || inp.hasDotDot) = false := by
                        cases hb : (inp.hasPercentTraversal || inp.hasDotDot)
                        · rfl
                        · exact False.elim (hTravBlk hb)
                      rw [Bool.or_eq_false_iff] at hTravF
                      refine ⟨rfl, hRawF, hRepF.1.1, hRepF.1.2, hRepF.2, hTravF.1, hTravF.2,
                        extractSafeNormalComponents_safe inp.components normalComps hValUnf,
                        ⟨normalComps, hVal, hCompsNe⟩,
                        hRootRepF, hRootDirT, ?_, hLeafRepF, hLeafDirF, hLinksLe, hInside,
                        isStrictlyInside_implies_ne hInside⟩
                      intro d hd
                      have hVer := perim_list_all_eq_true (verifyIntermediateDir sandboxRoot.finalPathSegments) dirs hDirsAll d hd
                      unfold verifyIntermediateDir at hVer
                      simp only [Bool.and_eq_true, Bool.not_eq_true'] at hVer
                      exact ⟨hVer.1.1.1.1.1, hVer.1.1.1.1.2, hVer.2⟩

theorem openConfined_blocks_curdir_only
    (sandboxRoot leaf : ConfinedHandleNode)
    (inp : SandboxPathInput)
    (dirs : List ConfinedHandleNode)
    (hCurOnly : inp.components = [.curDir]) :
    ∃ e : PerimeterPathError, openConfined sandboxRoot inp dirs leaf = .error e := by
  unfold openConfined
  cases hVal : validateSandboxRelativePath inp with
  | error e => exact ⟨e, rfl⟩
  | ok comps =>
    have hCompsNil : comps = [] := by
      unfold validateSandboxRelativePath at hVal
      split at hVal
      · cases hVal
      · split at hVal
        · cases hVal
        · split at hVal
          · cases hVal
          · rw [hCurOnly] at hVal
            simp [extractSafeNormalComponents] at hVal
            exact hVal
    subst hCompsNil
    by_cases h1 : sandboxRoot.isReparsePoint = true
    · simp only [eq_true h1, ite_true]; exact ⟨_, rfl⟩
    · simp only [eq_false h1, ite_false]
      by_cases h2 : (!sandboxRoot.isDir) = true
      · simp only [eq_true h2, ite_true]; exact ⟨_, rfl⟩
      · simp only [eq_false h2, ite_false]
        simp only [List.isEmpty_nil, ite_true]
        exact ⟨.EmptyComponents, rfl⟩

/-! ### Part 2: SSRF Classifier, URL Validation & DNS Pinning (`src/containment_ring/egress_proxy.rs`) -/

structure Ipv4Octets where
  a : Nat
  b : Nat
  c : Nat
  d : Nat
  deriving DecidableEq, Repr, BEq

structure Ipv6Segments where
  s0 : Nat
  s1 : Nat
  s2 : Nat
  s3 : Nat
  s4 : Nat
  s5 : Nat
  s6 : Nat
  s7 : Nat
  deriving DecidableEq, Repr, BEq

inductive IpAddrSpec : Type where
  | v4 (ip : Ipv4Octets)
  | v6 (ip : Ipv6Segments)
  deriving DecidableEq, Repr, BEq

def extractEmbeddedV4 (s6 s7 : Nat) : Ipv4Octets :=
  { a := s6 / 256, b := s6 % 256, c := s7 / 256, d := s7 % 256 }

/-- Exact 1-to-1 parity with IPv4 checks in `is_restricted_rebinding_ip` (`egress_proxy.rs:548-571`). -/
def isIpv4Restricted (v4 : Ipv4Octets) : Bool :=
  (v4.a == 0) ||                                                         -- 0.0.0.0/8 (includes 0.0.0.0)
  (v4.a == 10) ||                                                        -- 10.0.0.0/8 (RFC1918)
  (v4.a == 100 && decide (64 ≤ v4.b) && decide (v4.b < 128)) ||          -- 100.64.0.0/10 (CGNAT)
  (v4.a == 127) ||                                                       -- 127.0.0.0/8 (Loopback)
  (v4.a == 168 && v4.b == 63 && v4.c == 129 && v4.d == 16) ||            -- 168.63.129.16 (Azure WireServer)
  (v4.a == 169 && v4.b == 254) ||                                        -- 169.254.0.0/16 (Link-Local / IMDS)
  (v4.a == 172 && decide (16 ≤ v4.b) && decide (v4.b < 32)) ||           -- 172.16.0.0/12 (RFC1918)
  (v4.a == 192 && v4.b == 0 && v4.c == 0) ||                             -- 192.0.0.0/24 (IETF / Oracle IMDS 192.0.0.192)
  (v4.a == 192 && v4.b == 0 && v4.c == 2) ||                             -- 192.0.2.0/24 (TEST-NET-1)
  (v4.a == 192 && v4.b == 168) ||                                        -- 192.168.0.0/16 (RFC1918)
  (v4.a == 198 && (v4.b == 18 || v4.b == 19)) ||                         -- 198.18.0.0/15 (Benchmarking)
  (v4.a == 198 && v4.b == 51 && v4.c == 100) ||                          -- 198.51.100.0/24 (TEST-NET-2)
  (v4.a == 203 && v4.b == 0 && v4.c == 113) ||                           -- 203.0.113.0/24 (TEST-NET-3)
  (decide (224 ≤ v4.a) && decide (v4.a < 240)) ||                        -- 224.0.0.0/4 (Multicast)
  decide (240 ≤ v4.a)                                                    -- 240.0.0.0/4 (Class E & Broadcast)

/-- Exact 1-to-1 parity with IPv6 + recursive SIIT/mapped/compatible checks (`egress_proxy.rs:572-626`). -/
def isIpv6Restricted (v6 : Ipv6Segments) : Bool :=
  (v6.s0 == 0 && v6.s1 == 0 && v6.s2 == 0 && v6.s3 == 0 &&
   v6.s4 == 0 && v6.s5 == 0 && v6.s6 == 0 && v6.s7 == 1) ||              -- ::1 (Loopback)
  (v6.s0 == 0 && v6.s1 == 0 && v6.s2 == 0 && v6.s3 == 0 &&
   v6.s4 == 0 && v6.s5 == 0 && v6.s6 == 0 && v6.s7 == 0) ||              -- :: (Unspecified)
  (decide (0xff00 ≤ v6.s0) && decide (v6.s0 ≤ 0xffff)) ||                -- ff00::/8 (Multicast)
  (decide (0xfc00 ≤ v6.s0) && decide (v6.s0 ≤ 0xfdff)) ||                -- fc00::/7 (Unique Local)
  (decide (0xfe80 ≤ v6.s0) && decide (v6.s0 ≤ 0xfebf)) ||                -- fe80::/10 (Link-Local)
  (v6.s0 == 0x0064 && v6.s1 == 0xff9b && v6.s2 == 0 && v6.s3 == 0 &&
   v6.s4 == 0 && v6.s5 == 0) ||                                          -- 64:ff9b::/96 (NAT64)
  (v6.s0 == 0x0064 && v6.s1 == 0xff9b && v6.s2 == 1) ||                  -- 64:ff9b:1::/48 (Local-Use NAT64)
  (v6.s0 == 0x2002) ||                                                   -- 2002::/16 (6to4)
  (v6.s0 == 0x2001 && (v6.s1 == 0x0000 || v6.s1 == 0x0db8)) ||           -- 2001::/32 (Teredo), 2001:db8::/32 (Doc)
  (v6.s0 == 0x0100 && v6.s1 == 0 && v6.s2 == 0 && v6.s3 == 0) ||         -- 100::/64 (Discard-Only)
  (v6.s0 == 0 && v6.s1 == 0 && v6.s2 == 0 && v6.s3 == 0 &&
   v6.s4 == 0xffff && v6.s5 == 0 &&
   isIpv4Restricted (extractEmbeddedV4 v6.s6 v6.s7)) ||                   -- ::ffff:0:0:x.x.x.x (RFC 2765 SIIT)
  (v6.s0 == 0 && v6.s1 == 0 && v6.s2 == 0 && v6.s3 == 0 &&
   v6.s4 == 0 && v6.s5 == 0xffff &&
   isIpv4Restricted (extractEmbeddedV4 v6.s6 v6.s7)) ||                   -- ::ffff:x.x.x.x (IPv4-mapped)
  (v6.s0 == 0 && v6.s1 == 0 && v6.s2 == 0 && v6.s3 == 0 &&
   v6.s4 == 0 && v6.s5 == 0 &&
   isIpv4Restricted (extractEmbeddedV4 v6.s6 v6.s7))                      -- ::x.x.x.x (IPv4-compatible)

def isRestrictedRebindingIp : IpAddrSpec → Bool
  | .v4 ip => isIpv4Restricted ip
  | .v6 ip => isIpv6Restricted ip

inductive EgressUrlError : Type where
  | EmptyUrl
  | ControlChar
  | SmugglingPattern
  | NonStandardIpEncoding
  | InvalidScheme
  | UserinfoPresent
  | InvalidPort
  | RestrictedIp
  | InternalDomain
  | NotInAllowlist
  | EmptyDnsResolution
  deriving DecidableEq, Repr, BEq

structure EgressUrlRequest where
  rawTrimmed : String
  hasControlChars : Bool
  hasSmuggling : Bool
  hasNonStandardIpHost : Bool
  scheme : String
  hasUserinfo : Bool
  port : Option Nat
  hostDomain : String
  hostIsIp : Option IpAddrSpec
  isInternalOrLocalhostDomain : Bool
  deriving DecidableEq, Repr

def domainMatchesAllowlist (host : String) (allowedDomains : List String) : Bool :=
  allowedDomains.isEmpty ||
  allowedDomains.any (fun d => host == d || host.endsWith ("." ++ d))

/-- Mirror of `validate_agent_egress_url` (`egress_proxy.rs:632-786`). -/
def validateAgentEgressUrl
    (req : EgressUrlRequest)
    (allowedDomains : List String) : Except EgressUrlError Unit :=
  if req.hasControlChars then
    .error .ControlChar
  else if req.rawTrimmed.isEmpty then
    .error .EmptyUrl
  else if req.hasSmuggling then
    .error .SmugglingPattern
  else if req.hasNonStandardIpHost then
    .error .NonStandardIpEncoding
  else if req.scheme != "https" then
    .error .InvalidScheme
  else if req.hasUserinfo then
    .error .UserinfoPresent
  else if !(req.port == none || req.port == some 443) then
    .error .InvalidPort
  else if req.hostDomain.isEmpty then
    .error .InternalDomain
  else
    match req.hostIsIp with
    | some ip =>
      if isRestrictedRebindingIp ip then
        .error .RestrictedIp
      else if !domainMatchesAllowlist req.hostDomain allowedDomains then
        .error .NotInAllowlist
      else
        .ok ()
    | none =>
      if req.isInternalOrLocalhostDomain then
        .error .InternalDomain
      else if !domainMatchesAllowlist req.hostDomain allowedDomains then
        .error .NotInAllowlist
      else
        .ok ()

structure PinnedEgress where
  host : String
  port : Nat
  pinnedAddrs : List IpAddrSpec
  deriving DecidableEq, Repr

/-- Mirror of `resolve_and_pin` (`egress_proxy.rs:816-870`). -/
def resolveAndPin
    (req : EgressUrlRequest)
    (allowedDomains : List String)
    (resolvedIps : List IpAddrSpec) : Except EgressUrlError PinnedEgress :=
  match validateAgentEgressUrl req allowedDomains with
  | .error e => .error e
  | .ok () =>
    if resolvedIps.isEmpty then
      .error .EmptyDnsResolution
    else if resolvedIps.any isRestrictedRebindingIp then
      .error .RestrictedIp
    else
      .ok { host := req.hostDomain, port := req.port.getD 443, pinnedAddrs := resolvedIps }

def ipv4InRestrictedRange (v4 : Ipv4Octets) : Prop :=
  v4.a = 0 ∨
  v4.a = 10 ∨
  (v4.a = 100 ∧ 64 ≤ v4.b ∧ v4.b < 128) ∨
  v4.a = 127 ∨
  (v4.a = 168 ∧ v4.b = 63 ∧ v4.c = 129 ∧ v4.d = 16) ∨
  (v4.a = 169 ∧ v4.b = 254) ∨
  (v4.a = 172 ∧ 16 ≤ v4.b ∧ v4.b < 32) ∨
  (v4.a = 192 ∧ v4.b = 0 ∧ v4.c = 0) ∨
  (v4.a = 192 ∧ v4.b = 0 ∧ v4.c = 2) ∨
  (v4.a = 192 ∧ v4.b = 168) ∨
  (v4.a = 198 ∧ (v4.b = 18 ∨ v4.b = 19)) ∨
  (v4.a = 198 ∧ v4.b = 51 ∧ v4.c = 100) ∨
  (v4.a = 203 ∧ v4.b = 0 ∧ v4.c = 113) ∨
  (224 ≤ v4.a ∧ v4.a < 240) ∨
  240 ≤ v4.a

def ipv6InRestrictedRange (v6 : Ipv6Segments) : Prop :=
  (v6.s0 = 0 ∧ v6.s1 = 0 ∧ v6.s2 = 0 ∧ v6.s3 = 0 ∧ v6.s4 = 0 ∧ v6.s5 = 0 ∧ v6.s6 = 0 ∧ v6.s7 = 1) ∨
  (v6.s0 = 0 ∧ v6.s1 = 0 ∧ v6.s2 = 0 ∧ v6.s3 = 0 ∧ v6.s4 = 0 ∧ v6.s5 = 0 ∧ v6.s6 = 0 ∧ v6.s7 = 0) ∨
  (0xff00 ≤ v6.s0 ∧ v6.s0 ≤ 0xffff) ∨
  (0xfc00 ≤ v6.s0 ∧ v6.s0 ≤ 0xfdff) ∨
  (0xfe80 ≤ v6.s0 ∧ v6.s0 ≤ 0xfebf) ∨
  (v6.s0 = 0x0064 ∧ v6.s1 = 0xff9b ∧ v6.s2 = 0 ∧ v6.s3 = 0 ∧ v6.s4 = 0 ∧ v6.s5 = 0) ∨
  (v6.s0 = 0x0064 ∧ v6.s1 = 0xff9b ∧ v6.s2 = 1) ∨
  v6.s0 = 0x2002 ∨
  (v6.s0 = 0x2001 ∧ (v6.s1 = 0x0000 ∨ v6.s1 = 0x0db8)) ∨
  (v6.s0 = 0x0100 ∧ v6.s1 = 0 ∧ v6.s2 = 0 ∧ v6.s3 = 0) ∨
  (v6.s0 = 0 ∧ v6.s1 = 0 ∧ v6.s2 = 0 ∧ v6.s3 = 0 ∧ v6.s4 = 0xffff ∧ v6.s5 = 0 ∧
    ipv4InRestrictedRange (extractEmbeddedV4 v6.s6 v6.s7)) ∨
  (v6.s0 = 0 ∧ v6.s1 = 0 ∧ v6.s2 = 0 ∧ v6.s3 = 0 ∧ v6.s4 = 0 ∧ v6.s5 = 0xffff ∧
    ipv4InRestrictedRange (extractEmbeddedV4 v6.s6 v6.s7)) ∨
  (v6.s0 = 0 ∧ v6.s1 = 0 ∧ v6.s2 = 0 ∧ v6.s3 = 0 ∧ v6.s4 = 0 ∧ v6.s5 = 0 ∧
    ipv4InRestrictedRange (extractEmbeddedV4 v6.s6 v6.s7))

theorem isIpv4Restricted_iff (v4 : Ipv4Octets) :
    isIpv4Restricted v4 = true ↔ ipv4InRestrictedRange v4 := by
  unfold isIpv4Restricted ipv4InRestrictedRange
  simp only [Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq, and_assoc, or_assoc]

theorem isIpv6Restricted_iff (v6 : Ipv6Segments) :
    isIpv6Restricted v6 = true ↔ ipv6InRestrictedRange v6 := by
  unfold isIpv6Restricted ipv6InRestrictedRange
  have hv4 := isIpv4Restricted_iff (extractEmbeddedV4 v6.s6 v6.s7)
  simp only [Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq, hv4, and_assoc, or_assoc]

private theorem perim_any_true_of_mem {α : Type} (p : α → Bool) :
    ∀ {xs : List α} {x : α}, x ∈ xs → p x = true → xs.any p = true
  | [], _, hx, _ => by cases hx
  | a :: as, x, hx, hpx => by
    rw [List.any_cons]
    cases hx with
    | head => rw [hpx, Bool.true_or]
    | tail _ hmem => rw [perim_any_true_of_mem p hmem hpx, Bool.or_true]

/-- **Theorem 2 (`ssrf_blocks_all_restricted_ranges`)**:
    1. Every IPv4 address in any restricted range (RFC1918, loopback, IMDS 169.254/16,
       Azure WireServer 168.63.129.16, CGNAT 100.64/10, 0.0.0.0/8, 192.0.0/24, benchmarking,
       documentation, multicast, class E/broadcast) is classified restricted (`= true`).
    2. Every IPv6 address in `::1`, `::`, multicast `ff00::/8`, ULA `fc00::/7`, link-local
       `fe80::/10`, NAT64, 6to4, Teredo/Doc/Discard, OR wrapping any restricted IPv4 via
       SIIT `::ffff:0:0/96`, IPv4-mapped `::ffff:x.x.x.x`, or IPv4-compatible `::x.x.x.x`
       is classified restricted (`= true`).
    3. `resolveAndPin` guarantees HTTPS, port 443, no userinfo, no smuggling/non-standard IP
       encoding, non-empty `pinnedAddrs`, and that zero pinned or URL-literal IPs are restricted. -/
theorem ssrf_blocks_all_restricted_ranges
    (req : EgressUrlRequest)
    (allowedDomains : List String)
    (resolvedIps : List IpAddrSpec) :
    (∀ v4 : Ipv4Octets, ipv4InRestrictedRange v4 → isRestrictedRebindingIp (.v4 v4) = true) ∧
    (∀ v6 : Ipv6Segments, ipv6InRestrictedRange v6 → isRestrictedRebindingIp (.v6 v6) = true) ∧
    (∀ pinned : PinnedEgress,
      resolveAndPin req allowedDomains resolvedIps = .ok pinned →
      req.scheme = "https" ∧
      (req.port = none ∨ req.port = some 443) ∧
      req.hasUserinfo = false ∧
      req.hasControlChars = false ∧
      req.hasSmuggling = false ∧
      req.hasNonStandardIpHost = false ∧
      pinned.port = 443 ∧
      pinned.pinnedAddrs ≠ [] ∧
      (∀ ip, req.hostIsIp = some ip → isRestrictedRebindingIp ip = false) ∧
      (∀ ip ∈ pinned.pinnedAddrs, isRestrictedRebindingIp ip = false)) := by
  refine ⟨fun v4 h => (isIpv4Restricted_iff v4).mpr h, fun v6 h => (isIpv6Restricted_iff v6).mpr h, ?_⟩
  intro pinned hPin
  unfold resolveAndPin at hPin
  cases hVal : validateAgentEgressUrl req allowedDomains with
  | error e => rw [hVal] at hPin; cases hPin
  | ok _ =>
    rw [hVal] at hPin
    dsimp only at hPin
    by_cases hEmp : resolvedIps.isEmpty = true
    · simp only [eq_true hEmp, ite_true] at hPin; cases hPin
    · simp only [eq_false hEmp, ite_false] at hPin
      have hNe : resolvedIps ≠ [] := by
        intro hNil
        rw [hNil] at hEmp
        simp at hEmp
      by_cases hAny : resolvedIps.any isRestrictedRebindingIp = true
      · simp only [eq_true hAny, ite_true] at hPin; cases hPin
      · simp only [eq_false hAny, ite_false] at hPin
        injection hPin with hEq
        subst hEq
        have hNoneRes : ∀ ip ∈ resolvedIps, isRestrictedRebindingIp ip = false := by
          intro ip hip
          cases hRes : isRestrictedRebindingIp ip
          · rfl
          · exact False.elim (hAny (perim_any_true_of_mem isRestrictedRebindingIp hip hRes))
        unfold validateAgentEgressUrl at hVal
        by_cases h1 : req.hasControlChars = true
        · simp only [eq_true h1, ite_true] at hVal; cases hVal
        · simp only [eq_false h1, ite_false] at hVal
          have h1F : req.hasControlChars = false := by
            cases hb : req.hasControlChars
            · rfl
            · exact absurd hb h1
          by_cases h2 : req.rawTrimmed.isEmpty = true
          · simp only [eq_true h2, ite_true] at hVal; cases hVal
          · simp only [eq_false h2, ite_false] at hVal
            by_cases h3 : req.hasSmuggling = true
            · simp only [eq_true h3, ite_true] at hVal; cases hVal
            · simp only [eq_false h3, ite_false] at hVal
              have h3F : req.hasSmuggling = false := by
                cases hb : req.hasSmuggling
                · rfl
                · exact absurd hb h3
              by_cases h4 : req.hasNonStandardIpHost = true
              · simp only [eq_true h4, ite_true] at hVal; cases hVal
              · simp only [eq_false h4, ite_false] at hVal
                have h4F : req.hasNonStandardIpHost = false := by
                  cases hb : req.hasNonStandardIpHost
                  · rfl
                  · exact absurd hb h4
                by_cases h5 : (req.scheme != "https") = true
                · simp only [eq_true h5, ite_true] at hVal; cases hVal
                · simp only [eq_false h5, ite_false] at hVal
                  have hSch : req.scheme = "https" := by
                    by_cases heq : req.scheme = "https"
                    · exact heq
                    · have ht : (req.scheme != "https") = true := bne_iff_ne.mpr heq
                      exact absurd ht h5
                  by_cases h6 : req.hasUserinfo = true
                  · simp only [eq_true h6, ite_true] at hVal; cases hVal
                  · simp only [eq_false h6, ite_false] at hVal
                    have h6F : req.hasUserinfo = false := by
                      cases hb : req.hasUserinfo
                      · rfl
                      · exact absurd hb h6
                    by_cases h7 : (!(req.port == none || req.port == some 443)) = true
                    · simp only [eq_true h7, ite_true] at hVal; cases hVal
                    · simp only [eq_false h7, ite_false] at hVal
                      have hPort : req.port = none ∨ req.port = some 443 := by
                        cases hp : req.port with
                        | none => exact Or.inl rfl
                        | some p =>
                          by_cases hp443 : p = 443
                          · subst hp443; exact Or.inr rfl
                          · exfalso; apply h7; simp [hp, hp443]
                      have hPortVal : req.port.getD 443 = 443 := by
                        rcases hPort with hEq | hEq <;> simp [hEq]
                      by_cases h8 : req.hostDomain.isEmpty = true
                      · simp only [eq_true h8, ite_true] at hVal; cases hVal
                      · simp only [eq_false h8, ite_false] at hVal
                        have hHostIpOk : ∀ ip, req.hostIsIp = some ip → isRestrictedRebindingIp ip = false := by
                          intro ip hip
                          rw [hip] at hVal
                          dsimp only at hVal
                          by_cases hres : isRestrictedRebindingIp ip = true
                          · simp only [eq_true hres, ite_true] at hVal; cases hVal
                          · cases hb : isRestrictedRebindingIp ip
                            · rfl
                            · exact absurd hb hres
                        exact ⟨hSch, hPort, h6F, h1F, h3F, h4F, hPortVal, hNe, hHostIpOk, hNoneRes⟩

/-! ### Part 3: Token Posture, Job Object, AppContainer & Pre-Resume Gate
    (`src/security/token_posture.rs`, `src/security/windows_sandbox.rs`) -/

def INTEGRITY_UNTRUSTED : Nat := 0x0000
def INTEGRITY_LOW : Nat := 0x1000
def INTEGRITY_MEDIUM : Nat := 0x2000
def INTEGRITY_MEDIUM_RID : Nat := 0x2000
def INTEGRITY_HIGH : Nat := 0x3000
def INTEGRITY_SYSTEM : Nat := 0x4000
def MAX_WIN_MEMORY_BYTES : Nat := 512 * 1024 * 1024

/-- Exact 13-privilege list from `DANGEROUS_PRIVILEGES` (`src/security/token_posture.rs:34-48`). -/
def DANGEROUS_PRIVILEGES : List String :=
  [ "SeBackupPrivilege"
  , "SeRestorePrivilege"
  , "SeDebugPrivilege"
  , "SeTakeOwnershipPrivilege"
  , "SeLoadDriverPrivilege"
  , "SeImpersonatePrivilege"
  , "SeTcbPrivilege"
  , "SeAssignPrimaryTokenPrivilege"
  , "SeSecurityPrivilege"
  , "SeManageVolumePrivilege"
  , "SeCreateTokenPrivilege"
  , "SeRelabelPrivilege"
  , "SeSystemEnvironmentPrivilege"
  ]

theorem dangerous_privileges_length : DANGEROUS_PRIVILEGES.length = 13 := rfl

def asciiLowerChar (c : Char) : Char :=
  let n := c.toNat
  if 65 ≤ n && n ≤ 90 then Char.ofNat (n + 32) else c

def asciiLower (s : String) : String :=
  String.ofList (s.toList.map asciiLowerChar)

def isDangerousPrivilege (p : String) : Bool :=
  DANGEROUS_PRIVILEGES.any (fun d => asciiLower d == asciiLower p)

theorem mem_dangerous_privileges_isDangerous {p : String} (hp : p ∈ DANGEROUS_PRIVILEGES) :
    isDangerousPrivilege p = true := by
  unfold isDangerousPrivilege
  have hGen : ∀ (xs : List String), p ∈ xs → xs.any (fun d => asciiLower d == asciiLower p) = true := by
    intro xs hmem
    induction xs with
    | nil => cases hmem
    | cons d ds ih =>
      rw [List.any_cons]
      cases hmem with
      | head => simp
      | tail _ htail => simp [ih htail]
  exact hGen DANGEROUS_PRIVILEGES hp

structure TokenPosture where
  elevated : Bool
  integrityRid : Nat
  adminsEnabled : Bool
  adminsDenyOnly : Bool
  presentPrivileges : List String
  enabledPrivileges : List String
  deriving DecidableEq, Repr

/-- Mirror of `TokenPosture::verify_agent_safe` (`src/security/token_posture.rs:94-121`). -/
def verifyAgentSafe (tp : TokenPosture) : Bool :=
  !tp.elevated &&
  decide (tp.integrityRid ≤ INTEGRITY_MEDIUM) &&
  !tp.adminsEnabled &&
  !(tp.presentPrivileges.any isDangerousPrivilege)

structure WindowsConfinementPolicy where
  requireAppcontainer : Bool
  createSuspendedBeforeJobAssign : Bool
  killOnJobClose : Bool
  activeProcessLimit : Nat
  maxMemoryBytes : Nat
  enforceUiLimits : Bool
  deriving DecidableEq, Repr

/-- Mirror of `verify_windows_confinement_invariants` (`windows_sandbox.rs:2196-2227`). -/
def verifyWindowsConfinementInvariants (p : WindowsConfinementPolicy) : Bool :=
  p.createSuspendedBeforeJobAssign &&
  p.killOnJobClose &&
  decide (1 ≤ p.activeProcessLimit) &&
  decide (0 < p.maxMemoryBytes) &&
  decide (p.maxMemoryBytes ≤ MAX_WIN_MEMORY_BYTES) &&
  p.enforceUiLimits

/-- Mirror of `evaluate_pre_resume_confinement_gate` (`windows_sandbox.rs:2233-2264`). -/
def evaluatePreResumeConfinementGate
    (p : WindowsConfinementPolicy)
    (createdSuspended appcontainerBound assignedToJob verifiedInJob : Bool) : Bool :=
  verifyWindowsConfinementInvariants p &&
  createdSuspended &&
  (!p.requireAppcontainer || appcontainerBound) &&
  assignedToJob &&
  verifiedInJob

structure ChildSpawnAttempt where
  createdSuspended : Bool
  appcontainerBound : Bool
  appcontainerSidMatches : Bool
  assignedToJob : Bool
  verifiedInJob : Bool
  tokenPosture : TokenPosture
  deriving DecidableEq, Repr

inductive ChildLifecycle : Type where
  | Resumed
  | TerminatedBeforeResume
  deriving DecidableEq, Repr, BEq

/-- Models complete pre-resume gate (`spawn_tier2_appcontainer_command` / `spawn_deelevated_in_job_with_io` /
    `spawn_appcontainer_in_job_with_io_prepared`): any failure terminates the suspended process
    without ever invoking `ResumeThread`. -/
def tryResumeChild (policy : WindowsConfinementPolicy) (attempt : ChildSpawnAttempt) : ChildLifecycle :=
  if evaluatePreResumeConfinementGate policy attempt.createdSuspended attempt.appcontainerBound
      attempt.assignedToJob attempt.verifiedInJob &&
     (!policy.requireAppcontainer || attempt.appcontainerSidMatches) &&
     verifyAgentSafe attempt.tokenPosture then
    .Resumed
  else
    .TerminatedBeforeResume

/-- **Theorem 3 (`pre_resume_no_elevated_uncontained_child`)**:
    A child process can reach `.Resumed` ONLY if it is non-elevated, has `integrityRid ≤ 0x2000`
    (`INTEGRITY_MEDIUM`), has `adminsEnabled = false`, holds zero `DANGEROUS_PRIVILEGES`
    (even disabled in `presentPrivileges`), was spawned `CREATE_SUSPENDED`, was assigned to and
    verified inside a compliant `WindowsJobObject`, and (when required) is bound to the expected
    AppContainer SID. Otherwise it is deterministically terminated before resume. -/
theorem pre_resume_no_elevated_uncontained_child
    (policy : WindowsConfinementPolicy)
    (attempt : ChildSpawnAttempt) :
    (tryResumeChild policy attempt = .Resumed →
      attempt.tokenPosture.elevated = false ∧
      attempt.tokenPosture.integrityRid ≤ INTEGRITY_MEDIUM ∧
      attempt.tokenPosture.adminsEnabled = false ∧
      (∀ p ∈ attempt.tokenPosture.presentPrivileges,
        isDangerousPrivilege p = false ∧ p ∉ DANGEROUS_PRIVILEGES) ∧
      attempt.createdSuspended = true ∧
      attempt.assignedToJob = true ∧
      attempt.verifiedInJob = true ∧
      (policy.requireAppcontainer = true →
        attempt.appcontainerBound = true ∧ attempt.appcontainerSidMatches = true) ∧
      policy.createSuspendedBeforeJobAssign = true ∧
      policy.killOnJobClose = true ∧
      policy.enforceUiLimits = true ∧
      1 ≤ policy.activeProcessLimit ∧
      0 < policy.maxMemoryBytes ∧
      policy.maxMemoryBytes ≤ MAX_WIN_MEMORY_BYTES) ∧
    ((attempt.tokenPosture.elevated = true ∨
      attempt.tokenPosture.integrityRid > INTEGRITY_MEDIUM ∨
      attempt.tokenPosture.adminsEnabled = true ∨
      (∃ p ∈ attempt.tokenPosture.presentPrivileges, isDangerousPrivilege p = true) ∨
      attempt.createdSuspended = false ∨
      attempt.assignedToJob = false ∨
      attempt.verifiedInJob = false ∨
      (policy.requireAppcontainer = true ∧
        (attempt.appcontainerBound = false ∨ attempt.appcontainerSidMatches = false))) →
     tryResumeChild policy attempt = .TerminatedBeforeResume) := by
  have hForward :
      tryResumeChild policy attempt = .Resumed →
      attempt.tokenPosture.elevated = false ∧
      attempt.tokenPosture.integrityRid ≤ INTEGRITY_MEDIUM ∧
      attempt.tokenPosture.adminsEnabled = false ∧
      (∀ p ∈ attempt.tokenPosture.presentPrivileges,
        isDangerousPrivilege p = false ∧ p ∉ DANGEROUS_PRIVILEGES) ∧
      attempt.createdSuspended = true ∧
      attempt.assignedToJob = true ∧
      attempt.verifiedInJob = true ∧
      (policy.requireAppcontainer = true →
        attempt.appcontainerBound = true ∧ attempt.appcontainerSidMatches = true) ∧
      policy.createSuspendedBeforeJobAssign = true ∧
      policy.killOnJobClose = true ∧
      policy.enforceUiLimits = true ∧
      1 ≤ policy.activeProcessLimit ∧
      0 < policy.maxMemoryBytes ∧
      policy.maxMemoryBytes ≤ MAX_WIN_MEMORY_BYTES := by
    intro hRes
    unfold tryResumeChild at hRes
    by_cases hCond :
        (evaluatePreResumeConfinementGate policy attempt.createdSuspended attempt.appcontainerBound
          attempt.assignedToJob attempt.verifiedInJob &&
         (!policy.requireAppcontainer || attempt.appcontainerSidMatches) &&
         verifyAgentSafe attempt.tokenPosture) = true
    · unfold evaluatePreResumeConfinementGate verifyWindowsConfinementInvariants verifyAgentSafe at hCond
      simp only [Bool.and_eq_true, Bool.or_eq_true, Bool.not_eq_true', decide_eq_true_eq] at hCond
      rcases hCond with ⟨⟨hEvalGate, hAcSid⟩, hSafe⟩
      rcases hEvalGate with ⟨⟨⟨⟨hWinPol, hSuspAtt⟩, hAcBnd⟩, hJobAss⟩, hJobVer⟩
      rcases hWinPol with ⟨⟨⟨⟨⟨hSuspPol, hKill⟩, hActLim⟩, hMemPos⟩, hMemMax⟩, hUi⟩
      rcases hSafe with ⟨⟨⟨hElev, hRid⟩, hAdm⟩, hPriv⟩
      refine ⟨hElev, hRid, hAdm, ?_, hSuspAtt, hJobAss, hJobVer, ?_, hSuspPol, hKill, hUi, hActLim, hMemPos, hMemMax⟩
      · intro p hp
        have hNotAny : isDangerousPrivilege p = false := by
          cases hd : isDangerousPrivilege p
          · rfl
          · exfalso
            have hT := perim_any_true_of_mem isDangerousPrivilege hp hd
            rw [hT] at hPriv
            cases hPriv
        refine ⟨hNotAny, ?_⟩
        intro hpMem
        have hTrue := mem_dangerous_privileges_isDangerous hpMem
        rw [hNotAny] at hTrue
        cases hTrue
      · intro hReq
        rw [hReq] at hAcBnd hAcSid
        simp at hAcBnd hAcSid
        exact ⟨hAcBnd, hAcSid⟩
    · simp only [eq_false hCond, ite_false] at hRes
      cases hRes
  refine ⟨hForward, ?_⟩
  intro hFail
  cases hLife : tryResumeChild policy attempt with
  | TerminatedBeforeResume => rfl
  | Resumed =>
    exfalso
    have hOk := hForward hLife
    rcases hFail with h1 | h2 | h3 | h4 | h5 | h6 | h7 | h8
    · rw [hOk.1] at h1; cases h1
    · exact Nat.not_le_of_gt h2 hOk.2.1
    · rw [hOk.2.2.1] at h3; cases h3
    · obtain ⟨p, hpMem, hpDang⟩ := h4
      have hSafe := (hOk.2.2.2.1 p hpMem).1
      rw [hSafe] at hpDang
      cases hpDang
    · rw [hOk.2.2.2.2.1] at h5; cases h5
    · rw [hOk.2.2.2.2.2.1] at h6; cases h6
    · rw [hOk.2.2.2.2.2.2.1] at h7; cases h7
    · obtain ⟨hReq, hBad⟩ := h8
      have hBnd := hOk.2.2.2.2.2.2.2.1 hReq
      rcases hBad with hBadB | hBadS
      · rw [hBnd.1] at hBadB; cases hBadB
      · rw [hBnd.2] at hBadS; cases hBadS

/-! ### Part 4: Zero-Reboot Virtual-Patching Shield Latch (`src/security/virtual_patch_shield.rs`) -/

inductive KernelAttackSurface : Type where
  | SmbV3AndKsmbd
  | HttpSys
  | Ipv6Rce
  | NetfilterNfTables
  | IoUringEop
  | EbpfAndUserfaultfd
  | Win32kAndByovd
  | DarwinIokitKext
  | GenericKernelCve
  deriving DecidableEq, Repr, BEq

def baselineProactiveSurfaces : List KernelAttackSurface :=
  [ .SmbV3AndKsmbd
  , .HttpSys
  , .Ipv6Rce
  , .NetfilterNfTables
  , .IoUringEop
  , .EbpfAndUserfaultfd
  , .Win32kAndByovd
  , .DarwinIokitKext
  ]

theorem baseline_proactive_surfaces_length : baselineProactiveSurfaces.length = 8 := rfl

structure KernelShieldPosture where
  unpatchedCveIds : List String
  cisaKevIds : List String
  affectedSurfaces : List KernelAttackSurface
  rebootPending : Bool
  livepatchActive : Bool
  shieldLockedUntilReboot : Bool
  telemetryDegradedFailClosed : Bool
  integrityTampered : Bool
  monotonicRevision : Nat
  runningKernel : String
  deriving DecidableEq, Repr

def KernelShieldPosture.defaultFailClosed : KernelShieldPosture :=
  { unpatchedCveIds := []
  , cisaKevIds := []
  , affectedSurfaces := baselineProactiveSurfaces
  , rebootPending := false
  , livepatchActive := false
  , shieldLockedUntilReboot := false
  , telemetryDegradedFailClosed := true
  , integrityTampered := false
  , monotonicRevision := 1
  , runningKernel := "" }

def KernelShieldPosture.tamperedFailClosed : KernelShieldPosture :=
  { KernelShieldPosture.defaultFailClosed with
    shieldLockedUntilReboot := true
    integrityTampered := true }

def KernelShieldPosture.isShieldActiveWithDegraded
    (p : KernelShieldPosture) (failClosedOnDegraded : Bool) : Bool :=
  !p.unpatchedCveIds.isEmpty ||
  !p.cisaKevIds.isEmpty ||
  (p.rebootPending && !p.livepatchActive) ||
  p.shieldLockedUntilReboot ||
  p.integrityTampered ||
  (failClosedOnDegraded && p.telemetryDegradedFailClosed)

def KernelShieldPosture.isShieldActive (p : KernelShieldPosture) : Bool :=
  p.isShieldActiveWithDegraded true

def unionDedup {α : Type} [DecidableEq α] (base extra : List α) : List α :=
  extra.foldl (fun acc x => if acc.any (fun y => decide (y = x)) then acc else acc ++ [x]) base

private theorem mem_unionDedup_left {α : Type} [DecidableEq α] :
    ∀ (extra base : List α) (a : α), a ∈ base → a ∈ unionDedup base extra
  | [], base, _, ha => ha
  | x :: xs, base, a, ha => by
    unfold unionDedup
    simp only [List.foldl]
    apply mem_unionDedup_left xs
    by_cases hAny : (base.any (fun y => decide (y = x))) = true
    · simp only [eq_true hAny, ite_true]; exact ha
    · simp only [eq_false hAny, ite_false]
      exact List.mem_append.mpr (Or.inl ha)

private theorem mem_unionDedup_right {α : Type} [DecidableEq α] :
    ∀ (extra base : List α) (a : α), a ∈ extra → a ∈ unionDedup base extra
  | [], _, _, ha => by cases ha
  | x :: xs, base, a, ha => by
    unfold unionDedup
    simp only [List.foldl]
    cases ha with
    | head =>
      apply mem_unionDedup_left xs
      by_cases hAny : (base.any (fun y => decide (y = x))) = true
      · simp only [eq_true hAny, ite_true]
        clear xs
        induction base with
        | nil => simp at hAny
        | cons b bs ih =>
          rw [List.any_cons, Bool.or_eq_true, decide_eq_true_eq] at hAny
          cases hAny with
          | inl hb => subst hb; exact List.Mem.head _
          | inr hbs => exact List.Mem.tail _ (ih hbs)
      · simp only [eq_false hAny, ite_false]
        exact List.mem_append.mpr (Or.inr (List.Mem.head _))
    | tail _ hmem =>
      exact mem_unionDedup_right xs _ a hmem

/-- Mirror of `KernelShieldPosture::finalize` (`virtual_patch_shield.rs:268-283`). -/
def finalizePosture (p : KernelShieldPosture) : KernelShieldPosture :=
  { p with
    shieldLockedUntilReboot :=
      p.shieldLockedUntilReboot || (p.rebootPending && !p.livepatchActive) || p.integrityTampered }

inductive ShieldError : Type where
  | MonotonicLatchViolation
  | RebootStillPending
  | EmptyKernelRelease
  | KernelVersionUnchanged
  deriving DecidableEq, Repr, BEq

/-- Mirror of `VirtualPatchShieldStore::apply_posture` (`virtual_patch_shield.rs:461-510`). -/
def applyPosture (cur next : KernelShieldPosture) : Except ShieldError KernelShieldPosture :=
  if cur.shieldLockedUntilReboot && !next.shieldLockedUntilReboot then
    .error .MonotonicLatchViolation
  else
    let mergedCves :=
      if cur.shieldLockedUntilReboot then unionDedup next.unpatchedCveIds cur.unpatchedCveIds
      else next.unpatchedCveIds
    let mergedKevs :=
      if cur.shieldLockedUntilReboot then unionDedup next.cisaKevIds cur.cisaKevIds
      else next.cisaKevIds
    let mergedSurfaces :=
      if cur.shieldLockedUntilReboot then unionDedup next.affectedSurfaces cur.affectedSurfaces
      else next.affectedSurfaces
    let locked := cur.shieldLockedUntilReboot || next.shieldLockedUntilReboot
    let tampered := (cur.shieldLockedUntilReboot && cur.integrityTampered) || next.integrityTampered
    let kernel :=
      if cur.shieldLockedUntilReboot && next.runningKernel.isEmpty then cur.runningKernel
      else next.runningKernel
    let prelim : KernelShieldPosture :=
      { next with
        unpatchedCveIds := mergedCves
        cisaKevIds := mergedKevs
        affectedSurfaces := mergedSurfaces
        shieldLockedUntilReboot := locked
        integrityTampered := tampered
        runningKernel := kernel
        monotonicRevision := cur.monotonicRevision + 1 }
    let withBase :=
      if prelim.isShieldActive then
        { prelim with affectedSurfaces := unionDedup prelim.affectedSurfaces baselineProactiveSurfaces }
      else
        prelim
    .ok (finalizePosture withBase)

/-- Mirror of `VirtualPatchShieldStore::confirm_reboot_cleared` (`virtual_patch_shield.rs:557-590`). -/
def confirmRebootCleared
    (cur : KernelShieldPosture)
    (newKernel : String)
    (rebootStillPending : Bool) : Except ShieldError KernelShieldPosture :=
  if rebootStillPending then
    .error .RebootStillPending
  else if newKernel.isEmpty then
    .error .EmptyKernelRelease
  else if cur.shieldLockedUntilReboot && !cur.runningKernel.isEmpty && cur.runningKernel == newKernel then
    .error .KernelVersionUnchanged
  else
    .ok (finalizePosture
      { cur with
        rebootPending := false
        shieldLockedUntilReboot := false
        integrityTampered := false
        runningKernel := newKernel
        monotonicRevision := cur.monotonicRevision + 1 })

inductive ShieldApplyTrace : KernelShieldPosture → KernelShieldPosture → Prop where
  | refl (p : KernelShieldPosture) : ShieldApplyTrace p p
  | step {p0 p1 p2 : KernelShieldPosture} (next : KernelShieldPosture) :
      ShieldApplyTrace p0 p1 → applyPosture p1 next = .ok p2 → ShieldApplyTrace p0 p2

private theorem finalizePosture_preserves_and_latches (p : KernelShieldPosture) :
    (finalizePosture p).unpatchedCveIds = p.unpatchedCveIds ∧
    (finalizePosture p).cisaKevIds = p.cisaKevIds ∧
    (finalizePosture p).affectedSurfaces = p.affectedSurfaces ∧
    (finalizePosture p).integrityTampered = p.integrityTampered ∧
    (finalizePosture p).monotonicRevision = p.monotonicRevision ∧
    (p.shieldLockedUntilReboot = true → (finalizePosture p).shieldLockedUntilReboot = true) ∧
    (((p.rebootPending && !p.livepatchActive) || p.integrityTampered) = true →
      (finalizePosture p).shieldLockedUntilReboot = true ∧
      (finalizePosture p).isShieldActive = true) := by
  unfold finalizePosture KernelShieldPosture.isShieldActive KernelShieldPosture.isShieldActiveWithDegraded
  refine ⟨rfl, rfl, rfl, rfl, rfl, ?_, ?_⟩
  · intro h; simp [h]
  · intro h
    simp only [Bool.or_eq_true] at h ⊢
    rcases h with h1 | h2
    · simp [h1]
    · simp [h2]

/-- **Theorem 4 (`shield_latch_monotonic`)**:
    1. `finalizePosture` latches `shieldLockedUntilReboot = true` whenever
       `(rebootPending && !livepatchActive) || integrityTampered`.
    2. `applyPosture` strictly advances `monotonicRevision`, and once `shieldLockedUntilReboot = true`,
       preserves the latch (`true`), preserves `integrityTampered`, keeps the shield active, and
       monotonically preserves all tracked CVEs, CISA KEVs, and affected kernel surfaces.
    3. Multi-step `ShieldApplyTrace` preserves the latch, `integrityTampered`, and shield activity
       forever until a valid reboot.
    4. `confirmRebootCleared` fails closed whenever `rebootStillPending = true`, `newKernel = ""`,
       or the kernel version matches the locked pre-reboot kernel. -/
theorem shield_latch_monotonic
    (p cur next out : KernelShieldPosture)
    (newKernel : String)
    (rebootStillPending : Bool) :
    (((p.rebootPending && !p.livepatchActive) || p.integrityTampered) = true →
      (finalizePosture p).shieldLockedUntilReboot = true ∧
      (finalizePosture p).isShieldActive = true) ∧
    (applyPosture cur next = .ok out →
      cur.monotonicRevision < out.monotonicRevision ∧
      (cur.shieldLockedUntilReboot = true →
        out.shieldLockedUntilReboot = true ∧
        (cur.integrityTampered = true → out.integrityTampered = true) ∧
        out.isShieldActiveWithDegraded false = true ∧
        (∀ c ∈ cur.unpatchedCveIds, c ∈ out.unpatchedCveIds) ∧
        (∀ k ∈ cur.cisaKevIds, k ∈ out.cisaKevIds) ∧
        (∀ s ∈ cur.affectedSurfaces, s ∈ out.affectedSurfaces))) ∧
    (∀ p0 pN : KernelShieldPosture,
      ShieldApplyTrace p0 pN →
      p0.monotonicRevision ≤ pN.monotonicRevision ∧
      (p0.shieldLockedUntilReboot = true →
        pN.shieldLockedUntilReboot = true ∧
        (p0.integrityTampered = true → pN.integrityTampered = true) ∧
        pN.isShieldActiveWithDegraded false = true)) ∧
    ((rebootStillPending = true ∨ newKernel.isEmpty = true ∨
      (cur.shieldLockedUntilReboot = true ∧ cur.runningKernel.isEmpty = false ∧ cur.runningKernel = newKernel)) →
      ∃ e : ShieldError, confirmRebootCleared cur newKernel rebootStillPending = .error e) := by
  have hSingle :
      ∀ (c n o : KernelShieldPosture),
        applyPosture c n = .ok o →
        c.monotonicRevision < o.monotonicRevision ∧
        (c.shieldLockedUntilReboot = true →
          o.shieldLockedUntilReboot = true ∧
          (c.integrityTampered = true → o.integrityTampered = true) ∧
          o.isShieldActiveWithDegraded false = true ∧
          (∀ x ∈ c.unpatchedCveIds, x ∈ o.unpatchedCveIds) ∧
          (∀ k ∈ c.cisaKevIds, k ∈ o.cisaKevIds) ∧
          (∀ s ∈ c.affectedSurfaces, s ∈ o.affectedSurfaces)) := by
    intro c n o hApp
    unfold applyPosture at hApp
    by_cases hVio : (c.shieldLockedUntilReboot && !n.shieldLockedUntilReboot) = true
    · simp only [eq_true hVio, ite_true] at hApp; cases hApp
    · simp only [eq_false hVio, ite_false] at hApp
      injection hApp with hOutEq
      let prelim : KernelShieldPosture :=
        { n with
          unpatchedCveIds :=
            if c.shieldLockedUntilReboot then unionDedup n.unpatchedCveIds c.unpatchedCveIds else n.unpatchedCveIds
          cisaKevIds :=
            if c.shieldLockedUntilReboot then unionDedup n.cisaKevIds c.cisaKevIds else n.cisaKevIds
          affectedSurfaces :=
            if c.shieldLockedUntilReboot then unionDedup n.affectedSurfaces c.affectedSurfaces else n.affectedSurfaces
          shieldLockedUntilReboot := c.shieldLockedUntilReboot || n.shieldLockedUntilReboot
          integrityTampered := (c.shieldLockedUntilReboot && c.integrityTampered) || n.integrityTampered
          runningKernel := if c.shieldLockedUntilReboot && n.runningKernel.isEmpty then c.runningKernel else n.runningKernel
          monotonicRevision := c.monotonicRevision + 1 }
      let withBase : KernelShieldPosture :=
        if prelim.isShieldActive then
          { prelim with affectedSurfaces := unionDedup prelim.affectedSurfaces baselineProactiveSurfaces }
        else
          prelim
      have hOutDef : o = finalizePosture withBase := hOutEq.symm
      rw [hOutDef]
      have hFin := finalizePosture_preserves_and_latches withBase
      have hRev : c.monotonicRevision < (finalizePosture withBase).monotonicRevision := by
        rw [hFin.2.2.2.2.1]
        dsimp only [withBase]
        split <;> dsimp only [prelim] <;> omega
      refine ⟨hRev, ?_⟩
      intro hLock
      have hWithBaseLock : withBase.shieldLockedUntilReboot = true := by
        dsimp only [withBase]
        split <;> simp [prelim, hLock]
      have hFinLock : (finalizePosture withBase).shieldLockedUntilReboot = true :=
        hFin.2.2.2.2.2.1 hWithBaseLock
      have hDegFalse : (finalizePosture withBase).isShieldActiveWithDegraded false = true := by
        unfold KernelShieldPosture.isShieldActiveWithDegraded
        simp [hFinLock]
      refine ⟨hFinLock, ?_, hDegFalse, ?_, ?_, ?_⟩
      · intro hTamp
        rw [hFin.2.2.2.1]
        dsimp only [withBase]
        split <;> simp [prelim, hLock, hTamp]
      · intro x hx
        rw [hFin.1]
        have hIn := mem_unionDedup_right c.unpatchedCveIds n.unpatchedCveIds x hx
        dsimp only [withBase]
        split <;> simp [prelim, hLock, hIn]
      · intro k hk
        rw [hFin.2.1]
        have hIn := mem_unionDedup_right c.cisaKevIds n.cisaKevIds k hk
        dsimp only [withBase]
        split <;> simp [prelim, hLock, hIn]
      · intro s hs
        rw [hFin.2.2.1]
        have hIn := mem_unionDedup_right c.affectedSurfaces n.affectedSurfaces s hs
        dsimp only [withBase]
        split
        · apply mem_unionDedup_left baselineProactiveSurfaces
          simp [prelim, hLock, hIn]
        · simp [prelim, hLock, hIn]
  refine ⟨(finalizePosture_preserves_and_latches p).2.2.2.2.2.2, hSingle cur next out, ?_, ?_⟩
  · intro p0 pN hTr
    induction hTr with
    | refl =>
      refine ⟨Nat.le_refl _, ?_⟩
      intro hL
      refine ⟨hL, fun hT => hT, ?_⟩
      unfold KernelShieldPosture.isShieldActiveWithDegraded
      simp [hL]
    | step n _ hApp ih =>
      have hs := hSingle _ n _ hApp
      refine ⟨Nat.le_trans ih.1 (Nat.le_of_lt hs.1), ?_⟩
      intro hL0
      obtain ⟨hL1, hT1, _⟩ := ih.2 hL0
      obtain ⟨hL2, hT2, hAct2, _⟩ := hs.2 hL1
      exact ⟨hL2, fun hT0 => hT2 (hT1 hT0), hAct2⟩
  · intro hReject
    unfold confirmRebootCleared
    by_cases hPend : rebootStillPending = true
    · simp only [eq_true hPend, ite_true]; exact ⟨.RebootStillPending, rfl⟩
    · simp only [eq_false hPend, ite_false]
      by_cases hEmpty : newKernel.isEmpty = true
      · simp only [eq_true hEmpty, ite_true]; exact ⟨.EmptyKernelRelease, rfl⟩
      · simp only [eq_false hEmpty, ite_false]
        have hNe : newKernel ≠ "" := by
          intro hEq
          rw [hEq] at hEmpty
          simp at hEmpty
        rcases hReject with hP | hE | ⟨hLock, hNonEmpty, hSame⟩
        · exact absurd hP hPend
        · exact absurd hE hEmpty
        · simp [hLock, hSame, hNe]

/-! ### Part 5: Ring 4 Sentinel & `SEC-RING-01` (`sentinel.rs`, `sentinel_supervisor.rs`, `arm_ring.rs`) -/

/-- Exact 4-variant mirror of `SentinelSystemState` (`src/sentinel_ring/sentinel_supervisor.rs:31-40`). -/
inductive SentinelSystemState : Type where
  | Healthy
  | Degraded
  | Quarantined
  | Lockdown
  deriving DecidableEq, Repr, BEq

/-- Exact 5-variant mirror of `SentinelAction` (`sentinel.rs:28-39`, `sentinel_supervisor.rs:44-50`). -/
inductive SentinelAction : Type where
  | Continue
  | RevokeCapabilities
  | IsolateArm (armId : Nat)
  | TerminateArm (armId : Nat)
  | LockdownSystem
  deriving DecidableEq, Repr, BEq

structure SentinelObservation where
  armId : Nat
  generation : Nat
  workerAlive : Bool
  authorizationHealthy : Bool
  sandboxVerified : Bool
  unauthorizedEgressDetected : Bool
  supervisorHealthy : Bool
  terminationDeadlineExceeded : Bool
  proxyEnforcementIntact : Bool
  timestampSecs : Nat
  deriving DecidableEq, Repr

/-- Exact mirror of `sentinel::evaluate` (`src/containment_ring/sentinel.rs:97-122`). -/
def evaluateSentinel (obs : SentinelObservation) : SentinelAction :=
  if !obs.supervisorHealthy then
    .LockdownSystem
  else if !obs.authorizationHealthy || !obs.sandboxVerified || !obs.proxyEnforcementIntact then
    .LockdownSystem
  else if obs.terminationDeadlineExceeded && obs.workerAlive then
    .TerminateArm obs.armId
  else if obs.unauthorizedEgressDetected then
    .TerminateArm obs.armId
  else
    .Continue

structure SentinelSupervisorState where
  systemState : SentinelSystemState
  isLockedDown : Bool
  watchdogActive : Bool
  lastSequence : Nat
  lastUptimeMs : Nat
  deriving DecidableEq, Repr

/-- Exact mirror of `SentinelSupervisor::evaluate_observation` (`sentinel_supervisor.rs:337-404`). -/
def stepObservation
    (st : SentinelSupervisorState)
    (obs : SentinelObservation) : SentinelSupervisorState × SentinelAction :=
  match evaluateSentinel obs with
  | .LockdownSystem =>
    ({ st with systemState := .Lockdown, isLockedDown := true }, .LockdownSystem)
  | .TerminateArm armId =>
    if st.systemState == .Lockdown || st.isLockedDown then
      ({ st with systemState := .Lockdown, isLockedDown := true }, .TerminateArm armId)
    else if obs.terminationDeadlineExceeded && obs.workerAlive then
      ({ st with systemState := .Degraded }, .TerminateArm armId)
    else
      ({ st with systemState := .Quarantined }, .TerminateArm armId)
  | .IsolateArm armId =>
    if st.systemState == .Lockdown || st.isLockedDown then
      ({ st with systemState := .Lockdown, isLockedDown := true }, .IsolateArm armId)
    else
      ({ st with systemState := .Quarantined }, .IsolateArm armId)
  | .RevokeCapabilities => (st, .RevokeCapabilities)
  | .Continue => (st, .Continue)

/-- Exact mirror of `SentinelSupervisor::ingest_supervisor_heartbeat` (`sentinel_supervisor.rs:194-303`). -/
def stepHeartbeat
    (st : SentinelSupervisorState)
    (seq uptimeMs : Nat)
    (policyOk containmentOk hmacOk : Bool) : SentinelSupervisorState × Bool :=
  let valid :=
    decide (seq > st.lastSequence) &&
    decide (uptimeMs ≥ st.lastUptimeMs) &&
    policyOk &&
    containmentOk &&
    hmacOk
  if !valid then
    ({ st with systemState := .Lockdown, isLockedDown := true }, false)
  else
    let nextSys :=
      if st.systemState == .Lockdown || st.isLockedDown then .Lockdown else .Healthy
    ({ st with systemState := nextSys, lastSequence := seq, lastUptimeMs := uptimeMs }, true)

/-- Exact mirror of `SEC-RING-01` `ArmContainmentRing::verify_terminable_child_pid`
    (`src/containment_ring/arm_ring.rs:1368-1377`). -/
def verifyTerminableChildPid (pid selfPid : Nat) : Bool :=
  decide (pid > 4) && decide (pid ≠ selfPid)

/-- **Theorem 5 (`sentinel_fail_closed_lockdown`)**:
    1. Any global failure (`!supervisorHealthy`, `!authorizationHealthy`, `!sandboxVerified`, or
       `!proxyEnforcementIntact`) immediately yields `.LockdownSystem` and locks down the supervisor.
    2. When global checks hold, any zombie worker (`terminationDeadlineExceeded && workerAlive`) or
       `unauthorizedEgressDetected` triggers `.TerminateArm obs.armId` (never `.Continue`).
    3. `Lockdown` is absorbing across both `stepObservation` and `stepHeartbeat`.
    4. Any replay, clock rollback, digest mismatch, or invalid HMAC heartbeat forces `.Lockdown`.
    5. `SEC-RING-01`: `verifyTerminableChildPid pid selfPid = true ↔ pid > 4 ∧ pid ≠ selfPid`. -/
theorem sentinel_fail_closed_lockdown
    (st : SentinelSupervisorState)
    (obs : SentinelObservation)
    (seq uptimeMs pid selfPid : Nat)
    (policyOk containmentOk hmacOk : Bool) :
    ((obs.supervisorHealthy = false ∨
      obs.authorizationHealthy = false ∨
      obs.sandboxVerified = false ∨
      obs.proxyEnforcementIntact = false) →
      evaluateSentinel obs = .LockdownSystem ∧
      (stepObservation st obs).1.systemState = .Lockdown ∧
      (stepObservation st obs).1.isLockedDown = true) ∧
    ((obs.supervisorHealthy = true ∧
      obs.authorizationHealthy = true ∧
      obs.sandboxVerified = true ∧
      obs.proxyEnforcementIntact = true ∧
      ((obs.terminationDeadlineExceeded = true ∧ obs.workerAlive = true) ∨
       obs.unauthorizedEgressDetected = true)) →
      evaluateSentinel obs = .TerminateArm obs.armId ∧
      evaluateSentinel obs ≠ .Continue) ∧
    ((st.systemState = .Lockdown ∧ st.isLockedDown = true) →
      (stepObservation st obs).1.systemState = .Lockdown ∧
      (stepObservation st obs).1.isLockedDown = true ∧
      (stepHeartbeat st seq uptimeMs policyOk containmentOk hmacOk).1.systemState = .Lockdown ∧
      (stepHeartbeat st seq uptimeMs policyOk containmentOk hmacOk).1.isLockedDown = true) ∧
    ((seq ≤ st.lastSequence ∨ uptimeMs < st.lastUptimeMs ∨
      policyOk = false ∨ containmentOk = false ∨ hmacOk = false) →
      (stepHeartbeat st seq uptimeMs policyOk containmentOk hmacOk).1.systemState = .Lockdown ∧
      (stepHeartbeat st seq uptimeMs policyOk containmentOk hmacOk).1.isLockedDown = true ∧
      (stepHeartbeat st seq uptimeMs policyOk containmentOk hmacOk).2 = false) ∧
    (verifyTerminableChildPid pid selfPid = true ↔ pid > 4 ∧ pid ≠ selfPid) := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro hFail
    have hEval : evaluateSentinel obs = .LockdownSystem := by
      unfold evaluateSentinel
      rcases hFail with hSup | hAuth | hSbx | hPrx
      · simp [hSup]
      · cases hSup : obs.supervisorHealthy <;> simp [hAuth]
      · cases hSup : obs.supervisorHealthy <;> simp [hSbx]
      · cases hSup : obs.supervisorHealthy <;> simp [hPrx]
    refine ⟨hEval, ?_, ?_⟩ <;> simp [stepObservation, hEval]
  · rintro ⟨hSup, hAuth, hSbx, hPrx, hKill⟩
    have hEval : evaluateSentinel obs = .TerminateArm obs.armId := by
      unfold evaluateSentinel
      simp only [hSup, hAuth, hSbx, hPrx, Bool.not_true, Bool.false_or, Bool.false_eq_true, ite_false]
      rcases hKill with ⟨hT, hA⟩ | hEg
      · simp [hT, hA]
      · by_cases hZ : (obs.terminationDeadlineExceeded && obs.workerAlive) = true
        · simp [hZ]
        · simp [hZ, hEg]
    refine ⟨hEval, ?_⟩
    rw [hEval]
    intro hc
    cases hc
  · rintro ⟨hSys, hLock⟩
    refine ⟨?_, ?_, ?_, ?_⟩
    · unfold stepObservation
      cases evaluateSentinel obs <;> simp [hSys, hLock]
    · unfold stepObservation
      cases evaluateSentinel obs <;> simp [hSys, hLock]
    · unfold stepHeartbeat
      by_cases hv :
          (decide (seq > st.lastSequence) && decide (uptimeMs ≥ st.lastUptimeMs) &&
           policyOk && containmentOk && hmacOk) = true
      · simp [hv, hSys, hLock]
      · simp [hv]
    · unfold stepHeartbeat
      by_cases hv :
          (decide (seq > st.lastSequence) && decide (uptimeMs ≥ st.lastUptimeMs) &&
           policyOk && containmentOk && hmacOk) = true
      · simp [hv, hSys, hLock]
      · simp [hv]
  · intro hBad
    unfold stepHeartbeat
    have hNotV :
        (decide (seq > st.lastSequence) && decide (uptimeMs ≥ st.lastUptimeMs) &&
         policyOk && containmentOk && hmacOk) = false := by
      rcases hBad with hSeq | hUp | hPol | hCon | hMac
      · have hF : decide (seq > st.lastSequence) = false := decide_eq_false (Nat.not_lt_of_ge hSeq)
        simp [hF]
      · have hF : decide (uptimeMs ≥ st.lastUptimeMs) = false := decide_eq_false (Nat.not_le_of_gt hUp)
        simp [hF]
      · simp [hPol]
      · simp [hCon]
      · simp [hMac]
    simp [hNotV]
  · unfold verifyTerminableChildPid
    simp only [Bool.and_eq_true, decide_eq_true_eq]

/-! ### Non-Vacuity Witnesses (`rfl` / `decide`) -/

section NonVacuityWitnesses

private def witnessRootHandle : ConfinedHandleNode :=
  { name := "sandbox"
  , isReparsePoint := false
  , isDir := true
  , numLinks := 1
  , finalPathSegments := ["C:", "octopus", "sandbox"] }

private def witnessLeafHandle : ConfinedHandleNode :=
  { name := "report.json"
  , isReparsePoint := false
  , isDir := false
  , numLinks := 1
  , finalPathSegments := ["C:", "octopus", "sandbox", "report.json"] }

private def witnessValidPath : SandboxPathInput :=
  { rawTrimmed := "report.json"
  , components := [.normal "report.json"]
  , hasNull := false
  , hasColon := false
  , startsWithSlashOrBackslash := false
  , hasPercentTraversal := false
  , hasDotDot := false }

private def witnessTraversalPath : SandboxPathInput :=
  { rawTrimmed := "%2e%2e/secret.txt"
  , components := [.normal "%2e%2e", .normal "secret.txt"]
  , hasNull := false
  , hasColon := false
  , startsWithSlashOrBackslash := false
  , hasPercentTraversal := true
  , hasDotDot := false }

example :
    openConfined witnessRootHandle witnessValidPath [] witnessLeafHandle = .ok witnessLeafHandle := by
  rfl

example :
    openConfined witnessRootHandle witnessTraversalPath [] witnessLeafHandle =
      .error .TraversalBlocked := by
  rfl

-- Representative restricted SSRF targets: IMDS, Azure WireServer, CGNAT, RFC1918, ::1, IPv4-mapped IMDS
example :
    isRestrictedRebindingIp (.v4 ⟨169, 254, 169, 254⟩) = true ∧
    isRestrictedRebindingIp (.v4 ⟨168, 63, 129, 16⟩) = true ∧
    isRestrictedRebindingIp (.v4 ⟨100, 64, 0, 1⟩) = true ∧
    isRestrictedRebindingIp (.v4 ⟨192, 0, 0, 192⟩) = true ∧
    isRestrictedRebindingIp (.v6 ⟨0, 0, 0, 0, 0, 0, 0, 1⟩) = true ∧
    isRestrictedRebindingIp (.v6 ⟨0, 0, 0, 0, 0, 0xffff, 0xa9fe, 0xa9fe⟩) = true := by
  decide

-- TokenPosture + Pre-resume gate witnesses
private def witnessSafePolicy : WindowsConfinementPolicy :=
  { requireAppcontainer := true
  , createSuspendedBeforeJobAssign := true
  , killOnJobClose := true
  , activeProcessLimit := 1
  , maxMemoryBytes := 256 * 1024 * 1024
  , enforceUiLimits := true }

private def witnessSafeAttempt : ChildSpawnAttempt :=
  { createdSuspended := true
  , appcontainerBound := true
  , appcontainerSidMatches := true
  , assignedToJob := true
  , verifiedInJob := true
  , tokenPosture :=
      { elevated := false
      , integrityRid := INTEGRITY_MEDIUM
      , adminsEnabled := false
      , adminsDenyOnly := true
      , presentPrivileges := ["SeChangeNotifyPrivilege"]
      , enabledPrivileges := ["SeChangeNotifyPrivilege"] } }

example : tryResumeChild witnessSafePolicy witnessSafeAttempt = .Resumed := by
  rfl

example :
    tryResumeChild witnessSafePolicy
      { witnessSafeAttempt with
        tokenPosture := { witnessSafeAttempt.tokenPosture with integrityRid := INTEGRITY_HIGH } } =
      .TerminatedBeforeResume := by
  rfl

-- Shield latch & Sentinel witnesses
example :
    (finalizePosture { KernelShieldPosture.defaultFailClosed with rebootPending := true }).shieldLockedUntilReboot = true := by
  rfl

example :
    evaluateSentinel
      { armId := 3
      , generation := 1
      , workerAlive := true
      , authorizationHealthy := true
      , sandboxVerified := true
      , unauthorizedEgressDetected := false
      , supervisorHealthy := false
      , terminationDeadlineExceeded := false
      , proxyEnforcementIntact := true
      , timestampSecs := 42 } = .LockdownSystem := by
  rfl

end NonVacuityWitnesses

end AgentOctopusFormal
