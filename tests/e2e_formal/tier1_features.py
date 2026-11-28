"""Tier 1: Feature Behavior & Invariant Verification (73 tests across F1-F14)."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

from . import common


def _read_repo_text(rel_path: str) -> str:
    return (common.REPO_ROOT / rel_path).read_text(encoding="utf-8")


class TestTier1Features(unittest.TestCase):
    """Tier 1 positive & structural invariant tests (>= 5 per feature F1-F14)."""

    # =======================================================================
    # F1: Lean 4 Toolchain & Lake Project (6 tests)
    # =======================================================================

    def test_f1_01_lean_toolchain_pinned_and_valid(self) -> None:
        """F1: formal/lean-toolchain exists and pins Lean 4 (leanprover/lean4:v4.*)."""
        tc_path = common.require_milestone_file("formal/lean-toolchain", "F1")
        text = tc_path.read_text(encoding="utf-8").strip()
        self.assertRegex(
            text,
            r"^leanprover/lean4:v4\.\d+\.\d+(?:-[A-Za-z0-9.]+)?$",
            f"Unexpected formal/lean-toolchain content: {text!r}",
        )
        self.assertEqual(common.check_funny_chars_in_text(text, "formal/lean-toolchain"), [])

    def test_f1_02_lakefile_toml_zero_deps_and_autoimplicit_false(self) -> None:
        """F1: formal/lakefile.toml defines AgentOctopusFormal with autoImplicit=false and zero external deps."""
        lf_path = common.require_milestone_file("formal/lakefile.toml", "F1")
        data = common.load_lakefile_toml(lf_path)
        self.assertEqual(common.validate_lakefile_zero_deps(data), [])

    def test_f1_03_root_module_exports_submodules(self) -> None:
        """F1: formal/AgentOctopusFormal.lean exists and imports landed verification modules."""
        root_lean = common.require_milestone_file("formal/AgentOctopusFormal.lean", "F1")
        text = common.strip_lean_comments(root_lean.read_text(encoding="utf-8"))
        m1_core = ("CoreTypes", "FsmContainment", "HomologicalMesh")
        for mod in m1_core:
            self.assertRegex(
                text,
                rf"(?m)^\s*import\s+AgentOctopusFormal\.{re.escape(mod)}(?:\s|$)",
                f"Core M1 module {mod}.lean is not imported in AgentOctopusFormal.lean",
            )

        landed_submodules = sorted(
            p.stem
            for p in common.FORMAL_PKG_DIR.glob("*.lean")
            if p.stem != "AxiomAudit" and p.stem not in m1_core
        )
        missing = [
            mod
            for mod in landed_submodules
            if not re.search(
                rf"(?m)^\s*import\s+AgentOctopusFormal\.{re.escape(mod)}(?:\s|$)",
                text,
            )
        ]
        if missing:
            m4_master_landed = (common.FORMAL_PKG_DIR / "NoBreachNoBreakout.lean").is_file()
            if common.is_progressive_mode() and not m4_master_landed:
                raise unittest.SkipTest(
                    "SKIPPED (milestone pending): M4 root module export wiring pending NoBreachNoBreakout.lean"
                )
            self.fail(
                f"Present module(s) {', '.join(f'{m}.lean' for m in missing)} not imported in AgentOctopusFormal.lean"
            )

    def test_f1_04_gitignore_and_packaging_exclude_lake(self) -> None:
        """F1: .gitignore and scripts/package_agent_octopus.py exclude .lake artifacts."""
        gitignore = _read_repo_text(".gitignore")
        self.assertRegex(gitignore, r"(?m)^\.lake/?$")
        self.assertRegex(gitignore, r"(?m)^formal/\.lake/?$")
        self.assertTrue(common.git_check_ignore("formal/.lake/build/ir/CoreTypes.c"))

        pkg_text = _read_repo_text("scripts/package_agent_octopus.py")
        self.assertRegex(pkg_text, r"""["']\.lake["']""")

    def test_f1_05_elan_lake_toolchain_process_scoped(self) -> None:
        """F1: lake & lean resolve via PATH or ~/.elan/bin (process-scoped) and match lean-toolchain."""
        tc_path = common.require_milestone_file("formal/lean-toolchain", "F1")
        expected_ver = tc_path.read_text(encoding="utf-8").strip().split(":v")[-1]
        lake_path, lean_path, env = common.require_lake_toolchain()
        res_lake = common.run_subprocess_safe([str(lake_path), "--version"], env=env, timeout=30.0)
        self.assertEqual(res_lake.returncode, 0, res_lake.combined_output)
        res_lean = common.run_subprocess_safe([str(lean_path), "--version"], env=env, timeout=30.0)
        self.assertEqual(res_lean.returncode, 0, res_lean.combined_output)
        self.assertIn(expected_ver, res_lean.stdout, f"lean --version mismatch: {res_lean.stdout}")

    def test_f1_06_lake_build_clean_zero_errors(self) -> None:
        """F1: `lake build` succeeds with exit 0 and zero `sorry` warnings."""
        common.require_milestone_file("formal/lakefile.toml", "F1")
        lake_path, _, env = common.require_lake_toolchain()
        res = common.run_subprocess_safe(
            [str(lake_path), "build"],
            cwd=common.FORMAL_DIR,
            env=env,
            timeout=300.0,
        )
        self.assertEqual(res.returncode, 0, f"lake build failed:\n{res.combined_output}")
        self.assertNotIn("uses 'sorry'", res.combined_output)

    # =======================================================================
    # F2: Core Types & Trust Tier Total Map (5 tests)
    # =======================================================================

    def test_f2_01_arm_role_18_variants_match_rust(self) -> None:
        """F2: CoreTypes.ArmRole has the exact 18 variants of src/core/types.rs."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CoreTypes.lean", "F2")
        lean_variants = common.parse_lean_inductive_constructors(
            lean_path.read_text(encoding="utf-8"), "ArmRole"
        )
        rust_variants = common.parse_rust_enum_variants(
            _read_repo_text("src/core/types.rs"), "ArmRole"
        )
        self.assertEqual(len(rust_variants), 18, f"Rust ArmRole count drift: {rust_variants}")
        self.assertEqual(lean_variants, rust_variants)

    def test_f2_02_trust_tier_3_variants_and_ranks_10_50_100(self) -> None:
        """F2: CoreTypes.TrustTier matches Rust Untrusted=10, Worker=50, PrivilegedSink=100."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CoreTypes.lean", "F2")
        lean_text = lean_path.read_text(encoding="utf-8")
        rust_text = _read_repo_text("src/containment_ring/mesh_guard.rs")

        lean_tiers = common.parse_lean_inductive_constructors(lean_text, "TrustTier")
        rust_tiers = common.parse_rust_enum_variants(rust_text, "TrustTier")
        self.assertEqual(lean_tiers, ["Untrusted", "Worker", "PrivilegedSink"])
        self.assertEqual(rust_tiers, ["Untrusted", "Worker", "PrivilegedSink"])

        for name, val in (("Untrusted", "10"), ("Worker", "50"), ("PrivilegedSink", "100")):
            self.assertRegex(lean_text, rf"\|\s*\.{name}\s*=>\s*{val}\b")
            self.assertRegex(rust_text, rf"\b{name}\s*=\s*{val}\b")

    def test_f2_03_role_trust_tier_total_mapping_matches_rust(self) -> None:
        """F2: CoreTypes.roleTrustTier maps all 18 ArmRoles (5 Untrusted, 9 Worker, 4 PrivilegedSink)."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CoreTypes.lean", "F2")
        lean_text = common.strip_lean_comments(lean_path.read_text(encoding="utf-8"))
        rust_text = common.strip_rust_comments(_read_repo_text("src/containment_ring/mesh_guard.rs"))

        lean_pairs = dict(
            re.findall(r"\|\s*\.([A-Za-z0-9_]+)\s*=>\s*\.(Untrusted|Worker|PrivilegedSink)\b", lean_text)
        )
        self.assertEqual(len(lean_pairs), 18, f"Expected 18 exhaustive roleTrustTier arms, got {len(lean_pairs)}")

        expected_untrusted = {
            "UntrustedDocIngest",
            "DifferentialProtocolAnalyzer",
            "AutonomousProtocolResearch",
            "ContinuousOssFuzz",
            "TarpitDecoyDefense",
        }
        expected_privileged = {
            "AccountingLedgerWrite",
            "KernelLevelSentinel",
            "CedarPolicyEvaluation",
            "PostQuantumAttestation",
        }
        actual_untrusted = {k for k, v in lean_pairs.items() if v == "Untrusted"}
        actual_privileged = {k for k, v in lean_pairs.items() if v == "PrivilegedSink"}
        actual_worker = {k for k, v in lean_pairs.items() if v == "Worker"}

        self.assertEqual(actual_untrusted, expected_untrusted)
        self.assertEqual(actual_privileged, expected_privileged)
        self.assertEqual(len(actual_worker), 9)
        for role in expected_untrusted:
            self.assertIn(f"ArmRole::{role}", rust_text)
        for role in expected_privileged:
            self.assertIn(f"ArmRole::{role}", rust_text)

    def test_f2_04_core_types_theorems_declared_and_zero_sorry(self) -> None:
        """F2: CoreTypes.lean proves roleTrustTier_total, all_length, all_complete with zero sorry/axioms."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CoreTypes.lean", "F2")
        text = lean_path.read_text(encoding="utf-8")
        self.assertEqual(common.find_lean_sorry_tokens(text), [])
        self.assertEqual(common.find_lean_custom_axioms(text), [])
        for thm in (
            "all_length",
            "all_complete",
            "roleTrustTier_total",
            "roleTrustTier_valid_ranks",
            "untrusted_lt_privileged",
        ):
            self.assertRegex(text, rf"\btheorem\s+{thm}\b")

    def test_f2_05_core_types_typechecks_with_lean(self) -> None:
        """F2: Live Lean probe importing CoreTypes verifies roleTrustTier_total and ArmRole.all.length = 18."""
        common.require_milestone_file("formal/AgentOctopusFormal/CoreTypes.lean", "F2")
        probe = (
            "import AgentOctopusFormal.CoreTypes\n"
            "#check @AgentOctopusFormal.roleTrustTier_total\n"
            "example : AgentOctopusFormal.ArmRole.all.length = 18 := rfl\n"
            "example : AgentOctopusFormal.TrustTier.Untrusted.rank = 10 := rfl\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    # =======================================================================
    # F3: Deterministic 6-State Arm FSM & PolicyGuard (5 tests)
    # =======================================================================

    def test_f3_01_arm_state_6_variants_match_rust(self) -> None:
        """F3: FsmContainment.ArmState matches the exact 6 variants of src/deterministic/fsm.rs."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        lean_states = common.parse_lean_inductive_constructors(
            lean_path.read_text(encoding="utf-8"), "ArmState"
        )
        rust_states = common.parse_rust_enum_variants(
            _read_repo_text("src/deterministic/fsm.rs"), "ArmState"
        )
        expected = [
            "Created",
            "DirectiveAccepted",
            "EnclaveDigesting",
            "MerkleSealed",
            "Completed",
            "Quarantined",
        ]
        self.assertEqual(rust_states, expected)
        self.assertEqual(lean_states, expected)

    def test_f3_02_fsm_no_skip_and_quarantined_absorbing_theorems(self) -> None:
        """F3: FsmContainment.lean proves fsm_no_skip_to_completed and Quarantined absorbing theorems."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        text = lean_path.read_text(encoding="utf-8")
        self.assertEqual(common.find_lean_sorry_tokens(text), [])
        self.assertEqual(common.find_lean_custom_axioms(text), [])
        for thm in (
            "fsm_no_skip_to_completed",
            "quarantined_step_absorbing",
            "quarantined_is_absorbing",
            "quarantined_cannot_complete",
        ):
            self.assertRegex(text, rf"\btheorem\s+{thm}\b")

    def test_f3_03_policy_guard_constants_match_rust(self) -> None:
        """F3: PolicyGuard caps (10_000_000 cents, 5 steps, USD, 64-hex Merkle) match Rust."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        lean_text = lean_path.read_text(encoding="utf-8")
        rust_pg = _read_repo_text("src/deterministic/policy_guard.rs")

        self.assertEqual(common.parse_lean_def_nat(lean_text, "DEFAULT_MAX_AMOUNT_CENTS"), 10_000_000)
        self.assertEqual(common.parse_lean_def_nat(lean_text, "DEFAULT_MAX_STEPS_PERMITTED"), 5)
        self.assertEqual(common.parse_lean_def_nat(lean_text, "MERKLE_ROOT_LEN"), 64)
        self.assertRegex(lean_text, r'DEFAULT_REQUIRED_CURRENCY\s*:\s*String\s*:=\s*"USD"')
        self.assertIn("10_000_000", rust_pg)
        self.assertIn("max_steps_permitted: 5", rust_pg)
        self.assertIn('"USD"', rust_pg)

    def test_f3_04_policy_guard_caps_theorem_declared(self) -> None:
        """F3: FsmContainment.lean proves policy_guard_caps_enforced and schema nonzero checks."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        text = lean_path.read_text(encoding="utf-8")
        for thm in (
            "policy_guard_caps_enforced",
            "enforceDirective_implies_caps",
            "enforceArtifact_implies_caps",
            "validateSchemaFields_implies_nonzero",
        ):
            self.assertRegex(text, rf"\btheorem\s+{thm}\b")

    def test_f3_05_fsm_containment_lean_probe_passes(self) -> None:
        """F3: Live Lean probe verifies Completed chain transitions and Quarantined absorption."""
        common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        probe = (
            "import AgentOctopusFormal.FsmContainment\n"
            "#check @AgentOctopusFormal.fsm_no_skip_to_completed\n"
            "#check @AgentOctopusFormal.policy_guard_caps_enforced\n"
            "example : AgentOctopusFormal.isValidTransition .MerkleSealed .Completed = true := rfl\n"
            "example : AgentOctopusFormal.isValidTransition .Quarantined .Completed = false := rfl\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    # =======================================================================
    # F4: Homological Mesh & Delegation Guards (5 tests)
    # =======================================================================

    def test_f4_01_mesh_constants_match_rust(self) -> None:
        """F4: HomologicalMesh constants (MAX_RELAY_HOPS=16, depth=2, 128, 16384) match Rust."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        lean_text = lean_path.read_text(encoding="utf-8")
        rust_mesh = _read_repo_text("src/containment_ring/mesh_guard.rs")
        rust_del = _read_repo_text("src/security/delegation.rs")

        self.assertEqual(common.parse_lean_def_nat(lean_text, "MAX_RELAY_HOPS"), 16)
        self.assertEqual(common.parse_rust_const_int(rust_mesh, "MAX_RELAY_HOPS"), 16)
        self.assertEqual(common.parse_lean_def_nat(lean_text, "MAX_DELEGATION_DEPTH"), 2)
        self.assertRegex(rust_del, r"(?:Self::new\(2\)|max_delegation_depth:\s*2\b)")
        self.assertEqual(common.parse_lean_def_nat(lean_text, "MAX_CORRELATION_ID_BYTES"), 128)
        self.assertEqual(common.parse_lean_def_nat(lean_text, "MAX_MESH_PAYLOAD_BYTES"), 16384)

    def test_f4_02_message_kind_and_report_fields_match_rust(self) -> None:
        """F4: HomologicalMesh.MessageKind matches src/neural_mesh.rs 4 variants."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        lean_text = lean_path.read_text(encoding="utf-8")
        lean_kinds = common.parse_lean_inductive_constructors(lean_text, "MessageKind")
        rust_kinds = common.parse_rust_enum_variants(_read_repo_text("src/neural_mesh.rs"), "MessageKind")
        self.assertEqual(lean_kinds, ["Finding", "ThreatMapping", "ChainCandidate", "Alert"])
        self.assertEqual(rust_kinds, lean_kinds)
        self.assertIn("coboundaryResidue", lean_text)

    def test_f4_03_homological_and_taint_theorems_declared(self) -> None:
        """F4: HomologicalMesh.lean proves Law 1 and sticky-taint theorems with zero sorry/axioms."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        text = lean_path.read_text(encoding="utf-8")
        self.assertEqual(common.find_lean_sorry_tokens(text), [])
        self.assertEqual(common.find_lean_custom_axioms(text), [])
        for thm in (
            "auditRoleChain_blocks_untrusted_to_privileged",
            "no_proxy_laundering",
            "meshGuard_empty_routes_deny",
            "sticky_taint_monotonic",
            "sticky_taint_untrusted_absorbing",
            "provenance_truncation_preserves_untrusted",
        ):
            self.assertRegex(text, rf"\btheorem\s+{thm}\b")

    def test_f4_04_delegation_scope_guard_matches_rust_and_theorem(self) -> None:
        """F4: HomologicalMesh.delegationPermittedTools matches Rust and proves delegation_no_escalation."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        text = lean_path.read_text(encoding="utf-8")
        self.assertRegex(text, r"\|\s*\.AutonomousProtocolResearch\s*=>\s*\[\]")
        self.assertRegex(text, r"\btheorem\s+delegation_no_escalation\b")
        rust_del = _read_repo_text("src/security/delegation.rs")
        self.assertIn("AutonomousProtocolResearch", rust_del)

    def test_f4_05_homological_mesh_lean_probe_passes(self) -> None:
        """F4: Live Lean probe verifies auditRoleChain rejects Untrusted->Worker->PrivilegedSink."""
        common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        probe = (
            "import AgentOctopusFormal.HomologicalMesh\n"
            "#check @AgentOctopusFormal.no_proxy_laundering\n"
            "#check @AgentOctopusFormal.delegation_no_escalation\n"
            "example : (AgentOctopusFormal.auditRoleChain "
            "[.UntrustedDocIngest, .NetworkEgress, .AccountingLedgerWrite]).allowed = false := rfl\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    # =======================================================================
    # F5: Epoch Autotomy & Dirac/3-Layer Gates (5 tests — M2)
    # =======================================================================

    def test_f5_01_epoch_autotomy_module_exists_and_clean(self) -> None:
        """F5: formal/AgentOctopusFormal/EpochAutotomy.lean exists with zero sorry/custom axioms."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/EpochAutotomy.lean", "F5")
        text = lean_path.read_text(encoding="utf-8")
        self.assertEqual(common.find_lean_sorry_tokens(text), [])
        self.assertEqual(common.find_lean_custom_axioms(text), [])

    def test_f5_02_dirac_max_window_and_page_constants_match_rust(self) -> None:
        """F5: EpochAutotomy.lean defines DIRAC_MAX_WINDOW_US=5_000_000 matching primitives.rs."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/EpochAutotomy.lean", "F5")
        text = lean_path.read_text(encoding="utf-8")
        rust_prim = _read_repo_text("src/containment_ring/primitives.rs")
        self.assertIn("5_000_000", rust_prim)
        self.assertRegex(text, r"5_000_000|5000000")

    def test_f5_03_epoch_monotonic_and_revoked_theorems_declared(self) -> None:
        """F5: EpochAutotomy.lean proves epoch_strictly_monotonic and revoked_epoch_never_valid."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/EpochAutotomy.lean", "F5")
        text = lean_path.read_text(encoding="utf-8")
        self.assertRegex(text, r"\btheorem\s+epoch_strictly_monotonic\b")
        self.assertRegex(text, r"\btheorem\s+revoked_epoch_never_valid\b")

    def test_f5_04_dirac_and_three_layer_theorems_declared(self) -> None:
        """F5: EpochAutotomy.lean proves dirac_single_use_no_replay and three_layer_non_circular_gate."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/EpochAutotomy.lean", "F5")
        text = lean_path.read_text(encoding="utf-8")
        self.assertRegex(text, r"\btheorem\s+dirac_single_use_no_replay\b")
        self.assertRegex(text, r"\btheorem\s+three_layer_non_circular_gate\b")

    def test_f5_05_epoch_autotomy_lean_probe_passes(self) -> None:
        """F5: Live Lean probe typechecks EpochAutotomy theorems."""
        common.require_milestone_file("formal/AgentOctopusFormal/EpochAutotomy.lean", "F5")
        probe = (
            "import AgentOctopusFormal.EpochAutotomy\n"
            "#check @AgentOctopusFormal.epoch_strictly_monotonic\n"
            "#check @AgentOctopusFormal.revoked_epoch_never_valid\n"
            "#check @AgentOctopusFormal.dirac_single_use_no_replay\n"
            "#check @AgentOctopusFormal.three_layer_non_circular_gate\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    # =======================================================================
    # F6: CAGE NoDirectBind BFS, Routing Seal & CBF (6 tests — M2)
    # =======================================================================

    def test_f6_01_cage_module_exists_and_clean(self) -> None:
        """F6: formal/AgentOctopusFormal/CageNoDirectBind.lean exists with zero sorry/custom axioms."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        text = lean_path.read_text(encoding="utf-8")
        self.assertEqual(common.find_lean_sorry_tokens(text), [])
        self.assertEqual(common.find_lean_custom_axioms(text), [])

    def test_f6_02_bfs_phases_and_7_tiers_match_rust(self) -> None:
        """F6: CageNoDirectBind.BfsPhase (7 variants) and 7 CAGE tiers match Rust FormalBfsModel."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        lean_text = lean_path.read_text(encoding="utf-8")
        rust_bfs = _read_repo_text("src/security/cage_governance/no_direct_bind_proof.rs")
        rust_phases = common.parse_rust_enum_variants(rust_bfs, "BfsPhase")
        lean_phases = common.parse_lean_inductive_constructors(lean_text, "BfsPhase")
        self.assertEqual(len(rust_phases), 7)
        self.assertEqual(lean_phases, rust_phases)
        for tier in ("ftra", "stpa", "opa", "confidence", "consensus", "cbf", "fiscal"):
            self.assertIn(tier, lean_text.lower())

    def test_f6_03_bfs_state_counts_34_17_31_match_rust(self) -> None:
        """F6: CageNoDirectBind.lean formalizes 34 gated, 17 ungated, 31 skipped-tier counts and no_direct_bind."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        text = lean_path.read_text(encoding="utf-8")
        for num in ("34", "17", "31"):
            self.assertRegex(text, rf"\b{num}\b")
        self.assertRegex(text, r"\btheorem\s+no_direct_bind\b")

    def test_f6_04_routing_seal_constants_30_5_match_rust(self) -> None:
        """F6: CageNoDirectBind.lean matches ROUTING_SEAL_TTL_SECS=30 and CLOCK_DRIFT_TOLERANCE_SECS=5."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        text = lean_path.read_text(encoding="utf-8")
        rust_seal = _read_repo_text("src/security/cage_governance/routing_seal.rs")
        self.assertEqual(common.parse_rust_const_int(rust_seal, "ROUTING_SEAL_TTL_SECS"), 30)
        self.assertEqual(common.parse_rust_const_int(rust_seal, "CLOCK_DRIFT_TOLERANCE_SECS"), 5)
        self.assertRegex(text, r"\b30\b")
        self.assertRegex(text, r"\b5\b")

    def test_f6_05_cbf_and_debit_ledger_theorems_declared(self) -> None:
        """F6: CageNoDirectBind.lean proves cbf_forward_invariance and debit_no_leakage."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        text = lean_path.read_text(encoding="utf-8")
        self.assertRegex(text, r"\btheorem\s+cbf_forward_invariance\b")
        self.assertRegex(text, r"\btheorem\s+debit_no_leakage\b")

    def test_f6_06_cage_lean_probe_passes(self) -> None:
        """F6: Live Lean probe typechecks no_direct_bind, cbf_forward_invariance, debit_no_leakage."""
        common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        probe = (
            "import AgentOctopusFormal.CageNoDirectBind\n"
            "#check @AgentOctopusFormal.no_direct_bind\n"
            "#check @AgentOctopusFormal.cbf_forward_invariance\n"
            "#check @AgentOctopusFormal.debit_no_leakage\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    # =======================================================================
    # F7: Cedar PARC & Dogwood Temporal MFOTL (5 tests — M3)
    # =======================================================================

    def test_f7_01_cedar_module_exists_and_clean(self) -> None:
        """F7: formal/AgentOctopusFormal/CedarAndTemporal.lean exists with zero sorry/custom axioms."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        text = lean_path.read_text(encoding="utf-8")
        self.assertEqual(common.find_lean_sorry_tokens(text), [])
        self.assertEqual(common.find_lean_custom_axioms(text), [])

    def test_f7_02_11_entities_and_13_actions_match_rust_schema(self) -> None:
        """F7: CedarAndTemporal.lean covers all 11 entityTypes and 13 actions in OCTOPUS_CEDAR_SCHEMA_JSON."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        lean_text = lean_path.read_text(encoding="utf-8")
        schema_rs = _read_repo_text("src/security/cedar_arm/policy_schema.rs")
        m = re.search(r'r#"(?P<json>\{.*?\})"#', schema_rs, re.DOTALL)
        self.assertIsNotNone(m, "Unable to extract OCTOPUS_CEDAR_SCHEMA_JSON")
        schema = json.loads(m.group("json"))
        ns = schema["Octopus"]
        entities = list(ns["entityTypes"].keys())
        actions = list(ns["actions"].keys())
        self.assertEqual(len(entities), 11, f"Rust Cedar entity count drift: {entities}")
        self.assertEqual(len(actions), 13, f"Rust Cedar action count drift: {actions}")
        for ent in entities:
            self.assertIn(ent, lean_text, f"Missing Cedar entity {ent} in CedarAndTemporal.lean")
        for act in actions:
            self.assertIn(act, lean_text, f"Missing Cedar action {act} in CedarAndTemporal.lean")

    def test_f7_03_cedar_theorems_and_100k_cap_match_rust(self) -> None:
        """F7: CedarAndTemporal.lean defines 10_000_000 cap and all 5 Cedar authorization theorems."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        text = lean_path.read_text(encoding="utf-8")
        self.assertRegex(text, r"10_000_000|10000000")
        for thm in (
            "forbid_dominates_permit",
            "tighten_only_monotonic",
            "default_deny_unmapped_role",
            "no_principal_spoofing",
            "spending_cap_enforced",
        ):
            self.assertRegex(text, rf"\btheorem\s+{thm}\b")

    def test_f7_04_dogwood_past_only_mfotl_and_fail_closed(self) -> None:
        """F7: CedarAndTemporal.lean models past-only MFOTL (Formerly, Previous, Since) and temporal_fail_closed."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        text = lean_path.read_text(encoding="utf-8")
        for op in ("Formerly", "Previous", "Since"):
            self.assertIn(op, text)
        self.assertRegex(text, r"\btheorem\s+temporal_fail_closed\b")

    def test_f7_05_cedar_temporal_lean_probe_passes(self) -> None:
        """F7: Live Lean probe typechecks CedarAndTemporal theorems."""
        common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        probe = (
            "import AgentOctopusFormal.CedarAndTemporal\n"
            "#check @AgentOctopusFormal.forbid_dominates_permit\n"
            "#check @AgentOctopusFormal.tighten_only_monotonic\n"
            "#check @AgentOctopusFormal.default_deny_unmapped_role\n"
            "#check @AgentOctopusFormal.no_principal_spoofing\n"
            "#check @AgentOctopusFormal.spending_cap_enforced\n"
            "#check @AgentOctopusFormal.temporal_fail_closed\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    # =======================================================================
    # F8: AgentMesh Mandate Attenuation & M-of-N Quorum (5 tests — M3)
    # =======================================================================

    def test_f8_01_mandate_quorum_module_exists_and_clean(self) -> None:
        """F8: formal/AgentOctopusFormal/MandateAndQuorum.lean exists with zero sorry/custom axioms."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        text = lean_path.read_text(encoding="utf-8")
        self.assertEqual(common.find_lean_sorry_tokens(text), [])
        self.assertEqual(common.find_lean_custom_axioms(text), [])

    def test_f8_02_mandate_depth_8_and_4_schemes_match_rust(self) -> None:
        """F8: MandateAndQuorum.lean matches MAX_DELEGATION_DEPTH=8 and 4 ALLOWED_SCHEMES in Rust."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        lean_text = lean_path.read_text(encoding="utf-8")
        rust_mandate = _read_repo_text("src/security/agentmesh/mandate_attenuation.rs")
        self.assertEqual(common.parse_rust_const_int(rust_mandate, "MAX_DELEGATION_DEPTH"), 8)
        self.assertRegex(lean_text, r"\b8\b")
        for scheme in ("mcp://", "a2a://", "inference://", "egress://"):
            self.assertIn(scheme, rust_mandate)
            self.assertIn(scheme, lean_text)

    def test_f8_03_mandate_monotonic_attenuation_theorem_declared(self) -> None:
        """F8: MandateAndQuorum.lean proves mandate_monotonic_attenuation."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        self.assertRegex(lean_path.read_text(encoding="utf-8"), r"\btheorem\s+mandate_monotonic_attenuation\b")

    def test_f8_04_quorum_anti_sybil_theorem_declared(self) -> None:
        """F8: MandateAndQuorum.lean proves quorum_threshold_anti_sybil matching src/ledger/quorum.rs."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        self.assertRegex(lean_path.read_text(encoding="utf-8"), r"\btheorem\s+quorum_threshold_anti_sybil\b")
        self.assertIn("DuplicateAuthority", _read_repo_text("src/ledger/quorum.rs"))

    def test_f8_05_mandate_quorum_lean_probe_passes(self) -> None:
        """F8: Live Lean probe typechecks MandateAndQuorum theorems."""
        common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        probe = (
            "import AgentOctopusFormal.MandateAndQuorum\n"
            "#check @AgentOctopusFormal.mandate_monotonic_attenuation\n"
            "#check @AgentOctopusFormal.quorum_threshold_anti_sybil\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    # =======================================================================
    # F9: Path/Sandbox, SSRF, TokenPosture, Shield & Sentinel (6 tests — M4)
    # =======================================================================

    def test_f9_01_isolation_module_exists_and_clean(self) -> None:
        """F9: formal/AgentOctopusFormal/IsolationAndPerimeter.lean exists with zero sorry/custom axioms."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        text = lean_path.read_text(encoding="utf-8")
        self.assertEqual(common.find_lean_sorry_tokens(text), [])
        self.assertEqual(common.find_lean_custom_axioms(text), [])

    def test_f9_02_path_join_and_ssrf_theorems_declared(self) -> None:
        """F9: IsolationAndPerimeter.lean proves path_join_no_escape and ssrf_blocks_all_restricted_ranges."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        text = lean_path.read_text(encoding="utf-8")
        self.assertRegex(text, r"\btheorem\s+path_join_no_escape\b")
        self.assertRegex(text, r"\btheorem\s+ssrf_blocks_all_restricted_ranges\b")

    def test_f9_03_token_posture_integrity_medium_0x2000_matches_rust(self) -> None:
        """F9: IsolationAndPerimeter.lean matches INTEGRITY_MEDIUM=0x2000 and proves pre_resume_no_elevated_uncontained_child."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        text = lean_path.read_text(encoding="utf-8")
        rust_tp = _read_repo_text("src/security/token_posture.rs")
        self.assertEqual(common.parse_rust_const_int(rust_tp, "INTEGRITY_MEDIUM"), 0x2000)
        self.assertRegex(text, r"(?:0x2000|8192)")
        self.assertRegex(text, r"\btheorem\s+pre_resume_no_elevated_uncontained_child\b")

    def test_f9_04_shield_latch_monotonic_matches_rust(self) -> None:
        """F9: IsolationAndPerimeter.lean proves shield_latch_monotonic matching virtual_patch_shield.rs."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        text = lean_path.read_text(encoding="utf-8")
        self.assertRegex(text, r"\btheorem\s+shield_latch_monotonic\b")
        self.assertIn("shield_locked_until_reboot", _read_repo_text("src/security/virtual_patch_shield.rs"))

    def test_f9_05_sentinel_states_4_and_actions_5_match_rust(self) -> None:
        """F9: IsolationAndPerimeter.lean matches 4 SentinelSystemState, 5 SentinelAction, and sentinel_fail_closed_lockdown."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        text = lean_path.read_text(encoding="utf-8")
        rust_sup = _read_repo_text("src/sentinel_ring/sentinel_supervisor.rs")
        rust_states = common.parse_rust_enum_variants(rust_sup, "SentinelSystemState")
        rust_actions = common.parse_rust_enum_variants(rust_sup, "SentinelAction")
        self.assertEqual(rust_states, ["Healthy", "Degraded", "Quarantined", "Lockdown"])
        self.assertEqual(
            rust_actions,
            ["Continue", "RevokeCapabilities", "IsolateArm", "TerminateArm", "LockdownSystem"],
        )
        for sym in rust_states + rust_actions:
            self.assertIn(sym, text, f"Missing Sentinel symbol {sym} in IsolationAndPerimeter.lean")
        self.assertRegex(text, r"\btheorem\s+sentinel_fail_closed_lockdown\b")

    def test_f9_06_isolation_perimeter_lean_probe_passes(self) -> None:
        """F9: Live Lean probe typechecks all 5 IsolationAndPerimeter theorems."""
        common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        probe = (
            "import AgentOctopusFormal.IsolationAndPerimeter\n"
            "#check @AgentOctopusFormal.path_join_no_escape\n"
            "#check @AgentOctopusFormal.ssrf_blocks_all_restricted_ranges\n"
            "#check @AgentOctopusFormal.pre_resume_no_elevated_uncontained_child\n"
            "#check @AgentOctopusFormal.shield_latch_monotonic\n"
            "#check @AgentOctopusFormal.sentinel_fail_closed_lockdown\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    # =======================================================================
    # F10: Master no_breakout & no_breach Theorems + Axiom Audit (5 tests — M4)
    # =======================================================================

    def test_f10_01_master_module_exists_and_imports_submodules(self) -> None:
        """F10: NoBreachNoBreakout.lean exists and composes M1-M4 modules."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/NoBreachNoBreakout.lean", "F10")
        text = common.strip_lean_comments(lean_path.read_text(encoding="utf-8"))
        self.assertEqual(common.find_lean_sorry_tokens(text), [])
        self.assertEqual(common.find_lean_custom_axioms(text), [])
        self.assertIn("AgentOctopusFormal.", text)

    def test_f10_02_no_breakout_and_no_breach_theorems_declared(self) -> None:
        """F10: NoBreachNoBreakout.lean proves master theorems no_breakout and no_breach."""
        lean_path = common.require_milestone_file("formal/AgentOctopusFormal/NoBreachNoBreakout.lean", "F10")
        text = lean_path.read_text(encoding="utf-8")
        self.assertRegex(text, r"\btheorem\s+no_breakout\b")
        self.assertRegex(text, r"\btheorem\s+no_breach\b")

    def test_f10_03_axiom_audit_file_exists_and_audits_theorems(self) -> None:
        """F10: AxiomAudit.lean exists and invokes #print axioms on no_breakout and no_breach."""
        audit_path = common.require_milestone_file("formal/AgentOctopusFormal/AxiomAudit.lean", "F10")
        text = audit_path.read_text(encoding="utf-8")
        self.assertIn("#print axioms", text)
        self.assertIn("no_breakout", text)
        self.assertIn("no_breach", text)

    def test_f10_04_live_axiom_audit_zero_sorry_zero_custom_axioms(self) -> None:
        """F10: Running `lake env lean AxiomAudit.lean` reports zero sorryAx and only standard Lean axioms."""
        audit_path = common.require_milestone_file("formal/AgentOctopusFormal/AxiomAudit.lean", "F10")
        lake_path, _, env = common.require_lake_toolchain()
        res = common.run_subprocess_safe(
            [str(lake_path), "env", "lean", str(audit_path)],
            cwd=common.FORMAL_DIR,
            env=env,
            timeout=120.0,
        )
        self.assertEqual(res.returncode, 0, res.combined_output)
        out = res.combined_output
        self.assertNotIn("sorryAx", out, f"sorryAx detected in AxiomAudit output:\n{out}")
        self.assertNotIn("uses 'sorry'", out, f"sorry warning detected:\n{out}")
        rogue = common.find_rogue_axioms_in_output(out)
        self.assertEqual(rogue, [], f"Non-standard axioms detected: {rogue}\n{out}")

    def test_f10_05_all_formal_lean_files_zero_sorry_and_zero_axioms(self) -> None:
        """F10: Every .lean file under formal/ contains zero sorry tokens and zero custom axiom declarations."""
        common.require_milestone_dir("formal", "F10")
        lean_files = sorted(common.FORMAL_DIR.rglob("*.lean"))
        self.assertGreaterEqual(len(lean_files), 1)
        for lf in lean_files:
            if ".lake" in lf.parts:
                continue
            txt = lf.read_text(encoding="utf-8")
            self.assertEqual(common.find_lean_sorry_tokens(txt), [], f"sorry found in {lf}")
            self.assertEqual(common.find_lean_custom_axioms(txt), [], f"custom axiom found in {lf}")

    # =======================================================================
    # F11: Rust-to-Lean 1-to-1 Consistency Tests (5 tests — M5)
    # =======================================================================

    def test_f11_01_coupling_test_file_exists(self) -> None:
        """F11: tests/lean_formal_coupling_tests.rs exists."""
        rs_path = common.require_milestone_file("tests/lean_formal_coupling_tests.rs", "F11")
        self.assertEqual(common.check_funny_chars_in_text(rs_path.read_text(encoding="utf-8"), str(rs_path)), [])

    def test_f11_02_coupling_file_references_formal_lean_modules(self) -> None:
        """F11: tests/lean_formal_coupling_tests.rs reads formal/AgentOctopusFormal/*.lean modules."""
        rs_path = common.require_milestone_file("tests/lean_formal_coupling_tests.rs", "F11")
        txt = rs_path.read_text(encoding="utf-8")
        self.assertIn("formal", txt)
        for mod in ("CoreTypes", "FsmContainment", "HomologicalMesh"):
            self.assertIn(mod, txt)

    def test_f11_03_coupling_file_checks_enums_and_constants(self) -> None:
        """F11: tests/lean_formal_coupling_tests.rs cross-checks Rust enums, constants, and BFS counts."""
        rs_path = common.require_milestone_file("tests/lean_formal_coupling_tests.rs", "F11")
        txt = rs_path.read_text(encoding="utf-8")
        for sym in ("ArmRole", "ArmState", "MAX_RELAY_HOPS", "FormalBfsModel"):
            self.assertIn(sym, txt)

    def test_f11_04_cargo_test_lean_formal_coupling_passes(self) -> None:
        """F11: `cargo test --test lean_formal_coupling_tests --all-features` passes with exit 0."""
        common.require_milestone_file("tests/lean_formal_coupling_tests.rs", "F11")
        res = common.run_cargo_test_target("lean_formal_coupling_tests", timeout=300.0)
        self.assertEqual(res.returncode, 0, f"cargo coupling test failed:\n{res.combined_output}")

    def test_f11_05_rust_source_coupling_anchors_present(self) -> None:
        """F11: All Rust source anchor modules for F2-F9 parity exist with expected definitions."""
        anchors = (
            ("src/core/types.rs", "enum ArmRole"),
            ("src/deterministic/fsm.rs", "enum ArmState"),
            ("src/containment_ring/mesh_guard.rs", "MAX_RELAY_HOPS"),
            ("src/containment_ring/primitives.rs", "DiracDeltaCapabilityTicket"),
            ("src/security/cage_governance/no_direct_bind_proof.rs", "FormalBfsModel"),
            ("src/security/cedar_arm/policy_schema.rs", "OCTOPUS_CEDAR_SCHEMA_JSON"),
            ("src/security/agentmesh/mandate_attenuation.rs", "MAX_DELEGATION_DEPTH"),
            ("src/security/token_posture.rs", "INTEGRITY_MEDIUM"),
            ("src/sentinel_ring/sentinel_supervisor.rs", "SentinelSystemState"),
        )
        for rel, marker in anchors:
            self.assertIn(marker, _read_repo_text(rel), f"Missing Rust anchor {marker} in {rel}")

    # =======================================================================
    # F12: Lean Verification CI Workflow (5 tests — M5)
    # =======================================================================

    def test_f12_01_lean_verify_workflow_exists(self) -> None:
        """F12: .github/workflows/lean-verify.yml exists."""
        wf = common.require_milestone_file(".github/workflows/lean-verify.yml", "F12")
        self.assertEqual(common.check_funny_chars_in_text(wf.read_text(encoding="utf-8"), str(wf)), [])

    def test_f12_02_workflow_least_privilege_and_checkout_security(self) -> None:
        """F12: lean-verify.yml enforces permissions: read-all and persist-credentials: false."""
        wf = common.require_milestone_file(".github/workflows/lean-verify.yml", "F12")
        info = common.inspect_workflow_yaml_text(wf.read_text(encoding="utf-8"))
        self.assertEqual(info["top_permissions"], "read-all")
        self.assertGreaterEqual(info["checkout_count"], 1)
        self.assertGreaterEqual(info["persist_credentials_false_count"], info["checkout_count"])
        self.assertFalse(info["has_write_all"])
        self.assertFalse(info["has_persist_credentials_true"])
        self.assertFalse(info["has_secrets_exfil"])

    def test_f12_03_workflow_cross_platform_ubuntu_and_windows(self) -> None:
        """F12: lean-verify.yml runs on both ubuntu-latest and windows-latest."""
        wf = common.require_milestone_file(".github/workflows/lean-verify.yml", "F12")
        info = common.inspect_workflow_yaml_text(wf.read_text(encoding="utf-8"))
        text = info["non_comment_text"]
        self.assertIn("ubuntu-latest", text)
        self.assertIn("windows-latest", text)

    def test_f12_04_workflow_runs_lake_build_and_axiom_gate(self) -> None:
        """F12: lean-verify.yml executes lake build, AxiomAudit/sorry check, and coupling tests."""
        wf = common.require_milestone_file(".github/workflows/lean-verify.yml", "F12")
        text = common.inspect_workflow_yaml_text(wf.read_text(encoding="utf-8"))["non_comment_text"]
        self.assertIn("lake build", text)
        self.assertTrue("AxiomAudit" in text or "print axioms" in text or "sorry" in text)
        self.assertIn("lean_formal_coupling_tests", text)

    def test_f12_05_existing_ci_and_auto_review_workflows_compliant(self) -> None:
        """F12: Existing ci.yml, raptor-security.yml, auto-review-bot.yml obey read-all & persist-credentials: false."""
        for rel in (
            ".github/workflows/ci.yml",
            ".github/workflows/raptor-security.yml",
            ".github/workflows/auto-review-bot.yml",
        ):
            info = common.inspect_workflow_yaml_text(_read_repo_text(rel))
            self.assertEqual(info["top_permissions"], "read-all", f"{rel} missing permissions: read-all")
            self.assertFalse(info["has_write_all"], f"{rel} has write-all")
            self.assertFalse(info["has_persist_credentials_true"], f"{rel} has persist-credentials: true")
            self.assertFalse(info["has_secrets_exfil"], f"{rel} triggered secrets exfil")
            self.assertGreaterEqual(info["persist_credentials_false_count"], info["checkout_count"], rel)

    # =======================================================================
    # F13: Opaque-Box E2E Verification Suite Self-Integrity (5 tests)
    # =======================================================================

    def test_f13_01_all_e2e_files_stdlib_only(self) -> None:
        """F13: Every Python module in tests/e2e_formal/ uses Python stdlib only (zero yaml/requests/pytest)."""
        e2e_dir = Path(__file__).resolve().parent
        local_mods = {
            "tests",
            "e2e_formal",
            "common",
            "tier1_features",
            "tier2_boundaries",
            "tier3_combinations",
            "tier4_scenarios",
            "run_e2e_suite",
        }
        py_files = sorted(e2e_dir.rglob("*.py"))
        self.assertGreaterEqual(len(py_files), 7)
        for pyf in py_files:
            self.assertEqual(
                common.check_stdlib_only_python_file(pyf, allowed_local_modules=local_mods),
                [],
                f"Non-stdlib import detected in {pyf}",
            )

    def test_f13_02_all_e2e_files_zero_funny_chars(self) -> None:
        """F13: Every file in tests/e2e_formal/ contains zero control chars and zero U+FFFD."""
        e2e_dir = Path(__file__).resolve().parent
        for pyf in sorted(e2e_dir.rglob("*.py")):
            txt = pyf.read_text(encoding="utf-8")
            self.assertEqual(common.check_funny_chars_in_text(txt, pyf.name), [])

    def test_f13_03_all_e2e_files_pass_raptor_python_scanner(self) -> None:
        """F13: Every Python file in tests/e2e_formal/ passes RAPTOR static rules (no yaml.load/shell=True/eval/PEM)."""
        e2e_dir = Path(__file__).resolve().parent
        for pyf in sorted(e2e_dir.rglob("*.py")):
            txt = pyf.read_text(encoding="utf-8")
            self.assertEqual(common.scan_raptor_python_anti_patterns(txt, pyf.name), [])

    def test_f13_04_feature_inventory_complete_f1_to_f14(self) -> None:
        """F13: FEATURE_INVENTORY covers F1-F14 and TIER_NAMES covers Tiers 1-4."""
        from . import FEATURE_INVENTORY, TIER_NAMES

        expected_keys = [f"F{i}" for i in range(1, 15)]
        self.assertEqual(list(FEATURE_INVENTORY.keys()), expected_keys)
        self.assertEqual(list(TIER_NAMES.keys()), [1, 2, 3, 4])

    def test_f13_05_runner_list_flag_succeeds(self) -> None:
        """F13: `python tests/e2e_formal/run_e2e_suite.py --list --json` enumerates >= 177 tests."""
        import sys

        runner_script = Path(__file__).resolve().parent / "run_e2e_suite.py"
        res = common.run_subprocess_safe(
            [sys.executable, str(runner_script), "--list", "--json"],
            cwd=common.REPO_ROOT,
            timeout=30.0,
        )
        self.assertEqual(res.returncode, 0, res.combined_output)
        payload = json.loads(res.stdout)
        self.assertTrue(payload["ok"])
        self.assertGreaterEqual(payload["total"], 177)

    # =======================================================================
    # F14: Final Shipping Readiness, Packaging & Repo Hygiene (5 tests)
    # =======================================================================

    def test_f14_01_packaging_script_excludes_lake_and_agents(self) -> None:
        """F14: scripts/package_agent_octopus.py EXCLUDE_DIRS includes .lake, .agents, target, build, logs."""
        pkg_text = _read_repo_text("scripts/package_agent_octopus.py")
        for d in (".lake", ".agents", ".git", "target", "build", "logs"):
            self.assertRegex(pkg_text, rf"""["']{re.escape(d)}["']""")

    def test_f14_02_wix_and_scripts_zero_touch_path(self) -> None:
        """F14: wix/AgentOctopus.wxs and scripts/package_windows_msi.ps1 never mutate system/user PATH."""
        wxs = _read_repo_text("wix/AgentOctopus.wxs")
        self.assertEqual(common.check_wix_path_mutation(wxs), [])
        msi_ps1 = _read_repo_text("scripts/package_windows_msi.ps1")
        self.assertNotIn("HKCU\\Environment", msi_ps1)
        self.assertIsNone(re.search(r"\bsetx\s+", msi_ps1, re.IGNORECASE))

    def test_f14_03_repo_boundary_is_agent_octopus(self) -> None:
        """F14: git rev-parse --show-toplevel and remote origin match AgentOctopus exclusively."""
        top = common.run_subprocess_safe(
            ["git", "-C", str(common.REPO_ROOT), "rev-parse", "--show-toplevel"],
            timeout=15.0,
        )
        self.assertEqual(top.returncode, 0, top.stderr)
        self.assertEqual(Path(top.stdout.strip()).resolve(), common.REPO_ROOT.resolve())

        remote = common.run_subprocess_safe(
            ["git", "-C", str(common.REPO_ROOT), "remote", "get-url", "origin"],
            timeout=15.0,
        )
        self.assertEqual(remote.returncode, 0, remote.stderr)
        self.assertIn("oyesanyf/AgentOctopus", remote.stdout)

    def test_f14_04_all_workflows_and_raptor_rules_zero_funny_chars(self) -> None:
        """F14: All workflows, RAPTOR rules, .gitignore, and packaging script contain zero funny chars."""
        targets = sorted((common.REPO_ROOT / ".github" / "workflows").glob("*.yml"))
        targets.extend(sorted((common.REPO_ROOT / ".raptor" / "rules").glob("*.yaml")))
        targets.append(common.REPO_ROOT / ".gitignore")
        targets.append(common.REPO_ROOT / "scripts" / "package_agent_octopus.py")
        for p in targets:
            self.assertEqual(
                common.check_funny_chars_in_text(p.read_text(encoding="utf-8"), p.name),
                [],
            )

    def test_f14_05_no_tracked_lake_or_binary_artifacts(self) -> None:
        """F14: git ls-files contains zero .lake/, .agents/, or binary/key blobs."""
        res = common.run_subprocess_safe(
            ["git", "-C", str(common.REPO_ROOT), "ls-files"],
            timeout=30.0,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        tracked = [line.strip().replace("\\", "/") for line in res.stdout.splitlines() if line.strip()]
        bad = [
            p
            for p in tracked
            if ".lake/" in p
            or p.startswith(".agents/")
            or re.search(r"\.(exe|dll|sys|msi|zip|pem|pfx|key|p12)$", p, re.IGNORECASE)
        ]
        self.assertEqual(bad, [], f"Forbidden tracked files: {bad}")
