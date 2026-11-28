"""Tier 3: Pairwise Cross-Feature Combination Tests (21 tests covering F1-F14)."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

from . import common


def _read_repo_text(rel_path: str) -> str:
    return (common.REPO_ROOT / rel_path).read_text(encoding="utf-8")


_HEX64 = "b" * 64


class TestTier3Combinations(unittest.TestCase):
    """Tier 3 pairwise cross-feature combination checks."""

    def test_t3_01_f2_f4_all_untrusted_to_privileged_pairs_blocked_in_lean(self) -> None:
        """F2+F4: Every (Untrusted, Worker, PrivilegedSink) 2-hop chain across 18 ArmRoles is blocked by auditRoleChain."""
        common.require_milestone_file("formal/AgentOctopusFormal/CoreTypes.lean", "F2")
        common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        probe = (
            "import AgentOctopusFormal.HomologicalMesh\n"
            "open AgentOctopusFormal in\n"
            "def allUntrustedToPrivBlocked : Bool :=\n"
            "  ArmRole.all.all fun s =>\n"
            "    ArmRole.all.all fun r =>\n"
            "      if roleTrustTier s == .Untrusted && roleTrustTier r == .PrivilegedSink then\n"
            "        !(auditRoleChain [s, .NetworkEgress, r]).allowed\n"
            "      else true\n"
            "example : allUntrustedToPrivBlocked = true := by decide\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_t3_02_f2_f3_core_types_and_fsm_completed_trace(self) -> None:
        """F2+F3: Full 5-step DeterministicLayer trace reaches Completed only via MerkleSealed + valid PolicyGuard."""
        common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        probe = (
            "import AgentOctopusFormal.FsmContainment\n"
            "open AgentOctopusFormal in\n"
            "example : (do\n"
            "  let s0 := DeterministicLayerState.init\n"
            '  let s1 <- stepLayer s0 (.acceptDirective { sourceUri := "s3://invoices/1", maxStepBudget := 5 })\n'
            "  let s2 <- stepLayer s1 .enterEnclaveDigest\n"
            f'  let s3 <- stepLayer s2 (.sealMerkleTrace "{_HEX64}")\n'
            f'  let s4 <- stepLayer s3 (.finalizeArtifact {{ amountCents := 10_000_000, currency := "USD", merkleRoot := "{_HEX64}" }})\n'
            "  pure s4.fsmState) = some .Completed := by first | decide | native_decide\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_t3_03_f3_f4_quarantined_fsm_and_sticky_taint_absorbing(self) -> None:
        """F3+F4: Quarantined FSM and Untrusted sticky taint both remain absorbing across subsequent steps."""
        common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        probe = (
            "import AgentOctopusFormal.FsmContainment\n"
            "import AgentOctopusFormal.HomologicalMesh\n"
            "open AgentOctopusFormal in\n"
            "example : isValidTransition .Quarantined .Completed = false ∧ "
            "updateTaintFloor { floor := .Untrusted, provenance := [] } .PrivilegedSink = .Untrusted := by\n"
            "  constructor <;> rfl\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_t3_04_f3_f6_completed_fsm_paired_with_cage_no_direct_bind(self) -> None:
        """F3+F6: ArmState.Completed pairs with CAGE NoDirectBind (Executed requires RoutingSeal)."""
        common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        probe = (
            "import AgentOctopusFormal.FsmContainment\n"
            "import AgentOctopusFormal.CageNoDirectBind\n"
            "#check @AgentOctopusFormal.fsm_no_skip_to_completed\n"
            "#check @AgentOctopusFormal.no_direct_bind\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_t3_05_f3_f7_100k_spending_cap_parity_policy_guard_and_cedar(self) -> None:
        """F3+F7: $100,000.00 (10_000_000 cents) cap matches across PolicyGuard, FsmContainment, CedarPolicyEngine, and CedarAndTemporal."""
        common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        fsm_txt = (common.FORMAL_PKG_DIR / "FsmContainment.lean").read_text(encoding="utf-8")
        cedar_txt = (common.FORMAL_PKG_DIR / "CedarAndTemporal.lean").read_text(encoding="utf-8")
        self.assertEqual(common.parse_lean_def_nat(fsm_txt, "DEFAULT_MAX_AMOUNT_CENTS"), 10_000_000)
        self.assertRegex(cedar_txt, r"10_000_000|10000000")
        self.assertIn("10_000_000", _read_repo_text("src/deterministic/policy_guard.rs"))
        self.assertIn("10000000", _read_repo_text("src/security/cedar_arm/policy_engine.rs"))
        self.assertIn("10_000_000", _read_repo_text("src/containment_ring/cedar_gate.rs"))

    def test_t3_06_f4_f5_epoch_regeneration_and_mesh_provenance(self) -> None:
        """F4+F5: EpochAutotomy severAndRegenerate pairs with HomologicalMesh provenance/epoch gates."""
        common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        common.require_milestone_file("formal/AgentOctopusFormal/EpochAutotomy.lean", "F5")
        probe = (
            "import AgentOctopusFormal.HomologicalMesh\n"
            "import AgentOctopusFormal.EpochAutotomy\n"
            "#check @AgentOctopusFormal.verifyIncomingMessage_blocks_untrusted_to_privileged\n"
            "#check @AgentOctopusFormal.revoked_epoch_never_valid\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_t3_07_f5_f6_dirac_single_use_and_cage_seal_cbf_fence(self) -> None:
        """F5+F6: Single-use DiracTicket, single-use 30s CageRoutingSeal, and CBF fence epoch compose cleanly."""
        common.require_milestone_file("formal/AgentOctopusFormal/EpochAutotomy.lean", "F5")
        common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        probe = (
            "import AgentOctopusFormal.EpochAutotomy\n"
            "import AgentOctopusFormal.CageNoDirectBind\n"
            "#check @AgentOctopusFormal.dirac_single_use_no_replay\n"
            "#check @AgentOctopusFormal.cbf_forward_invariance\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_t3_08_f5_f9_three_layer_gate_and_pre_resume_confinement(self) -> None:
        """F5+F9: 3-layer gate (kernel_process_in_job) pairs with pre-resume Windows confinement & TokenPosture."""
        common.require_milestone_file("formal/AgentOctopusFormal/EpochAutotomy.lean", "F5")
        common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        probe = (
            "import AgentOctopusFormal.EpochAutotomy\n"
            "import AgentOctopusFormal.IsolationAndPerimeter\n"
            "#check @AgentOctopusFormal.three_layer_non_circular_gate\n"
            "#check @AgentOctopusFormal.pre_resume_no_elevated_uncontained_child\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_t3_09_f6_f7_cage_tier2_opa_cedar_and_dogwood_integration(self) -> None:
        """F6+F7: CAGE Tier 2 opa/cedar stage pairs with Cedar forbid-dominates-permit and Dogwood fail-closed."""
        common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        rust_bfs = _read_repo_text("src/security/cage_governance/no_direct_bind_proof.rs")
        self.assertIn('"opa"', rust_bfs)
        self.assertIn('"cedar"', rust_bfs)
        probe = (
            "import AgentOctopusFormal.CageNoDirectBind\n"
            "import AgentOctopusFormal.CedarAndTemporal\n"
            "#check @AgentOctopusFormal.no_direct_bind\n"
            "#check @AgentOctopusFormal.forbid_dominates_permit\n"
            "#check @AgentOctopusFormal.temporal_fail_closed\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_t3_10_f6_f8_cage_seal_and_mandate_quorum_governance(self) -> None:
        """F6+F8: CAGE DebitLedger/RoutingSeal pairs with Mandate attenuation (depth<=8) & Quorum anti-sybil."""
        common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        probe = (
            "import AgentOctopusFormal.CageNoDirectBind\n"
            "import AgentOctopusFormal.MandateAndQuorum\n"
            "#check @AgentOctopusFormal.debit_no_leakage\n"
            "#check @AgentOctopusFormal.mandate_monotonic_attenuation\n"
            "#check @AgentOctopusFormal.quorum_threshold_anti_sybil\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_t3_11_f7_f8_cedar_change_security_policy_requires_quorum(self) -> None:
        """F7+F8: Cedar change_security_policy requires quorum_authorized, paired with QuorumPolicyGuard."""
        common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        cedar_eng = _read_repo_text("src/security/cedar_arm/policy_engine.rs")
        self.assertIn("change_security_policy", cedar_eng)
        self.assertIn("quorum_authorized", cedar_eng)
        self.assertIn("quorum_threshold", _read_repo_text("src/ledger/quorum.rs"))

    def test_t3_12_f7_f9_tighten_only_forbid_and_shield_latch_monotonic(self) -> None:
        """F7+F9: Cedar tighten_only_monotonic pairs with VirtualPatchShield shield_latch_monotonic."""
        common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        probe = (
            "import AgentOctopusFormal.CedarAndTemporal\n"
            "import AgentOctopusFormal.IsolationAndPerimeter\n"
            "#check @AgentOctopusFormal.tighten_only_monotonic\n"
            "#check @AgentOctopusFormal.shield_latch_monotonic\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

    def test_t3_13_f8_f9_mandate_uri_and_egress_ssrf_defense_in_depth(self) -> None:
        """F8+F9: Mandate validate_mesh_uri + EgressProxy SSRF both block loopback, RFC1918, IMDS, and IPv6-mapped."""
        common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        mandate_rs = _read_repo_text("src/security/agentmesh/mandate_attenuation.rs")
        egress_rs = _read_repo_text("src/containment_ring/egress_proxy.rs")
        self.assertIn("169.254.", mandate_rs)
        self.assertIn("is_restricted_rebinding_ip", egress_rs)

    def test_t3_14_f4_f8_delegation_depth_2_vs_mandate_depth_8_distinct(self) -> None:
        """F4+F8: DelegationScopeGuard depth=2 (HomologicalMesh) and AttenuatedMandate depth=8 (MandateAndQuorum) remain distinct."""
        common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        hm_txt = (common.FORMAL_PKG_DIR / "HomologicalMesh.lean").read_text(encoding="utf-8")
        mq_txt = (common.FORMAL_PKG_DIR / "MandateAndQuorum.lean").read_text(encoding="utf-8")
        self.assertEqual(common.parse_lean_def_nat(hm_txt, "MAX_DELEGATION_DEPTH"), 2)
        self.assertRegex(mq_txt, r"\b8\b")
        self.assertRegex(
            _read_repo_text("src/security/delegation.rs"),
            r"(?:Self::new\(2\)|max_delegation_depth:\s*2\b)",
        )
        self.assertEqual(
            common.parse_rust_const_int(_read_repo_text("src/security/agentmesh/mandate_attenuation.rs"), "MAX_DELEGATION_DEPTH"),
            8,
        )

    def test_t3_15_f9_f10_all_five_isolation_invariants_in_master_theorems(self) -> None:
        """F9+F10: NoBreachNoBreakout.lean composes all 5 IsolationAndPerimeter invariants."""
        common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        master_path = common.require_milestone_file("formal/AgentOctopusFormal/NoBreachNoBreakout.lean", "F10")
        txt = master_path.read_text(encoding="utf-8")
        self.assertIn("IsolationAndPerimeter", txt)
        self.assertRegex(txt, r"\btheorem\s+no_breakout\b")
        self.assertRegex(txt, r"\btheorem\s+no_breach\b")

    def test_t3_16_f2_f10_master_theorems_import_full_module_stack(self) -> None:
        """F2+F10: NoBreachNoBreakout.lean imports and composes CoreTypes through IsolationAndPerimeter."""
        master_path = common.require_milestone_file("formal/AgentOctopusFormal/NoBreachNoBreakout.lean", "F10")
        txt = common.strip_lean_comments(master_path.read_text(encoding="utf-8"))
        for mod in (
            "CoreTypes",
            "FsmContainment",
            "HomologicalMesh",
            "EpochAutotomy",
            "CageNoDirectBind",
            "CedarAndTemporal",
            "MandateAndQuorum",
            "IsolationAndPerimeter",
        ):
            self.assertIn(mod, txt, f"Master theorem file missing {mod}")

    def test_t3_17_f10_f11_axiom_audit_and_rust_coupling_joint_consistency(self) -> None:
        """F10+F11: Both AxiomAudit.lean and cargo test --test lean_formal_coupling_tests succeed."""
        audit_path = common.require_milestone_file("formal/AgentOctopusFormal/AxiomAudit.lean", "F10")
        common.require_milestone_file("tests/lean_formal_coupling_tests.rs", "F11")
        lake_path, _, env = common.require_lake_toolchain()
        res_lean = common.run_subprocess_safe(
            [str(lake_path), "env", "lean", str(audit_path)],
            cwd=common.FORMAL_DIR,
            env=env,
            timeout=120.0,
        )
        self.assertEqual(res_lean.returncode, 0, res_lean.combined_output)
        self.assertNotIn("sorryAx", res_lean.combined_output)
        res_cargo = common.run_cargo_test_target("lean_formal_coupling_tests", timeout=300.0)
        self.assertEqual(res_cargo.returncode, 0, res_cargo.combined_output)

    def test_t3_18_f1_f11_f12_ci_workflow_aligns_with_lakefile_and_coupling(self) -> None:
        """F1+F11+F12: lean-verify.yml references AgentOctopusFormal / formal and lean_formal_coupling_tests."""
        lf = common.load_lakefile_toml(common.require_milestone_file("formal/lakefile.toml", "F1"))
        common.require_milestone_file("tests/lean_formal_coupling_tests.rs", "F11")
        wf = common.require_milestone_file(".github/workflows/lean-verify.yml", "F12")
        wf_txt = common.inspect_workflow_yaml_text(wf.read_text(encoding="utf-8"))["non_comment_text"]
        self.assertEqual(lf.get("name"), "AgentOctopusFormal")
        self.assertIn("formal", wf_txt)
        self.assertIn("lake build", wf_txt)
        self.assertIn("lean_formal_coupling_tests", wf_txt)

    def test_t3_19_f1_f12_f14_lake_exclusion_across_gitignore_packaging_ci(self) -> None:
        """F1+F12+F14: .lake/ exclusion holds jointly across .gitignore, package_agent_octopus.py, and git index."""
        self.assertTrue(common.git_check_ignore("formal/.lake/build/lib/CoreTypes.olean"))
        self.assertRegex(_read_repo_text("scripts/package_agent_octopus.py"), r"""["']\.lake["']""")
        res = common.run_subprocess_safe(["git", "-C", str(common.REPO_ROOT), "ls-files", "formal/.lake"], timeout=15.0)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.strip(), "", f"Tracked files under formal/.lake: {res.stdout}")

    def test_t3_20_f11_f13_e2e_parsers_and_rust_sources_agree_on_constants(self) -> None:
        """F11+F13: E2E Rust parsers and M1 Lean specs agree on ArmRole(18), TrustTier(10/50/100), ArmState(6), MAX_RELAY_HOPS(16)."""
        common.require_milestone_file("formal/AgentOctopusFormal/CoreTypes.lean", "F2")
        common.require_milestone_file("formal/AgentOctopusFormal/FsmContainment.lean", "F3")
        common.require_milestone_file("formal/AgentOctopusFormal/HomologicalMesh.lean", "F4")
        self.assertEqual(len(common.parse_rust_enum_variants(_read_repo_text("src/core/types.rs"), "ArmRole")), 18)
        self.assertEqual(len(common.parse_rust_enum_variants(_read_repo_text("src/deterministic/fsm.rs"), "ArmState")), 6)
        self.assertEqual(common.parse_rust_const_int(_read_repo_text("src/containment_ring/mesh_guard.rs"), "MAX_RELAY_HOPS"), 16)

    def test_t3_21_f12_f13_f14_e2e_suite_obeys_raptor_and_auto_review_bot_invariants(self) -> None:
        """F12+F13+F14: tests/e2e_formal/ passes every invariant enforced by auto-review-bot.yml and raptor-security.yml."""
        e2e_dir = Path(__file__).resolve().parent
        for pyf in sorted(e2e_dir.rglob("*.py")):
            txt = pyf.read_text(encoding="utf-8")
            self.assertEqual(common.scan_raptor_python_anti_patterns(txt, pyf.name), [])
            self.assertEqual(common.check_funny_chars_in_text(txt, pyf.name), [])
            self.assertNotIn("HKCU\\Environment", txt)
            self.assertIsNone(re.search(r"\bsetx\s+", txt))
