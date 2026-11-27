"""Tier 4: Realistic End-to-End Scenarios (7 scenarios matching TEST_INFRA.md)."""

from __future__ import annotations

import re
import unittest

from . import common


def _read_repo_text(rel_path: str) -> str:
    return (common.REPO_ROOT / rel_path).read_text(encoding="utf-8")


class TestTier4Scenarios(unittest.TestCase):
    """Tier 4 end-to-end verification scenarios."""

    def test_t4_01_full_formal_verification_cold_build_and_axiom_audit(self) -> None:
        """Scenario 1 (F1-F10): Complete lake build, AxiomAudit #print axioms, and repo-wide zero-sorry scan."""
        required_modules = (
            "formal/lean-toolchain",
            "formal/lakefile.toml",
            "formal/AgentOctopusFormal.lean",
            "formal/AgentOctopusFormal/CoreTypes.lean",
            "formal/AgentOctopusFormal/FsmContainment.lean",
            "formal/AgentOctopusFormal/HomologicalMesh.lean",
            "formal/AgentOctopusFormal/EpochAutotomy.lean",
            "formal/AgentOctopusFormal/CageNoDirectBind.lean",
            "formal/AgentOctopusFormal/CedarAndTemporal.lean",
            "formal/AgentOctopusFormal/MandateAndQuorum.lean",
            "formal/AgentOctopusFormal/IsolationAndPerimeter.lean",
            "formal/AgentOctopusFormal/NoBreachNoBreakout.lean",
            "formal/AgentOctopusFormal/AxiomAudit.lean",
        )
        for rel in required_modules:
            common.require_milestone_file(rel, "Scenario1")

        lake_path, _, env = common.require_lake_toolchain()
        build_res = common.run_subprocess_safe(
            [str(lake_path), "build"],
            cwd=common.FORMAL_DIR,
            env=env,
            timeout=300.0,
        )
        self.assertEqual(build_res.returncode, 0, f"lake build failed:\n{build_res.combined_output}")
        self.assertNotIn("uses 'sorry'", build_res.combined_output)

        audit_res = common.run_subprocess_safe(
            [str(lake_path), "env", "lean", str(common.FORMAL_PKG_DIR / "AxiomAudit.lean")],
            cwd=common.FORMAL_DIR,
            env=env,
            timeout=120.0,
        )
        self.assertEqual(audit_res.returncode, 0, audit_res.combined_output)
        self.assertNotIn("sorryAx", audit_res.combined_output)
        rogue = common.find_rogue_axioms_in_output(audit_res.combined_output)
        self.assertEqual(rogue, [], f"Custom axioms detected:\n{audit_res.combined_output}")

        for lf in sorted(common.FORMAL_DIR.rglob("*.lean")):
            if ".lake" in lf.parts:
                continue
            txt = lf.read_text(encoding="utf-8")
            self.assertEqual(common.find_lean_sorry_tokens(txt), [], f"sorry in {lf}")
            self.assertEqual(common.find_lean_custom_axioms(txt), [], f"custom axiom in {lf}")

    def test_t4_02_multi_ring_breakout_attempt_simulation(self) -> None:
        """Scenario 2 (F2, F4, F9, F10, F11): End-to-end breakout chain across Rings 1-4 is blocked in Lean & Rust."""
        common.require_milestone_file("formal/AgentOctopusFormal/IsolationAndPerimeter.lean", "F9")
        common.require_milestone_file("formal/AgentOctopusFormal/NoBreachNoBreakout.lean", "F10")
        probe = (
            "import AgentOctopusFormal.NoBreachNoBreakout\n"
            "open AgentOctopusFormal in\n"
            "-- Ring 2: Untrusted -> Worker -> PrivilegedSink proxy laundering must fail\n"
            "example : (auditRoleChain [.UntrustedDocIngest, .NetworkEgress, .AccountingLedgerWrite]).allowed = false := rfl\n"
            "#check @AgentOctopusFormal.path_join_no_escape\n"
            "#check @AgentOctopusFormal.ssrf_blocks_all_restricted_ranges\n"
            "#check @AgentOctopusFormal.pre_resume_no_elevated_uncontained_child\n"
            "#check @AgentOctopusFormal.sentinel_fail_closed_lockdown\n"
            "#check @AgentOctopusFormal.no_breakout\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

        # Verify corresponding Rust enforcement anchors are intact
        self.assertIn("%2e", _read_repo_text("src/security/breakouts/mod.rs"))
        self.assertIn("is_restricted_rebinding_ip", _read_repo_text("src/containment_ring/egress_proxy.rs"))
        self.assertIn("INTEGRITY_MEDIUM", _read_repo_text("src/security/token_posture.rs"))
        self.assertIn("!supervisor_healthy", _read_repo_text("src/containment_ring/sentinel.rs"))

    def test_t4_03_financial_and_governance_breach_simulation(self) -> None:
        """Scenario 3 (F3, F5, F6, F7, F8, F10, F11): Financial/governance breach vectors are rejected in Lean & Rust."""
        common.require_milestone_file("formal/AgentOctopusFormal/EpochAutotomy.lean", "F5")
        common.require_milestone_file("formal/AgentOctopusFormal/CageNoDirectBind.lean", "F6")
        common.require_milestone_file("formal/AgentOctopusFormal/CedarAndTemporal.lean", "F7")
        common.require_milestone_file("formal/AgentOctopusFormal/MandateAndQuorum.lean", "F8")
        common.require_milestone_file("formal/AgentOctopusFormal/NoBreachNoBreakout.lean", "F10")
        hex64 = "c" * 64
        probe = (
            "import AgentOctopusFormal.NoBreachNoBreakout\n"
            "open AgentOctopusFormal in\n"
            "example : enforceArtifact {} "
            f'{{ amountCents := 10_000_001, currency := "USD", merkleRoot := "{hex64}" }} = false := rfl\n'
            "#check @AgentOctopusFormal.dirac_single_use_no_replay\n"
            "#check @AgentOctopusFormal.no_direct_bind\n"
            "#check @AgentOctopusFormal.spending_cap_enforced\n"
            "#check @AgentOctopusFormal.mandate_monotonic_attenuation\n"
            "#check @AgentOctopusFormal.quorum_threshold_anti_sybil\n"
            "#check @AgentOctopusFormal.no_breach\n"
        )
        res = common.run_lean_probe(probe, use_lake_env=True)
        self.assertEqual(res.returncode, 0, res.combined_output)

        self.assertIn("10_000_000", _read_repo_text("src/deterministic/policy_guard.rs"))
        self.assertIn("AlreadyConsumed", _read_repo_text("src/security/cage_governance/routing_seal.rs"))
        self.assertIn("DuplicateAuthority", _read_repo_text("src/ledger/quorum.rs"))
        self.assertIn("MaxDelegationDepthExceeded", _read_repo_text("src/security/agentmesh/mandate_attenuation.rs"))

    def test_t4_04_rust_to_lean_drift_detection_e2e(self) -> None:
        """Scenario 4 (F2-F9, F11): Full Rust-to-Lean 1-to-1 parity check + `cargo test --test lean_formal_coupling_tests`."""
        common.require_milestone_file("tests/lean_formal_coupling_tests.rs", "F11")
        common.require_milestone_file("formal/AgentOctopusFormal/NoBreachNoBreakout.lean", "F10")

        # Cross-check exact Rust variants & constants directly against formal/
        rust_roles = common.parse_rust_enum_variants(_read_repo_text("src/core/types.rs"), "ArmRole")
        lean_roles = common.parse_lean_inductive_constructors(
            _read_repo_text("formal/AgentOctopusFormal/CoreTypes.lean"), "ArmRole"
        )
        self.assertEqual(rust_roles, lean_roles)

        rust_states = common.parse_rust_enum_variants(_read_repo_text("src/deterministic/fsm.rs"), "ArmState")
        lean_states = common.parse_lean_inductive_constructors(
            _read_repo_text("formal/AgentOctopusFormal/FsmContainment.lean"), "ArmState"
        )
        self.assertEqual(rust_states, lean_states)

        res = common.run_cargo_test_target("lean_formal_coupling_tests", timeout=300.0)
        self.assertEqual(res.returncode, 0, f"Rust-to-Lean coupling tests failed:\n{res.combined_output}")

    def test_t4_05_release_packaging_and_lake_exclusion_audit(self) -> None:
        """Scenario 5 (F1, F13, F14): Isolated packaging run includes formal/*.lean and excludes all .lake/ & .agents/ artifacts."""
        common.require_milestone_file("formal/lean-toolchain", "F1")
        common.require_milestone_file("formal/lakefile.toml", "F1")
        audit = common.run_isolated_package_audit()
        entries = audit["archive_entries"]
        self.assertIn("formal/lean-toolchain", entries)
        self.assertIn("formal/lakefile.toml", entries)
        self.assertIn("formal/AgentOctopusFormal/CoreTypes.lean", entries)
        forbidden = [
            e
            for e in entries
            if ".lake/" in e
            or e.startswith(".git/")
            or e.startswith(".agents/")
            or e.startswith("target/")
            or e.endswith(".olean")
        ]
        self.assertEqual(forbidden, [], f"Forbidden artifacts packaged into zip: {forbidden[:10]}")
        self.assertTrue(common.git_check_ignore("formal/.lake/build/CoreTypes.olean"))

    def test_t4_06_ci_and_auto_review_bot_security_compliance_audit(self) -> None:
        """Scenario 6 (F12, F13, F14): Security compliance audit across lean-verify.yml, ci.yml, raptor-security.yml, auto-review-bot.yml, and WiX."""
        lean_wf = common.require_milestone_file(".github/workflows/lean-verify.yml", "F12")
        workflows = [
            lean_wf,
            common.REPO_ROOT / ".github" / "workflows" / "ci.yml",
            common.REPO_ROOT / ".github" / "workflows" / "raptor-security.yml",
            common.REPO_ROOT / ".github" / "workflows" / "auto-review-bot.yml",
            common.REPO_ROOT / ".github" / "workflows" / "release-all-os.yml",
        ]
        for wf in workflows:
            text = wf.read_text(encoding="utf-8")
            self.assertEqual(common.check_funny_chars_in_text(text, wf.name), [])
            info = common.inspect_workflow_yaml_text(text)
            self.assertEqual(info["top_permissions"], "read-all", f"{wf.name} lacks permissions: read-all")
            self.assertFalse(info["has_write_all"], f"{wf.name} uses write-all")
            self.assertFalse(info["has_persist_credentials_true"], f"{wf.name} sets persist-credentials: true")
            self.assertFalse(info["has_secrets_exfil"], f"{wf.name} leaks secrets")

        wxs_text = _read_repo_text("wix/AgentOctopus.wxs")
        self.assertEqual(common.check_wix_path_mutation(wxs_text), [])
        self.assertIn("len(sarif_files) > 0", _read_repo_text(".github/workflows/raptor-security.yml"))

    def test_t4_07_opaque_box_e2e_self_integrity_and_clean_tree(self) -> None:
        """Scenario 7 (F1-F14): Self-integrity audit confirming stdlib-only code, zero funny chars, zero leftover probes, and clean git boundary."""
        e2e_dir = (common.REPO_ROOT / "tests" / "e2e_formal").resolve()
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
            txt = pyf.read_text(encoding="utf-8")
            self.assertEqual(common.check_stdlib_only_python_file(pyf, allowed_local_modules=local_mods), [])
            self.assertEqual(common.check_funny_chars_in_text(txt, pyf.name), [])
            self.assertEqual(common.scan_raptor_python_anti_patterns(txt, pyf.name), [])

        # Confirm zero leftover Probe.lean or temp zips in REPO_ROOT or formal/
        leftover_probes = list(common.FORMAL_DIR.rglob("Probe.lean"))
        self.assertEqual(leftover_probes, [], f"Leftover probe files in formal/: {leftover_probes}")
        self.assertFalse((common.REPO_ROOT / "agent_octopus_audit.zip").exists())
        status_lines = common.run_git_status_short()
        bad_status = [
            ln
            for ln in status_lines
            if "Probe.lean" in ln or "agent_octopus_audit.zip" in ln
        ]
        self.assertEqual(bad_status, [], f"Unexpected temp artifacts in git status: {bad_status}")
