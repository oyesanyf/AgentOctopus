"""Tier 1: Feature Behavior Tests (Category-Partition) — 30 tests (5 per F1-F6)."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import unittest

from . import helpers


class TestTier1Features(unittest.TestCase):
    """30 core feature-behavior tests across F1-F6."""

    # ------------------------------------------------------------------
    # F1: Deterministic Containment & Policy Enforcement (5 tests)
    # ------------------------------------------------------------------

    def test_f1_01_json_policy_allows_workspace_write(self) -> None:
        """F1: `octopus run` permits writing inside an allowed workspace directory."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            out_dir = ws.make_dir("work_out")
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [],
                    "denied_domains": [],
                    "denied_resolved_addresses": ["169.254.169.254/32"],
                    "commands": {"allow": ["python", "python3"], "deny": ["bash", "sh"]},
                    "filesystem": {
                        "allow_read": [str(ws.path)],
                        "allow_write": [str(out_dir)],
                        "deny": ["~/.ssh", "~/.aws", ".git/hooks"],
                    },
                    "limits": {"memory_mb": 256, "timeout_secs": 15},
                },
            )
            script = ws.write_file(
                "agent.py",
                (
                    "import pathlib, sys\n"
                    f"target = pathlib.Path({str(out_dir / 'result.txt')!r})\n"
                    "target.write_text('allowed_write_ok', encoding='utf-8')\n"
                    "print('WRITE_OK')\n"
                ),
            )
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--cwd", str(ws.path), "--", sys.executable, str(script)],
                octopus_bin=octo,
            )
            self.assertEqual(res.returncode, 0, f"Expected exit 0, got {res.returncode}: {res.combined_output}")
            self.assertIn("WRITE_OK", res.stdout)
            self.assertEqual((out_dir / "result.txt").read_text(encoding="utf-8"), "allowed_write_ok")

    def test_f1_02_json_policy_allows_listed_loopback_http(self) -> None:
        """F1: `octopus run` forwards HTTP via proxy to an explicitly listed 127.0.0.1:<port>."""
        octo = helpers.require_octopus_bin()
        with helpers.LocalLoopbackMockServer() as srv, helpers.TempWorkspace() as ws:
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [srv.host_port],
                    "denied_domains": [],
                    "denied_resolved_addresses": ["169.254.169.254/32"],
                    "commands": {"allow": ["python", "python3"], "deny": []},
                    "filesystem": {"allow_read": [str(ws.path)], "allow_write": [str(ws.path)], "deny": []},
                },
            )
            script = ws.write_file("probe.py", helpers.proxy_probe_script(f"{srv.base_url}/ok"))
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--", sys.executable, str(script)],
                octopus_bin=octo,
            )
            self.assertEqual(res.returncode, 0, f"Expected allowed proxy HTTP 200, got {res.returncode}: {res.combined_output}")
            self.assertEqual(srv.hit_count(), 1, f"Expected 1 hit on allowed mock server, got {srv.hit_count()}")
            self.assertIn('"status": 200', res.stdout)

    def test_f1_03_json_policy_blocks_unlisted_http(self) -> None:
        """F1: `octopus run` blocks HTTP egress to domains/ports omitted from allowed_domains."""
        octo = helpers.require_octopus_bin()
        with (
            helpers.LocalLoopbackMockServer() as allowed_srv,
            helpers.LocalLoopbackMockServer() as denied_srv,
            helpers.TempWorkspace() as ws,
        ):
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [allowed_srv.host_port],
                    "denied_domains": [],
                    "denied_resolved_addresses": ["169.254.169.254/32"],
                    "commands": {"allow": ["python", "python3"], "deny": []},
                    "filesystem": {"allow_read": [str(ws.path)], "allow_write": [str(ws.path)], "deny": []},
                },
            )
            script = ws.write_file("probe_denied.py", helpers.proxy_probe_script(f"{denied_srv.base_url}/secret"))
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--", sys.executable, str(script)],
                octopus_bin=octo,
            )
            helpers.assert_blocked_outcome(res, mock_server=denied_srv)

    def test_f1_04_cedar_policy_allows_permitted_action(self) -> None:
        """F1: Cedar `.cedar` quickstart policy and Cedar API permit explicitly authorized actions."""
        cfg = helpers.get_config()
        octo = helpers.require_octopus_bin(cfg)
        cedar_path = cfg.repo_root / "examples" / "quickstart" / "policy.cedar"
        self.assertTrue(cedar_path.is_file(), f"Missing quickstart Cedar policy: {cedar_path}")
        cedar_text = cedar_path.read_text(encoding="utf-8")
        self.assertIn("permit", cedar_text)

        with helpers.TempWorkspace() as ws:
            script = ws.write_file("ok.py", "print('CEDAR_OK')\n")
            res = ws.run_octopus(
                ["run", "--policy", str(cedar_path), "--cwd", str(ws.path), "--", sys.executable, str(script)],
                octopus_bin=octo,
            )
            self.assertEqual(res.returncode, 0, f"Cedar policy denied benign child: {res.combined_output}")
            self.assertIn("CEDAR_OK", res.stdout)

            # Also validate standard Octopus:: schema allow via Web API if agent binary is present
            agent_bin = helpers.require_agent_bin(cfg)
            with helpers.WebServerHandle(ws, agent_bin=agent_bin) as srv:
                status, data = srv.post_json(
                    "/api/evaluate-cedar",
                    {
                        "principal": "document_arm",
                        "action": "extract",
                        "resource": "doc_quickstart_1",
                        "context": {},
                    },
                )
                self.assertEqual(status, 200)
                self.assertTrue(data.get("is_allowed"), f"Expected Cedar extract allow, got: {data}")

    def test_f1_05_cedar_policy_denies_forbidden_action(self) -> None:
        """F1: Cedar policy denies unauthorized actions (IMDS, unlisted/forbid domain egress, and command forbid under `.cedar`)."""
        cfg = helpers.get_config()
        octo = helpers.require_octopus_bin(cfg)
        cedar_path = cfg.repo_root / "examples" / "quickstart" / "policy.cedar"
        self.assertTrue(cedar_path.is_file(), f"Missing quickstart Cedar policy: {cedar_path}")

        with helpers.LocalLoopbackMockServer() as unlisted_srv, helpers.TempWorkspace() as ws:
            # 1) Disallowed IMDS probe under quickstart policy.cedar
            probe = ws.write_file("imds.py", helpers.proxy_probe_script("http://169.254.169.254/latest/meta-data/"))
            res = ws.run_octopus(
                ["run", "--policy", str(cedar_path), "--cwd", str(ws.path), "--", sys.executable, str(probe)],
                octopus_bin=octo,
            )
            helpers.assert_blocked_outcome(res)

            # 2) Custom standalone .cedar policy: non-IMDS unlisted/forbid domain egress denial + command forbid denial
            denied_cmd_stem = "cmd" if sys.platform == "win32" else "sh"
            custom_cedar = ws.write_file(
                "strict_custom.cedar",
                (
                    'permit (\n'
                    '    principal,\n'
                    '    action == Octopus::Action::"exec",\n'
                    '    resource is Octopus::Command\n'
                    ') when {\n'
                    '    context has stem && (context.stem == "python" || context.stem == "python3")\n'
                    '};\n'
                    'forbid (\n'
                    '    principal,\n'
                    '    action == Octopus::Action::"exec",\n'
                    '    resource is Octopus::Command\n'
                    ') when {\n'
                    f'    context has stem && context.stem == "{denied_cmd_stem}"\n'
                    '};\n'
                    'permit (\n'
                    '    principal,\n'
                    '    action == Octopus::Action::"egress",\n'
                    '    resource is Octopus::NetworkTarget\n'
                    ') when {\n'
                    '    context has destination_domain && context.destination_domain == "approved.example.invalid"\n'
                    '};\n'
                    'forbid (\n'
                    '    principal,\n'
                    '    action == Octopus::Action::"egress",\n'
                    '    resource is Octopus::NetworkTarget\n'
                    ') when {\n'
                    '    context has destination_domain && context.destination_domain == "evil.example.com"\n'
                    '};\n'
                ),
            )
            unlisted_probe = ws.write_file("unlisted_egress.py", helpers.proxy_probe_script(f"{unlisted_srv.base_url}/secret"))
            res_unlisted = ws.run_octopus(
                ["run", "--policy", str(custom_cedar), "--cwd", str(ws.path), "--", sys.executable, str(unlisted_probe)],
                octopus_bin=octo,
            )
            helpers.assert_blocked_outcome(res_unlisted, mock_server=unlisted_srv)
            self.assertIn("cedar", res_unlisted.combined_output.lower())

            forbid_probe = ws.write_file("forbid_egress.py", helpers.proxy_probe_script("http://evil.example.com/leak"))
            res_forbid_dom = ws.run_octopus(
                ["run", "--policy", str(custom_cedar), "--cwd", str(ws.path), "--", sys.executable, str(forbid_probe)],
                octopus_bin=octo,
            )
            helpers.assert_blocked_outcome(res_forbid_dom)
            self.assertIn("cedar", res_forbid_dom.combined_output.lower())

            cmd_args = [denied_cmd_stem, "/c", "echo", "CEDAR_CMD_RAN"] if sys.platform == "win32" else [denied_cmd_stem, "-c", "echo CEDAR_CMD_RAN"]
            res_forbid_cmd = ws.run_octopus(
                ["run", "--policy", str(custom_cedar), "--cwd", str(ws.path), "--", *cmd_args],
                octopus_bin=octo,
            )
            helpers.assert_blocked_outcome(res_forbid_cmd)
            self.assertNotIn("CEDAR_CMD_RAN", res_forbid_cmd.stdout)
            self.assertIn("cedar", res_forbid_cmd.combined_output.lower())

            # 3) Disallowed egress action under standard Octopus:: Cedar schema
            agent_bin = helpers.require_agent_bin(cfg)
            with helpers.WebServerHandle(ws, agent_bin=agent_bin) as srv:
                status, data = srv.post_json(
                    "/api/evaluate-cedar",
                    {
                        "principal": "network_arm",
                        "action": "egress",
                        "resource": "https://evil.example.com",
                        "context": {"destination_domain": "evil.example.com"},
                    },
                )
                self.assertEqual(status, 200)
                self.assertFalse(data.get("is_allowed"), f"Expected Cedar deny on evil.example.com: {data}")

    # ------------------------------------------------------------------
    # F2: D3QN Default-Off & Non-Interference Invariants (5 tests)
    # ------------------------------------------------------------------

    def test_f2_01_default_run_disables_rl_and_skips_rl_disk_io(self) -> None:
        """F2: Default runs disable D3QN and never auto-create `config/rl_defense_policy.json`."""
        cfg = helpers.get_config()
        octo = helpers.require_octopus_bin(cfg)
        agent_bin = helpers.require_agent_bin(cfg)

        with helpers.TempWorkspace() as ws_cli:
            policy = ws_cli.write_json(
                "policy.json",
                {"allowed_domains": [], "denied_domains": [], "commands": {"allow": ["python", "python3"]}},
            )
            script = ws_cli.write_file("noop.py", "print('NOOP_OK')\n")
            res = ws_cli.run_octopus(
                ["run", "--policy", str(policy), "--", sys.executable, str(script)],
                octopus_bin=octo,
                env=helpers.default_clean_env(),
            )
            self.assertEqual(res.returncode, 0, res.combined_output)
            self.assertFalse(
                ws_cli.exists("config/rl_defense_policy.json"),
                "octopus run unexpectedly created config/rl_defense_policy.json when RL is disabled",
            )

        with helpers.TempWorkspace() as ws_web:
            with helpers.WebServerHandle(ws_web, agent_bin=agent_bin) as srv:
                st_code, _ = srv.get_json("/api/status")
                self.assertEqual(st_code, 200)
                srv.post_json(
                    "/api/evaluate-cedar",
                    {"principal": "document_arm", "action": "extract", "resource": "doc_1", "context": {}},
                )
                srv.post_json(
                    "/api/governor/inject-sample",
                    {"event_type": "shell_exec", "is_malicious": True, "use_rl_mitigation": True},
                )
            self.assertFalse(
                ws_web.exists("config/rl_defense_policy.json"),
                "Web server auto-created config/rl_defense_policy.json with OCTOPUS_ENABLE_RL_ADVISORY unset",
            )

    def test_f2_02_rl_advisory_opt_in_preserves_allow(self) -> None:
        """F2: Enabling `OCTOPUS_ENABLE_RL_ADVISORY=1` preserves deterministic allow verdicts."""
        cfg = helpers.get_config()
        octo = helpers.require_octopus_bin(cfg)
        with helpers.LocalLoopbackMockServer() as srv, helpers.TempWorkspace() as ws:
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [srv.host_port],
                    "denied_domains": [],
                    "commands": {"allow": ["python", "python3"]},
                },
            )
            script = ws.write_file("probe.py", helpers.proxy_probe_script(f"{srv.base_url}/ok"))
            res_off = ws.run_octopus(
                ["run", "--policy", str(policy), "--", sys.executable, str(script)],
                octopus_bin=octo,
                env=helpers.default_clean_env(),
            )
            res_on = ws.run_octopus(
                ["run", "--policy", str(policy), "--", sys.executable, str(script)],
                octopus_bin=octo,
                env=helpers.default_clean_env({"OCTOPUS_ENABLE_RL_ADVISORY": "1"}),
            )
            self.assertEqual(res_off.returncode, 0, res_off.combined_output)
            self.assertEqual(res_on.returncode, 0, res_on.combined_output)
            self.assertEqual(srv.hit_count(), 2)

    def test_f2_03_rl_advisory_opt_in_preserves_deny(self) -> None:
        """F2: Enabling `OCTOPUS_ENABLE_RL_ADVISORY=1` preserves deterministic deny verdicts."""
        cfg = helpers.get_config()
        octo = helpers.require_octopus_bin(cfg)
        with helpers.LocalLoopbackMockServer() as denied_srv, helpers.TempWorkspace() as ws:
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [],
                    "denied_domains": [denied_srv.host_port],
                    "commands": {"allow": ["python", "python3"]},
                },
            )
            script = ws.write_file("probe.py", helpers.proxy_probe_script(f"{denied_srv.base_url}/bad"))
            res_off = ws.run_octopus(
                ["run", "--policy", str(policy), "--", sys.executable, str(script)],
                octopus_bin=octo,
                env=helpers.default_clean_env(),
            )
            res_on = ws.run_octopus(
                ["run", "--policy", str(policy), "--", sys.executable, str(script)],
                octopus_bin=octo,
                env=helpers.default_clean_env({"OCTOPUS_ENABLE_RL_ADVISORY": "1"}),
            )
            helpers.assert_blocked_outcome(res_off, mock_server=denied_srv)
            helpers.assert_blocked_outcome(res_on, mock_server=denied_srv)

    def test_f2_04_web_status_reports_rl_disabled_by_default(self) -> None:
        """F2: `GET /api/status` reports D3QN/RL as disabled/advisory (never `"Active"`)."""
        agent_bin = helpers.require_agent_bin()
        with helpers.TempWorkspace() as ws, helpers.WebServerHandle(ws, agent_bin=agent_bin) as srv:
            code, payload = srv.get_json("/api/status")
            self.assertEqual(code, 200)
            rl = payload.get("rl_active_defense")
            self.assertIsInstance(rl, dict, f"Missing rl_active_defense in /api/status: {payload}")
            status_str = str(rl.get("status", "")).lower()
            self.assertNotEqual(status_str, "active", f"RL must not report Active by default: {rl}")
            self.assertTrue(
                any(tok in status_str for tok in ("disabled", "offline", "advisory", "off", "inactive"))
                or rl.get("enabled") is False,
                f"Expected disabled/advisory RL status, got: {rl}",
            )

    def test_f2_05_web_evaluate_cedar_deterministic_allow_and_deny(self) -> None:
        """F2: `POST /api/evaluate-cedar` enforces deterministic Cedar verdicts without RL veto."""
        agent_bin = helpers.require_agent_bin()
        with helpers.TempWorkspace() as ws, helpers.WebServerHandle(ws, agent_bin=agent_bin) as srv:
            c1, allow_resp = srv.post_json(
                "/api/evaluate-cedar",
                {"principal": "document_arm", "action": "extract", "resource": "doc_alpha", "context": {}},
            )
            self.assertEqual(c1, 200)
            self.assertTrue(allow_resp.get("is_allowed"), f"Expected allow: {allow_resp}")
            self.assertNotIn("VETO BY RL", str(allow_resp.get("reason", "")).upper())

            c2, deny_resp = srv.post_json(
                "/api/evaluate-cedar",
                {
                    "principal": "network_arm",
                    "action": "egress",
                    "resource": "https://blocked.invalid",
                    "context": {"destination_domain": "blocked.invalid"},
                },
            )
            self.assertEqual(c2, 200)
            self.assertFalse(deny_resp.get("is_allowed"), f"Expected deny: {deny_resp}")
            self.assertNotIn("RL_DEFENSE_ESCALATION", " ".join(deny_resp.get("diagnostic_errors", [])))

    # ------------------------------------------------------------------
    # F3: CLI UX, Subcommands, Flags & Exit Codes (5 tests)
    # ------------------------------------------------------------------

    def test_f3_01_octopus_help_exits_zero_without_demo(self) -> None:
        """F3: `octopus --help` exits 0 and prints CLI usage without running a self-demo."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            res = ws.run_octopus(["--help"], octopus_bin=octo)
            self.assertEqual(res.returncode, 0, res.combined_output)
            self.assertIn("run", res.stdout.lower())
            self.assertNotIn("9-scenario", res.stdout.lower())

    def test_f3_02_octopus_run_help_documents_contract(self) -> None:
        """F3: `octopus run --help` documents `--policy`, `--sandbox`, `--timeout`, `--cwd`, `--json`."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            res = ws.run_octopus(["run", "--help"], octopus_bin=octo)
            self.assertEqual(res.returncode, 0, res.combined_output)
            text = res.stdout.lower()
            for flag in ("--policy", "--sandbox", "--timeout", "--cwd", "--json"):
                self.assertIn(flag, text, f"Missing {flag} in `octopus run --help` output:\n{res.stdout}")

    def test_f3_03_child_exit_code_and_stdio_streamed(self) -> None:
        """F3: `octopus run` streams stdout/stderr and propagates the child exit code."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            policy = ws.write_json(
                "policy.json",
                {"allowed_domains": [], "denied_domains": [], "commands": {"allow": ["python", "python3"]}},
            )
            script = ws.write_file(
                "exit7.py",
                "import sys\nprint('CHILD_STDOUT_MARKER')\nprint('CHILD_STDERR_MARKER', file=sys.stderr)\nsys.exit(7)\n",
            )
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--", sys.executable, str(script)],
                octopus_bin=octo,
            )
            self.assertEqual(res.returncode, 7, f"Expected propagated exit 7, got {res.returncode}: {res.combined_output}")
            self.assertIn("CHILD_STDOUT_MARKER", res.stdout)
            self.assertIn("CHILD_STDERR_MARKER", res.stderr)

    def test_f3_04_cwd_flag_changes_child_working_directory(self) -> None:
        """F3: `--cwd <DIR>` sets the child process working directory to `<DIR>`."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            sub = ws.make_dir("nested_cwd")
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [],
                    "commands": {"allow": ["python", "python3"]},
                    "filesystem": {"allow_read": [str(ws.path)], "allow_write": [str(sub)], "deny": []},
                },
            )
            script = ws.write_file("pwd.py", "import os; print('CWD_MARKER=' + os.path.realpath(os.getcwd()))\n")
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--cwd", str(sub), "--", sys.executable, str(script)],
                octopus_bin=octo,
            )
            self.assertEqual(res.returncode, 0, res.combined_output)
            marker_line = next(
                (line for line in res.stdout.splitlines() if line.startswith("CWD_MARKER=")),
                None,
            )
            self.assertIsNotNone(marker_line, f"Missing CWD_MARKER= in stdout:\n{res.stdout}")
            reported = Path(marker_line.split("=", 1)[1].strip()).resolve()
            self.assertEqual(reported, sub.resolve())

    def test_f3_05_json_flag_produces_valid_json_output(self) -> None:
        """F3: `--json` emits a valid structured JSON containment summary."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            policy = ws.write_json(
                "policy.json",
                {"allowed_domains": [], "commands": {"allow": ["python", "python3"]}},
            )
            script = ws.write_file("ok.py", "print('hello_json')\n")
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--json", "--", sys.executable, str(script)],
                octopus_bin=octo,
            )
            self.assertEqual(res.returncode, 0, res.combined_output)
            parsed = helpers.extract_last_json_dict(res.stdout, res.stderr)
            self.assertIsInstance(
                parsed,
                dict,
                f"Expected JSON summary in stdout/stderr:\nstdout:\n{res.stdout}\nstderr:\n{res.stderr}",
            )

    # ------------------------------------------------------------------
    # F4: Repo Hygiene & History Preservation (5 tests)
    # ------------------------------------------------------------------

    def test_f4_01_no_tracked_agents_teamwork_files(self) -> None:
        """F4: `git ls-files` contains zero `.agents/` or `.agents/teamwork/` files."""
        repo = helpers.get_config().repo_root
        tracked = helpers.git_ls_files(repo)
        bad = [p for p in tracked if p.startswith(".agents/")]
        self.assertEqual(bad, [], f"Tracked .agents/ files found in git index: {bad}")

    def test_f4_02_no_tracked_internal_docs_or_root_reports(self) -> None:
        """F4: `git ls-files` contains zero `DEAD_ENDS.md`, `PROJECT.md`, `TEST_*`, `dist_manifest.json`, or `*_test_report.*`."""
        repo = helpers.get_config().repo_root
        tracked = helpers.git_ls_files(repo)
        bad = [
            p
            for p in tracked
            if p in helpers.FORBIDDEN_TRACKED_EXACT or helpers.FORBIDDEN_REPORT_RE.search(p)
        ]
        self.assertEqual(bad, [], f"Tracked internal/report artifacts found: {bad}")

    def test_f4_03_gitignore_blocks_agents_and_generated_reports(self) -> None:
        """F4: `.gitignore` ignores `.agents/` scratch logs and `logs/` and `git check-ignore` matches probe paths."""
        repo = helpers.get_config().repo_root
        gitignore = (repo / ".gitignore").read_text(encoding="utf-8")
        self.assertIn(".agents/", gitignore)
        self.assertIn("logs/", gitignore)
        for probe in (".agents/teamwork/probe.md", "logs/probe.log"):
            self.assertTrue(
                helpers.git_check_ignore(repo, probe),
                f"git check-ignore did not ignore {probe}",
            )

    def test_f4_04_git_history_preserved_base_commit_ancestor(self) -> None:
        """F4: Base commit `7fd028b` remains an ancestor of `HEAD` (history preserved, no force-rewrite)."""
        repo = helpers.get_config().repo_root
        self.assertTrue(
            helpers.git_is_ancestor(repo, helpers.BASELINE_ANCESTOR_SHA, "HEAD"),
            f"Baseline commit {helpers.BASELINE_ANCESTOR_SHA} is not an ancestor of HEAD!",
        )

    def test_f4_05_no_cross_repo_oshoosiclaw_files(self) -> None:
        """F4: No OshoosiClaw-only docs/assets remain tracked in `AgentOctopus`."""
        repo = helpers.get_config().repo_root
        tracked = helpers.git_ls_files(repo)
        bad = [p for p in tracked if helpers.is_forbidden_oshoosiclaw_path(p)]
        self.assertEqual(bad, [], f"OshoosiClaw-only files still tracked: {bad}")

    # ------------------------------------------------------------------
    # F5: Positioning, Docs & Quickstart Parity (5 tests)
    # ------------------------------------------------------------------

    def test_f5_01_readme_contains_agentmesh_and_cage_positioning(self) -> None:
        """F5: `README.md` positions AgentOctopus alongside `agentmesh` and in contrast to CAGE."""
        repo = helpers.get_config().repo_root
        readme = (repo / "README.md").read_text(encoding="utf-8")
        lower = readme.lower()
        self.assertIn("agentmesh", lower)
        self.assertIn("cage", lower)
        for tech in ("cedar", "wasmtime", "rt-asp"):
            self.assertIn(tech, lower, f"README.md missing deterministic layer `{tech}`")

    def test_f5_02_readme_leads_with_octopus_run_quickstart(self) -> None:
        """F5: `README.md` leads early with the 1-command `octopus run --policy` quickstart."""
        repo = helpers.get_config().repo_root
        lines = (repo / "README.md").read_text(encoding="utf-8").splitlines()
        head_section = "\n".join(lines[:160])
        self.assertIn("octopus run --policy", head_section)

    def test_f5_03_readme_frames_d3qn_as_optional_advisory_only(self) -> None:
        """F5: `README.md` does not headline D3QN/RL in the first 60 lines or Mermaid gate diagrams and frames it as optional/advisory."""
        repo = helpers.get_config().repo_root
        readme_text = (repo / "README.md").read_text(encoding="utf-8")
        violations = helpers.validate_readme_d3qn_advisory(readme_text)
        self.assertEqual(violations, [], "; ".join(violations))

    def test_f5_04_readme_links_valid_no_broken_license(self) -> None:
        """F5: `README.md` & all 7 `docs/*.md` have cross-nav links, valid relative links, and no bare `(LICENSE)` or `file:///`."""
        repo = helpers.get_config().repo_root
        readme = (repo / "README.md").read_text(encoding="utf-8")
        self.assertNotRegex(readme, r"\]\(LICENSE\)")
        self.assertNotIn("file:///", readme.lower())
        links = helpers.extract_markdown_links(readme)
        missing = []
        for target in links:
            rel_part = target.split("#", 1)[0].split("?", 1)[0]
            if not rel_part:
                continue
            if not (repo / rel_part).exists():
                missing.append(target)
        self.assertEqual(missing, [], f"Broken relative links in README.md: {missing}")

        for rel_doc in helpers.REQUIRED_DOCS_FILES:
            doc_path = repo / rel_doc
            self.assertTrue(doc_path.is_file(), f"Missing flagship doc file: {rel_doc}")
            self.assertIn(rel_doc, readme, f"README.md Documentation Index must link `{rel_doc}`")
            doc_text = doc_path.read_text(encoding="utf-8")
            self.assertNotRegex(doc_text, r"\]\(LICENSE\)", f"Broken ](LICENSE) link in {rel_doc}")
            self.assertNotIn("file:///", doc_text.lower(), f"file:/// leak in {rel_doc}")
            head = "\n".join(doc_text.splitlines()[:12])
            self.assertIn("../README.md", head, f"{rel_doc} top cross-nav bar must link ../README.md")
            for sib in helpers.REQUIRED_DOCS_FILES:
                sib_name = Path(sib).name
                self.assertIn(
                    f"({sib_name})",
                    head,
                    f"{rel_doc} top cross-nav bar missing link to sibling {sib_name}",
                )

    def test_f5_05_quickstart_files_exist_valid_stdlib_only(self) -> None:
        """F5: `examples/quickstart/{policy.json,policy.cedar,my_agent.py}` exist and `my_agent.py` is stdlib-only."""
        repo = helpers.get_config().repo_root
        qdir = repo / "examples" / "quickstart"
        p_json = qdir / "policy.json"
        p_cedar = qdir / "policy.cedar"
        agent_py = qdir / "my_agent.py"
        for p in (p_json, p_cedar, agent_py):
            self.assertTrue(p.is_file(), f"Missing quickstart file: {p}")
        data = json.loads(p_json.read_text(encoding="utf-8"))
        self.assertIsInstance(data, dict)
        non_stdlib = helpers.validate_stdlib_python_file(agent_py)
        self.assertEqual(non_stdlib, [], f"Quickstart my_agent.py has non-stdlib imports: {non_stdlib}")

    # ------------------------------------------------------------------
    # F6: Workspace Boundaries, Sibling Immutability & GitHub Metadata (5 tests)
    # ------------------------------------------------------------------

    def test_f6_01_sandbox_runtime_unmodified(self) -> None:
        """F6: Sibling repo `d:\\harfile\\sandbox-runtime` matches baseline HEAD, zero diffs/.agents, and only allowed pre-existing untracked artifacts."""
        violations = helpers.validate_sibling_repo_state(
            helpers.SIBLING_SANDBOX_RUNTIME,
            expected_head_sha=helpers.BASELINE_SANDBOX_RUNTIME_SHA,
            allowed_untracked=helpers.SANDBOX_RUNTIME_ALLOWED_UNTRACKED,
            allowed_porcelain=helpers.SANDBOX_RUNTIME_ALLOWED_PORCELAIN,
        )
        self.assertEqual(violations, [], "; ".join(violations))

    def test_f6_02_killswitch_unmodified(self) -> None:
        """F6: Sibling repo `d:\\harfile\\killswitch` matches baseline HEAD with zero diffs, .agents, untracked/ignored files, or empty dirs."""
        violations = helpers.validate_sibling_repo_state(
            helpers.SIBLING_KILLSWITCH,
            expected_head_sha=helpers.BASELINE_KILLSWITCH_SHA,
        )
        self.assertEqual(violations, [], "; ".join(violations))

    def test_f6_03_git_identity_configured(self) -> None:
        """F6: `AgentOctopus` git identity is `femi oyesanya <oyesanyf@gmail.com>`."""
        repo = helpers.get_config().repo_root
        self.assertEqual(helpers.git_config_get(repo, "user.name"), helpers.EXPECTED_GIT_USER_NAME)
        self.assertEqual(helpers.git_config_get(repo, "user.email"), helpers.EXPECTED_GIT_USER_EMAIL)

    def test_f6_04_origin_remote_matches_target(self) -> None:
        """F6: `AgentOctopus` `origin` remote targets `oyesanyf/AgentOctopus`."""
        repo = helpers.get_config().repo_root
        url = helpers.git_remote_url(repo, "origin")
        self.assertIn(helpers.EXPECTED_REMOTE_SUBSTR, url)

    def test_f6_05_github_description_non_empty_no_rl(self) -> None:
        """F6: GitHub repository `description` is non-empty and omits RL/D3QN headline framing (gated by --skip-remote)."""
        if helpers.get_config().skip_remote:
            self.skipTest("Explicit --skip-remote specified")
        meta = helpers.run_gh_repo_view(helpers.EXPECTED_REMOTE_SUBSTR)
        desc = (meta.get("description") or "").strip()
        self.assertTrue(desc, f"GitHub repository description is empty: {meta}")
        lower = desc.lower()
        for banned in ("d3qn", "q-learning", "reinforcement learning"):
            self.assertNotIn(banned, lower, f"GitHub description must not headline `{banned}`: {desc!r}")
