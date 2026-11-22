"""Tier 2: Boundary Value & Negative Tests — 30 tests (5 per F1-F6)."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import unittest

from . import helpers


class TestTier2Boundaries(unittest.TestCase):
    """30 boundary, edge-case, and negative-control tests across F1-F6."""

    # ------------------------------------------------------------------
    # F1 Boundaries (5 tests)
    # ------------------------------------------------------------------

    def test_f1_b01_imds_169_254_169_254_blocked(self) -> None:
        """F1-BVA: Cloud IMDS `169.254.169.254` is unconditionally blocked even alongside allowed domains."""
        octo = helpers.require_octopus_bin()
        with helpers.LocalLoopbackMockServer() as srv, helpers.TempWorkspace() as ws:
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [srv.host_port],
                    "denied_domains": [],
                    "denied_resolved_addresses": ["169.254.169.254/32"],
                    "commands": {"allow": ["python", "python3"]},
                },
            )
            script = ws.write_file(
                "imds_probe.py",
                helpers.proxy_probe_script("http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            )
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--", sys.executable, str(script)],
                octopus_bin=octo,
            )
            helpers.assert_blocked_outcome(res)

            # Even if a misconfigured policy tries to list IMDS in allowed_domains, containment must still block it
            bad_policy = ws.write_json(
                "policy_imds_allow.json",
                {
                    "allowed_domains": ["169.254.169.254"],
                    "denied_domains": [],
                    "commands": {"allow": ["python", "python3"]},
                },
            )
            res2 = ws.run_octopus(
                ["run", "--policy", str(bad_policy), "--", sys.executable, str(script)],
                octopus_bin=octo,
            )
            helpers.assert_blocked_outcome(res2)

    def test_f1_b02_sensitive_creds_and_mandatory_write_deny(self) -> None:
        """F1-BVA: Mandatory write-deny (`.git/hooks`, `.mcp.json`) and sensitive credential paths (`~/.aws`) are blocked."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            ws.make_dir(".git/hooks")
            out_dir = ws.make_dir("safe_out")
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [],
                    "commands": {"allow": ["python", "python3"]},
                    "filesystem": {
                        "allow_read": [str(ws.path)],
                        "allow_write": [str(ws.path)],
                        "deny": ["~/.ssh", "~/.aws", ".git/hooks", ".mcp.json"],
                    },
                },
            )
            # 1) Pre-flight command argument referencing sensitive credential path
            res_cred = ws.run_octopus(
                [
                    "run",
                    "--policy",
                    str(policy),
                    "--cwd",
                    str(ws.path),
                    "--",
                    sys.executable,
                    "-c",
                    "import pathlib; print(pathlib.Path('~/.aws/credentials').expanduser().read_text())",
                ],
                octopus_bin=octo,
            )
            self.assertNotIn(
                "FileNotFoundError",
                res_cred.stderr,
                "Sensitive credential path check passed vacuously via FileNotFoundError instead of policy block",
            )
            helpers.assert_blocked_outcome(res_cred)

            # 2) Mandatory write-deny targets inside writable workspace (.git/hooks/pre-commit & .mcp.json)
            # Must raise real <octopus_gate> PermissionError: blocked_by_octopus_policy without child-side masking.
            hook_target = ws.path / ".git" / "hooks" / "pre-commit"
            mcp_target = ws.path / ".mcp.json"
            for label, target_path in (("git_hook", hook_target), ("mcp_json", mcp_target)):
                writer_script = ws.write_file(
                    f"write_protected_{label}.py",
                    (
                        "import pathlib\n"
                        f"pathlib.Path({str(target_path)!r}).write_text('pwned', encoding='utf-8')\n"
                        "print('UNEXPECTED_WRITE_SUCCESS')\n"
                    ),
                )
                res_hook = ws.run_octopus(
                    ["run", "--policy", str(policy), "--cwd", str(ws.path), "--", sys.executable, str(writer_script)],
                    octopus_bin=octo,
                )
                self.assertNotIn("UNEXPECTED_WRITE_SUCCESS", res_hook.stdout)
                helpers.assert_blocked_outcome(res_hook)
                self.assertIn("blocked_by_octopus_policy", res_hook.stderr.lower())
                self.assertIn("permissionerror", res_hook.stderr.lower())
                self.assertFalse(target_path.exists(), f"{target_path.name} must not be written")

            # 3) Dynamic runtime FS denials (constructed '.s'+'sh' read and allow_write: [] write)
            dyn_ssh_script = ws.write_file(
                "dyn_ssh_read.py",
                (
                    "import pathlib\n"
                    "p = pathlib.Path.home() / ('.s' + 'sh') / 'id_rsa'\n"
                    "print(p.read_text(encoding='utf-8'))\n"
                ),
            )
            res_dyn_ssh = ws.run_octopus(
                ["run", "--policy", str(policy), "--cwd", str(ws.path), "--", sys.executable, str(dyn_ssh_script)],
                octopus_bin=octo,
            )
            self.assertNotIn("FileNotFoundError", res_dyn_ssh.stderr)
            helpers.assert_blocked_outcome(res_dyn_ssh)
            self.assertIn("blocked_by_octopus_policy", res_dyn_ssh.stderr.lower())
            self.assertIn("permissionerror", res_dyn_ssh.stderr.lower())

            ro_policy = ws.write_json(
                "ro_policy.json",
                {
                    "allowed_domains": [],
                    "commands": {"allow": ["python", "python3"]},
                    "filesystem": {"allow_read": [str(ws.path)], "allow_write": [], "deny": []},
                },
            )
            ro_target = ws.path / "should_fail_ro.txt"
            ro_write_script = ws.write_file(
                "ro_write.py",
                (
                    "import pathlib\n"
                    f"pathlib.Path({str(ro_target)!r}).write_text('no_write', encoding='utf-8')\n"
                    "print('UNEXPECTED_RO_WRITE')\n"
                ),
            )
            res_ro = ws.run_octopus(
                ["run", "--policy", str(ro_policy), "--cwd", str(ws.path), "--", sys.executable, str(ro_write_script)],
                octopus_bin=octo,
            )
            self.assertNotIn("UNEXPECTED_RO_WRITE", res_ro.stdout)
            helpers.assert_blocked_outcome(res_ro)
            self.assertIn("blocked_by_octopus_policy", res_ro.stderr.lower())
            self.assertFalse(ro_target.exists(), "allow_write: [] must block workspace write")
            self.assertTrue(out_dir.is_dir())

    def test_f1_b03_denied_domain_precedence_over_allowed(self) -> None:
        """F1-BVA: `denied_domains` takes strict precedence when a host appears in both allow and deny lists."""
        octo = helpers.require_octopus_bin()
        with helpers.LocalLoopbackMockServer() as srv, helpers.TempWorkspace() as ws:
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [srv.host_port],
                    "denied_domains": [srv.host_port],
                    "commands": {"allow": ["python", "python3"]},
                },
            )
            script = ws.write_file("probe.py", helpers.proxy_probe_script(f"{srv.base_url}/ok"))
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--", sys.executable, str(script)],
                octopus_bin=octo,
            )
            helpers.assert_blocked_outcome(res, mock_server=srv)

    def test_f1_b04_forbidden_command_and_shell_blocked(self) -> None:
        """F1-BVA: Forbidden shells (`bash`, `sh`, `powershell`, `cmd`) are rejected pre-flight."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [],
                    "commands": {
                        "allow": ["python", "python3"],
                        "deny": ["bash", "sh", "powershell", "pwsh", "cmd"],
                    },
                },
            )
            shell_cmd = ["cmd", "/c", "echo", "FORBIDDEN_SHELL_RAN"] if sys.platform == "win32" else ["sh", "-c", "echo FORBIDDEN_SHELL_RAN"]
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--", *shell_cmd],
                octopus_bin=octo,
            )
            self.assertNotEqual(res.returncode, 0, f"Forbidden shell unexpectedly exited 0: {res.combined_output}")
            self.assertNotIn("FORBIDDEN_SHELL_RAN", res.stdout)

    def test_f1_b05_timeout_terminates_runaway_child(self) -> None:
        """F1-BVA: `--timeout 1` kills a runaway sleeping child promptly and exits non-zero."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            policy = ws.write_json(
                "policy.json",
                {"allowed_domains": [], "commands": {"allow": ["python", "python3"]}},
            )
            sleeper = ws.write_file("sleep.py", "import time; print('STARTED', flush=True); time.sleep(30)\n")
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--timeout", "1", "--", sys.executable, str(sleeper)],
                octopus_bin=octo,
                timeout=12.0,
            )
            self.assertFalse(res.timed_out, "Outer test harness timed out; octopus --timeout did not kill child")
            self.assertNotEqual(res.returncode, 0, "Timed-out child must cause non-zero exit")
            self.assertLess(res.elapsed_s, 10.0, f"Timeout enforcement took too long: {res.elapsed_s:.2f}s")

    # ------------------------------------------------------------------
    # F2 Boundaries (5 tests)
    # ------------------------------------------------------------------

    def test_f2_b01_corrupt_rl_policy_file_ignored_when_default_off(self) -> None:
        """F2-BVA: Corrupt `config/rl_defense_policy.json` is ignored and untouched when D3QN is default-off."""
        cfg = helpers.get_config()
        octo = helpers.require_octopus_bin(cfg)
        agent_bin = helpers.require_agent_bin(cfg)
        corrupt_text = "{NOT_VALID_JSON!!!"

        with helpers.TempWorkspace() as ws:
            rl_file = ws.write_file("config/rl_defense_policy.json", corrupt_text)
            policy = ws.write_json(
                "policy.json",
                {"allowed_domains": [], "commands": {"allow": ["python", "python3"]}},
            )
            script = ws.write_file("ok.py", "print('CORRUPT_RL_IGNORED')\n")
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--cwd", str(ws.path), "--", sys.executable, str(script)],
                octopus_bin=octo,
                env=helpers.default_clean_env(),
            )
            self.assertEqual(res.returncode, 0, res.combined_output)
            self.assertIn("CORRUPT_RL_IGNORED", res.stdout)
            self.assertEqual(rl_file.read_text(encoding="utf-8"), corrupt_text)

            with helpers.WebServerHandle(ws, agent_bin=agent_bin) as srv:
                code, data = srv.post_json(
                    "/api/evaluate-cedar",
                    {"principal": "document_arm", "action": "extract", "resource": "doc_1", "context": {}},
                )
                self.assertEqual(code, 200)
                self.assertTrue(data.get("is_allowed"))
            self.assertEqual(rl_file.read_text(encoding="utf-8"), corrupt_text)

    def test_f2_b02_poisoned_hard_mitigation_qtable_cannot_veto_allow(self) -> None:
        """F2-BVA: A Q-table poisoned toward `HardMitigation` cannot veto a Cedar-allowed action even with advisory RL enabled."""
        agent_bin = helpers.require_agent_bin()
        with helpers.TempWorkspace() as ws:
            ws.write_poisoned_rl_policy(bias="HardMitigation")
            with helpers.WebServerHandle(
                ws,
                agent_bin=agent_bin,
                extra_env={"OCTOPUS_ENABLE_RL_ADVISORY": "1"},
            ) as srv:
                cs, st_data = srv.get_json("/api/status")
                self.assertEqual(cs, 200)
                rl_st = st_data.get("rl_active_defense") or {}
                self.assertTrue(rl_st.get("enabled"), f"Expected RL advisory enabled: {rl_st}")
                self.assertGreater(
                    int(rl_st.get("q_table_entries", 0)),
                    0,
                    f"Poisoned Q-table was not loaded into /api/status: {rl_st}",
                )

                c1, d1 = srv.post_json(
                    "/api/evaluate-cedar",
                    {"principal": "document_arm", "action": "extract", "resource": "doc_1", "context": {}},
                )
                self.assertEqual(c1, 200)
                self.assertTrue(d1.get("is_allowed"), f"Poisoned HardMitigation Q-table vetoed allow: {d1}")
                self.assertNotIn("VETO BY RL", str(d1.get("reason", "")).upper())

                c2, d2 = srv.post_json(
                    "/api/evaluate-cedar",
                    {
                        "principal": "network_arm",
                        "action": "egress",
                        "resource": "https://www.google.com",
                        "context": {"destination_domain": "www.google.com"},
                    },
                )
                self.assertEqual(c2, 200)
                self.assertTrue(d2.get("is_allowed"), f"Poisoned HardMitigation Q-table vetoed Google egress: {d2}")

    def test_f2_b03_poisoned_passive_observe_qtable_cannot_allow_deny(self) -> None:
        """F2-BVA: A Q-table poisoned toward `PassiveObserve` cannot weaken a Cedar deny decision."""
        agent_bin = helpers.require_agent_bin()
        with helpers.TempWorkspace() as ws:
            ws.write_poisoned_rl_policy(bias="PassiveObserve")
            with helpers.WebServerHandle(
                ws,
                agent_bin=agent_bin,
                extra_env={"OCTOPUS_ENABLE_RL_ADVISORY": "1"},
            ) as srv:
                cs, st_data = srv.get_json("/api/status")
                self.assertEqual(cs, 200)
                rl_st = st_data.get("rl_active_defense") or {}
                self.assertTrue(rl_st.get("enabled"), f"Expected RL advisory enabled: {rl_st}")
                self.assertGreater(
                    int(rl_st.get("q_table_entries", 0)),
                    0,
                    f"Poisoned Q-table was not loaded into /api/status: {rl_st}",
                )

                for req in (
                    {
                        "principal": "network_arm",
                        "action": "egress",
                        "resource": "https://evil.example.com",
                        "context": {"destination_domain": "evil.example.com"},
                    },
                    {
                        "principal": "rogue_adversary",
                        "action": "extract",
                        "resource": "doc_secret",
                        "context": {},
                    },
                ):
                    code, resp = srv.post_json("/api/evaluate-cedar", req)
                    self.assertEqual(code, 200)
                    self.assertFalse(resp.get("is_allowed"), f"Poisoned PassiveObserve permitted deny: {resp}")

    def test_f2_b04_dogwood_temporal_bypass_rejected(self) -> None:
        """F2-BVA: Dogwood temporal prerequisite missing is NOT self-healed by RL; schema errors return null RL tier."""
        agent_bin = helpers.require_agent_bin()
        with helpers.TempWorkspace() as ws:
            ws.write_poisoned_rl_policy(bias="PassiveObserve")
            with helpers.WebServerHandle(
                ws,
                agent_bin=agent_bin,
                extra_env={"OCTOPUS_ENABLE_RL_ADVISORY": "1"},
            ) as srv:
                code, resp = srv.post_json(
                    "/api/evaluate-cedar",
                    {
                        "principal": "ledger_arm",
                        "action": "write",
                        "resource": "main_ledger",
                        "context": {"amount_cents": 5000, "approved": True},
                        "attach_supervisor_approval": True,
                    },
                )
                self.assertEqual(code, 200)
                self.assertFalse(resp.get("is_allowed"), f"Dogwood prerequisite unexpectedly bypassed: {resp}")
                self.assertNotIn("rl_self_healed", json.dumps(resp).lower())

                # Schema tamper check must not emit hardcoded "MicroContainment"
                code2, resp2 = srv.post_json(
                    "/api/evaluate-cedar",
                    {
                        "principal": "ledger_arm",
                        "action": "write",
                        "resource": "main_ledger",
                        "context": {"amount_cents": 100.5, "approved": True},
                    },
                )
                self.assertEqual(code2, 200)
                self.assertFalse(resp2.get("is_allowed"))
                self.assertIsNone(
                    resp2.get("rl_action_tier"),
                    f"Schema error must not inject rl_action_tier: {resp2}",
                )

    def test_f2_b05_governor_hazard_zero_rl_attenuation(self) -> None:
        """F2-BVA: `POST /api/governor/inject-sample` enforces `effective_epsilon_t == raw_epsilon_t` (0% RL attenuation)."""
        agent_bin = helpers.require_agent_bin()
        with helpers.TempWorkspace() as ws:
            ws.write_poisoned_rl_policy(bias="HardMitigation")
            with helpers.WebServerHandle(
                ws,
                agent_bin=agent_bin,
                extra_env={"OCTOPUS_ENABLE_RL_ADVISORY": "1"},
            ) as srv:
                c1, r_no_rl = srv.post_json(
                    "/api/governor/inject-sample",
                    {"event_type": "shell_exec", "is_malicious": True, "use_rl_mitigation": False},
                )
                self.assertEqual(c1, 200)
                self.assertAlmostEqual(
                    float(r_no_rl["effective_epsilon_t"]),
                    float(r_no_rl["raw_epsilon_t"]),
                    places=9,
                )

                srv.post_json("/api/governor/reset", {})

                c2, r_with_rl = srv.post_json(
                    "/api/governor/inject-sample",
                    {"event_type": "shell_exec", "is_malicious": True, "use_rl_mitigation": True},
                )
                self.assertEqual(c2, 200)
                self.assertAlmostEqual(
                    float(r_with_rl["effective_epsilon_t"]),
                    float(r_with_rl["raw_epsilon_t"]),
                    places=9,
                    msg=f"RL attenuated Governor hazard rate: {r_with_rl}",
                )
                self.assertAlmostEqual(
                    float(r_with_rl["survival_probability"]),
                    float(r_no_rl["survival_probability"]),
                    places=9,
                )

    # ------------------------------------------------------------------
    # F3 Boundaries (5 tests)
    # ------------------------------------------------------------------

    def test_f3_b01_missing_policy_flag_fails_closed(self) -> None:
        """F3-BVA: `octopus run` without `--policy` fails closed without executing child."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            res = ws.run_octopus(
                ["run", "--", sys.executable, "-c", "print('SHOULD_NOT_RUN')"],
                octopus_bin=octo,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertNotIn("SHOULD_NOT_RUN", res.stdout)

    def test_f3_b02_nonexistent_policy_path_fails_closed(self) -> None:
        """F3-BVA: `octopus run --policy <missing>` fails closed without executing child."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            res = ws.run_octopus(
                ["run", "--policy", str(ws.path / "does_not_exist.json"), "--", sys.executable, "-c", "print('SHOULD_NOT_RUN')"],
                octopus_bin=octo,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertNotIn("SHOULD_NOT_RUN", res.stdout)

    def test_f3_b03_malformed_json_and_cedar_policies_fail_closed(self) -> None:
        """F3-BVA: Malformed `.json` and malformed `.cedar` policies fail closed before child spawn."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            bad_json = ws.write_file("bad.json", "{not valid json")
            bad_cedar = ws.write_file("bad.cedar", "permit (")
            for p in (bad_json, bad_cedar):
                res = ws.run_octopus(
                    ["run", "--policy", str(p), "--", sys.executable, "-c", "print('SHOULD_NOT_RUN')"],
                    octopus_bin=octo,
                )
                self.assertNotEqual(res.returncode, 0, f"Malformed policy {p.name} did not fail closed")
                self.assertNotIn("SHOULD_NOT_RUN", res.stdout)

    def test_f3_b04_missing_double_dash_or_empty_command_fails_closed(self) -> None:
        """F3-BVA: Missing `--` or empty command after `--` fails closed (never falls through to demo)."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            policy = ws.write_json("policy.json", {"allowed_domains": []})
            for args in (["run", "--policy", str(policy)], ["run", "--policy", str(policy), "--"]):
                res = ws.run_octopus(args, octopus_bin=octo)
                self.assertNotEqual(res.returncode, 0, f"Expected non-zero for {args}, got {res.returncode}")
                self.assertNotIn("9-scenario", res.stdout.lower())

    def test_f3_b05_invalid_flag_and_invalid_sandbox_mode_fail_closed(self) -> None:
        """F3-BVA: Unknown flags and invalid `--sandbox` modes fail closed."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            policy = ws.write_json("policy.json", {"allowed_domains": []})
            r1 = ws.run_octopus(["--definitely-unknown-flag"], octopus_bin=octo)
            self.assertNotEqual(r1.returncode, 0)

            r2 = ws.run_octopus(
                ["run", "--policy", str(policy), "--sandbox", "invalid_tier", "--", sys.executable, "-c", "print('RAN')"],
                octopus_bin=octo,
            )
            self.assertNotEqual(r2.returncode, 0)
            self.assertNotIn("RAN", r2.stdout)

    # ------------------------------------------------------------------
    # F4 Boundaries (5 tests)
    # ------------------------------------------------------------------

    def test_f4_b01_no_internal_agent_role_dirs_anywhere(self) -> None:
        """F4-BVA: Zero tracked Teamwork role folders or coordination state files anywhere in repo."""
        repo = helpers.get_config().repo_root
        tracked = helpers.git_ls_files(repo)
        forbidden_names = {"DISPATCH.md", "BRIEFING.md", "handoff.md", "ORIGINAL_REQUEST.md", "GATE_STATUS.md"}
        forbidden_segments = ("implementer_", "reviewer_", "victory_auditor", "sentinel_victory_auditor")
        hits = []
        for p in tracked:
            base = p.rsplit("/", 1)[-1]
            if base in forbidden_names or any(seg in p for seg in forbidden_segments):
                hits.append(p)
        self.assertEqual(hits, [], f"Internal agent state files tracked in repo: {hits}")

    def test_f4_b02_no_duplicate_test_dir_or_msi_or_zip(self) -> None:
        """F4-BVA: Zero tracked `test/` duplicate dir or `.msi`/`.zip`/`.exe`/`.log` artifacts."""
        repo = helpers.get_config().repo_root
        tracked = helpers.git_ls_files(repo)
        bad = [
            p
            for p in tracked
            if p.startswith("test/") or helpers.FORBIDDEN_BINARY_ARCHIVE_RE.search(p)
        ]
        self.assertEqual(bad, [], f"Duplicate test/ or binary/archive files tracked: {bad}")

    def test_f4_b03_zero_hardcoded_local_paths_in_docs(self) -> None:
        """F4-BVA: `README.md`, `docs/**/*.md`, `reports/*.md`, and `examples/**/*.md` contain zero `file:///`, `d:\\harfile`, or `d:\\tools` leaks."""
        repo = helpers.get_config().repo_root
        md_files = [repo / "README.md"]
        for sub_dir, recursive in (("docs", True), ("reports", False), ("examples", True)):
            d = repo / sub_dir
            if d.is_dir():
                md_files.extend(sorted(d.rglob("*.md") if recursive else d.glob("*.md")))
        leaks = []
        pattern = re.compile(r"(file:///|d:[/\\]harfile|d:[/\\]tools|c:[/\\]users[/\\])", re.IGNORECASE)
        for f in md_files:
            if not f.is_file():
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            m = pattern.search(text)
            if m:
                leaks.append(f"{f.relative_to(repo)}: {m.group(0)}")
        self.assertEqual(leaks, [], f"Hardcoded local filesystem paths in docs: {leaks}")

    def test_f4_b04_no_stale_port_5005_or_start_exe_headline(self) -> None:
        """F4-BVA: `README.md` & all `docs/**/*.md` omit `:5005`, `start.exe`, banned OshoosiClaw docs, and D3QN in Mermaid."""
        repo = helpers.get_config().repo_root
        targets = [repo / "README.md"] + sorted((repo / "docs").rglob("*.md"))
        for doc in targets:
            self.assertTrue(doc.is_file(), f"Missing doc file: {doc}")
            text = doc.read_text(encoding="utf-8", errors="replace")
            self.assertNotIn(":5005", text, f"Stale port :5005 found in {doc.name}")
            self.assertNotIn("start.exe", text.lower(), f"Stale start.exe reference in {doc.name}")
        for banned_rel in helpers.FORBIDDEN_OSHOOSICLAW_FILES:
            self.assertFalse(
                (repo / banned_rel).exists(),
                f"Banned hygiene file exists on disk: {banned_rel}",
            )
        mermaid_violations = helpers.validate_docs_mermaid_no_d3qn(repo / "docs")
        self.assertEqual(mermaid_violations, [], "; ".join(mermaid_violations))

    def test_f4_b05_cli_execution_leaves_repo_git_status_clean(self) -> None:
        """F4-BVA: Running `octopus` CLI leaves `git status --porcelain` clean and unchanged."""
        cfg = helpers.get_config()
        octo = helpers.require_octopus_bin(cfg)
        repo = cfg.repo_root

        before = helpers.git_status_porcelain(repo)
        with helpers.TempWorkspace() as ws:
            policy = ws.write_json("policy.json", {"allowed_domains": [], "commands": {"allow": ["python", "python3"]}})
            script = ws.write_file("ok.py", "print('clean_git_ok')\n")
            res1 = ws.run_octopus(["--help"], octopus_bin=octo, cwd=repo)
            self.assertEqual(res1.returncode, 0, res1.combined_output)
            res2 = ws.run_octopus(["run", "--policy", str(policy), "--", sys.executable, str(script)], octopus_bin=octo, cwd=repo)
            self.assertEqual(res2.returncode, 0, res2.combined_output)
        after = helpers.git_status_porcelain(repo)

        self.assertEqual(after, before, f"CLI execution dirtied git status: before={before}, after={after}")
        if cfg.allow_uncommitted_e2e:
            non_e2e = [
                line for line in after
                if "tests/e2e_release" not in line.replace("\\", "/")
            ]
            self.assertEqual(non_e2e, [], f"Dirty repo entries outside tests/e2e_release/: {non_e2e}")
        else:
            self.assertEqual(after, [], f"Repo git status is not clean: {after}")

    # ------------------------------------------------------------------
    # F5 Boundaries (5 tests)
    # ------------------------------------------------------------------

    def test_f5_b01_all_docs_relative_links_resolve(self) -> None:
        """F5-BVA: Every relative Markdown link in `README.md` and `docs/**/*.md` resolves to an existing file."""
        repo = helpers.get_config().repo_root
        md_files = [repo / "README.md"] + sorted((repo / "docs").rglob("*.md"))
        broken = []
        for f in md_files:
            text = f.read_text(encoding="utf-8", errors="replace")
            for target in helpers.extract_markdown_links(text):
                rel = target.split("#", 1)[0].split("?", 1)[0]
                if not rel:
                    continue
                resolved = (f.parent / rel).resolve()
                if not resolved.exists():
                    broken.append(f"{f.relative_to(repo)} -> {target}")
        self.assertEqual(broken, [], f"Broken relative Markdown links: {broken}")

    def test_f5_b02_readme_internal_anchors_resolve(self) -> None:
        """F5-BVA: Intra-file `#anchor` links in `README.md` & `docs/**/*.md` and cross-file `path.md#anchor` fragments resolve."""
        repo = helpers.get_config().repo_root
        md_files = [repo / "README.md"] + sorted((repo / "docs").rglob("*.md"))
        slug_cache: dict[Path, set[str]] = {}

        def _slugs_for(path: Path) -> set[str]:
            resolved = path.resolve()
            if resolved not in slug_cache:
                slug_cache[resolved] = helpers.extract_heading_slugs(
                    resolved.read_text(encoding="utf-8", errors="replace")
                )
            return slug_cache[resolved]

        broken = []
        for f in md_files:
            if not f.is_file():
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            slugs = _slugs_for(f)
            for anchor in helpers.extract_markdown_anchors(text):
                if anchor.lower() not in slugs:
                    broken.append(f"{f.relative_to(repo)} -> #{anchor}")
            for target in helpers.extract_markdown_links(text):
                if "#" not in target:
                    continue
                rel_part, frag = target.split("#", 1)
                rel_part = rel_part.split("?", 1)[0]
                frag = frag.strip()
                if not rel_part or not frag:
                    continue
                resolved = (f.parent / rel_part).resolve()
                if resolved.is_file() and resolved.suffix.lower() in (".md", ".markdown"):
                    if frag.lower() not in _slugs_for(resolved):
                        broken.append(f"{f.relative_to(repo)} -> {target}")
        self.assertEqual(broken, [], f"Broken Markdown anchors: {broken}")

    def test_f5_b03_vassilev_report_frames_d3qn_advisory(self) -> None:
        """F5-BVA: `reports/vassilev_mathematical_validation.md` frames D3QN as optional/advisory only."""
        repo = helpers.get_config().repo_root
        report = repo / "reports" / "vassilev_mathematical_validation.md"
        self.assertTrue(report.is_file(), f"Missing report: {report}")
        lower = report.read_text(encoding="utf-8", errors="replace").lower()
        self.assertTrue(
            "advisory" in lower or "optional" in lower,
            "vassilev_mathematical_validation.md must frame D3QN as optional/advisory",
        )
        self.assertTrue(
            "deterministic" in lower and ("cedar" in lower or "containment" in lower),
            "vassilev_mathematical_validation.md must distinguish deterministic containment",
        )

    def test_f5_b04_quickstart_policy_no_wildcard_or_imds(self) -> None:
        """F5-BVA: `examples/quickstart/policy.json` has zero wildcard `*` allows and does not permit IMDS."""
        repo = helpers.get_config().repo_root
        p_json = repo / "examples" / "quickstart" / "policy.json"
        data = json.loads(p_json.read_text(encoding="utf-8"))
        allowed = [str(x).strip() for x in data.get("allowed_domains", [])]
        self.assertNotIn("*", allowed, "Quickstart policy must not allow wildcard '*'")
        self.assertNotIn("169.254.169.254", allowed, "Quickstart policy must not allow IMDS")

    def test_f5_b05_cargo_toml_bin_and_deterministic_description(self) -> None:
        """F5-BVA: `Cargo.toml` defines `[[bin]] name = \"octopus\"` and deterministic containment description."""
        repo = helpers.get_config().repo_root
        cargo_toml = (repo / "Cargo.toml").read_text(encoding="utf-8")
        self.assertRegex(cargo_toml, r'\[\[bin\]\][\s\S]*?name\s*=\s*"octopus"')
        m = re.search(r'^description\s*=\s*"([^"]+)"', cargo_toml, re.MULTILINE)
        self.assertIsNotNone(m, "Missing package description in Cargo.toml")
        desc = m.group(1).lower()
        self.assertNotIn("d3qn", desc)
        self.assertNotIn("q-learning", desc)
        self.assertTrue(
            any(k in desc for k in ("deterministic", "cedar", "wasm", "sandbox", "containment")),
            f"Cargo.toml description should reflect deterministic containment: {desc!r}",
        )

    # ------------------------------------------------------------------
    # F6 Boundaries (5 tests)
    # ------------------------------------------------------------------

    def test_f6_b01_siblings_zero_untracked_files(self) -> None:
        """F6-BVA: `killswitch` has zero untracked files and `sandbox-runtime` has only allowed pre-existing untracked artifacts."""
        sr_violations = helpers.validate_sibling_repo_state(
            helpers.SIBLING_SANDBOX_RUNTIME,
            expected_head_sha=helpers.BASELINE_SANDBOX_RUNTIME_SHA,
            allowed_untracked=helpers.SANDBOX_RUNTIME_ALLOWED_UNTRACKED,
            allowed_porcelain=helpers.SANDBOX_RUNTIME_ALLOWED_PORCELAIN,
        )
        self.assertEqual(sr_violations, [], "; ".join(sr_violations))

        ks = helpers.SIBLING_KILLSWITCH
        res = helpers.run_git(ks, ["ls-files", "--others", "--exclude-standard"])
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.strip(), "", f"Untracked files in {ks}: {res.stdout}")
        ks_violations = helpers.validate_sibling_repo_state(
            ks,
            expected_head_sha=helpers.BASELINE_KILLSWITCH_SHA,
        )
        self.assertEqual(ks_violations, [], "; ".join(ks_violations))

    def test_f6_b02_no_dot_agents_teamwork_dir_in_any_repo(self) -> None:
        """F6-BVA: `.agents/teamwork` directory does not exist on disk in AgentOctopus or sibling repos."""
        repos = [helpers.get_config().repo_root, helpers.SIBLING_SANDBOX_RUNTIME, helpers.SIBLING_KILLSWITCH]
        for repo in repos:
            self.assertFalse(
                (repo / ".agents" / "teamwork").exists(),
                f".agents/teamwork directory exists on disk in {repo}",
            )

    def test_f6_b03_origin_main_in_sync_with_head(self) -> None:
        """F6-BVA: Local `HEAD` matches `origin/main` (gated by --skip-remote)."""
        if helpers.get_config().skip_remote:
            self.skipTest("Explicit --skip-remote specified")
        repo = helpers.get_config().repo_root
        local_head = helpers.git_rev_parse(repo, "HEAD")
        res = helpers.run_git(repo, ["ls-remote", "--heads", "origin", "main"])
        self.assertEqual(res.returncode, 0, f"git ls-remote failed: {res.stderr}")
        parts = res.stdout.strip().split()
        self.assertTrue(parts, "origin/main not found via git ls-remote")
        remote_head = parts[0]
        self.assertEqual(
            local_head,
            remote_head,
            f"Local HEAD ({local_head}) differs from origin/main ({remote_head})",
        )

    def test_f6_b04_history_not_force_rewritten(self) -> None:
        """F6-BVA: Commit count >= 147 and `7fd028b` is an ancestor of `HEAD` (and `origin/main` if remote enabled)."""
        repo = helpers.get_config().repo_root
        res = helpers.run_git(repo, ["rev-list", "--count", "HEAD"])
        self.assertEqual(res.returncode, 0, res.stderr)
        count = int(res.stdout.strip())
        self.assertGreaterEqual(count, 147, f"Expected >= 147 commits in preserved history, got {count}")
        self.assertTrue(helpers.git_is_ancestor(repo, helpers.BASELINE_ANCESTOR_SHA, "HEAD"))
        if not helpers.get_config().skip_remote:
            self.assertTrue(helpers.git_is_ancestor(repo, helpers.BASELINE_ANCESTOR_SHA, "origin/main"))

    def test_f6_b05_github_topics_and_metadata_present(self) -> None:
        """F6-BVA: `gh repo view` confirms `oyesanyf/AgentOctopus` URL, `main` default branch, and non-empty clean description."""
        if helpers.get_config().skip_remote:
            self.skipTest("Explicit --skip-remote specified")
        meta = helpers.run_gh_repo_view(helpers.EXPECTED_REMOTE_SUBSTR)
        self.assertIn(helpers.EXPECTED_REMOTE_SUBSTR.lower(), str(meta.get("url", "")).lower())
        default_branch = (meta.get("defaultBranchRef") or {}).get("name")
        self.assertEqual(default_branch, "main")
        desc = (meta.get("description") or "").strip()
        self.assertTrue(desc, f"GitHub repository description is empty: {meta}")
        lower = desc.lower()
        for banned in ("d3qn", "q-learning", "reinforcement learning"):
            self.assertNotIn(banned, lower, f"GitHub description must not headline `{banned}`: {desc!r}")
