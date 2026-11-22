"""12 isolated self-tests validating the E2E runner, mock binaries, proxy oracle, and validators without Cargo."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import unittest

from .. import helpers
from .. import run_e2e


def _create_mock_octopus_shim(ws: helpers.TempWorkspace, leaky_mode: bool = False) -> Path:
    """Create a cross-platform mock `octopus` binary (Python script + .cmd/.sh wrapper)."""
    mock_py = ws.write_file(
        "mock_octopus_impl.py",
        f"""
import http.server
import json
import os
from pathlib import Path
import socketserver
import subprocess
import sys
import threading
import urllib.request

LEAKY_MODE = {leaky_mode!r}

def main():
    args = sys.argv[1:]
    if args == ["--help"] or args == ["-h"]:
        print("octopus - Deterministic Rust agent containment runtime")
        print("Usage: octopus <COMMAND>\\nCommands:\\n  run  Run a command under deterministic containment")
        return 0
    if not args or args[0] != "run":
        print("Usage error: expected `run` subcommand", file=sys.stderr)
        return 2
    if "--help" in args or "-h" in args:
        if LEAKY_MODE:
            print("octopus run")
            return 0
        print("Usage: octopus run --policy <PATH> [--sandbox <strict|standard>] [--timeout <SECS>] [--cwd <DIR>] [--json] -- <COMMAND>...")
        return 0

    if "--" not in args:
        print("Missing `--` separator", file=sys.stderr)
        return 2
    sep = args.index("--")
    opts = args[:sep]
    cmd = args[sep + 1:]
    if not cmd:
        print("Missing command after `--`", file=sys.stderr)
        return 2

    policy_path = None
    cwd = None
    timeout_s = None
    json_out = False
    i = 1
    while i < len(opts):
        tok = opts[i]
        if tok == "--policy" and i + 1 < len(opts):
            policy_path = Path(opts[i + 1])
            i += 2
        elif tok == "--cwd" and i + 1 < len(opts):
            cwd = Path(opts[i + 1])
            i += 2
        elif tok == "--timeout" and i + 1 < len(opts):
            timeout_s = float(opts[i + 1])
            i += 2
        elif tok == "--sandbox" and i + 1 < len(opts):
            if opts[i + 1] not in ("strict", "standard"):
                print("Invalid sandbox mode", file=sys.stderr)
                return 2
            i += 2
        elif tok == "--json":
            json_out = True
            i += 1
        else:
            print(f"Unknown option: {{tok}}", file=sys.stderr)
            return 2

    if policy_path is None or not policy_path.is_file():
        print("Missing or unreadable --policy", file=sys.stderr)
        return 2

    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Invalid policy JSON: {{exc}}", file=sys.stderr)
        return 2

    allowed = set(policy.get("allowed_domains", []))
    denied = set(policy.get("denied_domains", []))

    class ProxyHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            return
        def do_GET(self):
            from urllib.parse import urlparse
            u = urlparse(self.path)
            host_port = u.netloc
            if not LEAKY_MODE and (host_port in denied or host_port not in allowed or "169.254.169.254" in host_port):
                body = json.dumps({{"error": "blocked_by_octopus_policy", "layer": "Cedar+EgressGuard", "host": host_port}}).encode()
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            with urllib.request.urlopen(self.path, timeout=5) as resp:
                data = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        child_env = os.environ.copy()
        child_env["HTTP_PROXY"] = f"http://127.0.0.1:{{port}}"
        child_env["HTTPS_PROXY"] = f"http://127.0.0.1:{{port}}"
        child_env["NO_PROXY"] = "127.0.0.1,localhost"
        proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=child_env, timeout=timeout_s)
        if json_out:
            print(json.dumps({{"exit_code": proc.returncode, "status": "ok" if proc.returncode == 0 else "nonzero"}}))
        return proc.returncode
    finally:
        srv.shutdown()
        srv.server_close()

if __name__ == "__main__":
    raise SystemExit(main())
""".lstrip()
    )
    if sys.platform == "win32":
        shim = ws.write_file(
            "octopus.cmd",
            f'@echo off\r\n"{sys.executable}" "{mock_py}" %*\r\n',
        )
    else:
        shim = ws.write_file(
            "octopus",
            f'#!/usr/bin/env sh\nexec "{sys.executable}" "{mock_py}" "$@"\n',
        )
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return shim


class TestE2ESuiteSelfTest(unittest.TestCase):
    """12 isolated pre-M4 self-tests verifying suite correctness, regressions, and failure sensitivity."""

    def test_selftest_list_and_dry_run_pre_m2(self) -> None:
        """Self-test 1: `--list --json` reports 82 tests (Tiers 1-5) and `--dry-run` exits 0 pre-M2 with zero Cargo calls."""
        res_list = helpers.run_subprocess_safe(
            [sys.executable, "-m", "tests.e2e_release", "--list", "--json"],
            cwd=helpers.REPO_ROOT,
        )
        self.assertEqual(res_list.returncode, 0, res_list.combined_output)
        data = json.loads(res_list.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["total"], 82)

        res_dry = helpers.run_subprocess_safe(
            [sys.executable, "-m", "tests.e2e_release", "--dry-run", "--json"],
            cwd=helpers.REPO_ROOT,
        )
        self.assertEqual(res_dry.returncode, 0, res_dry.combined_output)
        dry_data = json.loads(res_dry.stdout)
        self.assertTrue(dry_data["ok"])
        self.assertEqual(dry_data["mode"], "dry-run")

    def test_selftest_missing_binary_fails_closed(self) -> None:
        """Self-test 2: Running `--tier 1` with missing `--bin` fails closed with exit code 2 (zero fake skips)."""
        missing = str(helpers.REPO_ROOT / "__nonexistent_dir__" / "octopus.exe")
        res = helpers.run_subprocess_safe(
            [sys.executable, "-m", "tests.e2e_release", "--tier", "1", "--bin", missing],
            cwd=helpers.REPO_ROOT,
        )
        self.assertEqual(res.returncode, 2, f"Expected fail-closed exit 2, got {res.returncode}: {res.combined_output}")

        with helpers.TempWorkspace() as empty_ws:
            old_env = os.environ.pop("OCTOPUS_BIN", None)
            try:
                self.assertIsNone(
                    helpers.resolve_octopus_bin(explicit_bin=None, repo_root=empty_ws.path, allow_cargo_build=False)
                )
            finally:
                if old_env is not None:
                    os.environ["OCTOPUS_BIN"] = old_env

    def test_selftest_mock_binary_shim_tier1_f1_f3(self) -> None:
        """Self-test 3: Tier 1 F1+F3 tests pass against strict mock shim and FAIL against leaky mock shim."""
        from .. import test_tier1_features

        TestTier1Features = test_tier1_features.TestTier1Features
        old_cfg = helpers.get_config()
        try:
            with helpers.TempWorkspace() as shim_ws:
                strict_shim = _create_mock_octopus_shim(shim_ws, leaky_mode=False)
                helpers.set_config(
                    helpers.E2EConfig(
                        repo_root=helpers.REPO_ROOT,
                        octopus_bin=strict_shim,
                        skip_cargo=True,
                        skip_remote=True,
                    )
                )
                suite = unittest.TestSuite(
                    [
                        TestTier1Features("test_f1_01_json_policy_allows_workspace_write"),
                        TestTier1Features("test_f1_02_json_policy_allows_listed_loopback_http"),
                        TestTier1Features("test_f1_03_json_policy_blocks_unlisted_http"),
                        TestTier1Features("test_f3_01_octopus_help_exits_zero_without_demo"),
                        TestTier1Features("test_f3_02_octopus_run_help_documents_contract"),
                        TestTier1Features("test_f3_03_child_exit_code_and_stdio_streamed"),
                        TestTier1Features("test_f3_04_cwd_flag_changes_child_working_directory"),
                        TestTier1Features("test_f3_05_json_flag_produces_valid_json_output"),
                    ]
                )
                res_strict = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
                self.assertTrue(
                    res_strict.wasSuccessful(),
                    f"Strict mock shim failed Tier 1 F1/F3 tests: {res_strict.failures} {res_strict.errors}",
                )

                # Negative sensitivity check: leaky shim MUST cause test_f1_03 & test_f3_02 to FAIL!
                leaky_shim = _create_mock_octopus_shim(shim_ws, leaky_mode=True)
                helpers.set_config(helpers.E2EConfig(repo_root=helpers.REPO_ROOT, octopus_bin=leaky_shim))
                leaky_suite = unittest.TestSuite(
                    [
                        TestTier1Features("test_f1_03_json_policy_blocks_unlisted_http"),
                        TestTier1Features("test_f3_02_octopus_run_help_documents_contract"),
                    ]
                )
                res_leaky = unittest.TextTestRunner(stream=io.StringIO()).run(leaky_suite)
                self.assertFalse(res_leaky.wasSuccessful(), "Leaky mock shim was not caught by Tier 1 tests!")
                self.assertEqual(len(res_leaky.failures) + len(res_leaky.errors), 2)
        finally:
            helpers.set_config(old_cfg)

    def test_selftest_loopback_mock_http_server(self) -> None:
        """Self-test 4: `LocalLoopbackMockServer` records hits accurately and `assert_blocked_outcome` rejects bypasses."""
        with helpers.LocalLoopbackMockServer() as srv:
            import urllib.request

            with urllib.request.urlopen(f"{srv.base_url}/echo", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                body = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(body["ok"])
                self.assertEqual(body["path"], "/echo")
            self.assertEqual(srv.hit_count(), 1)

            # Sensitivity: assert_blocked_outcome must fail if exit=0 without 403 or if hit_count != 0
            ok_res = helpers.SubprocessResult(returncode=0, stdout="ok", stderr="", timed_out=False, elapsed_s=0.1)
            with self.assertRaises(AssertionError):
                helpers.assert_blocked_outcome(ok_res, mock_server=srv)

            blocked_res = helpers.SubprocessResult(
                returncode=43, stdout='{"status": 403}', stderr="blocked_by_octopus_policy", timed_out=False, elapsed_s=0.1
            )
            with self.assertRaises(AssertionError):
                helpers.assert_blocked_outcome(blocked_res, mock_server=srv)
            srv.clear_hits()
            helpers.assert_blocked_outcome(blocked_res, mock_server=srv)

    def test_selftest_hygiene_and_link_validators_clean_vs_dirty(self) -> None:
        """Self-test 5: Repo hygiene, link, and anchor validators pass on clean fixtures and fail on dirty fixtures."""
        clean_paths = ["Cargo.toml", "README.md", "src/lib.rs", "examples/quickstart/policy.json"]
        self.assertEqual(helpers.check_repo_hygiene_paths(clean_paths), [])

        dirty_paths = [
            ".agents/teamwork/handoff.md",
            "DEAD_ENDS.md",
            "TEST_READY.md",
            "PROJECT.md",
            "dist_manifest.json",
            "pyrit_test_report.json",
            "test/stale.py",
            "docs/community/LAUNCH_PLAYBOOK_500_STARS.md",
            "release/HugOS.msi",
        ]
        detected = helpers.check_repo_hygiene_paths(dirty_paths)
        self.assertEqual(len(detected), len(dirty_paths), f"Missed hygiene violations: {set(dirty_paths) - set(detected)}")

        md_clean = "# Title\nSee [License](LICENSE-MIT) and [Title](#title).\n"
        self.assertEqual(helpers.extract_markdown_links(md_clean), ["LICENSE-MIT"])
        self.assertIn("title", helpers.extract_heading_slugs(md_clean))
        self.assertEqual(helpers.extract_markdown_anchors(md_clean), ["title"])

        md_dirty = "# Intro\n[Broken](LICENSE) and [Missing](#does-not-exist)\n"
        self.assertIn("LICENSE", helpers.extract_markdown_links(md_dirty))
        self.assertNotIn("does-not-exist", helpers.extract_heading_slugs(md_dirty))

    def test_selftest_tier_filtering_and_json_report(self) -> None:
        """Self-test 6: Tier filter counts match 30/30/10/6/6 and every file in `tests/e2e_release` is stdlib-only."""
        expected_counts = {"1": 30, "2": 30, "3": 10, "4": 6, "5": 6, "all": 82}
        for tier, count in expected_counts.items():
            _, catalog = run_e2e.load_tier_suite(tier)
            self.assertEqual(len(catalog), count, f"Tier {tier} count mismatch: {len(catalog)} != {count}")

        e2e_dir = Path(__file__).resolve().parents[1]
        local_mods = {"tests", "helpers", "run_e2e", "test_tier1_features", "test_tier2_boundaries", "test_tier3_combinations", "test_tier4_scenarios", "test_tier5_adversarial", "self_tests"}
        py_files = sorted(e2e_dir.rglob("*.py"))
        self.assertGreaterEqual(len(py_files), 10)
        for pyf in py_files:
            violations = helpers.validate_stdlib_python_file(pyf, allowed_local_modules=local_mods)
            self.assertEqual(violations, [], f"Non-stdlib import in {pyf}: {violations}")

        # Sensitivity: synthetic non-stdlib import must be detected
        with helpers.TempWorkspace() as ws:
            bad_py = ws.write_file("bad_import.py", "import requests\n")
            self.assertTrue(helpers.validate_stdlib_python_file(bad_py))

    @staticmethod
    def _wrap_python_shim(ws: helpers.TempWorkspace, name: str, body: str) -> Path:
        py_path = ws.write_file(f"{name}.py", body.lstrip())
        if sys.platform == "win32":
            return ws.write_file(
                f"{name}.cmd",
                f'@echo off\r\n"{sys.executable}" "{py_path}" %*\r\n',
            )
        shim = ws.write_file(
            name,
            f'#!/usr/bin/env sh\nexec "{sys.executable}" "{py_path}" "$@"\n',
        )
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return shim

    def test_selftest_t4_01_rejects_crash_and_unmasked_cred(self) -> None:
        """Self-test 7 (Regression): `test_t4_01` fails on `crash_always` (exit 2) and `unmasked_cred`."""
        from .. import test_tier4_scenarios

        TestTier4Scenarios = test_tier4_scenarios.TestTier4Scenarios
        old_cfg = helpers.get_config()
        try:
            with helpers.TempWorkspace() as shim_ws:
                crash_shim = self._wrap_python_shim(
                    shim_ws,
                    "crash_always",
                    """
import sys
print("Simulated internal octopus crash", file=sys.stderr)
sys.exit(2)
""",
                )
                helpers.set_config(
                    helpers.E2EConfig(
                        repo_root=helpers.REPO_ROOT,
                        octopus_bin=crash_shim,
                        skip_cargo=True,
                        skip_remote=True,
                    )
                )
                res_crash = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite([TestTier4Scenarios("test_t4_01_multi_step_python_agent_containment_e2e")])
                )
                self.assertFalse(res_crash.wasSuccessful(), "test_t4_01 vacuously passed on crash_always (exit 2)!")

                unmasked_shim = self._wrap_python_shim(
                    shim_ws,
                    "unmasked_cred",
                    """
import http.server, json, os, subprocess, sys, threading, urllib.request
from pathlib import Path
from urllib.parse import urlparse

args = sys.argv[1:]
sep = args.index("--")
opts, cmd = args[:sep], args[sep + 1:]
policy = json.loads(Path(opts[opts.index("--policy") + 1]).read_text(encoding="utf-8"))
cwd = opts[opts.index("--cwd") + 1] if "--cwd" in opts else None
allowed = set(policy.get("allowed_domains", []))
denied = set(policy.get("denied_domains", []))

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): return
    def _go(self):
        u = urlparse(self.path)
        if u.netloc in denied or u.netloc not in allowed or "169.254.169.254" in u.netloc:
            b = json.dumps({"error": "blocked_by_octopus_policy"}).encode()
            self.send_response(403)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        with urllib.request.urlopen(self.path, timeout=5) as r:
            b = r.read()
            self.send_response(r.status)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    def do_GET(self): self._go()
    def do_POST(self): self._go()

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
try:
    env = os.environ.copy()
    env["HTTP_PROXY"] = f"http://127.0.0.1:{srv.server_address[1]}"
    env["HTTPS_PROXY"] = env["HTTP_PROXY"]
    # Intentionally leave OPENAI_API_KEY unmasked!
    p = subprocess.run(cmd, cwd=cwd, env=env)
    sys.exit(p.returncode)
finally:
    srv.shutdown()
    srv.server_close()
""",
                )
                helpers.set_config(
                    helpers.E2EConfig(
                        repo_root=helpers.REPO_ROOT,
                        octopus_bin=unmasked_shim,
                        skip_cargo=True,
                        skip_remote=True,
                    )
                )
                res_unmasked = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite([TestTier4Scenarios("test_t4_01_multi_step_python_agent_containment_e2e")])
                )
                self.assertFalse(res_unmasked.wasSuccessful(), "test_t4_01 vacuously passed on unmasked_cred!")
        finally:
            helpers.set_config(old_cfg)

    def test_selftest_f3_05_accepts_multiline_and_stderr_json(self) -> None:
        """Self-test 8 (Regression): `test_f3_05` passes on pretty-printed multi-line stdout and stderr `--json`."""
        from .. import test_tier1_features

        TestTier1Features = test_tier1_features.TestTier1Features
        old_cfg = helpers.get_config()
        try:
            with helpers.TempWorkspace() as shim_ws:
                for stream_target in ("stdout", "stderr"):
                    shim = self._wrap_python_shim(
                        shim_ws,
                        f"pretty_{stream_target}",
                        f"""
import json, subprocess, sys
args = sys.argv[1:]
sep = args.index("--")
cmd = args[sep + 1:]
proc = subprocess.run(cmd)
summary = json.dumps({{"exit_code": proc.returncode, "status": "ok", "nested": {{"layer": "cedar"}}}}, indent=2)
print(summary, file=sys.{stream_target})
sys.exit(proc.returncode)
""",
                    )
                    helpers.set_config(
                        helpers.E2EConfig(
                            repo_root=helpers.REPO_ROOT,
                            octopus_bin=shim,
                            skip_cargo=True,
                            skip_remote=True,
                        )
                    )
                    res = unittest.TextTestRunner(stream=io.StringIO()).run(
                        unittest.TestSuite([TestTier1Features("test_f3_05_json_flag_produces_valid_json_output")])
                    )
                    self.assertTrue(
                        res.wasSuccessful(),
                        f"test_f3_05 failed on pretty-printed {stream_target} JSON: {res.failures} {res.errors}",
                    )
        finally:
            helpers.set_config(old_cfg)

    def test_selftest_hygiene_scope_permits_rust_tests_flags_root_reports_and_oshoosiclaw_docs(self) -> None:
        """Self-test 9 (Regression): `check_repo_hygiene_paths` permits `tests/*.rs` & non-root `tests/` reports while flagging OshoosiClaw docs & root reports."""
        permitted = [
            "tests/oshoosiclaw_adapted_containment_tests.rs",
            "tests/octopus_exhaustive_test_report.json",
            "tests/strix_llm_test_report.md",
        ]
        self.assertEqual(
            helpers.check_repo_hygiene_paths(permitted),
            [],
            f"Legitimate test paths were falsely flagged: {permitted}",
        )

        flagged = [
            "docs/assets/oshoosiclaw-terminal-demo.png",
            "docs/demo/oshoosiclaw_demo.cast",
            "docs/CIS_BENCHMARK_AGENTOCTOPUS.md",
            "pyrit_test_report.json",
            "octopus_exhaustive_test_report.md",
        ]
        detected = helpers.check_repo_hygiene_paths(flagged)
        self.assertEqual(
            set(detected),
            set(flagged),
            f"Missed forbidden hygiene paths: {set(flagged) - set(detected)}",
        )

    def test_selftest_markdown_tilde_fences_and_mermaid_d3qn_rejection(self) -> None:
        """Self-test 10 (Regression): `strip_markdown_code` ignores `~~~`/nested fences, extracts image/ref links, and `test_f5_03` rejects `D3QN` inside Mermaid."""
        from .. import test_tier1_features

        TestTier1Features = test_tier1_features.TestTier1Features
        md_fenced = (
            "~~~markdown\n"
            "[fake_tilde](missing_tilde.md)\n"
            "~~~\n\n"
            "````markdown\n"
            "```markdown\n"
            "[fake_nested](missing_nested.md)\n"
            "```\n"
            "````\n"
            "![diagram](docs/arch.png)\n"
            "[ref][r1]\n\n"
            "[r1]: docs/ref_target.md\n"
        )
        self.assertEqual(
            helpers.extract_markdown_links(md_fenced),
            ["docs/arch.png", "docs/ref_target.md"],
        )

        old_cfg = helpers.get_config()
        try:
            with helpers.TempWorkspace() as fake_repo:
                padding = "\n".join(f"Line {i}: Deterministic Rust containment." for i in range(65))
                bad_readme = (
                    f"{padding}\n\n"
                    "## Containment Flow\n\n"
                    "```mermaid\n"
                    "flowchart TD\n"
                    "    Cedar --> D3QN[D3QN Gate] --> AllowDeny\n"
                    "```\n\n"
                    "## Appendix: Optional Advisory Scoring\n"
                    "D3QN is strictly optional and advisory.\n"
                )
                fake_repo.write_file("README.md", bad_readme)
                helpers.set_config(helpers.E2EConfig(repo_root=fake_repo.path))
                res_bad = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite([TestTier1Features("test_f5_03_readme_frames_d3qn_as_optional_advisory_only")])
                )
                self.assertFalse(res_bad.wasSuccessful(), "test_f5_03 failed to reject D3QN inside Mermaid block!")

                clean_readme = bad_readme.replace("D3QN[D3QN Gate]", "OSSandbox[OS Sandbox]")
                fake_repo.write_file("README.md", clean_readme)
                res_clean = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite([TestTier1Features("test_f5_03_readme_frames_d3qn_as_optional_advisory_only")])
                )
                self.assertTrue(
                    res_clean.wasSuccessful(),
                    f"test_f5_03 falsely rejected clean Mermaid diagram: {res_clean.failures} {res_clean.errors}",
                )
        finally:
            helpers.set_config(old_cfg)

    def test_selftest_t4_04_mermaid_d3qn_and_underscore_heading_slug(self) -> None:
        """Self-test 11 (Regression): `test_t4_04` rejects `D3QN` in Mermaid blocks and `github_heading_slug` + `test_f5_b02` preserve literal `_`."""
        from .. import test_tier2_boundaries
        from .. import test_tier4_scenarios

        TestTier2Boundaries = test_tier2_boundaries.TestTier2Boundaries
        TestTier4Scenarios = test_tier4_scenarios.TestTier4Scenarios

        # (b) Preserve literal underscores in github_heading_slug and resolve via test_f5_b02
        self.assertEqual(helpers.github_heading_slug("## Agent_Policy"), "agent_policy")
        self.assertEqual(helpers.github_heading_slug("Agent_Policy"), "agent_policy")
        self.assertEqual(helpers.github_heading_slug("## `WASI_ERR_ACCESS_DENIED`"), "wasi_err_access_denied")
        self.assertEqual(helpers.github_heading_slug("## _Italic_ Heading"), "italic-heading")

        old_cfg = helpers.get_config()
        try:
            with helpers.TempWorkspace() as anchor_ws:
                anchor_ws.write_file(
                    "README.md",
                    (
                        "# AgentOctopus\n\n"
                        "## Agent_Policy\n\n"
                        "See [Policy](#agent_policy) and [WASI Error](docs/ERRORS.md#wasi_err_access_denied).\n"
                    ),
                )
                anchor_ws.write_file(
                    "docs/ERRORS.md",
                    (
                        "## WASI_ERR_ACCESS_DENIED\n\n"
                        "Back to [Error](#wasi_err_access_denied).\n"
                    ),
                )
                helpers.set_config(helpers.E2EConfig(repo_root=anchor_ws.path, skip_cargo=True, skip_remote=True))
                res_anchor_ok = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite([TestTier2Boundaries("test_f5_b02_readme_internal_anchors_resolve")])
                )
                self.assertTrue(
                    res_anchor_ok.wasSuccessful(),
                    f"test_f5_b02 falsely failed on underscore anchor: {res_anchor_ok.failures} {res_anchor_ok.errors}",
                )

                anchor_ws.write_file(
                    "README.md",
                    "# AgentOctopus\n\n## Agent_Policy\n\n[Bad](#missing_underscore_anchor)\n",
                )
                res_anchor_bad = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite([TestTier2Boundaries("test_f5_b02_readme_internal_anchors_resolve")])
                )
                self.assertFalse(res_anchor_bad.wasSuccessful(), "test_f5_b02 failed to reject broken underscore anchor!")

            # (a) test_t4_04 rejects D3QN inside ```mermaid / ~~~mermaid in an isolated temp clone
            with helpers.TempWorkspace() as clone_ws:
                clone_dir = clone_ws.path / "repo_clone"
                try:
                    clone_res = helpers.run_subprocess_safe(
                        ["git", "clone", "--shared", "--quiet", str(helpers.REPO_ROOT), str(clone_dir)],
                        timeout=180.0,
                    )
                    self.assertEqual(clone_res.returncode, 0, clone_res.combined_output)

                    hygiene_bad = helpers.check_repo_hygiene_paths(helpers.git_ls_files(clone_dir))
                    if hygiene_bad:
                        rm_res = helpers.run_subprocess_safe(
                            ["git", "rm", "-q", "-f", "--ignore-unmatch", "--", *hygiene_bad],
                            cwd=clone_dir,
                            timeout=60.0,
                        )
                        self.assertEqual(rm_res.returncode, 0, rm_res.combined_output)
                        commit_res = helpers.run_subprocess_safe(
                            [
                                "git",
                                "-c",
                                "user.name=SelfTest",
                                "-c",
                                "user.email=selftest@example.invalid",
                                "commit",
                                "--quiet",
                                "-m",
                                "Clean pre-M3 hygiene in temp clone",
                            ],
                            cwd=clone_dir,
                            timeout=60.0,
                        )
                        self.assertEqual(commit_res.returncode, 0, commit_res.combined_output)

                    padding = "\n".join(f"Line {i}: Deterministic Rust containment." for i in range(65))
                    clean_readme = (
                        "# AgentOctopus\n\n"
                        "Complements `google/agentmesh` and replaces heavy Python gateways like CAGE.\n"
                        "Deterministic Cedar + Wasmtime + OS Sandbox + RT-ASP.\n\n"
                        "```bash\noctopus run --policy examples/quickstart/policy.json -- python my_agent.py\n```\n\n"
                        "Licensed under [MIT](LICENSE-MIT).\n\n"
                        f"{padding}\n\n"
                        "## Containment Flow\n\n"
                        "```mermaid\n"
                        "flowchart TD\n"
                        "    Cedar --> OSSandbox[OS Sandbox] --> AllowDeny\n"
                        "```\n\n"
                        "## Appendix: Optional Advisory Scoring\n"
                        "D3QN is strictly optional and advisory.\n"
                    )
                    (clone_dir / "README.md").write_text(clean_readme, encoding="utf-8")

                    helpers.set_config(helpers.E2EConfig(repo_root=clone_dir, skip_cargo=True, skip_remote=True))
                    res_t4_clean = unittest.TextTestRunner(stream=io.StringIO()).run(
                        unittest.TestSuite([TestTier4Scenarios("test_t4_04_staff_security_engineer_onboarding_audit")])
                    )
                    self.assertTrue(
                        res_t4_clean.wasSuccessful(),
                        f"test_t4_04 failed on clean temp clone: {res_t4_clean.failures} {res_t4_clean.errors}",
                    )

                    # Backtick ```mermaid fence containing D3QN past line 60 MUST fail test_t4_04
                    bad_backtick = clean_readme.replace("OSSandbox[OS Sandbox]", "D3QN[D3QN Gate]")
                    (clone_dir / "README.md").write_text(bad_backtick, encoding="utf-8")
                    res_t4_bt = unittest.TextTestRunner(stream=io.StringIO()).run(
                        unittest.TestSuite([TestTier4Scenarios("test_t4_04_staff_security_engineer_onboarding_audit")])
                    )
                    self.assertFalse(res_t4_bt.wasSuccessful(), "test_t4_04 failed to reject D3QN inside ```mermaid block!")

                    # Tilde ~~~mermaid fence containing D3QN past line 60 MUST fail test_t4_04
                    bad_tilde = bad_backtick.replace("```mermaid", "~~~mermaid").replace("```\n\n## Appendix", "~~~\n\n## Appendix")
                    (clone_dir / "README.md").write_text(bad_tilde, encoding="utf-8")
                    res_t4_tilde = unittest.TextTestRunner(stream=io.StringIO()).run(
                        unittest.TestSuite([TestTier4Scenarios("test_t4_04_staff_security_engineer_onboarding_audit")])
                    )
                    self.assertFalse(res_t4_tilde.wasSuccessful(), "test_t4_04 failed to reject D3QN inside ~~~mermaid block!")

                    # D3QN in hero (first 60 lines) MUST fail test_t4_04
                    bad_hero = "D3QN advisory headline\n" + clean_readme
                    (clone_dir / "README.md").write_text(bad_hero, encoding="utf-8")
                    res_t4_hero = unittest.TextTestRunner(stream=io.StringIO()).run(
                        unittest.TestSuite([TestTier4Scenarios("test_t4_04_staff_security_engineer_onboarding_audit")])
                    )
                    self.assertFalse(res_t4_hero.wasSuccessful(), "test_t4_04 failed to reject D3QN in first 60 lines!")
                finally:
                    if clone_dir.exists():
                        def _on_rm_error(func: object, path_str: str, _exc_info: object) -> None:
                            os.chmod(path_str, stat.S_IWRITE)
                            func(path_str)  # type: ignore[operator]

                        shutil.rmtree(clone_dir, onerror=_on_rm_error)
        finally:
            helpers.set_config(old_cfg)

    def test_selftest_f6_sandbox_runtime_fail_closed_allowlist(self) -> None:
        """Self-test 12 (Regression): F6 checks allow ONLY pre-existing `c.commit();` + `logs/otel_sessions.jsonl` and reject any new/dirty/diff/.agents/HEAD change."""
        from .. import test_tier1_features
        from .. import test_tier2_boundaries

        TestTier1Features = test_tier1_features.TestTier1Features
        TestTier2Boundaries = test_tier2_boundaries.TestTier2Boundaries

        old_sr_path = helpers.SIBLING_SANDBOX_RUNTIME
        old_sr_sha = helpers.BASELINE_SANDBOX_RUNTIME_SHA
        with helpers.TempWorkspace() as sim_ws:
            sim_sr = sim_ws.path / "sim_sandbox_runtime"
            sim_sr.mkdir(parents=True, exist_ok=True)
            try:
                self.assertEqual(helpers.run_subprocess_safe(["git", "init", "-q"], cwd=sim_sr).returncode, 0)
                (sim_sr / "README.md").write_text("baseline\n", encoding="utf-8")
                self.assertEqual(helpers.run_git(sim_sr, ["add", "README.md"]).returncode, 0)
                commit_res = helpers.run_git(
                    sim_sr,
                    ["-c", "user.name=SelfTest", "-c", "user.email=selftest@example.invalid", "commit", "-q", "-m", "init"],
                )
                self.assertEqual(commit_res.returncode, 0, commit_res.stderr)
                base_sha = helpers.git_rev_parse(sim_sr, "HEAD")

                # Pre-existing artifacts only -> MUST PASS
                (sim_sr / "c.commit();").write_text("host artifact\n", encoding="utf-8")
                (sim_sr / "logs").mkdir(exist_ok=True)
                (sim_sr / "logs" / "otel_sessions.jsonl").write_text("{}\n", encoding="utf-8")

                helpers.SIBLING_SANDBOX_RUNTIME = sim_sr
                helpers.BASELINE_SANDBOX_RUNTIME_SHA = base_sha

                pass_suite = unittest.TestSuite(
                    [
                        TestTier1Features("test_f6_01_sandbox_runtime_unmodified"),
                        TestTier2Boundaries("test_f6_b01_siblings_zero_untracked_files"),
                    ]
                )
                res_ok = unittest.TextTestRunner(stream=io.StringIO()).run(pass_suite)
                self.assertTrue(res_ok.wasSuccessful(), f"Expected F6 allowlist pass: {res_ok.failures} {res_ok.errors}")

                # 1) New file inside logs/ (catches collapsed `?? logs/` directory trap!) -> MUST FAIL
                rogue_log = sim_sr / "logs" / "new_untracked.jsonl"
                rogue_log.write_text("rogue\n", encoding="utf-8")
                res_log = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite(
                        [
                            TestTier1Features("test_f6_01_sandbox_runtime_unmodified"),
                            TestTier2Boundaries("test_f6_b01_siblings_zero_untracked_files"),
                        ]
                    )
                )
                self.assertEqual(len(res_log.failures) + len(res_log.errors), 2, "Missed new untracked file inside logs/!")
                rogue_log.unlink()

                # 2) New root untracked file -> MUST FAIL
                rogue_root = sim_sr / "rogue_file.txt"
                rogue_root.write_text("rogue\n", encoding="utf-8")
                res_root = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite([TestTier1Features("test_f6_01_sandbox_runtime_unmodified")])
                )
                self.assertFalse(res_root.wasSuccessful(), "Missed new root untracked file!")
                rogue_root.unlink()

                # 2b) Empty untracked directory (root & inside logs/) -> MUST FAIL closed
                empty_dir = sim_sr / "empty_untracked_dir"
                empty_dir.mkdir()
                direct_empty_violations = helpers.validate_sibling_repo_state(sim_sr, base_sha)
                self.assertTrue(
                    any("empty_untracked_dir" in v for v in direct_empty_violations),
                    f"validate_sibling_repo_state missed empty untracked directory: {direct_empty_violations}",
                )
                res_empty_dir = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite([TestTier1Features("test_f6_01_sandbox_runtime_unmodified")])
                )
                self.assertFalse(res_empty_dir.wasSuccessful(), "Missed empty untracked directory!")
                empty_dir.rmdir()

                empty_log_sub = sim_sr / "logs" / "empty_sub"
                empty_log_sub.mkdir()
                res_empty_log_sub = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite([TestTier1Features("test_f6_01_sandbox_runtime_unmodified")])
                )
                self.assertFalse(res_empty_log_sub.wasSuccessful(), "Missed empty untracked directory inside logs/!")
                empty_log_sub.rmdir()

                # 3) .agents directory on disk (even if gitignored) & ignored untracked files -> MUST FAIL
                (sim_sr / ".gitignore").write_text(".agents/\n*.ignored_tmp\n", encoding="utf-8")
                self.assertEqual(helpers.run_git(sim_sr, ["add", ".gitignore"]).returncode, 0)
                self.assertEqual(
                    helpers.run_git(
                        sim_sr,
                        ["-c", "user.name=SelfTest", "-c", "user.email=selftest@example.invalid", "commit", "-q", "-m", "ignore agents"],
                    ).returncode,
                    0,
                )
                new_base = helpers.git_rev_parse(sim_sr, "HEAD")
                helpers.BASELINE_SANDBOX_RUNTIME_SHA = new_base
                (sim_sr / ".agents" / "teamwork").mkdir(parents=True, exist_ok=True)
                (sim_sr / ".agents" / "teamwork" / "probe.md").write_text("x\n", encoding="utf-8")
                res_agents = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite([TestTier1Features("test_f6_01_sandbox_runtime_unmodified")])
                )
                self.assertFalse(res_agents.wasSuccessful(), "Missed .agents directory on disk!")
                shutil.rmtree(sim_sr / ".agents")

                ignored_file = sim_sr / "stray.ignored_tmp"
                ignored_file.write_text("ignored\n", encoding="utf-8")
                res_ignored = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite([TestTier1Features("test_f6_01_sandbox_runtime_unmodified")])
                )
                self.assertFalse(res_ignored.wasSuccessful(), "Missed gitignored untracked file!")
                ignored_file.unlink()

                # 4) Unstaged modification -> MUST FAIL
                (sim_sr / "README.md").write_text("modified\n", encoding="utf-8")
                res_diff = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite([TestTier1Features("test_f6_01_sandbox_runtime_unmodified")])
                )
                self.assertFalse(res_diff.wasSuccessful(), "Missed unstaged modification!")

                # 5) Staged modification -> MUST FAIL
                self.assertEqual(helpers.run_git(sim_sr, ["add", "README.md"]).returncode, 0)
                res_staged = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite([TestTier1Features("test_f6_01_sandbox_runtime_unmodified")])
                )
                self.assertFalse(res_staged.wasSuccessful(), "Missed staged modification!")

                # 6) HEAD drift -> MUST FAIL
                self.assertEqual(
                    helpers.run_git(
                        sim_sr,
                        ["-c", "user.name=SelfTest", "-c", "user.email=selftest@example.invalid", "commit", "-q", "-m", "drift"],
                    ).returncode,
                    0,
                )
                res_head = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.TestSuite([TestTier1Features("test_f6_01_sandbox_runtime_unmodified")])
                )
                self.assertFalse(res_head.wasSuccessful(), "Missed HEAD drift!")
            finally:
                helpers.SIBLING_SANDBOX_RUNTIME = old_sr_path
                helpers.BASELINE_SANDBOX_RUNTIME_SHA = old_sr_sha
                if sim_sr.exists():
                    def _on_rm_error(func: object, path_str: str, _exc_info: object) -> None:
                        os.chmod(path_str, stat.S_IWRITE)
                        func(path_str)  # type: ignore[operator]

                    shutil.rmtree(sim_sr, onerror=_on_rm_error)

    def test_selftest_tier5_quote_path_blocked_keywords_and_binary_exts(self) -> None:
        """Self-test 13 (Tier 5): `core.quotePath=false`, strict `assert_blocked_outcome`, and `.dll`/`.pem`/`.key` hygiene checks."""
        # 1. Non-ASCII paths under git must not be C-quoted or bypass hygiene checks
        with helpers.TempWorkspace() as u_ws:
            grepo = u_ws.path / "unicode_repo"
            grepo.mkdir()
            self.assertEqual(helpers.run_subprocess_safe(["git", "init", "-q"], cwd=grepo).returncode, 0)
            (grepo / ".agents" / "teamwork").mkdir(parents=True)
            (grepo / ".agents" / "teamwork" / "café.md").write_text("x\n", encoding="utf-8")
            (grepo / "café_test_report.json").write_text("{}\n", encoding="utf-8")
            self.assertEqual(helpers.run_git(grepo, ["add", "."]).returncode, 0)
            self.assertEqual(
                helpers.run_git(
                    grepo,
                    ["-c", "user.name=SelfTest", "-c", "user.email=selftest@example.invalid", "commit", "-q", "-m", "unicode"],
                ).returncode,
                0,
            )
            (grepo / "stray_é.txt").write_text("untracked\n", encoding="utf-8")

            ls_files = helpers.git_ls_files(grepo)
            self.assertIn(".agents/teamwork/café.md", ls_files)
            self.assertIn("café_test_report.json", ls_files)
            violations = helpers.check_repo_hygiene_paths(ls_files)
            self.assertEqual(len(violations), 2, f"Expected 2 unicode hygiene violations, got: {violations}")
            untracked = helpers.git_untracked_files(grepo)
            self.assertIn("stray_é.txt", untracked)

        # 2. assert_blocked_outcome must reject unrelated FileNotFoundError mentioning octopus/policy
        bogus_err = helpers.SubprocessResult(
            returncode=1,
            stdout="",
            stderr="FileNotFoundError: C:/tmp/octopus_run/policy.json",
            timed_out=False,
            elapsed_s=0.1,
        )
        with self.assertRaises(AssertionError):
            helpers.assert_blocked_outcome(bogus_err)

        # 3. FORBIDDEN_BINARY_ARCHIVE_RE catches .dll/.sys/.pem/.pfx/.key/.p12
        binary_dirty = [
            "bin/helper.dll",
            "driver/hook.sys",
            "certs/dev.pem",
            "certs/code.pfx",
            "certs/private.key",
            "certs/store.p12",
        ]
        detected = helpers.check_repo_hygiene_paths(binary_dirty)
        self.assertEqual(set(detected), set(binary_dirty))
