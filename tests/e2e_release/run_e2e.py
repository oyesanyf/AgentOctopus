"""CLI runner for the AgentOctopus 4-tier opaque-box E2E verification suite."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple
import unittest

if __package__ in (None, ""):
    _repo_root = Path(__file__).resolve().parents[2]
    if str(_repo_root) not in sys.path:
        sys.path.insert(0, str(_repo_root))
    __package__ = "tests.e2e_release"

from . import FEATURE_AREAS, TIER_NAMES
from . import helpers


TIER_MODULES: Dict[int, str] = {
    1: "tests.e2e_release.test_tier1_features",
    2: "tests.e2e_release.test_tier2_boundaries",
    3: "tests.e2e_release.test_tier3_combinations",
    4: "tests.e2e_release.test_tier4_scenarios",
    5: "tests.e2e_release.test_tier5_adversarial",
}

SELFTEST_MODULE = "tests.e2e_release.self_tests.test_suite_selftest"

_FEATURE_PREFIX_RE = re.compile(r"^test_(f[1-6])_", re.IGNORECASE)


def _infer_feature(method_name: str, doc: str) -> str:
    m = _FEATURE_PREFIX_RE.match(method_name)
    if m:
        return m.group(1).upper()
    m_doc = re.search(r"\b(F[1-6](?:\+F[1-6])*)\b", doc)
    if m_doc:
        return m_doc.group(1)
    return "E2E"


def _iter_suite_tests(suite: unittest.TestSuite) -> List[unittest.TestCase]:
    items: List[unittest.TestCase] = []
    for child in suite:
        if isinstance(child, unittest.TestSuite):
            items.extend(_iter_suite_tests(child))
        else:
            items.append(child)
    return items


def load_tier_suite(tier_arg: str) -> Tuple[unittest.TestSuite, List[Dict[str, Any]]]:
    tiers = [1, 2, 3, 4, 5] if tier_arg == "all" else [int(tier_arg)]
    loader = unittest.TestLoader()
    combined = unittest.TestSuite()
    catalog: List[Dict[str, Any]] = []
    for t in tiers:
        mod_name = TIER_MODULES[t]
        mod_suite = loader.loadTestsFromName(mod_name)
        for tc in _iter_suite_tests(mod_suite):
            method_name = tc._testMethodName
            doc = (tc.shortDescription() or "").strip()
            catalog.append(
                {
                    "id": tc.id(),
                    "name": method_name,
                    "tier": t,
                    "tier_name": TIER_NAMES[t],
                    "feature": _infer_feature(method_name, doc),
                    "description": doc,
                }
            )
            combined.addTest(tc)
    return combined, catalog


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tests.e2e_release",
        description="AgentOctopus 4-tier opaque-box E2E release verification suite (Python stdlib only).",
    )
    parser.add_argument(
        "--tier",
        choices=["1", "2", "3", "4", "5", "all"],
        default="all",
        help="Select test tier(s) to list or execute (default: all).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List discovered tests for the selected tier(s) and exit 0.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate imports, binary discovery, and execution plan without running tests.",
    )
    parser.add_argument(
        "--bin",
        dest="bin_path",
        default=None,
        help="Explicit path to the `octopus` binary (fails closed if missing).",
    )
    parser.add_argument(
        "--agent-bin",
        dest="agent_bin_path",
        default=None,
        help="Explicit path to the `agent_octopus` or `start` binary for Web API checks.",
    )
    parser.add_argument(
        "--skip-cargo",
        action="store_true",
        help="Explicitly skip ONLY Tier 4 Cargo release gate (`test_t4_03`). Disallowed in M4.",
    )
    parser.add_argument(
        "--skip-remote",
        action="store_true",
        help="Explicitly skip ONLY live GitHub (`gh`) / `origin/main` checks. Disallowed in M4.",
    )
    parser.add_argument(
        "--allow-cargo-build",
        action="store_true",
        help="Allow building missing binaries via `cargo build` when not pre-built.",
    )
    parser.add_argument(
        "--allow-uncommitted-e2e",
        action="store_true",
        help="In `test_f4_b05`, allow uncommitted changes strictly under `tests/e2e_release/`.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run isolated self-tests (`self_tests/test_suite_selftest.py`) with zero Cargo calls.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose test output.",
    )
    return parser


def _authorized_skip(test_name: str, skip_cargo: bool, skip_remote: bool) -> bool:
    if skip_cargo and "test_t4_03" in test_name:
        return True
    if skip_remote and any(
        tok in test_name for tok in ("test_f6_05", "test_f6_b03", "test_f6_b05", "test_t4_04")
    ):
        return True
    return False


def _format_unittest_results(
    result: unittest.TestResult,
    total_count: int,
    tier: str,
    mode: str,
    elapsed_s: float = 0.0,
) -> Dict[str, Any]:
    failures = [
        {"test": tc.id(), "trace": tb}
        for tc, tb in result.failures
    ]
    errors = [
        {"test": tc.id(), "trace": tb}
        for tc, tb in result.errors
    ]
    skipped = [
        {"test": tc.id(), "reason": reason}
        for tc, reason in result.skipped
    ]
    passed = result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)
    return {
        "mode": mode,
        "tier": tier,
        "total": total_count,
        "run": result.testsRun,
        "passed": max(0, passed),
        "failed": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "ok": result.wasSuccessful(),
        "failures": failures,
        "error_details": errors,
        "skipped_details": skipped,
    }


def _emit_error(msg: str, use_json: bool, code: int = 2) -> int:
    if use_json:
        print(json.dumps({"ok": False, "exit_code": code, "error": msg}, indent=2))
    else:
        print(f"ERROR: {msg}", file=sys.stderr)
    return code


def main(argv: Optional[Sequence[str]] = None) -> int:
    helpers.configure_stdio_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = helpers.REPO_ROOT

    # 1. --self-test mode (isolated pre-M2/M4 validation, zero Cargo calls)
    if args.self_test:
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName(SELFTEST_MODULE)
        tests = _iter_suite_tests(suite)
        stream = io.StringIO() if args.json else sys.stdout
        verbosity = 2 if args.verbose else (0 if args.json else 1)
        runner = unittest.TextTestRunner(stream=stream, verbosity=verbosity)
        res = runner.run(suite)
        if args.json:
            payload = _format_unittest_results(res, len(tests), tier="self-test", mode="self-test")
            print(json.dumps(payload, indent=2))
        return 0 if res.wasSuccessful() else 1

    # 2. Load selected tier suite
    suite, catalog = load_tier_suite(args.tier)

    # 3. --list mode (works pre-M2 without any compiled binary)
    if args.list:
        if args.json:
            print(
                json.dumps(
                    {
                        "ok": True,
                        "tier": args.tier,
                        "total": len(catalog),
                        "feature_areas": FEATURE_AREAS,
                        "tests": catalog,
                    },
                    indent=2,
                )
            )
        else:
            print(f"Discovered {len(catalog)} E2E tests (tier={args.tier}):")
            for item in catalog:
                print(
                    f"  [T{item['tier']}|{item['feature']}] {item['name']} - {item['description']}"
                )
        return 0

    # 4. Resolve binaries
    try:
        octopus_bin = helpers.resolve_octopus_bin(
            explicit_bin=args.bin_path,
            repo_root=repo_root,
            allow_cargo_build=args.allow_cargo_build if not args.dry_run else False,
        )
        agent_bin = helpers.resolve_agent_bin(
            explicit_bin=args.agent_bin_path,
            repo_root=repo_root,
            allow_cargo_build=args.allow_cargo_build if not args.dry_run else False,
        )
    except helpers.BinaryResolutionError as exc:
        return _emit_error(str(exc), args.json, code=2)

    # 5. --dry-run mode (exits 0 pre-M2 even if binaries not built yet)
    if args.dry_run:
        plan = {
            "ok": True,
            "mode": "dry-run",
            "tier": args.tier,
            "total_tests": len(catalog),
            "repo_root": str(repo_root),
            "octopus_bin": str(octopus_bin) if octopus_bin else None,
            "agent_bin": str(agent_bin) if agent_bin else None,
            "skip_cargo": args.skip_cargo,
            "skip_remote": args.skip_remote,
            "allow_cargo_build": args.allow_cargo_build,
            "allow_uncommitted_e2e": args.allow_uncommitted_e2e,
        }
        if args.json:
            print(json.dumps(plan, indent=2))
        else:
            print("AgentOctopus E2E Dry-Run Plan:")
            for k, v in plan.items():
                if k not in ("ok", "mode"):
                    print(f"  {k}: {v}")
        return 0

    # 6. Strict fail-closed binary gate for live `--tier 1..4|all` runs
    if octopus_bin is None:
        return _emit_error(
            "octopus binary not found (fail-closed, zero fake skips). "
            "Pass --bin PATH, set OCTOPUS_BIN, or build `cargo build --bin octopus`.",
            args.json,
            code=2,
        )

    cfg = helpers.E2EConfig(
        repo_root=repo_root,
        octopus_bin=octopus_bin,
        agent_bin=agent_bin,
        skip_cargo=args.skip_cargo,
        skip_remote=args.skip_remote,
        allow_cargo_build=args.allow_cargo_build,
        allow_uncommitted_e2e=args.allow_uncommitted_e2e,
        verbose=args.verbose,
    )
    helpers.set_config(cfg)

    stream = io.StringIO() if args.json else sys.stdout
    verbosity = 2 if args.verbose else (0 if args.json else 1)
    runner = unittest.TextTestRunner(stream=stream, verbosity=verbosity)
    result = runner.run(suite)

    # Enforce zero-unauthorized-skip invariant
    unauthorized_skips = [
        (tc.id(), reason)
        for tc, reason in result.skipped
        if not _authorized_skip(tc._testMethodName, args.skip_cargo, args.skip_remote)
    ]

    if args.json:
        payload = _format_unittest_results(result, len(catalog), tier=args.tier, mode="run")
        payload["unauthorized_skips"] = [
            {"test": t, "reason": r} for t, r in unauthorized_skips
        ]
        if unauthorized_skips:
            payload["ok"] = False
        print(json.dumps(payload, indent=2))
    elif unauthorized_skips:
        print(
            f"ERROR: Unauthorized skips detected (strict zero-fake-skip gate): {unauthorized_skips}",
            file=sys.stderr,
        )

    if not result.wasSuccessful() or unauthorized_skips:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
