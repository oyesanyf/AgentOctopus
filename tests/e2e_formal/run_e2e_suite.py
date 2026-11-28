"""CLI runner for the AgentOctopus 4-tier opaque-box Lean 4 formal verification E2E suite."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import re
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
import unittest

if __package__ in (None, ""):
    import importlib

    _repo_root = Path(__file__).resolve().parents[2]
    _tests_dir = Path(__file__).resolve().parent.parent
    _pkg_name = "tests.e2e_formal"
    try:
        if str(_repo_root) not in sys.path:
            sys.path.insert(0, str(_repo_root))
        importlib.import_module("tests.e2e_formal")
    except ModuleNotFoundError:
        if str(_tests_dir) not in sys.path:
            sys.path.insert(0, str(_tests_dir))
        _pkg_name = "e2e_formal"
    __package__ = _pkg_name

from . import FEATURE_INVENTORY, TIER_NAMES
from . import common


_BASE_PKG = __package__ or "tests.e2e_formal"
TIER_MODULES: Dict[int, str] = {
    1: f"{_BASE_PKG}.tier1_features",
    2: f"{_BASE_PKG}.tier2_boundaries",
    3: f"{_BASE_PKG}.tier3_combinations",
    4: f"{_BASE_PKG}.tier4_scenarios",
}

_FEATURE_RE = re.compile(r"^test_(?:t[34]_\d+_)?(f\d+)(?:_(f\d+))?", re.IGNORECASE)


def _infer_feature(method_name: str, doc: str) -> str:
    m_doc = re.match(r"^(Scenario\s+\d+\s*\([^)]+\)|F\d+(?:[+,/-]F?\d+)*)", doc)
    if m_doc:
        return m_doc.group(1)
    m = _FEATURE_RE.match(method_name)
    if m:
        f1 = m.group(1).upper()
        f2 = m.group(2).upper() if m.group(2) else ""
        return f"{f1}+{f2}" if f2 else f1
    return "E2E"


def _iter_suite_tests(suite: unittest.TestSuite) -> List[unittest.TestCase]:
    items: List[unittest.TestCase] = []
    for child in suite:
        if isinstance(child, unittest.TestSuite):
            items.extend(_iter_suite_tests(child))
        else:
            items.append(child)
    return items


def load_tier_suite(tier: Optional[int] = None) -> Tuple[unittest.TestSuite, List[Dict[str, Any]]]:
    tiers = [1, 2, 3, 4] if tier is None else [tier]
    loader = unittest.TestLoader()
    combined = unittest.TestSuite()
    catalog: List[Dict[str, Any]] = []
    for t in tiers:
        mod_suite = loader.loadTestsFromName(TIER_MODULES[t])
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


def compute_exit_code(was_successful: bool, skipped_count: int, progressive: bool) -> int:
    """Exit 0 iff `was_successful` AND (`progressive` OR `skipped_count == 0`)."""
    if not was_successful:
        return 1
    if not progressive and skipped_count > 0:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tests.e2e_formal.run_e2e_suite",
        description="AgentOctopus 4-tier Lean 4 formal verification E2E suite (Python stdlib only).",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--all",
        action="store_true",
        help="Run all 4 tiers (default when --tier is omitted). Fails closed on any skip.",
    )
    parser.add_argument(
        "--tier",
        type=int,
        choices=[1, 2, 3, 4],
        default=None,
        help="Run only the specified tier (1, 2, 3, or 4).",
    )
    mode_group.add_argument(
        "--progressive",
        "--allow-pending-milestones",
        dest="progressive",
        action="store_true",
        help="Allow skipping checks whose M2-M5 / elan deliverables are not yet landed.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Enumerate all test IDs, tiers, and feature mappings without running tests.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate imports, toolchain discovery, and execution plan without running tests.",
    )
    parser.add_argument(
        "--json-report",
        default=None,
        help="Write structured JSON execution report to the given file path (UTF-8).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output to stdout.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose unittest output.",
    )
    return parser


def _format_results(
    result: unittest.TestResult,
    catalog: List[Dict[str, Any]],
    tier_label: str,
    progressive: bool,
    elapsed_s: float,
) -> Dict[str, Any]:
    tier_counts: Dict[str, int] = {}
    for item in catalog:
        k = f"tier{item['tier']}"
        tier_counts[k] = tier_counts.get(k, 0) + 1

    failures = [{"test": tc.id(), "trace": tb} for tc, tb in result.failures]
    errors = [{"test": tc.id(), "trace": tb} for tc, tb in result.errors]
    skipped = [{"test": tc.id(), "reason": reason} for tc, reason in result.skipped]
    passed = max(0, result.testsRun - len(failures) - len(errors) - len(skipped))
    exit_code = compute_exit_code(result.wasSuccessful(), len(skipped), progressive)

    return {
        "ok": exit_code == 0,
        "exit_code": exit_code,
        "tier": tier_label,
        "progressive": progressive,
        "elapsed_s": round(elapsed_s, 3),
        "total": len(catalog),
        "tier_counts": tier_counts,
        "run": result.testsRun,
        "passed": passed,
        "failed": len(failures),
        "errors": len(errors),
        "skipped": len(skipped),
        "failures": failures,
        "error_details": errors,
        "skipped_details": skipped,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    common.configure_stdio_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)

    tier_label = str(args.tier) if args.tier is not None else "all"
    suite, catalog = load_tier_suite(args.tier)

    if args.list:
        if args.json:
            print(
                json.dumps(
                    {
                        "ok": True,
                        "tier": tier_label,
                        "total": len(catalog),
                        "feature_inventory": FEATURE_INVENTORY,
                        "tests": catalog,
                    },
                    indent=2,
                )
            )
        else:
            print(f"Discovered {len(catalog)} E2E tests (tier={tier_label}):")
            for item in catalog:
                print(
                    f"  [T{item['tier']}|{item['feature']}] {item['name']} - {item['description']}"
                )
        return 0

    if args.dry_run:
        lake_p, lean_p, _ = common.resolve_lake_lean()
        plan = {
            "ok": True,
            "mode": "dry-run",
            "tier": tier_label,
            "progressive": args.progressive,
            "total_tests": len(catalog),
            "repo_root": str(common.REPO_ROOT),
            "lake_path": str(lake_p) if lake_p else None,
            "lean_path": str(lean_p) if lean_p else None,
        }
        if args.json:
            print(json.dumps(plan, indent=2))
        else:
            print("AgentOctopus Lean Formal E2E Dry-Run Plan:")
            for k, v in plan.items():
                if k not in ("ok", "mode"):
                    print(f"  {k}: {v}")
        return 0

    common.set_progressive_mode(args.progressive)
    stream = io.StringIO() if args.json else sys.stdout
    verbosity = 2 if args.verbose else (0 if args.json else 1)
    runner = unittest.TextTestRunner(stream=stream, verbosity=verbosity)
    start = time.monotonic()
    result = runner.run(suite)
    elapsed_s = time.monotonic() - start

    payload = _format_results(result, catalog, tier_label, args.progressive, elapsed_s)

    if args.json_report:
        report_path = Path(args.json_report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(payload, indent=2))
    elif not args.progressive and payload["skipped"] > 0:
        print(
            f"\nFAIL-CLOSED: {payload['skipped']} test(s) skipped in strict mode "
            f"(pass --progressive while milestones M2-M5 / elan are pending).",
            file=sys.stderr,
        )

    return int(payload["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
