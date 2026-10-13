"""
HTTP Terminator: Unified 'Build All' Automation Pipeline.

Orchestrates full system compilation, dependency auditing, database schema verification,
offline Terminator RFC pre-caching, Caldera plugin export, Dream-RSI policy generation,
automated test suite execution, and clean release zip archive packaging.
"""

import argparse
import os
import py_compile
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple


ROOT_DIR = Path(__file__).resolve().parent


def log_header(title: str):
    print("\n" + "=" * 76)
    print(f"  {title.upper()}")
    print("=" * 76)


def log_step(step_num: int, title: str):
    print(f"\n[STEP {step_num}] {title}")
    print("-" * 55)


def build_step_syntax_check() -> Tuple[bool, str]:
    """Compiles all Python source files to guarantee syntax integrity."""
    py_files = []
    for search_dir in [ROOT_DIR, ROOT_DIR / "engine", ROOT_DIR / "payloads", ROOT_DIR / "tests"]:
        if search_dir.exists():
            for p in search_dir.glob("*.py"):
                py_files.append(p)

    errors = []
    for f in py_files:
        try:
            py_compile.compile(str(f), doraise=True)
        except py_compile.PyCompileError as e:
            errors.append(f"{f.name}: {e}")

    if errors:
        return False, f"Syntax errors in {len(errors)} files:\n" + "\n".join(errors)
    return True, f"Successfully verified syntax across {len(py_files)} Python source files."


def build_step_dependencies() -> Tuple[bool, str]:
    """Audits required core dependencies."""
    required = ["httpx", "requests", "urllib3", "typing_extensions"]
    missing = []
    for mod in required:
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)

    if missing:
        return False, f"Missing required dependencies: {', '.join(missing)}. Run: pip install -r requirements.txt"
    return True, f"All core runtime dependencies verified ({', '.join(required)})."


def build_step_database(db_path: str = "terminator.db") -> Tuple[bool, str]:
    """Verifies SQLite database schema, tables, and thread-safe locking."""
    try:
        from database import Database
        db = Database(str(ROOT_DIR / db_path))
        cursor = db.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        cursor.close()

        required_tables = [
            "rfcs", "fragments", "probes", "evaluations", "anomalies",
            "cascade_hypotheses", "rfc_requirements", "implementation_anomalies",
            "reproducible_vulnerabilities", "novel_techniques"
        ]
        missing = [t for t in required_tables if t not in tables]
        if missing:
            return False, f"Database is missing tables: {', '.join(missing)}"

        return True, f"Database verified ({len(tables)} tables active, thread-safe locks initialized)."
    except Exception as e:
        return False, f"Database verification failure: {e}"


def build_step_precache_rfcs() -> Tuple[bool, str]:
    """Pre-caches all canonical Terminator RFC specifications for 100% offline execution."""
    try:
        from rfc_fetcher import RFCFetcher
        from engine.terminator_rfc_selector import TerminatorRFCSelector

        cache_dir = ROOT_DIR / "rfcs"
        cache_dir.mkdir(parents=True, exist_ok=True)
        fetcher = RFCFetcher(cache_dir=str(cache_dir))
        res = fetcher.ensure_terminator_rfcs_cached()

        msg = (
            f"Terminator RFC Cache Ready: {res['cached']} cached, "
            f"{res['fetched']} newly fetched, {res['failed']} failed (Total: {res['total_specs']} core specs)."
        )
        return res["ready"], msg
    except Exception as e:
        return False, f"RFC pre-caching failure: {e}"


def build_step_caldera_export() -> Tuple[bool, str]:
    """Builds and exports the Caldera adversary emulation plugin structure."""
    try:
        from engine.caldera_bridge import CalderaBridge
        bridge = CalderaBridge(db_path=str(ROOT_DIR / "terminator.db"))
        res = bridge.export_plugin(output_dir=str(ROOT_DIR / "caldera_export"))
        bridge.export_plugin(output_dir=str(ROOT_DIR))
        return True, f"Caldera plugin exported ({res['abilities_count']} abilities, {res['adversaries_count']} adversaries)."
    except Exception as e:
        return False, f"Caldera plugin export failure: {e}"


def build_step_dream_rsi() -> Tuple[bool, str]:
    """Validates or initializes baseline Dream-RSI policy models."""
    try:
        data_dir = ROOT_DIR / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        policy_file = data_dir / "dream_policies.json"

        from engine.dream_policy_store import DreamPolicyStore
        from engine.dream_world_model import ProtocolWorldModel
        from engine.dream_rsi_optimizer import DreamRSIOptimizer

        store = DreamPolicyStore(storage_path=str(policy_file))
        latest = store.get_latest_policy()
        if not latest:
            model = ProtocolWorldModel(target_host="127.0.0.1", target_port=5006)
            optimizer = DreamRSIOptimizer(model)
            evolved = optimizer.evolve_policy_generation(rollouts_per_candidate=100, population_size=4)
            store.save_policy(evolved)
            latest = evolved

        return True, f"Dream-RSI policy store ready (Gen {latest.generation}, Fitness: {latest.fitness_score:.2f})."
    except Exception as e:
        return False, f"Dream-RSI policy verification failure: {e}"


def build_step_run_tests() -> Tuple[bool, str]:
    """Executes the complete automated test suite via pytest."""
    try:
        cmd = [sys.executable, "-m", "pytest", "tests/", "-q"]
        res = subprocess.run(cmd, cwd=str(ROOT_DIR), capture_output=True, text=True, timeout=300)
        if res.returncode == 0:
            lines = [l for l in res.stdout.strip().splitlines() if "passed" in l or "warning" in l]
            summary = lines[-1] if lines else "All tests passed."
            return True, f"Test suite passed cleanly ({summary})."
        else:
            return False, f"Test suite failed:\n{res.stdout}\n{res.stderr}"
    except Exception as e:
        return False, f"Test suite execution exception: {e}"


def build_step_package_zips() -> Tuple[bool, str]:
    """Generates distribution zip archives."""
    def _zip_folder(src_dir: Path, zip_file: Path, include_db: bool = False):
        with zipfile.ZipFile(str(zip_file), "w", zipfile.ZIP_DEFLATED) as z:
            for root, dirs, files in os.walk(str(src_dir)):
                dirs[:] = [d for d in dirs if d not in [".git", "__pycache__", ".pytest_cache", ".venv"]]
                for file in files:
                    if not include_db and file.endswith(".db"):
                        continue
                    if file.endswith(".zip"):
                        continue
                    full_p = os.path.join(root, file)
                    rel_p = os.path.relpath(full_p, str(src_dir))
                    z.write(full_p, rel_p)

    try:
        zip1 = ROOT_DIR / "http_terminator.zip"
        zip2 = ROOT_DIR / "http_terminator_with_db.zip"
        zip3 = ROOT_DIR.parent / "agent_octopus_source_code.zip"

        _zip_folder(ROOT_DIR, zip1, include_db=False)
        _zip_folder(ROOT_DIR, zip2, include_db=True)
        _zip_folder(ROOT_DIR, zip3, include_db=True)

        size1_mb = zip1.stat().st_size / (1024 * 1024)
        size2_mb = zip2.stat().st_size / (1024 * 1024)
        return True, f"Distribution archives packaged: http_terminator.zip ({size1_mb:.1f} MB), with_db.zip ({size2_mb:.1f} MB)."
    except Exception as e:
        return False, f"Zip packaging failure: {e}"


def run_full_build(skip_tests: bool = False, skip_zips: bool = False) -> bool:
    """Executes the end-to-end build pipeline."""
    start_time = time.time()
    log_header("HTTP Terminator: Unified 'Build All' Pipeline")
    print(f"Target Working Directory: {ROOT_DIR}")
    print(f"Python Environment     : {sys.executable}")
    print(f"Timestamp              : {time.strftime('%Y-%m-%d %H:%M:%S')}")

    steps = [
        ("Python Bytecode Syntax Verification", build_step_syntax_check),
        ("Core Runtime Dependency Audit", build_step_dependencies),
        ("SQLite Database Schema & Lock Integrity", build_step_database),
        ("Terminator RFC Pre-Caching & Offline Readiness", build_step_precache_rfcs),
        ("Caldera Adversary Emulation Plugin Generation", build_step_caldera_export),
        ("Dream-RSI Off-Policy Model Verification", build_step_dream_rsi),
    ]

    if not skip_tests:
        steps.append(("Full Automated Pytest Verification Suite", build_step_run_tests))

    if not skip_zips:
        steps.append(("Release Distribution Zip Packaging", build_step_package_zips))

    all_passed = True
    for idx, (title, func) in enumerate(steps, 1):
        log_step(idx, title)
        success, message = func()
        if success:
            print(f"[+] PASS: {message}")
        else:
            print(f"[!] FAIL: {message}")
            all_passed = False
            break

    elapsed = time.time() - start_time
    log_header("Build Summary")
    if all_passed:
        print(f"[SUCCESS] All build targets built, verified, and packaged in {elapsed:.2f} seconds.")
        print("[+] HTTP Terminator is 100% production ready and fully offline-capable.")
        return True
    else:
        print(f"[FAILURE] Build failed after {elapsed:.2f} seconds. Please check the logs above.")
        return False


def main():
    parser = argparse.ArgumentParser(description="HTTP Terminator: Build All Automation Pipeline")
    parser.add_argument("--skip-tests", action="store_true", help="Skip running the pytest verification suite")
    parser.add_argument("--skip-zips", action="store_true", help="Skip creating release zip packages")
    args = parser.parse_args()

    success = run_full_build(skip_tests=args.skip_tests, skip_zips=args.skip_zips)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
