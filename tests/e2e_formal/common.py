"""Shared harness, toolchain discovery, Lean probes, and structural parsers for tests/e2e_formal."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import tomllib
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
import unittest
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[2]
FORMAL_DIR = REPO_ROOT / "formal"
FORMAL_PKG_DIR = FORMAL_DIR / "AgentOctopusFormal"

_PROGRESSIVE_MODE: Optional[bool] = None
_TOOLCHAIN_PROBE_CACHE: Dict[Tuple[str, str], Tuple[bool, str]] = {}

# Control chars excluding TAB (0x09), LF (0x0A), CR (0x0D), plus Unicode replacement U+FFFD
_FUNNY_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffd]")

# Dynamic construction avoids literal PEM header false positives in static secret scanners.
PEM_BLOCK_PATTERN = re.compile(
    r"-----BEGIN " + r"(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)


def configure_stdio_utf8() -> None:
    """Configure UTF-8 stdio on Windows consoles without mutating environment or registry."""
    if sys.platform == "win32":
        for stream_name in ("stdout", "stderr"):
            stream = getattr(sys, stream_name, None)
            if stream is not None and hasattr(stream, "reconfigure"):
                try:
                    stream.reconfigure(encoding="utf-8", errors="replace")
                except Exception:
                    pass


def set_progressive_mode(enabled: bool) -> None:
    global _PROGRESSIVE_MODE
    _PROGRESSIVE_MODE = bool(enabled)


def is_progressive_mode() -> bool:
    if _PROGRESSIVE_MODE is not None:
        return _PROGRESSIVE_MODE
    return os.environ.get("OCTOPUS_E2E_FORMAL_PROGRESSIVE", "") == "1"


def require_milestone_file(
    rel_path: str | Path,
    feature_id: str,
    progressive: Optional[bool] = None,
) -> Path:
    """Return path inside REPO_ROOT or skip/fail-closed depending on progressive mode."""
    target = (REPO_ROOT / rel_path).resolve()
    if target.is_file():
        return target
    prog = is_progressive_mode() if progressive is None else progressive
    if prog:
        raise unittest.SkipTest(
            f"SKIPPED (milestone pending): {feature_id} deliverable missing: {rel_path}"
        )
    raise AssertionError(
        f"{feature_id} required deliverable missing (fail-closed): {rel_path}"
    )


def require_milestone_dir(
    rel_path: str | Path,
    feature_id: str,
    progressive: Optional[bool] = None,
) -> Path:
    """Return directory inside REPO_ROOT or skip/fail-closed depending on progressive mode."""
    target = (REPO_ROOT / rel_path).resolve()
    if target.is_dir():
        return target
    prog = is_progressive_mode() if progressive is None else progressive
    if prog:
        raise unittest.SkipTest(
            f"SKIPPED (milestone pending): {feature_id} directory missing: {rel_path}"
        )
    raise AssertionError(
        f"{feature_id} required directory missing (fail-closed): {rel_path}"
    )


def find_elan_bin_dir() -> Optional[Path]:
    """Locate ~/.elan/bin (or ELAN_HOME/bin) without reading or modifying registry."""
    candidates: List[Path] = []
    elan_home = os.environ.get("ELAN_HOME", "").strip()
    if elan_home:
        candidates.append(Path(elan_home).expanduser() / "bin")
    candidates.append(Path.home() / ".elan" / "bin")

    lake_exe = "lake.exe" if sys.platform == "win32" else "lake"
    lean_exe = "lean.exe" if sys.platform == "win32" else "lean"
    for cand in candidates:
        if cand.is_dir() and ((cand / lake_exe).is_file() or (cand / lean_exe).is_file()):
            return cand
    return None


def resolve_lake_lean() -> Tuple[Optional[Path], Optional[Path], Dict[str, str]]:
    """Resolve `lake` and `lean` executables using process-scoped PATH copy only."""
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    elan_bin = find_elan_bin_dir()
    if elan_bin is not None:
        cur_path = env.get("PATH", "")
        elan_str = str(elan_bin)
        parts = [p for p in cur_path.split(os.pathsep) if p]
        if elan_str not in parts:
            env["PATH"] = elan_str + (os.pathsep + cur_path if cur_path else "")

    lake_hit = shutil.which("lake", path=env.get("PATH"))
    lean_hit = shutil.which("lean", path=env.get("PATH"))
    lake_path = Path(lake_hit).resolve() if lake_hit else None
    lean_path = Path(lean_hit).resolve() if lean_hit else None
    return lake_path, lean_path, env


def check_lake_toolchain_functional(
    lake_path: Path,
    lean_path: Path,
    env: Dict[str, str],
) -> Tuple[bool, str]:
    """Verify `lake --version` and `lean --version` execute with exit 0 (not un-bootstrapped elan stubs)."""
    key = (str(lake_path), str(lean_path))
    cached = _TOOLCHAIN_PROBE_CACHE.get(key)
    if cached is not None:
        return cached

    res_lake = run_subprocess_safe([str(lake_path), "--version"], env=env, timeout=20.0)
    if res_lake.returncode != 0:
        out = (
            f"lake --version exited {res_lake.returncode}: {res_lake.combined_output}"
        )
        _TOOLCHAIN_PROBE_CACHE[key] = (False, out)
        return False, out

    res_lean = run_subprocess_safe([str(lean_path), "--version"], env=env, timeout=20.0)
    if res_lean.returncode != 0:
        out = (
            f"lean --version exited {res_lean.returncode}: {res_lean.combined_output}"
        )
        _TOOLCHAIN_PROBE_CACHE[key] = (False, out)
        return False, out

    _TOOLCHAIN_PROBE_CACHE[key] = (True, "")
    return True, ""


def require_lake_toolchain(
    progressive: Optional[bool] = None,
) -> Tuple[Path, Path, Dict[str, str]]:
    """Return `(lake_path, lean_path, env)` or skip/fail-closed if toolchain absent or un-bootstrapped."""
    lake_path, lean_path, env = resolve_lake_lean()
    prog = is_progressive_mode() if progressive is None else progressive
    if lake_path is None or lean_path is None:
        if prog:
            raise unittest.SkipTest(
                "SKIPPED (milestone pending): elan/lake/lean toolchain not installed on PATH or ~/.elan/bin"
            )
        raise AssertionError(
            "elan/lake/lean toolchain not found on PATH or ~/.elan/bin (fail-closed)."
        )

    ok, detail = check_lake_toolchain_functional(lake_path, lean_path, env)
    if not ok:
        if prog:
            raise unittest.SkipTest(
                f"SKIPPED (milestone pending): elan/lake/lean toolchain not ready ({detail})"
            )
        raise AssertionError(
            f"elan/lake/lean toolchain present but not functional (fail-closed): {detail}"
        )

    return lake_path, lean_path, env


@dataclass
class SubprocessResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    elapsed_s: float

    @property
    def combined_output(self) -> str:
        return f"{self.stdout}\n{self.stderr}".strip()


def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                check=False,
            )
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def run_subprocess_safe(
    cmd: Sequence[str],
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
    timeout: float = 60.0,
    input_text: Optional[str] = None,
) -> SubprocessResult:
    """Run subprocess with explicit UTF-8 decoding and full process-group timeout cleanup."""
    popen_kwargs: Dict[str, Any] = {
        "cwd": str(cwd) if cwd else None,
        "env": env,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if input_text is not None:
        popen_kwargs["stdin"] = subprocess.PIPE
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True

    start = time.monotonic()
    proc = subprocess.Popen(list(cmd), **popen_kwargs)
    timed_out = False
    try:
        stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_tree(proc)
        try:
            stdout, stderr = proc.communicate(timeout=5.0)
        except Exception:
            stdout, stderr = "", ""
    elapsed = time.monotonic() - start
    rc = proc.returncode if proc.returncode is not None else -1
    return SubprocessResult(
        returncode=rc,
        stdout=stdout or "",
        stderr=stderr or "",
        timed_out=timed_out,
        elapsed_s=elapsed,
    )


def run_lean_probe(
    lean_source: str,
    use_lake_env: bool = True,
    timeout: float = 60.0,
    progressive: Optional[bool] = None,
) -> SubprocessResult:
    """Compile an ephemeral Lean 4 probe inside `tempfile.TemporaryDirectory()` without touching `formal/`."""
    lake_path, lean_path, env = require_lake_toolchain(progressive=progressive)
    if use_lake_env:
        require_milestone_file("formal/lakefile.toml", "F1", progressive=progressive)
        require_milestone_file("formal/lean-toolchain", "F1", progressive=progressive)

    with tempfile.TemporaryDirectory(prefix="ao_lean_probe_") as tmpdir:
        probe_path = Path(tmpdir) / "Probe.lean"
        probe_path.write_text(lean_source, encoding="utf-8")
        if use_lake_env:
            cmd = [str(lake_path), "env", "lean", str(probe_path)]
            cwd = FORMAL_DIR
        else:
            cmd = [str(lean_path), str(probe_path)]
            cwd = Path(tmpdir)
        return run_subprocess_safe(cmd, cwd=cwd, env=env, timeout=timeout)


def load_lakefile_toml(path: Optional[Path] = None) -> Dict[str, Any]:
    target = path or (FORMAL_DIR / "lakefile.toml")
    with open(target, "rb") as f:
        return tomllib.load(f)


def parse_toml_text(text: str) -> Dict[str, Any]:
    return tomllib.loads(text)


def validate_lakefile_zero_deps(data: Dict[str, Any]) -> List[str]:
    """Validate parsed lakefile.toml satisfies AgentOctopus zero-dep & autoImplicit=false policy."""
    errors: List[str] = []
    if data.get("name") != "AgentOctopusFormal":
        errors.append(f"Expected name='AgentOctopusFormal', got {data.get('name')!r}")
    if "AgentOctopusFormal" not in (data.get("defaultTargets") or []):
        errors.append(f"Missing 'AgentOctopusFormal' in defaultTargets: {data.get('defaultTargets')!r}")
    lean_opts = data.get("leanOptions") or {}
    if lean_opts.get("autoImplicit") is not False:
        errors.append(f"autoImplicit must be false, got {lean_opts.get('autoImplicit')!r}")
    if "require" in data and data["require"]:
        errors.append(f"External [[require]] dependencies forbidden: {data['require']!r}")
    libs = data.get("lean_lib") or []
    if not any(isinstance(lib, dict) and lib.get("name") == "AgentOctopusFormal" for lib in libs):
        errors.append(f"Missing [[lean_lib]] AgentOctopusFormal in {libs!r}")
    return errors


ALLOWED_STANDARD_AXIOMS = frozenset({"propext", "Classical.choice", "Quot.sound"})


def find_rogue_axioms_in_output(out: str) -> List[str]:
    """Parse multiline `#print axioms` output and return any non-standard axioms."""
    rogue: List[str] = []
    for m in re.finditer(r"depends on axioms:\s*\[([^\]]+)\]", out, re.DOTALL):
        used = {tok.strip() for tok in m.group(1).split(",") if tok.strip()}
        rogue.extend(sorted(used - ALLOWED_STANDARD_AXIOMS))
    return rogue


_WIX_PATH_ENV_RE = re.compile(
    r"""<Environment\b[^>]*(?:Id|Name)\s*=\s*["']PATH["']""",
    re.IGNORECASE,
)


def check_wix_path_mutation(wxs_text: str) -> List[str]:
    """Return any prohibited WiX `<Environment ... Id|Name='PATH'>` tags."""
    return [m.group(0) for m in _WIX_PATH_ENV_RE.finditer(wxs_text)]


def _is_lean_ident_char(ch: str) -> bool:
    return ch.isalnum() or ch in ("_", "'")


def _try_consume_lean_char_literal(text: str, i: int) -> Optional[int]:
    """If `text[i:]` starts a Lean char literal `'...'` (not a primed ident like `sorry'`), return end index."""
    n = len(text)
    if i >= n or text[i] != "'":
        return None
    if i > 0 and _is_lean_ident_char(text[i - 1]):
        return None
    if i + 1 >= n:
        return None
    if text[i + 1] == "\\":
        j = i + 2
        if j < n and text[j] in ("x", "u"):
            j += 1
            while j < n and text[j] in "0123456789abcdefABCDEF" and (j - i) <= 10:
                j += 1
        elif j < n and text[j] != "\n":
            j += 1
        if j < n and text[j] == "'":
            return j + 1
        return None
    if text[i + 1] not in ("\\", "\n", "\r") and i + 2 < n and text[i + 2] == "'":
        return i + 3
    return None


def strip_lean_comments(text: str) -> str:
    """Remove Lean block comments (`/- ... -/` including nested) and line comments (`-- ...`)."""
    out: List[str] = []
    i = 0
    n = len(text)
    depth = 0
    in_string = False
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if depth == 0:
            if not in_string:
                char_end = _try_consume_lean_char_literal(text, i)
                if char_end is not None:
                    out.append(text[i:char_end])
                    i = char_end
                    continue
                if ch == '"':
                    in_string = True
                    out.append(ch)
                    i += 1
                    continue
            if in_string:
                out.append(ch)
                if ch == "\\" and i + 1 < n:
                    out.append(text[i + 1])
                    i += 2
                    continue
                if ch == '"':
                    in_string = False
                i += 1
                continue
            if ch == "/" and nxt == "-":
                depth = 1
                i += 2
                continue
            if ch == "-" and nxt == "-":
                while i < n and text[i] != "\n":
                    i += 1
                continue
            out.append(ch)
            i += 1
        else:
            if ch == "/" and nxt == "-":
                depth += 1
                i += 2
            elif ch == "-" and nxt == "/":
                depth -= 1
                i += 2
            else:
                if ch == "\n":
                    out.append("\n")
                i += 1
    return "".join(out)


def mask_lean_comments_and_strings(text: str) -> str:
    """Strip Lean comments and replace string/char literal interiors with spaces (preserving newlines)."""
    stripped = strip_lean_comments(text)
    out: List[str] = []
    i = 0
    n = len(stripped)
    in_string = False
    while i < n:
        ch = stripped[i]
        if not in_string:
            char_end = _try_consume_lean_char_literal(stripped, i)
            if char_end is not None:
                out.append(" " * (char_end - i))
                i = char_end
                continue
            if ch == '"':
                in_string = True
                out.append(" ")
                i += 1
                continue
            out.append(ch)
            i += 1
        else:
            if ch == "\\" and i + 1 < n:
                out.append(" ")
                out.append("\n" if stripped[i + 1] == "\n" else " ")
                i += 2
                continue
            if ch == '"':
                in_string = False
                out.append(" ")
                i += 1
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
    return "".join(out)


def find_lean_sorry_tokens(text: str) -> List[Tuple[int, str]]:
    """Return `(line_no, line)` for non-comment, non-string `sorry` / `sorryAx` tokens in Lean source."""
    stripped = strip_lean_comments(text)
    masked = mask_lean_comments_and_strings(text)
    hits: List[Tuple[int, str]] = []
    pat = re.compile(r"(?:^|[^A-Za-z0-9_'])(?:sorry|sorryAx)(?![A-Za-z0-9_'])")
    orig_lines = stripped.splitlines()
    for idx, masked_line in enumerate(masked.splitlines(), start=1):
        if pat.search(masked_line):
            orig = orig_lines[idx - 1].strip() if idx - 1 < len(orig_lines) else masked_line.strip()
            hits.append((idx, orig))
    return hits


def find_lean_custom_axioms(text: str) -> List[Tuple[int, str]]:
    """Return `(line_no, decl)` for any `axiom` declaration in non-comment, non-string Lean source."""
    masked = mask_lean_comments_and_strings(text)
    hits: List[Tuple[int, str]] = []
    pat = re.compile(
        r"(?<![\w'.])axiom(?![\w'])\s+((?:«[^»]+»|[^\W\d][\w']*)(?:\.(?:«[^»]+»|[^\W\d][\w']*))*)"
    )
    for m in pat.finditer(masked):
        line_no = masked.count("\n", 0, m.start()) + 1
        hits.append((line_no, m.group(1)))
    return hits


def parse_lean_inductive_constructors(lean_text: str, type_name: str) -> List[str]:
    """Extract constructor names from `(private|protected)? inductive <type_name> ... where` block."""
    cleaned = strip_lean_comments(lean_text)
    header_re = re.compile(
        rf"^\s*(?:private\s+|protected\s+)?inductive\s+{re.escape(type_name)}\b[^\n]*?\bwhere\b",
        re.MULTILINE,
    )
    m = header_re.search(cleaned)
    if not m:
        return []
    constructors: List[str] = []
    rest = cleaned[m.end() :]
    stop_re = re.compile(
        r"^(?:deriving|end|def|theorem|lemma|structure|inductive|namespace|section|"
        r"abbrev|instance|private|protected|axiom|example|partial|noncomputable|"
        r"unsafe|class|mutual|open|variable|universe|set_option|export|attribute)\b"
    )
    ctor_re = re.compile(r"(?:^|\s)\|\s*([A-Za-z_][A-Za-z0-9_']*)\b")
    for line in rest.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("@[") or s.startswith("#") or stop_re.match(s):
            break
        if s.startswith("|"):
            for cm in ctor_re.finditer(s):
                constructors.append(cm.group(1))
    return constructors


def _safe_eval_int_expr(expr: str) -> Optional[int]:
    """Evaluate simple integer literal/product/sum constants (no eval())."""
    cleaned = expr.strip().replace("_", "")
    # Strip optional inline type annotation or trailing comments
    if not cleaned:
        return None
    if re.fullmatch(r"0x[0-9a-fA-F]+", cleaned):
        return int(cleaned, 16)
    if re.fullmatch(r"\d+", cleaned):
        return int(cleaned, 10)
    if "*" in cleaned and re.fullmatch(r"[0-9a-fA-Fx*\s]+", cleaned):
        prod = 1
        for part in cleaned.split("*"):
            val = _safe_eval_int_expr(part)
            if val is None:
                return None
            prod *= val
        return prod
    return None


def parse_lean_def_nat(lean_text: str, const_name: str) -> Optional[int]:
    """Parse `def <const_name> ... := <int_expr>` from Lean source."""
    cleaned = strip_lean_comments(lean_text)
    pat = re.compile(
        rf"^\s*(?:private\s+|protected\s+)?def\s+{re.escape(const_name)}\b[^\n]*?:=\s*([^\n]+)",
        re.MULTILINE,
    )
    m = pat.search(cleaned)
    if not m:
        return None
    return _safe_eval_int_expr(m.group(1))


def strip_rust_comments(text: str) -> str:
    """Strip Rust `//` and `/* ... */` comments (preserving string, raw string, and char literals)."""
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            depth = 1
            i += 2
            while i < n and depth > 0:
                c2 = text[i]
                n2 = text[i + 1] if i + 1 < n else ""
                if c2 == "/" and n2 == "*":
                    depth += 1
                    i += 2
                elif c2 == "*" and n2 == "/":
                    depth -= 1
                    i += 2
                else:
                    if c2 == "\n":
                        out.append("\n")
                    i += 1
            continue
        lit_end = _advance_rust_literal(text, i)
        if lit_end is not None:
            out.append(text[i:lit_end])
            i = lit_end
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _advance_rust_literal(text: str, i: int) -> Optional[int]:
    """If `text[i:]` starts a Rust string, raw string, or char literal (not lifetime), return end index."""
    n = len(text)
    if i >= n:
        return None
    ch = text[i]
    if ch == '"':
        j = i + 1
        while j < n:
            if text[j] == "\\" and j + 1 < n:
                j += 2
                continue
            if text[j] == '"':
                return j + 1
            j += 1
        return n
    is_ident_start = i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")
    raw_r_idx: Optional[int] = None
    if ch == "r" and is_ident_start:
        raw_r_idx = i
    elif ch in ("b", "c") and is_ident_start and i + 1 < n and text[i + 1] == "r":
        raw_r_idx = i + 1
    if raw_r_idx is not None:
        j = raw_r_idx + 1
        hashes = 0
        while j < n and text[j] == "#":
            hashes += 1
            j += 1
        if j < n and text[j] == '"':
            j += 1
            closing = '"' + ("#" * hashes)
            end = text.find(closing, j)
            return (end + len(closing)) if end != -1 else n
    if ch == "'":
        if i + 1 < n and text[i + 1] == "\\":
            j = i + 2
            if j < n and text[j] == "x":
                j += 1
                while j < n and text[j] in "0123456789abcdefABCDEF" and (j - i) <= 6:
                    j += 1
            elif j < n and text[j] == "u" and j + 1 < n and text[j + 1] == "{":
                end_u = text.find("}", j + 2)
                if end_u != -1 and (end_u - j) <= 10:
                    j = end_u + 1
            elif j < n and text[j] != "\n":
                j += 1
            if j < n and text[j] == "'":
                return j + 1
            return None
        if i + 2 < n and text[i + 1] not in ("\\", "\n", "\r") and text[i + 2] == "'":
            return i + 3
    return None


def parse_rust_enum_variants(rust_text: str, enum_name: str) -> List[str]:
    """Extract top-level variant names of `enum <enum_name> { ... }` from Rust source."""
    cleaned = strip_rust_comments(rust_text)
    m = re.search(rf"\b(?:pub\s+)?enum\s+{re.escape(enum_name)}\b[^{{]*\{{", cleaned)
    if not m:
        return []
    brace_depth = 1
    pos = m.end()
    body_chars: List[str] = []
    while pos < len(cleaned) and brace_depth > 0:
        lit_end = _advance_rust_literal(cleaned, pos)
        if lit_end is not None:
            body_chars.append(cleaned[pos:lit_end])
            pos = lit_end
            continue
        ch = cleaned[pos]
        if ch == "{":
            brace_depth += 1
            body_chars.append(ch)
        elif ch == "}":
            brace_depth -= 1
            if brace_depth > 0:
                body_chars.append(ch)
        else:
            body_chars.append(ch)
        pos += 1
    body = "".join(body_chars)

    # Split on top-level commas only (outside (), {}, [], and string/char literals)
    variants: List[str] = []
    cur: List[str] = []
    p_depth = b_depth = k_depth = 0
    pos = 0
    n = len(body)
    while pos < n:
        lit_end = _advance_rust_literal(body, pos)
        if lit_end is not None:
            cur.append(body[pos:lit_end])
            pos = lit_end
            continue
        ch = body[pos]
        if ch == "(":
            p_depth += 1
        elif ch == ")":
            p_depth = max(0, p_depth - 1)
        elif ch == "[":
            b_depth += 1
        elif ch == "]":
            b_depth = max(0, b_depth - 1)
        elif ch == "{":
            k_depth += 1
        elif ch == "}":
            k_depth = max(0, k_depth - 1)
        if ch == "," and p_depth == 0 and b_depth == 0 and k_depth == 0:
            item = "".join(cur).strip()
            cur = []
            if item:
                v = _extract_rust_variant_ident(item)
                if v:
                    variants.append(v)
        else:
            cur.append(ch)
        pos += 1
    tail = "".join(cur).strip()
    if tail:
        v = _extract_rust_variant_ident(tail)
        if v:
            variants.append(v)
    return variants


def _extract_rust_variant_ident(item: str) -> Optional[str]:
    s = item.lstrip()
    while s.startswith("#["):
        pos = 2
        depth = 1
        n = len(s)
        while pos < n and depth > 0:
            lit_end = _advance_rust_literal(s, pos)
            if lit_end is not None:
                pos = lit_end
                continue
            if s[pos] == "[":
                depth += 1
            elif s[pos] == "]":
                depth -= 1
            pos += 1
        s = s[pos:].lstrip()
    if not s:
        return None
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\b", s)
    return m.group(1) if m else None


def parse_rust_const_int(rust_text: str, const_name: str) -> Optional[int]:
    cleaned = strip_rust_comments(rust_text)
    pat = re.compile(
        rf"\b(?:pub(?:\s*\([^)]+\))?\s+)?const\s+{re.escape(const_name)}\s*:[^=]+=\s*([^;]+);"
    )
    m = pat.search(cleaned)
    if not m:
        return None
    return _safe_eval_int_expr(m.group(1))


def _strip_yaml_inline_comment(line: str) -> str:
    """Strip `# ...` YAML inline comment outside single/double quotes (handles apostrophes in comments)."""
    in_single = False
    in_double = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if in_double:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
        elif in_single:
            if ch == "'":
                if i + 1 < n and line[i + 1] == "'":
                    i += 2
                    continue
                in_single = False
            i += 1
        else:
            if ch == '"':
                in_double = True
            elif ch == "'":
                in_single = True
            elif ch == "#" and (i == 0 or line[i - 1].isspace()):
                return line[:i].rstrip()
            i += 1
    return line.rstrip()


def _unquote_yaml_scalar(val: str) -> str:
    s = val.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def _extract_yaml_run_blocks(active_lines: List[Tuple[int, str]]) -> List[str]:
    """Extract command text from single-line and multi-line `run:` blocks."""
    blocks: List[str] = []
    i = 0
    n = len(active_lines)
    while i < n:
        indent, line = active_lines[i]
        s = line.strip()
        m = re.match(r"^(?:-\s+)?run:\s*(.*)$", s)
        if not m:
            i += 1
            continue
        rhs = m.group(1).strip()
        if re.fullmatch(r"[|>](?:[+-][1-9]?|[1-9][+-]?)?", rhs):
            buf: List[str] = []
            i += 1
            while i < n and active_lines[i][0] > indent:
                buf.append(active_lines[i][1])
                i += 1
            if buf:
                blocks.append(textwrap.dedent("\n".join(buf)))
        else:
            buf = [rhs] if rhs else []
            i += 1
            while i < n and active_lines[i][0] > indent:
                next_s = active_lines[i][1].strip()
                if re.match(r"^[A-Za-z0-9_-]+:", next_s) or next_s.startswith("- "):
                    break
                buf.append(active_lines[i][1])
                i += 1
            if buf:
                if rhs and len(buf) > 1:
                    blocks.append(buf[0] + "\n" + textwrap.dedent("\n".join(buf[1:])))
                elif rhs:
                    blocks.append(buf[0])
                else:
                    blocks.append(textwrap.dedent("\n".join(buf)))
    return blocks


_SHELL_CMD_PREFIX_WORDS = frozenset(
    {"if", "then", "elif", "else", "do", "!", "time", "command", "exec", "sudo", "nohup"}
)
_SHELL_BOUNDARY_CHARS = frozenset(";\n&|(){}`")
_SHELL_WORD_STOP_CHARS = frozenset(" \t\r\n;&|(){}<>'\"`#")
_GREP_VALUE_FLAGS = frozenset(
    {
        "-f",
        "--file",
        "-m",
        "--max-count",
        "-A",
        "-B",
        "-C",
        "--after-context",
        "--before-context",
        "--context",
        "--label",
        "--exclude",
        "--include",
        "--exclude-dir",
        "--include-dir",
    }
)


_SHELL_SECRET_EXPANSION_RE = re.compile(
    r"\$(?:\{?\s*(?:SECRETS|GITHUB_TOKEN)\b|\{\{\s*secrets\.)",
    re.IGNORECASE,
)


def _scan_shell_single_quoted(script: str, i: int) -> Tuple[int, bool]:
    n = len(script)
    j = i + 1
    while j < n:
        if script[j] == "'":
            return j + 1, True
        j += 1
    return n, False


def _scan_shell_double_quoted(script: str, i: int) -> Tuple[int, bool, bool]:
    n = len(script)
    j = i + 1
    has_subst_or_secret = False
    while j < n:
        ch = script[j]
        if ch == "\\" and j + 1 < n:
            j += 2
            continue
        if ch == "`":
            has_subst_or_secret = True
            j += 1
            continue
        if ch == "$":
            if j + 1 < n and script[j + 1] == "(":
                has_subst_or_secret = True
                j += 2
                continue
            if _SHELL_SECRET_EXPANSION_RE.match(script, j):
                has_subst_or_secret = True
            j += 1
            continue
        if ch == '"':
            return j + 1, has_subst_or_secret, True
        j += 1
    return n, has_subst_or_secret, False


def _scan_shell_unquoted_word(script: str, i: int) -> Tuple[int, bool]:
    n = len(script)
    j = i
    had_escape = False
    while j < n:
        ch = script[j]
        if ch == "\\" and j + 1 < n:
            if script[j + 1] == "\n":
                break
            had_escape = True
            j += 2
            continue
        if ch in _SHELL_WORD_STOP_CHARS:
            break
        j += 1
    return j, had_escape


def _parse_heredoc_delimiter(script: str, start: int) -> Optional[Tuple[str, bool, int]]:
    """Parse POSIX `<<` / `<<-` heredoc delimiter starting immediately after `<<`."""
    n = len(script)
    j = start
    strip_tabs = False
    if j < n and script[j] == "-":
        strip_tabs = True
        j += 1
    while j < n and script[j] in (" ", "\t"):
        j += 1
    delim_parts: List[str] = []
    has_token = False
    while j < n:
        ch = script[j]
        if ch in (" ", "\t", "\r", "\n", ";", "&", "|", "(", ")", "<", ">", "`"):
            break
        if ch == "#":
            if not has_token:
                return None
            break
        if ch == "'":
            has_token = True
            end_sq, closed_sq = _scan_shell_single_quoted(script, j)
            if not closed_sq:
                return None
            delim_parts.append(script[j + 1 : end_sq - 1])
            j = end_sq
            continue
        if ch == '"':
            has_token = True
            k = j + 1
            closed_dq = False
            while k < n:
                if script[k] == "\\" and k + 1 < n:
                    delim_parts.append(script[k + 1])
                    k += 2
                    continue
                if script[k] == '"':
                    closed_dq = True
                    k += 1
                    break
                delim_parts.append(script[k])
                k += 1
            if not closed_dq:
                return None
            j = k
            continue
        if ch == "\\" and j + 1 < n:
            has_token = True
            if script[j + 1] != "\n":
                delim_parts.append(script[j + 1])
            j += 2
            continue
        has_token = True
        delim_parts.append(ch)
        j += 1
    if not has_token:
        return None
    return "".join(delim_parts), strip_tabs, j


def _consume_grep_invocation_args(script: str, i: int, out: List[str]) -> int:
    """Sanitize only the pattern literal of an unquoted grep/egrep/rg command invocation."""
    n = len(script)
    expect_pattern_next = False
    expect_value_next = False
    saw_explicit_pattern_flag = False
    saw_end_of_opts = False

    while i < n:
        ch = script[i]
        if ch in (" ", "\t", "\r"):
            out.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n and script[i + 1] == "\n":
            out.append(script[i : i + 2])
            i += 2
            continue
        if ch in _SHELL_BOUNDARY_CHARS or ch in ("<", ">"):
            break
        if ch == "#":
            break

        if ch == "'":
            end, closed = _scan_shell_single_quoted(script, i)
            if not closed:
                out.append(script[i:end])
                return end
            if expect_value_next:
                out.append(script[i:end])
                expect_value_next = False
                i = end
                continue
            out.append("''")
            i = end
            if expect_pattern_next:
                expect_pattern_next = False
                continue
            break

        if ch == '"':
            end, has_subst_or_secret, closed = _scan_shell_double_quoted(script, i)
            if not closed:
                out.append(script[i:end])
                return end
            if expect_value_next or has_subst_or_secret:
                out.append(script[i:end])
            else:
                out.append('""')
            if expect_value_next:
                expect_value_next = False
                i = end
                continue
            i = end
            if expect_pattern_next:
                expect_pattern_next = False
                continue
            break

        end, had_escape = _scan_shell_unquoted_word(script, i)
        if end == i:
            break
        word = script[i:end]
        out.append(word)
        i = end

        if expect_value_next:
            expect_value_next = False
            continue
        if expect_pattern_next:
            expect_pattern_next = False
            continue
        if not saw_end_of_opts and not had_escape and word.startswith("-") and len(word) > 1:
            if word == "--":
                saw_end_of_opts = True
            elif word in ("-e", "--regexp") or (
                not word.startswith("--") and word.endswith("e") and word[1:].isalpha()
            ):
                expect_pattern_next = True
                saw_explicit_pattern_flag = True
            elif word in _GREP_VALUE_FLAGS:
                expect_value_next = True
            continue
        if saw_explicit_pattern_flag:
            break
        break

    return i


def _strip_grep_pattern_literals(script: str) -> str:
    """Blank out safe regex pattern args of unquoted grep/egrep/rg commands without masking shell escapes, heredocs, or $(...)."""
    out: List[str] = []
    i = 0
    n = len(script)
    at_cmd_pos = True
    pending_heredocs: List[Tuple[str, bool]] = []

    while i < n:
        ch = script[i]
        if ch in (" ", "\t", "\r"):
            out.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            if script[i + 1] == "\n":
                out.append(script[i : i + 2])
                i += 2
                continue
            end, _ = _scan_shell_unquoted_word(script, i)
            out.append(script[i:end])
            at_cmd_pos = False
            i = end
            continue
        if ch in _SHELL_BOUNDARY_CHARS:
            out.append(ch)
            at_cmd_pos = ch not in (")", "}")
            i += 1
            if ch == "\n" and pending_heredocs:
                while pending_heredocs and i < n:
                    delim, strip_tabs = pending_heredocs.pop(0)
                    while i < n:
                        nl = script.find("\n", i)
                        if nl == -1:
                            line = script[i:]
                            next_i = n
                        else:
                            line = script[i:nl]
                            next_i = nl + 1
                        out.append(script[i:next_i])
                        i = next_i
                        cmp_line = line.rstrip("\r")
                        if strip_tabs:
                            cmp_line = cmp_line.lstrip("\t")
                        if cmp_line == delim:
                            break
                at_cmd_pos = True
            continue
        if ch == "<":
            if i + 1 < n and script[i + 1] == "<" and not (i + 2 < n and script[i + 2] == "<"):
                hd = _parse_heredoc_delimiter(script, i + 2)
                if hd is not None:
                    delim, strip_tabs, next_j = hd
                    out.append(script[i:next_j])
                    pending_heredocs.append((delim, strip_tabs))
                    i = next_j
                    continue
            out.append(ch)
            i += 1
            continue
        if ch == ">":
            out.append(ch)
            i += 1
            continue
        if ch == "#":
            if i == 0 or script[i - 1] in (" ", "\t", "\r", "\n", ";", "&", "|", "(", "{", "`"):
                end_line = script.find("\n", i)
                if end_line == -1:
                    out.append(script[i:])
                    break
                out.append(script[i:end_line])
                i = end_line
                continue
            end, _ = _scan_shell_unquoted_word(script, i)
            out.append(script[i:end])
            at_cmd_pos = False
            i = end
            continue
        if ch == "'":
            end, closed = _scan_shell_single_quoted(script, i)
            out.append(script[i:end])
            at_cmd_pos = False
            i = end
            if not closed:
                break
            continue
        if ch == '"':
            end, _, closed = _scan_shell_double_quoted(script, i)
            out.append(script[i:end])
            at_cmd_pos = False
            i = end
            if not closed:
                break
            continue

        end, had_escape = _scan_shell_unquoted_word(script, i)
        word = script[i:end]
        out.append(word)
        i = end

        if at_cmd_pos and not had_escape and word in ("grep", "egrep", "rg"):
            at_cmd_pos = False
            i = _consume_grep_invocation_args(script, i, out)
        elif at_cmd_pos and not had_escape and (
            word in _SHELL_CMD_PREFIX_WORDS
            or bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", word))
        ):
            at_cmd_pos = True
        else:
            at_cmd_pos = False

    return "".join(out)


def inspect_workflow_yaml_text(yaml_text: str) -> Dict[str, Any]:
    """Stdlib-only GitHub Actions YAML security & structure inspector (zero `yaml.load`)."""
    raw_lines = yaml_text.splitlines()
    active_lines: List[Tuple[int, str]] = []
    for ln in raw_lines:
        no_comment = _strip_yaml_inline_comment(ln)
        if not no_comment.strip():
            continue
        indent = len(ln) - len(ln.lstrip(" "))
        active_lines.append((indent, no_comment))

    top_permissions: Optional[str] = None
    in_jobs = False
    jobs_indent: Optional[int] = None
    current_job: Optional[str] = None
    job_indent: Optional[int] = None
    job_names: List[str] = []
    job_permissions: Dict[str, Any] = {}
    in_job_perm = False
    job_perm_indent = 0

    for indent, line in active_lines:
        s = line.strip()
        if indent == 0:
            in_jobs = s == "jobs:"
            in_job_perm = False
            current_job = None
            if s.startswith("permissions:"):
                raw_perm = s.split(":", 1)[1].strip()
                top_permissions = _unquote_yaml_scalar(raw_perm) if raw_perm else "mapping"
            continue
        if in_jobs:
            if jobs_indent is None:
                jobs_indent = indent
            if indent == jobs_indent and s.endswith(":"):
                current_job = s[:-1].strip()
                job_names.append(current_job)
                job_indent = indent
                in_job_perm = False
                continue
            if current_job is not None and job_indent is not None:
                if indent > job_indent and s.startswith("permissions:"):
                    val = s.split(":", 1)[1].strip()
                    if val:
                        job_permissions[current_job] = _unquote_yaml_scalar(val)
                        in_job_perm = False
                    else:
                        job_permissions[current_job] = {}
                        in_job_perm = True
                        job_perm_indent = indent
                    continue
                if in_job_perm:
                    if indent > job_perm_indent and ":" in s:
                        k, v = s.split(":", 1)
                        if isinstance(job_permissions.get(current_job), dict):
                            job_permissions[current_job][k.strip()] = _unquote_yaml_scalar(v)
                    else:
                        in_job_perm = False

    non_comment_text = "\n".join(line for _, line in active_lines)
    checkout_count = len(re.findall(r"uses:\s*['\"]?actions/checkout@", non_comment_text))
    persist_false_count = len(
        re.findall(
            r"\bpersist-credentials:\s*['\"]?false['\"]?(?=\s|$)",
            non_comment_text,
            re.IGNORECASE,
        )
    )
    has_write_all = bool(
        re.search(
            r"\bpermissions:\s*['\"]?write-all['\"]?(?=\s|$)",
            non_comment_text,
            re.IGNORECASE,
        )
    )
    has_persist_true = bool(
        re.search(
            r"\bpersist-credentials:\s*['\"]?true['\"]?(?=\s|$)",
            non_comment_text,
            re.IGNORECASE,
        )
    )

    run_blocks = _extract_yaml_run_blocks(active_lines)
    exfil_targets = run_blocks if run_blocks else [non_comment_text]
    has_secrets_exfil = False
    for block in exfil_targets:
        cleaned_block = _strip_grep_pattern_literals(block)
        has_downloader = bool(re.search(r"\b(?:curl|wget)\b", cleaned_block, re.IGNORECASE))
        has_secret_ref = bool(
            re.search(
                r"(?:\$\{?\s*(?:SECRETS|GITHUB_TOKEN)\b|\$\{\{\s*secrets\.)",
                cleaned_block,
                re.IGNORECASE,
            )
        )
        if has_downloader and has_secret_ref:
            has_secrets_exfil = True
            break

    has_force_node24 = bool(
        re.search(
            r"FORCE_JAVASCRIPT_ACTIONS_TO_NODE24:\s*['\"]?true['\"]?",
            non_comment_text,
            re.IGNORECASE,
        )
    )
    runs_on_values = [
        _unquote_yaml_scalar(m.group(1))
        for m in re.finditer(r"^\s*runs-on:\s*(.+)$", non_comment_text, re.MULTILINE)
    ]

    return {
        "top_permissions": top_permissions,
        "jobs": job_names,
        "job_permissions": job_permissions,
        "checkout_count": checkout_count,
        "persist_credentials_false_count": persist_false_count,
        "has_write_all": has_write_all,
        "has_persist_credentials_true": has_persist_true,
        "has_secrets_exfil": has_secrets_exfil,
        "has_force_node24": has_force_node24,
        "runs_on_values": runs_on_values,
        "non_comment_text": non_comment_text,
    }


def check_stdlib_only_python_file(
    path: Path,
    allowed_local_modules: Iterable[str] = (),
) -> List[str]:
    """AST-validate that `path` imports only Python stdlib/builtins or `allowed_local_modules`."""
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(path))
    stdlib = set(sys.stdlib_module_names) | set(sys.builtin_module_names) | set(allowed_local_modules)
    violations: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top not in stdlib:
                    violations.append(f"{path}:{node.lineno}: import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                continue
            if node.module:
                top = node.module.split(".")[0]
                if top not in stdlib:
                    violations.append(f"{path}:{node.lineno}: from {node.module} import ...")
    return violations


def check_funny_chars_in_text(text: str, label: str = "<text>") -> List[str]:
    """Detect ASCII control characters (excluding \\t, \\n, \\r) and U+FFFD replacement chars."""
    violations: List[str] = []
    # Split strictly on '\n' so VT (\x0b) and FF (\x0c) are NOT swallowed by str.splitlines().
    for lineno, line in enumerate(text.split("\n"), start=1):
        for m in _FUNNY_CHAR_RE.finditer(line):
            ch = m.group(0)
            violations.append(
                f"{label}:{lineno}:{m.start() + 1}: forbidden char U+{ord(ch):04X}"
            )
    return violations


def scan_raptor_python_anti_patterns(text: str, label: str = "<python>") -> List[str]:
    """Scan Python source via AST + regex for RAPTOR-prohibited constructs."""
    violations: List[str] = []
    try:
        tree = ast.parse(text, filename=label)
    except SyntaxError as exc:
        return [f"{label}: SyntaxError: {exc}"]

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                violations.append(f"{label}:{node.lineno}: forbidden {node.func.id}()")
            elif isinstance(node.func, ast.Attribute):
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "yaml"
                    and node.func.attr == "load"
                ):
                    violations.append(f"{label}:{node.lineno}: forbidden yaml.load()")
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "tempfile"
                    and node.func.attr == "mktemp"
                ):
                    violations.append(f"{label}:{node.lineno}: forbidden tempfile.mktemp()")
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant):
                        if bool(kw.value.value) is True:
                            violations.append(
                                f"{label}:{node.lineno}: forbidden truthy shell={kw.value.value!r}"
                            )
                    else:
                        violations.append(
                            f"{label}:{node.lineno}: forbidden dynamic shell= argument"
                        )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "yaml" or alias.name.startswith("yaml."):
                    violations.append(f"{label}:{node.lineno}: forbidden import yaml")
        elif isinstance(node, ast.ImportFrom):
            if node.module and (node.module == "yaml" or node.module.startswith("yaml.")):
                violations.append(f"{label}:{node.lineno}: forbidden from yaml import")

    if PEM_BLOCK_PATTERN.search(text):
        violations.append(f"{label}: hardcoded PEM private key header matched")

    return violations


def run_cargo_test_target(
    test_target: str,
    timeout: float = 300.0,
) -> SubprocessResult:
    """Execute `cargo test --test <test_target> --all-features` at REPO_ROOT."""
    return run_subprocess_safe(
        ["cargo", "test", "--test", test_target, "--all-features"],
        cwd=REPO_ROOT,
        timeout=timeout,
    )


def run_isolated_package_audit(
    extra_check: Optional[Callable[[Path, zipfile.ZipFile, Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Run `scripts/package_agent_octopus.py` into a temp zip and restore `logs/dist_manifest.json`."""
    pkg_script = REPO_ROOT / "scripts" / "package_agent_octopus.py"
    if not pkg_script.is_file():
        raise AssertionError(f"Missing packaging script: {pkg_script}")

    logs_dir = REPO_ROOT / "logs"
    manifest_path = logs_dir / "dist_manifest.json"
    logs_existed = logs_dir.exists()
    manifest_existed = manifest_path.is_file()
    manifest_backup = manifest_path.read_bytes() if manifest_existed else None

    spec = importlib.util.spec_from_file_location("ao_pkg_mod_isolated", pkg_script)
    if spec is None or spec.loader is None:
        raise AssertionError(f"Unable to load {pkg_script}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    try:
        with tempfile.TemporaryDirectory(prefix="ao_pkg_audit_") as tmpdir:
            tmp_zip = Path(tmpdir) / "agent_octopus_audit.zip"
            ok = mod.package_agent_octopus(output_zip=tmp_zip)
            if not ok or not tmp_zip.is_file():
                raise AssertionError("package_agent_octopus() failed to produce temp archive")
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            with zipfile.ZipFile(tmp_zip, "r") as zf:
                names = [n.replace("\\", "/") for n in zf.namelist()]
                if extra_check is not None:
                    extra_check(tmp_zip, zf, manifest_data)
            return {
                "archive_entries": names,
                "manifest": manifest_data,
                "exclude_dirs": set(getattr(mod, "EXCLUDE_DIRS", set())),
            }
    finally:
        if manifest_existed and manifest_backup is not None:
            manifest_path.write_bytes(manifest_backup)
        elif manifest_path.is_file():
            manifest_path.unlink()
        if not logs_existed and logs_dir.is_dir():
            try:
                if not any(logs_dir.iterdir()):
                    logs_dir.rmdir()
            except OSError:
                pass


def run_git_status_short() -> List[str]:
    res = run_subprocess_safe(["git", "-C", str(REPO_ROOT), "status", "--short"], timeout=30.0)
    if res.returncode != 0:
        raise AssertionError(f"git status --short failed: {res.stderr}")
    return [line.rstrip() for line in res.stdout.splitlines() if line.strip()]


def git_check_ignore(rel_path: str) -> bool:
    res = run_subprocess_safe(
        ["git", "-C", str(REPO_ROOT), "check-ignore", "-q", rel_path],
        timeout=15.0,
    )
    return res.returncode == 0
