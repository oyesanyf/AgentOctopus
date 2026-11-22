"""Shared test harness, binary discovery, mock servers, and validators for E2E release tests."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import urllib.error
import urllib.parse
import urllib.request


REPO_ROOT = Path(__file__).resolve().parents[2]
SIBLING_SANDBOX_RUNTIME = REPO_ROOT.parent / "sandbox-runtime"
SIBLING_KILLSWITCH = REPO_ROOT.parent / "killswitch"

BASELINE_ANCESTOR_SHA = "7fd028b6a7c8426a8cc6d3eb8ba85fe7e4eeb91c"
BASELINE_SANDBOX_RUNTIME_SHA = "0bbebed0aa9a8e628dc4df8bc30293550a1988eb"
BASELINE_KILLSWITCH_SHA = "ef72b67f389a693a764251207ca0d9fd519abca9"

# Pre-existing untracked host artifacts in d:\harfile\sandbox-runtime (predating AgentOctopus M4):
# - c.commit(); (2026-11-19)
# - logs/otel_sessions.jsonl (2026-11-18)
SANDBOX_RUNTIME_ALLOWED_UNTRACKED = frozenset({"c.commit();", "logs/otel_sessions.jsonl"})
SANDBOX_RUNTIME_ALLOWED_PORCELAIN = frozenset({"?? c.commit();", "?? logs/", "?? logs/otel_sessions.jsonl"})

EXPECTED_GIT_USER_NAME = "femi oyesanya"
EXPECTED_GIT_USER_EMAIL = "oyesanyf@gmail.com"
EXPECTED_REMOTE_SUBSTR = "oyesanyf/AgentOctopus"

# Forbidden tracked artifacts under ORIGINAL_REQUEST.md R3 & PROJECT.md #13
FORBIDDEN_TRACKED_EXACT = {
    "DEAD_ENDS.md",
    "TEST_READY.md",
    "TEST_INFRA.md",
    "PROJECT.md",
    "dist_manifest.json",
}
FORBIDDEN_TRACKED_PREFIXES = (
    ".agents/",
    "test/",
)
FORBIDDEN_OSHOOSICLAW_FILES = {
    "docs/community/LAUNCH_PLAYBOOK_500_STARS.md",
    "docs/PERFORMANCE_AND_SECURITY_BENCHMARK.md",
    "docs/CIS_BENCHMARK_AGENTOCTOPUS.md",
}
REQUIRED_DOCS_FILES = (
    "docs/README.md",
    "docs/ARCHITECTURE_AND_SECURITY_MODEL.md",
    "docs/KERNEL_PATCHING_AND_ZERO_BREAKOUT_SHIELD.md",
    "docs/CLI_AND_POLICY_REFERENCE.md",
    "docs/OPERATIONS_AND_API_GUIDE.md",
    "docs/AGENTMESH_WASM_INTEGRATION.md",
    "docs/ADVERSARIAL_DEFENSE_AND_RED_TEAMING.md",
)
FORBIDDEN_REPORT_RE = re.compile(r"^[^/]+_test_report\.(json|md)$", re.IGNORECASE)
FORBIDDEN_BINARY_ARCHIVE_RE = re.compile(
    r"\.(msi|zip|exe|log|dll|sys|pem|pfx|key|p12)$",
    re.IGNORECASE,
)


def configure_stdio_utf8() -> None:
    """Ensure UTF-8 output on Windows consoles so emoji/Unicode diagnostics never raise."""
    if sys.platform == "win32":
        for stream_name in ("stdout", "stderr"):
            stream = getattr(sys, stream_name, None)
            if stream is not None and hasattr(stream, "reconfigure"):
                try:
                    stream.reconfigure(encoding="utf-8", errors="replace")
                except Exception:
                    pass


class BinaryResolutionError(RuntimeError):
    """Raised when an explicit binary or env override is invalid or cannot be resolved."""


@dataclass
class E2EConfig:
    repo_root: Path = REPO_ROOT
    octopus_bin: Optional[Path] = None
    agent_bin: Optional[Path] = None
    skip_cargo: bool = False
    skip_remote: bool = False
    allow_cargo_build: bool = False
    allow_uncommitted_e2e: bool = False
    verbose: bool = False


_ACTIVE_CONFIG: Optional[E2EConfig] = None


def set_config(cfg: E2EConfig) -> None:
    global _ACTIVE_CONFIG
    _ACTIVE_CONFIG = cfg


def get_config() -> E2EConfig:
    if _ACTIVE_CONFIG is not None:
        return _ACTIVE_CONFIG
    octo_env = os.environ.get("OCTOPUS_E2E_BIN") or os.environ.get("OCTOPUS_BIN")
    agent_env = os.environ.get("OCTOPUS_E2E_AGENT_BIN") or os.environ.get("AGENT_OCTOPUS_BIN")
    return E2EConfig(
        repo_root=REPO_ROOT,
        octopus_bin=Path(octo_env).resolve() if octo_env else None,
        agent_bin=Path(agent_env).resolve() if agent_env else None,
        skip_cargo=os.environ.get("OCTOPUS_E2E_SKIP_CARGO", "") == "1",
        skip_remote=os.environ.get("OCTOPUS_E2E_SKIP_REMOTE", "") == "1",
        allow_cargo_build=os.environ.get("OCTOPUS_E2E_ALLOW_CARGO_BUILD", "") == "1",
        allow_uncommitted_e2e=os.environ.get("OCTOPUS_E2E_ALLOW_UNCOMMITTED", "") == "1",
        verbose=os.environ.get("OCTOPUS_E2E_VERBOSE", "") == "1",
    )


def _exe_name(stem: str) -> str:
    return f"{stem}.exe" if sys.platform == "win32" else stem


def _is_usable_binary(path: Path) -> bool:
    if not path.is_file():
        return False
    if sys.platform != "win32":
        return os.access(path, os.X_OK)
    return True


def _candidate_target_paths(stem: str, repo_root: Path) -> List[Path]:
    exe = _exe_name(stem)
    candidates: List[Path] = []
    cargo_target = os.environ.get("CARGO_TARGET_DIR", "").strip()
    roots: List[Path] = []
    if cargo_target:
        roots.append(Path(cargo_target))
    roots.append(repo_root / "target")
    for root in roots:
        for profile in ("release", "debug"):
            candidates.append(root / profile / exe)
    return candidates


def _maybe_cargo_build(bin_name: str, repo_root: Path) -> None:
    cmd = ["cargo", "build", "--bin", bin_name]
    res = run_subprocess_safe(cmd, cwd=repo_root, timeout=600.0)
    if res.returncode != 0:
        raise BinaryResolutionError(
            f"Explicit --allow-cargo-build failed for `{bin_name}` (exit {res.returncode}):\n"
            f"{res.stderr or res.stdout}"
        )


def resolve_octopus_bin(
    explicit_bin: Optional[str] = None,
    repo_root: Path = REPO_ROOT,
    allow_cargo_build: bool = False,
) -> Optional[Path]:
    """Resolve the `octopus` CLI binary via strict precedence without implicit cargo calls.

    Precedence:
      1. Explicit `--bin` (fail-closed if missing/invalid)
      2. `OCTOPUS_BIN` env var (fail-closed if set and missing/invalid)
      3. `CARGO_TARGET_DIR` / workspace `target/release|debug/octopus[.exe]`
      4. `PATH` lookup (`shutil.which("octopus")`)
      5. Only if `allow_cargo_build=True`: `cargo build --bin octopus`
    """
    if explicit_bin is not None:
        p = Path(explicit_bin).expanduser()
        if not _is_usable_binary(p):
            raise BinaryResolutionError(
                f"Explicit --bin path does not exist or is not executable: {p}"
            )
        return p.resolve()

    env_bin = os.environ.get("OCTOPUS_BIN", "").strip()
    if env_bin:
        p = Path(env_bin).expanduser()
        if not _is_usable_binary(p):
            raise BinaryResolutionError(
                f"OCTOPUS_BIN path does not exist or is not executable: {p}"
            )
        return p.resolve()

    for candidate in _candidate_target_paths("octopus", repo_root):
        if _is_usable_binary(candidate):
            return candidate.resolve()

    which_hit = shutil.which("octopus")
    if which_hit:
        p = Path(which_hit)
        if _is_usable_binary(p):
            return p.resolve()

    if allow_cargo_build:
        _maybe_cargo_build("octopus", repo_root)
        for candidate in _candidate_target_paths("octopus", repo_root):
            if _is_usable_binary(candidate):
                return candidate.resolve()

    return None


def resolve_agent_bin(
    explicit_bin: Optional[str] = None,
    repo_root: Path = REPO_ROOT,
    allow_cargo_build: bool = False,
) -> Optional[Path]:
    """Resolve `agent_octopus` or `start` web-server binary via strict precedence."""
    if explicit_bin is not None:
        p = Path(explicit_bin).expanduser()
        if not _is_usable_binary(p):
            raise BinaryResolutionError(
                f"Explicit --agent-bin path does not exist or is not executable: {p}"
            )
        return p.resolve()

    for env_name in ("AGENT_OCTOPUS_BIN", "START_BIN"):
        env_bin = os.environ.get(env_name, "").strip()
        if env_bin:
            p = Path(env_bin).expanduser()
            if not _is_usable_binary(p):
                raise BinaryResolutionError(
                    f"{env_name} path does not exist or is not executable: {p}"
                )
            return p.resolve()

    for candidate in _candidate_target_paths("agent_octopus", repo_root):
        if _is_usable_binary(candidate):
            return candidate.resolve()
    for candidate in _candidate_target_paths("start", repo_root):
        if _is_usable_binary(candidate):
            return candidate.resolve()

    # Only search PATH for the unambiguous `agent_octopus` name (never generic `start` e.g. C:\tools\start.bat)
    which_hit = shutil.which("agent_octopus")
    if which_hit:
        p = Path(which_hit)
        if _is_usable_binary(p):
            return p.resolve()

    if allow_cargo_build:
        _maybe_cargo_build("agent_octopus", repo_root)
        for candidate in _candidate_target_paths("agent_octopus", repo_root):
            if _is_usable_binary(candidate):
                return candidate.resolve()

    return None


def require_octopus_bin(cfg: Optional[E2EConfig] = None) -> Path:
    c = cfg or get_config()
    if c.octopus_bin is not None and _is_usable_binary(c.octopus_bin):
        return c.octopus_bin
    resolved = resolve_octopus_bin(
        repo_root=c.repo_root,
        allow_cargo_build=c.allow_cargo_build,
    )
    if resolved is None:
        raise AssertionError(
            "octopus binary could not be resolved (fail-closed). "
            "Pass --bin PATH, set OCTOPUS_BIN, or build `cargo build --bin octopus`."
        )
    return resolved


def require_agent_bin(cfg: Optional[E2EConfig] = None) -> Path:
    c = cfg or get_config()
    if c.agent_bin is not None and _is_usable_binary(c.agent_bin):
        return c.agent_bin
    resolved = resolve_agent_bin(
        repo_root=c.repo_root,
        allow_cargo_build=c.allow_cargo_build,
    )
    if resolved is None:
        raise AssertionError(
            "agent_octopus / start binary could not be resolved (fail-closed). "
            "Pass --agent-bin PATH, set AGENT_OCTOPUS_BIN, or build `cargo build --bin agent_octopus`."
        )
    return resolved


def _is_win32_appcontainer_capable_python(py_exe: Path) -> bool:
    """Return True if `py_exe`'s parent dir has ALL APPLICATION PACKAGES RX or current-user FullControl/WRITE_DAC."""
    if not py_exe.is_file():
        return False
    parent = py_exe.parent
    res = run_subprocess_safe(["icacls", str(parent)], timeout=10.0)
    if res.returncode != 0:
        return False
    username = os.environ.get("USERNAME", "").strip().lower()
    userdomain = os.environ.get("USERDOMAIN", "").strip().lower()
    for raw_line in res.stdout.splitlines():
        line = raw_line.strip().lower()
        if not line:
            continue
        if "s-1-15-2-1" in line or "all application packages" in line:
            if any(perm in line for perm in ("(rx)", "(f)", "(m)", "(r)")):
                return True
        if username:
            user_match = (
                f"\\{username}:" in line
                or line.startswith(f"{username}:")
                or (userdomain and f"{userdomain}\\{username}:" in line)
            )
            if user_match and ("(f)" in line or "wdac" in line or "write_dac" in line):
                return True
    return False


def find_strict_sandbox_python() -> str:
    """Discover a Python interpreter capable of running inside `--sandbox strict` (Windows AppContainer)."""
    if sys.platform != "win32":
        return sys.executable

    current = Path(sys.executable)
    if _is_win32_appcontainer_capable_python(current):
        return str(current)

    candidates: List[Path] = []
    local_app = os.environ.get("LOCALAPPDATA", "").strip()
    if local_app:
        py_root = Path(local_app) / "Python"
        preferred = py_root / "pythoncore-3.14-64" / "python.exe"
        if preferred.is_file():
            candidates.append(preferred)
        if py_root.is_dir():
            for child in sorted(py_root.glob("pythoncore-*"), reverse=True):
                exe = child / "python.exe"
                if exe.is_file() and exe not in candidates:
                    candidates.append(exe)

    if shutil.which("py"):
        py_list = run_subprocess_safe(["py", "-0p"], timeout=10.0)
        if py_list.returncode == 0:
            for line in py_list.stdout.splitlines():
                m = re.search(
                    r"([A-Za-z]:\\[^\r\n]+?python[^\r\n]*\.exe)\s*$",
                    line.strip(),
                    re.IGNORECASE,
                )
                if m:
                    cand = Path(m.group(1).strip())
                    if cand.is_file() and cand not in candidates:
                        candidates.append(cand)

    for cand in candidates:
        if _is_win32_appcontainer_capable_python(cand):
            return str(cand)

    return sys.executable


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
    timeout: float = 30.0,
    input_text: Optional[str] = None,
) -> SubprocessResult:
    """Execute a subprocess with UTF-8 decoding and process-group timeout cleanup."""
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


def default_clean_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Return a copy of os.environ with OCTOPUS_ENABLE_RL_ADVISORY scrubbed by default."""
    env = os.environ.copy()
    env.pop("OCTOPUS_ENABLE_RL_ADVISORY", None)
    env["PYTHONUTF8"] = "1"
    if extra:
        env.update(extra)
    return env


class TempWorkspace:
    """Isolated temporary directory outside any git repo for policies, scripts, and outputs."""

    def __init__(self, prefix: str = "ao_e2e_") -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix=prefix)
        self.path = Path(self._tmpdir.name).resolve()

    def cleanup(self) -> None:
        self._tmpdir.cleanup()

    def __enter__(self) -> "TempWorkspace":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.cleanup()

    def path_for(self, rel: str) -> Path:
        p = (self.path / rel).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def write_file(self, rel: str, content: str) -> Path:
        p = self.path_for(rel)
        p.write_text(content, encoding="utf-8")
        return p

    def write_json(self, rel: str, data: Any) -> Path:
        return self.write_file(rel, json.dumps(data, indent=2) + "\n")

    def read_file(self, rel: str) -> str:
        return (self.path / rel).read_text(encoding="utf-8", errors="replace")

    def exists(self, rel: str) -> bool:
        return (self.path / rel).exists()

    def make_dir(self, rel: str) -> Path:
        d = (self.path / rel).resolve()
        d.mkdir(parents=True, exist_ok=True)
        return d

    def write_poisoned_rl_policy(
        self,
        bias: str = "HardMitigation",
        rel: str = "config/rl_defense_policy.json",
    ) -> Path:
        """Write an adversarial Q-table JSON biased toward HardMitigation (4) or PassiveObserve (0)."""
        target_idx = 4 if bias == "HardMitigation" else 0
        payload: Dict[str, float] = {}
        buckets = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 528, 596]
        for b in buckets:
            for a in range(5):
                payload[f"{b}:{a}"] = 9999.0 if a == target_idx else -9999.0
        return self.write_json(rel, payload)

    def run_octopus(
        self,
        args: Sequence[str],
        octopus_bin: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[Path] = None,
        timeout: float = 30.0,
    ) -> SubprocessResult:
        exe = octopus_bin or require_octopus_bin()
        run_env = env if env is not None else default_clean_env()
        return run_subprocess_safe(
            [str(exe), *args],
            cwd=cwd or self.path,
            env=run_env,
            timeout=timeout,
        )


@dataclass
class RecordedHit:
    method: str
    path: str
    headers: Dict[str, str]
    body: str


class LocalLoopbackMockServer:
    """Ephemeral 127.0.0.1:0 HTTP server for zero-internet proxy and credential-masking tests."""

    def __init__(self) -> None:
        self.hits: List[RecordedHit] = []
        self._lock = threading.Lock()
        parent = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _handle(self, method: str) -> None:
                length = int(self.headers.get("Content-Length", "0") or "0")
                raw_body = self.rfile.read(length) if length > 0 else b""
                body_text = raw_body.decode("utf-8", errors="replace")
                hdrs = {k.lower(): v for k, v in self.headers.items()}
                with parent._lock:
                    parent.hits.append(
                        RecordedHit(
                            method=method,
                            path=self.path,
                            headers=hdrs,
                            body=body_text,
                        )
                    )
                if self.path.startswith("/echo"):
                    resp_obj = {
                        "ok": True,
                        "method": method,
                        "path": self.path,
                        "headers": hdrs,
                        "body": body_text,
                    }
                else:
                    resp_obj = {"ok": True, "path": self.path, "server_port": parent.port}
                payload = json.dumps(resp_obj).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self) -> None:
                self._handle("GET")

            def do_POST(self) -> None:
                self._handle("POST")

            def do_PUT(self) -> None:
                self._handle("PUT")

            def do_HEAD(self) -> None:
                self._handle("HEAD")

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port: int = self._server.server_address[1]
        self.host_port: str = f"127.0.0.1:{self.port}"
        self.base_url: str = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def clear_hits(self) -> None:
        with self._lock:
            self.hits.clear()

    def hit_count(self) -> int:
        with self._lock:
            return len(self.hits)

    def stop(self) -> None:
        try:
            self._server.shutdown()
        finally:
            self._server.server_close()
            self._thread.join(timeout=3.0)

    def __enter__(self) -> "LocalLoopbackMockServer":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()


def pick_free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def proxy_probe_script(url: str, method: str = "GET", body: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> str:
    """Return stdlib Python script that routes explicitly through HTTP_PROXY (ignoring NO_PROXY)."""
    hdr_literal = repr(headers or {})
    body_literal = repr(body)
    return f"""
import http.client, json, os, sys, urllib.parse

proxy = os.environ.get("HTTP_PROXY") or os.environ.get("HTTPS_PROXY")
if not proxy:
    print("NO_PROXY_ENV_MISSING", file=sys.stderr)
    sys.exit(11)

p_url = urllib.parse.urlparse(proxy)
if not p_url.hostname or not p_url.port:
    print(f"INVALID_PROXY_URL: {{proxy}}", file=sys.stderr)
    sys.exit(12)

target = urllib.parse.urlparse({url!r})
req_headers = dict({hdr_literal})
if "Host" not in req_headers and "host" not in req_headers:
    req_headers["Host"] = target.netloc
if {body_literal} is not None and "Content-Length" not in req_headers:
    req_headers["Content-Length"] = str(len({body_literal}.encode("utf-8")))

try:
    conn = http.client.HTTPConnection(p_url.hostname, p_url.port, timeout=8)
    conn.request({method!r}, {url!r}, body={body_literal}, headers=req_headers)
    resp = conn.getresponse()
    text = resp.read().decode("utf-8", errors="replace")
    conn.close()
    print(json.dumps({{"status": resp.status, "body": text}}))
    sys.exit(0 if 200 <= resp.status < 400 else 43)
except Exception as exc:
    print(json.dumps({{"status": 0, "error": str(exc)}}))
    sys.exit(44)
""".lstrip()


class WebServerHandle:
    """Launches `agent_octopus start` or `start --daemon --no-browser` in an isolated TempWorkspace."""

    def __init__(
        self,
        workspace: TempWorkspace,
        agent_bin: Optional[Path] = None,
        extra_env: Optional[Dict[str, str]] = None,
        startup_timeout: float = 20.0,
    ) -> None:
        self.workspace = workspace
        self.agent_bin = agent_bin or require_agent_bin()
        self.extra_env = extra_env or {}
        self.startup_timeout = startup_timeout
        self.port: Optional[int] = None
        self.token: Optional[str] = None
        self._proc: Optional[subprocess.Popen[str]] = None

    def start(self) -> "WebServerHandle":
        requested_port = pick_free_loopback_port()
        stem = self.agent_bin.stem.lower()
        if stem == "start":
            cmd = [
                str(self.agent_bin),
                "--daemon",
                "--no-browser",
                "--port",
                str(requested_port),
            ]
        else:
            cmd = [
                str(self.agent_bin),
                "start",
                "--port",
                str(requested_port),
            ]

        env = default_clean_env(
            {
                "OCTOPUS_NO_BROWSER": "1",
                "HEADLESS": "1",
                "OCTOPUS_PORT": str(requested_port),
                **self.extra_env,
            }
        )
        popen_kwargs: Dict[str, Any] = {
            "cwd": str(self.workspace.path),
            "env": env,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
        }
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True

        self._proc = subprocess.Popen(cmd, **popen_kwargs)

        port_file = self.workspace.path / "logs" / "active_port.txt"
        token_file = self.workspace.path / "logs" / ".octopus_operator_token"
        deadline = time.monotonic() + self.startup_timeout
        last_err = ""
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                out, err = self._proc.communicate(timeout=2)
                raise RuntimeError(
                    f"Web server `{self.agent_bin.name}` exited prematurely ({self._proc.returncode}):\n"
                    f"stdout={out}\nstderr={err}"
                )
            if port_file.exists() and token_file.exists():
                try:
                    p_val = int(port_file.read_text(encoding="utf-8").strip())
                    tok = token_file.read_text(encoding="utf-8").strip()
                    if p_val > 0 and tok:
                        status, _ = self._raw_request("GET", "/api/status", port=p_val, token=tok)
                        if status == 200:
                            self.port = p_val
                            self.token = tok
                            return self
                except Exception as exc:
                    last_err = str(exc)
            time.sleep(0.15)

        self.stop()
        raise TimeoutError(
            f"Timed out waiting for web server readiness in {self.workspace.path} (last_err={last_err})"
        )

    def _raw_request(
        self,
        method: str,
        path: str,
        body: Optional[Any] = None,
        port: Optional[int] = None,
        token: Optional[str] = None,
    ) -> Tuple[int, str]:
        p = port or self.port
        t = token if token is not None else self.token
        if p is None:
            raise RuntimeError("WebServerHandle not started")
        conn = http.client.HTTPConnection("127.0.0.1", p, timeout=10.0)
        try:
            headers: Dict[str, str] = {"Host": f"127.0.0.1:{p}"}
            if t:
                headers["X-Octopus-Token"] = t
            payload: Optional[bytes] = None
            if body is not None:
                headers["Content-Type"] = "application/json"
                payload = json.dumps(body).encode("utf-8")
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, raw
        finally:
            conn.close()

    def get_json(self, path: str) -> Tuple[int, Any]:
        status, raw = self._raw_request("GET", path)
        return status, json.loads(raw)

    def post_json(self, path: str, body: Any) -> Tuple[int, Any]:
        status, raw = self._raw_request("POST", path, body=body)
        return status, json.loads(raw)

    def stop(self) -> None:
        if self._proc is not None:
            _terminate_process_tree(self._proc)
            try:
                self._proc.wait(timeout=5.0)
            except Exception:
                pass
            self._proc = None

    def __enter__(self) -> "WebServerHandle":
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()


def assert_blocked_outcome(
    res: SubprocessResult,
    mock_server: Optional[LocalLoopbackMockServer] = None,
    expected_keywords: Sequence[str] = (
        "blocked_by_octopus_policy",
        "cedar",
        "deny",
        "denied",
        "forbidden",
        "blocked",
        "403",
        "permissionerror",
        "eacces",
        "violation",
    ),
) -> None:
    """Assert non-brittle containment denial: non-zero exit (or 403 payload), 0 unauthorized hits, diagnostic present."""
    combined = res.combined_output.lower()
    has_403_json = "403" in combined or "blocked_by_octopus_policy" in combined
    if res.returncode == 0 and not has_403_json:
        raise AssertionError(
            f"Expected blocked outcome (non-zero exit or 403 block), got exit 0.\n"
            f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}"
        )
    if mock_server is not None and mock_server.hit_count() != 0:
        raise AssertionError(
            f"Expected 0 hits on forbidden mock server, observed {mock_server.hit_count()}: {mock_server.hits}"
        )
    if expected_keywords and not any(k.lower() in combined for k in expected_keywords):
        raise AssertionError(
            f"Blocked outcome lacked any expected diagnostic keyword {expected_keywords}.\n"
            f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}"
        )


# ---------------------------------------------------------------------------
# Git & GitHub Read-Only Validators
# ---------------------------------------------------------------------------

def run_git(repo: Path, args: Sequence[str], timeout: float = 15.0) -> SubprocessResult:
    return run_subprocess_safe(["git", "-C", str(repo), *args], timeout=timeout)


def git_ls_files(repo: Path) -> List[str]:
    res = run_git(repo, ["-c", "core.quotePath=false", "ls-files"])
    if res.returncode != 0:
        raise AssertionError(f"git ls-files failed on {repo}: {res.stderr}")
    return [line.strip().replace("\\", "/") for line in res.stdout.splitlines() if line.strip()]


def git_status_porcelain(repo: Path) -> List[str]:
    res = run_git(repo, ["-c", "core.quotePath=false", "status", "--porcelain"])
    if res.returncode != 0:
        raise AssertionError(f"git status --porcelain failed on {repo}: {res.stderr}")
    return [line.rstrip() for line in res.stdout.splitlines() if line.strip()]


def git_check_ignore(repo: Path, probe_path: str) -> bool:
    res = run_git(repo, ["check-ignore", "-q", probe_path])
    return res.returncode == 0


def git_is_ancestor(repo: Path, ancestor: str, descendant: str = "HEAD") -> bool:
    res = run_git(repo, ["merge-base", "--is-ancestor", ancestor, descendant])
    return res.returncode == 0


def git_rev_parse(repo: Path, ref: str = "HEAD") -> str:
    res = run_git(repo, ["rev-parse", ref])
    if res.returncode != 0:
        raise AssertionError(f"git rev-parse {ref} failed on {repo}: {res.stderr}")
    return res.stdout.strip()


def git_diff_name_only(repo: Path, cached: bool = False) -> List[str]:
    args = (
        ["-c", "core.quotePath=false", "diff", "--cached", "--name-only"]
        if cached
        else ["-c", "core.quotePath=false", "diff", "--name-only"]
    )
    res = run_git(repo, args)
    if res.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed on {repo}: {res.stderr}")
    return [line.strip().replace("\\", "/") for line in res.stdout.splitlines() if line.strip()]


def git_untracked_files(repo: Path) -> List[str]:
    res = run_git(repo, ["-c", "core.quotePath=false", "ls-files", "--others", "--exclude-standard"])
    if res.returncode != 0:
        raise AssertionError(f"git ls-files --others --exclude-standard failed on {repo}: {res.stderr}")
    return [line.strip().replace("\\", "/") for line in res.stdout.splitlines() if line.strip()]


def git_ignored_untracked_files(repo: Path) -> List[str]:
    res = run_git(
        repo,
        ["-c", "core.quotePath=false", "ls-files", "--others", "--ignored", "--exclude-standard"],
    )
    if res.returncode != 0:
        raise AssertionError(f"git ls-files --others --ignored --exclude-standard failed on {repo}: {res.stderr}")
    return [line.strip().replace("\\", "/") for line in res.stdout.splitlines() if line.strip()]


def validate_sibling_repo_state(
    repo: Path,
    expected_head_sha: str,
    allowed_untracked: Iterable[str] = (),
    allowed_porcelain: Iterable[str] = (),
    allowed_untracked_dirs: Iterable[str] = (),
) -> List[str]:
    """Fail-closed immutability validator for sibling repositories (`sandbox-runtime`, `killswitch`)."""
    violations: List[str] = []
    if not repo.is_dir():
        return [f"Missing sibling repo: {repo}"]

    head = git_rev_parse(repo, "HEAD")
    if head != expected_head_sha:
        violations.append(f"{repo}: HEAD {head} != expected {expected_head_sha}")

    if (repo / ".agents").exists():
        violations.append(f"{repo}: .agents directory exists on disk")

    tracked_agents = [
        p for p in git_ls_files(repo)
        if p == ".agents" or p.startswith(".agents/") or "/.agents/" in p or p.endswith("/.agents")
    ]
    if tracked_agents:
        violations.append(f"{repo}: tracked .agents entries in git index: {tracked_agents}")

    unstaged = git_diff_name_only(repo, cached=False)
    if unstaged:
        violations.append(f"{repo}: non-empty git diff --name-only: {unstaged}")

    staged = git_diff_name_only(repo, cached=True)
    if staged:
        violations.append(f"{repo}: non-empty git diff --cached --name-only: {staged}")

    allowed_untracked_set = set(allowed_untracked)
    untracked = git_untracked_files(repo)
    unexpected_untracked = [p for p in untracked if p not in allowed_untracked_set]
    if unexpected_untracked:
        violations.append(f"{repo}: unexpected untracked files: {unexpected_untracked}")

    ignored_untracked = git_ignored_untracked_files(repo)
    unexpected_ignored = [p for p in ignored_untracked if p not in allowed_untracked_set]
    if unexpected_ignored:
        violations.append(f"{repo}: unexpected ignored untracked files: {unexpected_ignored}")

    allowed_dirs_set = {d.strip("/").replace("\\", "/") for d in allowed_untracked_dirs}
    empty_dirs: List[str] = []
    for dirpath, dirnames, filenames in os.walk(repo, followlinks=False):
        cur = Path(dirpath)
        if cur == repo:
            dirnames[:] = [d for d in dirnames if d != ".git"]
            continue
        if not dirnames and not filenames:
            rel = cur.relative_to(repo).as_posix()
            if rel not in allowed_dirs_set:
                empty_dirs.append(rel)
    if empty_dirs:
        violations.append(f"{repo}: unexpected empty untracked directories: {sorted(empty_dirs)}")

    allowed_porcelain_set = set(allowed_porcelain)
    porcelain = git_status_porcelain(repo)
    unexpected_porcelain = [line for line in porcelain if line not in allowed_porcelain_set]
    if unexpected_porcelain:
        violations.append(f"{repo}: unexpected git status --porcelain entries: {unexpected_porcelain}")

    return violations


def git_config_get(repo: Path, key: str) -> str:
    res = run_git(repo, ["config", "--get", key])
    if res.returncode != 0:
        return ""
    return res.stdout.strip()


def git_remote_url(repo: Path, remote: str = "origin") -> str:
    res = run_git(repo, ["remote", "get-url", remote])
    if res.returncode != 0:
        return ""
    return res.stdout.strip()


def run_gh_repo_view(slug: str = "oyesanyf/AgentOctopus") -> Dict[str, Any]:
    res = run_subprocess_safe(
        ["gh", "repo", "view", slug, "--json", "description,url,defaultBranchRef"],
        timeout=20.0,
    )
    if res.returncode != 0:
        raise AssertionError(f"gh repo view {slug} failed (exit {res.returncode}): {res.stderr}")
    return json.loads(res.stdout)


def is_forbidden_oshoosiclaw_path(path: str) -> bool:
    """Return True if path is an OshoosiClaw-only doc, asset, or demo artifact (excluding tests/*.rs)."""
    norm = path.replace("\\", "/")
    if norm.startswith("./"):
        norm = norm[2:]
    if norm in FORBIDDEN_OSHOOSICLAW_FILES:
        return True
    lower = norm.lower()
    if "oshoosiclaw" in lower and (
        lower.startswith("docs/") or lower.startswith("assets/") or lower.startswith("demo/")
    ):
        return True
    return False


def check_repo_hygiene_paths(tracked_paths: Iterable[str]) -> List[str]:
    """Return list of forbidden tracked paths violating R3 / PROJECT.md #13."""
    violations: List[str] = []
    for raw in tracked_paths:
        norm = raw.replace("\\", "/")
        if norm.startswith("./"):
            norm = norm[2:]
        if norm in FORBIDDEN_TRACKED_EXACT:
            violations.append(norm)
            continue
        if any(norm.startswith(pfx) for pfx in FORBIDDEN_TRACKED_PREFIXES):
            violations.append(norm)
            continue
        if is_forbidden_oshoosiclaw_path(norm):
            violations.append(norm)
            continue
        if FORBIDDEN_REPORT_RE.search(norm):
            violations.append(norm)
            continue
        if FORBIDDEN_BINARY_ARCHIVE_RE.search(norm):
            violations.append(norm)
            continue
    return violations


# ---------------------------------------------------------------------------
# JSON, Markdown, Link, Anchor & Stdlib AST Validators
# ---------------------------------------------------------------------------

def extract_last_json_dict(*streams: str) -> Optional[Dict[str, Any]]:
    """Scan text streams from `{` offsets with JSONDecoder.raw_decode, returning the last valid JSON dict."""
    decoder = json.JSONDecoder()
    last_obj: Optional[Dict[str, Any]] = None
    for text in streams:
        if not text:
            continue
        idx = 0
        while True:
            start = text.find("{", idx)
            if start == -1:
                break
            try:
                obj, end = decoder.raw_decode(text, start)
            except json.JSONDecodeError:
                idx = start + 1
                continue
            if isinstance(obj, dict):
                last_obj = obj
            idx = max(start + 1, end)
    return last_obj


_FENCE_OPEN_RE = re.compile(r"^[ ]{0,3}(`{3,}|~{3,})(.*)$")
_INLINE_CODE_RE = re.compile(r"(`+)(?:(?!\1)[^\n])*?\1")
_MD_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+(?:\"[^\"]*\"|'[^']*'))?\)")
_MD_REF_DEF_RE = re.compile(
    r"^[ ]{0,3}\[([^\]]+)\]:[ \t]*<?([^\s>]+)>?(?:[ \t]+(?:\"[^\"]*\"|'[^']*'|\([^)]*\)))?[ \t]*$",
    re.MULTILINE,
)
_HTML_HREF_RE = re.compile(r"""href=["']([^"']+)["']""", re.IGNORECASE)
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$", re.MULTILINE)


def split_markdown_fences(text: str) -> Tuple[str, List[Tuple[str, str]]]:
    """Split Markdown into (non_fenced_text, [(info_string, block_body), ...]) using CommonMark fences."""
    non_fenced_lines: List[str] = []
    fences: List[Tuple[str, str]] = []
    in_fence = False
    fence_char = ""
    fence_len = 0
    fence_info = ""
    fence_body: List[str] = []

    for line in text.splitlines(keepends=True):
        stripped_nl = line.rstrip("\r\n")
        if not in_fence:
            m = _FENCE_OPEN_RE.match(stripped_nl)
            if m:
                marker = m.group(1)
                info = m.group(2).strip()
                if marker[0] == "`" and "`" in info:
                    non_fenced_lines.append(line)
                    continue
                in_fence = True
                fence_char = marker[0]
                fence_len = len(marker)
                fence_info = info
                fence_body = []
                continue
            non_fenced_lines.append(line)
        else:
            close_m = re.match(
                rf"^[ ]{{0,3}}{re.escape(fence_char)}{{{fence_len},}}[ \t]*$",
                stripped_nl,
            )
            if close_m:
                fences.append((fence_info, "".join(fence_body)))
                in_fence = False
                fence_char = ""
                fence_len = 0
                fence_info = ""
                fence_body = []
            else:
                fence_body.append(line)

    if in_fence:
        fences.append((fence_info, "".join(fence_body)))

    return "".join(non_fenced_lines), fences


def strip_markdown_code(text: str) -> str:
    no_fenced, _ = split_markdown_fences(text)
    return "\n".join(_INLINE_CODE_RE.sub("", line) for line in no_fenced.splitlines())


def _extract_raw_markdown_targets(text: str) -> List[str]:
    cleaned = strip_markdown_code(text)
    return (
        _MD_LINK_RE.findall(cleaned)
        + [target for _, target in _MD_REF_DEF_RE.findall(cleaned)]
        + _HTML_HREF_RE.findall(cleaned)
    )


def extract_markdown_links(text: str) -> List[str]:
    """Extract relative file/href targets from Markdown (excluding external URLs, mailto, and #anchors)."""
    targets: List[str] = []
    for raw in _extract_raw_markdown_targets(text):
        t = raw.strip().strip("<>")
        if not t or t.startswith("#"):
            continue
        if re.match(r"^(https?|mailto|tel|data):", t, re.IGNORECASE):
            continue
        targets.append(t)
    return targets


def extract_markdown_anchors(text: str) -> List[str]:
    anchors: List[str] = []
    for raw in _extract_raw_markdown_targets(text):
        t = raw.strip().strip("<>")
        if t.startswith("#") and len(t) > 1:
            anchors.append(t[1:])
    return anchors


def github_heading_slug(heading_text: str) -> str:
    # Strip optional leading ATX heading markers and trailing closing hashes
    cleaned = re.sub(r"^\s{0,3}#{1,6}\s+", "", heading_text)
    cleaned = re.sub(r"\s+#+\s*$", "", cleaned)
    # Strip markdown formatting/links inside heading while preserving literal underscores inside words
    cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", cleaned)
    cleaned = re.sub(r"[`*~]", "", cleaned)
    cleaned = re.sub(r"(?<!\w)_+|_+(?!\w)", "", cleaned).strip().lower()
    # Keep alphanumeric, underscores, spaces, hyphens; replace spaces with '-'
    slug = re.sub(r"[^\w\s-]", "", cleaned, flags=re.UNICODE)
    slug = re.sub(r"\s", "-", slug)
    return slug


def validate_readme_d3qn_advisory(readme_text: str) -> List[str]:
    """Validate that README.md does not headline D3QN/RL in the first 60 lines or Mermaid diagrams and frames it as optional/advisory."""
    violations: List[str] = []
    lines = readme_text.splitlines()
    hero = "\n".join(lines[:60]).lower()
    if "d3qn" in hero:
        violations.append("D3QN should not appear in README first 60 lines")
    if "double q-learning" in hero:
        violations.append("Q-learning should not headline README first 60 lines")

    _, fences = split_markdown_fences(readme_text)
    banned_mermaid_tokens = ("d3qn", "rlengine", "q-learning", "rl_defense")
    for info, body in fences:
        lang = info.split()[0].lower() if info.split() else ""
        if lang == "mermaid":
            body_lower = body.lower()
            for tok in banned_mermaid_tokens:
                if tok in body_lower:
                    violations.append(
                        f"Mermaid architecture diagram in README.md must not contain `{tok}`"
                    )

    full_lower = readme_text.lower()
    if "d3qn" in full_lower or "rl" in full_lower:
        if "advisory" not in full_lower and "optional" not in full_lower:
            violations.append(
                "D3QN/RL mention in README must explicitly frame it as optional/advisory"
            )
    return violations


def validate_docs_mermaid_no_d3qn(docs_root: Path) -> List[str]:
    """Validate that zero Mermaid diagrams across docs/**/*.md contain D3QN/RL gating tokens."""
    violations: List[str] = []
    if not docs_root.is_dir():
        return violations
    banned_mermaid_tokens = ("d3qn", "rlengine", "q-learning", "rl_defense")
    for md_path in sorted(docs_root.rglob("*.md")):
        text = md_path.read_text(encoding="utf-8", errors="replace")
        _, fences = split_markdown_fences(text)
        for info, body in fences:
            lang = info.split()[0].lower() if info.split() else ""
            if lang == "mermaid":
                body_lower = body.lower()
                for tok in banned_mermaid_tokens:
                    if tok in body_lower:
                        violations.append(
                            f"Mermaid diagram in {md_path.name} must not contain `{tok}`"
                        )
    return violations


def extract_heading_slugs(text: str) -> set[str]:
    no_fenced, _ = split_markdown_fences(text)
    seen: Dict[str, int] = {}
    slugs: set[str] = set()
    for m in _HEADING_RE.finditer(no_fenced):
        base = github_heading_slug(m.group(1))
        if not base:
            continue
        idx = seen.get(base, 0)
        seen[base] = idx + 1
        slug = base if idx == 0 else f"{base}-{idx}"
        slugs.add(slug)
    return slugs


def validate_stdlib_python_file(path: Path, allowed_local_modules: Iterable[str] = ()) -> List[str]:
    """Parse Python file via AST and return any non-stdlib top-level imports."""
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
