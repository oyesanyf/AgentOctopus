#!/usr/bin/env python3
"""
Captures high-resolution live headless Chrome screenshots of Tab 17
(Google AgentMesh x Wasmtime v49.0.4 Zero-Socket Execution Substrate)
against the running AgentOctopus Web Server.
"""

import http.client
import json
import os
import subprocess
import sys
from pathlib import Path

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
]


def find_browser() -> str:
    for p in CHROME_CANDIDATES:
        if os.path.exists(p):
            return p
    raise FileNotFoundError("No Chrome or Edge executable found for headless capture.")


def read_port_and_token(repo_root: Path):
    port = 5005
    port_file = repo_root / "logs" / "active_port.txt"
    if port_file.exists():
        raw = port_file.read_text(encoding="utf-8").strip()
        if raw.isdigit():
            port = int(raw)

    tok_file = repo_root / "logs" / ".octopus_operator_token"
    token = tok_file.read_text(encoding="utf-8").strip() if tok_file.exists() else ""
    return port, token


def mint_bootstrap_nonce(port: int, operator_token: str) -> str:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
    conn.request(
        "POST",
        "/api/session/bootstrap-nonce",
        body=b"{}",
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Octopus-Token": operator_token,
        },
    )
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", errors="replace")
    conn.close()
    if resp.status != 200:
        raise RuntimeError(f"Failed to mint bootstrap nonce: HTTP {resp.status} {body}")
    return json.loads(body)["bootstrap_nonce"]


def reset_killswitch(port: int, operator_token: str) -> None:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
    conn.request(
        "POST",
        "/api/agentmesh/killswitch/reset",
        body=b"{}",
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Octopus-Token": operator_token,
        },
    )
    conn.getresponse().read()
    conn.close()


def capture_screen(browser: str, url: str, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    cmd = [
        browser,
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--window-size=1920,1240",
        "--virtual-time-budget=4500",
        f"--screenshot={out_path}",
        url,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=35)
    if not out_path.exists() or out_path.stat().st_size < 15000:
        raise RuntimeError(
            f"Screenshot failed or blank ({out_path}): rc={proc.returncode} stderr={proc.stderr}"
        )
    print(f"[+] Captured {out_path.name} ({out_path.stat().st_size:,} bytes)")


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    browser = find_browser()
    port, token = read_port_and_token(repo_root)
    if not token:
        raise RuntimeError("Missing logs/.octopus_operator_token; ensure server is running.")

    assets_dir = repo_root / "docs" / "assets"
    reset_killswitch(port, token)

    scenarios = [
        ("allowed", assets_dir / "agentmesh_wasm_allowed.png"),
        ("denied", assets_dir / "agentmesh_wasm_denied.png"),
        ("killswitch", assets_dir / "agentmesh_killswitch_autotomy.png"),
    ]

    for demo_mode, target_png in scenarios:
        reset_killswitch(port, token)
        nonce = mint_bootstrap_nonce(port, token)
        url = f"http://127.0.0.1:{port}/?bootstrap={nonce}&tab=agentmesh-runtime&demo={demo_mode}"
        capture_screen(browser, url, target_png)

    reset_killswitch(port, token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
