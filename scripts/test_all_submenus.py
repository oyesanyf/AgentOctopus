#!/usr/bin/env python3
"""
Agent Octopus - Exhaustive Web Dashboard Submenu & Endpoint Verification Suite
Systematically tests all 10 tabs, interactive submenus, presets, controls, and API endpoints
on http://127.0.0.1:5005.
"""

import sys
import json
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:5005"

class TestSuiteResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.details = []

    def record_pass(self, tab, item, details=""):
        self.passed += 1
        msg = f"[PASS] [{tab}] {item}" + (f" -> {details}" if details else "")
        print(msg)
        self.details.append({"status": "PASS", "tab": tab, "item": item, "details": details})

    def record_fail(self, tab, item, error=""):
        self.failed += 1
        msg = f"[FAIL] [{tab}] {item} -> ERROR: {error}"
        print(msg)
        self.details.append({"status": "FAIL", "tab": tab, "item": item, "error": error})

def http_get(path, headers=None):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.getcode()
            body = resp.read().decode('utf-8', errors='replace')
            content_type = resp.headers.get('Content-Type', '')
            return status, body, content_type
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        return e.code, body, e.headers.get('Content-Type', '')
    except Exception as e:
        return 0, str(e), ''

def http_post(path, data=None, headers=None):
    url = f"{BASE_URL}{path}"
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    encoded = json.dumps(data).encode('utf-8') if data is not None else b"{}"
    req = urllib.request.Request(url, data=encoded, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.getcode()
            body = resp.read().decode('utf-8', errors='replace')
            return status, body, resp.headers.get('Content-Type', '')
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        return e.code, body, e.headers.get('Content-Type', '')
    except Exception as e:
        return 0, str(e), ''

def run_all_tests():
    print("=" * 80)
    print("AGENT OCTOPUS: EXHAUSTIVE SUBMENU & ENDPOINT VERIFICATION SUITE")
    print(f"Target: {BASE_URL}")
    print("=" * 80)

    results = TestSuiteResults()

    # Verify server reachable
    status, body, _ = http_get("/api/status")
    if status != 200:
        print(f"[FATAL] Server not reachable on {BASE_URL}/api/status (Status: {status}). Ensure start.exe is running.")
        sys.exit(1)
    print(f"[INIT] Server online and responsive. Initializing comprehensive verification...\n")

    # =========================================================================
    # TAB 1: Test Runner & Progression (#test-runner)
    # =========================================================================
    tab = "Tab 1: Test Runner & Progression"
    print(f"\n--- Checking {tab} ---")

    # 1.1 Core Swarm Telemetry
    status, body, _ = http_get("/api/status")
    if status == 200 and "status" in body:
        results.record_pass(tab, "GET /api/status (Core Swarm Telemetry)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/status", f"Status {status}: {body[:100]}")

    # 1.2 Live Test Status
    status, body, _ = http_get("/api/live-tests")
    if status == 200:
        results.record_pass(tab, "GET /api/live-tests (Live Test Status)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/live-tests", f"Status {status}")

    # 1.3 Download run log
    status, body, _ = http_get("/api/download-run-log")
    if status == 200:
        results.record_pass(tab, "GET /api/download-run-log (Execution Trace)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/download-run-log", f"Status {status}")

    # 1.4 Download test JSON
    status, body, _ = http_get("/api/download-test-json")
    if status == 200:
        results.record_pass(tab, "GET /api/download-test-json (Structured Test Results)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/download-test-json", f"Status {status}")

    # =========================================================================
    # TAB 2: Unified Runtime Activity (#runtime-feed)
    # =========================================================================
    tab = "Tab 2: Unified Runtime Activity"
    print(f"\n--- Checking {tab} ---")

    # 2.1 Unfiltered event stream
    status, body, _ = http_get("/api/runtime-activity/stream")
    if status == 200:
        results.record_pass(tab, "GET /api/runtime-activity/stream (All Subsystems)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/runtime-activity/stream", f"Status {status}")

    # 2.2 Subsystem filter pills
    subsystems = ["Cedar-Policy", "RL-ActiveDefense", "OpenTelemetry", "Swarm-Runner"]
    for sub in subsystems:
        status, body, _ = http_get(f"/api/runtime-activity/stream?subsystem={sub}")
        if status == 200:
            results.record_pass(tab, f"GET /api/runtime-activity/stream?subsystem={sub}", "200 OK")
        else:
            results.record_fail(tab, f"GET /api/runtime-activity/stream?subsystem={sub}", f"Status {status}")

    # =========================================================================
    # TAB 3: Cedar Policy Sandbox (#cedar-sandbox)
    # =========================================================================
    tab = "Tab 3: Cedar Policy Sandbox"
    print(f"\n--- Checking {tab} ---")

    # 3.1 Preset 1: Valid Ledger Write
    valid_write = {
        "principal": "ledger_arm",
        "action": "write",
        "resource": "Ledger",
        "context": {"amount_cents": 50000, "approved": True},
        "attach_supervisor_approval": True
    }
    status, body, _ = http_post("/api/evaluate-cedar", valid_write)
    if status == 200 and "is_allowed" in body:
        results.record_pass(tab, "POST /api/evaluate-cedar (Preset 1: Valid Write)", f"Allowed: {json.loads(body).get('is_allowed')}")
    else:
        results.record_fail(tab, "POST /api/evaluate-cedar (Preset 1: Valid Write)", f"Status {status}: {body[:100]}")

    # 3.2 Preset 2: Valid Egress
    valid_egress = {
        "principal": "network_arm",
        "action": "egress",
        "resource": "NetworkTarget",
        "context": {"domain": "api.vendor.com"},
        "attach_supervisor_approval": False
    }
    status, body, _ = http_post("/api/evaluate-cedar", valid_egress)
    if status == 200 and "is_allowed" in body:
        results.record_pass(tab, "POST /api/evaluate-cedar (Preset 2: Valid Egress)", "200 OK")
    else:
        results.record_fail(tab, "POST /api/evaluate-cedar (Preset 2: Valid Egress)", f"Status {status}")

    # 3.3 Preset 3: SSRF / Pivot Probe (Should be blocked)
    ssrf_probe = {
        "principal": "network_arm",
        "action": "egress",
        "resource": "NetworkTarget",
        "context": {"domain": "169.254.169.254"},
        "attach_supervisor_approval": False
    }
    status, body, _ = http_post("/api/evaluate-cedar", ssrf_probe)
    if status == 200:
        data = json.loads(body)
        if not data.get("is_allowed"):
            results.record_pass(tab, "POST /api/evaluate-cedar (Preset 3: SSRF Blocked)", f"Blocked as expected: verdict={data.get('breakout_verdict')}")
        else:
            results.record_fail(tab, "POST /api/evaluate-cedar (Preset 3: SSRF Probe)", "Unexpectedly ALLOWED!")
    else:
        results.record_fail(tab, "POST /api/evaluate-cedar (Preset 3: SSRF Probe)", f"Status {status}")

    # 3.4 Preset 4: Schema Tampered Context (Context injection blocked)
    tampered_ctx = {
        "principal": "ledger_arm",
        "action": "write",
        "resource": "Ledger",
        "context": {"amount_cents": 50000, "amount_cents_2": 99999999, "approved": True},
        "attach_supervisor_approval": False
    }
    status, body, _ = http_post("/api/evaluate-cedar", tampered_ctx)
    if status == 200:
        data = json.loads(body)
        if not data.get("is_allowed"):
            results.record_pass(tab, "POST /api/evaluate-cedar (Preset 4: Tampering Blocked)", f"Vetoed: {data.get('breakout_verdict')}")
        else:
            results.record_fail(tab, "POST /api/evaluate-cedar (Preset 4: Tampered Context)", "Tampered payload was allowed!")
    else:
        results.record_fail(tab, "POST /api/evaluate-cedar (Preset 4: Tampered Context)", f"Status {status}")

    # 3.5 Egress Domains Management
    status, body, _ = http_get("/api/egress-domains")
    if status == 200:
        results.record_pass(tab, "GET /api/egress-domains (Allowlist Configuration)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/egress-domains", f"Status {status}")

    # 3.6 Dogwood Temporal Policy Presets
    status, body, _ = http_get("/api/dogwood/presets")
    if status == 200 and "write_after_read" in body:
        results.record_pass(tab, "GET /api/dogwood/presets (MFOTL Policy Catalog)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/dogwood/presets", f"Status {status}")

    # 3.7 Dogwood Event Trace
    status, body, _ = http_get("/api/dogwood/trace")
    if status == 200 and "events" in body:
        results.record_pass(tab, "GET /api/dogwood/trace (Historical Event Ledger)", f"Events: {json.loads(body).get('total_events')}")
    else:
        results.record_fail(tab, "GET /api/dogwood/trace", f"Status {status}")

    # 3.8 Dogwood Temporal Evaluation (Write-after-Read)
    dw_eval = {
        "policy": 'permit(principal, action == Octopus::Action::"LedgerWrite", resource) when temporal { formerly within 1h Octopus::Action::"LedgerRead"::response{ input.user: context.input.user, input.document: context.input.document } };',
        "principal": "agent_worker_1",
        "resource": "contracts/2026-q3.pdf",
        "context": {
            "input.user": "agent_worker_1",
            "input.document": "contracts/2026-q3.pdf"
        }
    }
    status, body, _ = http_post("/api/dogwood/evaluate", dw_eval)
    if status == 200 and "PERMIT" in body:
        results.record_pass(tab, "POST /api/dogwood/evaluate (Write-after-Read MFOTL)", "Verdict: PERMIT")
    else:
        results.record_fail(tab, "POST /api/dogwood/evaluate", f"Status {status}: {body[:100]}")

    # 3.9 Dogwood Trace Event Simulation
    dw_sim = {
        "action": 'Octopus::Action::"LedgerRead"',
        "kind": "response",
        "principal": "agent_worker_1",
        "resource": "contracts/2026-q3.pdf",
        "fields": {
            "input.user": "agent_worker_1",
            "input.document": "contracts/2026-q3.pdf"
        },
        "offset_secs_ago": 30
    }
    status, body, _ = http_post("/api/dogwood/simulate-trace", dw_sim)
    if status == 200 and "RECORDED" in body:
        results.record_pass(tab, "POST /api/dogwood/simulate-trace (Synthetic Event Ingestion)", "200 OK")
    else:
        results.record_fail(tab, "POST /api/dogwood/simulate-trace", f"Status {status}")

    # =========================================================================
    # TAB 4: Cryptographic Audit Log (#audit-viewer)
    # =========================================================================
    tab = "Tab 4: Cryptographic Audit Log"
    print(f"\n--- Checking {tab} ---")

    # 4.1 Audit records list
    status, body, _ = http_get("/api/audit-log")
    if status == 200:
        records = json.loads(body)
        results.record_pass(tab, "GET /api/audit-log (Merkle Audit Trail)", f"Records count: {len(records) if isinstance(records, list) else 'OK'}")
    else:
        results.record_fail(tab, "GET /api/audit-log", f"Status {status}")

    # 4.2 Download full audit log
    status, body, _ = http_get("/api/download-audit-log")
    if status == 200:
        results.record_pass(tab, "GET /api/download-audit-log (Raw Forensic File)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/download-audit-log", f"Status {status}")

    # =========================================================================
    # TAB 5: Swarm & Invariants (#swarm-status)
    # =========================================================================
    tab = "Tab 5: Swarm & Invariants"
    print(f"\n--- Checking {tab} ---")

    # 5.1 Swarm rings telemetry (Level 1 rings for 50 arms + security arms)
    status, body, _ = http_get("/api/containment-rings")
    if status == 200:
        data = json.loads(body)
        total_rings = len(data.get("rings", [])) if isinstance(data, dict) else len(data) if isinstance(data, list) else 0
        results.record_pass(tab, "GET /api/containment-rings (All Arm Containment Rings)", f"Total rings: {total_rings}")
    else:
        results.record_fail(tab, "GET /api/containment-rings", f"Status {status}")

    # =========================================================================
    # TAB 6: 4-Ring Concentric Defense (#containment-rings)
    # =========================================================================
    tab = "Tab 6: 4-Ring Concentric Defense"
    print(f"\n--- Checking {tab} ---")

    # 6.1 Sever Arm 17 (Autotomy)
    sever_req = {"arm_id": 17, "reason": "Red team autotomy simulation"}
    status, body, _ = http_post("/api/containment-rings/sever", sever_req)
    if status == 200:
        results.record_pass(tab, "POST /api/containment-rings/sever (Arm 17 Autotomy Severance)", "200 OK")
    else:
        results.record_fail(tab, "POST /api/containment-rings/sever", f"Status {status}: {body[:100]}")

    # 6.2 Stale Epoch Replay Test (Arm 17 presented with old generation token)
    stale_test = {"arm_id": 17, "presented_epoch": 1}
    status, body, _ = http_post("/api/containment-rings/stale-replay", stale_test)
    if status == 200:
        data = json.loads(body)
        if not data.get("accepted"):
            results.record_pass(tab, "POST /api/containment-rings/stale-replay (Stale Token Blocked)", f"Defense triggered: {data.get('security_defense_triggered')}")
        else:
            results.record_fail(tab, "POST /api/containment-rings/stale-replay", "Stale epoch was accepted!")
    else:
        results.record_fail(tab, "POST /api/containment-rings/stale-replay", f"Status {status}")

    # 6.3 Regenerate Arm 17 (Advance generation)
    regen_req = {"arm_id": 17}
    status, body, _ = http_post("/api/containment-rings/regenerate", regen_req)
    if status == 200:
        data = json.loads(body)
        results.record_pass(tab, "POST /api/containment-rings/regenerate (Arm 17 Regenerated)", f"New generation: {data.get('new_generation')}")
    else:
        results.record_fail(tab, "POST /api/containment-rings/regenerate", f"Status {status}")

    # =========================================================================
    # TAB 7: Continuous Security & RL Active Defense (#rl-continuous)
    # =========================================================================
    tab = "Tab 7: Continuous Security & RL Active Defense"
    print(f"\n--- Checking {tab} ---")

    # 7.1 RL Defense Status
    status, body, _ = http_get("/api/rl-defense/status")
    if status == 200:
        results.record_pass(tab, "GET /api/rl-defense/status (D3QN Agent Posture)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/rl-defense/status", f"Status {status}")

    # 7.2 RL Defense Training Cycle
    status, body, _ = http_post("/api/rl-defense/train-cycle", {})
    if status == 200:
        results.record_pass(tab, "POST /api/rl-defense/train-cycle (Autonomous Retraining)", "200 OK")
    else:
        results.record_fail(tab, "POST /api/rl-defense/train-cycle", f"Status {status}")

    # 7.3 Resilience metrics (MTTD / MTTR)
    status, body, _ = http_get("/api/resilience/metrics")
    if status == 200:
        results.record_pass(tab, "GET /api/resilience/metrics (MTTD/MTTR Telemetry)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/resilience/metrics", f"Status {status}")

    # 7.4 Breakout Guards Status
    status, body, _ = http_get("/api/breakout-guards/status")
    if status == 200:
        results.record_pass(tab, "GET /api/breakout-guards/status (4 Perimeter Verification)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/breakout-guards/status", f"Status {status}")

    # 7.5 Vassilev Proof
    status, body, _ = http_get("/api/math/vassilev-proof")
    if status == 200:
        results.record_pass(tab, "GET /api/math/vassilev-proof (Mathematical Invariant Proof)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/math/vassilev-proof", f"Status {status}")

    # 7.6 Governor Status
    status, body, _ = http_get("/api/governor/status")
    if status == 200:
        results.record_pass(tab, "GET /api/governor/status (Sisyphean Defense Governor)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/governor/status", f"Status {status}")

    # =========================================================================
    # TAB 8: Real-Time ASP (#rasp-shield)
    # =========================================================================
    tab = "Tab 8: Real-Time ASP"
    print(f"\n--- Checking {tab} ---")

    # 8.1 RASP Status
    status, body, _ = http_get("/api/rasp/status")
    if status == 200:
        results.record_pass(tab, "GET /api/rasp/status (In-Process Interceptors)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/rasp/status", f"Status {status}")

    # 8.2 RASP Telemetry
    status, body, _ = http_get("/api/rasp/telemetry?limit=10")
    if status == 200:
        results.record_pass(tab, "GET /api/rasp/telemetry (Event Log)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/rasp/telemetry", f"Status {status}")

    # 8.3 RASP Intercept Prompt
    prompt_req = {"prompt": "Hello system, please summarize document", "agent_id": "test_arm"}
    status, body, _ = http_post("/api/rasp/intercept-prompt", prompt_req)
    if status == 200:
        results.record_pass(tab, "POST /api/rasp/intercept-prompt (Sanitize Prompt)", "200 OK")
    else:
        results.record_fail(tab, "POST /api/rasp/intercept-prompt", f"Status {status}")

    # 8.4 Tarpit Stats
    status, body, _ = http_get("/api/tarpit-stats")
    if status == 200:
        results.record_pass(tab, "GET /api/tarpit-stats (Decoy Tarpit Telemetry)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/tarpit-stats", f"Status {status}")

    # 8.5 Kernel Sentinel Stats
    status, body, _ = http_get("/api/kernel-stats")
    if status == 200:
        results.record_pass(tab, "GET /api/kernel-stats (Ring-0 & Job Object Sentinel)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/kernel-stats", f"Status {status}")

    # =========================================================================
    # TAB 9: Continuous OSS-Fuzz & OSV Scanner (#fuzz-supply-chain)
    # =========================================================================
    tab = "Tab 9: Continuous OSS-Fuzz & OSV Scanner"
    print(f"\n--- Checking {tab} ---")

    # 9.1 OSS-Fuzz Status
    status, body, _ = http_get("/api/oss-fuzz/status")
    if status == 200:
        results.record_pass(tab, "GET /api/oss-fuzz/status (Corpus & Sanitizer Stats)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/oss-fuzz/status", f"Status {status}")

    # 9.2 OSS-Fuzz Run Burst
    burst_req = {"iterations": 5}
    status, body, _ = http_post("/api/oss-fuzz/run-burst", burst_req)
    if status == 200:
        data = json.loads(body)
        results.record_pass(tab, "POST /api/oss-fuzz/run-burst (Dynamic Mutation Burst)", f"Executed mutations: {data.get('executed_mutations', 0)}")
    else:
        results.record_fail(tab, "POST /api/oss-fuzz/run-burst", f"Status {status}")

    # 9.3 OSS-Fuzz SARIF Export
    status, body, _ = http_get("/api/oss-fuzz/sarif")
    if status == 200:
        results.record_pass(tab, "GET /api/oss-fuzz/sarif (OASIS SARIF v2.1.0 Export)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/oss-fuzz/sarif", f"Status {status}")

    # 9.4 OSV Scanner Status
    status, body, _ = http_get("/api/osv-scanner/status")
    if status == 200:
        results.record_pass(tab, "GET /api/osv-scanner/status (Advisories & Dependencies)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/osv-scanner/status", f"Status {status}")

    # 9.5 OSV Scanner Scan Now
    status, body, _ = http_post("/api/osv-scanner/scan-now", {})
    if status == 200:
        data = json.loads(body)
        results.record_pass(tab, "POST /api/osv-scanner/scan-now (Dependency Audit)", f"Scanned: {data.get('total_dependencies_scanned', 0)} deps")
    else:
        results.record_fail(tab, "POST /api/osv-scanner/scan-now", f"Status {status}")

    # 9.6 OSV Scanner SARIF Export
    status, body, _ = http_get("/api/osv-scanner/sarif")
    if status == 200:
        results.record_pass(tab, "GET /api/osv-scanner/sarif (OASIS SARIF v2.1.0 Export)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/osv-scanner/sarif", f"Status {status}")

    # =========================================================================
    # TAB 10: Docs & Integration Guide (#user-guide)
    # =========================================================================
    tab = "Tab 10: Docs & Integration Guide"
    print(f"\n--- Checking {tab} ---")

    # 10.1 Main HTML dashboard index
    status, body, ctype = http_get("/")
    if status == 200 and "Agent Octopus" in body:
        results.record_pass(tab, "GET / (Dashboard Web Application)", f"200 OK ({len(body)} bytes)")
    else:
        results.record_fail(tab, "GET /", f"Status {status}")

    # 10.2 Logo asset
    status, body, _ = http_get("/logo.png")
    if status == 200:
        results.record_pass(tab, "GET /logo.png (Brand Asset)", "200 OK")
    else:
        results.record_fail(tab, "GET /logo.png", f"Status {status}")

    # 10.3 Architecture diagrams
    status, body, _ = http_get("/breakout_containment_architecture.png")
    if status == 200:
        results.record_pass(tab, "GET /breakout_containment_architecture.png (Architecture Diagram)", "200 OK")
    else:
        results.record_fail(tab, "GET /breakout_containment_architecture.png", f"Status {status}")

    status, body, _ = http_get("/compromised_arm_containment_flow.png")
    if status == 200:
        results.record_pass(tab, "GET /compromised_arm_containment_flow.png (Containment Flow Diagram)", "200 OK")
    else:
        results.record_fail(tab, "GET /compromised_arm_containment_flow.png", f"Status {status}")

    # 10.4 OpenTelemetry Sessions & Spans
    status, body, _ = http_get("/api/otel/sessions")
    if status == 200:
        results.record_pass(tab, "GET /api/otel/sessions (OpenTelemetry Telemetry)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/otel/sessions", f"Status {status}")

    status, body, _ = http_get("/api/otel/spans")
    if status == 200:
        results.record_pass(tab, "GET /api/otel/spans (Distributed Trace Spans)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/otel/spans", f"Status {status}")

    # 10.5 ATLAS Threat Intelligence Endpoints
    status, body, _ = http_get("/api/atlas/status")
    if status == 200:
        results.record_pass(tab, "GET /api/atlas/status (ATLAS STIX Status)", "200 OK")
    else:
        results.record_fail(tab, "GET /api/atlas/status", f"Status {status}")

    status, body, _ = http_post("/api/atlas/sync", {})
    if status == 200:
        results.record_pass(tab, "POST /api/atlas/sync (ATLAS Sync & Air-gap Verification)", "200 OK")
    else:
        results.record_fail(tab, "POST /api/atlas/sync", f"Status {status}")

    status, body, _ = http_post("/api/atlas/dynamic-tests", {})
    if status == 200:
        results.record_pass(tab, "POST /api/atlas/dynamic-tests (STIX Threat Synthesis)", "200 OK")
    else:
        results.record_fail(tab, "POST /api/atlas/dynamic-tests", f"Status {status}")

    # =========================================================================
    # SUMMARY REPORT
    # =========================================================================
    print("\n" + "=" * 80)
    print("SUBMENU VERIFICATION SUMMARY")
    print("=" * 80)
    print(f"Total Submenu Items / Endpoints Tested: {results.passed + results.failed}")
    print(f"Passed: {results.passed}")
    print(f"Failed: {results.failed}")
    print(f"Success Rate: {(results.passed / (results.passed + results.failed) * 100):.1f}%")
    print("=" * 80)

    if results.failed > 0:
        print(f"[!] {results.failed} tests failed.")
        sys.exit(1)
    else:
        print("[+] ALL SUBMENU ITEMS AND ENDPOINTS OPERATIONAL WITH ZERO FAILURES (100%)!")
        sys.exit(0)

if __name__ == "__main__":
    run_all_tests()
