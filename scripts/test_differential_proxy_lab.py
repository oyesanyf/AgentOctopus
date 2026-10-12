#!/usr/bin/env python3
"""
Isolated Laboratory Benchmark for Differential Protocol Analysis Engine.
Simulates and evaluates 50 real-world legitimate requests and 50 novel adversarial/desync vectors
modeled after PortSwigger Research (The HTTP Terminator Arsenal).
Asserts 0.0% False Positive Rate on legitimate traffic and 100.0% True Positive Rate on novel attacks.
"""

import sys
import json
import urllib.request
import urllib.error

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ENDPOINT = "http://127.0.0.1:5005/api/protocol-analyzer/analyze"

def analyze_raw(raw_http: str):
    payload = json.dumps({"raw_http": raw_http}).encode("utf-8")
    req = urllib.request.Request(
        ENDPOINT,
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))

def build_legitimate_test_cases():
    cases = []
    # 1-10: Standard REST API calls with query strings
    for i in range(1, 11):
        cases.append((
            f"Legit-GET-API-{i}",
            f"GET /api/status?subsystem=Arm-{i}&format=json&page={i} HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nAccept: application/json\r\n\r\n"
        ))
    # 11-20: POST requests with JSON payloads and accurate Content-Length
    for i in range(1, 11):
        body = f'{{"device_id": {i}, "status": "active", "timestamp": 170000000{i}}}'
        cl = len(body)
        cases.append((
            f"Legit-POST-JSON-{i}",
            f"POST /api/telemetry HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nContent-Type: application/json\r\nContent-Length: {cl}\r\n\r\n{body}"
        ))
    # 21-30: Static asset requests with standard User-Agent, Accept-Encoding, Cache-Control
    assets = ["logo.svg", "dashboard.js", "style.css", "favicon.ico", "bundle.min.js", "theme.dark.css", "fonts/inter.woff2", "vendor.js", "robots.txt", "manifest.json"]
    for i, asset in enumerate(assets):
        cases.append((
            f"Legit-Static-{asset}",
            f"GET /static/{asset} HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept-Encoding: gzip, deflate\r\nCache-Control: max-age=3600\r\n\r\n"
        ))
    # 31-40: Legal HTTP Range header requests (RFC 7233)
    for i in range(1, 11):
        start = (i - 1) * 1024
        end = i * 1024 - 1
        cases.append((
            f"Legit-Range-Request-{i}",
            f"GET /static/large-dataset.dat HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nRange: bytes={start}-{end}\r\nAccept: */*\r\n\r\n"
        ))
    # 41-50: Standard submenus across Agent Octopus tabs
    submenus = [
        "/api/breakout/status", "/api/cedar/policies", "/api/containment-rings", "/api/audit/logs",
        "/api/sentinel/status", "/api/rl-defense/status", "/api/tarpit/metrics", "/api/atlas/threats",
        "/api/fuzz/stats", "/api/egress-domains"
    ]
    for sub in submenus:
        cases.append((
            f"Legit-Submenu-{sub}",
            f"GET {sub} HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nAuthorization: Bearer token-octopus-dev\r\n\r\n"
        ))
    return cases

def build_adversarial_test_cases():
    cases = []
    # 1-10: Shared-Parser Confusion (multipart/byteranges in request)
    for i in range(1, 11):
        cases.append((
            f"Adv-MultipartByteranges-{i}",
            f"POST /api/order HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nContent-Type: multipart/byteranges; boundary=DIVIDER_{i}\r\nContent-Length: {50 + i}\r\n\r\n--DIVIDER_{i}\r\n"
        ))
    # 11-20: Transfer-Encoding: gzip (CL.0 desync trigger)
    for i in range(1, 11):
        cases.append((
            f"Adv-TransferEncodingGzip-{i}",
            f"POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nTransfer-Encoding: gzip\r\nContent-Length: {20 + i}\r\n\r\n"
        ))
    # 21-25: Shared-Parser Confusion via Content-Range in request
    for i in range(1, 6):
        cases.append((
            f"Adv-ContentRangeInRequest-{i}",
            f"POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nContent-Range: bytes 0-{i * 10}/1000\r\nContent-Length: {i * 10}\r\n\r\n"
        ))
    # 26-30: Early-Data smuggling triggers (0-RTT desync)
    for i in range(1, 6):
        cases.append((
            f"Adv-EarlyDataTrigger-{i}",
            f"GET /api/account HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nEarly-Data: {i}\r\n\r\n"
        ))
    # 31-35: Conflicting CL.TE / TE.CL framing
    for i in range(1, 6):
        cases.append((
            f"Adv-ConflictingCLTE-{i}",
            f"POST /api/data HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nContent-Length: {10 * i}\r\nTransfer-Encoding: chunked\r\n\r\n"
        ))
    # 36-40: Dual matching Content-Length (Citrix NetScaler CVE-2023-3519)
    for i in range(1, 6):
        cases.append((
            f"Adv-DualMatchingCL-{i}",
            f"POST /api/citrix/sso HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nContent-Length: {15 + i}\r\nContent-Length: {15 + i}\r\n\r\n"
        ))
    # 41-45: Max-Forwards 0 (CVE-2026-63078) & Asterisk early-response gadgets
    cases.append(("Adv-MaxForwards-1", "POST /api/test HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nMax-Forwards: 0\r\nContent-Length: 5\r\n\r\nhello"))
    cases.append(("Adv-MaxForwards-2", "DELETE /api/test HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nMax-Forwards: 0\r\n\r\n"))
    cases.append(("Adv-AsteriskUri-1", "OPTIONS *?debug=true HTTP/1.1\r\nHost: 127.0.0.1:5005\r\n\r\n"))
    cases.append(("Adv-AsteriskUri-2", "OPTIONS *?smuggle=payload HTTP/1.1\r\nHost: 127.0.0.1:5005\r\n\r\n"))
    cases.append(("Adv-ConflictingCLTE-6", "POST /api/test HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"))
    # 46-50: Line termination & NUL smuggling anomalies
    cases.append(("Adv-BareLF-1", "GET /api/test HTTP/1.1\nHost: 127.0.0.1:5005\n\n"))
    cases.append(("Adv-BareLF-2", "POST /api/test HTTP/1.1\nHost: 127.0.0.1:5005\nContent-Length: 5\n\nhello"))
    cases.append(("Adv-NulHeader-1", "GET /api/test HTTP/1.1\r\nHost: 127.0.0.1\x00.evil.com\r\n\r\n"))
    cases.append(("Adv-SharedConfusion-Location", "GET /api/test HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nLocation: https://evil.com/leak\r\n\r\n"))
    cases.append(("Adv-SharedConfusion-SetCookie", "GET /api/test HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nSet-Cookie: session=smuggled; Path=/\r\n\r\n"))
    return cases

def build_moderate_divergence_test_cases():
    cases = []
    paths = [
        "/api/../admin;role=root",
        "/api//system/../audit;action=clear",
        "/api/v1/../../etc/passwd;bypass=1",
        "/api/status/../sensitive;keys=all",
        "/api/..%2fadmin;bypass",
        "/api/v2/../config;override=true",
        "/api/status/../health;deep=1",
        "/api/metrics/../governor;debug=1",
        "/api/telemetry/../sentinel;bypass=1",
        "/api/rings/../isolate;arm=0"
    ]
    for i, p in enumerate(paths):
        cases.append((
            f"Moderate-PathDivergence-{i+1}",
            f"GET {p} HTTP/1.1\r\nHost: 127.0.0.1:5005\r\n\r\n"
        ))
    return cases

def run_benchmark():
    print("=" * 70)
    print("🧪 Differential Protocol Analysis Engine - Isolated Laboratory Benchmark")
    print("=" * 70)

    legit_cases = build_legitimate_test_cases()
    moderate_cases = build_moderate_divergence_test_cases()
    adv_cases = build_adversarial_test_cases()

    print(f"[*] Generated {len(legit_cases)} legitimate requests across REST, POST JSON, Range, and Submenus.")
    print(f"[*] Generated {len(moderate_cases)} moderate path-divergence requests for Observe tier calibration.")
    print(f"[*] Generated {len(adv_cases)} high-confidence novel desync vectors for Ring 1 quarantine calibration.")

    # 1. Test Legitimate Requests (Allow Tier: S < 0.30)
    fp_count = 0
    print("\n--- PHASE 1: Legitimate Traffic Verification (False Positive Calibration) ---")
    for name, stream in legit_cases:
        try:
            report = analyze_raw(stream)
            score = report["divergence_vector"]["novelty_score"]
            action = report["action"]
            if score >= 0.30 or action != "Allow":
                print(f"  ❌ FALSE POSITIVE on {name}: score={score:.2f}, action={action}")
                fp_count += 1
        except Exception as e:
            print(f"  ❌ Error evaluating {name}: {e}")
            fp_count += 1

    fp_rate = (fp_count / len(legit_cases)) * 100.0
    print(f"[+] Legitimate Phase Result: {len(legit_cases) - fp_count}/{len(legit_cases)} passed.")
    print(f"[+] False Positive Rate: {fp_rate:.2f}% (Target: 0.0%)")

    # 2. Test Moderate Divergence (Observe Tier: 0.30 <= S < 0.65)
    obs_count = 0
    print("\n--- PHASE 2: Moderate Divergence Calibration (Observe Tier) ---")
    for name, stream in moderate_cases:
        try:
            report = analyze_raw(stream)
            score = report["divergence_vector"]["novelty_score"]
            action = report["action"]
            if 0.30 <= score < 0.65 and action == "Observe":
                obs_count += 1
            else:
                print(f"  ❌ MISCALIBRATED OBSERVE on {name}: score={score:.2f}, action={action}")
        except Exception as e:
            print(f"  ❌ Error evaluating {name}: {e}")

    obs_rate = (obs_count / len(moderate_cases)) * 100.0
    print(f"[+] Moderate Divergence Result: {obs_count}/{len(moderate_cases)} accurately classified in Observe tier ({obs_rate:.2f}%).")

    # 3. Test High-Confidence Novel Attacks (Quarantine Tier: S >= 0.65)
    tp_count = 0
    quarantine_verified = 0
    print("\n--- PHASE 3: Novel Attack & Desync Detection (Ring 1 Quarantine Tier) ---")
    for name, stream in adv_cases:
        try:
            report = analyze_raw(stream)
            score = report["divergence_vector"]["novelty_score"]
            action = report["action"]
            quarantined_arm = report.get("quarantined_in_arm")
            containment_hmac = report.get("containment_proof_hmac")

            if score >= 0.65 and action == "QuarantineAndSever" and quarantined_arm == 106:
                tp_count += 1
                if containment_hmac and len(containment_hmac) == 64:
                    quarantine_verified += 1
            else:
                print(f"  ❌ MISSED DETECTION on {name}: score={score:.2f}, action={action}, arm={quarantined_arm}")
        except Exception as e:
            print(f"  ❌ Error evaluating {name}: {e}")

    tp_rate = (tp_count / len(adv_cases)) * 100.0
    print(f"[+] Adversarial Phase Result: {tp_count}/{len(adv_cases)} detected.")
    print(f"[+] True Positive (Detection) Rate: {tp_rate:.2f}% (Target: 100.0%)")
    print(f"[+] Authoritative Arm 106 Ring 1 Containment Proofs: {quarantine_verified}/{len(adv_cases)}")

    print("\n" + "=" * 70)
    if fp_count == 0 and obs_count == len(moderate_cases) and tp_count == len(adv_cases):
        print("🎯 BENCHMARK PASSED: 0.0% False Positives | 100.0% Detection | Level 1 Ring 106 Confirmed")
        print("=" * 70)
        return 0
    else:
        print("❌ BENCHMARK FAILED CALIBRATION CRITERIA")
        print("=" * 70)
        return 1

if __name__ == "__main__":
    sys.exit(run_benchmark())
