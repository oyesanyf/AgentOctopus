#!/usr/bin/env python3
import http.client
import json
import time
import sys
import urllib.parse

BASE_URL = "http://127.0.0.1:5005"

def test_endpoint(name, method, path, data=None, expected_status=200):
    parsed = urllib.parse.urlsplit(f"{BASE_URL}{path}")
    headers = {}
    body_bytes = None
    if data is not None:
        body_bytes = data.encode("utf-8") if isinstance(data, str) else data
        headers["Content-Type"] = "application/json"

    print(f"[*] Testing {name} ({method} {path})...", end=" ")
    try:
        conn = http.client.HTTPConnection(parsed.hostname or "127.0.0.1", parsed.port or 5005, timeout=5.0)
        target_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        conn.request(method, target_path, body=body_bytes, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        body = resp.read().decode("utf-8", errors="replace")
        conn.close()
        if status != expected_status:
            print(f"FAILED (expected status {expected_status}, got {status})")
            return False, body
        print(f"PASSED (HTTP {status})")
        return True, body
    except Exception as e:
        print(f"ERROR: {e}")
        return False, str(e)

def main():
    print("=== LIVE ENDPOINT ERROR BOUNDARY AUDIT ===")
    
    # 1. Status endpoint
    ok, body = test_endpoint("Online status", "GET", "/api/status", expected_status=200)
    assert ok, f"Status failed: {body}"
    status_json = json.loads(body)
    assert status_json.get("status") == "ONLINE", f"Unexpected status: {body}"
    print(f"    Active policies: {status_json.get('active_policies')}")

    # 2. Malformed JSON on evaluate-cedar -> 400 with structured JSON
    ok, body = test_endpoint("Malformed JSON on evaluate-cedar", "POST", "/api/evaluate-cedar", data="{\"broken json", expected_status=400)
    assert ok, f"Malformed JSON test failed: {body}"
    err_json = json.loads(body)
    assert err_json.get("error") is True, f"Missing error: true in payload: {body}"
    assert err_json.get("code") == "INVALID_JSON", f"Unexpected error code: {body}"
    assert "timestamp" in err_json, f"Missing timestamp in payload: {body}"
    print(f"    Structured payload verified: {err_json['code']} - {err_json['message']}")

    # 3. Parameter tampering / duplicate key semantic on evaluate-cedar -> 200 with VETO_SCHEMA_TAMPERING
    tamper_payload = json.dumps({
        "principal": "ledger_arm",
        "action": "write",
        "resource": "account_101",
        "context": {
            "amount_cents": 50000,
            "amount_cents_2": 99999999,
            "approved": True
        }
    })
    ok, body = test_endpoint("Duplicate key tampering on evaluate-cedar", "POST", "/api/evaluate-cedar", data=tamper_payload, expected_status=200)
    assert ok, f"Tamper test failed: {body}"
    resp_json = json.loads(body)
    assert resp_json.get("is_allowed") is False, f"Tampering was permitted! {body}"
    assert resp_json.get("breakout_verdict") == "VETO_SCHEMA_TAMPERING", f"Unexpected verdict: {body}"
    print(f"    Schema tampering veto verified: {resp_json['breakout_verdict']}")

    # 4. Unknown API endpoint -> 404 with structured JSON
    ok, body = test_endpoint("Unknown API endpoint", "GET", "/api/unknown-security-endpoint-xyz", expected_status=404)
    assert ok, f"404 test failed: {body}"
    err_json = json.loads(body)
    assert err_json.get("error") is True, f"Missing error: true in 404: {body}"
    assert err_json.get("code") == "ENDPOINT_NOT_FOUND", f"Unexpected code: {body}"
    print(f"    Structured 404 verified: {err_json['code']} - {err_json['message']}")

    # 5. Malformed JSON on egress-domains -> 400 with structured JSON
    ok, body = test_endpoint("Malformed JSON on egress-domains", "POST", "/api/egress-domains", data="not json", expected_status=400)
    assert ok, f"Egress malformed test failed: {body}"
    err_json = json.loads(body)
    assert err_json.get("error") is True, f"Missing error: true in egress 400: {body}"
    assert err_json.get("code") == "INVALID_JSON", f"Unexpected code: {body}"
    print(f"    Structured egress 400 verified: {err_json['code']}")

    # 6. Malformed JSON on rl-defense evaluate-action -> 400 with structured JSON
    ok, body = test_endpoint("Malformed JSON on evaluate-action", "POST", "/api/rl-defense/evaluate-action", data="{bad", expected_status=400)
    assert ok, f"RL evaluate action test failed: {body}"
    err_json = json.loads(body)
    assert err_json.get("error") is True, f"Missing error: true in RL 400: {body}"
    assert err_json.get("code") == "INVALID_JSON", f"Unexpected code: {body}"
    print(f"    Structured RL 400 verified: {err_json['code']}")

    # 7. Valid twin control probe -> authorized by Cedar
    twin_payload = json.dumps({
        "principal": "ledger_arm",
        "action": "write",
        "resource": "account_101",
        "context": {
            "amount_cents": 50000,
            "approved": True
        },
        "attach_supervisor_approval": True
    })
    ok, body = test_endpoint("Twin Control Authorized Request", "POST", "/api/evaluate-cedar", data=twin_payload, expected_status=200)
    assert ok, f"Twin control failed: {body}"
    twin_json = json.loads(body)
    assert twin_json.get("is_allowed") is True, f"Twin control was denied! {body}"
    print(f"    Twin control permitted: {twin_json.get('reason')}")

    print("\nALL LIVE ENDPOINT ERROR BOUNDARY AUDITS PASSED!")

if __name__ == "__main__":
    main()
