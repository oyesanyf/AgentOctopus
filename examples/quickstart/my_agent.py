"""AgentOctopus 30-second quickstart demo (Python 3 stdlib only, offline-safe)."""

import json
import os
import pathlib
import sys
import urllib.error
import urllib.request


def main() -> int:
    # 1. Allowed action: read workspace policy.json under deterministic confinement
    policy_path = pathlib.Path(__file__).with_name("policy.json")
    policy_data = json.loads(policy_path.read_text(encoding="utf-8"))
    allowed_domains = policy_data.get("allowed_domains", [])
    print(f"[ALLOW] Policy-permitted Python execution & policy.json read: OK (allowed_domains={allowed_domains})")

    proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if not proxy:
        print("[ERROR] HTTP_PROXY is not configured by octopus runtime", file=sys.stderr)
        return 1

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )

    probes = [
        ("Cloud IMDS 169.254.169.254", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("Unapproved domain evil.example.com", "http://evil.example.com/exfil"),
    ]

    for label, url in probes:
        try:
            with opener.open(url, timeout=5) as resp:
                print(f"[UNEXPECTED ALLOW] {label} returned HTTP {resp.status}", file=sys.stderr)
                return 1
        except urllib.error.HTTPError as err:
            body = err.read().decode("utf-8", errors="replace")
            if err.code != 403 or "blocked_by_octopus_policy" not in body:
                print(f"[ERROR] {label} returned unexpected HTTP {err.code}: {body}", file=sys.stderr)
                return 1
            print(f"[BLOCKED] {label} -> HTTP {err.code} (blocked_by_octopus_policy)")
        except Exception as err:
            print(f"[BLOCKED] {label} -> {type(err).__name__}: {err}")

    return 0


if __name__ == "__main__":
    sys.exit(main())