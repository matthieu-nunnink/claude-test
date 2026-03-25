#!/usr/bin/env python3
"""
security-headers-scanner
Checks a target URL for missing or misconfigured HTTP security headers.
"""

import sys
import urllib.request
import urllib.error
import json
from datetime import datetime


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS)",
        "severity": "HIGH",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks",
        "severity": "HIGH",
        "recommendation": "Define a strict CSP policy restricting script/style sources",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer info is sent",
        "severity": "LOW",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Restricts access to browser features (camera, mic, etc.)",
        "severity": "LOW",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (older browsers)",
        "severity": "LOW",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block",
    },
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEVERITY_ICONS = {"HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[i]"}


def scan(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "url": url,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status_code": None,
        "server": None,
        "findings": [],
        "score": 0,
    }

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "security-headers-scanner/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            result["status_code"] = response.status
            headers = {k.lower(): v for k, v in response.headers.items()}

            # Check for server info disclosure
            if "server" in headers:
                result["server"] = headers["server"]

            # Check each security header
            passed = 0
            for header, meta in SECURITY_HEADERS.items():
                present = header.lower() in headers
                finding = {
                    "header": header,
                    "present": present,
                    "severity": meta["severity"] if not present else None,
                    "description": meta["description"],
                    "recommendation": meta["recommendation"] if not present else None,
                    "value": headers.get(header.lower()),
                }
                result["findings"].append(finding)
                if present:
                    passed += 1

            result["score"] = round((passed / len(SECURITY_HEADERS)) * 100)

    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    return result


def print_report(result: dict):
    width = 64
    print("=" * width)
    print(f"  Security Headers Scanner")
    print(f"  Target : {result['url']}")
    print(f"  Time   : {result['timestamp']}")
    if result.get("status_code"):
        print(f"  Status : HTTP {result['status_code']}")
    if result.get("server"):
        print(f"  Server : {result['server']}  <-- info disclosure")
    print("=" * width)

    if result.get("error"):
        print(f"\n  ERROR: {result['error']}\n")
        return

    # Sort findings: missing headers first, by severity
    findings = sorted(
        result["findings"],
        key=lambda f: (f["present"], SEVERITY_ORDER.get(f["severity"] or "LOW", 2)),
    )

    missing = [f for f in findings if not f["present"]]
    present = [f for f in findings if f["present"]]

    if missing:
        print("\n  MISSING HEADERS\n")
        for f in missing:
            icon = SEVERITY_ICONS.get(f["severity"], "[?]")
            print(f"  {icon} {f['header']}")
            print(f"     Severity : {f['severity']}")
            print(f"     Why      : {f['description']}")
            print(f"     Fix      : {f['recommendation']}")
            print()

    if present:
        print("  PRESENT HEADERS\n")
        for f in present:
            print(f"  [+] {f['header']}")
            if f["value"]:
                print(f"     Value : {f['value']}")
        print()

    # Score
    score = result["score"]
    if score >= 80:
        grade = "A"
    elif score >= 60:
        grade = "B"
    elif score >= 40:
        grade = "C"
    else:
        grade = "F"

    print("=" * width)
    print(f"  Score : {score}/100  |  Grade : {grade}")
    print("=" * width)
    print()


def main():
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <url> [--json]")
        print("Example: python scanner.py https://example.com")
        sys.exit(1)

    url = sys.argv[1]
    as_json = "--json" in sys.argv

    result = scan(url)

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)


if __name__ == "__main__":
    main()
