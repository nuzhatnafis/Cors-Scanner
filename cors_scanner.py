#!/usr/bin/env python3
"""
cors_scanner.py
Tests an endpoint for common CORS (Cross-Origin Resource Sharing)
misconfigurations: arbitrary origin reflection, wildcard + credentials,
trusted-null-origin, and subdomain-based origin bypass.

Only run this against targets you own or are explicitly authorized to test.
"""

import argparse
import sys

import requests

TIMEOUT = 10

TEST_ORIGINS = [
    ("https://evil-attacker.com", "Arbitrary unrelated origin"),
    ("null", "Null origin (sandboxed iframe / file:// trick)"),
    ("https://{target}.evil-attacker.com", "Subdomain-prefix bypass (if target checks '.endswith(target)')"),
    ("https://evil-attacker.com.{target}", "Subdomain-suffix bypass (if target checks 'in' substring)"),
    ("http://{target}", "Scheme downgrade (https -> http)"),
]


def run_check(url: str, origin: str, headers: dict) -> dict:
    req_headers = dict(headers)
    req_headers["Origin"] = origin
    try:
        resp = requests.get(url, headers=req_headers, timeout=TIMEOUT)
    except requests.RequestException as e:
        return {"error": str(e)}

    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials")

    return {
        "origin_sent": origin,
        "status_code": resp.status_code,
        "access_control_allow_origin": acao,
        "access_control_allow_credentials": acac,
        "reflects_origin": acao == origin,
        "wildcard": acao == "*",
    }


def evaluate(result: dict, label: str) -> list:
    findings = []
    if result.get("error"):
        return findings

    acac = (result.get("access_control_allow_credentials") or "").lower() == "true"

    if result["wildcard"] and acac:
        findings.append(f"[CRITICAL] Wildcard ACAO (*) combined with Allow-Credentials: true — "
                         f"invalid per spec but some servers misconfigure this; if accepted by browsers "
                         f"this is a severe cross-origin data leak.")
    elif result["reflects_origin"] and acac:
        findings.append(f"[HIGH] '{label}' is reflected back in Access-Control-Allow-Origin WITH "
                         f"Allow-Credentials: true — any site can read authenticated responses from "
                         f"this endpoint on behalf of a logged-in victim.")
    elif result["reflects_origin"]:
        findings.append(f"[MEDIUM] '{label}' is reflected back in Access-Control-Allow-Origin "
                         f"(no credentials flag, so impact is lower but still broader than intended).")
    elif result["wildcard"]:
        findings.append(f"[LOW] Access-Control-Allow-Origin is '*' — fine for public data only, "
                         f"confirm no sensitive data is served here.")
    return findings


def main():
    parser = argparse.ArgumentParser(description="CORS misconfiguration scanner")
    parser.add_argument("url", help="Target URL to test, e.g. https://api.target.com/me")
    parser.add_argument("--target-host", required=True,
                         help="The target's own hostname, e.g. target.com (used to build bypass origins)")
    parser.add_argument("--header", action="append", default=[], help="Extra header 'Name: Value', e.g. auth cookie")
    args = parser.parse_args()

    headers = {}
    for h in args.header:
        if ":" in h:
            name, value = h.split(":", 1)
            headers[name.strip()] = value.strip()

    print(f"[*] Target: {args.url}\n")

    all_findings = []
    for origin_template, label in TEST_ORIGINS:
        origin = origin_template.format(target=args.target_host)
        print(f"[*] Testing Origin: {origin}  ({label})")
        result = run_check(args.url, origin, headers)

        if result.get("error"):
            print(f"    [!] Request failed: {result['error']}")
            continue

        print(f"    -> ACAO: {result['access_control_allow_origin']!r}, "
              f"ACAC: {result['access_control_allow_credentials']!r}")

        findings = evaluate(result, label)
        for f in findings:
            print(f"    {f}")
            all_findings.append((origin, f))
        print()

    if not all_findings:
        print("[+] No CORS misconfigurations detected with this test set.")
    else:
        print(f"[!!] {len(all_findings)} potential issue(s) found. Review severities above and confirm manually "
              f"(e.g. with a real cross-origin fetch() from a test page) before reporting.")


if __name__ == "__main__":
    main()
