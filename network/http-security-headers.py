#!/usr/bin/env python3
"""Read-only HTTP response security-header audit for authorized targets."""

import argparse
import json
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

SECURITY_HEADERS = {
    "content-security-policy": "Restricts browser content sources and helps mitigate XSS.",
    "strict-transport-security": "Enforces HTTPS for future browser connections.",
    "x-content-type-options": "Prevents MIME-type sniffing when set to nosniff.",
    "referrer-policy": "Controls referrer information sent to other sites.",
    "permissions-policy": "Restricts access to browser features and device APIs.",
    "x-frame-options": "Legacy clickjacking protection; CSP frame-ancestors is preferred.",
    "cross-origin-opener-policy": "Helps isolate browsing contexts from cross-origin pages.",
    "cross-origin-resource-policy": "Controls which origins may embed the response.",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Audit common HTTP security headers without modifying the target."
    )
    parser.add_argument("url", help="Authorized http:// or https:// URL to inspect")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout in seconds (default: 8)")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects (disabled by default)")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    return parser.parse_args()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_url(raw_url):
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must include http:// or https:// and a hostname")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not supported")
    return parsed


def fetch_headers(url, timeout, follow_redirects):
    handlers = [] if follow_redirects else [NoRedirect()]
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": "EZTech-Security-Header-Audit/1.0"},
    )

    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        # HTTPError still carries response headers, including redirect responses when
        # redirects are intentionally disabled.
        response = exc
    return response


def audit(response):
    headers = {key.lower(): value.strip() for key, value in response.headers.items()}
    checks = []

    for name, purpose in SECURITY_HEADERS.items():
        value = headers.get(name)
        checks.append(
            {
                "header": name,
                "present": value is not None,
                "value": value,
                "purpose": purpose,
            }
        )

    warnings = []
    csp = headers.get("content-security-policy", "")
    if csp and "unsafe-inline" in csp.lower():
        warnings.append("Content-Security-Policy contains 'unsafe-inline'; review whether it is necessary.")

    hsts = headers.get("strict-transport-security", "")
    if hsts and "max-age=0" in hsts.replace(" ", "").lower():
        warnings.append("Strict-Transport-Security sets max-age=0, which disables HSTS.")

    xcto = headers.get("x-content-type-options")
    if xcto and xcto.lower() != "nosniff":
        warnings.append("X-Content-Type-Options is present but is not set to 'nosniff'.")

    return checks, warnings


def main():
    args = parse_args()
    try:
        validate_url(args.url)
        response = fetch_headers(args.url, args.timeout, args.follow_redirects)
    except (ValueError, urllib.error.URLError, TimeoutError) as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 2

    checks, warnings = audit(response)
    status = getattr(response, "status", None) or getattr(response, "code", None)
    final_url = response.geturl()
    missing = [item["header"] for item in checks if not item["present"]]

    result = {
        "requested_url": args.url,
        "response_url": final_url,
        "status": status,
        "headers": checks,
        "missing": missing,
        "warnings": warnings,
    }

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print(f"Target: {final_url}")
    print(f"HTTP status: {status}")
    print("\nSecurity headers:")
    for item in checks:
        marker = "OK" if item["present"] else "MISSING"
        value = f" = {item['value']}" if item["value"] else ""
        print(f"[{marker}] {item['header']}{value}")

    if warnings:
        print("\nReview notes:")
        for warning in warnings:
            print(f"- {warning}")

    print(f"\nSummary: {len(checks) - len(missing)}/{len(checks)} checked headers present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
