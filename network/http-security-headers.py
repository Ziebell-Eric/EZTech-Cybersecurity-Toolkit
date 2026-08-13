#!/usr/bin/env python3
"""Audit common HTTP security headers for an authorized web endpoint."""

import argparse
import ssl
import sys
import urllib.error
import urllib.request

RECOMMENDED_HEADERS = {
    "strict-transport-security": "HSTS helps enforce HTTPS (HTTPS endpoints only).",
    "content-security-policy": "CSP reduces exposure to script injection attacks.",
    "x-content-type-options": "Use nosniff to prevent MIME-type sniffing.",
    "referrer-policy": "Controls how much referrer information leaves the site.",
    "permissions-policy": "Restricts access to browser features and sensors.",
    "x-frame-options": "Helps mitigate clickjacking when CSP frame-ancestors is not used.",
}


def audit(url: str, timeout: float) -> int:
    request = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": "EZTech-HTTP-Security-Audit/1.0"},
    )

    context = ssl.create_default_context()

    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            status = getattr(response, "status", "unknown")
            final_url = response.geturl()
    except urllib.error.HTTPError as exc:
        headers = {key.lower(): value for key, value in exc.headers.items()}
        status = exc.code
        final_url = exc.geturl()
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 2

    print(f"URL: {final_url}")
    print(f"HTTP status: {status}")
    print("\nSecurity header review:")

    missing = 0
    for header, guidance in RECOMMENDED_HEADERS.items():
        value = headers.get(header)
        if value:
            print(f"[OK] {header}: {value}")
        else:
            missing += 1
            print(f"[MISSING] {header} - {guidance}")

    if "server" in headers:
        print(f"\n[INFO] Server header exposed: {headers['server']}")

    print(f"\nSummary: {len(RECOMMENDED_HEADERS) - missing}/{len(RECOMMENDED_HEADERS)} recommended headers present.")
    return 1 if missing else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Review common HTTP security headers on an authorized endpoint."
    )
    parser.add_argument("url", help="Full http:// or https:// URL to audit")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout in seconds")
    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        parser.error("url must begin with http:// or https://")

    return audit(args.url, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
