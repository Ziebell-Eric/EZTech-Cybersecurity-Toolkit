#!/usr/bin/env python3
"""Summarize sudo authentication failures from a local Linux auth log.

Read-only and offline. Accepts common Debian/Ubuntu and RHEL-style sudo log
messages. This tool does not change authentication settings.
"""
import argparse
import collections
import json
import re
import sys
from pathlib import Path

SUDO_LINE = re.compile(r"\bsudo(?:\[\d+\])?:\s*(.*)$", re.IGNORECASE)
USER_FIELD = re.compile(r"^\s*([^:;\s]+)\s*:")
FAILURE = re.compile(
    r"authentication failure|incorrect password|password is required|"
    r"not in the sudoers file|not allowed to execute|"
    r"command not allowed|a password is required",
    re.IGNORECASE,
)


def audit(path: Path):
    users = collections.Counter()
    categories = collections.Counter()
    lines_scanned = 0
    failures = 0
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            lines_scanned += 1
            match = SUDO_LINE.search(line)
            if not match:
                continue
            message = match.group(1)
            reason = FAILURE.search(message)
            if not reason:
                continue
            failures += 1
            categories[reason.group(0).lower()] += 1
            user_match = USER_FIELD.search(message)
            users[user_match.group(1) if user_match else "(unknown)"] += 1
    return {
        "log_file": str(path),
        "lines_scanned": lines_scanned,
        "sudo_failure_events": failures,
        "failure_reasons": dict(categories.most_common()),
        "users": dict(users.most_common()),
        "limitations": (
            "Pattern-based summary; log formats vary. Review source logs before "
            "treating results as confirmed security incidents."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log_file", type=Path, help="Local auth.log or secure log")
    parser.add_argument("--json", action="store_true", help="Print JSON")
    args = parser.parse_args()
    try:
        report = audit(args.log_file)
    except OSError as exc:
        parser.exit(2, f"Unable to read log: {exc}\n")
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Scanned {report['lines_scanned']} lines")
        print(f"Potential sudo failures: {report['sudo_failure_events']}")
        for user, count in report["users"].items():
            print(f"  {user}: {count}")
        print(report["limitations"])


if __name__ == "__main__":
    main()
