#!/usr/bin/env python3
"""Summarize SSH authentication failures from local log files.

Read-only, offline parser. No network activity or system changes.
"""
import argparse
import collections
import json
import re
from pathlib import Path

IP = r"(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-fA-F:]+)"
FAILED = re.compile(r"sshd(?:\[\d+\])?: Failed password for (?:invalid user )?\S+ from " + IP + r"\b")
INVALID = re.compile(r"sshd(?:\[\d+\])?: Invalid user \S+ from " + IP + r"\b")


def summarize(path):
    counts = collections.Counter()
    failures = 0
    invalid_users = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = FAILED.search(line)
            if match:
                failures += 1
                counts[match.group("ip")] += 1
            elif INVALID.search(line):
                invalid_users += 1
    return {
        "file": str(path),
        "failed_password_events": failures,
        "invalid_user_events_without_failed_password": invalid_users,
        "top_failure_sources": [
            {"source_ip": ip, "count": count}
            for ip, count in counts.most_common(20)
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", type=Path, help="Local SSH/authentication log file")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()
    try:
        result = summarize(args.logfile)
    except (OSError, UnicodeError) as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Failed password events: {result['failed_password_events']}")
        print(f"Other invalid-user events: {result['invalid_user_events_without_failed_password']}")
        for row in result["top_failure_sources"]:
            print(f"{row['source_ip']}: {row['count']}")


if __name__ == "__main__":
    main()
