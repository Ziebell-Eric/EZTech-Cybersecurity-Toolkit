#!/usr/bin/env python3
"""Read-only audit of selected Linux kernel hardening settings.

Run on systems you administer: python3 linux/kernel-hardening-audit.py
Exit 0: all checks meet baseline; 1: review findings; 2: incomplete audit.
This generic baseline is not a compliance certification. Some workloads
require exceptions. No settings are changed and no network access is used.
"""
import argparse
import json
from pathlib import Path

BASELINE = {
    "kernel/randomize_va_space": (2, "Full address space randomization"),
    "kernel/kptr_restrict": (1, "Restrict kernel pointer disclosure"),
    "kernel/dmesg_restrict": (1, "Restrict kernel log access"),
    "fs/protected_symlinks": (1, "Protect symlinks in sticky directories"),
    "fs/protected_hardlinks": (1, "Restrict unsafe hardlink creation"),
}


def audit(root=Path("/proc/sys")):
    results = []
    for key, (minimum, purpose) in BASELINE.items():
        row = {"setting": key.replace("/", "."), "minimum": minimum,
               "purpose": purpose}
        try:
            with (root / key).open(encoding="ascii") as handle:
                raw = handle.read(128)
            value = int(raw.strip())
            # These controls have small, documented integer ranges.
            maximum = 2 if key in ("kernel/randomize_va_space",
                                   "kernel/kptr_restrict") else 1
            if not 0 <= value <= maximum:
                raise ValueError("unexpected setting value")
            row.update(value=value, status="pass" if value >= minimum else "review")
        except (OSError, ValueError) as exc:
            row.update(value=None, status="error", error=str(exc))
        results.append(row)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit structured results")
    args = parser.parse_args()
    rows = audit()
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            print(f"{row['status'].upper()}: {row['setting']} "
                  f"value={row['value']} minimum={row['minimum']} "
                  f"({row['purpose']})")
            if "error" in row:
                print(f"  {row['error']}")
    if any(row["status"] == "error" for row in rows):
        return 2
    return int(any(row["status"] == "review" for row in rows))


if __name__ == "__main__":
    raise SystemExit(main())
