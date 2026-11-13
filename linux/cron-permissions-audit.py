#!/usr/bin/env python3
"""Read-only audit of Linux cron configuration permissions.

Inspects conventional cron paths without executing jobs or reading their
contents. Run with sufficient privileges to inspect system cron directories.
Exit status: 0 = no findings, 1 = findings, 2 = inspection errors.
"""
import argparse
import json
import os
import stat
from pathlib import Path

DEFAULT_PATHS = (
    "/etc/crontab", "/etc/cron.d", "/etc/cron.hourly",
    "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
    "/etc/cron.allow", "/etc/cron.deny", "/var/spool/cron",
    "/var/spool/cron/crontabs",
)


def inspect(path, findings, errors):
    try:
        info = path.lstat()  # Do not follow symlinks.
    except FileNotFoundError:
        return
    except OSError as exc:
        errors.append({"path": str(path), "error": str(exc)})
        return
    mode = info.st_mode
    if stat.S_ISLNK(mode):
        findings.append({"path": str(path), "issue": "symlink requires review"})
        return
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        findings.append({"path": str(path), "issue": "unexpected file type"})
        return
    if mode & stat.S_IWOTH:
        findings.append({"path": str(path), "issue": "world-writable"})
    if mode & stat.S_IWGRP:
        findings.append({"path": str(path), "issue": "group-writable; verify trusted group"})
    if info.st_uid != 0:
        findings.append({"path": str(path), "issue": "not owned by root; verify ownership"})


def audit(paths):
    findings, errors = [], []
    for path in paths:
        inspect(path, findings, errors)
        try:
            if path.is_dir() and not path.is_symlink():
                with os.scandir(path) as entries:
                    for entry in entries:
                        inspect(Path(entry.path), findings, errors)
        except OSError as exc:
            errors.append({"path": str(path), "error": str(exc)})
    return {"findings": findings, "errors": errors,
            "note": "Ownership policies vary, especially for user crontabs. Review findings before remediation."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", action="append", type=Path,
                        help="Audit this path instead of defaults (repeatable)")
    parser.add_argument("--json", action="store_true", help="Machine-readable report")
    args = parser.parse_args()
    report = audit(args.path or [Path(p) for p in DEFAULT_PATHS])
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for finding in report["findings"]:
            print(f"FINDING {finding['path']}: {finding['issue']}")
        for error in report["errors"]:
            print(f"ERROR {error['path']}: {error['error']}")
        print(report["note"])
        print(f"{len(report['findings'])} findings, {len(report['errors'])} errors")
    return 2 if report["errors"] else 1 if report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
