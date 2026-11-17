#!/usr/bin/env python3
"""Read-only audit of SSH authorized_keys file permissions and ownership.

Checks only paths explicitly supplied by an administrator. Never follows symlinks.
"""
import argparse
import json
import os
import stat
import sys
from pathlib import Path


def inspect(path: Path):
    findings = []
    try:
        info = path.lstat()
    except OSError as exc:
        return {"path": str(path), "findings": ["inspection_error"], "error": str(exc)}
    if stat.S_ISLNK(info.st_mode):
        findings.append("symlink")
        return {"path": str(path), "findings": findings}
    if not stat.S_ISREG(info.st_mode):
        findings.append("not_regular_file")
        return {"path": str(path), "findings": findings}
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        findings.append("writable_by_group_or_others")
    if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        findings.append("accessible_by_group_or_others")
    if info.st_uid not in (0, os.getuid()):
        findings.append("unexpected_owner")
    parent = path.parent
    try:
        parent_info = parent.lstat()
        if stat.S_ISLNK(parent_info.st_mode):
            findings.append("parent_symlink")
        elif not stat.S_ISDIR(parent_info.st_mode):
            findings.append("parent_not_directory")
        else:
            if parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                findings.append("parent_writable_by_group_or_others")
            if parent_info.st_uid not in (0, os.getuid()):
                findings.append("unexpected_parent_owner")
    except OSError as exc:
        findings.append("parent_inspection_error")
        return {"path": str(path), "findings": findings, "error": str(exc)}
    return {"path": str(path), "findings": findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="Explicit authorized_keys paths to audit")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()
    results = [inspect(path) for path in args.paths]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            print(f"{result['path']}: {', '.join(result['findings']) or 'OK'}")
            if "error" in result:
                print(f"  {result['error']}", file=sys.stderr)
    if any("inspection_error" in finding for result in results for finding in result["findings"]):
        return 2
    return 1 if any(result["findings"] for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())
