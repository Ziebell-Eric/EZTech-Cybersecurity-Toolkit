#!/usr/bin/env python3
"""Read-only audit of explicitly supplied sudoers files and directories.

Checks ownership, file type, and write permissions without following symlinks.
Does not parse sudo policy or change permissions. Run with sufficient privileges
to inspect the selected paths. Exit: 0 clean, 1 findings, 2 inspection errors.
"""
import argparse
import json
import os
import stat
import sys
from pathlib import Path


def inspect(path):
    """Return findings for a single path using lstat (never follow links)."""
    findings = []
    try:
        info = path.lstat()
    except OSError as exc:
        return {"path": str(path), "findings": [], "error": str(exc)}

    mode = info.st_mode
    if stat.S_ISLNK(mode):
        findings.append("symbolic link; target not inspected")
    elif stat.S_ISREG(mode):
        if mode & 0o022:
            findings.append("file is group- or world-writable")
        if mode & 0o007:
            findings.append("file grants permissions to other users")
        if mode & 0o100:
            findings.append("file is executable by owner")
    elif stat.S_ISDIR(mode):
        if mode & 0o022:
            findings.append("directory is group- or world-writable")
    else:
        findings.append("unexpected file type")
    if info.st_uid != 0:
        findings.append("not owned by root")
    return {"path": str(path), "findings": findings, "error": None}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path,
                        help="sudoers files/directories to inspect (no recursive traversal)")
    parser.add_argument("--json", action="store_true", help="machine-readable results")
    args = parser.parse_args(argv)
    results = [inspect(path) for path in args.paths]
    if args.json:
        print(json.dumps({"results": results}, indent=2))
    else:
        for result in results:
            if result["error"]:
                print(f"ERROR {result['path']}: {result['error']}")
            elif result["findings"]:
                for finding in result["findings"]:
                    print(f"FINDING {result['path']}: {finding}")
            else:
                print(f"OK {result['path']}")
    if any(result["error"] for result in results):
        return 2
    return 1 if any(result["findings"] for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())
