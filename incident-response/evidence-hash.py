#!/usr/bin/env python3
"""Create or verify SHA-256 manifests for incident-response evidence.

Read-only with respect to evidence files. Manifest creation writes only the
specified manifest file. Use only on systems and evidence you are authorized
to examine.
"""

import argparse
import hashlib
import sys
from pathlib import Path

CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_files(root: Path, manifest: Path):
    manifest_resolved = manifest.resolve()
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink() and path.resolve() != manifest_resolved:
            yield path


def create_manifest(root: Path, manifest: Path) -> int:
    root = root.resolve()
    if not root.is_dir():
        print(f"error: evidence directory not found: {root}", file=sys.stderr)
        return 2

    entries = []
    for path in evidence_files(root, manifest):
        relative = path.relative_to(root).as_posix()
        entries.append(f"{sha256_file(path)}  {relative}")

    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text("\n".join(entries) + ("\n" if entries else ""), encoding="utf-8")
    print(f"manifest: {manifest}")
    print(f"files hashed: {len(entries)}")
    return 0


def verify_manifest(root: Path, manifest: Path) -> int:
    root = root.resolve()
    if not root.is_dir() or not manifest.is_file():
        print("error: evidence directory or manifest not found", file=sys.stderr)
        return 2

    failures = 0
    checked = 0
    for line_number, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            expected, relative = raw.split("  ", 1)
        except ValueError:
            print(f"INVALID line {line_number}")
            failures += 1
            continue

        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            print(f"UNSAFE  {relative}")
            failures += 1
            continue

        checked += 1
        if not candidate.is_file() or candidate.is_symlink():
            print(f"MISSING {relative}")
            failures += 1
            continue

        actual = sha256_file(candidate)
        if actual.lower() == expected.lower():
            print(f"OK      {relative}")
        else:
            print(f"CHANGED {relative}")
            failures += 1

    print(f"checked: {checked}; failures: {failures}")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or verify SHA-256 evidence manifests.")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Hash evidence files and write a manifest.")
    create.add_argument("directory", type=Path)
    create.add_argument("manifest", type=Path)

    verify = sub.add_parser("verify", help="Verify evidence files against a manifest.")
    verify.add_argument("directory", type=Path)
    verify.add_argument("manifest", type=Path)

    args = parser.parse_args()
    if args.command == "create":
        return create_manifest(args.directory, args.manifest)
    return verify_manifest(args.directory, args.manifest)


if __name__ == "__main__":
    raise SystemExit(main())
