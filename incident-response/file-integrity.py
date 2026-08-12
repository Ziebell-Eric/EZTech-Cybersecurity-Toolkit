#!/usr/bin/env python3
"""Create or verify SHA-256 file-integrity baselines."""
import argparse, hashlib, json
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def scan(root: Path):
    data = {}
    for p in root.rglob('*'):
        if p.is_file():
            try:
                data[str(p.resolve())] = sha256(p)
            except (PermissionError, OSError):
                pass
    return data

p = argparse.ArgumentParser()
p.add_argument('path', type=Path)
p.add_argument('--output', default='integrity-baseline.json')
p.add_argument('--verify', help='Existing baseline JSON to verify')
a = p.parse_args()
current = scan(a.path)

if a.verify:
    baseline = json.loads(Path(a.verify).read_text(encoding='utf-8'))
    added = sorted(set(current) - set(baseline))
    removed = sorted(set(baseline) - set(current))
    changed = sorted(k for k in set(current) & set(baseline) if current[k] != baseline[k])
    print(json.dumps({'added': added, 'removed': removed, 'changed': changed}, indent=2))
else:
    Path(a.output).write_text(json.dumps(current, indent=2), encoding='utf-8')
    print(f'Wrote {len(current)} hashes to {a.output}')
