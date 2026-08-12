#!/usr/bin/env python3
"""Match newline-delimited IOCs against text/log files without sending data externally."""
import argparse
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('ioc_file', type=Path, help='One IOC per line')
p.add_argument('targets', nargs='+', type=Path)
a = p.parse_args()

iocs = {x.strip().lower() for x in a.ioc_file.read_text(errors='ignore').splitlines() if x.strip() and not x.startswith('#')}
found = 0
for target in a.targets:
    try:
        for n, line in enumerate(target.open(errors='ignore'), 1):
            low = line.lower()
            matches = sorted(i for i in iocs if i in low)
            if matches:
                found += len(matches)
                print(f'{target}:{n}: {", ".join(matches)}')
    except (PermissionError, OSError) as e:
        print(f'[!] {target}: {e}')
print(f'Matches: {found}')
