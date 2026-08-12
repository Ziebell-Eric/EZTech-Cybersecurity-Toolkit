#!/usr/bin/env python3
"""Summarize common successful/failed authentication indicators in text logs."""
import argparse, re
from collections import Counter
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('log', type=Path)
a = p.parse_args()
patterns = {
    'failed': re.compile(r'failed|failure|invalid user|authentication error', re.I),
    'success': re.compile(r'accepted|successful|session opened', re.I),
}
ip_re = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
counts = Counter()
ips = Counter()
for line in a.log.open(errors='ignore'):
    for name, rx in patterns.items():
        if rx.search(line):
            counts[name] += 1
            if name == 'failed':
                ips.update(ip_re.findall(line))
print('Authentication summary')
print(f"Successful indicators: {counts['success']}")
print(f"Failed indicators: {counts['failed']}")
print('\nTop source IPs associated with failures:')
for ip, count in ips.most_common(15):
    print(f'{count:6}  {ip}')
