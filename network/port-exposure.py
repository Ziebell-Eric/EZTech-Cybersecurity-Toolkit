#!/usr/bin/env python3
"""Check a small explicit list of TCP ports on an authorized host."""
import argparse, socket

p = argparse.ArgumentParser(description='Authorized TCP exposure checker')
p.add_argument('host')
p.add_argument('--ports', default='22,80,443,445,3389', help='Comma-separated TCP ports')
p.add_argument('--timeout', type=float, default=0.75)
a = p.parse_args()
ports = sorted({int(x) for x in a.ports.split(',') if x.strip()})
if len(ports) > 100:
    raise SystemExit('Refusing more than 100 ports; this utility is intended for targeted validation.')
for port in ports:
    try:
        with socket.create_connection((a.host, port), timeout=a.timeout):
            print(f'OPEN  {a.host}:{port}')
    except (TimeoutError, ConnectionRefusedError, OSError):
        print(f'CLOSED/FILTERED {a.host}:{port}')
