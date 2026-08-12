#!/usr/bin/env python3
"""Resolve DNS records for a domain using the local resolver. Defensive investigation helper."""
import argparse, socket

p=argparse.ArgumentParser()
p.add_argument('domain')
a=p.parse_args()
print(f'Domain: {a.domain}')
try:
    for fam, _, _, canon, sockaddr in socket.getaddrinfo(a.domain, None):
        print('Address:', sockaddr[0], 'Family:', 'IPv6' if fam == socket.AF_INET6 else 'IPv4')
except socket.gaierror as e:
    print('Resolution error:', e)
try:
    print('Hostname aliases:', socket.gethostbyname_ex(a.domain))
except socket.gaierror:
    pass
