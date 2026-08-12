#!/usr/bin/env python3
"""Inspect a server certificate and negotiated TLS details."""
import argparse, socket, ssl
from datetime import datetime, timezone

p = argparse.ArgumentParser()
p.add_argument('host')
p.add_argument('--port', type=int, default=443)
a = p.parse_args()
ctx = ssl.create_default_context()
with socket.create_connection((a.host, a.port), timeout=8) as raw:
    with ctx.wrap_socket(raw, server_hostname=a.host) as s:
        cert = s.getpeercert()
        expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        remaining = expires - datetime.now(timezone.utc)
        print(f'Host: {a.host}:{a.port}')
        print(f'TLS: {s.version()}')
        print(f'Cipher: {s.cipher()[0]}')
        print(f'Expires: {expires.isoformat()} ({remaining.days} days)')
        print('Subject:', dict(x[0] for x in cert.get('subject', [])))
        print('Issuer:', dict(x[0] for x in cert.get('issuer', [])))
        sans = [v for k, v in cert.get('subjectAltName', []) if k == 'DNS']
        print('DNS SANs:', ', '.join(sans))
