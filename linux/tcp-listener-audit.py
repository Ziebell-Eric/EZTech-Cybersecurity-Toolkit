#!/usr/bin/env python3
"""Read-only audit of listening TCP sockets on an authorized Linux host."""
import argparse
import ipaddress
import json
import socket
import sys
from pathlib import Path


def parse_table(path, ipv6=False):
    rows = []
    with path.open(encoding="ascii") as stream:
        next(stream, None)
        for line in stream:
            fields = line.split()
            if len(fields) < 10:
                raise ValueError("Malformed TCP table row")
            if fields[3] != "0A":  # TCP_LISTEN
                continue
            address, port = fields[1].split(":")
            raw = bytes.fromhex(address)
            if len(raw) != (16 if ipv6 else 4):
                raise ValueError("Invalid address length")
            # Kernel prints each 32-bit word in native byte order.
            packed = b"".join(
                int.from_bytes(raw[i:i+4], "big").to_bytes(4, sys.byteorder)
                for i in range(0, len(raw), 4)
            )
            ip = ipaddress.ip_address(socket.inet_ntop(
                socket.AF_INET6 if ipv6 else socket.AF_INET, packed))
            effective = getattr(ip, "ipv4_mapped", None) or ip
            scope = ("loopback" if effective.is_loopback else
                     "wildcard" if effective.is_unspecified else "non-loopback")
            rows.append({"address": str(ip), "port": int(port, 16),
                         "scope": scope, "uid": int(fields[7])})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    rows, errors = [], []
    for name, ipv6 in (("tcp", False), ("tcp6", True)):
        try:
            rows.extend(parse_table(Path("/proc/net") / name, ipv6))
        except (OSError, ValueError) as exc:
            errors.append(f"{name}: {exc}")
    rows.sort(key=lambda row: (row["port"], row["address"], row["uid"]))
    if args.json:
        print(json.dumps({"listeners": rows, "errors": errors}, indent=2))
    else:
        for row in rows:
            print(f'[{row["address"]}]:{row["port"]} {row["scope"]} uid={row["uid"]}')
        for error in errors:
            print(error, file=sys.stderr)
        print("Non-loopback bindings merit review; firewall reachability is not tested.")
    return 2 if errors else 1 if any(
        row["scope"] != "loopback" for row in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
