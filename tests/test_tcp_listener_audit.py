"""Regression tests for local TCP listener classification."""
import importlib.util
import ipaddress
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import io
import json

SCRIPT = Path(__file__).resolve().parents[1] / "linux" / "tcp-listener-audit.py"
SPEC = importlib.util.spec_from_file_location("tcp_listener_audit", SCRIPT)
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def row(address, port=443, state="0A", uid=1000):
    packed = ipaddress.ip_address(address).packed
    encoded = "".join(
        f"{int.from_bytes(packed[i:i+4], sys.byteorder):08X}"
        for i in range(0, len(packed), 4)
    )
    return f"0: {encoded}:{port:04X} {encoded}:0000 {state} 0:0 0:0 0 {uid} 0 1\n"


class ListenerAuditTests(unittest.TestCase):
    def parse(self, rows, ipv6=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tcp"
            path.write_text("header\n" + "".join(rows), encoding="ascii")
            return audit.parse_table(path, ipv6)

    def test_ipv4_scopes_and_fields(self):
        result = self.parse([row("127.0.0.1"), row("0.0.0.0"),
                             row("192.0.2.10", 8443, uid=42)])
        self.assertEqual([r["scope"] for r in result],
                         ["loopback", "wildcard", "non-loopback"])
        self.assertEqual(result[2], {"address": "192.0.2.10", "port": 8443,
                                     "scope": "non-loopback", "uid": 42})

    def test_ipv6_and_mapped_addresses(self):
        result = self.parse([row("::1"), row("::"), row("2001:db8::1234"),
                             row("::ffff:127.0.0.1"), row("::ffff:0.0.0.0")], True)
        self.assertEqual([r["scope"] for r in result],
                         ["loopback", "wildcard", "non-loopback",
                          "loopback", "wildcard"])
        self.assertEqual(result[2]["address"], "2001:db8::1234")

    def test_non_listeners_ignored(self):
        self.assertEqual(self.parse([row("192.0.2.1", state="01")]), [])

    def test_malformed_rows_rejected(self):
        with self.assertRaises(ValueError):
            self.parse(["broken\n"])
        with self.assertRaises(ValueError):
            self.parse([row("::1")])

    def invoke(self, tables):
        output = io.StringIO()
        with patch.object(audit, "parse_table", side_effect=tables), \
             patch.object(sys, "argv", [str(SCRIPT), "--json"]), \
             patch.object(sys, "stdout", output):
            status = audit.main()
        return status, json.loads(output.getvalue())

    def test_clean_status(self):
        status, report = self.invoke([[{"address": "127.0.0.1", "port": 80,
                                       "uid": 0, "scope": "loopback"}], []])
        self.assertEqual(status, 0)
        self.assertEqual(report["errors"], [])

    def test_exposure_status(self):
        status, report = self.invoke([[{"address": "0.0.0.0", "port": 80,
                                       "uid": 0, "scope": "wildcard"}], []])
        self.assertEqual(status, 1)
        self.assertEqual(len(report["listeners"]), 1)

    def test_partial_failure_takes_precedence(self):
        status, report = self.invoke([[{"address": "0.0.0.0", "port": 80,
                                       "uid": 0, "scope": "wildcard"}],
                                     PermissionError("denied")])
        self.assertEqual(status, 2)
        self.assertEqual(len(report["listeners"]), 1)
        self.assertEqual(report["errors"], ["tcp6: denied"])


if __name__ == "__main__":
    unittest.main()
