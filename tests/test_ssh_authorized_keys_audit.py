"""Regression tests for the read-only SSH authorized_keys permissions audit."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "linux" / "ssh-authorized-keys-audit.py"


@unittest.skipUnless(os.name == "posix", "POSIX permissions required")
class AuthorizedKeysAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ssh = self.root / ".ssh"
        self.ssh.mkdir(mode=0o700)
        self.ssh.chmod(0o700)
        self.keys = self.ssh / "authorized_keys"
        self.keys.write_text("ssh-ed25519 example test-key\n", encoding="utf-8")
        self.keys.chmod(0o600)

    def audit(self, *paths):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json", *(str(p) for p in paths)],
            capture_output=True, text=True, timeout=10, check=False,
        )
        return result, json.loads(result.stdout)

    def test_secure_file_and_directory(self):
        result, records = self.audit(self.keys)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(records[0]["findings"], [])

    def test_group_writable_file(self):
        self.keys.chmod(0o620)
        result, records = self.audit(self.keys)
        self.assertEqual(result.returncode, 1)
        self.assertIn("writable_by_group_or_others", records[0]["findings"])

    def test_group_readable_file(self):
        self.keys.chmod(0o640)
        result, records = self.audit(self.keys)
        self.assertEqual(result.returncode, 1)
        self.assertIn("accessible_by_group_or_others", records[0]["findings"])

    def test_insecure_parent_directory(self):
        self.ssh.chmod(0o720)
        result, records = self.audit(self.keys)
        self.assertEqual(result.returncode, 1)
        self.assertIn("parent_writable_by_group_or_others", records[0]["findings"])

    def test_symlink_is_reported_not_followed(self):
        link = self.ssh / "linked_keys"
        link.symlink_to(self.keys)
        result, records = self.audit(link)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(records[0]["findings"], ["symlink"])

    def test_directory_instead_of_file(self):
        result, records = self.audit(self.ssh)
        self.assertEqual(result.returncode, 1)
        self.assertIn("not_regular_file", records[0]["findings"])

    def test_missing_file_returns_inspection_error(self):
        result, records = self.audit(self.ssh / "missing")
        self.assertEqual(result.returncode, 2)
        self.assertIn("inspection_error", records[0]["findings"])
        self.assertIn("error", records[0])

    def test_multiple_paths_and_error_precedence(self):
        result, records = self.audit(self.keys, self.ssh / "missing")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["findings"], [])
        self.assertIn("inspection_error", records[1]["findings"])


if __name__ == "__main__":
    unittest.main()
