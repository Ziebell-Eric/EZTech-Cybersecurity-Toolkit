"""Regression tests for the read-only Linux cron permissions auditor."""
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "linux" / "cron-permissions-audit.py"
SPEC = importlib.util.spec_from_file_location("cron_permissions_audit", SCRIPT)
audit_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_module)


class CronPermissionsAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def make_file(self, name, mode=0o600):
        path = self.root / name
        path.write_text("# test fixture\n", encoding="utf-8")
        path.chmod(mode)
        return path

    def issues_for(self, report, path):
        return {item["issue"] for item in report["findings"]
                if item["path"] == str(path)}

    def test_world_writable_file_is_reported(self):
        path = self.make_file("world", 0o606)
        report = audit_module.audit([path])
        self.assertIn("world-writable", self.issues_for(report, path))
        self.assertEqual(report["errors"], [])

    def test_group_writable_file_is_reported(self):
        path = self.make_file("group", 0o660)
        report = audit_module.audit([path])
        self.assertIn("group-writable; verify trusted group",
                      self.issues_for(report, path))

    def test_symlink_is_flagged_without_following_target(self):
        target = self.make_file("target", 0o600)
        link = self.root / "link"
        link.symlink_to(target)
        report = audit_module.audit([link])
        self.assertEqual(self.issues_for(report, link),
                         {"symlink requires review"})

    def test_directory_children_are_inspected(self):
        child = self.make_file("cronjob", 0o666)
        report = audit_module.audit([self.root])
        self.assertIn("world-writable", self.issues_for(report, child))

    def test_missing_paths_are_skipped(self):
        report = audit_module.audit([self.root / "does-not-exist"])
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["errors"], [])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX named pipes")
    def test_unexpected_file_type_is_reported(self):
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        report = audit_module.audit([fifo])
        self.assertIn("unexpected file type", self.issues_for(report, fifo))


if __name__ == "__main__":
    unittest.main()
