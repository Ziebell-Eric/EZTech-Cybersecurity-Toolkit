"""Exercise private report creation without scanning the host."""
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "linux" / "linux-security-audit.sh"


@unittest.skipUnless(os.name == "posix", "POSIX file permissions required")
class LinuxAuditReportTests(unittest.TestCase):
    def test_reports_are_private_and_unique(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            # Stub host inspection commands; retain real date and mktemp.
            for name in ("hostnamectl", "uname", "who", "awk", "ss",
                         "netstat", "ufw", "firewall-cmd", "nft", "lastb",
                         "find", "apt", "dnf"):
                stub = bin_dir / name
                stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                stub.chmod(0o755)
            env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"])
            for _ in range(2):
                result = subprocess.run(
                    ["bash", "-c", 'umask 000; exec bash "$1"', "audit", str(SCRIPT)],
                    cwd=root, env=env, capture_output=True, text=True, timeout=15,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            reports = sorted(root.glob("linux-security-audit-*.txt"))
            self.assertEqual(len(reports), 2)
            for report in reports:
                self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
                self.assertIn("EZTech Linux Security Audit", report.read_text())

    def test_creation_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stub = root / "mktemp"
            stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            stub.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"])
            result = subprocess.run(
                ["bash", str(SCRIPT)], cwd=root, env=env,
                capture_output=True, text=True, timeout=15,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Unable to create a private audit report", result.stderr)
            self.assertNotIn("Security audit written", result.stdout)
            self.assertFalse(list(root.glob("linux-security-audit-*.txt")))


if __name__ == "__main__":
    unittest.main()
