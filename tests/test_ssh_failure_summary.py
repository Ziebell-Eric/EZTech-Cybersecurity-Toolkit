"""Regression tests for the read-only SSH failure summary utility.

Run: python -m unittest discover -s tests -p 'test_ssh_failure_summary.py'
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "log-analysis" / "ssh-failure-summary.py"
spec = importlib.util.spec_from_file_location("ssh_failure_summary", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SSHFailureSummaryTests(unittest.TestCase):
    def test_counts_failed_passwords_by_source_without_double_counting(self):
        sample = (
            "Nov 12 08:00:00 host sshd[100]: Invalid user guest from 192.0.2.10 port 4000\n"
            "Nov 12 08:00:01 host sshd[100]: Failed password for invalid user guest from 192.0.2.10 port 4000 ssh2\n"
            "Nov 12 08:00:02 host sshd[101]: Failed password for root from 192.0.2.10 port 4001 ssh2\n"
            "Nov 12 08:00:03 host sshd[102]: Failed password for admin from 2001:db8::5 port 4002 ssh2\n"
            "Nov 12 08:00:04 host sshd[103]: Accepted publickey for admin from 192.0.2.11 port 4003 ssh2\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text(sample, encoding="utf-8")
            result = module.summarize(path)
        self.assertEqual(result["failed_password_events"], 3)
        self.assertEqual(result["invalid_user_events_without_failed_password"], 1)
        self.assertEqual(result["top_failure_sources"], [
            {"source_ip": "192.0.2.10", "count": 2},
            {"source_ip": "2001:db8::5", "count": 1},
        ])

    def test_empty_log(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.log"
            path.touch()
            result = module.summarize(path)
        self.assertEqual(result["failed_password_events"], 0)
        self.assertEqual(result["top_failure_sources"], [])

    def test_json_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text(
                "Nov 12 host sshd[9]: Failed password for root from 198.51.100.7 port 22 ssh2\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), str(path), "--json"],
                capture_output=True, text=True, check=True,
            )
        report = json.loads(completed.stdout)
        self.assertEqual(report["failed_password_events"], 1)
        self.assertEqual(report["top_failure_sources"][0]["source_ip"], "198.51.100.7")

    def test_missing_file_exits_with_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.log"
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), str(path)],
                capture_output=True, text=True,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("error:", completed.stderr.lower())


if __name__ == "__main__":
    unittest.main()
