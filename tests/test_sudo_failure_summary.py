"""Regression tests for the read-only sudo failure log summary.

Run with: python3 -m unittest discover -s tests -v
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "log-analysis" / "sudo-failure-summary.py"
SPEC = importlib.util.spec_from_file_location("sudo_failure_summary", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SudoFailureSummaryTests(unittest.TestCase):
    def write_log(self, directory, text):
        path = Path(directory) / "auth.log"
        path.write_text(text, encoding="utf-8")
        return path

    def test_counts_failures_without_counting_successes(self):
        with tempfile.TemporaryDirectory() as directory:
            log = self.write_log(directory, (
                "Nov 11 08:00:00 host sudo: alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id\n"
                "Nov 11 08:01:00 host sudo: alice : 3 incorrect password attempts ; TTY=pts/0\n"
                "Nov 11 08:02:00 host sudo: bob : user NOT in the sudoers file ; TTY=pts/1\n"
                "Nov 11 08:03:00 host sshd[123]: Failed password for alice\n"
            ))
            report = MODULE.audit(log)
            self.assertEqual(report["lines_scanned"], 4)
            self.assertEqual(report["sudo_failure_events"], 2)
            self.assertEqual(report["users"], {"alice": 1, "bob": 1})
            self.assertEqual(sum(report["failure_reasons"].values()), 2)

    def test_empty_and_unrecognized_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            log = self.write_log(directory, "unrelated message\n")
            report = MODULE.audit(log)
            self.assertEqual(report["sudo_failure_events"], 0)
            self.assertEqual(report["users"], {})

    def test_json_command_line_output(self):
        with tempfile.TemporaryDirectory() as directory:
            log = self.write_log(directory, (
                "Nov 11 08:00:00 host sudo[42]: alice : incorrect password\n"
            ))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(log), "--json"],
                capture_output=True, text=True, check=True,
            )
            report = json.loads(result.stdout)
            self.assertEqual(report["sudo_failure_events"], 1)
            self.assertEqual(report["users"], {"alice": 1})

    def test_missing_file_returns_error(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.log"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(missing)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("Unable to read log", result.stderr)


if __name__ == "__main__":
    unittest.main()
