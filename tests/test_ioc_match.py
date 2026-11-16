"""Regression checks for the offline IOC matching command."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "incident-response" / "ioc-match.py"


class IOCMatchTests(unittest.TestCase):
    def run_matcher(self, indicators, targets):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ioc_file = root / "indicators.txt"
            ioc_file.write_text(indicators, encoding="utf-8")
            paths = []
            for index, body in enumerate(targets):
                target = root / f"target-{index}.log"
                target.write_text(body, encoding="utf-8")
                paths.append(str(target))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(ioc_file), *paths],
                capture_output=True, text=True, timeout=10, check=False,
            )
            return result

    def test_case_insensitive_matches(self):
        result = self.run_matcher("EXAMPLE.COM\n", ["Request to example.com\n"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("example.com", result.stdout)
        self.assertIn("Matches: 1", result.stdout)

    def test_comments_are_not_indicators(self):
        result = self.run_matcher("# ignore-me\nmalware.test\n", ["ignore-me\n"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Matches: 0", result.stdout)

    def test_blank_lines_are_ignored(self):
        result = self.run_matcher("\n \nindicator\n", ["unrelated\n"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Matches: 0", result.stdout)

    def test_multiple_targets_and_line_numbers(self):
        result = self.run_matcher("needle\n", ["nothing\nneedle\n", "needle\n"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("target-0.log:2:", result.stdout)
        self.assertIn("target-1.log:1:", result.stdout)
        self.assertIn("Matches: 2", result.stdout)

    def test_no_match(self):
        result = self.run_matcher("indicator\n", ["safe activity\n"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Matches: 0", result.stdout)


if __name__ == "__main__":
    unittest.main()
