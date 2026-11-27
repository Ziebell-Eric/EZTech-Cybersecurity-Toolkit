"""Regression checks using synthetic sysctl files, never the host kernel."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "kernel_audit", Path(__file__).resolve().parents[1] /
    "linux" / "kernel-hardening-audit.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class KernelHardeningTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for key, (minimum, _) in audit.BASELINE.items():
            self.write(key, str(minimum))

    def write(self, key, value):
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value + "\n", encoding="ascii")

    def run_cli(self):
        rows = audit.audit(self.root)
        output = io.StringIO()
        with patch.object(audit, "audit", return_value=rows), \
                patch("sys.argv", ["audit", "--json"]), redirect_stdout(output):
            code = audit.main()
        self.assertEqual(json.loads(output.getvalue()), rows)
        return code, rows

    def test_baseline_passes(self):
        code, rows = self.run_cli()
        self.assertEqual(code, 0)
        self.assertEqual(len(rows), len(audit.BASELINE))
        self.assertTrue(all(row["status"] == "pass" for row in rows))

    def test_weaker_aslr_requires_review(self):
        self.write("kernel/randomize_va_space", "1")
        code, rows = self.run_cli()
        self.assertEqual(code, 1)
        self.assertEqual(rows[0]["status"], "review")

    def test_stronger_pointer_restriction_passes(self):
        self.write("kernel/kptr_restrict", "2")
        self.assertEqual(self.run_cli()[0], 0)

    def test_invalid_values_are_errors(self):
        for value in ("garbage", "-1", "3", ""):
            with self.subTest(value=value):
                self.write("kernel/kptr_restrict", value)
                code, rows = self.run_cli()
                self.assertEqual(code, 2)
                self.assertEqual(rows[1]["status"], "error")

    def test_missing_setting_takes_precedence_over_review(self):
        self.write("kernel/randomize_va_space", "0")
        (self.root / "fs/protected_hardlinks").unlink()
        code, rows = self.run_cli()
        self.assertEqual(code, 2)
        self.assertEqual(rows[0]["status"], "review")
        self.assertEqual(rows[-1]["status"], "error")
        self.assertIsNone(rows[-1]["value"])


if __name__ == "__main__":
    unittest.main()
