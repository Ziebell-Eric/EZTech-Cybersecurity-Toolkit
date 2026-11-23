"""Read-only regression tests for sudoers file and directory auditing."""
import importlib.util
import io
import json
import stat
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "linux" / "sudoers-permissions-audit.py"
spec = importlib.util.spec_from_file_location("sudoers_permissions_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class SudoersPermissionsAuditTests(unittest.TestCase):
    def inspect_mode(self, mode, uid=0):
        with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=mode, st_uid=uid)):
            return audit.inspect(Path("/etc/sudoers"))

    def test_secure_root_owned_file(self):
        result = self.inspect_mode(stat.S_IFREG | 0o440)
        self.assertEqual(result["findings"], [])
        self.assertIsNone(result["error"])

    def test_group_and_world_writable_file(self):
        result = self.inspect_mode(stat.S_IFREG | 0o666)
        self.assertIn("file is group- or world-writable", result["findings"])
        self.assertIn("file grants permissions to other users", result["findings"])

    def test_executable_file(self):
        self.assertIn("file is executable by owner", self.inspect_mode(stat.S_IFREG | 0o500)["findings"])

    def test_unexpected_owner(self):
        self.assertIn("not owned by root", self.inspect_mode(stat.S_IFREG | 0o440, uid=1000)["findings"])

    def test_secure_directory(self):
        self.assertEqual(self.inspect_mode(stat.S_IFDIR | 0o750)["findings"], [])

    def test_writable_directory(self):
        self.assertIn("directory is group- or world-writable", self.inspect_mode(stat.S_IFDIR | 0o777)["findings"])

    def test_symlink_is_reported_without_following(self):
        self.assertIn("symbolic link; target not inspected", self.inspect_mode(stat.S_IFLNK | 0o777)["findings"])

    def test_unexpected_file_type(self):
        self.assertIn("unexpected file type", self.inspect_mode(stat.S_IFIFO | 0o600)["findings"])

    def test_missing_path_is_inspection_error(self):
        with patch.object(Path, "lstat", side_effect=FileNotFoundError("missing")):
            result = audit.inspect(Path("/missing"))
        self.assertEqual(result["findings"], [])
        self.assertIn("missing", result["error"])

    def test_json_output_and_finding_exit_code(self):
        findings = [{"path": "/etc/sudoers", "findings": ["not owned by root"], "error": None}]
        output = io.StringIO()
        with patch.object(audit, "inspect", return_value=findings[0]), redirect_stdout(output):
            code = audit.main(["--json", "/etc/sudoers"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["results"], findings)

    def test_inspection_error_takes_precedence(self):
        results = iter([
            {"path": "/bad", "findings": ["not owned by root"], "error": None},
            {"path": "/missing", "findings": [], "error": "missing"},
        ])
        with patch.object(audit, "inspect", side_effect=lambda path: next(results)), redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main(["/bad", "/missing"]), 2)

    def test_clean_exit_code(self):
        with patch.object(audit, "inspect", return_value={"path": "/ok", "findings": [], "error": None}), redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main(["/ok"]), 0)


if __name__ == "__main__":
    unittest.main()
