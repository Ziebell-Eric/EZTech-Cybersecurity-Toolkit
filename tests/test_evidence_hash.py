"""Regression checks for the read-only evidence manifest utility.

Run with: python -m unittest discover -s tests -p 'test_evidence_hash.py'
"""
import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "incident-response" / "evidence-hash.py"
spec = importlib.util.spec_from_file_location("evidence_hash", MODULE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class EvidenceManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.evidence = self.base / "evidence"
        self.evidence.mkdir()
        self.manifest = self.base / "manifest.sha256"

    def test_create_and_verify_nested_binary_evidence(self):
        nested = self.evidence / "nested"
        nested.mkdir()
        (nested / "capture.bin").write_bytes(b"\x00\xff\x01")
        (self.evidence / "notes.txt").write_text("case notes\n", encoding="utf-8")
        self.assertEqual(audit.create_manifest(self.evidence, self.manifest), 0)
        self.assertEqual(len(self.manifest.read_text().splitlines()), 2)
        self.assertEqual(audit.verify_manifest(self.evidence, self.manifest), 0)

    def test_tampering_is_detected(self):
        target = self.evidence / "evidence.txt"
        target.write_text("original", encoding="utf-8")
        self.assertEqual(audit.create_manifest(self.evidence, self.manifest), 0)
        target.write_text("altered", encoding="utf-8")
        self.assertEqual(audit.verify_manifest(self.evidence, self.manifest), 1)

    def test_missing_file_is_detected(self):
        target = self.evidence / "evidence.txt"
        target.write_bytes(b"data")
        self.assertEqual(audit.create_manifest(self.evidence, self.manifest), 0)
        target.unlink()
        self.assertEqual(audit.verify_manifest(self.evidence, self.manifest), 1)

    def test_manifest_path_traversal_is_rejected(self):
        outside = self.base / "outside.txt"
        outside.write_text("private", encoding="utf-8")
        self.manifest.write_text(f"{audit.sha256_file(outside)}  ../outside.txt\n", encoding="utf-8")
        self.assertEqual(audit.verify_manifest(self.evidence, self.manifest), 1)

    def test_malformed_manifest_line_is_rejected(self):
        self.manifest.write_text("not a valid manifest entry\n", encoding="utf-8")
        self.assertEqual(audit.verify_manifest(self.evidence, self.manifest), 1)

    def test_missing_directory_is_error(self):
        self.assertEqual(audit.create_manifest(self.base / "absent", self.manifest), 2)


if __name__ == "__main__":
    unittest.main()
