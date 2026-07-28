import io
import json
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

from packlint import AuditInputError, AuditPolicy, Finding
from packlint.audit import format_findings
from packlint.cli import main


class CliTests(unittest.TestCase):
    def test_json_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "safe.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("file.txt", "content")
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["scan", str(archive), "--json"])
            payload = json.loads(output.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(payload["status"], "PASS")
            self.assertTrue(payload["scan_complete"])

    def test_invalid_archive_returns_two(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "plain.txt"
            source.write_text("not an archive", encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["scan", str(source), "--json"])
            payload = json.loads(output.getvalue())
            self.assertEqual(code, 2)
            self.assertEqual(payload["status"], "ERROR")

    def test_strict_warning_returns_one(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "nested.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("inner.zip", b"x")
            with redirect_stdout(io.StringIO()):
                code = main(["scan", str(archive), "--strict"])
            self.assertEqual(code, 1)

    def test_non_finite_ratio_is_rejected(self):
        for ratio in (float("nan"), float("inf"), float("-inf"), "10"):
            with self.subTest(ratio=ratio):
                with self.assertRaises(AuditInputError):
                    AuditPolicy(max_ratio=ratio).validate()

    def test_human_output_escapes_entry_control_characters(self):
        finding = Finding("error", "TEST", "line\n\x1b[31mname", "message")
        line = format_findings([finding])[0]
        self.assertIn(r"line\n\u001b[31mname", line)
        self.assertNotIn("\n", line)

    def test_human_output_escapes_archive_control_characters(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "line\nbreak.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("file.txt", "content")
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["scan", str(archive)])
            self.assertEqual(code, 0)
            self.assertIn(r"line\nbreak.zip", output.getvalue())
            self.assertEqual(output.getvalue().count("\n"), 1)


if __name__ == "__main__":
    unittest.main()
