import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from packlint import AuditInputError, AuditPolicy, scan_archive


class TarAuditTests(unittest.TestCase):
    def test_safe_tar_passes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "safe.tar.gz"
            content = b"hello"
            info = tarfile.TarInfo("app/readme.txt")
            info.size = len(content)
            with tarfile.open(archive, "w:gz") as handle:
                handle.addfile(info, io.BytesIO(content))
            report = scan_archive(archive)
            self.assertEqual(report.status, "PASS")
            self.assertEqual(report.format, "tar")

    def test_tar_traversal_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "traversal.tar"
            info = tarfile.TarInfo("../../escape.txt")
            info.size = 1
            with tarfile.open(archive, "w") as handle:
                handle.addfile(info, io.BytesIO(b"x"))
            report = scan_archive(archive)
            self.assertIn("PATH_TRAVERSAL", {item.code for item in report.findings})

    def test_tar_hardlink_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "hardlink.tar"
            info = tarfile.TarInfo("linked")
            info.type = tarfile.LNKTYPE
            info.linkname = "../../outside"
            with tarfile.open(archive, "w") as handle:
                handle.addfile(info)
            report = scan_archive(archive)
            self.assertIn("HARDLINK_ENTRY", {item.code for item in report.findings})

    def test_tar_special_file_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "fifo.tar"
            info = tarfile.TarInfo("pipe")
            info.type = tarfile.FIFOTYPE
            with tarfile.open(archive, "w") as handle:
                handle.addfile(info)
            report = scan_archive(archive)
            self.assertIn("SPECIAL_FILE", {item.code for item in report.findings})

    def test_entry_limit_stops_scan_and_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "many.tar"
            with tarfile.open(archive, "w") as handle:
                for index in range(4):
                    info = tarfile.TarInfo(f"{index}.txt")
                    info.size = 1
                    handle.addfile(info, io.BytesIO(b"x"))
            report = scan_archive(archive, AuditPolicy(max_entries=3))
            self.assertEqual(report.status, "FAIL")
            self.assertIn("TOO_MANY_ENTRIES", {item.code for item in report.findings})

    def test_declared_size_limit_stops_tar_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "large.tar"
            content = b"x" * 32
            info = tarfile.TarInfo("large.bin")
            info.size = len(content)
            with tarfile.open(archive, "w") as handle:
                handle.addfile(info, io.BytesIO(content))
            report = scan_archive(archive, AuditPolicy(max_file_size=16))
            codes = {item.code for item in report.findings}
            self.assertIn("FILE_SIZE_LIMIT", codes)
            self.assertIn("SCAN_STOPPED", codes)

    def test_zip_tar_polyglot_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "polyglot.bin"
            info = tarfile.TarInfo("../../escape.txt")
            info.size = 1
            with tarfile.open(archive, "w") as handle:
                handle.addfile(info, io.BytesIO(b"x"))
            with zipfile.ZipFile(archive, "a") as handle:
                handle.writestr("safe.txt", "safe")
            self.assertTrue(tarfile.is_tarfile(archive))
            self.assertTrue(zipfile.is_zipfile(archive))
            with self.assertRaises(AuditInputError):
                scan_archive(archive)

    def test_tar_ratio_limit_stops_before_next_member(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "ratio.tar.gz"
            content = b"A" * (2 * 1024 * 1024)
            info = tarfile.TarInfo("large.txt")
            info.size = len(content)
            with tarfile.open(archive, "w:gz") as handle:
                handle.addfile(info, io.BytesIO(content))
            report = scan_archive(archive, AuditPolicy(max_ratio=10))
            codes = {item.code for item in report.findings}
            self.assertIn("ARCHIVE_RATIO_LIMIT", codes)
            self.assertIn("SCAN_STOPPED", codes)
            self.assertFalse(report.scan_complete)


if __name__ == "__main__":
    unittest.main()
