import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from packlint import AuditInputError, AuditPolicy, scan_archive


class ZipAuditTests(unittest.TestCase):
    def test_safe_zip_passes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "safe.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
                handle.writestr("app/readme.txt", "hello")
            report = scan_archive(archive)
            self.assertEqual(report.status, "PASS")
            self.assertEqual(report.format, "zip")

    def test_parent_traversal_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "traversal.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("../escape.txt", "bad")
            report = scan_archive(archive)
            self.assertEqual(report.status, "FAIL")
            self.assertIn("PATH_TRAVERSAL", {item.code for item in report.findings})

    def test_zip_symlink_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "symlink.zip"
            info = zipfile.ZipInfo("latest")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(info, "target.txt")
            report = scan_archive(archive)
            self.assertIn("SYMLINK_ENTRY", {item.code for item in report.findings})

    def test_high_expansion_ratio_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "ratio.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
                handle.writestr("large.txt", b"A" * (2 * 1024 * 1024))
            report = scan_archive(archive, AuditPolicy(max_ratio=10))
            self.assertIn("ENTRY_RATIO_LIMIT", {item.code for item in report.findings})

    def test_nested_archive_warns(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "nested.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("payload.tar.gz", b"not really an archive")
            report = scan_archive(archive)
            self.assertEqual(report.status, "WARN")
            self.assertIn("NESTED_ARCHIVE", {item.code for item in report.findings})

    def test_entry_limit_stops_scan_and_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "many.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                for index in range(4):
                    handle.writestr(f"{index}.txt", "x")
            report = scan_archive(archive, AuditPolicy(max_entries=3))
            self.assertEqual(report.status, "FAIL")
            self.assertIn("TOO_MANY_ENTRIES", {item.code for item in report.findings})

    def test_central_directory_limit_fails_before_full_parse(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "metadata.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("a-long-entry-name.txt", "x")
            report = scan_archive(archive, AuditPolicy(max_metadata_size=16))
            self.assertEqual(report.status, "FAIL")
            self.assertIn(
                "METADATA_SIZE_LIMIT", {item.code for item in report.findings}
            )

    def test_eocd_entry_count_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "count.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("one.txt", "x")
            payload = bytearray(archive.read_bytes())
            eocd = payload.rfind(b"PK\x05\x06")
            payload[eocd + 8 : eocd + 12] = b"\x00\x00\x00\x00"
            archive.write_bytes(payload)
            with self.assertRaises(AuditInputError):
                scan_archive(archive)

    def test_invalid_utf8_filename_is_rejected_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "invalid-name.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("x", "content")
            payload = bytearray(archive.read_bytes())
            local = payload.find(b"PK\x03\x04")
            central = payload.find(b"PK\x01\x02")
            for header, flag_offset, name_offset in (
                (local, 6, 30),
                (central, 8, 46),
            ):
                flags = int.from_bytes(
                    payload[header + flag_offset : header + flag_offset + 2],
                    "little",
                )
                payload[header + flag_offset : header + flag_offset + 2] = (
                    flags | 0x800
                ).to_bytes(2, "little")
                payload[header + name_offset] = 0xFF
            archive.write_bytes(payload)
            with self.assertRaises(AuditInputError):
                scan_archive(archive)

    def test_zip64_sentinel_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "zip64-marker.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("one.txt", "x")
            payload = bytearray(archive.read_bytes())
            eocd = payload.rfind(b"PK\x05\x06")
            payload[eocd + 8 : eocd + 12] = b"\xff\xff\xff\xff"
            archive.write_bytes(payload)
            with self.assertRaises(AuditInputError):
                scan_archive(archive)

    def test_zip_type_bits_must_match_name_form(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "type-mismatch.zip"
            info = zipfile.ZipInfo("looks-like-a-file.txt")
            info.create_system = 3
            info.external_attr = (stat.S_IFDIR | 0o755) << 16
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(info, b"")
            report = scan_archive(archive)
            self.assertIn(
                "TYPE_NAME_MISMATCH", {item.code for item in report.findings}
            )


if __name__ == "__main__":
    unittest.main()
