import unittest

from packlint.paths import PathRegistry, check_member_path


class PathCheckTests(unittest.TestCase):
    def test_safe_relative_path(self):
        checked = check_member_path("folder/file.txt")
        self.assertEqual(checked.normalized, "folder/file.txt")
        self.assertEqual(checked.issues, ())

    def test_parent_traversal_is_error(self):
        checked = check_member_path("folder/../../escape.txt")
        self.assertIn("PATH_TRAVERSAL", {issue.code for issue in checked.issues})

    def test_windows_drive_path_is_error(self):
        checked = check_member_path(r"C:\Windows\file.txt")
        codes = {issue.code for issue in checked.issues}
        self.assertIn("ABSOLUTE_PATH", codes)
        self.assertIn("BACKSLASH_PATH", codes)

    def test_case_collision_is_warning(self):
        registry = PathRegistry()
        self.assertEqual(registry.add("Readme", "Readme", is_dir=False), [])
        issues = registry.add("README", "README", is_dir=False)
        self.assertIn("PORTABLE_PATH_COLLISION", {issue.code for issue in issues})

    def test_file_directory_conflict(self):
        registry = PathRegistry()
        registry.add("config", "config", is_dir=False)
        issues = registry.add("config/app.ini", "config/app.ini", is_dir=False)
        self.assertIn("FILE_DIRECTORY_CONFLICT", {issue.code for issue in issues})

    def test_file_directory_conflict_in_reverse_order(self):
        registry = PathRegistry()
        registry.add("config/app.ini", "config/app.ini", is_dir=False)
        issues = registry.add("config", "config", is_dir=False)
        self.assertIn("FILE_DIRECTORY_CONFLICT", {issue.code for issue in issues})

    def test_dot_prefixed_drive_path_is_error(self):
        checked = check_member_path("./C:/Windows/file.txt")
        self.assertIn("ABSOLUTE_PATH", {issue.code for issue in checked.issues})

    def test_windows_reserved_name_is_error(self):
        checked = check_member_path("docs/CON.txt")
        self.assertIn(
            "WINDOWS_RESERVED_NAME", {issue.code for issue in checked.issues}
        )

    def test_windows_data_stream_path_is_error(self):
        checked = check_member_path("docs/report.txt:payload")
        self.assertIn("WINDOWS_ADS_PATH", {issue.code for issue in checked.issues})

    def test_casefolded_parent_file_conflict_is_error(self):
        registry = PathRegistry()
        registry.add("Foo", "Foo", is_dir=False)
        issues = registry.add("foo/bar.txt", "foo/bar.txt", is_dir=False)
        self.assertIn("FILE_DIRECTORY_CONFLICT", {issue.code for issue in issues})

    def test_trailing_space_parent_segment_is_traversal(self):
        checked = check_member_path(".. /.. /escape.txt")
        self.assertIn("PATH_TRAVERSAL", {issue.code for issue in checked.issues})

    def test_path_over_limit_is_error(self):
        checked = check_member_path("folder/" + "x" * 32, max_length=16)
        issues = {issue.code: issue.severity for issue in checked.issues}
        self.assertEqual(issues["LONG_PATH"], "error")

    def test_deep_registry_path_is_handled_iteratively(self):
        normalized = "/".join(["a"] * 5_000)
        registry = PathRegistry()
        self.assertEqual(registry.add(normalized, normalized, is_dir=False), [])


if __name__ == "__main__":
    unittest.main()
