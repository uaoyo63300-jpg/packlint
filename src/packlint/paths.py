"""Portable archive-path checks shared by ZIP and TAR scanners."""

from __future__ import annotations

import posixpath
import re
import unicodedata
from dataclasses import dataclass

_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


def _portable_parts(path: str) -> list[str]:
    return [
        unicodedata.normalize("NFC", part).rstrip(" .").casefold()
        for part in path.split("/")
    ]


class _PathNode:
    __slots__ = ("children", "kind")

    def __init__(self) -> None:
        self.children: dict[str, _PathNode] = {}
        self.kind: bool | None = None


@dataclass(frozen=True)
class PathIssue:
    severity: str
    code: str
    message: str


@dataclass(frozen=True)
class PathCheck:
    normalized: str
    issues: tuple[PathIssue, ...]


def check_member_path(name: str, *, max_length: int = 240) -> PathCheck:
    """Normalize an archive member name and report unsafe or non-portable forms."""
    issues: list[PathIssue] = []

    if "\x00" in name:
        issues.append(PathIssue("error", "NUL_IN_PATH", "Path contains a NUL byte"))

    if "\\" in name:
        issues.append(
            PathIssue(
                "warning",
                "BACKSLASH_PATH",
                "Path uses backslashes and may be interpreted differently across platforms",
            )
        )

    portable = name.replace("\\", "/")
    absolute_like = bool(
        portable.startswith("/") or portable.startswith("//") or _DRIVE_RE.match(portable)
    )
    if absolute_like:
        issues.append(
            PathIssue("error", "ABSOLUTE_PATH", "Path is absolute or drive-qualified")
        )

    raw_parts = portable.split("/")
    if ".." in raw_parts:
        issues.append(
            PathIssue("error", "PATH_TRAVERSAL", "Path contains a parent-directory segment")
        )

    for index, part in enumerate(raw_parts):
        if part in {"", ".", ".."}:
            continue
        if part.rstrip(" ") in {".", ".."}:
            issues.append(
                PathIssue(
                    "error",
                    "PATH_TRAVERSAL",
                    "Path contains a dot segment disguised with trailing spaces",
                )
            )
        if any(ord(character) < 32 or ord(character) == 127 for character in part):
            issues.append(
                PathIssue(
                    "error",
                    "CONTROL_CHARACTER",
                    "Path contains a control character",
                )
            )
        if ":" in part and not (
            index == 0 and re.fullmatch(r"[A-Za-z]:", part)
        ):
            issues.append(
                PathIssue(
                    "error",
                    "WINDOWS_ADS_PATH",
                    "Path contains a colon that may address a Windows data stream",
                )
            )
        if part.endswith((" ", ".")):
            issues.append(
                PathIssue(
                    "warning",
                    "WINDOWS_TRAILING_DOT_SPACE",
                    "Path component ends with a dot or space",
                )
            )
        reserved_base = part.rstrip(" .").split(".", 1)[0].upper()
        if reserved_base in _WINDOWS_RESERVED:
            issues.append(
                PathIssue(
                    "error",
                    "WINDOWS_RESERVED_NAME",
                    "Path uses a reserved Windows device name",
                )
            )

    if "." in raw_parts or "//" in portable:
        issues.append(
            PathIssue(
                "warning",
                "NON_CANONICAL_PATH",
                "Path contains redundant separators or dot segments",
            )
        )

    normalized = posixpath.normpath(portable)
    while normalized.startswith("./"):
        normalized = normalized[2:]

    if not absolute_like and (
        normalized.startswith("/") or _DRIVE_RE.match(normalized)
    ):
        issues.append(
            PathIssue("error", "ABSOLUTE_PATH", "Path resolves to an absolute path")
        )

    if normalized in {"", "."}:
        issues.append(PathIssue("error", "EMPTY_PATH", "Path resolves to an empty name"))

    if len(portable) > max_length:
        issues.append(
            PathIssue(
                "error",
                "LONG_PATH",
                f"Path length {len(portable)} exceeds the configured limit {max_length}",
            )
        )

    return PathCheck(normalized=normalized, issues=tuple(issues))


class PathRegistry:
    """Track normalized paths and portability collisions within one archive."""

    def __init__(self) -> None:
        self._raw_by_normalized: dict[str, str] = {}
        self._portable_by_key: dict[str, str] = {}
        self._root = _PathNode()

    def add(self, raw_name: str, normalized: str, *, is_dir: bool) -> list[PathIssue]:
        issues: list[PathIssue] = []

        previous = self._raw_by_normalized.get(normalized)
        if previous is not None:
            issues.append(
                PathIssue(
                    "error",
                    "DUPLICATE_PATH",
                    f"Path collides with another member: {previous!r}",
                )
            )
        else:
            self._raw_by_normalized[normalized] = raw_name

        portable_parts = _portable_parts(normalized)
        portable_key = "/".join(portable_parts)
        portable_previous = self._portable_by_key.get(portable_key)
        if portable_previous is not None and portable_previous != normalized:
            issues.append(
                PathIssue(
                    "warning",
                    "PORTABLE_PATH_COLLISION",
                    f"Path collides by case or Unicode normalization with {portable_previous!r}",
                )
            )
        else:
            self._portable_by_key[portable_key] = normalized

        node = self._root
        ancestor_conflict = False
        for index, part in enumerate(portable_parts):
            if index > 0 and node.kind is False:
                issues.append(
                    PathIssue(
                        "error",
                        "FILE_DIRECTORY_CONFLICT",
                        "A portable parent path is stored as a file",
                    )
                )
                ancestor_conflict = True
                break
            node = node.children.setdefault(part, _PathNode())

        if not ancestor_conflict and node.kind is not None and node.kind != is_dir:
            issues.append(
                PathIssue(
                    "error",
                    "FILE_DIRECTORY_CONFLICT",
                    "The same portable path is stored as both a file and a directory",
                )
            )

        if not ancestor_conflict and not is_dir and node.children:
            issues.append(
                PathIssue(
                    "error",
                    "FILE_DIRECTORY_CONFLICT",
                    "File path conflicts with an existing descendant",
                )
            )

        if not ancestor_conflict and node.kind is None:
            node.kind = is_dir
        return issues
