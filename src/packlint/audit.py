"""Metadata-only ZIP and TAR archive auditing."""

from __future__ import annotations

import json
import math
import stat
import struct
import tarfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .paths import PathIssue, PathRegistry, check_member_path

_NESTED_ARCHIVE_SUFFIXES = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".7z",
    ".rar",
)


class AuditInputError(ValueError):
    """Raised when an input cannot be treated as a supported archive."""


@dataclass(frozen=True)
class AuditPolicy:
    max_entries: int = 100_000
    max_metadata_size: int = 64 * 1024 * 1024
    max_file_size: int = 512 * 1024 * 1024
    max_total_size: int = 2 * 1024 * 1024 * 1024
    max_ratio: float = 100.0
    max_path_length: int = 240

    def validate(self) -> None:
        for field_name in (
            "max_entries",
            "max_metadata_size",
            "max_file_size",
            "max_total_size",
            "max_path_length",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise AuditInputError(f"{field_name} must be greater than zero")
        if not isinstance(self.max_ratio, (int, float)) or isinstance(
            self.max_ratio, bool
        ):
            raise AuditInputError("max_ratio must be a finite number")
        ratio = float(self.max_ratio)
        if not math.isfinite(ratio):
            raise AuditInputError("max_ratio must be a finite number")
        if ratio <= 1:
            raise AuditInputError("max_ratio must be greater than one")


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    entry: str | None
    message: str


@dataclass(frozen=True)
class AuditReport:
    archive: str
    format: str
    archive_size: int
    entry_count: int
    total_uncompressed: int
    scan_complete: bool
    findings: tuple[Finding, ...]

    @property
    def status(self) -> str:
        if any(item.severity == "error" for item in self.findings):
            return "FAIL"
        if self.findings:
            return "WARN"
        return "PASS"

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "archive": self.archive,
            "format": self.format,
            "archive_size": self.archive_size,
            "entry_count": self.entry_count,
            "total_uncompressed": self.total_uncompressed,
            "scan_complete": self.scan_complete,
            "findings": [asdict(item) for item in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def _finding(issue: PathIssue, entry: str) -> Finding:
    return Finding(issue.severity, issue.code, entry, issue.message)


def _nested_archive_finding(name: str, *, is_dir: bool) -> Finding | None:
    if is_dir:
        return None
    lowered = name.casefold()
    if lowered.endswith(_NESTED_ARCHIVE_SUFFIXES):
        return Finding(
            "warning",
            "NESTED_ARCHIVE",
            name,
            "Filename has an archive-like suffix; nested content was not inspected",
        )
    return None


def _apply_common_limits(
    *,
    archive_size: int,
    entry_count: int,
    total_uncompressed: int,
    policy: AuditPolicy,
    findings: list[Finding],
    ratio_supported: bool,
) -> None:
    existing_codes = {item.code for item in findings}
    if entry_count > policy.max_entries and "TOO_MANY_ENTRIES" not in existing_codes:
        findings.append(
            Finding(
                "error",
                "TOO_MANY_ENTRIES",
                None,
                f"Entry count {entry_count} exceeds limit {policy.max_entries}",
            )
        )
    if (
        total_uncompressed > policy.max_total_size
        and "TOTAL_SIZE_LIMIT" not in existing_codes
    ):
        findings.append(
            Finding(
                "error",
                "TOTAL_SIZE_LIMIT",
                None,
                f"Uncompressed size {total_uncompressed} exceeds limit "
                f"{policy.max_total_size}",
            )
        )
    if ratio_supported and total_uncompressed >= 1024 * 1024:
        ratio = total_uncompressed / max(archive_size, 1)
        if (
            ratio > policy.max_ratio
            and "ARCHIVE_RATIO_LIMIT" not in existing_codes
        ):
            findings.append(
                Finding(
                    "error",
                    "ARCHIVE_RATIO_LIMIT",
                    None,
                    f"Overall expansion ratio {ratio:.1f} exceeds limit "
                    f"{policy.max_ratio:.1f}",
                )
            )


def _read_zip_directory_summary(
    path: Path, policy: AuditPolicy
) -> tuple[int, int]:
    """Bound and count the central directory before ZipFile allocates ZipInfo objects."""
    eocd_signature = b"PK\x05\x06"
    eocd_size = 22
    max_tail = eocd_size + 65_535
    central_header = struct.Struct("<4s6H3L5H2L")

    try:
        archive_size = path.stat().st_size
        with path.open("rb") as handle:
            tail_start = max(archive_size - max_tail, 0)
            handle.seek(tail_start)
            tail = handle.read(max_tail)
    except OSError as exc:
        raise AuditInputError(f"cannot preflight ZIP archive: {exc}") from exc

    search_end = len(tail)
    while search_end:
        offset = tail.rfind(eocd_signature, 0, search_end)
        if offset < 0:
            break
        if len(tail) - offset >= eocd_size:
            fields = struct.unpack("<4s4H2LH", tail[offset : offset + eocd_size])
            comment_length = fields[-1]
            if offset + eocd_size + comment_length == len(tail):
                disk_number = fields[1]
                directory_disk = fields[2]
                entries_on_disk = fields[3]
                entry_count = fields[4]
                directory_size = fields[5]
                directory_offset = fields[6]
                if disk_number or directory_disk or entries_on_disk != entry_count:
                    raise AuditInputError("multi-disk ZIP archives are not supported")
                if (
                    entry_count == 0xFFFF
                    or directory_size == 0xFFFFFFFF
                    or directory_offset == 0xFFFFFFFF
                ):
                    raise AuditInputError(
                        "ZIP64 central-directory sentinels are not supported"
                    )
                if (
                    entry_count > policy.max_entries
                    or directory_size > policy.max_metadata_size
                ):
                    return entry_count, directory_size

                eocd_absolute = tail_start + offset
                directory_start = eocd_absolute - directory_size
                if (
                    directory_start < 0
                    or directory_offset > directory_start
                ):
                    raise AuditInputError("ZIP central-directory offset is invalid")

                actual_entries = 0
                remaining = directory_size
                try:
                    with path.open("rb") as archive:
                        archive.seek(directory_start)
                        while remaining:
                            if remaining < central_header.size:
                                raise AuditInputError(
                                    "ZIP central directory ends inside a record"
                                )
                            header = archive.read(central_header.size)
                            if len(header) != central_header.size:
                                raise AuditInputError(
                                    "ZIP central directory is truncated"
                                )
                            fields = central_header.unpack(header)
                            if fields[0] != b"PK\x01\x02":
                                raise AuditInputError(
                                    "ZIP central-directory signature is invalid"
                                )
                            variable_size = fields[10] + fields[11] + fields[12]
                            record_size = central_header.size + variable_size
                            if record_size > remaining:
                                raise AuditInputError(
                                    "ZIP central-directory record exceeds its boundary"
                                )
                            archive.seek(variable_size, 1)
                            remaining -= record_size
                            actual_entries += 1
                            if actual_entries > policy.max_entries:
                                return actual_entries, directory_size
                except OSError as exc:
                    raise AuditInputError(
                        f"cannot preflight ZIP central directory: {exc}"
                    ) from exc

                if actual_entries != entry_count:
                    raise AuditInputError(
                        "ZIP central-directory entry count does not match EOCD"
                    )
                return actual_entries, directory_size
        search_end = offset

    raise AuditInputError("cannot locate a valid ZIP end-of-central-directory record")


def _scan_zip(path: Path, policy: AuditPolicy) -> AuditReport:
    findings: list[Finding] = []
    registry = PathRegistry()
    total_uncompressed = 0
    entry_count = 0
    archive_size = path.stat().st_size
    expected_entries, metadata_size = _read_zip_directory_summary(path, policy)

    if expected_entries > policy.max_entries:
        findings.append(
            Finding(
                "error",
                "TOO_MANY_ENTRIES",
                None,
                f"Entry count {expected_entries} exceeds limit {policy.max_entries}",
            )
        )
    if metadata_size > policy.max_metadata_size:
        findings.append(
            Finding(
                "error",
                "METADATA_SIZE_LIMIT",
                None,
                f"Central directory size {metadata_size} exceeds limit "
                f"{policy.max_metadata_size}",
            )
        )
    if findings:
        return AuditReport(
            archive=str(path),
            format="zip",
            archive_size=archive_size,
            entry_count=expected_entries,
            total_uncompressed=0,
            scan_complete=False,
            findings=tuple(findings),
        )

    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) != expected_entries:
                raise AuditInputError(
                    "ZIP parser entry count does not match central-directory preflight"
                )
            for entry_count, info in enumerate(entries, start=1):
                name = info.filename
                is_dir = info.is_dir()
                total_uncompressed += info.file_size

                checked = check_member_path(name, max_length=policy.max_path_length)
                findings.extend(_finding(issue, name) for issue in checked.issues)
                if not any(issue.severity == "error" for issue in checked.issues):
                    findings.extend(
                        _finding(issue, name)
                        for issue in registry.add(
                            name, checked.normalized, is_dir=is_dir
                        )
                    )

                if info.file_size > policy.max_file_size:
                    findings.append(
                        Finding(
                            "error",
                            "FILE_SIZE_LIMIT",
                            name,
                            f"Uncompressed size {info.file_size} exceeds limit "
                            f"{policy.max_file_size}",
                        )
                    )

                if info.flag_bits & 0x1:
                    findings.append(
                        Finding(
                            "error",
                            "ENCRYPTED_ENTRY",
                            name,
                            "Encrypted entries cannot be inspected reliably",
                        )
                    )

                mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if file_type == stat.S_IFLNK:
                    findings.append(
                        Finding(
                            "error",
                            "SYMLINK_ENTRY",
                            name,
                            "Symbolic links are unsafe for unattended extraction",
                        )
                    )
                elif (
                    file_type not in {0, stat.S_IFREG, stat.S_IFDIR}
                ):
                    findings.append(
                        Finding(
                            "error",
                            "SPECIAL_FILE",
                            name,
                            "Entry represents a non-regular filesystem object",
                        )
                    )
                elif (
                    (file_type == stat.S_IFDIR and not is_dir)
                    or (file_type == stat.S_IFREG and is_dir)
                ):
                    findings.append(
                        Finding(
                            "error",
                            "TYPE_NAME_MISMATCH",
                            name,
                            "ZIP type bits conflict with the trailing-slash name form",
                        )
                    )

                if not is_dir and info.file_size > 0 and info.compress_size == 0:
                    findings.append(
                        Finding(
                            "error",
                            "ZERO_COMPRESSED_SIZE",
                            name,
                            "Non-empty entry reports zero compressed bytes",
                        )
                    )

                if not is_dir and info.file_size >= 1024 * 1024:
                    ratio = info.file_size / max(info.compress_size, 1)
                    if ratio > policy.max_ratio:
                        findings.append(
                            Finding(
                                "error",
                                "ENTRY_RATIO_LIMIT",
                                name,
                                f"Expansion ratio {ratio:.1f} exceeds limit "
                                f"{policy.max_ratio:.1f}",
                            )
                        )

                nested = _nested_archive_finding(name, is_dir=is_dir)
                if nested is not None:
                    findings.append(nested)

    except AuditInputError:
        raise
    except (OSError, UnicodeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise AuditInputError(f"cannot read ZIP archive: {exc}") from exc

    _apply_common_limits(
        archive_size=archive_size,
        entry_count=entry_count,
        total_uncompressed=total_uncompressed,
        policy=policy,
        findings=findings,
        ratio_supported=True,
    )
    return AuditReport(
        archive=str(path),
        format="zip",
        archive_size=archive_size,
        entry_count=entry_count,
        total_uncompressed=total_uncompressed,
        scan_complete=True,
        findings=tuple(findings),
    )


def _scan_tar(path: Path, policy: AuditPolicy) -> AuditReport:
    findings: list[Finding] = []
    registry = PathRegistry()
    total_uncompressed = 0
    entry_count = 0
    archive_size = path.stat().st_size
    scan_complete = True

    try:
        with tarfile.open(path, mode="r:*") as archive:
            for entry_count, member in enumerate(archive, start=1):
                if entry_count > policy.max_entries:
                    scan_complete = False
                    break

                name = member.name
                is_dir = member.isdir()
                total_uncompressed += max(member.size, 0)

                checked = check_member_path(name, max_length=policy.max_path_length)
                findings.extend(_finding(issue, name) for issue in checked.issues)
                if not any(issue.severity == "error" for issue in checked.issues):
                    findings.extend(
                        _finding(issue, name)
                        for issue in registry.add(
                            name, checked.normalized, is_dir=is_dir
                        )
                    )

                if member.size > policy.max_file_size:
                    findings.append(
                        Finding(
                            "error",
                            "FILE_SIZE_LIMIT",
                            name,
                            f"Uncompressed size {member.size} exceeds limit "
                            f"{policy.max_file_size}",
                        )
                    )
                ratio_exceeded = (
                    total_uncompressed >= 1024 * 1024
                    and total_uncompressed / max(archive_size, 1) > policy.max_ratio
                )
                if ratio_exceeded:
                    ratio = total_uncompressed / max(archive_size, 1)
                    findings.append(
                        Finding(
                            "error",
                            "ARCHIVE_RATIO_LIMIT",
                            None,
                            f"Overall expansion ratio {ratio:.1f} exceeds limit "
                            f"{policy.max_ratio:.1f}",
                        )
                    )
                if (
                    member.size > policy.max_file_size
                    or total_uncompressed > policy.max_total_size
                    or ratio_exceeded
                ):
                    scan_complete = False
                    findings.append(
                        Finding(
                            "warning",
                            "SCAN_STOPPED",
                            name,
                            "Scanning stopped after a declared resource limit was exceeded",
                        )
                    )
                    break

                if member.issym():
                    findings.append(
                        Finding(
                            "error",
                            "SYMLINK_ENTRY",
                            name,
                            f"Symbolic link points to {member.linkname!r}",
                        )
                    )
                elif member.islnk():
                    findings.append(
                        Finding(
                            "error",
                            "HARDLINK_ENTRY",
                            name,
                            f"Hard link points to {member.linkname!r}",
                        )
                    )
                elif not (member.isfile() or member.isdir()):
                    findings.append(
                        Finding(
                            "error",
                            "SPECIAL_FILE",
                            name,
                            "Entry represents a non-regular filesystem object",
                        )
                    )

                nested = _nested_archive_finding(name, is_dir=is_dir)
                if nested is not None:
                    findings.append(nested)

    except (OSError, tarfile.TarError, EOFError) as exc:
        raise AuditInputError(f"cannot read TAR archive: {exc}") from exc

    _apply_common_limits(
        archive_size=archive_size,
        entry_count=entry_count,
        total_uncompressed=total_uncompressed,
        policy=policy,
        findings=findings,
        ratio_supported=True,
    )
    return AuditReport(
        archive=str(path),
        format="tar",
        archive_size=archive_size,
        entry_count=entry_count,
        total_uncompressed=total_uncompressed,
        scan_complete=scan_complete,
        findings=tuple(findings),
    )


def scan_archive(
    archive_path: str | Path, policy: AuditPolicy | None = None
) -> AuditReport:
    """Audit one ZIP or TAR archive without extracting its entries."""
    path = Path(archive_path)
    selected_policy = policy or AuditPolicy()
    selected_policy.validate()

    if not path.is_file():
        raise AuditInputError(f"archive does not exist or is not a file: {path}")

    try:
        is_zip = zipfile.is_zipfile(path)
        is_tar = tarfile.is_tarfile(path)
        if is_zip and is_tar:
            raise AuditInputError(
                "archive is valid as both ZIP and TAR; ambiguous polyglot input rejected"
            )
        if is_zip:
            return _scan_zip(path, selected_policy)
        if is_tar:
            return _scan_tar(path, selected_policy)
    except OSError as exc:
        raise AuditInputError(f"cannot inspect archive: {exc}") from exc

    raise AuditInputError("unsupported or invalid archive; expected ZIP or TAR")


def format_findings(findings: Iterable[Finding]) -> list[str]:
    lines: list[str] = []
    for item in findings:
        escaped_entry = (
            json.dumps(item.entry, ensure_ascii=False)[1:-1]
            if item.entry is not None
            else None
        )
        location = f" [{escaped_entry}]" if escaped_entry is not None else ""
        lines.append(f"{item.severity.upper()} {item.code}{location}: {item.message}")
    return lines
