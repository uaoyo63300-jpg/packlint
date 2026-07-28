"""Command-line interface for PackLint."""

from __future__ import annotations

import argparse
import json
import math
import sys

from . import __version__
from .audit import AuditInputError, AuditPolicy, format_findings, scan_archive


def _terminal_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)[1:-1]


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _ratio(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 1:
        raise argparse.ArgumentTypeError("must be greater than one")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packlint",
        description="Inspect ZIP and TAR metadata for unsafe extraction patterns.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan one ZIP or TAR archive")
    scan.add_argument("archive", help="path to the archive")
    scan.add_argument("--json", action="store_true", help="print machine-readable JSON")
    scan.add_argument(
        "--strict",
        action="store_true",
        help="return exit code 1 for warnings as well as errors",
    )
    scan.add_argument("--max-entries", type=_positive_int, default=100_000)
    scan.add_argument(
        "--max-metadata-size",
        type=_positive_int,
        default=64 * 1024 * 1024,
        metavar="BYTES",
    )
    scan.add_argument(
        "--max-file-size",
        type=_positive_int,
        default=512 * 1024 * 1024,
        metavar="BYTES",
    )
    scan.add_argument(
        "--max-total-size",
        type=_positive_int,
        default=2 * 1024 * 1024 * 1024,
        metavar="BYTES",
    )
    scan.add_argument("--max-ratio", type=_ratio, default=100.0)
    scan.add_argument("--max-path-length", type=_positive_int, default=240)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    policy = AuditPolicy(
        max_entries=args.max_entries,
        max_metadata_size=args.max_metadata_size,
        max_file_size=args.max_file_size,
        max_total_size=args.max_total_size,
        max_ratio=args.max_ratio,
        max_path_length=args.max_path_length,
    )

    try:
        report = scan_archive(args.archive, policy)
    except AuditInputError as exc:
        if args.json:
            print(f'{{"status":"ERROR","message":{_json_string(str(exc))}}}')
        else:
            print(f"packlint: {_terminal_string(str(exc))}", file=sys.stderr)
        return 2

    if args.json:
        print(report.to_json())
    else:
        completion = "complete" if report.scan_complete else "stopped early"
        print(
            f"{report.status} {_terminal_string(report.archive)} "
            f"({report.format}, {report.entry_count} entries, "
            f"{report.total_uncompressed} declared uncompressed bytes, {completion})"
        )
        for line in format_findings(report.findings):
            print(line)

    if report.status == "FAIL":
        return 1
    if report.status == "WARN" and args.strict:
        return 1
    return 0


def _json_string(value: str) -> str:
    return json.dumps(value)


def entrypoint() -> None:
    raise SystemExit(main())
