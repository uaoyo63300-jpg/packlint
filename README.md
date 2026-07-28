# PackLint

PackLint checks ZIP and TAR metadata for patterns that can make unattended
extraction unsafe. It does not extract files and has no runtime dependencies
outside the Python standard library.

The current checks cover:

- parent-directory traversal and absolute paths;
- ZIP symbolic links, TAR symbolic and hard links, and special files;
- duplicate paths, file/directory conflicts, and portable path collisions;
- Windows device names, alternate data stream paths, and trailing dots or spaces;
- per-file and total declared-uncompressed-size limits;
- ZIP central-directory size limits and ambiguous ZIP/TAR polyglots;
- suspicious expansion ratios and archive-like filename suffixes;
- encrypted ZIP entries that cannot be inspected reliably.

## Install

PackLint requires Python 3.10 or newer.

```bash
git clone https://github.com/uaoyo63300-jpg/packlint.git
cd packlint
python -m pip install -e .
```

## Use

Scan a ZIP, TAR, TAR.GZ, TAR.BZ2, or TAR.XZ file:

```bash
packlint scan release.zip
packlint scan source.tar.gz
```

Use `--strict` when warnings should fail a CI job:

```bash
packlint scan release.zip --strict
```

Request stable JSON output:

```bash
packlint scan release.zip --json
```

JSON reports include `scan_complete`. A value of `false` means a policy limit
stopped parsing before every member was visited.

Example:

```text
FAIL unsafe.zip (zip, 1 entries, 3 declared uncompressed bytes, complete)
ERROR PATH_TRAVERSAL [../outside.txt]: Path contains a parent-directory segment
```

The process exits with code `0` when the archive passes. Exit code `1` means an
error was found, or a warning was found while `--strict` was enabled. Input and
format errors use exit code `2`.

## Policy limits

The defaults are conservative starting points, not universal extraction limits.
Each value can be changed on the command line. Paths longer than the configured
limit are rejected rather than entered into collision tracking.

| Option | Default |
| --- | ---: |
| `--max-entries` | 100,000 |
| `--max-metadata-size` | 67,108,864 bytes |
| `--max-file-size` | 536,870,912 bytes |
| `--max-total-size` | 2,147,483,648 bytes |
| `--max-ratio` | 100 |
| `--max-path-length` | 240 characters |

Run `packlint scan --help` for the complete command reference.

## What PackLint does not prove

PackLint is a metadata linter, not an antivirus engine, digital-signature
verifier, or safe extraction sandbox. ZIP expansion checks depend on central
directory metadata, which a hostile archive may falsify. Compressed TAR files
must be read far enough to enumerate their headers. ZIP64 central-directory
sentinels and multi-disk ZIP files are rejected in version 0.1.0.

Treat a passing report as one input to an extraction policy. Keep operating
system permissions, memory and disk quotas, timeouts, and an isolated extraction
directory in place when processing untrusted archives.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m packlint --version
```

PackLint is at version `0.1.0`. The archive checks and JSON fields may expand in
later releases, but existing finding codes will not be renamed without a
documented compatibility note.

## License

MIT. See [LICENSE](LICENSE).
