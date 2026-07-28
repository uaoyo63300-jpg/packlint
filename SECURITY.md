# Security policy

PackLint never calls `extract()`, writes archive members to disk, or executes
archive content. ZIP scans read central-directory metadata. Compressed TAR scans
may decompress the stream far enough to reach each member header.

ZIP files are checked for an ambiguous TAR interpretation before their central
directory is parsed. The central directory also has a configurable byte limit.
Compressed TAR headers still require decompression by Python's standard-library
parser, so untrusted scans should run with an external memory limit and timeout.

If you find a path-handling bypass, parser crash, resource-exhaustion case, or
misclassified archive entry, use GitHub's private vulnerability reporting for
this repository. If private reporting is unavailable, open an issue that
describes the affected version and impact without attaching a live exploit.

Please include a minimal synthetic archive when it can be shared safely. Do not
include credentials, private source code, customer files, or personal data.

Security fixes are developed against the supported Python versions listed in
`pyproject.toml`. A passing PackLint report is not a guarantee that an archive is
benign; callers should still extract untrusted content inside a restricted
environment.
