# Contributing

Bug reports and small, focused pull requests are welcome.

Before opening a pull request:

1. Add a test that demonstrates the archive pattern or regression.
2. Keep the runtime dependency list empty.
3. Run `PYTHONPATH=src python -m unittest discover -s tests -v`.
4. Update the README if a public option, output field, or finding code changes.

Tests that need hostile archives should construct them in a temporary directory
instead of committing opaque binary fixtures. Do not submit real malware,
credentials, private files, or customer data.
