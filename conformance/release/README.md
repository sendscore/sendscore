# Release fixtures

Each package's download test serves these directories from a local web server, because a test must never reach GitHub. The version in the file names is `0.0.0-test`, and the archives have the layout `.goreleaser.yaml` produces.

- `good/` holds archives that match `checksums.txt`. Each one also has a `../evil` entry, which must never be written.
- `tampered/` holds the same archives with a `checksums.txt` that does not match, so a package must refuse them and leave nothing in its cache.

The binary inside is a shell script that prints `fake sendscore`.
