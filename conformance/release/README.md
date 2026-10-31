# Release fixtures

Each package's download test serves these directories from a local web server, because a test must never reach GitHub. The version in the file names is `0.0.0-test`, and the archives have the layout `.goreleaser.yaml` produces.

- `good/` holds archives that match `pins.json`. Each one also has a `../evil` entry, which must never be written.
- `altered/` holds changed archives with a `checksums.txt` that agrees with them. A package must still refuse them, because it trusts its pins and never a file from the release, and it must leave nothing in its cache.
- `pins.json` holds what a package pins for `good/`, written by `go run ./scripts/pinhashes -fixture conformance/release/pins.json conformance/release/good`.

The binary inside is a shell script that prints `fake sendscore`.
