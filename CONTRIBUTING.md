# Contributing

Bug reports and pull requests are welcome. For anything large, open an issue first so we can agree on the approach.

A sample `.eml` that reproduces a wrong verdict is the most helpful bug report. Remove anything private from it before you share it.

Before you open a pull request, read `AGENTS.md`, which holds the project's rules, and run this.

```sh
make check
```

Checks must stay deterministic, every check returns its evidence, and a check that cannot run is skipped, never passed. Add a test with any change in behavior.

## Packages

`packages/` holds one thin wrapper per language around this CLI, and each runs the binary, so no check is ever written twice. A change to a check needs no change there unless the JSON gains a field worth typing.

`conformance/cases.json` records what every package must return. After a change in the engine, run this and read the diff.

```sh
go test . -run TestConformance -update
```

## Releasing

Every package has the same version as the CLI, and pins that version in a constant it downloads when no CLI is installed, so a package only ever runs a CLI it was tested against. `TestPackageVersions` fails if any of them disagree, so a new version changes all of them in one commit, along with the `want` constant in that test.

The tag comes after that commit. Tagging creates a draft GitHub release with the binaries, and the packages can only be published once that release is public, because they download from it.
