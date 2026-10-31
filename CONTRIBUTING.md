# Contributing

Bug reports and pull requests are welcome. For anything large, open an issue first so we can agree on the approach.

A sample `.eml` that reproduces a wrong verdict is the most helpful bug report. Remove anything private from it before you share it.

Before you open a pull request, read `AGENTS.md`, which holds the project's rules, and run this.

```sh
make check
```

Checks must stay deterministic, every check returns its evidence, and a check that cannot run is skipped, never passed. Add a test with any change in behavior.
