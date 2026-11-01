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

Every package has the same version as the CLI. `packageVersion` in `packages_test.go` names it, and `TestPackageVersions` fails if any package disagrees, so a new version changes all of them in one commit. A package only ever runs a CLI of that version, unless `SENDSCORE_BIN` says otherwise. The release workflow runs the same test, so a tag that differs from `packageVersion` stops the release.

Go serves a tag forever once anyone has fetched it, so a tag is never moved. If one was wrong, release the next version.

A package trusts the SHA-256 values committed in its own hashes file, not `checksums.txt`, because anyone who could replace a release file could replace that too. Before a release those files are empty, and a package refuses to download anything, which is why the hashes come after the tag.

1. Commit the new version everywhere, with `go run ./scripts/pinhashes -clear`.
2. Tag that commit and push the tag. The release workflow makes a draft GitHub release.
3. Look over the draft, then pin it.

   ```sh
   gh release download v0.3.0 --dir /tmp/release
   go run ./scripts/pinhashes /tmp/release
   ```

4. Commit and push the hashes. The script refuses a file that does not match `checksums.txt`, and `TestPackagePins` checks that all eight packages agree.
5. Publish the GitHub release, because packages download from it, and turn on immutable releases for the repository so its files cannot change afterward.
6. Publish the packages from the commit with the hashes. For npm and PyPI, run the Publish packages workflow with the version.

   ```sh
   gh workflow run publish.yml -f version=0.3.0
   ```

### Registries

crates.io, RubyGems, NuGet, and Hex publish from their `packages/` directories.

npm and PyPI carry the binary, so they publish what `scripts/buildpackages` makes from the release files, never `packages/sdk` or `packages/python` themselves. The script refuses an archive that does not match the committed hashes. It writes one `@sendscore/cli-<os>-<arch>` package per platform, the `sendscore` package that names them in `optionalDependencies`, and one wheel per platform. There is no source distribution, because it would have no binary. `-local` builds from a checkout for `scripts/test-bundled.sh`, and those files are never published.

The workflow needs a GitHub environment named `release`, which should require a reviewer. PyPI needs a trusted publisher for `sendscore`, with the workflow `publish.yml` and that environment. npm can only trust a package that already exists, so the first publish needs a short-lived `NPM_TOKEN` secret in that environment, from a token that can publish `sendscore` and the `@sendscore` scope. After it, add `publish.yml` as the trusted publisher of all seven packages and delete the secret.

Packagist reads `composer.json` from the root of a repository, so PHP needs a read-only split. Create `sendscore/sendscore-php`, push `packages/php` to it with `git subtree split --prefix packages/php`, tag each release there with the same version, and submit that repository to Packagist. `packages/php/.gitattributes` keeps tests out of the installed package.

Maven Central needs the `ai.sendscore` namespace verified at central.sonatype.com, and a GPG key. Then run `mvn -Prelease deploy` in `packages/java`.
