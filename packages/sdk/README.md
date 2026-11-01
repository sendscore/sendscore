# SendScore for TypeScript and JavaScript

A typed wrapper around the [SendScore](https://github.com/sendscore/sendscore) CLI, which checks a newsletter email before it goes out. Every language package runs the same binary, so they all return the same verdict.

Not published yet.

```sh
npm install sendscore
```

It also gives you the `sendscore` command, which takes the same arguments and exit codes as the CLI.

```sh
npx sendscore check issue.eml
npm install -g sendscore
```

```ts
import { check, diff } from "sendscore";

const verdict = await check("issue.eml");
if (!verdict.ready_to_send) {
  for (const fix of verdict.top_fixes) console.log(fix.who, fix.fix);
}

await check(rawBytes, { offline: true });
await diff("before.eml", "after.eml");
```

A message that fails its checks is still a report, so `check` returns it. `SendScoreError` is thrown only when no report could be made, and its `exitCode` is the CLI's. Receipt at SendScore does not prove inbox placement at Gmail or any other provider.

Pass `timeout` in milliseconds to `check` or `diff` to kill the CLI when it runs out. A killed CLI raises `SendScoreError` with `exitCode` set to `KILLED`, which is -1.

## The binary

The binary installs with the package. `npm install sendscore` also installs one `@sendscore/cli-<os>-<arch>` package for your machine, through `optionalDependencies`, on macOS, Linux, and Windows, for x64 and arm64. Nothing runs at install time, and nothing is downloaded when you use it.

The package uses `SENDSCORE_BIN`, then that bundled binary, then the CLI on `PATH` if its version matches, then your user cache. If you install with optional dependencies turned off, the first call downloads the pinned release from GitHub, and checks it against the SHA-256 values in the package before it runs anything, including a cached binary.
