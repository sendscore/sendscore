# SendScore for TypeScript and JavaScript

A typed wrapper around the [SendScore](https://github.com/sendscore/sendscore) CLI, which checks a newsletter email before it goes out. Every language package runs the same binary, so they all return the same verdict.

Not published yet.

```sh
npm install sendscore
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

The package uses `SENDSCORE_BIN`, then the CLI on `PATH` if its version matches, then your user cache. If none has it, the first call downloads the pinned release from GitHub. The package carries the SHA-256 of each release file and of the binary inside it, and checks them before it runs anything, including a cached binary. `SENDSCORE_BIN` is your own choice, so its version is not checked. There is no install script.
