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

## The binary

The package looks for the CLI in `SENDSCORE_BIN`, then on `PATH`, then in your user cache. If none has it, the first call downloads the pinned release from GitHub, and checks it against the release's `checksums.txt` before it is ever run. There is no install script. This package needs an environment that can run a binary, so it does not work in Cloudflare Workers or a browser.
