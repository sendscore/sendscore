# SendScore for Python

A typed wrapper around the [SendScore](https://github.com/sendscore/sendscore) CLI, which checks a newsletter email before it goes out. Every language package runs the same binary, so they all return the same verdict.

Not published yet.

```sh
pip install sendscore
```

```python
from sendscore import check, diff

verdict = check("issue.eml")
if not verdict["ready_to_send"]:
    for fix in verdict["top_fixes"]:
        print(fix["who"], fix["fix"])

check(raw_bytes, offline=True)
diff("before.eml", "after.eml")
```

A message that fails its checks is still a report, so `check` returns it. `SendScoreError` is raised only when no report could be made, and its `exit_code` is the CLI's. Receipt at SendScore does not prove inbox placement at Gmail or any other provider.

Pass `timeout` in seconds to `check` or `diff` to kill the CLI when it runs out. A killed CLI raises `SendScoreError` with `exit_code` set to `KILLED`, which is -1.

## The binary

The binary installs with the package. `pip install sendscore` picks the wheel for your machine, on macOS 12 or later, Linux with glibc or musl, and Windows, for x64 and arm64. Nothing runs at install time, and nothing is downloaded when you use it. There is no source distribution, so a platform without a wheel gets a clear error from pip.

The package uses `SENDSCORE_BIN`, then that bundled binary, then the CLI on `PATH` if its version matches, then your user cache. Running from a source checkout, which has no binary, the first call downloads the pinned release from GitHub, and checks it against the SHA-256 values in the package before it runs anything, including a cached binary.
