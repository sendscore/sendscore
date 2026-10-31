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

## The binary

The package looks for the CLI in `SENDSCORE_BIN`, then on `PATH`, then in your user cache. If none has it, the first call downloads the pinned release from GitHub, and checks it against the release's `checksums.txt` before it is ever run. There is no install script and no dependency.
