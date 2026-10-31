# SendScore for Rust

A typed wrapper around the [SendScore](https://github.com/sendscore/sendscore) CLI, which checks a newsletter email before it goes out. Every language package runs the same binary, so they all return the same verdict.

Not published yet.

```sh
cargo add sendscore
```

```rust
use sendscore::{check, diff, CheckOptions, Input};

let verdict = check("issue.eml", &CheckOptions::default())?;
if !verdict.ready_to_send {
    for fix in &verdict.top_fixes {
        println!("{} {}", fix.who, fix.fix);
    }
}

check(Input::Bytes(&raw), &CheckOptions { offline: true, ..Default::default() })?;
diff("before.eml", "after.eml")?;
```

A message that fails its checks is still a report, so `check` returns it. An `Error` means no report could be made, and its `exit_code` is the CLI's. Receipt at SendScore does not prove inbox placement at Gmail or any other provider.

## The binary

The crate looks for the CLI in `SENDSCORE_BIN`, then on `PATH`, then in your user cache. If none has it, the first call downloads the pinned release from GitHub, and checks it against the release's `checksums.txt` before it is ever run. There is no build script.
