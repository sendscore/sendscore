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

Set `timeout` in `CheckOptions`, or use `diff_with`, to kill the CLI when it runs out. A killed CLI returns an `Error` with `exit_code` set to `KILLED`, which is -1.

## The binary

The crate uses `SENDSCORE_BIN`, then the CLI on `PATH` if its version matches, then your user cache. If none has it, the first call downloads the pinned release from GitHub. The crate carries the SHA-256 of each release file and of the binary inside it, and checks them before it runs anything, including a cached binary. `SENDSCORE_BIN` is your own choice, so its version is not checked. There is no install script.
