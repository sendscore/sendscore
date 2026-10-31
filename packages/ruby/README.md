# SendScore for Ruby

A typed wrapper around the [SendScore](https://github.com/sendscore/sendscore) CLI, which checks a newsletter email before it goes out. Every language package runs the same binary, so they all return the same verdict.

Not published yet.

```sh
gem install sendscore
```

```ruby
require "sendscore"

verdict = SendScore.check("issue.eml")
unless verdict["ready_to_send"]
  verdict["top_fixes"].each { |fix| puts "#{fix['who']} #{fix['fix']}" }
end

SendScore.check(raw_bytes, bytes: true, offline: true)
SendScore.diff("before.eml", "after.eml")
```

A message that fails its checks is still a report, so `check` returns it. `SendScore::Error` is raised only when no report could be made, and its `exit_code` is the CLI's. Receipt at SendScore does not prove inbox placement at Gmail or any other provider.

Pass `timeout:` in seconds to `check` or `diff` to kill the CLI when it runs out. A killed CLI raises `SendScore::Error` with `exit_code` set to `SendScore::KILLED`, which is -1.

## The binary

The gem uses `SENDSCORE_BIN`, then the CLI on `PATH` if its version matches, then your user cache. If none has it, the first call downloads the pinned release from GitHub. The gem carries the SHA-256 of each release file and of the binary inside it, and checks them before it runs anything, including a cached binary. `SENDSCORE_BIN` is your own choice, so its version is not checked. There is no install script.
