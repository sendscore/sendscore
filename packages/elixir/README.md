# SendScore for Elixir

A typed wrapper around the [SendScore](https://github.com/sendscore/sendscore) CLI, which checks a newsletter email before it goes out. Every language package runs the same binary, so they all return the same verdict.

Not published yet.

```elixir
def deps do
  [{:sendscore, "~> 0.2"}]
end
```

```elixir
{:ok, verdict} = SendScore.check("issue.eml")

unless verdict["ready_to_send"] do
  for fix <- verdict["top_fixes"], do: IO.puts("#{fix["who"]} #{fix["fix"]}")
end

SendScore.check({:bytes, raw}, offline: true)
SendScore.diff("before.eml", "after.eml")
```

A message that fails its checks is still a report, so `check/2` returns `{:ok, verdict}`. `{:error, %SendScore.Error{}}` means no report could be made, and its `exit_code` is the CLI's. Receipt at SendScore does not prove inbox placement at Gmail or any other provider.

Pass `timeout:` in milliseconds to `check/2` or `diff/3` to kill the CLI when it runs out. A killed CLI returns `%SendScore.Error{exit_code: -1}`. Erlang ports cannot capture stderr on its own, so the CLI's stderr goes to your program's stderr, and an error's message names only the exit code.

## The binary

The package uses `SENDSCORE_BIN`, then the CLI on `PATH` if its version matches, then your user cache. If none has it, the first call downloads the pinned release from GitHub. The package carries the SHA-256 of each release file and of the binary inside it, and checks them before it runs anything, including a cached binary. `SENDSCORE_BIN` is your own choice, so its version is not checked. There is no install script.
