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

## The binary

The package looks for the CLI in `SENDSCORE_BIN`, then on `PATH`, then in your user cache. If none has it, the first call downloads the pinned release from GitHub, and checks it against the release's `checksums.txt` before it is ever run. There is no install script. Bytes go through a private temporary file, because Erlang ports cannot close a program's standard input on their own.
