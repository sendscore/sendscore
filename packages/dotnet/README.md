# SendScore for .NET

A typed wrapper around the [SendScore](https://github.com/sendscore/sendscore) CLI, which checks a newsletter email before it goes out. Every language package runs the same binary, so they all return the same verdict. It needs .NET 8.

Not published yet.

```sh
dotnet add package SendScore
```

```csharp
using SendScore;

var verdict = await SendScoreClient.CheckAsync("issue.eml");
if (!verdict.ReadyToSend)
{
    foreach (var fix in verdict.TopFixes)
    {
        Console.WriteLine($"{fix.Who} {fix.Fix}");
    }
}

await SendScoreClient.CheckAsync(rawBytes, new CheckOptions { Offline = true });
await SendScoreClient.DiffAsync("before.eml", "after.eml");
```

A message that fails its checks is still a report, so `CheckAsync` returns it. `SendScoreException` is thrown only when no report could be made, and its `ExitCode` is the CLI's. Receipt at SendScore does not prove inbox placement at Gmail or any other provider.

Set `Timeout` in `CheckOptions`, or pass one to `DiffAsync`, to kill the CLI when it runs out. A killed CLI throws `SendScoreException` with `ExitCode` equal to `SendScoreException.Killed`, which is -1. Cancelling the token kills it too.

## The binary

The package uses `SENDSCORE_BIN`, then the CLI on `PATH` if its version matches, then your user cache. If none has it, the first call downloads the pinned release from GitHub. The package carries the SHA-256 of each release file and of the binary inside it, and checks them before it runs anything, including a cached binary. `SENDSCORE_BIN` is your own choice, so its version is not checked. There is no install script.
