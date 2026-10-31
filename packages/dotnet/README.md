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

## The binary

The package looks for the CLI in `SENDSCORE_BIN`, then on `PATH`, then in your user cache. If none has it, the first call downloads the pinned release from GitHub, and checks it against the release's `checksums.txt` before it is ever run. There is no install script.
