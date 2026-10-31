using System.Text.Json;
using Xunit;

namespace SendScore.Tests;

public class ConformanceTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "conformance", "cases.json")))
        {
            dir = dir.Parent;
        }
        return dir?.FullName ?? throw new InvalidOperationException("no conformance directory");
    }

    private static readonly string Root = Path.Combine(RepoRoot(), "conformance");

    public static IEnumerable<object[]> Cases()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "cases.json")));
        foreach (var c in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            yield return new object[] { c.GetProperty("name").GetString()!, c.GetRawText() };
        }
    }

    private static string P(JsonElement c, string key) => Path.Combine(Root, c.GetProperty(key).GetString()!);

    private static List<string> List(JsonElement c, string key) =>
        c.TryGetProperty(key, out var v) ? v.EnumerateArray().Select(x => x.GetString()!).ToList() : new List<string>();

    private static CheckOptions Options(JsonElement c)
    {
        var o = new CheckOptions { Offline = true };
        if (!c.TryGetProperty("options", out var given))
        {
            return o;
        }
        if (given.TryGetProperty("links", out var links)) o = o with { Links = links.GetBoolean() };
        if (given.TryGetProperty("ip", out var ip)) o = o with { Ip = ip.GetString() };
        if (given.TryGetProperty("mail_from", out var from)) o = o with { MailFrom = from.GetString() };
        if (given.TryGetProperty("helo", out var helo)) o = o with { Helo = helo.GetString() };
        if (given.TryGetProperty("tls", out var tls)) o = o with { Tls = tls.GetBoolean() };
        if (given.TryGetProperty("previous", out var prev)) o = o with { Previous = Path.Combine(Root, prev.GetString()!) };
        return o;
    }

    private static Task<Verdict> Check(JsonElement c) =>
        c.GetProperty("via").GetString() == "stdin"
            ? SendScoreClient.CheckAsync(File.ReadAllBytes(P(c, "message")), Options(c))
            : SendScoreClient.CheckAsync(P(c, "message"), Options(c));

    private static void Changes(JsonElement c, List<Change>? got)
    {
        got ??= new List<Change>();
        Assert.Equal(List(c, "changes"), got.Select(x => x.Field).ToList());
        Assert.Equal(List(c, "worsened"), got.Where(x => x.Worsened is not null).Select(x => x.Worsened!).ToList());
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Conforms(string name, string json)
    {
        Assert.NotEmpty(name);
        using var doc = JsonDocument.Parse(json);
        var c = doc.RootElement;
        var isDiff = c.GetProperty("command").GetString() == "diff";
        var exit = c.GetProperty("exit").GetInt32();
        if (exit > 2)
        {
            var e = await Assert.ThrowsAsync<SendScoreException>(async () =>
            {
                if (isDiff)
                {
                    await SendScoreClient.DiffAsync(P(c, "before"), P(c, "after"));
                }
                else
                {
                    await Check(c);
                }
            });
            Assert.Equal(exit, e.ExitCode);
            return;
        }
        if (isDiff)
        {
            Changes(c, (await SendScoreClient.DiffAsync(P(c, "before"), P(c, "after"))).Changes);
            return;
        }
        var got = await Check(c);
        Assert.Equal(c.GetProperty("verdict").GetString(), got.Status);
        Assert.Equal(c.GetProperty("ready_to_send").GetBoolean(), got.ReadyToSend);
        var want = c.GetProperty("checks").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString());
        Assert.Equal(want, got.Checks.ToDictionary(x => x.Id, x => (string?)x.Status));
        Changes(c, got.Changes);
    }
}
