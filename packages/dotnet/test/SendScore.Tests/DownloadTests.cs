using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Xunit;

namespace SendScore.Tests;

public class DownloadTests : IDisposable
{
    private readonly HttpListener _server = new();
    private readonly string _base;
    private readonly string _tmp = Directory.CreateTempSubdirectory("sendscore-").FullName;

    public DownloadTests()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        _base = $"http://127.0.0.1:{port}";
        _server.Prefixes.Add(_base + "/");
        _server.Start();
        var fixtures = Fixtures();
        _ = Task.Run(async () =>
        {
            while (_server.IsListening)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await _server.GetContextAsync();
                }
                catch (Exception e) when (e is HttpListenerException or ObjectDisposedException)
                {
                    return;
                }
                var path = Path.Combine(fixtures, ctx.Request.Url!.AbsolutePath.TrimStart('/'));
                if (File.Exists(path))
                {
                    var body = await File.ReadAllBytesAsync(path);
                    await ctx.Response.OutputStream.WriteAsync(body);
                }
                else
                {
                    ctx.Response.StatusCode = 404;
                }
                ctx.Response.Close();
            }
        });
    }

    private static readonly (string Os, string Arch) Linux = ("linux", "amd64");

    private static (string Archive, string Binary) Pin(string os, string arch)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(Fixtures(), "pins.json")));
        var entry = doc.RootElement.GetProperty($"{os}_{arch}");
        return (entry.GetProperty("archive").GetString()!, entry.GetProperty("binary").GetString()!);
    }

    private static string Fixtures()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "conformance", "release")))
        {
            dir = dir.Parent;
        }
        return Path.Combine(dir!.FullName, "conformance", "release");
    }

    public void Dispose()
    {
        _server.Close();
        Directory.Delete(_tmp, true);
    }

    [Theory]
    [InlineData("linux", "amd64")]
    [InlineData("darwin", "arm64")]
    [InlineData("windows", "amd64")]
    public async Task InstallsTheBinaryAndNothingElse(string os, string arch)
    {
        var cache = Path.Combine(_tmp, "cache");
        var path = await Binary.DownloadAsync("0.0.0-test", $"{_base}/good", cache, Pin(os, arch), (os, arch));
        Assert.Contains("fake sendscore", await File.ReadAllTextAsync(path));
        Assert.Equal(new[] { Path.GetFileName(path) }, Directory.GetFileSystemEntries(cache).Select(Path.GetFileName));
        Assert.False(File.Exists(Path.Combine(_tmp, "evil")));
    }

    [Fact]
    public async Task RefusesAMismatch()
    {
        var cache = Path.Combine(_tmp, "cache");
        await Assert.ThrowsAsync<SendScoreException>(() => Binary.DownloadAsync("0.0.0-test", $"{_base}/altered", cache, Pin("linux", "amd64"), Linux));
        Assert.False(Directory.Exists(cache));
    }

    [Fact]
    public async Task FailsOnAMissingRelease()
    {
        var cache = Path.Combine(_tmp, "cache");
        await Assert.ThrowsAsync<SendScoreException>(() => Binary.DownloadAsync("0.0.0-test", $"{_base}/nothing", cache, Pin("linux", "amd64"), Linux));
    }

    [Fact]
    public async Task RefusesABinaryThatDoesNotMatch()
    {
        var cache = Path.Combine(_tmp, "cache");
        var wrong = (Pin("linux", "amd64").Archive, new string('0', 64));
        await Assert.ThrowsAsync<SendScoreException>(() => Binary.DownloadAsync("0.0.0-test", $"{_base}/good", cache, wrong, Linux));
        Assert.False(Directory.Exists(cache));
    }

    [Fact]
    public async Task ACachedBinaryIsTrustedOnlyWhileItMatches()
    {
        var pin = Pin("linux", "amd64");
        var path = await Binary.DownloadAsync("0.0.0-test", $"{_base}/good", Path.Combine(_tmp, "cache"), pin, Linux);
        Assert.True(Binary.MatchesPin(path, pin));
        await File.WriteAllTextAsync(path, "planted");
        Assert.False(Binary.MatchesPin(path, pin));
    }

    [Fact]
    public void NoPinMeansNoDownload()
    {
        Assert.Throws<SendScoreException>(() => Binary.PinFor(Linux, new()));
    }
}
