using System.Diagnostics;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace SendScore.Tests;

public class CliTests : IDisposable
{
    private static readonly string Exe = OperatingSystem.IsWindows() ? "sendscore.exe" : "sendscore";
    private static readonly string Repo = FindRepo();
    private static readonly string Sample = Path.Combine(Repo, "conformance", "messages", "clean.eml");
    private static readonly string[] Keys = { "SENDSCORE_BIN", "PATH", "XDG_CACHE_HOME" };

    private readonly Dictionary<string, string?> _saved = Keys.ToDictionary(k => k, Environment.GetEnvironmentVariable);
    private readonly string _tmp = Directory.CreateTempSubdirectory("sendscore-cli-").FullName;
    private readonly string _built;

    public CliTests()
    {
        _built = Path.Combine(_tmp, "built", Exe);
        var info = new ProcessStartInfo("go") { WorkingDirectory = Repo };
        foreach (var arg in new[] { "build", "-o", _built, "./conformance/fakecli" })
        {
            info.ArgumentList.Add(arg);
        }
        using var go = Process.Start(info)!;
        go.WaitForExit();
        Assert.Equal(0, go.ExitCode);
    }

    private static string FindRepo()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "conformance", "cases.json")))
        {
            dir = dir.Parent;
        }
        return dir!.FullName;
    }

    public void Dispose()
    {
        foreach (var (key, value) in _saved)
        {
            Environment.SetEnvironmentVariable(key, value);
        }
        Directory.Delete(_tmp, true);
    }

    private string Fake(string mode)
    {
        var dir = Path.Combine(_tmp, mode);
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, Exe);
        File.Copy(_built, path, true);
        return path;
    }

    private void Use(string mode) => Environment.SetEnvironmentVariable("SENDSCORE_BIN", Fake(mode));

    private void OnlyPath(string path)
    {
        Environment.SetEnvironmentVariable("SENDSCORE_BIN", null);
        Environment.SetEnvironmentVariable("PATH", path);
        Environment.SetEnvironmentVariable("XDG_CACHE_HOME", Path.Combine(_tmp, "cache"));
    }

    [Fact]
    public async Task ATimeoutKillsTheCli()
    {
        Use("hang");
        var t = TimeSpan.FromMilliseconds(200);
        var e = await Assert.ThrowsAsync<SendScoreException>(() => SendScoreClient.CheckAsync(Sample, new CheckOptions { Timeout = t }));
        Assert.Equal(SendScoreException.Killed, e.ExitCode);
        e = await Assert.ThrowsAsync<SendScoreException>(() => SendScoreClient.DiffAsync(Sample, Sample, t));
        Assert.Equal(SendScoreException.Killed, e.ExitCode);
    }

    [Fact]
    public async Task CancellingKillsTheCli()
    {
        Use("hang");
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => SendScoreClient.CheckAsync(Sample, null, cancel.Token));
    }

    [Fact]
    public async Task AKilledCliHasOneExitCode()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }
        Use("killed");
        var e = await Assert.ThrowsAsync<SendScoreException>(() => SendScoreClient.CheckAsync(Sample));
        Assert.Equal(SendScoreException.Killed, e.ExitCode);
    }

    [Fact]
    public async Task OutputThatIsNotAVerdictIsRefused()
    {
        Use("planted");
        await Assert.ThrowsAsync<SendScoreException>(() => SendScoreClient.CheckAsync(Sample));
        await Assert.ThrowsAsync<SendScoreException>(() => SendScoreClient.DiffAsync(Sample, Sample));
    }

    [Fact]
    public async Task UnknownFieldsAndStderrAreTolerated()
    {
        Use("noisy");
        var got = await SendScoreClient.CheckAsync(Sample);
        Assert.Equal("pass", got.Status);
        Assert.Equal("brand_new", got.Checks[0].Status);
    }

    [Fact]
    public async Task AWrongVersionOnPathIsNotRun()
    {
        OnlyPath(Path.GetDirectoryName(Fake("version-9.9.9"))!);
        var e = await Assert.ThrowsAsync<SendScoreException>(() => Binary.FindAsync());
        Assert.Contains("no pinned hash", e.Message);
    }

    [Fact]
    public async Task ThePinnedVersionOnPathIsUsed()
    {
        var path = Fake($"version-{Binary.EngineVersion}");
        OnlyPath(Path.GetDirectoryName(path)!);
        Assert.Equal(path, await Binary.FindAsync());
    }

    [Fact]
    public async Task RelativePathEntriesAreSkipped()
    {
        var name = $"version-{Binary.EngineVersion}";
        Directory.CreateDirectory(name);
        File.Copy(Fake(name), Path.Combine(name, Exe), true);
        try
        {
            OnlyPath(Path.PathSeparator + name);
            var e = await Assert.ThrowsAsync<SendScoreException>(() => Binary.FindAsync());
            Assert.Contains("no pinned hash", e.Message);
        }
        finally
        {
            Directory.Delete(name, true);
        }
    }

    [Fact]
    public async Task PathsThatLookLikeFlagsAreFiles()
    {
        foreach (var name in new[] { "-", "-dash.eml" })
        {
            File.Copy(Sample, name, true);
            try
            {
                var got = await SendScoreClient.CheckAsync(name, new CheckOptions { Offline = true });
                Assert.NotEmpty(got.Message.Subject);
            }
            finally
            {
                File.Delete(name);
            }
        }
    }
}
