using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SendScore;

/// <summary>Finds the CLI, and downloads a release when none is installed.</summary>
public static class Binary
{
    /// <summary>The CLI release this package downloads when none is installed.</summary>
    public const string EngineVersion = "0.2.0";

    private const string Releases = "https://github.com/sendscore/sendscore/releases/download";
    private const long MaxDownload = 100 << 20;
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(2), MaxResponseContentBufferSize = MaxDownload };

    /// <summary>
    /// Finds the CLI: SENDSCORE_BIN, then the pinned version on PATH, then the cache, then a download.
    /// A cached binary is checked against its pinned hash every time, so a file planted in the cache
    /// is replaced and never run.
    /// </summary>
    public static async Task<string> FindAsync(CancellationToken cancel = default)
    {
        var fromEnv = Environment.GetEnvironmentVariable("SENDSCORE_BIN");
        if (!string.IsNullOrEmpty(fromEnv))
        {
            return fromEnv;
        }
        var exe = OperatingSystem.IsWindows() ? "sendscore.exe" : "sendscore";
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
        {
            if (!Path.IsPathFullyQualified(dir))
            {
                continue;
            }
            var candidate = Path.Combine(dir, exe);
            if (Executable(candidate) && await RightVersionAsync(candidate, cancel).ConfigureAwait(false))
            {
                return candidate;
            }
        }
        var target = Platform();
        var pin = PinFor(target, Hashes.Pins);
        var cache = Path.Combine(CacheRoot(target.Os), "sendscore", EngineVersion);
        var cached = Path.Combine(cache, exe);
        return MatchesPin(cached, pin)
            ? cached
            : await DownloadAsync(EngineVersion, $"{Releases}/v{EngineVersion}", cache, pin, target, cancel).ConfigureAwait(false);
    }

    private static string CacheRoot(string os)
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (os == "darwin")
        {
            return Path.Combine(home, "Library", "Caches");
        }
        if (os == "linux")
        {
            var xdg = Environment.GetEnvironmentVariable("XDG_CACHE_HOME");
            return !string.IsNullOrEmpty(xdg) && Path.IsPathFullyQualified(xdg) ? xdg : Path.Combine(home, ".cache");
        }
        return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);
    }

    private static bool Executable(string path)
    {
        if (!File.Exists(path))
        {
            return false;
        }
        const UnixFileMode Any = UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;
        return OperatingSystem.IsWindows() || (File.GetUnixFileMode(path) & Any) != 0;
    }

    private static async Task<bool> RightVersionAsync(string path, CancellationToken cancel)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        var info = new ProcessStartInfo(path) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        info.ArgumentList.Add("--version");
        using var process = new Process { StartInfo = info };
        try
        {
            process.Start();
            var error = process.StandardError.ReadToEndAsync(timeout.Token);
            var output = await process.StandardOutput.ReadToEndAsync(timeout.Token).ConfigureAwait(false);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            await error.ConfigureAwait(false);
            var words = output.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            return process.ExitCode == 0 && words.Length > 0 && words[^1].TrimStart('v') == EngineVersion;
        }
        catch (OperationCanceledException)
        {
            process.Kill(true);
            cancel.ThrowIfCancellationRequested();
            return false;
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or IOException)
        {
            return false;
        }
    }

    /// <summary>The archive and binary hashes of a platform. With none, nothing is trusted.</summary>
    internal static (string Archive, string Binary) PinFor((string Os, string Arch) target, Dictionary<string, (string Archive, string Binary)> pins)
    {
        var key = $"{target.Os}_{target.Arch}";
        return pins.TryGetValue(key, out var pin)
            ? pin
            : throw new SendScoreException($"this package has no pinned hash for {key}, so it will not download a CLI. Install the matching sendscore on PATH, or set SENDSCORE_BIN.", 0);
    }

    /// <summary>Whether a file exists and is exactly the pinned binary.</summary>
    internal static bool MatchesPin(string path, (string Archive, string Binary) pin)
    {
        try
        {
            return File.Exists(path) && Hash(File.ReadAllBytes(path)) == pin.Binary;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static string Exe(string os) => os == "windows" ? "sendscore.exe" : "sendscore";

    internal static (string Os, string Arch) Platform()
    {
        var os = OperatingSystem.IsLinux() ? "linux"
            : OperatingSystem.IsMacOS() ? "darwin"
            : OperatingSystem.IsWindows() ? "windows"
            : null;
        var arch = RuntimeInformation.OSArchitecture switch
        {
            Architecture.X64 => "amd64",
            Architecture.Arm64 => "arm64",
            _ => null,
        };
        if (os is null || arch is null)
        {
            throw new SendScoreException($"no SendScore build for {RuntimeInformation.OSDescription} on {RuntimeInformation.OSArchitecture}", 0);
        }
        return (os, arch);
    }

    private static async Task<byte[]> FetchAsync(string url, CancellationToken cancel)
    {
        try
        {
            using var res = await Http.GetAsync(url, cancel).ConfigureAwait(false);
            if (!res.IsSuccessStatusCode)
            {
                throw new SendScoreException($"download of {url} answered {(int)res.StatusCode}", 0);
            }
            return await res.Content.ReadAsByteArrayAsync(cancel).ConfigureAwait(false);
        }
        catch (Exception e) when (e is HttpRequestException or IOException || (e is TaskCanceledException && !cancel.IsCancellationRequested))
        {
            throw new SendScoreException($"download of {url} failed: {e.Message}", 0);
        }
    }

    // One file, by its exact name, so no path in the archive is ever used.
    private static byte[]? Extract(byte[] archive, string os, string name)
    {
        using var source = new MemoryStream(archive);
        using var output = new MemoryStream();
        if (os == "windows")
        {
            using var zip = new ZipArchive(source, ZipArchiveMode.Read);
            var entry = zip.Entries.FirstOrDefault(e => e.FullName == name);
            if (entry is null)
            {
                return null;
            }
            using var stream = entry.Open();
            stream.CopyTo(output);
            return output.ToArray();
        }
        using var gz = new GZipStream(source, CompressionMode.Decompress);
        using var tar = new TarReader(gz);
        for (var e = tar.GetNextEntry(); e is not null; e = tar.GetNextEntry())
        {
            if (e.Name == name && e.EntryType is TarEntryType.RegularFile or TarEntryType.V7RegularFile && e.DataStream is not null)
            {
                e.DataStream!.CopyTo(output);
                return output.ToArray();
            }
        }
        return null;
    }

    /// <summary>
    /// Downloads a release into dir, and returns the binary's path. The archive must match its pin
    /// before anything is extracted, and the binary must match its pin before it reaches the disk.
    /// </summary>
    internal static async Task<string> DownloadAsync(string version, string baseUrl, string dir, (string Archive, string Binary) pin, (string Os, string Arch) target, CancellationToken cancel = default)
    {
        var exe = Exe(target.Os);
        var ext = target.Os == "windows" ? "zip" : "tar.gz";
        var name = $"sendscore_{version}_{target.Os}_{target.Arch}.{ext}";
        var archive = await FetchAsync($"{baseUrl}/{name}", cancel).ConfigureAwait(false);
        if (Hash(archive) != pin.Archive)
        {
            throw new SendScoreException($"{name} does not match its pinned hash", 0);
        }
        byte[]? binary;
        try
        {
            binary = Extract(archive, target.Os, exe);
        }
        catch (Exception e) when (e is InvalidDataException or FormatException)
        {
            throw new SendScoreException($"could not read {name}: {e.Message}", 0);
        }
        if (binary is null)
        {
            throw new SendScoreException($"{name} has no {exe}", 0);
        }
        if (Hash(binary) != pin.Binary)
        {
            throw new SendScoreException($"the binary in {name} does not match its pinned hash", 0);
        }
        try
        {
            Directory.CreateDirectory(dir);
            var temp = Path.Combine(dir, $".download-{Guid.NewGuid():N}");
            try
            {
                await File.WriteAllBytesAsync(temp, binary, cancel).ConfigureAwait(false);
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(temp, (UnixFileMode)0b111_101_101);
                }
                var path = Path.Combine(dir, exe);
                File.Move(temp, path, overwrite: true);
                return path;
            }
            finally
            {
                File.Delete(temp);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new SendScoreException($"could not write to {dir}: {e.Message}", 0);
        }
    }
}
