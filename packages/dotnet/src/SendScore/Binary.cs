using System.Formats.Tar;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SendScore;

/// <summary>Finds the CLI, and downloads a release when none is installed.</summary>
public static class Binary
{
    /// <summary>The CLI release this package downloads when none is installed.</summary>
    public const string EngineVersion = "0.2.0";

    private const string Releases = "https://github.com/sendscore/sendscore/releases/download";
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(2) };

    /// <summary>Finds the CLI: SENDSCORE_BIN, then PATH, then the cache, then a download.</summary>
    public static async Task<string> FindAsync(CancellationToken cancel = default)
    {
        var fromEnv = Environment.GetEnvironmentVariable("SENDSCORE_BIN");
        if (!string.IsNullOrEmpty(fromEnv))
        {
            return fromEnv;
        }
        var target = Platform();
        var exe = Exe(target.Os);
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
        {
            if (dir.Length > 0 && File.Exists(Path.Combine(dir, exe)))
            {
                return Path.Combine(dir, exe);
            }
        }
        var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);
        if (target.Os == "darwin")
        {
            root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Library", "Caches");
        }
        else if (target.Os == "linux")
        {
            root = Environment.GetEnvironmentVariable("XDG_CACHE_HOME")
                ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cache");
        }
        var cache = Path.Combine(root, "sendscore", EngineVersion);
        var cached = Path.Combine(cache, exe);
        return File.Exists(cached)
            ? cached
            : await DownloadAsync(EngineVersion, $"{Releases}/v{EngineVersion}", cache, target, cancel).ConfigureAwait(false);
    }

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
        catch (HttpRequestException e)
        {
            throw new SendScoreException($"download of {url} failed: {e.Message}", 0);
        }
    }

    private static string ExpectedHash(string checksums, string name)
    {
        foreach (var line in checksums.Split('\n'))
        {
            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 2 && parts[1] == name)
            {
                return parts[0].ToLowerInvariant();
            }
        }
        throw new SendScoreException($"checksums.txt does not list {name}", 0);
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
    /// Downloads a release into dir, and returns the binary's path. The archive is checked against
    /// checksums.txt before anything is extracted, so a binary that does not match never reaches the disk.
    /// </summary>
    internal static async Task<string> DownloadAsync(string version, string baseUrl, string dir, (string Os, string Arch) target, CancellationToken cancel = default)
    {
        var exe = Exe(target.Os);
        var ext = target.Os == "windows" ? "zip" : "tar.gz";
        var name = $"sendscore_{version}_{target.Os}_{target.Arch}.{ext}";
        var checksums = Encoding.UTF8.GetString(await FetchAsync($"{baseUrl}/checksums.txt", cancel).ConfigureAwait(false));
        var archive = await FetchAsync($"{baseUrl}/{name}", cancel).ConfigureAwait(false);
        var actual = Convert.ToHexString(SHA256.HashData(archive)).ToLowerInvariant();
        if (actual != ExpectedHash(checksums, name))
        {
            throw new SendScoreException($"{name} does not match checksums.txt", 0);
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
}
