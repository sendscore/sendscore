using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;

namespace SendScore;

/// <summary>What a check should do beyond reading the message.</summary>
public sealed record CheckOptions
{
    /// <summary>Make no DNS lookups. Checks that need DNS are skipped.</summary>
    public bool Offline { get; init; }

    /// <summary>Fetch every link and image, never unsubscribe or confirm links.</summary>
    public bool Links { get; init; }

    /// <summary>IP address of the server that delivered the message.</summary>
    public string? Ip { get; init; }

    /// <summary>Envelope sender. Defaults to the Return-Path.</summary>
    public string? MailFrom { get; init; }

    /// <summary>HELO name the delivering server gave.</summary>
    public string? Helo { get; init; }

    /// <summary>Whether delivery used TLS.</summary>
    public bool? Tls { get; init; }

    /// <summary>Path of the publication's previous issue, to list what changed.</summary>
    public string? Previous { get; init; }

    /// <summary>Kill the CLI and throw after this long. No limit by default.</summary>
    public TimeSpan? Timeout { get; init; }
}

/// <summary>
/// Checks newsletter emails with the SendScore CLI. A message that fails checks is still a report;
/// SendScoreException means no report could be made.
/// </summary>
public static class SendScoreClient
{
    /// <summary>Checks a saved message.</summary>
    public static async Task<Verdict> CheckAsync(string path, CheckOptions? options = null, CancellationToken cancel = default)
    {
        options ??= new();
        var result = await RunAsync(Args(options, PathArg(path)), null, options.Timeout, cancel).ConfigureAwait(false);
        return ParseVerdict(result);
    }

    /// <summary>Checks a message given as its bytes.</summary>
    public static async Task<Verdict> CheckAsync(byte[] message, CheckOptions? options = null, CancellationToken cancel = default)
    {
        options ??= new();
        var result = await RunAsync(Args(options, "-"), message, options.Timeout, cancel).ConfigureAwait(false);
        return ParseVerdict(result);
    }

    /// <summary>Compares two saved messages.</summary>
    public static async Task<DiffResult> DiffAsync(string before, string after, TimeSpan? timeout = null, CancellationToken cancel = default)
    {
        var args = new List<string> { "diff", "--json", "--", PathArg(before), PathArg(after) };
        var result = await RunAsync(args, null, timeout, cancel).ConfigureAwait(false);
        using var doc = Document(result, 0, 1);
        if (doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("changes", out _))
        {
            throw new SendScoreException("sendscore printed something that is not a comparison", 0);
        }
        var diff = Convert<DiffResult>(result);
        return diff with { Changes = diff.Changes ?? new List<Change>() };
    }

    // A lone "-" would mean standard input to the CLI.
    private static string PathArg(string path) => path == "-" ? "./-" : path;

    private static Verdict ParseVerdict((int Code, byte[] Stdout, string Stderr) result)
    {
        using var doc = Document(result, 0, 1, 2);
        var schema = doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("schema", out var s) && s.ValueKind == JsonValueKind.String
            ? s.GetString()
            : null;
        if (schema is null || !schema.StartsWith("sendscore.verdict/", StringComparison.Ordinal))
        {
            throw new SendScoreException("sendscore printed something that is not a verdict", 0);
        }
        return Convert<Verdict>(result);
    }

    private static List<string> Args(CheckOptions o, string input)
    {
        var args = new List<string> { "check", "--json" };
        if (o.Offline) args.Add("--offline");
        if (o.Links) args.Add("--links");
        if (o.Ip is not null) args.AddRange(new[] { "--ip", o.Ip });
        if (o.MailFrom is not null) args.AddRange(new[] { "--mail-from", o.MailFrom });
        if (o.Helo is not null) args.AddRange(new[] { "--helo", o.Helo });
        if (o.Tls is not null) args.AddRange(new[] { "--tls", o.Tls.Value ? "yes" : "no" });
        if (o.Previous is not null) args.AddRange(new[] { "--previous", PathArg(o.Previous) });
        args.AddRange(new[] { "--", input });
        return args;
    }

    private static async Task<(int Code, byte[] Stdout, string Stderr)> RunAsync(List<string> args, byte[]? stdin, TimeSpan? timeout, CancellationToken cancel)
    {
        var binary = await Binary.FindAsync(cancel).ConfigureAwait(false);
        // ArgumentList with UseShellExecute off runs the program directly, with no shell.
        var info = new ProcessStartInfo(binary)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var arg in args)
        {
            info.ArgumentList.Add(arg);
        }
        using var process = new Process { StartInfo = info };
        try
        {
            process.Start();
        }
        catch (Win32Exception e)
        {
            throw new SendScoreException($"could not run {binary}: {e.Message}", 0);
        }
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        if (timeout is not null)
        {
            limit.CancelAfter(timeout.Value);
        }
        using var stdout = new MemoryStream();
        try
        {
            var readOut = process.StandardOutput.BaseStream.CopyToAsync(stdout, limit.Token);
            var readErr = process.StandardError.ReadToEndAsync(limit.Token);
            try
            {
                if (stdin is not null)
                {
                    await process.StandardInput.BaseStream.WriteAsync(stdin, limit.Token).ConfigureAwait(false);
                }
                process.StandardInput.Close();
            }
            catch (IOException)
            {
                // The CLI stopped reading, and its exit code says why.
            }
            await process.WaitForExitAsync(limit.Token).ConfigureAwait(false);
            await readOut.ConfigureAwait(false);
            var code = process.ExitCode is < 0 or >= 128 ? SendScoreException.Killed : process.ExitCode;
            return (code, stdout.ToArray(), await readErr.ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // Whatever cancelled the wait, the child must not outlive it.
            process.Kill(true);
            cancel.ThrowIfCancellationRequested();
            throw new SendScoreException($"sendscore did not finish within {timeout}", SendScoreException.Killed);
        }
    }

    private static JsonDocument Document((int Code, byte[] Stdout, string Stderr) r, params int[] verdictCodes)
    {
        if (!verdictCodes.Contains(r.Code))
        {
            var text = r.Stderr.Trim();
            throw new SendScoreException(text.Length == 0 ? $"sendscore exited {r.Code}" : text, r.Code);
        }
        try
        {
            return JsonDocument.Parse(r.Stdout);
        }
        catch (JsonException)
        {
            throw new SendScoreException("sendscore printed something this package cannot read", r.Code);
        }
    }

    private static T Convert<T>((int Code, byte[] Stdout, string Stderr) r)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(r.Stdout) ?? throw new JsonException("null");
        }
        catch (JsonException)
        {
            throw new SendScoreException("sendscore printed something this package cannot read", r.Code);
        }
    }
}
