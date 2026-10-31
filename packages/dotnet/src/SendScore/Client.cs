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
        var result = await RunAsync(Args(options ?? new(), path), null, cancel).ConfigureAwait(false);
        return Parse<Verdict>(result, 0, 1, 2);
    }

    /// <summary>Checks a message given as its bytes.</summary>
    public static async Task<Verdict> CheckAsync(byte[] message, CheckOptions? options = null, CancellationToken cancel = default)
    {
        var result = await RunAsync(Args(options ?? new(), "-"), message, cancel).ConfigureAwait(false);
        return Parse<Verdict>(result, 0, 1, 2);
    }

    /// <summary>Compares two saved messages.</summary>
    public static async Task<DiffResult> DiffAsync(string before, string after, CancellationToken cancel = default)
    {
        var result = await RunAsync(new List<string> { "diff", "--json", "--", before, after }, null, cancel).ConfigureAwait(false);
        var diff = Parse<DiffResult>(result, 0, 1);
        return diff with { Changes = diff.Changes ?? new List<Change>() };
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
        if (o.Previous is not null) args.AddRange(new[] { "--previous", o.Previous });
        args.AddRange(new[] { "--", input });
        return args;
    }

    private static async Task<(int Code, byte[] Stdout, string Stderr)> RunAsync(List<string> args, byte[]? stdin, CancellationToken cancel)
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
        using var stdout = new MemoryStream();
        var readOut = process.StandardOutput.BaseStream.CopyToAsync(stdout, cancel);
        var readErr = process.StandardError.ReadToEndAsync(cancel);
        try
        {
            if (stdin is not null)
            {
                await process.StandardInput.BaseStream.WriteAsync(stdin, cancel).ConfigureAwait(false);
            }
            process.StandardInput.Close();
        }
        catch (IOException)
        {
            // The CLI stopped reading, and its exit code says why.
        }
        await process.WaitForExitAsync(cancel).ConfigureAwait(false);
        await readOut.ConfigureAwait(false);
        return (process.ExitCode, stdout.ToArray(), await readErr.ConfigureAwait(false));
    }

    private static T Parse<T>((int Code, byte[] Stdout, string Stderr) r, params int[] verdictCodes)
    {
        if (!verdictCodes.Contains(r.Code))
        {
            var text = r.Stderr.Trim();
            throw new SendScoreException(text.Length == 0 ? $"sendscore exited {r.Code}" : text, r.Code);
        }
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
