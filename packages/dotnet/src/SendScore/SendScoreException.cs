namespace SendScore;

/// <summary>The CLI could not produce a report, or could not be found or installed.</summary>
public sealed class SendScoreException : Exception
{
    public SendScoreException(string message, int exitCode) : base(message) => ExitCode = exitCode;

    /// <summary>The CLI's exit code: 64 and above, or 0 when the CLI never ran.</summary>
    public int ExitCode { get; }
}
