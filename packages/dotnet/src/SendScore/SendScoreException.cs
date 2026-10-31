namespace SendScore;

/// <summary>The CLI could not produce a report, or could not be found or installed.</summary>
public sealed class SendScoreException : Exception
{
    /// <summary>The exit code of a CLI that was killed, or stopped by a timeout.</summary>
    public const int Killed = -1;

    public SendScoreException(string message, int exitCode) : base(message) => ExitCode = exitCode;

    /// <summary>The CLI's exit code: 64 and above, 0 when the CLI never ran, or Killed.</summary>
    public int ExitCode { get; }
}
