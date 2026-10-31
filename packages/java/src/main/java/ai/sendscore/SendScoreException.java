package ai.sendscore;

/** The CLI could not produce a report, or could not be found or installed. */
public class SendScoreException extends RuntimeException {
  private final int exitCode;

  public SendScoreException(String message, int exitCode) {
    super(message);
    this.exitCode = exitCode;
  }

  /** The CLI's exit code: 64 and above, or 0 when the CLI never ran. */
  public int exitCode() {
    return exitCode;
  }
}
