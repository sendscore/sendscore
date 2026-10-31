package ai.sendscore;

/** The CLI could not produce a report, or could not be found or installed. */
public class SendScoreException extends RuntimeException {
  /** The exit code of a CLI that was killed, or stopped by a timeout. */
  public static final int KILLED = -1;

  private final int exitCode;

  public SendScoreException(String message, int exitCode) {
    super(message);
    this.exitCode = exitCode;
  }

  /** The CLI's exit code: 64 and above, 0 when the CLI never ran, or KILLED. */
  public int exitCode() {
    return exitCode;
  }
}
