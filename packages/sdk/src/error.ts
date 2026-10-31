/** The CLI could not produce a report, or could not be found or installed. */
export class SendScoreError extends Error {
  /** The CLI's exit code: 64 and above, or 0 when the CLI never ran. */
  readonly exitCode: number;

  constructor(message: string, exitCode: number) {
    super(message);
    this.name = "SendScoreError";
    this.exitCode = exitCode;
  }
}
