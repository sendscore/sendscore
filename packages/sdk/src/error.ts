/** The exitCode of a CLI that was killed, or stopped by a timeout. */
export const KILLED = -1;

/** The CLI could not produce a report, or could not be found or installed. */
export class SendScoreError extends Error {
  /** The CLI's exit code: 64 and above, 0 when the CLI never ran, or KILLED. */
  readonly exitCode: number;

  constructor(message: string, exitCode: number) {
    super(message);
    this.name = "SendScoreError";
    this.exitCode = exitCode;
  }
}
