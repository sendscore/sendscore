from __future__ import annotations

KILLED = -1
"""The exit_code of a CLI that was killed, or stopped by a timeout."""


class SendScoreError(Exception):
    """The CLI could not produce a report, or could not be found or installed.

    exit_code is the CLI's: 64 and above, 0 when the CLI never ran, or KILLED.
    """

    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code
