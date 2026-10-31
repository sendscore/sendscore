from __future__ import annotations


class SendScoreError(Exception):
    """The CLI could not produce a report, or could not be found or installed.

    exit_code is the CLI's: 64 and above, or 0 when the CLI never ran.
    """

    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code
