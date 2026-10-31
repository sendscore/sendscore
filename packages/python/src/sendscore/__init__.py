"""Check a newsletter email before it goes out, with the SendScore CLI."""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, cast

from ._binary import ENGINE_VERSION, find_binary
from ._error import SendScoreError
from .types import Change, Check, DiffResult, Fingerprint, Fix, Message, TopFix, Verdict

__all__ = [
    "ENGINE_VERSION",
    "Change",
    "Check",
    "DiffResult",
    "Fingerprint",
    "Fix",
    "Message",
    "SendScoreError",
    "TopFix",
    "Verdict",
    "check",
    "diff",
]


def _run(args: list[str], stdin: bytes | None, verdict_codes: tuple[int, ...]) -> dict[str, Any]:
    binary = find_binary()
    try:
        r = subprocess.run(
            [binary, *args],
            input=stdin,
            capture_output=True,
            check=False,
        )
    except OSError as e:
        raise SendScoreError(f"could not run {binary}: {e}", 0) from e
    if r.returncode not in verdict_codes:
        text = r.stderr.decode(errors="replace").strip()
        raise SendScoreError(text or f"sendscore exited {r.returncode}", r.returncode)
    try:
        return cast("dict[str, Any]", json.loads(r.stdout))
    except ValueError as e:
        raise SendScoreError("sendscore printed something that is not JSON", r.returncode) from e


def check(
    message: str | os.PathLike[str] | bytes,
    *,
    offline: bool = False,
    links: bool = False,
    ip: str | None = None,
    mail_from: str | None = None,
    helo: str | None = None,
    tls: bool | None = None,
    previous: str | os.PathLike[str] | None = None,
) -> Verdict:
    """Checks one message, given as a path or as its bytes.

    A message that fails checks is still a report. This raises SendScoreError
    only when no report could be made.
    """
    args = ["check", "--json"]
    if offline:
        args.append("--offline")
    if links:
        args.append("--links")
    if ip is not None:
        args += ["--ip", ip]
    if mail_from is not None:
        args += ["--mail-from", mail_from]
    if helo is not None:
        args += ["--helo", helo]
    if tls is not None:
        args += ["--tls", "yes" if tls else "no"]
    if previous is not None:
        args += ["--previous", os.fspath(previous)]
    is_bytes = isinstance(message, (bytes, bytearray))
    args += ["--", "-" if is_bytes else os.fspath(message)]  # type: ignore[arg-type]
    return cast(Verdict, _run(args, bytes(message) if is_bytes else None, (0, 1, 2)))  # type: ignore[arg-type]


def diff(before: str | os.PathLike[str], after: str | os.PathLike[str]) -> DiffResult:
    """Compares two saved messages, given as paths."""
    result = _run(["diff", "--json", "--", os.fspath(before), os.fspath(after)], None, (0, 1))
    result["changes"] = result.get("changes") or []
    return cast(DiffResult, result)
