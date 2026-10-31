"""Check a newsletter email before it goes out, with the SendScore CLI."""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, cast

from ._binary import ENGINE_VERSION, find_binary
from ._error import KILLED, SendScoreError
from .types import Change, Check, DiffResult, Fingerprint, Fix, Message, TopFix, Verdict

__all__ = [
    "ENGINE_VERSION",
    "KILLED",
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


def _path(path: str | os.PathLike[str]) -> str:
    # A lone "-" would mean standard input to the CLI.
    text = os.fspath(path)
    return "./-" if text == "-" else text


def _run(
    args: list[str],
    stdin: bytes | None,
    verdict_codes: tuple[int, ...],
    timeout: float | None,
) -> dict[str, Any]:
    binary = find_binary()
    try:
        r = subprocess.run(
            [binary, *args],
            input=stdin,
            stdin=subprocess.DEVNULL if stdin is None else None,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise SendScoreError(f"sendscore did not finish within {timeout} seconds", KILLED) from e
    except OSError as e:
        raise SendScoreError(f"could not run {binary}: {e}", 0) from e
    code = KILLED if r.returncode < 0 or r.returncode >= 128 else r.returncode
    if code not in verdict_codes:
        text = r.stderr.decode(errors="replace").strip()
        raise SendScoreError(text or f"sendscore exited {code}", code)
    try:
        result = json.loads(r.stdout)
    except ValueError as e:
        raise SendScoreError("sendscore printed something that is not JSON", code) from e
    if not isinstance(result, dict):
        raise SendScoreError("sendscore printed something that is not a report", code)
    return cast("dict[str, Any]", result)


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
    timeout: float | None = None,
) -> Verdict:
    """Checks one message, given as a path or as its bytes.

    A message that fails checks is still a report. This raises SendScoreError
    only when no report could be made. With a timeout in seconds, the CLI is
    killed when it runs out.
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
        args += ["--previous", _path(previous)]
    is_bytes = isinstance(message, (bytes, bytearray))
    args += ["--", "-" if is_bytes else _path(message)]  # type: ignore[arg-type]
    result = _run(args, bytes(message) if is_bytes else None, (0, 1, 2), timeout)  # type: ignore[arg-type]
    if not str(result.get("schema", "")).startswith("sendscore.verdict/"):
        raise SendScoreError("sendscore printed something that is not a verdict", 0)
    return cast(Verdict, result)


def diff(
    before: str | os.PathLike[str],
    after: str | os.PathLike[str],
    *,
    timeout: float | None = None,
) -> DiffResult:
    """Compares two saved messages, given as paths."""
    result = _run(["diff", "--json", "--", _path(before), _path(after)], None, (0, 1), timeout)
    if "changes" not in result:
        raise SendScoreError("sendscore printed something that is not a comparison", 0)
    result["changes"] = result.get("changes") or []
    return cast(DiffResult, result)
