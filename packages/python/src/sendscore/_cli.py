"""The sendscore command: finds the CLI the same way the library does, then runs it."""

from __future__ import annotations

import os
import subprocess
import sys

from ._binary import find_binary
from ._error import SendScoreError

# EX_SOFTWARE, as the CLI uses for an internal error.
INTERNAL = 70

# The PATH search may find this launcher and run it to read its version. The
# mark makes that run fail at once, so the search moves on instead of looping.
MARK = "SENDSCORE_LAUNCHED"


def main() -> int:
    if os.environ.get(MARK):
        print("sendscore: found itself instead of the CLI", file=sys.stderr)
        return INTERNAL
    os.environ[MARK] = "1"
    try:
        path = find_binary()
    except SendScoreError as e:
        print(f"sendscore: {e}", file=sys.stderr)
        return INTERNAL
    args = [path, *sys.argv[1:]]
    if os.name == "nt":
        # Windows has no real exec: os.execv would return to the shell early.
        try:
            return subprocess.run(args, check=False).returncode
        except OSError as e:
            print(f"sendscore: could not run {path}: {e}", file=sys.stderr)
            return INTERNAL
        except KeyboardInterrupt:
            return 130
    try:
        os.execv(path, args)
    except OSError as e:
        print(f"sendscore: could not run {path}: {e}", file=sys.stderr)
        return INTERNAL
    return INTERNAL
