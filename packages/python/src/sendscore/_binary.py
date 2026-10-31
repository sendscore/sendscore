"""Finds the CLI, and downloads a release when none is installed."""

from __future__ import annotations

import gzip
import hashlib
import http.client
import io
import os
import platform
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from ._error import SendScoreError
from ._hashes import HASHES

ENGINE_VERSION = "0.2.0"
RELEASES = "https://github.com/sendscore/sendscore/releases/download"
MAX_DOWNLOAD = 100 << 20

_OS = {"linux": "linux", "darwin": "darwin", "win32": "windows"}
_ARCH = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}


def current_platform() -> tuple[str, str]:
    os_name = _OS.get(sys.platform)
    arch = _ARCH.get(platform.machine().lower())
    if not os_name or not arch:
        raise SendScoreError(f"no SendScore build for {sys.platform} on {platform.machine()}", 0)
    return os_name, arch


def _cache_root() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches"
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    xdg = os.environ.get("XDG_CACHE_HOME")
    return Path(xdg) if xdg and os.path.isabs(xdg) else Path.home() / ".cache"


def archive_name(version: str, os_name: str, arch: str) -> str:
    ext = "zip" if os_name == "windows" else "tar.gz"
    return f"sendscore_{version}_{os_name}_{arch}.{ext}"


def _fetch(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=60) as res:
            body = res.read(MAX_DOWNLOAD + 1)
    except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
        raise SendScoreError(f"download of {url} failed: {e}", 0) from e
    if len(body) > MAX_DOWNLOAD:
        raise SendScoreError(f"download of {url} is too large", 0)
    return body


def pin_for(os_name: str, arch: str, pins: dict[str, tuple[str, str]] = HASHES) -> tuple[str, str]:
    """The (archive, binary) hashes of a platform. With none, nothing is trusted."""
    pin = pins.get(f"{os_name}_{arch}")
    if pin is None:
        raise SendScoreError(
            f"this package has no pinned hash for {os_name}_{arch}, so it will not download a CLI. "
            "Install the matching sendscore on PATH, or set SENDSCORE_BIN.",
            0,
        )
    return pin


def matches_pin(path: Path, pin: tuple[str, str]) -> bool:
    """Whether a file exists and is exactly the pinned binary."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest() == pin[1]
    except OSError:
        return False


def _extract(archive: bytes, os_name: str, bin_name: str) -> bytes | None:
    # One file, by its exact name, so no path in the archive is ever used.
    try:
        if os_name == "windows":
            with zipfile.ZipFile(io.BytesIO(archive)) as z:
                return z.read(bin_name) if bin_name in z.namelist() else None
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(archive))) as t:
            for member in t:
                if member.name == bin_name and member.isfile():
                    f = t.extractfile(member)
                    return f.read() if f else None
    except (OSError, EOFError, zipfile.BadZipFile, tarfile.TarError) as e:
        raise SendScoreError(f"could not read the archive: {e}", 0) from e
    return None


def download(
    version: str,
    base: str,
    directory: Path,
    pin: tuple[str, str],
    target: tuple[str, str] | None = None,
) -> Path:
    """Downloads a release into directory, and returns the binary's path.

    The archive must match its pin before anything is extracted, and the
    binary must match its pin before it reaches the disk.
    """
    os_name, arch = target or current_platform()
    bin_name = "sendscore.exe" if os_name == "windows" else "sendscore"
    name = archive_name(version, os_name, arch)
    archive = _fetch(f"{base}/{name}")
    if hashlib.sha256(archive).hexdigest() != pin[0]:
        raise SendScoreError(f"{name} does not match its pinned hash", 0)
    binary = _extract(archive, os_name, bin_name)
    if binary is None:
        raise SendScoreError(f"{name} has no {bin_name}", 0)
    if hashlib.sha256(binary).hexdigest() != pin[1]:
        raise SendScoreError(f"the binary in {name} does not match its pinned hash", 0)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(dir=directory, prefix=".download-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(binary)
            os.chmod(temp, 0o755)
            path = directory / bin_name
            os.replace(temp, path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    except OSError as e:
        raise SendScoreError(f"could not write to {directory}: {e}", 0) from e
    return path


def _executable(path: str) -> bool:
    try:
        return stat.S_ISREG(os.stat(path).st_mode) and os.access(path, os.X_OK)
    except OSError:
        return False


def _right_version(path: str) -> bool:
    try:
        r = subprocess.run(
            [path, "--version"], stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False
    words = r.stdout.decode(errors="replace").split()
    return r.returncode == 0 and bool(words) and words[-1].removeprefix("v") == ENGINE_VERSION


def find_binary() -> str:
    """Finds the CLI: SENDSCORE_BIN, then the pinned version on PATH, then the cache, then a download.

    A cached binary is checked against its pinned hash every time, so a file
    planted in the cache is replaced and never run.
    """
    from_env = os.environ.get("SENDSCORE_BIN")
    if from_env:
        return from_env
    name = "sendscore.exe" if sys.platform == "win32" else "sendscore"
    # A search of its own, because shutil.which looks in the current directory
    # on Windows, and follows PATHEXT to .bat and .cmd files.
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(entry, name)
        if os.path.isabs(entry) and _executable(candidate) and _right_version(candidate):
            return candidate
    target = current_platform()
    pin = pin_for(*target)
    directory = _cache_root() / "sendscore" / ENGINE_VERSION
    cached = directory / name
    if matches_pin(cached, pin):
        return str(cached)
    return str(download(ENGINE_VERSION, f"{RELEASES}/v{ENGINE_VERSION}", directory, pin, target))
