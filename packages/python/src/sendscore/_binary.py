"""Finds the CLI, and downloads a release when none is installed."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import platform
import shutil
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from ._error import SendScoreError

ENGINE_VERSION = "0.2.0"
RELEASES = "https://github.com/sendscore/sendscore/releases/download"

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
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")


def archive_name(version: str, os_name: str, arch: str) -> str:
    ext = "zip" if os_name == "windows" else "tar.gz"
    return f"sendscore_{version}_{os_name}_{arch}.{ext}"


def _fetch(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=60) as res:
            return res.read()
    except (urllib.error.URLError, OSError) as e:
        raise SendScoreError(f"download of {url} failed: {e}", 0) from e


def _expected_hash(checksums: str, name: str) -> str:
    for line in checksums.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == name:
            return parts[0].lower()
    raise SendScoreError(f"checksums.txt does not list {name}", 0)


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


def download(version: str, base: str, directory: Path, target: tuple[str, str] | None = None) -> Path:
    """Downloads a release into directory, and returns the binary's path.

    The archive is checked against checksums.txt before anything is
    extracted, so a binary that does not match never reaches the disk.
    """
    os_name, arch = target or current_platform()
    bin_name = "sendscore.exe" if os_name == "windows" else "sendscore"
    name = archive_name(version, os_name, arch)
    checksums = _fetch(f"{base}/checksums.txt").decode()
    archive = _fetch(f"{base}/{name}")
    if hashlib.sha256(archive).hexdigest() != _expected_hash(checksums, name):
        raise SendScoreError(f"{name} does not match checksums.txt", 0)
    binary = _extract(archive, os_name, bin_name)
    if binary is None:
        raise SendScoreError(f"{name} has no {bin_name}", 0)
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
    return path


def find_binary() -> str:
    """Finds the CLI: SENDSCORE_BIN, then PATH, then the cache, then a download."""
    from_env = os.environ.get("SENDSCORE_BIN")
    if from_env:
        return from_env
    on_path = shutil.which("sendscore")
    if on_path:
        return on_path
    directory = _cache_root() / "sendscore" / ENGINE_VERSION
    cached = directory / ("sendscore.exe" if sys.platform == "win32" else "sendscore")
    if os.access(cached, os.X_OK):
        return str(cached)
    return str(download(ENGINE_VERSION, f"{RELEASES}/v{ENGINE_VERSION}", directory))
