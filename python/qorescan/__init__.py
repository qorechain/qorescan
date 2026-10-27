# SPDX-License-Identifier: Apache-2.0
"""Runs the qorescan release binary for this platform.

The binary is downloaded on first use and its SHA-256 is checked against
checksums.json, which is generated from the release's checksum file and
shipped inside this package. A binary whose digest does not match is never
executed.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

__all__ = ["main", "ensure_binary", "asset_name", "ChecksumError"]

_MANIFEST = json.loads((Path(__file__).parent / "checksums.json").read_text(encoding="utf-8"))
__version__ = _MANIFEST["version"]

DEFAULT_BASE = f"https://github.com/qorechain/qorescan/releases/download/v{__version__}/"


class ChecksumError(RuntimeError):
    """A binary's SHA-256 does not match the published digest."""


def _target() -> tuple[str, str]:
    if sys.platform.startswith("darwin"):
        goos = "darwin"
    elif sys.platform.startswith("linux"):
        goos = "linux"
    elif sys.platform.startswith("win"):
        goos = "windows"
    else:
        raise RuntimeError(f"no qorescan binary for {sys.platform}")
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if arch is None:
        raise RuntimeError(f"no qorescan binary for {sys.platform}/{machine}")
    return goos, arch


def asset_name() -> str:
    goos, arch = _target()
    return f"qorescan_{__version__}_{goos}_{arch}" + (".exe" if goos == "windows" else "")


def cache_dir() -> Path:
    if os.environ.get("QORESCAN_CACHE_DIR"):
        return Path(os.environ["QORESCAN_CACHE_DIR"])
    if sys.platform.startswith("win") and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "qorescan" / "Cache"
    if sys.platform.startswith("darwin"):
        return Path.home() / "Library" / "Caches" / "qorescan"
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "qorescan"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _expected(name: str) -> str:
    digest = _MANIFEST.get("files", {}).get(name, "")
    if not re.fullmatch(r"[0-9a-f]{64}", digest or ""):
        raise ChecksumError(f"checksums.json has no SHA-256 for {name}; refusing to run")
    return digest


def ensure_binary() -> Path:
    """Return the path of a verified binary, downloading it if needed."""
    name = asset_name()
    want = _expected(name)
    directory = cache_dir() / __version__
    target = directory / name
    if target.exists():
        got = _sha256(target)
        if got != want:
            raise ChecksumError(
                f"SHA-256 mismatch for the cached {name} (expected {want}, got {got}); "
                f"refusing to run. Delete {target} to download it again."
            )
        return target

    directory.mkdir(parents=True, exist_ok=True)
    base = os.environ.get("QORESCAN_DOWNLOAD_BASE") or DEFAULT_BASE
    if not base.endswith("/"):
        base += "/"
    url = base + name
    if not url.startswith(("https://", "http://")):
        raise RuntimeError(f"unsupported download URL {url}")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{name}.", suffix=".download", dir=directory)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 (scheme checked above)
            for chunk in iter(lambda: resp.read(1 << 20), b""):
                out.write(chunk)
        got = _sha256(tmp)
        if got != want:
            raise ChecksumError(
                f"SHA-256 mismatch for {name} downloaded from {url} (expected {want}, got {got}); refusing to run"
            )
        tmp.chmod(0o755)
        os.replace(tmp, target)
    finally:
        if tmp.exists():
            tmp.unlink()
    return target


def main() -> None:
    try:
        binary = ensure_binary()
    except Exception as e:  # report every failure the same way and exit
        print(f"qorescan: {e}", file=sys.stderr)
        sys.exit(1)
    sys.exit(subprocess.call([str(binary), *sys.argv[1:]]))
