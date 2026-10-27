#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Writes npm/checksums.json and python/qorescan/checksums.json from the
GoReleaser checksum file, so each wrapper package carries the SHA-256 of
every raw release binary it may download.

Usage: scripts/wrapper-checksums.py dist/qorescan_<version>_checksums.txt <version>
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [("darwin", "amd64"), ("darwin", "arm64"), ("linux", "amd64"), ("linux", "arm64"), ("windows", "amd64"), ("windows", "arm64")]


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    checksums, version = Path(sys.argv[1]), sys.argv[2]
    sums = {}
    for line in checksums.read_text().splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})\s+\*?(\S+)", line.strip())
        if m:
            sums[m.group(2)] = m.group(1)
    files = {}
    for goos, arch in TARGETS:
        name = f"qorescan_{version}_{goos}_{arch}" + (".exe" if goos == "windows" else "")
        if name not in sums:
            print(f"missing {name} in {checksums}", file=sys.stderr)
            return 1
        files[name] = sums[name]
    doc = json.dumps({"version": version, "files": files}, indent=2) + "\n"
    for path in (ROOT / "npm" / "checksums.json", ROOT / "python" / "qorescan" / "checksums.json"):
        path.write_text(doc)
        print(f"wrote {path.relative_to(ROOT)}")
    for path, pattern in ((ROOT / "npm" / "package.json", r'"version": "[^"]+"'), (ROOT / "python" / "pyproject.toml", r'^version = "[^"]+"')):
        text = path.read_text()
        found = re.search(pattern, text, re.M)
        if not found or version not in found.group(0):
            print(f"{path.relative_to(ROOT)} version does not match {version}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
