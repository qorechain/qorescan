# SPDX-License-Identifier: Apache-2.0
"""Exercises the wrapper against a qorescan binary built from this repository
and served from a local HTTP server. Nothing is published or fetched from the
internet. Run from the repository root: python -m unittest discover -s python/tests
"""

from __future__ import annotations

import functools
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PKG = REPO / "python" / "qorescan"
VERSION = json.loads((PKG / "checksums.json").read_text())["version"]

_built: Path | None = None


def built_binary() -> Path:
    global _built
    if os.environ.get("QORESCAN_TEST_BINARY"):
        return Path(os.environ["QORESCAN_TEST_BINARY"])
    if _built is None:
        d = Path(tempfile.mkdtemp(prefix="qorescan-build-"))
        _built = d / ("qorescan.exe" if sys.platform.startswith("win") else "qorescan")
        subprocess.run(
            ["go", "build", "-trimpath", "-ldflags", f"-X main.version={VERSION}", "-o", str(_built), "./cmd/qorescan"],
            cwd=REPO,
            check=True,
        )
    return _built


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass


class WrapperTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="qorescan-py-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        sys.path.insert(0, str(REPO / "python"))
        self.addCleanup(sys.path.remove, str(REPO / "python"))
        import qorescan

        self.name = qorescan.asset_name()

    def prepare(self, tamper=False, omit_digest=False):
        binary = built_binary().read_bytes()
        served = self.dir / "release"
        served.mkdir()
        (served / self.name).write_bytes(binary + (b"\0" if tamper else b""))
        pkg_root = self.dir / "pkg"
        shutil.copytree(PKG, pkg_root / "qorescan", ignore=shutil.ignore_patterns("__pycache__"))
        files = {} if omit_digest else {self.name: hashlib.sha256(binary).hexdigest()}
        (pkg_root / "qorescan" / "checksums.json").write_text(json.dumps({"version": VERSION, "files": files}))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=str(served)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.env = {
            **os.environ,
            "PYTHONPATH": str(pkg_root),
            "QORESCAN_DOWNLOAD_BASE": f"http://127.0.0.1:{server.server_address[1]}/",
            "QORESCAN_CACHE_DIR": str(self.dir / "cache"),
        }
        self.cached = self.dir / "cache" / VERSION / self.name

    def run_wrapper(self, *args):
        return subprocess.run([sys.executable, "-m", "qorescan", *args], env=self.env, capture_output=True, text=True)

    def test_downloads_verifies_and_runs(self):
        self.prepare()
        r = self.run_wrapper("version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), f"qorescan {VERSION}")
        self.assertTrue(self.cached.exists())
        self.assertEqual(self.run_wrapper("version").returncode, 0)

    def test_passes_exit_code(self):
        self.prepare()
        self.assertEqual(self.run_wrapper("no-such-command").returncode, 2)

    def test_refuses_mismatched_download(self):
        self.prepare(tamper=True)
        r = self.run_wrapper("version")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SHA-256 mismatch", r.stderr)
        self.assertEqual(r.stdout, "")
        self.assertFalse(self.cached.exists())
        self.assertEqual(list((self.dir / "cache" / VERSION).iterdir()), [])

    def test_refuses_modified_cache(self):
        self.prepare()
        self.assertEqual(self.run_wrapper("version").returncode, 0)
        with self.cached.open("ab") as f:
            f.write(b"x")
        r = self.run_wrapper("version")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SHA-256 mismatch for the cached", r.stderr)
        self.assertEqual(r.stdout, "")

    def test_refuses_without_digest(self):
        self.prepare(omit_digest=True)
        r = self.run_wrapper("version")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no SHA-256", r.stderr)


if __name__ == "__main__":
    unittest.main()
