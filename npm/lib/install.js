// SPDX-License-Identifier: Apache-2.0
//
// Downloads the qorescan release binary for this platform and checks its
// SHA-256 against checksums.json, which is generated from the release's
// checksum file and published inside this package. A binary whose digest
// does not match is never executed.
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const pkgDir = path.join(__dirname, "..");
const manifest = JSON.parse(fs.readFileSync(path.join(pkgDir, "checksums.json"), "utf8"));

const DEFAULT_BASE = `https://github.com/qorechain/qorescan/releases/download/v${manifest.version}/`;

function platformTarget() {
  const osMap = { darwin: "darwin", linux: "linux", win32: "windows" };
  const archMap = { x64: "amd64", arm64: "arm64" };
  const goos = osMap[process.platform];
  const goarch = archMap[process.arch];
  if (!goos || !goarch) {
    throw new Error(`no qorescan binary for ${process.platform}/${process.arch}`);
  }
  return { goos, goarch };
}

function assetName() {
  const { goos, goarch } = platformTarget();
  return `qorescan_${manifest.version}_${goos}_${goarch}${goos === "windows" ? ".exe" : ""}`;
}

function cacheDir() {
  if (process.env.QORESCAN_CACHE_DIR) return process.env.QORESCAN_CACHE_DIR;
  if (process.platform === "win32" && process.env.LOCALAPPDATA) {
    return path.join(process.env.LOCALAPPDATA, "qorescan", "Cache");
  }
  if (process.platform === "darwin") return path.join(os.homedir(), "Library", "Caches", "qorescan");
  return path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache"), "qorescan");
}

function sha256File(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function expectedDigest(name) {
  const digest = manifest.files[name];
  if (!/^[0-9a-f]{64}$/.test(digest || "")) {
    throw new Error(`checksums.json has no SHA-256 for ${name}; refusing to run`);
  }
  return digest;
}

async function download(url, dest) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) {
    throw new Error(`download of ${url} failed: HTTP ${res.status}`);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  fs.writeFileSync(dest, buf, { mode: 0o700 });
}

// ensureBinary returns the path of a verified binary, downloading it first if
// needed. It throws (and never returns a path) when a digest does not match.
async function ensureBinary() {
  const name = assetName();
  const want = expectedDigest(name);
  const dir = path.join(cacheDir(), manifest.version);
  const target = path.join(dir, name);

  if (fs.existsSync(target)) {
    const got = sha256File(target);
    if (got !== want) {
      throw new Error(
        `SHA-256 mismatch for the cached ${name} (expected ${want}, got ${got}); refusing to run. Delete ${target} to download it again.`
      );
    }
    return target;
  }

  fs.mkdirSync(dir, { recursive: true });
  const base = process.env.QORESCAN_DOWNLOAD_BASE || DEFAULT_BASE;
  const url = new URL(name, base.endsWith("/") ? base : base + "/").toString();
  const tmp = path.join(dir, `.${name}.${process.pid}.download`);
  try {
    await download(url, tmp);
    const got = sha256File(tmp);
    if (got !== want) {
      throw new Error(`SHA-256 mismatch for ${name} downloaded from ${url} (expected ${want}, got ${got}); refusing to run`);
    }
    fs.chmodSync(tmp, 0o755);
    fs.renameSync(tmp, target);
  } finally {
    fs.rmSync(tmp, { force: true });
  }
  return target;
}

module.exports = { ensureBinary, assetName, cacheDir, manifest };
