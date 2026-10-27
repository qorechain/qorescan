// SPDX-License-Identifier: Apache-2.0
//
// Exercises the wrapper against a qorescan binary built from this
// repository and served from a local HTTP server. Nothing is published or
// fetched from the internet.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn } = require("node:child_process");

const repo = path.join(__dirname, "..", "..");
const version = require("../package.json").version;

function goTarget() {
  const goos = { darwin: "darwin", linux: "linux", win32: "windows" }[process.platform];
  const goarch = { x64: "amd64", arm64: "arm64" }[process.arch];
  return { goos, goarch, name: `qorescan_${version}_${goos}_${goarch}${goos === "windows" ? ".exe" : ""}` };
}

// The binary is built once for all tests.
let built;
function buildBinary() {
  if (process.env.QORESCAN_TEST_BINARY) return process.env.QORESCAN_TEST_BINARY;
  if (!built) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qorescan-build-"));
    process.on("exit", () => fs.rmSync(dir, { recursive: true, force: true }));
    built = path.join(dir, "qorescan" + (process.platform === "win32" ? ".exe" : ""));
    execFileSync("go", ["build", "-trimpath", "-ldflags", `-X main.version=${version}`, "-o", built, "./cmd/qorescan"], { cwd: repo, stdio: "inherit" });
  }
  return built;
}

// run executes the wrapper asynchronously: the local HTTP server lives in
// this process, so a synchronous spawn would block it.
function runNode(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

// makePackage copies the wrapper into dir and writes checksums.json the way
// the release workflow does.
function makePackage(dir, files) {
  const pkg = path.join(dir, "pkg");
  for (const d of ["bin", "lib"]) {
    fs.mkdirSync(path.join(pkg, d), { recursive: true });
    for (const f of fs.readdirSync(path.join(__dirname, "..", d))) {
      fs.copyFileSync(path.join(__dirname, "..", d, f), path.join(pkg, d, f));
    }
  }
  fs.copyFileSync(path.join(__dirname, "..", "package.json"), path.join(pkg, "package.json"));
  fs.writeFileSync(path.join(pkg, "checksums.json"), JSON.stringify({ version, files }, null, 2));
  return pkg;
}

function serve(root) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const file = path.join(root, path.basename(decodeURIComponent(req.url)));
      if (!fs.existsSync(file)) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { "Content-Type": "application/octet-stream" });
      res.end(fs.readFileSync(file));
    });
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

async function setup(t, { tamper = false, omitDigest = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qorescan-npm-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const { name } = goTarget();
  const binary = fs.readFileSync(buildBinary());
  const served = path.join(dir, "release");
  fs.mkdirSync(served);
  fs.writeFileSync(path.join(served, name), tamper ? Buffer.concat([binary, Buffer.from([0])]) : binary);
  const pkg = makePackage(dir, omitDigest ? {} : { [name]: sha256(binary) });
  const server = await serve(served);
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  const env = {
    ...process.env,
    QORESCAN_DOWNLOAD_BASE: `http://127.0.0.1:${server.address().port}/`,
    QORESCAN_CACHE_DIR: path.join(dir, "cache"),
  };
  const run = (...args) => runNode([path.join(pkg, "bin", "qorescan.js"), ...args], env);
  return { dir, name, run, cached: path.join(dir, "cache", version, name) };
}

test("downloads, verifies and runs the binary", async (t) => {
  const { run, cached } = await setup(t);
  const r = await run("version");
  assert.strictEqual(r.status, 0, r.stderr);
  assert.strictEqual(r.stdout.trim(), `qorescan ${version}`);
  assert.ok(fs.existsSync(cached));
  const again = await run("version");
  assert.strictEqual(again.status, 0, again.stderr);
});

test("passes the exit code through", async (t) => {
  const { run } = await setup(t);
  const r = await run("no-such-command");
  assert.strictEqual(r.status, 2);
});

test("refuses a download whose SHA-256 does not match", async (t) => {
  const { run, cached, dir } = await setup(t, { tamper: true });
  const r = await run("version");
  assert.notStrictEqual(r.status, 0);
  assert.match(r.stderr, /SHA-256 mismatch/);
  assert.strictEqual(r.stdout, "");
  assert.ok(!fs.existsSync(cached), "a rejected binary must not be cached");
  const leftovers = fs.readdirSync(path.join(dir, "cache", version));
  assert.deepStrictEqual(leftovers, []);
});

test("refuses a cached binary that was modified", async (t) => {
  const { run, cached } = await setup(t);
  assert.strictEqual((await run("version")).status, 0);
  fs.appendFileSync(cached, "x");
  const r = await run("version");
  assert.notStrictEqual(r.status, 0);
  assert.match(r.stderr, /SHA-256 mismatch for the cached/);
  assert.strictEqual(r.stdout, "");
});

test("refuses to run without a published digest", async (t) => {
  const { run } = await setup(t, { omitDigest: true });
  const r = await run("version");
  assert.notStrictEqual(r.status, 0);
  assert.match(r.stderr, /no SHA-256/);
});
