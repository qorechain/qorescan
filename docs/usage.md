# Usage

```
qorescan scan [--node-home DIR] [--network mainnet|testnet | --rest URL] [--address ADDR]...
              [--tls HOST:PORT]... [--solidity DIR]... [--out FILE]
qorescan tls HOST:PORT... [--out FILE]
qorescan solidity DIR... [--out FILE]
qorescan report --framework finma|nis|dora --cbom FILE [--out FILE]
qorescan template agility|questionnaire --cbom FILE [--out FILE]
qorescan version
```

Flags may come before or after positional arguments. `--out -` (the default) writes to standard output.

## `scan`

Combines any of the sources below into one CBOM. At least one source is required.

| Flag | Meaning |
|---|---|
| `--node-home DIR` | Node home directory, the one that contains `config/`. |
| `--network mainnet\|testnet` | Read live state from `https://api.qore.host` (mainnet, `qorechain-vladi`) or `https://api-testnet.qore.host` (testnet, `qorechain-diana`). |
| `--rest URL` | Any REST endpoint instead, for example your own node (`http://127.0.0.1:1317`). Overrides `--network`. |
| `--address ADDR` | Account whose PQC key status and KEM key are read. Repeatable. Needs `--network` or `--rest`. |
| `--tls HOST:PORT` | TLS endpoint to handshake with. Repeatable. Port 443 is assumed when omitted. |
| `--solidity PATH` | Directory or `.sol` file. Repeatable. `node_modules`, `lib`, `out`, `cache`, `artifacts` and `typechain-types` are skipped unless `--include-deps` is given. |
| `--name NAME` | Name of the scanned deployment in the CBOM metadata. |
| `--timeout D` | Network timeout per request (default `20s`). |
| `--verbose` | Log each file read and each request to standard error. |

Exit codes: `0` success, `1` a scan or I/O error, `2` a usage error.

Timestamps: the CBOM timestamp is the current time, or `SOURCE_DATE_EPOCH` when set. The serial number is derived from the content, so the same input at the same time gives the same document.

### Reading a network without direct internet access

If the machine running QoreScan cannot reach the public endpoints, point `--rest` at a node you run or at a relay that forwards GET requests to the public endpoint. QoreScan only sends GET requests.

## `tls`

Performs one TLS handshake per endpoint with Go's default client preferences, which offer the hybrid groups `X25519MLKEM768`, `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` first. The negotiated group therefore shows whether the server supports hybrid post-quantum key exchange. TLS 1.0 and later are accepted so that old servers are recorded (and noted). The certificate chain is verified against the system roots separately; the result is a property of the leaf certificate, not a reason to abort. `--servername` overrides SNI.

## `solidity`

Text-based detection on source files, with comments and string literals blanked first. See [what is scanned](scanned-data.md#solidity-sources) for the patterns.

## `report`

Reads a CBOM (QoreScan's or another tool's CycloneDX 1.6 CBOM) and writes Markdown: the framework mapping table, a summary by classification, every algorithm with its NIST category, its status against FIPS 203/204/205 and NIST IR 8547, and its evidence, then protocols, certificates, keys, libraries, scanned facts, scan notes and the cited sources. See [frameworks](frameworks.md).

## `template`

- `agility`: a crypto-agility statement (scope, algorithms in use, ability to replace algorithms, transition plan, responsibilities).
- `questionnaire`: five questions for a vendor or service provider, following the five measures of FINMA Guidance 05/2026 section 3.

Both are pre-filled only with facts the CBOM contains. Everything else reads "To be completed".

## npm and PyPI

```bash
npx @qorechain/qorescan scan --network mainnet --out cbom.json
pipx run qorescan scan --network mainnet --out cbom.json
```

Both packages download `qorescan_<version>_<os>_<arch>` from the matching GitHub release on first use, check its SHA-256 against the digests shipped in the package (`checksums.json`), and refuse to run if it does not match, both after the download and on every later run of the cached copy. The binary is cached in the user cache directory (`QORESCAN_CACHE_DIR` overrides it). `QORESCAN_DOWNLOAD_BASE` sets another download location, for a mirror; the digest check still applies.

## GitHub Action

```yaml
permissions:
  contents: read
steps:
  - uses: actions/checkout@<sha>
  - id: qorescan
    uses: qorechain/qorescan@<commit sha>
    with:
      solidity: contracts
      network: mainnet
      addresses: qor1...
      out: qorescan.cbom.json
      framework: finma
  - uses: actions/upload-artifact@<sha>
    with:
      name: cbom
      path: |
        ${{ steps.qorescan.outputs.cbom }}
        ${{ steps.qorescan.outputs.report }}
```

The action builds qorescan from its own source at the pinned commit, so no binary is downloaded. Inputs: `node-home`, `network`, `rest`, `addresses`, `tls`, `solidity` (lists separated by spaces or new lines), `out`, `framework`. Outputs: `cbom`, `report`.

## Docker

```bash
docker build -t qorescan .
docker run --rm -v "$HOME/.qorechain:/scan/home:ro" qorescan scan --node-home /scan/home > cbom.json
```

The image is distroless and runs as user 65532. Mount the node home read-only.
