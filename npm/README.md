# @qorechain/qorescan

npm launcher for [QoreScan Community](https://github.com/qorechain/qorescan): a read-only tool that inventories the cryptography of a QoreChain deployment and writes a CycloneDX 1.6 CBOM.

```bash
npx @qorechain/qorescan scan --node-home ~/.qorechain --network mainnet --out cbom.json
npx @qorechain/qorescan report --framework finma --cbom cbom.json
```

On first use the package downloads the qorescan release binary for your platform from GitHub, checks its SHA-256 against the digests shipped in this package (`checksums.json`), and caches it. A binary whose digest does not match, after download or later in the cache, is never run. No install script runs at `npm install`.

- `QORESCAN_CACHE_DIR`: cache location (default: the user cache directory).
- `QORESCAN_DOWNLOAD_BASE`: download from a mirror instead; the digest check still applies.

QoreScan output is an inventory aid, not a certification or a legal opinion. Documentation: <https://github.com/qorechain/qorescan>. Apache-2.0.
