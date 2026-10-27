# QoreScan Community

QoreScan inventories the cryptography of a [QoreChain](https://www.qorechain.io) deployment and writes it as a **CycloneDX 1.6 CBOM** (cryptographic bill of materials). It reads a node home directory, the live state of the network, TLS endpoints and Solidity sources, and records each algorithm, protocol, certificate and key it finds, with the file and line or the endpoint where it was found.

From the CBOM it produces Markdown reports that map the inventory to FINMA Guidance 05/2026, the EU NIS Cooperation Group PQC roadmap and the DORA RTS on ICT risk management (Article 6), with a status per algorithm against FIPS 203/204/205 and the NIST IR 8547 transition timeline. Two templates, a crypto-agility statement and a five-question vendor questionnaire, are pre-filled from the scanned facts only.

> **QoreScan is an inventory aid.** It is not a certification, an audit or a legal opinion, and it does not establish conformity with any regulation or standard. Anything the scan cannot establish is left as "to be completed".

## What it reads, and what it never reads

| Source | What QoreScan records |
|---|---|
| Node home (`--node-home`) | `config.toml`: P2P transport, RPC TLS certificate, key file locations, remote signer. `app.toml`: listeners and the EVM JSON-RPC TLS certificate. `genesis.json`: pqc module parameters, the on-chain algorithm registry, validator consensus key types. `priv_validator_key.json`: key type, public key and address. `node_key.json`: key type. |
| Network (`--network`, `--rest`) | Protocol feature switches, pqc parameters, consensus key types of the active validator set, active EVM precompiles, and for each `--address` its PQC key status (`/qorechain/pqc/v1/account/{address}`) and published KEM key. |
| TLS (`--tls`, `qorescan tls`) | One handshake: protocol version, cipher suite, key exchange group (including hybrid ML-KEM groups), the certificates and their public key and signature algorithms. |
| Solidity (`--solidity`, `qorescan solidity`) | `ecrecover`, calls to the ecrecover (0x01), pqcVerify (0x0A01), pqcKeyStatus (0x0A02) and P-256 (0x100) precompiles, hashing, and OpenZeppelin, Solady and IQorePQC imports. |

QoreScan **never reads private key values**. Key files are decoded into structures that have no field for the private key, so its bytes are never decoded, stored, logged or written; a test checks that freshly generated private keys never appear in any output or log. Keyring directories and the key files named by `tls_key_file` and `tls.key-path` are not opened. Every request to the network is a read-only GET. See [what is scanned](docs/scanned-data.md).

## Install

| Channel | Command |
|---|---|
| Release binary (macOS, Linux, Windows) | download from [GitHub releases](https://github.com/qorechain/qorescan/releases) and check it against `qorescan_<version>_checksums.txt` |
| Go | `go install github.com/qorechain/qorescan/cmd/qorescan@latest` |
| npm | `npx @qorechain/qorescan scan ...` |
| PyPI | `pipx run qorescan scan ...` |
| Docker | `docker build -t qorescan .` (runs as a non-root user) |
| GitHub Actions | `uses: qorechain/qorescan@<commit sha>` |

The npm and PyPI packages download the release binary for your platform and verify its SHA-256 against digests shipped inside the package; they refuse to run a binary that does not match.

## Use

```bash
# Node home plus live mainnet state, one CBOM
qorescan scan --node-home ~/.qorechain --network mainnet --out cbom.json

# PQC key status of accounts, TLS endpoints and contracts in the same scan
qorescan scan --network testnet --address qor1... --tls rpc.example.org:443 --solidity ./contracts --out cbom.json

# Single sources
qorescan tls api.example.org:443 --out tls.json
qorescan solidity ./contracts --out contracts.json

# Reports and templates from a CBOM
qorescan report --framework finma --cbom cbom.json --out finma.md
qorescan report --framework nis   --cbom cbom.json
qorescan report --framework dora  --cbom cbom.json
qorescan template agility       --cbom cbom.json --out agility-statement.md
qorescan template questionnaire --cbom cbom.json --out vendor-questionnaire.md
```

See [usage](docs/usage.md) for every flag, the GitHub Action and Docker.

## Output

A CycloneDX 1.6 JSON document. Each finding is a `cryptographic-asset` component with `cryptoProperties` (asset type, primitive, parameter set, curve, classical security level, NIST quantum security category where one is defined, OID) and `evidence.occurrences` (file and line, or endpoint). Certificates link to their signature algorithm and public key, protocols to the algorithms they use, libraries to the algorithms they provide. QoreScan adds a few `qorescan:*` properties (classification, NIST IR 8547 transition, standard, source) and records scanned facts and notes in the metadata. Paths are always relative to the scanned directory.

Every CBOM written in the tests is validated against the official CycloneDX 1.6 JSON schema.

## Documentation

- [Usage](docs/usage.md)
- [What is scanned and what is never read](docs/scanned-data.md)
- [Framework mapping and sources](docs/frameworks.md)
- [Limitations](docs/limitations.md)
- [Design and licence check](docs/design.md): why QoreScan writes the CBOM format itself instead of extending CBOMkit

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE). Copyright 2026 QoreChain Association.
