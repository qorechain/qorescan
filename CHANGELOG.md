# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org); before 1.0, a minor version may contain breaking changes, which are always called out.

## [0.1.0] - 2026-10-27

First release.

### Added

- `qorescan scan`: one CycloneDX 1.6 CBOM from a node home directory, the live network (mainnet or testnet REST), account PQC key status, TLS endpoints and Solidity sources.
- Node home scanning: P2P transport, RPC and EVM JSON-RPC TLS certificates, listeners without TLS, remote signer, validator and node key types and public keys (private key values are never read), key file permissions, genesis pqc parameters, on-chain algorithm registry and validator consensus key types.
- Network scanning over read-only REST: protocol feature switches, pqc parameters, validator set key types, active EVM precompiles, PQC and KEM keys of given accounts.
- `qorescan tls`: negotiated TLS version, cipher suite, key exchange group (hybrid ML-KEM groups included) and certificates.
- `qorescan solidity`: ecrecover, the ecrecover, pqcVerify, pqcKeyStatus and P-256 precompiles, hashing, and OpenZeppelin, Solady and IQorePQC imports.
- `qorescan report --framework finma|nis|dora`: mapping to FINMA Guidance 05/2026, the EU NIS Cooperation Group PQC roadmap and DORA RTS Article 6, with a status per algorithm against FIPS 203/204/205 and NIST IR 8547.
- `qorescan template agility|questionnaire`: crypto-agility statement and five-question vendor questionnaire, pre-filled only from scanned facts.
- Distribution: GoReleaser configuration (macOS, Linux, Windows; amd64 and arm64; SHA-256 checksums), non-root Docker image, GitHub Action, npm package `@qorechain/qorescan` and PyPI package `qorescan` that verify the binary's SHA-256 before running it.
