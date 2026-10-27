# Cryptographic inventory mapped to DORA RTS on ICT risk management, Article 6

> **Disclaimer.** QoreScan output is an inventory aid. It is not a certification, an audit or a legal opinion, and it does not establish conformity with any regulation or standard. The mapping below shows where the inventory can serve as input; whether an organisation meets a requirement depends on facts outside the scan and is for the organisation and its advisers to assess.

| | |
|---|---|
| CBOM | `urn:uuid:00000000-0000-5000-8000-000000000000` |
| Generated | 2026-10-27T12:00:00Z by qorescan 0.1.0-test |
| Chain | `qorechain-diana` |
| Scanned | chain, node-home, solidity |

## Framework mapping

| RTS 2024/1774 | Requirement (paraphrased) | What this inventory provides | Status |
|---|---|---|---|
| Art. 6(1) | Develop, document and implement a policy on encryption and cryptographic controls. | Inventory input for the policy. | _To be completed._ |
| Art. 6(2)(a) | Rules for encrypting data at rest and in transit. | Key exchange of the scanned transports: Consensus engine P2P secret connection: X25519 (fixed by the protocol). Data at rest is not scanned. | In transit: input; at rest _to be completed._ |
| Art. 6(2)(c) | Rules for encrypting internal network connections and traffic with external parties. | P2P transport and TLS endpoint records; listeners without TLS are listed under scan notes. | Input for the scanned scope |
| Art. 6(2)(d) | Cryptographic key management in line with Article 7. | 8 key records (types and public keys only). | Key lifecycle _to be completed._ |
| Art. 6(3) | Criteria for selecting cryptographic techniques, considering leading practices and standards. | Each algorithm stated against FIPS 203/204/205 and NIST IR 8547 below. | Input |
| Art. 6(4) | Update or change cryptographic technology on the basis of developments in cryptanalysis. | Scanned evidence: on-chain algorithm registry with 2 entries (1 dilithium5 (signature, active, NIST level 5); 2 mlkem1024 (kem, active, NIST level 5)); native-lane hybrid signature mode required; algorithm migration dual-signature period of 1000000 blocks (module parameter). | Evidence listed; assessment _to be completed._ |
| Art. 6(5) | Record mitigation and monitoring measures adopted under paragraphs 3 and 4, with reasons. | Nothing: organisational record. | _To be completed._ |

## Summary

| Classification | Algorithms |
|---|---|
| post-quantum | 2: ML-DSA-87, ML-KEM-1024 |
| quantum-vulnerable | 4: ECDSA P-256, ECDSA secp256k1, Ed25519, X25519 |
| symmetric | 5: ChaCha20-Poly1305, HKDF-SHA256, Keccak-256, RIPEMD-160, SHA-256 |

NIST IR 8547 deprecates quantum-vulnerable public-key algorithms (RSA, ECDSA, EdDSA, finite-field and elliptic-curve DH) after 2030 and disallows them under NIST standards after 2035; applications may be given earlier dates.

## Algorithms and status

| Algorithm | Primitive | Parameter set | NIST category | FIPS 203/204/205 | NIST IR 8547 | Evidence |
|---|---|---|---|---|---|---|
| ECDSA P-256 | signature | - | 0 | not covered (quantum-vulnerable) | Deprecated after 2030, disallowed after 2035 (NIST IR 8547) | `contracts/Verifier.sol:36` (+1 more) |
| ECDSA secp256k1 | signature | - | 0 | not covered (quantum-vulnerable) | Deprecated after 2030, disallowed after 2035 (NIST IR 8547) | `config/genesis.json:31` (+8 more) |
| Ed25519 | signature | - | 0 | not covered (quantum-vulnerable) | Deprecated after 2030, disallowed after 2035 (NIST IR 8547) | `config/config.toml:8` (+7 more) |
| X25519 | key-agree | - | 0 | not covered (quantum-vulnerable) | Deprecated after 2030, disallowed after 2035 (NIST IR 8547) | `config/config.toml:22` |
| ML-DSA-87 | signature | 87 | 5 | FIPS 204 | Not scheduled for deprecation by NIST IR 8547 | `config/genesis.json:31` (+8 more) |
| ML-KEM-1024 | kem | 1024 | 5 | FIPS 203 | Not scheduled for deprecation by NIST IR 8547 | `config/genesis.json:51` (+1 more) |
| ChaCha20-Poly1305 | ae | 256 | not defined | not applicable (symmetric or hash) | Not a NIST-standardised algorithm; not scheduled by NIST IR 8547 | `config/config.toml:22` |
| HKDF-SHA256 | kdf | 256 | not defined | not applicable (symmetric or hash) | Not scheduled for deprecation by NIST IR 8547 | `config/config.toml:22` |
| Keccak-256 | hash | 256 | not defined | not applicable (symmetric or hash) | Not a NIST-standardised algorithm; not scheduled by NIST IR 8547 | `contracts/Verifier.sol:5` (+2 more) |
| RIPEMD-160 | hash | 160 | not defined | not applicable (symmetric or hash) | Not a NIST-standardised algorithm; not scheduled by NIST IR 8547 | `contracts/Verifier.sol:40` |
| SHA-256 | hash | 256 | 2 | not applicable (symmetric or hash) | Not scheduled for deprecation by NIST IR 8547 | `contracts/Verifier.sol:40` |

## Protocols

| Protocol | Version | Cipher suite | Key exchange | Algorithms |
|---|---|---|---|---|
| Consensus engine P2P secret connection | - | - | X25519 | X25519, Ed25519, HKDF-SHA256, ChaCha20-Poly1305 |

## Keys

QoreScan records public keys and key types only; it never reads private key values.

| Key | Type | Algorithm | Count | Evidence |
|---|---|---|---|---|
| Account classical public key qor1fixtureaccount | public-key | ECDSA secp256k1 | - | `http://chain.test/qorechain/pqc/v1/account/qor1fixtureaccount` |
| Account KEM public key qor1fixtureaccount | public-key | ML-KEM-1024 | - | `http://chain.test/qorechain/pqc/v1/kem/qor1fixtureaccount` |
| Account PQC public key qor1fixtureaccount | public-key | ML-DSA-87 | - | `http://chain.test/qorechain/pqc/v1/account/qor1fixtureaccount` |
| Active validator consensus public keys (Ed25519) | public-key | Ed25519 | 3 | `http://chain.test/cosmos/base/tendermint/v1beta1/validatorsets/latest?pagination.limit=1000` |
| Genesis validator consensus public keys (Ed25519) | public-key | Ed25519 | 1 | `config/genesis.json:15` |
| Node identity private key (file) | private-key | Ed25519 | - | `config/node_key.json` |
| Validator consensus private key (file) | private-key | Ed25519 | - | `config/priv_validator_key.json` |
| Validator consensus public key | public-key | Ed25519 | - | `config/priv_validator_key.json` |

## Libraries

| Library | Provides | Evidence |
|---|---|---|
| @openzeppelin/contracts ECDSA | ECDSA secp256k1 | `contracts/Verifier.sol:4` |
| @openzeppelin/contracts MessageHashUtils / EIP712 | Keccak-256 | `contracts/Verifier.sol:5` |
| qorechain IQorePQC | ML-DSA-87 | `contracts/Verifier.sol:6` |

## Scanned facts

| Fact | Value |
|---|---|
| `chain:account-pqc-status` | qor1fixtureaccount: hybrid key, dilithium5 |
| `chain:app-version` | v0.0.0-fixture |
| `chain:consensus-engine-version` | 0.38.26 |
| `chain:evm:active-precompile` | rlConsensusParams (0x0000000000000000000000000000000000000C01); pqcVerify (0x0000000000000000000000000000000000000a01); pqcKeyStatus (0x0000000000000000000000000000000000000a02); p256 (0x0000000000000000000000000000000000000100) |
| `chain:id` | qorechain-diana |
| `chain:pqc:allow-classical-fallback` | false |
| `chain:pqc:default-migration-blocks` | 1000000 |
| `chain:pqc:hybrid-signature-mode` | required |
| `chain:pqc:min-security-level` | 5 |
| `chain:pqc:pqc-primary` | true |
| `chain:protocol-feature` | pqc-sign-bytes-v2; evm-pqc-authorisation-window |
| `chain:protocol-features` | 3 enabled at height 123456 (2 PQC-related listed) |
| `chain:rest` | http://chain.test |
| `genesis:chain-id` | qorechain-fixture |
| `genesis:pqc:accounts` | 1 (hybrid 1) |
| `genesis:pqc:allow-classical-fallback` | false |
| `genesis:pqc:default-migration-blocks` | 1000000 |
| `genesis:pqc:default-signature-algorithm-id` | 1 |
| `genesis:pqc:hybrid-signature-mode` | required |
| `genesis:pqc:min-security-level` | 5 |
| `genesis:pqc:pqc-primary` | true |
| `genesis:pqc:registry` | 1 dilithium5 (signature, active, NIST level 5); 2 mlkem1024 (kem, active, NIST level 5) |
| `genesis:protocol-feature` | pqc-sign-bytes-v2; evm-pqc-authorisation-window |
| `genesis:protocol-features` | 3 enabled at genesis (2 PQC-related listed) |
| `genesis:validator-pub-key-type` | ed25519 |

## Scan notes

- [info] node-home: RPC listener tcp://0.0.0.0:26657 binds a non-loopback address without TLS configured on the node; if TLS is terminated by a proxy, scan that endpoint with `qorescan tls` (config/config.toml:14)
- [info] node-home: REST API listener tcp://0.0.0.0:1317 binds a non-loopback address without TLS configured on the node; if TLS is terminated by a proxy, scan that endpoint with `qorescan tls` (config/app.toml:5)
- [info] node-home: EVM JSON-RPC listener 0.0.0.0:8545 binds a non-loopback address without TLS configured on the node; if TLS is terminated by a proxy, scan that endpoint with `qorescan tls` (config/app.toml:13)
- [info] node-home: account keyring directory present (file backend); not opened (keyring-file)

## Sources

- Commission Delegated Regulation (EU) 2024/1774 of 13 March 2024 (regulatory technical standards on the ICT risk management framework under Regulation (EU) 2022/2554, DORA), Article 6: <https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj>
- NIST IR 8547, "Transition to Post-Quantum Cryptography Standards", final, October 2026: <https://doi.org/10.6028/NIST.IR.8547>
- FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard: <https://csrc.nist.gov/pubs/fips/203/final>
- FIPS 204, Module-Lattice-Based Digital Signature Standard: <https://csrc.nist.gov/pubs/fips/204/final>
- FIPS 205, Stateless Hash-Based Digital Signature Standard: <https://csrc.nist.gov/pubs/fips/205/final>

The framework rows paraphrase the source documents; read the sources for the authoritative wording.
