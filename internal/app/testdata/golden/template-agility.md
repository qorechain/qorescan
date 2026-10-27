# Crypto-agility statement (draft)

> **Disclaimer.** QoreScan output is an inventory aid. It is not a certification, an audit or a legal opinion, and it does not establish conformity with any regulation or standard. This draft is pre-filled only with facts the scan recorded; the organisation is responsible for completing, checking and adopting it.

Prepared from CBOM `urn:uuid:00000000-0000-5000-8000-000000000000` (2026-10-27T12:00:00Z). Statements are limited to what the scan recorded; everything else is marked to be completed.

## 1. Scope

Network: `qorechain-diana`.

Scanned: live network state via REST (http://chain.test); node configuration, genesis and key files (types and public keys only); Solidity sources.

Systems outside this scan: _To be completed._

## 2. Algorithms in use

| Algorithm | Classification | Where it was found |
|---|---|---|
| ECDSA P-256 | quantum-vulnerable | ECDSA P-256 verification (RIP-7212 precompile 0x100 or a P256 library); EVM precompile p256 (0x0000000000000000000000000000000000000100) is active: signature verification from contracts |
| ECDSA secp256k1 | quantum-vulnerable | classical half of the native-lane hybrid signature; imports @openzeppelin/contracts/utils/cryptography/ECDSA.sol (9 occurrences in the CBOM) |
| Ed25519 | quantum-vulnerable | validator key file location; node key file location (8 occurrences in the CBOM) |
| X25519 | quantum-vulnerable | peer-to-peer listener tcp://0.0.0.0:26656; handshake defined by the consensus engine |
| ML-DSA-87 | post-quantum | native-lane transactions: hybrid signature mode required; on-chain algorithm registry: id 1, name "dilithium5", active (9 occurrences in the CBOM) |
| ML-KEM-1024 | post-quantum | on-chain algorithm registry: id 2, name "mlkem1024", active; KEM public key published by qor1fixtureaccount |
| ChaCha20-Poly1305 | symmetric | peer-to-peer listener tcp://0.0.0.0:26656; handshake defined by the consensus engine |
| HKDF-SHA256 | symmetric | peer-to-peer listener tcp://0.0.0.0:26656; handshake defined by the consensus engine |
| Keccak-256 | symmetric | imports @openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol; Keccak-256 hash (3 occurrences in the CBOM) |
| RIPEMD-160 | symmetric | RIPEMD-160 (precompile 0x03) |
| SHA-256 | symmetric | SHA-256 (precompile 0x02) |

## 3. Ability to replace algorithms

- The pqc module keeps an on-chain algorithm registry; at genesis it lists: 1 dilithium5 (signature, active, NIST level 5); 2 mlkem1024 (kem, active, NIST level 5). Each entry carries a lifecycle status (active, migrating, deprecated, disabled).
- Native-lane transactions: hybrid signature mode `required` (classical secp256k1 signature plus the registry's default post-quantum signature).
- Default post-quantum signature algorithm for new keys: ML-DSA-87.
- An algorithm migration runs with a dual-signature period of 1000000 blocks (module parameter `default_migration_blocks`).
- PQC-related protocol switches recorded as enabled: evm-pqc-authorisation-window, pqc-sign-bytes-v2.
- Consensus engine P2P secret connection: algorithms are fixed by the protocol and cannot be changed by configuration.
- Solidity sources have 10 signature-related occurrences; replacing their algorithms requires a contract change and redeployment.

Procedure, approvals and testing for an algorithm change: _To be completed._

## 4. Transition plan

Quantum-vulnerable algorithms in scope: ECDSA P-256, ECDSA secp256k1, Ed25519, X25519. NIST IR 8547 deprecates these families after 2030 and disallows them after 2035.

Target dates per system and use case: _To be completed._

## 5. Responsibilities and review

Owner: _To be completed._

Review cycle: _To be completed._
