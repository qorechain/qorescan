# Vendor questionnaire: post-quantum readiness (5 questions)

> **Disclaimer.** QoreScan output is an inventory aid. It is not a certification, an audit or a legal opinion, and it does not establish conformity with any regulation or standard. This draft is pre-filled only with facts the scan recorded; the organisation is responsible for completing, checking and adopting it.

The questions follow the five measures of FINMA Guidance 05/2026, section 3. Answers are pre-filled only from CBOM `urn:uuid:00000000-0000-5000-8000-000000000000`; anything the scan cannot establish is marked to be completed.

## 1. Strategy and roadmap

Do you have a post-quantum strategy approved by your governing body, with a roadmap and target dates for complete migration and for critical processes?

**Answer:** _To be completed._

## 2. Inventory

Which cryptographic methods does the service use for data in transit, stored data, signatures, key management and authentication, and which of them are quantum-vulnerable?

**Answer (from the scan):**

- post-quantum: ML-DSA-87, ML-KEM-1024
- quantum-vulnerable: ECDSA P-256, ECDSA secp256k1, Ed25519, X25519
- symmetric: ChaCha20-Poly1305, HKDF-SHA256, Keccak-256, RIPEMD-160, SHA-256

Scope of the scan: live network state via REST (http://chain.test); node configuration, genesis and key files (types and public keys only); Solidity sources. Stored data and systems outside the scan: _To be completed._

## 3. Long-lived data

How is data that needs long-term confidentiality or integrity protected against harvest-now-decrypt-later attacks? Do you use hybrid key exchange or hybrid signatures?

**Answer (from the scan):**

- Key exchange of the scanned transports: Consensus engine P2P secret connection: X25519 (fixed by the protocol).
- Native-lane transaction signatures: hybrid signature mode `required`.
- Which data needs long-term protection: _To be completed._

## 4. Crypto-agility

Can the algorithms be replaced without major changes to the architecture?

**Answer (from the scan):** Scanned evidence: on-chain algorithm registry with 2 entries (1 dilithium5 (signature, active, NIST level 5); 2 mlkem1024 (kem, active, NIST level 5)); native-lane hybrid signature mode required; algorithm migration dual-signature period of 1000000 blocks (module parameter).

Assessment and change procedure: _To be completed._

## 5. Dependencies on other providers

Which external providers does the service depend on for cryptography (certificate authorities, hosting, key management), and what is their migration status?

**Answer (from the scan):**

- Other providers and their migration status: _To be completed._
