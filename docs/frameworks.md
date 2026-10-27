# Framework mapping

`qorescan report --framework finma|nis|dora` maps the inventory to one framework. The tables paraphrase each source; the source documents are authoritative. The mapping says where the inventory can serve as input. It does not say that an organisation meets any requirement: that depends on facts outside the scan and is for the organisation and its advisers to assess.

## Status per algorithm

Every algorithm in the CBOM is classified as:

| Classification | Meaning | FIPS 203/204/205 column | NIST IR 8547 column |
|---|---|---|---|
| post-quantum | ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), LMS/XMSS (SP 800-208) | the standard | not scheduled for deprecation |
| hybrid | a classical key exchange combined with ML-KEM, for example the TLS group X25519MLKEM768 | post-quantum part per FIPS 203 | post-quantum part approved; classical part deprecated after 2030, disallowed after 2035 |
| quantum-vulnerable | RSA, ECDSA, EdDSA, finite-field and elliptic-curve DH, pairing-based signatures | not covered | deprecated after 2030, disallowed after 2035 |
| symmetric | block ciphers, AEADs, hashes, XOFs, KDFs | not applicable | not scheduled (SHA-1 and 112-bit symmetric schemes excepted) |

NIST IR 8547 lists the ECDSA and EdDSA families (FIPS 186-5) and elliptic-curve DH (SP 800-56A). QoreScan applies that schedule to every curve of those families, including curves NIST does not list (secp256k1) and X25519 key agreement, because the quantum exposure is the same. BLS12-381 is not in the IR 8547 tables; QoreScan marks it quantum-vulnerable and outside the tables. These are inventory classifications, not statements about NIST approval.

The NIST quantum security category is the one FIPS 203/204/205 define for the post-quantum parameter sets and the one NIST IR 8547 (Tables 6 and 8) gives block ciphers and hash functions; for hashes QoreScan uses the collision category, the lower one. Quantum-vulnerable public-key algorithms get category 0, which CycloneDX defines as "none of the categories are met". Algorithms without a NIST category (ChaCha20-Poly1305, Keccak-256, HKDF) have none in the CBOM.

## FINMA Guidance 05/2026

Source: FINMA Guidance 05/2026 "Quantum computing", 9 July 2026, section 3.

| Section | Paraphrase | Inventory input |
|---|---|---|
| 3.1 Strategy and roadmap | Board-adopted strategy, implementation plan with milestones, PQC roadmap by mid-2027 at the latest | none (organisational) |
| 3.2 Risk analysis and inventory | Inventory of cryptographic methods across ICT systems including distributed ledger technology; identify quantum-vulnerable algorithms | the CBOM and the algorithm table |
| 3.3 Critical data | Long-term protection needs, harvest-now-decrypt-later, hybrid schemes | key exchange of scanned transports, native-lane hybrid signature mode |
| 3.4 Crypto-agility | Ability to replace algorithms without major architecture changes | on-chain algorithm registry, migration period, protocol switches |
| 3.5 External service providers | Plan with providers, crypto-agility as a prerequisite in outsourcing | certificate issuers of scanned endpoints; the vendor questionnaire template |

## EU NIS Cooperation Group PQC roadmap

Source: EU PQC Workstream of the NIS Cooperation Group, "A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography", Part 1, version 1.1, 11 June 2025. The roadmap is addressed to Member States.

| Item | Paraphrase | Inventory input |
|---|---|---|
| First Steps: cryptographic asset management | Inventories of cryptographic assets; a standardised format such as CBOM is recommended | the CBOM |
| Milestone 1, 31.12.2026 | First Steps, national roadmaps, planning and pilots for high- and medium-risk use cases | none (planning) |
| Milestone 2, 31.12.2030 | High-risk use cases transitioned; post-quantum upgrades enabled by default | the list of quantum-vulnerable algorithms |
| Milestone 3, 31.12.2035 | Medium-risk use cases transitioned; low-risk as far as feasible | the same list |
| Cryptographic agility | Support agility and an upgrade path | registry, migration period, protocol switches |

## DORA

Source: Commission Delegated Regulation (EU) 2024/1774 of 13 March 2024, the regulatory technical standards on the ICT risk management framework under Regulation (EU) 2022/2554 (DORA), Article 6 "Encryption and cryptographic controls".

| Provision | Paraphrase | Inventory input |
|---|---|---|
| Art. 6(1) | Policy on encryption and cryptographic controls | input for the policy |
| Art. 6(2)(a) | Encryption of data at rest and in transit | transport key exchange; data at rest is not scanned |
| Art. 6(2)(c) | Encryption of internal network connections and traffic with external parties | P2P and TLS records, listeners without TLS |
| Art. 6(2)(d) | Key management (Article 7) | key records (types and public keys only) |
| Art. 6(3) | Criteria for selecting techniques, leading practices and standards | each algorithm against FIPS 203/204/205 and NIST IR 8547 |
| Art. 6(4) | Update or change cryptographic technology as cryptanalysis develops | registry, migration period, protocol switches |
| Art. 6(5) | Record mitigation and monitoring measures | none (organisational) |

## Sources

- FINMA Guidance 05/2026 "Quantum computing", 9 July 2026: <https://www.finma.ch/en/~/media/finma/dokumente/dokumentencenter/myfinma/4dokumentation/finma-aufsichtsmitteilungen/20260709-finma-aufsichtsmitteilung-05-2026.pdf>
- EU PQC Workstream of the NIS Cooperation Group, "A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography", Part 1, v1.1, 11 June 2025: <https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography>
- Commission Delegated Regulation (EU) 2024/1774, Article 6: <https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj>
- NIST IR 8547, "Transition to Post-Quantum Cryptography Standards", final, October 2026 (initial public draft November 2024): <https://doi.org/10.6028/NIST.IR.8547>. Tables 2 and 4 schedule quantum-vulnerable signature and key-establishment families as "Deprecated after 2030, Disallowed after 2035".
- FIPS 203: <https://csrc.nist.gov/pubs/fips/203/final>
- FIPS 204: <https://csrc.nist.gov/pubs/fips/204/final>
- FIPS 205: <https://csrc.nist.gov/pubs/fips/205/final>
