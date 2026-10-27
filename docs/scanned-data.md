# What is scanned, and what is never read

QoreScan only reads. It writes nothing except the output file you name.

## Node home

| File | Read | Recorded |
|---|---|---|
| `config/config.toml` | `p2p.laddr`, `rpc.laddr`, `rpc.tls_cert_file`, `rpc.tls_key_file` (only whether it is set), `priv_validator_key_file`, `priv_validator_laddr`, `node_key_file` | The P2P transport of the consensus engine and its algorithms (X25519 key agreement, Ed25519 node authentication, HKDF-SHA256, ChaCha20-Poly1305; fixed by the protocol). The RPC TLS certificate. A remote signer. A note for an RPC listener on a non-loopback address without TLS. |
| `config/app.toml` | `[api]`, `[grpc]`, `[json-rpc]`, `[svm-rpc]` enable and address, `[tls] certificate-path` and `key-path` (only whether it is set) | The EVM JSON-RPC TLS certificate. Notes for enabled listeners on non-loopback addresses without TLS. |
| `config/genesis.json` | `chain_id`, consensus `validator.pub_key_types`, validator consensus key types from `validators`, `genutil.gen_txs` and `staking.validators`, the `pqc` module state | Allowed and used consensus key types (with counts), the pqc parameters (hybrid signature mode, minimum security level, default signature algorithm, migration period), the on-chain algorithm registry, the number of PQC accounts, and the PQC-related protocol switches enabled at genesis. |
| `priv_validator_key.json` | `address`, `pub_key.type`, `pub_key.value`, `priv_key.type` | The consensus key algorithm, public key size and address. The fact that a private key of that type is stored in a plaintext file. |
| `node_key.json` | `priv_key.type` | The node identity key algorithm. The node ID is not derived, because that would need the private key. |
| certificate files | `CERTIFICATE` PEM blocks | Subject, issuer, validity, public key algorithm and size, signature algorithm, SHA-256 fingerprint. Any other PEM block in the same file (for example a bundled private key) is skipped without being decoded. |
| `keyring-*` directories | the directory name | A note that the keyring exists. It is not opened. |
| key file metadata | permissions | A warning when group or other users can access a key file. |

### How private keys are kept out

The key files are decoded into Go structs whose private key member is a type with a single field, the key type name (`internal/nodehome/keys.go`). The JSON decoder skips members that have no field, so the private key value is never decoded into memory as a value of its own; the raw file buffer is overwritten after decoding and decoding errors (which can quote input) are never returned. `TestKeyStructsHaveNoPrivateValue` fails if these structs gain a field that could carry private data, and `TestPrivateKeyNeverInOutputOrLogs` scans a node home with freshly generated keys (and a certificate file that bundles a private key) and checks that no encoding of those keys appears in the CBOM, the reports, the templates or the verbose log.

Key type names are matched on the part after the slash, so the consensus engine's amino prefix does not matter (`<engine>/PubKeyEd25519`, `/cosmos.crypto.ed25519.PubKey` and `ed25519` are the same).

## Network (REST, read-only GET)

| Route | Recorded |
|---|---|
| `/cosmos/base/tendermint/v1beta1/node_info` | Chain id, consensus engine version, application version. |
| `/qorechain/pqc/v1/protocol_features` | Number of enabled switches and the names of the PQC-related ones. |
| `/qorechain/pqc/v1/params` | Hybrid signature mode, default signature algorithm, minimum security level, migration period. Not served by every node; a note records that. |
| `/cosmos/base/tendermint/v1beta1/validatorsets/latest` | Consensus key types of the active validator set, with counts. |
| `/cosmos/evm/vm/v1/params` | Active precompiles. pqcVerify (0x0A01) and P-256 (0x100) are recorded as signature verification available to contracts. The Ethereum rules that hold on every EVM (ECDSA secp256k1 over Keccak-256 for transactions) are recorded once. |
| `/qorechain/pqc/v1/account/{address}` | Whether the account has a registered PQC key, its algorithm, key type (hybrid, PQC only, classical only), public key size and the source of the classical key. |
| `/qorechain/pqc/v1/kem/{address}` | A published KEM public key, when the node serves the route. |

The on-chain algorithm registry is not exposed over REST; QoreScan reads it from `genesis.json` when a node home is scanned. A route a node does not serve becomes a note, not an error.

## TLS endpoints

One handshake per endpoint, no application data. Recorded: TLS version, cipher suite (with the algorithms it implies), key exchange group, ALPN protocol, SNI name, and every certificate the server sent. The leaf chain is verified against the system roots and the result is stored as a property.

## Solidity sources

Comments and string literal contents are blanked before matching; function declarations are not counted as uses.

| Pattern | Recorded as |
|---|---|
| `ecrecover(`, `address(1).staticcall`, assembly `staticcall(gas(), 0x01, ...)` | ECDSA secp256k1 |
| `pqcVerify(`, `address(0x0A01)`, the full `0x...0A01` address, assembly calls to `0x0A01` | ML-DSA-87 |
| `pqcKeyStatus(`, `address(0x0A02)` | ML-DSA-87 (key status lookup) |
| `address(0x100)`, `P256.verify...(` | ECDSA P-256 |
| `ECDSA.recover(`, `ECDSA.tryRecover(`, `using ECDSA for`, `SignatureChecker.isValid...(` | ECDSA secp256k1 |
| `RSA.pkcs1...(` | RSA |
| `keccak256(`, `sha256(`, `ripemd160(` | Keccak-256, SHA-256, RIPEMD-160 |
| imports of OpenZeppelin `ECDSA.sol`, `SignatureChecker.sol`, `P256.sol`, `RSA.sol`, `MessageHashUtils.sol`, `EIP712.sol`; Solady `ECDSA.sol`, `SignatureCheckerLib.sol`, `P256.sol`; `IQorePQC.sol` | a library component that provides the algorithm |

Evidence paths are relative to the directory given on the command line.
