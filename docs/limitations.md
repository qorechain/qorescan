# Limitations

- **An inventory aid.** QoreScan records what it can observe. It does not certify, audit or give legal advice, and its reports do not establish conformity with any regulation or standard.
- **Scope.** Only the sources you point it at are scanned. Stored data, backups, HSMs, key management systems, operating system and library configuration, wallets, bridges and off-chain services are outside the scan unless you add their TLS endpoints.
- **Live state.** The on-chain algorithm registry is not served over REST; it is read from `genesis.json`, which reflects the network at genesis, not later governance changes. Nodes that do not serve `/qorechain/pqc/v1/params` give no live hybrid signature mode. Validator consensus keys are read for the latest validator set only.
- **TLS.** One handshake with Go's default client preferences shows what the server negotiates with a modern client, not every protocol version, suite or group the server accepts. Endpoints behind a load balancer may answer differently on another connection.
- **Remote signers.** With `priv_validator_laddr` set, the validator key lives elsewhere and its type is not visible from the node home.
- **Solidity.** Detection is textual. It does not resolve imports, follow inheritance or compute addresses at run time, so a precompile address assembled at run time is missed, and a variable that happens to be named like a pattern can be reported. Dependencies are skipped unless `--include-deps` is given.
- **Algorithm names.** Reports classify CBOMs from other tools by algorithm name only.
- **Categories and transitions.** NIST quantum categories and IR 8547 transitions are taken from the cited documents as of October 2026. Application-specific guidance can set earlier dates.
