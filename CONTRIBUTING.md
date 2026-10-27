# Contributing to QoreScan

Thanks for your interest. Issues, pull requests and discussion are welcome.

## Layout

| Path | Contents |
|---|---|
| `cmd/qorescan` | the command |
| `internal/app` | command line, end-to-end and golden tests |
| `internal/nodehome`, `internal/chain`, `internal/tlsscan`, `internal/solidity` | the four scanners |
| `internal/catalog` | algorithms, security categories, NIST IR 8547 status |
| `internal/inventory`, `internal/cbom`, `internal/certs` | the in-memory inventory and the CycloneDX 1.6 writer and reader |
| `internal/report` | framework reports and templates |
| `internal/fixture` | generated node homes for tests (no real keys) |
| `npm`, `python` | wrapper packages |
| `docs` | usage, scanned data, frameworks, limitations, design |

## Build and test

```bash
gofmt -l . && go vet ./... && go test ./...
(cd npm && npm test)                                  # builds the binary, serves it locally
python -m unittest discover -s python/tests -v        # same, for the PyPI wrapper
scripts/check-content.sh                              # SPDX headers and wording rules
```

Golden files live in `internal/app/testdata/golden`. After an intended output change, run `go test ./internal/app -update` and review the diff.

Live read-only checks against the public networks run only with `QORE_LIVE_TEST=1` (`go test -run TestLive ./internal/chain`). `QORE_LIVE_REST_MAINNET` and `QORE_LIVE_REST_TESTNET` point them at another endpoint, for example a local relay.

## Rules

- QoreScan must never read private key values. A new key format needs a decode struct without a private value field and a case in `TestPrivateKeyNeverInOutputOrLogs`.
- Fixtures are generated in the tests. Never commit a real key, node home or genesis.
- Every CBOM a test produces is validated against the CycloneDX 1.6 schema.
- Output paths stay relative to the scanned directory.
- Wording in output and docs: an inventory aid, never a claim of conformity or certification.
- New dependencies must be Apache-2.0, MIT or BSD licensed and listed in NOTICE.

## Code of Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Do not open public issues for vulnerabilities; see [SECURITY.md](SECURITY.md).
