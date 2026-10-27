# Design and licence check

## Decision

QoreScan **writes the CycloneDX 1.6 CBOM format itself** and validates its output against the official CycloneDX 1.6 JSON schema in its tests. It does not embed or fork the PQCA CBOMkit projects and contains none of their code. Because the output is plain CycloneDX 1.6, a QoreScan CBOM can be loaded by any CycloneDX 1.6 consumer, including the CBOMkit viewer and cbomkit-theia, which accepts a CycloneDX 1.6 BOM as input.

## What was checked (October 2026)

| Project | Licence | Language and shape | Relevant facts |
|---|---|---|---|
| [PQCA/cbomkit-theia](https://github.com/PQCA/cbomkit-theia) | Apache-2.0 | Go CLI (module `github.com/cbomkit/cbomkit-theia`, `go 1.26.8` directive) that scans directories and container images | Plugins implement `Plugin { GetName; GetExplanation; GetType; UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error }` and are registered by editing `GetAllPluginConstructors` in `scanner/scanner.go`: there is no way to load a plugin without changing theia's source. Plugins receive a filesystem, not network access. CycloneDX 1.6 in and out, via `github.com/CycloneDX/cyclonedx-go`. Large dependency tree (container runtimes, image libraries, a secret scanner). |
| [PQCA/cbomkit](https://github.com/PQCA/cbomkit) | Apache-2.0 | Java (Quarkus) service with a Vue front end and PostgreSQL | Generates CBOMs from git repositories through its scanners, stores them, shows them and checks them against a policy. A deployable service, not a library. |
| [PQCA/sonar-cryptography](https://github.com/PQCA/sonar-cryptography) | Apache-2.0 for its own code; the packaged plugin also contains sonar-java, sonar-python and sonar-go under the Sonar Source-Available License v1.0 | SonarQube plugin | Detects cryptography in Java, Python and Go; no Solidity. The packaged form does not meet the Apache/MIT/BSD-only rule. |

## Why not cbomkit-theia plugins (option a)

1. A theia plugin cannot be added without patching theia's plugin registry, so QoreScan would ship a fork.
2. Two of QoreScan's four sources (live chain state over REST and TLS handshakes) are not filesystem scans and do not fit the plugin input.
3. theia's dependency tree is large; every transitive licence would need to be audited and tracked in NOTICE, against a tool whose job is to be easy to audit.
4. QoreScan's binary needs nothing beyond the Go standard library.

## Staying compatible

- The output is CycloneDX 1.6 with `cryptographic-asset` components, `cryptoProperties` and `evidence.occurrences`, the same structure cbomkit-theia and the other CBOMkit tools exchange.
- Every CBOM produced in the tests passes the official schema (`internal/cbom/schemacheck`, schema files copied unmodified from the CycloneDX specification, tag 1.6.1) and a check that every `bom-ref` used is defined.
- The node-home scanner works on a directory and writes components and occurrences, so it could later be proposed upstream as a theia plugin with a thin adapter. That would be a separate contribution under theia's Apache-2.0 licence.

## Dependency licences

| Where | Dependency | Licence |
|---|---|---|
| `qorescan` binary | Go standard library only | BSD-3-Clause |
| tests only | `github.com/santhosh-tekuri/jsonschema/v6` | Apache-2.0 |
| tests only | `golang.org/x/text`, `github.com/dlclark/regexp2` (listed in `go.sum`) | BSD-3-Clause, MIT |
| tests only | CycloneDX 1.6 JSON schema files | Apache-2.0 |
| npm wrapper | Node.js built-in modules only | none added |
| PyPI wrapper | Python standard library only; `setuptools` at build time | none added at run time; MIT |
| GitHub Action | `actions/setup-go` (pinned by commit) | MIT |
| Docker image | `golang` (build stage), `gcr.io/distroless/static-debian12:nonroot` (pinned by digest) | BSD-3-Clause for Go; Debian package licences for the base image |

No CBOMkit code is reused, so no CBOMkit licence notice is required. If code is ever taken from a CBOMkit project, its Apache-2.0 notices must be kept and listed in NOTICE.
