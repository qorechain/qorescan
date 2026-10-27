# Security Policy

QoreScan reads node configuration and key files, so we treat security reports for it with priority.

## Reporting a vulnerability

Please **do not** report vulnerabilities through public issues, discussions or pull requests. Email:

**security@qore.network**

Include, as far as you can: a description and the impact, steps to reproduce or a proof of concept, the version and channel (binary, Go, npm, PyPI, Docker, GitHub Action), and a suggested fix.

Qualifying reports are eligible for the QoreChain bug bounty; scope and rules are published at <https://www.qorechain.io/security>.

Of particular interest: any way to make QoreScan read, keep, log or output private key material, to follow a path outside the scanned directory, or to make a wrapper run a binary whose digest does not match.

## What to expect

- We acknowledge your report and keep you informed while we investigate.
- We coordinate disclosure with you once a fix is released.

## Supported versions

QoreScan is pre-1.0. Security fixes go into the latest minor version.
