// SPDX-License-Identifier: Apache-2.0

package report

import (
	"strings"
	"testing"

	"github.com/qorechain/qorescan/internal/cbom"
)

// A CBOM written by another tool has no qorescan properties; algorithms are
// classified by name.
const foreign = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {"tools": {"components": [{"type": "application", "name": "other-scanner"}]}},
  "components": [
    {"type": "cryptographic-asset", "bom-ref": "a", "name": "RSA-2048", "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "pke"}}},
    {"type": "cryptographic-asset", "bom-ref": "b", "name": "ML-KEM-768", "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "kem", "nistQuantumSecurityLevel": 3}}},
    {"type": "cryptographic-asset", "bom-ref": "c", "name": "SHA512", "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}}}
  ]
}`

func TestForeignCBOM(t *testing.T) {
	b, err := cbom.Decode([]byte(foreign))
	if err != nil {
		t.Fatal(err)
	}
	md, err := Report(b, "dora")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"not written by QoreScan",
		"| RSA-2048 | pke | - | not defined | not covered (quantum-vulnerable) | Deprecated after 2030, disallowed after 2035 (NIST IR 8547) |",
		"| ML-KEM-768 | kem | - | 3 | FIPS 203 |",
		"| symmetric | 1: SHA512 |",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in\n%s", want, md)
		}
	}
	if _, err := Report(b, "sox"); err == nil {
		t.Error("unknown framework accepted")
	}
	if _, err := Template(b, "nope"); err == nil {
		t.Error("unknown template accepted")
	}
}
