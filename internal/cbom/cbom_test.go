// SPDX-License-Identifier: Apache-2.0

package cbom_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/qorechain/qorescan/internal/catalog"
	"github.com/qorechain/qorescan/internal/cbom"
	"github.com/qorechain/qorescan/internal/cbom/schemacheck"
	"github.com/qorechain/qorescan/internal/inventory"
)

var fixed = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func sample() *inventory.Inventory {
	inv := inventory.New("sample")
	occ := inventory.Occurrence{Location: "config/genesis.json", Line: 12, Symbol: "app_state.pqc.algorithms[0]", Context: "registry"}
	ml := inv.AddAlgorithm(catalog.Get("ml-dsa-87"), inventory.SourceNodeHome, occ)
	ed := inv.AddAlgorithm(catalog.Get("ed25519"), inventory.SourceNodeHome, inventory.Occurrence{Location: "config/config.toml", Line: 3})
	sig := inv.AddAlgorithm(catalog.Get("ecdsa-p256"), inventory.SourceTLS, inventory.Occurrence{Location: "host:443"})
	key := inv.AddAsset(inventory.Asset{Ref: "crypto/key/x", Name: "key", Kind: inventory.KindMaterial, Material: &inventory.Material{Type: "public-key", AlgorithmRef: ml, SizeBits: 20736}})
	cert := inv.AddAsset(inventory.Asset{Ref: "crypto/certificate/x", Name: "cert", Kind: inventory.KindCertificate, Certificate: &inventory.Certificate{
		Subject: "CN=x", Issuer: "CN=y", NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z", SignatureAlgorithmRef: sig, SubjectPublicKeyRef: key, ChainVerificationAttempted: true, ChainError: "unknown authority"}})
	inv.AddAsset(inventory.Asset{Ref: "crypto/protocol/x", Name: "TLS", Kind: inventory.KindProtocol, Protocol: &inventory.Protocol{Type: "tls", Version: "1.3",
		CipherSuites: []inventory.CipherSuite{{Name: "TLS_AES_128_GCM_SHA256", Identifier: "0x1301", Algorithms: []string{ed}}}, Refs: []string{ed, cert}}})
	inv.AddLibrary(inventory.Library{Ref: "lib/x", Name: "ECDSA", Group: "@openzeppelin/contracts", Purl: "pkg:npm/%40openzeppelin/contracts", Provides: []string{sig}, Occurrences: []inventory.Occurrence{{Location: "a.sol", Line: 1}}})
	inv.AddFact("qorescan:chain:id", "qorechain-test")
	inv.AddNote("node-home", "info", "x", "note %d", 1)
	return inv
}

func TestSampleIsSchemaValid(t *testing.T) {
	data, err := cbom.Encode(sample(), cbom.Options{ToolVersion: "0.1.0", Time: fixed})
	if err != nil {
		t.Fatal(err)
	}
	if err := schemacheck.Validate(data); err != nil {
		t.Fatalf("schema: %v\n%s", err, data)
	}
}

func TestSchemaRejectsInvalid(t *testing.T) {
	bad := []string{
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{"assetType":"nonsense"}}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"nistQuantumSecurityLevel":9}}}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","unknownTopLevel":1}`,
	}
	for _, b := range bad {
		if err := schemacheck.Validate([]byte(b)); err == nil {
			t.Errorf("accepted invalid document %s", b)
		}
	}
}

func TestEncodeIsDeterministic(t *testing.T) {
	a, _ := cbom.Encode(sample(), cbom.Options{ToolVersion: "0.1.0", Time: fixed})
	b, _ := cbom.Encode(sample(), cbom.Options{ToolVersion: "0.1.0", Time: fixed})
	if !bytes.Equal(a, b) {
		t.Fatal("same inventory encoded differently")
	}
	var doc struct {
		SerialNumber string `json:"serialNumber"`
	}
	_ = json.Unmarshal(a, &doc)
	if !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") || len(doc.SerialNumber) != 45 {
		t.Fatalf("serial %q", doc.SerialNumber)
	}
}

func TestEveryReferenceResolves(t *testing.T) {
	data, _ := cbom.Encode(sample(), cbom.Options{Time: fixed})
	if err := schemacheck.Refs(data); err != nil {
		t.Fatal(err)
	}
	if err := schemacheck.Refs([]byte(`{"components":[{"bom-ref":"a"}],"dependencies":[{"ref":"a","dependsOn":["b"]}]}`)); err == nil {
		t.Fatal("dangling reference not detected")
	}
}

func TestDecode(t *testing.T) {
	if _, err := cbom.Decode([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`)); err == nil {
		t.Error("1.5 accepted")
	}
	if _, err := cbom.Decode([]byte(`{"bomFormat":"SPDX","specVersion":"1.6"}`)); err == nil {
		t.Error("non-CycloneDX accepted")
	}
	if _, err := cbom.Decode([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","components":[]}`)); err != nil {
		t.Errorf("1.7 refused: %v", err)
	}
}

func TestDisclaimerInMetadata(t *testing.T) {
	data, _ := cbom.Encode(sample(), cbom.Options{Time: fixed})
	b, _ := cbom.Decode(data)
	if v := b.Metadata.PropertyValues("qorescan:disclaimer"); len(v) != 1 || v[0] != cbom.Disclaimer {
		t.Fatalf("disclaimer %v", v)
	}
}
