// SPDX-License-Identifier: Apache-2.0

package nodehome

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/qorechain/qorescan/internal/fixture"
	"github.com/qorechain/qorescan/internal/inventory"
)

// The key-file structs are the proof that private key bytes are never
// decoded: the private key member has a type with a single string field for
// the type name and nothing else.
func TestKeyStructsHaveNoPrivateValue(t *testing.T) {
	kt := reflect.TypeOf(KeyTypeOnly{})
	if kt.NumField() != 1 || kt.Field(0).Name != "Type" || kt.Field(0).Tag.Get("json") != "type" {
		t.Fatalf("KeyTypeOnly must hold only the type name, has %d fields", kt.NumField())
	}
	check := func(typ reflect.Type) {
		f, ok := typ.FieldByName("PrivKey")
		if !ok {
			t.Fatalf("%s has no PrivKey field", typ.Name())
		}
		if f.Type != kt {
			t.Fatalf("%s.PrivKey is %s, want KeyTypeOnly", typ.Name(), f.Type)
		}
		for i := 0; i < typ.NumField(); i++ {
			tag := typ.Field(i).Tag.Get("json")
			if strings.Contains(strings.ToLower(tag), "priv") && typ.Field(i).Type != kt {
				t.Fatalf("%s.%s may carry private data", typ.Name(), typ.Field(i).Name)
			}
		}
	}
	check(reflect.TypeOf(ValidatorKeyFile{}))
	check(reflect.TypeOf(NodeKeyFile{}))
}

func TestReadKeyFileRefusesOtherTargets(t *testing.T) {
	var m map[string]any
	if err := readKeyFile("does-not-matter", &m); err == nil {
		t.Fatal("decoding a key file into a map must be refused")
	}
}

func TestKeyFileDecodeKeepsOnlyTypeAndPublicKey(t *testing.T) {
	h := fixture.NewHome(t, fixture.Options{})
	var f ValidatorKeyFile
	if err := readKeyFile(filepath.Join(h.Dir, "config", "priv_validator_key.json"), &f); err != nil {
		t.Fatal(err)
	}
	if f.PrivKey.Type != fixture.AminoPrefix+"PrivKeyEd25519" || f.PubKey.Type == "" || f.Address != h.ValidatorAddress {
		t.Fatalf("unexpected decode %+v", f)
	}
	dump := reflect.ValueOf(f).String() + " " + strings.Join([]string{f.Address, f.PubKey.Type, f.PubKey.Value, f.PrivKey.Type}, " ")
	for _, s := range h.Secrets {
		if strings.Contains(dump, s) {
			t.Fatal("decoded struct holds private key material")
		}
	}
}

func scan(t *testing.T, opt fixture.Options) (*fixture.Home, *inventory.Inventory, string) {
	t.Helper()
	h := fixture.NewHome(t, opt)
	inv := inventory.New("test")
	var log strings.Builder
	if err := Scan(h.Dir, inv, func(f string, a ...any) { log.WriteString(f + "\n") }); err != nil {
		t.Fatal(err)
	}
	return h, inv, log.String()
}

func refs(inv *inventory.Inventory) map[string]*inventory.Asset {
	m := map[string]*inventory.Asset{}
	for _, a := range inv.Assets() {
		m[a.Ref] = a
	}
	return m
}

func TestScanFixtureHome(t *testing.T) {
	h, inv, _ := scan(t, fixture.Options{})
	m := refs(inv)
	for _, want := range []string{
		"crypto/algorithm/ed25519", "crypto/algorithm/x25519", "crypto/algorithm/chacha20-poly1305",
		"crypto/algorithm/hkdf-sha256", "crypto/algorithm/ml-dsa-87", "crypto/algorithm/ml-kem-1024",
		"crypto/algorithm/ecdsa-secp256k1", "crypto/protocol/p2p-secret-connection",
		"crypto/key/node-identity", "crypto/key/genesis-validators/ed25519",
		"crypto/key/validator-consensus/" + strings.ToLower(h.ValidatorAddress),
	} {
		if _, ok := m[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	vk := m["crypto/key/validator-consensus/"+strings.ToLower(h.ValidatorAddress)]
	if vk.Material.SizeBits != 256 || vk.Material.AlgorithmRef != "crypto/algorithm/ed25519" {
		t.Errorf("validator key %+v", vk.Material)
	}
	mldsa := m["crypto/algorithm/ml-dsa-87"]
	if !hasProp(mldsa, "qorescan:pqc:registry-name", "dilithium5") || !hasProp(mldsa, "qorescan:pqc:hybrid-signature-mode", "required") {
		t.Errorf("ML-DSA-87 properties %+v", mldsa.Properties)
	}
	// Evidence lines point at the right lines.
	p2p := m["crypto/protocol/p2p-secret-connection"].Occurrences[0]
	if p2p.Location != "config/config.toml" || p2p.Line != 22 {
		t.Errorf("p2p evidence %+v", p2p)
	}
	for _, o := range mldsa.Occurrences {
		if o.Location != "config/genesis.json" || o.Line == 0 {
			t.Errorf("ML-DSA-87 evidence %+v", o)
		}
	}
	facts := map[string]string{}
	for _, f := range inv.Facts {
		facts[f.Name] = f.Value
	}
	if facts["qorescan:genesis:chain-id"] != "qorechain-fixture" || facts["qorescan:genesis:pqc:default-migration-blocks"] != "1000000" {
		t.Errorf("facts %v", facts)
	}
	notes := noteText(inv)
	for _, want := range []string{"RPC listener tcp://0.0.0.0:26657", "REST API listener", "EVM JSON-RPC listener 0.0.0.0:8545", "keyring directory present (file backend); not opened"} {
		if !strings.Contains(notes, want) {
			t.Errorf("missing note %q in\n%s", want, notes)
		}
	}
	if strings.Contains(notes, "gRPC listener") || strings.Contains(notes, "WebSocket") || strings.Contains(notes, "SVM") {
		t.Errorf("loopback or disabled listeners must not be noted:\n%s", notes)
	}
	// No absolute path of this machine in any value.
	for _, a := range inv.Assets() {
		for _, o := range a.Occurrences {
			if filepath.IsAbs(o.Location) || strings.Contains(o.Location, h.Dir) {
				t.Errorf("absolute path in evidence: %s", o.Location)
			}
		}
	}
	if strings.Contains(notes, h.Dir) {
		t.Error("absolute path in notes")
	}
}

func TestRemoteSignerAndPermissions(t *testing.T) {
	_, inv, _ := scan(t, fixture.Options{RemoteSigner: true, KeyFileMode: 0o644})
	notes := noteText(inv)
	if !strings.Contains(notes, "remote signer at tcp://127.0.0.1:26659") {
		t.Errorf("remote signer not noted:\n%s", notes)
	}
	if !strings.Contains(notes, "key file permissions are 0644") {
		t.Errorf("permissions not noted:\n%s", notes)
	}
}

func TestRPCTLSCertificateSkipsPrivateKeyBlocks(t *testing.T) {
	h, inv, _ := scan(t, fixture.Options{RPCTLS: true})
	var cert *inventory.Asset
	for _, a := range inv.Assets() {
		if a.Kind == inventory.KindCertificate {
			cert = a
		}
	}
	if cert == nil || cert.Certificate.Subject != "CN=rpc.fixture.test" || cert.Occurrences[0].Symbol != "rpc.tls_cert_file" {
		t.Fatalf("certificate not recorded: %+v", cert)
	}
	if _, ok := refs(inv)["crypto/algorithm/ecdsa-p256"]; !ok {
		t.Error("certificate key algorithm missing")
	}
	if strings.Contains(noteText(inv), "RPC listener tcp://0.0.0.0:26657 binds") {
		t.Error("RPC with TLS reported as plaintext")
	}
	_ = h
}

func TestMissingConfigDirectory(t *testing.T) {
	if err := Scan(t.TempDir(), inventory.New("x"), nil); err == nil {
		t.Fatal("expected an error for a home without config/")
	}
}

func TestMissingFilesBecomeNotes(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "config"), 0o700); err != nil {
		t.Fatal(err)
	}
	inv := inventory.New("x")
	if err := Scan(dir, inv, nil); err != nil {
		t.Fatal(err)
	}
	n := noteText(inv)
	if !strings.Contains(n, "config.toml not readable") || !strings.Contains(n, "genesis.json not readable") || strings.Contains(n, dir) {
		t.Fatalf("notes:\n%s", n)
	}
}

func TestParseTOML(t *testing.T) {
	doc := parseTOML([]byte(`top = "a # not a comment" # comment
[s]
k = 'lit'
arr = [
  "x",
  "y",
]
b = true
n = 42
`))
	if v := doc["top"]; v.String() != "a # not a comment" || v.Line != 1 {
		t.Errorf("top %+v", v)
	}
	if v := doc["s.k"]; v.String() != "lit" || v.Line != 3 {
		t.Errorf("s.k %+v", v)
	}
	if v := doc["s.arr"]; v.Line != 4 || !strings.Contains(v.Raw, `"y"`) {
		t.Errorf("s.arr %+v", v)
	}
	if !doc["s.b"].Bool() || doc["s.n"].String() != "42" || doc["s.b"].Line != 8 {
		t.Errorf("scalars %+v %+v", doc["s.b"], doc["s.n"])
	}
}

func TestExposed(t *testing.T) {
	for addr, want := range map[string]bool{
		"tcp://0.0.0.0:26657": true, "tcp://127.0.0.1:26657": false, "localhost:9090": false,
		":8545": true, "[::1]:8545": false, "10.0.0.5:1317": true, "node.example:1317": true,
	} {
		if got := exposed(addr); got != want {
			t.Errorf("exposed(%q) = %v", addr, got)
		}
	}
}

func hasProp(a *inventory.Asset, name, value string) bool {
	for _, p := range a.Properties {
		if p.Name == name && p.Value == value {
			return true
		}
	}
	return false
}

func noteText(inv *inventory.Inventory) string {
	var b strings.Builder
	for _, n := range inv.Notes {
		b.WriteString(n.Text + " (" + n.Location + ")\n")
	}
	return b.String()
}
