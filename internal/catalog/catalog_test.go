// SPDX-License-Identifier: Apache-2.0

package catalog

import "testing"

func TestPostQuantumLevels(t *testing.T) {
	want := map[string]int{
		"ml-dsa-44": 2, "ml-dsa-65": 3, "ml-dsa-87": 5,
		"ml-kem-512": 1, "ml-kem-768": 3, "ml-kem-1024": 5,
		"aes-128-gcm": 1, "aes-256-gcm": 5, "sha-256": 2, "sha-384": 4, "shake-256": 5,
		"ecdsa-secp256k1": 0, "ed25519": 0, "x25519": 0, "rsa-2048": 0,
	}
	for k, lvl := range want {
		a := Get(k)
		if a.NISTLevel == nil || *a.NISTLevel != lvl {
			t.Errorf("%s: NIST level %v, want %d", k, a.NISTLevel, lvl)
		}
	}
	for _, k := range []string{"chacha20-poly1305", "keccak-256", "hkdf-sha256"} {
		if Get(k).NISTLevel != nil {
			t.Errorf("%s: NIST level should be undefined", k)
		}
	}
}

func TestClassesAndTransitions(t *testing.T) {
	for _, k := range Keys() {
		a := Get(k)
		if a.Name == "" || a.Primitive == "" || a.Class == "" || a.Transition == "" {
			t.Errorf("%s: incomplete entry %+v", k, a)
		}
		if a.Class == QuantumVulnerable && a.NISTLevel != nil && *a.NISTLevel != 0 {
			t.Errorf("%s: quantum-vulnerable entry with category %d", k, *a.NISTLevel)
		}
		if a.Class == PostQuantum && a.Standard == "" {
			t.Errorf("%s: post-quantum entry without a standard", k)
		}
	}
}

func TestGetReturnsCopies(t *testing.T) {
	a := Get("ml-dsa-87")
	*a.NISTLevel = 1
	a.Functions[0] = "x"
	if b := Get("ml-dsa-87"); *b.NISTLevel != 5 || b.Functions[0] == "x" {
		t.Fatal("Get must not expose catalog storage")
	}
}

func TestKeyTypeNameIgnoresAminoPrefix(t *testing.T) {
	cases := map[string]string{
		"anything/PubKeyEd25519":                    "ed25519",
		"other-engine/PrivKeyEd25519":               "ed25519",
		"/cosmos.crypto.ed25519.PubKey":             "ed25519",
		"ed25519":                                   "ed25519",
		"/cosmos.crypto.secp256k1.PubKey":           "ecdsa-secp256k1",
		"/cosmos.evm.crypto.v1.ethsecp256k1.PubKey": "ecdsa-secp256k1",
		"x/PubKeyBls12_381":                         "bls12-381",
		"bls12_381":                                 "bls12-381",
	}
	for in, want := range cases {
		got, ok := KeyTypeName(in)
		if !ok || got != want {
			t.Errorf("KeyTypeName(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if _, ok := KeyTypeName("x/PubKeyUnknown"); ok {
		t.Error("unknown type accepted")
	}
}

func TestOnChainName(t *testing.T) {
	for in, want := range map[string]string{"dilithium5": "ml-dsa-87", "DILITHIUM5": "ml-dsa-87", "mlkem1024": "ml-kem-1024"} {
		if got, ok := OnChainName(in); !ok || got != want {
			t.Errorf("OnChainName(%q) = %q", in, got)
		}
	}
}

func TestClassifyForeignNames(t *testing.T) {
	cases := []struct {
		name, prim string
		want       Class
	}{
		{"ML-DSA-65", "", PostQuantum},
		{"SLH-DSA-SHA2-128s", "", PostQuantum},
		{"X25519MLKEM768", "", Hybrid},
		{"RSA-3072", "", QuantumVulnerable},
		{"ECDSA with SHA-256", "", QuantumVulnerable},
		{"AES-256-GCM", "", Symmetric},
		{"SHA3-512", "", Symmetric},
		{"Mystery", "hash", Symmetric},
		{"Mystery", "", Unknown},
	}
	for _, c := range cases {
		if got, _, _ := Classify(c.name, c.prim); got != c.want {
			t.Errorf("Classify(%q) = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestRSASizes(t *testing.T) {
	for bits, want := range map[int]int{1024: 80, 2048: 112, 3072: 128, 4096: 128, 7680: 192} {
		if got := RSA(bits).ClassicalBits; got != want {
			t.Errorf("RSA(%d) classical %d, want %d", bits, got, want)
		}
	}
}
