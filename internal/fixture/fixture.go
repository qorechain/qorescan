// SPDX-License-Identifier: Apache-2.0

// Package fixture builds node home directories for tests. Every key is
// generated here, from crypto/rand or from a public test seed; no fixture
// contains a real key.
package fixture

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// AminoPrefix stands in for the consensus engine's amino type prefix. Key
// type matching uses only the segment after the slash, so any prefix works.
const AminoPrefix = "engine/"

// Home is a generated node home.
type Home struct {
	Dir string
	// Secrets are encodings of private key material that must never appear
	// in any QoreScan output or log.
	Secrets []string
	// ValidatorAddress is the address written into priv_validator_key.json.
	ValidatorAddress string
}

// Options shape the generated home.
type Options struct {
	// Deterministic derives the keys from a fixed public seed, for golden
	// files. Otherwise keys come from crypto/rand.
	Deterministic bool
	// RPCTLS writes a self-signed certificate and enables RPC TLS. The
	// certificate file also carries a private key block, which QoreScan must
	// skip.
	RPCTLS bool
	// RemoteSigner sets priv_validator_laddr.
	RemoteSigner bool
	// KeyFileMode is the permission of the key files (default 0600).
	KeyFileMode os.FileMode
}

func seed(label string, deterministic bool) []byte {
	if deterministic {
		s := sha256.Sum256([]byte("qorescan test fixture, not a real key: " + label))
		return s[:]
	}
	s := make([]byte, 32)
	if _, err := rand.Read(s); err != nil {
		panic(err)
	}
	return s
}

// NewHome writes a node home under t.TempDir().
func NewHome(t testing.TB, opt Options) *Home {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "home")
	cfg := filepath.Join(dir, "config")
	must(t, os.MkdirAll(cfg, 0o700))
	must(t, os.MkdirAll(filepath.Join(dir, "keyring-file"), 0o700))
	h := &Home{Dir: dir}
	mode := opt.KeyFileMode
	if mode == 0 {
		mode = 0o600
	}

	valPriv := ed25519.NewKeyFromSeed(seed("validator", opt.Deterministic))
	valPub := valPriv.Public().(ed25519.PublicKey)
	addr := sha256.Sum256(valPub)
	h.ValidatorAddress = strings.ToUpper(hex.EncodeToString(addr[:20]))
	h.addSecret(valPriv)
	writeJSON(t, filepath.Join(cfg, "priv_validator_key.json"), mode, map[string]any{
		"address":  h.ValidatorAddress,
		"pub_key":  map[string]string{"type": AminoPrefix + "PubKeyEd25519", "value": base64.StdEncoding.EncodeToString(valPub)},
		"priv_key": map[string]string{"type": AminoPrefix + "PrivKeyEd25519", "value": base64.StdEncoding.EncodeToString(valPriv)},
	})

	nodePriv := ed25519.NewKeyFromSeed(seed("node", opt.Deterministic))
	h.addSecret(nodePriv)
	writeJSON(t, filepath.Join(cfg, "node_key.json"), mode, map[string]any{
		"priv_key": map[string]string{"type": AminoPrefix + "PrivKeyEd25519", "value": base64.StdEncoding.EncodeToString(nodePriv)},
	})

	laddr := ""
	if opt.RemoteSigner {
		laddr = "tcp://127.0.0.1:26659"
	}
	certLine, keyLine := `tls_cert_file = ""`, `tls_key_file = ""`
	if opt.RPCTLS {
		certPEM, keyPEM := selfSigned(t)
		h.Secrets = append(h.Secrets, strings.TrimSpace(string(keyPEM)))
		for _, l := range strings.Split(string(keyPEM), "\n") {
			if len(l) > 40 && !strings.HasPrefix(l, "-----") {
				h.Secrets = append(h.Secrets, l)
			}
		}
		// The certificate file deliberately bundles the private key.
		must(t, os.WriteFile(filepath.Join(cfg, "rpc.crt"), append(certPEM, keyPEM...), 0o600))
		must(t, os.WriteFile(filepath.Join(cfg, "rpc.key"), keyPEM, 0o600))
		certLine, keyLine = `tls_cert_file = "rpc.crt"`, `tls_key_file = "rpc.key"`
	}
	config := `# generated test configuration
proxy_app = "tcp://127.0.0.1:26658"
moniker = "fixture"

#######################################################
###       Main Base Config Options                  ###
#######################################################
priv_validator_key_file = "config/priv_validator_key.json"
priv_validator_state_file = "data/priv_validator_state.json"
priv_validator_laddr = "` + laddr + `"
node_key_file = "config/node_key.json"

[rpc]
laddr = "tcp://0.0.0.0:26657" # all interfaces
cors_allowed_origins = [
  "https://example.org",
]
` + certLine + `
` + keyLine + `

[p2p]
laddr = "tcp://0.0.0.0:26656"
external_address = ""
`
	must(t, os.WriteFile(filepath.Join(cfg, "config.toml"), []byte(config), 0o644))

	app := `minimum-gas-prices = "0.1uqor"

[api]
enable = true
address = "tcp://0.0.0.0:1317"

[grpc]
enable = true
address = "localhost:9090"

[json-rpc]
enable = true
address = "0.0.0.0:8545"
ws-address = "127.0.0.1:8546"

[tls]
certificate-path = ""
key-path = ""

[svm-rpc]
enable = false
address = "0.0.0.0:8899"
`
	must(t, os.WriteFile(filepath.Join(cfg, "app.toml"), []byte(app), 0o644))
	must(t, os.WriteFile(filepath.Join(cfg, "genesis.json"), []byte(Genesis(base64.StdEncoding.EncodeToString(valPub))), 0o644))
	return h
}

func (h *Home) addSecret(priv ed25519.PrivateKey) {
	h.Secrets = append(h.Secrets,
		base64.StdEncoding.EncodeToString(priv),
		base64.StdEncoding.EncodeToString(priv.Seed()),
		hex.EncodeToString(priv.Seed()),
		strings.ToUpper(hex.EncodeToString(priv.Seed())),
		string(priv.Seed()),
	)
}

// Genesis returns a small genesis document with the pqc module state of a
// QoreChain network.
func Genesis(valPubB64 string) string {
	return `{
  "app_name": "qorechaind",
  "genesis_time": "2026-01-01T00:00:00Z",
  "chain_id": "qorechain-fixture",
  "initial_height": 1,
  "app_state": {
    "genutil": {
      "gen_txs": [
        {
          "body": {
            "messages": [
              {
                "@type": "/cosmos.staking.v1beta1.MsgCreateValidator",
                "pubkey": {
                  "@type": "/cosmos.crypto.ed25519.PubKey",
                  "key": "` + valPubB64 + `"
                }
              }
            ]
          }
        }
      ]
    },
    "pqc": {
      "params": {
        "pqc_primary": true,
        "allow_classical_fallback": false,
        "min_security_level": 5,
        "default_migration_blocks": "1000000",
        "default_signature_algo": 1,
        "hybrid_signature_mode": 2
      },
      "accounts": [
        {"address": "qor1fixture", "algorithm_id": 1, "key_type": "hybrid"}
      ],
      "stats": {},
      "algorithms": [
        {
          "id": 1,
          "name": "dilithium5",
          "category": "signature",
          "nist_level": 5,
          "status": 0,
          "public_key_size": 2592,
          "private_key_size": 4896,
          "signature_size": 4627,
          "added_at_height": 0
        },
        {
          "id": 2,
          "name": "mlkem1024",
          "category": "kem",
          "nist_level": 5,
          "status": 0,
          "public_key_size": 1568,
          "private_key_size": 3168,
          "ciphertext_size": 1568,
          "added_at_height": 0
        }
      ],
      "protocol_features": [
        "pqc-sign-bytes-v2",
        "evm-pqc-authorisation-window",
        "amm-swap-integrity"
      ]
    }
  },
  "consensus": {
    "params": {
      "validator": {
        "pub_key_types": [
          "ed25519"
        ]
      }
    }
  }
}
`
}

func selfSigned(t testing.TB) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rpc.fixture.test"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{"rpc.fixture.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(t, err)
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	must(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
}

func writeJSON(t testing.TB, path string, mode os.FileMode, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	must(t, err)
	must(t, os.WriteFile(path, b, mode))
	must(t, os.Chmod(path, mode))
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
