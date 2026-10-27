// SPDX-License-Identifier: Apache-2.0

package tlsscan

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/qorechain/qorescan/internal/inventory"
)

// testPKI is a throwaway CA and a leaf certificate for 127.0.0.1, generated
// per test.
type testPKI struct {
	roots *x509.CertPool
	leaf  tls.Certificate
}

func newPKI(t *testing.T, rsaLeaf bool) testPKI {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "QoreScan Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	var leafKey crypto.Signer
	if rsaLeaf {
		leafKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		leafKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "endpoint.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return testPKI{roots: roots, leaf: tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}
}

func serve(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				buf := make([]byte, 1)
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Read(buf)
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func protocol(t *testing.T, inv *inventory.Inventory) *inventory.Asset {
	t.Helper()
	for _, a := range inv.Assets() {
		if a.Kind == inventory.KindProtocol {
			return a
		}
	}
	t.Fatal("no protocol asset")
	return nil
}

func prop(a *inventory.Asset, name string) string {
	for _, p := range a.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func TestTLS13HybridGroup(t *testing.T) {
	pki := newPKI(t, false)
	addr := serve(t, &tls.Config{Certificates: []tls.Certificate{pki.leaf}, MinVersion: tls.VersionTLS13})
	inv := inventory.New("t")
	if err := Scan(context.Background(), inv, addr, Options{Roots: pki.roots}); err != nil {
		t.Fatal(err)
	}
	p := protocol(t, inv)
	if p.Protocol.Version != "1.3" || prop(p, "qorescan:tls:key-exchange-group") != "X25519MLKEM768" {
		t.Fatalf("protocol %+v props %+v", p.Protocol, p.Properties)
	}
	cs := p.Protocol.CipherSuites[0]
	if !strings.HasPrefix(cs.Name, "TLS_AES_") && cs.Name != "TLS_CHACHA20_POLY1305_SHA256" {
		t.Errorf("suite %s", cs.Name)
	}
	refs := strings.Join(p.Protocol.Refs, " ")
	for _, want := range []string{"crypto/algorithm/x25519mlkem768", "crypto/algorithm/ecdsa-p256", "crypto/certificate/"} {
		if !strings.Contains(refs, want) {
			t.Errorf("protocol refs %s lack %s", refs, want)
		}
	}
	if _, ok := inv.Asset("crypto/algorithm/ecdsa-sha384"); !ok {
		t.Error("certificate signature algorithm (ECDSA with SHA-384 from the P-384 CA) missing")
	}
	var leaf *inventory.Asset
	for _, a := range inv.Assets() {
		if a.Kind == inventory.KindCertificate && a.Certificate.Subject == "CN=endpoint.test" {
			leaf = a
		}
	}
	if leaf == nil || !leaf.Certificate.ChainVerified {
		t.Fatalf("leaf certificate not verified: %+v", leaf)
	}
}

func TestTLS13ClassicalGroupAndUnverifiedChain(t *testing.T) {
	pki := newPKI(t, false)
	addr := serve(t, &tls.Config{Certificates: []tls.Certificate{pki.leaf}, CurvePreferences: []tls.CurveID{tls.X25519}})
	inv := inventory.New("t")
	if err := Scan(context.Background(), inv, addr, Options{Roots: x509.NewCertPool()}); err != nil {
		t.Fatal(err)
	}
	p := protocol(t, inv)
	if prop(p, "qorescan:tls:key-exchange-group") != "X25519" {
		t.Fatalf("group %s", prop(p, "qorescan:tls:key-exchange-group"))
	}
	for _, a := range inv.Assets() {
		if a.Kind == inventory.KindCertificate && a.Certificate.Subject == "CN=endpoint.test" {
			if a.Certificate.ChainVerified || a.Certificate.ChainError == "" {
				t.Fatal("chain must not verify against an empty root pool")
			}
		}
	}
}

func TestTLS12RSA(t *testing.T) {
	pki := newPKI(t, true)
	addr := serve(t, &tls.Config{
		Certificates: []tls.Certificate{pki.leaf}, MaxVersion: tls.VersionTLS12,
		CipherSuites:     []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	})
	inv := inventory.New("t")
	if err := Scan(context.Background(), inv, addr, Options{Roots: pki.roots}); err != nil {
		t.Fatal(err)
	}
	p := protocol(t, inv)
	cs := p.Protocol.CipherSuites[0]
	if p.Protocol.Version != "1.2" || cs.Name != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" || cs.Identifier != "0xC02F" {
		t.Fatalf("protocol %+v", p.Protocol)
	}
	want := []string{"crypto/algorithm/ecdh-p256", "crypto/algorithm/rsa-2048", "crypto/algorithm/aes-128-gcm", "crypto/algorithm/sha-256"}
	if strings.Join(cs.Algorithms, " ") != strings.Join(want, " ") {
		t.Errorf("suite algorithms %v, want %v", cs.Algorithms, want)
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"api.example":          "api.example:443",
		"https://api.example/": "api.example:443",
		"api.example:8443":     "api.example:8443",
		"[::1]:443":            "[::1]:443",
	} {
		got, _, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v", in, got, err)
		}
	}
	if _, _, err := Normalize(" "); err == nil {
		t.Error("empty target accepted")
	}
}

func TestUnreachable(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	if err := Scan(context.Background(), inventory.New("t"), addr, Options{Timeout: 2 * time.Second}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSuiteAlgorithms(t *testing.T) {
	cases := map[string]string{
		"TLS_AES_256_GCM_SHA384":                  "aes-256-gcm hkdf-sha384 sha-384",
		"TLS_CHACHA20_POLY1305_SHA256":            "chacha20-poly1305 hkdf-sha256 sha-256",
		"TLS_RSA_WITH_AES_128_CBC_SHA":            "aes-128-cbc sha-1",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "aes-256-gcm sha-384",
	}
	for in, want := range cases {
		if got := strings.Join(suiteAlgorithms(in), " "); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
