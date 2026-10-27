// SPDX-License-Identifier: Apache-2.0

// Package tlsscan performs one TLS handshake with an endpoint and records the
// negotiated protocol version, cipher suite, key exchange group and the
// certificates the server presented. No application data is sent.
package tlsscan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/qorechain/qorescan/internal/catalog"
	"github.com/qorechain/qorescan/internal/certs"
	"github.com/qorechain/qorescan/internal/inventory"
)

const src = inventory.SourceTLS

// Options configure a handshake.
type Options struct {
	Timeout time.Duration
	// ServerName overrides the SNI name (default: the host of the target).
	ServerName string
	// Roots verifies the certificate chain; nil means the system roots.
	Roots *x509.CertPool
	// Now is the time used for chain verification; zero means now.
	Now  time.Time
	Logf func(format string, args ...any)
}

// Normalize returns target as host:port, adding port 443 when absent.
func Normalize(target string) (string, string, error) {
	t := strings.TrimSpace(target)
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimSuffix(t, "/")
	if t == "" {
		return "", "", fmt.Errorf("empty TLS target")
	}
	host, port, err := net.SplitHostPort(t)
	if err != nil {
		host, port = t, "443"
		if strings.Count(t, ":") > 1 && !strings.HasPrefix(t, "[") {
			host = t // bare IPv6
		}
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", "", fmt.Errorf("TLS target %q has no host", target)
	}
	return net.JoinHostPort(host, port), host, nil
}

// Scan handshakes with target (host:port) and records the result in inv.
func Scan(ctx context.Context, inv *inventory.Inventory, target string, opt Options) error {
	addr, host, err := Normalize(target)
	if err != nil {
		return err
	}
	logf := opt.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	sni := opt.ServerName
	if sni == "" && net.ParseIP(host) == nil {
		sni = host
	}
	cfg := &tls.Config{
		ServerName: sni,
		// The handshake records what the server offers even when its chain
		// does not verify; verification is done separately below and
		// recorded as a property of the certificate.
		InsecureSkipVerify: true, //nolint:gosec // inventory, not trust
		MinVersion:         tls.VersionTLS10,
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: cfg}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	logf("TLS handshake with %s", addr)
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("tls %s: %w", addr, err)
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()

	occ := inventory.Occurrence{Location: addr, Symbol: "tls-handshake", Context: "negotiated by QoreScan's client with default key exchange preferences (hybrid ML-KEM groups offered first)"}
	var refs []string
	add := func(r string) {
		if r == "" {
			return
		}
		for _, x := range refs {
			if x == r {
				return
			}
		}
		refs = append(refs, r)
	}

	// Key exchange.
	kx, kxNote := keyExchange(st)
	if kx != "" {
		add(inv.AddAlgorithm(catalog.Get(kx), src, inventory.Occurrence{Location: addr, Symbol: "key-exchange", Context: kxNote}))
	}

	// Certificates.
	var leafKey string
	for i, c := range st.PeerCertificates {
		o := inventory.Occurrence{Location: addr, Symbol: fmt.Sprintf("certificate[%d]", i), Context: "presented by the server"}
		copt := certs.Options{Source: src, Occurrence: o}
		if i == 0 {
			copt.Verify, copt.Roots, copt.Intermediates, copt.DNSName, copt.Now = true, opt.Roots, st.PeerCertificates[1:], host, opt.Now
			leafKey = inventory.AlgorithmRef(certs.PublicKeyAlgorithm(c).Key)
		}
		add(certs.Add(inv, c, copt))
	}

	// Cipher suite.
	suiteName := tls.CipherSuiteName(st.CipherSuite)
	suiteAlgs := suiteAlgorithms(suiteName)
	var suiteRefs []string
	if kx != "" {
		suiteRefs = append(suiteRefs, inventory.AlgorithmRef(kx))
	}
	if leafKey != "" && st.Version < tls.VersionTLS13 {
		suiteRefs = append(suiteRefs, leafKey)
	}
	for _, k := range suiteAlgs {
		r := inv.AddAlgorithm(catalog.Get(k), src, inventory.Occurrence{Location: addr, Symbol: "cipher-suite", Context: suiteName})
		suiteRefs = append(suiteRefs, r)
		add(r)
	}
	if leafKey != "" {
		add(leafKey)
	}

	version := strings.TrimPrefix(tls.VersionName(st.Version), "TLS ")
	props := []inventory.Property{
		{Name: "qorescan:tls:key-exchange-group", Value: groupName(st.CurveID)},
	}
	if st.NegotiatedProtocol != "" {
		props = append(props, inventory.Property{Name: "qorescan:tls:alpn", Value: st.NegotiatedProtocol})
	}
	if sni != "" {
		props = append(props, inventory.Property{Name: "qorescan:tls:server-name", Value: sni})
	}
	inv.AddAsset(inventory.Asset{
		Ref:  "crypto/protocol/tls/" + inventory.Slug(addr),
		Name: "TLS " + version + " at " + addr,
		Kind: inventory.KindProtocol,
		Protocol: &inventory.Protocol{
			Type:    "tls",
			Version: version,
			CipherSuites: []inventory.CipherSuite{{
				Name:       suiteName,
				Identifier: fmt.Sprintf("0x%04X", st.CipherSuite),
				Algorithms: suiteRefs,
			}},
			Refs: refs,
		},
		Sources:     []string{src},
		Occurrences: []inventory.Occurrence{occ},
		Properties:  props,
	})
	if st.Version < tls.VersionTLS12 {
		inv.AddNote(src, "warning", addr, "server negotiated %s", tls.VersionName(st.Version))
	}
	return nil
}

func groupName(id tls.CurveID) string {
	if id == 0 {
		return "none (RSA key transport)"
	}
	return id.String()
}

// keyExchange returns the catalog key of the negotiated key exchange.
func keyExchange(st tls.ConnectionState) (string, string) {
	switch st.CurveID {
	case tls.X25519MLKEM768:
		return "x25519mlkem768", "hybrid key exchange X25519MLKEM768"
	case tls.SecP256r1MLKEM768:
		return "secp256r1mlkem768", "hybrid key exchange SecP256r1MLKEM768"
	case tls.SecP384r1MLKEM1024:
		return "secp384r1mlkem1024", "hybrid key exchange SecP384r1MLKEM1024"
	case tls.X25519:
		return "x25519", "key exchange X25519"
	case tls.CurveP256:
		return "ecdh-p256", "key exchange ECDHE P-256"
	case tls.CurveP384:
		return "ecdh-p384", "key exchange ECDHE P-384"
	case tls.CurveP521:
		return "ecdh-p521", "key exchange ECDHE P-521"
	case 0:
		if strings.HasPrefix(tls.CipherSuiteName(st.CipherSuite), "TLS_RSA_") {
			return "rsa-kex", "RSA key transport (no forward secrecy)"
		}
	}
	return "", ""
}

// suiteAlgorithms returns the bulk cipher and hash of a cipher suite name.
func suiteAlgorithms(name string) []string {
	var out []string
	switch {
	case strings.Contains(name, "AES_128_GCM"):
		out = append(out, "aes-128-gcm")
	case strings.Contains(name, "AES_256_GCM"):
		out = append(out, "aes-256-gcm")
	case strings.Contains(name, "AES_128_CBC"):
		out = append(out, "aes-128-cbc")
	case strings.Contains(name, "AES_256_CBC"):
		out = append(out, "aes-256-cbc")
	case strings.Contains(name, "CHACHA20_POLY1305"):
		out = append(out, "chacha20-poly1305")
	}
	tls13 := !strings.Contains(name, "_WITH_")
	switch {
	case strings.HasSuffix(name, "_SHA384"):
		if tls13 {
			out = append(out, "hkdf-sha384")
		}
		out = append(out, "sha-384")
	case strings.HasSuffix(name, "_SHA256"):
		if tls13 {
			out = append(out, "hkdf-sha256")
		}
		out = append(out, "sha-256")
	case strings.HasSuffix(name, "_SHA"):
		out = append(out, "sha-1")
	}
	return out
}
