// SPDX-License-Identifier: Apache-2.0

// Package certs records X.509 certificates as CBOM assets: the certificate,
// its subject public key and the algorithms involved. Only public data is
// read.
package certs

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/qorechain/qorescan/internal/catalog"
	"github.com/qorechain/qorescan/internal/inventory"
)

// maxCertFileSize bounds certificate files read from a node home.
const maxCertFileSize = 1 << 20

// Options control how a certificate is recorded.
type Options struct {
	Source     string
	Occurrence inventory.Occurrence
	// Roots, when not nil, is used to verify the chain; Intermediates are
	// the other certificates the peer sent.
	Verify        bool
	Roots         *x509.CertPool
	Intermediates []*x509.Certificate
	DNSName       string
	Now           time.Time
}

// Add records cert in inv and returns the certificate's bom-ref.
func Add(inv *inventory.Inventory, cert *x509.Certificate, opt Options) string {
	fp := sha256.Sum256(cert.Raw)
	fpHex := hex.EncodeToString(fp[:])
	ref := "crypto/certificate/" + fpHex[:16]

	keyAlg := PublicKeyAlgorithm(cert)
	keyAlgRef := inv.AddAlgorithm(keyAlg, opt.Source, opt.Occurrence)
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	keyRef := inv.AddAsset(inventory.Asset{
		Ref:  "crypto/key/certificate/" + hex.EncodeToString(spki[:8]),
		Name: "Certificate public key (" + keyAlg.Name + ")",
		Kind: inventory.KindMaterial,
		Material: &inventory.Material{
			Type:         "public-key",
			ID:           "spki-sha256:" + hex.EncodeToString(spki[:]),
			AlgorithmRef: keyAlgRef,
			SizeBits:     publicKeyBits(cert),
			Format:       "X.509 SubjectPublicKeyInfo",
		},
		Sources:     []string{opt.Source},
		Occurrences: []inventory.Occurrence{opt.Occurrence},
	})

	sigAlg := SignatureAlgorithm(cert.SignatureAlgorithm)
	sigRef := inv.AddAlgorithm(sigAlg, opt.Source, opt.Occurrence)

	c := &inventory.Certificate{
		Subject:               cert.Subject.String(),
		Issuer:                cert.Issuer.String(),
		NotBefore:             cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:              cert.NotAfter.UTC().Format(time.RFC3339),
		SignatureAlgorithmRef: sigRef,
		SubjectPublicKeyRef:   keyRef,
		Format:                "X.509",
		FingerprintSHA256:     fpHex,
	}
	if opt.Verify {
		c.ChainVerificationAttempted = true
		inter := x509.NewCertPool()
		for _, ic := range opt.Intermediates {
			inter.AddCert(ic)
		}
		vo := x509.VerifyOptions{Roots: opt.Roots, Intermediates: inter, DNSName: opt.DNSName}
		if !opt.Now.IsZero() {
			vo.CurrentTime = opt.Now
		}
		if _, err := cert.Verify(vo); err != nil {
			c.ChainError = err.Error()
		} else {
			c.ChainVerified = true
		}
	}
	name := cert.Subject.CommonName
	if name == "" {
		name = cert.Subject.String()
	}
	if name == "" {
		name = fpHex[:16]
	}
	return inv.AddAsset(inventory.Asset{
		Ref:         ref,
		Name:        "Certificate " + name,
		Kind:        inventory.KindCertificate,
		Certificate: c,
		Sources:     []string{opt.Source},
		Occurrences: []inventory.Occurrence{opt.Occurrence},
	})
}

// LoadPEMFile reads every CERTIFICATE block of a PEM file. Blocks of any
// other type (for example a private key bundled in the same file) are
// skipped without being decoded.
func LoadPEMFile(path string) ([]*x509.Certificate, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > maxCertFileSize {
		return nil, fmt.Errorf("larger than %d bytes", maxCertFileSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var out []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			clear(block.Bytes)
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", len(out)+1, err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no CERTIFICATE block")
	}
	return out, nil
}

// PublicKeyAlgorithm maps a certificate's subject public key to the catalog.
func PublicKeyAlgorithm(cert *x509.Certificate) catalog.Algorithm {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return catalog.RSA(k.N.BitLen())
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return catalog.Get("ecdsa-p256")
		case elliptic.P384():
			return catalog.Get("ecdsa-p384")
		case elliptic.P521():
			return catalog.Get("ecdsa-p521")
		}
		return catalog.Get("ecdsa")
	case ed25519.PublicKey:
		return catalog.Get("ed25519")
	}
	// Go does not parse every key type (for example ML-DSA). Read the
	// algorithm OID from the SubjectPublicKeyInfo instead.
	if oid := spkiOID(cert.RawSubjectPublicKeyInfo); oid != "" {
		for _, k := range catalog.Keys() {
			if a, _ := catalog.Lookup(k); a.OID == oid && a.Primitive == "signature" {
				return a
			}
		}
		return catalog.Algorithm{Key: "oid-" + inventory.Slug(oid), Name: "Public key algorithm " + oid, Primitive: "unknown", OID: oid, Class: catalog.Unknown, Transition: catalog.TransitionUnknown}
	}
	return catalog.Algorithm{Key: "unknown-public-key", Name: "Unknown public key algorithm", Primitive: "unknown", Class: catalog.Unknown, Transition: catalog.TransitionUnknown}
}

func spkiOID(raw []byte) string {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(raw, &spki); err != nil {
		return ""
	}
	return spki.Algorithm.Algorithm.String()
}

func publicKeyBits(cert *x509.Certificate) int {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	}
	return 0
}

// SignatureAlgorithm maps an X.509 signature algorithm to a catalog entry.
// The issuer's key size or curve is not known from the certificate alone, so
// the entry names the scheme and hash.
func SignatureAlgorithm(s x509.SignatureAlgorithm) catalog.Algorithm {
	mk := func(key, name, family string) catalog.Algorithm {
		base := catalog.Get("rsa")
		if family == "ECDSA" {
			base = catalog.Get("ecdsa")
		}
		base.Key = key
		base.Name = name
		base.Family = family
		base.Note = "Signature scheme of a certificate; the issuer key size or curve is recorded with the issuer, not here."
		base.OID = ""
		return base
	}
	switch s {
	case x509.SHA256WithRSA:
		return mk("rsa-pkcs1v15-sha256", "RSA PKCS#1 v1.5 with SHA-256", "RSA")
	case x509.SHA384WithRSA:
		return mk("rsa-pkcs1v15-sha384", "RSA PKCS#1 v1.5 with SHA-384", "RSA")
	case x509.SHA512WithRSA:
		return mk("rsa-pkcs1v15-sha512", "RSA PKCS#1 v1.5 with SHA-512", "RSA")
	case x509.SHA256WithRSAPSS:
		return mk("rsa-pss-sha256", "RSA-PSS with SHA-256", "RSA")
	case x509.SHA384WithRSAPSS:
		return mk("rsa-pss-sha384", "RSA-PSS with SHA-384", "RSA")
	case x509.SHA512WithRSAPSS:
		return mk("rsa-pss-sha512", "RSA-PSS with SHA-512", "RSA")
	case x509.ECDSAWithSHA256:
		return mk("ecdsa-sha256", "ECDSA with SHA-256", "ECDSA")
	case x509.ECDSAWithSHA384:
		return mk("ecdsa-sha384", "ECDSA with SHA-384", "ECDSA")
	case x509.ECDSAWithSHA512:
		return mk("ecdsa-sha512", "ECDSA with SHA-512", "ECDSA")
	case x509.PureEd25519:
		return catalog.Get("ed25519")
	case x509.SHA1WithRSA:
		return mk("rsa-pkcs1v15-sha1", "RSA PKCS#1 v1.5 with SHA-1", "RSA")
	case x509.ECDSAWithSHA1:
		return mk("ecdsa-sha1", "ECDSA with SHA-1", "ECDSA")
	}
	return catalog.Algorithm{Key: "signature-" + inventory.Slug(s.String()), Name: "Signature algorithm " + s.String(), Primitive: "signature", Class: catalog.Unknown, Transition: catalog.TransitionUnknown}
}
