// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

// A certificate whose key Go does not parse (here: an ML-DSA-87 OID) is
// still classified from the SubjectPublicKeyInfo algorithm OID.
func TestPublicKeyAlgorithmFromOID(t *testing.T) {
	spki, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}}, asn1.BitString{Bytes: make([]byte, 2592), BitLength: 2592 * 8}})
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{RawSubjectPublicKeyInfo: spki}
	if a := PublicKeyAlgorithm(c); a.Key != "ml-dsa-87" {
		t.Fatalf("got %s", a.Key)
	}
	spki2, _ := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}}, asn1.BitString{Bytes: []byte{1}, BitLength: 8}})
	if a := PublicKeyAlgorithm(&x509.Certificate{RawSubjectPublicKeyInfo: spki2}); a.OID != "1.2.3.4" || a.Class != "unknown" {
		t.Fatalf("got %+v", a)
	}
}

func TestSignatureAlgorithmNames(t *testing.T) {
	for s, want := range map[x509.SignatureAlgorithm]string{
		x509.SHA256WithRSA:   "rsa-pkcs1v15-sha256",
		x509.ECDSAWithSHA384: "ecdsa-sha384",
		x509.PureEd25519:     "ed25519",
	} {
		if got := SignatureAlgorithm(s).Key; got != want {
			t.Errorf("%v: %s, want %s", s, got, want)
		}
	}
}
