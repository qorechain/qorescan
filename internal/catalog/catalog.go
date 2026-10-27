// SPDX-License-Identifier: Apache-2.0

// Package catalog describes the cryptographic algorithms QoreScan knows:
// their CycloneDX primitive, parameter set, security levels, the standard
// that defines them and how NIST IR 8547 schedules them.
//
// Security categories come from FIPS 203, FIPS 204 and FIPS 205 for the
// post-quantum algorithms and from NIST IR 8547 (Tables 6 and 8) for block
// ciphers and hash functions. Quantum-vulnerable public-key algorithms get
// category 0, which CycloneDX defines as "none of the categories are met".
// Hash functions use their collision category, the lower of the two IR 8547
// lists.
package catalog

import (
	"fmt"
	"sort"
	"strings"
)

// Class is QoreScan's classification of an algorithm.
type Class string

const (
	// PostQuantum is an algorithm standardised in FIPS 203, 204 or 205.
	PostQuantum Class = "post-quantum"
	// Hybrid combines a classical and a post-quantum algorithm.
	Hybrid Class = "hybrid"
	// QuantumVulnerable is public-key cryptography that a cryptographically
	// relevant quantum computer breaks (RSA, ECDSA, EdDSA, DH, ECDH, pairings).
	QuantumVulnerable Class = "quantum-vulnerable"
	// Symmetric covers block ciphers, AEADs, MACs, KDFs, hashes and XOFs.
	Symmetric Class = "symmetric"
	// Unknown is anything QoreScan cannot classify.
	Unknown Class = "unknown"
)

// IR 8547 transition wording, quoted from the final report (October 2026),
// Tables 2 and 4.
const (
	TransitionQuantumVulnerable = "Deprecated after 2030, disallowed after 2035 (NIST IR 8547)"
	TransitionOutsideTables     = "Not listed in NIST IR 8547; quantum-vulnerable, same exposure as the listed families"
	TransitionNotScheduled      = "Not scheduled for deprecation by NIST IR 8547"
	TransitionNotNIST           = "Not a NIST-standardised algorithm; not scheduled by NIST IR 8547"
	TransitionHybrid            = "Hybrid: post-quantum component approved; classical component deprecated after 2030, disallowed after 2035 (NIST IR 8547)"
	TransitionUnknown           = "Unknown"
)

// Algorithm is one entry of the catalog.
type Algorithm struct {
	// Key is a stable lower-case identifier used in bom-refs.
	Key string
	// Name is the display name written to the CBOM.
	Name string
	// Family groups parameter sets (ML-DSA, ECDSA, AES, ...).
	Family string
	// Primitive is the CycloneDX 1.6 algorithmProperties.primitive value.
	Primitive string
	// ParameterSet is the CycloneDX parameterSetIdentifier, if any.
	ParameterSet string
	// Curve is the elliptic curve name, if any.
	Curve string
	// Mode is the CycloneDX block cipher mode, if any.
	Mode string
	// ClassicalBits is the classical security strength in bits; 0 when not
	// defined.
	ClassicalBits int
	// NISTLevel is the NIST security category; nil when not defined.
	NISTLevel *int
	// Functions are CycloneDX cryptoFunctions.
	Functions []string
	// OID is the algorithm's object identifier, if one is assigned.
	OID string
	// Standard names the defining standard.
	Standard string
	Class    Class
	// Transition is the NIST IR 8547 status text.
	Transition string
	// Note is extra context shown in reports.
	Note string
}

func level(n int) *int { return &n }

var entries = []Algorithm{
	// FIPS 204
	{Key: "ml-dsa-44", Name: "ML-DSA-44", Family: "ML-DSA", Primitive: "signature", ParameterSet: "44", ClassicalBits: 128, NISTLevel: level(2), Functions: []string{"keygen", "sign", "verify"}, OID: "2.16.840.1.101.3.4.3.17", Standard: "FIPS 204", Class: PostQuantum, Transition: TransitionNotScheduled},
	{Key: "ml-dsa-65", Name: "ML-DSA-65", Family: "ML-DSA", Primitive: "signature", ParameterSet: "65", ClassicalBits: 192, NISTLevel: level(3), Functions: []string{"keygen", "sign", "verify"}, OID: "2.16.840.1.101.3.4.3.18", Standard: "FIPS 204", Class: PostQuantum, Transition: TransitionNotScheduled},
	{Key: "ml-dsa-87", Name: "ML-DSA-87", Family: "ML-DSA", Primitive: "signature", ParameterSet: "87", ClassicalBits: 256, NISTLevel: level(5), Functions: []string{"keygen", "sign", "verify"}, OID: "2.16.840.1.101.3.4.3.19", Standard: "FIPS 204", Class: PostQuantum, Transition: TransitionNotScheduled},
	// FIPS 203
	{Key: "ml-kem-512", Name: "ML-KEM-512", Family: "ML-KEM", Primitive: "kem", ParameterSet: "512", ClassicalBits: 128, NISTLevel: level(1), Functions: []string{"keygen", "encapsulate", "decapsulate"}, OID: "2.16.840.1.101.3.4.4.1", Standard: "FIPS 203", Class: PostQuantum, Transition: TransitionNotScheduled},
	{Key: "ml-kem-768", Name: "ML-KEM-768", Family: "ML-KEM", Primitive: "kem", ParameterSet: "768", ClassicalBits: 192, NISTLevel: level(3), Functions: []string{"keygen", "encapsulate", "decapsulate"}, OID: "2.16.840.1.101.3.4.4.2", Standard: "FIPS 203", Class: PostQuantum, Transition: TransitionNotScheduled},
	{Key: "ml-kem-1024", Name: "ML-KEM-1024", Family: "ML-KEM", Primitive: "kem", ParameterSet: "1024", ClassicalBits: 256, NISTLevel: level(5), Functions: []string{"keygen", "encapsulate", "decapsulate"}, OID: "2.16.840.1.101.3.4.4.3", Standard: "FIPS 203", Class: PostQuantum, Transition: TransitionNotScheduled},
	// Hybrid TLS key exchange groups (classical ECDH + ML-KEM).
	{Key: "x25519mlkem768", Name: "X25519MLKEM768", Family: "Hybrid KEM", Primitive: "kem", ParameterSet: "768", ClassicalBits: 128, NISTLevel: level(3), Functions: []string{"encapsulate", "decapsulate"}, Standard: "FIPS 203 (ML-KEM-768) combined with X25519", Class: Hybrid, Transition: TransitionHybrid, Note: "Post-quantum security comes from the ML-KEM-768 component."},
	{Key: "secp256r1mlkem768", Name: "SecP256r1MLKEM768", Family: "Hybrid KEM", Primitive: "kem", ParameterSet: "768", Curve: "secp256r1", ClassicalBits: 128, NISTLevel: level(3), Functions: []string{"encapsulate", "decapsulate"}, Standard: "FIPS 203 (ML-KEM-768) combined with ECDH P-256", Class: Hybrid, Transition: TransitionHybrid, Note: "Post-quantum security comes from the ML-KEM-768 component."},
	{Key: "secp384r1mlkem1024", Name: "SecP384r1MLKEM1024", Family: "Hybrid KEM", Primitive: "kem", ParameterSet: "1024", Curve: "secp384r1", ClassicalBits: 192, NISTLevel: level(5), Functions: []string{"encapsulate", "decapsulate"}, Standard: "FIPS 203 (ML-KEM-1024) combined with ECDH P-384", Class: Hybrid, Transition: TransitionHybrid, Note: "Post-quantum security comes from the ML-KEM-1024 component."},
	// Classical signatures (FIPS 186-5).
	{Key: "ecdsa-secp256k1", Name: "ECDSA secp256k1", Family: "ECDSA", Primitive: "signature", Curve: "secp256k1", ClassicalBits: 128, NISTLevel: level(0), Functions: []string{"sign", "verify"}, Standard: "SEC 2 curve, ECDSA per FIPS 186-5", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable, Note: "IR 8547 schedules the ECDSA family; QoreScan applies that schedule to every curve in the family."},
	{Key: "ecdsa-p256", Name: "ECDSA P-256", Family: "ECDSA", Primitive: "signature", Curve: "secp256r1", ClassicalBits: 128, NISTLevel: level(0), Functions: []string{"sign", "verify"}, Standard: "FIPS 186-5", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable},
	{Key: "ecdsa-p384", Name: "ECDSA P-384", Family: "ECDSA", Primitive: "signature", Curve: "secp384r1", ClassicalBits: 192, NISTLevel: level(0), Functions: []string{"sign", "verify"}, Standard: "FIPS 186-5", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable},
	{Key: "ecdsa-p521", Name: "ECDSA P-521", Family: "ECDSA", Primitive: "signature", Curve: "secp521r1", ClassicalBits: 256, NISTLevel: level(0), Functions: []string{"sign", "verify"}, Standard: "FIPS 186-5", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable},
	{Key: "ecdsa", Name: "ECDSA", Family: "ECDSA", Primitive: "signature", NISTLevel: level(0), Functions: []string{"sign", "verify"}, Standard: "FIPS 186-5", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable, Note: "Curve not determined from the evidence."},
	{Key: "ed25519", Name: "Ed25519", Family: "EdDSA", Primitive: "signature", Curve: "Ed25519", ClassicalBits: 128, NISTLevel: level(0), Functions: []string{"sign", "verify"}, OID: "1.3.101.112", Standard: "FIPS 186-5", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable},
	{Key: "rsa-2048", Name: "RSA-2048", Family: "RSA", Primitive: "signature", ParameterSet: "2048", ClassicalBits: 112, NISTLevel: level(0), Functions: []string{"sign", "verify"}, OID: "1.2.840.113549.1.1.1", Standard: "FIPS 186-5", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable},
	{Key: "rsa-3072", Name: "RSA-3072", Family: "RSA", Primitive: "signature", ParameterSet: "3072", ClassicalBits: 128, NISTLevel: level(0), Functions: []string{"sign", "verify"}, OID: "1.2.840.113549.1.1.1", Standard: "FIPS 186-5", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable},
	{Key: "rsa-4096", Name: "RSA-4096", Family: "RSA", Primitive: "signature", ParameterSet: "4096", ClassicalBits: 128, NISTLevel: level(0), Functions: []string{"sign", "verify"}, OID: "1.2.840.113549.1.1.1", Standard: "FIPS 186-5", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable},
	{Key: "rsa", Name: "RSA", Family: "RSA", Primitive: "signature", NISTLevel: level(0), Functions: []string{"sign", "verify"}, OID: "1.2.840.113549.1.1.1", Standard: "FIPS 186-5", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable, Note: "Key size not determined from the evidence."},
	{Key: "rsa-kex", Name: "RSA key transport", Family: "RSA", Primitive: "pke", NISTLevel: level(0), Functions: []string{"encrypt", "decrypt"}, Standard: "SP 800-56B", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable},
	{Key: "bls12-381", Name: "BLS12-381", Family: "BLS", Primitive: "signature", Curve: "BLS12-381", NISTLevel: level(0), Functions: []string{"sign", "verify"}, Standard: "IETF draft-irtf-cfrg-bls-signature", Class: QuantumVulnerable, Transition: TransitionOutsideTables},
	// Key agreement.
	{Key: "x25519", Name: "X25519", Family: "ECDH", Primitive: "key-agree", Curve: "Curve25519", ClassicalBits: 128, NISTLevel: level(0), Functions: []string{"keygen", "keyderive"}, OID: "1.3.101.110", Standard: "RFC 7748", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable, Note: "IR 8547 schedules elliptic-curve DH; X25519 is not in SP 800-56A but has the same quantum exposure."},
	{Key: "ecdh-p256", Name: "ECDH P-256", Family: "ECDH", Primitive: "key-agree", Curve: "secp256r1", ClassicalBits: 128, NISTLevel: level(0), Functions: []string{"keygen", "keyderive"}, Standard: "SP 800-56A", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable},
	{Key: "ecdh-p384", Name: "ECDH P-384", Family: "ECDH", Primitive: "key-agree", Curve: "secp384r1", ClassicalBits: 192, NISTLevel: level(0), Functions: []string{"keygen", "keyderive"}, Standard: "SP 800-56A", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable},
	{Key: "ecdh-p521", Name: "ECDH P-521", Family: "ECDH", Primitive: "key-agree", Curve: "secp521r1", ClassicalBits: 256, NISTLevel: level(0), Functions: []string{"keygen", "keyderive"}, Standard: "SP 800-56A", Class: QuantumVulnerable, Transition: TransitionQuantumVulnerable},
	// Symmetric: AEADs and block ciphers (IR 8547 Table 6).
	{Key: "aes-128-gcm", Name: "AES-128-GCM", Family: "AES", Primitive: "ae", ParameterSet: "128", Mode: "gcm", ClassicalBits: 128, NISTLevel: level(1), Functions: []string{"encrypt", "decrypt"}, OID: "2.16.840.1.101.3.4.1.6", Standard: "FIPS 197, SP 800-38D", Class: Symmetric, Transition: TransitionNotScheduled},
	{Key: "aes-256-gcm", Name: "AES-256-GCM", Family: "AES", Primitive: "ae", ParameterSet: "256", Mode: "gcm", ClassicalBits: 256, NISTLevel: level(5), Functions: []string{"encrypt", "decrypt"}, OID: "2.16.840.1.101.3.4.1.46", Standard: "FIPS 197, SP 800-38D", Class: Symmetric, Transition: TransitionNotScheduled},
	{Key: "aes-128-cbc", Name: "AES-128-CBC", Family: "AES", Primitive: "block-cipher", ParameterSet: "128", Mode: "cbc", ClassicalBits: 128, NISTLevel: level(1), Functions: []string{"encrypt", "decrypt"}, OID: "2.16.840.1.101.3.4.1.2", Standard: "FIPS 197, SP 800-38A", Class: Symmetric, Transition: TransitionNotScheduled},
	{Key: "aes-256-cbc", Name: "AES-256-CBC", Family: "AES", Primitive: "block-cipher", ParameterSet: "256", Mode: "cbc", ClassicalBits: 256, NISTLevel: level(5), Functions: []string{"encrypt", "decrypt"}, OID: "2.16.840.1.101.3.4.1.42", Standard: "FIPS 197, SP 800-38A", Class: Symmetric, Transition: TransitionNotScheduled},
	{Key: "chacha20-poly1305", Name: "ChaCha20-Poly1305", Family: "ChaCha20-Poly1305", Primitive: "ae", ParameterSet: "256", ClassicalBits: 256, Functions: []string{"encrypt", "decrypt"}, Standard: "RFC 8439", Class: Symmetric, Transition: TransitionNotNIST},
	// Hashes, XOFs and KDFs (IR 8547 Table 8, collision category).
	{Key: "sha-256", Name: "SHA-256", Family: "SHA-2", Primitive: "hash", ParameterSet: "256", ClassicalBits: 128, NISTLevel: level(2), Functions: []string{"digest"}, OID: "2.16.840.1.101.3.4.2.1", Standard: "FIPS 180-4", Class: Symmetric, Transition: TransitionNotScheduled},
	{Key: "sha-384", Name: "SHA-384", Family: "SHA-2", Primitive: "hash", ParameterSet: "384", ClassicalBits: 192, NISTLevel: level(4), Functions: []string{"digest"}, OID: "2.16.840.1.101.3.4.2.2", Standard: "FIPS 180-4", Class: Symmetric, Transition: TransitionNotScheduled},
	{Key: "sha-512", Name: "SHA-512", Family: "SHA-2", Primitive: "hash", ParameterSet: "512", ClassicalBits: 256, NISTLevel: level(5), Functions: []string{"digest"}, OID: "2.16.840.1.101.3.4.2.3", Standard: "FIPS 180-4", Class: Symmetric, Transition: TransitionNotScheduled},
	{Key: "sha-1", Name: "SHA-1", Family: "SHA-1", Primitive: "hash", ParameterSet: "160", NISTLevel: level(0), Functions: []string{"digest"}, OID: "1.3.14.3.2.26", Standard: "FIPS 180-4", Class: Symmetric, Transition: "Deprecated; disallowed in FIPS-validated modules after 2030 (NIST IR 8547)"},
	{Key: "shake-256", Name: "SHAKE256", Family: "SHA-3", Primitive: "xof", ParameterSet: "256", ClassicalBits: 256, NISTLevel: level(5), Functions: []string{"digest"}, OID: "2.16.840.1.101.3.4.2.12", Standard: "FIPS 202", Class: Symmetric, Transition: TransitionNotScheduled},
	{Key: "keccak-256", Name: "Keccak-256", Family: "Keccak", Primitive: "hash", ParameterSet: "256", ClassicalBits: 128, Functions: []string{"digest"}, Standard: "Keccak submission padding (as used by Ethereum), not FIPS 202", Class: Symmetric, Transition: TransitionNotNIST},
	{Key: "ripemd-160", Name: "RIPEMD-160", Family: "RIPEMD", Primitive: "hash", ParameterSet: "160", ClassicalBits: 80, Functions: []string{"digest"}, OID: "1.3.36.3.2.1", Standard: "ISO/IEC 10118-3", Class: Symmetric, Transition: TransitionNotNIST},
	{Key: "hkdf-sha256", Name: "HKDF-SHA256", Family: "HKDF", Primitive: "kdf", ParameterSet: "256", Functions: []string{"keyderive"}, Standard: "RFC 5869, SP 800-56C", Class: Symmetric, Transition: TransitionNotScheduled},
	{Key: "hkdf-sha384", Name: "HKDF-SHA384", Family: "HKDF", Primitive: "kdf", ParameterSet: "384", Functions: []string{"keyderive"}, Standard: "RFC 5869, SP 800-56C", Class: Symmetric, Transition: TransitionNotScheduled},
}

var byKey = func() map[string]Algorithm {
	m := make(map[string]Algorithm, len(entries))
	for _, e := range entries {
		if _, dup := m[e.Key]; dup {
			panic("catalog: duplicate key " + e.Key)
		}
		m[e.Key] = e
	}
	return m
}()

// Get returns the catalog entry for key. It panics on an unknown key, which
// is a programming error.
func Get(key string) Algorithm {
	a, ok := byKey[key]
	if !ok {
		panic("catalog: unknown key " + key)
	}
	return clone(a)
}

// Lookup returns the catalog entry for key.
func Lookup(key string) (Algorithm, bool) {
	a, ok := byKey[key]
	if !ok {
		return Algorithm{}, false
	}
	return clone(a), true
}

// Keys returns every catalog key, sorted.
func Keys() []string {
	out := make([]string, 0, len(byKey))
	for k := range byKey {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func clone(a Algorithm) Algorithm {
	a.Functions = append([]string(nil), a.Functions...)
	if a.NISTLevel != nil {
		a.NISTLevel = level(*a.NISTLevel)
	}
	return a
}

// RSA returns the catalog entry for an RSA key of the given modulus size.
// Classical strengths follow SP 800-57 Part 1: 2048 bits gives 112, 3072 up
// to 7679 bits gives 128.
func RSA(bits int) Algorithm {
	switch {
	case bits == 2048:
		return Get("rsa-2048")
	case bits == 3072:
		return Get("rsa-3072")
	case bits == 4096:
		return Get("rsa-4096")
	}
	a := Get("rsa")
	if bits > 0 {
		a.Key = fmt.Sprintf("rsa-%d", bits)
		a.Name = fmt.Sprintf("RSA-%d", bits)
		a.ParameterSet = fmt.Sprint(bits)
		a.Note = ""
		switch {
		case bits >= 7680:
			a.ClassicalBits = 192
		case bits >= 3072:
			a.ClassicalBits = 128
		case bits >= 2048:
			a.ClassicalBits = 112
		default:
			a.ClassicalBits = 80
		}
	}
	return a
}

// OnChainName maps an algorithm name used in the QoreChain pqc module
// registry to a catalog key.
func OnChainName(name string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "dilithium5", "ml-dsa-87", "mldsa87":
		return "ml-dsa-87", true
	case "dilithium3", "ml-dsa-65", "mldsa65":
		return "ml-dsa-65", true
	case "dilithium2", "ml-dsa-44", "mldsa44":
		return "ml-dsa-44", true
	case "mlkem1024", "ml-kem-1024", "kyber1024":
		return "ml-kem-1024", true
	case "mlkem768", "ml-kem-768", "kyber768":
		return "ml-kem-768", true
	case "mlkem512", "ml-kem-512", "kyber512":
		return "ml-kem-512", true
	}
	return "", false
}

// KeyTypeName maps a public key type identifier (an amino name such as
// "<engine>/PubKeyEd25519", a protobuf type URL such as
// "/cosmos.crypto.ed25519.PubKey", or a short name such as "ed25519") to a
// catalog key. Only the last segment of an amino name is used, so the
// engine-specific prefix does not matter.
func KeyTypeName(t string) (string, bool) {
	s := strings.TrimSpace(t)
	if i := strings.LastIndex(s, "/"); i >= 0 && !strings.HasPrefix(s, "/") {
		s = s[i+1:]
	}
	s = strings.ToLower(strings.TrimPrefix(s, "/"))
	switch s {
	case "pubkeyed25519", "privkeyed25519", "ed25519", "cosmos.crypto.ed25519.pubkey", "cosmos.crypto.ed25519.privkey":
		return "ed25519", true
	case "pubkeysecp256k1", "privkeysecp256k1", "secp256k1", "cosmos.crypto.secp256k1.pubkey", "cosmos.crypto.secp256k1.privkey",
		"cosmos.evm.crypto.v1.ethsecp256k1.pubkey", "eth_secp256k1", "ethsecp256k1":
		return "ecdsa-secp256k1", true
	case "pubkeysecp256r1", "secp256r1", "cosmos.crypto.secp256r1.pubkey":
		return "ecdsa-p256", true
	case "pubkeybls12_381", "privkeybls12_381", "bls12_381", "bls12-381", "cosmos.crypto.bls12_381.pubkey":
		return "bls12-381", true
	}
	return "", false
}

// Classify returns a class and IR 8547 transition text for an algorithm name
// found in any CBOM, including CBOMs written by other tools. Catalog names
// match exactly; other names match by family.
func Classify(name, primitive string) (Class, string, string) {
	for _, e := range entries {
		if strings.EqualFold(e.Name, name) || strings.EqualFold(e.Key, name) {
			return e.Class, e.Transition, e.Standard
		}
	}
	n := strings.ToUpper(name)
	has := func(s ...string) bool {
		for _, x := range s {
			if strings.Contains(n, x) {
				return true
			}
		}
		return false
	}
	switch {
	case has("MLKEM", "ML-KEM") && has("X25519", "SECP", "P256", "P384", "ECDH"):
		return Hybrid, TransitionHybrid, "FIPS 203 combined with ECDH"
	case has("ML-KEM", "MLKEM"):
		return PostQuantum, TransitionNotScheduled, "FIPS 203"
	case has("ML-DSA", "MLDSA", "DILITHIUM"):
		return PostQuantum, TransitionNotScheduled, "FIPS 204"
	case has("SLH-DSA", "SPHINCS"):
		return PostQuantum, TransitionNotScheduled, "FIPS 205"
	case has("LMS", "XMSS"):
		return PostQuantum, TransitionNotScheduled, "SP 800-208"
	case has("BLS"):
		return QuantumVulnerable, TransitionOutsideTables, ""
	case has("RSA", "ECDSA", "EDDSA", "ED25519", "ED448", "ECDH", "X25519", "X448", "DIFFIE", "SECP", "DSA"):
		return QuantumVulnerable, TransitionQuantumVulnerable, "FIPS 186-5 / SP 800-56A / SP 800-56B"
	case has("AES", "SHA", "SHAKE", "HMAC", "HKDF", "CHACHA", "POLY1305", "KECCAK", "RIPEMD", "BLAKE", "ASCON"):
		return Symmetric, TransitionNotScheduled, ""
	}
	switch primitive {
	case "hash", "xof", "mac", "kdf", "ae", "block-cipher", "stream-cipher", "drbg":
		return Symmetric, TransitionNotScheduled, ""
	}
	return Unknown, TransitionUnknown, ""
}
