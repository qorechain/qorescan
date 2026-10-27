// SPDX-License-Identifier: Apache-2.0

// Package inventory holds what the scanners found, independent of the output
// format. The cbom package turns an Inventory into CycloneDX 1.6.
package inventory

import (
	"fmt"
	"sort"
	"strings"

	"github.com/qorechain/qorescan/internal/catalog"
)

// Source names the scanner that produced an entry.
const (
	SourceNodeHome = "node-home"
	SourceChain    = "chain"
	SourceTLS      = "tls"
	SourceSolidity = "solidity"
)

// Occurrence is one piece of evidence: a file and line, or an endpoint.
type Occurrence struct {
	// Location is a path relative to the scanned root, or a URL / host:port.
	Location string
	// Line is 1-based; 0 means not applicable.
	Line int
	// Symbol is the configuration key, JSON path or source symbol.
	Symbol string
	// Context is a short human-readable explanation.
	Context string
}

// Property is a name/value pair written as a CycloneDX property.
type Property struct {
	Name  string
	Value string
}

// Kind is the CycloneDX cryptoProperties.assetType.
type Kind string

const (
	KindAlgorithm   Kind = "algorithm"
	KindCertificate Kind = "certificate"
	KindProtocol    Kind = "protocol"
	KindMaterial    Kind = "related-crypto-material"
)

// Certificate describes an X.509 certificate. Only public data is kept.
type Certificate struct {
	Subject, Issuer            string
	NotBefore, NotAfter        string // RFC 3339
	SignatureAlgorithmRef      string
	SubjectPublicKeyRef        string
	Format                     string
	FingerprintSHA256          string
	ChainVerified              bool
	ChainVerificationAttempted bool
	ChainError                 string
}

// CipherSuite is a negotiated TLS cipher suite.
type CipherSuite struct {
	Name       string
	Identifier string
	Algorithms []string // asset refs
}

// Protocol describes a protocol instance (TLS endpoint, P2P transport).
type Protocol struct {
	Type         string // CycloneDX protocolProperties.type: tls, other
	Version      string
	CipherSuites []CipherSuite
	Refs         []string // all algorithm refs the protocol uses
}

// Material describes key material. QoreScan only records public keys and,
// for files that hold private keys, the key type: never private key bytes.
type Material struct {
	Type         string // CycloneDX type: public-key, private-key, ...
	ID           string
	AlgorithmRef string
	SizeBits     int
	Format       string
}

// Asset is one CycloneDX cryptographic-asset component.
type Asset struct {
	Ref         string
	Name        string
	Kind        Kind
	Algorithm   *catalog.Algorithm
	Certificate *Certificate
	Protocol    *Protocol
	Material    *Material
	Sources     []string
	Occurrences []Occurrence
	Properties  []Property
}

// Library is a software component (for example a Solidity library) that
// provides algorithms.
type Library struct {
	Ref         string
	Name        string
	Group       string
	Purl        string
	Occurrences []Occurrence
	Provides    []string
}

// Note is a finding that is not itself a cryptographic asset (a listener
// without TLS, a route the node does not serve, a key file that is absent).
type Note struct {
	Source   string
	Level    string // info, warning
	Text     string
	Location string
}

// Inventory is the merged result of every scanner.
type Inventory struct {
	// Target is a short description of what was scanned.
	Target    string
	assets    map[string]*Asset
	order     []string
	libraries map[string]*Library
	libOrder  []string
	Notes     []Note
	Facts     []Property
}

// New returns an empty inventory.
func New(target string) *Inventory {
	return &Inventory{Target: target, assets: map[string]*Asset{}, libraries: map[string]*Library{}}
}

// AlgorithmRef is the bom-ref of an algorithm asset.
func AlgorithmRef(key string) string { return "crypto/algorithm/" + key }

// AddAlgorithm records an algorithm with one occurrence and returns its ref.
// Repeated calls merge occurrences.
func (inv *Inventory) AddAlgorithm(alg catalog.Algorithm, source string, occ ...Occurrence) string {
	ref := AlgorithmRef(alg.Key)
	a, ok := inv.assets[ref]
	if !ok {
		alg := alg
		a = &Asset{Ref: ref, Name: alg.Name, Kind: KindAlgorithm, Algorithm: &alg}
		inv.put(a)
	}
	a.addSource(source)
	for _, o := range occ {
		a.addOccurrence(o)
	}
	return ref
}

// AddAsset records a non-algorithm asset. An asset with the same ref merges
// sources, occurrences and properties.
func (inv *Inventory) AddAsset(asset Asset) string {
	if asset.Ref == "" {
		panic("inventory: asset without ref")
	}
	a, ok := inv.assets[asset.Ref]
	if !ok {
		cp := asset
		cp.Sources = nil
		cp.Occurrences = nil
		cp.Properties = nil
		a = &cp
		inv.put(a)
	}
	for _, s := range asset.Sources {
		a.addSource(s)
	}
	for _, o := range asset.Occurrences {
		a.addOccurrence(o)
	}
	for _, p := range asset.Properties {
		a.AddProperty(p.Name, p.Value)
	}
	return a.Ref
}

// Asset returns the asset with ref, if present.
func (inv *Inventory) Asset(ref string) (*Asset, bool) {
	a, ok := inv.assets[ref]
	return a, ok
}

// AddLibrary records a library and what it provides.
func (inv *Inventory) AddLibrary(lib Library) {
	l, ok := inv.libraries[lib.Ref]
	if !ok {
		cp := lib
		cp.Occurrences = nil
		cp.Provides = nil
		l = &cp
		inv.libraries[lib.Ref] = l
		inv.libOrder = append(inv.libOrder, lib.Ref)
	}
	for _, o := range lib.Occurrences {
		if !containsOcc(l.Occurrences, o) {
			l.Occurrences = append(l.Occurrences, o)
		}
	}
	for _, p := range lib.Provides {
		if !contains(l.Provides, p) {
			l.Provides = append(l.Provides, p)
		}
	}
}

// AddNote records a note.
func (inv *Inventory) AddNote(source, level, location, format string, args ...any) {
	inv.Notes = append(inv.Notes, Note{Source: source, Level: level, Location: location, Text: fmt.Sprintf(format, args...)})
}

// AddFact records a metadata property.
func (inv *Inventory) AddFact(name, value string) {
	for _, f := range inv.Facts {
		if f.Name == name && f.Value == value {
			return
		}
	}
	inv.Facts = append(inv.Facts, Property{Name: name, Value: value})
}

// Assets returns the assets sorted by kind then ref, with occurrences sorted.
func (inv *Inventory) Assets() []*Asset {
	out := make([]*Asset, 0, len(inv.order))
	for _, r := range inv.order {
		a := inv.assets[r]
		sortOccurrences(a.Occurrences)
		sort.Strings(a.Sources)
		out = append(out, a)
	}
	rank := map[Kind]int{KindAlgorithm: 0, KindProtocol: 1, KindCertificate: 2, KindMaterial: 3}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Kind] != rank[out[j].Kind] {
			return rank[out[i].Kind] < rank[out[j].Kind]
		}
		return out[i].Ref < out[j].Ref
	})
	return out
}

// Libraries returns the libraries sorted by ref.
func (inv *Inventory) Libraries() []*Library {
	out := make([]*Library, 0, len(inv.libOrder))
	for _, r := range inv.libOrder {
		l := inv.libraries[r]
		sortOccurrences(l.Occurrences)
		sort.Strings(l.Provides)
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// Empty reports whether nothing was recorded.
func (inv *Inventory) Empty() bool { return len(inv.assets) == 0 && len(inv.libraries) == 0 }

func (inv *Inventory) put(a *Asset) {
	inv.assets[a.Ref] = a
	inv.order = append(inv.order, a.Ref)
}

// AddProperty adds a property unless the same name/value pair exists.
func (a *Asset) AddProperty(name, value string) {
	for _, p := range a.Properties {
		if p.Name == name && p.Value == value {
			return
		}
	}
	a.Properties = append(a.Properties, Property{Name: name, Value: value})
}

func (a *Asset) addSource(s string) {
	if s != "" && !contains(a.Sources, s) {
		a.Sources = append(a.Sources, s)
	}
}

func (a *Asset) addOccurrence(o Occurrence) {
	if o.Location == "" {
		return
	}
	if !containsOcc(a.Occurrences, o) {
		a.Occurrences = append(a.Occurrences, o)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func containsOcc(list []Occurrence, o Occurrence) bool {
	for _, x := range list {
		if x == o {
			return true
		}
	}
	return false
}

func sortOccurrences(o []Occurrence) {
	sort.SliceStable(o, func(i, j int) bool {
		if o[i].Location != o[j].Location {
			return o[i].Location < o[j].Location
		}
		if o[i].Line != o[j].Line {
			return o[i].Line < o[j].Line
		}
		return o[i].Symbol < o[j].Symbol
	})
}

// Slug turns s into a bom-ref friendly token.
func Slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r == ':':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
