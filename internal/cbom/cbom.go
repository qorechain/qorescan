// SPDX-License-Identifier: Apache-2.0

// Package cbom writes an inventory as a CycloneDX 1.6 JSON BOM whose
// components are cryptographic assets (a CBOM), and reads CBOMs back for
// reports.
package cbom

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/qorechain/qorescan/internal/inventory"
)

// SpecVersion is the CycloneDX version QoreScan writes.
const SpecVersion = "1.6"

// Disclaimer is written into every CBOM and report.
const Disclaimer = "QoreScan output is an inventory aid. It is not a certification, an audit or a legal opinion, and it does not establish conformity with any regulation or standard."

// Options control metadata that is not part of the inventory.
type Options struct {
	ToolVersion string
	// Time is the BOM timestamp; zero means now.
	Time time.Time
}

// BOM is the subset of the CycloneDX 1.6 BOM object QoreScan writes.
type BOM struct {
	Schema       string       `json:"$schema"`
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber,omitempty"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

type Metadata struct {
	Timestamp  string     `json:"timestamp"`
	Tools      Tools      `json:"tools"`
	Component  *Component `json:"component,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type Tools struct {
	Components []Component `json:"components"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ExternalReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type OrganizationalEntity struct {
	Name string `json:"name"`
}

type Component struct {
	Type               string                `json:"type"`
	BOMRef             string                `json:"bom-ref,omitempty"`
	Supplier           *OrganizationalEntity `json:"supplier,omitempty"`
	Group              string                `json:"group,omitempty"`
	Name               string                `json:"name"`
	Version            string                `json:"version,omitempty"`
	Description        string                `json:"description,omitempty"`
	Purl               string                `json:"purl,omitempty"`
	ExternalReferences []ExternalReference   `json:"externalReferences,omitempty"`
	Evidence           *Evidence             `json:"evidence,omitempty"`
	CryptoProperties   *CryptoProperties     `json:"cryptoProperties,omitempty"`
	Properties         []Property            `json:"properties,omitempty"`
}

type Evidence struct {
	Occurrences []Occurrence `json:"occurrences,omitempty"`
}

type Occurrence struct {
	Location          string `json:"location"`
	Line              *int   `json:"line,omitempty"`
	Symbol            string `json:"symbol,omitempty"`
	AdditionalContext string `json:"additionalContext,omitempty"`
}

type CryptoProperties struct {
	AssetType                       string                           `json:"assetType"`
	AlgorithmProperties             *AlgorithmProperties             `json:"algorithmProperties,omitempty"`
	CertificateProperties           *CertificateProperties           `json:"certificateProperties,omitempty"`
	RelatedCryptoMaterialProperties *RelatedCryptoMaterialProperties `json:"relatedCryptoMaterialProperties,omitempty"`
	ProtocolProperties              *ProtocolProperties              `json:"protocolProperties,omitempty"`
	OID                             string                           `json:"oid,omitempty"`
}

type AlgorithmProperties struct {
	Primitive                string   `json:"primitive,omitempty"`
	ParameterSetIdentifier   string   `json:"parameterSetIdentifier,omitempty"`
	Curve                    string   `json:"curve,omitempty"`
	Mode                     string   `json:"mode,omitempty"`
	CryptoFunctions          []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel   *int     `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel *int     `json:"nistQuantumSecurityLevel,omitempty"`
}

type CertificateProperties struct {
	SubjectName           string `json:"subjectName,omitempty"`
	IssuerName            string `json:"issuerName,omitempty"`
	NotValidBefore        string `json:"notValidBefore,omitempty"`
	NotValidAfter         string `json:"notValidAfter,omitempty"`
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
	SubjectPublicKeyRef   string `json:"subjectPublicKeyRef,omitempty"`
	CertificateFormat     string `json:"certificateFormat,omitempty"`
}

type RelatedCryptoMaterialProperties struct {
	Type         string `json:"type,omitempty"`
	ID           string `json:"id,omitempty"`
	AlgorithmRef string `json:"algorithmRef,omitempty"`
	Size         *int   `json:"size,omitempty"`
	Format       string `json:"format,omitempty"`
}

type ProtocolProperties struct {
	Type           string        `json:"type,omitempty"`
	Version        string        `json:"version,omitempty"`
	CipherSuites   []CipherSuite `json:"cipherSuites,omitempty"`
	CryptoRefArray []string      `json:"cryptoRefArray,omitempty"`
}

type CipherSuite struct {
	Name        string   `json:"name,omitempty"`
	Algorithms  []string `json:"algorithms,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
}

type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
	Provides  []string `json:"provides,omitempty"`
}

// TargetRef is the bom-ref of the metadata component that stands for the
// scanned deployment.
const TargetRef = "target"

// Build converts an inventory into a BOM.
func Build(inv *inventory.Inventory, opt Options) *BOM {
	ts := opt.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	version := opt.ToolVersion
	if version == "" {
		version = "dev"
	}
	b := &BOM{
		Schema:      "http://cyclonedx.org/schema/bom-1.6.schema.json",
		BOMFormat:   "CycloneDX",
		SpecVersion: SpecVersion,
		Version:     1,
		Metadata: Metadata{
			Timestamp: ts.UTC().Format(time.RFC3339),
			Tools: Tools{Components: []Component{{
				Type:     "application",
				Supplier: &OrganizationalEntity{Name: "QoreChain Association"},
				Name:     "qorescan",
				Version:  version,
				ExternalReferences: []ExternalReference{
					{Type: "vcs", URL: "https://github.com/qorechain/qorescan"},
				},
			}}},
			Component: &Component{
				Type:   "platform",
				BOMRef: TargetRef,
				Name:   orDefault(inv.Target, "QoreChain deployment"),
			},
		},
		Components: []Component{},
	}
	props := []Property{{Name: "qorescan:disclaimer", Value: Disclaimer}}
	for _, f := range inv.Facts {
		props = append(props, Property(f))
	}
	for _, n := range inv.Notes {
		v := fmt.Sprintf("[%s] %s: %s", n.Level, n.Source, n.Text)
		if n.Location != "" {
			v += " (" + n.Location + ")"
		}
		props = append(props, Property{Name: "qorescan:note", Value: v})
	}
	b.Metadata.Properties = props

	var targetDeps []string
	for _, a := range inv.Assets() {
		b.Components = append(b.Components, component(a))
		targetDeps = append(targetDeps, a.Ref)
		if deps := assetDependencies(a); len(deps) > 0 {
			b.Dependencies = append(b.Dependencies, Dependency{Ref: a.Ref, DependsOn: deps})
		}
	}
	for _, l := range inv.Libraries() {
		c := Component{Type: "library", BOMRef: l.Ref, Group: l.Group, Name: l.Name, Purl: l.Purl, Evidence: evidence(l.Occurrences)}
		b.Components = append(b.Components, c)
		targetDeps = append(targetDeps, l.Ref)
		if len(l.Provides) > 0 {
			b.Dependencies = append(b.Dependencies, Dependency{Ref: l.Ref, Provides: l.Provides})
		}
	}
	if len(targetDeps) > 0 {
		b.Dependencies = append([]Dependency{{Ref: TargetRef, DependsOn: targetDeps}}, b.Dependencies...)
	}
	return b
}

// Encode writes the BOM as indented JSON. The serial number is derived from
// the content, so the same inventory at the same time encodes identically.
func Encode(inv *inventory.Inventory, opt Options) ([]byte, error) {
	b := Build(inv, opt)
	body, err := marshal(b)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	sum[6] = (sum[6] & 0x0f) | 0x50 // version 5 style, name-based
	sum[8] = (sum[8] & 0x3f) | 0x80 // RFC 4122 variant
	b.SerialNumber = fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
	return marshal(b)
}

func marshal(b *BOM) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func component(a *inventory.Asset) Component {
	c := Component{Type: "cryptographic-asset", BOMRef: a.Ref, Name: a.Name, Evidence: evidence(a.Occurrences)}
	cp := &CryptoProperties{AssetType: string(a.Kind)}
	var props []Property
	switch a.Kind {
	case inventory.KindAlgorithm:
		alg := a.Algorithm
		ap := &AlgorithmProperties{
			Primitive:              alg.Primitive,
			ParameterSetIdentifier: alg.ParameterSet,
			Curve:                  alg.Curve,
			Mode:                   alg.Mode,
			CryptoFunctions:        alg.Functions,
		}
		if alg.ClassicalBits > 0 {
			v := alg.ClassicalBits
			ap.ClassicalSecurityLevel = &v
		}
		if alg.NISTLevel != nil {
			v := *alg.NISTLevel
			ap.NISTQuantumSecurityLevel = &v
		}
		cp.AlgorithmProperties = ap
		cp.OID = alg.OID
		props = append(props,
			Property{Name: "qorescan:classification", Value: string(alg.Class)},
			Property{Name: "qorescan:transition", Value: alg.Transition},
		)
		if alg.Standard != "" {
			props = append(props, Property{Name: "qorescan:standard", Value: alg.Standard})
		}
		if alg.Family != "" {
			props = append(props, Property{Name: "qorescan:family", Value: alg.Family})
		}
		if alg.Note != "" {
			props = append(props, Property{Name: "qorescan:algorithm-note", Value: alg.Note})
		}
	case inventory.KindCertificate:
		ct := a.Certificate
		cp.CertificateProperties = &CertificateProperties{
			SubjectName:           ct.Subject,
			IssuerName:            ct.Issuer,
			NotValidBefore:        ct.NotBefore,
			NotValidAfter:         ct.NotAfter,
			SignatureAlgorithmRef: ct.SignatureAlgorithmRef,
			SubjectPublicKeyRef:   ct.SubjectPublicKeyRef,
			CertificateFormat:     orDefault(ct.Format, "X.509"),
		}
		if ct.FingerprintSHA256 != "" {
			props = append(props, Property{Name: "qorescan:certificate:sha256", Value: ct.FingerprintSHA256})
		}
		if ct.ChainVerificationAttempted {
			v := "verified against the system roots"
			if !ct.ChainVerified {
				v = "not verified: " + ct.ChainError
			}
			props = append(props, Property{Name: "qorescan:certificate:chain", Value: v})
		}
	case inventory.KindProtocol:
		p := a.Protocol
		pp := &ProtocolProperties{Type: p.Type, Version: p.Version, CryptoRefArray: p.Refs}
		for _, cs := range p.CipherSuites {
			s := CipherSuite{Name: cs.Name, Algorithms: cs.Algorithms}
			if cs.Identifier != "" {
				s.Identifiers = []string{cs.Identifier}
			}
			pp.CipherSuites = append(pp.CipherSuites, s)
		}
		cp.ProtocolProperties = pp
	case inventory.KindMaterial:
		m := a.Material
		rp := &RelatedCryptoMaterialProperties{Type: m.Type, ID: m.ID, AlgorithmRef: m.AlgorithmRef, Format: m.Format}
		if m.SizeBits > 0 {
			v := m.SizeBits
			rp.Size = &v
		}
		cp.RelatedCryptoMaterialProperties = rp
	}
	c.CryptoProperties = cp
	for _, s := range a.Sources {
		props = append(props, Property{Name: "qorescan:source", Value: s})
	}
	for _, p := range a.Properties {
		props = append(props, Property(p))
	}
	c.Properties = props
	return c
}

func assetDependencies(a *inventory.Asset) []string {
	var out []string
	add := func(r string) {
		if r == "" || r == a.Ref {
			return
		}
		for _, x := range out {
			if x == r {
				return
			}
		}
		out = append(out, r)
	}
	switch a.Kind {
	case inventory.KindCertificate:
		add(a.Certificate.SignatureAlgorithmRef)
		add(a.Certificate.SubjectPublicKeyRef)
	case inventory.KindProtocol:
		for _, r := range a.Protocol.Refs {
			add(r)
		}
	case inventory.KindMaterial:
		add(a.Material.AlgorithmRef)
	}
	return out
}

func evidence(occ []inventory.Occurrence) *Evidence {
	if len(occ) == 0 {
		return nil
	}
	e := &Evidence{}
	for _, o := range occ {
		x := Occurrence{Location: o.Location, Symbol: o.Symbol, AdditionalContext: o.Context}
		if o.Line > 0 {
			l := o.Line
			x.Line = &l
		}
		e.Occurrences = append(e.Occurrences, x)
	}
	return e
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// Decode parses a CycloneDX JSON document into a BOM. Unknown fields are
// ignored, so CBOMs from other tools can be read.
func Decode(data []byte) (*BOM, error) {
	var b BOM
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("cbom: not a CycloneDX JSON document: %w", err)
	}
	if b.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("cbom: bomFormat is %q, want CycloneDX", b.BOMFormat)
	}
	major, minor, ok := parseSpec(b.SpecVersion)
	if !ok || major != 1 || minor < 6 {
		return nil, fmt.Errorf("cbom: specVersion %q has no cryptographic assets (need 1.6 or later)", b.SpecVersion)
	}
	return &b, nil
}

func parseSpec(v string) (int, int, bool) {
	var maj, min string
	for i := 0; i < len(v); i++ {
		if v[i] == '.' {
			maj, min = v[:i], v[i+1:]
			break
		}
	}
	a, err1 := strconv.Atoi(maj)
	b, err2 := strconv.Atoi(min)
	return a, b, err1 == nil && err2 == nil
}

// Property returns the first value of a component property.
func (c *Component) Property(name string) string {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// PropertyValues returns every value of a metadata property.
func (m *Metadata) PropertyValues(name string) []string {
	var out []string
	for _, p := range m.Properties {
		if p.Name == name {
			out = append(out, p.Value)
		}
	}
	return out
}
