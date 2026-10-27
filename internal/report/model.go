// SPDX-License-Identifier: Apache-2.0

// Package report turns a CBOM into Markdown: a framework mapping report and
// two templates (a crypto-agility statement and a vendor questionnaire). It
// works on QoreScan CBOMs and, with less detail, on CycloneDX 1.6 CBOMs from
// other tools.
package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/qorechain/qorescan/internal/catalog"
	"github.com/qorechain/qorescan/internal/cbom"
)

// ToBeCompleted marks anything the scan cannot know.
const ToBeCompleted = "_To be completed._"

type algRow struct {
	Ref, Name, Primitive, ParamSet string
	Level                          *int
	Class                          catalog.Class
	Transition, Standard           string
	Evidence                       []cbom.Occurrence
	Props                          map[string][]string
}

type view struct {
	bom        *cbom.BOM
	algs       []algRow
	byRef      map[string]*cbom.Component
	protocols  []cbom.Component
	certs      []cbom.Component
	materials  []cbom.Component
	libraries  []cbom.Component
	facts      map[string][]string
	notes      []string
	sources    []string
	foreignBOM bool
}

func newView(b *cbom.BOM) *view {
	v := &view{bom: b, byRef: map[string]*cbom.Component{}, facts: map[string][]string{}}
	srcSet := map[string]bool{}
	for i := range b.Components {
		c := &b.Components[i]
		if c.BOMRef != "" {
			v.byRef[c.BOMRef] = c
		}
		for _, p := range c.Properties {
			if p.Name == "qorescan:source" {
				srcSet[p.Value] = true
			}
		}
		if c.Type == "library" {
			v.libraries = append(v.libraries, *c)
			continue
		}
		if c.Type != "cryptographic-asset" || c.CryptoProperties == nil {
			continue
		}
		switch c.CryptoProperties.AssetType {
		case "algorithm":
			v.algs = append(v.algs, toRow(c))
		case "protocol":
			v.protocols = append(v.protocols, *c)
		case "certificate":
			v.certs = append(v.certs, *c)
		case "related-crypto-material":
			v.materials = append(v.materials, *c)
		}
	}
	for s := range srcSet {
		v.sources = append(v.sources, s)
	}
	sort.Strings(v.sources)
	for _, p := range b.Metadata.Properties {
		if p.Name == "qorescan:note" {
			v.notes = append(v.notes, p.Value)
			continue
		}
		v.facts[p.Name] = append(v.facts[p.Name], p.Value)
	}
	v.foreignBOM = len(b.Metadata.Tools.Components) == 0 || b.Metadata.Tools.Components[0].Name != "qorescan"
	rank := map[catalog.Class]int{catalog.QuantumVulnerable: 0, catalog.Unknown: 1, catalog.Hybrid: 2, catalog.PostQuantum: 3, catalog.Symmetric: 4}
	sort.SliceStable(v.algs, func(i, j int) bool {
		if rank[v.algs[i].Class] != rank[v.algs[j].Class] {
			return rank[v.algs[i].Class] < rank[v.algs[j].Class]
		}
		return v.algs[i].Name < v.algs[j].Name
	})
	return v
}

func toRow(c *cbom.Component) algRow {
	r := algRow{Ref: c.BOMRef, Name: c.Name, Props: map[string][]string{}}
	if ap := c.CryptoProperties.AlgorithmProperties; ap != nil {
		r.Primitive, r.ParamSet, r.Level = ap.Primitive, ap.ParameterSetIdentifier, ap.NISTQuantumSecurityLevel
	}
	for _, p := range c.Properties {
		r.Props[p.Name] = append(r.Props[p.Name], p.Value)
	}
	class, transition, std := catalog.Classify(c.Name, r.Primitive)
	if v := c.Property("qorescan:classification"); v != "" {
		class = catalog.Class(v)
	}
	if v := c.Property("qorescan:transition"); v != "" {
		transition = v
	}
	if v := c.Property("qorescan:standard"); v != "" {
		std = v
	}
	r.Class, r.Transition, r.Standard = class, transition, std
	if c.Evidence != nil {
		r.Evidence = c.Evidence.Occurrences
	}
	return r
}

func (v *view) fact(name string) string {
	if x := v.facts[name]; len(x) > 0 {
		return x[0]
	}
	return ""
}

func (v *view) count(class catalog.Class) int {
	n := 0
	for _, a := range v.algs {
		if a.Class == class {
			n++
		}
	}
	return n
}

func (v *view) names(class catalog.Class) []string {
	var out []string
	for _, a := range v.algs {
		if a.Class == class {
			out = append(out, a.Name)
		}
	}
	return out
}

// fipsStatus states the algorithm against FIPS 203/204/205.
func fipsStatus(a algRow) string {
	switch a.Class {
	case catalog.PostQuantum:
		for _, f := range []string{"FIPS 203", "FIPS 204", "FIPS 205"} {
			if strings.Contains(a.Standard, f) {
				return f
			}
		}
		return "post-quantum, outside FIPS 203/204/205"
	case catalog.Hybrid:
		return "hybrid; PQ part per FIPS 203"
	case catalog.QuantumVulnerable:
		return "not covered (quantum-vulnerable)"
	case catalog.Symmetric:
		return "not applicable (symmetric or hash)"
	}
	return "unknown"
}

func levelText(l *int) string {
	if l == nil {
		return "not defined"
	}
	return fmt.Sprint(*l)
}

func evidenceText(occ []cbom.Occurrence) string {
	if len(occ) == 0 {
		return "none recorded"
	}
	first := occ[0].Location
	if occ[0].Line != nil {
		first += fmt.Sprintf(":%d", *occ[0].Line)
	}
	first = "`" + first + "`"
	if len(occ) > 1 {
		first += fmt.Sprintf(" (+%d more)", len(occ)-1)
	}
	return first
}

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	if s == "" {
		return "-"
	}
	return s
}

func (v *view) refName(ref string) string {
	if c, ok := v.byRef[ref]; ok {
		return c.Name
	}
	return ref
}
