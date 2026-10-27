// SPDX-License-Identifier: Apache-2.0

// Package schemacheck validates documents against the official CycloneDX 1.6
// JSON schema. It is used by tests only, so the validator is not linked into
// the qorescan binary.
//
// The schema files in schema/ are copied unmodified from
// https://github.com/CycloneDX/specification (tag 1.6.1, directory schema/),
// published under the Apache License 2.0.
package schemacheck

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schema/*.json
var files embed.FS

const bomID = "http://cyclonedx.org/schema/bom-1.6.schema.json"

var (
	once     sync.Once
	compiled *jsonschema.Schema
	compErr  error
)

func load() (*jsonschema.Schema, error) {
	once.Do(func() {
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		for _, f := range []string{"bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"} {
			data, err := files.ReadFile("schema/" + f)
			if err != nil {
				compErr = err
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
			if err != nil {
				compErr = fmt.Errorf("%s: %w", f, err)
				return
			}
			if err := c.AddResource("http://cyclonedx.org/schema/"+f, doc); err != nil {
				compErr = err
				return
			}
		}
		compiled, compErr = c.Compile(bomID)
	})
	return compiled, compErr
}

// Validate checks data against the CycloneDX 1.6 schema.
func Validate(data []byte) error {
	s, err := load()
	if err != nil {
		return fmt.Errorf("loading CycloneDX schema: %w", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return s.Validate(inst)
}

// Refs checks that every bom-ref the document uses is defined once, by a
// component or by the metadata component.
func Refs(data []byte) error {
	var doc struct {
		Metadata struct {
			Component *struct {
				BOMRef string `json:"bom-ref"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			BOMRef           string `json:"bom-ref"`
			CryptoProperties *struct {
				CertificateProperties *struct {
					SignatureAlgorithmRef string `json:"signatureAlgorithmRef"`
					SubjectPublicKeyRef   string `json:"subjectPublicKeyRef"`
				} `json:"certificateProperties"`
				RelatedCryptoMaterialProperties *struct {
					AlgorithmRef string `json:"algorithmRef"`
				} `json:"relatedCryptoMaterialProperties"`
				ProtocolProperties *struct {
					CryptoRefArray []string `json:"cryptoRefArray"`
					CipherSuites   []struct {
						Algorithms []string `json:"algorithms"`
					} `json:"cipherSuites"`
				} `json:"protocolProperties"`
			} `json:"cryptoProperties"`
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
			Provides  []string `json:"provides"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	defined := map[string]bool{}
	if c := doc.Metadata.Component; c != nil && c.BOMRef != "" {
		defined[c.BOMRef] = true
	}
	var errs []string
	for _, c := range doc.Components {
		if c.BOMRef == "" {
			continue
		}
		if defined[c.BOMRef] {
			errs = append(errs, "duplicate bom-ref "+c.BOMRef)
		}
		defined[c.BOMRef] = true
	}
	use := func(r string) {
		if r != "" && !defined[r] {
			errs = append(errs, "dangling reference "+r)
		}
	}
	for _, c := range doc.Components {
		cp := c.CryptoProperties
		if cp == nil {
			continue
		}
		if p := cp.CertificateProperties; p != nil {
			use(p.SignatureAlgorithmRef)
			use(p.SubjectPublicKeyRef)
		}
		if p := cp.RelatedCryptoMaterialProperties; p != nil {
			use(p.AlgorithmRef)
		}
		if p := cp.ProtocolProperties; p != nil {
			for _, r := range p.CryptoRefArray {
				use(r)
			}
			for _, s := range p.CipherSuites {
				for _, r := range s.Algorithms {
					use(r)
				}
			}
		}
	}
	for _, d := range doc.Dependencies {
		use(d.Ref)
		for _, r := range d.DependsOn {
			use(r)
		}
		for _, r := range d.Provides {
			use(r)
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
