// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/qorechain/qorescan/internal/catalog"
	"github.com/qorechain/qorescan/internal/cbom"
)

// Templates QoreScan can fill.
var Templates = []string{"agility", "questionnaire"}

// Template renders a template ("agility" or "questionnaire") pre-filled
// only from facts in the CBOM. Everything else reads "To be completed".
func Template(b *cbom.BOM, name string) (string, error) {
	v := newView(b)
	var w strings.Builder
	switch name {
	case "agility":
		agility(&w, v)
	case "questionnaire":
		questionnaire(&w, v)
	default:
		return "", fmt.Errorf("unknown template %q (want one of %s)", name, strings.Join(Templates, ", "))
	}
	return w.String(), nil
}

func scopeLine(v *view) string {
	var parts []string
	for _, s := range v.sources {
		switch s {
		case "node-home":
			parts = append(parts, "node configuration, genesis and key files (types and public keys only)")
		case "chain":
			parts = append(parts, "live network state via REST ("+orDash(v.fact("qorescan:chain:rest"))+")")
		case "tls":
			parts = append(parts, "TLS endpoints")
		case "solidity":
			parts = append(parts, "Solidity sources")
		default:
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return "No QoreScan source recorded."
	}
	return strings.Join(parts, "; ") + "."
}

func algorithmsUse(w *strings.Builder, v *view) {
	if len(v.algs) == 0 {
		w.WriteString(ToBeCompleted + "\n\n")
		return
	}
	w.WriteString("| Algorithm | Classification | Where it was found |\n|---|---|---|\n")
	for _, a := range v.algs {
		var ctxs []string
		for _, o := range a.Evidence {
			c := o.AdditionalContext
			if c == "" {
				c = o.Location
			}
			if !contains(ctxs, c) {
				ctxs = append(ctxs, c)
			}
			if len(ctxs) == 2 {
				break
			}
		}
		ctx := strings.Join(ctxs, "; ")
		if len(a.Evidence) > len(ctxs) {
			ctx += fmt.Sprintf(" (%d occurrences in the CBOM)", len(a.Evidence))
		}
		fmt.Fprintf(w, "| %s | %s | %s |\n", cell(a.Name), a.Class, cell(ctx))
	}
	w.WriteString("\n")
}

func agility(w *strings.Builder, v *view) {
	w.WriteString("# Crypto-agility statement (draft)\n\n")
	disclaimer(w, templateDisclaimer)
	fmt.Fprintf(w, "Prepared from CBOM `%s` (%s). Statements are limited to what the scan recorded; everything else is marked to be completed.\n\n", orDash(v.bom.SerialNumber), orDash(v.bom.Metadata.Timestamp))

	w.WriteString("## 1. Scope\n\n")
	if id := firstNonEmpty(v.fact("qorescan:chain:id"), v.fact("qorescan:genesis:chain-id")); id != "" {
		fmt.Fprintf(w, "Network: `%s`.\n\n", id)
	}
	fmt.Fprintf(w, "Scanned: %s\n\nSystems outside this scan: %s\n\n", scopeLine(v), ToBeCompleted)

	w.WriteString("## 2. Algorithms in use\n\n")
	algorithmsUse(w, v)

	w.WriteString("## 3. Ability to replace algorithms\n\n")
	var items []string
	if r := v.facts["qorescan:genesis:pqc:registry"]; len(r) > 0 {
		items = append(items, "The pqc module keeps an on-chain algorithm registry; at genesis it lists: "+strings.Join(r, "; ")+". Each entry carries a lifecycle status (active, migrating, deprecated, disabled).")
	}
	if m := firstNonEmpty(v.fact("qorescan:chain:pqc:hybrid-signature-mode"), v.fact("qorescan:genesis:pqc:hybrid-signature-mode")); m != "" {
		items = append(items, "Native-lane transactions: hybrid signature mode `"+m+"` (classical secp256k1 signature plus the registry's default post-quantum signature).")
	}
	for _, a := range v.algs {
		if len(a.Props["qorescan:pqc:default-signature-algorithm"]) > 0 {
			items = append(items, "Default post-quantum signature algorithm for new keys: "+a.Name+".")
			break
		}
	}
	if b := firstNonEmpty(v.fact("qorescan:chain:pqc:default-migration-blocks"), v.fact("qorescan:genesis:pqc:default-migration-blocks")); b != "" {
		items = append(items, "An algorithm migration runs with a dual-signature period of "+b+" blocks (module parameter `default_migration_blocks`).")
	}
	feats := append(append([]string{}, v.facts["qorescan:chain:protocol-feature"]...), v.facts["qorescan:genesis:protocol-feature"]...)
	if len(feats) > 0 {
		sort.Strings(feats)
		items = append(items, "PQC-related protocol switches recorded as enabled: "+strings.Join(dedupe(feats), ", ")+".")
	}
	for _, p := range v.protocols {
		if p.Property("qorescan:protocol:configurable") == "no" {
			items = append(items, p.Name+": algorithms are fixed by the protocol and cannot be changed by configuration.")
		}
	}
	if n := countSolidity(v); n > 0 {
		items = append(items, fmt.Sprintf("Solidity sources have %d signature-related occurrences; replacing their algorithms requires a contract change and redeployment.", n))
	}
	if len(items) == 0 {
		w.WriteString(ToBeCompleted + "\n\n")
	} else {
		for _, it := range items {
			fmt.Fprintf(w, "- %s\n", it)
		}
		w.WriteString("\n")
	}
	w.WriteString("Procedure, approvals and testing for an algorithm change: " + ToBeCompleted + "\n\n")

	w.WriteString("## 4. Transition plan\n\n")
	if q := v.names(catalog.QuantumVulnerable); len(q) > 0 {
		fmt.Fprintf(w, "Quantum-vulnerable algorithms in scope: %s. NIST IR 8547 deprecates these families after 2030 and disallows them after 2035.\n\n", strings.Join(q, ", "))
	} else {
		w.WriteString("No quantum-vulnerable algorithm was recorded in the scanned scope.\n\n")
	}
	w.WriteString("Target dates per system and use case: " + ToBeCompleted + "\n\n")

	w.WriteString("## 5. Responsibilities and review\n\n")
	w.WriteString("Owner: " + ToBeCompleted + "\n\nReview cycle: " + ToBeCompleted + "\n")
}

func countSolidity(v *view) int {
	n := 0
	for _, a := range v.algs {
		if a.Class != catalog.QuantumVulnerable && a.Class != catalog.PostQuantum {
			continue
		}
		for _, src := range a.Props["qorescan:source"] {
			if src == "solidity" {
				for _, o := range a.Evidence {
					if o.Line != nil && strings.HasSuffix(o.Location, ".sol") {
						n++
					}
				}
			}
		}
	}
	return n
}

func questionnaire(w *strings.Builder, v *view) {
	w.WriteString("# Vendor questionnaire: post-quantum readiness (5 questions)\n\n")
	disclaimer(w, templateDisclaimer)
	fmt.Fprintf(w, "The questions follow the five measures of FINMA Guidance 05/2026, section 3. Answers are pre-filled only from CBOM `%s`; anything the scan cannot establish is marked to be completed.\n\n", orDash(v.bom.SerialNumber))

	w.WriteString("## 1. Strategy and roadmap\n\nDo you have a post-quantum strategy approved by your governing body, with a roadmap and target dates for complete migration and for critical processes?\n\n")
	w.WriteString("**Answer:** " + ToBeCompleted + "\n\n")

	w.WriteString("## 2. Inventory\n\nWhich cryptographic methods does the service use for data in transit, stored data, signatures, key management and authentication, and which of them are quantum-vulnerable?\n\n**Answer (from the scan):**\n\n")
	if len(v.algs) == 0 {
		w.WriteString(ToBeCompleted + "\n\n")
	} else {
		for _, c := range []catalog.Class{catalog.PostQuantum, catalog.Hybrid, catalog.QuantumVulnerable, catalog.Symmetric, catalog.Unknown} {
			if n := v.names(c); len(n) > 0 {
				fmt.Fprintf(w, "- %s: %s\n", c, strings.Join(n, ", "))
			}
		}
		fmt.Fprintf(w, "\nScope of the scan: %s Stored data and systems outside the scan: %s\n\n", scopeLine(v), ToBeCompleted)
	}

	w.WriteString("## 3. Long-lived data\n\nHow is data that needs long-term confidentiality or integrity protected against harvest-now-decrypt-later attacks? Do you use hybrid key exchange or hybrid signatures?\n\n**Answer (from the scan):**\n\n")
	found := false
	if len(v.protocols) > 0 {
		fmt.Fprintf(w, "- %s\n", v.transportLine())
		found = true
	}
	if m := firstNonEmpty(v.fact("qorescan:chain:pqc:hybrid-signature-mode"), v.fact("qorescan:genesis:pqc:hybrid-signature-mode")); m != "" {
		fmt.Fprintf(w, "- Native-lane transaction signatures: hybrid signature mode `%s`.\n", m)
		found = true
	}
	if !found {
		w.WriteString("- " + ToBeCompleted + "\n")
	}
	w.WriteString("- Which data needs long-term protection: " + ToBeCompleted + "\n\n")

	w.WriteString("## 4. Crypto-agility\n\nCan the algorithms be replaced without major changes to the architecture?\n\n**Answer (from the scan):** " + v.agilityLine() + "\n\nAssessment and change procedure: " + ToBeCompleted + "\n\n")

	w.WriteString("## 5. Dependencies on other providers\n\nWhich external providers does the service depend on for cryptography (certificate authorities, hosting, key management), and what is their migration status?\n\n**Answer (from the scan):**\n\n")
	issuers := map[string]bool{}
	for _, c := range v.certs {
		if cp := c.CryptoProperties.CertificateProperties; cp != nil && cp.IssuerName != "" && cp.IssuerName != cp.SubjectName {
			issuers[cp.IssuerName] = true
		}
	}
	if len(issuers) > 0 {
		var list []string
		for i := range issuers {
			list = append(list, i)
		}
		sort.Strings(list)
		fmt.Fprintf(w, "- Certificate issuers seen on scanned TLS endpoints: %s\n", strings.Join(list, "; "))
	}
	w.WriteString("- Other providers and their migration status: " + ToBeCompleted + "\n")
}

func dedupe(s []string) []string {
	var out []string
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
