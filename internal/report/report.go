// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/qorechain/qorescan/internal/catalog"
	"github.com/qorechain/qorescan/internal/cbom"
)

// Frameworks QoreScan maps to.
var Frameworks = []string{"finma", "nis", "dora"}

// Source documents cited by the reports.
const (
	srcFINMA   = "FINMA Guidance 05/2026 \"Quantum computing\", 9 July 2026: <https://www.finma.ch/en/~/media/finma/dokumente/dokumentencenter/myfinma/4dokumentation/finma-aufsichtsmitteilungen/20260709-finma-aufsichtsmitteilung-05-2026.pdf>"
	srcNIS     = "EU PQC Workstream of the NIS Cooperation Group, \"A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography\", Part 1, version 1.1, 11 June 2025: <https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography>"
	srcDORA    = "Commission Delegated Regulation (EU) 2024/1774 of 13 March 2024 (regulatory technical standards on the ICT risk management framework under Regulation (EU) 2022/2554, DORA), Article 6: <https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj>"
	srcIR8547  = "NIST IR 8547, \"Transition to Post-Quantum Cryptography Standards\", final, October 2026: <https://doi.org/10.6028/NIST.IR.8547>"
	srcFIPS203 = "FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard: <https://csrc.nist.gov/pubs/fips/203/final>"
	srcFIPS204 = "FIPS 204, Module-Lattice-Based Digital Signature Standard: <https://csrc.nist.gov/pubs/fips/204/final>"
	srcFIPS205 = "FIPS 205, Stateless Hash-Based Digital Signature Standard: <https://csrc.nist.gov/pubs/fips/205/final>"
)

// Report renders the framework report for framework ("finma", "nis",
// "dora") from a CBOM.
func Report(b *cbom.BOM, framework string) (string, error) {
	v := newView(b)
	var w strings.Builder
	var title, source string
	switch framework {
	case "finma":
		title, source = "FINMA Guidance 05/2026", srcFINMA
	case "nis":
		title, source = "EU NIS Cooperation Group PQC roadmap", srcNIS
	case "dora":
		title, source = "DORA RTS on ICT risk management, Article 6", srcDORA
	default:
		return "", fmt.Errorf("unknown framework %q (want one of %s)", framework, strings.Join(Frameworks, ", "))
	}
	fmt.Fprintf(&w, "# Cryptographic inventory mapped to %s\n\n", title)
	disclaimer(&w, reportDisclaimer)
	header(&w, v)

	w.WriteString("## Framework mapping\n\n")
	switch framework {
	case "finma":
		finma(&w, v)
	case "nis":
		nis(&w, v)
	case "dora":
		dora(&w, v)
	}

	summary(&w, v)
	assetTable(&w, v)
	otherAssets(&w, v)
	facts(&w, v)
	notes(&w, v)

	w.WriteString("## Sources\n\n")
	for _, s := range []string{source, srcIR8547, srcFIPS203, srcFIPS204, srcFIPS205} {
		fmt.Fprintf(&w, "- %s\n", s)
	}
	w.WriteString("\nThe framework rows paraphrase the source documents; read the sources for the authoritative wording.\n")
	return w.String(), nil
}

func disclaimer(w *strings.Builder, extra string) {
	fmt.Fprintf(w, "> **Disclaimer.** %s %s\n\n", cbom.Disclaimer, extra)
}

const (
	reportDisclaimer   = "The mapping below shows where the inventory can serve as input; whether an organisation meets a requirement depends on facts outside the scan and is for the organisation and its advisers to assess."
	templateDisclaimer = "This draft is pre-filled only with facts the scan recorded; the organisation is responsible for completing, checking and adopting it."
)

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func header(w *strings.Builder, v *view) {
	tool := "unknown tool"
	if t := v.bom.Metadata.Tools.Components; len(t) > 0 {
		tool = strings.TrimSpace(t[0].Name + " " + t[0].Version)
	}
	fmt.Fprintf(w, "| | |\n|---|---|\n")
	fmt.Fprintf(w, "| CBOM | `%s` |\n", cell(v.bom.SerialNumber))
	fmt.Fprintf(w, "| Generated | %s by %s |\n", cell(v.bom.Metadata.Timestamp), cell(tool))
	if id := firstNonEmpty(v.fact("qorescan:chain:id"), v.fact("qorescan:genesis:chain-id")); id != "" {
		fmt.Fprintf(w, "| Chain | `%s` |\n", id)
	}
	if len(v.sources) > 0 {
		fmt.Fprintf(w, "| Scanned | %s |\n", strings.Join(v.sources, ", "))
	}
	if v.foreignBOM {
		w.WriteString("| Note | This CBOM was not written by QoreScan; algorithms are classified by name only. |\n")
	}
	w.WriteString("\n")
}

func summary(w *strings.Builder, v *view) {
	w.WriteString("## Summary\n\n")
	fmt.Fprintf(w, "| Classification | Algorithms |\n|---|---|\n")
	for _, c := range []catalog.Class{catalog.PostQuantum, catalog.Hybrid, catalog.QuantumVulnerable, catalog.Symmetric, catalog.Unknown} {
		names := v.names(c)
		if len(names) == 0 {
			continue
		}
		fmt.Fprintf(w, "| %s | %d: %s |\n", c, len(names), cell(strings.Join(names, ", ")))
	}
	w.WriteString("\nNIST IR 8547 deprecates quantum-vulnerable public-key algorithms (RSA, ECDSA, EdDSA, finite-field and elliptic-curve DH) after 2030 and disallows them under NIST standards after 2035; applications may be given earlier dates.\n\n")
}

func assetTable(w *strings.Builder, v *view) {
	w.WriteString("## Algorithms and status\n\n")
	if len(v.algs) == 0 {
		w.WriteString("No algorithm assets in this CBOM.\n\n")
		return
	}
	w.WriteString("| Algorithm | Primitive | Parameter set | NIST category | FIPS 203/204/205 | NIST IR 8547 | Evidence |\n|---|---|---|---|---|---|---|\n")
	for _, a := range v.algs {
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s |\n", cell(a.Name), cell(a.Primitive), cell(a.ParamSet), levelText(a.Level), cell(fipsStatus(a)), cell(a.Transition), evidenceText(a.Evidence))
	}
	w.WriteString("\n")
}

func otherAssets(w *strings.Builder, v *view) {
	if len(v.protocols) > 0 {
		w.WriteString("## Protocols\n\n| Protocol | Version | Cipher suite | Key exchange | Algorithms |\n|---|---|---|---|---|\n")
		for _, p := range v.protocols {
			pp := p.CryptoProperties.ProtocolProperties
			ver, suite, refs := "-", "-", []string{}
			if pp != nil {
				ver = orDash(pp.Version)
				if len(pp.CipherSuites) > 0 {
					suite = pp.CipherSuites[0].Name
				}
				for _, r := range pp.CryptoRefArray {
					if c, ok := v.byRef[r]; ok && c.CryptoProperties != nil && c.CryptoProperties.AssetType == "algorithm" {
						refs = append(refs, c.Name)
					}
				}
			}
			kx := firstNonEmpty(p.Property("qorescan:tls:key-exchange-group"), p.Property("qorescan:protocol:key-exchange"))
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n", cell(p.Name), cell(ver), cell(suite), cell(kx), cell(strings.Join(refs, ", ")))
		}
		w.WriteString("\n")
	}
	if len(v.certs) > 0 {
		w.WriteString("## Certificates\n\n| Certificate | Public key | Signature | Valid until | Chain |\n|---|---|---|---|---|\n")
		for _, c := range v.certs {
			cp := c.CryptoProperties.CertificateProperties
			if cp == nil {
				continue
			}
			key := v.refName(cp.SubjectPublicKeyRef)
			if k, ok := v.byRef[cp.SubjectPublicKeyRef]; ok && k.CryptoProperties != nil && k.CryptoProperties.RelatedCryptoMaterialProperties != nil {
				key = v.refName(k.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef)
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n", cell(c.Name), cell(key), cell(v.refName(cp.SignatureAlgorithmRef)), cell(cp.NotValidAfter), cell(c.Property("qorescan:certificate:chain")))
		}
		w.WriteString("\n")
	}
	if len(v.materials) > 0 {
		w.WriteString("## Keys\n\nQoreScan records public keys and key types only; it never reads private key values.\n\n| Key | Type | Algorithm | Count | Evidence |\n|---|---|---|---|---|\n")
		for _, m := range v.materials {
			rp := m.CryptoProperties.RelatedCryptoMaterialProperties
			typ, alg := "-", "-"
			if rp != nil {
				typ, alg = rp.Type, v.refName(rp.AlgorithmRef)
			}
			count := orDash(m.Property("qorescan:count"))
			var occ []cbom.Occurrence
			if m.Evidence != nil {
				occ = m.Evidence.Occurrences
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n", cell(m.Name), cell(typ), cell(alg), count, evidenceText(occ))
		}
		w.WriteString("\n")
	}
	if len(v.libraries) > 0 {
		w.WriteString("## Libraries\n\n| Library | Provides | Evidence |\n|---|---|---|\n")
		for _, l := range v.libraries {
			var provides []string
			for _, d := range v.bom.Dependencies {
				if d.Ref == l.BOMRef {
					for _, p := range d.Provides {
						provides = append(provides, v.refName(p))
					}
				}
			}
			var occ []cbom.Occurrence
			if l.Evidence != nil {
				occ = l.Evidence.Occurrences
			}
			fmt.Fprintf(w, "| %s | %s | %s |\n", cell(strings.TrimSpace(l.Group+" "+l.Name)), cell(strings.Join(provides, ", ")), evidenceText(occ))
		}
		w.WriteString("\n")
	}
}

func facts(w *strings.Builder, v *view) {
	var keys []string
	for k := range v.facts {
		if strings.HasPrefix(k, "qorescan:chain:") || strings.HasPrefix(k, "qorescan:genesis:") {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return
	}
	sort.Strings(keys)
	w.WriteString("## Scanned facts\n\n| Fact | Value |\n|---|---|\n")
	for _, k := range keys {
		fmt.Fprintf(w, "| `%s` | %s |\n", strings.TrimPrefix(k, "qorescan:"), cell(strings.Join(v.facts[k], "; ")))
	}
	w.WriteString("\n")
}

func notes(w *strings.Builder, v *view) {
	if len(v.notes) == 0 {
		return
	}
	w.WriteString("## Scan notes\n\n")
	for _, n := range v.notes {
		fmt.Fprintf(w, "- %s\n", n)
	}
	w.WriteString("\n")
}

func row(w *strings.Builder, ref, expectation, provides, status string) {
	fmt.Fprintf(w, "| %s | %s | %s | %s |\n", ref, expectation, provides, status)
}

func (v *view) inventoryLine() string {
	return fmt.Sprintf("CBOM with %s (%d quantum-vulnerable, %d post-quantum, %d hybrid), %s, %s, %s", plural(len(v.algs), "algorithm", "algorithms"), v.count(catalog.QuantumVulnerable), v.count(catalog.PostQuantum), v.count(catalog.Hybrid), plural(len(v.protocols), "protocol", "protocols"), plural(len(v.certs), "certificate", "certificates"), plural(len(v.materials), "key record", "key records"))
}

func (v *view) transportLine() string {
	var parts []string
	for _, p := range v.protocols {
		g := p.Property("qorescan:tls:key-exchange-group")
		if g == "" {
			if g = p.Property("qorescan:protocol:key-exchange"); g != "" && p.Property("qorescan:protocol:configurable") == "no" {
				g += " (fixed by the protocol)"
			}
		}
		parts = append(parts, fmt.Sprintf("%s: %s", p.Name, orDash(g)))
	}
	if len(parts) == 0 {
		return "No transport was scanned."
	}
	return "Key exchange of the scanned transports: " + strings.Join(parts, "; ") + "."
}

func (v *view) agilityLine() string {
	var parts []string
	if r := v.facts["qorescan:genesis:pqc:registry"]; len(r) > 0 {
		parts = append(parts, "on-chain algorithm registry with "+fmt.Sprint(len(r))+" entries ("+strings.Join(r, "; ")+")")
	}
	if m := firstNonEmpty(v.fact("qorescan:chain:pqc:hybrid-signature-mode"), v.fact("qorescan:genesis:pqc:hybrid-signature-mode")); m != "" {
		parts = append(parts, "native-lane hybrid signature mode "+m)
	}
	if b := firstNonEmpty(v.fact("qorescan:chain:pqc:default-migration-blocks"), v.fact("qorescan:genesis:pqc:default-migration-blocks")); b != "" {
		parts = append(parts, "algorithm migration dual-signature period of "+b+" blocks (module parameter)")
	}
	if len(parts) == 0 {
		return "No crypto-agility evidence in this CBOM."
	}
	return "Scanned evidence: " + strings.Join(parts, "; ") + "."
}

func finma(w *strings.Builder, v *view) {
	w.WriteString("| FINMA 05/2026 | Expectation (paraphrased) | What this inventory provides | Status |\n|---|---|---|---|\n")
	row(w, "3.1 Strategy and roadmap", "Strategy adopted by the board, implementation plan with milestones; PQC roadmap by mid-2027 at the latest.", "Nothing: organisational measure.", ToBeCompleted)
	row(w, "3.2 Risk analysis and inventory", "Inventory of the cryptographic methods of all ICT systems, including distributed ledger technology, covering transport, stored data, signatures, key management and authentication; identify quantum-vulnerable algorithms.", v.inventoryLine()+".", "Input for the scanned scope; other systems and stored data "+strings.ToLower(ToBeCompleted))
	row(w, "3.3 Critical data", "Identify data needing long-term protection; consider harvest-now-decrypt-later; hybrid schemes in the short to medium term.", v.transportLine(), "Data classification "+strings.ToLower(ToBeCompleted))
	row(w, "3.4 Crypto-agility", "Ability to replace algorithms without major architecture changes, as a requirement for systems procured or developed.", v.agilityLine(), "Evidence listed; assessment "+strings.ToLower(ToBeCompleted))
	row(w, "3.5 External service providers", "Plan the migration with providers; make crypto-agility a prerequisite in new outsourcing arrangements.", "Scanned TLS endpoints and certificate issuers below; see the vendor questionnaire template (`qorescan template questionnaire`).", ToBeCompleted)
	w.WriteString("\n")
}

func nis(w *strings.Builder, v *view) {
	w.WriteString("| Roadmap item | Expectation (paraphrased) | What this inventory provides | Status |\n|---|---|---|---|\n")
	row(w, "First Steps: cryptographic asset management", "Create and maintain inventories of assets that perform or rely on cryptographic operations; a standardised format such as CBOM is recommended.", v.inventoryLine()+", in CycloneDX 1.6.", "Input for the scanned scope")
	row(w, "Milestone 1 (31.12.2026)", "Member States: First Steps implemented, national roadmaps in place, transition planning and pilots for high- and medium-risk use cases started.", "Nothing: planning measure.", ToBeCompleted)
	row(w, "Milestone 2 (31.12.2030)", "Transition of high-risk use cases completed; post-quantum software and firmware upgrades enabled by default.", fmt.Sprintf("%d quantum-vulnerable algorithms listed below with their evidence.", v.count(catalog.QuantumVulnerable)), "Risk classification per use case "+strings.ToLower(ToBeCompleted))
	row(w, "Milestone 3 (31.12.2035)", "Transition of medium-risk use cases completed; low-risk use cases as far as feasible.", "Same list; NIST IR 8547 disallows the listed families after 2035.", ToBeCompleted)
	row(w, "Cryptographic agility", "Support crypto-agility and an upgrade path when products are developed.", v.agilityLine(), "Evidence listed; assessment "+strings.ToLower(ToBeCompleted))
	w.WriteString("\n")
}

func dora(w *strings.Builder, v *view) {
	w.WriteString("| RTS 2024/1774 | Requirement (paraphrased) | What this inventory provides | Status |\n|---|---|---|---|\n")
	row(w, "Art. 6(1)", "Develop, document and implement a policy on encryption and cryptographic controls.", "Inventory input for the policy.", ToBeCompleted)
	row(w, "Art. 6(2)(a)", "Rules for encrypting data at rest and in transit.", v.transportLine()+" Data at rest is not scanned.", "In transit: input; at rest "+strings.ToLower(ToBeCompleted))
	row(w, "Art. 6(2)(c)", "Rules for encrypting internal network connections and traffic with external parties.", "P2P transport and TLS endpoint records; listeners without TLS are listed under scan notes.", "Input for the scanned scope")
	row(w, "Art. 6(2)(d)", "Cryptographic key management in line with Article 7.", plural(len(v.materials), "key record", "key records")+" (types and public keys only).", "Key lifecycle "+strings.ToLower(ToBeCompleted))
	row(w, "Art. 6(3)", "Criteria for selecting cryptographic techniques, considering leading practices and standards.", "Each algorithm stated against FIPS 203/204/205 and NIST IR 8547 below.", "Input")
	row(w, "Art. 6(4)", "Update or change cryptographic technology on the basis of developments in cryptanalysis.", v.agilityLine(), "Evidence listed; assessment "+strings.ToLower(ToBeCompleted))
	row(w, "Art. 6(5)", "Record mitigation and monitoring measures adopted under paragraphs 3 and 4, with reasons.", "Nothing: organisational record.", ToBeCompleted)
	w.WriteString("\n")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}
