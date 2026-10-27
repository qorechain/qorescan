// SPDX-License-Identifier: Apache-2.0

package nodehome

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/qorechain/qorescan/internal/catalog"
	"github.com/qorechain/qorescan/internal/inventory"
)

// flexInt decodes a JSON number or a quoted number (the chain writes 64-bit
// integers as strings).
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*f = flexInt(v)
	return nil
}

type consensusParams struct {
	Validator *struct {
		PubKeyTypes []string `json:"pub_key_types"`
	} `json:"validator"`
}

type pqcAlgorithm struct {
	ID             flexInt `json:"id"`
	Name           string  `json:"name"`
	Category       string  `json:"category"`
	NISTLevel      flexInt `json:"nist_level"`
	Status         flexInt `json:"status"`
	PublicKeySize  flexInt `json:"public_key_size"`
	SignatureSize  flexInt `json:"signature_size"`
	CiphertextSize flexInt `json:"ciphertext_size"`
	DeprecatedAt   flexInt `json:"deprecated_at"`
}

type pqcGenesis struct {
	Params *struct {
		PQCPrimary             bool    `json:"pqc_primary"`
		AllowClassicalFallback bool    `json:"allow_classical_fallback"`
		MinSecurityLevel       flexInt `json:"min_security_level"`
		DefaultMigrationBlocks flexInt `json:"default_migration_blocks"`
		DefaultSignatureAlgo   flexInt `json:"default_signature_algo"`
		HybridSignatureMode    flexInt `json:"hybrid_signature_mode"`
	} `json:"params"`
	Algorithms []pqcAlgorithm `json:"algorithms"`
	Accounts   []struct {
		AlgorithmID flexInt `json:"algorithm_id"`
		KeyType     string  `json:"key_type"`
	} `json:"accounts"`
	KEMKeys []struct {
		AlgorithmID flexInt `json:"algorithm_id"`
	} `json:"kem_keys"`
	ProtocolFeatures []string `json:"protocol_features"`
}

type typed struct {
	Type string `json:"@type"`
}

type genesisDoc struct {
	ChainID   string `json:"chain_id"`
	Consensus *struct {
		Params *consensusParams `json:"params"`
	} `json:"consensus"`
	ConsensusParams *consensusParams `json:"consensus_params"`
	Validators      []struct {
		PubKey struct {
			Type string `json:"type"`
		} `json:"pub_key"`
	} `json:"validators"`
	AppState struct {
		PQC     *pqcGenesis `json:"pqc"`
		Genutil *struct {
			GenTxs []struct {
				Body struct {
					Messages []struct {
						Type   string `json:"@type"`
						Pubkey typed  `json:"pubkey"`
					} `json:"messages"`
				} `json:"body"`
			} `json:"gen_txs"`
		} `json:"genutil"`
		Staking *struct {
			Validators []struct {
				ConsensusPubkey typed `json:"consensus_pubkey"`
			} `json:"validators"`
		} `json:"staking"`
	} `json:"app_state"`
}

// HybridModeName spells the pqc module's hybrid_signature_mode.
func HybridModeName(m int64) string {
	switch m {
	case 0:
		return "disabled"
	case 1:
		return "optional"
	case 2:
		return "required"
	}
	return fmt.Sprintf("unknown (%d)", m)
}

// RegistryStatusName spells a pqc algorithm registry status.
func RegistryStatusName(s int64) string {
	switch s {
	case 0:
		return "active"
	case 1:
		return "migrating"
	case 2:
		return "deprecated"
	case 3:
		return "disabled"
	}
	return fmt.Sprintf("status %d", s)
}

// RegistryAlgorithm returns the catalog entry for an on-chain registry
// entry. A name QoreScan does not know is recorded as written, with the
// category and NIST level the registry declares.
func RegistryAlgorithm(name, category string, nistLevel int64) catalog.Algorithm {
	if k, ok := catalog.OnChainName(name); ok {
		return catalog.Get(k)
	}
	class, transition, std := catalog.Classify(name, "")
	prim := "unknown"
	switch category {
	case "signature":
		prim = "signature"
	case "kem":
		prim = "kem"
	}
	a := catalog.Algorithm{Key: "registry-" + inventory.Slug(name), Name: name, Primitive: prim, Class: class, Transition: transition, Standard: std, Note: "Name as written in the on-chain registry; not in the QoreScan catalog."}
	if nistLevel > 0 {
		l := int(nistLevel)
		a.NISTLevel = &l
	}
	return a
}

func (s *scanner) genesis() {
	path := filepath.Join(s.home, "config", "genesis.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		s.inv.AddNote(src, "info", "config/genesis.json", "genesis.json not readable: %v", errText(err))
		return
	}
	s.logf("reading %s (%d bytes)", s.rel(path), len(raw))
	var g genesisDoc
	if err := json.Unmarshal(raw, &g); err != nil {
		s.inv.AddNote(src, "warning", "config/genesis.json", "genesis.json is not valid JSON")
		return
	}
	loc := s.rel(path)
	lines := newLineIndex(raw)
	if g.ChainID != "" {
		s.inv.AddFact("qorescan:genesis:chain-id", g.ChainID)
	}

	// Consensus key types allowed for validators.
	cp := g.ConsensusParams
	if g.Consensus != nil && g.Consensus.Params != nil {
		cp = g.Consensus.Params
	}
	if cp != nil && cp.Validator != nil {
		line := lines.find(nil, `"pub_key_types"`)
		for _, t := range cp.Validator.PubKeyTypes {
			s.inv.AddFact("qorescan:genesis:validator-pub-key-type", t)
			if k, ok := catalog.KeyTypeName(t); ok {
				s.inv.AddAlgorithm(catalog.Get(k), src, inventory.Occurrence{Location: loc, Line: line, Symbol: "consensus.params.validator.pub_key_types", Context: "consensus key type allowed for validators: " + t})
			} else {
				s.inv.AddNote(src, "warning", loc, "unrecognised validator key type %q in consensus params", t)
			}
		}
	}

	// Consensus keys of the genesis validator set.
	counts := map[string]int{}
	symbols := map[string]string{}
	for _, v := range g.Validators {
		counts[v.PubKey.Type]++
		symbols[v.PubKey.Type] = "validators[].pub_key.type"
	}
	if g.AppState.Genutil != nil {
		for _, tx := range g.AppState.Genutil.GenTxs {
			for _, m := range tx.Body.Messages {
				if strings.HasSuffix(m.Type, "MsgCreateValidator") && m.Pubkey.Type != "" {
					counts[m.Pubkey.Type]++
					symbols[m.Pubkey.Type] = "app_state.genutil.gen_txs[].body.messages[].pubkey"
				}
			}
		}
	}
	if g.AppState.Staking != nil {
		for _, v := range g.AppState.Staking.Validators {
			if v.ConsensusPubkey.Type != "" {
				counts[v.ConsensusPubkey.Type]++
				symbols[v.ConsensusPubkey.Type] = "app_state.staking.validators[].consensus_pubkey"
			}
		}
	}
	for _, t := range sortedKeys(counts) {
		k, ok := catalog.KeyTypeName(t)
		if !ok {
			s.inv.AddNote(src, "warning", loc, "unrecognised validator consensus key type %q (%d validators)", t, counts[t])
			continue
		}
		occ := inventory.Occurrence{Location: loc, Line: lines.find(nil, regexp.QuoteMeta(`"`+t+`"`)), Symbol: symbols[t], Context: fmt.Sprintf("%d genesis validator consensus keys of type %s", counts[t], t)}
		ref := s.inv.AddAlgorithm(catalog.Get(k), src, occ)
		s.inv.AddAsset(inventory.Asset{
			Ref:         "crypto/key/genesis-validators/" + k,
			Name:        "Genesis validator consensus public keys (" + catalog.Get(k).Name + ")",
			Kind:        inventory.KindMaterial,
			Material:    &inventory.Material{Type: "public-key", AlgorithmRef: ref},
			Sources:     []string{src},
			Occurrences: []inventory.Occurrence{occ},
			Properties:  []inventory.Property{{Name: "qorescan:count", Value: strconv.Itoa(counts[t])}},
		})
	}

	s.pqc(g.AppState.PQC, loc, lines)
}

func (s *scanner) pqc(p *pqcGenesis, loc string, lines *lineIndex) {
	if p == nil {
		s.inv.AddNote(src, "info", loc, "genesis has no pqc module state")
		return
	}
	anchor := regexp.MustCompile(`"pqc"\s*:\s*\{`)
	if p.Params != nil {
		s.inv.AddFact("qorescan:genesis:pqc:hybrid-signature-mode", HybridModeName(int64(p.Params.HybridSignatureMode)))
		s.inv.AddFact("qorescan:genesis:pqc:pqc-primary", strconv.FormatBool(p.Params.PQCPrimary))
		s.inv.AddFact("qorescan:genesis:pqc:allow-classical-fallback", strconv.FormatBool(p.Params.AllowClassicalFallback))
		s.inv.AddFact("qorescan:genesis:pqc:min-security-level", strconv.FormatInt(int64(p.Params.MinSecurityLevel), 10))
		s.inv.AddFact("qorescan:genesis:pqc:default-migration-blocks", strconv.FormatInt(int64(p.Params.DefaultMigrationBlocks), 10))
		s.inv.AddFact("qorescan:genesis:pqc:default-signature-algorithm-id", strconv.FormatInt(int64(p.Params.DefaultSignatureAlgo), 10))
	}
	modeLine := lines.find(anchor, `"hybrid_signature_mode"`)
	for i, a := range p.Algorithms {
		alg := RegistryAlgorithm(a.Name, a.Category, int64(a.NISTLevel))
		occ := inventory.Occurrence{
			Location: loc,
			Line:     lines.find(anchor, `"name"\s*:\s*"`+regexp.QuoteMeta(a.Name)+`"`),
			Symbol:   fmt.Sprintf("app_state.pqc.algorithms[%d]", i),
			Context:  fmt.Sprintf("on-chain algorithm registry: id %d, name %q, %s", a.ID, a.Name, RegistryStatusName(int64(a.Status))),
		}
		ref := s.inv.AddAlgorithm(alg, src, occ)
		if as, ok := s.inv.Asset(ref); ok {
			as.AddProperty("qorescan:pqc:registry-id", strconv.FormatInt(int64(a.ID), 10))
			as.AddProperty("qorescan:pqc:registry-name", a.Name)
			as.AddProperty("qorescan:pqc:registry-status", RegistryStatusName(int64(a.Status)))
			if p.Params != nil && a.ID == p.Params.DefaultSignatureAlgo && a.Category == "signature" {
				as.AddProperty("qorescan:pqc:default-signature-algorithm", "true")
				as.AddProperty("qorescan:pqc:hybrid-signature-mode", HybridModeName(int64(p.Params.HybridSignatureMode)))
				if modeLine > 0 {
					s.inv.AddAlgorithm(alg, src, inventory.Occurrence{Location: loc, Line: modeLine, Symbol: "app_state.pqc.params.hybrid_signature_mode", Context: "native-lane transactions: hybrid signature mode " + HybridModeName(int64(p.Params.HybridSignatureMode))})
				}
			}
		}
		s.inv.AddFact("qorescan:genesis:pqc:registry", fmt.Sprintf("%d %s (%s, %s, NIST level %d)", a.ID, a.Name, a.Category, RegistryStatusName(int64(a.Status)), a.NISTLevel))
	}
	if p.Params != nil && p.Params.HybridSignatureMode > 0 {
		// The classical half of a hybrid native-lane signature is secp256k1.
		s.inv.AddAlgorithm(catalog.Get("ecdsa-secp256k1"), src, inventory.Occurrence{Location: loc, Line: modeLine, Symbol: "app_state.pqc.params.hybrid_signature_mode", Context: "classical half of the native-lane hybrid signature"})
	}
	byKind := map[string]int{}
	for _, a := range p.Accounts {
		byKind[a.KeyType]++
	}
	if len(p.Accounts) > 0 {
		parts := []string{}
		for _, k := range sortedKeys(byKind) {
			parts = append(parts, fmt.Sprintf("%s %d", orDash(k), byKind[k]))
		}
		s.inv.AddFact("qorescan:genesis:pqc:accounts", fmt.Sprintf("%d (%s)", len(p.Accounts), strings.Join(parts, ", ")))
	}
	if len(p.KEMKeys) > 0 {
		s.inv.AddFact("qorescan:genesis:pqc:kem-keys", strconv.Itoa(len(p.KEMKeys)))
	}
	pqcFeatures := 0
	for _, f := range p.ProtocolFeatures {
		if strings.HasPrefix(f, "pqc-") || strings.Contains(f, "-pqc-") {
			s.inv.AddFact("qorescan:genesis:protocol-feature", f)
			pqcFeatures++
		}
	}
	if len(p.ProtocolFeatures) > 0 {
		s.inv.AddFact("qorescan:genesis:protocol-features", fmt.Sprintf("%d enabled at genesis (%d PQC-related listed)", len(p.ProtocolFeatures), pqcFeatures))
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lineIndex finds the line of the first match of a pattern, optionally after
// an anchor pattern.
type lineIndex struct {
	raw   []byte
	cache map[string]int
}

func newLineIndex(raw []byte) *lineIndex { return &lineIndex{raw: raw, cache: map[string]int{}} }

func (l *lineIndex) find(anchor *regexp.Regexp, pattern string) int {
	key := pattern
	start := 0
	if anchor != nil {
		key = anchor.String() + "|" + pattern
		loc := anchor.FindIndex(l.raw)
		if loc == nil {
			return 0
		}
		start = loc[0]
	}
	if v, ok := l.cache[key]; ok {
		return v
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return 0
	}
	m := re.FindIndex(l.raw[start:])
	line := 0
	if m != nil {
		line = bytes.Count(l.raw[:start+m[0]], []byte("\n")) + 1
	}
	l.cache[key] = line
	return line
}
