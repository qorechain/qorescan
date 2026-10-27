// SPDX-License-Identifier: Apache-2.0

// Package chain reads the cryptographic configuration of a live QoreChain
// network through its public REST API. Every request is a read-only GET.
package chain

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/qorechain/qorescan/internal/catalog"
	"github.com/qorechain/qorescan/internal/inventory"
	"github.com/qorechain/qorescan/internal/nodehome"
)

// Public REST endpoints.
var Networks = map[string]string{
	"mainnet": "https://api.qore.host",
	"testnet": "https://api-testnet.qore.host",
}

// maxBody bounds a REST response.
const maxBody = 16 << 20

const src = inventory.SourceChain

// Options configure a chain scan.
type Options struct {
	// REST is the REST base URL.
	REST string
	// Addresses are accounts whose PQC key status is read.
	Addresses []string
	Timeout   time.Duration
	UserAgent string
	Client    *http.Client
	Logf      func(format string, args ...any)
}

// HTTPError is a non-200 answer.
type HTTPError struct {
	Status int
	Code   int
	Msg    string
}

func (e *HTTPError) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("HTTP %d: %s", e.Status, e.Msg)
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

// NotServed reports whether the node does not implement the route.
func (e *HTTPError) NotServed() bool {
	return e.Status == http.StatusNotImplemented || e.Status == http.StatusNotFound || e.Code == 12
}

type client struct {
	base string
	ua   string
	hc   *http.Client
	logf func(string, ...any)
}

func (c *client) get(ctx context.Context, path string, out any) error {
	u := c.base + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	c.logf("GET %s", u)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		he := &HTTPError{Status: resp.StatusCode}
		var e struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &e) == nil {
			he.Code, he.Msg = e.Code, e.Message
		}
		return he
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding %s: %w", path, err)
	}
	return nil
}

// Scan reads the network at opt.REST into inv.
func Scan(ctx context.Context, inv *inventory.Inventory, opt Options) error {
	if opt.REST == "" {
		return errors.New("chain: no REST endpoint")
	}
	base, err := url.Parse(opt.REST)
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
		return fmt.Errorf("chain: invalid REST URL %q", opt.REST)
	}
	hc := opt.Client
	if hc == nil {
		t := opt.Timeout
		if t <= 0 {
			t = 20 * time.Second
		}
		hc = &http.Client{Timeout: t}
	}
	logf := opt.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	c := &client{base: strings.TrimRight(opt.REST, "/"), ua: orDefault(opt.UserAgent, "qorescan"), hc: hc, logf: logf}
	inv.AddFact("qorescan:chain:rest", c.base)

	ok := 0
	var firstErr error
	try := func(name string, fn func() error) {
		err := fn()
		if err == nil {
			ok++
			return
		}
		var he *HTTPError
		if errors.As(err, &he) && he.NotServed() {
			inv.AddNote(src, "info", c.base, "%s: route not served by this node (%v)", name, err)
			ok++
			return
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", name, err)
		}
		inv.AddNote(src, "warning", c.base, "%s: %v", name, err)
	}
	try("node info", func() error { return c.nodeInfo(ctx, inv) })
	try("protocol features", func() error { return c.protocolFeatures(ctx, inv) })
	try("pqc params", func() error { return c.pqcParams(ctx, inv) })
	try("validator set", func() error { return c.validatorSet(ctx, inv) })
	try("evm params", func() error { return c.evmParams(ctx, inv) })
	for _, a := range opt.Addresses {
		try("pqc account "+a, func() error { return c.account(ctx, inv, a) })
		try("kem key "+a, func() error { return c.kemKey(ctx, inv, a) })
	}
	if ok == 0 && firstErr != nil {
		return fmt.Errorf("chain: no query succeeded against %s: %w", c.base, firstErr)
	}
	return nil
}

func (c *client) occ(path, symbol, context string) inventory.Occurrence {
	return inventory.Occurrence{Location: c.base + path, Symbol: symbol, Context: context}
}

const nodeInfoPath = "/cosmos/base/tendermint/v1beta1/node_info"

func (c *client) nodeInfo(ctx context.Context, inv *inventory.Inventory) error {
	var r struct {
		Default struct {
			Network string `json:"network"`
			Version string `json:"version"`
		} `json:"default_node_info"`
		App struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"application_version"`
	}
	if err := c.get(ctx, nodeInfoPath, &r); err != nil {
		return err
	}
	if r.Default.Network != "" {
		inv.AddFact("qorescan:chain:id", r.Default.Network)
	}
	if r.Default.Version != "" {
		inv.AddFact("qorescan:chain:consensus-engine-version", r.Default.Version)
	}
	if r.App.Version != "" {
		inv.AddFact("qorescan:chain:app-version", r.App.Version)
	}
	return nil
}

const featuresPath = "/qorechain/pqc/v1/protocol_features"

func (c *client) protocolFeatures(ctx context.Context, inv *inventory.Inventory) error {
	var r struct {
		Features []struct {
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
			Known   bool   `json:"known"`
			Staged  bool   `json:"staged"`
		} `json:"features"`
		Height flexInt `json:"height"`
	}
	if err := c.get(ctx, featuresPath, &r); err != nil {
		return err
	}
	enabled, pqc := 0, 0
	for _, f := range r.Features {
		if !f.Enabled {
			continue
		}
		enabled++
		if strings.HasPrefix(f.Name, "pqc-") || strings.Contains(f.Name, "-pqc-") {
			inv.AddFact("qorescan:chain:protocol-feature", f.Name)
			pqc++
		}
	}
	inv.AddFact("qorescan:chain:protocol-features", fmt.Sprintf("%d enabled at height %d (%d PQC-related listed)", enabled, r.Height, pqc))
	return nil
}

const paramsPath = "/qorechain/pqc/v1/params"

func (c *client) pqcParams(ctx context.Context, inv *inventory.Inventory) error {
	var r struct {
		Params struct {
			PQCPrimary               bool    `json:"pqc_primary"`
			AllowClassicalFallback   bool    `json:"allow_classical_fallback"`
			MinSecurityLevel         flexInt `json:"min_security_level"`
			DefaultMigrationBlocks   flexInt `json:"default_migration_blocks"`
			DefaultSignatureAlgo     flexInt `json:"default_signature_algo"`
			DefaultSignatureAlgoName string  `json:"default_signature_algo_name"`
			HybridSignatureMode      flexInt `json:"hybrid_signature_mode"`
			HybridSignatureModeName  string  `json:"hybrid_signature_mode_name"`
		} `json:"params"`
	}
	if err := c.get(ctx, paramsPath, &r); err != nil {
		return err
	}
	p := r.Params
	mode := p.HybridSignatureModeName
	if mode == "" {
		mode = nodehome.HybridModeName(int64(p.HybridSignatureMode))
	}
	inv.AddFact("qorescan:chain:pqc:hybrid-signature-mode", mode)
	inv.AddFact("qorescan:chain:pqc:pqc-primary", strconv.FormatBool(p.PQCPrimary))
	inv.AddFact("qorescan:chain:pqc:allow-classical-fallback", strconv.FormatBool(p.AllowClassicalFallback))
	inv.AddFact("qorescan:chain:pqc:min-security-level", strconv.FormatInt(int64(p.MinSecurityLevel), 10))
	inv.AddFact("qorescan:chain:pqc:default-migration-blocks", strconv.FormatInt(int64(p.DefaultMigrationBlocks), 10))
	if p.DefaultSignatureAlgoName != "" {
		alg := nodehome.RegistryAlgorithm(p.DefaultSignatureAlgoName, "signature", 0)
		ref := inv.AddAlgorithm(alg, src, c.occ(paramsPath, "params.default_signature_algo_name", fmt.Sprintf("default signature algorithm for new keys: id %d, %q; hybrid signature mode %s", p.DefaultSignatureAlgo, p.DefaultSignatureAlgoName, mode)))
		if a, ok := inv.Asset(ref); ok {
			a.AddProperty("qorescan:pqc:default-signature-algorithm", "true")
			a.AddProperty("qorescan:pqc:hybrid-signature-mode", mode)
		}
	}
	if p.HybridSignatureMode > 0 {
		inv.AddAlgorithm(catalog.Get("ecdsa-secp256k1"), src, c.occ(paramsPath, "params.hybrid_signature_mode", "classical half of the native-lane hybrid signature"))
	}
	return nil
}

const validatorSetPath = "/cosmos/base/tendermint/v1beta1/validatorsets/latest?pagination.limit=1000"

func (c *client) validatorSet(ctx context.Context, inv *inventory.Inventory) error {
	var r struct {
		BlockHeight flexInt `json:"block_height"`
		Validators  []struct {
			PubKey struct {
				Type string `json:"@type"`
			} `json:"pub_key"`
		} `json:"validators"`
	}
	if err := c.get(ctx, validatorSetPath, &r); err != nil {
		return err
	}
	counts := map[string]int{}
	for _, v := range r.Validators {
		counts[v.PubKey.Type]++
	}
	types := make([]string, 0, len(counts))
	for t := range counts {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		k, ok := catalog.KeyTypeName(t)
		if !ok {
			inv.AddNote(src, "warning", c.base+validatorSetPath, "unrecognised consensus key type %q (%d validators)", t, counts[t])
			continue
		}
		occ := c.occ(validatorSetPath, "validators[].pub_key", fmt.Sprintf("%d active validators with %s consensus keys at height %d", counts[t], t, r.BlockHeight))
		ref := inv.AddAlgorithm(catalog.Get(k), src, occ)
		inv.AddAsset(inventory.Asset{
			Ref:         "crypto/key/active-validators/" + k,
			Name:        "Active validator consensus public keys (" + catalog.Get(k).Name + ")",
			Kind:        inventory.KindMaterial,
			Material:    &inventory.Material{Type: "public-key", AlgorithmRef: ref},
			Sources:     []string{src},
			Occurrences: []inventory.Occurrence{occ},
			Properties:  []inventory.Property{{Name: "qorescan:count", Value: strconv.Itoa(counts[t])}},
		})
	}
	return nil
}

const evmParamsPath = "/cosmos/evm/vm/v1/params"

// precompiles maps active_static_precompiles addresses (lower case) to a
// name and, where the precompile performs a signature check, the algorithm.
var precompiles = map[string]struct{ name, alg string }{
	"0x0000000000000000000000000000000000000a01": {"pqcVerify", "ml-dsa-87"},
	"0x0000000000000000000000000000000000000a02": {"pqcKeyStatus", ""},
	"0x0000000000000000000000000000000000000100": {"p256", "ecdsa-p256"},
	"0x0000000000000000000000000000000000000901": {"crossVmBridge", ""},
	"0x0000000000000000000000000000000000000b01": {"aiRiskScore", ""},
	"0x0000000000000000000000000000000000000b02": {"aiAnomalyCheck", ""},
	"0x0000000000000000000000000000000000000c01": {"rlConsensusParams", ""},
	"0x0000000000000000000000000000000000000400": {"bech32", ""},
	"0x0000000000000000000000000000000000000800": {"staking", ""},
	"0x0000000000000000000000000000000000000801": {"distribution", ""},
	"0x0000000000000000000000000000000000000802": {"ics20", ""},
	"0x0000000000000000000000000000000000000804": {"bank", ""},
	"0x0000000000000000000000000000000000000805": {"gov", ""},
	"0x0000000000000000000000000000000000000806": {"slashing", ""},
}

func (c *client) evmParams(ctx context.Context, inv *inventory.Inventory) error {
	var r struct {
		Params struct {
			Active []string `json:"active_static_precompiles"`
		} `json:"params"`
	}
	if err := c.get(ctx, evmParamsPath, &r); err != nil {
		return err
	}
	// Ethereum rules that hold on every EVM: transactions are signed with
	// ECDSA secp256k1 over Keccak-256, and the ecrecover, sha256 and
	// ripemd160 precompiles exist at 0x01 to 0x03.
	evm := c.occ(evmParamsPath, "evm", "EVM lane: transactions signed with ECDSA secp256k1 over Keccak-256; ecrecover (0x01), sha256 (0x02) and ripemd160 (0x03) precompiles")
	inv.AddAlgorithm(catalog.Get("ecdsa-secp256k1"), src, evm)
	inv.AddAlgorithm(catalog.Get("keccak-256"), src, evm)
	if len(r.Params.Active) == 0 {
		inv.AddFact("qorescan:chain:evm:active-precompiles", "none beyond the standard Ethereum precompiles")
		return nil
	}
	for _, a := range r.Params.Active {
		p, known := precompiles[strings.ToLower(a)]
		name := a
		if known {
			name = p.name + " (" + a + ")"
		}
		inv.AddFact("qorescan:chain:evm:active-precompile", name)
		if known && p.alg != "" {
			inv.AddAlgorithm(catalog.Get(p.alg), src, c.occ(evmParamsPath, "params.active_static_precompiles", "EVM precompile "+name+" is active: signature verification from contracts"))
		}
	}
	return nil
}

func (c *client) account(ctx context.Context, inv *inventory.Inventory, address string) error {
	path := "/qorechain/pqc/v1/account/" + url.PathEscape(address)
	var r struct {
		Found   bool `json:"found"`
		Account *struct {
			Address              string  `json:"address"`
			PublicKey            string  `json:"public_key"`
			AlgorithmID          flexInt `json:"algorithm_id"`
			AlgorithmName        string  `json:"algorithm_name"`
			ECDSAPubkey          string  `json:"ecdsa_pubkey"`
			KeyType              string  `json:"key_type"`
			CreatedAtHeight      flexInt `json:"created_at_height"`
			MigrationPublicKey   string  `json:"migration_public_key"`
			MigrationAlgorithmID flexInt `json:"migration_algorithm_id"`
			ClassicalKeySource   string  `json:"classical_key_source"`
		} `json:"account"`
	}
	if err := c.get(ctx, path, &r); err != nil {
		return err
	}
	if !r.Found || r.Account == nil {
		inv.AddNote(src, "info", c.base+path, "account %s has no registered PQC key", address)
		inv.AddFact("qorescan:chain:account-pqc-status", address+": no PQC key registered")
		return nil
	}
	a := r.Account
	alg := nodehome.RegistryAlgorithm(a.AlgorithmName, "signature", 0)
	occ := c.occ(path, "account", fmt.Sprintf("PQC key of %s: %s, key type %s, registered at height %d", address, a.AlgorithmName, a.KeyType, a.CreatedAtHeight))
	algRef := inv.AddAlgorithm(alg, src, occ)
	pub := decodeB64(a.PublicKey)
	props := []inventory.Property{
		{Name: "qorescan:pqc:key-type", Value: a.KeyType},
		{Name: "qorescan:pqc:registry-id", Value: strconv.FormatInt(int64(a.AlgorithmID), 10)},
	}
	if a.ClassicalKeySource != "" {
		props = append(props, inventory.Property{Name: "qorescan:pqc:classical-key-source", Value: a.ClassicalKeySource})
	}
	if a.MigrationAlgorithmID > 0 {
		props = append(props, inventory.Property{Name: "qorescan:pqc:migration-algorithm-id", Value: strconv.FormatInt(int64(a.MigrationAlgorithmID), 10)})
	}
	inv.AddAsset(inventory.Asset{
		Ref:         "crypto/key/account-pqc/" + inventory.Slug(address),
		Name:        "Account PQC public key " + address,
		Kind:        inventory.KindMaterial,
		Material:    &inventory.Material{Type: "public-key", ID: address, AlgorithmRef: algRef, SizeBits: len(pub) * 8, Format: "raw"},
		Sources:     []string{src},
		Occurrences: []inventory.Occurrence{occ},
		Properties:  props,
	})
	if ec := decodeB64(a.ECDSAPubkey); len(ec) > 0 {
		ecRef := inv.AddAlgorithm(catalog.Get("ecdsa-secp256k1"), src, c.occ(path, "account.ecdsa_pubkey", "classical key of "+address))
		inv.AddAsset(inventory.Asset{
			Ref:         "crypto/key/account-classical/" + inventory.Slug(address),
			Name:        "Account classical public key " + address,
			Kind:        inventory.KindMaterial,
			Material:    &inventory.Material{Type: "public-key", ID: address, AlgorithmRef: ecRef, SizeBits: len(ec) * 8, Format: "SEC 1"},
			Sources:     []string{src},
			Occurrences: []inventory.Occurrence{c.occ(path, "account.ecdsa_pubkey", "source: "+orDefault(a.ClassicalKeySource, "stored"))},
		})
	}
	inv.AddFact("qorescan:chain:account-pqc-status", fmt.Sprintf("%s: %s key, %s", address, a.KeyType, a.AlgorithmName))
	return nil
}

func (c *client) kemKey(ctx context.Context, inv *inventory.Inventory, address string) error {
	path := "/qorechain/pqc/v1/kem/" + url.PathEscape(address)
	var r struct {
		Found bool `json:"found"`
		Key   *struct {
			AlgorithmID   flexInt `json:"algorithm_id"`
			AlgorithmName string  `json:"algorithm_name"`
			PublicKey     string  `json:"public_key"`
		} `json:"key"`
	}
	if err := c.get(ctx, path, &r); err != nil {
		return err
	}
	if !r.Found || r.Key == nil {
		return nil
	}
	alg := nodehome.RegistryAlgorithm(r.Key.AlgorithmName, "kem", 0)
	occ := c.occ(path, "key", "KEM public key published by "+address)
	ref := inv.AddAlgorithm(alg, src, occ)
	pub := decodeB64(r.Key.PublicKey)
	inv.AddAsset(inventory.Asset{
		Ref:         "crypto/key/account-kem/" + inventory.Slug(address),
		Name:        "Account KEM public key " + address,
		Kind:        inventory.KindMaterial,
		Material:    &inventory.Material{Type: "public-key", ID: address, AlgorithmRef: ref, SizeBits: len(pub) * 8, Format: "raw"},
		Sources:     []string{src},
		Occurrences: []inventory.Occurrence{occ},
	})
	return nil
}

func decodeB64(s string) []byte {
	if s == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

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
