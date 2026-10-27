// SPDX-License-Identifier: Apache-2.0

// Package nodehome inventories the cryptography configured in a QoreChain
// node home directory: config.toml, app.toml, genesis.json and the
// validator and node key files.
//
// Key files are read only for the key type and the public key. See
// keys.go for how private key bytes are kept out of every value QoreScan
// builds.
package nodehome

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/qorechain/qorescan/internal/catalog"
	"github.com/qorechain/qorescan/internal/certs"
	"github.com/qorechain/qorescan/internal/inventory"
)

// Logf receives progress messages.
type Logf func(format string, args ...any)

const src = inventory.SourceNodeHome

// Scan inventories the node home at home into inv.
func Scan(home string, inv *inventory.Inventory, logf Logf) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	st, err := os.Stat(home)
	if err != nil {
		return fmt.Errorf("node home: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("node home %s is not a directory", filepath.Base(home))
	}
	cfgDir := filepath.Join(home, "config")
	if _, err := os.Stat(cfgDir); err != nil {
		return errors.New("node home has no config directory")
	}
	s := &scanner{home: home, inv: inv, logf: logf}
	s.config()
	s.app()
	s.genesis()
	s.keyrings()
	return nil
}

type scanner struct {
	home string
	inv  *inventory.Inventory
	logf Logf
}

// rel returns path relative to the node home, for evidence. Absolute paths
// of the machine running the scan are never written.
func (s *scanner) rel(path string) string {
	if r, err := filepath.Rel(s.home, path); err == nil && !strings.HasPrefix(r, "..") {
		return filepath.ToSlash(r)
	}
	return filepath.Base(path)
}

// resolve resolves a path from config.toml: absolute, or relative to the
// node home.
func (s *scanner) resolve(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(s.home, p)
}

func (s *scanner) config() {
	path := filepath.Join(s.home, "config", "config.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		s.inv.AddNote(src, "warning", "config/config.toml", "config.toml not readable: %v", errText(err))
		return
	}
	s.logf("reading %s", s.rel(path))
	doc := parseTOML(data)
	loc := s.rel(path)

	// Consensus engine P2P transport. Its handshake is defined by the
	// engine, not by configuration: X25519 key agreement, Ed25519 node
	// authentication, HKDF-SHA256 key derivation and ChaCha20-Poly1305
	// framing.
	if v, ok := doc["p2p.laddr"]; ok {
		occ := inventory.Occurrence{Location: loc, Line: v.Line, Symbol: "p2p.laddr", Context: "peer-to-peer listener " + v.String() + "; handshake defined by the consensus engine"}
		refs := []string{
			s.inv.AddAlgorithm(catalog.Get("x25519"), src, occ),
			s.inv.AddAlgorithm(catalog.Get("ed25519"), src, occ),
			s.inv.AddAlgorithm(catalog.Get("hkdf-sha256"), src, occ),
			s.inv.AddAlgorithm(catalog.Get("chacha20-poly1305"), src, occ),
		}
		s.inv.AddAsset(inventory.Asset{
			Ref:         "crypto/protocol/p2p-secret-connection",
			Name:        "Consensus engine P2P secret connection",
			Kind:        inventory.KindProtocol,
			Protocol:    &inventory.Protocol{Type: "other", Refs: refs},
			Sources:     []string{src},
			Occurrences: []inventory.Occurrence{occ},
			Properties: []inventory.Property{
				{Name: "qorescan:protocol:handshake", Value: "station-to-station: ephemeral X25519, Ed25519 node key signature over a Merlin transcript"},
				{Name: "qorescan:protocol:configurable", Value: "no"},
				{Name: "qorescan:protocol:key-exchange", Value: "X25519"},
			},
		})
	}

	// RPC listener TLS.
	certFile, keyFile := doc["rpc.tls_cert_file"], doc["rpc.tls_key_file"]
	rpcTLS := certFile.String() != "" && keyFile.String() != ""
	if rpcTLS {
		p := certFile.String()
		if !filepath.IsAbs(p) {
			p = filepath.Join(s.home, "config", p)
		}
		s.certFile(p, inventory.Occurrence{Location: loc, Line: certFile.Line, Symbol: "rpc.tls_cert_file", Context: "certificate of the RPC HTTPS listener"})
		s.inv.AddNote(src, "info", loc, "RPC listener serves HTTPS; the key file named by rpc.tls_key_file was not opened")
	}
	if v, ok := doc["rpc.laddr"]; ok && !rpcTLS && exposed(v.String()) {
		s.inv.AddNote(src, "info", fmt.Sprintf("%s:%d", loc, v.Line), "RPC listener %s binds a non-loopback address without TLS configured on the node; if TLS is terminated by a proxy, scan that endpoint with `qorescan tls`", v.String())
	}

	// Validator key.
	if v, ok := doc["priv_validator_laddr"]; ok && v.String() != "" {
		s.inv.AddNote(src, "info", fmt.Sprintf("%s:%d", loc, v.Line), "validator signing is delegated to a remote signer at %s; its key type is not visible from the node home", v.String())
	}
	pvPath := "config/priv_validator_key.json"
	pvLine := 0
	if v, ok := doc["priv_validator_key_file"]; ok && v.String() != "" {
		pvPath, pvLine = v.String(), v.Line
	}
	s.validatorKey(s.resolve(pvPath), loc, pvLine)

	nkPath := "config/node_key.json"
	nkLine := 0
	if v, ok := doc["node_key_file"]; ok && v.String() != "" {
		nkPath, nkLine = v.String(), v.Line
	}
	s.nodeKey(s.resolve(nkPath), loc, nkLine)
}

func (s *scanner) app() {
	path := filepath.Join(s.home, "config", "app.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		s.inv.AddNote(src, "info", "config/app.toml", "app.toml not readable: %v", errText(err))
		return
	}
	s.logf("reading %s", s.rel(path))
	doc := parseTOML(data)
	loc := s.rel(path)

	certPath, keyPath := doc["tls.certificate-path"], doc["tls.key-path"]
	evmTLS := certPath.String() != "" && keyPath.String() != ""
	if evmTLS {
		s.certFile(s.resolve(certPath.String()), inventory.Occurrence{Location: loc, Line: certPath.Line, Symbol: "tls.certificate-path", Context: "certificate of the EVM JSON-RPC TLS listener"})
		s.inv.AddNote(src, "info", loc, "EVM JSON-RPC TLS is configured; the key file named by tls.key-path was not opened")
	}

	type listener struct{ enable, addr, name string }
	for _, l := range []listener{
		{"api.enable", "api.address", "REST API"},
		{"grpc.enable", "grpc.address", "gRPC"},
		{"json-rpc.enable", "json-rpc.address", "EVM JSON-RPC"},
		{"json-rpc.enable", "json-rpc.ws-address", "EVM JSON-RPC WebSocket"},
		{"svm-rpc.enable", "svm-rpc.address", "SVM JSON-RPC"},
	} {
		en, ok := doc[l.enable]
		if !ok || !en.Bool() {
			continue
		}
		a, ok := doc[l.addr]
		if !ok || !exposed(a.String()) {
			continue
		}
		if evmTLS && strings.HasPrefix(l.addr, "json-rpc.") {
			continue
		}
		s.inv.AddNote(src, "info", fmt.Sprintf("%s:%d", loc, a.Line), "%s listener %s binds a non-loopback address without TLS configured on the node; if TLS is terminated by a proxy, scan that endpoint with `qorescan tls`", l.name, a.String())
	}
}

func (s *scanner) certFile(path string, occ inventory.Occurrence) {
	list, err := certs.LoadPEMFile(path)
	if err != nil {
		s.inv.AddNote(src, "warning", occ.Location, "certificate file named by %s not usable: %v", occ.Symbol, errText(err))
		return
	}
	for _, c := range list {
		certs.Add(s.inv, c, certs.Options{Source: src, Occurrence: occ})
	}
}

func (s *scanner) validatorKey(path, cfgLoc string, cfgLine int) {
	var f ValidatorKeyFile
	if err := readKeyFile(path, &f); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.inv.AddNote(src, "info", s.rel(path), "no validator key file; the node is not a validator or uses a remote signer")
			return
		}
		s.inv.AddNote(src, "warning", s.rel(path), "validator key file not readable: %v", errText(err))
		return
	}
	s.logf("reading key type and public key of %s", s.rel(path))
	s.permissions(path)
	loc := s.rel(path)
	key, ok := catalog.KeyTypeName(f.PubKey.Type)
	occ := inventory.Occurrence{Location: loc, Symbol: "pub_key.type", Context: "validator consensus key type " + f.PubKey.Type}
	if !ok {
		s.inv.AddNote(src, "warning", loc, "unrecognised validator key type %q", f.PubKey.Type)
		return
	}
	algRef := s.inv.AddAlgorithm(catalog.Get(key), src, occ)
	if cfgLine > 0 {
		s.inv.AddAlgorithm(catalog.Get(key), src, inventory.Occurrence{Location: cfgLoc, Line: cfgLine, Symbol: "priv_validator_key_file", Context: "validator key file location"})
	}
	pub := publicKeyBytes(f.PubKey.Value)
	id := strings.ToUpper(f.Address)
	if id == "" && len(pub) > 0 {
		id = "pubkey:" + hex.EncodeToString(pub[:min(8, len(pub))])
	}
	s.inv.AddAsset(inventory.Asset{
		Ref:  "crypto/key/validator-consensus/" + inventory.Slug(id),
		Name: "Validator consensus public key",
		Kind: inventory.KindMaterial,
		Material: &inventory.Material{
			Type: "public-key", ID: id, AlgorithmRef: algRef, SizeBits: len(pub) * 8, Format: "base64 in JSON",
		},
		Sources:     []string{src},
		Occurrences: []inventory.Occurrence{{Location: loc, Symbol: "pub_key", Context: "public key and address read; the private key value was not decoded"}},
	})
	if pk, ok := catalog.KeyTypeName(f.PrivKey.Type); ok {
		s.inv.AddAsset(inventory.Asset{
			Ref:         "crypto/key/validator-consensus-private/" + inventory.Slug(id),
			Name:        "Validator consensus private key (file)",
			Kind:        inventory.KindMaterial,
			Material:    &inventory.Material{Type: "private-key", ID: id, AlgorithmRef: s.inv.AddAlgorithm(catalog.Get(pk), src), Format: "plaintext JSON file"},
			Sources:     []string{src},
			Occurrences: []inventory.Occurrence{{Location: loc, Symbol: "priv_key.type", Context: "only the key type name was read"}},
		})
	}
}

func (s *scanner) nodeKey(path, cfgLoc string, cfgLine int) {
	var f NodeKeyFile
	if err := readKeyFile(path, &f); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.inv.AddNote(src, "info", s.rel(path), "no node key file")
			return
		}
		s.inv.AddNote(src, "warning", s.rel(path), "node key file not readable: %v", errText(err))
		return
	}
	s.logf("reading key type of %s", s.rel(path))
	s.permissions(path)
	loc := s.rel(path)
	key, ok := catalog.KeyTypeName(f.PrivKey.Type)
	if !ok {
		s.inv.AddNote(src, "warning", loc, "unrecognised node key type %q", f.PrivKey.Type)
		return
	}
	occ := inventory.Occurrence{Location: loc, Symbol: "priv_key.type", Context: "node identity key type " + f.PrivKey.Type + "; only the type name was read"}
	algRef := s.inv.AddAlgorithm(catalog.Get(key), src, occ)
	if cfgLine > 0 {
		s.inv.AddAlgorithm(catalog.Get(key), src, inventory.Occurrence{Location: cfgLoc, Line: cfgLine, Symbol: "node_key_file", Context: "node key file location"})
	}
	s.inv.AddAsset(inventory.Asset{
		Ref:         "crypto/key/node-identity",
		Name:        "Node identity private key (file)",
		Kind:        inventory.KindMaterial,
		Material:    &inventory.Material{Type: "private-key", AlgorithmRef: algRef, Format: "plaintext JSON file"},
		Sources:     []string{src},
		Occurrences: []inventory.Occurrence{occ},
	})
}

// permissions notes key files that other users can read. Only file metadata
// is inspected.
func (s *scanner) permissions(path string) {
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	if mode := st.Mode().Perm(); mode&0o077 != 0 {
		s.inv.AddNote(src, "warning", s.rel(path), "key file permissions are %04o; group or other users can access it", mode)
	}
}

// keyrings notes keyring directories without opening them.
func (s *scanner) keyrings() {
	entries, err := os.ReadDir(s.home)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "keyring-") {
			s.inv.AddNote(src, "info", e.Name(), "account keyring directory present (%s backend); not opened", strings.TrimPrefix(e.Name(), "keyring-"))
		}
	}
}

// exposed reports whether a listen address binds beyond loopback.
func exposed(addr string) bool {
	a := addr
	if i := strings.Index(a, "://"); i >= 0 {
		a = a[i+3:]
	}
	host, _, err := net.SplitHostPort(a)
	if err != nil {
		host = a
	}
	switch strings.ToLower(host) {
	case "localhost", "":
		return host == ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	return !ip.IsLoopback()
}

// errText returns an error message without the file path, so notes never
// carry paths of the machine running the scan.
func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
