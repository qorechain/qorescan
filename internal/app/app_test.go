// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/qorechain/qorescan/internal/cbom/schemacheck"
	"github.com/qorechain/qorescan/internal/fixture"
	"github.com/qorechain/qorescan/internal/tlsscan"
)

var update = flag.Bool("update", false, "rewrite golden files")

var fixedTime = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func run(t *testing.T, a *App, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	a.Stdout, a.Stderr = &out, &errb
	if a.Now == nil {
		a.Now = func() time.Time { return fixedTime }
	}
	if a.Version == "" {
		a.Version = "0.1.0-test"
	}
	code := a.Run(context.Background(), args)
	return code, out.String(), errb.String()
}

// fakeChain serves the chain package fixtures.
func fakeChain(t *testing.T) *httptest.Server {
	t.Helper()
	dir := filepath.Join("..", "chain", "testdata")
	routes := map[string]string{
		"/cosmos/base/tendermint/v1beta1/node_info":            "node_info.json",
		"/qorechain/pqc/v1/protocol_features":                  "protocol_features.json",
		"/qorechain/pqc/v1/params":                             "params.json",
		"/cosmos/base/tendermint/v1beta1/validatorsets/latest": "validatorsets.json",
		"/cosmos/evm/vm/v1/params":                             "evm_params.json",
		"/qorechain/pqc/v1/account/qor1fixtureaccount":         "account_found.json",
		"/qorechain/pqc/v1/kem/qor1fixtureaccount":             "kem_found.json",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := routes[r.URL.Path]
		if !ok {
			f = "not_implemented.json"
			w.WriteHeader(http.StatusNotImplemented)
		}
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Error(err)
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/app -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden file; run go test ./internal/app -update and review the diff", name)
	}
}

func validate(t *testing.T, data []byte) {
	t.Helper()
	if err := schemacheck.Validate(data); err != nil {
		t.Fatalf("CBOM fails the CycloneDX 1.6 schema: %v", err)
	}
	if err := schemacheck.Refs(data); err != nil {
		t.Fatalf("CBOM references: %v", err)
	}
}

// goldenScan scans the deterministic fixture home, the fake chain and the
// Solidity fixtures, with the chain URL normalised.
func goldenScan(t *testing.T) []byte {
	t.Helper()
	h := fixture.NewHome(t, fixture.Options{Deterministic: true})
	srv := fakeChain(t)
	code, out, errs := run(t, &App{}, "scan",
		"--node-home", h.Dir,
		"--rest", srv.URL, "--address", "qor1fixtureaccount",
		"--solidity", filepath.Join("..", "solidity", "testdata", "project"),
		"--name", "QoreChain fixture")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	// The chain URL has a random port, and the serial number is derived from
	// the content, so both are normalised.
	out = strings.ReplaceAll(out, srv.URL, "http://chain.test")
	out = regexp.MustCompile(`urn:uuid:[0-9a-f-]{36}`).ReplaceAllString(out, "urn:uuid:00000000-0000-5000-8000-000000000000")
	return []byte(out)
}

func TestGoldenCBOM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("golden files use forward-slash paths; covered on Linux and macOS")
	}
	data := goldenScan(t)
	validate(t, data)
	golden(t, "scan.cbom.json", data)
}

func TestGoldenReportsAndTemplates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("golden files use forward-slash paths; covered on Linux and macOS")
	}
	cbomPath := filepath.Join(t.TempDir(), "cbom.json")
	if err := os.WriteFile(cbomPath, goldenScan(t), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, fw := range []string{"finma", "nis", "dora"} {
		code, out, errs := run(t, &App{}, "report", "--framework", fw, "--cbom", cbomPath)
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", fw, code, errs)
		}
		checkContent(t, fw, out)
		if !strings.Contains(out, "not a certification") {
			t.Errorf("%s: disclaimer missing", fw)
		}
		golden(t, "report-"+fw+".md", []byte(out))
	}
	for _, tpl := range []string{"agility", "questionnaire"} {
		code, out, errs := run(t, &App{}, "template", tpl, "--cbom", cbomPath)
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", tpl, code, errs)
		}
		checkContent(t, tpl, out)
		if !strings.Contains(out, "To be completed") {
			t.Errorf("%s: nothing left to be completed", tpl)
		}
		golden(t, "template-"+tpl+".md", []byte(out))
	}
}

func TestQuestionnaireUnknownsStayOpen(t *testing.T) {
	// A CBOM with only a Solidity scan has no strategy, transport or
	// provider facts: those answers must stay open.
	code, out, _ := run(t, &App{}, "solidity", filepath.Join("..", "solidity", "testdata", "project"))
	if code != 0 {
		t.Fatal(code)
	}
	p := filepath.Join(t.TempDir(), "c.json")
	_ = os.WriteFile(p, []byte(out), 0o644)
	_, md, _ := run(t, &App{}, "template", "questionnaire", "--cbom", p)
	if n := strings.Count(md, "To be completed"); n < 5 {
		t.Errorf("expected at least 5 open answers, got %d:\n%s", n, md)
	}
	if strings.Contains(md, "hybrid signature mode") {
		t.Error("a fact that was not scanned was filled in")
	}
}

var forbidden = regexp.MustCompile(`(?i)quantum[- ]safe|quantum[- ]proof|\bcompliant\b|\bcertified\b|\x{2014}|\x{2013}`)

func checkContent(t *testing.T, name, s string) {
	t.Helper()
	if m := forbidden.FindString(s); m != "" {
		t.Errorf("%s contains forbidden wording %q", name, m)
	}
}

// TestPrivateKeyNeverInOutputOrLogs scans a fixture home whose key files
// and certificate bundle carry freshly generated private keys, with verbose
// logging, and checks that no encoding of those keys appears in the CBOM,
// the reports, the templates or the logs.
func TestPrivateKeyNeverInOutputOrLogs(t *testing.T) {
	h := fixture.NewHome(t, fixture.Options{RPCTLS: true})
	if len(h.Secrets) < 10 {
		t.Fatalf("fixture produced %d secrets", len(h.Secrets))
	}
	dir := t.TempDir()
	cbomPath := filepath.Join(dir, "cbom.json")
	var all strings.Builder
	code, out, errs := run(t, &App{}, "scan", "--node-home", h.Dir, "--verbose", "--out", cbomPath)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(errs, "reading key type and public key of config/priv_validator_key.json") {
		t.Fatalf("verbose log missing: %s", errs)
	}
	all.WriteString(out + errs)
	data, err := os.ReadFile(cbomPath)
	if err != nil {
		t.Fatal(err)
	}
	validate(t, data)
	all.Write(data)
	code, out, errs = run(t, &App{}, "scan", "--node-home", h.Dir, "--verbose")
	if code != 0 {
		t.Fatal(errs)
	}
	all.WriteString(out + errs)
	for _, fw := range []string{"finma", "nis", "dora"} {
		_, out, errs := run(t, &App{}, "report", "--framework", fw, "--cbom", cbomPath)
		all.WriteString(out + errs)
	}
	for _, tpl := range []string{"agility", "questionnaire"} {
		_, out, errs := run(t, &App{}, "template", tpl, "--cbom", cbomPath)
		all.WriteString(out + errs)
	}
	text := all.String()
	for i, s := range h.Secrets {
		if s != "" && strings.Contains(text, s) {
			t.Fatalf("private key material (secret %d) found in output or logs", i)
		}
	}
	if strings.Contains(text, "PRIVATE KEY") {
		t.Fatal("a PEM private key block reached the output")
	}
	if strings.Contains(text, h.Dir) {
		t.Fatal("absolute path of the node home in output")
	}
}

func TestTLSCommandSchemaValid(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "local.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	code, out, errs := run(t, &App{TLS: tlsscan.Options{Roots: roots}}, "tls", ln.Addr().String())
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	validate(t, []byte(out))
	if !strings.Contains(out, `"name": "X25519MLKEM768"`) || !strings.Contains(out, "verified against the system roots") {
		t.Errorf("unexpected TLS CBOM:\n%s", out)
	}
}

func TestSolidityCommandSchemaValid(t *testing.T) {
	code, out, errs := run(t, &App{}, "solidity", filepath.Join("..", "solidity", "testdata", "project"))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	validate(t, []byte(out))
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"nope"},
		{"scan"},
		{"scan", "--network", "devnet"},
		{"scan", "--address", "qor1x", "--node-home", "."},
		{"scan", "extra"},
		{"tls"},
		{"solidity"},
		{"report", "--cbom", "x.json"},
		{"template", "--cbom", "x.json"},
	}
	for _, c := range cases {
		if code, _, _ := run(t, &App{}, c...); code != ExitUsage {
			t.Errorf("%q: exit %d, want %d", c, code, ExitUsage)
		}
	}
	if code, out, _ := run(t, &App{}, "version"); code != 0 || out != "qorescan 0.1.0-test\n" {
		t.Errorf("version: %d %q", code, out)
	}
	if code, _, _ := run(t, &App{}, "report", "--framework", "sox", "--cbom", filepath.Join("testdata", "golden", "scan.cbom.json")); code != ExitUsage {
		t.Errorf("unknown framework: exit %d", code)
	}
	if code, _, _ := run(t, &App{}, "scan", "--node-home", t.TempDir()); code != ExitError {
		t.Errorf("home without config: exit %d", code)
	}
}

func TestFlagsAfterPositionals(t *testing.T) {
	out := filepath.Join(t.TempDir(), "s.json")
	code, _, errs := run(t, &App{}, "solidity", filepath.Join("..", "solidity", "testdata", "project"), "--out", out)
	if code != 0 {
		t.Fatal(errs)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal("flag after the positional argument was ignored")
	}
}

func TestSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1800000000")
	a := &App{}
	if got := a.now(); !got.Equal(time.Unix(1800000000, 0)) {
		t.Fatalf("now %v", got)
	}
}
