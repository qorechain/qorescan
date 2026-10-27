// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/qorechain/qorescan/internal/inventory"
)

// fakeNode serves the fixture responses. paramsServed toggles the
// /qorechain/pqc/v1/params route (older nodes answer 501).
func fakeNode(t *testing.T, paramsServed bool) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	file := func(name string) []byte {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	routes := map[string]string{
		"/cosmos/base/tendermint/v1beta1/node_info":            "node_info.json",
		"/qorechain/pqc/v1/protocol_features":                  "protocol_features.json",
		"/cosmos/base/tendermint/v1beta1/validatorsets/latest": "validatorsets.json",
		"/cosmos/evm/vm/v1/params":                             "evm_params.json",
		"/qorechain/pqc/v1/account/qor1fixtureaccount":         "account_found.json",
		"/qorechain/pqc/v1/account/qor1nokey":                  "account_missing.json",
		"/qorechain/pqc/v1/kem/qor1fixtureaccount":             "kem_found.json",
		"/qorechain/pqc/v1/kem/qor1nokey":                      "account_missing.json",
	}
	if paramsServed {
		routes["/qorechain/pqc/v1/params"] = "params.json"
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("non-GET request %s", r.Method)
		}
		seen = append(seen, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if f, ok := routes[r.URL.Path]; ok {
			_, _ = w.Write(file(f))
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write(file("not_implemented.json"))
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func facts(inv *inventory.Inventory) string {
	var b strings.Builder
	for _, f := range inv.Facts {
		b.WriteString(f.Name + "=" + f.Value + "\n")
	}
	return b.String()
}

func TestScanFixtureNode(t *testing.T) {
	srv, seen := fakeNode(t, true)
	inv := inventory.New("t")
	err := Scan(context.Background(), inv, Options{REST: srv.URL, Addresses: []string{"qor1fixtureaccount", "qor1nokey"}})
	if err != nil {
		t.Fatal(err)
	}
	f := facts(inv)
	for _, want := range []string{
		"qorescan:chain:id=qorechain-diana",
		"qorescan:chain:pqc:hybrid-signature-mode=required",
		"qorescan:chain:pqc:default-migration-blocks=1000000",
		"qorescan:chain:protocol-feature=pqc-sign-bytes-v2",
		"qorescan:chain:protocol-features=3 enabled at height 123456 (2 PQC-related listed)",
		"qorescan:chain:evm:active-precompile=pqcVerify (0x0000000000000000000000000000000000000a01)",
		"qorescan:chain:account-pqc-status=qor1fixtureaccount: hybrid key, dilithium5",
		"qorescan:chain:account-pqc-status=qor1nokey: no PQC key registered",
	} {
		if !strings.Contains(f, want+"\n") {
			t.Errorf("missing fact %s in\n%s", want, f)
		}
	}
	if strings.Contains(f, "pqc-future-switch") {
		t.Error("a staged, disabled switch was reported as enabled")
	}
	m := map[string]*inventory.Asset{}
	for _, a := range inv.Assets() {
		m[a.Ref] = a
	}
	pk := m["crypto/key/account-pqc/qor1fixtureaccount"]
	if pk == nil || pk.Material.SizeBits != 2592*8 || pk.Material.AlgorithmRef != "crypto/algorithm/ml-dsa-87" {
		t.Fatalf("account PQC key %+v", pk)
	}
	if ec := m["crypto/key/account-classical/qor1fixtureaccount"]; ec == nil || ec.Material.SizeBits != 33*8 {
		t.Fatalf("account classical key %+v", ec)
	}
	if kem := m["crypto/key/account-kem/qor1fixtureaccount"]; kem == nil || kem.Material.AlgorithmRef != "crypto/algorithm/ml-kem-1024" {
		t.Fatalf("KEM key %+v", kem)
	}
	if v := m["crypto/key/active-validators/ed25519"]; v == nil || v.Properties[0].Value != "3" {
		t.Fatalf("validator set %+v", v)
	}
	for _, ref := range []string{"crypto/algorithm/ecdsa-p256", "crypto/algorithm/keccak-256", "crypto/algorithm/ecdsa-secp256k1"} {
		if m[ref] == nil {
			t.Errorf("missing %s", ref)
		}
	}
	for _, p := range *seen {
		if strings.Contains(p, "..") {
			t.Errorf("unexpected path %s", p)
		}
	}
}

func TestParamsNotServedIsANote(t *testing.T) {
	srv, _ := fakeNode(t, false)
	inv := inventory.New("t")
	if err := Scan(context.Background(), inv, Options{REST: srv.URL}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range inv.Notes {
		if strings.Contains(n.Text, "pqc params: route not served") {
			found = true
		}
	}
	if !found {
		t.Fatalf("notes %+v", inv.Notes)
	}
	if strings.Contains(facts(inv), "hybrid-signature-mode") {
		t.Error("hybrid mode reported without the params route")
	}
}

func TestUnreachableNodeFails(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	err := Scan(context.Background(), inventory.New("t"), Options{REST: url, Timeout: 2 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "no query succeeded") {
		t.Fatalf("err %v", err)
	}
}

func TestInvalidREST(t *testing.T) {
	for _, u := range []string{"", "ftp://x", "not a url"} {
		if err := Scan(context.Background(), inventory.New("t"), Options{REST: u}); err == nil {
			t.Errorf("REST %q accepted", u)
		}
	}
}

func TestAddressIsPathEscaped(t *testing.T) {
	srv, seen := fakeNode(t, true)
	_ = Scan(context.Background(), inventory.New("t"), Options{REST: srv.URL, Addresses: []string{"../../evil"}})
	for _, p := range *seen {
		if strings.HasPrefix(p, "/evil") || p == "/qorechain/evil" {
			t.Fatalf("address escaped the route: %s", p)
		}
	}
}

// TestLive reads the public networks. It runs only with QORE_LIVE_TEST=1.
// QORE_LIVE_REST_MAINNET / QORE_LIVE_REST_TESTNET override the endpoints,
// for example with a local relay where outbound HTTPS is not available.
func TestLive(t *testing.T) {
	if os.Getenv("QORE_LIVE_TEST") != "1" {
		t.Skip("set QORE_LIVE_TEST=1 to read the public networks")
	}
	for _, n := range []struct{ name, env, chainID string }{
		{"mainnet", "QORE_LIVE_REST_MAINNET", "qorechain-vladi"},
		{"testnet", "QORE_LIVE_REST_TESTNET", "qorechain-diana"},
	} {
		t.Run(n.name, func(t *testing.T) {
			rest := os.Getenv(n.env)
			if rest == "" {
				rest = Networks[n.name]
			}
			inv := inventory.New(n.name)
			if err := Scan(context.Background(), inv, Options{REST: rest, Timeout: 30 * time.Second}); err != nil {
				t.Fatal(err)
			}
			f := facts(inv)
			if !strings.Contains(f, "qorescan:chain:id="+n.chainID+"\n") {
				t.Errorf("chain id not %s:\n%s", n.chainID, f)
			}
			if !strings.Contains(f, "qorescan:chain:protocol-feature=pqc-sign-bytes-v2\n") {
				t.Errorf("pqc-sign-bytes-v2 not enabled:\n%s", f)
			}
			if _, ok := inv.Asset("crypto/key/active-validators/ed25519"); !ok {
				t.Error("validator set not read")
			}
		})
	}
}
