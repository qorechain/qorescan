// SPDX-License-Identifier: Apache-2.0

package solidity

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/qorechain/qorescan/internal/inventory"
)

func findings(inv *inventory.Inventory) map[string][]string {
	out := map[string][]string{}
	for _, a := range inv.Assets() {
		for _, o := range a.Occurrences {
			out[a.Ref] = append(out[a.Ref], fmt.Sprintf("%s:%d %s", o.Location, o.Line, o.Symbol))
		}
		sort.Strings(out[a.Ref])
	}
	return out
}

func TestDetections(t *testing.T) {
	inv := inventory.New("t")
	res, err := Scan("testdata/project", inv, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 3 {
		t.Fatalf("scanned %d files, want 3 (node_modules skipped)", res.Files)
	}
	got := findings(inv)
	want := map[string][]string{
		"crypto/algorithm/ecdsa-secp256k1": {
			"contracts/Verifier.sol:14 ecrecover",
			"contracts/Verifier.sol:18 ECDSA.recover",
			"contracts/Verifier.sol:31 precompile 0x01",
			"contracts/Verifier.sol:4 import",
			"contracts/Verifier.sol:9 using ECDSA",
		},
		"crypto/algorithm/ml-dsa-87": {
			"contracts/Verifier.sol:11 pqcVerify",
			"contracts/Verifier.sol:22 pqcVerify",
			"contracts/Verifier.sol:26 pqcVerify",
			"contracts/Verifier.sol:6 import",
		},
		"crypto/algorithm/ecdsa-p256": {"contracts/Verifier.sol:36 p256"},
		"crypto/algorithm/keccak-256": {"contracts/Verifier.sol:40 keccak256", "contracts/Verifier.sol:5 import"},
		"crypto/algorithm/sha-256":    {"contracts/Verifier.sol:40 sha256"},
		"crypto/algorithm/ripemd-160": {"contracts/Verifier.sol:40 ripemd160"},
	}
	for ref, w := range want {
		sort.Strings(w)
		if strings.Join(got[ref], "\n") != strings.Join(w, "\n") {
			t.Errorf("%s:\n got  %q\n want %q", ref, got[ref], w)
		}
	}
	for ref, g := range got {
		if _, ok := want[ref]; !ok {
			t.Errorf("unexpected %s: %q", ref, g)
		}
		for _, x := range g {
			if strings.Contains(x, "Negative.sol") || strings.Contains(x, "IQorePQC.sol") {
				t.Errorf("false positive %s", x)
			}
		}
	}
	libs := inv.Libraries()
	names := []string{}
	for _, l := range libs {
		names = append(names, l.Ref+"="+strings.Join(l.Provides, ","))
	}
	sort.Strings(names)
	wantLibs := []string{
		"lib/openzeppelin/ECDSA=crypto/algorithm/ecdsa-secp256k1",
		"lib/openzeppelin/MessageHashUtils-EIP712=crypto/algorithm/keccak-256",
		"lib/qorechain/IQorePQC=crypto/algorithm/ml-dsa-87",
	}
	if strings.Join(names, " ") != strings.Join(wantLibs, " ") {
		t.Errorf("libraries %q", names)
	}
}

func TestIncludeDependencies(t *testing.T) {
	inv := inventory.New("t")
	res, err := Scan("testdata/project", inv, Options{IncludeDependencies: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 4 {
		t.Fatalf("scanned %d files, want 4", res.Files)
	}
	found := false
	for _, x := range findings(inv)["crypto/algorithm/ecdsa-secp256k1"] {
		if strings.HasPrefix(x, "node_modules/") {
			found = true
		}
	}
	if !found {
		t.Error("dependency finding missing")
	}
}

func TestSingleFile(t *testing.T) {
	inv := inventory.New("t")
	res, err := Scan("testdata/project/contracts/Negative.sol", inv, Options{})
	if err != nil || res.Files != 1 || !inv.Empty() {
		t.Fatalf("res %+v err %v findings %v", res, err, findings(inv))
	}
}

func TestBlankKeepsLayout(t *testing.T) {
	src := "a // c\nb /* x\ny */ \"s\\\"t\" 'u'\n"
	nc, code := blank([]byte(src))
	if len(nc) != len(src) || len(code) != len(src) || strings.Count(code, "\n") != strings.Count(src, "\n") {
		t.Fatal("layout changed")
	}
	if strings.Contains(nc, "c") || !strings.Contains(nc, `"s\"t"`) || strings.Contains(code, "s\\\"t") || strings.Contains(code, "u") {
		t.Fatalf("blank: %q / %q", nc, code)
	}
}
