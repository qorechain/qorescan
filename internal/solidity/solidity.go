// SPDX-License-Identifier: Apache-2.0

// Package solidity finds cryptography in Solidity sources: signature
// recovery and verification (ecrecover, the QoreChain pqcVerify precompile,
// P-256 verification), hashing, and well-known cryptography libraries. It
// works on source text: comments and string literals are blanked before
// matching, so commented-out code is not reported.
package solidity

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/qorechain/qorescan/internal/catalog"
	"github.com/qorechain/qorescan/internal/inventory"
)

const src = inventory.SourceSolidity

// maxFileSize skips generated or flattened files that are unusually large.
const maxFileSize = 4 << 20

// Options configure a Solidity scan.
type Options struct {
	// IncludeDependencies also scans node_modules and lib directories.
	IncludeDependencies bool
	Logf                func(format string, args ...any)
}

// Result summarises a scan.
type Result struct {
	Files    int
	Findings int
}

type detector struct {
	re      *regexp.Regexp
	alg     string
	symbol  string
	context string
}

const (
	addrArg = `(?:[^,()]+(?:\([^()]*\))?)`
	hex01   = `(?:0x0*1|1)`
	hexA01  = `(?:0x0*[aA]01)`
	hexA02  = `(?:0x0*[aA]02)`
	hex100  = `(?:0x0*100)`
)

func callTo(addr string) []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`address\s*\(\s*` + addr + `\s*\)\s*\.\s*(?:staticcall|call)\b`),
		regexp.MustCompile(`\b(?:staticcall|call)\s*\(\s*` + addrArg + `\s*,\s*` + addr + `\s*,`),
	}
}

var detectors = func() []detector {
	var d []detector
	d = append(d, detector{regexp.MustCompile(`\becrecover\s*\(`), "ecdsa-secp256k1", "ecrecover", "ecrecover: ECDSA secp256k1 public key recovery (precompile 0x01)"})
	for _, re := range callTo(hex01) {
		d = append(d, detector{re, "ecdsa-secp256k1", "precompile 0x01", "direct call to the ecrecover precompile (0x01)"})
	}
	pqc := []*regexp.Regexp{
		regexp.MustCompile(`\bpqcVerify\s*\(`),
		regexp.MustCompile(`address\s*\(\s*` + hexA01 + `\s*\)`),
		regexp.MustCompile(`\b0x0{37}[aA]01\b`),
	}
	pqc = append(pqc, callTo(hexA01)...)
	for _, re := range pqc {
		d = append(d, detector{re, "ml-dsa-87", "pqcVerify", "QoreChain pqcVerify precompile (0x0A01): ML-DSA-87 signature verification"})
	}
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`\bpqcKeyStatus\s*\(`),
		regexp.MustCompile(`address\s*\(\s*` + hexA02 + `\s*\)`),
		regexp.MustCompile(`\b0x0{37}[aA]02\b`),
	} {
		d = append(d, detector{re, "ml-dsa-87", "pqcKeyStatus", "QoreChain pqcKeyStatus precompile (0x0A02): reads an account's registered ML-DSA-87 key"})
	}
	p256 := []*regexp.Regexp{
		regexp.MustCompile(`address\s*\(\s*` + hex100 + `\s*\)`),
		regexp.MustCompile(`\b0x0{37}100\b`),
		regexp.MustCompile(`\bP256\s*\.\s*(?:verify|verifyNative|verifySolidity|tryVerify)\w*\s*\(`),
	}
	p256 = append(p256, callTo(hex100)...)
	for _, re := range p256 {
		d = append(d, detector{re, "ecdsa-p256", "p256", "ECDSA P-256 verification (RIP-7212 precompile 0x100 or a P256 library)"})
	}
	d = append(d,
		detector{regexp.MustCompile(`\bECDSA\s*\.\s*(?:recover|tryRecover)\w*\s*\(`), "ecdsa-secp256k1", "ECDSA.recover", "ECDSA library recovery"},
		detector{regexp.MustCompile(`\busing\s+ECDSA\s+for\b`), "ecdsa-secp256k1", "using ECDSA", "ECDSA library attached to a type"},
		detector{regexp.MustCompile(`\bSignatureChecker\s*\.\s*isValid\w*\s*\(`), "ecdsa-secp256k1", "SignatureChecker", "ECDSA or ERC-1271 signature check"},
		detector{regexp.MustCompile(`\bRSA\s*\.\s*pkcs1\w*\s*\(`), "rsa", "RSA.pkcs1", "RSA PKCS#1 v1.5 signature verification"},
		detector{regexp.MustCompile(`\bkeccak256\s*\(`), "keccak-256", "keccak256", "Keccak-256 hash"},
		detector{regexp.MustCompile(`\bsha256\s*\(`), "sha-256", "sha256", "SHA-256 (precompile 0x02)"},
		detector{regexp.MustCompile(`\bripemd160\s*\(`), "ripemd-160", "ripemd160", "RIPEMD-160 (precompile 0x03)"},
	)
	return d
}()

type knownLib struct {
	match *regexp.Regexp
	ref   string
	group string
	name  string
	purl  string
	algs  []string
}

var libraries = []knownLib{
	{regexp.MustCompile(`openzeppelin[^"']*/utils/cryptography/ECDSA\.sol$`), "lib/openzeppelin/ECDSA", "@openzeppelin/contracts", "ECDSA", "pkg:npm/%40openzeppelin/contracts", []string{"ecdsa-secp256k1"}},
	{regexp.MustCompile(`openzeppelin[^"']*/utils/cryptography/SignatureChecker\.sol$`), "lib/openzeppelin/SignatureChecker", "@openzeppelin/contracts", "SignatureChecker", "pkg:npm/%40openzeppelin/contracts", []string{"ecdsa-secp256k1"}},
	{regexp.MustCompile(`openzeppelin[^"']*/utils/cryptography/P256\.sol$`), "lib/openzeppelin/P256", "@openzeppelin/contracts", "P256", "pkg:npm/%40openzeppelin/contracts", []string{"ecdsa-p256"}},
	{regexp.MustCompile(`openzeppelin[^"']*/utils/cryptography/RSA\.sol$`), "lib/openzeppelin/RSA", "@openzeppelin/contracts", "RSA", "pkg:npm/%40openzeppelin/contracts", []string{"rsa", "sha-256"}},
	{regexp.MustCompile(`openzeppelin[^"']*/utils/cryptography/(?:MessageHashUtils|EIP712)\.sol$`), "lib/openzeppelin/MessageHashUtils-EIP712", "@openzeppelin/contracts", "MessageHashUtils / EIP712", "pkg:npm/%40openzeppelin/contracts", []string{"keccak-256"}},
	{regexp.MustCompile(`solady[^"']*/utils/ECDSA\.sol$`), "lib/solady/ECDSA", "solady", "ECDSA", "pkg:npm/solady", []string{"ecdsa-secp256k1"}},
	{regexp.MustCompile(`solady[^"']*/utils/SignatureCheckerLib\.sol$`), "lib/solady/SignatureCheckerLib", "solady", "SignatureCheckerLib", "pkg:npm/solady", []string{"ecdsa-secp256k1"}},
	{regexp.MustCompile(`solady[^"']*/utils/P256\.sol$`), "lib/solady/P256", "solady", "P256", "pkg:npm/solady", []string{"ecdsa-p256"}},
	{regexp.MustCompile(`IQorePQC\.sol$`), "lib/qorechain/IQorePQC", "qorechain", "IQorePQC", "", []string{"ml-dsa-87"}},
}

var importRe = regexp.MustCompile(`\bimport\s+(?:[^"';]*?\s+from\s+)?["']([^"']+)["']`)

var skipDirs = map[string]bool{".git": true, "node_modules": true, "lib": true, "out": true, "cache": true, "artifacts": true, "typechain-types": true}

// Scan walks root for .sol files and records findings in inv.
func Scan(root string, inv *inventory.Inventory, opt Options) (Result, error) {
	logf := opt.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var res Result
	st, err := os.Stat(root)
	if err != nil {
		return res, err
	}
	walkRoot := root
	single := !st.IsDir()
	if single {
		walkRoot = filepath.Dir(root)
	}
	err = filepath.WalkDir(walkRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != walkRoot && !opt.IncludeDependencies && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if single && path != root {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".sol") || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(walkRoot, path)
		rel = filepath.ToSlash(rel)
		logf("scanning %s", rel)
		res.Files++
		res.Findings += scanFile(rel, data, inv)
		return nil
	})
	return res, err
}

func scanFile(rel string, data []byte, inv *inventory.Inventory) int {
	noComments, code := blank(data)
	lines := lineStarts(data)
	n := 0
	seen := map[string]bool{}
	for _, det := range detectors {
		for _, m := range det.re.FindAllStringIndex(code, -1) {
			if strings.HasSuffix(strings.TrimRight(code[:m[0]], " \t\r\n"), "function") {
				continue // a declaration, not a use
			}
			line := lineOf(lines, m[0])
			key := det.alg + "|" + det.symbol + "|" + rel + "|" + strconv.Itoa(line)
			if seen[key] {
				continue
			}
			seen[key] = true
			inv.AddAlgorithm(catalog.Get(det.alg), src, inventory.Occurrence{Location: rel, Line: line, Symbol: det.symbol, Context: det.context})
			n++
		}
	}
	for _, m := range importRe.FindAllStringSubmatchIndex(noComments, -1) {
		path := noComments[m[2]:m[3]]
		for _, lib := range libraries {
			if !lib.match.MatchString(path) {
				continue
			}
			line := lineOf(lines, m[0])
			occ := inventory.Occurrence{Location: rel, Line: line, Symbol: "import", Context: "imports " + path}
			var provides []string
			for _, a := range lib.algs {
				provides = append(provides, inv.AddAlgorithm(catalog.Get(a), src, occ))
			}
			inv.AddLibrary(inventory.Library{Ref: lib.ref, Name: lib.name, Group: lib.group, Purl: lib.purl, Occurrences: []inventory.Occurrence{occ}, Provides: provides})
			n++
		}
	}
	return n
}

// blank returns two copies of src with the same length and line structure:
// the first with comments replaced by spaces, the second with comments and
// string literal contents replaced by spaces.
func blank(src []byte) (string, string) {
	a := []byte(string(src))
	b := []byte(string(src))
	const (
		code = iota
		line
		block
		str
	)
	state := code
	var quote byte
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch state {
		case code:
			switch {
			case c == '/' && i+1 < len(src) && src[i+1] == '/':
				state = line
				a[i], b[i] = ' ', ' '
			case c == '/' && i+1 < len(src) && src[i+1] == '*':
				state = block
				a[i], a[i+1], b[i], b[i+1] = ' ', ' ', ' ', ' '
				i++
			case c == '"' || c == '\'':
				state, quote = str, c
			}
		case line:
			if c == '\n' {
				state = code
			} else {
				a[i], b[i] = ' ', ' '
			}
		case block:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				a[i], a[i+1], b[i], b[i+1] = ' ', ' ', ' ', ' '
				i++
				state = code
			} else if c != '\n' {
				a[i], b[i] = ' ', ' '
			}
		case str:
			switch {
			case c == '\\' && i+1 < len(src):
				b[i] = ' '
				if src[i+1] != '\n' {
					b[i+1] = ' '
				}
				i++
			case c == quote:
				state = code
			case c == '\n':
				state = code
			default:
				b[i] = ' '
			}
		}
	}
	return string(a), string(b)
}

func lineStarts(src []byte) []int {
	starts := []int{0}
	for i := 0; i < len(src); i++ {
		if src[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func lineOf(starts []int, off int) int {
	return sort.Search(len(starts), func(i int) bool { return starts[i] > off })
}
