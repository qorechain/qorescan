// SPDX-License-Identifier: Apache-2.0

// Package app implements the qorescan command line.
package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/qorechain/qorescan/internal/cbom"
	"github.com/qorechain/qorescan/internal/chain"
	"github.com/qorechain/qorescan/internal/inventory"
	"github.com/qorechain/qorescan/internal/nodehome"
	"github.com/qorechain/qorescan/internal/report"
	"github.com/qorechain/qorescan/internal/solidity"
	"github.com/qorechain/qorescan/internal/tlsscan"
)

// App holds the command's environment, so tests can run it in process.
type App struct {
	Version string
	Stdout  io.Writer
	Stderr  io.Writer
	// Now returns the BOM timestamp; nil means time.Now, or
	// SOURCE_DATE_EPOCH when that is set.
	Now func() time.Time
	// TLS overrides handshake options (tests use their own roots).
	TLS tlsscan.Options
}

// Exit codes.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
)

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

const usage = `qorescan: cryptographic inventory (CycloneDX 1.6 CBOM) of a QoreChain deployment

Usage:
  qorescan scan [--node-home DIR] [--network mainnet|testnet | --rest URL] [--address ADDR]...
                [--tls HOST:PORT]... [--solidity DIR]... [--out FILE]
  qorescan tls HOST:PORT... [--out FILE]
  qorescan solidity DIR... [--out FILE]
  qorescan report --framework finma|nis|dora --cbom FILE [--out FILE]
  qorescan template agility|questionnaire --cbom FILE [--out FILE]
  qorescan version

QoreScan only reads. It never reads private key values: from key files it
takes the key type and the public key. Output is an inventory aid, not a
certification or a legal opinion.

Run "qorescan <command> -h" for the flags of a command.
`

// Run executes the command line args (without the program name) and returns
// the exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	if a.Stdout == nil {
		a.Stdout = os.Stdout
	}
	if a.Stderr == nil {
		a.Stderr = os.Stderr
	}
	if len(args) == 0 {
		fmt.Fprint(a.Stderr, usage)
		return ExitUsage
	}
	var err error
	switch args[0] {
	case "scan":
		err = a.scan(ctx, args[1:])
	case "tls":
		err = a.tls(ctx, args[1:])
	case "solidity":
		err = a.solidity(args[1:])
	case "report":
		err = a.report(args[1:])
	case "template":
		err = a.template(args[1:])
	case "version", "--version", "-version":
		fmt.Fprintf(a.Stdout, "qorescan %s\n", a.version())
		return ExitOK
	case "help", "-h", "--help":
		fmt.Fprint(a.Stdout, usage)
		return ExitOK
	default:
		err = usageError{fmt.Sprintf("unknown command %q", args[0])}
	}
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	var ue usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(a.Stderr, "qorescan: %s\n\n%s", ue.msg, usage)
		return ExitUsage
	}
	fmt.Fprintf(a.Stderr, "qorescan: %v\n", err)
	return ExitError
}

func (a *App) version() string {
	if a.Version == "" {
		return "dev"
	}
	return a.Version
}

func (a *App) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	if s := os.Getenv("SOURCE_DATE_EPOCH"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return time.Unix(n, 0).UTC()
		}
	}
	return time.Now().UTC()
}

func (a *App) logger(verbose bool) func(string, ...any) {
	if !verbose {
		return func(string, ...any) {}
	}
	return func(format string, args ...any) {
		fmt.Fprintf(a.Stderr, "qorescan: "+format+"\n", args...)
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// parse parses flags that may appear before or after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("qorescan "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func (a *App) scan(ctx context.Context, args []string) error {
	fs := newFlags("scan", a.Stderr)
	home := fs.String("node-home", "", "node home directory (contains config/)")
	network := fs.String("network", "", "read live state from mainnet or testnet")
	rest := fs.String("rest", "", "REST base URL (overrides --network, for a local node or relay)")
	var addrs, tlsTargets, solDirs multi
	fs.Var(&addrs, "address", "account whose PQC key status is read (repeatable; needs --network or --rest)")
	fs.Var(&tlsTargets, "tls", "TLS endpoint HOST:PORT to handshake with (repeatable)")
	fs.Var(&solDirs, "solidity", "directory or .sol file to scan (repeatable)")
	includeDeps := fs.Bool("include-deps", false, "also scan node_modules and lib under Solidity directories")
	out := fs.String("out", "-", "CBOM output file (- for stdout)")
	name := fs.String("name", "", "name of the scanned deployment in the CBOM metadata")
	timeout := fs.Duration("timeout", 20*time.Second, "network timeout per request")
	verbose := fs.Bool("verbose", false, "log progress to stderr")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usageError{fmt.Sprintf("scan takes no positional arguments (got %q)", pos[0])}
	}
	restURL := *rest
	if restURL == "" && *network != "" {
		u, ok := chain.Networks[*network]
		if !ok {
			return usageError{fmt.Sprintf("--network must be mainnet or testnet (got %q)", *network)}
		}
		restURL = u
	}
	if len(addrs) > 0 && restURL == "" {
		return usageError{"--address needs --network or --rest"}
	}
	if *home == "" && restURL == "" && len(tlsTargets) == 0 && len(solDirs) == 0 {
		return usageError{"nothing to scan: give --node-home, --network/--rest, --tls or --solidity"}
	}
	logf := a.logger(*verbose)
	target := *name
	if target == "" {
		target = "QoreChain deployment"
		if *network != "" {
			target = "QoreChain " + *network
		}
	}
	inv := inventory.New(target)
	if *network != "" {
		inv.AddFact("qorescan:chain:network", *network)
	}
	if *home != "" {
		if err := nodehome.Scan(*home, inv, logf); err != nil {
			return err
		}
	}
	if restURL != "" {
		err := chain.Scan(ctx, inv, chain.Options{REST: restURL, Addresses: addrs, Timeout: *timeout, UserAgent: "qorescan/" + a.version(), Logf: logf})
		if err != nil {
			return err
		}
	}
	for _, t := range tlsTargets {
		if err := a.tlsOne(ctx, inv, t, "", *timeout, logf); err != nil {
			return err
		}
	}
	for _, d := range solDirs {
		if err := a.solOne(inv, d, *includeDeps, logf); err != nil {
			return err
		}
	}
	return a.writeCBOM(inv, *out)
}

func (a *App) tlsOne(ctx context.Context, inv *inventory.Inventory, target, sni string, timeout time.Duration, logf func(string, ...any)) error {
	opt := a.TLS
	opt.Timeout = timeout
	opt.Logf = logf
	if sni != "" {
		opt.ServerName = sni
	}
	return tlsscan.Scan(ctx, inv, target, opt)
}

func (a *App) solOne(inv *inventory.Inventory, dir string, deps bool, logf func(string, ...any)) error {
	res, err := solidity.Scan(dir, inv, solidity.Options{IncludeDependencies: deps, Logf: logf})
	if err != nil {
		return fmt.Errorf("solidity: %w", err)
	}
	if res.Files == 0 {
		inv.AddNote(inventory.SourceSolidity, "warning", "", "no .sol files found under a --solidity path")
	}
	inv.AddFact("qorescan:solidity:files", strconv.Itoa(res.Files))
	return nil
}

func (a *App) tls(ctx context.Context, args []string) error {
	fs := newFlags("tls", a.Stderr)
	out := fs.String("out", "-", "CBOM output file (- for stdout)")
	sni := fs.String("servername", "", "SNI server name (default: the host)")
	timeout := fs.Duration("timeout", 15*time.Second, "handshake timeout")
	verbose := fs.Bool("verbose", false, "log progress to stderr")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return usageError{"tls needs at least one HOST:PORT"}
	}
	inv := inventory.New("TLS endpoints")
	for _, t := range pos {
		if err := a.tlsOne(ctx, inv, t, *sni, *timeout, a.logger(*verbose)); err != nil {
			return err
		}
	}
	return a.writeCBOM(inv, *out)
}

func (a *App) solidity(args []string) error {
	fs := newFlags("solidity", a.Stderr)
	out := fs.String("out", "-", "CBOM output file (- for stdout)")
	deps := fs.Bool("include-deps", false, "also scan node_modules and lib")
	verbose := fs.Bool("verbose", false, "log progress to stderr")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return usageError{"solidity needs at least one directory or .sol file"}
	}
	inv := inventory.New("Solidity sources")
	for _, d := range pos {
		if err := a.solOne(inv, d, *deps, a.logger(*verbose)); err != nil {
			return err
		}
	}
	return a.writeCBOM(inv, *out)
}

func (a *App) readCBOM(path string) (*cbom.BOM, error) {
	if path == "" {
		return nil, usageError{"--cbom is required"}
	}
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, 256<<20))
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	return cbom.Decode(data)
}

func (a *App) report(args []string) error {
	fs := newFlags("report", a.Stderr)
	framework := fs.String("framework", "", "finma, nis or dora")
	in := fs.String("cbom", "", "CBOM file written by qorescan scan (- for stdin)")
	out := fs.String("out", "-", "Markdown output file (- for stdout)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *framework == "" {
		return usageError{"--framework is required (finma, nis or dora)"}
	}
	b, err := a.readCBOM(*in)
	if err != nil {
		return err
	}
	md, err := report.Report(b, strings.ToLower(*framework))
	if err != nil {
		return usageError{err.Error()}
	}
	return a.write(*out, []byte(md))
}

func (a *App) template(args []string) error {
	fs := newFlags("template", a.Stderr)
	in := fs.String("cbom", "", "CBOM file written by qorescan scan (- for stdin)")
	out := fs.String("out", "-", "Markdown output file (- for stdout)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError{"template needs one name: agility or questionnaire"}
	}
	b, err := a.readCBOM(*in)
	if err != nil {
		return err
	}
	md, err := report.Template(b, pos[0])
	if err != nil {
		return usageError{err.Error()}
	}
	return a.write(*out, []byte(md))
}

func (a *App) writeCBOM(inv *inventory.Inventory, out string) error {
	data, err := cbom.Encode(inv, cbom.Options{ToolVersion: a.version(), Time: a.now()})
	if err != nil {
		return err
	}
	return a.write(out, data)
}

func (a *App) write(out string, data []byte) error {
	if out == "" || out == "-" {
		_, err := a.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return err
	}
	return nil
}
