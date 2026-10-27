// SPDX-License-Identifier: Apache-2.0

// Command qorescan inventories the cryptography of a QoreChain deployment
// and writes a CycloneDX 1.6 CBOM.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/qorechain/qorescan/internal/app"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := (&app.App{Version: version}).Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
