// Command drivecat builds a catalogue of every file on a set of drives and
// network shares, to find duplicates and plan a cleaner structure.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/ThomasZeman/drivecat/internal/cli"
)

func main() {
	// Ctrl+C cancels the context, so a running scan can commit what it has
	// and mark itself aborted instead of dying mid-transaction.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
