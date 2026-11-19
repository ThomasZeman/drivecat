// Package cli parses the command line and runs drivecat's commands.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/ThomasZeman/drivecat/internal/store"
)

// Version is set at build time with -ldflags "-X github.com/ThomasZeman/drivecat/internal/cli.Version=...".
var Version = "dev"

const usage = `drivecat builds a catalogue of every file on your drives and shares.

Usage:
  drivecat [--db PATH] <command> [arguments]

Commands:
  init              create the database, or bring its schema up to date
  sources           list the drives and shares scanned so far
  identify PATH     show how drivecat recognizes the drive or share behind PATH
                    (--json for machine-readable output)
  scan PATH         scan PATH and record every file with its SHA-256
                    (--label NAME for a new drive or share, --workers N,
                    --rehash to read unchanged files again,
                    -v / --verbose to print every file with its SHA-256)
  report            show total versus unique files and bytes, per source what
                    exists nowhere else, and the largest duplicates
                    (--top N duplicates, default 10; --json)
  version           print the version

Global flags:
  --db PATH         database file (default: $DRIVECAT_DB, else %LOCALAPPDATA%\drivecat\drivecat.db)
`

// errUsage marks errors caused by a bad command line (exit code 2).
var errUsage = errors.New("usage error")

type env struct {
	ctx    context.Context
	dbPath string
	// defaultDB is set when dbPath is the default location, whose folder
	// init may create.
	defaultDB bool
	stdout    io.Writer
	stderr    io.Writer
}

// Run executes drivecat with args (without the program name) and returns
// the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	global := flag.NewFlagSet("drivecat", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	dbPath := global.String("db", "", "")
	help := global.Bool("help", false, "")
	global.BoolVar(help, "h", false, "")
	if err := global.Parse(args); err != nil {
		fmt.Fprintf(stderr, "drivecat: %v\n\n%s", err, usage)
		return 2
	}
	rest := global.Args()
	if *help || len(rest) == 0 || rest[0] == "help" {
		fmt.Fprint(stdout, usage)
		return 0
	}

	e := &env{ctx: ctx, stdout: stdout, stderr: stderr}
	cmd, cmdArgs := rest[0], rest[1:]
	var err error
	if cmd != "version" {
		e.dbPath, e.defaultDB, err = resolveDBPath(*dbPath)
	}
	switch {
	case err != nil:
	case cmd == "version":
		fmt.Fprintf(stdout, "drivecat %s\n", Version)
	default:
		err = e.dispatch(cmd, cmdArgs)
	}

	switch {
	case err == nil:
		return 0
	case errors.Is(err, errUsage):
		fmt.Fprintf(stderr, "drivecat: %v\n\n%s", err, usage)
		return 2
	default:
		fmt.Fprintf(stderr, "drivecat: %v\n", err)
		return 1
	}
}

func (e *env) dispatch(cmd string, args []string) error {
	switch cmd {
	case "init":
		return e.runInit(args)
	case "sources":
		return e.runSources(args)
	case "identify":
		return e.runIdentify(args)
	case "scan":
		return e.runScan(args)
	case "report":
		return e.runReport(args)
	}
	return fmt.Errorf("%w: unknown command %q", errUsage, cmd)
}

// resolveDBPath picks the database path: --db, else $DRIVECAT_DB, else
// %LOCALAPPDATA%\drivecat\drivecat.db. It must be absolute: a relative path
// would put the database wherever drivecat happens to run, possibly on a
// drive being scanned.
func resolveDBPath(flagValue string) (path string, isDefault bool, err error) {
	if flagValue != "" {
		if !filepath.IsAbs(flagValue) {
			return "", false, fmt.Errorf("%w: --db must be an absolute path, got %q", errUsage, flagValue)
		}
		return filepath.Clean(flagValue), false, nil
	}
	if p := os.Getenv("DRIVECAT_DB"); p != "" {
		if !filepath.IsAbs(p) {
			return "", false, fmt.Errorf("DRIVECAT_DB must be an absolute path, got %q", p)
		}
		return filepath.Clean(p), false, nil
	}
	base := os.Getenv("LOCALAPPDATA")
	if !filepath.IsAbs(base) {
		return "", false, errors.New("LOCALAPPDATA is not set to an absolute path: pass --db with an absolute path")
	}
	return filepath.Join(base, "drivecat", "drivecat.db"), true, nil
}

func noArgs(cmd string, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("%w: %s takes no arguments", errUsage, cmd)
	}
	return nil
}

func (e *env) runInit(args []string) error {
	if err := noArgs("init", args); err != nil {
		return err
	}
	// Create only where nothing exists; otherwise open, which verifies the
	// file is a drivecat database before migrating it.
	s, err := store.Open(e.ctx, e.dbPath)
	if errors.Is(err, store.ErrNotFound) {
		// Only the default folder is created; for --db and DRIVECAT_DB the
		// folder must exist, so a typo cannot create folders on a drive.
		s, err = store.Create(e.ctx, e.dbPath, e.defaultDB)
	}
	if err != nil {
		return err
	}
	defer s.Close()
	v, err := s.SchemaVersion(e.ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "Database %s is ready (schema version %d).\n", e.dbPath, v)
	return nil
}

func (e *env) runSources(args []string) error {
	if err := noArgs("sources", args); err != nil {
		return err
	}
	s, err := store.OpenReadOnly(e.ctx, e.dbPath)
	if errors.Is(err, store.ErrNotFound) {
		fmt.Fprintf(e.stdout, "No database at %s yet. Create it with: drivecat init\n", e.dbPath)
		return nil
	}
	if err != nil {
		return err
	}
	defer s.Close()
	rows, err := s.ListSources(e.ctx)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintln(e.stdout, "No sources yet. Scan one with: drivecat scan PATH --label NAME")
		return nil
	}
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tLABEL\tKIND\tBUS\tFS\tFILES\tSIZE\tLAST SEEN")
	for _, r := range rows {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			r.ID, r.Label, r.Kind, r.BusType, r.FSType, r.Files, formatBytes(r.Bytes), r.LastSeen)
	}
	return tw.Flush()
}

// formatBytes renders n in binary units (KiB, MiB, ...), matching what
// Windows Explorer shows for drive sizes.
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
