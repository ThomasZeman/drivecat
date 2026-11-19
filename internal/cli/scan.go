package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ThomasZeman/drivecat/internal/scan"
	"github.com/ThomasZeman/drivecat/internal/store"
	"github.com/ThomasZeman/drivecat/internal/volume"
)

// progressEvery is how often a running scan reports its counts.
const progressEvery = 5 * time.Second

func (e *env) runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	label := fs.String("label", "", "")
	workers := fs.Int("workers", 0, "")
	rehash := fs.Bool("rehash", false, "")
	verbose := fs.Bool("verbose", false, "")
	fs.BoolVar(verbose, "v", false, "")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return fmt.Errorf("%w: scan: %v", errUsage, err)
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: scan takes exactly one PATH", errUsage)
	}
	if *workers < 0 || *workers > 64 {
		return fmt.Errorf("%w: --workers must be between 1 and 64", errUsage)
	}
	opt := scan.Options{Label: *label, Workers: *workers, Rehash: *rehash}

	if server, ok := volume.ServerOnly(pos[0]); ok {
		return e.scanServer(server, opt, *verbose)
	}

	id, err := identifyFunc(pos[0])
	if err != nil {
		return err
	}
	if err := e.checkDBOutside(id.Fingerprint, id.RelRoot); err != nil {
		return err
	}
	s, err := e.openForScan()
	if err != nil {
		return err
	}
	defer s.Close()
	return e.scanOne(s, id, opt, *verbose)
}

// scanServer scans every share of a server, each as its own source. A new
// share is named after the --label prefix and its share name ("NAS" and
// photos make "NAS photos"); without --label, every share must be known
// already. One share failing does not stop the others; Ctrl+C does.
func (e *env) scanServer(server string, opt scan.Options, verbose bool) error {
	shares, err := listSharesFunc(server)
	if err != nil {
		return err
	}
	if len(shares) == 0 {
		return fmt.Errorf("\\\\%s offers no shares that drivecat can scan", server)
	}
	s, err := e.openForScan()
	if err != nil {
		return err
	}
	defer s.Close()

	// Identify every share first, so a missing label is reported before
	// anything is scanned rather than after hours of the first share.
	ids := make([]*volume.Identity, len(shares))
	var unknown []string
	for i, sh := range shares {
		id, err := identifyFunc(sh.Path)
		if err != nil {
			return fmt.Errorf("%s: %w", sh.Path, err)
		}
		if err := e.checkDBOutside(id.Fingerprint, id.RelRoot); err != nil {
			return err
		}
		ids[i] = id
		if _, _, found, err := s.FindSource(e.ctx, id.Fingerprint); err != nil {
			return err
		} else if !found {
			unknown = append(unknown, sh.Name)
		}
	}
	if len(unknown) > 0 && opt.Label == "" {
		return fmt.Errorf("%w: new shares on \\\\%s (%s): give a name prefix with --label, e.g. --label NAS",
			errUsage, server, strings.Join(unknown, ", "))
	}

	fmt.Fprintf(e.stdout, "\\\\%s: %d shares: %s\n", server, len(shares), shareNames(shares))
	prefix := opt.Label
	var failed []string
	for i, id := range ids {
		if e.ctx.Err() != nil {
			break
		}
		o := opt
		if prefix != "" {
			o.Label = prefix + " " + shares[i].Name
		}
		if err := e.scanOne(s, id, o, verbose); err != nil {
			fmt.Fprintf(e.stderr, "drivecat: %s: %v\n", shares[i].Path, err)
			failed = append(failed, shares[i].Name)
		}
	}
	if e.ctx.Err() != nil {
		return errors.New("scan interrupted; the files read so far are stored, scan again to continue")
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d of %d shares failed: %s", len(failed), len(shares), strings.Join(failed, ", "))
	}
	return nil
}

func shareNames(shares []volume.Share) string {
	names := make([]string, len(shares))
	for i, sh := range shares {
		names[i] = sh.Name
	}
	return strings.Join(names, ", ")
}

// openForScan opens the database for writing; it never creates one.
func (e *env) openForScan() (*store.Store, error) {
	s, err := store.Open(e.ctx, e.dbPath)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("no database at %s yet: create it with drivecat init", e.dbPath)
	}
	return s, err
}

// scanOne scans one drive, share or folder and prints its progress and
// summary.
func (e *env) scanOne(s *store.Store, id *volume.Identity, opt scan.Options, verbose bool) error {
	var mu sync.Mutex
	line := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(e.stderr, format+"\n", args...)
	}
	opt.ProgressEvery = progressEvery
	opt.Progress = func(st scan.Stats) {
		line("  %s  %s", progressLine(st), shorten(st.LastPath, 60))
	}
	opt.Warn = func(msg string) { line("  warning: %s", msg) }
	opt.File = func(row store.FileRow, reused bool) {
		switch {
		case row.Error != "":
			// Always shown: the summary only counts them.
			line("  error: %s: %s", row.RelPath, row.Error)
		case verbose:
			note := ""
			if reused {
				note = "  (unchanged)"
			}
			mu.Lock()
			fmt.Fprintf(e.stdout, "  %x  %10s  %s%s\n", row.SHA256, formatBytes(row.Size), row.RelPath, note)
			mu.Unlock()
		}
	}

	fmt.Fprintf(e.stdout, "Scanning %s\n", scan.Root(id))
	stats, err := scan.Scan(e.ctx, s, id, opt)
	if stats.ScanID != 0 {
		printScanSummary(e.stdout, stats)
	}
	return err
}

// checkDBOutside refuses a scan whose folder contains the database: drivecat
// would change the source it scans, and hash its own database while writing
// it. A database elsewhere on the same drive is allowed, with a warning.
func (e *env) checkDBOutside(fingerprint, relRoot string) error {
	dbID, err := identifyFunc(filepath.Dir(e.dbPath))
	if err != nil {
		return nil // no database folder yet; Open reports that
	}
	if dbID.Fingerprint != fingerprint {
		return nil
	}
	dbRel := strings.ToLower(dbID.RelRoot)
	root := strings.ToLower(strings.TrimSuffix(relRoot, "/"))
	if root == "" || dbRel == root || strings.HasPrefix(dbRel, root+"/") {
		return fmt.Errorf("the database %s is inside the folder being scanned: "+
			"put it on another drive with --db or DRIVECAT_DB", e.dbPath)
	}
	fmt.Fprintf(e.stderr, "warning: the database %s is on the drive being scanned; "+
		"drivecat writes only the database there\n", e.dbPath)
	return nil
}

func progressLine(st scan.Stats) string {
	rate := ""
	if secs := st.Elapsed.Seconds(); secs > 0 {
		rate = ", " + formatBytes(int64(float64(st.HashedBytes)/secs)) + "/s"
	}
	return fmt.Sprintf("%s files (%s unchanged), %s read, %s%s",
		group(st.Files), group(st.Reused), formatBytes(st.HashedBytes), plural(st.Errors, "error"), rate)
}

func printScanSummary(w io.Writer, st scan.Stats) {
	status := "Done"
	if st.Aborted {
		status = "Aborted"
	}
	source := fmt.Sprintf("%s (source %d)", st.SourceLabel, st.SourceID)
	if st.NewSource {
		source += ", new"
	}
	fmt.Fprintf(w, "%s: scan %d of %s, %d workers, %s\n", status, st.ScanID, source, st.Workers,
		st.Elapsed.Round(time.Second))
	fmt.Fprintf(w, "  %s\n", progressLine(st))
	fmt.Fprintf(w, "  %s files hashed, %s folders skipped\n", group(st.Hashed), group(st.SkippedDirs))
}

// group writes n with thousands separators: 1234567 -> 1,234,567.
func group(n int64) string {
	s := strconv.FormatInt(n, 10)
	if n < 0 {
		return "-" + group(-n)
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// shorten keeps the end of a long path, which is the part that changes.
func shorten(p string, max int) string {
	r := []rune(p)
	if len(r) <= max {
		return p
	}
	return "..." + string(r[len(r)-max+3:])
}

// plural writes n with its noun: 1 error, 2 errors.
func plural(n int64, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return group(n) + " " + noun + "s"
}
