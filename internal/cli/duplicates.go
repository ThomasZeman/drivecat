package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ThomasZeman/drivecat/internal/store"
)

func (e *env) runDuplicates(args []string) error {
	fs := flag.NewFlagSet("duplicates", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	source := fs.String("source", "", "")
	minSize := fs.String("min-size", "", "")
	asJSON := fs.Bool("json", false, "")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return fmt.Errorf("%w: duplicates: %v", errUsage, err)
	}
	if len(pos) != 0 {
		return fmt.Errorf("%w: duplicates takes no PATH; use --source to pick a drive or share", errUsage)
	}
	var filter store.DuplicateFilter
	if *minSize != "" {
		if filter.MinSize, err = parseSize(*minSize); err != nil {
			return fmt.Errorf("%w: --min-size: %v", errUsage, err)
		}
	}

	s, err := store.OpenReadOnly(e.ctx, e.dbPath)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no database at %s yet: create it with drivecat init", e.dbPath)
	}
	if err != nil {
		return err
	}
	defer s.Close()
	if *source != "" {
		if filter.SourceID, _, err = s.ResolveSource(e.ctx, *source); err != nil {
			return err
		}
	}

	var groups, extraCopies, extraBytes int64
	var enc *json.Encoder
	if *asJSON {
		// One JSON object per line, so a long list streams and stays easy
		// to filter.
		enc = json.NewEncoder(e.stdout)
	}
	err = s.Duplicates(e.ctx, filter, func(d store.Duplicate) error {
		groups++
		extraCopies += int64(len(d.Copies)) - 1
		extraBytes += d.Extra
		if enc != nil {
			return enc.Encode(d)
		}
		fmt.Fprintf(e.stdout, "%d copies of %s, %s extra, sha256 %x\n", len(d.Copies), formatBytes(d.Size),
			formatBytes(d.Extra), d.SHA256)
		for _, c := range d.Copies {
			fmt.Fprintf(e.stdout, "  %s  %s: %s\n", shortDate(c.MTime), c.Source, c.Path)
		}
		fmt.Fprintln(e.stdout)
		return nil
	})
	if err != nil {
		return err
	}
	if enc != nil {
		return nil
	}
	if groups == 0 {
		fmt.Fprintln(e.stdout, "No duplicates found.")
		return nil
	}
	fmt.Fprintf(e.stdout, "%s files exist more than once: %s extra copies, %s.\n",
		group(groups), group(extraCopies), formatBytes(extraBytes))
	return nil
}

// parseSize reads a size like 500, 64K, 1.5M or 2G (binary units, as
// drivecat prints them).
func parseSize(s string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	t = strings.TrimSuffix(strings.TrimSuffix(t, "B"), "I")
	mult := int64(1)
	if n := len(t); n > 0 {
		if i := strings.IndexByte("KMGT", t[n-1]); i >= 0 {
			mult = int64(1) << (10 * (i + 1))
			t = t[:n-1]
		}
	}
	f, err := strconv.ParseFloat(t, 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("%q is not a size like 500, 64K, 1.5M or 2G", s)
	}
	return int64(f * float64(mult)), nil
}
