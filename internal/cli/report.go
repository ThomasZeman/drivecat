package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/ThomasZeman/drivecat/internal/store"
)

func (e *env) runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	asJSON := fs.Bool("json", false, "")
	top := fs.Int("top", 10, "")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return fmt.Errorf("%w: report: %v", errUsage, err)
	}
	if len(pos) != 0 {
		return fmt.Errorf("%w: report takes no PATH", errUsage)
	}
	if *top < 0 {
		return fmt.Errorf("%w: --top must be 0 or more", errUsage)
	}

	s, err := store.OpenReadOnly(e.ctx, e.dbPath)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no database at %s yet: create it with drivecat init", e.dbPath)
	}
	if err != nil {
		return err
	}
	defer s.Close()

	r, err := s.Report(e.ctx, *top)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(e.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	if len(r.Sources) == 0 {
		fmt.Fprintln(e.stdout, "No sources yet. Scan one with: drivecat scan PATH --label NAME")
		return nil
	}
	return printReport(e.stdout, r, *top)
}

func printReport(w io.Writer, r *store.Report, top int) error {
	o := r.Overall
	fmt.Fprintln(w, "All sources")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintf(tw, "  Files\t%s\t%s\t\n", group(o.Files), formatBytes(o.Bytes))
	fmt.Fprintf(tw, "  Unique content\t%s\t%s\t\n", group(o.UniqueFiles), formatBytes(o.UniqueBytes))
	fmt.Fprintf(tw, "  Extra copies\t%s\t%s\t\n", group(o.Files-o.UniqueFiles), formatBytes(o.Bytes-o.UniqueBytes))
	if o.Unreadable > 0 {
		fmt.Fprintf(tw, "  Without checksum\t%s\t\t\n", group(o.Unreadable))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(w, "\nPer source (only here: content found on no other source)")
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  SOURCE\tFILES\tSIZE\tCOPIES INSIDE\tONLY HERE\tONLY HERE SIZE\tNO CHECKSUM\tLAST SEEN")
	for _, s := range r.Sources {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s.Label, group(s.Files), formatBytes(s.Bytes),
			formatBytes(s.Bytes-s.UniqueBytes), group(s.OnlyHereFiles), formatBytes(s.OnlyHereBytes),
			group(s.Unreadable), shortDate(s.LastSeen))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	switch {
	case top == 0:
		return nil
	case len(r.Duplicates) == 0 && o.Files > o.UniqueFiles:
		fmt.Fprintln(w, "\nNo duplicates apart from empty files.")
		return nil
	case len(r.Duplicates) == 0:
		fmt.Fprintln(w, "\nNo duplicates found.")
		return nil
	}
	fmt.Fprintf(w, "\nLargest duplicates (%d)\n", len(r.Duplicates))
	for _, g := range r.Duplicates {
		fmt.Fprintf(w, "  %d copies of %s, %s extra, sha256 %x\n", g.Copies, formatBytes(g.Size),
			formatBytes(g.Spare), g.SHA256[:8])
		for _, p := range g.Places {
			fmt.Fprintf(w, "    %s\n", p)
		}
		if more := g.Copies - int64(len(g.Places)); more > 0 {
			fmt.Fprintf(w, "    and %d more\n", more)
		}
	}
	return nil
}

// shortDate keeps the date of an RFC 3339 timestamp.
func shortDate(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}
