package cli

import (
	"flag"
	"fmt"
	"io"
)

// runForget deletes a source from the catalogue. Without --yes it only shows
// what would be deleted. Only the database changes, never the drive or share.
func (e *env) runForget(args []string) error {
	fs := flag.NewFlagSet("forget", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return fmt.Errorf("%w: forget: %v", errUsage, err)
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: forget needs one source, by label or id (see drivecat sources)", errUsage)
	}

	s, err := e.openForScan()
	if err != nil {
		return err
	}
	defer s.Close()
	id, label, err := s.ResolveSource(e.ctx, pos[0])
	if err != nil {
		return err
	}

	if !*yes {
		c, err := s.SourceContents(e.ctx, id)
		if err != nil {
			return err
		}
		fmt.Fprintf(e.stdout, "This would remove source %d %q from the catalogue: %s (%s) and %s.\n",
			id, label, plural(c.Files, "file"), formatBytes(c.Bytes), plural(c.Scans, "scan"))
		fmt.Fprintln(e.stdout, "Nothing on the drive or share is touched. To go ahead, add --yes.")
		return nil
	}
	c, err := s.ForgetSource(e.ctx, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "Removed source %d %q from the catalogue: %s (%s) and %s.\n",
		id, label, plural(c.Files, "file"), formatBytes(c.Bytes), plural(c.Scans, "scan"))
	fmt.Fprintln(e.stdout, "Scanning it again adds it back as a new source, which needs --label.")
	return nil
}
