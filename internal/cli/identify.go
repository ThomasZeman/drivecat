package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/ThomasZeman/drivecat/internal/store"
	"github.com/ThomasZeman/drivecat/internal/volume"
)

// identifyFunc is volume.Identify, replaceable in tests.
var identifyFunc = volume.Identify

type identifyResult struct {
	*volume.Identity
	KnownSourceID    int64  `json:"known_source_id,omitempty"`
	KnownSourceLabel string `json:"known_source_label,omitempty"`
}

func (e *env) runIdentify(args []string) error {
	fs := flag.NewFlagSet("identify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	asJSON := fs.Bool("json", false, "")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return fmt.Errorf("%w: identify: %v", errUsage, err)
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: identify takes exactly one PATH", errUsage)
	}

	id, err := identifyFunc(pos[0])
	if err != nil {
		return err
	}
	res := identifyResult{Identity: id}

	// Look the source up read-only, and only if a database exists: identify
	// must neither create nor migrate one.
	s, err := store.OpenReadOnly(e.ctx, e.dbPath)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return err
	default:
		defer s.Close()
		srcID, label, found, err := s.FindSource(e.ctx, id.Fingerprint)
		if err != nil {
			return err
		}
		if found {
			res.KnownSourceID, res.KnownSourceLabel = srcID, label
		}
	}

	if *asJSON {
		enc := json.NewEncoder(e.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	return printIdentity(e.stdout, res)
}

func printIdentity(w io.Writer, r identifyResult) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(tw, "%s\t%s\n", k, v)
		}
	}
	id := r.Identity

	row("Kind", id.Kind)
	row("Fingerprint", id.Fingerprint)
	if r.KnownSourceID != 0 {
		row("Known as", fmt.Sprintf("%s (source %d)", r.KnownSourceLabel, r.KnownSourceID))
	} else {
		row("Known as", "not in the database yet")
	}
	row("Mounted as", id.MountedAs)
	row("Folder", id.RelRoot)

	if id.Kind == volume.KindSMB {
		row("Server", id.SMBServer)
		row("Share", id.SMBShare)
	} else {
		var disk []string
		for _, s := range []string{id.DiskModel, id.BusType} {
			if s != "" {
				disk = append(disk, s)
			}
		}
		if id.DiskSize > 0 {
			disk = append(disk, formatBytes(id.DiskSize))
		}
		if id.SeekPenalty != nil {
			disk = append(disk, map[bool]string{true: "spinning (HDD)", false: "no seek penalty (SSD)"}[*id.SeekPenalty])
		}
		if id.DiskNumber >= 0 {
			disk = append(disk, fmt.Sprintf("disk %d on this PC", id.DiskNumber))
		}
		row("Disk", strings.Join(disk, ", "))
		row("Disk serial", id.DiskSerial)
		row("Disk id", id.DiskID)
		if id.PartitionStyle != "" {
			row("Partition", fmt.Sprintf("%s, offset %s", id.PartitionStyle, formatBytes(id.PartitionOffset)))
		}
		row("Partition id", id.PartitionID)
		row("Volume", id.VolumeGUIDPath)
	}

	fsDesc := id.FSType
	if id.FSLabel != "" {
		fsDesc += fmt.Sprintf(" %q", id.FSLabel)
	}
	row("File system", fsDesc)
	row("FS serial", id.FSSerial)
	row("Marker", id.MarkerID)
	for _, w := range id.Warnings {
		row("Warning", w)
	}
	return tw.Flush()
}

// parseInterleaved parses flags that may come before, between or after the
// positional arguments, so "identify E:\ --json" works as well as
// "identify --json E:\". A lone "--" ends flag parsing.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var tail []string
	for i, a := range args {
		if a == "--" {
			args, tail = args[:i], args[i+1:]
			break
		}
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return append(pos, tail...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}
