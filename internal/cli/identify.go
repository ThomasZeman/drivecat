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

// identifyFunc and listSharesFunc are replaceable in tests.
var (
	identifyFunc   = volume.Identify
	listSharesFunc = volume.ListShares
)

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

	if server, ok := volume.ServerOnly(pos[0]); ok {
		return e.identifyServer(server, *asJSON)
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

// shareResult is one share in identify's output for a server.
type shareResult struct {
	volume.Share
	Fingerprint      string `json:"fingerprint"`
	KnownSourceID    int64  `json:"known_source_id,omitempty"`
	KnownSourceLabel string `json:"known_source_label,omitempty"`
}

// identifyServer lists the shares a scan of the whole server would cover.
func (e *env) identifyServer(server string, asJSON bool) error {
	shares, err := listSharesFunc(server)
	if err != nil {
		return err
	}
	var s *store.Store
	switch st, err := store.OpenReadOnly(e.ctx, e.dbPath); {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return err
	default:
		s = st
		defer s.Close()
	}

	res := make([]shareResult, 0, len(shares))
	for _, sh := range shares {
		r := shareResult{Share: sh}
		if id, err := identifyFunc(sh.Path); err == nil {
			r.Fingerprint = id.Fingerprint
		}
		if s != nil && r.Fingerprint != "" {
			id, label, found, err := s.FindSource(e.ctx, r.Fingerprint)
			if err != nil {
				return err
			}
			if found {
				r.KnownSourceID, r.KnownSourceLabel = id, label
			}
		}
		res = append(res, r)
	}

	if asJSON {
		enc := json.NewEncoder(e.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	if len(res) == 0 {
		fmt.Fprintf(e.stdout, "\\\\%s offers no shares that drivecat can scan.\n", server)
		return nil
	}
	fmt.Fprintf(e.stdout, "\\\\%s shares %d folders; drivecat scan \\\\%s scans each as its own source.\n\n",
		server, len(res), server)
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SHARE\tKNOWN AS\tREMARK")
	for _, r := range res {
		known := "new"
		switch {
		case r.Fingerprint == "":
			known = "cannot open"
		case r.KnownSourceID != 0:
			known = fmt.Sprintf("%s (source %d)", r.KnownSourceLabel, r.KnownSourceID)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Path, known, r.Remark)
	}
	return tw.Flush()
}
