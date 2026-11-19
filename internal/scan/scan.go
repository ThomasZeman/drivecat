// Package scan walks a drive or share and records every file with its
// SHA-256 in the database.
//
// Everything on the source is read through internal/readonly: directories
// are listed and files opened with read access only, links are never
// followed, and offline or cloud files are recorded without being read.
// A file that cannot be read is stored with its error and no checksum; the
// scan carries on.
package scan

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/ThomasZeman/drivecat/internal/readonly"
	"github.com/ThomasZeman/drivecat/internal/store"
	"github.com/ThomasZeman/drivecat/internal/volume"
)

// Options tune a scan.
type Options struct {
	// Label names a new source; for a known one it renames it if set.
	Label string
	// Workers is the number of files read at the same time; 0 picks one
	// for spinning or unknown disks and DefaultParallel otherwise.
	Workers int
	// Rehash reads every file again, even if size and modification time
	// match what an earlier scan recorded.
	Rehash bool
	// Progress, if set, is called every ProgressEvery with the counts so far.
	Progress      func(Stats)
	ProgressEvery time.Duration
	// Warn, if set, receives folders and links that were skipped. It is
	// called from more than one goroutine.
	Warn func(string)
	// File, if set, is called for every file as it is recorded: with its
	// checksum, or with Error set if it could not be read. reused tells a
	// checksum taken over from an earlier scan. It is called from one
	// goroutine only.
	File func(row store.FileRow, reused bool)
}

// DefaultParallel is the number of workers for SSDs and network shares.
const DefaultParallel = 4

// Stats counts what a scan did.
type Stats struct {
	SourceID    int64
	SourceLabel string
	NewSource   bool
	ScanID      int64
	Workers     int

	Files       int64 // files recorded
	Hashed      int64 // files read and hashed in this scan
	HashedBytes int64
	Reused      int64 // unchanged files whose checksum came from an earlier scan
	Errors      int64 // files recorded without a checksum
	SkippedDirs int64 // folders not entered: links, system folders, unreadable
	LastPath    string
	Elapsed     time.Duration
	Aborted     bool
}

// batchSize and flushEvery bound how much work an interrupted scan loses.
const (
	batchSize  = 1000
	flushEvery = 2 * time.Second
)

// Workers picks the default number of parallel readers for a source:
// several parallel reads make a spinning disk's head jump back and forth,
// so those get one; SSDs and shares get DefaultParallel.
func Workers(id *volume.Identity) int {
	if id.Kind == volume.KindDisk && (id.SeekPenalty == nil || *id.SeekPenalty) {
		return 1
	}
	return DefaultParallel
}

// Root is the path a scan of id starts at: the mount point and the folder
// below it, as Windows understands it.
func Root(id *volume.Identity) string {
	rel := strings.Trim(strings.ReplaceAll(id.RelRoot, "/", `\`), `\`)
	return joinWin(id.MountedAs, rel)
}

// Scan records every file below the path identified by id. It returns the
// counts even when it fails or is interrupted; an interrupted scan keeps
// what it stored and is marked aborted.
func Scan(ctx context.Context, st *store.Store, id *volume.Identity, opt Options) (Stats, error) {
	start := time.Now()
	stats := Stats{Workers: opt.Workers}
	if stats.Workers <= 0 {
		stats.Workers = Workers(id)
	}

	var err error
	stats.SourceID, stats.SourceLabel, stats.NewSource, err = st.UpsertSource(ctx, sourceInfo(id, opt.Label), start)
	if err != nil {
		return stats, err
	}
	relRoot := norm.NFC.String(id.RelRoot)
	stats.ScanID, err = st.StartScan(ctx, stats.SourceID, relRoot, id.MountedAs, start)
	if err != nil {
		return stats, err
	}

	r := &run{st: st, opt: opt, sourceID: stats.SourceID, stats: &stats}
	walkErr := r.run(ctx, Root(id), relRoot, stats.Workers)

	// Finish the scan record even when ctx is cancelled: that is exactly
	// the case where it must say aborted.
	stats.Aborted = walkErr != nil || ctx.Err() != nil
	status := store.ScanDone
	if stats.Aborted {
		status = store.ScanAborted
	}
	stats.Elapsed = time.Since(start)
	if err := st.FinishScan(context.WithoutCancel(ctx), stats.ScanID, status, time.Now()); err != nil && walkErr == nil {
		walkErr = err
	}
	if ctx.Err() != nil && (walkErr == nil || errors.Is(walkErr, ctx.Err())) {
		walkErr = errors.New("scan interrupted; the files read so far are stored, scan again to continue")
	}
	return stats, walkErr
}

func sourceInfo(id *volume.Identity, label string) store.SourceInfo {
	return store.SourceInfo{
		Kind: id.Kind, Fingerprint: id.Fingerprint, Label: label,
		BusType: id.BusType, DiskModel: id.DiskModel, DiskSerial: id.DiskSerial, DiskSize: id.DiskSize,
		PartitionID: id.PartitionID, FSType: id.FSType, FSSerial: id.FSSerial, FSLabel: id.FSLabel,
		SMBServer: id.SMBServer, SMBShare: id.SMBShare, MarkerID: id.MarkerID,
	}
}

// run is one scan in progress.
type run struct {
	st       *store.Store
	opt      Options
	sourceID int64
	stats    *Stats // written by the writer goroutine only
	skipped  atomic.Int64
}

// job is a file to read and hash.
type job struct {
	abs string
	row store.FileRow // RelPath, Size and MTime from the listing
}

type resultKind int

const (
	hashed resultKind = iota
	reused
	failed
)

type result struct {
	row  store.FileRow
	kind resultKind
}

// run walks root in one goroutine, hashes files in workers goroutines and
// writes the results in batches from the calling goroutine, which is the
// only one that touches stats.
func (r *run) run(ctx context.Context, root, relRoot string, workers int) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan job, 64)
	results := make(chan result, 256)

	var walkErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(jobs)
		walkErr = r.walkRoot(ctx, root, relRoot, jobs, results)
	}()
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1<<20)
			for j := range jobs {
				if res, ok := hashFile(ctx, j, buf); ok {
					results <- res
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	writeErr := r.write(ctx, results, cancel)
	if writeErr != nil {
		return writeErr
	}
	return walkErr
}

// write stores results in batches until results is closed. On a database
// error it cancels the scan and drains results, so no goroutine blocks.
func (r *run) write(ctx context.Context, results <-chan result, cancel func()) error {
	var batch []store.FileRow
	var writeErr error
	flush := func() {
		if writeErr == nil && len(batch) > 0 {
			// Store what was read even if the scan is being interrupted.
			writeErr = r.st.WriteFiles(context.WithoutCancel(ctx), r.sourceID, r.stats.ScanID, time.Now(), batch)
			if writeErr != nil {
				cancel()
			}
		}
		batch = batch[:0]
	}

	tick := time.NewTicker(flushEvery)
	defer tick.Stop()
	var progress <-chan time.Time
	if r.opt.Progress != nil && r.opt.ProgressEvery > 0 {
		pt := time.NewTicker(r.opt.ProgressEvery)
		defer pt.Stop()
		progress = pt.C
	}
	start := time.Now()

	for {
		select {
		case res, ok := <-results:
			if !ok {
				r.stats.SkippedDirs = r.skipped.Load()
				flush()
				return writeErr
			}
			if writeErr != nil {
				continue // draining after a failure
			}
			s := r.stats
			s.Files++
			s.LastPath = res.row.RelPath
			switch res.kind {
			case hashed:
				s.Hashed++
				s.HashedBytes += res.row.Size
			case reused:
				s.Reused++
			case failed:
				s.Errors++
			}
			if r.opt.File != nil {
				r.opt.File(res.row, res.kind == reused)
			}
			batch = append(batch, res.row)
			if len(batch) >= batchSize {
				flush()
			}
		case <-tick.C:
			flush()
		case <-progress:
			r.stats.Elapsed = time.Since(start)
			r.stats.SkippedDirs = r.skipped.Load()
			r.opt.Progress(*r.stats)
		}
	}
}

// skipDirs are folders that hold no files of the owner's: the recycle bin,
// Windows' own data, and the snapshot and recycle folders of NAS systems,
// which would repeat every file once per snapshot. Names are lower case.
var skipDirs = map[string]bool{
	"$recycle.bin":              true,
	"system volume information": true,
	"#snapshot":                 true, // Synology
	"#recycle":                  true, // Synology
	"@recycle":                  true, // QNAP
	"@recently-snapshot":        true, // QNAP
	".snapshot":                 true, // NetApp and others
	"~snapshot":                 true,
}

// skipRootDirs are skipped only directly in the source's root: the recycle
// bins of Windows XP and 9x, whose names could be an ordinary folder deeper
// down.
var skipRootDirs = map[string]bool{"recycler": true, "recycled": true}

func (r *run) warn(format string, args ...any) {
	if r.opt.Warn != nil {
		r.opt.Warn(fmt.Sprintf(format, args...))
	}
}

func (r *run) walkRoot(ctx context.Context, root, relRoot string, jobs chan<- job, results chan<- result) error {
	entries, err := readonly.ReadDir(root)
	if err != nil {
		return fmt.Errorf("cannot list %s: %w", root, err)
	}
	return r.walkEntries(ctx, root, relRoot, entries, jobs, results)
}

func (r *run) walk(ctx context.Context, abs, rel string, jobs chan<- job, results chan<- result) error {
	entries, err := readonly.ReadDir(abs)
	if err != nil {
		r.warn("skipped folder %s: %v", rel, unwrapPath(err))
		r.skippedDir()
		return nil
	}
	return r.walkEntries(ctx, abs, rel, entries, jobs, results)
}

// skippedDir counts a folder that was not entered. The walker counts, the
// writer copies the count into stats.
func (r *run) skippedDir() { r.skipped.Add(1) }

func (r *run) walkEntries(ctx context.Context, abs, rel string, entries []readonly.Entry, jobs chan<- job,
	results chan<- result) error {
	// Two names in one folder can normalize to the same NFC form (one
	// copied from a Mac, one not). A name that already is NFC keeps it; the
	// other keeps its original form, so neither overwrites the other in the
	// database, whatever order the listing has.
	raw := make(map[string]bool, len(entries))
	for _, e := range entries {
		raw[e.Name] = true
	}
	used := make(map[string]bool, len(entries))
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := norm.NFC.String(e.Name)
		if name != e.Name && (raw[name] || used[name]) {
			name = e.Name
		}
		used[name] = true
		childRel := joinRel(rel, name)
		childAbs := joinWin(abs, e.Name)
		lower := strings.ToLower(e.Name)

		switch {
		case e.BadName:
			r.warn("skipped %s: the name is not valid Unicode, so it cannot be opened by name", childRel)
			if e.IsDir {
				r.skippedDir()
			}
			continue
		case e.Device:
			r.warn("skipped %s: a device, not a file", childRel)
			continue
		case e.IsDir && e.Link:
			r.warn("skipped folder %s: a link or junction, not followed", childRel)
			r.skippedDir()
			continue
		case e.IsDir && (skipDirs[lower] || (rel == "/" && skipRootDirs[lower])):
			r.skippedDir()
			continue
		case e.IsDir && e.NotLocal:
			r.warn("skipped folder %s: its content is not local (offline or cloud)", childRel)
			r.skippedDir()
			continue
		case e.IsDir:
			if err := r.walk(ctx, childAbs, childRel, jobs, results); err != nil {
				return err
			}
			continue
		}

		row := store.FileRow{RelPath: childRel, Size: e.Size, MTime: store.Timestamp(e.ModTime)}
		switch {
		case e.Link:
			row.Error = readonly.ErrReparsePoint.Error()
		case e.NotLocal:
			row.Error = readonly.ErrNotLocal.Error()
		}
		if row.Error != "" {
			if !send(ctx, results, result{row: row, kind: failed}) {
				return ctx.Err()
			}
			continue
		}

		if !r.opt.Rehash {
			known, found, err := r.st.LookupFile(ctx, r.sourceID, childRel)
			if err != nil {
				return fmt.Errorf("look up %s: %w", childRel, err)
			}
			if found && known.SHA256 != nil && known.Size == row.Size && known.MTime == row.MTime {
				row.SHA256 = known.SHA256
				if !send(ctx, results, result{row: row, kind: reused}) {
					return ctx.Err()
				}
				continue
			}
		}
		select {
		case jobs <- job{abs: childAbs, row: row}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func send(ctx context.Context, ch chan<- result, res result) bool {
	select {
	case ch <- res:
		return true
	case <-ctx.Done():
		return false
	}
}

// ErrChanged means a file changed while it was being read, so its checksum
// would not match any version of it.
var ErrChanged = errors.New("file changed while it was being read")

// hashFile reads a file and returns its row. ok is false if the scan was
// interrupted mid-file; nothing is recorded for it then.
func hashFile(ctx context.Context, j job, buf []byte) (result, bool) {
	row := j.row
	fail := func(err error) (result, bool) {
		row.SHA256 = nil
		row.Error = unwrapPath(err).Error()
		return result{row: row, kind: failed}, true
	}

	f, err := readonly.Open(j.abs)
	if err != nil {
		return fail(err)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	// The handle is what is read: if the file changed since it was listed,
	// record what is actually hashed.
	row.Size, row.MTime = before.Size(), store.Timestamp(before.ModTime())

	h := sha256.New()
	n, err := io.CopyBuffer(h, ctxReader{ctx, f}, buf)
	if ctx.Err() != nil {
		return result{}, false
	}
	if err != nil {
		return fail(err)
	}
	after, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return fail(ErrChanged)
	}
	row.SHA256 = h.Sum(nil)
	return result{row: row, kind: hashed}, true
}

// ctxReader stops a long read when the scan is interrupted.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// unwrapPath drops the path from an error: the database stores the path in
// its own column, and the long \\?\ form only adds noise.
func unwrapPath(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// joinWin appends name to a Windows path, which may end in a separator
// (E:\) or not.
func joinWin(dir, name string) string {
	if name == "" {
		return dir
	}
	if strings.HasSuffix(dir, `\`) {
		return dir + name
	}
	return dir + `\` + name
}

// joinRel appends name to a source-relative path ("/" for the root).
func joinRel(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}
