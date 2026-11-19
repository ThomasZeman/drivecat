//go:build windows

package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/ThomasZeman/drivecat/internal/readonly"
	"github.com/ThomasZeman/drivecat/internal/store"
	"github.com/ThomasZeman/drivecat/internal/volume"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// tree builds a source folder with the cases a scan must handle, and
// returns which files it must record with which content ("" content and
// ok=false for files recorded with an error).
func tree(t *testing.T) (root string, want map[string]string, offline bool) {
	root = t.TempDir()
	want = map[string]string{}
	add := func(rel, content string) {
		write(t, root, rel, content)
		want["/"+rel] = content
	}
	add("a.txt", "hello")
	add("empty.bin", "")
	add("sub/deep/b.txt", "world")
	// RECYCLER is only skipped in the root of a drive, and root is a
	// folder on the temp drive.
	add("RECYCLER/old.txt", "not in the drive root")
	add("Café.txt", "nfc")
	// The same name in NFD, as a Mac writes it: kept apart, in its own form.
	write(t, root, "Café.txt", "nfd")
	want["/Café.txt"] = "nfd"

	write(t, root, "$RECYCLE.BIN/deleted.txt", "skip")
	write(t, root, "System Volume Information/x", "skip")
	write(t, root, "sub/#snapshot/copy.txt", "skip")

	// A junction to a folder outside the source: not followed.
	outside := t.TempDir()
	write(t, outside, "elsewhere.txt", "must not be read")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(root, "link"), outside).
		CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}

	// A file marked offline, like a cloud placeholder: recorded, not read.
	write(t, root, "cloud.txt", "only online")
	p := windows.StringToUTF16Ptr(filepath.Join(root, "cloud.txt"))
	if err := windows.SetFileAttributes(p, windows.FILE_ATTRIBUTE_OFFLINE); err == nil {
		offline = true
	} else {
		t.Logf("cannot set the offline attribute here: %v", err)
		os.Remove(filepath.Join(root, "cloud.txt"))
	}
	return root, want, offline
}

func tempStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Create(context.Background(), filepath.Join(t.TempDir(), "drivecat.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func scanDir(t *testing.T, ctx context.Context, s *store.Store, root string, opt Options) (Stats, error) {
	t.Helper()
	id, err := volume.Identify(root)
	if err != nil {
		t.Fatal(err)
	}
	return Scan(ctx, s, id, opt)
}

// state is everything about the tree that a scan must leave alone. Last
// access times are left out: reading may update them, which is accepted.
func state(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		var a windows.Win32FileAttributeData
		if err := windows.GetFileAttributesEx(windows.StringToUTF16Ptr(p), windows.GetFileExInfoStandard,
			(*byte)(unsafePointer(&a))); err != nil {
			return err
		}
		v := []any{a.FileAttributes, a.CreationTime, a.LastWriteTime, a.FileSizeHigh, a.FileSizeLow}
		if d.Type().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			v = append(v, sha256.Sum256(b))
		}
		out[p] = fmt.Sprint(v...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestScanRecordsFilesAndChangesNothing(t *testing.T) {
	root, want, offline := tree(t)
	s := tempStore(t)
	before := state(t, root)

	var warnings []string
	stats, err := scanDir(t, context.Background(), s, root, Options{
		Label: "test", Warn: func(m string) { warnings = append(warnings, m) },
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if after := state(t, root); !equalMaps(before, after) {
		t.Errorf("the scan changed the source:\nbefore %v\nafter  %v", before, after)
	}

	rows, err := s.Files(context.Background(), stats.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	rel := relRootOf(t, root)
	got := map[string]store.FileRow{}
	for _, r := range rows {
		if !strings.HasPrefix(r.RelPath, rel+"/") {
			t.Fatalf("row %q is not below the scanned folder %q", r.RelPath, rel)
		}
		got[strings.TrimPrefix(r.RelPath, rel)] = r
	}

	for p, content := range want {
		r, ok := got[p]
		if !ok {
			t.Errorf("%s not recorded", p)
			continue
		}
		sum := sha256.Sum256([]byte(content))
		if r.Error != "" || !bytes.Equal(r.SHA256, sum[:]) || r.Size != int64(len(content)) {
			t.Errorf("%s: %+v, want size %d and sha256 %x", p, r, len(content), sum)
		}
		delete(got, p)
	}
	if offline {
		r, ok := got["/cloud.txt"]
		if !ok || r.SHA256 != nil || !strings.Contains(r.Error, "not local") {
			t.Errorf("offline file: %+v, %v; want recorded without checksum", r, ok)
		}
		delete(got, "/cloud.txt")
	}
	for p := range got {
		t.Errorf("unexpected row %s", p)
	}

	if !strings.Contains(strings.Join(warnings, "\n"), "link") {
		t.Errorf("no warning about the junction: %q", warnings)
	}
	wantFiles := int64(len(want))
	if offline {
		wantFiles++
	}
	if stats.Files != wantFiles || stats.Hashed != int64(len(want)) || stats.Reused != 0 || stats.Aborted {
		t.Errorf("stats = %+v", stats)
	}
	// $RECYCLE.BIN, System Volume Information, #snapshot, link
	if stats.SkippedDirs != 4 {
		t.Errorf("skipped %d folders, want 4", stats.SkippedDirs)
	}
	if st, _ := s.ScanStatus(context.Background(), stats.ScanID); st != store.ScanDone {
		t.Errorf("scan status %q, want done", st)
	}
}

func TestRescanReusesUnchangedFiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.txt", "one")
	write(t, root, "b.txt", "two")
	s := tempStore(t)
	ctx := context.Background()

	if _, err := scanDir(t, ctx, s, root, Options{Label: "test"}); err != nil {
		t.Fatal(err)
	}
	// A known source needs no label the second time.
	st, err := scanDir(t, ctx, s, root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Reused != 2 || st.Hashed != 0 || st.NewSource {
		t.Errorf("unchanged rescan: %+v", st)
	}

	write(t, root, "a.txt", "changed")
	later := time.Now().Add(time.Minute)
	os.Chtimes(filepath.Join(root, "a.txt"), later, later)
	if st, _ = scanDir(t, ctx, s, root, Options{}); st.Reused != 1 || st.Hashed != 1 {
		t.Errorf("rescan after a change: %+v", st)
	}
	if st, _ = scanDir(t, ctx, s, root, Options{Rehash: true}); st.Reused != 0 || st.Hashed != 2 {
		t.Errorf("rescan with Rehash: %+v", st)
	}

	rows, _ := s.Files(ctx, st.SourceID)
	sum := sha256.Sum256([]byte("changed"))
	for _, r := range rows {
		if strings.HasSuffix(r.RelPath, "/a.txt") && !bytes.Equal(r.SHA256, sum[:]) {
			t.Errorf("a.txt still has its old checksum")
		}
	}
}

func TestNewSourceNeedsLabel(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.txt", "x")
	if _, err := scanDir(t, context.Background(), tempStore(t), root, Options{}); err != store.ErrLabelRequired {
		t.Fatalf("err = %v, want ErrLabelRequired", err)
	}
}

func TestInterruptedScanIsMarkedAborted(t *testing.T) {
	root, _, _ := tree(t)
	s := tempStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Interrupt at the first warning (the junction), mid-walk.
	stats, err := scanDir(t, ctx, s, root, Options{Label: "test", Warn: func(string) { cancel() }})
	if err == nil || !stats.Aborted {
		t.Fatalf("err = %v, stats = %+v; want an aborted scan", err, stats)
	}
	if st, _ := s.ScanStatus(context.Background(), stats.ScanID); st != store.ScanAborted {
		t.Errorf("scan status %q, want aborted", st)
	}
}

func TestScanRefusesRootLink(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	stats, err := scanDir(t, context.Background(), tempStore(t), link, Options{Label: "test"})
	if err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("err = %v, want a refusal to follow the junction", err)
	}
	if stats.Files != 0 {
		t.Errorf("recorded %d files through a junction", stats.Files)
	}
}

func relRootOf(t *testing.T, root string) string {
	t.Helper()
	id, err := volume.Identify(root)
	if err != nil {
		t.Fatal(err)
	}
	return id.RelRoot
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestRecycleBinsOfOldWindowsSkippedOnlyInDriveRoot(t *testing.T) {
	r := &run{stats: &Stats{}}
	entries := []readonly.Entry{{Name: "RECYCLER", IsDir: true}, {Name: "Recycled", IsDir: true}}
	if err := r.walkEntries(context.Background(), `E:\`, "/", entries, nil, nil); err != nil {
		t.Fatal(err)
	}
	if n := r.skipped.Load(); n != 2 {
		t.Errorf("skipped %d folders in the drive root, want 2", n)
	}
}
