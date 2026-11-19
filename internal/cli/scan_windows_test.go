//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/ThomasZeman/drivecat/internal/volume"
)

// These tests scan temp folders only, never a real drive.

func TestScanAndSources(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "photo.jpg"), []byte("jpeg"), 0o644); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(t.TempDir(), "drivecat.db")
	if code, _, errOut := run(t, "--db", db, "init"); code != 0 {
		t.Fatalf("init: %s", errOut)
	}

	code, out, errOut := run(t, "--db", db, "scan", src)
	if code != 1 || !strings.Contains(errOut, "--label") {
		t.Errorf("scan of a new source without --label: code %d, stderr %q", code, errOut)
	}

	code, out, errOut = run(t, "--db", db, "scan", src, "--label", "Temp test")
	if code != 0 || !strings.Contains(out, "Done: scan") || !strings.Contains(out, "1 files hashed") {
		t.Fatalf("scan: code %d, out %q, stderr %q", code, out, errOut)
	}

	code, out, _ = run(t, "--db", db, "sources")
	if code != 0 || !strings.Contains(out, "Temp test") {
		t.Errorf("sources after scan: code %d, out %q", code, out)
	}
}

func TestScanNeedsDatabase(t *testing.T) {
	src := t.TempDir()
	db := filepath.Join(t.TempDir(), "drivecat.db")
	code, _, errOut := run(t, "--db", db, "scan", src, "--label", "x")
	if code != 1 || !strings.Contains(errOut, "drivecat init") {
		t.Errorf("code %d, stderr %q", code, errOut)
	}
	if _, err := os.Stat(db); err == nil {
		t.Error("scan created a database")
	}
}

func TestScanRefusesDatabaseInsideFolder(t *testing.T) {
	src := t.TempDir()
	db := filepath.Join(src, "drivecat.db")
	if code, _, errOut := run(t, "--db", db, "init"); code != 0 {
		t.Fatalf("init: %s", errOut)
	}
	code, _, errOut := run(t, "--db", db, "scan", src, "--label", "x")
	if code != 1 || !strings.Contains(errOut, "inside the folder being scanned") {
		t.Errorf("code %d, stderr %q", code, errOut)
	}
}

func TestScanUsageErrors(t *testing.T) {
	db := filepath.Join(t.TempDir(), "drivecat.db")
	for _, args := range [][]string{
		{"--db", db, "scan"},
		{"--db", db, "scan", "a", "b"},
		{"--db", db, "scan", t.TempDir(), "--workers", "-1"},
		{"--db", db, "scan", t.TempDir(), "--frobnicate"},
	} {
		if code, _, errOut := run(t, args...); code != 2 {
			t.Errorf("%v: code %d, stderr %q", args, code, errOut)
		}
	}
}

func TestScanShowsErrorsAndChecksums(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "photo.jpg"), []byte("jpeg"), 0o644); err != nil {
		t.Fatal(err)
	}
	cloud := filepath.Join(src, "cloud.txt")
	if err := os.WriteFile(cloud, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	offline := windows.SetFileAttributes(windows.StringToUTF16Ptr(cloud), windows.FILE_ATTRIBUTE_OFFLINE) == nil
	db := filepath.Join(t.TempDir(), "drivecat.db")
	run(t, "--db", db, "init")

	code, out, errOut := run(t, "--db", db, "scan", src, "--label", "x", "-v")
	if code != 0 {
		t.Fatalf("scan: code %d, stderr %q", code, errOut)
	}
	const jpegSum = "41e5787e9f28562d07b891b1816b492309d646c0f2829743fa4963a9f9cc1d61" // sha256("jpeg")
	if !strings.Contains(out, jpegSum) || !strings.Contains(out, "/photo.jpg") {
		t.Errorf("verbose output lacks the file and its checksum: %q", out)
	}
	if offline && !strings.Contains(errOut, "error: ") {
		t.Errorf("error not shown: %q", errOut)
	}
	if offline && !strings.Contains(errOut, "cloud.txt: file content is not local") {
		t.Errorf("error lacks path or reason: %q", errOut)
	}

	// Without -v, checksums are not printed, errors still are.
	code, out, errOut = run(t, "--db", db, "scan", src)
	if code != 0 || strings.Contains(out, "/photo.jpg") {
		t.Errorf("non-verbose scan: code %d, out %q", code, out)
	}
	if offline && !strings.Contains(errOut, "cloud.txt") {
		t.Errorf("error not shown without -v: %q", errOut)
	}
}

func TestScanServerScansEachShare(t *testing.T) {
	// Two temp folders stand in for the shares of a server.
	photos, backup := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(photos, "a.jpg"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(backup, "b.zip"), []byte("b"), 0o644)
	orig := listSharesFunc
	listSharesFunc = func(server string) ([]volume.Share, error) {
		if server != "nas" {
			t.Errorf("server %q, want nas", server)
		}
		return []volume.Share{{Name: "backup", Path: backup}, {Name: "photos", Path: photos}}, nil
	}
	t.Cleanup(func() { listSharesFunc = orig })
	// Both folders are on the same temp drive, so they would share one
	// fingerprint; real shares each have their own.
	origID := identifyFunc
	identifyFunc = func(p string) (*volume.Identity, error) {
		id, err := origID(p)
		if err == nil {
			id.Fingerprint = "smb:nas/" + filepath.Base(p)
		}
		return id, err
	}
	t.Cleanup(func() { identifyFunc = origID })

	db := filepath.Join(t.TempDir(), "drivecat.db")
	run(t, "--db", db, "init")

	code, _, errOut := run(t, "--db", db, "scan", `\\nas`)
	if code != 2 || !strings.Contains(errOut, "backup, photos") || !strings.Contains(errOut, "--label") {
		t.Errorf("new shares without --label: code %d, stderr %q", code, errOut)
	}

	code, out, errOut := run(t, "--db", db, "scan", `\\nas\`, "--label", "NAS")
	if code != 0 || strings.Count(out, "Done: scan") != 2 {
		t.Fatalf("scan: code %d, out %q, stderr %q", code, out, errOut)
	}
	_, out, _ = run(t, "--db", db, "sources")
	if !strings.Contains(out, "NAS backup") || !strings.Contains(out, "NAS photos") {
		t.Errorf("sources: %q", out)
	}

	// Known shares need no label again.
	if code, _, errOut := run(t, "--db", db, "scan", `\\nas`); code != 0 {
		t.Errorf("rescan: code %d, stderr %q", code, errOut)
	}

	code, out, _ = run(t, "--db", db, "identify", `\\nas`)
	if code != 0 || !strings.Contains(out, "NAS photos (source") {
		t.Errorf("identify server: code %d, out %q", code, out)
	}
}
