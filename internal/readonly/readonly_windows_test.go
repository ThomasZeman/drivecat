//go:build windows

package readonly

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// fileState is everything about a file that drivecat must not change.
// Last-access time is left out on purpose: reading content may update it,
// which is accepted.
type fileState struct {
	attrs             uint32
	created, written  windows.Filetime
	sizeHigh, sizeLow uint32
	content           string
}

func stateOf(t *testing.T, path string) fileState {
	t.Helper()
	var d windows.Win32FileAttributeData
	if err := windows.GetFileAttributesEx(windows.StringToUTF16Ptr(path), windows.GetFileExInfoStandard,
		(*byte)(unsafePointer(&d))); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fileState{d.FileAttributes, d.CreationTime, d.LastWriteTime, d.FileSizeHigh, d.FileSizeLow, string(b)}
}

func tempFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "photo.jpg")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOpenReadsWithoutChanging(t *testing.T) {
	p := tempFile(t, "family photo bytes")
	before := stateOf(t, p)

	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	if err != nil || string(got) != "family photo bytes" {
		t.Fatalf("read %q, %v", got, err)
	}
	if _, err := f.Write([]byte("x")); err == nil {
		t.Error("write through a readonly handle succeeded")
	}
	if err := f.Truncate(0); err == nil {
		t.Error("truncate through a readonly handle succeeded")
	}
	f.Close()

	if after := stateOf(t, p); after != before {
		t.Errorf("file changed:\nbefore %+v\nafter  %+v", before, after)
	}
}

func TestOpenDoesNotBlockOthers(t *testing.T) {
	p := tempFile(t, "content")
	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// While drivecat reads, the owner can still write, rename and delete.
	if err := os.WriteFile(p, []byte("changed"), 0o644); err != nil {
		t.Errorf("write blocked: %v", err)
	}
	moved := p + ".moved"
	if err := os.Rename(p, moved); err != nil {
		t.Errorf("rename blocked: %v", err)
	}
	if err := os.Remove(moved); err != nil {
		t.Errorf("delete blocked: %v", err)
	}
}

func TestOpenRefusesDirectory(t *testing.T) {
	if _, err := Open(t.TempDir()); !errors.Is(err, ErrNotFile) {
		t.Fatalf("err = %v, want ErrNotFile", err)
	}
}

func TestOpenRefusesMissing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "missing")
	if _, err := Open(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want not-exist", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("Open created the file")
	}
}

func TestOpenRefusesOfflineFile(t *testing.T) {
	p := tempFile(t, "only in the cloud")
	if err := windows.SetFileAttributes(windows.StringToUTF16Ptr(p), windows.FILE_ATTRIBUTE_OFFLINE); err != nil {
		t.Skipf("cannot set the offline attribute here: %v", err)
	}
	if _, err := Open(p); !errors.Is(err, ErrNotLocal) {
		t.Fatalf("err = %v, want ErrNotLocal", err)
	}
}

func TestOpenRefusesSymlink(t *testing.T) {
	target := tempFile(t, "target")
	link := filepath.Join(t.TempDir(), "link.jpg")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks without Developer Mode or admin rights: %v", err)
	}
	if _, err := Open(link); !errors.Is(err, ErrReparsePoint) {
		t.Fatalf("err = %v, want ErrReparsePoint", err)
	}
}

func TestLongPath(t *testing.T) {
	for in, want := range map[string]string{
		`C:\a\b.jpg`:         `\\?\C:\a\b.jpg`,
		`\\nas\photos\a.jpg`: `\\?\UNC\nas\photos\a.jpg`,
		`\\?\C:\a`:           `\\?\C:\a`,
		`\\.\PhysicalDrive0`: `\\.\PhysicalDrive0`,
		`relative\a.jpg`:     `relative\a.jpg`,
	} {
		if got := longPath(in); got != want {
			t.Errorf("longPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOpenVeryLongPath(t *testing.T) {
	dir := t.TempDir()
	deep := dir
	for len(deep) < 300 {
		deep = filepath.Join(deep, "a-folder-name-of-forty-characters-length")
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Skipf("cannot create a long path here: %v", err)
	}
	p := filepath.Join(deep, "x.jpg")
	if err := os.WriteFile(p, []byte("deep"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Open(p)
	if err != nil {
		t.Fatalf("Open of a %d-character path: %v", len(p), err)
	}
	f.Close()
}

// Junctions need no special rights, unlike symlinks, so this always runs.
func TestOpenRefusesJunction(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J failed: %v: %s", err, out)
	}
	if _, err := Open(link); !errors.Is(err, ErrReparsePoint) {
		t.Fatalf("err = %v, want ErrReparsePoint", err)
	}
}
