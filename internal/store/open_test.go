package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateNeedsExistingFolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "typo")
	if s, err := Create(context.Background(), filepath.Join(dir, "drivecat.db"), false); err == nil {
		s.Close()
		t.Fatal("Create made a database in a folder that did not exist")
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("Create made the missing folder")
	}
}

func TestCreateMakesOnlyTheLastFolder(t *testing.T) {
	base := t.TempDir()
	s, err := Create(context.Background(), filepath.Join(base, "drivecat", "drivecat.db"), true)
	if err != nil {
		t.Fatalf("Create with makeFolder: %v", err)
	}
	s.Close()

	deep := filepath.Join(base, "a", "b", "drivecat.db")
	if s, err := Create(context.Background(), deep, true); err == nil {
		s.Close()
		t.Fatal("Create made more than one folder")
	}
	if _, err := os.Lstat(filepath.Join(base, "a")); !os.IsNotExist(err) {
		t.Fatal("Create made a parent folder of the database folder")
	}
}

func TestCreateRefusesExistingSideFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drivecat.db")
	writeFile(t, path+"-wal", "someone else's")
	if s, err := Create(context.Background(), path, false); err == nil {
		s.Close()
		t.Fatal("Create ignored an existing -wal file")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("Create made the database anyway")
	}
	if got := string(readFile(t, path+"-wal")); got != "someone else's" {
		t.Fatal("the -wal file was changed")
	}
}

func TestUNCPathsRefused(t *testing.T) {
	ctx := context.Background()
	for _, p := range []string{`\\localhost\C$\x\drivecat.db`, `\\?\C:\x\drivecat.db`, `\\.\C:\x\drivecat.db`} {
		if s, err := Create(ctx, p, false); err == nil {
			s.Close()
			t.Errorf("Create accepted %s", p)
		}
		if _, err := Open(ctx, p); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Open(%s): err = %v, want a refusal", p, err)
		}
	}
}

// The mode in the URI must reach SQLite: with mode=ro or rw it must not
// create a missing file, which a plain path DSN would do.
func TestModeReachesSQLite(t *testing.T) {
	for _, mode := range []string{"ro", "rw"} {
		path := filepath.Join(t.TempDir(), "missing.db")
		if s, err := open(path, mode, nil); err == nil {
			s.Close()
			t.Errorf("mode=%s opened a missing file", mode)
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("mode=%s created the file", mode)
		}
	}
	if d := dsn(`C:\x\drivecat.db`, "ro"); !strings.HasPrefix(d, "file:///C:/x/drivecat.db?") ||
		!strings.Contains(d, "mode=ro") {
		t.Errorf("dsn = %s", d)
	}
}

func TestOpenChecksItIsTheVerifiedFile(t *testing.T) {
	s, a := createTemp(t)
	s.Close()
	b := filepath.Join(t.TempDir(), "other.db")
	writeFile(t, b, "")
	other, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := open(a, "ro", other); err == nil {
		s.Close()
		t.Fatal("open accepted a file other than the verified one")
	}
}

func TestAuthorizerBlocksOtherFiles(t *testing.T) {
	s, path := createTemp(t)
	dir := filepath.Dir(path)
	target := filepath.Join(dir, "copy.db")

	for _, q := range []string{
		"ATTACH DATABASE '" + target + "' AS other",
		"VACUUM INTO '" + target + "'",
		"PRAGMA temp_store = 1",
		"PRAGMA temp_store_directory = '" + dir + "'",
	} {
		if _, err := s.db.Exec(q); err == nil {
			t.Errorf("%s succeeded", q)
		}
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Error("a second database file was created")
	}
	var ts int
	if err := s.db.QueryRow("PRAGMA temp_store").Scan(&ts); err != nil || ts != 2 {
		t.Errorf("temp_store = %d, %v; want 2 (memory)", ts, err)
	}
	// Normal work still runs, including transactions and the store's own
	// queries.
	if _, err := s.ListSources(context.Background()); err != nil {
		t.Errorf("ListSources: %v", err)
	}
}
