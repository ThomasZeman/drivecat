package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func createTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "drivecat.db")
	s, err := Create(context.Background(), path, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestCreateSchema(t *testing.T) {
	s, _ := createTemp(t)
	ctx := context.Background()

	v, err := s.SchemaVersion(ctx)
	if err != nil || v != len(migrations) {
		t.Fatalf("schema version = %d, %v; want %d", v, err, len(migrations))
	}
	var appID int64
	if err := s.db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil || appID != ApplicationID {
		t.Fatalf("application_id = %#x, %v", appID, err)
	}
	for _, table := range []string{"sources", "scans", "files"} {
		var n int
		err := s.db.QueryRowContext(ctx,
			"SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&n)
		if err != nil || n != 1 {
			t.Errorf("table %s: count %d, err %v", table, n, err)
		}
	}
}

func TestCreateRefusesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	writeFile(t, path, "")
	if s, err := Create(context.Background(), path, false); err == nil {
		s.Close()
		t.Fatal("Create took over an existing file")
	}
}

func TestReopen(t *testing.T) {
	s, path := createTemp(t)
	s.Close()

	s2, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s2.Close()
	if v, _ := s2.SchemaVersion(context.Background()); v != len(migrations) {
		t.Fatalf("schema version after reopen = %d, want %d", v, len(migrations))
	}
}

func TestOpenRefusesMissingWithoutCreating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	for name, open := range map[string]func(context.Context, string) (*Store, error){
		"Open": Open, "OpenReadOnly": OpenReadOnly,
	} {
		if _, err := open(context.Background(), path); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", name, err)
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s created the file", name)
		}
	}
}

func TestOpenRefusesForeignFilesUntouched(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.db")
	writeFile(t, empty, "")

	text := filepath.Join(dir, "notes.txt")
	writeFile(t, text, strings.Repeat("not a database\n", 20))

	// A real SQLite database that is not drivecat's, like a Lightroom catalog.
	foreign := filepath.Join(dir, "catalog.lrcat")
	db, err := sql.Open("sqlite", foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE photos (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	for _, path := range []string{empty, text, foreign} {
		before := readFile(t, path)
		for name, open := range map[string]func(context.Context, string) (*Store, error){
			"Open": Open, "OpenReadOnly": OpenReadOnly,
		} {
			if s, err := open(context.Background(), path); err == nil {
				s.Close()
				t.Errorf("%s accepted %s", name, filepath.Base(path))
			}
		}
		if !bytes.Equal(before, readFile(t, path)) {
			t.Errorf("%s was modified", filepath.Base(path))
		}
		for _, side := range []string{"-wal", "-shm", "-journal"} {
			if _, err := os.Lstat(path + side); err == nil {
				t.Errorf("%s%s was created", filepath.Base(path), side)
			}
		}
	}
}

func TestRelativePathRefused(t *testing.T) {
	ctx := context.Background()
	if s, err := Create(ctx, "rel.db", false); err == nil {
		s.Close()
		os.Remove("rel.db")
		t.Error("Create accepted a relative path")
	}
	if _, err := Open(ctx, "rel.db"); err == nil {
		t.Error("Open accepted a relative path")
	}
	if _, err := OpenReadOnly(ctx, `C:rel.db`); err == nil {
		t.Error("OpenReadOnly accepted a drive-relative path")
	}
}

func TestReadOnlyRefusesWrites(t *testing.T) {
	s, path := createTemp(t)
	s.Close()
	before := readFile(t, path)

	ro, err := OpenReadOnly(context.Background(), path)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	now := Timestamp(time.Now())
	if _, err := ro.db.Exec(`INSERT INTO sources (kind, fingerprint, label, first_seen, last_seen)
		VALUES ('disk', 'fp', 'x', ?, ?)`, now, now); err == nil {
		t.Error("insert through a read-only store succeeded")
	}
	if _, err := ro.ListSources(context.Background()); err != nil {
		t.Errorf("read through a read-only store failed: %v", err)
	}
	ro.Close()
	if !bytes.Equal(before, readFile(t, path)) {
		t.Error("read-only open modified the database file")
	}
}

func TestReadOnlyRefusesOldSchema(t *testing.T) {
	s, path := createTemp(t)
	mustExec(t, s, "PRAGMA user_version = 0")
	s.Close()
	if ro, err := OpenReadOnly(context.Background(), path); err == nil {
		ro.Close()
		t.Fatal("OpenReadOnly accepted an outdated schema")
	}
}

func TestRejectsNewerSchema(t *testing.T) {
	s, path := createTemp(t)
	mustExec(t, s, "PRAGMA user_version = 999")
	s.Close()

	if s2, err := Open(context.Background(), path); err == nil {
		s2.Close()
		t.Fatal("Open accepted a database from a newer drivecat")
	}
}

func TestForeignKeysEnforced(t *testing.T) {
	s, _ := createTemp(t)
	now := Timestamp(time.Now())
	_, err := s.db.Exec(`INSERT INTO files (source_id, rel_path, size, mtime, scan_id, seen_at)
		VALUES (42, 'a.txt', 1, ?, 42, ?)`, now, now)
	if err == nil {
		t.Fatal("insert with unknown source_id succeeded; foreign keys are off")
	}
}

func TestListSources(t *testing.T) {
	s, _ := createTemp(t)
	ctx := context.Background()

	got, err := s.ListSources(ctx)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty ListSources = %v, %v", got, err)
	}

	now := Timestamp(time.Now())
	mustExec(t, s, `INSERT INTO sources (id, kind, fingerprint, label, bus_type, fs_type, first_seen, last_seen)
		VALUES (1, 'disk', 'fp-b', 'b drive', 'USB', 'NTFS', ?, ?),
		       (2, 'smb',  'fp-a', 'A share', 'SMB', NULL,   ?, ?)`, now, now, now, now)
	mustExec(t, s, `INSERT INTO scans (id, source_id, root, mounted_as, started_at, status)
		VALUES (1, 1, '/', 'E:\', ?, 'done')`, now)
	mustExec(t, s, `INSERT INTO files (source_id, rel_path, size, mtime, scan_id, seen_at)
		VALUES (1, 'x', 10, ?, 1, ?), (1, 'y', 32, ?, 1, ?)`, now, now, now, now)

	got, err = s.ListSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Label != "A share" || got[1].Label != "b drive" {
		t.Fatalf("order by label (case-insensitive) broken: %+v", got)
	}
	if got[0].Files != 0 || got[1].Files != 2 || got[1].Bytes != 42 {
		t.Fatalf("counts wrong: %+v", got)
	}
}

func TestFindSource(t *testing.T) {
	s, _ := createTemp(t)
	ctx := context.Background()

	if _, _, found, err := s.FindSource(ctx, "disk:x"); err != nil || found {
		t.Fatalf("empty db: found %v, err %v", found, err)
	}
	now := Timestamp(time.Now())
	mustExec(t, s, `INSERT INTO sources (kind, fingerprint, label, first_seen, last_seen)
		VALUES ('disk', 'disk:x', 'WD 2TB black', ?, ?)`, now, now)
	id, label, found, err := s.FindSource(ctx, "disk:x")
	if err != nil || !found || id == 0 || label != "WD 2TB black" {
		t.Fatalf("got %d %q %v %v", id, label, found, err)
	}
}

func mustExec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
