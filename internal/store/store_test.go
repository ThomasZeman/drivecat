package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "drivecat.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestOpenCreatesSchema(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()

	v, err := s.SchemaVersion(ctx)
	if err != nil || v != len(migrations) {
		t.Fatalf("schema version = %d, %v; want %d", v, err, len(migrations))
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

func TestOpenIsIdempotent(t *testing.T) {
	s, path := openTemp(t)
	s.Close()

	s2, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer s2.Close()
	if v, _ := s2.SchemaVersion(context.Background()); v != len(migrations) {
		t.Fatalf("schema version after reopen = %d, want %d", v, len(migrations))
	}
}

func TestRejectsNewerSchema(t *testing.T) {
	s, path := openTemp(t)
	if _, err := s.db.Exec("PRAGMA user_version = 999"); err != nil {
		t.Fatal(err)
	}
	s.Close()

	if s2, err := Open(context.Background(), path); err == nil {
		s2.Close()
		t.Fatal("Open accepted a database from a newer drivecat")
	}
}

func TestForeignKeysEnforced(t *testing.T) {
	s, _ := openTemp(t)
	now := Timestamp(time.Now())
	_, err := s.db.Exec(`INSERT INTO files (source_id, rel_path, size, mtime, scan_id, seen_at)
		VALUES (42, 'a.txt', 1, ?, 42, ?)`, now, now)
	if err == nil {
		t.Fatal("insert with unknown source_id succeeded; foreign keys are off")
	}
}

func TestListSources(t *testing.T) {
	s, _ := openTemp(t)
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

func mustExec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}
