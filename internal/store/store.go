// Package store owns the SQLite database: opening it, keeping its schema
// current and the queries the commands need.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Store is an open drivecat database.
type Store struct {
	db *sql.DB
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// SchemaVersion reports how many migrations the database has applied.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v)
	return v, err
}

func (s *Store) migrate(ctx context.Context) error {
	current, err := s.SchemaVersion(ctx)
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if current > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this drivecat (%d): upgrade drivecat",
			current, len(migrations))
	}
	for v := current; v < len(migrations); v++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", v+1, err)
		}
		// PRAGMA does not take bound parameters; v is our own integer.
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", v+1)); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %d: %w", v+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", v+1, err)
		}
	}
	return nil
}

// Timestamp formats t the way every timestamp column stores it: UTC,
// RFC 3339 with nanoseconds, so equal instants compare equal as text.
func Timestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// FindSource looks a source up by fingerprint. found is false if there is
// none.
func (s *Store) FindSource(ctx context.Context, fingerprint string) (id int64, label string, found bool, err error) {
	err = s.db.QueryRowContext(ctx, "SELECT id, label FROM sources WHERE fingerprint = ?", fingerprint).
		Scan(&id, &label)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", false, nil
	}
	return id, label, err == nil, err
}

// SourceSummary is one row of the sources listing.
type SourceSummary struct {
	ID       int64
	Label    string
	Kind     string
	BusType  string
	FSType   string
	LastSeen string
	Files    int64
	Bytes    int64
}

// ListSources returns every source with its file count and total size,
// ordered by label.
func (s *Store) ListSources(ctx context.Context) ([]SourceSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT s.id, s.label, s.kind, coalesce(s.bus_type, ''), coalesce(s.fs_type, ''), s.last_seen,
       count(f.id), coalesce(sum(f.size), 0)
FROM sources s
LEFT JOIN files f ON f.source_id = s.id
GROUP BY s.id
ORDER BY s.label COLLATE NOCASE, s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SourceSummary
	for rows.Next() {
		var r SourceSummary
		if err := rows.Scan(&r.ID, &r.Label, &r.Kind, &r.BusType, &r.FSType, &r.LastSeen,
			&r.Files, &r.Bytes); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
