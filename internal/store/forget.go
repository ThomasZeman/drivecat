package store

import (
	"context"
	"database/sql"
	"fmt"
)

// SourceContents counts what the catalogue holds for one source.
type SourceContents struct {
	Files, Bytes, Scans int64
}

// SourceContents counts the files, bytes and scans recorded for a source.
func (s *Store) SourceContents(ctx context.Context, id int64) (SourceContents, error) {
	return sourceContents(ctx, s.db, id)
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func sourceContents(ctx context.Context, q querier, id int64) (SourceContents, error) {
	var c SourceContents
	err := q.QueryRowContext(ctx, `
SELECT (SELECT count(*) FROM files WHERE source_id = ?1),
       (SELECT coalesce(sum(size), 0) FROM files WHERE source_id = ?1),
       (SELECT count(*) FROM scans WHERE source_id = ?1)`, id).Scan(&c.Files, &c.Bytes, &c.Scans)
	return c, err
}

// ForgetSource deletes a source from the catalogue with all its files and
// scans, in one transaction, and returns what was deleted. It changes only
// the database, never the drive or share itself.
func (s *Store) ForgetSource(ctx context.Context, id int64) (SourceContents, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SourceContents{}, err
	}
	defer tx.Rollback()
	c, err := sourceContents(ctx, tx, id)
	if err != nil {
		return SourceContents{}, err
	}
	// Children first: files reference scans, both reference the source.
	for _, q := range []string{
		"DELETE FROM files WHERE source_id = ?",
		"DELETE FROM scans WHERE source_id = ?",
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return SourceContents{}, err
		}
	}
	res, err := tx.ExecContext(ctx, "DELETE FROM sources WHERE id = ?", id)
	if err != nil {
		return SourceContents{}, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return SourceContents{}, err
	} else if n != 1 {
		return SourceContents{}, fmt.Errorf("no source with id %d", id)
	}
	return c, tx.Commit()
}
