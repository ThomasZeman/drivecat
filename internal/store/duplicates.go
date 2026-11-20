package store

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
)

// DuplicateCopy is one place where a duplicated content is stored.
type DuplicateCopy struct {
	SourceID int64  `json:"source_id"`
	Source   string `json:"source"`
	Path     string `json:"path"`
	MTime    string `json:"mtime"`
}

// Duplicate is a content that exists more than once, with every copy.
type Duplicate struct {
	SHA256 []byte          `json:"sha256"`
	Size   int64           `json:"size"`
	Extra  int64           `json:"extra_bytes"` // bytes beyond the first copy
	Copies []DuplicateCopy `json:"copies"`
}

// DuplicateFilter narrows Duplicates.
type DuplicateFilter struct {
	// SourceID, if not 0, keeps only contents with at least one copy on
	// that source. Copies on other sources are still listed.
	SourceID int64
	// MinSize keeps only files of at least this many bytes. Empty files are
	// always left out: they all share one checksum.
	MinSize int64
}

// Duplicates calls fn for every content stored more than once, largest
// extra bytes first, with its copies ordered by source and path. It streams
// the rows, so the full list never has to fit in memory.
func (s *Store) Duplicates(ctx context.Context, f DuplicateFilter, fn func(Duplicate) error) error {
	minSize := max(f.MinSize, 1)
	having := "count(*) > 1"
	args := []any{minSize}
	if f.SourceID != 0 {
		having += " AND sum(source_id = ?) > 0"
		args = append(args, f.SourceID)
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT f.sha256, f.size, g.extra, f.source_id, s.label, f.rel_path, f.mtime
FROM (
  SELECT sha256, (count(*) - 1) * max(size) AS extra
  FROM files
  WHERE sha256 IS NOT NULL AND size >= ?
  GROUP BY sha256
  HAVING `+having+`
) g
JOIN files f ON f.sha256 = g.sha256
JOIN sources s ON s.id = f.source_id
ORDER BY g.extra DESC, g.sha256, s.label COLLATE NOCASE, f.rel_path`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	var cur *Duplicate
	for rows.Next() {
		var sum []byte
		var size, extra int64
		var c DuplicateCopy
		if err := rows.Scan(&sum, &size, &extra, &c.SourceID, &c.Source, &c.Path, &c.MTime); err != nil {
			return err
		}
		if cur != nil && !bytes.Equal(cur.SHA256, sum) {
			if err := fn(*cur); err != nil {
				return err
			}
			cur = nil
		}
		if cur == nil {
			cur = &Duplicate{SHA256: sum, Size: size, Extra: extra}
		}
		cur.Copies = append(cur.Copies, c)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if cur != nil {
		return fn(*cur)
	}
	return nil
}

// ResolveSource finds a source by its id or by its label (case ignored). A
// label shared by several sources must be given as an id.
func (s *Store) ResolveSource(ctx context.Context, idOrLabel string) (int64, string, error) {
	if id, err := strconv.ParseInt(idOrLabel, 10, 64); err == nil {
		var label string
		if err := s.db.QueryRowContext(ctx, "SELECT label FROM sources WHERE id = ?", id).Scan(&label); err == nil {
			return id, label, nil
		}
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, label FROM sources WHERE label = ? COLLATE NOCASE ORDER BY id", idOrLabel)
	if err != nil {
		return 0, "", err
	}
	defer rows.Close()
	var ids []string
	var id int64
	var label string
	for rows.Next() {
		if err := rows.Scan(&id, &label); err != nil {
			return 0, "", err
		}
		ids = append(ids, strconv.FormatInt(id, 10))
	}
	if err := rows.Err(); err != nil {
		return 0, "", err
	}
	switch len(ids) {
	case 0:
		return 0, "", fmt.Errorf("no source %q: see drivecat sources", idOrLabel)
	case 1:
		return id, label, nil
	}
	return 0, "", fmt.Errorf("several sources are called %q: give the id instead (%s)", idOrLabel,
		strings.Join(ids, ", "))
}
