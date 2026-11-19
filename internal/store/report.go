package store

import (
	"context"
	"database/sql"
)

// Totals counts files and bytes. Unique counts each content (checksum)
// once, however many copies exist.
type Totals struct {
	Files       int64 `json:"files"`
	Bytes       int64 `json:"bytes"`
	UniqueFiles int64 `json:"unique_files"`
	UniqueBytes int64 `json:"unique_bytes"`
	Unreadable  int64 `json:"unreadable"` // files without a checksum
}

// SourceReport is one source in the report.
type SourceReport struct {
	ID       int64  `json:"id"`
	Label    string `json:"label"`
	Kind     string `json:"kind"`
	LastSeen string `json:"last_seen"`
	Totals
	// OnlyHere counts files whose content exists on no other source: losing
	// this source would lose them.
	OnlyHereFiles int64 `json:"only_here_files"`
	OnlyHereBytes int64 `json:"only_here_bytes"`
}

// DuplicateGroup is one content that exists more than once.
type DuplicateGroup struct {
	SHA256 []byte   `json:"sha256"`
	Size   int64    `json:"size"`
	Copies int64    `json:"copies"`
	Spare  int64    `json:"spare_bytes"` // bytes beyond the first copy
	Places []string `json:"places"`      // "label: /path", at most placesPerGroup
}

// Report is the duplicate analysis over everything recorded.
type Report struct {
	Overall    Totals           `json:"overall"`
	Sources    []SourceReport   `json:"sources"`
	Duplicates []DuplicateGroup `json:"largest_duplicates"`
}

// placesPerGroup limits how many locations a duplicate group lists.
const placesPerGroup = 5

// Report computes totals overall and per source, and the top duplicate
// groups by spare bytes. Empty files are counted but never listed as
// duplicates: they all share one checksum.
func (s *Store) Report(ctx context.Context, top int) (*Report, error) {
	r := &Report{}
	if err := s.db.QueryRowContext(ctx, `
SELECT count(sha256), coalesce(sum(CASE WHEN sha256 IS NOT NULL THEN size END), 0),
       count(*) - count(sha256)
FROM files`).Scan(&r.Overall.Files, &r.Overall.Bytes, &r.Overall.Unreadable); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `
SELECT count(*), coalesce(sum(size), 0)
FROM (SELECT max(size) AS size FROM files WHERE sha256 IS NOT NULL GROUP BY sha256)`).
		Scan(&r.Overall.UniqueFiles, &r.Overall.UniqueBytes); err != nil {
		return nil, err
	}

	var err error
	if r.Sources, err = s.sourceReports(ctx); err != nil {
		return nil, err
	}
	if r.Duplicates, err = s.largestDuplicates(ctx, top); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) sourceReports(ctx context.Context) ([]SourceReport, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT s.id, s.label, s.kind, s.last_seen,
       count(f.sha256), coalesce(sum(CASE WHEN f.sha256 IS NOT NULL THEN f.size END), 0),
       count(f.id) - count(f.sha256)
FROM sources s
LEFT JOIN files f ON f.source_id = s.id
GROUP BY s.id
ORDER BY s.label COLLATE NOCASE, s.id`)
	if err != nil {
		return nil, err
	}
	var out []SourceReport
	byID := map[int64]*SourceReport{}
	for rows.Next() {
		var r SourceReport
		if err := rows.Scan(&r.ID, &r.Label, &r.Kind, &r.LastSeen, &r.Files, &r.Bytes, &r.Unreadable); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		byID[out[i].ID] = &out[i]
	}

	// Unique content within each source.
	if err := s.eachRow(ctx, `
SELECT source_id, count(*), coalesce(sum(size), 0)
FROM (SELECT source_id, max(size) AS size FROM files WHERE sha256 IS NOT NULL GROUP BY source_id, sha256)
GROUP BY source_id`, func(id, n, bytes int64) {
		if r := byID[id]; r != nil {
			r.UniqueFiles, r.UniqueBytes = n, bytes
		}
	}); err != nil {
		return nil, err
	}

	// Content found on no other source, counted once per content.
	if err := s.eachRow(ctx, `
SELECT source_id, count(*), coalesce(sum(size), 0)
FROM (
  SELECT f.source_id, max(f.size) AS size
  FROM files f
  WHERE f.sha256 IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM files g WHERE g.sha256 = f.sha256 AND g.source_id != f.source_id)
  GROUP BY f.source_id, f.sha256)
GROUP BY source_id`, func(id, n, bytes int64) {
		if r := byID[id]; r != nil {
			r.OnlyHereFiles, r.OnlyHereBytes = n, bytes
		}
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// eachRow runs a query whose rows are three integers.
func (s *Store) eachRow(ctx context.Context, query string, fn func(a, b, c int64)) error {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var a, b, c int64
		if err := rows.Scan(&a, &b, &c); err != nil {
			return err
		}
		fn(a, b, c)
	}
	return rows.Err()
}

func (s *Store) largestDuplicates(ctx context.Context, top int) ([]DuplicateGroup, error) {
	if top <= 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT sha256, max(size) AS size, count(*) AS copies, (count(*) - 1) * max(size) AS spare
FROM files
WHERE sha256 IS NOT NULL AND size > 0
GROUP BY sha256
HAVING count(*) > 1
ORDER BY spare DESC, sha256
LIMIT ?`, top)
	if err != nil {
		return nil, err
	}
	var groups []DuplicateGroup
	for rows.Next() {
		var g DuplicateGroup
		if err := rows.Scan(&g.SHA256, &g.Size, &g.Copies, &g.Spare); err != nil {
			rows.Close()
			return nil, err
		}
		groups = append(groups, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range groups {
		places, err := s.places(ctx, groups[i].SHA256)
		if err != nil {
			return nil, err
		}
		groups[i].Places = places
	}
	return groups, nil
}

func (s *Store) places(ctx context.Context, sha256 []byte) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT s.label, f.rel_path
FROM files f JOIN sources s ON s.id = f.source_id
WHERE f.sha256 = ?
ORDER BY s.label COLLATE NOCASE, f.rel_path
LIMIT ?`, sha256, placesPerGroup)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var label, path sql.NullString
		if err := rows.Scan(&label, &path); err != nil {
			return nil, err
		}
		out = append(out, label.String+": "+path.String)
	}
	return out, rows.Err()
}
