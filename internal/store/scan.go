package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SourceInfo is what a scan records about a drive or share. Kind and
// Fingerprint identify it; the rest is refreshed on every scan.
type SourceInfo struct {
	Kind, Fingerprint string
	Label             string // required for a new source, optional otherwise

	BusType, DiskModel, DiskSerial string
	DiskSize                       int64
	PartitionID                    string
	FSType, FSSerial, FSLabel      string
	SMBServer, SMBShare            string
	MarkerID                       string
}

// ErrLabelRequired means a source is scanned for the first time without a
// label.
var ErrLabelRequired = errors.New("this drive or share is new: give it a name with --label")

// UpsertSource records a source: it adds a new one, or refreshes the details
// and last_seen of a known one (and its label, if info has one). It returns
// the source's id and label.
func (s *Store) UpsertSource(ctx context.Context, info SourceInfo, now time.Time) (id int64, label string,
	created bool, err error) {
	ts := Timestamp(now)
	details := []any{
		nullStr(info.BusType), nullStr(info.DiskModel), nullStr(info.DiskSerial), nullInt(info.DiskSize),
		nullStr(info.PartitionID), nullStr(info.FSType), nullStr(info.FSSerial), nullStr(info.FSLabel),
		nullStr(info.SMBServer), nullStr(info.SMBShare), nullStr(info.MarkerID),
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, "", false, err
	}
	defer tx.Rollback()

	err = tx.QueryRowContext(ctx, "SELECT id, label FROM sources WHERE fingerprint = ?", info.Fingerprint).
		Scan(&id, &label)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if info.Label == "" {
			return 0, "", false, ErrLabelRequired
		}
		args := append([]any{info.Kind, info.Fingerprint, info.Label}, details...)
		args = append(args, ts, ts)
		res, err := tx.ExecContext(ctx, `
INSERT INTO sources (kind, fingerprint, label, bus_type, disk_model, disk_serial, disk_size, partition_id,
                     fs_type, fs_serial, fs_label, smb_server, smb_share, marker_id, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...)
		if err != nil {
			return 0, "", false, fmt.Errorf("add source: %w", err)
		}
		if id, err = res.LastInsertId(); err != nil {
			return 0, "", false, err
		}
		label, created = info.Label, true
	case err != nil:
		return 0, "", false, err
	default:
		if info.Label != "" {
			label = info.Label
		}
		args := append([]any{label}, details...)
		args = append(args, ts, id)
		if _, err := tx.ExecContext(ctx, `
UPDATE sources SET label = ?, bus_type = ?, disk_model = ?, disk_serial = ?, disk_size = ?, partition_id = ?,
                   fs_type = ?, fs_serial = ?, fs_label = ?, smb_server = ?, smb_share = ?, marker_id = ?,
                   last_seen = ?
WHERE id = ?`, args...); err != nil {
			return 0, "", false, fmt.Errorf("update source: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, "", false, err
	}
	return id, label, created, nil
}

// Scan statuses.
const (
	ScanRunning = "running"
	ScanDone    = "done"
	ScanAborted = "aborted"
)

// StartScan records the start of a scan of root (relative to the source)
// and returns its id.
func (s *Store) StartScan(ctx context.Context, sourceID int64, root, mountedAs string, started time.Time) (int64,
	error) {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO scans (source_id, root, mounted_as, started_at, status) VALUES (?, ?, ?, ?, ?)`,
		sourceID, root, mountedAs, Timestamp(started), ScanRunning)
	if err != nil {
		return 0, fmt.Errorf("start scan: %w", err)
	}
	return res.LastInsertId()
}

// FinishScan records the end of a scan with status done or aborted.
func (s *Store) FinishScan(ctx context.Context, scanID int64, status string, finished time.Time) error {
	_, err := s.db.ExecContext(ctx, "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
		status, Timestamp(finished), scanID)
	if err != nil {
		return fmt.Errorf("finish scan: %w", err)
	}
	return nil
}

// KnownFile is what an earlier scan recorded about a file.
type KnownFile struct {
	Size   int64
	MTime  string
	SHA256 []byte // nil if it could not be read
}

// LookupFile returns what the database has for relPath on a source.
func (s *Store) LookupFile(ctx context.Context, sourceID int64, relPath string) (KnownFile, bool, error) {
	var k KnownFile
	err := s.db.QueryRowContext(ctx, "SELECT size, mtime, sha256 FROM files WHERE source_id = ? AND rel_path = ?",
		sourceID, relPath).Scan(&k.Size, &k.MTime, &k.SHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return KnownFile{}, false, nil
	}
	if err != nil {
		return KnownFile{}, false, err
	}
	return k, true, nil
}

// FileRow is one file as a scan found it.
type FileRow struct {
	RelPath string
	Size    int64
	MTime   string
	SHA256  []byte // nil if the file could not be read
	Error   string // why it could not be read
}

// WriteFiles stores rows from a scan in one transaction, replacing what an
// earlier scan recorded for the same paths.
func (s *Store) WriteFiles(ctx context.Context, sourceID, scanID int64, seenAt time.Time, rows []FileRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO files (source_id, rel_path, size, mtime, sha256, error, scan_id, seen_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (source_id, rel_path) DO UPDATE SET
  size = excluded.size, mtime = excluded.mtime, sha256 = excluded.sha256, error = excluded.error,
  scan_id = excluded.scan_id, seen_at = excluded.seen_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	ts := Timestamp(seenAt)
	for _, r := range rows {
		var sum any
		if r.SHA256 != nil {
			sum = r.SHA256
		}
		if _, err := stmt.ExecContext(ctx, sourceID, r.RelPath, r.Size, r.MTime, sum, nullStr(r.Error),
			scanID, ts); err != nil {
			return fmt.Errorf("store %s: %w", r.RelPath, err)
		}
	}
	return tx.Commit()
}

// Files returns every file recorded for a source, ordered by path.
func (s *Store) Files(ctx context.Context, sourceID int64) ([]FileRow, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT rel_path, size, mtime, sha256, coalesce(error, '') FROM files WHERE source_id = ? ORDER BY rel_path`,
		sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FileRow
	for rows.Next() {
		var r FileRow
		if err := rows.Scan(&r.RelPath, &r.Size, &r.MTime, &r.SHA256, &r.Error); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ScanStatus returns the status of a scan.
func (s *Store) ScanStatus(ctx context.Context, scanID int64) (string, error) {
	var status string
	err := s.db.QueryRowContext(ctx, "SELECT status FROM scans WHERE id = ?", scanID).Scan(&status)
	return status, err
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}
