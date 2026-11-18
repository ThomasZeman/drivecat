package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
)

// ApplicationID marks a SQLite file as a drivecat database ("DRCT"). It is
// stored in the file header, so drivecat can recognize its own databases
// with a plain read before SQLite opens, and possibly changes, anything.
const ApplicationID = 0x44524354

// ErrNotFound means there is no database at the path yet.
var ErrNotFound = errors.New("no database there yet: create it with drivecat init")

// Create creates a new database at path. It refuses if anything already
// exists there, so it can never take over someone else's file.
func Create(ctx context.Context, path string) (*Store, error) {
	if err := checkAbs(path); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, fmt.Errorf("refusing to create %s: a file already exists there", path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create database folder: %w", err)
	}

	s, err := open(path, "rwc")
	if err != nil {
		return nil, err
	}
	// application_id first, while the file is still in rollback-journal
	// mode, so it lands in the main file's header right away.
	for _, p := range []string{
		fmt.Sprintf("PRAGMA application_id = %d", ApplicationID),
		"PRAGMA journal_mode = WAL",
	} {
		if _, err := s.db.ExecContext(ctx, p); err != nil {
			s.Close()
			return nil, fmt.Errorf("initialize database: %w", err)
		}
	}
	if err := s.migrate(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Open opens an existing drivecat database for reading and writing and
// applies pending migrations. It never creates a file, and it refuses any
// file that is not a drivecat database before SQLite touches it.
func Open(ctx context.Context, path string) (*Store, error) {
	if err := verify(path); err != nil {
		return nil, err
	}
	s, err := open(path, "rw")
	if err != nil {
		return nil, err
	}
	if err := s.migrate(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// OpenReadOnly opens an existing drivecat database without writing to it:
// no migrations, and SQLite refuses every change.
func OpenReadOnly(ctx context.Context, path string) (*Store, error) {
	if err := verify(path); err != nil {
		return nil, err
	}
	s, err := open(path, "ro")
	if err != nil {
		return nil, err
	}
	v, err := s.SchemaVersion(ctx)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("read schema version: %w", err)
	}
	if v != len(migrations) {
		s.Close()
		return nil, fmt.Errorf("database schema version %d, this drivecat expects %d: run drivecat init",
			v, len(migrations))
	}
	return s, nil
}

// open connects to path. mode is SQLite's URI mode: rwc creates the file,
// rw and ro require it to exist. The file: URI form is what makes SQLite
// honour the mode; with a plain path the driver would create a missing file.
func open(path, mode string) (*Store, error) {
	q := url.Values{}
	q.Set("mode", mode)
	// Pragmas in the DSN run on every new connection, which matters for
	// foreign_keys: it is a per-connection setting in SQLite.
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	if mode == "ro" {
		q.Add("_pragma", "query_only(1)")
	} else {
		q.Add("_pragma", "synchronous(NORMAL)")
	}
	u := url.URL{Scheme: "file", Path: "/" + filepath.ToSlash(path), RawQuery: q.Encode()}

	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// One connection: drivecat has a single writer, and this rules out
	// SQLITE_BUSY between its own connections.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// verify checks with a plain read that path is a drivecat database: an
// absolute path to a regular file with the SQLite magic and drivecat's
// application id in its header. Anything else, including an empty file, is
// refused before SQLite gets a chance to convert or extend it.
func verify(path string) error {
	if err := checkAbs(path); err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s: %w", path, ErrNotFound)
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing to use %s: not a regular file", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var hdr [100]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return fmt.Errorf("refusing to use %s: not a drivecat database (too short)", path)
	}
	if !bytes.Equal(hdr[:16], []byte("SQLite format 3\x00")) {
		return fmt.Errorf("refusing to use %s: not a SQLite database", path)
	}
	if id := binary.BigEndian.Uint32(hdr[68:72]); id != ApplicationID {
		return fmt.Errorf("refusing to use %s: a SQLite database, but not drivecat's (application id %#x)", path, id)
	}
	return nil
}

func checkAbs(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("database path %q must be absolute", path)
	}
	return nil
}
