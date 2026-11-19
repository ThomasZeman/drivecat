package store

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"modernc.org/sqlite"

	"github.com/ThomasZeman/drivecat/internal/readonly"
)

// ApplicationID marks a SQLite file as a drivecat database ("DRCT"). It is
// stored in the file header, so drivecat can recognize its own databases
// with a plain read before SQLite opens, and possibly changes, anything.
const ApplicationID = 0x44524354

// ErrNotFound means there is no database at the path yet.
var ErrNotFound = errors.New("no database there yet: create it with drivecat init")

// sideFiles are the files SQLite keeps next to a database.
var sideFiles = []string{"-wal", "-shm", "-journal"}

// Create creates a new database at path. It refuses if anything already
// exists there, so it can never take over someone else's file. The folder
// must exist, unless makeFolder is set: then Create makes the last folder of
// the path (and only that one), which is meant for the default location.
func Create(ctx context.Context, path string, makeFolder bool) (*Store, error) {
	if err := checkPath(path); err != nil {
		return nil, err
	}
	for _, side := range sideFiles {
		if _, err := os.Lstat(path + side); err == nil {
			return nil, fmt.Errorf("refusing to create %s: %s already exists", path, path+side)
		}
	}
	if makeFolder {
		if err := os.Mkdir(filepath.Dir(path), 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("create database folder: %w", err)
		}
	}

	// O_EXCL makes "nothing exists there" and "create it" one step: if any
	// file or link appears at path in between, this fails instead of
	// taking it over. SQLite then opens the empty file without mode=rwc.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("refusing to create %s: a file already exists there", path)
	}
	if err != nil {
		return nil, fmt.Errorf("create database: %w", err)
	}
	created, err := f.Stat()
	f.Close()
	if err != nil {
		return nil, err
	}

	s, err := initialize(ctx, path, created)
	if err != nil {
		// Remove the file only if it is still the one created above.
		if fi, statErr := os.Lstat(path); statErr == nil && os.SameFile(fi, created) {
			os.Remove(path)
		}
		return nil, err
	}
	return s, nil
}

func initialize(ctx context.Context, path string, created os.FileInfo) (*Store, error) {
	s, err := open(path, "rw", created)
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
	fi, err := verify(path)
	if err != nil {
		return nil, err
	}
	s, err := open(path, "rw", fi)
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
	fi, err := verify(path)
	if err != nil {
		return nil, err
	}
	s, err := open(path, "ro", fi)
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

// sqliteDriver is drivecat's own instance of the SQLite driver, so its
// connection hook (the authorizer) applies to drivecat's connections only.
var sqliteDriver = func() *sqlite.Driver {
	d := &sqlite.Driver{}
	d.RegisterConnectionHook(func(c sqlite.ExecQuerierContext, _ string) error {
		r, ok := c.(sqlite.AuthorizerRegisterer)
		if !ok {
			return errors.New("the SQLite driver does not support an authorizer")
		}
		return r.RegisterAuthorizer(authorize)
	})
	return d
}()

// authorize refuses the SQL that could make SQLite create or write files
// other than the database: ATTACH and DETACH, and the pragmas that move or
// re-enable temporary files.
func authorize(action sqlite.AuthorizerActionCode, arg1, arg2, _, _ string) sqlite.AuthorizerReturnCode {
	switch action {
	case sqlite.AuthAttach, sqlite.AuthDetach:
		return sqlite.AuthorizerDeny
	case sqlite.AuthPragma:
		switch strings.ToLower(arg1) {
		case "temp_store_directory", "data_store_directory":
			return sqlite.AuthorizerDeny
		case "temp_store":
			if arg2 != "" {
				return sqlite.AuthorizerDeny
			}
		}
	}
	return sqlite.AuthorizerOK
}

type connector struct{ dsn string }

func (c connector) Connect(context.Context) (driver.Conn, error) { return sqliteDriver.Open(c.dsn) }
func (c connector) Driver() driver.Driver                        { return sqliteDriver }

// open connects to path, which must be the file described by want. mode is
// SQLite's URI mode: rw and ro require the file to exist. The file: URI form
// is what makes SQLite honour the mode; with a plain path the driver would
// create a missing file.
func open(path, mode string, want os.FileInfo) (*Store, error) {
	db := sql.OpenDB(connector{dsn(path, mode)})
	// One connection: drivecat has a single writer, and this rules out
	// SQLITE_BUSY between its own connections.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	s := &Store{db: db}
	if err := s.checkFile(want); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func dsn(path, mode string) string {
	q := url.Values{}
	q.Set("mode", mode)
	// Pragmas in the DSN run on every new connection, which matters for
	// foreign_keys: it is a per-connection setting in SQLite.
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	// Temporary tables and sort spills stay in memory. On disk they would go
	// to %TEMP%, which may be on a drive being scanned.
	q.Add("_pragma", "temp_store(2)")
	if mode == "ro" {
		q.Add("_pragma", "query_only(1)")
	} else {
		q.Add("_pragma", "synchronous(NORMAL)")
	}
	u := url.URL{Scheme: "file", Path: "/" + filepath.ToSlash(path), RawQuery: q.Encode()}
	return u.String()
}

// checkFile makes sure SQLite opened the file drivecat checked, and not
// another one that the URI resolved to.
func (s *Store) checkFile(want os.FileInfo) error {
	rows, err := s.db.Query("PRAGMA database_list")
	if err != nil {
		return err
	}
	defer rows.Close()
	var file string
	for rows.Next() {
		var seq int
		var name, f string
		if err := rows.Scan(&seq, &name, &f); err != nil {
			return err
		}
		if name == "main" {
			file = f
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	got, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("check database file %q: %w", file, err)
	}
	if !os.SameFile(got, want) {
		return fmt.Errorf("SQLite opened %q, which is not the file drivecat checked", file)
	}
	return nil
}

// verify checks with a plain read that path is a drivecat database: a
// regular file with the SQLite magic and drivecat's application id in its
// header. Anything else, including an empty file, is refused before SQLite
// gets a chance to convert or extend it. The read goes through
// internal/readonly, so a tiered or cloud file is refused, not recalled.
func verify(path string) (os.FileInfo, error) {
	if err := checkPath(path); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", path, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to use %s: not a regular file", path)
	}

	f, err := readonly.Open(path)
	if err != nil {
		return nil, fmt.Errorf("refusing to use %s: %w", path, err)
	}
	defer f.Close()
	var hdr [100]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return nil, fmt.Errorf("refusing to use %s: not a drivecat database (too short)", path)
	}
	if !bytes.Equal(hdr[:16], []byte("SQLite format 3\x00")) {
		return nil, fmt.Errorf("refusing to use %s: not a SQLite database", path)
	}
	if id := binary.BigEndian.Uint32(hdr[68:72]); id != ApplicationID {
		return nil, fmt.Errorf("refusing to use %s: a SQLite database, but not drivecat's (application id %#x)",
			path, id)
	}
	return f.Stat()
}

// checkPath accepts only an absolute path on a drive letter, like
// C:\Users\me\drivecat.db. UNC paths (\\server\share\...) and the \\?\ and
// \\.\ namespaces are refused: SQLite could resolve them to a different
// file than the one drivecat checked, and SQLite's locking is not reliable
// on network shares anyway.
func checkPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("database path %s must be absolute", path)
	}
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) {
		return fmt.Errorf("database path %s must be on a drive letter, not a UNC or device path", path)
	}
	return nil
}
