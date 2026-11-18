package store

// migrations holds the schema, one entry per version. The database's
// PRAGMA user_version records how many entries have been applied, so a
// migration must never be edited once released: append a new one instead.
var migrations = []string{
	// 1: sources, scans and files.
	`
CREATE TABLE sources (
  id           INTEGER PRIMARY KEY,
  kind         TEXT NOT NULL CHECK (kind IN ('disk', 'smb')),
  fingerprint  TEXT NOT NULL UNIQUE,  -- partition id + fs serial, or server/share
  label        TEXT NOT NULL,         -- the owner's name for it, e.g. 'WD 2TB black'
  bus_type     TEXT,                  -- USB, SATA, NVMe, SMB
  disk_model   TEXT,
  disk_serial  TEXT,
  disk_size    INTEGER,
  partition_id TEXT,                  -- GPT partition GUID or MBR signature + offset
  fs_type      TEXT,
  fs_serial    TEXT,
  fs_label     TEXT,
  smb_server   TEXT,
  smb_share    TEXT,
  marker_id    TEXT,                  -- UUID of the optional .drivecat-id marker file
  first_seen   TEXT NOT NULL,
  last_seen    TEXT NOT NULL
);

CREATE TABLE scans (
  id          INTEGER PRIMARY KEY,
  source_id   INTEGER NOT NULL REFERENCES sources(id),
  root        TEXT NOT NULL,          -- scanned folder, relative to the source
  mounted_as  TEXT NOT NULL,          -- e.g. E:\ or \\nas\photos, information only
  started_at  TEXT NOT NULL,
  finished_at TEXT,
  status      TEXT NOT NULL CHECK (status IN ('running', 'done', 'aborted'))
);

CREATE INDEX scans_source ON scans(source_id);

CREATE TABLE files (
  id        INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id),
  rel_path  TEXT NOT NULL,            -- relative to the source, '/' separated, NFC
  size      INTEGER NOT NULL,
  mtime     TEXT NOT NULL,
  sha256    BLOB CHECK (sha256 IS NULL OR length(sha256) = 32),
  error     TEXT,
  scan_id   INTEGER NOT NULL REFERENCES scans(id),
  seen_at   TEXT NOT NULL,
  UNIQUE (source_id, rel_path)
);

CREATE INDEX files_sha256 ON files(sha256);
CREATE INDEX files_scan ON files(scan_id);
`,
}
