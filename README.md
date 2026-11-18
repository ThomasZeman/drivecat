# drivecat

Builds a catalogue of every file on a set of USB drives, internal drives and NAS shares: where each drive physically
is, and every file's relative path, size, modification time and SHA-256. The goal is to find duplicates and plan a
cleaner structure. drivecat only reads from the drives it scans.

Design and background: the "Bringing Order to Decades of Drives" series on tomcore.io.

## Build and test

Requires Go 1.27 or newer.

```shell
go test ./...
go build -o drivecat.exe ./cmd/drivecat
```

## Usage

```shell
drivecat init
drivecat sources
drivecat identify E:\
drivecat identify \\nas\photos --json
```

The database defaults to `%LOCALAPPDATA%\drivecat\drivecat.db`; override it with `--db PATH` or `DRIVECAT_DB`,
which must be absolute. Only `init` creates a database. `sources` and `identify` open it read-only.
`scan` and `report` are planned and not implemented yet.

## Read-only towards your drives

drivecat must never change anything on the drives and shares it identifies or scans. The only file it writes is its
own database. The safeguards so far:

- Source files are opened through `internal/readonly`: read access only, an existing file only, and sharing for
  read, write and delete. A handle is still held while a file is read, so a program that wants exclusive access, or
  renames a parent folder, has to wait until drivecat moves on. A link in the last part of the path is not followed,
  and offline or cloud-only files are skipped instead of recalled. Links in parent folders are not detected yet.
- Drive queries go through an allowlist of five read-only IOCTLs. A test decodes each code from its number.
- A test in `internal/policy` fails if code outside `internal/store` uses known Go or Windows functions and constants
  that write, rename, delete or change files, or loads a DLL function that is not on the allowlist. It checks names,
  so it catches mistakes, not every possible way around it. A stricter, type-based check is planned before `scan`.
- The database is refused, before SQLite opens it, unless the file header carries drivecat's application id. A
  mistyped `--db` therefore cannot convert someone else's SQLite file or an empty file.

One thing drivecat cannot avoid: reading a file's content may update its last-access time, if Windows or the NAS
keeps it. Preventing that would require write access to the file, which is itself a change. Content, size,
modification time and attributes stay untouched.

## License

MIT, see [LICENSE](LICENSE).
