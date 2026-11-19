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
which must be an absolute path on a drive letter (not a UNC path). Only `init` creates a database, and only in a
folder that already exists; the default `drivecat` folder is the one folder it creates itself. `sources` and
`identify` open the database read-only.
`scan` and `report` are planned and not implemented yet.

## Read-only towards your drives

drivecat must never change anything on the drives and shares it identifies or scans. The only file it writes is its
own database. The safeguards so far:

- Source files are opened through `internal/readonly`: read access only, an existing file only, and sharing for
  read, write and delete. A handle is still held while a file is read, so a program that wants exclusive access, or
  renames a parent folder, has to wait until drivecat moves on. A link in the last part of the path is not followed,
  and offline or cloud-only files are skipped instead of recalled. Links in parent folders are not detected yet.
- Drive queries go through an allowlist of five read-only IOCTLs, and the one that takes input only accepts the two
  standard queries drivecat builds itself. A test decodes each code from its number.
- `identify` refuses device paths (`COM3`, `NUL`, `\\.\PhysicalDrive0`, `\\?\GLOBALROOT\...`) before anything opens
  them.
- A test in `internal/policy` loads all packages with full type information and checks them against allowlists:
  what each package may import, and which functions, constants and variables of `os`, `os/signal`,
  `golang.org/x/sys/windows` and the SQLite driver it may use, however they are reached (dot imports, function
  values, method values). Every `CreateFile` call must pass constant read-only access and `OPEN_EXISTING`; `os.OpenFile`
  may only create a new file; `DeviceIoControl` may only be called inside the IOCTL allowlist function; DLLs and
  their functions may only be loaded by listed names. cgo, assembly, `go:linkname` and files hidden behind build
  constraints fail the test. It is a test, not a compiler: it stops a mistake from being merged, not a determined
  attempt that also edits the test. Writing to an `*os.File` through an interface such as `io.Writer` is not
  visible to it; that case is left to the operating system, which refuses writes on the read-only handles.
- The database is refused, before SQLite opens it, unless the file header carries drivecat's application id. A
  mistyped `--db` therefore cannot convert someone else's SQLite file or an empty file. After opening, drivecat
  checks that SQLite opened that same file.
- `init` creates the database file atomically and refuses if the file or a SQLite side file (`-wal`, `-shm`,
  `-journal`) already exists.
- SQLite keeps temporary tables and sorts in memory instead of `%TEMP%`, and refuses `ATTACH`, `VACUUM INTO` and
  the pragmas that move temporary files, so it cannot be made to write a second file.

One thing drivecat cannot avoid: reading a file's content may update its last-access time, if Windows or the NAS
keeps it. Preventing that would require write access to the file, which is itself a change. Content, size,
modification time and attributes stay untouched.

## License

MIT, see [LICENSE](LICENSE).
