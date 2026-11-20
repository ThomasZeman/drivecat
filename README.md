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
drivecat scan E:\ --label "WD 2TB black"
drivecat scan \\nas\photos --label "NAS photos"
drivecat identify \\nas
drivecat scan \\nas --label NAS
drivecat report
drivecat report --top 50 --json
drivecat duplicates --source "NAS photos" --min-size 1M
drivecat forget "NAS home" --yes
```

Given only a server (`\\nas` or `\\192.168.1.20`), `identify` lists its shares and `scan` scans each one as its own
source, named after the `--label` prefix and the share (`NAS photos`, `NAS backup`). Admin shares (`C$`, `ADMIN$`),
`IPC$`, printers and other hidden shares ending in `$` are left out; a hidden share can still be scanned by its full
path. A share is recognized by server and share name, so always use the same name for the server: `\\nas` and
`\\192.168.1.20` count as different sources.

The database defaults to `%LOCALAPPDATA%\drivecat\drivecat.db`; override it with `--db PATH` or `DRIVECAT_DB`,
which must be an absolute path on a drive letter (not a UNC path). Only `init` creates a database, and only in a
folder that already exists; the default `drivecat` folder is the one folder it creates itself. `sources`,
`identify`, `report` and `duplicates` open the database read-only.

### Scanning

`scan PATH` records every file below PATH with its relative path, size, modification time and SHA-256. A drive
or share seen for the first time needs a name with `--label`; later scans recognize it and keep the name (or
rename it, if `--label` is given again).

- A file that cannot be read is stored with its error and no checksum, and the scan carries on. So are links and
  offline or cloud-only files, which are recorded but never read.
- Folders that are links or junctions are not entered. Nor are `$RECYCLE.BIN`, `System Volume Information`, NAS
  snapshot and recycle folders (`#snapshot`, `#recycle`, `@Recycle`, `@Recently-Snapshot`, `.snapshot`,
  `~snapshot`), and, in the root of a drive only, the old `RECYCLER` and `RECYCLED` bins. Folders that cannot be
  listed are reported as warnings.
- Paths are stored `/`-separated and in Unicode NFC, so names written by a Mac match. If a folder holds the same
  name in both forms, the second keeps its original form instead of overwriting the first.
- Spinning disks, and disks that do not say, are read one file at a time; SSDs and shares with 4 parallel readers.
  `--workers N` overrides it.
- A file whose size and modification time match the last scan keeps its checksum without being read again, so
  scanning a drive again only reads what changed. `--rehash` reads everything. This also resumes an interrupted
  scan: Ctrl+C stores what was read so far and marks the scan aborted.
- A file that changes while it is read is stored with an error instead of a checksum that matches no version of
  it.
- The scan refuses to run if the database is inside the folder being scanned, and warns if it is on the same
  drive.
- Errors are printed as they happen; `-v` prints every file with its checksum. The progress and summary count
  files whose content is already recorded on another source, and the summary names those sources.

### Report

`report` compares everything recorded so far by checksum:

- all sources: files and bytes, unique content (each checksum counted once), and the extra copies beyond it;
- per source: files, size, copies inside the source, and what is **only here**: content found on no other source,
  so losing that source would lose it;
- the largest duplicates by extra bytes (`--top N`, default 10, `0` to leave them out), with up to five places each.

Empty files are counted, but never listed as duplicates, since they all share one checksum. `--json` prints the
same data for scripts.

`duplicates` lists every file that exists more than once with all of its copies (source, path and modification
date), largest extra bytes first, and ends with the totals. `--source NAME` (or the id from `sources`) keeps only
files with a copy on that source, and still lists their copies elsewhere; `--min-size 1M` leaves out small files;
`--json` prints one object per line. It opens the database read-only, like `report`.

`forget SOURCE` removes a source (by label or id) from the database together with its files and scans, for
example a share that turned out to be another view of one already scanned. Without `--yes` it only shows what
would be removed. Nothing on the drive or share is touched; scanning it again adds it back as a new source.

Not handled yet: a file deleted or renamed on a drive keeps its row after the next scan (with an older `seen_at`),
so `report` and `duplicates` still count it under its old path.

## Read-only towards your drives

drivecat must never change anything on the drives and shares it identifies or scans. The only file it writes is its
own database. The safeguards so far:

- Source files are opened through `internal/readonly`: read access only, an existing file only, and sharing for
  read, write and delete. A handle is still held while a file is read, so a program that wants exclusive access, or
  renames a parent folder, has to wait until drivecat moves on. A link in the last part of the path is not followed,
  and offline or cloud-only files are skipped instead of recalled.
- Folders are listed through `internal/readonly` with the same read-only access. A folder that is itself a link is
  refused, so a scan never follows a link, including at the folder it starts from. A link that someone creates in
  place of a folder while the scan runs is not detected; it would make drivecat read elsewhere, never write.
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
