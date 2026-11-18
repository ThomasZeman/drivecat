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
```

The database defaults to `%LOCALAPPDATA%\drivecat\drivecat.db`; override it with `--db PATH` or `DRIVECAT_DB`.
`identify`, `scan` and `report` are planned and not implemented yet.
