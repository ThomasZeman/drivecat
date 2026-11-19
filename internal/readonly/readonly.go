// Package readonly opens files on sources: the drives and shares drivecat
// identifies and scans. It is the only way drivecat reads a source file's
// content, and it opens files so that drivecat cannot change them:
//
//   - read access only, and no access that allows writing, deleting or
//     changing attributes or timestamps;
//   - the file must already exist; nothing is ever created;
//   - full sharing, so other programs can still write, rename or delete the
//     file while drivecat reads it;
//   - links (reparse points) are not followed, and offline or cloud files
//     are refused instead of being downloaded or recalled.
//
// Directories are listed the same way: read access only, the directory must
// exist, and a directory that is itself a link is refused rather than
// followed.
//
// Reading a file's content can still update its last-access time; avoiding
// that would need write access to the file, which is itself a change. The
// same goes for listing a directory.
package readonly

import (
	"errors"
	"time"
)

// Entry is one item of a directory listing, with the details the listing
// itself carries, so no file has to be opened to learn them.
type Entry struct {
	Name    string
	Size    int64
	ModTime time.Time
	Attrs   uint32 // FILE_ATTRIBUTE_* bits

	IsDir bool
	// Link is set for reparse points (symbolic links, junctions, mount
	// points, cloud placeholders), which drivecat does not follow.
	Link bool
	// NotLocal is set for offline, tiered or cloud files whose content is
	// not on the drive.
	NotLocal bool
	// Device is set for entries that are devices, not files.
	Device bool
	// BadName is set if the name is not valid Unicode (unpaired UTF-16
	// surrogates). Name then holds a replacement character instead, so the
	// entry cannot be opened by that name and must be skipped.
	BadName bool
}

// ErrNotLocal means the file's content is not on the drive (an offline,
// tiered or cloud-only file); reading it would download or recall it.
var ErrNotLocal = errors.New("file content is not local (offline or cloud file); not read to avoid a recall")

// ErrReparsePoint means the path is a link, junction or other reparse
// point, which drivecat does not follow.
var ErrReparsePoint = errors.New("reparse point (link or junction); not followed")

// ErrNotFile means the path is a directory or device, not a file.
var ErrNotFile = errors.New("not a regular file")
