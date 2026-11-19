//go:build windows

package readonly

import (
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// Access and flags for every source open. GENERIC_READ is FILE_READ_DATA,
// FILE_READ_ATTRIBUTES, FILE_READ_EA, READ_CONTROL and SYNCHRONIZE: nothing
// that can write.
const (
	access    = windows.GENERIC_READ
	shareMode = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
	flags     = windows.FILE_FLAG_OPEN_NO_RECALL | windows.FILE_FLAG_OPEN_REPARSE_POINT |
		windows.FILE_FLAG_SEQUENTIAL_SCAN

	notLocalAttrs = windows.FILE_ATTRIBUTE_OFFLINE | windows.FILE_ATTRIBUTE_RECALL_ON_OPEN |
		windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)

// Open opens an existing file on a source for reading. See the package
// documentation for what it guarantees.
func Open(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(longPath(path))
	if err != nil {
		return nil, err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return nil, &os.PathError{Op: "readonly.Open", Path: path, Err: err}
	}
	if err := check(attrs); err != nil {
		return nil, &os.PathError{Op: "readonly.Open", Path: path, Err: err}
	}

	h, err := windows.CreateFile(p, access, shareMode, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "readonly.Open", Path: path, Err: err}
	}

	// Check again on the handle: the file may have changed between the two
	// calls, and the handle is what will be read.
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "readonly.Open", Path: path, Err: err}
	}
	if err := check(info.FileAttributes); err != nil {
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "readonly.Open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// Flags for opening a directory to list it. BACKUP_SEMANTICS is what lets
// CreateFile open a directory at all; it grants no write access.
const dirFlags = windows.FILE_FLAG_BACKUP_SEMANTICS | windows.FILE_FLAG_OPEN_NO_RECALL |
	windows.FILE_FLAG_OPEN_REPARSE_POINT

// dirBufSize is the listing buffer. 64 KiB is the most an SMB server
// returns per request, so a larger buffer would not save round trips.
const dirBufSize = 64 << 10

// dirBufs hands out listing buffers. Windows needs them 8-byte aligned
// (ERROR_NOACCESS otherwise). A byte array the compiler keeps on the stack
// is only byte-aligned; the pool keeps them on the heap, where every
// allocation of this size is aligned.
var dirBufs = sync.Pool{New: func() any { return new([dirBufSize]byte) }}

// ReadDir lists the directory at path. It refuses a directory that is a
// link or whose content is not local, like Open does for files. The
// entries come in the order the file system returns them; "." and ".."
// are left out.
func ReadDir(path string) ([]Entry, error) {
	p, err := windows.UTF16PtrFromString(longPath(path))
	if err != nil {
		return nil, err
	}
	pathErr := func(err error) error { return &os.PathError{Op: "readonly.ReadDir", Path: path, Err: err} }

	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return nil, pathErr(err)
	}
	if err := checkDir(attrs); err != nil {
		return nil, pathErr(err)
	}
	h, err := windows.CreateFile(p, access, shareMode, nil, windows.OPEN_EXISTING, dirFlags, 0)
	if err != nil {
		return nil, pathErr(err)
	}
	defer windows.CloseHandle(h)

	// Check again on the handle: it is what will be listed.
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, pathErr(err)
	}
	if err := checkDir(info.FileAttributes); err != nil {
		return nil, pathErr(err)
	}

	var entries []Entry
	bp := dirBufs.Get().(*[dirBufSize]byte)
	defer dirBufs.Put(bp)
	buf := bp[:]
	class := uint32(windows.FileFullDirectoryRestartInfo)
	for {
		err := windows.GetFileInformationByHandleEx(h, class, &buf[0], uint32(len(buf)))
		if err == windows.ERROR_NO_MORE_FILES || (err == windows.ERROR_FILE_NOT_FOUND && entries == nil) {
			return entries, nil
		}
		if err != nil {
			return nil, pathErr(err)
		}
		class = windows.FileFullDirectoryInfo
		n := len(entries)
		entries, err = parseFullDirInfo(buf, entries)
		if err != nil {
			return nil, pathErr(err)
		}
		for i := n; i < len(entries); i++ {
			entryFromAttrs(&entries[i])
		}
	}
}

func checkDir(attrs uint32) error {
	switch {
	case attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return ErrReparsePoint
	case attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0, attrs&windows.FILE_ATTRIBUTE_DEVICE != 0:
		return ErrNotDir
	case attrs&notLocalAttrs != 0:
		return ErrNotLocal
	}
	return nil
}

// entryFromAttrs fills the flags of an entry from its attributes.
func entryFromAttrs(e *Entry) {
	e.IsDir = e.Attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	e.Link = e.Attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
	e.NotLocal = e.Attrs&notLocalAttrs != 0
	e.Device = e.Attrs&windows.FILE_ATTRIBUTE_DEVICE != 0
}

func check(attrs uint32) error {
	switch {
	case attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return ErrReparsePoint
	case attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0, attrs&windows.FILE_ATTRIBUTE_DEVICE != 0:
		return ErrNotFile
	case attrs&notLocalAttrs != 0:
		return ErrNotLocal
	}
	return nil
}

// longPath adds the \\?\ prefix to absolute paths, so paths longer than
// MAX_PATH work, which old backup drives often have. The prefix also stops
// Windows from rewriting the path (trailing dots and spaces are kept).
func longPath(p string) string {
	switch {
	case strings.HasPrefix(p, `\\?\`), strings.HasPrefix(p, `\\.\`):
		return p
	case strings.HasPrefix(p, `\\`):
		return `\\?\UNC\` + p[2:]
	case len(p) >= 3 && p[1] == ':' && p[2] == '\\':
		return `\\?\` + p
	}
	return p
}
