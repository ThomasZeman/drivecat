//go:build windows

package readonly

import (
	"os"
	"strings"

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
