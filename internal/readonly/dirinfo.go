package readonly

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unicode/utf16"
)

// ErrNotDir means the path is a file or device, not a directory.
var ErrNotDir = errors.New("not a directory")

// parseFullDirInfo decodes a buffer of FILE_FULL_DIR_INFO records and
// appends them to entries, skipping "." and "..". Each record is:
//
//	0  NextEntryOffset uint32 (0 for the last record)
//	4  FileIndex       uint32
//	8  CreationTime, 16 LastAccessTime, 24 LastWriteTime, 32 ChangeTime int64
//	40 EndOfFile int64, 48 AllocationSize int64
//	56 FileAttributes uint32, 60 FileNameLength uint32 (bytes), 64 EaSize uint32
//	68 FileName, UTF-16, not NUL-terminated
//
// Only Name, Size, ModTime and Attrs are set; the caller derives the flags.
func parseFullDirInfo(buf []byte, entries []Entry) ([]Entry, error) {
	const header = 68
	for off := 0; ; {
		if off+header > len(buf) {
			return nil, fmt.Errorf("directory listing record at %d is cut off", off)
		}
		r := buf[off:]
		next := int(binary.LittleEndian.Uint32(r[0:4]))
		nameLen := int(binary.LittleEndian.Uint32(r[60:64]))
		if nameLen%2 != 0 || header+nameLen > len(r) || (next != 0 && next < header+nameLen) {
			return nil, fmt.Errorf("directory listing record at %d is malformed", off)
		}
		units := make([]uint16, nameLen/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(r[header+2*i:])
		}
		name, ok := decodeName(units)
		if name != "." && name != ".." {
			entries = append(entries, Entry{
				Name:    name,
				Size:    int64(binary.LittleEndian.Uint64(r[40:48])),
				ModTime: filetimeToTime(binary.LittleEndian.Uint64(r[24:32])),
				Attrs:   binary.LittleEndian.Uint32(r[56:60]),
				BadName: !ok,
			})
		}
		if next == 0 {
			return entries, nil
		}
		off += next
	}
}

// decodeName turns a UTF-16 file name into a string. ok is false if the
// name has unpaired surrogates or a NUL, which Windows allows on some file
// systems but which cannot be turned into a string and back unchanged.
func decodeName(units []uint16) (name string, ok bool) {
	ok = true
	for i := 0; i < len(units); i++ {
		switch u := units[i]; {
		case u == 0:
			ok = false
		case 0xd800 <= u && u <= 0xdbff:
			if i+1 < len(units) && 0xdc00 <= units[i+1] && units[i+1] <= 0xdfff {
				i++
			} else {
				ok = false
			}
		case 0xdc00 <= u && u <= 0xdfff:
			ok = false
		}
	}
	return string(utf16.Decode(units)), ok
}

// filetimeToTime converts a FILETIME (100 ns steps since 1601-01-01 UTC) to
// a time.Time. It works in seconds first, so a corrupt, huge value from an
// old drive cannot overflow.
func filetimeToTime(ft uint64) time.Time {
	const epochDiff = 116444736000000000 // 1601 to 1970 in 100 ns steps
	v := int64(ft)
	if v < 0 {
		return time.Time{}
	}
	v -= epochDiff
	sec, rem := v/1e7, v%1e7
	if rem < 0 {
		sec--
		rem += 1e7
	}
	return time.Unix(sec, rem*100).UTC()
}
