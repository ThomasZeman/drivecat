//go:build windows

package volume

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	netapi32         = windows.NewLazySystemDLL("netapi32.dll")
	procNetShareEnum = netapi32.NewProc("NetShareEnum")
)

// shareInfo1 is SHARE_INFO_1: the share's name, type and comment.
type shareInfo1 struct {
	netname *uint16
	typ     uint32
	remark  *uint16
}

// maxPreferredLength asks NetShareEnum for all entries in one buffer.
const maxPreferredLength = 0xffffffff

// ListShares asks server which folders it shares and returns the ones worth
// scanning (see scannableShares). It only reads the server's share list,
// with the permissions of the current Windows session.
func ListShares(server string) ([]Share, error) {
	name, err := windows.UTF16PtrFromString(`\\` + server)
	if err != nil {
		return nil, err
	}
	var buf *byte
	var read, total uint32
	r, _, _ := procNetShareEnum.Call(
		uintptr(unsafe.Pointer(name)),
		1, // SHARE_INFO_1
		uintptr(unsafe.Pointer(&buf)),
		maxPreferredLength,
		uintptr(unsafe.Pointer(&read)),
		uintptr(unsafe.Pointer(&total)),
		0)
	if buf != nil {
		defer windows.NetApiBufferFree(buf)
	}
	if r != 0 {
		return nil, fmt.Errorf("list the shares of \\\\%s: %w", server, windows.Errno(r))
	}
	if read == 0 || buf == nil {
		return nil, nil
	}

	entries := unsafe.Slice((*shareInfo1)(unsafe.Pointer(buf)), read)
	raw := make([]rawShare, 0, len(entries))
	for _, e := range entries {
		raw = append(raw, rawShare{
			name:   windows.UTF16PtrToString(e.netname),
			remark: windows.UTF16PtrToString(e.remark),
			typ:    e.typ,
		})
	}
	return scannableShares(server, raw), nil
}
