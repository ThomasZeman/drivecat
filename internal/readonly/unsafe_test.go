//go:build windows

package readonly

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func unsafePointer(d *windows.Win32FileAttributeData) unsafe.Pointer { return unsafe.Pointer(d) }
