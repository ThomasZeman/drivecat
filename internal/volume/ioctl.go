package volume

import "fmt"

// IOCTL codes, CTL_CODE(device, function, METHOD_BUFFERED, FILE_ANY_ACCESS).
// FILE_ANY_ACCESS lets them work on a handle opened without read access,
// which needs no administrator rights.
const (
	ioctlStorageGetDeviceNumber = 0x2D1080
	ioctlStorageQueryProperty   = 0x2D1400
	ioctlDiskGetPartitionInfoEx = 0x70048
	ioctlDiskGetDriveLayoutEx   = 0x70050
	ioctlDiskGetDriveGeometryEx = 0x700A0
)

// ctlCode is a decoded Windows I/O control code:
// CTL_CODE(DeviceType, Function, Method, Access) =
// DeviceType<<16 | Access<<14 | Function<<2 | Method.
type ctlCode struct {
	Device, Access, Function, Method uint32
}

func decodeCtlCode(code uint32) ctlCode {
	return ctlCode{
		Device:   code >> 16,
		Access:   (code >> 14) & 3,
		Function: (code >> 2) & 0xfff,
		Method:   code & 3,
	}
}

// fileAnyAccess is the Access value of codes that need neither read nor
// write access to the handle. Refusing other values is only a first filter:
// some codes that change state also use FILE_ANY_ACCESS (FSCTL_LOCK_VOLUME,
// FSCTL_DISMOUNT_VOLUME, IOCTL_DISK_UPDATE_PROPERTIES). The allowlist below
// is what actually protects the drive.
const fileAnyAccess = 0

// allowedIoctls lists the only codes drivecat may send: read-only queries.
// Function numbers are checked against the Windows SDK: the matching SET
// codes (for example IOCTL_DISK_SET_DRIVE_LAYOUT_EX, function 0x15) are
// different numbers with write access.
var allowedIoctls = map[uint32]string{
	ioctlStorageGetDeviceNumber: "IOCTL_STORAGE_GET_DEVICE_NUMBER",
	ioctlStorageQueryProperty:   "IOCTL_STORAGE_QUERY_PROPERTY",
	ioctlDiskGetPartitionInfoEx: "IOCTL_DISK_GET_PARTITION_INFO_EX",
	ioctlDiskGetDriveLayoutEx:   "IOCTL_DISK_GET_DRIVE_LAYOUT_EX",
	ioctlDiskGetDriveGeometryEx: "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX",
}

// checkIoctl refuses any code that is not an allowed read-only query.
func checkIoctl(code uint32) error {
	if decodeCtlCode(code).Access != fileAnyAccess {
		return fmt.Errorf("refusing IOCTL %#x: it requires handle access (%d); drivecat only sends queries",
			code, decodeCtlCode(code).Access)
	}
	if _, ok := allowedIoctls[code]; !ok {
		return fmt.Errorf("refusing IOCTL %#x: not on drivecat's list of read-only queries", code)
	}
	return nil
}
